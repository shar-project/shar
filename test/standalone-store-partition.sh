#!/usr/bin/env bash
set -euo pipefail

: "${SHAR_TEST_POSTGRES_URL:?set SHAR_TEST_POSTGRES_URL to an isolated PostgreSQL database}"
: "${SHAR_TEST_REDIS_URL:?set SHAR_TEST_REDIS_URL to an isolated Redis-compatible service}"

workspace=$(cd "$(dirname "$0")/.." && pwd)
test_directory=$(mktemp -d /tmp/shar-store-partition.XXXXXX)
proxy_pid=
rust_pid=
javascript_pid=
fault_postgres_url=$(node -e 'const value=new URL(process.env.SHAR_TEST_POSTGRES_URL); value.hostname="127.0.0.1"; value.port="45432"; console.log(value.href)')
fault_redis_url=$(node -e 'const value=new URL(process.env.SHAR_TEST_REDIS_URL); value.hostname="127.0.0.1"; value.port="46379"; console.log(value.href)')

cleanup() {
  local status=$?
  if [[ -n "$javascript_pid" ]]; then kill "$javascript_pid" 2>/dev/null || true; fi
  if [[ -n "$rust_pid" ]]; then kill "$rust_pid" 2>/dev/null || true; fi
  if [[ -n "$proxy_pid" ]]; then kill "$proxy_pid" 2>/dev/null || true; fi
  if [[ -n "$javascript_pid" ]]; then wait "$javascript_pid" 2>/dev/null || true; fi
  if [[ -n "$rust_pid" ]]; then wait "$rust_pid" 2>/dev/null || true; fi
  if [[ -n "$proxy_pid" ]]; then wait "$proxy_pid" 2>/dev/null || true; fi
  if [[ "$status" -ne 0 ]]; then
    for log in proxy rust javascript; do
      if [[ -f "$test_directory/$log.log" ]]; then
        echo "--- $log log ---" >&2
        cat "$test_directory/$log.log" >&2
      fi
    done
  fi
  if [[ "$test_directory" == /tmp/shar-store-partition.* ]]; then
    rm -rf -- "$test_directory"
  fi
  return "$status"
}

wait_for_log() {
  local description=$1
  local pattern=$2
  local pid=$3
  local log=$4
  for _ in $(seq 1 200); do
    if grep -q "$pattern" "$log"; then return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "$description exited before becoming ready" >&2
      cat "$log"
      return 1
    fi
    sleep 0.1
  done
  echo "timed out waiting for $description" >&2
  cat "$log"
  return 1
}

wait_for_endpoint() {
  local description=$1
  local endpoint=$2
  local pid=$3
  local log=$4
  for _ in $(seq 1 200); do
    if curl --fail --silent "$endpoint/readyz" >/dev/null 2>&1; then return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "$description exited before becoming ready" >&2
      cat "$log"
      return 1
    fi
    sleep 0.1
  done
  echo "timed out waiting for $description" >&2
  cat "$log"
  return 1
}

stop_server() {
  local label=$1
  local pid=$2
  local log=$3
  kill "$pid" 2>/dev/null || true
  if ! wait "$pid"; then
    echo "$label did not shut down cleanly" >&2
    cat "$log"
    return 1
  fi
}

trap cleanup EXIT
cd "$workspace"
npm run build
cargo build --locked --release --bin shar-server --bin shar-keygen
target/release/shar-keygen --output "$test_directory/keys.json"

node test/tcp-fault-proxy.mjs >"$test_directory/proxy.log" 2>&1 &
proxy_pid=$!
wait_for_log \
  "fault proxy" \
  '^fault proxy ready$' \
  "$proxy_pid" \
  "$test_directory/proxy.log"

env \
  SHAR_INSECURE_DEVELOPMENT=1 \
  SHAR_KEY_FILE="$test_directory/keys.json" \
  SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
  SHAR_POSTGRES_URL="$fault_postgres_url" \
  SHAR_REDIS_URL="$fault_redis_url" \
  SHAR_LISTEN=127.0.0.1:4488 \
  SHAR_ADMIN_ASSETS="$workspace/dist/admin" \
  SHAR_REQUEST_LOG=0 \
  SHAR_STATE_TIMEOUT_MS=500 \
  target/release/shar-server >"$test_directory/rust.log" 2>&1 &
rust_pid=$!
env \
  SHAR_INSECURE_DEVELOPMENT=1 \
  SHAR_KEY_FILE="$test_directory/keys.json" \
  SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
  SHAR_POSTGRES_URL="$fault_postgres_url" \
  SHAR_REDIS_URL="$fault_redis_url" \
  SHAR_LISTEN=127.0.0.1:4489 \
  SHAR_ADMIN_ASSETS="$workspace/dist/admin" \
  SHAR_REQUEST_LOG=0 \
  SHAR_STATE_TIMEOUT_MS=500 \
  node standalone/js/server.mjs >"$test_directory/javascript.log" 2>&1 &
javascript_pid=$!

wait_for_endpoint \
  "Rust standalone" \
  http://127.0.0.1:4488 \
  "$rust_pid" \
  "$test_directory/rust.log"
wait_for_endpoint \
  "JavaScript standalone" \
  http://127.0.0.1:4489 \
  "$javascript_pid" \
  "$test_directory/javascript.log"

SHAR_TEST_ENDPOINTS=http://127.0.0.1:4488,http://127.0.0.1:4489 \
  node test/store-partition.mjs healthy
kill -USR1 "$proxy_pid"
sleep 0.2
SHAR_TEST_ENDPOINTS=http://127.0.0.1:4488,http://127.0.0.1:4489 \
  node test/store-partition.mjs partitioned
kill -USR2 "$proxy_pid"
sleep 0.2
SHAR_TEST_ENDPOINTS=http://127.0.0.1:4488,http://127.0.0.1:4489 \
  node test/store-partition.mjs recovered

stop_server "JavaScript standalone" "$javascript_pid" "$test_directory/javascript.log"
javascript_pid=
stop_server "Rust standalone" "$rust_pid" "$test_directory/rust.log"
rust_pid=
kill "$proxy_pid"
wait "$proxy_pid"
proxy_pid=

echo "PostgreSQL/Redis partition failure and recovery passed for both standalones"
