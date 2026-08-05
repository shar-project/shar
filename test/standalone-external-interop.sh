#!/usr/bin/env bash
set -euo pipefail

: "${SHAR_TEST_POSTGRES_URL:?set SHAR_TEST_POSTGRES_URL to an isolated PostgreSQL database}"
: "${SHAR_TEST_REDIS_URL:?set SHAR_TEST_REDIS_URL to an isolated Redis-compatible service}"

workspace=$(cd "$(dirname "$0")/.." && pwd)
test_directory=$(mktemp -d /tmp/shar-external-interop.XXXXXX)
rust_pid=
javascript_pid=

cleanup() {
  if [[ -n "$javascript_pid" ]]; then kill "$javascript_pid" 2>/dev/null || true; fi
  if [[ -n "$rust_pid" ]]; then kill "$rust_pid" 2>/dev/null || true; fi
  if [[ -n "$javascript_pid" ]]; then wait "$javascript_pid" 2>/dev/null || true; fi
  if [[ -n "$rust_pid" ]]; then wait "$rust_pid" 2>/dev/null || true; fi
  if [[ "$test_directory" == /tmp/shar-external-interop.* ]]; then
    rm -rf -- "$test_directory"
  fi
}

wait_for_server() {
  local endpoint=$1
  local pid=$2
  local log=$3
  for _ in $(seq 1 150); do
    if curl --fail --silent "$endpoint/readyz" >/dev/null 2>&1; then return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then
      cat "$log"
      return 1
    fi
    sleep 0.1
  done
  cat "$log"
  return 1
}

stop_servers() {
  kill "$javascript_pid" "$rust_pid" 2>/dev/null || true
  wait "$javascript_pid" 2>/dev/null || true
  wait "$rust_pid" 2>/dev/null || true
  javascript_pid=
  rust_pid=
}

start_servers() {
  env \
    SHAR_INSECURE_DEVELOPMENT=1 \
    SHAR_KEY_FILE="$test_directory/keys.json" \
    SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
    SHAR_POSTGRES_URL="$SHAR_TEST_POSTGRES_URL" \
    SHAR_REDIS_URL="$SHAR_TEST_REDIS_URL" \
    SHAR_LISTEN=127.0.0.1:4388 \
    SHAR_ADMIN_ASSETS="$workspace/dist/admin" \
    SHAR_REQUEST_LOG=0 \
    SHAR_MAX_CONCURRENT_REQUESTS=1 \
    SHAR_STATE_TIMEOUT_MS=2000 \
    target/release/shar-server >>"$test_directory/rust.log" 2>&1 &
  rust_pid=$!
  env \
    SHAR_INSECURE_DEVELOPMENT=1 \
    SHAR_KEY_FILE="$test_directory/keys.json" \
    SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
    SHAR_POSTGRES_URL="$SHAR_TEST_POSTGRES_URL" \
    SHAR_REDIS_URL="$SHAR_TEST_REDIS_URL" \
    SHAR_LISTEN=127.0.0.1:4389 \
    SHAR_ADMIN_ASSETS="$workspace/dist/admin" \
    SHAR_REQUEST_LOG=0 \
    SHAR_MAX_CONCURRENT_REQUESTS=1 \
    SHAR_STATE_TIMEOUT_MS=2000 \
    node standalone/js/server.mjs >>"$test_directory/javascript.log" 2>&1 &
  javascript_pid=$!
  wait_for_server http://127.0.0.1:4388 "$rust_pid" "$test_directory/rust.log"
  wait_for_server http://127.0.0.1:4389 "$javascript_pid" "$test_directory/javascript.log"
}

trap cleanup EXIT
cd "$workspace"
npm run build
cargo build --locked --release --bin shar-server --bin shar-keygen
target/release/shar-keygen --output "$test_directory/keys.json"

start_servers
SHAR_ENDPOINT_A=http://127.0.0.1:4388 \
SHAR_ENDPOINT_B=http://127.0.0.1:4389 \
SHAR_KEY_FILE="$test_directory/keys.json" \
node test/interop.mjs

SHAR_ROTATION_ENDPOINT=http://127.0.0.1:4388 \
SHAR_ROTATION_CHALLENGE="$test_directory/restart-challenge.json" \
node test/rotation-interop.mjs prepare
stop_servers

start_servers
SHAR_ROTATION_ENDPOINT=http://127.0.0.1:4389 \
SHAR_ROTATION_CHALLENGE="$test_directory/restart-challenge.json" \
SHAR_KEY_FILE="$test_directory/keys.json" \
node test/rotation-interop.mjs complete

echo "PostgreSQL/Redis cross-process replay and restart interoperability passed"
