#!/usr/bin/env bash
set -euo pipefail

: "${SHAR_TEST_POSTGRES_URL:?set SHAR_TEST_POSTGRES_URL to an isolated PostgreSQL database}"
: "${SHAR_TEST_REDIS_URL:?set SHAR_TEST_REDIS_URL to an isolated Redis-compatible service}"

postgres_url_rust=${SHAR_TEST_POSTGRES_URL_RUST:-$SHAR_TEST_POSTGRES_URL}
postgres_url_javascript=${SHAR_TEST_POSTGRES_URL_JAVASCRIPT:-$SHAR_TEST_POSTGRES_URL}
redis_url_rust=${SHAR_TEST_REDIS_URL_RUST:-$SHAR_TEST_REDIS_URL}
redis_url_javascript=${SHAR_TEST_REDIS_URL_JAVASCRIPT:-$SHAR_TEST_REDIS_URL}
postgres_ca_file=${SHAR_TEST_POSTGRES_CA_FILE:-}
redis_ca_file=${SHAR_TEST_REDIS_CA_FILE:-}
insecure_development=${SHAR_TEST_INSECURE_DEVELOPMENT:-1}
skip_build=${SHAR_TEST_SKIP_BUILD:-0}

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
  local failed=0
  kill "$javascript_pid" "$rust_pid" 2>/dev/null || true
  if ! wait "$javascript_pid"; then
    echo "JavaScript standalone did not shut down cleanly" >&2
    cat "$test_directory/javascript.log"
    failed=1
  fi
  if ! wait "$rust_pid"; then
    echo "Rust standalone did not shut down cleanly" >&2
    cat "$test_directory/rust.log"
    failed=1
  fi
  javascript_pid=
  rust_pid=
  return "$failed"
}

start_servers() {
  local common_environment=(
    SHAR_KEY_FILE="$test_directory/keys.json"
    SHAR_ALLOWED_ORIGINS=http://localhost:3000
    SHAR_TRUSTED_PROXY_CIDRS=127.0.0.1/32
    SHAR_ASSURANCE_MODE=trusted-header
    SHAR_ADMIN_ASSETS="$workspace/dist/admin"
    SHAR_REQUEST_LOG=0
    SHAR_MAX_CONCURRENT_REQUESTS=1
    SHAR_STATE_TIMEOUT_MS=2000
  )
  if [[ "$insecure_development" == 1 ]]; then
    common_environment+=(SHAR_INSECURE_DEVELOPMENT=1)
  elif [[ "$insecure_development" != 0 ]]; then
    echo "SHAR_TEST_INSECURE_DEVELOPMENT must be 0 or 1" >&2
    return 2
  fi
  if [[ -n "$postgres_ca_file" ]]; then
    common_environment+=(SHAR_POSTGRES_CA_FILE="$postgres_ca_file")
  fi
  if [[ -n "$redis_ca_file" ]]; then
    common_environment+=(SHAR_REDIS_CA_FILE="$redis_ca_file")
  fi
  env \
    "${common_environment[@]}" \
    SHAR_POSTGRES_URL="$postgres_url_rust" \
    SHAR_REDIS_URL="$redis_url_rust" \
    SHAR_LISTEN=127.0.0.1:4388 \
    target/release/shar-server >>"$test_directory/rust.log" 2>&1 &
  rust_pid=$!
  env \
    "${common_environment[@]}" \
    SHAR_POSTGRES_URL="$postgres_url_javascript" \
    SHAR_REDIS_URL="$redis_url_javascript" \
    SHAR_LISTEN=127.0.0.1:4389 \
    node standalone/js/server.mjs >>"$test_directory/javascript.log" 2>&1 &
  javascript_pid=$!
  wait_for_server http://127.0.0.1:4388 "$rust_pid" "$test_directory/rust.log"
  wait_for_server http://127.0.0.1:4389 "$javascript_pid" "$test_directory/javascript.log"
}

trap cleanup EXIT
cd "$workspace"
if [[ "$skip_build" == 0 ]]; then
  npm run build
  cargo build --locked --release --bin shar-server --bin shar-keygen
elif [[ "$skip_build" != 1 ]]; then
  echo "SHAR_TEST_SKIP_BUILD must be 0 or 1" >&2
  exit 2
fi
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

stop_servers
echo "PostgreSQL/Redis cross-process replay and restart interoperability passed"
