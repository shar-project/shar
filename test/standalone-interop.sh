#!/usr/bin/env bash
set -euo pipefail

workspace=$(cd "$(dirname "$0")/.." && pwd)
test_directory=$(mktemp -d /tmp/shar-standalone-interop.XXXXXX)
rust_pid=
javascript_pid=

cleanup() {
  if [[ -n "$javascript_pid" ]]; then kill "$javascript_pid" 2>/dev/null || true; fi
  if [[ -n "$rust_pid" ]]; then kill "$rust_pid" 2>/dev/null || true; fi
  if [[ -n "$javascript_pid" ]]; then wait "$javascript_pid" 2>/dev/null || true; fi
  if [[ -n "$rust_pid" ]]; then wait "$rust_pid" 2>/dev/null || true; fi
  rm -rf "$test_directory"
}

wait_for_server() {
  local endpoint=$1
  local pid=$2
  local log=$3
  for _ in $(seq 1 100); do
    if curl --fail --silent "$endpoint" >/dev/null 2>&1; then return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then
      cat "$log"
      return 1
    fi
    sleep 0.1
  done
  cat "$log"
  return 1
}

trap cleanup EXIT
cd "$workspace"
npm run build
cargo build --locked --release --bin shar-server --bin shar-keygen
target/release/shar-keygen --output "$test_directory/keys.json"
node test/corrupt-rsw-key.mjs \
  "$test_directory/keys.json" \
  "$test_directory/corrupt-keys.json"

assert_configuration_rejected() {
  local label=$1
  local variable=$2
  local value=$3
  local expected=$4
  local rust_status
  local javascript_status

  set +e
  timeout 10s env \
    SHAR_KEY_FILE="$test_directory/keys.json" \
    SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
    SHAR_DATABASE="$test_directory/$label-rust.sqlite" \
    SHAR_LISTEN=127.0.0.1:4290 \
    "$variable=$value" \
    target/release/shar-server >"$test_directory/$label-rust.log" 2>&1
  rust_status=$?
  timeout 10s env \
    SHAR_KEY_FILE="$test_directory/keys.json" \
    SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
    SHAR_DATABASE="$test_directory/$label-javascript.sqlite" \
    SHAR_LISTEN=127.0.0.1:4291 \
    "$variable=$value" \
    node standalone/js/server.mjs >"$test_directory/$label-javascript.log" 2>&1
  javascript_status=$?
  set -e

  if [[ "$rust_status" -ne 78 ]]; then
    cat "$test_directory/$label-rust.log"
    echo "Rust server did not reject invalid $variable with EX_CONFIG" >&2
    exit 1
  fi
  if [[ "$javascript_status" -ne 78 ]]; then
    cat "$test_directory/$label-javascript.log"
    echo "JavaScript server did not reject invalid $variable with EX_CONFIG" >&2
    exit 1
  fi
  grep -Fq "$expected" "$test_directory/$label-rust.log"
  grep -Fq "$expected" "$test_directory/$label-javascript.log"
}

assert_configuration_rejected \
  region-too-long \
  SHAR_REGION \
  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  "SHAR_REGION must be a non-control value of at most 64 bytes"
assert_configuration_rejected \
  retention-too-short \
  SHAR_TRUST_RETENTION_SECONDS \
  59 \
  "SHAR_TRUST_RETENTION_SECONDS must be an integer from 60 through 2592000"
assert_configuration_rejected \
  retention-not-integer \
  SHAR_TRUST_RETENTION_SECONDS \
  60.0 \
  "SHAR_TRUST_RETENTION_SECONDS must be an integer from 60 through 2592000"
assert_configuration_rejected \
  listen-zero-port \
  SHAR_LISTEN \
  localhost:0 \
  "SHAR_LISTEN port must be an integer from 1 through 65535"
assert_configuration_rejected \
  body-timeout-too-short \
  SHAR_REQUEST_BODY_TIMEOUT_MS \
  99 \
  "SHAR_REQUEST_BODY_TIMEOUT_MS must be an integer from 100 through 60000"
assert_configuration_rejected \
  shutdown-timeout-too-short \
  SHAR_SHUTDOWN_TIMEOUT_MS \
  5999 \
  "SHAR_SHUTDOWN_TIMEOUT_MS must be an integer from 6000 through 300000"
assert_configuration_rejected \
  missing-admin-assets \
  SHAR_ADMIN_ASSETS \
  "$test_directory/missing-admin-assets" \
  "cannot read SHAR_ADMIN_ASSETS"
assert_configuration_rejected \
  root-admin-assets \
  SHAR_ADMIN_ASSETS \
  / \
  "SHAR_ADMIN_ASSETS must not be a filesystem root"
assert_configuration_rejected \
  wildcard-origin \
  SHAR_ALLOWED_ORIGINS \
  '*' \
  "SHAR_ALLOWED_ORIGINS must contain unique, canonical HTTPS origins or local HTTP origins"
assert_configuration_rejected \
  origin-with-path \
  SHAR_ALLOWED_ORIGINS \
  https://app.example/path \
  "SHAR_ALLOWED_ORIGINS must contain unique, canonical HTTPS origins or local HTTP origins"

set +e
timeout 10s env \
  SHAR_KEY_FILE="$test_directory/corrupt-keys.json" \
  SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
  SHAR_DATABASE="$test_directory/corrupt-rust.sqlite" \
  SHAR_LISTEN=127.0.0.1:4290 \
  target/release/shar-server >"$test_directory/corrupt-rust.log" 2>&1
corrupt_rust_status=$?
timeout 10s env \
  SHAR_KEY_FILE="$test_directory/corrupt-keys.json" \
  SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
  SHAR_DATABASE="$test_directory/corrupt-javascript.sqlite" \
  SHAR_LISTEN=127.0.0.1:4291 \
  node standalone/js/server.mjs >"$test_directory/corrupt-javascript.log" 2>&1
corrupt_javascript_status=$?
set -e
if [[ "$corrupt_rust_status" -ne 78 ]]; then
  cat "$test_directory/corrupt-rust.log"
  echo "Rust server did not reject an inconsistent RSW trapdoor with EX_CONFIG" >&2
  exit 1
fi
if [[ "$corrupt_javascript_status" -ne 78 ]]; then
  cat "$test_directory/corrupt-javascript.log"
  echo "JavaScript server did not reject an inconsistent RSW trapdoor with EX_CONFIG" >&2
  exit 1
fi
grep -q "trapdoor is inconsistent with its modulus" "$test_directory/corrupt-rust.log"
grep -q "trapdoor is inconsistent with its modulus" "$test_directory/corrupt-javascript.log"

set +e
timeout 10s env \
  SHAR_KEY_FILE="$test_directory/keys.json" \
  SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
  SHAR_DATABASE="$test_directory/assurance-rust.sqlite" \
  SHAR_LISTEN=127.0.0.1:4290 \
  SHAR_ASSURANCE_MODE=trusted-header \
  target/release/shar-server >"$test_directory/assurance-rust.log" 2>&1
assurance_rust_status=$?
timeout 10s env \
  SHAR_KEY_FILE="$test_directory/keys.json" \
  SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
  SHAR_DATABASE="$test_directory/assurance-javascript.sqlite" \
  SHAR_LISTEN=127.0.0.1:4291 \
  SHAR_ASSURANCE_MODE=trusted-header \
  node standalone/js/server.mjs >"$test_directory/assurance-javascript.log" 2>&1
assurance_javascript_status=$?
set -e
if [[ "$assurance_rust_status" -ne 78 ]]; then
  cat "$test_directory/assurance-rust.log"
  echo "Rust server did not reject assurance without a proxy with EX_CONFIG" >&2
  exit 1
fi
if [[ "$assurance_javascript_status" -ne 78 ]]; then
  cat "$test_directory/assurance-javascript.log"
  echo "JavaScript server did not reject assurance without a proxy with EX_CONFIG" >&2
  exit 1
fi
grep -q "requires SHAR_TRUSTED_PROXY_CIDRS" "$test_directory/assurance-rust.log"
grep -q "requires SHAR_TRUSTED_PROXY_CIDRS" "$test_directory/assurance-javascript.log"

SHAR_KEY_FILE="$test_directory/keys.json" \
SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
SHAR_DATABASE="$test_directory/shutdown-rust.sqlite" \
SHAR_LISTEN=127.0.0.1:4292 \
SHAR_ADMIN_ASSETS="$workspace/dist/admin" \
SHAR_REQUEST_BODY_TIMEOUT_MS=60000 \
SHAR_SHUTDOWN_TIMEOUT_MS=6000 \
target/release/shar-server >"$test_directory/shutdown-rust.log" 2>&1 &
rust_pid=$!
wait_for_server http://127.0.0.1:4292/healthz "$rust_pid" "$test_directory/shutdown-rust.log"

SHAR_KEY_FILE="$test_directory/keys.json" \
SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
SHAR_DATABASE="$test_directory/shutdown-javascript.sqlite" \
SHAR_LISTEN=127.0.0.1:4293 \
SHAR_ADMIN_ASSETS="$workspace/dist/admin" \
SHAR_REQUEST_BODY_TIMEOUT_MS=60000 \
SHAR_SHUTDOWN_TIMEOUT_MS=6000 \
node standalone/js/server.mjs >"$test_directory/shutdown-javascript.log" 2>&1 &
javascript_pid=$!
wait_for_server http://127.0.0.1:4293/healthz "$javascript_pid" "$test_directory/shutdown-javascript.log"

node test/shutdown-deadline-check.mjs "$rust_pid" 4292 "$javascript_pid" 4293
set +e
wait "$rust_pid"
shutdown_rust_status=$?
wait "$javascript_pid"
shutdown_javascript_status=$?
set -e
rust_pid=
javascript_pid=
if [[ "$shutdown_rust_status" -ne 1 ]]; then
  cat "$test_directory/shutdown-rust.log"
  echo "Rust forced shutdown did not exit nonzero" >&2
  exit 1
fi
if [[ "$shutdown_javascript_status" -ne 1 ]]; then
  cat "$test_directory/shutdown-javascript.log"
  echo "JavaScript forced shutdown did not exit nonzero" >&2
  exit 1
fi
grep -Fq "graceful request drain exceeded its bounded deadline" "$test_directory/shutdown-rust.log"
grep -Fq "graceful request drain exceeded its bounded deadline" "$test_directory/shutdown-javascript.log"

SHAR_KEY_FILE="$test_directory/keys.json" \
SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
SHAR_DATABASE="$test_directory/state.sqlite" \
SHAR_LISTEN=127.0.0.1:4288 \
SHAR_ADMIN_ASSETS="$workspace/dist/admin" \
SHAR_REQUEST_LOG=1 \
SHAR_MAX_CONCURRENT_REQUESTS=1 \
SHAR_STATE_TIMEOUT_MS=1000 \
SHAR_REQUEST_BODY_TIMEOUT_MS=1000 \
SHAR_TRUSTED_PROXY_CIDRS=127.0.0.1/32 \
SHAR_ASSURANCE_MODE=trusted-header \
target/release/shar-server >"$test_directory/rust.log" 2>&1 &
rust_pid=$!
wait_for_server http://127.0.0.1:4288/healthz "$rust_pid" "$test_directory/rust.log"

SHAR_KEY_FILE="$test_directory/keys.json" \
SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
SHAR_DATABASE="$test_directory/state.sqlite" \
SHAR_LISTEN=127.0.0.1:4289 \
SHAR_ADMIN_ASSETS="$workspace/dist/admin" \
SHAR_REQUEST_LOG=1 \
SHAR_MAX_CONCURRENT_REQUESTS=1 \
SHAR_STATE_TIMEOUT_MS=1000 \
SHAR_REQUEST_BODY_TIMEOUT_MS=1000 \
SHAR_TRUSTED_PROXY_CIDRS=127.0.0.1/32 \
SHAR_ASSURANCE_MODE=trusted-header \
node standalone/js/server.mjs >"$test_directory/javascript.log" 2>&1 &
javascript_pid=$!
wait_for_server http://127.0.0.1:4289/healthz "$javascript_pid" "$test_directory/javascript.log"
SHAR_LISTEN=0.0.0.0:4288 target/release/shar-server --healthcheck
SHAR_LISTEN=0.0.0.0:4289 node standalone/js/healthcheck.mjs
node test/slow-body-check.mjs 4288 4289

set +e
timeout 10s env \
  SHAR_KEY_FILE="$test_directory/keys.json" \
  SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
  SHAR_DATABASE="$test_directory/occupied-rust.sqlite" \
  SHAR_LISTEN=127.0.0.1:4288 \
  target/release/shar-server >"$test_directory/occupied-rust.log" 2>&1
occupied_rust_status=$?
timeout 10s env \
  SHAR_KEY_FILE="$test_directory/keys.json" \
  SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
  SHAR_DATABASE="$test_directory/occupied-javascript.sqlite" \
  SHAR_LISTEN=127.0.0.1:4289 \
  node standalone/js/server.mjs >"$test_directory/occupied-javascript.log" 2>&1
occupied_javascript_status=$?
set -e
if [[ "$occupied_rust_status" -ne 78 || "$occupied_javascript_status" -ne 78 ]]; then
  cat "$test_directory/occupied-rust.log"
  cat "$test_directory/occupied-javascript.log"
  echo "standalones must reject an occupied listener with EX_CONFIG" >&2
  exit 1
fi
grep -Fq "cannot bind SHAR_LISTEN 127.0.0.1:4288" "$test_directory/occupied-rust.log"
grep -Fq "cannot bind SHAR_LISTEN 127.0.0.1:4289" "$test_directory/occupied-javascript.log"

SHAR_ENDPOINT_A=http://127.0.0.1:4288 \
SHAR_ENDPOINT_B=http://127.0.0.1:4289 \
SHAR_KEY_FILE="$test_directory/keys.json" \
node test/interop.mjs

node test/request-log-check.mjs \
  "$test_directory/rust.log" \
  "$test_directory/javascript.log"

SHAR_ROTATION_ENDPOINT=http://127.0.0.1:4288 \
SHAR_ROTATION_CHALLENGE="$test_directory/rotation.json" \
node test/rotation-interop.mjs prepare

kill "$javascript_pid" 2>/dev/null || true
kill "$rust_pid" 2>/dev/null || true
wait "$javascript_pid" 2>/dev/null || true
wait "$rust_pid" 2>/dev/null || true
javascript_pid=
rust_pid=

npm run keygen:js -- rotate --input "$test_directory/keys.json" --output "$test_directory/rotated-keys.json"
SHAR_KEY_FILE="$test_directory/rotated-keys.json" \
SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
SHAR_DATABASE="$test_directory/state.sqlite" \
SHAR_LISTEN=127.0.0.1:4288 \
SHAR_ADMIN_ASSETS="$workspace/dist/admin" \
target/release/shar-server >"$test_directory/rotated-rust.log" 2>&1 &
rust_pid=$!
wait_for_server http://127.0.0.1:4288/healthz "$rust_pid" "$test_directory/rotated-rust.log"

SHAR_ROTATION_ENDPOINT=http://127.0.0.1:4288 \
SHAR_ROTATION_CHALLENGE="$test_directory/rotation.json" \
SHAR_KEY_FILE="$test_directory/rotated-keys.json" \
node test/rotation-interop.mjs complete

SHAR_ROTATION_ENDPOINT=http://127.0.0.1:4288 \
SHAR_ROTATION_CHALLENGE="$test_directory/rotation-rust.json" \
node test/rotation-interop.mjs prepare
kill "$rust_pid" 2>/dev/null || true
wait "$rust_pid" 2>/dev/null || true
rust_pid=

target/release/shar-keygen rotate \
  --input "$test_directory/rotated-keys.json" \
  --output "$test_directory/rust-rotated-keys.json"
SHAR_KEY_FILE="$test_directory/rust-rotated-keys.json" \
SHAR_ALLOWED_ORIGINS=http://localhost:3000 \
SHAR_DATABASE="$test_directory/state.sqlite" \
SHAR_LISTEN=127.0.0.1:4288 \
SHAR_ADMIN_ASSETS="$workspace/dist/admin" \
target/release/shar-server >"$test_directory/rust-rotated.log" 2>&1 &
rust_pid=$!
wait_for_server http://127.0.0.1:4288/healthz "$rust_pid" "$test_directory/rust-rotated.log"

SHAR_ROTATION_ENDPOINT=http://127.0.0.1:4288 \
SHAR_ROTATION_CHALLENGE="$test_directory/rotation-rust.json" \
SHAR_KEY_FILE="$test_directory/rust-rotated-keys.json" \
node test/rotation-interop.mjs complete
