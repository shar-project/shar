#!/usr/bin/env bash
set -euo pipefail

workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runtime=${SHAR_CONTAINER_RUNTIME:-}
if [[ -z "$runtime" ]]; then
  if command -v podman >/dev/null 2>&1; then
    runtime=podman
  elif command -v docker >/dev/null 2>&1; then
    runtime=docker
  else
    echo "Podman or Docker is required" >&2
    exit 1
  fi
fi
case "$runtime" in
  podman|docker) ;;
  *)
    echo "SHAR_CONTAINER_RUNTIME must be podman or docker" >&2
    exit 2
    ;;
esac

postgres_image=${SHAR_TEST_POSTGRES_IMAGE:-postgres@sha256:7a396fd264a2067788b6551122b50f162bf6136312c7fc9d74381cb92c648382}
redis_image=${SHAR_TEST_REDIS_IMAGE:-redis@sha256:9702d01c1f10c3ea9f48211b4362e44f154ff02d063e6f7268eba804059f53bf}
test_directory=$(mktemp -d /tmp/shar-store-tls.XXXXXX)
postgres_container=
redis_container=

cleanup() {
  if [[ -n "$redis_container" ]]; then
    "$runtime" rm -f "$redis_container" >/dev/null 2>&1 || true
  fi
  if [[ -n "$postgres_container" ]]; then
    "$runtime" rm -f "$postgres_container" >/dev/null 2>&1 || true
  fi
  if [[ "$test_directory" == /tmp/shar-store-tls.* ]]; then
    rm -rf -- "$test_directory"
  fi
}
trap cleanup EXIT

wait_for_container_command() {
  local container=$1
  shift
  for _ in $(seq 1 100); do
    if "$runtime" exec "$container" "$@" >/dev/null 2>&1; then return 0; fi
    if ! "$runtime" inspect "$container" >/dev/null 2>&1; then
      echo "container $container exited before becoming ready" >&2
      return 1
    fi
    sleep 0.1
  done
  "$runtime" logs "$container" >&2
  return 1
}

mapped_port() {
  local container=$1
  local container_port=$2
  local mapping
  mapping=$("$runtime" port "$container" "$container_port/tcp" | head -n 1)
  echo "${mapping##*:}"
}

expect_not_ready() {
  local label=$1
  local port=$2
  local expected_log=$3
  shift 3
  local log="$test_directory/$label.log"
  env "$@" >"$log" 2>&1 &
  local pid=$!
  local became_ready=0
  for _ in $(seq 1 30); do
    if curl --fail --silent "http://127.0.0.1:$port/readyz" >/dev/null 2>&1; then
      became_ready=1
      break
    fi
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
  if [[ "$became_ready" == 1 ]]; then
    echo "$label unexpectedly became ready" >&2
    cat "$log" >&2
    return 1
  fi
  if ! grep -F "$expected_log" "$log" >/dev/null; then
    echo "$label did not report the expected TLS refusal: $expected_log" >&2
    cat "$log" >&2
    return 1
  fi
}

cd "$workspace"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$test_directory/ca.key" \
  -out "$test_directory/ca.crt" \
  -subj /CN=Shar-store-test-CA \
  -days 1 >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$test_directory/server.key" \
  -out "$test_directory/server.csr" \
  -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost >/dev/null 2>&1
openssl x509 -req \
  -in "$test_directory/server.csr" \
  -CA "$test_directory/ca.crt" \
  -CAkey "$test_directory/ca.key" \
  -CAcreateserial \
  -copy_extensions copyall \
  -out "$test_directory/server.crt" \
  -days 1 >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$test_directory/wrong-ca.key" \
  -out "$test_directory/wrong-ca.crt" \
  -subj /CN=Shar-wrong-test-CA \
  -days 1 >/dev/null 2>&1
chmod 700 "$test_directory"
chmod 600 "$test_directory/ca.key" "$test_directory/server.key" "$test_directory/wrong-ca.key"

postgres_container=$("$runtime" run --detach \
  --publish 127.0.0.1::5432 \
  --env POSTGRES_DB=shar \
  --env POSTGRES_USER=shar \
  --env POSTGRES_PASSWORD=shar-test-only \
  --volume "$test_directory:/certs:ro" \
  --entrypoint sh \
  "$postgres_image" \
  -c 'cp /certs/server.crt /tmp/shar-server.crt && cp /certs/server.key /tmp/shar-server.key && chown postgres:postgres /tmp/shar-server.crt /tmp/shar-server.key && chmod 600 /tmp/shar-server.key && exec docker-entrypoint.sh postgres "$@"' \
  sh \
  -c ssl=on \
  -c ssl_min_protocol_version=TLSv1.2 \
  -c ssl_cert_file=/tmp/shar-server.crt \
  -c ssl_key_file=/tmp/shar-server.key)
redis_container=$("$runtime" run --detach \
  --publish 127.0.0.1::6379 \
  --volume "$test_directory:/certs:ro" \
  --entrypoint sh \
  "$redis_image" \
  -c 'cp /certs/ca.crt /tmp/shar-ca.crt && cp /certs/server.crt /tmp/shar-server.crt && cp /certs/server.key /tmp/shar-server.key && chown redis:redis /tmp/shar-ca.crt /tmp/shar-server.crt /tmp/shar-server.key && chmod 600 /tmp/shar-server.key && exec docker-entrypoint.sh "$@"' \
  sh \
  redis-server \
  --port 0 \
  --tls-port 6379 \
  --tls-protocols 'TLSv1.2 TLSv1.3' \
  --tls-cert-file /tmp/shar-server.crt \
  --tls-key-file /tmp/shar-server.key \
  --tls-ca-cert-file /tmp/shar-ca.crt \
  --tls-auth-clients no)

wait_for_container_command "$postgres_container" pg_isready -U shar -d shar
wait_for_container_command "$redis_container" redis-cli --tls --cacert /tmp/shar-ca.crt -h localhost ping
postgres_port=$(mapped_port "$postgres_container" 5432)
redis_port=$(mapped_port "$redis_container" 6379)
postgres_url="postgresql://shar:shar-test-only@localhost:$postgres_port/shar?sslmode=require"
redis_url="rediss://localhost:$redis_port"

npm run build
cargo build --locked --release --bin shar-server --bin shar-keygen

SHAR_TEST_POSTGRES_URL="$postgres_url" \
SHAR_TEST_POSTGRES_CA_FILE="$test_directory/ca.crt" \
SHAR_TEST_REDIS_URL="$redis_url" \
SHAR_TEST_REDIS_CA_FILE="$test_directory/ca.crt" \
node test/live-stores.mjs

SHAR_TEST_POSTGRES_URL="$postgres_url" \
SHAR_TEST_POSTGRES_CA_FILE="$test_directory/ca.crt" \
SHAR_TEST_REDIS_URL="$redis_url" \
SHAR_TEST_REDIS_CA_FILE="$test_directory/ca.crt" \
SHAR_TEST_INSECURE_DEVELOPMENT=0 \
SHAR_TEST_SKIP_BUILD=1 \
npm run test:standalone-external-interop

target/release/shar-keygen --output "$test_directory/negative-keys.json"
common=(
  SHAR_KEY_FILE="$test_directory/negative-keys.json"
  SHAR_ALLOWED_ORIGINS=http://localhost:3000
  SHAR_REQUEST_LOG=0
  SHAR_STATE_TIMEOUT_MS=500
)

expect_not_ready rust-postgres-untrusted 4488 "cannot connect to PostgreSQL" \
  "${common[@]}" \
  SHAR_LISTEN=127.0.0.1:4488 \
  SHAR_POSTGRES_URL="$postgres_url" \
  SHAR_POSTGRES_CA_FILE="$test_directory/wrong-ca.crt" \
  target/release/shar-server
expect_not_ready javascript-postgres-hostname 4489 "certificate" \
  "${common[@]}" \
  SHAR_LISTEN=127.0.0.1:4489 \
  SHAR_POSTGRES_URL="postgresql://shar:shar-test-only@127.0.0.1:$postgres_port/shar?sslmode=require" \
  SHAR_POSTGRES_CA_FILE="$test_directory/ca.crt" \
  node standalone/js/server.mjs
expect_not_ready rust-redis-hostname 4488 "cannot initialize Redis state" \
  "${common[@]}" \
  SHAR_LISTEN=127.0.0.1:4488 \
  SHAR_DATABASE="$test_directory/rust-negative.sqlite" \
  SHAR_REDIS_URL="rediss://127.0.0.1:$redis_port" \
  SHAR_REDIS_CA_FILE="$test_directory/ca.crt" \
  target/release/shar-server
expect_not_ready javascript-redis-untrusted 4489 "certificate" \
  "${common[@]}" \
  SHAR_LISTEN=127.0.0.1:4489 \
  SHAR_DATABASE="$test_directory/javascript-negative.sqlite" \
  SHAR_REDIS_URL="$redis_url" \
  SHAR_REDIS_CA_FILE="$test_directory/wrong-ca.crt" \
  node standalone/js/server.mjs
expect_not_ready rust-redis-plaintext 4488 "SHAR_REDIS_URL must use rediss" \
  "${common[@]}" \
  SHAR_LISTEN=127.0.0.1:4488 \
  SHAR_DATABASE="$test_directory/rust-plaintext.sqlite" \
  SHAR_REDIS_URL="redis://localhost:$redis_port" \
  target/release/shar-server
expect_not_ready javascript-postgres-plaintext 4489 "sslmode=disable only in insecure development" \
  "${common[@]}" \
  SHAR_LISTEN=127.0.0.1:4489 \
  SHAR_POSTGRES_URL="postgresql://shar:shar-test-only@localhost:$postgres_port/shar?sslmode=disable" \
  node standalone/js/server.mjs

echo "Verified TLS, private CA, hostname, trust, and plaintext refusal behavior across both standalones"
