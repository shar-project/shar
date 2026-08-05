#!/usr/bin/env bash
set -euo pipefail

version=8.30.1
case "$(uname -m)" in
  x86_64)
    archive_name="gitleaks_${version}_linux_x64.tar.gz"
    archive_sha256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
    ;;
  aarch64|arm64)
    archive_name="gitleaks_${version}_linux_arm64.tar.gz"
    archive_sha256=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
    ;;
  *)
    echo "unsupported Gitleaks host architecture: $(uname -m)" >&2
    exit 2
    ;;
esac

temporary_directory=$(mktemp -d /tmp/shar-gitleaks.XXXXXX)
cleanup() {
  if [[ "$temporary_directory" == /tmp/shar-gitleaks.* ]]; then
    rm -rf -- "$temporary_directory"
  fi
}
trap cleanup EXIT

archive="$temporary_directory/$archive_name"
curl --fail --show-error --silent --location \
  --proto '=https' \
  --tlsv1.2 \
  "https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive_name}" \
  --output "$archive"
echo "$archive_sha256  $archive" | sha256sum --check --strict
tar --extract --gzip --file "$archive" --directory "$temporary_directory" gitleaks

mkdir "$temporary_directory/self-test"
printf -v self_test_key '%s_%s' api key
printf '%s = %s%s\n' "$self_test_key" 'q7Zp9Vm2Kx8Rc4Nt' '6Wy3Hs5Jd1Lf0BgU' \
  >"$temporary_directory/self-test/credential.txt"
set +e
"$temporary_directory/gitleaks" dir \
  --config .gitleaks.toml \
  --no-banner \
  --no-color \
  --redact=100 \
  "$temporary_directory/self-test" >/dev/null 2>&1
self_test_status=$?
set -e
if [[ "$self_test_status" != 1 ]]; then
  echo "Gitleaks fail-closed self-test returned $self_test_status instead of detecting its synthetic credential" >&2
  exit 1
fi

"$temporary_directory/gitleaks" git \
  --config .gitleaks.toml \
  --gitleaks-ignore-path .gitleaksignore \
  --log-opts=--all \
  --no-banner \
  --no-color \
  --redact=100 \
  --timeout 120 \
  --verbose \
  .
