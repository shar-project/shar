#!/usr/bin/env bash
set -euo pipefail

project="${1:-webkit}"
case "$project" in
  chromium|firefox|webkit) ;;
  *)
    echo "usage: $0 [chromium|firefox|webkit]" >&2
    exit 2
    ;;
esac

runtime="${SHAR_CONTAINER_RUNTIME:-}"
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

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="mcr.microsoft.com/playwright:v1.62.1-noble@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e"

exec "$runtime" run --rm --ipc=host --network=host \
  --volume "$repo_root:/work" \
  --workdir /work \
  "$image" \
  npx playwright test "--project=$project"
