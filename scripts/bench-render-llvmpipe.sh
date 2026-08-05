#!/usr/bin/env bash
set -euo pipefail

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
  --env LIBGL_ALWAYS_SOFTWARE=true \
  --env GALLIUM_DRIVER=llvmpipe \
  --env SHAR_BENCH_GPU_MODE=llvmpipe \
  --env SHAR_BENCH_HEADED=1 \
  --env SHAR_BENCH_CONTAINER_IMAGE="$image" \
  --env SHAR_BENCH_OUTPUT=bench/render/results/local-llvmpipe-calibration.json \
  "$image" \
  bash scripts/run-isolated-xvfb.sh node bench/render/browser-calibration.mjs
