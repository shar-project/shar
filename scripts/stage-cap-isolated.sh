#!/usr/bin/env bash
set -euo pipefail

target=${SHAR_BENCH_SSH_TARGET:-}
remote_root=${SHAR_BENCH_REMOTE_ROOT:-}
stage_javascript=${SHAR_BENCH_STAGE_JAVASCRIPT:-0}

if [[ ! $target =~ ^[A-Za-z0-9_.@:-]+$ ]]; then
  echo "SHAR_BENCH_SSH_TARGET must be a plain SSH target" >&2
  exit 2
fi
if [[ ! $remote_root =~ ^/tmp/shar-cap-stage-[A-Za-z0-9._-]+$ ]]; then
  echo "SHAR_BENCH_REMOTE_ROOT must be a narrow /tmp/shar-cap-stage-* path" >&2
  exit 2
fi
if [[ $stage_javascript != 0 && $stage_javascript != 1 ]]; then
  echo "SHAR_BENCH_STAGE_JAVASCRIPT must be 0 or 1" >&2
  exit 2
fi
if [[ -n $(git status --porcelain) ]]; then
  echo "isolated benchmark staging requires a clean committed worktree" >&2
  exit 2
fi

required=(
  bench/cap/lib.mjs
  bench/cap/manifest.json
  bench/cap/standalone-host.mjs
  target/release/shar-server
  target/release/shar-keygen
  dist/admin/index.html
  .bench/cap/source/standalone/standalone/src/index.js
  .bench/cap/source/standalone/standalone/node_modules
)
for path in "${required[@]}"; do
  if [[ ! -e $path ]]; then
    echo "required benchmark input is missing: $path" >&2
    exit 2
  fi
done

bun_binary=$(command -v bun || true)
if [[ -z $bun_binary || ! -x $bun_binary ]]; then
  echo "a local Bun executable is required to stage pinned Cap" >&2
  exit 2
fi

if ! ssh -o BatchMode=yes "$target" test ! -e "$remote_root"; then
  echo "remote staging directory already exists; choose a fresh path" >&2
  exit 2
fi
ssh -o BatchMode=yes "$target" mkdir -m 700 "$remote_root"

inputs=(
  bench/cap/lib.mjs
  bench/cap/manifest.json
  bench/cap/standalone-host.mjs
  target/release/shar-server
  target/release/shar-keygen
  dist/admin
  .bench/cap/source/standalone/standalone
)
if [[ $stage_javascript == 1 ]]; then
  for path in dist standalone/js node_modules package.json; do
    if [[ ! -e $path ]]; then
      echo "JavaScript staging input is missing: $path" >&2
      exit 2
    fi
    inputs+=("$path")
  done
fi

rsync -aR --protect-args "${inputs[@]}" "$target:$remote_root/"
ssh -o BatchMode=yes "$target" mkdir -m 700 "$remote_root/.bench/bin"
rsync -a --protect-args "$bun_binary" "$target:$remote_root/.bench/bin/bun"

revision=$(git rev-parse HEAD)
echo "Staged revision $revision at $target:$remote_root"
echo "Use SHAR_BENCH_REMOTE_BUN=$remote_root/.bench/bin/bun"
