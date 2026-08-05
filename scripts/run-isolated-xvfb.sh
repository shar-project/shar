#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  echo "usage: $0 command [argument ...]" >&2
  exit 2
fi

display_number=99
display=":$display_number"
socket="/tmp/.X11-unix/X$display_number"
xvfb_log="$(mktemp /tmp/shar-xvfb.XXXXXX.log)"
Xvfb "$display" -screen 0 1280x1024x24 -nolisten tcp -ac 2>"$xvfb_log" &
xvfb_pid=$!
cleanup() {
  kill "$xvfb_pid" 2>/dev/null || true
  wait "$xvfb_pid" 2>/dev/null || true
  rm -f "$xvfb_log"
}
trap cleanup EXIT INT TERM

for _ in {1..200}; do
  if [[ -S "$socket" ]]; then
    DISPLAY="$display" "$@"
    exit $?
  fi
  if ! kill -0 "$xvfb_pid" 2>/dev/null; then
    echo "Xvfb exited before creating $socket" >&2
    sed -n '1,120p' "$xvfb_log" >&2
    exit 1
  fi
  sleep 0.05
done

echo "Xvfb did not create $socket within 10 seconds" >&2
sed -n '1,120p' "$xvfb_log" >&2
exit 1
