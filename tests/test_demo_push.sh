#!/usr/bin/env sh
set -eu

cleanup() {
  if [ -n "${dummy_listener_pid:-}" ]; then
    kill "$dummy_listener_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

python3 - <<'PY' &
import socket
import time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 8089))
s.listen(1)
while True:
    time.sleep(1)
PY

dummy_listener_pid=$!
sleep 1

output="$(./scan --demo-push 2>&1)"
if printf '%s' "$output" | grep -q 'demo push delivered'; then
  echo 'demo push test passed'
else
  echo 'demo push test failed' >&2
  echo "$output" >&2
  exit 1
fi
