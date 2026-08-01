#!/usr/bin/env sh
set -eu

output="$(./scan --info | head -n 1)"
if [ "$output" = "Scan: common C base initialized" ]; then
  echo "smoke test passed"
else
  echo "smoke test failed: $output" >&2
  exit 1
fi
