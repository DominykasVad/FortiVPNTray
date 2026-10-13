#!/bin/bash
# Runs the three clients against the installed daemon and prints a verdict. No root.
#   spikes/xpc-codesign/run.sh [signed|uid-only]      (default: signed)
# "signed" expects A accepted, B and C rejected. "uid-only" expects all three accepted.
source "$(dirname "$0")/common.sh"
expect_mode="${1:-signed}"
failures=0

try() {
  local name="$1" expected="$2" output status verdict
  set +e
  output="$("$dist_dir/$name" "$label" 2>&1)"
  status=$?
  set -e
  if { [[ "$expected" == accept && $status -eq 0 ]] || [[ "$expected" == reject && $status -eq 1 ]]; }; then
    verdict=ok
  else
    verdict=UNEXPECTED
    failures=$((failures + 1))
  fi
  printf '%-10s expected=%-6s exit=%s %-10s cdhash=%s\n           %s\n' "$name" "$expected" "$status" "$verdict" "$(cdhash "$dist_dir/$name")" "$output"
}

others=reject
[[ "$expect_mode" == uid-only ]] && others=accept
echo "== First build"
try client-a accept
try client-b "$others"
try client-c "$others"

echo "== Rebuild client A with the same identity (different binary, different cdhash)"
before="$(cdhash "$dist_dir/client-a")"
SPIKE_BUILD_NOTE="rebuilt $(date +%s)" "$spike_dir/build.sh" >/dev/null
after="$(cdhash "$dist_dir/client-a")"
if [[ "$before" == "$after" ]]; then
  echo "cdhash did not change ($before): the rebuild proves nothing"
  failures=$((failures + 1))
fi
try client-a accept
try client-b "$others"
try client-c "$others"

echo "== Daemon log ($log_path)"
cat "$log_path" 2>/dev/null || echo "(not readable)"
if [[ $failures -eq 0 ]]; then
  echo "RESULT: PASS ($expect_mode)"
else
  echo "RESULT: FAIL ($failures unexpected outcome(s))"
  exit 1
fi
