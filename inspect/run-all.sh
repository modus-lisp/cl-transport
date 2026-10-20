#!/bin/sh
# run-all.sh — every inspect suite, each in its own SBCL, with nothing beyond SBCL.
#
#   inspect/run-all.sh
#
# Exits non-zero if any suite does.  The ICE suites are not here: cl-transport/ice
# needs bordeaux-threads and ironclad, and has its own requirements.
cd "$(dirname "$0")/.." || exit 2
out=$(mktemp) || exit 2
trap 'rm -f "$out"' EXIT
rc=0
for f in sockets tcp transport-gate gate-hooks gate-threads http-connect socks-client; do
  printf '\n== inspect/%s.lisp\n' "$f"
  if sbcl --script "inspect/$f.lisp" >"$out" 2>&1; then status=0; else status=$?; fi
  grep -v '^;' "$out" | tail -3
  [ "$status" = 0 ] || { echo "   FAILED (exit $status): inspect/$f.lisp"; rc=1; }
done
echo
[ $rc = 0 ] && echo "cl-transport: every suite passed" || echo "cl-transport: FAILURES"
exit $rc
