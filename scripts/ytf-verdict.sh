#!/usr/bin/env bash
# scripts/ytf-verdict.sh — derive a YTF tier/suite verdict from RAW evidence,
# never from runner prose (YSG-RISK-206 class fix).
#
# A tier used to be "GREEN" if its pytest exited 0. pytest exits 0 when every
# collected test SKIPS (e.g. Tier-C against an unreachable stack, YSG-RISK-207)
# — so a run that executed ZERO tests printed "PASS / All requested tiers
# GREEN". This script is the only place a YTF verdict may be produced:
#
#   PASS  iff  runner-rc == 0
#          AND the junit XML exists and parses
#          AND executed (= tests - skipped) >= --min-executed (default 1)
#          AND failures == 0 AND errors == 0
#
# It emits ONE machine-readable line (stdout + optional --out file):
#
#   YTF-VERDICT: tier=<t> suite=<s> leg=<l> mode=<m> rc=<n> collected=<n> \
#     executed=<n> passed=<n> failed=<n> errors=<n> skipped=<n> \
#     min_executed=<n> verdict=<PASS|FAIL> reason=<->|<slug>
#
# and exits 0 iff verdict=PASS. Downstream gates (release-gate-check.sh)
# grep-assert these lines from the evidence file — they never trust the
# runner's summary text.
#
# Usage:
#   ytf-verdict.sh --junit FILE --rc N --tier a|b|c --suite NAME
#                  [--leg LEG] [--mode MODE] [--min-executed N] [--out FILE]
set -euo pipefail

JUNIT="" RC="" TIER="" SUITE="" LEG="-" MODE="-" MIN_EXECUTED=1 OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --junit) JUNIT="$2"; shift 2 ;;
    --rc) RC="$2"; shift 2 ;;
    --tier) TIER="$2"; shift 2 ;;
    --suite) SUITE="$2"; shift 2 ;;
    --leg) LEG="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --min-executed) MIN_EXECUTED="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "ytf-verdict.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$JUNIT" ] && [ -n "$RC" ] && [ -n "$TIER" ] && [ -n "$SUITE" ] || {
  echo "ytf-verdict.sh: --junit, --rc, --tier, --suite are required" >&2; exit 2;
}

PYBIN="${YTF_PYTHON:-python3}"
command -v "$PYBIN" >/dev/null 2>&1 || PYBIN=python3

# Counts come from the junit XML ONLY (raw artifact written by pytest itself),
# aggregated across <testsuite> elements. Missing/unparseable file => FAIL.
_counts=""
if [ -f "$JUNIT" ]; then
  _counts="$("$PYBIN" - "$JUNIT" <<'PYEOF' 2>/dev/null || true
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
t = f = e = s = 0
for su in suites:
    t += int(su.get("tests", 0))
    f += int(su.get("failures", 0))
    e += int(su.get("errors", 0))
    s += int(su.get("skipped", 0))
print(f"{t} {f} {e} {s}")
PYEOF
)"
fi

REASON="-"
if [ -z "$_counts" ]; then
  COLLECTED=0; FAILED=0; ERRORS=0; SKIPPED=0; EXECUTED=0; PASSED=0
  VERDICT="FAIL"; REASON="junit-missing-or-unparseable"
else
  read -r COLLECTED FAILED ERRORS SKIPPED <<EOF
$_counts
EOF
  EXECUTED=$((COLLECTED - SKIPPED))
  PASSED=$((EXECUTED - FAILED - ERRORS))
  VERDICT="PASS"
  if [ "$RC" -ne 0 ]; then
    VERDICT="FAIL"; REASON="runner-rc-${RC}"
  elif [ "$EXECUTED" -lt "$MIN_EXECUTED" ]; then
    # The YSG-RISK-206 line: exit 0 with nothing executed is a FAIL, loudly.
    VERDICT="FAIL"; REASON="zero-or-below-min-executed"
  elif [ "$FAILED" -ne 0 ] || [ "$ERRORS" -ne 0 ]; then
    VERDICT="FAIL"; REASON="failures-or-errors-in-junit"
  fi
fi

LINE="YTF-VERDICT: tier=${TIER} suite=${SUITE} leg=${LEG} mode=${MODE} rc=${RC} collected=${COLLECTED} executed=${EXECUTED} passed=${PASSED} failed=${FAILED} errors=${ERRORS} skipped=${SKIPPED} min_executed=${MIN_EXECUTED} verdict=${VERDICT} reason=${REASON}"
echo "$LINE"
if [ -n "$OUT" ]; then
  mkdir -p "$(dirname "$OUT")"
  echo "$LINE" >> "$OUT"
fi
[ "$VERDICT" = "PASS" ]
