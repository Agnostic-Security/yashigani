#!/usr/bin/env bats
# Behavioral tests for scripts/ytf-verdict.sh — the YSG-RISK-206 class fix.
#
# The defect being locked down: the YTF runner derived tier verdicts from
# pytest's exit code alone. pytest exits 0 when every collected test SKIPS
# (Tier-C against an unreachable stack — YSG-RISK-207), so a run that
# executed ZERO tests printed "PASS / All requested tiers GREEN".
# ytf-verdict.sh derives the verdict from the junit XML (raw artifact),
# and these tests feed it synthetic XMLs covering every arm.

setup() {
  REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  V="${REPO_ROOT}/scripts/ytf-verdict.sh"
  T="${BATS_TEST_TMPDIR}"
}

_junit() {
  # _junit tests failures errors skipped > file
  cat > "$T/junit.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" tests="$1" failures="$2" errors="$3" skipped="$4" time="1.0"/></testsuites>
EOF
}

@test "RISK-206: rc=0 with ALL tests skipped (zero executed) is FAIL" {
  _junit 34 0 0 34
  run "$V" --junit "$T/junit.xml" --rc 0 --tier c --suite e2e-integration --leg docker-linux
  [ "$status" -ne 0 ]
  [[ "$output" == *"executed=0"* ]]
  [[ "$output" == *"verdict=FAIL"* ]]
  [[ "$output" == *"reason=zero-or-below-min-executed"* ]]
}

@test "RISK-206: rc=0 with an EMPTY junit (tests=0) is FAIL" {
  _junit 0 0 0 0
  run "$V" --junit "$T/junit.xml" --rc 0 --tier c --suite e2e-integration
  [ "$status" -ne 0 ]
  [[ "$output" == *"verdict=FAIL"* ]]
}

@test "missing junit file is FAIL even with rc=0" {
  run "$V" --junit "$T/does-not-exist.xml" --rc 0 --tier a --suite conformance-security
  [ "$status" -ne 0 ]
  [[ "$output" == *"reason=junit-missing-or-unparseable"* ]]
}

@test "unparseable junit is FAIL even with rc=0" {
  echo "this is not xml <<<" > "$T/junit.xml"
  run "$V" --junit "$T/junit.xml" --rc 0 --tier a --suite conformance-security
  [ "$status" -ne 0 ]
  [[ "$output" == *"reason=junit-missing-or-unparseable"* ]]
}

@test "nonzero runner rc is FAIL even when junit shows passes" {
  _junit 100 0 0 0
  run "$V" --junit "$T/junit.xml" --rc 1 --tier b --suite playwright --leg podman-macos --mode headless
  [ "$status" -ne 0 ]
  [[ "$output" == *"reason=runner-rc-1"* ]]
}

@test "failures in junit are FAIL even with rc=0 (defense in depth)" {
  _junit 50 3 0 2
  run "$V" --junit "$T/junit.xml" --rc 0 --tier b --suite playwright
  [ "$status" -ne 0 ]
  [[ "$output" == *"failed=3"* ]]
  [[ "$output" == *"reason=failures-or-errors-in-junit"* ]]
}

@test "errors in junit are FAIL even with rc=0" {
  _junit 50 0 2 0
  run "$V" --junit "$T/junit.xml" --rc 0 --tier c --suite e2e-integration
  [ "$status" -ne 0 ]
  [[ "$output" == *"errors=2"* ]]
}

@test "genuine pass: rc=0, N executed, 0 failed → PASS with correct counts" {
  _junit 120 0 0 7
  run "$V" --junit "$T/junit.xml" --rc 0 --tier a --suite conformance-security
  [ "$status" -eq 0 ]
  [[ "$output" == *"collected=120"* ]]
  [[ "$output" == *"executed=113"* ]]
  [[ "$output" == *"passed=113"* ]]
  [[ "$output" == *"verdict=PASS"* ]]
}

@test "multiple <testsuite> elements are aggregated" {
  cat > "$T/junit.xml" <<'EOF'
<?xml version="1.0"?>
<testsuites>
  <testsuite name="s1" tests="10" failures="0" errors="0" skipped="2"/>
  <testsuite name="s2" tests="5" failures="0" errors="0" skipped="5"/>
</testsuites>
EOF
  run "$V" --junit "$T/junit.xml" --rc 0 --tier a --suite agg
  [ "$status" -eq 0 ]
  [[ "$output" == *"collected=15"* ]]
  [[ "$output" == *"executed=8"* ]]
}

@test "--min-executed floor is enforced" {
  _junit 10 0 0 8
  run "$V" --junit "$T/junit.xml" --rc 0 --tier b --suite playwright --min-executed 5
  [ "$status" -ne 0 ]
  [[ "$output" == *"reason=zero-or-below-min-executed"* ]]
}

@test "--out appends the identical verdict line to the evidence file" {
  _junit 20 0 0 0
  run "$V" --junit "$T/junit.xml" --rc 0 --tier c --suite e2e-integration --out "$T/VERDICT.txt"
  [ "$status" -eq 0 ]
  grep -q "YTF-VERDICT: tier=c suite=e2e-integration .* executed=20 .* verdict=PASS" "$T/VERDICT.txt"
}

# --- runner wiring (every junit-producing pytest call must be gated) --------

@test "runner: every --junitxml pytest call site is followed by a ytf-verdict.sh gate" {
  local runner="${REPO_ROOT}/scripts/run-test-framework.sh"
  local junit_sites verdict_calls
  junit_sites="$(grep -c -- '--junitxml=' "$runner")"
  verdict_calls="$(grep -c 'ytf-verdict\.sh" --junit' "$runner")"
  [ "$junit_sites" -ge 3 ]
  [ "$verdict_calls" -eq "$junit_sites" ]
}

@test "runner: summary is derived from YTF-VERDICT lines (zero-executed guard present)" {
  local runner="${REPO_ROOT}/scripts/run-test-framework.sh"
  grep -q 'zero-tests-executed-across-run' "$runner"
  grep -q 'tier-.*-has-no-verdict-lines\|has-no-verdict-lines' "$runner"
  grep -q 'YTF-SUMMARY:' "$runner"
}

# --- end-to-end mutation: the ORIGINAL RISK-206 scenario through the runner
# summary logic (all-skip junit, rc 0) must yield overall FAIL ---------------

@test "e2e: verdict gate turns an all-skip 'green' into FAIL, and a real pass stays PASS" {
  # all-skip: FAIL
  _junit 34 0 0 34
  run "$V" --junit "$T/junit.xml" --rc 0 --tier c --suite e2e-integration --out "$T/V1.txt"
  [ "$status" -ne 0 ]
  # real pass: PASS — proves the gate is not simply failing everything
  _junit 34 0 0 4
  run "$V" --junit "$T/junit.xml" --rc 0 --tier c --suite e2e-integration --out "$T/V2.txt"
  [ "$status" -eq 0 ]
  grep -q "verdict=FAIL" "$T/V1.txt"
  grep -q "verdict=PASS" "$T/V2.txt"
}
