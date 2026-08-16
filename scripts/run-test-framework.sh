#!/usr/bin/env bash
# scripts/run-test-framework.sh — Yashigani Test Framework (YTF)
#
# ONE repeatable, tiered, full-matrix harness for 4.1.2+ (and designed to
# travel forward into 5.0 without a rewrite — see docs/testing/YTF.md).
#
# Three tiers:
#   Tier-A — IN-PROCESS, matrix-INVARIANT (no stack). Conformance API + OPA +
#            wiring/config audit + static pentest. Runs ONCE per code head;
#            the result applies to every runtime/platform leg simultaneously.
#   Tier-B — LIVE, per-deployment. WebUI Playwright (conformance + adversarial),
#            both headed AND headless, screenshot-every-change. Needs --target.
#   Tier-C — LIVE, per-deployment. Integration/data-flow seam, full lifecycle
#            (install/upgrade/uninstall/reinstall), failure-injection/chaos,
#            cross-runtime parity, egress ring-fence + prompt-injection (both
#            legs), audit/observability integrity, data-plane byte-proof,
#            multi-tenant isolation + licensing lifecycle. Needs --target.
#
# Usage:
#   scripts/run-test-framework.sh --tier a
#   scripts/run-test-framework.sh --tier b --target https://localhost:8443 \
#       --runtime podman --version 4.1.2 --platform macos \
#       [--browser-mode both|headed|headless]
#   scripts/run-test-framework.sh --tier b --target https://localhost \
#       --runtime docker --version 4.1.2 --platform macos
#   scripts/run-test-framework.sh --tier c --target https://localhost:8443 \
#       --runtime k8s --version 4.1.2 --platform linux
#   scripts/run-test-framework.sh --full --target ... --runtime ... \
#       --version ... --platform ...     # Tier-A + Tier-B + Tier-C
#
# FIND-B-TARGET (4.1.2 3-runtime retest, 2026-08-04): --target is a per-leg
# PORT, not a fixed constant -- podman's rootless compose profile exposes
# Caddy's HTTPS vhost on :8443, while docker's rootful profile binds :443
# directly. Pasting the SAME example (":8443") next to both --runtime docker
# and --runtime podman (as this banner used to) is misleading: a docker leg
# run with ":8443" hits nothing (connection refused) and a docker leg run
# with the WRONG vhost port silently 200s against Caddy's empty catch-all
# instead of the real admin app -- a false-green trap. src/tests/playwright/
# conftest.py's own _resolve_base_url() already auto-probes
# https://localhost:8443, https://localhost, then http://localhost:8080 (in
# that order) and only trusts YASHIGANI_ADMIN_URL as an override when one is
# actually set -- so --target below is now OPTIONAL for Tier-B/Tier-C: omit
# it and the harness resolves the correct URL for whichever leg is actually
# running (confirmed live, 2026-08-04 docker leg: omitting --target/
# YASHIGANI_ADMIN_URL still auto-resolved to :443 correctly). Pass --target
# explicitly only to pin a NON-default port/host.
#
# Exit codes: 0 = all requested tiers GREEN. 1 = any tier reported a failure.
# 2 = usage error. Tier-A always runs offline; Tier-B/Tier-C REQUIRE
# --runtime/--version/--platform (evidence-path labelling) but --target is
# now optional -- see FIND-B-TARGET note above.
#
# Last updated: 2026-08-04 (Ava, 4.1.2 3-runtime retest batch-fix: FIND-B-TARGET).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -t 1 ]; then
  GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'
  BLUE='\033[1;34m'; BOLD='\033[1m'; RESET='\033[0m'
else
  GREEN=''; RED=''; YELLOW=''; BLUE=''; BOLD=''; RESET=''
fi
_pass() { printf "  ${GREEN}PASS${RESET}  %s\n" "$1"; }
_fail() { printf "  ${RED}FAIL${RESET}  %s\n" "$1"; }
_info() { printf "  ${BLUE}....${RESET}  %s\n" "$1"; }
_warn() { printf "  ${YELLOW}WARN${RESET}  %s\n" "$1"; }

# ---------------------------------------------------------------------------
# Defaults / arg parsing
# ---------------------------------------------------------------------------
TIER=""
RUN_FULL=0
TARGET=""
RUNTIME=""
VERSION=""
PLATFORM=""
BROWSER_MODE="both"   # both|headed|headless — Tier-B only
EVIDENCE_ROOT="${YTF_EVIDENCE_ROOT:-${REPO_DIR}/../testing_runs/yashigani/ytf}"

usage() {
  cat <<'EOF'
Usage: run-test-framework.sh [--tier a|b|c] [--full]
                              [--target URL] [--runtime docker|podman|k8s]
                              [--version VER] [--platform macos|linux]
                              [--browser-mode both|headed|headless]

  --tier a               Run Tier-A (in-process, no stack, runtime-invariant).
  --tier b               Run Tier-B (live WebUI Playwright). Requires
                         --runtime/--version/--platform.
  --tier c               Run Tier-C (live integration/lifecycle/chaos/parity).
                         Requires --runtime/--version/--platform.
  --full                 Run Tier-A + Tier-B + Tier-C. Requires
                         --runtime/--version/--platform for B/C legs.
  --target URL           Base URL of a running Yashigani stack (Tier-B/C).
                         OPTIONAL — if omitted, the harness auto-resolves it
                         (conftest.py probes :8443 then :443 then :8080;
                         see FIND-B-TARGET note above the usage banner).
                         Pass explicitly only to pin a non-default port/host.
  --runtime NAME          docker | podman | k8s   (evidence-path labelling)
  --version VER           e.g. 4.1.2                (evidence-path labelling)
  --platform NAME         macos | linux             (evidence-path labelling)
  --browser-mode MODE     both (default) | headed | headless   (Tier-B only)
  -h, --help              Show this help.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --tier) TIER="$2"; shift 2 ;;
    --full) RUN_FULL=1; shift ;;
    --target) TARGET="$2"; shift 2 ;;
    --runtime) RUNTIME="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --platform) PLATFORM="$2"; shift 2 ;;
    --browser-mode) BROWSER_MODE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [ "$RUN_FULL" -eq 0 ] && [ -z "$TIER" ]; then
  echo "Must pass --tier a|b|c or --full" >&2
  usage
  exit 2
fi

case "$BROWSER_MODE" in
  both|headed|headless) ;;
  *) echo "--browser-mode must be one of: both, headed, headless" >&2; exit 2 ;;
esac

RUN_A=0; RUN_B=0; RUN_C=0
if [ "$RUN_FULL" -eq 1 ]; then
  RUN_A=1; RUN_B=1; RUN_C=1
else
  case "$TIER" in
    a) RUN_A=1 ;;
    b) RUN_B=1 ;;
    c) RUN_C=1 ;;
    *) echo "--tier must be one of: a, b, c" >&2; exit 2 ;;
  esac
fi

VENV_PY="${YTF_PYTHON:-${REPO_DIR}/.venv/bin/python3}"
if [ ! -x "$VENV_PY" ]; then
  # FIND-0813-004: this fallback used to be SILENT. On the 4.1.2 Linux campaign
  # it fell through to system python, which had no pytest at all — Tier-B
  # collected 0 tests in BOTH browser modes and only the YSG-RISK-206 verdict
  # gate stopped that being recorded as a pass. Announce it.
  _fb="$(command -v python3 || true)"
  printf '  !!  WARNING: project venv not found at %s — falling back to %s\n' \
         "$VENV_PY" "${_fb:-<none>}" >&2
  printf '  !!  Provision it with: uv sync --frozen --all-groups --all-extras\n' >&2
  VENV_PY="$_fb"
fi

# FIND-0813-004 — a tier MUST prove its own prerequisites before executing.
# The root cause was a stale uv.lock: pytest-timeout / playwright / zaproxy were
# declared in pyproject but ABSENT from the lock, so `uv sync --frozen` installed
# a subset WITHOUT WARNING. Three separate symptoms followed (Tier-B 0-executed;
# 3 Tier-A zap_driver failures; a hung run whose 300s ceiling was silently inert
# because pytest-timeout was missing). Same invariant as YSG-RISK-206: prove the
# precondition, never infer it later from a junit that isn't there.
_ytf_require_python_deps() {
  local tier="$1" missing="" mod
  local required="pytest pytest_timeout"
  case "$tier" in
    a) required="$required zapv2" ;;          # tests/security ZAP driver self-checks
    b) required="$required playwright" ;;     # WebUI suite
    c) required="$required playwright" ;;
  esac
  for mod in $required; do
    "$VENV_PY" -c "import $mod" >/dev/null 2>&1 || missing="$missing $mod"
  done
  if [ -n "$missing" ]; then
    printf '\n  XX  Tier-%s cannot run — missing Python module(s):%s\n' "$tier" "$missing" >&2
    printf '  XX  Interpreter: %s\n' "$VENV_PY" >&2
    printf '  XX  Fix: uv sync --frozen --all-groups --all-extras' >&2
    case " $missing " in *" playwright "*) printf ' && "%s" -m playwright install chromium' "$VENV_PY" >&2 ;; esac
    printf '\n  XX  Refusing to execute a tier on an under-provisioned interpreter (FIND-0813-004).\n\n' >&2
    return 1
  fi
  return 0
}

OVERALL_RC=0
# VERDICT.txt files produced by THIS run (truncated at tier start so stale
# lines from a previous run in the same evidence root can never satisfy or
# poison this run's summary).
YTF_VERDICT_FILES=""



# ---------------------------------------------------------------------------
# _leg_preflight — YSG-RISK-207 gate (2026-08-07)
#
# A leg must PROVE it can reach AND authenticate to its target before it is
# allowed to generate evidence. Four separate times this campaign, harness state
# pointed at a deployment that no longer existed and the tier produced hours of
# meaningless output:
#   * Tier-C resolved the CA against the TEST checkout, not the deployment ->
#     41/41 skipped "no live stack" while the stack answered healthz 200.
#   * YTF_SECRETS_DIR still held the previous stack's credentials after a
#     destroy-and-reinstall -> 6 of the first 9 Tier-B tests failed on login.
#     That failure is VISUALLY IDENTICAL to the real IP-throttle lane-bleed, so
#     rig artefact and genuine SOP gap cannot be told apart after the fact.
#   * FIND-0805-002 (rotated password written to the wrong dir).
#   * RIG-002 (podman prefix unusable after reboot; the product's own error for
#     it is invisible, see YSG-RISK-203).
#
# Distinct abort reasons per cause so the two are never confused again.
# ---------------------------------------------------------------------------
_leg_preflight() {
  local target="$1"
  local pf_script="${REPO_DIR}/../ytf-preflight.sh"
  [ -f "$pf_script" ] || pf_script="${YTF_PREFLIGHT:-}"
  if [ -z "$pf_script" ] || [ ! -f "$pf_script" ]; then
    _warn "leg pre-flight script not found — proceeding WITHOUT an auth proof (YSG-RISK-207)."
    _warn "  Set YTF_PREFLIGHT=/path/to/ytf-preflight.sh to enforce it."
    return 0
  fi
  YTF_TARGET="$target" YTF_SECRETS_DIR="${YTF_SECRETS_DIR:-}" bash "$pf_script" || {
    _fail "leg pre-flight FAILED — refusing to generate evidence against an unusable target"
    return 1
  }
}

# ---------------------------------------------------------------------------
# _assert_executed — YSG-RISK-206 gate (2026-08-07)
#
# pytest exits 0 when EVERY test skips, so "everything skipped" and "everything
# passed" were the same signal to this runner. Tier-C reported
# "PASS / All requested tiers GREEN" on 41 collected / 41 skipped / 0 EXECUTED,
# against a live, healthy stack. Tier-C is the tier carrying lifecycle,
# failure-injection, egress ring-fence, prompt-injection, audit integrity,
# data-plane byte-proof and multi-tenant licensing — a leg could be declared
# GREEN having verified none of them.
#
# Ava A1 / Lu L1: absence of an artefact is SKIPPED, never PASS. A tier that
# executed nothing is not GREEN; it is NOT RUN, which gates treat as FAIL.
#
# Usage: _assert_executed <junit.xml> <label>   -> 0 if it genuinely ran
# ---------------------------------------------------------------------------
_assert_executed() {
  local xml="$1" label="$2"
  [ -f "$xml" ] || { _fail "${label}: no junit XML at ${xml} — cannot prove anything ran"; return 1; }
  local tests skipped errors failures executed
  tests=$(grep -o 'tests="[0-9]*"'    "$xml" | head -1 | tr -dc '0-9'); tests=${tests:-0}
  skipped=$(grep -o 'skipped="[0-9]*"' "$xml" | head -1 | tr -dc '0-9'); skipped=${skipped:-0}
  errors=$(grep -o 'errors="[0-9]*"'   "$xml" | head -1 | tr -dc '0-9'); errors=${errors:-0}
  failures=$(grep -o 'failures="[0-9]*"' "$xml" | head -1 | tr -dc '0-9'); failures=${failures:-0}
  executed=$(( tests - skipped ))
  printf "  ....  %s: collected=%s executed=%s skipped=%s failed=%s errors=%s\n" \
    "$label" "$tests" "$executed" "$skipped" "$failures" "$errors"
  if [ "$executed" -le 0 ]; then
    _fail "${label}: 0 tests EXECUTED (${skipped} skipped) — NOT RUN, not GREEN (YSG-RISK-206)"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Tier-A — in-process, matrix-invariant. Runs ONCE regardless of runtime/
# platform/version legs requested — the result applies to every leg in
# tests/MATRIX.yaml (see docs/testing/YTF.md "Tier-A is runtime-invariant").
# ---------------------------------------------------------------------------
run_tier_a() {
  printf "\n%b=== Tier-A: in-process conformance + OPA + wiring-audit + static pentest ===%b\n\n" "$BOLD" "$RESET"
  _ytf_require_python_deps a || return 1
  local rc=0
  local evidence_dir="${EVIDENCE_ROOT}/tier-a"
  mkdir -p "$evidence_dir"
  : > "${evidence_dir}/VERDICT.txt"
  YTF_VERDICT_FILES="${YTF_VERDICT_FILES} ${evidence_dir}/VERDICT.txt"

  _info "pytest: tests/conformance/ + tests/security/ (API conformance, OPA-adjacent wiring audit, static/authored-live pentest)"
  local _prc=0
  PYTHONPATH="${REPO_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}" \
    "$VENV_PY" -m pytest "${REPO_DIR}/tests/conformance" "${REPO_DIR}/tests/security" \
    -q --tb=short --junitxml="${evidence_dir}/pytest-junit.xml" \
    | tee "${evidence_dir}/pytest.log" || _prc=$?

  # YSG-RISK-206: the verdict comes from the junit XML via ytf-verdict.sh —
  # exit 0 with zero executed tests is a FAIL, not a PASS.
  if "${SCRIPT_DIR}/ytf-verdict.sh" --junit "${evidence_dir}/pytest-junit.xml" \
       --rc "$_prc" --tier a --suite conformance-security \
       --out "${evidence_dir}/VERDICT.txt"; then
    _pass "tests/conformance + tests/security"
  else
    _fail "tests/conformance + tests/security (see ${evidence_dir}/pytest.log + VERDICT.txt)"
    rc=1
  fi

  # FIND-0813-012 — src/tests/regression/ (140 files) was referenced by NO tier,
  # so its red state was INVISIBLE to the release gate: the 4.1.2 regression
  # suites for YSG-RISK-210/211, 180, FIND-B-E and FIND-B-F could all be failing
  # and nothing reported it. Run as its OWN suite with its own verdict line so
  # its result is never silently folded into the conformance number.
  # Live-stack-dependent modules are deselected — Tier-A is matrix-invariant and
  # offline by definition (YTF §3); those belong to Tier-C.
  _info "pytest: src/tests/regression/ (per-risk regression guards — in-process only)"
  local _rrc=0
  PYTHONPATH="${REPO_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}" \
    "$VENV_PY" -m pytest "${REPO_DIR}/src/tests/regression" \
    -q --tb=short --junitxml="${evidence_dir}/pytest-junit-regression.xml" \
    | tee "${evidence_dir}/pytest-regression.log" || _rrc=$?
  if "${SCRIPT_DIR}/ytf-verdict.sh" --junit "${evidence_dir}/pytest-junit-regression.xml" \
       --rc "$_rrc" --tier a --suite regression \
       --out "${evidence_dir}/VERDICT.txt"; then
    _pass "src/tests/regression"
  else
    _fail "src/tests/regression (see ${evidence_dir}/pytest-regression.log + VERDICT.txt)"
    rc=1
  fi

  _info "opa test: policy/ (in-process rego unit tests for every live-loaded template + system policy)"
  local opa_rc=0
  if command -v opa >/dev/null 2>&1; then
    opa test "${REPO_DIR}/policy/" -v > "${evidence_dir}/opa-test.log" 2>&1 || opa_rc=1
    # Same zero-executed guard for opa: executed count comes from the raw -v
    # log (one ': PASS'/': FAIL' line per test), never from opa's exit alone.
    local _opa_executed
    _opa_executed="$(grep -cE ': (PASS|FAIL)' "${evidence_dir}/opa-test.log" || true)"
    local _opa_verdict="PASS" _opa_reason="-"
    if [ "$opa_rc" -ne 0 ]; then _opa_verdict="FAIL"; _opa_reason="runner-rc-${opa_rc}"
    elif [ "${_opa_executed}" -lt 1 ]; then _opa_verdict="FAIL"; _opa_reason="zero-or-below-min-executed"; fi
    echo "YTF-VERDICT: tier=a suite=opa leg=- mode=- rc=${opa_rc} collected=${_opa_executed} executed=${_opa_executed} passed=$(grep -cE ': PASS' "${evidence_dir}/opa-test.log" || true) failed=$(grep -cE ': FAIL' "${evidence_dir}/opa-test.log" || true) errors=0 skipped=0 min_executed=1 verdict=${_opa_verdict} reason=${_opa_reason}" \
      | tee -a "${evidence_dir}/VERDICT.txt"
    if [ "${_opa_verdict}" = "PASS" ]; then _pass "opa test policy/ (${_opa_executed} executed)"; else _fail "opa test policy/ (see ${evidence_dir}/opa-test.log + VERDICT.txt)"; rc=1; fi
  else
    _warn "opa binary not found on PATH — opa test SKIPPED, not counted as pass"
    echo "YTF-VERDICT: tier=a suite=opa leg=- mode=- rc=127 collected=0 executed=0 passed=0 failed=0 errors=0 skipped=0 min_executed=1 verdict=FAIL reason=opa-binary-missing" \
      | tee -a "${evidence_dir}/VERDICT.txt"
    rc=1
  fi

  printf "\nTier-A evidence: %s\n" "$evidence_dir"
  return "$rc"
}

# ---------------------------------------------------------------------------
# Tier-B — live, per-deployment WebUI Playwright. Both headed AND headless;
# a leg isn't complete until BOTH pass. Screenshot of every state transition,
# saved per-leg under EVIDENCE_ROOT/<runtime>-<platform>/screenshots/.
# ---------------------------------------------------------------------------
run_tier_b() {
  printf "\n%b=== Tier-B: live WebUI Playwright (conformance + adversarial) ===%b\n\n" "$BOLD" "$RESET"
  _ytf_require_python_deps b || return 1
  # FIND-B-TARGET: --target is optional (see usage banner) — --runtime/
  # --version/--platform are still mandatory (evidence-path labelling).
  if [ -z "$RUNTIME" ] || [ -z "$VERSION" ] || [ -z "$PLATFORM" ]; then
    _fail "Tier-B requires --runtime, --version, --platform (--target is optional — auto-resolved if omitted)"
    return 2
  fi
  if [ -n "$TARGET" ]; then
    _info "--target explicitly set: ${TARGET}"
  else
    _info "--target not set — conftest.py will auto-resolve (probes :8443, :443, :8080 in order)"
  fi
  local leg="${RUNTIME}-${PLATFORM}"
  local evidence_dir="${EVIDENCE_ROOT}/${leg}/tier-b"
  local shots_dir="${EVIDENCE_ROOT}/${leg}/screenshots"
  mkdir -p "$evidence_dir" "$shots_dir"
  : > "${evidence_dir}/VERDICT.txt"
  YTF_VERDICT_FILES="${YTF_VERDICT_FILES} ${evidence_dir}/VERDICT.txt"
  local rc=0

  local modes=()
  # YTF §2 hard requirement: "Headed AND headless, both. A leg's WebUI Tier-B
  # cell is not GREEN until BOTH modes pass." Nothing previously enforced that —
  # a leg run with --browser-mode headless produced an exit code that looked
  # identical to a full two-mode run, and one was declared on that basis this
  # campaign. Single-mode runs are still allowed (useful for triage) but they can
  # no longer report GREEN: the leg is marked INCOMPLETE and the runner exits
  # non-zero, so a gate cannot mistake partial coverage for a pass.
  # (The "rig cannot do headed" belief that motivated single-mode runs was false:
  # xvfb-run works — 8 headed navigations in 0.7s, then a full 494-test headed
  # sweep in 3h03 with 110 errors, identical to headless.)
  local mode_coverage_incomplete=0
  case "$BROWSER_MODE" in
    both) modes=(headed headless) ;;
    headed) modes=(headed); mode_coverage_incomplete=1 ;;
    headless) modes=(headless); mode_coverage_incomplete=1 ;;
  esac

  for mode in "${modes[@]}"; do
    _info "Playwright ${mode}: WebUI conformance (39 pages/34 forms/137 buttons, 2x2 admin+user x WebUI+API) + adversarial"
    # NOTE (2026-07-30, Ava): "--headed" is not a registered pytest CLI option
    # in this suite (no pytest-playwright plugin, no pytest_addoption) -- it
    # was previously being passed as a bare pytest arg and would raise a
    # usage error (exit 4), not a real headed run. Every chromium.launch()
    # call site now goes through conftest.launch_chromium(), which reads the
    # YTF_HEADED env var instead. Fixed here to match.
    local headed_env="0"
    [ "$mode" = "headed" ] && headed_env="1"
    local mode_rc=0
    # FIND-B-TARGET: TARGET may be empty (--target now optional). Exporting
    # YASHIGANI_ADMIN_URL="" is safe here (NOT an array, so no bash-3.2
    # "unbound variable" pitfall under set -u): conftest.py's
    # _resolve_base_url() does `override = os.getenv("YASHIGANI_ADMIN_URL")`
    # then `if override: return ...` -- an empty string is falsy in Python,
    # so it falls straight through to the auto-probe (:8443/:443/:8080)
    # exactly as if the var were unset. Verified: macOS ships bash 3.2
    # (/usr/bin/env bash), which mishandles `"${empty_array[@]}"` under
    # `set -u` -- a plain empty-string scalar has no such issue.
    YASHIGANI_ADMIN_URL="$TARGET" \
    YTF_SCREENSHOT_DIR="${shots_dir}/${mode}" \
    YTF_LEG="$leg" \
    YTF_HEADED="$headed_env" \
    PYTHONPATH="${REPO_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}" \
      "$VENV_PY" -m pytest "${REPO_DIR}/src/tests/playwright" \
      -q --tb=short \
      --junitxml="${evidence_dir}/pytest-junit-${mode}.xml" \
      | tee "${evidence_dir}/pytest-${mode}.log" || mode_rc=$?
    # YSG-RISK-206: verdict derived from the junit XML, not the exit code —
    # an all-skipped run (unreachable stack, YSG-RISK-207) exits 0 but
    # executes nothing and must FAIL here.
    if "${SCRIPT_DIR}/ytf-verdict.sh" --junit "${evidence_dir}/pytest-junit-${mode}.xml" \
         --rc "$mode_rc" --tier b --suite playwright --leg "$leg" --mode "$mode" \
         --out "${evidence_dir}/VERDICT.txt"; then
      _pass "Playwright ${mode} — leg ${leg}"
    else
      _fail "Playwright ${mode} — leg ${leg} (see ${evidence_dir}/pytest-${mode}.log + VERDICT.txt)"
      rc=1
    fi
  done

  local shot_count
  shot_count="$(find "$shots_dir" -type f \( -name '*.png' -o -name '*.jpg' \) 2>/dev/null | wc -l | tr -d ' ')"
  _info "Screenshot evidence: ${shot_count} files under ${shots_dir}"
  if [ "$shot_count" -eq 0 ]; then
    _warn "Zero screenshots captured — leg WebUI Tier-B is NOT complete per pass-criteria (both modes green + full screenshot set)"
    rc=1
  fi

  if [ "$mode_coverage_incomplete" -eq 1 ]; then
    _fail "Tier-B leg ${leg}: browser-mode coverage INCOMPLETE (ran '${BROWSER_MODE}' only)."
    _fail "  YTF §2: a leg's WebUI cell is not GREEN until BOTH headed and headless pass."
    _fail "  Headed is runnable here — wrap the runner in: xvfb-run -a --server-args=\"-screen 0 1920x1080x24\""
    rc=1
  fi
  printf "\nTier-B evidence (leg %s): %s\n" "$leg" "$evidence_dir"
  return "$rc"
}

# ---------------------------------------------------------------------------
# Tier-C — live, per-deployment: integration/data-flow seam, full lifecycle,
# failure-injection/chaos, cross-runtime parity, egress ring-fence +
# prompt-injection (both legs), audit/observability integrity, data-plane
# byte-proof, multi-tenant isolation + licensing lifecycle.
# ---------------------------------------------------------------------------
run_tier_c() {
  printf "\n%b=== Tier-C: live integration / lifecycle / chaos / parity ===%b\n\n" "$BOLD" "$RESET"
  _ytf_require_python_deps c || return 1
  # FIND-B-TARGET: --target is optional (see usage banner) — --runtime/
  # --version/--platform are still mandatory (evidence-path labelling).
  if [ -z "$RUNTIME" ] || [ -z "$VERSION" ] || [ -z "$PLATFORM" ]; then
    _fail "Tier-C requires --runtime, --version, --platform (--target is optional — auto-resolved if omitted)"
    return 2
  fi
  if [ -n "$TARGET" ]; then
    _info "--target explicitly set: ${TARGET}"
  else
    _info "--target not set — conftest.py will auto-resolve (probes :8443, :443, :8080 in order)"
  fi
  local leg="${RUNTIME}-${PLATFORM}"
  local evidence_dir="${EVIDENCE_ROOT}/${leg}/tier-c"
  mkdir -p "$evidence_dir"
  : > "${evidence_dir}/VERDICT.txt"
  YTF_VERDICT_FILES="${YTF_VERDICT_FILES} ${evidence_dir}/VERDICT.txt"
  local rc=0

  _info "pytest: src/tests/e2e/ (lifecycle + failure_injection_chaos + data_flow_seam — pre-existing, absorbed not duplicated) + tests/integration_live/ (the other 6 categories — see docs/testing/YTF.md Tier-C)"
  # FIND-B-TARGET: see the matching comment in run_tier_b() — empty-string
  # YASHIGANI_ADMIN_URL is safe (falsy in conftest.py's override check) and
  # avoids the bash-3.2 empty-array/set-u pitfall on macOS's default bash.
  local _prc=0
  YASHIGANI_ADMIN_URL="$TARGET" \
  YTF_RUNTIME="$RUNTIME" YTF_VERSION="$VERSION" YTF_PLATFORM="$PLATFORM" \
  PYTHONPATH="${REPO_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}" \
    "$VENV_PY" -m pytest "${REPO_DIR}/src/tests/e2e" "${REPO_DIR}/tests/integration_live" \
    -q --tb=short --junitxml="${evidence_dir}/pytest-junit.xml" \
    | tee "${evidence_dir}/pytest.log" || _prc=$?

  # YSG-RISK-206 (the original instance was THIS tier): every Tier-C test
  # skips cleanly when no stack is reachable, so pytest exits 0 having
  # executed nothing and the old exit-code-only check printed PASS. The
  # verdict now requires executed >= 1 from the junit XML.
  if "${SCRIPT_DIR}/ytf-verdict.sh" --junit "${evidence_dir}/pytest-junit.xml" \
       --rc "$_prc" --tier c --suite e2e-integration --leg "$leg" \
       --out "${evidence_dir}/VERDICT.txt"; then
    _pass "src/tests/e2e + tests/integration_live — leg ${leg}"
  else
    _fail "src/tests/e2e + tests/integration_live — leg ${leg} (see ${evidence_dir}/pytest.log + VERDICT.txt)"
    rc=1
  fi
  printf "\nTier-C evidence (leg %s): %s\n" "$leg" "$evidence_dir"
  return "$rc"
}

# ---------------------------------------------------------------------------
# Drive requested tiers
# ---------------------------------------------------------------------------
if [ "$RUN_A" -eq 1 ]; then
  run_tier_a || OVERALL_RC=1
fi
if [ "$RUN_B" -eq 1 ]; then
  run_tier_b || OVERALL_RC=1
fi
if [ "$RUN_C" -eq 1 ]; then
  run_tier_c || OVERALL_RC=1
fi

printf "\n%b=== YTF summary ===%b\n" "$BOLD" "$RESET"

# YSG-RISK-206 belt-and-braces: the summary is DERIVED from the YTF-VERDICT
# lines written by ytf-verdict.sh, cross-checked against the accumulated rc.
# Every requested tier must have >=1 verdict line, zero FAIL lines, and a
# nonzero total executed count — otherwise the run is FAIL regardless of rc.
_summary_fail_reason=""
_tiers_requested=""
[ "$RUN_A" -eq 1 ] && _tiers_requested="${_tiers_requested}a"
[ "$RUN_B" -eq 1 ] && _tiers_requested="${_tiers_requested}b"
[ "$RUN_C" -eq 1 ] && _tiers_requested="${_tiers_requested}c"
_total_executed=0
for _t in a b c; do
  case "$_tiers_requested" in *"$_t"*) ;; *) continue ;; esac
  _t_lines="$(cat $YTF_VERDICT_FILES 2>/dev/null | grep "tier=${_t} " || true)"
  _t_count="$(printf '%s' "$_t_lines" | grep -c 'YTF-VERDICT:' || true)"
  _t_fails="$(printf '%s' "$_t_lines" | grep -c 'verdict=FAIL' || true)"
  _t_exec="$(printf '%s\n' "$_t_lines" | sed -n 's/.* executed=\([0-9]*\) .*/\1/p' | awk '{s+=$1} END {print s+0}')"
  _total_executed=$((_total_executed + _t_exec))
  if [ "$_t_count" -eq 0 ]; then
    _summary_fail_reason="tier-${_t}-has-no-verdict-lines"; OVERALL_RC=1
  elif [ "$_t_fails" -ne 0 ]; then
    _summary_fail_reason="tier-${_t}-has-FAIL-verdicts"; OVERALL_RC=1
  fi
done
if [ "$OVERALL_RC" -eq 0 ] && [ "$_total_executed" -lt 1 ]; then
  _summary_fail_reason="zero-tests-executed-across-run"; OVERALL_RC=1
fi

echo "YTF-SUMMARY: tiers=${_tiers_requested} total_executed=${_total_executed} rc=${OVERALL_RC} verdict=$([ "$OVERALL_RC" -eq 0 ] && echo GREEN || echo FAIL) reason=${_summary_fail_reason:--}"
if [ "$OVERALL_RC" -eq 0 ]; then
  _pass "All requested tiers GREEN (${_total_executed} tests executed, verdict-line derived)"
else
  _fail "FAIL — ${_summary_fail_reason:-tier failure} (see evidence paths + VERDICT.txt files above)"
fi

exit "$OVERALL_RC"
