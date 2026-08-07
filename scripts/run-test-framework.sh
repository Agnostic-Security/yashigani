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
#       --runtime docker --version 4.1.2 --platform macos \
#       [--browser-mode both|headed|headless]
#   scripts/run-test-framework.sh --tier c --target https://localhost:8443 \
#       --runtime k8s --version 4.1.2 --platform linux
#   scripts/run-test-framework.sh --full --target ... --runtime ... \
#       --version ... --platform ...     # Tier-A + Tier-B + Tier-C
#
# Exit codes: 0 = all requested tiers GREEN. 1 = any tier reported a failure.
# 2 = usage error. Tier-A always runs offline; Tier-B/Tier-C REQUIRE --target
# (a live, reachable stack) and are skipped (exit 2) without one.
#
# Last updated: 2026-07-29 (Iris, YTF build).
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
  --tier b               Run Tier-B (live WebUI Playwright). Requires --target.
  --tier c               Run Tier-C (live integration/lifecycle/chaos/parity).
                         Requires --target.
  --full                 Run Tier-A + Tier-B + Tier-C. Requires --target for
                         B/C legs.
  --target URL           Base URL of a running Yashigani stack (Tier-B/C).
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
  VENV_PY="$(command -v python3)"
fi

OVERALL_RC=0



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
  local rc=0
  local evidence_dir="${EVIDENCE_ROOT}/tier-a"
  mkdir -p "$evidence_dir"

  _info "pytest: tests/conformance/ + tests/security/ (API conformance, OPA-adjacent wiring audit, static/authored-live pentest)"
  PYTHONPATH="${REPO_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}" \
    "$VENV_PY" -m pytest "${REPO_DIR}/tests/conformance" "${REPO_DIR}/tests/security" \
    -q --tb=short --junitxml="${evidence_dir}/pytest-junit.xml" \
    | tee "${evidence_dir}/pytest.log" || rc=1

  _assert_executed "${evidence_dir}/pytest-junit.xml" "Tier-A pytest" || rc=1
  if [ "$rc" -eq 0 ]; then _pass "tests/conformance + tests/security"; else _fail "tests/conformance + tests/security (see ${evidence_dir}/pytest.log)"; fi

  _info "opa test: policy/ (in-process rego unit tests for every live-loaded template + system policy)"
  local opa_rc=0
  if command -v opa >/dev/null 2>&1; then
    opa test "${REPO_DIR}/policy/" -v > "${evidence_dir}/opa-test.log" 2>&1 || opa_rc=1
    if [ "$opa_rc" -eq 0 ]; then _pass "opa test policy/"; else _fail "opa test policy/ (see ${evidence_dir}/opa-test.log)"; rc=1; fi
  else
    _warn "opa binary not found on PATH — opa test SKIPPED, not counted as pass"
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
  if [ -z "$TARGET" ] || [ -z "$RUNTIME" ] || [ -z "$VERSION" ] || [ -z "$PLATFORM" ]; then
    _fail "Tier-B requires --target, --runtime, --version, --platform"
    return 2
  fi
  local leg="${RUNTIME}-${PLATFORM}"
  local evidence_dir="${EVIDENCE_ROOT}/${leg}/tier-b"
  local shots_dir="${EVIDENCE_ROOT}/${leg}/screenshots"
  mkdir -p "$evidence_dir" "$shots_dir"
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
    YASHIGANI_ADMIN_URL="$TARGET" \
    YTF_SCREENSHOT_DIR="${shots_dir}/${mode}" \
    YTF_LEG="$leg" \
    YTF_HEADED="$headed_env" \
    PYTHONPATH="${REPO_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}" \
      "$VENV_PY" -m pytest "${REPO_DIR}/src/tests/playwright" \
      -q --tb=short \
      --junitxml="${evidence_dir}/pytest-junit-${mode}.xml" \
      | tee "${evidence_dir}/pytest-${mode}.log" || mode_rc=1
    # YSG-RISK-206: a mode that executed nothing is NOT RUN, not GREEN.
    _assert_executed "${evidence_dir}/pytest-junit-${mode}.xml" "Tier-B ${mode} (leg ${leg})" || mode_rc=1
    if [ "$mode_rc" -eq 0 ]; then _pass "Playwright ${mode} — leg ${leg}"; else _fail "Playwright ${mode} — leg ${leg} (see ${evidence_dir}/pytest-${mode}.log)"; rc=1; fi
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
  if [ -z "$TARGET" ] || [ -z "$RUNTIME" ] || [ -z "$VERSION" ] || [ -z "$PLATFORM" ]; then
    _fail "Tier-C requires --target, --runtime, --version, --platform"
    return 2
  fi
  local leg="${RUNTIME}-${PLATFORM}"
  local evidence_dir="${EVIDENCE_ROOT}/${leg}/tier-c"
  mkdir -p "$evidence_dir"
  local rc=0

  _info "pytest: src/tests/e2e/ (lifecycle + failure_injection_chaos + data_flow_seam — pre-existing, absorbed not duplicated) + tests/integration_live/ (the other 6 categories — see docs/testing/YTF.md Tier-C)"
  YASHIGANI_ADMIN_URL="$TARGET" \
  YTF_RUNTIME="$RUNTIME" YTF_VERSION="$VERSION" YTF_PLATFORM="$PLATFORM" \
  PYTHONPATH="${REPO_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}" \
    "$VENV_PY" -m pytest "${REPO_DIR}/src/tests/e2e" "${REPO_DIR}/tests/integration_live" \
    -q --tb=short --junitxml="${evidence_dir}/pytest-junit.xml" \
    | tee "${evidence_dir}/pytest.log" || rc=1

  _assert_executed "${evidence_dir}/pytest-junit.xml" "Tier-C pytest (leg ${leg})" || rc=1
  if [ "$rc" -eq 0 ]; then _pass "src/tests/e2e + tests/integration_live — leg ${leg}"; else _fail "src/tests/e2e + tests/integration_live — leg ${leg} (see ${evidence_dir}/pytest.log)"; fi
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
if [ "$OVERALL_RC" -eq 0 ]; then
  _pass "All requested tiers GREEN"
else
  _fail "One or more requested tiers reported a failure — see evidence paths above"
fi

exit "$OVERALL_RC"
