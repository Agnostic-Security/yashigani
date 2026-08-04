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
  VENV_PY="$(command -v python3)"
fi

OVERALL_RC=0

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
  local rc=0

  local modes=()
  case "$BROWSER_MODE" in
    both) modes=(headed headless) ;;
    headed) modes=(headed) ;;
    headless) modes=(headless) ;;
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
      | tee "${evidence_dir}/pytest-${mode}.log" || mode_rc=1
    if [ "$mode_rc" -eq 0 ]; then _pass "Playwright ${mode} — leg ${leg}"; else _fail "Playwright ${mode} — leg ${leg} (see ${evidence_dir}/pytest-${mode}.log)"; rc=1; fi
  done

  local shot_count
  shot_count="$(find "$shots_dir" -type f \( -name '*.png' -o -name '*.jpg' \) 2>/dev/null | wc -l | tr -d ' ')"
  _info "Screenshot evidence: ${shot_count} files under ${shots_dir}"
  if [ "$shot_count" -eq 0 ]; then
    _warn "Zero screenshots captured — leg WebUI Tier-B is NOT complete per pass-criteria (both modes green + full screenshot set)"
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
  local rc=0

  _info "pytest: src/tests/e2e/ (lifecycle + failure_injection_chaos + data_flow_seam — pre-existing, absorbed not duplicated) + tests/integration_live/ (the other 6 categories — see docs/testing/YTF.md Tier-C)"
  # FIND-B-TARGET: see the matching comment in run_tier_b() — empty-string
  # YASHIGANI_ADMIN_URL is safe (falsy in conftest.py's override check) and
  # avoids the bash-3.2 empty-array/set-u pitfall on macOS's default bash.
  YASHIGANI_ADMIN_URL="$TARGET" \
  YTF_RUNTIME="$RUNTIME" YTF_VERSION="$VERSION" YTF_PLATFORM="$PLATFORM" \
  PYTHONPATH="${REPO_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}" \
    "$VENV_PY" -m pytest "${REPO_DIR}/src/tests/e2e" "${REPO_DIR}/tests/integration_live" \
    -q --tb=short --junitxml="${evidence_dir}/pytest-junit.xml" \
    | tee "${evidence_dir}/pytest.log" || rc=1

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
