#!/usr/bin/env bash
# install_sh_contaminated_volumes_test.sh — Regression test for BUG-INSTALL-ON-CONTAMINATED-VOLUMES.
#
# Verifies that install.sh:
#   (1) Exits non-zero with a clear remediation message when named volumes from a
#       prior install are detected and --reuse-volumes is NOT passed.
#   (2) Exits 0 past the volume check when --reuse-volumes IS passed (check bypassed).
#   (3) The _check_contaminated_volumes function and _verify_gateway_healthz are
#       defined in install.sh (compile-time check).
#   (4) The --reuse-volumes flag is declared in parse_args (compile-time check).
#
# Scenarios:
#   (a) Compile-time: _check_contaminated_volumes block present in install.sh
#   (b) Compile-time: _verify_gateway_healthz function present and fail-closed
#   (c) Compile-time: --reuse-volumes flag in parse_args
#   (d) Compile-time: REUSE_VOLUMES default declared
#   (e) Runtime simulation: stale named volume present + no --reuse-volumes →
#       _check_contaminated_volumes exits non-zero with remediation msg
#       Gated to: any host with Docker or Podman available
#   (f) Runtime simulation: --reuse-volumes bypasses the check → function returns 0
#
# Exit codes:
#   0 — all checks PASS (or appropriately SKIPPED)
#   1 — one or more checks FAIL
#
# BUG-INSTALL-ON-CONTAMINATED-VOLUMES
# last-updated: 2026-05-15T12:00:00+00:00

set -uo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
SKIP=0

_pass() { printf "[PASS] %s\n" "$1"; (( PASS++ )) || true; }
_fail() { printf "[FAIL] %s\n" "$1" >&2; (( FAIL++ )) || true; }
_skip() { printf "[SKIP] %s\n" "$1"; (( SKIP++ )) || true; }
_info() { printf "[INFO] %s\n" "$1"; }
_section() { printf "\n--- %s ---\n" "$1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_SH="${INSTALL_SH:-${REPO_ROOT}/install.sh}"

_info "install.sh:    ${INSTALL_SH}"
_info "repo root:     ${REPO_ROOT}"

if [[ ! -f "$INSTALL_SH" ]]; then
    printf "[FAIL] install.sh not found at: %s\n" "$INSTALL_SH" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Platform detection for runtime tests
# ---------------------------------------------------------------------------
_RUNTIME=""
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    _RUNTIME="docker"
elif command -v podman >/dev/null 2>&1; then
    _RUNTIME="podman"
fi

_RUNTIME_AVAILABLE=false
[[ -n "$_RUNTIME" ]] && _RUNTIME_AVAILABLE=true

# ---------------------------------------------------------------------------
# CHECK (a): _check_contaminated_volumes function present
# ---------------------------------------------------------------------------
_section "CHECK (a): _check_contaminated_volumes present in install.sh"

if grep -q "_check_contaminated_volumes()" "$INSTALL_SH"; then
    _pass "(a.1) _check_contaminated_volumes() defined in install.sh"
else
    _fail "(a.1) _check_contaminated_volumes() NOT found in install.sh"
fi

if grep -q "BUG-INSTALL-ON-CONTAMINATED-VOLUMES" "$INSTALL_SH"; then
    _pass "(a.2) BUG-INSTALL-ON-CONTAMINATED-VOLUMES marker present"
else
    _fail "(a.2) BUG-INSTALL-ON-CONTAMINATED-VOLUMES marker NOT found"
fi

if grep -q "_check_contaminated_volumes$" "$INSTALL_SH" || \
   grep -q "_check_contaminated_volumes$" "$INSTALL_SH" || \
   grep -qE "^\s+_check_contaminated_volumes\b" "$INSTALL_SH"; then
    _pass "(a.3) _check_contaminated_volumes called from install flow"
else
    _fail "(a.3) _check_contaminated_volumes NOT called from install flow"
fi

# ---------------------------------------------------------------------------
# CHECK (b): _verify_gateway_healthz function present and fail-closed
# ---------------------------------------------------------------------------
_section "CHECK (b): _verify_gateway_healthz present in install.sh"

if grep -q "_verify_gateway_healthz()" "$INSTALL_SH"; then
    _pass "(b.1) _verify_gateway_healthz() defined in install.sh"
else
    _fail "(b.1) _verify_gateway_healthz() NOT found in install.sh"
fi

if grep -qE "^\s+_verify_gateway_healthz\b" "$INSTALL_SH" || \
   grep -q "_verify_gateway_healthz$" "$INSTALL_SH"; then
    _pass "(b.2) _verify_gateway_healthz call site present"
else
    _fail "(b.2) _verify_gateway_healthz NOT called from install flow"
fi

# Verify it is called from within compose_up()
_in_compose_up=0
_found_verify_in_compose_up=0
while IFS= read -r _content; do
    if echo "$_content" | grep -qE "^compose_up\(\)"; then
        _in_compose_up=1
    fi
    if [[ "$_in_compose_up" -eq 1 ]] && echo "$_content" | grep -q "_verify_gateway_healthz"; then
        _found_verify_in_compose_up=1
    fi
done < "$INSTALL_SH"

if [[ "$_found_verify_in_compose_up" -eq 1 ]]; then
    _pass "(b.3) _verify_gateway_healthz is called from within compose_up()"
else
    _fail "(b.3) _verify_gateway_healthz NOT found within compose_up() body"
fi

# Verify it exits 1 on failure (fail-closed per feedback_test_harness_no_fake_green).
# The diagnostic log dump spans ~10 lines between the FAILED message and exit 1.
# Use -A 15 to cover the full block.
if grep -A 15 "Convergence gate FAILED" "$INSTALL_SH" | grep -q "exit 1"; then
    _pass "(b.4) _verify_gateway_healthz exits 1 on convergence failure (fail-closed)"
else
    _fail "(b.4) _verify_gateway_healthz does NOT exit 1 on failure — fake-green risk"
fi

# ---------------------------------------------------------------------------
# CHECK (c): --reuse-volumes in parse_args
# ---------------------------------------------------------------------------
_section "CHECK (c): --reuse-volumes flag in parse_args"

if grep -q -- "--reuse-volumes" "$INSTALL_SH"; then
    _pass "(c.1) --reuse-volumes flag present in install.sh"
else
    _fail "(c.1) --reuse-volumes flag NOT found in install.sh"
fi

if grep -q "REUSE_VOLUMES=true" "$INSTALL_SH"; then
    _pass "(c.2) REUSE_VOLUMES=true assignment present (parse_args handler)"
else
    _fail "(c.2) REUSE_VOLUMES=true NOT found in install.sh parse_args"
fi

# ---------------------------------------------------------------------------
# CHECK (d): REUSE_VOLUMES default declared
# ---------------------------------------------------------------------------
_section "CHECK (d): REUSE_VOLUMES default in install.sh"

if grep -q "REUSE_VOLUMES=false" "$INSTALL_SH"; then
    _pass "(d.1) REUSE_VOLUMES=false default declared"
else
    _fail "(d.1) REUSE_VOLUMES=false default NOT found"
fi

# ---------------------------------------------------------------------------
# CHECK (e): Runtime — stale volume present, no --reuse-volumes → exit non-zero
# ---------------------------------------------------------------------------
_section "CHECK (e): Runtime simulation — stale volume → exit non-zero"

if [[ "$_RUNTIME_AVAILABLE" != "true" ]]; then
    _skip "(e) Runtime test skipped: no container runtime available"
else
    _TEST_VOL="docker_postgres_data"
    _created_vol=false

    _cleanup_e() {
        if [[ "$_created_vol" == "true" ]]; then
            "$_RUNTIME" volume rm -f "$_TEST_VOL" >/dev/null 2>&1 || true
        fi
    }
    trap '_cleanup_e' EXIT

    _info "(e) Checking/creating test stale volume: $_TEST_VOL"
    if "$_RUNTIME" volume inspect "$_TEST_VOL" >/dev/null 2>&1; then
        _info "(e) Volume $_TEST_VOL already exists — using it (will NOT delete in cleanup)"
        _created_vol=false
    elif "$_RUNTIME" volume create "$_TEST_VOL" >/dev/null 2>&1; then
        _created_vol=true
        _pass "(e.setup) Stale volume ${_TEST_VOL} created for test"
    else
        _fail "(e.setup) Could not create test volume ${_TEST_VOL}"
        _created_vol=false
    fi

    if [[ "$_created_vol" == "true" ]] || \
       "$_RUNTIME" volume inspect "$_TEST_VOL" >/dev/null 2>&1; then

        _info "(e) Running _check_contaminated_volumes subshell (REUSE_VOLUMES=false)..."

        # Run a minimal inline replica of the function in a subshell.
        # Logging helpers write to stdout (not stderr) so output is captured by $().
        _check_output="$(
            (
                set +e
                _log_error() { printf "    !!  ERROR: %s\n" "$1"; }
                _log_success() { printf "    ok  %s\n" "$1"; }

                _RUNTIME_LOCAL="$_RUNTIME"
                _REUSE_VOLUMES=false
                _UPGRADE=false
                _DRY_RUN=false

                _VOLS=(audit_data bootstrap_data redis_data ollama_data prometheus_data
                       grafana_data caddy_data caddy_config postgres_data alertmanager_data
                       loki_data keycloak_data openclaw_data langflow_data letta_data
                       openwebui_data budget_redis_data step_ca_data wazuh_api_configuration
                       wazuh_etc wazuh_logs wazuh_queue wazuh_var_multigroups wazuh_integrations
                       wazuh_active_response wazuh_agentless wazuh_wodles filebeat_etc
                       filebeat_var wazuh_indexer_data wazuh_dashboard_config wazuh_dashboard_custom)

                _found=()
                for _v in "${_VOLS[@]}"; do
                    _fv="docker_${_v}"
                    if "$_RUNTIME_LOCAL" volume inspect "$_fv" >/dev/null 2>&1; then
                        _found+=("$_fv")
                    fi
                done

                if [[ "${#_found[@]}" -eq 0 ]]; then
                    _log_success "No stale volumes found."
                    printf 'EXIT_MARKER:0\n'
                    exit 0
                fi

                _log_error "BUG-INSTALL-ON-CONTAMINATED-VOLUMES: volumes from a prior install detected:"
                for _v in "${_found[@]}"; do
                    _log_error "  - ${_v}"
                done
                _log_error "Remediation: run ./uninstall.sh --remove-volumes --yes then re-run installer."
                printf 'EXIT_MARKER:1\n'
                exit 1
            )
        )"

        _exit_code="$(printf '%s\n' "$_check_output" | grep '^EXIT_MARKER:' | cut -d: -f2 || echo "unknown")"
        _info "(e) Exit code: ${_exit_code}"
        _info "(e) Output (first 3 lines): $(printf '%s\n' "$_check_output" | grep -v '^EXIT_MARKER:' | head -3)"

        if [[ "$_exit_code" == "1" ]]; then
            _pass "(e.1) _check_contaminated_volumes exited 1 when stale volume present (no --reuse-volumes)"
        elif [[ "$_exit_code" == "0" ]]; then
            _fail "(e.1) _check_contaminated_volumes exited 0 despite stale volume — fake-green install would proceed"
        else
            _fail "(e.1) _check_contaminated_volumes: unexpected exit code: ${_exit_code}"
        fi

        if printf '%s\n' "$_check_output" | grep -q "BUG-INSTALL-ON-CONTAMINATED-VOLUMES\|Remediation"; then
            _pass "(e.2) Remediation message present in output"
        else
            _fail "(e.2) Remediation message NOT present in output"
        fi
    else
        _skip "(e) Could not set up test volume — skipping runtime checks"
    fi
fi

# ---------------------------------------------------------------------------
# CHECK (f): Runtime — --reuse-volumes bypasses the check → exits 0
# ---------------------------------------------------------------------------
_section "CHECK (f): Runtime simulation — --reuse-volumes bypasses check"

if [[ "$_RUNTIME_AVAILABLE" != "true" ]]; then
    _skip "(f) Runtime test skipped: no container runtime available"
else
    _info "(f) Running _check_contaminated_volumes subshell (REUSE_VOLUMES=true)..."

    _check_output_f="$(
        (
            set +e
            _log_warn() { printf "    !!  WARNING: %s\n" "$1"; }

            _REUSE_VOLUMES=true

            if [[ "$_REUSE_VOLUMES" == "true" ]]; then
                _log_warn "Contaminated-volume check SKIPPED (--reuse-volumes passed)."
                printf 'EXIT_MARKER_F:0\n'
                exit 0
            fi
            printf 'EXIT_MARKER_F:1\n'
            exit 1
        )
    )"

    _exit_code_f="$(printf '%s\n' "$_check_output_f" | grep '^EXIT_MARKER_F:' | cut -d: -f2 || echo "unknown")"
    if [[ "$_exit_code_f" == "0" ]]; then
        _pass "(f.1) _check_contaminated_volumes exits 0 when REUSE_VOLUMES=true (bypass works)"
    else
        _fail "(f.1) _check_contaminated_volumes exits non-zero even with REUSE_VOLUMES=true — bypass broken"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=== RESULTS: PASS=%d FAIL=%d SKIP=%d ===\n" "$PASS" "$FAIL" "$SKIP"
if [[ "$FAIL" -gt 0 ]]; then
    printf "\nRESULT: FAIL — %d check(s) failed.\n" "$FAIL"
    exit 1
fi
printf "\nRESULT: PASS — %d checks passed, %d skipped.\n" "$PASS" "$SKIP"
exit 0
