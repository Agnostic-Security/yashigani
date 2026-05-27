# Last updated: 2026-05-27T00:00:00+00:00
"""
Contract tests for v2.25.0 P2 k8s install CRITICAL findings.

B1 — GAP 1: k8s install path never wrote .yashigani-install-state
    Without the state file, uninstall.sh falls through to podman/docker
    auto-detect and never reaches _teardown_k8s. Operator sees clean exit
    while Helm release + PKI Secrets all survive.

    Fix: install.sh k8s path now writes the state file after k8s_print_access,
    including RUNTIME=k8s, NAMESPACE, HELM_RELEASE, INSTALL_UID, INSTALL_USER,
    INSTALL_TIMESTAMP, YASHIGANI_VERSION.

    Symmetry fix in uninstall.sh: state-file reader now also reads NAMESPACE
    and HELM_RELEASE and populates YASHIGANI_NAMESPACE / YASHIGANI_HELM_RELEASE
    so _teardown_k8s uses the correct namespace, not the default "yashigani".

B2 — GAP 2: .env.helm was never written by any code path
    k8s_helm_install checked for .env.helm and warned if absent, then deployed
    with chart defaults. Every k8s install produced a functionally misconfigured
    system (empty tlsDomain, no upstream URL, random AES key from Helm).

    Fix: _write_helm_values() generates .env.helm from operator flags before
    k8s_helm_dep_update. k8s_helm_install now exits 1 if the file is absent
    (error, not warn). AES key is pre-seeded into the backoffice K8s Secret
    so Helm's lookup() preserves it instead of generating a random key.

These tests operate on the static script text. Live k8s cluster verification
is documented as deferred to the next wave (no k8s cluster available in this
test environment). The static contracts are sufficient to verify correctness
of the call chain, state-file write site, and _write_helm_values logic.
"""
from __future__ import annotations

import re
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"
UNINSTALL_SH = REPO_ROOT / "uninstall.sh"


def _read_install() -> str:
    return INSTALL_SH.read_text(encoding="utf-8")


def _read_uninstall() -> str:
    return UNINSTALL_SH.read_text(encoding="utf-8")


def _main_k8s_block(script: str) -> str:
    """Return the k8s block from main() — the LAST occurrence of the k8s mode check.

    There are multiple 'if [[ "$MODE" == "k8s" ]]; then' occurrences in install.sh
    (parse_args, TOTAL_STEPS, platform summary, main). We want the main() one which
    is the last occurrence.

    The block ends at the matching '\\n  else\\n' that begins the compose path.
    """
    needle = 'if [[ "$MODE" == "k8s" ]]; then'
    # Find the last occurrence (main())
    pos = 0
    last = -1
    while True:
        found = script.find(needle, pos)
        if found == -1:
            break
        last = found
        pos = found + 1
    assert last != -1, f"'{needle}' not found in install.sh"
    # Find the matching else (compose path starts here)
    else_pos = script.find('\n  else\n', last)
    assert else_pos != -1, "else clause after main() k8s block not found"
    return script[last:else_pos]


# ===========================================================================
# B1 — State file written by k8s install path (install.sh side)
# ===========================================================================

class TestB1StateFileInstallSide:
    """install.sh k8s path must write .yashigani-install-state."""

    def test_state_file_written_in_k8s_block(self):
        """State file write must appear inside the MODE==k8s if block.

        The write must be AFTER k8s_print_access and BEFORE the 'else' that
        starts the compose path.
        """
        script = _read_install()
        k8s_block = _main_k8s_block(script)
        assert '.yashigani-install-state' in k8s_block, (
            ".yashigani-install-state write not found in k8s block "
            "(write must happen inside the MODE==k8s if block)"
        )

    def test_state_file_runtime_is_k8s(self):
        """State file write must set RUNTIME=k8s (not a variable)."""
        script = _read_install()
        k8s_block = _main_k8s_block(script)
        assert "printf 'RUNTIME=%s\\n'" in k8s_block, (
            "State file write does not use printf 'RUNTIME=%s\\n' form"
        )
        assert '"k8s"' in k8s_block, (
            'State file write does not write literal "k8s" as RUNTIME value'
        )

    def test_state_file_includes_namespace(self):
        """State file write must include NAMESPACE so uninstall can read it."""
        script = _read_install()
        k8s_block = _main_k8s_block(script)
        assert "printf 'NAMESPACE=%s\\n'" in k8s_block, (
            "State file write does not include NAMESPACE key"
        )
        assert '"${NAMESPACE}"' in k8s_block or '"$NAMESPACE"' in k8s_block, (
            "State file write does not use $NAMESPACE variable for NAMESPACE value"
        )

    def test_state_file_includes_helm_release(self):
        """State file write must include HELM_RELEASE."""
        script = _read_install()
        k8s_block = _main_k8s_block(script)
        assert "printf 'HELM_RELEASE=%s\\n'" in k8s_block, (
            "State file write does not include HELM_RELEASE key"
        )

    def test_state_file_includes_install_uid_and_user(self):
        """State file write must include INSTALL_UID and INSTALL_USER."""
        script = _read_install()
        k8s_block = _main_k8s_block(script)
        assert "printf 'INSTALL_UID=%s\\n'" in k8s_block, (
            "State file write does not include INSTALL_UID"
        )
        assert "printf 'INSTALL_USER=%s\\n'" in k8s_block, (
            "State file write does not include INSTALL_USER"
        )

    def test_state_file_write_gated_on_not_dry_run(self):
        """State file write must be inside a DRY_RUN guard so dry runs stay clean."""
        script = _read_install()
        k8s_block = _main_k8s_block(script)
        # Search for the actual redirect write (not the comment mention)
        write_pos = k8s_block.find('> "${WORK_DIR}/docker/.yashigani-install-state"')
        assert write_pos != -1, "Actual state file redirect not found in k8s block"
        # The state file write must be preceded by a DRY_RUN guard
        preceding = k8s_block[max(0, write_pos - 800):write_pos]
        assert 'DRY_RUN' in preceding and '"true"' in preceding, (
            "State file write is not inside a DRY_RUN != true guard"
        )

    def test_state_file_write_after_k8s_print_access(self):
        """State file must be written AFTER k8s_print_access (last user-visible step)."""
        script = _read_install()
        k8s_block = _main_k8s_block(script)
        print_access_pos = k8s_block.find('k8s_print_access')
        state_write_pos = k8s_block.find('.yashigani-install-state')
        assert print_access_pos != -1, "k8s_print_access call not in k8s block"
        assert state_write_pos != -1, "state file write not in k8s block"
        assert state_write_pos > print_access_pos, (
            "State file write must come AFTER k8s_print_access"
        )

    def test_state_file_write_uses_mkdir_p(self):
        """State file write must mkdir -p the docker/ dir in case it doesn't exist on k8s."""
        script = _read_install()
        k8s_block = _main_k8s_block(script)
        # Search for the actual redirect write (not the comment mention)
        write_pos = k8s_block.find('> "${WORK_DIR}/docker/.yashigani-install-state"')
        assert write_pos != -1, "Actual state file redirect not found in k8s block"
        # Look at the 600 chars before the write for mkdir -p
        preceding = k8s_block[max(0, write_pos - 600):write_pos]
        assert 'mkdir -p' in preceding, (
            "State file write does not mkdir -p the docker/ directory first"
        )

    def test_state_file_chmod_0644(self):
        """State file must be chmod 0644 — uninstall.sh may run as different user."""
        script = _read_install()
        k8s_block = _main_k8s_block(script)
        # Search for the actual redirect write (not the comment mention)
        write_pos = k8s_block.find('> "${WORK_DIR}/docker/.yashigani-install-state"')
        assert write_pos != -1, "Actual state file redirect not found in k8s block"
        # chmod 0644 follows within 200 chars after the redirect
        following = k8s_block[write_pos:write_pos + 200]
        assert '0644' in following, (
            "State file chmod 0644 not found after state file write redirect"
        )


# ===========================================================================
# B1 — State file read by uninstall.sh (uninstall.sh side)
# ===========================================================================

class TestB1StateFileUninstallSide:
    """uninstall.sh must read NAMESPACE and HELM_RELEASE from the state file."""

    def test_state_file_reads_namespace(self):
        """State file reader must read NAMESPACE key from the file."""
        script = _read_uninstall()
        # Find the state file parsing block
        state_block_start = script.find('if [ -f "$_STATE_FILE" ]')
        assert state_block_start != -1, "State file reader block not found"
        state_block_end = script.find('\nfi\n', state_block_start)
        state_block = script[state_block_start:state_block_end + 4]

        assert 'NAMESPACE=' in state_block, (
            "State file reader does not read NAMESPACE key"
        )
        assert '_state_namespace' in state_block, (
            "_state_namespace variable not found in state file reader"
        )

    def test_state_file_reads_helm_release(self):
        """State file reader must read HELM_RELEASE key from the file."""
        script = _read_uninstall()
        state_block_start = script.find('if [ -f "$_STATE_FILE" ]')
        state_block_end = script.find('\nfi\n', state_block_start)
        state_block = script[state_block_start:state_block_end + 4]

        assert 'HELM_RELEASE=' in state_block, (
            "State file reader does not read HELM_RELEASE key"
        )
        assert '_state_helm_release' in state_block, (
            "_state_helm_release variable not found in state file reader"
        )

    def test_yashigani_namespace_populated_from_state_file(self):
        """YASHIGANI_NAMESPACE must be set from state file when not already set."""
        script = _read_uninstall()
        state_block_start = script.find('if [ -f "$_STATE_FILE" ]')
        state_block_end = script.find('\nfi\n', state_block_start)
        state_block = script[state_block_start:state_block_end + 4]

        assert 'YASHIGANI_NAMESPACE=' in state_block, (
            "YASHIGANI_NAMESPACE not populated from state file reader"
        )

    def test_yashigani_helm_release_populated_from_state_file(self):
        """YASHIGANI_HELM_RELEASE must be set from state file when not already set."""
        script = _read_uninstall()
        state_block_start = script.find('if [ -f "$_STATE_FILE" ]')
        state_block_end = script.find('\nfi\n', state_block_start)
        state_block = script[state_block_start:state_block_end + 4]

        assert 'YASHIGANI_HELM_RELEASE=' in state_block, (
            "YASHIGANI_HELM_RELEASE not populated from state file reader"
        )

    def test_namespace_only_populated_for_k8s_runtime(self):
        """NAMESPACE/HELM_RELEASE population must be gated on k8s state runtime.

        We must not set YASHIGANI_NAMESPACE from a state file written by a
        compose/podman install (those installs don't have a meaningful namespace).
        """
        script = _read_uninstall()
        state_block_start = script.find('if [ -f "$_STATE_FILE" ]')
        state_block_end = script.find('\nfi\n', state_block_start)
        state_block = script[state_block_start:state_block_end + 4]

        # The YASHIGANI_NAMESPACE assignment must be inside a k8s-specific guard
        ns_assign_pos = state_block.find('YASHIGANI_NAMESPACE=')
        assert ns_assign_pos != -1, "YASHIGANI_NAMESPACE assignment not found"
        # Check there is a k8s guard before the assignment within the state block
        preceding = state_block[0:ns_assign_pos]
        assert '"k8s"' in preceding or "'k8s'" in preceding, (
            "YASHIGANI_NAMESPACE assignment is not gated on k8s state runtime"
        )

    def test_env_var_override_takes_precedence_over_state_file(self):
        """Operator's YASHIGANI_NAMESPACE env var must take precedence over state file.

        If the operator has set YASHIGANI_NAMESPACE explicitly, don't overwrite it.
        """
        script = _read_uninstall()
        state_block_start = script.find('if [ -f "$_STATE_FILE" ]')
        state_block_end = script.find('\nfi\n', state_block_start)
        state_block = script[state_block_start:state_block_end + 4]

        # The assignment must be inside a guard: -z "${YASHIGANI_NAMESPACE:-}"
        ns_assign_pos = state_block.find('YASHIGANI_NAMESPACE=')
        surrounding = state_block[max(0, ns_assign_pos - 200):ns_assign_pos]
        assert 'YASHIGANI_NAMESPACE' in surrounding, (
            "YASHIGANI_NAMESPACE assignment not guarded by -z check on existing value"
        )


# ===========================================================================
# B2 — _write_helm_values function (install.sh)
# ===========================================================================

class TestB2WriteHelmValues:
    """_write_helm_values must exist and generate .env.helm correctly."""

    def test_function_exists(self):
        """_write_helm_values function must be defined."""
        script = _read_install()
        assert '_write_helm_values()' in script, (
            "_write_helm_values function not defined in install.sh"
        )

    def test_function_writes_global_tls_domain(self):
        """_write_helm_values must write global.tlsDomain."""
        script = _read_install()
        fn_start = script.find('_write_helm_values()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        assert 'tlsDomain' in fn_body, (
            "_write_helm_values does not write global.tlsDomain"
        )
        assert 'DOMAIN' in fn_body, (
            "_write_helm_values does not use $DOMAIN for tlsDomain"
        )

    def test_function_writes_global_tls_mode(self):
        """_write_helm_values must write global.tlsMode."""
        script = _read_install()
        fn_start = script.find('_write_helm_values()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        assert 'tlsMode' in fn_body, (
            "_write_helm_values does not write global.tlsMode"
        )

    def test_function_writes_global_acme_email(self):
        """_write_helm_values must write global.acmeEmail from ADMIN_EMAIL."""
        script = _read_install()
        fn_start = script.find('_write_helm_values()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        assert 'acmeEmail' in fn_body, (
            "_write_helm_values does not write global.acmeEmail"
        )
        assert 'ADMIN_EMAIL' in fn_body, (
            "_write_helm_values does not use $ADMIN_EMAIL for acmeEmail"
        )

    def test_function_writes_gateway_upstream_url(self):
        """_write_helm_values must write gateway.env.upstreamUrl."""
        script = _read_install()
        fn_start = script.find('_write_helm_values()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        assert 'upstreamUrl' in fn_body, (
            "_write_helm_values does not write gateway.env.upstreamUrl"
        )
        assert 'UPSTREAM_URL' in fn_body, (
            "_write_helm_values does not use $UPSTREAM_URL for upstreamUrl"
        )

    def test_function_writes_fips_mode(self):
        """_write_helm_values must write fips.mode based on FIPS_MODE."""
        script = _read_install()
        fn_start = script.find('_write_helm_values()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        assert 'fips' in fn_body, (
            "_write_helm_values does not write fips.mode"
        )
        assert 'FIPS_MODE' in fn_body, (
            "_write_helm_values does not check FIPS_MODE"
        )

    def test_function_handles_license_key_file(self):
        """_write_helm_values must handle LICENSE_KEY_PATH — read file and write to values."""
        script = _read_install()
        fn_start = script.find('_write_helm_values()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        assert 'LICENSE_KEY_PATH' in fn_body, (
            "_write_helm_values does not handle LICENSE_KEY_PATH"
        )
        assert 'licenseKey' in fn_body, (
            "_write_helm_values does not write licensing.licenseKey"
        )

    def test_function_creates_file_with_0600(self):
        """_write_helm_values must set file permissions to 0600 (may contain license key)."""
        script = _read_install()
        fn_start = script.find('_write_helm_values()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        assert '0600' in fn_body, (
            "_write_helm_values does not set 0600 permissions on .env.helm"
        )

    def test_function_handles_dry_run(self):
        """_write_helm_values must short-circuit on DRY_RUN=true."""
        script = _read_install()
        fn_start = script.find('_write_helm_values()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        assert 'DRY_RUN' in fn_body, (
            "_write_helm_values does not handle DRY_RUN mode"
        )

    def test_function_preseeds_aes_key_into_k8s_secret(self):
        """_write_helm_values must pre-seed DB_AES_KEY into K8s Secret before helm install.

        This is the workaround for the Captain schema change (backoffice.dbAesKey
        not yet in values.yaml). Pre-seeding ensures Helm's lookup() preserves
        the operator-generated key rather than generating randAlphaNum.
        """
        script = _read_install()
        fn_start = script.find('_write_helm_values()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        assert 'DB_AES_KEY' in fn_body, (
            "_write_helm_values does not handle DB_AES_KEY"
        )
        assert 'kubectl create secret' in fn_body or 'kubectl apply' in fn_body, (
            "_write_helm_values does not pre-seed K8s Secret with AES key"
        )

    def test_function_called_before_helm_dep_update(self):
        """_write_helm_values must be called BEFORE k8s_helm_dep_update in main()."""
        script = _read_install()
        k8s_block = _main_k8s_block(script)

        import re
        # Find the call lines (not comment mentions)
        helm_match = re.search(r'^\s+_write_helm_values\b', k8s_block, re.MULTILINE)
        dep_match = re.search(r'^\s+k8s_helm_dep_update\b', k8s_block, re.MULTILINE)
        assert helm_match is not None, "_write_helm_values call line not found in k8s block"
        assert dep_match is not None, "k8s_helm_dep_update call line not found in k8s block"
        assert helm_match.start() < dep_match.start(), (
            "_write_helm_values must be called BEFORE k8s_helm_dep_update"
        )

    def test_function_called_after_write_aes_key_to_env(self):
        """_write_helm_values must be called AFTER _write_aes_key_to_env (DB_AES_KEY must be set).

        We look for the standalone call line (leading whitespace + function name),
        not mentions in comments, to get the actual call order.
        """
        script = _read_install()
        k8s_block = _main_k8s_block(script)

        import re
        # Find the call line (not comment mentions)
        aes_match = re.search(r'^\s+_write_aes_key_to_env\b', k8s_block, re.MULTILINE)
        helm_match = re.search(r'^\s+_write_helm_values\b', k8s_block, re.MULTILINE)
        assert aes_match is not None, "_write_aes_key_to_env call line not found in k8s block"
        assert helm_match is not None, "_write_helm_values call line not found in k8s block"
        assert helm_match.start() > aes_match.start(), (
            "_write_helm_values must come AFTER _write_aes_key_to_env "
            "(DB_AES_KEY must be populated before pre-seeding)"
        )


# ===========================================================================
# B2 — k8s_helm_install gates on .env.helm existence (error, not warn)
# ===========================================================================

class TestB2HelmInstallGate:
    """k8s_helm_install must exit 1 when .env.helm is absent (B2-fix)."""

    def test_helm_install_errors_not_warns_on_missing_values(self):
        """k8s_helm_install must call log_error (not log_warn) when values file absent."""
        script = _read_install()
        fn_start = script.find('k8s_helm_install()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        # Find the values file check block
        # Must NOT contain "log_warn" for the absent-values-file condition
        # Must contain "log_error" + "exit 1" for that condition
        helm_values_check_pos = fn_body.find('helm_values')
        assert helm_values_check_pos != -1, "helm_values variable not found in k8s_helm_install"

        # Within the function, the absent-file branch must use exit 1
        # (not the old log_warn + continue pattern)
        assert 'exit 1' in fn_body, (
            "k8s_helm_install does not exit 1 when .env.helm is absent"
        )

    def test_helm_install_old_warn_path_removed(self):
        """The old 'log_warn ... using chart defaults' path must be gone."""
        script = _read_install()
        fn_start = script.find('k8s_helm_install()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        assert 'using chart defaults' not in fn_body, (
            "Old 'using chart defaults' warn path is still present in k8s_helm_install — "
            "it must be replaced with the exit 1 error path (B2-fix)"
        )

    def test_fips_injection_still_present(self):
        """FIPS_MODE --set injection must still fire after B2 fix.

        The existing Iris drift gate fix (d8ef0fc) must not be removed.
        """
        script = _read_install()
        fn_start = script.find('k8s_helm_install()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        assert 'fips.mode=true' in fn_body, (
            "FIPS_MODE --set injection removed from k8s_helm_install — "
            "Iris drift gate fix d8ef0fc must be preserved"
        )
        assert 'FIPS_MODE' in fn_body, (
            "FIPS_MODE check removed from k8s_helm_install"
        )
        assert 'FIPS_MODE=1' in fn_body or '"1"' in fn_body, (
            "FIPS_MODE=1 condition removed from k8s_helm_install"
        )

    def test_fips_log_message_preserved(self):
        """The operator-visible FIPS_MODE=1 log message must be preserved."""
        script = _read_install()
        fn_start = script.find('k8s_helm_install()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        assert 'FIPS_MODE=1' in fn_body, (
            "FIPS_MODE=1 operator log message removed from k8s_helm_install"
        )

    def test_helm_values_file_loaded_with_f_flag(self):
        """k8s_helm_install must pass -f .env.helm to the helm invocation."""
        script = _read_install()
        fn_start = script.find('k8s_helm_install()')
        fn_end = script.find('\n}\n', fn_start)
        fn_body = script[fn_start:fn_end]

        assert 'helm_args+=(-f "$helm_values")' in fn_body, (
            "k8s_helm_install does not add -f .env.helm to helm_args"
        )


# ===========================================================================
# Regression — compose state file write unchanged
# ===========================================================================

class TestRegressionComposeStateFile:
    """Verify compose-path state file write is not affected by k8s B1 fix."""

    def _compose_block(self, script: str) -> str:
        """Return the compose else-block from main()."""
        needle = 'if [[ "$MODE" == "k8s" ]]; then'
        pos = 0
        last = -1
        while True:
            found = script.find(needle, pos)
            if found == -1:
                break
            last = found
            pos = found + 1
        else_start = script.find('\n  else\n', last)
        # fi closes the if/else block — find it after else
        fi_end = script.find('\n  fi\n', else_start)
        return script[else_start:fi_end]

    def test_compose_state_file_still_written(self):
        """Compose path must still write the state file at step 12b."""
        script = _read_install()
        compose_block = self._compose_block(script)
        assert '.yashigani-install-state' in compose_block, (
            "Compose path state file write removed (regression) — "
            "compose-path write must remain at step 12b"
        )

    def test_compose_state_file_runtime_not_hardcoded_k8s(self):
        """Compose-path state file must NOT hardcode RUNTIME=k8s."""
        script = _read_install()
        compose_block = self._compose_block(script)
        state_write_pos = compose_block.find('.yashigani-install-state')
        surrounding = compose_block[state_write_pos:state_write_pos + 500]
        # The compose write uses ${RUNTIME:-...} variable, not literal "k8s"
        assert '"k8s"' not in surrounding[:200], (
            "Compose state file write hardcodes RUNTIME=k8s (regression)"
        )
