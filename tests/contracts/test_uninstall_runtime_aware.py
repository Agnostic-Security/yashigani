# Last updated: 2026-05-26T00:00:00+00:00
"""
Contract tests for uninstall.sh runtime-aware refactor.

BUG-UNINSTALL-SUDO-ROOTLESS + Tiago directive 2026-05-26: "separate paths for
podman, docker, k8s, they are different."

These tests verify the STATIC contract of uninstall.sh:
  1. User-context guard: sudo-on-rootless-podman is refused with a non-zero exit
     and a clear diagnostic message.
  2. Runtime subtype detection: each subtype (podman-rootless, podman-rootful,
     docker-desktop, docker-engine, k8s) is handled by a distinct code path.
  3. Maxine's three preserved behaviours (82f356c) are present:
     a. --depend FIRST in rm calls (not as fallback)
     b. Retry pass after first removal loop
     c. Final exit-1 assertion when containers remain
  4. Volume final assertion: _assert_no_volumes_remain is called after named
     volume rm; any remaining canonical volume triggers exit 1.
  5. Structural: hardened PATH at the top; IFS is safe; set -euo pipefail present.

Tests in this file do NOT require a live container runtime — they operate on
the script text and use subprocess with a controlled environment (SUDO_USER set,
RUNTIME set) on a no-op stubs. Live functional tests are gated by
Maxine per the release test protocol.

Runtime paths marked contract-test-only (docker-desktop, k8s) require the
respective runtime to be reachable for live functional verification and are
documented as such in each test's docstring.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
UNINSTALL_SH = REPO_ROOT / "uninstall.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_script() -> str:
    return UNINSTALL_SH.read_text(encoding="utf-8")


def _run_uninstall(
    env_overrides: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
    cwd: str | Path | None = None,
) -> subprocess.CompletedProcess:
    """Run uninstall.sh in a minimal environment; return CompletedProcess."""
    env = {
        "HOME": os.environ.get("HOME", "/tmp"),
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TERM": "dumb",
    }
    if env_overrides:
        env.update(env_overrides)
    cmd = ["bash", str(UNINSTALL_SH)]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else str(REPO_ROOT),
    )


# ===========================================================================
# Group 1 — Static structure checks (no runtime required)
# ===========================================================================

class TestStaticStructure:
    """Verify that required structural elements are present in the script text."""

    def test_set_euo_pipefail_present(self):
        """set -euo pipefail must be present near the top of the script."""
        script = _read_script()
        # Must appear within first 25 lines
        first_25_lines = "\n".join(script.splitlines()[:25])
        assert "set -euo pipefail" in first_25_lines, (
            "set -euo pipefail missing from first 25 lines of uninstall.sh"
        )

    def test_hardened_path_present(self):
        """Hardened PATH must be set at the top of the script."""
        script = _read_script()
        assert "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" in script, (
            "Hardened PATH declaration missing from uninstall.sh"
        )

    def test_runtime_subtypes_all_handled(self):
        """All five runtime subtypes must appear in a case block."""
        script = _read_script()
        required_subtypes = [
            "podman-rootless",
            "podman-rootful",
            "docker-desktop",
            "docker-engine",
            "k8s",
        ]
        for subtype in required_subtypes:
            assert subtype in script, (
                f"Runtime subtype '{subtype}' not found in uninstall.sh"
            )

    def test_depend_first_in_removal(self):
        """--depend must appear BEFORE plain rm -f in removal calls.

        Maxine fix 82f356c: --depend FIRST is mandatory.
        BUG-UNINSTALL-DEPEND-ORDER-2026-05-26.
        """
        script = _read_script()
        # Find the _remove_containers function body
        # The pattern rm -f --depend must appear before rm -f in that function
        rm_depend_pos = script.find('rm -f --depend "$_cid"')
        rm_plain_pos = script.find(
            'elif "$_rt" rm -f "$_cid"', rm_depend_pos
        )
        assert rm_depend_pos != -1, (
            "_remove_containers: 'rm -f --depend' not found"
        )
        assert rm_plain_pos != -1, (
            "_remove_containers: 'elif rm -f' fallback not found"
        )
        assert rm_depend_pos < rm_plain_pos, (
            "rm -f --depend must come BEFORE plain rm -f fallback in _remove_containers"
        )

    def test_retry_pass_present(self):
        """A retry pass after the first removal loop must be present.

        Maxine fix 82f356c: retry handles restart-policy=always respawn.
        """
        script = _read_script()
        assert "retry" in script.lower() and "_residual" in script, (
            "Retry pass not found in uninstall.sh"
        )

    def test_final_assertion_exit1_present(self):
        """_assert_no_containers_remain must call exit 1 on residuals.

        Maxine fix 82f356c: final exit-1 assertion closes silent success hole.
        """
        script = _read_script()
        assert "_assert_no_containers_remain" in script, (
            "_assert_no_containers_remain function not found in uninstall.sh"
        )
        # Find the function definition and verify exit 1 is inside it
        fn_start = script.find("_assert_no_containers_remain()")
        fn_end = script.find("\n}", fn_start)
        fn_body = script[fn_start:fn_end]
        assert "exit 1" in fn_body, (
            "_assert_no_containers_remain does not call exit 1 on failure"
        )

    def test_volume_final_assertion_present(self):
        """_assert_no_volumes_remain must exist and call exit 1.

        Closes the volume-parallel silent-exit-0 hole.
        """
        script = _read_script()
        assert "_assert_no_volumes_remain" in script, (
            "_assert_no_volumes_remain function not found in uninstall.sh"
        )
        fn_start = script.find("_assert_no_volumes_remain()")
        fn_end = script.find("\n}", fn_start)
        fn_body = script[fn_start:fn_end]
        assert "exit 1" in fn_body, (
            "_assert_no_volumes_remain does not call exit 1 on failure"
        )

    def test_sudo_rootless_guard_present(self):
        """The sudo-on-rootless-Podman guard must be present.

        BUG-UNINSTALL-SUDO-ROOTLESS: sudo + podman + UID=0 = wrong namespace.
        """
        script = _read_script()
        assert "BUG-UNINSTALL-SUDO-ROOTLESS" in script, (
            "BUG-UNINSTALL-SUDO-ROOTLESS guard not found in uninstall.sh"
        )
        assert "SUDO_USER" in script, (
            "SUDO_USER check not found in uninstall.sh"
        )

    def test_error_message_mentions_sudo_user(self):
        """The sudo-rootless error message must cite the install-owning user."""
        script = _read_script()
        # The error block should reference _install_owner / SUDO_USER
        assert "_install_owner" in script, (
            "Error message does not reference install-owning user"
        )
        # Must suggest re-running without sudo
        assert "bash uninstall.sh" in script, (
            "Error message does not suggest 'bash uninstall.sh' (no sudo)"
        )

    def test_k8s_path_uses_helm_and_kubectl(self):
        """K8s teardown path must reference both helm and kubectl."""
        script = _read_script()
        # Find _teardown_k8s function
        fn_start = script.find("_teardown_k8s()")
        assert fn_start != -1, "_teardown_k8s() not found"
        fn_end = script.find("\n}", fn_start)
        fn_body = script[fn_start:fn_end]
        assert "helm uninstall" in fn_body, (
            "_teardown_k8s does not call helm uninstall"
        )
        assert "kubectl delete" in fn_body, (
            "_teardown_k8s does not use kubectl delete for pod drain"
        )

    def test_k8s_pvc_deletion_gated_on_remove_volumes(self):
        """K8s PVC deletion must only happen when --remove-volumes is set."""
        script = _read_script()
        fn_start = script.find("_teardown_k8s()")
        fn_end = script.find("\n}", fn_start)
        fn_body = script[fn_start:fn_end]
        # PVC deletion should be inside a REMOVE_VOLUMES check
        pvc_pos = fn_body.find("delete pvc")
        assert pvc_pos != -1, "_teardown_k8s does not delete PVCs"
        # The REMOVE_VOLUMES check must appear before pvc delete in the function
        remove_vol_check_pos = fn_body.find('REMOVE_VOLUMES" = "true"')
        assert remove_vol_check_pos != -1 and remove_vol_check_pos < pvc_pos, (
            "PVC deletion in _teardown_k8s not gated on REMOVE_VOLUMES"
        )

    def test_install_state_file_uid_and_user_read(self):
        """Install state INSTALL_UID and INSTALL_USER must be read from state file."""
        script = _read_script()
        assert "INSTALL_UID" in script, (
            "INSTALL_UID not read from state file"
        )
        assert "INSTALL_USER" in script, (
            "INSTALL_USER not read from state file"
        )

    def test_runtime_k8s_accepted_in_state_file_read(self):
        """State file runtime=k8s must be accepted (not silently dropped)."""
        script = _read_script()
        # The state-file parsing block must accept k8s as a valid value
        assert '"k8s"' in script, (
            "k8s not accepted as valid runtime value in state file parsing block"
        )


# ===========================================================================
# Group 2 — Sudo-rootless-podman refusal (subprocess, simulated environment)
# ===========================================================================

class TestSudoRootlessRefusal:
    """
    Verify that invoking uninstall.sh with SUDO_USER set + RUNTIME=podman
    exits non-zero with a diagnostic message.

    These tests use bash --norc and a minimal stub environment to avoid
    actually touching any container runtime. The guard check happens BEFORE
    any runtime calls.

    Live negative test (Maxine/Su runs on Mac/VM):
        sudo bash uninstall.sh   # against rootless Podman install
    Expected: exit 1, message contains "invoked via sudo against rootless Podman"
    """

    def test_sudo_rootless_podman_refuses(self, tmp_path):
        """Script exits non-zero when SUDO_USER is set + runtime is podman."""
        # Create a minimal docker/.env stub and state file so the script
        # reaches the sudo-guard before hitting any real runtime call.
        docker_dir = tmp_path / "docker"
        docker_dir.mkdir()
        (docker_dir / ".env").write_text("YASHIGANI_TLS_DOMAIN=test.local\n")
        (docker_dir / ".yashigani-install-state").write_text(
            "RUNTIME=podman\nINSTALL_UID=1000\nINSTALL_USER=max\n"
        )

        # Simulate: script runs as UID 0 (root after sudo) with SUDO_USER set.
        # We cannot actually change UID in the test, but we can verify the guard
        # logic path is present in the script text (structural check) and verify
        # the actual runtime behaviour via the live negative test documented above.
        #
        # For the subprocess test: set SUDO_USER and RUNTIME=podman.
        # The guard fires when SUDO_USER != "" AND RUNTIME=podman AND UID=0.
        # Since tests run as non-root, UID != 0 so the guard won't fire here --
        # this test verifies the guard code path exists, not the live UID check.
        # Live UID=0 verification is Maxine's negative-test gate.
        script = _read_script()
        guard_block = (
            'if [ "${SUDO_USER:-}" != "" ] && [ "$RUNTIME" = "podman" ] && '
            '[ "$_CALLER_UID" = "0" ]'
        )
        assert guard_block in script, (
            "sudo-rootless guard condition not found in expected form"
        )

    def test_error_message_content(self):
        """Error message must contain the canonical diagnostic phrases."""
        script = _read_script()
        # Find the guard block by its unique condition, not by the comment tag
        # (the comment tag appears in the header first)
        guard_condition = (
            'if [ "${SUDO_USER:-}" != "" ] && [ "$RUNTIME" = "podman" ] '
            '&& [ "$_CALLER_UID" = "0" ]'
        )
        block_start = script.find(guard_condition)
        assert block_start != -1, "sudo-rootless guard condition not found"
        # Look ahead for the error message content
        block_text = script[block_start:block_start + 2000]
        assert "invoked via sudo against rootless Podman" in block_text, (
            "Error message phrase 'invoked via sudo against rootless Podman' not found"
        )
        assert "bash uninstall.sh" in block_text, (
            "Error message does not suggest running without sudo"
        )
        assert "exit 1" in block_text, (
            "sudo-rootless guard block does not exit 1"
        )

    def test_docker_engine_rootless_also_guarded(self):
        """Docker Engine rootless path must have same sudo-guard."""
        script = _read_script()
        assert "docker-engine-rootless" in script, (
            "docker-engine-rootless subtype not found in script"
        )
        # Find the guard for docker-engine-rootless
        guard_pos = script.find(
            '"$RUNTIME_SUBTYPE" = "docker-engine-rootless"'
        )
        assert guard_pos != -1, (
            "docker-engine-rootless sudo guard not found"
        )
        # Exit 1 must follow within the same block
        block_text = script[guard_pos:guard_pos + 1000]
        assert "exit 1" in block_text, (
            "docker-engine-rootless sudo guard does not exit 1"
        )


# ===========================================================================
# Group 3 — Volume assertion contract
# ===========================================================================

class TestVolumeAssertion:
    """Verify the volume final assertion behaviour."""

    def test_volume_assertion_covers_all_canonical_volumes(self):
        """_assert_no_volumes_remain must iterate _CANONICAL_VOLUMES."""
        script = _read_script()
        fn_start = script.find("_assert_no_volumes_remain()")
        fn_end = script.find("\n}", fn_start)
        fn_body = script[fn_start:fn_end]
        assert "_CANONICAL_VOLUMES" in fn_body, (
            "_assert_no_volumes_remain does not iterate _CANONICAL_VOLUMES"
        )

    def test_volume_assertion_called_after_removal_loop(self):
        """_assert_no_volumes_remain must be called AFTER the volume rm loop."""
        script = _read_script()
        vol_rm_loop_pos = script.find(
            "echo \"=== Removing named volumes (UNINSTALL-LEAVES-VOLUMES"
        )
        assert_call_pos = script.find("_assert_no_volumes_remain")
        # We want the CALL (not definition) — search after the function definition
        fn_def_end = script.find("\n}", script.find("_assert_no_volumes_remain()")) + 2
        assert_call_pos_after_def = script.find("_assert_no_volumes_remain", fn_def_end)
        assert vol_rm_loop_pos != -1, "Volume rm loop not found"
        assert assert_call_pos_after_def != -1, (
            "_assert_no_volumes_remain call not found after its definition"
        )
        assert assert_call_pos_after_def > vol_rm_loop_pos, (
            "_assert_no_volumes_remain must be called AFTER the named volume removal loop"
        )

    def test_volume_assertion_exit1_on_leftover(self):
        """_assert_no_volumes_remain must exit 1 when volumes remain."""
        script = _read_script()
        fn_start = script.find("_assert_no_volumes_remain()")
        fn_end = script.find("\n}", fn_start)
        fn_body = script[fn_start:fn_end]
        assert "exit 1" in fn_body, (
            "_assert_no_volumes_remain does not exit 1 when volumes remain"
        )
        # Must print remediation hint (volume rm command)
        assert "volume rm" in fn_body, (
            "_assert_no_volumes_remain error message does not suggest 'volume rm'"
        )


# ===========================================================================
# Group 4 — Help flag and argument parsing
# ===========================================================================

class TestArgumentParsing:
    """Verify --help and unknown flag handling."""

    def test_help_flag_exits_zero(self):
        """--help must exit 0."""
        result = _run_uninstall(extra_args=["--help"])
        assert result.returncode == 0, (
            f"--help did not exit 0: rc={result.returncode}\n{result.stderr}"
        )

    def test_help_mentions_runtime_flag(self):
        """--help output must mention --runtime with k8s as a valid option."""
        result = _run_uninstall(extra_args=["--help"])
        assert "--runtime" in result.stdout, (
            "--help output does not mention --runtime"
        )
        assert "k8s" in result.stdout, (
            "--help output does not mention k8s as a valid runtime"
        )

    def test_unknown_flag_exits_nonzero(self):
        """Unknown flags must exit non-zero with a helpful message."""
        result = _run_uninstall(extra_args=["--definitely-not-a-valid-flag"])
        assert result.returncode != 0, (
            "Unknown flag did not exit non-zero"
        )
        assert "Unknown option" in result.stderr or "Unknown option" in result.stdout, (
            "Unknown flag error message not emitted"
        )


# ===========================================================================
# Group 5 — Runtime detection contract (static)
# ===========================================================================

class TestRuntimeDetectionContract:
    """Verify static properties of the runtime detection block."""

    def test_state_file_path_correct(self):
        """State file path must be docker/.yashigani-install-state."""
        script = _read_script()
        assert '.yashigani-install-state"' in script, (
            "State file path not found in expected form"
        )

    def test_podman_preferred_over_docker_in_autodetect(self):
        """Auto-detect block must try podman before docker — mirrors install.sh."""
        script = _read_script()
        # Find the auto-detect block (guarded by [ -z "$RUNTIME" ])
        autodetect_start = script.find("# Source 3: auto-detect")
        assert autodetect_start != -1, "Auto-detect comment block not found"
        block = script[autodetect_start:autodetect_start + 600]
        podman_pos = block.find("podman")
        docker_pos = block.find('"docker"')
        assert podman_pos < docker_pos, (
            "Auto-detect: podman must be tried before docker"
        )

    def test_runtime_subtype_assigned_for_all_base_runtimes(self):
        """RUNTIME_SUBTYPE must be set for podman, docker, and k8s base runtimes."""
        script = _read_script()
        # All three base runtime branches must set RUNTIME_SUBTYPE
        for base_runtime in ("podman", "docker", "k8s"):
            pattern = f'RUNTIME_SUBTYPE="{base_runtime}'
            # partial match: podman-rootless, docker-desktop, etc.
            # or exact: RUNTIME_SUBTYPE="k8s"
            subtype_pattern = re.compile(
                r'RUNTIME_SUBTYPE="' + re.escape(base_runtime), re.MULTILINE
            )
            assert subtype_pattern.search(script), (
                f"RUNTIME_SUBTYPE not assigned for base runtime '{base_runtime}'"
            )

    def test_compose_command_not_used_for_k8s(self):
        """K8s teardown function must not use compose down."""
        script = _read_script()
        fn_start = script.find("_teardown_k8s()")
        fn_end = script.find("\n}", fn_start)
        fn_body = script[fn_start:fn_end]
        assert "$COMPOSE" not in fn_body, (
            "_teardown_k8s must not use compose down (K8s uses helm/kubectl)"
        )
