# Last updated: 2026-05-28T00:00:00+01:00
"""
Contract tests for DRIFT-B5-COMPOSE-AGENT-BACKUP.

Iris drift gate finding: compose deployments with agent bundles enabled have
silently excluded agent state (langflow flows + DB, letta memory + config,
openclaw policies) from every backup since v2.23.3.  The Helm side was fixed
by B5 (scripts/backup.sh --extra-dirs + backup-cronjob.yaml PVC mounts).
This fix extends _backup_existing_data() in install.sh to snapshot each
agent bundle's named Docker/Podman volume when it exists on the compose host.

Assertions:
  1. All three volume names are referenced in _backup_existing_data().
  2. The warn-not-fail pattern is present (volume-absent path warns, does not exit).
  3. The tar invocation is properly quoted (volume name via variable, not literal).
  4. Tarballs are created at 0600 (umask 177 + explicit chmod 0600).
  5. The block is gated on compose path (skipped on k8s MODE).
  6. The runtime command variable (_runtime_cmd) is used — not a hardcoded "docker".
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _read_install() -> str:
    return INSTALL_SH.read_text(encoding="utf-8")


def _backup_function_body(script: str) -> str:
    """Extract the text of _backup_existing_data() from install.sh.

    The function starts at the line containing '^_backup_existing_data()' and
    ends at the line containing '^}' that follows (top-level closing brace).
    """
    lines = script.splitlines()
    start = None
    end = None
    depth = 0
    for i, line in enumerate(lines):
        if start is None:
            if re.match(r'^_backup_existing_data\(\)', line):
                start = i
                depth = 0
                continue
        else:
            # Count braces to find the matching top-level closing brace.
            depth += line.count('{') - line.count('}')
            if depth <= 0 and line.strip() == '}':
                end = i
                break
    assert start is not None, "_backup_existing_data() not found in install.sh"
    assert end is not None, "_backup_existing_data(): closing '}' not found"
    return '\n'.join(lines[start:end + 1])


# ──────────────────────────────────────────────────────────────────────────────
# Test suite
# ──────────────────────────────────────────────────────────────────────────────

class TestComposeAgentBackupVolumes:
    """
    DRIFT-B5-COMPOSE-AGENT-BACKUP: _backup_existing_data() must snapshot each
    agent bundle named volume when present on the compose host.
    """

    @pytest.fixture(scope="class")
    def backup_body(self) -> str:
        return _backup_function_body(_read_install())

    # ── 1. Volume names present ───────────────────────────────────────────────

    def test_langflow_data_volume_referenced(self, backup_body: str) -> None:
        """langflow_data must appear in _backup_existing_data."""
        assert "langflow_data" in backup_body, (
            "DRIFT-B5-COMPOSE REGRESSION: langflow_data volume name absent from "
            "_backup_existing_data(). Langflow agent state will be excluded from "
            "compose backups."
        )

    def test_letta_data_volume_referenced(self, backup_body: str) -> None:
        """letta_data must appear in _backup_existing_data."""
        assert "letta_data" in backup_body, (
            "DRIFT-B5-COMPOSE REGRESSION: letta_data volume name absent from "
            "_backup_existing_data(). Letta agent state will be excluded from "
            "compose backups."
        )

    def test_openclaw_data_volume_referenced(self, backup_body: str) -> None:
        """openclaw_data must appear in _backup_existing_data."""
        assert "openclaw_data" in backup_body, (
            "DRIFT-B5-COMPOSE REGRESSION: openclaw_data volume name absent from "
            "_backup_existing_data(). Openclaw agent state will be excluded from "
            "compose backups."
        )

    def test_agent_volumes_use_compose_project_prefix(self, backup_body: str) -> None:
        """LIVE-FIX2-001 (VM smoke 2026-05-28): compose-created volumes carry the
        project prefix (compose file in docker/ => 'docker_langflow_data', NOT bare
        'langflow_data'). The backup MUST inspect the prefixed names or it always
        reports 'not present — skipping' and silently loses agent state. The first
        VM smoke caught exactly this. Guard: the _agent_volumes array must build
        names from _compose_project_prefix, matching the agent-bundle chown path."""
        assert "_compose_project_prefix" in backup_body, (
            "LIVE-FIX2-001 REGRESSION: _backup_existing_data() agent-volume block "
            "must use _compose_project_prefix to build the volume names. Bare "
            "'langflow_data' will not match the live 'docker_langflow_data' volume."
        )
        assert '${_compose_project_prefix}_langflow_data' in backup_body, (
            "LIVE-FIX2-001 REGRESSION: langflow volume name must be prefixed "
            "(${_compose_project_prefix}_langflow_data), not bare langflow_data."
        )
        assert '${_compose_project_prefix}_letta_data' in backup_body, (
            "LIVE-FIX2-001 REGRESSION: letta volume name must be prefixed."
        )
        assert '${_compose_project_prefix}_openclaw_data' in backup_body, (
            "LIVE-FIX2-001 REGRESSION: openclaw volume name must be prefixed."
        )

    # ── 2. Warn-not-fail pattern ──────────────────────────────────────────────

    def test_absent_volume_produces_warn_not_fail(self, backup_body: str) -> None:
        """
        When a volume is absent, the code must emit a log_info/log_warn message
        and continue — not exit or return non-zero.

        We verify that the volume-absent branch calls log_info or log_warn and
        does NOT call 'exit' or 'return 1'.
        """
        # The pattern we expect: volume inspect fails → log_info/log_warn the skip.
        # We check that "not present" / "skipping" / "not enabled" appears in the body
        # (the exact message wording) and is paired with log_info or log_warn, not exit.
        skip_patterns = [
            r'log_info.*not present',
            r'log_info.*skipping',
            r'log_info.*not enabled',
            r'log_warn.*not present',
            r'log_warn.*skipping',
        ]
        found_skip = any(re.search(p, backup_body) for p in skip_patterns)
        assert found_skip, (
            "DRIFT-B5-COMPOSE: no warn-not-fail skip message found for absent agent "
            "volumes in _backup_existing_data(). The function must log_info/log_warn "
            "when a volume is absent and continue — not exit."
        )

    def test_no_unconditional_exit_on_volume_miss(self, backup_body: str) -> None:
        """
        The agent-volume block must not contain 'exit 1' or 'return 1' on the
        absent-volume branch. Extract the DRIFT-B5 block and verify.
        """
        # Find the DRIFT-B5-COMPOSE-AGENT-BACKUP block specifically.
        block_start = backup_body.find("DRIFT-B5-COMPOSE-AGENT-BACKUP")
        assert block_start != -1, (
            "DRIFT-B5-COMPOSE: DRIFT-B5-COMPOSE-AGENT-BACKUP sentinel comment not "
            "found in _backup_existing_data(). The agent volume block may have been "
            "removed or renamed."
        )
        block_text = backup_body[block_start:]
        # Any 'exit 1' in the agent volume block is a regression (fail-not-warn).
        # Allow 'exit 1' in the CWE-732 assertion at the end (pre-existing).
        # We check the block up to the BUG-58B-04a comment which follows our block.
        bug58_pos = block_text.find("BUG-58B-04a")
        if bug58_pos != -1:
            agent_block_only = block_text[:bug58_pos]
        else:
            agent_block_only = block_text
        assert "exit 1" not in agent_block_only, (
            "DRIFT-B5-COMPOSE REGRESSION: 'exit 1' found inside the agent volume "
            "backup block. Absent volumes must warn-and-continue, not fail the "
            "overall backup."
        )

    # ── 3. Tar invocation is quoted / uses variable ───────────────────────────

    def test_tar_invocation_uses_volume_name_variable(self, backup_body: str) -> None:
        """
        The tar invocation must reference the volume by a shell variable
        (e.g. "${_vol_name}") not a hardcoded literal volume name.
        This confirms the loop-variable pattern is present.
        """
        # The -v flag must reference _vol_name variable
        assert re.search(r'-v\s+["\047]?\$\{?_vol_name\}?', backup_body), (
            "DRIFT-B5-COMPOSE: tar/run invocation does not use $_vol_name variable. "
            "The volume backup must iterate over the volume-name list via a loop "
            "variable to avoid hardcoding and enable future bundle additions."
        )

    def test_tar_invocation_uses_double_dash(self, backup_body: str) -> None:
        """
        The tar invocation must include '--' before positional args to prevent
        filenames beginning with '-' from being treated as flags.
        """
        # We look for: tar ... -- .
        assert re.search(r'tar\b.*--\s+\.', backup_body), (
            "DRIFT-B5-COMPOSE: tar invocation in agent volume backup does not use "
            "'-- .' to terminate option parsing. Filenames starting with '-' inside "
            "a volume could be treated as tar flags."
        )

    def test_runtime_cmd_variable_used_not_hardcoded_docker(self, backup_body: str) -> None:
        """
        The agent volume backup must use $_runtime_cmd (already set in the function
        for Docker/Podman parity) rather than a hardcoded 'docker' literal.
        """
        # Find the DRIFT-B5 block only (not the _runtime_cmd assignment line itself).
        block_start = backup_body.find("DRIFT-B5-COMPOSE-AGENT-BACKUP")
        assert block_start != -1
        block_text = backup_body[block_start:]
        # Must reference _runtime_cmd in the volume inspect and run calls.
        assert re.search(r'\$_runtime_cmd\s+volume\s+inspect', block_text), (
            "DRIFT-B5-COMPOSE: agent volume block does not use $_runtime_cmd for "
            "'volume inspect'. Hardcoded 'docker' would break Podman installs."
        )
        assert re.search(r'\$_runtime_cmd\s+run\b', block_text), (
            "DRIFT-B5-COMPOSE: agent volume block does not use $_runtime_cmd for "
            "'run'. Hardcoded 'docker' would break Podman installs."
        )

    # ── 4. Permissions ────────────────────────────────────────────────────────

    def test_tarball_pre_created_at_restricted_mode(self, backup_body: str) -> None:
        """
        The tarball must be pre-created at a restricted mode before content is
        written. We expect either 'umask 177' or 'install -m 0600'.
        """
        assert re.search(r'umask\s+177', backup_body) or \
               re.search(r'install\s+-m\s+0600', backup_body), (
            "DRIFT-B5-COMPOSE: agent volume tarballs are not pre-created at a "
            "restricted mode. Use 'umask 177' + '> $file' or 'install -m 0600' "
            "so content never touches disk at a world-readable mode."
        )

    def test_tarball_chmod_0600_after_write(self, backup_body: str) -> None:
        """chmod 0600 must be applied to each tarball after writing."""
        assert re.search(r'chmod\s+0600\s+["\047]?\$\{?_vol_tar\}?', backup_body), (
            "DRIFT-B5-COMPOSE: 'chmod 0600 $_vol_tar' not found after agent volume "
            "tarball write. Agent volumes may contain API keys and bearer tokens; "
            "tarballs must be owner-read-only (0600)."
        )

    # ── 5. K8s gate ───────────────────────────────────────────────────────────

    def test_agent_volume_block_gated_on_compose_not_k8s(self, backup_body: str) -> None:
        """
        The agent volume backup block must be gated on compose mode (skipped on k8s).
        K8s backups are handled by backup-cronjob.yaml PVC mounts (B5 Helm side).
        """
        # The guard is: [[ "${MODE:-compose}" != "k8s" && "${YSG_RUNTIME:-}" != "k8s" ]]
        assert re.search(r'\bMODE\b.*!=.*k8s', backup_body) or \
               re.search(r'k8s.*MODE\b', backup_body), (
            "DRIFT-B5-COMPOSE: agent volume backup block is not gated on compose "
            "mode. K8s path should skip this block (PVCs are handled by the Helm "
            "backup CronJob). Add: if [[ ... MODE ... != k8s ... ]]; then"
        )

    # ── 6. Output dir structure ───────────────────────────────────────────────

    def test_output_path_uses_agent_volumes_subdir(self, backup_body: str) -> None:
        """
        Tarballs must be written into agent-volumes/ sub-directory of backup_dir,
        not directly into backup_dir (to keep the manifest structure tidy and
        to allow a single 'chmod 0700 agent-volumes/' guard).
        """
        assert "agent-volumes" in backup_body, (
            "DRIFT-B5-COMPOSE: 'agent-volumes' sub-directory not found in "
            "_backup_existing_data(). Tarballs must be written to "
            "${backup_dir}/agent-volumes/<bundle>.tar for clean manifest structure."
        )


def test_agent_vol_alpine_digest_pinned():
    """Iris SU-FIX2-IRIS-001: agent-volume tar must use the digest-pinned alpine image,
    matching the install.sh codebase norm. Regression-guards against floating-tag drift."""
    from pathlib import Path

    text = Path("install.sh").read_text()
    # The pinned digest used codebase-wide.
    pinned = "alpine:3@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11"
    assert pinned in text, "pinned alpine digest must be present"

    # Agent-volume block must reference the local digest var (not a floating tag).
    assert '_agent_vol_alpine="alpine:3@sha256:' in text, (
        "agent-volume block must declare _agent_vol_alpine with digest pin"
    )

    # Floating tag must NOT appear in the agent-volume block.
    assert "docker.io/library/alpine:3.20" not in text, (
        "floating alpine:3.20 tag must not appear; use the pinned digest fallback"
    )
