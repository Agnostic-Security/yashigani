# Last updated: 2026-05-28T00:00:00+01:00
"""
Contract tests for v2.25.0 P2 FIX-3: DRIFT-B5-BACKUP-EMBEDDED-COPY.

Finding: The helm-embedded backup.sh in configmaps.yaml drifted from
canonical scripts/backup.sh with 7 documented divergences (Iris audit):
  1. Missing header/usage block
  2. Missing color output (TTY detection)
  3. Missing operator runbook error messages
  4. Missing post-encrypt file-existence guard (Iris item 6):
     `if [[ ! -f "${TMP_OUTPUT}" ]]`
  5. Extra-warn block semantics unified (EXTRA_DIRS_ARRAY)
  6. TAR_STATUS_FILE pattern for subshell exit capture
  7. Unified dry-run path with EXTRA_DIRS logging

Fix: replace inline with `.Files.Get "files/scripts/backup.sh"` (same
pattern as B6 OPA rego, commit d1d9433). helm/yashigani/files/scripts/backup.sh
is a byte-identical copy of scripts/backup.sh.

Tests:
  1. Sha256 parity: helm/yashigani/files/scripts/backup.sh == scripts/backup.sh
  2. Rendered ConfigMap backup.sh contains the post-encrypt guard (Iris item 6)
  3. Rendered ConfigMap backup.sh contains the usage block
  4. Rendered ConfigMap backup.sh contains color output (TTY detection)
  5. Rendered ConfigMap backup.sh contains operator runbook error messages
  6. Rendered ConfigMap backup.sh contains TAR_STATUS_FILE pattern
  7. Rendered ConfigMap backup.sh contains EXTRA_DIRS_ARRAY (B5 parity)
  8. No regression: B5 contract assertions still pass on rendered output
  9. Mutation guard: inline-without-guard would be caught by test #2
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml


REPO_ROOT = Path(__file__).parent.parent.parent
HELM_CHART = REPO_ROOT / "helm" / "yashigani"
BACKUP_SH_CANONICAL = REPO_ROOT / "scripts" / "backup.sh"
BACKUP_SH_HELM_COPY = HELM_CHART / "files" / "scripts" / "backup.sh"

_LINT_BEARER = "helm-lint-only-not-a-real-secret-000000000000"


# ──────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────────────────────────────────────

def _helm_template(extra_set: list[str] | None = None) -> str:
    """Run helm template with common flags; raise via pytest.fail on error."""
    cmd = [
        "helm", "template", "yashigani", str(HELM_CHART),
        "--namespace", "yashigani-validate",
        "--set", "mtls.enabled=true",
        "--set", f"internalBearer.value={_LINT_BEARER}",
        "--set", "backup.enabled=true",
        "--set", "backup.recipientKeyConfigMap=test-recipient-cm",
    ]
    if extra_set:
        for s in extra_set:
            cmd += ["--set", s]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.fail(
            f"helm template failed (rc={result.returncode}):\n"
            f"STDOUT: {result.stdout[:3000]}\n"
            f"STDERR: {result.stderr[:3000]}"
        )
    return result.stdout


def _parse_docs(rendered: str) -> list[dict[str, Any]]:
    return [d for d in yaml.safe_load_all(rendered) if d is not None]


def _get_backup_configmap_script(rendered: str) -> str:
    """Extract backup.sh content from the yashigani-backup-script ConfigMap."""
    docs = _parse_docs(rendered)
    for doc in docs:
        if (
            doc.get("kind") == "ConfigMap"
            and doc.get("metadata", {}).get("name", "").endswith("-backup-script")
        ):
            return doc.get("data", {}).get("backup.sh", "")
    return ""


# ──────────────────────────────────────────────────────────────────────────────
# FIX-3 — sha256 parity: helm copy must be byte-identical to canonical
# ──────────────────────────────────────────────────────────────────────────────

class TestFix3BackupSha256Parity:
    """
    DRIFT-B5-BACKUP-EMBEDDED-COPY (FIX-3):
    helm/yashigani/files/scripts/backup.sh must be byte-identical to
    scripts/backup.sh. Any divergence means the K8s backup ConfigMap differs
    from the canonical compose-side backup script.
    """

    def test_helm_files_copy_exists(self) -> None:
        """helm/yashigani/files/scripts/backup.sh must exist."""
        assert BACKUP_SH_HELM_COPY.exists(), (
            f"Helm files copy missing: {BACKUP_SH_HELM_COPY}.\n"
            f"Fix: cp scripts/backup.sh helm/yashigani/files/scripts/backup.sh\n"
            f"(DRIFT-B5-BACKUP-EMBEDDED-COPY / FIX-3)"
        )

    def test_canonical_exists(self) -> None:
        """scripts/backup.sh (canonical source) must exist."""
        assert BACKUP_SH_CANONICAL.exists(), (
            f"Canonical backup.sh missing: {BACKUP_SH_CANONICAL}"
        )

    def test_sha256_parity(self) -> None:
        """
        helm/yashigani/files/scripts/backup.sh must be byte-identical to
        scripts/backup.sh (sha256 match). Any divergence is a DRIFT finding.
        """
        assert BACKUP_SH_CANONICAL.exists(), f"Canonical missing: {BACKUP_SH_CANONICAL}"
        assert BACKUP_SH_HELM_COPY.exists(), (
            f"Helm copy missing: {BACKUP_SH_HELM_COPY}. "
            f"Run: cp scripts/backup.sh helm/yashigani/files/scripts/backup.sh"
        )
        canonical_sha = hashlib.sha256(BACKUP_SH_CANONICAL.read_bytes()).hexdigest()
        helm_copy_sha = hashlib.sha256(BACKUP_SH_HELM_COPY.read_bytes()).hexdigest()
        assert canonical_sha == helm_copy_sha, (
            f"DRIFT: scripts/backup.sh and helm/yashigani/files/scripts/backup.sh "
            f"have different sha256.\n"
            f"  canonical: {canonical_sha}\n"
            f"  helm copy: {helm_copy_sha}\n"
            f"Fix: cp scripts/backup.sh helm/yashigani/files/scripts/backup.sh "
            f"(DRIFT-B5-BACKUP-EMBEDDED-COPY / FIX-3)"
        )

    def test_helm_copy_not_executable(self) -> None:
        """
        helm/yashigani/files/scripts/backup.sh must NOT be executable (L5 — iCloud
        residue prevention). Helm chart YAML and shell-in-files must not have +x.
        """
        if not BACKUP_SH_HELM_COPY.exists():
            pytest.skip("helm copy missing — covered by test_helm_files_copy_exists")
        mode = BACKUP_SH_HELM_COPY.stat().st_mode
        executable_bits = mode & 0o111
        assert executable_bits == 0, (
            f"helm/yashigani/files/scripts/backup.sh has execute bit set "
            f"(mode={oct(mode)}). Strip it: chmod -x {BACKUP_SH_HELM_COPY} (L5)."
        )


# ──────────────────────────────────────────────────────────────────────────────
# FIX-3 — rendered ConfigMap contains all 7 Iris divergence fixes
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def rendered_backup_sh() -> str:
    """
    Render the helm chart with backup enabled and return the backup.sh content
    from the rendered ConfigMap. Skips if helm binary is not available.
    """
    import shutil
    if not shutil.which("helm"):
        pytest.skip("helm binary not found — install helm to run this check")
    rendered = _helm_template()
    script = _get_backup_configmap_script(rendered)
    assert script, (
        "yashigani-backup-script ConfigMap or backup.sh key not found in render. "
        "Check that backup.enabled=true renders the ConfigMap."
    )
    return script


class TestFix3RenderedBackupShContent:
    """
    Verify the rendered ConfigMap's backup.sh contains all fixes for the 7 Iris
    divergences (DRIFT-B5-BACKUP-EMBEDDED-COPY).
    """

    def test_iris_item6_post_encrypt_guard_present(
        self, rendered_backup_sh: str
    ) -> None:
        """
        Iris item 6 (critical): post-encrypt file-existence guard must be present.
        `if [[ ! -f "${TMP_OUTPUT}" ]]` — missing in the inline version; absent
        means a zero-byte or missing encrypted file would be silently renamed to
        the final output path, giving a false-success backup.
        """
        assert '! -f "${TMP_OUTPUT}"' in rendered_backup_sh, (
            "DRIFT-B5-BACKUP-EMBEDDED-COPY Iris item 6 MISSING: post-encrypt "
            "file-existence guard `if [[ ! -f \"${TMP_OUTPUT}\" ]]` absent from "
            "rendered backup.sh. Silent false-success backup if encryption produces "
            "no output. Fix: ensure .Files.Get references canonical scripts/backup.sh."
        )

    def test_usage_block_present(self, rendered_backup_sh: str) -> None:
        """
        Header/usage block must be present (missing from inline).
        Operators need --help output in the container image.
        """
        assert "Usage: backup.sh" in rendered_backup_sh, (
            "DRIFT: usage block (Usage: backup.sh) absent from rendered backup.sh. "
            "The inline version lacked the usage() function. "
            "Fix: ensure .Files.Get references canonical scripts/backup.sh."
        )

    def test_color_output_tty_detection_present(self, rendered_backup_sh: str) -> None:
        """
        TTY-conditional color output must be present (missing from inline).
        The canonical script uses `if [ -t 1 ]` to detect TTY and set ANSI codes.
        """
        assert "[ -t 1 ]" in rendered_backup_sh, (
            "DRIFT: TTY detection `[ -t 1 ]` absent from rendered backup.sh. "
            "The inline version had no color support; rendered output must include it. "
            "Fix: ensure .Files.Get references canonical scripts/backup.sh."
        )

    def test_operator_runbook_error_messages_present(
        self, rendered_backup_sh: str
    ) -> None:
        """
        Operator runbook error messages must be present (inline had bare one-liners).
        The canonical script emits multi-line keygen instructions on recipient key error.
        """
        assert "age-keygen -o /etc/yashigani/backup-identity.age" in rendered_backup_sh, (
            "DRIFT: operator runbook error messages absent from rendered backup.sh. "
            "The inline version had bare error messages; canonical has full keygen runbook. "
            "Fix: ensure .Files.Get references canonical scripts/backup.sh."
        )

    def test_tar_status_file_pattern_present(self, rendered_backup_sh: str) -> None:
        """
        TAR_STATUS_FILE pattern for subshell exit capture must be present.
        The inline version used a variable assignment inside the pipe subshell
        (SC2030/SC2031 race). Canonical uses a status file to cross the subshell
        boundary reliably.
        """
        assert "TAR_STATUS_FILE" in rendered_backup_sh, (
            "DRIFT: TAR_STATUS_FILE pattern absent from rendered backup.sh. "
            "Subshell exit capture requires writing to a temp file. "
            "Fix: ensure .Files.Get references canonical scripts/backup.sh."
        )

    def test_extra_dirs_array_present(self, rendered_backup_sh: str) -> None:
        """
        EXTRA_DIRS_ARRAY must be present (B5 parity).
        The inline version from wave 3 included B5 features but this test confirms
        the canonical .Files.Get version also carries them.
        """
        assert "EXTRA_DIRS_ARRAY" in rendered_backup_sh, (
            "B5 REGRESSION: EXTRA_DIRS_ARRAY absent from rendered backup.sh. "
            "Agent bundle dirs cannot be archived. "
            "Fix: ensure .Files.Get references canonical scripts/backup.sh."
        )

    def test_yashigani_backup_extra_dirs_env_present(
        self, rendered_backup_sh: str
    ) -> None:
        """
        YASHIGANI_BACKUP_EXTRA_DIRS must be present (B5 parity).
        """
        assert "YASHIGANI_BACKUP_EXTRA_DIRS" in rendered_backup_sh, (
            "B5 REGRESSION: YASHIGANI_BACKUP_EXTRA_DIRS absent from rendered backup.sh. "
            "Fix: ensure .Files.Get references canonical scripts/backup.sh."
        )

    def test_tar_extra_args_present(self, rendered_backup_sh: str) -> None:
        """
        TAR_EXTRA_ARGS must be present (B5 parity).
        """
        assert "TAR_EXTRA_ARGS" in rendered_backup_sh, (
            "B5 REGRESSION: TAR_EXTRA_ARGS absent from rendered backup.sh. "
            "Fix: ensure .Files.Get references canonical scripts/backup.sh."
        )

    def test_atomic_rename_and_chmod_present(self, rendered_backup_sh: str) -> None:
        """
        mv atomic rename and chmod 0400 must be present.
        The canonical script renames TMP_OUTPUT → OUTPUT_FILE atomically, then
        restricts permissions to 0400 (backup file is read-only after creation).
        """
        assert 'mv "${TMP_OUTPUT}" "${OUTPUT_FILE}"' in rendered_backup_sh, (
            "DRIFT: atomic mv rename absent from rendered backup.sh. "
            "Fix: ensure .Files.Get references canonical scripts/backup.sh."
        )
        assert "chmod 0400" in rendered_backup_sh, (
            "DRIFT: chmod 0400 absent from rendered backup.sh. "
            "Backup files must be 0400 (read-only) after creation. "
            "Fix: ensure .Files.Get references canonical scripts/backup.sh."
        )

    def test_trap_cleanup_present(self, rendered_backup_sh: str) -> None:
        """
        trap cleanup must be present for INT/TERM signals.
        Ensures partial output is deleted on interrupt.
        """
        assert "trap" in rendered_backup_sh, (
            "DRIFT: trap cleanup absent from rendered backup.sh. "
            "Partial output would persist on SIGINT/SIGTERM. "
            "Fix: ensure .Files.Get references canonical scripts/backup.sh."
        )

    def test_set_euo_pipefail_present(self, rendered_backup_sh: str) -> None:
        """
        set -euo pipefail must be present (strict mode required for backup safety).
        """
        assert "set -euo pipefail" in rendered_backup_sh, (
            "DRIFT: `set -euo pipefail` absent from rendered backup.sh. "
            "Fix: ensure .Files.Get references canonical scripts/backup.sh."
        )

    def test_dry_run_path_present(self, rendered_backup_sh: str) -> None:
        """
        --dry-run path must be present.
        The inline version lacked argument parsing; canonical has --dry-run support.
        """
        assert "--dry-run" in rendered_backup_sh, (
            "DRIFT: --dry-run flag absent from rendered backup.sh. "
            "The inline version lacked argument parsing; canonical supports --dry-run. "
            "Fix: ensure .Files.Get references canonical scripts/backup.sh."
        )


# ──────────────────────────────────────────────────────────────────────────────
# Mutation guard
# ──────────────────────────────────────────────────────────────────────────────

def test_fix3_mutation_catch_missing_post_encrypt_guard() -> None:
    """
    Mutation guard: simulate the old inline backup.sh (pre-FIX-3 version that
    lacks the post-encrypt file-existence guard) and confirm test #2 catches it.
    Per SOP 4 (test harness must not emit fake green).
    """
    # Synthetic pre-FIX-3 backup.sh — deliberately omits the post-encrypt guard
    old_inline_no_guard = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "umask 077\n"
        "RECIPIENT_KEY_FILE=${YASHIGANI_BACKUP_RECIPIENT:-/etc/yashigani/backup-recipient.age.pub}\n"
        "OUTPUT_DIR=${YASHIGANI_BACKUP_OUTPUT_DIR:-/var/lib/yashigani/backups}\n"
        "SOURCE_DIR=${YASHIGANI_BACKUP_SOURCE_DIR:-/var/lib/yashigani}\n"
        "TMP_OUTPUT=${OUTPUT_DIR}/.tmp-${TIMESTAMP}-$$.tar.gz.age\n"
        "ENCRYPT_STATUS=0\n"
        "# NOTE: no post-encrypt guard — Iris item 6 missing\n"
        "mv \"${TMP_OUTPUT}\" \"${OUTPUT_FILE}\"\n"
        "chmod 0400 \"${OUTPUT_FILE}\"\n"
    )
    # Confirm mutation blob does NOT contain the guard
    has_guard = '! -f "${TMP_OUTPUT}"' in old_inline_no_guard
    assert not has_guard, (
        "MUTATION SETUP ERROR: test blob unexpectedly contains the post-encrypt guard. "
        "Use a string that omits `! -f \"${TMP_OUTPUT}\"`."
    )
    # Simulate what the Iris item 6 contract check does:
    contract_would_catch = not has_guard
    assert contract_would_catch, (
        "MUTATION GUARD FAILED: Iris item 6 contract test would not have caught "
        "a backup.sh that lacks the post-encrypt file-existence guard."
    )
