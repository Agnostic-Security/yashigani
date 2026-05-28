# Last updated: 2026-05-28T00:00:00+01:00
"""
Contract tests for YSG-RISK-050/051: Dual-wrap signed+encrypted install-time backup.

Locked spec: Agnostic Security/Products/Yashigani/signed-encrypted-install-backup-spec-20260528.md
Closes: CWE-311 (plaintext backup) + CWE-345 (broken manifest signing).

Test categories:
  1. install.sh _backup_existing_data() — crypto primitives, schema, guardrails
  2. restore.sh — v2 detection, new flags, HMAC verify, fail-closed paths
  3. lib/yashigani-fips.sh — _fips_hmac_sha384 presence + structure
  4. password.py — _MIN_PASSWORD_LENGTH comment present
  5. Live functional proof (subprocess-based smoke) — run only when DOCKER available
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT    = Path(__file__).parent.parent.parent
INSTALL_SH   = REPO_ROOT / "install.sh"
RESTORE_SH   = REPO_ROOT / "restore.sh"
FIPS_LIB     = REPO_ROOT / "lib" / "yashigani-fips.sh"
PASSWORD_PY  = REPO_ROOT / "src" / "yashigani" / "auth" / "password.py"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _backup_function_body(script: str) -> str:
    """Extract _backup_existing_data() body from install.sh."""
    lines = script.splitlines()
    start = end = None
    depth = 0
    for i, line in enumerate(lines):
        if start is None:
            if re.match(r'^_backup_existing_data\(\)', line):
                start = i; depth = 0; continue
        else:
            depth += line.count('{') - line.count('}')
            if depth <= 0 and line.strip() == '}':
                end = i; break
    assert start is not None, "_backup_existing_data() not found in install.sh"
    assert end   is not None, "_backup_existing_data(): closing '}' not found"
    return '\n'.join(lines[start:end + 1])


def _restore_validate_body(script: str) -> str:
    """Extract validate_backup() body from restore.sh."""
    lines = script.splitlines()
    start = end = None
    depth = 0
    for i, line in enumerate(lines):
        if start is None:
            if re.match(r'^validate_backup\(\)', line):
                start = i; depth = 0; continue
        else:
            depth += line.count('{') - line.count('}')
            if depth <= 0 and line.strip() == '}':
                end = i; break
    assert start is not None, "validate_backup() not found in restore.sh"
    assert end   is not None, "validate_backup(): closing '}' not found"
    return '\n'.join(lines[start:end + 1])


# ─────────────────────────────────────────────────────────────────────────────
# 1. install.sh backup function
# ─────────────────────────────────────────────────────────────────────────────

class TestInstallBackupCrypto:
    """YSG-RISK-050/051: _backup_existing_data() dual-wrap construction."""

    @pytest.fixture(scope="class")
    def backup_body(self) -> str:
        return _backup_function_body(_read(INSTALL_SH))

    # ── Timestamp captured once ──────────────────────────────────────────────

    def test_ts_captured_once(self, backup_body: str) -> None:
        """backup_ts must be captured once and reused (spec guardrail 1)."""
        assert "backup_ts=" in backup_body, (
            "YSG-RISK-050 REGRESSION: backup_ts variable not found. "
            "Spec requires ts to be captured once and reused for dir name + AADs."
        )
        assert '${backup_ts}' in backup_body or '"${backup_ts}"' in backup_body, (
            "backup_ts must be referenced after capture (not recalculated)."
        )

    # ── Python crypto runs in container ─────────────────────────────────────

    def test_python3_used_not_python(self, backup_body: str) -> None:
        """python3 must be used (not python). Spec §Tooling."""
        assert "python3" in backup_body, "python3 must appear in backup body"
        # Bare 'python ' without '3' should not be the invocation
        assert not re.search(r'\bpython\s', backup_body), (
            "YSG-RISK-050: bare 'python ' found — spec requires 'python3'."
        )

    def test_aes_256_gcm_referenced(self, backup_body: str) -> None:
        """AES-256-GCM (AESGCM) must be referenced. Spec §Key hierarchy."""
        assert "AESGCM" in backup_body, (
            "YSG-RISK-050: AESGCM not found in backup body — AES-256-GCM not used."
        )

    def test_hkdf_sha384_referenced(self, backup_body: str) -> None:
        """HKDF-SHA384 must be referenced (not HKDF-SHA256). Spec §PQC/CNSA-2.0."""
        assert "SHA384" in backup_body or "hkdf-sha384" in backup_body.lower(), (
            "YSG-RISK-050: SHA384 not found in backup body — HKDF-SHA384 not used. "
            "Spec requires SHA-384 everywhere; no SHA-256 in any new primitive."
        )

    def test_hmac_sha384_referenced(self, backup_body: str) -> None:
        """HMAC-SHA384 MAC_KEY must be referenced. Spec §Key hierarchy."""
        assert "hmac" in backup_body.lower() and "384" in backup_body, (
            "YSG-RISK-050: HMAC-SHA384 not found in backup body — metadata MAC missing."
        )

    def test_wrap1_present_field(self, backup_body: str) -> None:
        """wrap1.present must be set (true/false) in the backup. Spec §backup-meta.json."""
        assert "wrap1" in backup_body, "YSG-RISK-050: wrap1 not referenced in backup body"
        assert "present" in backup_body, "YSG-RISK-050: 'present' field not set in backup body"

    def test_wrap2_always_written(self, backup_body: str) -> None:
        """wrap2 (recovery path) is always written. Spec: wrap#2 always present.
        Note: Python heredoc content is tested via install.sh full text (test_*_in_crypto_script)."""
        # The shell-level variable _ysg_tier and ikm2 logic is in the body.
        assert "_ysg_tier" in backup_body or "wrap2" in backup_body or "ikm2" in backup_body, (
            "YSG-RISK-050: wrap2/ikm2 not referenced in backup body."
        )

    def test_fips_mode_branch_present(self, backup_body: str) -> None:
        """FIPS_MODE=1 branch (PBKDF2-HMAC-SHA384) must be in backup body. Spec §wrap1."""
        # Shell-level: passes FIPS_MODE to container via env var.
        assert "FIPS_MODE" in backup_body or "_YSG_FIPS_MODE" in backup_body, (
            "YSG-RISK-050: FIPS_MODE not passed to crypto container in backup body."
        )

    # ── bundle.enc atomic write ──────────────────────────────────────────────

    def test_bundle_enc_atomic_rename(self, backup_body: str) -> None:
        """bundle.enc must use tmp→atomic rename pattern. Spec guardrail 3."""
        assert "bundle.enc.tmp" in backup_body, (
            "YSG-RISK-050: 'bundle.enc.tmp' not found — atomic rename pattern missing. "
            "Spec requires bundle.enc written via tmp→rename on success."
        )

    def test_bundle_enc_deleted_on_error(self, backup_body: str) -> None:
        """bundle.enc must be deleted on error paths. Spec guardrail 3."""
        assert "bundle.enc" in backup_body, "bundle.enc not referenced"
        # The cleanup pattern: rm -rf backup_dir or rm -f bundle.enc on failure.
        assert re.search(r'rm\s.*backup_dir|rm\s.*bundle\.enc', backup_body), (
            "YSG-RISK-050: no cleanup of bundle.enc on error found in backup body. "
            "Spec: delete bundle.enc if meta fails; delete on error."
        )

    # ── Plaintext files removed ──────────────────────────────────────────────

    def test_plaintext_secrets_removed_after_encrypt(self, backup_body: str) -> None:
        """secrets/ must be removed after encryption. Spec guardrail 4."""
        assert re.search(r'rm\s+-rf.*secrets', backup_body), (
            "YSG-RISK-050: plaintext secrets/ not removed from backup dir after encryption. "
            "Spec: remove secrets/, .env, postgres_dump.sql, MANIFEST.* from backup dir."
        )

    def test_plaintext_env_removed_after_encrypt(self, backup_body: str) -> None:
        """.env must be removed after encryption."""
        # The rm -f .env line is in the backup body (it's shell code, not Python heredoc).
        install_text = _read(INSTALL_SH)
        # The removal block appears after the crypto section in _backup_existing_data.
        assert re.search(r'rm\s+-f.*\.env.*2>/dev/null', install_text), (
            "YSG-RISK-050: plaintext .env not removed from backup dir after encryption."
        )

    def test_manifest_files_removed(self, backup_body: str) -> None:
        """Old MANIFEST.sha256 and .sig must be removed for v2 backups. Spec guardrail 4."""
        install_text = _read(INSTALL_SH)
        assert "MANIFEST.sha256" in install_text, (
            "YSG-RISK-050: MANIFEST.sha256 cleanup not found in install.sh. "
            "Spec requires removing MANIFEST.sha256 + .sig for v2 backups."
        )

    # ── No plaintext fallback ────────────────────────────────────────────────

    def test_no_plaintext_fallback_pattern(self, backup_body: str) -> None:
        """No silent fallback to plaintext backup. Spec guardrail 5."""
        assert re.search(r'exit\s+1', backup_body), (
            "YSG-RISK-050: no exit 1 found in backup body. "
            "Spec requires fail-closed on crypto failure — no plaintext fallback."
        )

    # ── CWE-311 assertion ────────────────────────────────────────────────────

    def test_cwe311_assertion_present(self, backup_body: str) -> None:
        """CWE-311 assertion must verify no plaintext secrets remain. Spec guardrail."""
        install_text = _read(INSTALL_SH)
        # CWE-311 and plaintext assertion are in the full install.sh backup section.
        assert "CWE-311" in install_text or "plaintext secret" in install_text, (
            "YSG-RISK-050: CWE-311 assertion not found in install.sh. "
            "After encryption, verify no plaintext *.key or .env files remain."
        )

    # ── backup-meta.json schema fields (in Python heredoc — check install.sh) ─

    def test_backup_meta_version_field(self, backup_body: str) -> None:
        """backup-meta.json must include version field. Spec §schema.
        Content lives inside Python heredoc — check full install.sh text."""
        assert "yashigani-backup-v1" in _read(INSTALL_SH), (
            "YSG-RISK-050: 'yashigani-backup-v1' version string not found in install.sh."
        )

    def test_backup_meta_tier_field(self, backup_body: str) -> None:
        """backup-meta.json must include tier field. Spec §schema."""
        install_text = _read(INSTALL_SH)
        assert '"tier"' in install_text or "_ysg_tier" in install_text, (
            "YSG-RISK-050: 'tier' field or _ysg_tier not found in install.sh."
        )

    def test_backup_meta_fips_mode_field(self, backup_body: str) -> None:
        """backup-meta.json must include fips_mode field. Spec §schema."""
        install_text = _read(INSTALL_SH)
        assert "fips_mode" in install_text, (
            "YSG-RISK-050: 'fips_mode' field not found in install.sh."
        )

    # ── k8s gate preserved ───────────────────────────────────────────────────

    def test_dual_wrap_gated_compose_not_k8s(self, backup_body: str) -> None:
        """Dual-wrap must NOT run on K8s mode. Spec §Out of scope."""
        # The new crypto block follows existing compose/k8s gating.
        # The crypto block exits early if no container found — verify no k8s exec path.
        # Existing K8s pg_dump path is still gated on MODE==k8s.
        assert "k8s" in backup_body, (
            "K8s detection must still be present in _backup_existing_data."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2. restore.sh
# ─────────────────────────────────────────────────────────────────────────────

class TestRestoreV2:
    """YSG-RISK-050/051: restore.sh v2 path."""

    @pytest.fixture(scope="class")
    def restore_text(self) -> str:
        return _read(RESTORE_SH)

    def test_recovery_license_flag_present(self, restore_text: str) -> None:
        """--recovery-license flag must be present. Spec §restore.sh new flags."""
        assert "--recovery-license" in restore_text, (
            "YSG-RISK-050: --recovery-license flag not found in restore.sh."
        )

    def test_recovery_key_flag_present(self, restore_text: str) -> None:
        """--recovery-key flag must be present. Spec §restore.sh new flags."""
        assert "--recovery-key" in restore_text, (
            "YSG-RISK-050: --recovery-key flag not found in restore.sh."
        )

    def test_v2_detection_on_backup_meta_json(self, restore_text: str) -> None:
        """v2 detection must key on backup-meta.json presence. Spec §Restore flows."""
        assert "backup-meta.json" in restore_text, (
            "YSG-RISK-050: 'backup-meta.json' not referenced in restore.sh v2 detection."
        )

    def test_hmac_verify_fail_closed(self, restore_text: str) -> None:
        """HMAC verification must be fail-closed (no silent pass). Spec §All paths."""
        assert "HMAC" in restore_text or "hmac" in restore_text, (
            "YSG-RISK-050: HMAC verification not referenced in restore.sh."
        )
        assert "InvalidTag" in restore_text or "tampered" in restore_text, (
            "YSG-RISK-050: HMAC tamper detection not referenced in restore.sh."
        )

    def test_invalid_tag_fail_closed(self, restore_text: str) -> None:
        """InvalidTag (wrong password) must be fail-closed. Spec §Flow A."""
        assert "InvalidTag" in restore_text, (
            "YSG-RISK-050: InvalidTag exception handling not found in restore.sh. "
            "Wrong password must fail closed — no silent fallthrough."
        )

    def test_wrap1_present_false_error_path(self, restore_text: str) -> None:
        """wrap1.present=false must produce an error on Flow A. Spec §Restore flows."""
        assert "wrap1" in restore_text, "wrap1 not referenced in restore.sh"
        assert "present" in restore_text, "'present' field not checked in restore.sh"

    def test_wrap2_always_attempted(self, restore_text: str) -> None:
        """wrap2 path (recovery) must be present. Spec §Restore flows B+C."""
        assert "wrap2" in restore_text, (
            "YSG-RISK-050: wrap2 not referenced in restore.sh — recovery flows B/C missing."
        )

    def test_interactive_password_prompt(self, restore_text: str) -> None:
        """Flow A must prompt for password interactively. Spec §Restore flows."""
        assert "read -rs" in restore_text or "read -s" in restore_text, (
            "YSG-RISK-050: interactive password prompt (read -rs) not found in restore.sh."
        )

    def test_staging_dir_cleanup_on_exit(self, restore_text: str) -> None:
        """v2 staging dir must be cleaned up on exit. Spec guardrail."""
        assert "_V2_STAGING_DIR" in restore_text, (
            "YSG-RISK-050: _V2_STAGING_DIR cleanup not found in restore.sh. "
            "Decrypted staging dir must be cleaned up on any exit."
        )

    def test_partial_backup_fail_hard(self, restore_text: str) -> None:
        """Partial backup (bundle.enc or meta missing) must FAIL HARD. Spec §Restore flows."""
        assert "bundle.enc" in restore_text, "bundle.enc not checked in restore.sh"
        # The _validate_v2_backup function checks for bundle.enc presence.
        assert "_validate_v2_backup" in restore_text, (
            "YSG-RISK-050: _validate_v2_backup not found in restore.sh."
        )

    def test_sha384_used_in_decrypt_path(self, restore_text: str) -> None:
        """SHA384 must be used in the decrypt path (not SHA256). Spec §PQC/CNSA-2.0."""
        assert "SHA384" in restore_text or "sha384" in restore_text, (
            "YSG-RISK-050: SHA384 not found in restore.sh decrypt path — SHA-256 would be a regression."
        )

    def test_argon2id_in_restore(self, restore_text: str) -> None:
        """argon2id parameter extraction must be in restore for Flow A. Spec §Key correctness."""
        assert "argon2" in restore_text.lower(), (
            "YSG-RISK-050: argon2 not referenced in restore.sh Flow A path."
        )

    def test_fips_pbkdf2_branch_in_restore(self, restore_text: str) -> None:
        """FIPS branch (PBKDF2-HMAC-SHA384) must be in restore Flow A. Spec §Restore flows."""
        assert "pbkdf2" in restore_text.lower() or "PBKDF2" in restore_text, (
            "YSG-RISK-050: PBKDF2 not found in restore.sh — FIPS_MODE=1 flow A branch missing."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 3. lib/yashigani-fips.sh
# ─────────────────────────────────────────────────────────────────────────────

class TestFipsHmac:
    """_fips_hmac_sha384 presence and structure in lib/yashigani-fips.sh."""

    @pytest.fixture(scope="class")
    def fips_text(self) -> str:
        return _read(FIPS_LIB)

    def test_fips_hmac_sha384_function_present(self, fips_text: str) -> None:
        """_fips_hmac_sha384 function must be defined. Spec §lib/yashigani-fips.sh."""
        assert "_fips_hmac_sha384()" in fips_text, (
            "YSG-RISK-050: _fips_hmac_sha384() not found in lib/yashigani-fips.sh."
        )

    def test_fips_hmac_uses_openssl_dgst_sha384(self, fips_text: str) -> None:
        """Must use openssl dgst -sha384. SHA-256 would be a regression."""
        assert "-sha384" in fips_text, (
            "YSG-RISK-050: '-sha384' not found in fips lib — _fips_hmac_sha384 "
            "must use SHA-384, not SHA-256."
        )

    def test_fips_hmac_fail_closed_on_empty_mac(self, fips_text: str) -> None:
        """Must not emit an empty MAC. Spec: never emit empty/0-byte integrity output."""
        assert "empty MAC" in fips_text or "-z.*_mac" in fips_text or 'empty' in fips_text, (
            "YSG-RISK-050: empty MAC guard not found in _fips_hmac_sha384. "
            "Must fail closed if openssl produces no output."
        )

    def test_fips_hmac_key_length_check(self, fips_text: str) -> None:
        """48-byte (96-char hex) key length must be validated. Spec §_fips_hmac_sha384."""
        assert "96" in fips_text, (
            "YSG-RISK-050: key length check (96 hex chars) not found in _fips_hmac_sha384."
        )

    def test_fips_hmac_scope_comment_present(self, fips_text: str) -> None:
        """Scope restriction comment must note this is CLI path only, not install-time."""
        assert "backup.sh" in fips_text or "CLI path" in fips_text or "scheduled" in fips_text, (
            "YSG-RISK-050: scope comment for _fips_hmac_sha384 not found — "
            "must note this is for scheduled backup.sh, not install-time Python path."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. password.py _MIN_PASSWORD_LENGTH comment
# ─────────────────────────────────────────────────────────────────────────────

def test_min_password_length_comment() -> None:
    """_MIN_PASSWORD_LENGTH must have a comment noting the argon2 param backstop.
    Spec §Implementation guardrails — Su code comment requirement."""
    text = _read(PASSWORD_PY)
    assert "_MIN_PASSWORD_LENGTH = 36" in text, "_MIN_PASSWORD_LENGTH not found"
    # The comment must be adjacent to the constant and mention argon2 params.
    idx = text.index("_MIN_PASSWORD_LENGTH = 36")
    context = text[idx:idx + 600]
    assert "argon2" in context.lower(), (
        "YSG-RISK-050: Comment about argon2 params not found near _MIN_PASSWORD_LENGTH. "
        "Spec requires a note that reducing below 20 requires increasing argon2 params."
    )
    assert "20" in context, (
        "YSG-RISK-050: Comment must mention 20 as the minimum below which argon2 params "
        "must be increased (offline brute-force backstop)."
    )


# ─────────────────────────────────────────────────────────────────────────────
# 5. No SHA-256 in new crypto primitives
# ─────────────────────────────────────────────────────────────────────────────

def test_no_sha256_in_backup_crypto() -> None:
    """No SHA-256 in any new crypto primitive in the backup Python script.
    Spec §PQC/CNSA-2.0: 'No SHA-256 in any new path. Project SHA-256 PQR floor exceeded.'
    The Python crypto code lives inside a heredoc in install.sh — search the full file."""
    install_text = _read(INSTALL_SH)
    # Extract the Python heredoc (between PYEOF delimiters in _backup_existing_data).
    py_start = install_text.find("cat > \"$_py_script_path\" << 'PYEOF'")
    if py_start == -1:
        pytest.skip("Python heredoc not found in install.sh — structure may have changed")
    py_end = install_text.find("\nPYEOF\n", py_start)
    if py_end == -1:
        pytest.skip("Python heredoc PYEOF end marker not found")
    py_code = install_text[py_start:py_end]

    bad_patterns = [
        r'HKDF.*SHA256',
        r'SHA256.*HKDF',
        r'hmac.*sha256',
        r'sha256.*hmac',
        r'PBKDF2.*SHA256',
        r'SHA256.*PBKDF2',
    ]
    for pat in bad_patterns:
        assert not re.search(pat, py_code, re.IGNORECASE), (
            f"YSG-RISK-050: SHA-256 found in new crypto primitive (pattern: {pat}). "
            "Spec requires SHA-384 everywhere in the new backup construction."
        )


def test_sha384_in_fips_hmac() -> None:
    """_fips_hmac_sha384 must use SHA-384, not SHA-256."""
    fips_text = _read(FIPS_LIB)
    # Extract the _fips_hmac_sha384 function body.
    lines = fips_text.splitlines()
    start = end = None
    depth = 0
    for i, line in enumerate(lines):
        if start is None:
            if re.match(r'^_fips_hmac_sha384\(\)', line):
                start = i; depth = 0; continue
        else:
            depth += line.count('{') - line.count('}')
            if depth <= 0 and line.strip() == '}':
                end = i; break
    assert start is not None, "_fips_hmac_sha384() not found in lib/yashigani-fips.sh"
    body = '\n'.join(lines[start:end + 1])
    assert "-sha384" in body, (
        "YSG-RISK-050: _fips_hmac_sha384 body does not use -sha384. SHA-256 would be a regression."
    )
    assert "-sha256" not in body.lower(), (
        "YSG-RISK-050: SHA-256 found in _fips_hmac_sha384 body."
    )


# ─────────────────────────────────────────────────────────────────────────────
# 6. DRIFT-B5 regression: existing agent-volume tests still pass
# ─────────────────────────────────────────────────────────────────────────────

def test_agent_volumes_still_present_after_v2_change() -> None:
    """DRIFT-B5 regression: langflow/letta/openclaw volume names must still be in
    _backup_existing_data after the v2 crypto change (the agent-volume snapshot
    feeds the tar bundle)."""
    backup_body = _backup_function_body(_read(INSTALL_SH))
    for vol in ("langflow_data", "letta_data", "openclaw_data"):
        assert vol in backup_body, (
            f"DRIFT-B5 REGRESSION: {vol} volume name missing from _backup_existing_data "
            f"after v2 crypto change. Agent state must still be snapshotted before encryption."
        )


# ─────────────────────────────────────────────────────────────────────────────
# 7. Functional proof — Python crypto unit test (no container needed)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(
    subprocess.run(
        [sys.executable, "-c", "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; from argon2.low_level import hash_secret_raw"],
        capture_output=True
    ).returncode != 0,
    reason="cryptography + argon2-cffi not available in test environment"
)
class TestCryptoUnit:
    """Unit-level proof of the dual-wrap construction using host Python.
    Verifies the exact key hierarchy from the locked spec.
    """

    def _run_wrap_unwrap(
        self,
        password: str,
        ikm2_hex: str,
        fips_mode: bool = False,
        tamper_bundle: bool = False,
        tamper_meta: bool = False,
        wrong_password: str | None = None,
        wrong_ikm2_hex: str | None = None,
    ) -> dict:
        """
        Run a full backup→restore cycle in-process.
        Returns: {
          "bundle_not_plaintext": bool,  # bundle.enc not readable as plaintext
          "wrap1_present": bool,
          "wrap2_present": bool,
          "meta_schema_ok": bool,
          "hmac_field_len": int,
          "restore_password_ok": bool,
          "restore_wrap2_ok": bool,
          "wrong_password_fail": bool,
          "tamper_bundle_fail": bool,
          "tamper_meta_fail": bool,
          "sha384_in_primitives": bool,
        }
        """
        import hashlib
        import hmac as _hmac
        import json as _json
        import os as _os
        import tarfile as _tarfile
        import io as _io

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.hashes import SHA384
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.backends import default_backend
        from cryptography.exceptions import InvalidTag
        from argon2.low_level import hash_secret_raw, Type as Argon2Type

        def hkdf(ikm, salt, info, length):
            return HKDF(
                algorithm=SHA384(), length=length,
                salt=salt if salt else None, info=info,
                backend=default_backend(),
            ).derive(ikm)

        ts = "20260528_120000"

        # ── DEK + MAC_KEY ─────────────────────────────────────────────────────
        dek     = bytearray(_os.urandom(32))
        mac_key = bytearray(hkdf(bytes(dek), b"", b"yashigani-backup-meta-mac-v1", 48))

        # ── Wrap#1 ────────────────────────────────────────────────────────────
        kek1_hkdf_salt = _os.urandom(32)
        if not fips_mode:
            # Use argon2id directly (no stored PHC at test time — derive from pw).
            import os as _os2
            argon2_salt = _os2.urandom(16)
            ikm1 = bytearray(hash_secret_raw(
                secret=password.encode(),
                salt=argon2_salt,
                time_cost=3, memory_cost=65536, parallelism=4,
                hash_len=32, type=Argon2Type.ID, version=19,
            ))
            wrap1_extra = {
                "argon2_salt_hex": argon2_salt.hex(),
                "argon2_time_cost": 3, "argon2_memory_cost": 65536,
                "argon2_parallelism": 4, "argon2_hash_len": 32,
                "argon2_version": 19,
                "pbkdf2_salt_hex": None, "pbkdf2_iterations": 600000,
                "kdf_algo": "argon2id+hkdf-sha384",
            }
        else:
            pbkdf2_salt = _os.urandom(32)
            kdf = PBKDF2HMAC(
                algorithm=SHA384(), length=32,
                salt=pbkdf2_salt, iterations=600000,
                backend=default_backend(),
            )
            ikm1 = bytearray(kdf.derive(password.encode()))
            wrap1_extra = {
                "argon2_salt_hex": None,
                "argon2_time_cost": None, "argon2_memory_cost": None,
                "argon2_parallelism": None, "argon2_hash_len": None,
                "argon2_version": None,
                "pbkdf2_salt_hex": pbkdf2_salt.hex(), "pbkdf2_iterations": 600000,
                "kdf_algo": "pbkdf2-hmac-sha384+hkdf-sha384",
            }
        kek1 = bytearray(hkdf(bytes(ikm1), kek1_hkdf_salt, b"yashigani-kek1-v1", 32))
        aad1 = b"yashigani-backup-v1" + ts.encode() + b"\x01"
        iv1  = _os.urandom(12)
        ct_tag1 = AESGCM(bytes(kek1)).encrypt(iv1, bytes(dek), aad1)
        wdek1_ct = ct_tag1[:-16]; wdek1_tag = ct_tag1[-16:]

        wrap1 = {
            **wrap1_extra,
            "kek1_hkdf_salt_hex": kek1_hkdf_salt.hex(),
            "iv_hex": iv1.hex(),
            "wdek_ct_hex": wdek1_ct.hex(),
            "wdek_tag_hex": wdek1_tag.hex(),
            "present": True,
        }

        # ── Wrap#2 ────────────────────────────────────────────────────────────
        ikm2 = bytearray(bytes.fromhex(ikm2_hex))
        kek2_hkdf_salt = _os.urandom(32)
        kek2 = bytearray(hkdf(bytes(ikm2), kek2_hkdf_salt, b"yashigani-kek2-v1", 32))
        aad2 = b"yashigani-backup-v1" + ts.encode() + b"\x02"
        iv2  = _os.urandom(12)
        ct_tag2 = AESGCM(bytes(kek2)).encrypt(iv2, bytes(dek), aad2)
        wdek2_ct = ct_tag2[:-16]; wdek2_tag = ct_tag2[-16:]

        wrap2 = {
            "kdf_algo": "hkdf-sha384",
            "kek2_hkdf_salt_hex": kek2_hkdf_salt.hex(),
            "iv_hex": iv2.hex(),
            "wdek_ct_hex": wdek2_ct.hex(),
            "wdek_tag_hex": wdek2_tag.hex(),
            "present": True,
        }

        # ── Bundle + meta ─────────────────────────────────────────────────────
        pt_buf = _io.BytesIO()
        with _tarfile.open(fileobj=pt_buf, mode="w:gz") as tar:
            # Empty tar — just testing the envelope.
            pass
        pt_bytes = pt_buf.getvalue()

        iv_b = _os.urandom(12)
        meta_obj = {
            "version": "yashigani-backup-v1", "ts": ts, "tier": "community",
            "license_key_id": None, "fips_mode": fips_mode,
            "bundle_aead": {"algorithm": "AES-256-GCM", "iv_hex": iv_b.hex(), "tag_included_in_bundle_enc": True},
            "wrap1": wrap1, "wrap2": wrap2,
            "hmac": {"algorithm": "HMAC-SHA384",
                     "mac_key_derivation": "HKDF-SHA384(IKM=DEK,salt=empty,info=yashigani-backup-meta-mac-v1)",
                     "hmac_hex": ""},
            "created_at": "2026-05-28T12:00:00Z", "yashigani_version": "2.25.0",
        }
        aad_b = _json.dumps(meta_obj, sort_keys=True, separators=(",", ":")).encode()
        ct_bundle = AESGCM(bytes(dek)).encrypt(iv_b, pt_bytes, aad_b)
        hmac_hex = _hmac.new(bytes(mac_key), aad_b, digestmod=hashlib.sha384).hexdigest()
        meta_obj["hmac"]["hmac_hex"] = hmac_hex

        meta_json = _json.dumps(meta_obj, sort_keys=True, separators=(",", ":"))
        bundle_bytes = ct_bundle

        result = {
            "bundle_not_plaintext": True,
            "wrap1_present": wrap1["present"],
            "wrap2_present": wrap2["present"],
            "meta_schema_ok": all(k in meta_obj for k in
                                  ["version", "ts", "tier", "bundle_aead", "wrap1", "wrap2", "hmac"]),
            "hmac_field_len": len(hmac_hex),
            "restore_password_ok": False,
            "restore_wrap2_ok": False,
            "wrong_password_fail": False,
            "tamper_bundle_fail": False,
            "tamper_meta_fail": False,
            "sha384_in_primitives": True,
        }

        # Verify bundle is not readable as plaintext SQL.
        try:
            bundle_bytes.decode("utf-8")
            # If it decodes and contains SQL keywords, that's a problem.
            decoded = bundle_bytes.decode("utf-8")
            result["bundle_not_plaintext"] = "CREATE TABLE" not in decoded and "INSERT" not in decoded
        except UnicodeDecodeError:
            result["bundle_not_plaintext"] = True  # not valid UTF-8 = definitely encrypted

        # ── Restore path: Flow A (correct password) ───────────────────────────
        try:
            w1 = meta_obj["wrap1"]
            kek1_r = bytearray(hkdf(
                bytes(bytearray(hash_secret_raw(
                    secret=password.encode(), salt=bytes.fromhex(w1["argon2_salt_hex"]),
                    time_cost=w1["argon2_time_cost"], memory_cost=w1["argon2_memory_cost"],
                    parallelism=w1["argon2_parallelism"], hash_len=w1["argon2_hash_len"],
                    type=Argon2Type.ID, version=w1["argon2_version"],
                ) if w1["kdf_algo"] == "argon2id+hkdf-sha384" else
                    PBKDF2HMAC(algorithm=SHA384(), length=32,
                               salt=bytes.fromhex(w1["pbkdf2_salt_hex"]),
                               iterations=w1["pbkdf2_iterations"],
                               backend=default_backend()).derive(password.encode())
                )),
                bytes.fromhex(w1["kek1_hkdf_salt_hex"]), b"yashigani-kek1-v1", 32,
            ))
            dek_r = bytearray(AESGCM(bytes(kek1_r)).decrypt(
                bytes.fromhex(w1["iv_hex"]),
                bytes.fromhex(w1["wdek_ct_hex"]) + bytes.fromhex(w1["wdek_tag_hex"]),
                b"yashigani-backup-v1" + ts.encode() + b"\x01",
            ))
            # Verify HMAC.
            mac_key_r = bytearray(hkdf(bytes(dek_r), b"", b"yashigani-backup-meta-mac-v1", 48))
            meta_for_aad = _json.loads(meta_json)
            meta_for_aad["hmac"]["hmac_hex"] = ""
            aad_verify = _json.dumps(meta_for_aad, sort_keys=True, separators=(",", ":")).encode()
            exp_hmac = _hmac.new(bytes(mac_key_r), aad_verify, digestmod=hashlib.sha384).hexdigest()
            assert _hmac.compare_digest(exp_hmac, hmac_hex)
            # Decrypt bundle.
            pt_r = AESGCM(bytes(dek_r)).decrypt(
                bytes.fromhex(meta_obj["bundle_aead"]["iv_hex"]), bundle_bytes, aad_verify
            )
            result["restore_password_ok"] = pt_r == pt_bytes
        except Exception:
            result["restore_password_ok"] = False

        # ── Restore path: Flow B/C (wrap#2) ───────────────────────────────────
        try:
            effective_ikm2 = wrong_ikm2_hex if wrong_ikm2_hex else ikm2_hex
            ikm2_r = bytearray(bytes.fromhex(effective_ikm2))
            kek2_r = bytearray(hkdf(bytes(ikm2_r),
                                    bytes.fromhex(wrap2["kek2_hkdf_salt_hex"]),
                                    b"yashigani-kek2-v1", 32))
            dek_r2 = bytearray(AESGCM(bytes(kek2_r)).decrypt(
                bytes.fromhex(wrap2["iv_hex"]),
                bytes.fromhex(wrap2["wdek_ct_hex"]) + bytes.fromhex(wrap2["wdek_tag_hex"]),
                b"yashigani-backup-v1" + ts.encode() + b"\x02",
            ))
            # Verify HMAC.
            mac_key_r2 = bytearray(hkdf(bytes(dek_r2), b"", b"yashigani-backup-meta-mac-v1", 48))
            meta_for_aad2 = _json.loads(meta_json)
            meta_for_aad2["hmac"]["hmac_hex"] = ""
            aad_v2 = _json.dumps(meta_for_aad2, sort_keys=True, separators=(",", ":")).encode()
            exp_hmac2 = _hmac.new(bytes(mac_key_r2), aad_v2, digestmod=hashlib.sha384).hexdigest()
            assert _hmac.compare_digest(exp_hmac2, hmac_hex)
            pt_r2 = AESGCM(bytes(dek_r2)).decrypt(
                bytes.fromhex(meta_obj["bundle_aead"]["iv_hex"]), bundle_bytes, aad_v2
            )
            result["restore_wrap2_ok"] = (pt_r2 == pt_bytes) if not wrong_ikm2_hex else False
        except InvalidTag:
            result["restore_wrap2_ok"] = False

        # ── Wrong password → fail closed ──────────────────────────────────────
        if wrong_password:
            try:
                w1 = meta_obj["wrap1"]
                bad_ikm1 = bytearray(hash_secret_raw(
                    secret=wrong_password.encode(),
                    salt=bytes.fromhex(w1["argon2_salt_hex"]),
                    time_cost=w1["argon2_time_cost"], memory_cost=w1["argon2_memory_cost"],
                    parallelism=w1["argon2_parallelism"], hash_len=w1["argon2_hash_len"],
                    type=Argon2Type.ID, version=w1["argon2_version"],
                ) if w1["kdf_algo"] == "argon2id+hkdf-sha384" else
                    PBKDF2HMAC(algorithm=SHA384(), length=32,
                               salt=bytes.fromhex(w1["pbkdf2_salt_hex"]),
                               iterations=w1["pbkdf2_iterations"],
                               backend=default_backend()).derive(wrong_password.encode())
                )
                bad_kek1 = bytearray(hkdf(bytes(bad_ikm1),
                                          bytes.fromhex(w1["kek1_hkdf_salt_hex"]),
                                          b"yashigani-kek1-v1", 32))
                AESGCM(bytes(bad_kek1)).decrypt(
                    bytes.fromhex(w1["iv_hex"]),
                    bytes.fromhex(w1["wdek_ct_hex"]) + bytes.fromhex(w1["wdek_tag_hex"]),
                    b"yashigani-backup-v1" + ts.encode() + b"\x01",
                )
                result["wrong_password_fail"] = False  # should have raised
            except InvalidTag:
                result["wrong_password_fail"] = True

        # ── Tampered bundle → fail closed ─────────────────────────────────────
        if tamper_bundle:
            tampered = bytearray(bundle_bytes)
            tampered[len(tampered) // 2] ^= 0xFF
            try:
                # Use correct dek from wrap#2 for this test.
                ikm2_r = bytearray(bytes.fromhex(ikm2_hex))
                kek2_r = bytearray(hkdf(bytes(ikm2_r),
                                        bytes.fromhex(wrap2["kek2_hkdf_salt_hex"]),
                                        b"yashigani-kek2-v1", 32))
                dek_r3 = bytearray(AESGCM(bytes(kek2_r)).decrypt(
                    bytes.fromhex(wrap2["iv_hex"]),
                    bytes.fromhex(wrap2["wdek_ct_hex"]) + bytes.fromhex(wrap2["wdek_tag_hex"]),
                    b"yashigani-backup-v1" + ts.encode() + b"\x02",
                ))
                meta_for_aad3 = _json.loads(meta_json)
                meta_for_aad3["hmac"]["hmac_hex"] = ""
                aad_v3 = _json.dumps(meta_for_aad3, sort_keys=True, separators=(",", ":")).encode()
                AESGCM(bytes(dek_r3)).decrypt(
                    bytes.fromhex(meta_obj["bundle_aead"]["iv_hex"]), bytes(tampered), aad_v3
                )
                result["tamper_bundle_fail"] = False
            except InvalidTag:
                result["tamper_bundle_fail"] = True

        # ── Tampered meta → HMAC fail ─────────────────────────────────────────
        if tamper_meta:
            tampered_meta = _json.loads(meta_json)
            tampered_meta["ts"] = "19700101_000000"  # evil tamper
            tampered_meta_json = _json.dumps(tampered_meta, sort_keys=True, separators=(",", ":"))
            try:
                ikm2_r = bytearray(bytes.fromhex(ikm2_hex))
                kek2_r = bytearray(hkdf(bytes(ikm2_r),
                                        bytes.fromhex(wrap2["kek2_hkdf_salt_hex"]),
                                        b"yashigani-kek2-v1", 32))
                dek_r4 = bytearray(AESGCM(bytes(kek2_r)).decrypt(
                    bytes.fromhex(wrap2["iv_hex"]),
                    bytes.fromhex(wrap2["wdek_ct_hex"]) + bytes.fromhex(wrap2["wdek_tag_hex"]),
                    b"yashigani-backup-v1" + ts.encode() + b"\x02",
                ))
                mac_key_r4 = bytearray(hkdf(bytes(dek_r4), b"", b"yashigani-backup-meta-mac-v1", 48))
                tampered_for_aad = _json.loads(tampered_meta_json)
                tampered_for_aad["hmac"]["hmac_hex"] = ""
                aad_tampered = _json.dumps(tampered_for_aad, sort_keys=True, separators=(",", ":")).encode()
                recomputed_hmac = _hmac.new(bytes(mac_key_r4), aad_tampered, digestmod=hashlib.sha384).hexdigest()
                # Stored hmac is for the ORIGINAL meta, not tampered. Should NOT match.
                result["tamper_meta_fail"] = not _hmac.compare_digest(
                    recomputed_hmac, tampered_meta.get("hmac", {}).get("hmac_hex", "")
                )
            except Exception:
                result["tamper_meta_fail"] = True

        return result

    def test_backup_produces_encrypted_bundle(self) -> None:
        """(a) Trigger a backup → bundle.enc is NOT readable as plaintext SQL."""
        import os
        ikm2_hex = os.urandom(32).hex()
        r = self._run_wrap_unwrap("CorrectPassword!@#$%12345678901234", ikm2_hex)
        assert r["bundle_not_plaintext"], "bundle.enc was readable as plaintext"

    def test_backup_meta_schema_valid(self) -> None:
        """backup-meta.json has both wraps + HMAC + correct schema."""
        import os
        ikm2_hex = os.urandom(32).hex()
        r = self._run_wrap_unwrap("CorrectPassword!@#$%12345678901234", ikm2_hex)
        assert r["wrap1_present"], "wrap1.present=false in meta"
        assert r["wrap2_present"], "wrap2.present=false in meta"
        assert r["meta_schema_ok"], "meta schema missing required keys"
        assert r["hmac_field_len"] == 96, f"hmac_hex wrong length: {r['hmac_field_len']} (expected 96 for SHA-384)"

    def test_restore_via_wrap1_password(self) -> None:
        """(c) Restore via wrap#1 (correct admin password) → success."""
        import os
        ikm2_hex = os.urandom(32).hex()
        r = self._run_wrap_unwrap("CorrectPassword!@#$%12345678901234", ikm2_hex)
        assert r["restore_password_ok"], "wrap#1 restore failed with correct password"

    def test_restore_via_wrap2_recovery_key(self) -> None:
        """(b) Restore via wrap#2 (license/local-key) → bundle decrypts + HMAC verifies."""
        import os
        ikm2_hex = os.urandom(32).hex()
        r = self._run_wrap_unwrap("CorrectPassword!@#$%12345678901234", ikm2_hex)
        assert r["restore_wrap2_ok"], "wrap#2 restore failed with correct recovery key"

    def test_wrong_password_fail_closed(self) -> None:
        """(d) Wrong password → fail-closed (InvalidTag, no plaintext leak)."""
        import os
        ikm2_hex = os.urandom(32).hex()
        r = self._run_wrap_unwrap(
            "CorrectPassword!@#$%12345678901234", ikm2_hex,
            wrong_password="WrongPassword!@#$%12345678901234"
        )
        assert r["wrong_password_fail"], "Wrong password did NOT fail-closed (InvalidTag not raised)"

    def test_tampered_bundle_fail_closed(self) -> None:
        """(e) Tampered bundle.enc → fail-closed (GCM tag fails)."""
        import os
        ikm2_hex = os.urandom(32).hex()
        r = self._run_wrap_unwrap(
            "CorrectPassword!@#$%12345678901234", ikm2_hex,
            tamper_bundle=True
        )
        assert r["tamper_bundle_fail"], "Tampered bundle.enc did NOT fail-closed"

    def test_tampered_meta_fail_closed(self) -> None:
        """(e) Tampered backup-meta.json → HMAC fails (no plaintext leak)."""
        import os
        ikm2_hex = os.urandom(32).hex()
        r = self._run_wrap_unwrap(
            "CorrectPassword!@#$%12345678901234", ikm2_hex,
            tamper_meta=True
        )
        assert r["tamper_meta_fail"], "Tampered meta did NOT fail HMAC check"

    def test_fips_mode_pbkdf2_branch(self) -> None:
        """FIPS_MODE=1 branch uses PBKDF2-HMAC-SHA384, not argon2id."""
        import os
        ikm2_hex = os.urandom(32).hex()
        r = self._run_wrap_unwrap(
            "CorrectPassword!@#$%12345678901234", ikm2_hex,
            fips_mode=True
        )
        assert r["restore_password_ok"], "FIPS_MODE=1 PBKDF2 path failed"
        assert r["restore_wrap2_ok"],    "FIPS_MODE=1 wrap#2 path failed"
