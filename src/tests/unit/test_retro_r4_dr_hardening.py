"""
Regression tests for RETRO-R4-1, RETRO-R4-2, RETRO-R4-3 — v2.23.2 DR hardening.

RETRO-R4-1: restore.sh CA bundle parity
  - _refresh_pgdata_ca must concatenate ca_root.crt + ca_intermediate.crt,
    not write only ca_root.crt (which left the postgres trust store incomplete).

RETRO-R4-2: asyncpg restart resilience
  - connect_with_retry_sync has a connect_timeout and retries on OperationalError.
  - create_pool passes timeout= so per-connection establishment has a cap.
  - advisory lock bootstrap in app.py uses connect_with_retry_sync.

RETRO-R4-3: backup integrity — dual-wrap HMAC-SHA384 (ISSUE-250-02)
  SUPERSESSION NOTE: The original RETRO-R4-3 control (openssl dgst -sha256 -sign /
  MANIFEST.sha256 / MANIFEST.sha256.sig / ca_intermediate.key) was REPLACED in
  v2.25.0-rc1 (ISSUE-250-02) by the YSG-RISK-050/051 dual-wrap encrypted backup:
    - All sensitive content (secrets/, .env, postgres_dump.sql, agent-volumes/) is
      encrypted with AES-256-GCM under a random DEK.
    - The DEK is dual-wrapped (wrap#1: argon2id admin-password path;
      wrap#2: license/.ysg bytes or YASHIGANI_DB_AES_KEY).
    - Integrity of backup-meta.json is protected by HMAC-SHA384, key-separated
      via HKDF-SHA384(IKM=DEK, info="yashigani-backup-meta-mac-v1").
    - Output artifacts: bundle.enc (0600, AES-256-GCM ciphertext) +
      backup-meta.json (0444, cleartext envelope with HMAC).
    - Old MANIFEST.sha256 / MANIFEST.sha256.sig / openssl dgst -sha256 -sign
      constructs are GONE from install.sh. The v1 files are actively cleaned up
      as guardrail 4 of the locked spec (install.sh lines 3063-3068).
  These tests assert the REAL current mechanism. Each assertion is sourced
  directly against the install.sh/restore.sh lines cited in the test body.

Last updated: 2026-05-29T00:00:00+01:00
"""
from __future__ import annotations

import importlib
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

SRC = Path(__file__).parent.parent.parent / "yashigani"
REPO = Path(__file__).parent.parent.parent.parent  # /Users/max/Documents/Claude/yashigani
RESTORE_SH = REPO / "restore.sh"
INSTALL_SH = REPO / "install.sh"
POSTGRES_PY = SRC / "db" / "postgres.py"
DB_INIT_PY = SRC / "db" / "__init__.py"
APP_PY = SRC / "backoffice" / "app.py"


# =============================================================================
# RETRO-R4-1: CA bundle parity in restore.sh
# =============================================================================

class TestRetroR41CaBundleParity:
    """restore.sh _refresh_pgdata_ca must write root.crt as a concatenation of
    ca_root.crt AND ca_intermediate.crt, matching install.sh."""

    def test_restore_sh_concatenates_ca_bundle(self):
        """Verify _refresh_pgdata_ca uses `cat ca_root.crt ca_intermediate.crt`
        not just `install -m 0644 ... ca_root.crt`."""
        assert RESTORE_SH.exists(), f"restore.sh not found at {RESTORE_SH}"
        content = RESTORE_SH.read_text()

        # Must contain the cat concatenation, matching install.sh pattern
        assert "cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt" in content, (
            "RETRO-R4-1: _refresh_pgdata_ca must concatenate ca_root.crt + ca_intermediate.crt "
            "into ${PGDATA}/root.crt to match install.sh trust bundle"
        )

    def test_restore_sh_does_not_solo_install_ca_root(self):
        """Ensure there is no bare `install ... ca_root.crt ${PGDATA}/root.crt` call
        that would write only the root (incomplete chain)."""
        assert RESTORE_SH.exists()
        content = RESTORE_SH.read_text()

        # The old pattern that caused the bug was a single-line:
        # install -m 0644 -o postgres -g postgres /run/secrets/ca_root.crt "${PGDATA}/root.crt"
        # (no re.DOTALL: must match on a single line to avoid false-positives from
        # the legitimate `install ... ca_root.crt "${PGDATA}/server.crt"` line which
        # appears on the same logical block but targets a different destination).
        bad_pattern = re.compile(
            r'install\s+-m\s+0644.*?ca_root\.crt[^"\n]*\$\{?PGDATA\}?/root\.crt',
        )
        assert not bad_pattern.search(content), (
            "RETRO-R4-1: Found solo `install ca_root.crt -> root.crt` — "
            "must use `cat ca_root.crt ca_intermediate.crt > root.crt` to match install.sh"
        )

    def test_install_sh_ca_bundle_pattern_matches_restore(self):
        """install.sh and restore.sh must produce the same root.crt content.
        Both must use cat ca_root.crt ca_intermediate.crt."""
        assert INSTALL_SH.exists()
        assert RESTORE_SH.exists()

        install_content = INSTALL_SH.read_text()
        restore_content = RESTORE_SH.read_text()

        # install.sh reference pattern
        assert "cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt" in install_content, (
            "install.sh trust bundle pattern changed — update this test"
        )
        # restore.sh must match
        assert "cat /run/secrets/ca_root.crt /run/secrets/ca_intermediate.crt" in restore_content, (
            "RETRO-R4-1: restore.sh CA bundle pattern does not match install.sh"
        )


# =============================================================================
# RETRO-R4-2: asyncpg restart resilience
# =============================================================================

class TestRetroR42AsyncpgRestart:
    """connect_with_retry_sync and create_pool must handle postgres restarts
    without hanging indefinitely."""

    def test_connect_with_retry_sync_exists(self):
        """connect_with_retry_sync must be importable from yashigani.db."""
        from yashigani.db import connect_with_retry_sync  # noqa: F401
        assert callable(connect_with_retry_sync)

    def test_connect_with_retry_sync_exported(self):
        """connect_with_retry_sync must be in yashigani.db.__all__."""
        import yashigani.db as db_module
        assert "connect_with_retry_sync" in db_module.__all__

    def _make_mock_psycopg2(self):
        """Build a minimal psycopg2 mock for unit tests (not installed in local venv)."""
        mock_pg2 = MagicMock()
        mock_pg2.OperationalError = type("OperationalError", (Exception,), {})
        return mock_pg2

    def test_connect_with_retry_sync_retries_on_operational_error(self):
        """Must retry up to max_attempts on psycopg2.OperationalError."""
        import sys

        mock_pg2 = self._make_mock_psycopg2()

        call_count = 0
        mock_conn = MagicMock()

        def _mock_connect(dsn):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise mock_pg2.OperationalError("connection refused")
            return mock_conn

        mock_pg2.connect = _mock_connect

        with patch.dict(sys.modules, {"psycopg2": mock_pg2}):
            # Re-import to pick up the mock
            import importlib
            import yashigani.db.postgres as _pg_mod
            importlib.reload(_pg_mod)
            try:
                with patch("time.sleep"):
                    result = _pg_mod.connect_with_retry_sync(
                        "postgresql://u:p@localhost:5432/db",
                        max_attempts=5,
                        backoff_s=1.0,
                    )
                assert result is mock_conn
                assert call_count == 3
            finally:
                importlib.reload(_pg_mod)  # restore

    def test_connect_with_retry_sync_raises_after_max_attempts(self):
        """Must raise OperationalError after max_attempts exhausted."""
        import sys

        mock_pg2 = self._make_mock_psycopg2()
        mock_pg2.connect = MagicMock(side_effect=mock_pg2.OperationalError("refused"))

        with patch.dict(sys.modules, {"psycopg2": mock_pg2}):
            import yashigani.db.postgres as _pg_mod
            importlib.reload(_pg_mod)
            try:
                with patch("time.sleep"):
                    with pytest.raises(mock_pg2.OperationalError):
                        _pg_mod.connect_with_retry_sync(
                            "postgresql://u:p@localhost:5432/db",
                            max_attempts=3,
                            backoff_s=1.0,
                        )
            finally:
                importlib.reload(_pg_mod)

    def test_connect_with_retry_sync_injects_connect_timeout(self):
        """connect_timeout must be injected into the DSN as a query parameter."""
        import sys

        mock_pg2 = self._make_mock_psycopg2()
        captured_dsns: list[str] = []

        def _mock_connect(dsn):
            captured_dsns.append(dsn)
            return MagicMock()

        mock_pg2.connect = _mock_connect

        with patch.dict(sys.modules, {"psycopg2": mock_pg2}):
            import yashigani.db.postgres as _pg_mod
            importlib.reload(_pg_mod)
            try:
                _pg_mod.connect_with_retry_sync(
                    "postgresql://u:p@localhost:5432/db",
                    connect_timeout=15,
                )
                assert len(captured_dsns) == 1
                assert "connect_timeout=15" in captured_dsns[0], (
                    f"connect_timeout not injected into DSN: {captured_dsns[0]}"
                )
            finally:
                importlib.reload(_pg_mod)

    def test_create_pool_passes_timeout(self):
        """create_pool must pass timeout= to asyncpg.create_pool so per-connection
        establishment is bounded (RETRO-R4-2 fix)."""
        assert POSTGRES_PY.exists()
        content = POSTGRES_PY.read_text()

        # The fix adds `timeout=_CONNECT_TIMEOUT_S` to create_pool call
        assert "timeout=" in content, (
            "RETRO-R4-2: create_pool must pass timeout= to asyncpg.create_pool"
        )
        assert "_CONNECT_TIMEOUT_S" in content, (
            "RETRO-R4-2: _CONNECT_TIMEOUT_S constant must be defined and used"
        )

    def test_app_py_uses_connect_with_retry(self):
        """app.py advisory lock bootstrap must use connect_with_retry_sync,
        not bare psycopg2.connect()."""
        assert APP_PY.exists()
        content = APP_PY.read_text()

        assert "connect_with_retry_sync" in content, (
            "RETRO-R4-2: backoffice app.py advisory lock must use connect_with_retry_sync "
            "not bare psycopg2.connect() (which hangs on pg restart)"
        )
        # Should NOT have bare psycopg2.connect( for the advisory lock
        # (it may appear in a comment explaining the old code, but not as a call)
        import ast
        try:
            tree = ast.parse(content)
        except SyntaxError:
            pytest.skip("app.py has syntax error — cannot AST-check")
            return

        class _FindPsycopg2Connect(ast.NodeVisitor):
            found: list[int] = []
            def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
                # Match _psycopg2.connect(...) or psycopg2.connect(...)
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "connect":
                        if isinstance(node.func.value, ast.Name):
                            if "psycopg2" in node.func.value.id:
                                self.found.append(node.lineno)
                self.generic_visit(node)

        finder = _FindPsycopg2Connect()
        finder.visit(tree)
        assert not finder.found, (
            f"RETRO-R4-2: bare psycopg2.connect() call found at lines {finder.found} in app.py — "
            "must use connect_with_retry_sync instead"
        )

    def test_db_init_uses_connect_with_retry(self):
        """run_migrations() in db/__init__.py must use connect_with_retry_sync."""
        assert DB_INIT_PY.exists()
        content = DB_INIT_PY.read_text()

        assert "connect_with_retry_sync" in content, (
            "RETRO-R4-2: run_migrations() must use connect_with_retry_sync "
            "not bare psycopg2.connect() for the advisory lock connection"
        )


# =============================================================================
# RETRO-R4-3: backup integrity — dual-wrap HMAC-SHA384 (ISSUE-250-02)
# =============================================================================

class TestRetroR43BackupSignatureVerify:
    """install.sh _backup_existing_data + restore.sh validate_backup must implement
    the YSG-RISK-050/051 dual-wrap HMAC-SHA384 backup integrity control introduced
    in v2.25.0-rc1 (ISSUE-250-02), which supersedes the original RETRO-R4-3
    openssl dgst -sha256 -sign / MANIFEST.sha256 / MANIFEST.sha256.sig mechanism.

    Assertions are sourced directly against named install.sh and restore.sh line
    ranges; any assertion failure is a regression against the locked spec."""

    def test_install_sh_dual_wrap_backup_replaces_openssl_sign(self):
        """install.sh _backup_existing_data must use the dual-wrap encrypted backup
        (YSG-RISK-050/051) and must NOT use the removed openssl dgst -sha256 -sign
        mechanism.

        Verified against install.sh lines 2512-2546 (spec comment block) and
        lines 2881-2883 (Python inline: hmac_hex computation).
        Absence of openssl dgst -sha256 -sign verified against full file scan."""
        assert INSTALL_SH.exists()
        content = INSTALL_SH.read_text()

        # ── Presence: dual-wrap spec block ────────────────────────────────────
        # install.sh line 2512: "# ── YSG-RISK-050/051: Dual-wrap signed+encrypted backup"
        assert "YSG-RISK-050/051" in content, (
            "RETRO-R4-3/ISSUE-250-02: install.sh must contain the YSG-RISK-050/051 "
            "dual-wrap backup block (lines 2512+)"
        )
        # install.sh line 2518: "# HMAC-SHA384 (key-separated via HKDF) covers the cleartext backup-meta.json."
        assert "HMAC-SHA384" in content, (
            "RETRO-R4-3/ISSUE-250-02: install.sh must contain HMAC-SHA384 in the "
            "dual-wrap spec (line 2518)"
        )
        # install.sh line 2531: "# bundle.enc = AES-256-GCM(DEK, IV_B, aad=meta_bytes_with_empty_hmac, pt=tar.gz)"
        assert "bundle.enc" in content, (
            "RETRO-R4-3/ISSUE-250-02: install.sh must reference bundle.enc as the "
            "encrypted backup artifact (line 2531)"
        )
        # install.sh line 2731: "meta_path = output / 'backup-meta.json'"
        assert "backup-meta.json" in content, (
            "RETRO-R4-3/ISSUE-250-02: install.sh must reference backup-meta.json as "
            "the cleartext envelope artifact (line 2731)"
        )
        # install.sh line 2525: "MAC_KEY = HKDF-SHA384(DEK, info=b'yashigani-backup-meta-mac-v1', len=48)"
        assert "HKDF-SHA384" in content, (
            "RETRO-R4-3/ISSUE-250-02: install.sh must contain HKDF-SHA384 key "
            "derivation for the MAC key (line 2525)"
        )
        # install.sh line 2853: '"version": "yashigani-backup-v1"'
        assert '"yashigani-backup-v1"' in content, (
            "RETRO-R4-3/ISSUE-250-02: install.sh must write version='yashigani-backup-v1' "
            "into backup-meta.json (line 2853)"
        )

        # ── Absence: old v1 openssl-sign mechanism is gone ────────────────────
        # install.sh was audited: the only MANIFEST.sha256* occurrences are the
        # cleanup `rm -f` lines at 3067-3068 (guardrail 4 removes v1 leftovers).
        # There must be NO `openssl dgst -sha256 -sign` call anywhere.
        assert "openssl dgst -sha256 -sign" not in content, (
            "RETRO-R4-3/ISSUE-250-02: install.sh must NOT contain `openssl dgst -sha256 -sign` "
            "— the v1 manifest-signing mechanism was superseded by dual-wrap HMAC-SHA384"
        )

    def test_install_sh_hmac_derivation_info_string(self):
        """The MAC key info string used by HKDF-SHA384 must be exactly
        'yashigani-backup-meta-mac-v1' — any change breaks restore compatibility.

        Verified against install.sh line 2525 (spec comment) and line 2750
        (Python inline: _hkdf_sha384 call with the literal info string)."""
        assert INSTALL_SH.exists()
        content = INSTALL_SH.read_text()

        # install.sh line 2750: bytes(dek), b"", b"yashigani-backup-meta-mac-v1", 48
        assert "yashigani-backup-meta-mac-v1" in content, (
            "RETRO-R4-3/ISSUE-250-02: install.sh HKDF info string must be "
            "'yashigani-backup-meta-mac-v1' (lines 2525 + 2750)"
        )

    def test_install_sh_bundle_enc_written_atomically_0600(self):
        """bundle.enc must be written atomically (tmp→rename) and chmod'd 0600.
        This is the CWE-732 guardrail for the primary encrypted artifact.

        Verified against install.sh lines 2868-2869 (Python inline: os.chmod 0o600
        + os.rename) and line 3051 (shell: install -m 0600 ...)."""
        assert INSTALL_SH.exists()
        content = INSTALL_SH.read_text()

        # install.sh line 2868: os.chmod(str(bundle_enc_tmp), 0o600)
        assert "0o600" in content, (
            "RETRO-R4-3/ISSUE-250-02: install.sh Python crypto must chmod bundle.enc.tmp "
            "to 0o600 before atomic rename (line 2868)"
        )
        # install.sh line 3051: install -m 0600 ... bundle.enc
        assert "install -m 0600" in content and "bundle.enc" in content, (
            "RETRO-R4-3/ISSUE-250-02: install.sh must use `install -m 0600` when staging "
            "bundle.enc to the final backup_dir (line 3051)"
        )
        # install.sh line 2869: os.rename(str(bundle_enc_tmp), str(bundle_enc_path))
        assert "os.rename" in content, (
            "RETRO-R4-3/ISSUE-250-02: install.sh must use os.rename for atomic write "
            "of bundle.enc (line 2869)"
        )

    def test_install_sh_v1_manifest_files_cleaned_up(self):
        """After dual-wrap encryption, install.sh must actively remove any
        MANIFEST.sha256 / MANIFEST.sha256.sig v1 leftovers (spec guardrail 4).

        Verified against install.sh lines 3067-3068."""
        assert INSTALL_SH.exists()
        content = INSTALL_SH.read_text()

        # install.sh line 3067: rm -f  "${backup_dir}/MANIFEST.sha256"
        assert 'rm -f' in content and 'MANIFEST.sha256' in content, (
            "RETRO-R4-3/ISSUE-250-02: install.sh must rm -f MANIFEST.sha256 after "
            "dual-wrap encryption to prevent v1 artifact leakage (line 3067)"
        )
        # install.sh line 3068: rm -f  "${backup_dir}/MANIFEST.sha256.sig"
        assert "MANIFEST.sha256.sig" in content, (
            "RETRO-R4-3/ISSUE-250-02: install.sh must also rm -f MANIFEST.sha256.sig "
            "(line 3068)"
        )
        # Verify the rm comes AFTER the bundle.enc success check
        # (cleanup is only safe once encryption succeeded).
        bundle_install_pos = content.find("install -m 0600")
        manifest_rm_pos = content.find("rm -f", bundle_install_pos)
        assert manifest_rm_pos > bundle_install_pos, (
            "RETRO-R4-3/ISSUE-250-02: MANIFEST.sha256 rm must appear after "
            "bundle.enc is successfully staged (spec guardrail 4 ordering)"
        )

    def test_restore_sh_v2_backup_detected_by_meta_file(self):
        """restore.sh validate_backup must detect a v2 backup by the presence of
        backup-meta.json and dispatch to _validate_v2_backup.

        Verified against restore.sh lines 708-710 (validate_backup v2 branch)."""
        assert RESTORE_SH.exists()
        content = RESTORE_SH.read_text()

        # restore.sh line 708: if [[ -f "${backup_dir}/backup-meta.json" ]]; then
        assert 'backup-meta.json' in content, (
            "RETRO-R4-3/ISSUE-250-02: restore.sh validate_backup must check for "
            "backup-meta.json to detect a v2 backup (line 708)"
        )
        # restore.sh line 709: _validate_v2_backup "$backup_dir"
        assert "_validate_v2_backup" in content, (
            "RETRO-R4-3/ISSUE-250-02: restore.sh must call _validate_v2_backup for "
            "v2 encrypted backups (line 709)"
        )

    def test_restore_sh_v2_requires_bundle_enc(self):
        """_validate_v2_backup must hard-fail if bundle.enc is absent alongside
        backup-meta.json — a partial backup must be rejected.

        Verified against restore.sh lines 339-342 (_validate_v2_backup)."""
        assert RESTORE_SH.exists()
        content = RESTORE_SH.read_text()

        # restore.sh line 339: if [[ ! -f "${backup_dir}/bundle.enc" ]]; then
        assert "bundle.enc" in content, (
            "RETRO-R4-3/ISSUE-250-02: restore.sh _validate_v2_backup must check for "
            "bundle.enc and hard-fail if absent (lines 339-342)"
        )
        # Verify bundle.enc check precedes any error-count increment
        bundle_check_pos = content.find('bundle.enc" ]]; then')
        error_inc_pos = content.find("errors=$((errors + 1))", bundle_check_pos)
        assert error_inc_pos > bundle_check_pos, (
            "RETRO-R4-3/ISSUE-250-02: errors must be incremented when bundle.enc is "
            "absent in _validate_v2_backup"
        )

    def test_restore_sh_hmac_verification_fails_closed(self):
        """The HMAC-SHA384 verification in _v2_decrypt_to_staging must be a hard
        fail — a mismatched HMAC causes sys.exit(3), not a warning.

        Verified against restore.sh lines 552-559 (HMAC verify + sys.exit(3))."""
        assert RESTORE_SH.exists()
        content = RESTORE_SH.read_text()

        # restore.sh line 552: expected_hmac = _hmac.new(bytes(mac_key), aad_b, digestmod=hashlib.sha384).hexdigest()
        assert "hashlib.sha384" in content, (
            "RETRO-R4-3/ISSUE-250-02: restore.sh _v2_decrypt_to_staging must compute "
            "expected HMAC using hashlib.sha384 (line 552)"
        )
        # restore.sh line 556: if not _hmac.compare_digest(expected_hmac, stored_hmac):
        assert "_hmac.compare_digest" in content, (
            "RETRO-R4-3/ISSUE-250-02: restore.sh must use hmac.compare_digest for "
            "constant-time HMAC comparison (line 556)"
        )
        # restore.sh line 557: sys.stderr.write("FATAL: HMAC-SHA384 verification failed ..."
        assert "HMAC-SHA384 verification failed" in content, (
            "RETRO-R4-3/ISSUE-250-02: restore.sh must emit the exact fatal message "
            "when HMAC verification fails (line 557)"
        )
        # restore.sh line 559: sys.exit(3) — hard fail, not warn
        hmac_fail_pos = content.find("HMAC-SHA384 verification failed")
        exit3_pos = content.find("sys.exit(3)", hmac_fail_pos)
        assert exit3_pos > hmac_fail_pos, (
            "RETRO-R4-3/ISSUE-250-02: HMAC failure must cause sys.exit(3) (hard fail), "
            "not a warning — backup tamper must be refused (lines 557-559)"
        )

    def test_restore_sh_hmac_mac_key_uses_same_hkdf_info(self):
        """restore.sh must re-derive the MAC key using the identical HKDF info string
        as install.sh — any mismatch causes every backup to fail HMAC verification.

        Verified against restore.sh line 545 (_v2_decrypt_to_staging MAC key derivation)."""
        assert RESTORE_SH.exists()
        content = RESTORE_SH.read_text()

        # restore.sh line 545: mac_key = bytearray(_hkdf(bytes(dek), b"", b"yashigani-backup-meta-mac-v1", 48))
        assert "yashigani-backup-meta-mac-v1" in content, (
            "RETRO-R4-3/ISSUE-250-02: restore.sh HKDF info string must match "
            "install.sh exactly: 'yashigani-backup-meta-mac-v1' (line 545)"
        )
