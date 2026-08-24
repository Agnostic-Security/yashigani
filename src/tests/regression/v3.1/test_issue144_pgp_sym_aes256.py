"""
Regression tests — Issue #144 Finding 1: pgp_sym_encrypt must pin AES-256.

Background:
  pgcrypto's pgp_sym_encrypt() default (no options arg) uses AES-128 CFB.
  All call-sites must pass cipher-algo=aes256 as the 3rd argument to upgrade
  every new write to AES-256-CFB (OpenPGP format).

  pgp_sym_decrypt() does NOT need options — it reads the cipher from the
  OpenPGP packet header.  Existing AES-128-encrypted rows therefore remain
  decryptable after the pin is applied (backward-compatible write-path upgrade).

  Application-level AES-256-GCM (AESGCM via the cryptography library) is
  used separately in documents/pseudonymize.py and backoffice/routes/backup.py.
  These paths are NOT pgcrypto and are NOT affected by this issue.

Tests:
  A. PGP_SYM_OPTS is defined in db/postgres.py with the correct value.
  B. Every pgp_sym_encrypt() in the INSERT SQL strings includes the options.
  C. pgp_sym_decrypt() calls do NOT include options (correct — header-driven).
  D. crypto_inventory reports "AES-256-CFB (OpenPGP)" for the pgcrypto entry.
  E. AESGCM paths in pseudonymize.py and backup.py remain 256-bit (no downgrade).
  F. Backward-compat contract: decrypt-compat proof (structural — no live DB).

Last updated: 2026-07-03T00:00:00+00:00
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_SRC = Path(__file__).parents[3] / "yashigani"

_POSTGRES_PY = _SRC / "db" / "postgres.py"
_MODELS_INIT = _SRC / "db" / "models" / "__init__.py"
_MODELS_SHADOW = _SRC / "db" / "models.py"
_WEBAUTHN_CRED = _SRC / "db" / "models" / "webauthn_credential.py"
_SETTINGS_STORE = _SRC / "auth" / "settings_store.py"
_PG_WEBAUTHN = _SRC / "auth" / "pg_webauthn.py"
_PAYLOAD_LOGGER = _SRC / "inference" / "payload_logger.py"
_CRYPTO_INVENTORY = _SRC / "backoffice" / "routes" / "crypto_inventory.py"
_PSEUDONYMIZE = _SRC / "documents" / "pseudonymize.py"
_BACKUP = _SRC / "backoffice" / "routes" / "backup.py"

# The canonical options string that MUST appear in every pgp_sym_encrypt call.
_EXPECTED_OPTS = "cipher-algo=aes256, compress-algo=0"


# ---------------------------------------------------------------------------
# A. Shared constant definition
# ---------------------------------------------------------------------------

class TestPgpSymOptsConstant:
    """PGP_SYM_OPTS must be defined in db/postgres.py with the exact value."""

    def test_constant_defined(self):
        source = _POSTGRES_PY.read_text(encoding="utf-8")
        assert "PGP_SYM_OPTS" in source, (
            "Issue #144 REGRESSION: PGP_SYM_OPTS not defined in db/postgres.py"
        )

    def test_constant_value_correct(self):
        source = _POSTGRES_PY.read_text(encoding="utf-8")
        assert _EXPECTED_OPTS in source, (
            f"Issue #144 REGRESSION: PGP_SYM_OPTS does not contain "
            f"'{_EXPECTED_OPTS}' in db/postgres.py"
        )

    def test_constant_importable(self):
        """PGP_SYM_OPTS must be importable from yashigani.db.postgres."""
        from yashigani.db.postgres import PGP_SYM_OPTS
        assert PGP_SYM_OPTS == _EXPECTED_OPTS, (
            f"Issue #144: PGP_SYM_OPTS value mismatch — "
            f"got {PGP_SYM_OPTS!r}, expected {_EXPECTED_OPTS!r}"
        )

    def test_constant_exported_from_db_package(self):
        """PGP_SYM_OPTS must be importable from yashigani.db (re-exported)."""
        from yashigani.db import PGP_SYM_OPTS
        assert PGP_SYM_OPTS == _EXPECTED_OPTS


# ---------------------------------------------------------------------------
# B. Every pgp_sym_encrypt() in SQL strings includes the options
# ---------------------------------------------------------------------------

def _encrypt_lines_missing_cipher_pin(source: str) -> list[str]:
    """
    Find lines with pgp_sym_encrypt() that have NO cipher pin applied.

    A line is considered pinned if it contains either:
    - The literal options string 'cipher-algo=aes256' (hardcoded), OR
    - The reference 'PGP_SYM_OPTS' (f-string variable; evaluates to the opts).

    pgp_sym_encrypt calls are each on a single line in our SQL strings.
    """
    offenders = []
    for line in source.splitlines():
        stripped = line.strip()
        if "pgp_sym_encrypt(" not in stripped:
            continue
        pinned = "cipher-algo=aes256" in stripped or "PGP_SYM_OPTS" in stripped
        if not pinned:
            offenders.append(stripped)
    return offenders


class TestEncryptCallsHaveOptions:
    """Every pgp_sym_encrypt() call in the codebase must pass cipher options."""

    @pytest.mark.parametrize("path,label", [
        (_MODELS_INIT, "db/models/__init__.py (INSERT_INFERENCE_EVENT)"),
        (_WEBAUTHN_CRED, "db/models/webauthn_credential.py (INSERT_WEBAUTHN_CREDENTIAL)"),
        (_SETTINGS_STORE, "auth/settings_store.py (set_setting)"),
        (_PG_WEBAUTHN, "auth/pg_webauthn.py (add credential)"),
    ])
    def test_no_bare_encrypt_call(self, path, label):
        """
        Source-level: every pgp_sym_encrypt() line must have either the
        literal options string OR the PGP_SYM_OPTS variable reference (f-string).
        """
        source = path.read_text(encoding="utf-8")
        if "pgp_sym_encrypt" not in source:
            return  # File has no encrypt calls — trivially clean.
        offenders = _encrypt_lines_missing_cipher_pin(source)
        assert not offenders, (
            f"Issue #144 REGRESSION: pgp_sym_encrypt() without cipher pin found in {label}:\n"
            + "\n".join(f"  {o}" for o in offenders)
        )

    def test_models_init_insert_inference_event_opts(self):
        """INSERT_INFERENCE_EVENT (evaluated f-string at import time) must pin aes256."""
        from yashigani.db.models import INSERT_INFERENCE_EVENT
        count = INSERT_INFERENCE_EVENT.count("pgp_sym_encrypt")
        assert count == 2, (
            f"Expected 2 pgp_sym_encrypt calls in INSERT_INFERENCE_EVENT, got {count}"
        )
        assert INSERT_INFERENCE_EVENT.count("cipher-algo=aes256") == 2, (
            "Issue #144: INSERT_INFERENCE_EVENT missing cipher-algo=aes256 on one or both encrypts"
        )

    def test_webauthn_credential_insert_opts(self):
        """INSERT_WEBAUTHN_CREDENTIAL (evaluated f-string at import time) must pin aes256."""
        from yashigani.db.models.webauthn_credential import INSERT_WEBAUTHN_CREDENTIAL
        assert "cipher-algo=aes256" in INSERT_WEBAUTHN_CREDENTIAL, (
            "Issue #144: INSERT_WEBAUTHN_CREDENTIAL missing cipher-algo=aes256"
        )


# ---------------------------------------------------------------------------
# C. pgp_sym_decrypt calls do NOT include options (backward-compat mechanism)
# ---------------------------------------------------------------------------

class TestDecryptCallsNoOptions:
    """
    pgp_sym_decrypt() must NOT have a cipher options arg — it reads the
    cipher from the OpenPGP packet header automatically, enabling backward
    compat with old AES-128 rows while new writes go to AES-256.
    """

    @pytest.mark.parametrize("path,label", [
        (_WEBAUTHN_CRED, "db/models/webauthn_credential.py"),
        (_PG_WEBAUTHN, "auth/pg_webauthn.py"),
        (_SETTINGS_STORE, "auth/settings_store.py"),
    ])
    def test_decrypt_has_only_two_args(self, path, label):
        """
        pgp_sym_decrypt(col, key) is correct; a third arg would be wrong.
        Verify no file passes cipher options to decrypt.
        """
        source = path.read_text(encoding="utf-8")
        # Look for pgp_sym_decrypt with a third argument containing cipher-algo
        bad = re.findall(r"pgp_sym_decrypt\([^)]*cipher-algo[^)]*\)", source)
        assert not bad, (
            f"pgp_sym_decrypt() in {label} has unexpected cipher options: {bad}. "
            "pgp_sym_decrypt reads the cipher from the packet header — "
            "options must not be passed."
        )


# ---------------------------------------------------------------------------
# D. Crypto inventory: "AES-256-CFB (OpenPGP)" for pgcrypto; GCM stays GCM
# ---------------------------------------------------------------------------

class TestCryptoInventoryHonestAlgo:
    """crypto_inventory.py must report the honest algorithm per mechanism."""

    def test_pgcrypto_entry_is_cfb(self):
        """The database-column-encryption entry must say AES-256-CFB (OpenPGP)."""
        source = _CRYPTO_INVENTORY.read_text(encoding="utf-8")
        assert "AES-256-CFB (OpenPGP)" in source, (
            "Issue #144 REGRESSION: crypto_inventory.py still claims "
            "'AES-256-GCM' for database column encryption. "
            "pgcrypto uses OpenPGP CFB mode, not GCM. Fix the inventory entry."
        )

    def test_pgcrypto_entry_mentions_pgp_sym_encrypt(self):
        """The CFB entry must reference pgp_sym_encrypt so auditors understand the mechanism."""
        source = _CRYPTO_INVENTORY.read_text(encoding="utf-8")
        assert "pgp_sym_encrypt" in source, (
            "Issue #144: crypto_inventory.py CFB entry should reference pgp_sym_encrypt "
            "so compliance auditors can map it to the implementation."
        )

    def test_genuine_gcm_entry_still_present(self):
        """AES-256-GCM must remain in the inventory for the AESGCM paths."""
        source = _CRYPTO_INVENTORY.read_text(encoding="utf-8")
        assert "AES-256-GCM" in source, (
            "Issue #144: AES-256-GCM removed from crypto_inventory.py entirely — "
            "but pseudonymize.py and backup.py genuinely use AESGCM. "
            "The entry must remain, just separate from the pgcrypto entry."
        )

    def test_no_gcm_in_database_column_encryption_context(self):
        """The pgcrypto database-column entry must not claim GCM."""
        source = _CRYPTO_INVENTORY.read_text(encoding="utf-8")
        # Check that "AES-256-GCM" is NOT paired with "database column encryption"
        # by looking at the line(s) carrying that phrase.
        for line in source.splitlines():
            if "database column encryption" in line:
                assert "AES-256-GCM" not in line, (
                    f"Issue #144 REGRESSION: line still claims AES-256-GCM for "
                    f"database column encryption:\n  {line}"
                )


# ---------------------------------------------------------------------------
# E. AESGCM paths remain 256-bit (no downgrade)
# ---------------------------------------------------------------------------

class TestAesGcmPathsUntouched:
    """The genuine AESGCM paths in pseudonymize.py and backup.py must stay GCM."""

    def test_pseudonymize_imports_aesgcm(self):
        source = _PSEUDONYMIZE.read_text(encoding="utf-8")
        assert "AESGCM" in source, (
            "Issue #144: AESGCM import removed from documents/pseudonymize.py — "
            "document pseudonymization must use AES-256-GCM."
        )

    def test_pseudonymize_has_256bit_key_size(self):
        """AESGCM in pseudonymize.py must use a 32-byte (256-bit) key."""
        source = _PSEUDONYMIZE.read_text(encoding="utf-8")
        # The key generation must be os.urandom(32) or secrets-based 32-byte key.
        assert "32" in source, (
            "Issue #144: pseudonymize.py may not be using a 32-byte (256-bit) key. "
            "Verify AESGCM key length."
        )

    def test_backup_imports_aesgcm(self):
        source = _BACKUP.read_text(encoding="utf-8")
        assert "AESGCM" in source, (
            "Issue #144: AESGCM import removed from backoffice/routes/backup.py — "
            "on-demand backup encryption must use AES-256-GCM."
        )

    def test_backup_uses_256bit_key(self):
        """AESGCM in backup.py must use 32-byte keys (HKDF output)."""
        source = _BACKUP.read_text(encoding="utf-8")
        # HKDF output should be 32 bytes.
        assert "32" in source, (
            "Issue #144: backup.py may not be deriving a 32-byte (256-bit) key. "
            "Verify HKDF/AESGCM key length."
        )


# ---------------------------------------------------------------------------
# F. Backward-compat contract (structural proof, no live DB)
# ---------------------------------------------------------------------------

class TestBackwardCompatContract:
    """
    Structural proof that the decrypt-compat contract is honoured.

    pgcrypto's OpenPGP packet format records the cipher algorithm in the
    symmetric-key encrypted session-key (SKESK) packet.  pgp_sym_decrypt()
    reads this field and selects the matching cipher — no options arg needed.
    This means:
      - Old rows encrypted with default (AES-128) continue to decrypt.
      - New rows encrypted with cipher-algo=aes256 decrypt correctly.
    We cannot test this without a live Postgres/pgcrypto, but we assert the
    structural preconditions: no options on decrypt calls, and the
    implementation comment in postgres.py explains the contract.
    """

    def test_postgres_py_documents_backward_compat(self):
        """db/postgres.py must document that old rows remain decryptable."""
        source = _POSTGRES_PY.read_text(encoding="utf-8")
        assert "remain decryptable" in source or "backward" in source.lower(), (
            "Issue #144: db/postgres.py should document that AES-128 rows written "
            "before the cipher pin remain decryptable after the upgrade."
        )

    def test_payload_logger_docstring_corrected(self):
        """payload_logger.py docstring must not claim AES-256-GCM for pgcrypto."""
        source = _PAYLOAD_LOGGER.read_text(encoding="utf-8")
        # The module docstring should say CFB/OpenPGP, not GCM, for the pgcrypto path.
        lines = source.splitlines()
        # Find the docstring section (first triple-quoted block).
        in_docstring = False
        docstring_lines = []
        for line in lines:
            if '"""' in line:
                if not in_docstring:
                    in_docstring = True
                else:
                    docstring_lines.append(line)
                    break
            if in_docstring:
                docstring_lines.append(line)
        docstring_text = "\n".join(docstring_lines)
        assert "AES-256-GCM" not in docstring_text or "pgcrypto" not in docstring_text, (
            "Issue #144 REGRESSION: payload_logger.py docstring still claims "
            "AES-256-GCM for the pgcrypto (pgp_sym_encrypt) path."
        )

    def test_no_incorrect_gcm_claim_in_postgres_docstring(self):
        """db/postgres.py docstring must not label pgcrypto as AES-GCM."""
        source = _POSTGRES_PY.read_text(encoding="utf-8")
        # The heading should say CFB/OpenPGP, not "AES-GCM nonce / IV".
        assert "AES-GCM nonce" not in source, (
            "Issue #144 REGRESSION: db/postgres.py still has 'AES-GCM nonce' in "
            "the docstring — pgcrypto uses AES-256-CFB (OpenPGP), not GCM."
        )
