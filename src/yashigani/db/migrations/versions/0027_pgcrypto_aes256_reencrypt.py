"""v4.1 — re-encrypt pgcrypto columns from AES-128 to AES-256 (issue #144).

Revision ID: 0027
Revises: 0026
Create Date: 2026-07-06

Rationale:
    pgp_sym_encrypt(data, key) without an options argument encrypts with
    AES-128 (RFC 4880 algo id 7). v4.1 switches every encrypt call site to
    pgp_sym_encrypt(data, key, 'cipher-algo=aes256') — see
    yashigani/db/pgcrypto.py. New writes are AES-256; this migration
    re-encrypts EXISTING rows so the switch is complete, not just forward.
    pgp_sym_decrypt reads the cipher from the PGP packet, so pre- and
    post-migration rows both decrypt with the unchanged read paths.

Cipher detection (ground-truthed against postgres:16 pgcrypto, 2026-07-06):
    pgp_sym_encrypt output starts with a new-format SKESK packet:
    byte 0 = 0xC3, byte 1 = length (13), byte 2 = version (4),
    byte 3 = cipher algo id (7=AES-128, 9=AES-256).
    ``get_byte(col, 3) <> 9`` therefore selects exactly the rows that still
    need re-encryption, which also makes this migration IDEMPOTENT: a second
    run (and a run on a fresh/empty DB) selects zero rows and is a no-op.

Tables:
    auth_settings.value_encrypted        — strict SQL re-encrypt, fail-closed.
    webauthn_credentials.public_key      — strict SQL re-encrypt, fail-closed.
        Both are written exclusively by the backoffice, which fail-fasts at
        startup when YASHIGANI_DB_AES_KEY is unset (app.py B2), so every row
        is encrypted under the deployment key. A decrypt failure here means
        key mismatch/corruption → the migration aborts loudly.
    inference_events.payload_content / response_content — GUARDED Python
        re-encrypt. Rows may predate a key rotation, and a bulk UPDATE
        aborts entirely on the first decrypt failure, permanently bricking
        backoffice startup over rows that are already unreadable. Strategy:
        try one bulk UPDATE inside a SAVEPOINT (fast path — all rows under
        the deployment key); on failure fall back to row-by-row, leaving
        any row that does not decrypt under the deployment key untouched
        and counted in a WARNING (re-encrypting it is impossible without
        its key; it was already unreadable by every code path).
        Ground truth 2026-07-06: pgcrypto REJECTS empty passphrases
        ("Illegal argument to function"), so rows encrypted under a
        missing/empty env key cannot exist — a keyless writer fails at
        write time, it does not produce empty-passphrase rows.

Privileges / RLS:
    Runs as the admin identity (YASHIGANI_DB_DSN_ADMIN — see
    db/__init__.py:run_migrations), the owner/superuser that 0015
    established for DDL. inference_events has FORCE ROW LEVEL SECURITY
    (0015) and UPDATE revoked from yashigani_app; ``SET LOCAL row_security
    = off`` makes an under-privileged run fail LOUDLY instead of silently
    matching zero rows.

Key handling:
    The AES key is read from YASHIGANI_DB_AES_KEY and injected via
    set_config('app.aes_key', ..., true) — the same session GUC the
    application uses — as a bind parameter, never interpolated into SQL
    text and never logged. If rows need migration and the key is unset,
    the migration raises (fail-closed).

Downgrade:
    Intentional no-op. AES-256 packets decrypt fine under older code
    (pgp_sym_decrypt is cipher-agnostic); actively downgrading data to a
    weaker cipher is never desirable.

Last updated: 2026-07-06T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import context, op

revision: str = "0027"
down_revision: Union[str, None] = "0026"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

logger = logging.getLogger("alembic.runtime.migration")

_AES_KEY_ENV = "YASHIGANI_DB_AES_KEY"

# Frozen copies of yashigani.db.pgcrypto constants — migrations are immutable
# snapshots and must not import application code.
_PGP_OPTS = "cipher-algo=aes256"
_AES256_ALGO_ID = 9  # RFC 4880 §9.2; byte 3 of the pgcrypto SKESK packet

_COUNT_AUTH_SETTINGS = """
SELECT count(*) FROM auth_settings
WHERE value_encrypted IS NOT NULL AND get_byte(value_encrypted, 3) <> 9
"""

_COUNT_WEBAUTHN = """
SELECT count(*) FROM webauthn_credentials
WHERE public_key IS NOT NULL AND get_byte(public_key, 3) <> 9
"""

_COUNT_INFERENCE = """
SELECT count(*) FROM inference_events
WHERE (payload_content  IS NOT NULL AND get_byte(payload_content, 3)  <> 9)
   OR (response_content IS NOT NULL AND get_byte(response_content, 3) <> 9)
"""

# Strict re-encrypts — run under the app.aes_key session GUC, exactly like
# the application's own encrypt paths. Abort loudly on any decrypt failure.
_REENCRYPT_AUTH_SETTINGS = f"""
UPDATE auth_settings
SET value_encrypted = pgp_sym_encrypt(
        pgp_sym_decrypt(value_encrypted, current_setting('app.aes_key')),
        current_setting('app.aes_key'),
        '{_PGP_OPTS}')
WHERE value_encrypted IS NOT NULL AND get_byte(value_encrypted, 3) <> 9
"""

_REENCRYPT_WEBAUTHN = f"""
UPDATE webauthn_credentials
SET public_key = pgp_sym_encrypt(
        pgp_sym_decrypt(public_key, current_setting('app.aes_key')),
        current_setting('app.aes_key'),
        '{_PGP_OPTS}')::bytea
WHERE public_key IS NOT NULL AND get_byte(public_key, 3) <> 9
"""

# Guarded re-encrypt for inference_events — key passed as a bind parameter
# so per-candidate retries are possible (see module docstring).
_REENCRYPT_INFERENCE_BULK = f"""
UPDATE inference_events
SET payload_content = CASE
        WHEN payload_content IS NOT NULL AND get_byte(payload_content, 3) <> 9
        THEN pgp_sym_encrypt(pgp_sym_decrypt(payload_content, :k), :k, '{_PGP_OPTS}')
        ELSE payload_content END,
    response_content = CASE
        WHEN response_content IS NOT NULL AND get_byte(response_content, 3) <> 9
        THEN pgp_sym_encrypt(pgp_sym_decrypt(response_content, :k), :k, '{_PGP_OPTS}')
        ELSE response_content END
WHERE (payload_content  IS NOT NULL AND get_byte(payload_content, 3)  <> 9)
   OR (response_content IS NOT NULL AND get_byte(response_content, 3) <> 9)
"""

_SELECT_INFERENCE_PENDING = """
SELECT id, created_at FROM inference_events
WHERE (payload_content  IS NOT NULL AND get_byte(payload_content, 3)  <> 9)
   OR (response_content IS NOT NULL AND get_byte(response_content, 3) <> 9)
"""

_REENCRYPT_INFERENCE_ROW = _REENCRYPT_INFERENCE_BULK.replace(
    "WHERE (payload_content  IS NOT NULL AND get_byte(payload_content, 3)  <> 9)\n"
    "   OR (response_content IS NOT NULL AND get_byte(response_content, 3) <> 9)",
    "WHERE id = :id AND created_at = :created_at",
)


def _reencrypt(conn: sa.engine.Connection, aes_key: str) -> dict:
    """Core data migration. Separated from upgrade() so it is directly
    testable against a scratch database (see
    src/tests/integration/test_v41_pgcrypto_aes256_integration.py).

    Returns counters: {"auth_settings": n, "webauthn": n,
                       "inference": n, "inference_skipped": n}.
    """
    # Fail loudly (not silently match 0 rows) if run without RLS-bypassing
    # privileges — inference_events has FORCE RLS since 0015.
    conn.execute(sa.text("SET LOCAL row_security = off"))

    stats = {"auth_settings": 0, "webauthn": 0, "inference": 0, "inference_skipped": 0}

    pending_auth = conn.execute(sa.text(_COUNT_AUTH_SETTINGS)).scalar() or 0
    pending_webauthn = conn.execute(sa.text(_COUNT_WEBAUTHN)).scalar() or 0
    pending_inference = conn.execute(sa.text(_COUNT_INFERENCE)).scalar() or 0

    if not (pending_auth or pending_webauthn or pending_inference):
        logger.info("0027: no AES-128 pgcrypto rows found — nothing to re-encrypt")
        return stats

    if not aes_key:
        raise RuntimeError(
            "0027: encrypted rows require re-encryption to AES-256 but "
            f"{_AES_KEY_ENV} is not set in the migration environment. "
            "Set the deployment AES key (install.sh generates it) and retry."
        )

    # Same session GUC the application encrypt/decrypt paths use.
    conn.execute(sa.text("SELECT set_config('app.aes_key', :k, true)"), {"k": aes_key})

    if pending_auth:
        stats["auth_settings"] = conn.execute(sa.text(_REENCRYPT_AUTH_SETTINGS)).rowcount
    if pending_webauthn:
        stats["webauthn"] = conn.execute(sa.text(_REENCRYPT_WEBAUTHN)).rowcount

    if pending_inference:
        # Fast path: every pending row decrypts under the deployment key.
        try:
            with conn.begin_nested():
                conn.execute(sa.text(_REENCRYPT_INFERENCE_BULK), {"k": aes_key})
        except sa.exc.DBAPIError:
            pass  # savepoint rolled back — some row uses a rotated/lost key

        remaining = conn.execute(sa.text(_SELECT_INFERENCE_PENDING)).fetchall()
        for row in remaining:
            try:
                with conn.begin_nested():
                    conn.execute(
                        sa.text(_REENCRYPT_INFERENCE_ROW),
                        {"k": aes_key, "id": row.id, "created_at": row.created_at},
                    )
            except sa.exc.DBAPIError:
                stats["inference_skipped"] += 1

        stats["inference"] = pending_inference - stats["inference_skipped"]
        if stats["inference_skipped"]:
            logger.warning(
                "0027: %d inference_events row(s) do not decrypt under the "
                "deployment key (rotated/lost key) — left as-is (they were "
                "already unreadable by every code path).",
                stats["inference_skipped"],
            )

    logger.info(
        "0027: re-encrypted to AES-256 — auth_settings=%d webauthn=%d "
        "inference=%d (skipped=%d)",
        stats["auth_settings"], stats["webauthn"],
        stats["inference"], stats["inference_skipped"],
    )
    return stats


def upgrade() -> None:
    if context.is_offline_mode():
        # Data migration requires a live connection (savepoints, bind
        # parameters, env key). Yashigani always runs migrations online
        # (db/__init__.py:run_migrations at backoffice startup).
        logger.warning("0027: skipped in offline (--sql) mode — run online.")
        return
    _reencrypt(op.get_bind(), os.environ.get(_AES_KEY_ENV, ""))


def downgrade() -> None:
    # Intentional no-op: AES-256 packets remain readable by all prior code
    # (pgp_sym_decrypt is cipher-agnostic); never downgrade data to AES-128.
    pass
