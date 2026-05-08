"""
Yashigani Auth — Encrypted auth settings store.

Persistent key/value store backed by the auth_settings Postgres table.
All values are encrypted at rest using pgp_sym_encrypt (pgcrypto) with the
per-deployment AES key injected via app.aes_key (same mechanism as all other
encrypted columns in the schema — see postgres.py:tenant_transaction).

Thread-safety: all methods are async; the asyncpg pool handles concurrency.

Callers outside a tenant transaction (e.g. system-level admin config) should
use the NO-tenant variant get_setting_system / set_setting_system which sets
app.aes_key only, not app.tenant_id.

Last updated: 2026-05-07T00:00:00+01:00
"""
from __future__ import annotations

import datetime
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_AES_KEY_ENV = "YASHIGANI_DB_AES_KEY"


class AuthSettingsStore:
    """
    Encrypted key/value store for operator-configurable auth settings.

    All reads/writes operate under an AES-keyed pgcrypto transaction so values
    are never stored or transmitted in plaintext. The pool must be initialised
    before any method is called (call create_pool() at startup).

    Missing row → treated as empty string (not an error).
    """

    def __init__(self, pool) -> None:
        self._pool = pool

    async def get_setting(self, key: str) -> str:
        """
        Return the decrypted value for *key*, or '' if the row does not exist.

        Never logs the value. Failure to decrypt (e.g. AES key mismatch)
        raises and propagates — callers should treat this as a configuration
        error, not a missing value.
        """
        aes_key = os.environ.get(_AES_KEY_ENV, "")
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "SELECT set_config('app.aes_key', $1, true)",
                    aes_key,
                )
                row = await conn.fetchrow(
                    """
                    SELECT pgp_sym_decrypt(value_encrypted, current_setting('app.aes_key'))
                           AS plaintext
                    FROM auth_settings
                    WHERE key = $1
                    """,
                    key,
                )
        if row is None:
            return ""
        return row["plaintext"] or ""

    async def set_setting(
        self,
        key: str,
        value: str,
        updated_by: str,
    ) -> None:
        """
        Upsert *key* = *value* (encrypted). Never logs the value.

        *updated_by* is the admin username stored for audit trail purposes.
        The value itself is not logged at any level.
        """
        aes_key = os.environ.get(_AES_KEY_ENV, "")
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "SELECT set_config('app.aes_key', $1, true)",
                    aes_key,
                )
                await conn.execute(
                    """
                    INSERT INTO auth_settings (key, value_encrypted, updated_at, updated_by)
                    VALUES (
                        $1,
                        pgp_sym_encrypt($2, current_setting('app.aes_key')),
                        $3,
                        $4
                    )
                    ON CONFLICT (key) DO UPDATE
                        SET value_encrypted = pgp_sym_encrypt($2, current_setting('app.aes_key')),
                            updated_at      = $3,
                            updated_by      = $4
                    """,
                    key,
                    value,
                    now,
                    updated_by,
                )
        logger.info(
            "auth_settings: key=%r updated_by=%r updated_at=%s",
            key, updated_by, now.isoformat(),
        )

    async def get_metadata(self, key: str) -> Optional[dict]:
        """
        Return {'updated_at': str, 'updated_by': str} for *key*, or None if missing.
        Does NOT return the value.
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT updated_at, updated_by FROM auth_settings WHERE key = $1",
                key,
            )
        if row is None:
            return None
        return {
            "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
            "updated_by": row["updated_by"],
        }
