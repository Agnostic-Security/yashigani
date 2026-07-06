"""
Integration — v4.1 issue #144 (DB-crypto half): pgcrypto AES-128 → AES-256.

Proves against a LIVE Postgres (pgcrypto):

  1. New writes through the application SQL (AuthSettingsStore upsert,
     INSERT_WEBAUTHN_CREDENTIAL) produce an AES-256 PGP packet —
     get_byte(col, 3) == 9 (RFC 4880 algo id, ground-truthed 2026-07-06).
  2. Decrypt works for BOTH pre-migration (AES-128-framed) and
     post-migration (AES-256-framed) rows — pgp_sym_decrypt reads the
     cipher from the packet.
  3. Migration 0027's _reencrypt() converts existing AES-128 rows, skips
     inference rows under a rotated/lost key without aborting, is
     IDEMPOTENT, and is a no-op on empty tables (fresh install).

All tables are created inside a throwaway schema (search_path pinned), so
running against a real deployment DSN never touches real tables.

Run with:
    pytest -m integration src/tests/integration/test_v41_pgcrypto_aes256_integration.py

Requires a reachable Postgres with pgcrypto pointed at by YASHIGANI_DB_DSN.
Skipped automatically when the DSN is not configured.

Last updated: 2026-07-06T00:00:00+00:00
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import secrets
import uuid

import pytest

pytestmark = pytest.mark.integration

_AES256 = 9   # RFC 4880 algo id — byte 3 of the SKESK packet
_AES128 = 7

_MIGRATION_PATH = (
    pathlib.Path(__file__).resolve().parents[2]
    / "yashigani" / "db" / "migrations" / "versions"
    / "0027_pgcrypto_aes256_reencrypt.py"
)

_SCRATCH_DDL = """
CREATE TABLE auth_settings (
    key             TEXT PRIMARY KEY,
    value_encrypted BYTEA NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by      TEXT NOT NULL DEFAULT ''
);
CREATE TABLE webauthn_credentials (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         TEXT         NOT NULL,
    credential_id   BYTEA        NOT NULL UNIQUE,
    public_key      BYTEA        NOT NULL,
    sign_count      INTEGER      NOT NULL DEFAULT 0,
    aaguid          TEXT         NOT NULL DEFAULT '',
    name            TEXT         NOT NULL DEFAULT 'Passkey',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);
CREATE TABLE inference_events (
    id               UUID NOT NULL DEFAULT gen_random_uuid(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload_content  BYTEA,
    response_content BYTEA,
    PRIMARY KEY (id, created_at)
);
"""


@pytest.fixture(scope="module")
def dsn() -> str:
    val = os.environ.get("YASHIGANI_DB_DSN", "")
    if not val or "${POSTGRES_PASSWORD}" in val:
        pytest.skip("YASHIGANI_DB_DSN not configured — skipping live-DB test")
    return val


@pytest.fixture()
def aes_key() -> str:
    return secrets.token_hex(32)


def _load_migration_0027():
    spec = importlib.util.spec_from_file_location("mig_0027", _MIGRATION_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# 1+2 — application write paths produce AES-256; decrypt is cipher-agnostic
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_settings_store_writes_aes256_and_reads_both_ciphers(
    dsn: str, aes_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncpg

    from yashigani.auth.settings_store import AuthSettingsStore

    monkeypatch.setenv("YASHIGANI_DB_AES_KEY", aes_key)
    schema = f"t_aes256_{secrets.token_hex(4)}"

    admin = await asyncpg.connect(dsn)
    try:
        await admin.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        await admin.execute(f'CREATE SCHEMA "{schema}"')
        await admin.execute(f'SET search_path TO "{schema}", public')
        await admin.execute(_SCRATCH_DDL)

        pool = await asyncpg.create_pool(
            dsn, min_size=1, max_size=2,
            server_settings={"search_path": f"{schema}, public"},
        )
        try:
            store = AuthSettingsStore(pool)

            # New write → AES-256 packet on disk, round-trips.
            await store.set_setting("hibp_api_key", "secret-value-256", "tom")
            algo = await admin.fetchval(
                "SELECT get_byte(value_encrypted, 3) FROM auth_settings "
                "WHERE key = 'hibp_api_key'"
            )
            assert algo == _AES256, f"new write is not AES-256 (algo id {algo})"
            assert await store.get_setting("hibp_api_key") == "secret-value-256"

            # Pre-migration row (AES-128-framed, as all rows were before
            # v4.1) → unchanged read path decrypts it.
            await admin.execute(
                "INSERT INTO auth_settings (key, value_encrypted) "
                "VALUES ('legacy128', pgp_sym_encrypt('old-value', $1))",
                aes_key,
            )
            assert await admin.fetchval(
                "SELECT get_byte(value_encrypted, 3) FROM auth_settings "
                "WHERE key = 'legacy128'"
            ) == _AES128
            assert await store.get_setting("legacy128") == "old-value"

            # Upsert over the legacy row re-frames it AES-256.
            await store.set_setting("legacy128", "new-value", "tom")
            assert await admin.fetchval(
                "SELECT get_byte(value_encrypted, 3) FROM auth_settings "
                "WHERE key = 'legacy128'"
            ) == _AES256
            assert await store.get_setting("legacy128") == "new-value"
        finally:
            await pool.close()
    finally:
        await admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await admin.close()


@pytest.mark.asyncio
async def test_webauthn_insert_sql_writes_aes256(dsn: str, aes_key: str) -> None:
    import asyncpg

    from yashigani.db.models.webauthn_credential import (
        INSERT_WEBAUTHN_CREDENTIAL,
        SELECT_WEBAUTHN_CREDENTIAL_BY_CREDENTIAL_ID,
    )

    schema = f"t_aes256_{secrets.token_hex(4)}"
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        await conn.execute(f'CREATE SCHEMA "{schema}"')
        await conn.execute(f'SET search_path TO "{schema}", public')
        await conn.execute(_SCRATCH_DDL)
        await conn.execute("SELECT set_config('app.aes_key', $1, false)", aes_key)

        cred_id = secrets.token_bytes(16)
        cose_hex = secrets.token_bytes(77).hex()
        await conn.execute(
            INSERT_WEBAUTHN_CREDENTIAL,
            uuid.uuid4(), "admin-1", cred_id, cose_hex, 0, "aaguid", "Passkey",
        )

        algo = await conn.fetchval(
            "SELECT get_byte(public_key, 3) FROM webauthn_credentials"
        )
        assert algo == _AES256, f"webauthn public_key is not AES-256 (algo id {algo})"

        row = await conn.fetchrow(
            SELECT_WEBAUTHN_CREDENTIAL_BY_CREDENTIAL_ID, cred_id
        )
        assert row is not None
        assert row["public_key"].decode() == cose_hex
    finally:
        await conn.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        await conn.close()


# ---------------------------------------------------------------------------
# 3 — migration 0027: complete, guarded, idempotent, fresh-install no-op
# ---------------------------------------------------------------------------

def _sync_engine(dsn: str):
    import sqlalchemy as sa

    sync_dsn = dsn.replace("postgresql://", "postgresql+psycopg2://").replace(
        "postgresql+asyncpg://", "postgresql+psycopg2://"
    )
    return sa.create_engine(sync_dsn, poolclass=sa.pool.NullPool)


def test_migration_0027_reencrypts_idempotent_and_empty_noop(
    dsn: str, aes_key: str
) -> None:
    import sqlalchemy as sa

    mig = _load_migration_0027()
    schema = f"t_aes256_{secrets.token_hex(4)}"
    engine = _sync_engine(dsn)
    try:
        with engine.begin() as conn:
            conn.execute(sa.text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
            conn.execute(sa.text(f'CREATE SCHEMA "{schema}"'))
            conn.execute(sa.text(f'SET search_path TO "{schema}", public'))
            conn.execute(sa.text(_SCRATCH_DDL))

            # ---- Fresh install: empty tables → no-op, no key required ----
            stats = mig._reencrypt(conn, "")
            assert stats == {
                "auth_settings": 0, "webauthn": 0,
                "inference": 0, "inference_skipped": 0,
            }

            # ---- Seed a pre-v4.1 shape ----
            seed = {"k": aes_key}
            conn.execute(sa.text(
                "INSERT INTO auth_settings (key, value_encrypted) VALUES "
                "('a128', pgp_sym_encrypt('v-a128', :k)),"          # AES-128
                "('b128', pgp_sym_encrypt('v-b128', :k)),"          # AES-128
                "('c256', pgp_sym_encrypt('v-c256', :k, 'cipher-algo=aes256'))"
            ), seed)
            conn.execute(sa.text(
                "INSERT INTO webauthn_credentials (user_id, credential_id, public_key) "
                "VALUES ('u1', '\\x01'::bytea, pgp_sym_encrypt('cose-hex', :k))"
            ), seed)
            id_keyed, id_nullresp, id_lost = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
            conn.execute(sa.text(
                "INSERT INTO inference_events (id, payload_content, response_content) VALUES "
                # written under the current deployment key
                "(:id_keyed, pgp_sym_encrypt('p-keyed', :k), pgp_sym_encrypt('r-keyed', :k)),"
                # NULL response_content
                "(:id_nullresp, pgp_sym_encrypt('p-null-resp', :k), NULL),"
                # unreadable: encrypted under a rotated/lost key
                "(:id_lost, pgp_sym_encrypt('p-lost', 'lost-key'), NULL)"
            ), {**seed, "id_keyed": id_keyed, "id_nullresp": id_nullresp, "id_lost": id_lost})

            # ---- Missing key with pending strict rows → fail-closed ----
            with pytest.raises(RuntimeError, match="YASHIGANI_DB_AES_KEY"):
                with conn.begin_nested():
                    mig._reencrypt(conn, "")

            # ---- Run the migration ----
            stats = mig._reencrypt(conn, aes_key)
            assert stats["auth_settings"] == 2          # c256 untouched
            assert stats["webauthn"] == 1
            assert stats["inference"] == 2              # keyed + null-resp
            assert stats["inference_skipped"] == 1      # lost-key row left as-is

            # Everything decryptable is now AES-256-framed…
            assert conn.execute(sa.text(
                "SELECT count(*) FROM auth_settings WHERE get_byte(value_encrypted,3) <> 9"
            )).scalar() == 0
            assert conn.execute(sa.text(
                "SELECT count(*) FROM webauthn_credentials WHERE get_byte(public_key,3) <> 9"
            )).scalar() == 0
            assert conn.execute(sa.text(
                "SELECT count(*) FROM inference_events "
                "WHERE payload_content IS NOT NULL AND get_byte(payload_content,3) <> 9"
            )).scalar() == 1  # only the lost-key row

            # …and decrypts to the original plaintexts under the right keys.
            assert conn.execute(sa.text(
                "SELECT pgp_sym_decrypt(value_encrypted, :k) FROM auth_settings "
                "WHERE key='a128'"), seed).scalar() == "v-a128"
            assert conn.execute(sa.text(
                "SELECT pgp_sym_decrypt(public_key, :k) FROM webauthn_credentials"
            ), seed).scalar() == "cose-hex"
            for row_id, plaintext in ((id_keyed, "p-keyed"), (id_nullresp, "p-null-resp")):
                assert conn.execute(sa.text(
                    "SELECT pgp_sym_decrypt(payload_content, :k) "
                    "FROM inference_events WHERE id = :id"
                ), {**seed, "id": row_id}).scalar() == plaintext
            # lost-key row untouched (still AES-128, still decrypts under ITS key)
            assert conn.execute(sa.text(
                "SELECT get_byte(payload_content, 3) FROM inference_events WHERE id = :id"
            ), {"id": id_lost}).scalar() == _AES128
            assert conn.execute(sa.text(
                "SELECT pgp_sym_decrypt(payload_content, 'lost-key') "
                "FROM inference_events WHERE id = :id"
            ), {"id": id_lost}).scalar() == "p-lost"

            # ---- Idempotency: second run re-encrypts nothing new ----
            stats2 = mig._reencrypt(conn, aes_key)
            assert stats2["auth_settings"] == 0
            assert stats2["webauthn"] == 0
            assert stats2["inference"] == 0
            # the lost-key row is still pending — counted, still skipped
            assert stats2["inference_skipped"] == 1
    finally:
        with engine.begin() as conn:
            conn.execute(sa.text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        engine.dispose()
