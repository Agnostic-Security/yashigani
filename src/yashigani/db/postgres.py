"""
Postgres connection pool via asyncpg + PgBouncer.

Design:
- Single asyncpg pool per process, shared across all coroutines.
- PgBouncer is the actual Postgres connection manager (transaction mode).
  asyncpg connects to PgBouncer (port 5432), not Postgres directly.
- app.tenant_id and app.aes_key are SET at the start of every transaction.
  This is safe in PgBouncer transaction mode because the SET is within the
  transaction boundary.
- All queries use asyncpg's $1/$2 parameterized syntax. No f-strings in SQL.

AES-256-CFB (OpenPGP) IV uniqueness guarantee (ASVS 11.3.4):
  Column-level encryption in this module uses PostgreSQL's pgcrypto extension
  via pgp_sym_encrypt() with cipher-algo=aes256 (see PGP_SYM_OPTS below).
  This produces AES-256-CFB in OpenPGP format, NOT AES-GCM.  pgcrypto
  generates a unique random session-key IV for every call using OpenSSL's
  CSPRNG — documented in the pgcrypto source (src/contrib/pgcrypto/
  pgp-encrypt.c: pgp_create_pkt_writer calls px_get_random_bytes for each
  session key packet).  No manual IV management is required.
  pgp_sym_decrypt() reads the cipher algorithm from the OpenPGP packet header,
  so rows written with the default (AES-128) before this pin was applied
  remain decryptable — the cipher upgrade is write-path only.
  Application-level AES-256-GCM (AESGCM via the cryptography library) is used
  separately in documents/pseudonymize.py and backoffice/routes/backup.py.

Restart resilience (RETRO-R4-2):
  asyncpg pools drop broken connections automatically: when postgres restarts,
  the next acquire() call on a stale connection raises
  asyncpg.exceptions.PostgresConnectionError (or TLSError during the mTLS
  handshake). asyncpg.Pool swallows the broken connection and opens a fresh
  one. The application does NOT need explicit reconnect logic for normal
  query paths.

  The advisory-lock path (psycopg2, bootstrap/migration) is different:
  psycopg2.connect() has no default connect timeout and hangs indefinitely
  when postgres is mid-restart. We set connect_timeout=30 on that connection
  (see app.py) via a dedicated helper: connect_with_retry_sync().
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

import asyncpg
from asyncpg import Pool, Connection

logger = logging.getLogger(__name__)

_pool: Pool | None = None
_AES_KEY_ENV = "YASHIGANI_DB_AES_KEY"

# Issue #144 — pin AES-256 cipher on all pgp_sym_encrypt() call-sites.
# pgcrypto's default (no options arg) is AES-128 CFB.  Passing this options
# string upgrades every new write to AES-256-CFB (OpenPGP).
# compress-algo=0 disables compression (cleaner; symmetric payloads gain no
# useful compression and avoiding it removes any CRIME-style oracle surface
# even though the threat is negligible for symmetric-only data).
# pgp_sym_DECRYPT does NOT need this — it reads the cipher from the OpenPGP
# packet header.  Old AES-128 rows remain decryptable after the upgrade.
# All pgp_sym_encrypt() call-sites MUST pass this as the 3rd argument.
PGP_SYM_OPTS: str = "cipher-algo=aes256, compress-algo=0"

# Per-connection establishment timeout. asyncpg's default is 60 s; we reduce
# to 15 s so a postgres restart (which causes pgbouncer to return connection
# refused briefly) fails fast rather than blocking the lifespan for a minute.
# The pool will retry on the next acquire() — total user-visible wait is
# bounded by command_timeout (10 s) on the query, not the connect timeout.
_CONNECT_TIMEOUT_S = 15


async def create_pool() -> Pool:
    dsn = os.environ["YASHIGANI_DB_DSN"]
    global _pool
    # statement_cache_size=0 is REQUIRED when connecting through pgbouncer in
    # transaction-pool mode (the only mode we run in). pgbouncer reuses backend
    # connections across clients on every transaction boundary, so a prepared
    # statement created by client A may be served back to client B which then
    # tries to PREPARE the same name and gets:
    #   asyncpg.exceptions.DuplicatePreparedStatementError:
    #     prepared statement "__asyncpg_stmt_1__" already exists
    # This bites multi-replica K8s deployments (replicaCount: 2 by default for
    # gateway + backoffice) but not single-replica compose. Platform gate #58c #3bu
    # evidence (2026-04-29). Cost: every query is parsed each time (no plan
    # cache reuse), but pgbouncer in transaction mode would invalidate the
    # cache anyway — disabling it explicitly is the documented fix.
    # Refs: https://magicstack.github.io/asyncpg/current/api/index.html#asyncpg.connection.Connection
    #       https://www.pgbouncer.org/faq.html#how-to-use-prepared-statements-with-transaction-pooling
    _pool = await asyncpg.create_pool(
        dsn=dsn,
        min_size=2,
        max_size=10,
        max_inactive_connection_lifetime=300,
        # RETRO-R4-2: cap per-connection establishment at 15 s so a postgres
        # restart (connection refused window) fails fast. asyncpg pool will
        # retry on the next acquire().
        timeout=_CONNECT_TIMEOUT_S,
        command_timeout=10,
        statement_cache_size=0,
        init=_init_connection,
    )
    logger.info("Postgres pool created (PgBouncer DSN, statement_cache_size=0 for txn-pool, connect_timeout=%ds)", _CONNECT_TIMEOUT_S)
    return _pool


def connect_with_retry_sync(dsn: str, *, max_attempts: int = 5, backoff_s: float = 3.0, connect_timeout: int = 15) -> "psycopg2.extensions.connection":  # type: ignore[name-defined]
    """
    Connect to postgres synchronously (psycopg2) with retry + connect_timeout.

    RETRO-R4-2: the advisory lock path (run_migrations + bootstrap in app.py)
    uses a bare psycopg2 connection that previously had no connect timeout.
    When postgres restarts mid-lifespan, psycopg2.connect() hangs indefinitely
    (TCP SYN_SENT with no server to accept). Fix:
      - Add connect_timeout=N (passed as a DSN parameter, or via dsn_params).
      - Retry with exponential backoff for up to max_attempts if the connection
        fails with OperationalError (connection refused, server starting up).
      - Raise after max_attempts so the lifespan fails loudly rather than
        hanging the process.

    Callers: yashigani.db.__init__.run_migrations(), backoffice.app.lifespan().
    """
    import psycopg2
    from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

    # Inject connect_timeout into the DSN query string without breaking the URL.
    parsed = urlparse(dsn)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params.setdefault("connect_timeout", [str(connect_timeout)])
    new_query = urlencode({k: v[0] for k, v in params.items()})
    dsn_with_timeout = urlunparse(parsed._replace(query=new_query))

    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            conn = psycopg2.connect(dsn_with_timeout)
            if attempt > 1:
                logger.info("connect_with_retry_sync: connected on attempt %d", attempt)
            return conn
        except psycopg2.OperationalError as exc:
            last_exc = exc
            if attempt < max_attempts:
                wait = backoff_s * attempt
                logger.warning(
                    "connect_with_retry_sync: attempt %d/%d failed (%s) — retrying in %.1fs",
                    attempt, max_attempts, exc, wait,
                )
                time.sleep(wait)
            else:
                logger.error(
                    "connect_with_retry_sync: all %d attempts failed — giving up",
                    max_attempts,
                )
    raise psycopg2.OperationalError(f"Failed to connect after {max_attempts} attempts") from last_exc


async def _init_connection(conn: Connection) -> None:
    await conn.execute("SET application_name = 'yashigani-gateway'")


async def close_pool() -> None:
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


@asynccontextmanager
async def tenant_transaction(tenant_id: str) -> AsyncIterator[Connection]:
    """
    Acquire a connection, open a transaction, and SET the tenant context.
    RLS policies evaluate current_setting('app.tenant_id') on every row access.
    The AES key is also injected here so pgcrypto functions can reference it.
    """
    if _pool is None:
        raise RuntimeError("DB pool not initialized — call create_pool() at startup")
    aes_key = os.environ.get(_AES_KEY_ENV, "")
    async with _pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "SELECT set_config('app.tenant_id', $1, true),"
                "       set_config('app.aes_key', $2, true)",
                tenant_id,
                aes_key,
            )
            yield conn


def get_pool() -> Pool:
    if _pool is None:
        raise RuntimeError("DB pool not initialized — call create_pool() at startup")
    return _pool
