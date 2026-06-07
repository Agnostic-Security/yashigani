# Last updated: 2026-05-02T00:00:00+01:00 (RETRO-R4-2: expose connect_with_retry_sync)
from yashigani.db.postgres import create_pool, close_pool, tenant_transaction, get_pool, connect_with_retry_sync

__all__ = ["create_pool", "close_pool", "tenant_transaction", "get_pool", "run_migrations", "connect_with_retry_sync"]


# Stable 64-bit advisory-lock key for Yashigani schema/bootstrap operations.
# Generated from `python -c "import zlib; print(hex(zlib.crc32(b'yashigani.bootstrap')))"`
# and biased into the int64 range. Any value works as long as it's stable across
# all replicas. Documented so future migration code uses the same key for
# bootstrap-class operations rather than inventing new ones.
_BOOTSTRAP_ADVISORY_LOCK_KEY = 0x7959470062535F31


def run_migrations() -> None:
    """Run Alembic migrations to head (sync, safe to call from startup).

    Multi-replica safety: when multiple backoffice/gateway replicas come up
    concurrently in K8s, only ONE replica should run the migrations to avoid
    alembic_version row contention and partial-DDL races. We acquire a
    PostgreSQL session-scoped advisory lock BEFORE alembic upgrades, hold it
    for the whole upgrade, then release. Other replicas block on the same key
    until the holder releases, then run alembic which detects "already at
    head" and is a no-op. Platform gate #58c #3bv evidence (2026-04-29) — found
    by static audit between Round 7 and Round 8.
    """
    import logging
    import os
    from alembic.config import Config
    from alembic import command
    from urllib.parse import urlparse, unquote

    logger = logging.getLogger(__name__)
    migrations_dir = os.path.join(os.path.dirname(__file__), "migrations")
    alembic_cfg = Config()
    alembic_cfg.set_main_option("script_location", migrations_dir)
    # v2.25.2 (Lu wire-sink-gate P1 — least-privilege runtime role):
    # DDL / migrations MUST run as the admin superuser (yashigani_admin), NOT as
    # the demoted runtime role (yashigani_app, NOSUPERUSER + non-owner).  The
    # admin DSN is provided via YASHIGANI_DB_DSN_ADMIN; we fall back to the
    # runtime DSN only when the admin DSN is unset (legacy single-role installs /
    # tests that have not split credentials).  ALTER ROLE / REASSIGN OWNED in
    # migration 0015 require the admin identity.
    dsn = os.environ.get("YASHIGANI_DB_DSN_ADMIN") or os.environ.get("YASHIGANI_DB_DSN", "")
    if os.environ.get("YASHIGANI_DB_DSN_ADMIN"):
        logger.info("run_migrations: using admin DSN (YASHIGANI_DB_DSN_ADMIN) for DDL")
    sync_dsn = dsn.replace("postgresql://", "postgresql+psycopg2://").replace(
        "postgresql+asyncpg://", "postgresql+psycopg2://"
    )
    # v2.23.1 fix: alembic.Config backs onto ConfigParser, which treats '%' as
    # an interpolation sigil. URL-encoded passwords (e.g. ',' -> '%2C',
    # '!' -> '%21') therefore raise "invalid interpolation syntax" on
    # set_main_option. Double '%' to escape, then libpq / SQLAlchemy decode it
    # back to the encoded form, and psycopg2 URL-unquotes it to the real
    # password before sending to pgbouncer.
    sync_dsn_alembic = sync_dsn.replace("%", "%%")
    alembic_cfg.set_main_option("sqlalchemy.url", sync_dsn_alembic)

    # Multi-replica advisory lock: hold this for the duration of the upgrade.
    # Use a dedicated psycopg2 connection (not the alembic-internal one) so the
    # lock outlives any of alembic's per-revision transactions.
    #
    # CRITICAL (Platform gate #58c #3bw, 2026-04-29): the lock connection MUST go
    # direct to postgres, NOT through pgbouncer. pgbouncer in transaction-pool
    # mode routes each new connection to a different postgres backend, and
    # postgres advisory locks are session-scoped (per-backend). If both
    # replicas connect through pgbouncer they land on different backends and
    # both successfully "acquire" the same lock key independently — no
    # serialisation. We use YASHIGANI_DB_DSN_DIRECT (set in K8s helm chart
    # pointing at yashigani-postgres:5432, bypassing yashigani-pgbouncer:5432)
    # for the lock connection when it's set; compose runs single-replica so
    # falls back to YASHIGANI_DB_DSN where contention doesn't matter.
    # v2.25.2: the advisory-lock connection runs the same DDL session, so it must
    # use the admin direct DSN when available (admin identity, bypassing pgbouncer
    # for session-scoped advisory locks).
    lock_dsn = (
        os.environ.get("YASHIGANI_DB_DSN_ADMIN_DIRECT")
        or os.environ.get("YASHIGANI_DB_DSN_DIRECT")
        or dsn
    )
    # RETRO-R4-2: use connect_with_retry_sync instead of bare psycopg2.connect()
    # so a postgres restart mid-startup fails fast (connect_timeout=15s) and
    # retries rather than hanging the process indefinitely.
    lock_conn = connect_with_retry_sync(lock_dsn, max_attempts=5, backoff_s=3.0)
    try:
        lock_conn.autocommit = True
        with lock_conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_lock(%s)", (_BOOTSTRAP_ADVISORY_LOCK_KEY,))
        logger.info("Acquired migration advisory lock %s", hex(_BOOTSTRAP_ADVISORY_LOCK_KEY))
        # env.py (the alembic environment) resolves the connection from the
        # YASHIGANI_DB_DSN env var, which points at pgbouncer as the RUNTIME role
        # yashigani_app. On a FRESH install that role does not exist until migration
        # 0001 creates it, so pgbouncer's auth_query (ysg_pgbouncer_get_auth) returns
        # no row and the connection is rejected "no such user" — DDL can never
        # bootstrap (only upgrades, where the role pre-exists, worked). DDL MUST run
        # as the admin superuser DIRECT to postgres (see `dsn` above + the lock
        # connection). Point env.py at the admin DSN for the duration of the upgrade,
        # then restore so the lifespan's later create_pool() still uses the runtime
        # DSN. Regression introduced with the 2.25.2 least-privilege role split.
        _prev_runtime_dsn = os.environ.get("YASHIGANI_DB_DSN")
        os.environ["YASHIGANI_DB_DSN"] = dsn
        try:
            command.upgrade(alembic_cfg, "head")
            logger.info("Database migrations applied successfully (replica-safe)")
            # v2.25.3: replace the placeholder password that migration 0001 sets on
            # the yashigani_app runtime role (CREATE ROLE ... IF NOT EXISTS ...
            # PASSWORD 'PLACEHOLDER_REPLACED_BY_BOOTSTRAP') with the single
            # install-generated credential (docker/secrets/postgres_password — the
            # one and only password generator, install.sh _gen_password). This MUST
            # run here: after migrations create the role and BEFORE the lifespan's
            # create_pool() opens the yashigani_app connection. On a FRESH install
            # the role is created with the placeholder, so without this swap the app
            # crash-loops with "SASL authentication failed" (asyncpg→pgbouncer→
            # postgres). Upgrades keep the existing password via IF NOT EXISTS, so
            # this is a no-op-equivalent re-set there. Runs on the admin advisory-
            # lock connection (multi-replica safe — only the lock holder re-sets).
            # Replaces the lost install.sh bootstrap step dropped by commit e0e6f72.
            _sync_app_role_password(lock_conn, logger)
        except Exception as exc:
            logger.warning("Database migration failed: %s", exc)
        finally:
            # Restore the runtime DSN so the lifespan's create_pool() connects as
            # yashigani_app via pgbouncer (not the admin DSN used for DDL above).
            if _prev_runtime_dsn is None:
                os.environ.pop("YASHIGANI_DB_DSN", None)
            else:
                os.environ["YASHIGANI_DB_DSN"] = _prev_runtime_dsn
            with lock_conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_unlock(%s)", (_BOOTSTRAP_ADVISORY_LOCK_KEY,))
            logger.info("Released migration advisory lock")
    finally:
        lock_conn.close()


def _sync_app_role_password(conn, logger) -> None:
    """Set the yashigani_app runtime role password to the single install-generated
    credential, replacing migration 0001's placeholder.

    `conn` is the admin (superuser) connection already held by run_migrations under
    the bootstrap advisory lock; it is autocommit. Reads the raw password from the
    install-written secret (docker/secrets/postgres_password — the same value the
    backoffice DSN resolves ${POSTGRES_PASSWORD} from). Never generates a password.
    Swallows+logs its own errors: a real failure surfaces clearly when create_pool()
    next opens the yashigani_app connection, rather than being mislabelled a
    migration failure by the caller's except handler.
    """
    import os
    from psycopg2 import sql

    secrets_dir = os.environ.get("YASHIGANI_SECRETS_DIR", "/run/secrets")
    pw_path = os.path.join(secrets_dir, "postgres_password")
    try:
        with open(pw_path, encoding="utf-8") as fh:
            app_pw = fh.read().strip()
    except OSError as exc:
        logger.error("yashigani_app credential sync skipped — cannot read %s: %s", pw_path, exc)
        return
    if not app_pw:
        logger.error("yashigani_app credential sync skipped — %s is empty", pw_path)
        return
    # ALTER ROLE ... PASSWORD does not accept bind parameters (utility statement);
    # use psycopg2 sql.Literal for correct, injection-safe quoting of the literal.
    try:
        with conn.cursor() as cur:
            cur.execute(
                sql.SQL("ALTER ROLE yashigani_app WITH PASSWORD {}").format(sql.Literal(app_pw))
            )
        logger.info(
            "yashigani_app runtime credential synced (migration-0001 placeholder replaced)"
        )
    except Exception as exc:  # noqa: BLE001 — log + continue; create_pool surfaces real fault
        logger.error("Failed to sync yashigani_app credential: %s", exc)
