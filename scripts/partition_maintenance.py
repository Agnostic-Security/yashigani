#!/usr/bin/env python3
"""
Yashigani DB Partition Maintenance
====================================
Ensures the current month + next `months_ahead` months of audit_events and
inference_events partitions exist.

Safe to run repeatedly — CREATE TABLE IF NOT EXISTS semantics.
Called from pg_cron or the Kubernetes CronJob on the 1st of each month at 00:05 UTC.

Usage:
    DATABASE_URL=postgresql://user:pass@host/db python scripts/partition_maintenance.py
    python scripts/partition_maintenance.py --months-ahead 6

Last updated: 2026-05-01T23:47:00+01:00
mTLS fix: extract sslrootcert/sslcert/sslkey from DSN, build ssl.SSLContext
for asyncpg (asyncpg does not parse libpq ssl params from DSN query string).
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import ssl
import sys
from datetime import date
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)

# Identifier quoting: only allow identifiers that are safe ASCII alphanumeric +
# underscore, matching the naming convention enforced by _PARTITIONED_TABLES and
# _partition_name().  This is a defence-in-depth guard — asyncpg DDL params
# bind date literals; we use safe quoting for the identifier tokens.
_SAFE_IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _quote_ident(name: str) -> str:
    """Quote a PostgreSQL identifier safely.

    Only ASCII alphanumeric + underscore identifiers are permitted; anything
    else raises ValueError so the caller (and the unit test) can catch a
    maliciously-crafted name before it ever reaches the database.

    This mirrors the behaviour of psycopg.sql.Identifier: wraps the name in
    double-quotes and rejects names that cannot be safely expressed that way
    without allowlisting.
    """
    if not _SAFE_IDENT_RE.match(name):
        raise ValueError(
            f"Identifier {name!r} contains characters outside [a-zA-Z0-9_] "
            "and cannot be safely quoted — possible injection attempt."
        )
    # Double any embedded double-quotes (none expected given the regex above,
    # but defensive completeness per SQL standard).
    escaped = name.replace('"', '""')
    return f'"{escaped}"'


_PARTITIONED_TABLES = ["audit_events", "inference_events"]


def _partition_range(year: int, month: int) -> tuple[date, date]:
    """Return (start_inclusive, end_exclusive) for a monthly partition."""
    start = date(year, month, 1)
    if month == 12:
        end = date(year + 1, 1, 1)
    else:
        end = date(year, month + 1, 1)
    return start, end


def _partition_name(table: str, year: int, month: int) -> str:
    return f"{table}_{year}_{month:02d}"


def _build_ssl_context(dsn: str) -> tuple[str, ssl.SSLContext | None]:
    """Extract libpq SSL params from DSN query string, build ssl.SSLContext.

    asyncpg does not parse sslrootcert/sslcert/sslkey from the DSN query
    string — it expects an ssl.SSLContext object or the string 'require'.
    This helper pulls the params out and returns a clean DSN + context.
    """
    parsed = urlparse(dsn)
    params = parse_qs(parsed.query, keep_blank_values=True)
    sslmode = params.pop("sslmode", [None])[0]
    sslrootcert = params.pop("sslrootcert", [None])[0]
    sslcert = params.pop("sslcert", [None])[0]
    sslkey = params.pop("sslkey", [None])[0]

    new_query = urlencode({k: v[0] for k, v in params.items()})
    clean_dsn = urlunparse(parsed._replace(query=new_query))

    if sslmode is None or sslmode == "disable":
        return clean_dsn, None

    ctx = ssl.create_default_context(cafile=sslrootcert)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # TLS 1.3 only (2.25.1; Postgres 16 supports it)
    if sslcert and sslkey:
        ctx.load_cert_chain(certfile=sslcert, keyfile=sslkey)
    if sslmode in ("require", "verify-ca"):
        ctx.check_hostname = False
        if sslmode == "require":
            ctx.verify_mode = ssl.CERT_NONE
    return clean_dsn, ctx


async def ensure_partitions(conn_dsn: str, months_ahead: int = 3) -> dict[str, list[str]]:
    """
    Ensure partitions exist for the current month through months_ahead months forward.

    Returns a dict mapping table name → list of partition names ensured.
    """
    try:
        import asyncpg
    except ImportError:
        logger.error("asyncpg is required. pip install asyncpg")
        sys.exit(1)

    clean_dsn, ssl_ctx = _build_ssl_context(conn_dsn)
    conn_kwargs: dict = {"ssl": ssl_ctx} if ssl_ctx is not None else {}
    conn = await asyncpg.connect(clean_dsn, **conn_kwargs)
    created: dict[str, list[str]] = {t: [] for t in _PARTITIONED_TABLES}

    try:
        today = date.today().replace(day=1)
        for i in range(months_ahead + 1):
            month_offset = today.month - 1 + i
            year = today.year + month_offset // 12
            month = month_offset % 12 + 1
            start, end = _partition_range(year, month)

            for table in _PARTITIONED_TABLES:
                name = _partition_name(table, year, month)
                # Safe identifier quoting — _quote_ident rejects any name
                # that doesn't match [a-zA-Z_][a-zA-Z0-9_]* before the
                # statement is composed (CWE-89, YSG-RISK-001 #3ar).
                # Date literals are formatted directly as ISO-8601 strings
                # (YYYY-MM-DD). asyncpg bind parameters ($1/$2) are NOT
                # supported in DDL statements like CREATE TABLE — the server
                # reports "expects 0 arguments" and fails. The date values
                # come from Python date arithmetic (not user input) so
                # direct string interpolation is safe here.
                q_name = _quote_ident(name)
                q_table = _quote_ident(table)
                await conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {q_name}"
                    f" PARTITION OF {q_table}"
                    f" FOR VALUES FROM ('{start.isoformat()}') TO ('{end.isoformat()}')"
                )
                created[table].append(name)
                logger.info("Partition %s: OK", name)
    finally:
        await conn.close()

    return created


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Create missing audit/inference log partitions"
    )
    parser.add_argument(
        "--months-ahead",
        type=int,
        default=3,
        help="Number of future months to pre-create (default: 3)",
    )
    args = parser.parse_args()

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        logger.error("DATABASE_URL environment variable is required")
        sys.exit(1)

    created = asyncio.run(ensure_partitions(dsn, months_ahead=args.months_ahead))

    total = sum(len(v) for v in created.values())
    print(f"Partition maintenance complete: {total} partition(s) ensured.")
    for table, names in created.items():
        for name in names:
            print(f"  {name}: OK")


if __name__ == "__main__":
    main()
