"""
yashigani.net.readiness — dependency-checked readiness helpers.

YSG-RISK-179: ``/readyz`` was referenced in every rate-limit / DDoS exemption
allowlist (``gateway/ddos.py``, ``gateway/endpoint_ratelimit.py``,
``auth/caddy_verified.py``) but no route ever implemented it — Caddy / k8s
readiness probes pointed at a 404. ``/healthz`` stays a shallow liveness
probe (process is up, event loop is responsive) by design; ``/readyz`` is
the DEP-CHECKED signal: postgres reachable (when configured) AND redis
reachable (when wired) -> 200, otherwise 503.

Both checks are best-effort and bounded by a short timeout so a hung
dependency cannot turn the readiness probe itself into a hang — Kubernetes /
Caddy health probes have their own timeouts, but a slow /readyz still ties
up a worker thread/coroutine, so we bound each check independently.

Postgres: if no DSN is configured (community/dev deploy without a DB — see
``gateway/entrypoint.py`` M-02 comment), the DB is not part of this
deployment's dependency graph and is reported ready trivially — a
readiness probe must not fail on an intentionally-absent optional
dependency. If a DSN *is* configured (``_YASHIGANI_DB_READY=1``) the pool
must exist and answer ``SELECT 1``.

Redis: callers pass whichever already-wired sync redis client is available
on their app state (e.g. the rate limiter's or DDoS protector's client —
same Redis server, different logical DB index, so any one of them is a
valid liveness signal for "is Redis reachable"). If no redis client is
wired at all, redis is not part of this deployment and is reported ready
trivially, mirroring the postgres behaviour above.
"""
from __future__ import annotations

import asyncio
import logging
import os

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_S = 2.0


async def postgres_ready(timeout: float = _DEFAULT_TIMEOUT_S) -> tuple[bool, str]:
    """Return (ready, detail). Trivially ready when no DB is configured."""
    if os.environ.get("_YASHIGANI_DB_READY") != "1":
        return True, "postgres_not_configured"

    try:
        from yashigani.db import get_pool
        pool = get_pool()
    except RuntimeError as exc:
        return False, f"postgres_pool_not_initialized: {exc}"

    conn = None
    try:
        conn = await asyncio.wait_for(pool.acquire(), timeout=timeout)
        await asyncio.wait_for(conn.fetchval("SELECT 1"), timeout=timeout)
        return True, "postgres_ok"
    except Exception as exc:
        logger.warning("readyz: postgres dep check failed: %s", exc)
        return False, f"postgres_unreachable: {exc}"
    finally:
        if conn is not None:
            try:
                await pool.release(conn)
            except Exception:
                pass


def redis_ready(redis_client, timeout: float = _DEFAULT_TIMEOUT_S) -> tuple[bool, str]:
    """Return (ready, detail). Trivially ready when no redis client is wired."""
    if redis_client is None:
        return True, "redis_not_configured"

    try:
        prior_timeout = getattr(redis_client, "socket_timeout", None)
        # redis-py sync client: .ping() honours the connection's configured
        # socket_timeout; we don't mutate it here to avoid cross-request races
        # on a shared client — bounded best-effort, not a hard guarantee.
        del prior_timeout
        ok = bool(redis_client.ping())
        return ok, ("redis_ok" if ok else "redis_ping_false")
    except Exception as exc:
        logger.warning("readyz: redis dep check failed: %s", exc)
        return False, f"redis_unreachable: {exc}"


async def dependency_readiness(redis_client, timeout: float = _DEFAULT_TIMEOUT_S) -> tuple[bool, dict]:
    """Run postgres + redis dep checks, return (all_ready, detail_dict)."""
    pg_ok, pg_detail = await postgres_ready(timeout=timeout)
    redis_ok, redis_detail = redis_ready(redis_client, timeout=timeout)
    return (pg_ok and redis_ok), {"postgres": pg_detail, "redis": redis_detail}
