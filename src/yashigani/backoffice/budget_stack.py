"""
Yashigani Backoffice — Budget-Redis stack builders (config store + enforcer).

YSG-RISK-122: extracted from entrypoint._bootstrap() alongside rbac_stack.py.
Two INDEPENDENT Redis connections back the budget admin surface:

  * budget_config_store — backoffice Redis db/3 (same instance as the RBAC
    stack, different key namespace: budget:config:*). Backs /admin/budget/*
    (org/group/user caps).
  * budget_enforcer      — the SEPARATE `budget-redis` instance, db/0. Backs
    /admin/budget/usage/{identity_id} (usage counters written by the gateway).

Both were previously single-attempt, no-retry try/except blocks in
`_bootstrap()` — unlike the RBAC stack they never even had a 5x backoff loop,
so they were, if anything, MORE exposed to the same k8s boot-race Ava
confirmed live (backoffice scheduled before its Redis dependency; headless
Service DNS not yet resolvable). Once either try/except failed, the field
stayed `None` for the container's entire lifetime — `/admin/budget/usage/*`
returns 503 "Budget enforcer not available" forever, even once budget-redis
is healthy.

Extracted here (not inlined in entrypoint.py) for the same reason as
rbac_stack.py: route/middleware code needs to call this again, later, at
request time, without importing entrypoint.py and re-running its module-level
bootstrap side effects.

Last updated: 2026-07-24T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


def build_budget_config_store(redis_url: str) -> Any:
    """Construct BudgetConfigStore against backoffice Redis db/3. Raises on failure."""
    import redis as _redis
    from yashigani.billing.budget_config_store import BudgetConfigStore

    redis_budget_client = _redis.from_url(redis_url, decode_responses=False)
    budget_config_store = BudgetConfigStore(redis_client=redis_budget_client)
    logger.info("Budget config store initialised (Redis db/3)")
    return budget_config_store


def build_budget_enforcer(redis_url: str) -> Any:
    """Construct BudgetEnforcer against the separate budget-redis instance (db/0).

    Raises on failure — including the explicit `.ping()` that was already
    part of the original inline block (fail fast on a stale/unreachable
    connection rather than deferring the failure to first use).
    """
    import redis as _redis
    from yashigani.billing.budget_enforcer import BudgetEnforcer

    budget_redis_client = _redis.from_url(redis_url, decode_responses=False)
    budget_redis_client.ping()
    budget_enforcer = BudgetEnforcer(redis_client=budget_redis_client)
    logger.info("Budget enforcer initialised (budget-redis)")
    return budget_enforcer


def budget_config_redis_url(backoffice_redis_url_fn) -> str:
    """db/3 on the SAME backoffice Redis instance as the RBAC stack."""
    return backoffice_redis_url_fn(3)


def budget_enforcer_redis_url(
    *, password: str | None, use_tls: bool, secrets_dir: str,
) -> str:
    """db/0 on the SEPARATE budget-redis instance.

    Host/port default to BUDGET_REDIS_HOST / BUDGET_REDIS_PORT env vars
    (compose: "budget-redis"; k8s: "yashigani-budget-redis" — see
    helm/yashigani/templates/backoffice.yaml env block, which now sets these
    explicitly, mirroring gateway.yaml. Without an explicit override the code
    default ("budget-redis") does not resolve in-cluster — a second,
    independent root cause found during YSG-RISK-122 inspection, fixed
    alongside the reconnect-latch bug since the lazy reconnect would
    otherwise retry the wrong hostname forever.
    """
    from yashigani.gateway._redis_url import build_redis_url

    budget_redis_host = os.getenv("BUDGET_REDIS_HOST", "budget-redis")
    budget_redis_port = os.getenv("BUDGET_REDIS_PORT", "6380")
    return build_redis_url(
        0,
        host=budget_redis_host,
        port=budget_redis_port,
        password=password,
        use_tls=use_tls,
        secrets_dir=secrets_dir,
        client_cert_name="backoffice_client",
    )
