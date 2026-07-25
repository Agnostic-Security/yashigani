"""
Yashigani Backoffice — bounded lazy reconnect for Redis-backed control-plane
state (RBAC, agent registry, permission store, budget).

YSG-RISK-122 (Ava, live docker-desktop k8s @ ca720724): `yashigani-backoffice`
started 7s before `yashigani-redis-0`. The in-process retry in
`entrypoint._bootstrap()` (1/2/4/8s x5, ~31s budget) exhausted before k8s DNS
for the headless Redis Service was resolvable, logged "RBAC and agent
registry disabled", and NEVER retried again: 10+ minutes later, with Redis
fully healthy, `GET /admin/agents` still returned 503 "Agent registry
unavailable", `/admin/api/permissions/declarations` still returned 503
"permission_store_not_configured", and `/admin/budget/usage/*` still returned
503 "Budget enforcer not available" — a transient boot-order race permanently
disabled RBAC, the agent registry, the permission store, and budget
enforcement for the whole pod lifetime. docker/podman compose ordering
(`depends_on`) doesn't hit this; k8s has no equivalent gate on Deployments
without an initContainer (added alongside this fix — see
helm/yashigani/templates/backoffice.yaml wait-for-redis / wait-for-budget-redis).

This module is the RUNTIME half of the fix: it stops the "disabled" state
from being permanent. Each `ensure_*()` function:

  1. Returns immediately (no Redis round-trip) if the relevant
     `backoffice_state` field is already populated — zero overhead on the
     hot path once healthy.
  2. Otherwise attempts AT MOST ONE reconnect per `cooldown_s` window (default
     15s, `YASHIGANI_RBAC_RECONNECT_COOLDOWN_S` /
     `YASHIGANI_BUDGET_RECONNECT_COOLDOWN_S`), so a burst of concurrent
     requests during an outage does not turn into a Redis connection storm,
     and a genuinely-down Redis does not add per-request latency beyond one
     bounded connect attempt every `cooldown_s`.
  3. On success, repopulates `backoffice_state` (and the budget-routes
     module-level `_state`) so subsequent requests are served normally.
  4. On failure, changes NOTHING — the existing `if X is None: raise 503`
     checks in the route helpers are untouched and still fire. This is
     explicitly NOT a fail-open change: if Redis is genuinely unreachable,
     denying/503 remains correct. The bug being fixed is that nothing ever
     tried again, not that the fail-closed response was wrong.

`maybe_selfheal()` is the entrypoint called from ASGI middleware
(`backoffice/app.py`) on admin requests — it does the cheap None-check
synchronously and only dispatches the (blocking, sync redis-py) reconnect
attempt to a worker thread via `asyncio.to_thread`, so the event loop is never
blocked by a Redis connect() in the common (already-healthy) case.

Last updated: 2026-07-24T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
import threading
import time

from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)

_RBAC_COOLDOWN_S = float(os.getenv("YASHIGANI_RBAC_RECONNECT_COOLDOWN_S", "15"))
_BUDGET_COOLDOWN_S = float(os.getenv("YASHIGANI_BUDGET_RECONNECT_COOLDOWN_S", "15"))

_lock = threading.Lock()
_last_attempt_monotonic: dict[str, float] = {}


def _cooldown_elapsed(name: str, cooldown_s: float) -> bool:
    """Thread-safe "at most one attempt per cooldown_s window" gate."""
    now = time.monotonic()
    with _lock:
        last = _last_attempt_monotonic.get(name)
        if last is not None and (now - last) < cooldown_s:
            return False
        _last_attempt_monotonic[name] = now
        return True


def ensure_rbac_stack(cooldown_s: float = _RBAC_COOLDOWN_S) -> bool:
    """Return True if the RBAC/Agent/Binding/.../CapabilityPolicy stack is
    available, attempting one bounded lazy reconnect if it currently is not.
    """
    if backoffice_state.agent_registry is not None:
        return True

    if not _cooldown_elapsed("rbac_agent_stack", cooldown_s):
        return False

    try:
        from yashigani.gateway._redis_url import build_redis_url
        from yashigani.backoffice.rbac_stack import build_rbac_agent_stack

        redis_rbac_url = build_redis_url(3, client_cert_name="backoffice_client")
        stack = build_rbac_agent_stack(redis_rbac_url)
    except Exception as exc:
        logger.warning(
            "RBAC/Agent Redis lazy reconnect failed (%s) — RBAC, agent registry, "
            "permission store, and dependent stores remain unavailable; "
            "will retry after %.0fs",
            exc, cooldown_s,
        )
        return False

    backoffice_state.rbac_store = stack.rbac_store
    backoffice_state.agent_registry = stack.agent_registry
    backoffice_state.binding_store = stack.binding_store
    backoffice_state.document_policy_store = stack.document_policy_store
    backoffice_state.document_set_store = stack.document_set_store
    backoffice_state.envelope_pending_store = stack.envelope_pending_store
    backoffice_state.dp_weaken_store = stack.dp_weaken_store
    backoffice_state.capability_policy_store = stack.capability_policy_store
    logger.info(
        "RBAC/Agent Redis lazy reconnect SUCCEEDED — RBAC, agent registry, "
        "permission store, and dependent stores are back online "
        "(YSG-RISK-122 self-heal)"
    )
    return True


def ensure_budget_config_store(cooldown_s: float = _BUDGET_COOLDOWN_S) -> bool:
    """Return True if the budget config store (backoffice Redis db/3) is
    available, attempting one bounded lazy reconnect if it currently is not.
    """
    from yashigani.backoffice.routes import budget as _budget_routes

    if _budget_routes._state.budget_store is not None:
        return True

    if not _cooldown_elapsed("budget_config_store", cooldown_s):
        return False

    try:
        from yashigani.gateway._redis_url import build_redis_url
        from yashigani.backoffice.budget_stack import build_budget_config_store

        redis_url = build_redis_url(3, client_cert_name="backoffice_client")
        budget_config_store = build_budget_config_store(redis_url)
    except Exception as exc:
        logger.warning(
            "Budget config store lazy reconnect failed (%s) — /admin/budget/* "
            "caps will not persist; will retry after %.0fs",
            exc, cooldown_s,
        )
        return False

    # configure() resets any kwarg not passed — preserve the other two fields
    # instead of wiping them out.
    _budget_routes.configure(
        budget_enforcer=_budget_routes._state.budget_enforcer,
        identity_registry=_budget_routes._state.identity_registry,
        budget_store=budget_config_store,
    )
    logger.info(
        "Budget config store lazy reconnect SUCCEEDED — /admin/budget/* caps "
        "back online (YSG-RISK-122 self-heal)"
    )
    return True


def ensure_budget_enforcer(cooldown_s: float = _BUDGET_COOLDOWN_S) -> bool:
    """Return True if the budget enforcer (separate budget-redis instance) is
    available, attempting one bounded lazy reconnect if it currently is not.
    """
    from yashigani.backoffice.routes import budget as _budget_routes

    if _budget_routes._state.budget_enforcer is not None:
        return True

    if not _cooldown_elapsed("budget_enforcer", cooldown_s):
        return False

    try:
        from yashigani.backoffice.budget_stack import (
            build_budget_enforcer,
            budget_enforcer_redis_url,
        )

        redis_use_tls = os.getenv("REDIS_USE_TLS", "true").lower() == "true"
        secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
        redis_url = budget_enforcer_redis_url(
            password=None, use_tls=redis_use_tls, secrets_dir=secrets_dir,
        )
        budget_enforcer = build_budget_enforcer(redis_url)
    except Exception as exc:
        logger.warning(
            "Budget enforcer lazy reconnect failed (%s) — "
            "/admin/budget/usage/* remains unavailable; will retry after %.0fs",
            exc, cooldown_s,
        )
        return False

    _budget_routes.configure(
        budget_enforcer=budget_enforcer,
        identity_registry=_budget_routes._state.identity_registry,
        budget_store=_budget_routes._state.budget_store,
    )
    logger.info(
        "Budget enforcer lazy reconnect SUCCEEDED — /admin/budget/usage/* "
        "back online (YSG-RISK-122 self-heal)"
    )
    return True


async def maybe_selfheal() -> None:
    """Cheap async entrypoint for ASGI middleware (backoffice/app.py).

    Does the None-check inline (no thread dispatch) and only hands off to a
    worker thread — via asyncio.to_thread — when a reconnect attempt is
    actually needed, so the event loop is never blocked by a Redis connect()
    in the steady-state (already-healthy) case.
    """
    import asyncio

    if backoffice_state.agent_registry is None:
        await asyncio.to_thread(ensure_rbac_stack)

    from yashigani.backoffice.routes import budget as _budget_routes

    if _budget_routes._state.budget_store is None:
        await asyncio.to_thread(ensure_budget_config_store)
    if _budget_routes._state.budget_enforcer is None:
        await asyncio.to_thread(ensure_budget_enforcer)
