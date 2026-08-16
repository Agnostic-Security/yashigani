"""
Yashigani Gateway — bounded lazy reconnect for every Redis-backed control-plane
dependency the gateway builds at cold boot.

YSG-RISK-139 (Iris systemic review, following the live-reproduced chat
blocker): ``gateway/entrypoint.py`` builds 13 distinct Redis-dependent
subsystems, each in its own one-shot try/except at cold boot (no retry, no
self-heal). On k8s, ``yashigani-redis`` Service-DNS is not always resolvable
at that exact instant (Redis Pod scheduled slightly after the gateway Pod) —
a single failed connection attempt then leaves the dependent field ``None``
for the ENTIRE pod lifetime, since nothing at request time ever tries again.
Live-reproduced: both gateway replicas ran 17h, 0 restarts, permanently
degraded — "RBAC/Agent Redis unavailable" logged once at boot and never
retried, chat requests returning ``agent_registry_unavailable`` the whole
time. docker/podman compose ordering (``depends_on: condition:
service_healthy``) hides this class entirely; only k8s reproduces the
boot-order race. Full analysis:
``testing_runs/yashigani/v412-e2e-latest-20260727/iris/remediation_map.md``.

## Design

Reuses the shared cooldown-gated bounded-reconnect primitive from
``yashigani.common.redis_selfheal`` (see that module's docstring) instead of
duplicating ``backoffice/redis_selfheal.py``'s bookkeeping a second time.
Each ``ensure_*()`` function below supplies:

  1. A health check reading whatever live-state container that subsystem's
     real consumers already check at request time — no new state is
     invented where a live one exists:
       * ``openai_router._state`` (module singleton, already read live by
         ``chat_completions()``) for agent_registry / rbac_store /
         permission_store / identity_registry / budget_enforcer /
         model_allocation_store / model_alias_store / ddos_protector /
         optimization_engine.cloud_override_getter.
       * ``app_state`` — the SAME dict ``create_gateway_app()`` builds and
         every proxy.py middleware/route already reads via
         ``state["key"]`` / ``state.get("key")`` — exposed to this module by
         ``proxy.py`` via ``app.state.internal_state`` (see that module) for
         rate_limiter / endpoint_rate_limiter / response_cache /
         jwt_inspector / workflow_scheduler / ddos_protector /
         rbac_store / agent_registry / capability_policy_store /
         permission_store.
       * ``egress_proxy._state`` (that module's own module-level singleton,
         already read live) for egress_limit_enforcer.
     Two additional consumers snapshot a value at construction time instead
     of reading live state (``AgentAuthMiddleware._registry`` and
     ``MetricsCollector``'s rbac/agent gauges) — the middleware one is fixed
     via ``gateway/state.py``'s tiny fallback singleton (see that module's
     docstring for why ``MetricsCollector`` is an accepted, documented,
     metrics-only residual and NOT wired the same way).
  2. A builder that reconstructs the object using the IDENTICAL construction
     call already used at cold boot in ``entrypoint.py`` (row #1 — the RBAC/
     Agent/Capability-Policy/Permission-store stack — is fully extracted into
     ``gateway/rbac_stack.py`` and reused by BOTH the boot retry loop and
     this module, exactly like backoffice's YSG-RISK-122 fix, since it is the
     confirmed live blocker. Rows #2-13 are lower-severity siblings from the
     SAME class (Iris's remediation map, findings #2-13): their cold-boot
     try/except blocks in entrypoint.py are left untouched in this change —
     each already works correctly whenever Redis is reachable in time, and
     refactoring 12 already-passing boot paths into shared builders carries
     more regression risk than value for this fix. This module reconstructs
     each of them independently, verified line-for-line against its
     entrypoint.py cold-boot counterpart. Extracting shared builder functions
     for rows #2-13 is a reasonable low-priority follow-up, not a blocker.)
  3. A success callback writing the rebuilt object into every consumer found
     above.

## What is deferred (see Iris's remediation map for the full list)

* Backoffice findings #14-19 (rate_limiter, backend_registry, model_alias_
  store, model_allocation_store, response_cache, identity_registry) are the
  SAME bug class but P2 (admin-plane only, smaller blast radius) — explicitly
  out of scope for this change per dispatch.
* The missing ``wait-for-redis`` initContainer in
  ``helm/yashigani/templates/gateway.yaml`` (backoffice has one,
  ``backoffice.yaml:61-125``) is belt-and-braces defence-in-depth that
  reduces the ODDS of hitting this race — it does not replace the self-heal
  fix (per the 122 postmortem, DNS propagation can outlast even the
  initContainer's wait budget). Flagged for Captain; not implemented here.
* Live k8s re-verification of this fix is deferred (Tiago: k8s leg paused
  for the Docker/Podman legs) — this change is verified via local regression
  tests proving the reconnect mechanics, not a live redeploy.

Last updated: 2026-07-28T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
from typing import Any, Callable

from yashigani.common import redis_selfheal as _common
from yashigani.gateway.state import gateway_fallback_state

logger = logging.getLogger(__name__)

_DEFAULT_COOLDOWN_S = float(os.getenv("YASHIGANI_GATEWAY_SELFHEAL_COOLDOWN_S", "15"))


def _gw_redis_url(db: int, host: str | None = None, port: str | None = None) -> str:
    from yashigani.gateway._redis_url import build_redis_url

    secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
    redis_use_tls = os.getenv("REDIS_USE_TLS", "true").lower() == "true"
    return build_redis_url(
        db,
        host=host,
        port=port,
        use_tls=redis_use_tls,
        secrets_dir=secrets_dir,
        client_cert_name="gateway_client",
    )


def _setter(container: dict, key: str) -> Callable[[Any], None]:
    def _set(value: Any) -> None:
        container[key] = value
    return _set


# ---------------------------------------------------------------------------
# #1 (P0, confirmed live blocker) — rbac_store / agent_registry /
# capability_policy_store / permission_store (Redis db/3)
# ---------------------------------------------------------------------------

def ensure_rbac_agent_stack(app_state: dict, cooldown_s: float = _DEFAULT_COOLDOWN_S) -> bool:
    from yashigani.gateway import openai_router as _oai
    from yashigani.gateway.rbac_stack import build_rbac_agent_stack

    def _build():
        return build_rbac_agent_stack(_gw_redis_url(3))

    def _on_success(stack) -> None:
        _oai._state.agent_registry = stack.agent_registry
        _oai._state.rbac_store = stack.rbac_store
        _oai._state.permission_store = stack.permission_store
        try:
            _oai._load_token_role_map(stack.agent_registry)
        except Exception as exc:
            logger.warning(
                "Gateway token-role map refresh after self-heal failed (%s)", exc
            )

        gateway_fallback_state.agent_registry = stack.agent_registry
        gateway_fallback_state.rbac_store = stack.rbac_store

        app_state["rbac_store"] = stack.rbac_store
        app_state["agent_registry"] = stack.agent_registry
        app_state["capability_policy_store"] = stack.capability_policy_store
        app_state["permission_store"] = stack.permission_store

    return _common.ensure(
        "gateway_rbac_agent_stack",
        is_healthy=lambda: _oai._state.agent_registry is not None,
        build=_build,
        on_success=_on_success,
        cooldown_s=cooldown_s,
        unavailable_msg=(
            "Gateway RBAC/Agent Redis lazy reconnect failed — agent routing, "
            "RBAC group backfill, and cloud-model permission gate remain unavailable"
        ),
        recovered_msg=(
            "Gateway RBAC/Agent Redis lazy reconnect SUCCEEDED — agent routing, "
            "RBAC group backfill, and cloud-model permission gate back online"
        ),
    )


# ---------------------------------------------------------------------------
# #2 — rate_limiter (Redis db/2)
# ---------------------------------------------------------------------------

def _build_rate_limiter():
    import redis as _redis
    from yashigani.ratelimit.limiter import RateLimiter
    from yashigani.ratelimit.config import RateLimitConfig
    from yashigani.chs.resource_monitor import ResourceMonitor
    from yashigani.gateway._ratelimit_env import resolve_rate_limit_fail_mode

    redis_client = _redis.from_url(_gw_redis_url(2), decode_responses=False)
    redis_client.ping()

    fail_mode = resolve_rate_limit_fail_mode()
    per_user_rps = 100.0
    _raw = os.environ.get("YASHIGANI_RATE_LIMIT_PER_USER_RPS", "").strip()
    if _raw:
        try:
            _v = float(_raw)
            if _v > 0:
                per_user_rps = _v
        except ValueError:
            logger.warning(
                "YASHIGANI_RATE_LIMIT_PER_USER_RPS=%r invalid during self-heal — "
                "defaulting to 100.0", _raw,
            )
    per_user_burst = max(1, int(per_user_rps * 2))

    return RateLimiter(
        redis_client=redis_client,
        config=RateLimitConfig(
            fail_mode=fail_mode,
            per_user_rps=per_user_rps,
            per_user_burst=per_user_burst,
        ),
        resource_monitor=ResourceMonitor(),
    )


def ensure_rate_limiter(app_state: dict, cooldown_s: float = _DEFAULT_COOLDOWN_S) -> bool:
    return _common.ensure(
        "gateway_rate_limiter",
        is_healthy=lambda: app_state.get("rate_limiter") is not None,
        build=_build_rate_limiter,
        on_success=_setter(app_state, "rate_limiter"),
        cooldown_s=cooldown_s,
        unavailable_msg="Gateway rate limiter Redis lazy reconnect failed — rate limiting remains disabled",
        recovered_msg="Gateway rate limiter Redis lazy reconnect SUCCEEDED — per-user/session rate limiting back online",
    )


# ---------------------------------------------------------------------------
# #3 — endpoint_rate_limiter (Redis db/2)
# ---------------------------------------------------------------------------

def _build_endpoint_rate_limiter():
    import redis as _redis
    from yashigani.gateway.endpoint_ratelimit import EndpointRateLimiter

    redis_client = _redis.from_url(_gw_redis_url(2), decode_responses=False)
    redis_client.ping()
    return EndpointRateLimiter(redis_client=redis_client)


def ensure_endpoint_rate_limiter(app_state: dict, cooldown_s: float = _DEFAULT_COOLDOWN_S) -> bool:
    return _common.ensure(
        "gateway_endpoint_rate_limiter",
        is_healthy=lambda: app_state.get("endpoint_rate_limiter") is not None,
        build=_build_endpoint_rate_limiter,
        on_success=_setter(app_state, "endpoint_rate_limiter"),
        cooldown_s=cooldown_s,
        unavailable_msg="Gateway endpoint rate limiter Redis lazy reconnect failed — endpoint rate limiting remains disabled",
        recovered_msg="Gateway endpoint rate limiter Redis lazy reconnect SUCCEEDED",
    )


# ---------------------------------------------------------------------------
# #4 — response_cache (Redis db/4)
# ---------------------------------------------------------------------------

def _build_response_cache():
    import redis as _redis
    from yashigani.gateway.response_cache import ResponseCache

    redis_client = _redis.from_url(_gw_redis_url(4), decode_responses=False)
    redis_client.ping()
    return ResponseCache(redis_client=redis_client)


def ensure_response_cache(app_state: dict, cooldown_s: float = _DEFAULT_COOLDOWN_S) -> bool:
    return _common.ensure(
        "gateway_response_cache",
        is_healthy=lambda: app_state.get("response_cache") is not None,
        build=_build_response_cache,
        on_success=_setter(app_state, "response_cache"),
        cooldown_s=cooldown_s,
        unavailable_msg="Gateway response cache Redis lazy reconnect failed — caching remains disabled",
        recovered_msg="Gateway response cache Redis lazy reconnect SUCCEEDED",
    )


# ---------------------------------------------------------------------------
# #5 — jwt_inspector (Redis db/1)
# ---------------------------------------------------------------------------

def _build_jwt_inspector():
    import redis as _redis
    from yashigani.gateway.jwt_inspector import JWTInspector

    redis_client = _redis.from_url(_gw_redis_url(1), decode_responses=False)
    redis_client.ping()
    return JWTInspector(redis_client=redis_client)


def ensure_jwt_inspector(app_state: dict, cooldown_s: float = _DEFAULT_COOLDOWN_S) -> bool:
    return _common.ensure(
        "gateway_jwt_inspector",
        is_healthy=lambda: app_state.get("jwt_inspector") is not None,
        build=_build_jwt_inspector,
        on_success=_setter(app_state, "jwt_inspector"),
        cooldown_s=cooldown_s,
        unavailable_msg="Gateway JWT inspector Redis lazy reconnect failed — JWT validation remains disabled",
        recovered_msg="Gateway JWT inspector Redis lazy reconnect SUCCEEDED",
    )


# ---------------------------------------------------------------------------
# #6 — identity_registry (Redis db/3, independent connection)
# ---------------------------------------------------------------------------

def _build_identity_registry():
    import redis as _redis
    from yashigani.identity import IdentityRegistry
    from yashigani.identity.durable_store import IdentityDurableStore

    redis_client = _redis.from_url(_gw_redis_url(3), decode_responses=False)
    redis_client.ping()
    durable = None
    try:
        durable = IdentityDurableStore()
    except Exception as exc:
        logger.warning(
            "Gateway identity durable store unavailable during self-heal (%s) — Redis-only mode",
            exc,
        )
    return IdentityRegistry(redis_client=redis_client, durable_store=durable)


def ensure_identity_registry(app_state: dict, cooldown_s: float = _DEFAULT_COOLDOWN_S) -> bool:
    from yashigani.gateway import openai_router as _oai

    def _on_success(reg) -> None:
        _oai._state.identity_registry = reg
        app_state["identity_registry"] = reg

    return _common.ensure(
        "gateway_identity_registry",
        is_healthy=lambda: _oai._state.identity_registry is not None,
        build=_build_identity_registry,
        on_success=_on_success,
        cooldown_s=cooldown_s,
        unavailable_msg="Gateway identity registry Redis lazy reconnect failed",
        recovered_msg="Gateway identity registry Redis lazy reconnect SUCCEEDED",
    )


# ---------------------------------------------------------------------------
# #7 — budget_enforcer (budget-redis, separate instance)
# ---------------------------------------------------------------------------

def _build_budget_enforcer():
    import redis as _redis
    from yashigani.billing.budget_enforcer import BudgetEnforcer

    host = os.getenv("BUDGET_REDIS_HOST", "budget-redis")
    port = os.getenv("BUDGET_REDIS_PORT", "6380")
    redis_client = _redis.from_url(_gw_redis_url(0, host=host, port=port), decode_responses=False)
    redis_client.ping()
    return BudgetEnforcer(redis_client=redis_client)


def ensure_budget_enforcer(cooldown_s: float = _DEFAULT_COOLDOWN_S) -> bool:
    from yashigani.gateway import openai_router as _oai

    def _on_success(enforcer) -> None:
        _oai._state.budget_enforcer = enforcer

    return _common.ensure(
        "gateway_budget_enforcer",
        is_healthy=lambda: _oai._state.budget_enforcer is not None,
        build=_build_budget_enforcer,
        on_success=_on_success,
        cooldown_s=cooldown_s,
        unavailable_msg="Gateway budget enforcer Redis lazy reconnect failed — budget enforcement remains disabled",
        recovered_msg="Gateway budget enforcer Redis lazy reconnect SUCCEEDED",
    )


# ---------------------------------------------------------------------------
# #8 — cloud_override_getter (Redis db/0, dual-admin cloud-LLM override)
# ---------------------------------------------------------------------------

def _build_cloud_override_getter():
    import redis as _redis_co_mod
    from yashigani.optimization.cloud_override import CloudLlmOverrideManager
    from yashigani.gateway import openai_router as _oai

    redis_client = _redis_co_mod.from_url(_gw_redis_url(0), decode_responses=False)
    redis_client.ping()
    mgr = CloudLlmOverrideManager(redis_client, _oai._state.audit_writer)
    cache: dict[str, Any] = {"t": 0.0, "v": None}

    def _getter():
        import time as _t
        now = _t.monotonic()
        if now - cache["t"] > 5.0:
            try:
                cache["v"] = mgr.get_active()
            except Exception:
                cache["v"] = None
            cache["t"] = now
        return cache["v"]

    return _getter


def ensure_cloud_override_getter(cooldown_s: float = _DEFAULT_COOLDOWN_S) -> bool:
    from yashigani.gateway import openai_router as _oai

    def _is_healthy() -> bool:
        engine = _oai._state.optimization_engine
        if engine is None:
            return True  # no engine to wire this into — not this subsystem's problem
        return getattr(engine, "_cloud_override_getter", None) is not None

    def _on_success(getter) -> None:
        engine = _oai._state.optimization_engine
        if engine is not None:
            engine._cloud_override_getter = getter

    return _common.ensure(
        "gateway_cloud_override_getter",
        is_healthy=_is_healthy,
        build=_build_cloud_override_getter,
        on_success=_on_success,
        cooldown_s=cooldown_s,
        unavailable_msg="Gateway cloud-override getter Redis lazy reconnect failed — engine override remains disabled",
        recovered_msg="Gateway cloud-override getter Redis lazy reconnect SUCCEEDED — dual-admin cloud-LLM override re-enabled",
    )


# ---------------------------------------------------------------------------
# #9 — model_allocation_store (Redis db/3)
# ---------------------------------------------------------------------------

def _build_model_allocation_store():
    import redis as _redis
    from yashigani.models.allocation_store import ModelAllocationStore

    redis_client = _redis.from_url(_gw_redis_url(3), decode_responses=False)
    redis_client.ping()
    durable = None
    try:
        from yashigani.models.allocation_durable_store import (
            AllocationDurableStore, _direct_dsn,
        )
        if _direct_dsn() and "${POSTGRES_PASSWORD}" not in _direct_dsn():
            durable = AllocationDurableStore()
    except Exception as exc:
        logger.warning(
            "Gateway allocation durable store unavailable during self-heal (%s)", exc
        )
    store = ModelAllocationStore(redis_client=redis_client, durable_store=durable)
    if durable is not None:
        try:
            from yashigani.models.allocation_durable_store import (
                reconcile_allocations_from_durable,
            )
            reconcile_allocations_from_durable(store, durable)
        except Exception as exc:
            logger.error(
                "Gateway ALLOC-RECONCILE after self-heal failed (%s) — allocations "
                "may be absent until the next admin mutation", exc,
            )
    return store


def ensure_model_allocation_store(cooldown_s: float = _DEFAULT_COOLDOWN_S) -> bool:
    from yashigani.gateway import openai_router as _oai

    def _on_success(store) -> None:
        _oai._state.model_allocation_store = store

    return _common.ensure(
        "gateway_model_allocation_store",
        is_healthy=lambda: _oai._state.model_allocation_store is not None,
        build=_build_model_allocation_store,
        on_success=_on_success,
        cooldown_s=cooldown_s,
        unavailable_msg=(
            "Gateway model allocation store Redis lazy reconnect failed — callers "
            "remain restricted to their own allowed_models"
        ),
        recovered_msg="Gateway model allocation store Redis lazy reconnect SUCCEEDED",
    )


# ---------------------------------------------------------------------------
# #10 — model_alias_store (Redis db/1)
# ---------------------------------------------------------------------------

def _build_model_alias_store():
    import redis as _redis
    from yashigani.models.alias_store import ModelAliasStore
    from yashigani.gateway import openai_router as _oai

    redis_client = _redis.from_url(_gw_redis_url(1), decode_responses=False)
    redis_client.ping()
    store = ModelAliasStore(redis_client=redis_client)

    # Best-effort refresh of the OptimizationEngine's alias map — mirrors the
    # boot-time wiring; non-fatal if the engine or aliases are absent.
    try:
        engine = _oai._state.optimization_engine
        aliases = store.list_all()
        if engine is not None and aliases:
            engine.update_aliases({
                name: (cfg.provider, cfg.model, cfg.force_local)
                for name, cfg in aliases.items()
            })
    except Exception as exc:
        logger.warning("Gateway OE alias map refresh after self-heal failed (%s)", exc)

    return store


def ensure_model_alias_store(cooldown_s: float = _DEFAULT_COOLDOWN_S) -> bool:
    from yashigani.gateway import openai_router as _oai

    def _on_success(store) -> None:
        _oai._state.model_alias_store = store

    return _common.ensure(
        "gateway_model_alias_store",
        is_healthy=lambda: _oai._state.model_alias_store is not None,
        build=_build_model_alias_store,
        on_success=_on_success,
        cooldown_s=cooldown_s,
        unavailable_msg=(
            "Gateway model alias store Redis lazy reconnect failed — allocated "
            "aliases will only be matched by name, not expanded to concrete models"
        ),
        recovered_msg="Gateway model alias store Redis lazy reconnect SUCCEEDED",
    )


# ---------------------------------------------------------------------------
# #11 — workflow_scheduler (Redis db/6)
#
# NOTE: build_workflow_scheduler() only constructs the scheduler; `.start()`
# calls asyncio.ensure_future() and MUST run on the event loop, never inside
# the asyncio.to_thread() worker thread this builder executes in. The
# orchestrator (maybe_selfheal, below) calls `.start()` itself, on the loop,
# after this ensure_*() returns — WorkflowScheduler.start() is idempotent
# (no-ops with a log line if already running), so this is safe even if
# called more than once.
# ---------------------------------------------------------------------------

def _build_workflow_scheduler():
    import redis as _redis
    from yashigani.gateway.workflow_scheduler import build_workflow_scheduler
    from yashigani.gateway import openai_router as _oai

    redis_client = _redis.from_url(_gw_redis_url(6), decode_responses=False)
    redis_client.ping()
    return build_workflow_scheduler(
        redis_client,
        audit_writer=_oai._state.audit_writer,
        identity_registry=_oai._state.identity_registry,
        agent_registry=_oai._state.agent_registry,
    )


def ensure_workflow_scheduler(app_state: dict, cooldown_s: float = _DEFAULT_COOLDOWN_S) -> bool:
    return _common.ensure(
        "gateway_workflow_scheduler",
        is_healthy=lambda: app_state.get("workflow_scheduler") is not None,
        build=_build_workflow_scheduler,
        on_success=_setter(app_state, "workflow_scheduler"),
        cooldown_s=cooldown_s,
        unavailable_msg="Gateway workflow scheduler Redis lazy reconnect failed — scheduled workflows remain disabled",
        recovered_msg="Gateway workflow scheduler Redis lazy reconnect SUCCEEDED — scheduled workflows re-enabled (not yet started)",
    )


# ---------------------------------------------------------------------------
# #12 — ddos_protector (Redis db/5)
# ---------------------------------------------------------------------------

def _build_ddos_protector():
    import redis as _redis
    from yashigani.gateway.ddos import (
        DDoSProtector,
        ENV_PER_IP_LIMIT,
        ENV_WINDOW_SECONDS,
        ENV_EXEMPT_PATHS,
        _EXEMPT_PATHS,
        _ddos_default_per_ip_limit,
    )

    env_limit = os.getenv(ENV_PER_IP_LIMIT)
    if env_limit is not None:
        per_ip = int(env_limit)
    else:
        try:
            from yashigani.licensing.enforcer import get_license as _get_license
            max_end_users = _get_license().max_end_users
        except Exception:
            max_end_users = 5  # community fallback, matches boot-time default
        per_ip = _ddos_default_per_ip_limit(max_end_users)
    window = int(os.getenv(ENV_WINDOW_SECONDS, "60"))
    extra_exempt_raw = os.getenv(ENV_EXEMPT_PATHS, "")
    extra_exempt = frozenset(p.strip() for p in extra_exempt_raw.split(",") if p.strip())

    redis_client = _redis.from_url(_gw_redis_url(5), decode_responses=False)
    redis_client.ping()
    protector = DDoSProtector(
        redis_client=redis_client,
        max_connections_per_ip=per_ip,
        window_seconds=window,
    )
    if extra_exempt:
        import yashigani.gateway.ddos as _ddos_mod
        _ddos_mod._EXEMPT_PATHS = _EXEMPT_PATHS | extra_exempt
    return protector


def ensure_ddos_protector(app_state: dict, cooldown_s: float = _DEFAULT_COOLDOWN_S) -> bool:
    from yashigani.gateway import openai_router as _oai

    def _on_success(protector) -> None:
        _oai._state.ddos_protector = protector
        app_state["ddos_protector"] = protector

    return _common.ensure(
        "gateway_ddos_protector",
        is_healthy=lambda: _oai._state.ddos_protector is not None,
        build=_build_ddos_protector,
        on_success=_on_success,
        cooldown_s=cooldown_s,
        unavailable_msg="Gateway DDoSProtector Redis lazy reconnect failed — per-IP DDoS throttle remains disabled",
        recovered_msg="Gateway DDoSProtector Redis lazy reconnect SUCCEEDED — per-IP DDoS throttle back online",
    )


# ---------------------------------------------------------------------------
# #13 — egress_limit_enforcer (Redis db/2)
# ---------------------------------------------------------------------------

def _build_egress_limit_enforcer():
    import redis as _redis
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    redis_client = _redis.from_url(_gw_redis_url(2), decode_responses=False)
    redis_client.ping()
    return EgressLimitEnforcer(redis_client=redis_client)


def ensure_egress_limit_enforcer(cooldown_s: float = _DEFAULT_COOLDOWN_S) -> bool:
    from yashigani.gateway import egress_proxy as _egress

    def _on_success(enforcer) -> None:
        _egress._state.egress_limit_enforcer = enforcer

    return _common.ensure(
        "gateway_egress_limit_enforcer",
        is_healthy=lambda: _egress._state.egress_limit_enforcer is not None,
        build=_build_egress_limit_enforcer,
        on_success=_on_success,
        cooldown_s=cooldown_s,
        unavailable_msg="Gateway egress limit enforcer Redis lazy reconnect failed — /egress/eval rate cap remains disabled",
        recovered_msg="Gateway egress limit enforcer Redis lazy reconnect SUCCEEDED — /egress/eval rate cap back online",
    )


# ---------------------------------------------------------------------------
# ASGI entrypoint — dispatches only the currently-unhealthy subsystems
# ---------------------------------------------------------------------------

async def maybe_selfheal(app_state: dict) -> None:
    """Cheap async entrypoint for the gateway's self-heal middleware
    (``gateway/proxy.py``).

    Every subsystem's health check is a pure in-process None-check (zero
    Redis round-trips) — this coroutine only dispatches a blocking reconnect
    attempt (via ``asyncio.to_thread``) for subsystems that are CURRENTLY
    unhealthy, so the event loop is never blocked by a Redis connect() in the
    steady-state (already-healthy) case, and a burst of concurrent requests
    during an outage cannot turn into a reconnect storm (each ensure_*() is
    independently cooldown-gated).
    """
    import asyncio

    from yashigani.gateway import openai_router as _oai
    from yashigani.gateway import egress_proxy as _egress

    pending: list[tuple[str, "asyncio.Task"]] = []

    def _dispatch(tag: str, fn: Callable[..., bool], *args: Any) -> None:
        pending.append((tag, asyncio.ensure_future(asyncio.to_thread(fn, *args))))

    if _oai._state.agent_registry is None:
        _dispatch("rbac_agent_stack", ensure_rbac_agent_stack, app_state)
    if app_state.get("rate_limiter") is None:
        _dispatch("rate_limiter", ensure_rate_limiter, app_state)
    if app_state.get("endpoint_rate_limiter") is None:
        _dispatch("endpoint_rate_limiter", ensure_endpoint_rate_limiter, app_state)
    if app_state.get("response_cache") is None:
        _dispatch("response_cache", ensure_response_cache, app_state)
    if app_state.get("jwt_inspector") is None:
        _dispatch("jwt_inspector", ensure_jwt_inspector, app_state)
    if _oai._state.identity_registry is None:
        _dispatch("identity_registry", ensure_identity_registry, app_state)
    if _oai._state.budget_enforcer is None:
        _dispatch("budget_enforcer", ensure_budget_enforcer)
    _oe = _oai._state.optimization_engine
    if _oe is not None and getattr(_oe, "_cloud_override_getter", None) is None:
        _dispatch("cloud_override_getter", ensure_cloud_override_getter)
    if _oai._state.model_allocation_store is None:
        _dispatch("model_allocation_store", ensure_model_allocation_store)
    if _oai._state.model_alias_store is None:
        _dispatch("model_alias_store", ensure_model_alias_store)
    if app_state.get("workflow_scheduler") is None:
        _dispatch("workflow_scheduler", ensure_workflow_scheduler, app_state)
    if _oai._state.ddos_protector is None:
        _dispatch("ddos_protector", ensure_ddos_protector, app_state)
    if _egress._state.egress_limit_enforcer is None:
        _dispatch("egress_limit_enforcer", ensure_egress_limit_enforcer)

    if not pending:
        return

    for tag, task in pending:
        try:
            ok = await task
        except Exception:
            logger.exception("Gateway self-heal task %s raised unexpectedly", tag)
            continue
        if tag == "workflow_scheduler" and ok:
            sched = app_state.get("workflow_scheduler")
            if sched is not None:
                try:
                    sched.start()
                except Exception as exc:
                    logger.warning("WorkflowScheduler self-heal start() failed: %s", exc)
        elif tag == "rbac_agent_stack" and ok:
            # YSG-RISK-141 — ensure_rbac_agent_stack() (above) rebuilds a
            # BRAND NEW AgentRegistry wrapping whatever is CURRENTLY in Redis
            # db/3. If Redis db/3 lost its data mid-life (the connection
            # itself recovered — e.g. a `redis-cli FLUSHDB` / volume-less
            # recreate that completed fast enough that agent_registry never
            # actually went `None` between requests, or simply the window
            # between the connection dropping and this self-heal firing) the
            # rebuilt registry is EMPTY even though the durable Postgres
            # mirror (agent_registry table) still holds every registration.
            # proxy.py's lifespan reconcile (ISSUE-AGENT-REG-DURABILITY) only
            # runs ONCE, before uvicorn starts accepting connections — it
            # never re-fires after this lazy self-heal path reconnects, so a
            # mid-life Redis wipe would leave every @agent permanently
            # `agent_not_found` until the gateway container itself restarts.
            # Must run HERE, back on the event loop (not inside the
            # to_thread worker above) — reconcile_agents_from_durable() reads
            # the asyncpg pool, which is bound to the loop it was created on.
            _agent_reg = _oai._state.agent_registry
            if _agent_reg is not None:
                try:
                    from yashigani.agents.durable_store import AgentDurableStore
                    from yashigani.agents.reconciler import reconcile_agents_from_durable

                    await reconcile_agents_from_durable(_agent_reg, AgentDurableStore())
                except Exception as exc:
                    logger.error(
                        "Gateway self-heal: agent reconcile from durable store "
                        "FAILED (%s) — @agent routes may return agent_not_found "
                        "until the registry is restored", exc,
                    )
