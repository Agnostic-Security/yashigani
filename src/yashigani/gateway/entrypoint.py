"""
Yashigani Gateway — ASGI entrypoint.
Wires all services together and creates the FastAPI app.
Environment variables configure service endpoints and behaviour.

Last updated: 2026-05-08T00:00:00+00:00
"""
from __future__ import annotations

import asyncio
import logging
import os

from yashigani.audit.config import AuditConfig
from yashigani.audit.scope import MaskingScopeConfig
from yashigani.audit.writer import AuditLogWriter
from yashigani.chs.handle import CredentialHandleService
from yashigani.chs.resource_monitor import ResourceMonitor
from yashigani.inspection.classifier import PromptInjectionClassifier
from yashigani.inspection.pipeline import InspectionPipeline, ResponseInspectionPipeline
from yashigani.kms.factory import create_provider
from yashigani.ratelimit.config import RateLimitConfig
from yashigani.ratelimit.limiter import RateLimiter
from yashigani.rbac.store import RBACStore
from yashigani.agents.registry import AgentRegistry
from yashigani.metrics.collectors import MetricsCollector
from yashigani.metrics.middleware import PrometheusMiddleware
from yashigani.gateway.proxy import GatewayConfig, create_gateway_app
from yashigani.gateway.agent_auth import AgentAuthMiddleware
from yashigani.gateway.openai_router import router as openai_router, configure as configure_openai_router
from yashigani.gateway.spiffe_middleware import SpiffePeerCertMiddleware
from yashigani.gateway._ratelimit_env import resolve_rate_limit_fail_mode
from yashigani.auth.caddy_verified import CaddyVerifiedMiddleware
from yashigani.licensing.grace_period import LicenseEnforcementMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def _build_app():
    # ── OTEL tracing — initialise before anything else ─────────────────────
    try:
        from yashigani.tracing import setup_tracer
        setup_tracer("yashigani-gateway")
    except Exception as exc:
        logger.warning("OTEL setup skipped: %s", exc)

    # KSM provider
    kms_provider = create_provider()

    # Audit
    audit_config = AuditConfig.from_env()
    audit_writer = AuditLogWriter(
        config=audit_config,
        masking_scope=MaskingScopeConfig(),
    )

    # Resource monitor (cgroup v2 for dynamic TTL)
    resource_monitor = ResourceMonitor()

    # CHS
    chs = CredentialHandleService(
        kms_provider=kms_provider,
        resource_monitor=resource_monitor,
        on_audit=audit_writer,
    )

    # Inspection pipeline
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
    model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
    if "OLLAMA_MODEL" not in os.environ:
        logger.warning("OLLAMA_MODEL not set — using default '%s'", model)
    classifier = PromptInjectionClassifier(model=model, ollama_base_url=ollama_url)

    pipeline = InspectionPipeline(
        classifier=classifier,
        sanitize_threshold=float(os.getenv("YASHIGANI_INJECT_THRESHOLD", "0.85")),
    )

    # Response inspection pipeline — v0.9.0 F-01
    response_pipeline = None
    if os.getenv("YASHIGANI_INSPECT_RESPONSES", "false").lower() == "true":
        response_pipeline = ResponseInspectionPipeline(classifier=classifier)
        logger.info("Response inspection pipeline enabled")

    # sklearn first-pass classifier — v2.23.3 (replaces fasttext-wheel)
    fasttext_backend = None  # legacy name retained; wired into SensitivityClassifier below
    try:
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend
        fasttext_backend = SklearnBackend()
        logger.info("sklearn sensitivity backend loaded: %s", fasttext_backend.model_path)
    except Exception as exc:
        logger.warning("sklearn backend unavailable (%s) — LLM-only inspection", exc)

    # Gateway config
    upstream_url = os.environ["YASHIGANI_UPSTREAM_URL"]
    opa_url = os.getenv("YASHIGANI_OPA_URL", "https://policy:8181")

    cfg = GatewayConfig(
        upstream_base_url=upstream_url,
        opa_url=opa_url,
    )

    # Redis URL helper — all DB-specific URLs are built by build_redis_url().
    # v2.23.1: TLS-only (rediss://) with client cert authentication. Redis
    # rejects plaintext connections (port 0 in redis.conf).
    # See gateway/_redis_url.py for cert-path and DB-ordering rationale.
    from yashigani.gateway._redis_url import build_redis_url
    secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
    redis_use_tls = os.getenv("REDIS_USE_TLS", "true").lower() == "true"

    def _gw_redis_url(db: int, host: str | None = None, port: str | None = None) -> str:
        return build_redis_url(
            db,
            host=host,
            port=port,
            use_tls=redis_use_tls,
            secrets_dir=secrets_dir,
            client_cert_name="gateway_client",
        )

    # Rate limiter — Redis DB 2
    _rl_fail_mode = resolve_rate_limit_fail_mode()
    logger.info("Rate limiter fail mode: %s", _rl_fail_mode)
    rate_limiter = None
    try:
        import redis as _redis
        redis_client_rl = _redis.from_url(_gw_redis_url(2), decode_responses=False)
        redis_client_rl.ping()
        rate_limiter = RateLimiter(
            redis_client=redis_client_rl,
            config=RateLimitConfig(fail_mode=_rl_fail_mode),
            resource_monitor=resource_monitor,
        )
    except Exception as exc:
        logger.warning("Rate limiter Redis unavailable (%s) — rate limiting disabled", exc)

    # Endpoint rate limiter — Redis DB 2 (same DB, different key namespace) — Phase 5
    endpoint_rate_limiter = None
    try:
        import redis as _redis
        from yashigani.gateway.endpoint_ratelimit import EndpointRateLimiter
        redis_client_ep = _redis.from_url(_gw_redis_url(2), decode_responses=False)
        redis_client_ep.ping()
        endpoint_rate_limiter = EndpointRateLimiter(redis_client=redis_client_ep)
        logger.info("Endpoint rate limiter ready")
    except Exception as exc:
        logger.warning("Endpoint rate limiter unavailable (%s) — disabled", exc)

    # Response cache — Redis DB 4 — Phase 6
    response_cache = None
    try:
        import redis as _redis
        from yashigani.gateway.response_cache import ResponseCache
        redis_client_cache = _redis.from_url(_gw_redis_url(4), decode_responses=False)
        redis_client_cache.ping()
        response_cache = ResponseCache(redis_client=redis_client_cache)
        logger.info("Response cache ready (Redis DB 4)")
    except Exception as exc:
        logger.warning("Response cache unavailable (%s) — caching disabled", exc)

    # RBAC store and Agent registry — Redis DB 3 (shared instance, separate key namespaces)
    rbac_store = None
    agent_registry = None
    redis_client_rbac = None
    try:
        import redis as _redis
        redis_client_rbac = _redis.from_url(_gw_redis_url(3), decode_responses=False)
        redis_client_rbac.ping()
        rbac_store = RBACStore(redis_client=redis_client_rbac)
        logger.info("Gateway RBAC store ready: %d group(s)", len(rbac_store.list_groups()))
        agent_registry = AgentRegistry(redis_client=redis_client_rbac)
        logger.info(
            "Gateway agent registry ready: %d agent(s)",
            agent_registry.count("all"),
        )
    except Exception as exc:
        logger.warning(
            "RBAC/Agent Redis unavailable (%s) — RBAC and agent routing disabled", exc
        )

    # JWT inspector — Phase 7
    jwt_inspector = None
    try:
        import redis as _redis
        from yashigani.gateway.jwt_inspector import JWTInspector
        redis_client_jwt = _redis.from_url(_gw_redis_url(1), decode_responses=False)
        redis_client_jwt.ping()
        jwt_inspector = JWTInspector(redis_client=redis_client_jwt)
        logger.info(
            "JWT inspector ready (stream=%s)",
            os.getenv("YASHIGANI_DEPLOYMENT_STREAM", "opensource"),
        )
    except Exception as exc:
        logger.warning("JWT inspector unavailable (%s) — JWT validation disabled", exc)

    # PostgreSQL pool + inference logger + anomaly detector — Phases 1, 2
    # M-02 (SOP 1 fail-closed): if YASHIGANI_DB_DSN is configured and DB init
    # fails, re-raise so the container exits non-zero.  A warn-and-continue here
    # produces a healthy-looking zombie: container reports healthy but every
    # request that touches inference/audit/anomaly fails with AttributeError.
    # Not having a DSN set is legitimate (community / dev deploy without DB) and
    # does not raise — only a configured-but-broken DB is fatal.
    db_pool = None
    inference_logger = None
    anomaly_detector = None
    content_relay_detector = None
    _db_dsn_configured = False
    try:
        from yashigani.db import create_pool, run_migrations
        from yashigani.inference import InferencePayloadLogger, AnomalyDetector

        db_dsn = os.getenv("YASHIGANI_DB_DSN", "")
        if db_dsn and "${POSTGRES_PASSWORD}" in db_dsn:
            pg_pwd_file = os.path.join(secrets_dir, "postgres_password")
            try:
                with open(pg_pwd_file) as f:
                    pg_password = f.read().strip()
                db_dsn = db_dsn.replace("${POSTGRES_PASSWORD}", pg_password)
                os.environ["YASHIGANI_DB_DSN"] = db_dsn
            except OSError:
                logger.warning("postgres_password secret not found — DB DSN unresolved")
        if db_dsn and "${POSTGRES_PASSWORD}" not in db_dsn:
            _db_dsn_configured = True
            run_migrations()
            # Pool creation deferred to _db_startup() — called from lifespan
            os.environ["_YASHIGANI_DB_READY"] = "1"
            db_pool = True

            inference_logger = InferencePayloadLogger()

            import redis as _redis
            redis_client_anomaly = _redis.from_url(_gw_redis_url(2), decode_responses=False)
            redis_client_anomaly.ping()
            anomaly_detector = AnomalyDetector(redis_client=redis_client_anomaly)
            from yashigani.inference.content_relay import ContentRelayDetector
            content_relay_detector = ContentRelayDetector(redis_client=redis_client_anomaly)
            logger.info("DB pool + inference logger + anomaly detector + content relay detector ready")
        else:
            logger.warning("YASHIGANI_DB_DSN not set — Postgres features disabled")
    except Exception as exc:
        if _db_dsn_configured:
            # DB DSN was set but init failed — this is a fatal misconfiguration,
            # not a graceful degradation.  Re-raise so the process exits non-zero
            # and the orchestrator surfaces the real fault (M-02 / SOP 1).
            logger.exception(
                "Gateway DB/inference init FAILED with YASHIGANI_DB_DSN configured "
                "— refusing to start in degraded mode (M-02). "
                "Fix the DB connection before restarting."
            )
            raise
        # No DSN configured: DB features simply unavailable, not a fatal error.
        logger.warning("DB/inference init failed (%s) — Postgres features disabled", exc)

    # ── v1.0: Unified Identity Registry (Redis DB 3, same as agents) ────────
    identity_registry = None
    try:
        from yashigani.identity import IdentityRegistry
        if redis_client_rbac:
            identity_registry = IdentityRegistry(redis_client=redis_client_rbac)
    except Exception as exc:
        logger.warning("Identity registry unavailable (%s)", exc)

    # ── v1.0: Sensitivity Classifier (three-layer pipeline) ───────────────
    sensitivity_classifier = None
    try:
        from yashigani.optimization.sensitivity_classifier import SensitivityClassifier
        sensitivity_classifier = SensitivityClassifier(
            enable_sklearn=fasttext_backend is not None,
            enable_ollama=True,
            sklearn_backend=fasttext_backend,
            ollama_url=ollama_url,
            ollama_model=model,
        )
    except Exception as exc:
        logger.warning("Sensitivity classifier unavailable (%s)", exc)

    # ── v1.0: Complexity Scorer ───────────────────────────────────────────
    complexity_scorer = None
    try:
        from yashigani.optimization.complexity_scorer import ComplexityScorer
        threshold = int(os.getenv("YASHIGANI_COMPLEXITY_THRESHOLD", "2000"))
        complexity_scorer = ComplexityScorer(token_threshold=threshold)
    except Exception as exc:
        logger.warning("Complexity scorer unavailable (%s)", exc)

    # ── v1.0: Budget Enforcer (budget-redis, also TLS-only in v2.23.1) ────
    budget_enforcer = None
    try:
        import redis as _redis
        budget_redis_host = os.getenv("BUDGET_REDIS_HOST", "budget-redis")
        budget_redis_port = os.getenv("BUDGET_REDIS_PORT", "6380")
        budget_url = _gw_redis_url(0, host=budget_redis_host, port=budget_redis_port)
        budget_redis_client = _redis.from_url(
            budget_url,
            decode_responses=False,
        )
        budget_redis_client.ping()
        from yashigani.billing.budget_enforcer import BudgetEnforcer
        budget_enforcer = BudgetEnforcer(redis_client=budget_redis_client)
    except Exception as exc:
        logger.warning("Budget enforcer unavailable (%s) — budget enforcement disabled", exc)

    # ── v1.0: Token Counter ───────────────────────────────────────────────
    token_counter = None
    try:
        from yashigani.billing.token_counter import TokenCounter
        token_counter = TokenCounter()
    except Exception as exc:
        logger.warning("Token counter unavailable (%s)", exc)

    # ── v1.0: Optimization Engine ─────────────────────────────────────────
    optimization_engine = None
    try:
        from yashigani.optimization.engine import OptimizationEngine
        optimization_engine = OptimizationEngine(
            default_model=model,
            default_cloud_provider=os.getenv("YASHIGANI_DEFAULT_CLOUD_PROVIDER", "anthropic"),
            default_cloud_model=os.getenv("YASHIGANI_DEFAULT_CLOUD_MODEL", "claude-sonnet-4-6"),
        )
    except Exception as exc:
        logger.warning("Optimization Engine unavailable (%s)", exc)

    # ── v2.2: PII Detector ────────────────────────────────────────────────
    # PII filtering is ON by default for ALL traffic (local and cloud).
    # Mode is configurable via YASHIGANI_PII_MODE (default: log).
    # Cloud bypass is OFF by default — admin must explicitly enable it.
    pii_detector = None
    pii_cloud_bypass = False
    try:
        from yashigani.pii.detector import PiiDetector, PiiMode
        _pii_mode_str = os.getenv("YASHIGANI_PII_MODE", "log").lower()
        try:
            _pii_mode = PiiMode(_pii_mode_str)
        except ValueError:
            logger.warning(
                "Invalid YASHIGANI_PII_MODE='%s' — defaulting to 'log'", _pii_mode_str
            )
            _pii_mode = PiiMode.LOG
        pii_detector = PiiDetector(mode=_pii_mode)
        pii_cloud_bypass = (
            os.getenv("YASHIGANI_PII_CLOUD_BYPASS", "false").lower() == "true"
        )
        logger.info(
            "PII detector ready (mode=%s, cloud_bypass=%s)",
            _pii_mode.value,
            pii_cloud_bypass,
        )
    except Exception as exc:
        logger.warning("PII detector unavailable (%s) — PII filtering disabled", exc)

    # Configure and prepare the /v1 router BEFORE creating the gateway app
    # (it must be registered before the catch-all proxy route)
    configure_openai_router(
        identity_registry=identity_registry,
        sensitivity_classifier=sensitivity_classifier,
        complexity_scorer=complexity_scorer,
        budget_enforcer=budget_enforcer,
        token_counter=token_counter,
        optimization_engine=optimization_engine,
        audit_writer=audit_writer,
        ollama_url=ollama_url,
        default_model=model,
        agent_registry=agent_registry,
        response_inspection_pipeline=response_pipeline,
        pii_detector=pii_detector,
        pii_cloud_bypass=pii_cloud_bypass,
        opa_url=opa_url,
        content_relay_detector=content_relay_detector,
    )

    gateway_app = create_gateway_app(
        config=cfg,
        inspection_pipeline=pipeline,
        chs=chs,
        audit_writer=audit_writer,
        rate_limiter=rate_limiter,
        rbac_store=rbac_store,
        agent_registry=agent_registry,
        jwt_inspector=jwt_inspector,
        endpoint_rate_limiter=endpoint_rate_limiter,
        response_cache=response_cache,
        fasttext_backend=fasttext_backend,
        inference_logger=inference_logger,
        anomaly_detector=anomaly_detector,
        response_inspection_pipeline=response_pipeline,
        extra_routers=[openai_router],
        pii_detector=pii_detector,
    )
    logger.info("OpenAI-compatible /v1 router mounted (before catch-all)")

    # Layer B: Caddy-verified shared-secret middleware (EX-231-10 Layer B).
    # Checks X-Caddy-Verified-Secret on every non-healthcheck request. Must run
    # second from outermost — added BEFORE SpiffePeerCertMiddleware so that in
    # Starlette LIFO order, Spiffe runs outermost and CaddyVerified runs second.
    # load_caddy_secret() is called in the gateway _lifespan (proxy.py), not here,
    # so the module-level secret is populated before any request dispatch.
    gateway_app.add_middleware(CaddyVerifiedMiddleware)

    # SPIFFE peer-cert middleware — LF-SPIFFE-FORGE fix (V10.3.5).
    # Extracts the TLS peer cert URI SAN from the ASGI handshake scope and
    # injects it as X-SPIFFE-ID-Peer-Cert.  This is a server-controlled header
    # that cannot be forged by the client, closing the direct-to-gateway bypass.
    # Must run outermost (added last = executed first in starlette middleware stack).
    gateway_app.add_middleware(SpiffePeerCertMiddleware)

    # Licence enforcement middleware — converts GatewayBlockedError → 503 and
    # GatewayReadOnlyError → 403.  Runs AFTER Spiffe+Caddy verification (inbound
    # request is from a legitimate peer) and BEFORE AgentAuth (blocked requests
    # do not reach auth).  Added AFTER CaddyVerifiedMiddleware in code so that
    # in Starlette LIFO execution order it runs third (after Spiffe and Caddy).
    gateway_app.add_middleware(LicenseEnforcementMiddleware)

    # Agent auth middleware — must run before Prometheus middleware so agent
    # requests are authenticated before metrics are emitted.
    gateway_app.add_middleware(
        AgentAuthMiddleware,
        agent_registry=agent_registry,
        audit_writer=audit_writer,
    )

    # Add Prometheus request metrics middleware
    gateway_app.add_middleware(PrometheusMiddleware, service="gateway")

    # Start background metrics collector
    collector = MetricsCollector(
        resource_monitor=resource_monitor,
        rate_limiter=rate_limiter,
        chs=chs,
        inspection_pipeline=pipeline,
        rbac_store=rbac_store,
        agent_registry=agent_registry,
        poll_interval_seconds=15,
    )
    collector.start()

    # ── v2.1: Pool Manager health monitor (background daemon) ─────────────
    try:
        from yashigani.pool.manager import PoolManager
        from yashigani.pool.health import PoolHealthMonitor
        from yashigani.pool.backend import create_backend

        container_backend = create_backend()

        # LIC-002 / GROUP-5-1: read tier from the verified LicenseState rather
        # than the YASHIGANI_LICENSE_TIER env var. An attacker who can set env
        # vars could elevate the pool manager to Enterprise tier without a valid
        # license. The env var is now removed; tier comes exclusively from the
        # cryptographically-verified license loaded at startup.
        try:
            from yashigani.licensing.enforcer import get_license as _get_license
            _verified_tier = _get_license().tier.value
        except Exception:
            _verified_tier = "community"

        pool_manager = PoolManager(
            backend=container_backend,
            tier=_verified_tier,
        )
        pool_health = PoolHealthMonitor(pool_manager)
        pool_health.start()
        logger.info("Pool Manager health monitor started (daemon thread)")
    except Exception as exc:
        logger.warning("Pool Manager unavailable (%s) — container isolation disabled", exc)

    return gateway_app


app = _build_app()
