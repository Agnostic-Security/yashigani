"""
Yashigani Gateway — Internal mesh ASGI entrypoint (plain HTTP, port 8081).

This entrypoint builds the same FastAPI application as entrypoint.py but
WITHOUT the mTLS-specific middleware layers:
  - SpiffePeerCertMiddleware (reads TLS peer cert from ASGI scope — N/A on plain HTTP)
  - CaddyVerifiedMiddleware  (enforces X-Caddy-Verified-Secret — N/A for direct mesh calls)

Security model:
  Port 8080 (mTLS) — reached via Caddy only; protected by:
    (1) Docker network isolation: caddy_internal only
    (2) mTLS: client cert required (ssl.CERT_REQUIRED)
    (3) CaddyVerifiedMiddleware: X-Caddy-Verified-Secret header check
    (4) SpiffePeerCertMiddleware: SPIFFE peer cert URI forwarding

  Port 8081 (plain HTTP) — reached by Open WebUI only; protected by:
    (1) Docker network isolation: data network only (never host-mapped)
    (2) AgentAuthMiddleware: Open WebUI presents its OPENAI_API_KEY
    (3) LicenseEnforcementMiddleware: licence state enforced

Open WebUI is in-cluster (same Docker bridge / K8s namespace) and does not
require cryptographic auth at the transport layer — network isolation on the
`data` bridge is sufficient, consistent with how gateway→redis, gateway→OPA,
gateway→ollama connections are protected.

Last updated: 2026-05-17T00:00:00+00:00
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
from yashigani.gateway._ratelimit_env import resolve_rate_limit_fail_mode
from yashigani.licensing.grace_period import LicenseEnforcementMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _build_mesh_app():
    """Build the gateway FastAPI app for the internal mesh port (no mTLS middleware)."""
    # ── OTEL tracing ────────────────────────────────────────────────────────
    try:
        from yashigani.tracing import setup_tracer
        setup_tracer("yashigani-gateway-mesh")
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

    # Resource monitor
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

    # Response inspection pipeline
    response_pipeline = None
    if os.getenv("YASHIGANI_INSPECT_RESPONSES", "false").lower() == "true":
        response_pipeline = ResponseInspectionPipeline(classifier=classifier)
        logger.info("Response inspection pipeline enabled")

    # sklearn sensitivity classifier
    fasttext_backend = None
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

    # Redis
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

    # RBACStore
    rbac_store = RBACStore(redis_url=_gw_redis_url(0))

    # AgentRegistry
    agent_registry = AgentRegistry(redis_url=_gw_redis_url(1))

    # RateLimiter
    rate_limit_config = RateLimitConfig.from_env()
    fail_mode = resolve_rate_limit_fail_mode()
    rate_limiter = RateLimiter(
        config=rate_limit_config,
        redis_url=_gw_redis_url(2),
        fail_mode=fail_mode,
    )

    # Endpoint rate limiter
    from yashigani.ratelimit.endpoint_limiter import EndpointRateLimiter
    from yashigani.ratelimit.endpoint_config import EndpointRateLimitConfig
    endpoint_rl_config = EndpointRateLimitConfig.from_env()
    endpoint_rate_limiter = EndpointRateLimiter(
        config=endpoint_rl_config,
        redis_url=_gw_redis_url(2),
    )

    # JWT inspector
    from yashigani.auth.jwt_inspector import JWTInspector
    jwt_inspector = JWTInspector()

    # Response cache
    from yashigani.gateway.response_cache import ResponseCache
    response_cache = ResponseCache(redis_url=_gw_redis_url(3))

    # Identity registry
    from yashigani.agents.identity_registry import IdentityRegistry
    identity_registry = IdentityRegistry(redis_url=_gw_redis_url(4))

    # Sensitivity classifier
    from yashigani.inspection.sensitivity import SensitivityClassifier
    sensitivity_classifier = SensitivityClassifier(fasttext_backend=fasttext_backend)

    # Complexity scorer
    from yashigani.gateway.complexity import ComplexityScorer
    complexity_scorer = ComplexityScorer()

    # Budget enforcer
    budget_redis_host = os.getenv("BUDGET_REDIS_HOST", "budget-redis")
    budget_redis_port = os.getenv("BUDGET_REDIS_PORT", "6380")
    from yashigani.budget.enforcer import BudgetEnforcer
    budget_enforcer = BudgetEnforcer(
        redis_url=_gw_redis_url(0, host=budget_redis_host, port=budget_redis_port),
    )

    # Token counter
    from yashigani.budget.token_counter import TokenCounter
    token_counter = TokenCounter()

    # Optimization engine
    from yashigani.gateway.optimization import OptimizationEngine
    optimization_engine = OptimizationEngine()

    # Inference logger
    from yashigani.audit.inference_logger import InferenceLogger
    inference_logger = InferenceLogger(audit_writer=audit_writer)

    # Anomaly detector
    from yashigani.gateway.anomaly import AnomalyDetector
    anomaly_detector = AnomalyDetector()

    # Content relay detector
    try:
        from yashigani.inspection.relay_detector import ContentRelayDetector
        content_relay_detector = ContentRelayDetector()
    except Exception as exc:
        logger.warning("ContentRelayDetector unavailable (%s)", exc)
        content_relay_detector = None

    # PII detector
    pii_detector = None
    pii_cloud_bypass = False
    try:
        from yashigani.inspection.pii import PIIDetector, PIIMode
        _pii_mode_str = os.getenv("YASHIGANI_PII_MODE", "log").lower()
        try:
            _pii_mode = PIIMode(_pii_mode_str)
        except ValueError:
            _pii_mode = PIIMode.LOG
            logger.warning("Unknown PII mode %r — defaulting to log", _pii_mode_str)
        pii_detector = PIIDetector(mode=_pii_mode)
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

    mesh_app = create_gateway_app(
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
    logger.info("Internal mesh app built (no CaddyVerified / no Spiffe middleware)")

    # NOTE: CaddyVerifiedMiddleware and SpiffePeerCertMiddleware are intentionally
    # NOT added here. This app runs on port 8081 (plain HTTP, data-network-only).
    # Security is provided by Docker/K8s network isolation — the port is never
    # host-mapped and is not accessible from caddy_internal or edge networks.

    # LicenseEnforcementMiddleware — still enforced on the mesh port.
    mesh_app.add_middleware(LicenseEnforcementMiddleware)

    # AgentAuthMiddleware — Open WebUI presents OPENAI_API_KEY as Bearer token.
    mesh_app.add_middleware(
        AgentAuthMiddleware,
        agent_registry=agent_registry,
        audit_writer=audit_writer,
    )

    # Prometheus metrics middleware
    mesh_app.add_middleware(PrometheusMiddleware, service="gateway")

    # Background metrics collector (shared state — only start if main process)
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

    # Pool Manager
    try:
        from yashigani.pool.manager import PoolManager
        from yashigani.pool.health import PoolHealthMonitor
        from yashigani.pool.backend import create_backend

        container_backend = create_backend()
        try:
            from yashigani.licensing.enforcer import get_license as _get_license
            _verified_tier = _get_license().tier.value
        except Exception:
            _verified_tier = "community"

        pool_manager = PoolManager(backend=container_backend, tier=_verified_tier)
        pool_health = PoolHealthMonitor(pool_manager)
        pool_health.start()
        logger.info("Pool Manager health monitor started (daemon thread)")
    except Exception as exc:
        logger.warning("Pool Manager unavailable (%s) — container isolation disabled", exc)

    return mesh_app


app = _build_mesh_app()
