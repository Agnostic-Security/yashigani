"""
Yashigani Backoffice — ASGI entrypoint.
Wires all admin-plane services and populates the singleton BackofficeState.

First-run behaviour:
  If no credentials exist, generates 36-char random passwords for:
    - Admin account
    - Grafana admin
    - Prometheus basic auth
    - Redis
  Prints all credentials once to stdout in a clearly delimited block.
  Marks bootstrap complete via sentinel file so this never repeats.

Last updated: 2026-05-07T00:00:00+01:00
"""
from __future__ import annotations

import logging
import os
import time

from yashigani.audit.config import AuditConfig
from yashigani.audit.scope import MaskingScopeConfig
from yashigani.audit.writer import AuditLogWriter
from yashigani.auth.bootstrap import (
    load_or_generate,
    print_credentials,
    write_docker_secrets,
    mark_bootstrapped,
)
from yashigani.auth.local_auth import LocalAuthService
from yashigani.auth.pg_auth import PostgresLocalAuthService
from yashigani.auth.session import SessionStore
from yashigani.chs.handle import CredentialHandleService
from yashigani.chs.resource_monitor import ResourceMonitor
from yashigani.inspection.classifier import PromptInjectionClassifier
from yashigani.inspection.pipeline import InspectionPipeline
from yashigani.kms.factory import create_provider
from yashigani.kms.rotation import KSMRotationScheduler
from yashigani.ratelimit.config import RateLimitConfig
from yashigani.ratelimit.limiter import RateLimiter
from yashigani.rbac.store import RBACStore
from yashigani.agents.registry import AgentRegistry
from yashigani.metrics.collectors import MetricsCollector
from yashigani.backoffice.app import create_backoffice_app
from yashigani.backoffice.state import backoffice_state

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _bootstrap():
    # ── First-run credential generation ────────────────────────────────────
    admin_username = os.getenv("YASHIGANI_ADMIN_USERNAME", "admin@yashigani.local")
    secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")

    creds = load_or_generate(admin_username=admin_username, secrets_dir=secrets_dir)
    if creds is not None:
        # New deployment — print credentials and store them
        # If installer already wrote secrets, use those instead of generated ones
        redis_pwd_file = os.path.join(secrets_dir, "redis_password")
        if os.path.exists(redis_pwd_file):
            creds.redis_password = open(redis_pwd_file).read().strip()
        grafana_pwd_file = os.path.join(secrets_dir, "grafana_admin_password")
        if os.path.exists(grafana_pwd_file):
            creds.grafana_admin_password = open(grafana_pwd_file).read().strip()
        print_credentials(creds)
        write_docker_secrets(creds, secrets_dir=secrets_dir)
        mark_bootstrapped()
        initial_admin_password = creds.admin_password
        _redis_password = creds.redis_password
    else:
        # Credentials already exist — read from secret file
        admin_pwd_file = os.path.join(secrets_dir, "admin_initial_password")
        with open(admin_pwd_file) as f:
            initial_admin_password = f.read().strip()

        redis_pwd_file = os.path.join(secrets_dir, "redis_password")
        _redis_password = (
            open(redis_pwd_file).read().strip()
            if os.path.exists(redis_pwd_file)
            else os.getenv("REDIS_PASSWORD", "")
        )

    # ── KSM ────────────────────────────────────────────────────────────────
    kms_provider = create_provider()

    # ── Audit ───────────────────────────────────────────────────────────────
    audit_config = AuditConfig.from_env()
    audit_writer = AuditLogWriter(
        config=audit_config,
        masking_scope=MaskingScopeConfig(),
    )

    # ── Session store (Redis db/1) ──────────────────────────────────────────
    from yashigani.gateway._redis_url import build_redis_url
    redis_use_tls = os.getenv("REDIS_USE_TLS", "true").lower() == "true"
    _secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")

    def _backoffice_redis_url(db: int) -> str:
        """Build a redis URL for the given DB index using the shared helper.

        Passes _redis_password explicitly so the helper skips file-read
        (password is already loaded above into creds.redis_password).
        """
        return build_redis_url(
            db,
            password=_redis_password,
            use_tls=redis_use_tls,
            secrets_dir=_secrets_dir,
            client_cert_name="backoffice_client",
        )

    redis_url = _backoffice_redis_url(1)
    session_store = SessionStore(redis_url=redis_url)

    # ── Auth service ────────────────────────────────────────────────────────
    # v2.23.1 P0-2 fix: auth_service is now a PostgresLocalAuthService backed
    # by the admin_accounts table. The DB pool is created asynchronously in
    # the FastAPI lifespan (after alembic upgrade head), so the service
    # instance + bootstrap seeding both have to defer until the lifespan
    # runs. We stash the bootstrap inputs on the state object here and let
    # backoffice.app.lifespan finalise once the pool is open.
    backoffice_state._auth_bootstrap = {
        "admin_username": admin_username,
        "initial_admin_password": initial_admin_password,
        "secrets_dir": secrets_dir,
    }
    # Leave auth_service = None for now — lifespan will assign the
    # PostgresLocalAuthService instance after create_pool() completes.
    # The only code that touches auth_service between module import and
    # lifespan start is MetricsCollector (instantiated at bottom of this
    # file) and it tolerates None gracefully via the dashboard degradation
    # logic in routes/dashboard.py.
    auth_service = None

    # ── Resource monitor ───────────────────────────────────────────────────
    resource_monitor = ResourceMonitor()

    # ── CHS ─────────────────────────────────────────────────────────────────
    chs = CredentialHandleService(
        kms_provider=kms_provider,
        resource_monitor=resource_monitor,
        on_audit=audit_writer,
    )

    # ── Rotation scheduler (optional) ──────────────────────────────────────
    rotation_scheduler = None
    secret_key = os.getenv("KSM_ROTATION_SECRET_KEY", "")
    cron_expr = os.getenv("KSM_ROTATION_CRON", "0 3 * * *")
    if secret_key:
        rotation_scheduler = KSMRotationScheduler(
            provider=kms_provider,
            secret_key=secret_key,
            cron_expr=cron_expr,
        )
        rotation_scheduler.start()

    # ── Inspection pipeline ────────────────────────────────────────────────
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
    model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
    classifier = PromptInjectionClassifier(model=model, ollama_base_url=ollama_url)
    inspection_pipeline = InspectionPipeline(
        classifier=classifier,
        sanitize_threshold=float(os.getenv("YASHIGANI_INJECT_THRESHOLD", "0.85")),
    )

    # ── Rate limiter ─────────────────────────────────────────────────────────
    rate_limiter = None
    try:
        import redis as _redis
        redis_rl_url = _backoffice_redis_url(2)
        redis_rl_client = _redis.from_url(redis_rl_url, decode_responses=False)
        rate_limiter = RateLimiter(
            redis_client=redis_rl_client,
            config=RateLimitConfig(),
            resource_monitor=resource_monitor,
        )
    except Exception as exc:
        logger.warning("Rate limiter Redis unavailable (%s) — rate limiting disabled", exc)

    # ── RBAC store + Agent registry (Redis db/3) ─────────────────────────────
    rbac_store = None
    agent_registry = None
    try:
        import redis as _redis
        redis_rbac_url = _backoffice_redis_url(3)
        redis_rbac_client = _redis.from_url(redis_rbac_url, decode_responses=False)
        rbac_store = RBACStore(redis_client=redis_rbac_client)
        logger.info(
            "RBAC store initialised: %d group(s) loaded from Redis",
            len(rbac_store.list_groups()),
        )
        # Agent registry shares the same Redis db/3 instance (different key namespace)
        agent_registry = AgentRegistry(redis_client=redis_rbac_client)
        logger.info(
            "Agent registry initialised: %d agent(s) in index",
            agent_registry.count("all"),
        )
    except Exception as exc:
        logger.warning("RBAC/Agent Redis unavailable (%s) — RBAC and agent registry disabled", exc)

    # ── Backend registry + config store (Redis db/1, separate key namespace) ─
    backend_registry = None
    backend_config_store = None
    try:
        import redis as _redis
        from yashigani.inspection.backends.ollama import OllamaBackend
        from yashigani.inspection.backend_registry import BackendRegistry
        from yashigani.inspection.backend_config import BackendConfigStore

        # BackendConfigStore shares Redis db/1 (session store) — different key namespace
        redis_session_client = _redis.from_url(
            _backoffice_redis_url(1),
            decode_responses=False,
        )
        backend_config_store = BackendConfigStore(redis_client=redis_session_client)

        # Determine default active backend from env or Redis
        default_backend_name = os.getenv(
            "YASHIGANI_INSPECTION_DEFAULT_BACKEND",
            backend_config_store.get_active(),
        )
        fallback_chain_raw = os.getenv(
            "YASHIGANI_INSPECTION_FALLBACK_CHAIN",
            "",
        )
        if fallback_chain_raw:
            fallback_chain = [b.strip() for b in fallback_chain_raw.split(",") if b.strip()]
        else:
            fallback_chain = backend_config_store.get_fallback_chain()

        # Build the initial active backend (Ollama is always available locally)
        ollama_backend = OllamaBackend(
            base_url=ollama_url,
            model=model,
        )

        backend_registry = BackendRegistry(
            active_backend=ollama_backend,
            fallback_chain=fallback_chain,
            all_backends={"ollama": ollama_backend},
            audit_writer=audit_writer,
        )

        # Inject backend_registry into the inspection pipeline
        inspection_pipeline._backend_registry = backend_registry

        logger.info(
            "Backend registry initialised: active=%s, chain=%s",
            ollama_backend.name, fallback_chain,
        )
    except Exception as exc:
        logger.warning(
            "Backend registry init failed (%s) — inspection pipeline uses legacy classifier",
            exc,
        )

    # ── Model alias store (Redis db/1, separate key namespace) ─────────────
    model_alias_store = None
    try:
        import redis as _redis
        from yashigani.models.alias_store import ModelAliasStore
        redis_alias_client = _redis.from_url(
            _backoffice_redis_url(1),
            decode_responses=False,
        )
        model_alias_store = ModelAliasStore(redis_client=redis_alias_client)
        model_alias_store.seed_defaults()
        logger.info(
            "Model alias store initialised: %d alias(es) in index",
            len(model_alias_store.list_all()),
        )
    except Exception as exc:
        logger.warning(
            "Model alias store init failed (%s) — aliases will fall back to in-memory defaults",
            exc,
        )

    # ── OTEL tracing ───────────────────────────────────────────────────────
    try:
        from yashigani.tracing import setup_tracer
        setup_tracer("yashigani-backoffice")
    except Exception as exc:
        logger.warning("OTEL setup skipped: %s", exc)

    # ── Response cache (Redis DB 4) — for admin management (Phase 6) ──────────
    response_cache = None
    try:
        import redis as _redis
        from yashigani.gateway.response_cache import ResponseCache
        redis_cache_url = _backoffice_redis_url(4)
        redis_cache_client = _redis.from_url(redis_cache_url, decode_responses=False)
        response_cache = ResponseCache(redis_client=redis_cache_client)
        logger.info("Backoffice: response cache client ready (Redis DB 4)")
    except Exception as exc:
        logger.warning("Response cache init failed (%s) — cache management disabled", exc)

    # ── PostgreSQL pool + inference logger + anomaly detector ───────────────
    # v2.23.1: The async init (create_pool + logger.start) is deferred to the
    # FastAPI lifespan in app.py. Reason: uvicorn imports this module inside
    # its server loop, so calling loop.run_until_complete() here raises
    # "this event loop is already running" and disables Postgres features.
    # Here we only resolve the ${POSTGRES_PASSWORD} placeholder in the DSN;
    # the lifespan picks up the resolved env var and does `await create_pool()`.
    inference_logger = None
    anomaly_detector = None
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
    if not db_dsn:
        logger.warning("YASHIGANI_DB_DSN not set — Postgres features disabled in backoffice")
    elif "${POSTGRES_PASSWORD}" in db_dsn:
        logger.warning("YASHIGANI_DB_DSN contains unresolved ${POSTGRES_PASSWORD} — Postgres features disabled")
    else:
        logger.info("Backoffice: DB DSN resolved — pool creation deferred to lifespan")

    # ── License ──────────────────────────────────────────────────────────────
    from yashigani.licensing import load_license, set_license
    license_state = load_license()
    set_license(license_state)
    logger.info(
        "License: tier=%s agents=%s/%s expires=%s",
        license_state.tier.value,
        "?",
        license_state.max_agents if license_state.max_agents != -1 else "unlimited",
        license_state.expires_at or "never",
    )

    # ── Populate singleton state ────────────────────────────────────────────
    # auth_service is populated from the FastAPI lifespan in app.py after
    # create_pool() — see v2.23.1 P0-2 notes above.
    backoffice_state.auth_service = auth_service
    backoffice_state.session_store = session_store
    backoffice_state.audit_writer = audit_writer
    backoffice_state.kms_provider = kms_provider
    backoffice_state.rotation_scheduler = rotation_scheduler
    backoffice_state.inspection_pipeline = inspection_pipeline
    backoffice_state.chs = chs
    backoffice_state.resource_monitor = resource_monitor
    backoffice_state.rate_limiter = rate_limiter
    backoffice_state.rbac_store = rbac_store
    backoffice_state.agent_registry = agent_registry
    backoffice_state.backend_registry = backend_registry
    backoffice_state.backend_config_store = backend_config_store
    backoffice_state.opa_url = os.getenv("YASHIGANI_OPA_URL", "https://policy:8181")
    backoffice_state.admin_min_total = int(os.getenv("YASHIGANI_ADMIN_MIN_TOTAL", "2"))
    backoffice_state.admin_min_active = int(os.getenv("YASHIGANI_ADMIN_MIN_ACTIVE", "2"))
    backoffice_state.admin_soft_target = int(os.getenv("YASHIGANI_ADMIN_SOFT_TARGET", "3"))
    backoffice_state.user_min_total = int(os.getenv("YASHIGANI_USER_MIN_TOTAL", "1"))
    backoffice_state.inference_logger = inference_logger
    backoffice_state.anomaly_detector = anomaly_detector
    backoffice_state.response_cache = response_cache
    backoffice_state.license_state = license_state
    backoffice_state.model_alias_store = model_alias_store

    # v0.9.0 — WebAuthn + EventBus (optional, graceful degradation if unavailable)
    try:
        from yashigani.auth.webauthn import WebAuthnService
        backoffice_state.webauthn_service = WebAuthnService()
        logger.info("WebAuthn service initialized")
    except Exception as exc:
        logger.warning("WebAuthn service unavailable (%s) — passkey routes will return 503", exc)

    try:
        from yashigani.events.bus import EventBus
        backoffice_state.event_bus = EventBus()
        logger.info("EventBus initialized")
    except Exception as exc:
        logger.warning("EventBus unavailable (%s) — SSE feed will return 503", exc)

    # v2.1 — Identity broker (OIDC/SAML SSO)
    try:
        from yashigani.auth.broker import IdentityBroker, IdPConfig
        tier_name = license_state.tier.value if license_state else "community"
        identity_broker = IdentityBroker(tier=tier_name)

        # Read IdP configurations from environment
        # Format: YASHIGANI_IDP_<N>_ID, _NAME, _PROTOCOL, _DISCOVERY_URL, _CLIENT_ID, _CLIENT_SECRET, _EMAIL_DOMAINS
        idp_index = 1
        while True:
            prefix = f"YASHIGANI_IDP_{idp_index}_"
            idp_id = os.getenv(f"{prefix}ID", "")
            if not idp_id:
                break
            idp_config = IdPConfig(
                id=idp_id,
                name=os.getenv(f"{prefix}NAME", idp_id),
                protocol=os.getenv(f"{prefix}PROTOCOL", "oidc"),
                metadata_url=os.getenv(f"{prefix}DISCOVERY_URL", ""),
                client_id=os.getenv(f"{prefix}CLIENT_ID", ""),
                client_secret=os.getenv(f"{prefix}CLIENT_SECRET", ""),
                email_domains=[
                    d.strip() for d in os.getenv(f"{prefix}EMAIL_DOMAINS", "").split(",") if d.strip()
                ],
            )
            redirect_uri = os.getenv(
                f"{prefix}REDIRECT_URI",
                f"https://{os.getenv('YASHIGANI_TLS_DOMAIN', 'localhost')}/auth/sso/oidc/{idp_id}/callback",
            )
            try:
                identity_broker.add_idp(idp_config, redirect_uri=redirect_uri)
                logger.info("IdP registered: %s (%s, %s)", idp_id, idp_config.name, idp_config.protocol)
            except ValueError as exc:
                logger.warning("IdP %s rejected: %s", idp_id, exc)
            idp_index += 1

        backoffice_state.identity_broker = identity_broker
        logger.info("Identity broker initialised: tier=%s, %d IdP(s)", tier_name, len(identity_broker.list_idps()))
    except Exception as exc:
        logger.warning("Identity broker init failed (%s) — SSO routes will return 503", exc)

    # v2.1 — Identity registry (Redis db/3, shared with RBAC)
    try:
        from yashigani.identity.registry import IdentityRegistry
        import redis as _redis
        redis_identity_url = _backoffice_redis_url(3)
        redis_identity_client = _redis.from_url(redis_identity_url, decode_responses=False)
        backoffice_state.identity_registry = IdentityRegistry(redis_client=redis_identity_client)
        logger.info("Identity registry initialised")
    except Exception as exc:
        logger.warning("Identity registry init failed (%s) — SSO identity resolution disabled", exc)

    # v2.1 — Break glass emergency access
    # ROOTFUL-P2-001: break-glass redis client now carries socket_timeout +
    # socket_connect_timeout (5 s each) plus retry-with-backoff on ping().
    # Break-glass is ADVISORY — failure degrades gracefully (warning + skip).
    # Max retry window: 6 attempts × 5 s timeout + (1+2+4+8+16) s backoff = 61 s.
    # This stays well inside the 90 s bootstrap probe / 120 s healthcheck window
    # even on slow GHA runners.  Ref: Captain PR #52 debug.
    _BG_SOCKET_TIMEOUT = 5.0       # per-operation cap (incl. ping)
    _BG_CONNECT_TIMEOUT = 5.0      # TCP + TLS handshake cap
    _BG_MAX_ATTEMPTS = 6           # total ping attempts before giving up
    try:
        from yashigani.auth.break_glass import init_break_glass
        import redis as _redis
        redis_bg = _redis.from_url(
            _backoffice_redis_url(0),
            decode_responses=True,
            socket_timeout=_BG_SOCKET_TIMEOUT,
            socket_connect_timeout=_BG_CONNECT_TIMEOUT,
            retry_on_timeout=True,
            health_check_interval=30,
        )
        # Retry-with-backoff ping: 1 s, 2 s, 4 s, 8 s, 16 s between attempts.
        _ping_ok = False
        _backoff = 1.0
        for _attempt in range(1, _BG_MAX_ATTEMPTS + 1):
            try:
                redis_bg.ping()
                _ping_ok = True
                break
            except Exception as _ping_exc:
                if _attempt < _BG_MAX_ATTEMPTS:
                    logger.warning(
                        "Break glass Redis ping attempt %d/%d failed (%s) — retrying in %.0f s",
                        _attempt, _BG_MAX_ATTEMPTS, _ping_exc, _backoff,
                    )
                    time.sleep(_backoff)
                    _backoff = min(_backoff * 2, 16.0)
                else:
                    logger.warning(
                        "Break glass Redis ping attempt %d/%d failed (%s) — giving up",
                        _attempt, _BG_MAX_ATTEMPTS, _ping_exc,
                    )
        if _ping_ok:
            backoffice_state.break_glass_manager = init_break_glass(redis_bg, audit_writer)
            logger.info("Break glass manager initialized")
        else:
            logger.warning("Break glass unavailable — Redis unreachable after %d attempts", _BG_MAX_ATTEMPTS)
    except Exception as exc:
        logger.warning("Break glass unavailable (%s)", exc)


_bootstrap()
app = create_backoffice_app()

# Start background metrics collector for backoffice-side services
_collector = MetricsCollector(
    resource_monitor=backoffice_state.resource_monitor,
    rate_limiter=backoffice_state.rate_limiter,
    chs=backoffice_state.chs,
    rotation_scheduler=backoffice_state.rotation_scheduler,
    inspection_pipeline=backoffice_state.inspection_pipeline,
    rbac_store=backoffice_state.rbac_store,
    agent_registry=backoffice_state.agent_registry,
    backend_registry=backoffice_state.backend_registry,
    poll_interval_seconds=15,
)
_collector.start()
