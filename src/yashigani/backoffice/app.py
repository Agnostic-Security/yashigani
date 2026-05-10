"""
Yashigani Backoffice — FastAPI admin portal.
Isolated on port 8443. Local auth only (username + password + TOTP).
No data-plane access. TLS required.

Last updated: 2026-05-10T00:00:00+01:00
"""

from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from yashigani.auth.spiffe import require_spiffe_id

try:
    from prometheus_client import (
        Counter,
        Histogram,
        generate_latest,
        CONTENT_TYPE_LATEST,
    )

    _PROM_AVAILABLE = True
except ImportError:
    _PROM_AVAILABLE = False

if _PROM_AVAILABLE:
    _bo_requests_total = Counter(
        "yashigani_backoffice_requests_total",
        "Total backoffice HTTP requests.",
        ["method", "path_prefix", "status_code"],
    )
    _bo_request_duration_seconds = Histogram(
        "yashigani_backoffice_request_duration_seconds",
        "Backoffice request latency in seconds.",
        ["method", "path_prefix"],
        buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
    )
    _bo_auth_failures_total = Counter(
        "yashigani_backoffice_auth_failures_total",
        "Backoffice authentication failures by reason.",
        ["reason"],
    )

from yashigani.backoffice.routes import (
    auth_router,
    accounts_router,
    users_router,
    kms_router,
    audit_router,
    inspection_router,
    inspection_backend_router,
    dashboard_router,
    ratelimit_router,
    rbac_router,
    scim_router,
    agents_router,
    infrastructure_router,
    jwt_config_router,
    cache_router,
    audit_sinks_router,
    kms_vault_router,
    license_router,
    opa_assistant_router,
    alerts_router,
    agent_bundles_router,
    # v0.9.0 — Phase 6 + Phase 7
    webauthn_router,
    events_router,
    audit_search_router,
    # v2.1
    models_router,
    sensitivity_router,
    sso_router,
    # v2.23.2 — Backup status + verify (#47)
    backup_router,
    # v2.23.3 — Admin-triggered secret rotation
    secrets_router,
    # v2.23.3 — HIBP API key admin panel (#59)
    hibp_router,
    # v2.23.3 — WebAuthn v1 API (public login + step-up revoke)
    webauthn_v1_router,
    # v2.23.3 — PKI admin UI + BYO-CA driver (#51 + #53)
    pki_v1_router,
)


async def _bootstrap_admin_accounts(auth_service, state) -> None:
    """
    Seed admin1 (+ optional admin2) from installer secrets on first boot.

    Replaces the old in-memory `if not auth_service._accounts` guard with
    a Postgres-backed count so restarts never trigger a re-seed — rotated
    passwords and re-enrolled TOTPs persist.

    Resolves P0-2 (YCS-20260423-v2.23.1-OWASP-3X).
    """
    import logging as _lg
    import os as _os

    _log = _lg.getLogger("yashigani.backoffice.auth_bootstrap")
    ctx = getattr(state, "_auth_bootstrap", None)
    if ctx is None:
        return

    if await auth_service.total_admin_count() != 0:
        _log.info("Bootstrap: admin accounts already present — skipping seed")
        return

    admin_username = ctx["admin_username"]
    initial_admin_password = ctx["initial_admin_password"]
    secrets_dir = ctx["secrets_dir"]

    await auth_service.create_admin(
        username=admin_username,
        auto_generate=False,
        plaintext_password=initial_admin_password,
    )
    totp_file = _os.path.join(secrets_dir, "admin1_totp_secret")
    if _os.path.exists(totp_file):
        totp_secret = open(totp_file).read().strip()
        if totp_secret:
            # installer-privileged bootstrap path — see docstring on
            # PostgresLocalAuthService.set_totp_secret_direct
            await auth_service.set_totp_secret_direct(admin_username, totp_secret)
            _log.info("Bootstrap: TOTP pre-provisioned from installer secret")
    _log.info("Bootstrap: initial admin account created — %s", admin_username)

    # --- Admin 2 (backup — anti-lockout) -------------------------------------
    admin2_user_file = _os.path.join(secrets_dir, "admin2_username")
    admin2_pwd_file = _os.path.join(secrets_dir, "admin2_password")
    if _os.path.exists(admin2_user_file) and _os.path.exists(admin2_pwd_file):
        admin2_username = open(admin2_user_file).read().strip()
        admin2_password = open(admin2_pwd_file).read().strip()
        if admin2_username and admin2_password:
            await auth_service.create_admin(
                username=admin2_username,
                auto_generate=False,
                plaintext_password=admin2_password,
            )
            totp2_file = _os.path.join(secrets_dir, "admin2_totp_secret")
            if _os.path.exists(totp2_file):
                totp2_secret = open(totp2_file).read().strip()
                if totp2_secret:
                    await auth_service.set_totp_secret_direct(admin2_username, totp2_secret)
                    _log.info("Bootstrap: admin2 TOTP pre-provisioned from installer secret")
            _log.info("Bootstrap: backup admin account created — %s", admin2_username)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # v2.23.1: Async DB pool + inference logger + anomaly detector init.
    # Moved from _bootstrap() because uvicorn imports the entrypoint module
    # inside its running server loop, so sync loop.run_until_complete() raises
    # "this event loop is already running" and disables Postgres features.
    import logging as _logging
    import os

    _log = _logging.getLogger("yashigani.backoffice.lifespan")

    # Layer B: load the per-install caddy_internal_hmac secret.
    # Must be first so _caddy_secret is populated before any request reaches
    # CaddyVerifiedMiddleware. Raises RuntimeError if secret is missing
    # (fail-closed per SOP 1 / CLAUDE.md §3).
    from yashigani.auth.caddy_verified import load_caddy_secret as _load_caddy_secret

    _load_caddy_secret()

    db_dsn = os.getenv("YASHIGANI_DB_DSN", "")
    if db_dsn and "${POSTGRES_PASSWORD}" not in db_dsn:
        try:
            from yashigani.db import create_pool, get_pool, run_migrations
            from yashigani.db import _BOOTSTRAP_ADVISORY_LOCK_KEY
            from yashigani.inference import InferencePayloadLogger, AnomalyDetector
            from yashigani.backoffice.state import backoffice_state

            # v2.23.1 P0-2: alembic must run BEFORE the pool opens so the
            # admin_accounts + used_totp_codes tables exist when the auth
            # service first reads/writes. run_migrations() is sync and uses
            # its own psycopg2 connection. Multi-replica safety: alembic
            # acquires a postgres advisory lock internally — see
            # yashigani/db/__init__.py:run_migrations() (Platform gate #58c #3bv).
            #
            # v2.23.3 fix: run_migrations() is sync (psycopg2 + alembic). Calling
            # it directly on the async event loop blocks the loop for the full
            # migration duration (~1-3 s on cold DB). Docker's first healthcheck
            # fires at T+start_period (was 30 s); if migrations exhaust that window
            # the container is marked unhealthy before /healthz can respond.
            # Wrapping in asyncio.to_thread() offloads the blocking work to the
            # default ThreadPoolExecutor, keeping the event loop responsive.
            import asyncio as _asyncio  # noqa: PLC0415 — inline; _asyncio re-used below
            await _asyncio.to_thread(run_migrations)

            await create_pool()

            # --- v2.23.1 P0-2: bootstrap PostgresLocalAuthService -------------
            # Seed admin accounts from installer secrets ONLY if the DB has
            # zero admins. Previously the guard was `if not auth_service._accounts`
            # (in-memory dict); now we consult the durable store so restarts
            # never clobber rotated passwords / re-enrolled TOTP.
            #
            # K8s multi-replica race: replicas 1 and 2 both check
            # total_admin_count() concurrently before either commits the
            # admin1 row -> both pass the != 0 guard -> second insert hits a
            # unique-constraint violation and the pod CrashLoopBackOff's.
            # Hold the same advisory lock as run_migrations() across the
            # bootstrap so replica 2 only enters the bootstrap block AFTER
            # replica 1 has committed the admin rows; replica 2 then sees
            # count != 0 and skips.
            #
            # CRITICAL (Platform gate #58c #3bw + #3bx, 2026-04-29): the lock
            # connection MUST go direct to postgres, NOT through pgbouncer.
            # pgbouncer in txn-pool mode routes each new connection to a
            # different postgres backend, and pg_advisory_lock is session-
            # scoped (per-backend). Replicas land on different backends ->
            # both "acquire" the same key independently -> no serialisation.
            # Plus the asyncpg pool's command_timeout=10 was making replica 2
            # raise TimeoutError before replica 1 finished bootstrap.
            # Use bare psycopg2 with YASHIGANI_DB_DSN_DIRECT (env var set in
            # the K8s Helm chart pointing at yashigani-postgres:5432). Falls
            # back to YASHIGANI_DB_DSN for compose (single-replica = no race).
            from yashigani.auth.pg_auth import PostgresLocalAuthService

            auth_service = PostgresLocalAuthService(pool=get_pool())
            backoffice_state.auth_service = auth_service

            # v2.23.3 (#59): auth_settings_store for encrypted operator config
            # (e.g. HIBP API key). Initialised after the pool is ready.
            # B2 fail-fast: YASHIGANI_DB_AES_KEY MUST be set; an empty or
            # missing key causes pgp_sym_encrypt to encrypt with an empty
            # passphrase, which is a silent data-security failure. We reject
            # at startup rather than allowing a degraded-but-running state.
            _aes_key = os.environ.get("YASHIGANI_DB_AES_KEY", "")
            if not _aes_key:
                raise RuntimeError(
                    "YASHIGANI_DB_AES_KEY is not set. "
                    "This key is required to encrypt auth_settings values at rest "
                    "using pgcrypto pgp_sym_encrypt. "
                    "Generate a 32-byte hex key (64 chars) with: "
                    "openssl rand -hex 32 "
                    "and add it to your .env file or Helm values secret."
                )
            from yashigani.auth.settings_store import AuthSettingsStore
            backoffice_state.auth_settings_store = AuthSettingsStore(pool=get_pool())
            _log.info("auth_settings_store initialised (pgcrypto-backed encrypted store)")

            import asyncio as _asyncio
            from yashigani.db.postgres import connect_with_retry_sync as _connect_retry

            direct_dsn = os.environ.get("YASHIGANI_DB_DSN_DIRECT") or db_dsn

            def _acquire_lock_sync():
                # RETRO-R4-2: use connect_with_retry_sync (connect_timeout=15s,
                # up to 5 attempts with backoff) instead of bare psycopg2.connect()
                # which hangs indefinitely when postgres is mid-restart.
                # F-NEW-02 finding: pg_advisory_lock blocked the entire lifespan
                # for 60+ s when postgres restarted during K8s rolling update.
                conn = _connect_retry(direct_dsn, max_attempts=5, backoff_s=3.0)
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute("SELECT pg_advisory_lock(%s)", (_BOOTSTRAP_ADVISORY_LOCK_KEY,))
                return conn

            def _release_lock_sync(conn):
                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT pg_advisory_unlock(%s)", (_BOOTSTRAP_ADVISORY_LOCK_KEY,))
                finally:
                    conn.close()

            _lock_conn = await _asyncio.to_thread(_acquire_lock_sync)
            _log.info("Bootstrap: acquired admin advisory lock %s", hex(_BOOTSTRAP_ADVISORY_LOCK_KEY))
            try:
                await _bootstrap_admin_accounts(auth_service, backoffice_state)
            finally:
                await _asyncio.to_thread(_release_lock_sync, _lock_conn)
                _log.info("Bootstrap: released admin advisory lock")

            inference_logger = InferencePayloadLogger()
            inference_logger.start()
            backoffice_state.inference_logger = inference_logger

            # Anomaly detector Redis client (DB 2), mirrors _bootstrap URL logic.
            from yashigani.gateway._redis_url import build_redis_url

            anomaly_redis_url = build_redis_url(
                2,
                use_tls=os.getenv("REDIS_USE_TLS", "true").lower() == "true",
                secrets_dir=os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets"),
                client_cert_name="backoffice_client",
            )

            import redis as _redis

            anomaly_client = _redis.from_url(anomaly_redis_url, decode_responses=False)
            backoffice_state.anomaly_detector = AnomalyDetector(redis_client=anomaly_client)
            _log.info("Backoffice: DB pool + inference logger + anomaly detector ready (lifespan)")

            # v2.23.3 — PgWebAuthnService: DB+Redis backed FIDO2 service.
            # Initialised here (after create_pool) so the credential store can
            # open tenant_transaction()s immediately on first registration.
            # Shares the session Redis (DB 1) for challenge storage with a
            # yashigani:webauthn:challenge: namespace.
            try:
                from yashigani.auth.pg_webauthn import build_pg_webauthn_service
                from yashigani.gateway._redis_url import build_redis_url as _build_redis_url
                _webauthn_redis_url = _build_redis_url(
                    1,
                    use_tls=os.getenv("REDIS_USE_TLS", "true").lower() == "true",
                    secrets_dir=os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets"),
                    client_cert_name="backoffice_client",
                )
                _webauthn_redis = _redis.from_url(_webauthn_redis_url, decode_responses=False)
                backoffice_state.pg_webauthn_service = build_pg_webauthn_service(_webauthn_redis)
                _log.info("PgWebAuthnService initialised (v2.23.3 FIDO2)")
            except Exception as _wa_exc:
                # Non-fatal: WebAuthn is optional.  Routes return 503 if pg_webauthn_service is None.
                # W19 fix: log with exc_info=True so the full traceback is captured (not just
                # str(exc)) — Iris integration-audit warning on PR #62.  Without exc_info the
                # stack frame that caused the failure is lost, making mis-config hard to diagnose.
                _log.warning(
                    "PgWebAuthnService init failed (%s) — /api/v1/admin/webauthn/* will return 503",
                    _wa_exc,
                    exc_info=True,
                )
        except Exception as exc:
            # Retro #3ar — fail-closed on lifespan init failure (CLAUDE.md §3).
            # The previous behaviour was to log a warning and continue with
            # auth_service=None, which left the container in a "healthy"
            # but unauthenticatable zombie state — every /auth/login returned
            # HTTP 500 with `AttributeError: 'NoneType' object has no attribute
            # 'authenticate'`. Caught only by gate #58a restore test.
            # Log the full traceback so the failing dependency is identifiable,
            # then re-raise so the container exits non-zero and orchestrator
            # surfaces the real fault instead of the secondary 500.
            _log.exception("Backoffice lifespan init FAILED — refusing to start with auth_service=None")
            raise

    # Startup — schedule daily licence expiry check (v0.7.1),
    # grace-period audit emitter (v2.23.3),
    # and inactive-account disable (v2.23.3, FedRAMP AC-2(F2) / LU-YSG-002).
    scheduler = None
    try:
        import asyncio
        import logging as _sched_log
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from yashigani.licensing.expiry_monitor import check_and_alert_licence_expiry
        from yashigani.licensing.grace_period import emit_grace_period_audit
        from yashigani.backoffice.inactive_account_task import run_inactive_account_disable

        _inactive_interval_hours: int = 24
        try:
            _inactive_interval_hours = int(os.getenv("YASHIGANI_INACTIVE_DISABLE_INTERVAL_HOURS", "24"))
            if _inactive_interval_hours < 1:
                _inactive_interval_hours = 24
        except (ValueError, TypeError):
            pass

        scheduler = AsyncIOScheduler()
        # Licence expiry — every 24 hours
        scheduler.add_job(
            check_and_alert_licence_expiry,
            trigger="interval",
            hours=24,
            id="licence_expiry_check",
            replace_existing=True,
        )
        # Grace-period audit — daily (v2.23.3)
        scheduler.add_job(
            emit_grace_period_audit,
            trigger="interval",
            hours=24,
            id="licence_grace_period_audit",
            replace_existing=True,
        )
        # Inactive-account disable — configurable interval (default 24h)
        scheduler.add_job(
            run_inactive_account_disable,
            trigger="interval",
            hours=_inactive_interval_hours,
            id="inactive_account_disable",
            replace_existing=True,
        )
        scheduler.start()
        # Fire all immediately so the first check happens at startup
        asyncio.ensure_future(check_and_alert_licence_expiry())
        asyncio.ensure_future(emit_grace_period_audit())
        asyncio.ensure_future(run_inactive_account_disable())
    except ImportError:
        pass  # apscheduler not installed — expiry alerts + inactive-disable disabled
    except Exception as exc:
        import logging

        logging.getLogger(__name__).warning("Could not start backoffice scheduler: %s", exc)

    yield

    # Shutdown
    if scheduler is not None:
        scheduler.shutdown(wait=False)


def create_backoffice_app() -> FastAPI:
    app = FastAPI(
        title="Yashigani Backoffice",
        version="2.1.0",
        docs_url=None,  # disable Swagger in production
        redoc_url=None,
        openapi_url=None,  # never expose schema externally
        lifespan=lifespan,
    )

    # Layer B: Caddy-verified shared-secret middleware (EX-231-10 Layer B).
    # Checks X-Caddy-Verified-Secret on every non-healthcheck request. Must run
    # second from outermost — added BEFORE SpiffePeerCertMiddleware so that in
    # Starlette LIFO order, Spiffe runs outermost and CaddyVerified runs second.
    # load_caddy_secret() is called in lifespan() above.
    from yashigani.auth.caddy_verified import CaddyVerifiedMiddleware

    app.add_middleware(CaddyVerifiedMiddleware)

    # SPIFFE peer-cert middleware — LF-SPIFFE-FORGE backoffice leg (Compliance F-1B
    # EX-231-10, 2026-04-29). Extracts the TLS peer cert URI SAN from the ASGI
    # handshake scope and injects it as X-SPIFFE-ID-Peer-Cert. This is a
    # server-controlled header that cannot be forged by the client.
    #
    # Why backoffice needs this: backoffice listens on 0.0.0.0:8443 with
    # `--ssl-cert-reqs 2` (mutual TLS required). Any internal-mesh peer holding
    # a CA-minted client cert can connect direct to https://backoffice:8443/
    # internal/metrics, present its own cert, and forge `X-SPIFFE-ID:
    # spiffe://yashigani.internal/prometheus` to bypass the SPIFFE allowlist
    # on Prometheus metrics. Same bypass shape as the gateway leg that was
    # closed at a054877 — the fix here is the same middleware on the
    # backoffice ASGI app, written deliberately as the OUTERMOST middleware
    # so it sets the trustworthy header BEFORE any application code reads
    # x-spiffe-id (auth/spiffe.py:73).
    #
    # Must run outermost (added last = executed first in starlette middleware
    # stack), matching gateway/entrypoint.py placement.
    from yashigani.gateway.spiffe_middleware import SpiffePeerCertMiddleware

    app.add_middleware(SpiffePeerCertMiddleware)

    # CORS: backoffice serves its own frontend — no cross-origin needed
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],  # no CORS allowed
        allow_credentials=False,
        allow_methods=[],
        allow_headers=[],
    )

    # Prometheus instrumentation middleware — must be registered before security headers
    # so we record metrics even on requests that return error responses.
    # /internal/metrics is excluded to avoid self-scrape cardinality noise.
    @app.middleware("http")
    async def prometheus_middleware(request: Request, call_next):
        if not _PROM_AVAILABLE or request.url.path == "/internal/metrics":
            return await call_next(request)
        # Collapse path to a low-cardinality prefix (first two segments)
        segments = [s for s in request.url.path.split("/") if s]
        path_prefix = "/" + "/".join(segments[:2]) if segments else "/"
        start = time.monotonic()
        response = await call_next(request)
        elapsed = time.monotonic() - start
        _bo_requests_total.labels(
            method=request.method,
            path_prefix=path_prefix,
            status_code=str(response.status_code),
        ).inc()
        _bo_request_duration_seconds.labels(
            method=request.method,
            path_prefix=path_prefix,
        ).observe(elapsed)
        return response

    # Security headers middleware
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "no-referrer"
        # CSP: strict for all pages — no inline scripts or styles allowed
        # ASVS 3.4.3: object-src 'none' + base-uri 'none'; 3.4.7: report-uri
        _csp = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; report-uri /admin/csp-report; report-to default"
        response.headers["Content-Security-Policy"] = _csp
        return response

    # Per-endpoint body-size limits (ASVS 4.3.1).
    #
    # The global 4 MB app limit + 10 MB Caddy limit covers everything, but
    # endpoints that only accept small JSON (search, policy probes, admin
    # config POSTs) should reject oversized bodies early to resist
    # resource-exhaustion abuse. Patterns are prefix-matched, longest first.
    # Override via YASHIGANI_BODY_LIMITS_DISABLED=1 for debugging; never in
    # production.
    _BODY_LIMITS = [
        # (prefix, max_bytes)
        ("/admin/audit/search", 64 * 1024),  # JSON search query
        ("/admin/agents", 16 * 1024),  # agent register metadata
        ("/admin/users", 4 * 1024),  # username + opt email
        ("/admin/license", 4 * 1024),  # confirm flag or small LIC
        ("/api/v1/license", 256),  # status GET only, no body
        ("/api/v1/admin/secrets", 256),  # secret name only (ASVS 4.3.1)
        ("/api/v1/admin/auth/hibp", 512),  # HIBP key (UUID ≤128 + envelope)
        ("/api/v1/admin/pki", 256),        # PKI rotate body (service name in URL, no body)
        ("/admin/ratelimit", 8 * 1024),
        ("/admin/rbac", 32 * 1024),
        ("/admin/alerts", 32 * 1024),
        ("/admin/budget", 16 * 1024),
        ("/admin/backup", 256),  # backup_name only (ASVS 4.3.1)
        ("/auth/login", 4 * 1024),  # u/p/totp
        ("/auth/password/change", 8 * 1024),
        ("/auth/password/self-reset", 4 * 1024),
        ("/auth/totp/provision", 4 * 1024),  # start + confirm variants
        ("/auth/stepup", 4 * 1024),  # 6-digit TOTP code only
        # /v1/chat/completions is intentionally not limited here — LLM prompts
        # can legitimately be large; the global 4 MB limit still applies.
    ]

    @app.middleware("http")
    async def per_endpoint_body_size(request: Request, call_next):
        if os.getenv("YASHIGANI_BODY_LIMITS_DISABLED") == "1":
            return await call_next(request)
        cl = request.headers.get("content-length")
        if cl:
            try:
                length = int(cl)
            except ValueError:
                length = 0
            for prefix, limit in _BODY_LIMITS:
                if request.url.path.startswith(prefix) and length > limit:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": "payload_too_large",
                            "max_bytes": limit,
                            "received_bytes": length,
                        },
                    )
        return await call_next(request)

    # Uniform 401 for unauthenticated /admin/* requests (QA Wave 2 Issue 10).
    # Before this middleware, some admin endpoints returned 401 (route exists,
    # auth dep failed) while others returned 404 (no root route under that
    # prefix, e.g. /admin/license/status existed but /admin/license didn't).
    # The inconsistency leaked which routes were mounted. This middleware
    # inspects the response AFTER routing: if the result is 404 for an
    # /admin/* path AND the caller has no session cookie, we mask the 404
    # as 401 authentication_required so every /admin/* probe looks the same
    # pre-auth.
    _ADMIN_SESSION_COOKIES = (
        "__Host-yashigani_admin_session",
        "__Host-yashigani_session",
    )

    @app.middleware("http")
    async def uniform_admin_404_as_401(request: Request, call_next):
        response = await call_next(request)
        if response.status_code == 404 and request.url.path.startswith("/admin/"):
            has_session = any(request.cookies.get(k) for k in _ADMIN_SESSION_COOKIES)
            if not has_session:
                return JSONResponse(
                    status_code=401,
                    content={"error": "authentication_required"},
                )
        return response

    # Generic error handlers — never leak internal state
    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "message": "An internal error occurred"},
        )

    # Unauthenticated health endpoint for Docker healthcheck
    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    # Internal Prometheus metrics endpoint — Caddy-gated with SPIFFE URI ACL.
    # EX-231-08 (v2.23.1, zero-trust default): Prometheus scrapes via Caddy's
    # :8444 internal listener; Caddy validates the peer cert and sets
    # X-SPIFFE-ID from the URI SAN. require_spiffe_id enforces the allowlist
    # defined in service_identities.yaml endpoint_acls. Bridge-network
    # isolation is now a defence-in-depth measure, not the sole control.
    @app.get(
        "/internal/metrics",
        dependencies=[Depends(require_spiffe_id("/internal/metrics"))],
    )
    async def internal_metrics():
        if not _PROM_AVAILABLE:
            return PlainTextResponse("# prometheus_client not installed\n")
        return PlainTextResponse(
            generate_latest().decode("utf-8"),
            media_type=CONTENT_TYPE_LATEST,
        )

    # Static files (CSS/JS for login pages etc.)
    import pathlib

    _static_dir = pathlib.Path(__file__).parent / "static"
    if _static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

    # Admin UI — HTML pages
    _templates_dir = pathlib.Path(__file__).parent / "templates"
    if _templates_dir.exists():
        _templates = Jinja2Templates(directory=str(_templates_dir))

        @app.get("/login", include_in_schema=False)
        async def user_login_page(request: Request):
            return _templates.TemplateResponse(request, "user_login.html")

        @app.get("/admin/login", include_in_schema=False)
        async def admin_login_page(request: Request):
            return _templates.TemplateResponse(request, "login.html")

        @app.get("/admin/", include_in_schema=False)
        async def admin_dashboard_page(request: Request):
            # Server-side session-presence check before serving the dashboard HTML.
            # ASVS V1.4.1: access control enforced at trusted enforcement point.
            # A missing cookie means no valid session → redirect to login.
            # Note: cryptographic validation of the session token happens in the
            # API layer (SessionStore.get()) on every subsequent API call; this
            # check is a lightweight pre-flight to avoid serving the SPA shell to
            # unauthenticated clients (closes SWEEP-06 / OWASP A07 finding).
            # Fix: 2026-05-09 (v2.23.3).
            _admin_cookies = (
                "__Host-yashigani_admin_session",
                "__Host-yashigani_session",
            )
            if not any(request.cookies.get(k) for k in _admin_cookies):
                next_path = request.url.path
                return RedirectResponse(
                    url=f"/admin/login?next={next_path}",
                    status_code=302,
                )
            return _templates.TemplateResponse(request, "dashboard.html")

    # Routers
    app.include_router(auth_router, prefix="/auth", tags=["auth"])
    app.include_router(dashboard_router, prefix="/dashboard", tags=["dashboard"])
    app.include_router(accounts_router, prefix="/admin/accounts", tags=["admin-accounts"])
    app.include_router(users_router, prefix="/admin/users", tags=["user-accounts"])
    app.include_router(kms_router, prefix="/admin/kms", tags=["kms"])
    app.include_router(audit_router, prefix="/admin/audit", tags=["audit"])
    app.include_router(inspection_router, prefix="/admin/inspection", tags=["inspection"])
    app.include_router(inspection_backend_router, prefix="/admin/inspection", tags=["inspection-backend"])
    app.include_router(ratelimit_router, prefix="/admin/ratelimit", tags=["ratelimit"])
    app.include_router(rbac_router, prefix="/admin/rbac", tags=["rbac"])
    app.include_router(scim_router, prefix="/scim/v2", tags=["scim"])
    app.include_router(agents_router, tags=["agents"])
    app.include_router(infrastructure_router, prefix="/admin/infrastructure", tags=["infrastructure"])
    app.include_router(jwt_config_router, tags=["jwt-config"])
    app.include_router(cache_router, tags=["cache"])
    app.include_router(audit_sinks_router, tags=["audit-sinks"])
    app.include_router(kms_vault_router, tags=["kms-vault"])
    app.include_router(license_router, prefix="/admin/license", tags=["license"])

    # v2.23.3 — Machine-readable expiry status also available as /api/v1/license/status
    # so CLI tools and monitoring scripts can query without knowing the /admin/ prefix.
    # The handler is re-exported from license_router; auth is still required.
    from yashigani.backoffice.routes.license import get_license_expiry_status

    app.add_api_route(
        "/api/v1/license/status",
        get_license_expiry_status,
        methods=["GET"],
        tags=["license"],
        summary="Machine-readable licence expiry status (v2.23.3)",
    )
    app.include_router(opa_assistant_router, prefix="/admin/opa-assistant", tags=["opa-assistant"])
    app.include_router(alerts_router, prefix="/admin/alerts", tags=["alerts"])
    app.include_router(agent_bundles_router, prefix="/admin/agent-bundles", tags=["agent-bundles"])
    # v1.0 — Budget admin API
    from yashigani.backoffice.routes.budget import router as budget_router

    app.include_router(budget_router, tags=["budget"])

    # v2.1 — Model alias management + Sensitivity patterns
    app.include_router(models_router, prefix="/admin/models", tags=["models"])
    app.include_router(sensitivity_router, prefix="/admin/sensitivity", tags=["sensitivity"])
    # v2.1 — SSO / OIDC login flow (no auth required — serves anonymous users)
    app.include_router(sso_router, prefix="/auth", tags=["sso"])

    # v2.2 — PII detection admin API
    from yashigani.backoffice.routes.pii import router as pii_router

    app.include_router(pii_router, prefix="/admin/pii", tags=["pii"])

    # v2.3 — Cryptographic inventory (ASVS 11.1.3)
    from yashigani.backoffice.routes.crypto_inventory import router as crypto_inventory_router

    app.include_router(crypto_inventory_router, prefix="/admin", tags=["crypto"])

    # ASVS 3.4.7 — CSP violation report endpoint
    from yashigani.backoffice.routes.csp_report import router as csp_report_router

    app.include_router(csp_report_router, prefix="/admin", tags=["csp"])

    # Service management — enable/disable optional compose profiles from admin panel
    from yashigani.backoffice.routes.services import router as services_router

    app.include_router(services_router, tags=["services"])

    # v2.23.2 — Backup status + verify (#47)
    app.include_router(backup_router, tags=["backup"])

    # v2.23.3 — Admin-triggered secret rotation
    app.include_router(secrets_router, tags=["secrets"])

    # v2.23.3 — HIBP API key admin panel (#59)
    app.include_router(
        hibp_router,
        prefix="/api/v1/admin/auth/hibp",
        tags=["hibp-config"],
    )
    # v2.23.3 — WebAuthn v1 API (Postgres+Redis backed, public login endpoints)
    # Routes carry full /api/v1/admin/webauthn/ path — no prefix stripping.
    app.include_router(webauthn_v1_router, tags=["webauthn-v1"])

    # v2.23.3 — PKI admin UI + BYO-CA driver (#51 + #53)
    # Routes carry /api/v1/admin/pki/ prefix defined in the router itself.
    app.include_router(pki_v1_router, tags=["pki"])

    # v0.9.0 — Phase 6: WebAuthn/Passkeys
    # webauthn_router carries its own full path segments (no prefix stripping needed)
    app.include_router(webauthn_router, tags=["webauthn"])
    # v0.9.0 — Phase 7: Operator Visibility
    app.include_router(events_router, prefix="/admin/events", tags=["events"])
    app.include_router(audit_search_router, prefix="/admin/audit", tags=["audit-search"])

    return app
