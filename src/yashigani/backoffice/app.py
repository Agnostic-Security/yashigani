"""
Yashigani Backoffice — FastAPI admin portal.
Isolated on port 8443. Local auth only (username + password + TOTP).
No data-plane access. TLS required.

Last updated: 2026-05-17T00:00:00+01:00
"""

from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from yashigani.api_docs import swagger_ui_html as _swagger_ui_html, redoc_html as _redoc_html
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
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
    # v2.26 — Document Enforcement admin surface
    documents_router,
    # 3.0 — Capability-envelope re-approval admin surface (YSG-RISK-060)
    envelope_reapproval_router,
    # 4.0 — MCP Server Registry admin surface (list + import ceremony)
    mcp_servers_router,
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
    # v2.23.4 — Gap 4: user self-service Bearer issuance (/me/api-key*)
    me_router,
    # v2.24.1 — LU-AMEND-02/03: manifest registration ledger + ceremony record
    manifest_history_router,
    # v2.24.1 — admin-surfaces-all-runtime-settings: runtime settings admin API
    runtime_settings_router,
    # v2.25.5 — R13: RBAC sources / R26: version check
    rbac_sources_router,
    version_check_router,
    cloud_keys_router,
    # 3.0 — admin-configurable browser Permissions-Policy
    capability_policy_router,
    # 3.1 Phase 8 — unified permission grant admin API
    permissions_router,
    # 4.0 Phase 2 — user-plane routes (OWUI replacement; RISK-100/112)
    user_ui_router,
    # 4.0 Chat persistence — conversation + message CRUD (BOLA-enforced)
    user_conversations_router,
    # 4.0 Workflow run history (wf-exec)
    user_workflows_router,
    # 4.0 Admin workflow-oversight (cross-user read + disable)
    admin_workflows_router,
    # 4.1 Phase B — Agent Policy Templates (policy template apply/revoke + status join)
    agent_policies_router,
)
# 4.0 LAURA-V400-R2-001 — Dual-admin data-protection maker-checker (lazy import)
from yashigani.backoffice.routes.dp_weaken import router as dp_weaken_router


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
            # PostgresLocalAuthService.set_totp_secret_direct.
            # Phase 13: admin accounts use SHA-512/8-digit TOTP.
            await auth_service.set_totp_secret_direct(admin_username, totp_secret, algorithm="SHA512")
            _log.info("Bootstrap: TOTP pre-provisioned from installer secret (SHA-512/8-digit)")
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
                    # Phase 13: admin tier → SHA-512/8-digit TOTP.
                    await auth_service.set_totp_secret_direct(admin2_username, totp2_secret, algorithm="SHA512")
                    _log.info("Bootstrap: admin2 TOTP pre-provisioned from installer secret (SHA-512/8-digit)")
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

    # Iris FIX-1 (v2.25.0 P2 wave 2 B12 follow-up): operator-visibility gap.
    # When openWebui.existingSecretName is a BYO Secret that lacks the
    # 'secret_key' key, the env var resolves to empty string and agent
    # provisioning to Open WebUI silently fails at runtime.  The chart cannot
    # detect this at template time, so we warn here at startup.
    # Threat-model: OWUI_API_URL is operator-supplied; use %s parameterised
    # logging (not f-string) to prevent log-injection.
    _owui_api_url = os.environ.get("OWUI_API_URL", "").strip()
    _owui_secret_key = os.environ.get("OWUI_SECRET_KEY", "").strip()
    if _owui_api_url and not _owui_secret_key:
        _log.warning(
            "OWUI_API_URL is set (%s) but OWUI_SECRET_KEY is empty or absent. "
            "Open WebUI agent provisioning will fail silently at runtime. "
            "Either unset OWUI_API_URL to disable Open WebUI integration, or set "
            "OWUI_SECRET_KEY (via Helm openWebui.existingSecretName containing key "
            "'secret_key', or via docker/.env OWUI_SECRET_KEY for compose).",
            _owui_api_url,
        )

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

            # v2.25.2 — wire the PostgresSink (DB audit mirror) + daily merkle
            # checkpoint scheduler now that the asyncpg pool is open.
            #   - PostgresSink reuses get_pool (zero-arg) — no second pool.
            #   - The file sink remains the canonical anchor; the DB sink is a
            #     fire-and-forget mirror whose failures never affect a request.
            #   - The same AuditChainService instance backs both row-level
            #     hashing and the daily checkpoint signer.
            #   - Guarded by AuditConfig.db_sink_enabled (YASHIGANI_AUDIT_DB_SINK).
            # Non-fatal: a wiring failure here must NOT crash backoffice — the
            # file audit trail is the durability anchor.  (This is deliberately
            # NOT a fail-closed path: audit DB mirroring is defence-in-depth on
            # top of the always-on file sink, per Tiago's non-blocking mandate.)
            try:
                from yashigani.audit.config import AuditConfig as _AuditConfig
                if _AuditConfig.from_env().db_sink_enabled:
                    from yashigani.audit.sinks import build_postgres_audit_sink
                    from yashigani.audit.checkpoint_job import AuditCheckpointScheduler
                    _audit_db_sink, _audit_chain_svc = build_postgres_audit_sink(get_pool)
                    backoffice_state.db_audit_sink = _audit_db_sink
                    _aw = backoffice_state.audit_writer
                    if _aw is not None and hasattr(_aw, "attach_db_sink"):
                        _aw.attach_db_sink(_audit_db_sink)
                        _log.info("Backoffice: DB audit sink attached to audit writer")
                    else:
                        _log.warning(
                            "Backoffice: audit_writer missing attach_db_sink — "
                            "DB audit sink NOT attached (file sink unaffected)"
                        )
                    # Daily merkle-root checkpoint scheduler — now that events
                    # actually arrive in audit_events, the previously-dormant
                    # checkpoint capability is activated.  Uses get_pool (zero-arg)
                    # and the SAME chain service so the signing config matches.
                    try:
                        _ckpt_sched = AuditCheckpointScheduler(
                            chain_service=_audit_chain_svc,
                            pool_getter=get_pool,
                        )
                        _ckpt_sched.start()
                        backoffice_state.audit_checkpoint_scheduler = _ckpt_sched
                        _log.info(
                            "Backoffice: audit checkpoint scheduler started "
                            "(daily merkle root at 00:05 UTC)"
                        )
                    except Exception as _ckpt_exc:
                        _log.warning(
                            "Backoffice: audit checkpoint scheduler failed to start "
                            "(%s) — DB sink still active; checkpoints can be run "
                            "manually via run_now()", _ckpt_exc,
                        )
                else:
                    _log.info(
                        "Backoffice: DB audit sink disabled "
                        "(YASHIGANI_AUDIT_DB_SINK=false)"
                    )
            except Exception as _dbsink_exc:
                _log.warning(
                    "Backoffice: DB audit sink wiring failed (%s) — "
                    "continuing with file sink only", _dbsink_exc,
                )

            # v2.24.1 — RuntimeSettingsService: admin-surfaces-all-runtime-settings rule.
            # Seeded from env vars on first boot; subsequent boots read from DB.
            # A separate Redis client on DB 1 (session Redis) is used for pub/sub.
            try:
                from yashigani.runtime_settings.service import RuntimeSettingsService as _RSS
                from yashigani.gateway._redis_url import build_redis_url as _build_rs_redis_url
                _rs_redis_url = _build_rs_redis_url(
                    1,
                    use_tls=os.getenv("REDIS_USE_TLS", "true").lower() == "true",
                    secrets_dir=os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets"),
                    client_cert_name="backoffice_client",
                )
                import redis as _redis_rs
                _rs_redis_client = _redis_rs.from_url(_rs_redis_url, decode_responses=False)
                _rs = _RSS(pool=get_pool(), redis_client=_rs_redis_client)
                await _rs.seed_defaults()
                backoffice_state.runtime_settings = _rs
                _log.info("RuntimeSettingsService initialised and defaults seeded (v2.24.1)")
            except Exception as _rs_exc:
                _log.warning(
                    "RuntimeSettingsService init failed (%s) — runtime settings admin API "
                    "unavailable; settings will fall back to env vars / class defaults",
                    _rs_exc,
                )
                # Non-fatal: all consumers fall back to env vars / class defaults.

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

            # v4.1 unified-sidecar §2.5 — bundled-agent ingress envelopes.
            # The agent INGRESS fronts forward_auth to /auth/verify-mcp, whose
            # step 3 requires an ACTIVE capability envelope; bundled agents
            # (openclaw/langflow/letta) never pass the BYO import ceremony, so
            # without this bootstrap every dispatch through their fronts 403s
            # server_not_onboarded.  Idempotent; closed allowlist; registry-
            # derived (only profiles the operator actually installed).
            # Non-fatal BY DESIGN (documented SOP-1 exception, audit-DB-sink
            # precedent above): no service-critical attribute is set to None
            # here and the failure mode is fail-CLOSED (verify-mcp keeps
            # denying the bundled fronts) — availability-only degradation,
            # retried on the next boot.
            try:
                from yashigani.backoffice.bundled_envelopes import (
                    bootstrap_bundled_agent_envelopes,
                )
                from yashigani.mcp.envelope_service import CapabilityEnvelopeService
                _minted = await bootstrap_bundled_agent_envelopes(
                    CapabilityEnvelopeService(get_pool()),
                    backoffice_state.agent_registry,
                )
                if _minted:
                    _log.info(
                        "Backoffice: bundled-agent envelopes minted: %s",
                        ", ".join(_minted),
                    )
                else:
                    _log.info(
                        "Backoffice: bundled-agent envelopes already present "
                        "or no bundled agents registered"
                    )
            except Exception as _be_exc:  # noqa: BLE001 — see rationale above
                _log.exception(
                    "Backoffice: bundled-agent envelope bootstrap FAILED (%s) "
                    "— bundled agent ingress fronts will DENY "
                    "server_not_onboarded (fail-closed) until the next boot",
                    _be_exc,
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
    # inactive-account disable (v2.23.3, FedRAMP AC-2(F2) / LU-YSG-002),
    # and SoD cross-store conflict audit (v2.24.1, Iris #96, NIST AC-5).
    scheduler = None
    try:
        import asyncio
        import logging as _sched_log
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from yashigani.licensing.expiry_monitor import check_and_alert_licence_expiry
        from yashigani.licensing.grace_period import emit_grace_period_audit
        from yashigani.backoffice.inactive_account_task import run_inactive_account_disable
        from yashigani.backoffice.sod_conflict_audit_task import run_sod_conflict_audit

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
        # SoD cross-store conflict audit — daily at 00:30 UTC (Iris #96 / v2.24.1)
        # Runs after midnight audit checkpoint (00:05). Emits IDENTITY_STORE_CONFLICT
        # events for any admin/user username or email collision found across stores.
        # NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4.
        scheduler.add_job(
            run_sod_conflict_audit,
            trigger="cron",
            hour=0,
            minute=30,
            id="sod_conflict_audit",
            replace_existing=True,
        )

        # TRACK1-F-04 — Langflow flow-discovery reconciler (60s interval).
        # Discovers flows created in langflow's own UI (not through Yashigani's
        # governed builder path) and creates INERT pending records so they
        # surface in the admin UI as "discovered — pending admin approval".
        # Guard: only register if langflow is in the enabled profiles; avoids
        # log noise on non-langflow installs (reconciler degrades gracefully on
        # network/store errors regardless, but skip registration is cleaner).
        _lf_profiles = {
            p.strip().lower()
            for p in (os.getenv("YASHIGANI_ENABLED_PROFILES", "") or "").split(",")
            if p.strip()
        }
        if "langflow" in _lf_profiles:
            from yashigani.backoffice.langflow_reconciler import (  # noqa: PLC0415
                run_langflow_discovery as _run_lf_discovery,
            )
            _lf_log = _sched_log.getLogger("yashigani.backoffice.langflow_reconciler")

            def _langflow_discovery_job() -> None:
                """Sync scheduler wrapper: wire store/writer then run reconciler."""
                from yashigani.backoffice.state import (  # noqa: PLC0415
                    backoffice_state as _bs,
                )
                try:
                    import redis as _redis_lf  # noqa: PLC0415
                    from yashigani.gateway._redis_url import (  # noqa: PLC0415
                        build_redis_url as _build_lf_redis_url,
                    )
                    from yashigani.mcp._durable_registry import (  # noqa: PLC0415
                        DurableMcpRegistryStore as _LfRegistryStore,
                    )
                    _lf_redis_url = _build_lf_redis_url(
                        3,
                        use_tls=os.getenv("REDIS_USE_TLS", "true").lower() == "true",
                        secrets_dir=os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets"),
                        client_cert_name="backoffice_client",
                    )
                    _lf_redis = _redis_lf.from_url(_lf_redis_url, decode_responses=False)
                    _lf_store = _LfRegistryStore(_lf_redis)
                except Exception as _lf_store_exc:  # noqa: BLE001
                    _lf_log.warning(
                        "langflow-reconciler-job: registry store unavailable (%s) "
                        "— skipping this run (TRACK1-F-04)", _lf_store_exc,
                    )
                    return
                _run_lf_discovery(
                    registry_store=_lf_store,
                    audit_writer=_bs.audit_writer,
                )

            # max_instances=1: if a tick takes longer than 60 s (e.g. langflow
            # has many flows), APScheduler skips the next tick rather than
            # stacking concurrent runs (Laura F9 overlap guard).
            scheduler.add_job(
                _langflow_discovery_job,
                trigger="interval",
                seconds=60,
                id="langflow_flow_discovery",
                replace_existing=True,
                max_instances=1,
            )

        scheduler.start()
        # Fire all immediately so the first check happens at startup
        asyncio.ensure_future(check_and_alert_licence_expiry())
        asyncio.ensure_future(emit_grace_period_audit())
        asyncio.ensure_future(run_inactive_account_disable())
        asyncio.ensure_future(run_sod_conflict_audit())
        if "langflow" in _lf_profiles:
            # Sync job — run in the default executor so the event loop stays
            # responsive.  asyncio.to_thread() is Python 3.9+ (Yashigani ≥3.12).
            asyncio.ensure_future(asyncio.to_thread(_langflow_discovery_job))
    except ImportError:
        pass  # apscheduler not installed — expiry alerts + inactive-disable disabled
    except Exception as exc:
        import logging

        logging.getLogger(__name__).warning("Could not start backoffice scheduler: %s", exc)

    # (OPA-PERSIST): re-sync OPA from the durable Redis-backed stores at the END of
    # lifespan startup — NOT in _bootstrap(), which runs at module import before the internal-PKI
    # client is ready (it fails with "no bootstrap_token_sha256 in the manifest"). OPA holds its
    # data documents in memory ONLY, so an OPA (or upgrade) restart drops them even though the
    # stores persist to Redis db/3 — leaving OPA empty until the next mutation. Re-pushing here
    # recovers OPA's view from the durable stores on every deploy/upgrade/restart. Best-effort with
    # retries; the data is safe in Redis, so a transient OPA-not-ready never blocks startup.
    import asyncio  # noqa: PLC0415 — local; the await sleep below must not depend on the
    #                                 scheduler block having imported it.
    _osync_log = _logging.getLogger("yashigani.backoffice.lifespan")

    # --- RBAC + agents data document (data.yashigani.rbac / .agents) ---
    try:
        _rbac_store = backoffice_state.rbac_store
        if _rbac_store is not None:
            from yashigani.rbac.opa_push import push_rbac_data
            _grp_n = len(_rbac_store.list_groups())
            for _attempt in range(1, 4):
                try:
                    push_rbac_data(
                        _rbac_store,
                        backoffice_state.opa_url,
                        agent_registry=backoffice_state.agent_registry,
                    )
                    _osync_log.info(
                        "OPA-PERSIST: re-synced OPA from RBAC store on startup (%d group(s))", _grp_n
                    )
                    break
                except Exception as _push_exc:
                    if _attempt < 3:
                        await asyncio.sleep(2)
                    else:
                        _osync_log.warning(
                            "OPA-PERSIST: RBAC startup re-sync failed after 3 attempts (%s) — groups "
                            "remain in Redis; OPA will sync on next mutation", _push_exc
                        )
    except Exception as _outer_exc:
        _osync_log.warning("OPA-PERSIST: RBAC startup re-sync skipped (%s)", _outer_exc)

    # #16 (OPA Phase 2): re-push client-policy bindings to OPA on startup (OPA holds
    # data in memory only). SEPARATE /v1/data/client_bindings namespace — does not
    # touch the rbac push above. Same retry pattern; failure is non-fatal (bindings
    # stay durable in Redis and re-push on the next mutation).
    try:
        _binding_store = backoffice_state.binding_store
        if _binding_store is not None:
            from yashigani.policy_bindings.opa_push import push_bindings_data
            _bsync_log = _logging.getLogger("yashigani.backoffice.lifespan")
            _bind_n = len(_binding_store.list())
            for _battempt in range(1, 4):
                try:
                    push_bindings_data(_binding_store, backoffice_state.opa_url)
                    _bsync_log.info(
                        "OPA-PERSIST: re-synced client-policy bindings on startup (%d binding(s))",
                        _bind_n,
                    )
                    break
                except Exception as _bpush_exc:
                    if _battempt < 3:
                        await asyncio.sleep(2)
                    else:
                        _bsync_log.warning(
                            "OPA-PERSIST: binding re-sync failed after 3 attempts (%s) — bindings "
                            "remain in Redis; OPA will sync on next mutation", _bpush_exc
                        )
    except Exception as _bouter_exc:
        _logging.getLogger("yashigani.backoffice.lifespan").warning(
            "OPA-PERSIST: binding re-sync skipped (%s)", _bouter_exc
        )

    # Track B1 (model-RBAC): reconcile model allocations from the Postgres durable
    # mirror into Redis db/3 — SAME drift class as the agent-reg reconcile below.
    # Redis db/3 has NO persistence; a `docker compose up -d redis` recreate (or a
    # redis restart) wipes every allocation and model RBAC silently stops enforcing
    # until the next admin mutation. This re-hydrates Postgres → Redis db/3 on every
    # boot. Idempotent; existing Redis allocations win. MUST run BEFORE the OPA
    # allocation re-sync below so OPA sees the restored set.
    try:
        _alloc_store = backoffice_state.model_allocation_store
        _alloc_durable = getattr(_alloc_store, "_durable", None) if _alloc_store else None
        if _alloc_store is not None and _alloc_durable is not None:
            from yashigani.models.allocation_durable_store import (
                reconcile_allocations_from_durable,
            )
            reconcile_allocations_from_durable(_alloc_store, _alloc_durable)
    except Exception as _arec_exc:
        _logging.getLogger("yashigani.backoffice.lifespan").error(
            "ALLOC-RECONCILE: startup reconcile FAILED (%s) — allocations may be "
            "absent until the next admin mutation", _arec_exc
        )

    # Track B1 (model-RBAC): re-sync the model-allocation document to OPA from the
    # durable Redis db/3 store on startup. OPA holds data in memory only, so an OPA
    # restart drops the allocation document; the gateway enforces from the durable
    # store directly (so enforcement is unaffected), but re-pushing keeps OPA's
    # inspectable view consistent. SEPARATE /v1/data/yashigani/allocations namespace
    # — does not touch the rbac push above. Non-fatal (allocations stay durable in
    # Redis and re-push on the next mutation).
    try:
        _alloc_store = backoffice_state.model_allocation_store
        if _alloc_store is not None:
            from yashigani.models.opa_push import push_allocations_data
            _async_log = _logging.getLogger("yashigani.backoffice.lifespan")
            _alloc_n = len(_alloc_store.list_all())
            for _aattempt in range(1, 4):
                try:
                    push_allocations_data(_alloc_store, backoffice_state.opa_url)
                    _async_log.info(
                        "OPA-PERSIST: re-synced model allocations on startup (%d allocation(s))",
                        _alloc_n,
                    )
                    break
                except Exception as _apush_exc:
                    if _aattempt < 3:
                        await asyncio.sleep(2)
                    else:
                        _async_log.warning(
                            "OPA-PERSIST: allocation re-sync failed after 3 attempts (%s) — "
                            "allocations remain in Redis; OPA will sync on next mutation",
                            _apush_exc,
                        )
    except Exception as _aouter_exc:
        _logging.getLogger("yashigani.backoffice.lifespan").warning(
            "OPA-PERSIST: allocation re-sync skipped (%s)", _aouter_exc
        )

    # ISSUE-AGENT-REG-DURABILITY (Iris, 2026-06-10): reconcile the agent registry
    # from the durable Postgres mirror into Redis db/3 — SAME drift class as the
    # OPA re-push above. @agent registrations live in Redis db/3, which has NO
    # persistence (appendonly no / save ""); a `docker compose up -d redis`
    # recreate wipes them all and the gateway returns agent_not_found with zero
    # operator signal. register_agent_bundles() only runs at install, so they
    # never self-heal. This re-pushes Postgres → Redis db/3 on every boot,
    # DIRECTLY (no admin API, no admin password — self-heals even without the
    # install-path service account). Idempotent; existing Redis entries win.
    try:
        _agent_reg = backoffice_state.agent_registry
        _agent_durable = getattr(_agent_reg, "_durable", None) if _agent_reg else None
        if _agent_reg is not None and _agent_durable is not None:
            from yashigani.agents.reconciler import reconcile_agents_from_durable
            await reconcile_agents_from_durable(_agent_reg, _agent_durable)
        else:
            _logging.getLogger("yashigani.backoffice.lifespan").warning(
                "AGENT-RECONCILE: agent_registry or durable store not wired — "
                "agents will NOT auto-restore after a redis recreate"
            )
    except Exception as _areconcile_exc:
        # Fail-loud but non-blocking: backoffice must still start so the operator
        # can investigate; the gateway also runs this reconcile independently.
        _logging.getLogger("yashigani.backoffice.lifespan").error(
            "AGENT-RECONCILE: startup reconcile FAILED (%s) — @agent routes may "
            "return agent_not_found until the registry is restored", _areconcile_exc
        )

    # TRACK1-F-04 RCA-2 — post-reconcile bundled-envelope bootstrap (ordering fix).
    #
    # The FIRST bootstrap pass (inside `if db_dsn:`, ~40 lines into lifespan)
    # runs with a potentially-empty agent registry: Redis db/3 has NO persistence
    # (appendonly no / save "") so a container/Docker-Desktop restart wipes all
    # registered agents from db/3 BEFORE the first bootstrap fires.
    #
    # reconcile_agents_from_durable (immediately above) re-pushes any agents
    # present in the durable Postgres mirror back into Redis db/3.  Running
    # bootstrap a SECOND TIME here guarantees that envelopes are always minted
    # after the registry is fully re-hydrated, regardless of the Redis state at
    # the start of the lifespan.
    #
    # Idempotent: bootstrap_bundled_agent_envelopes skips any ACTIVE envelope.
    # Same non-fatal SOP-1 exception rationale as the first pass: the failure
    # mode is fail-closed (verify-mcp keeps denying until next boot), so a
    # transient DB blip MUST NOT abort the lifespan.
    if db_dsn:
        try:
            from yashigani.backoffice.bundled_envelopes import (  # noqa: PLC0415
                bootstrap_bundled_agent_envelopes as _bootstrap_post_reconcile,
            )
            from yashigani.mcp.envelope_service import (  # noqa: PLC0415
                CapabilityEnvelopeService as _CES2,
            )
            _minted_post = await _bootstrap_post_reconcile(
                _CES2(get_pool()),
                backoffice_state.agent_registry,
            )
            if _minted_post:
                _log.info(
                    "Backoffice: bundled-agent envelopes minted (post-reconcile pass): %s",
                    ", ".join(_minted_post),
                )
        except Exception as _be2_exc:  # noqa: BLE001 — see SOP-1 rationale, line ~483
            _log.error(
                "Backoffice: post-reconcile bundled-envelope bootstrap FAILED (%s) "
                "— bundled ingress fronts remain fail-closed until the next boot",
                _be2_exc,
            )

    # --- Document-enforcement policy matrix (data.yashigani.document) — 2.26 ---
    # Same persistence + re-push pattern as RBAC, targeting the document sub-tree
    # so the production rego (policy/document.rego) evaluates the operator's live
    # matrix after any policy-container restart.
    try:
        _doc_store = backoffice_state.document_policy_store
        if _doc_store is not None:
            from yashigani.documents.opa_push import push_document_data
            _pol_n = len(_doc_store.list_policies())
            for _attempt in range(1, 6):
                try:
                    push_document_data(_doc_store, backoffice_state.opa_url)
                    _osync_log.info(
                        "OPA-PERSIST: re-synced OPA from document policy store on startup "
                        "(%d policy(ies))", _pol_n
                    )
                    break
                except Exception as _push_exc:
                    if _attempt < 5:
                        await asyncio.sleep(3)
                    else:
                        _osync_log.warning(
                            "OPA-PERSIST: document startup re-sync failed after 5 attempts (%s) — "
                            "policies remain in Redis; OPA will sync on next mutation", _push_exc
                        )
    except Exception as _outer_exc:
        _osync_log.warning("OPA-PERSIST: document startup re-sync skipped (%s)", _outer_exc)

    # B1 follow-on (2.25.5) — IdentityDurableStore startup reconcile.
    # Re-hydrates identities from Postgres into Redis db/3 if they are absent.
    # Protects against volume-deletion (beyond Su's AOF recreate fix).
    try:
        _id_reg = getattr(backoffice_state, "identity_registry", None)
        _id_durable = getattr(_id_reg, "_durable", None) if _id_reg else None
        if _id_reg is not None and _id_durable is not None:
            from yashigani.identity.durable_store import reconcile_identities_from_durable
            reconcile_identities_from_durable(_id_reg, _id_durable)
        else:
            _logging.getLogger("yashigani.backoffice.lifespan").warning(
                "IDENTITY-RECONCILE: identity_registry or durable store not wired — "
                "identities will NOT auto-restore after a volume-deletion"
            )
    except Exception as _ireconcile_exc:
        _logging.getLogger("yashigani.backoffice.lifespan").error(
            "IDENTITY-RECONCILE: startup reconcile FAILED (%s) — identities may be "
            "absent from Redis until restored manually", _ireconcile_exc
        )

    # LAURA-4.0-S1-001 (MEDIUM): normalise stale email/slug scope_ids in policy
    # bindings to the canonical idnt_ PK so they actually enforce.
    # MUST run AFTER identity reconcile (above) so the full registry is in Redis
    # before we attempt slug/email lookups.  If any bindings are rewritten the
    # corrected document is re-pushed to OPA immediately (no wait for next mutation).
    try:
        _brid_store = backoffice_state.binding_store
        _brid_registry = getattr(backoffice_state, "identity_registry", None)
        if _brid_store is not None and _brid_registry is not None:
            from yashigani.policy_bindings.reconcile import reconcile_binding_scope_ids
            _brid_result = reconcile_binding_scope_ids(
                binding_store=_brid_store,
                identity_registry=_brid_registry,
                opa_url=backoffice_state.opa_url,
                audit_writer=backoffice_state.audit_writer,
            )
            if _brid_result["rewritten"] > 0 or _brid_result["unresolvable"] > 0:
                _logging.getLogger("yashigani.backoffice.lifespan").warning(
                    "BINDING-RECONCILE: %d stale binding(s) rewritten to idnt_ PK, "
                    "%d unresolvable (scope_id cannot be resolved — see audit log). "
                    "OPA re-pushed: %s (LAURA-4.0-S1-001)",
                    _brid_result["rewritten"],
                    _brid_result["unresolvable"],
                    _brid_result["opa_re_pushed"],
                )
            else:
                _logging.getLogger("yashigani.backoffice.lifespan").info(
                    "BINDING-RECONCILE: all %d human-scoped binding(s) already use "
                    "idnt_ PKs — no rewrites needed (LAURA-4.0-S1-001)",
                    _brid_result["already_pk"],
                )
        else:
            _logging.getLogger("yashigani.backoffice.lifespan").warning(
                "BINDING-RECONCILE: binding_store or identity_registry not wired — "
                "stale scope_id normalisation skipped (LAURA-4.0-S1-001)"
            )
    except Exception as _brid_exc:
        _logging.getLogger("yashigani.backoffice.lifespan").error(
            "BINDING-RECONCILE: startup reconcile FAILED (%s) — stale email/slug "
            "bindings may not enforce until the next redeploy (LAURA-4.0-S1-001)",
            _brid_exc,
        )

    # ISSUE-USER-PLANE-DURABILITY (4.0): wire the user-plane durable store and
    # run the startup reconciler. ua:* and wf:* keys in Redis db/3 are volatile
    # (appendonly no / save ""); a Redis recreate loses all user agents, memory
    # blocks, and workflow definitions. This mirrors the AgentRegistry pattern:
    # dual-write to Postgres on every mutation + reconcile Postgres → Redis on
    # every boot. Degrade-safe: if the store cannot connect, the routes continue
    # Redis-only and user data is not restored (but nothing crashes).
    try:
        from yashigani.agents.user_plane_durable_store import UserPlaneDurableStore
        backoffice_state.user_plane_durable = UserPlaneDurableStore()
        _logging.getLogger("yashigani.backoffice.lifespan").info(
            "USER-PLANE-DURABLE: UserPlaneDurableStore wired"
        )
    except Exception as _upd_init_exc:
        _logging.getLogger("yashigani.backoffice.lifespan").error(
            "USER-PLANE-DURABLE: failed to construct UserPlaneDurableStore (%s) — "
            "user-plane data will NOT be mirrored to Postgres this session", _upd_init_exc
        )

    try:
        _upd = getattr(backoffice_state, "user_plane_durable", None)
        _upd_ir = getattr(backoffice_state, "identity_registry", None)
        _upd_redis = getattr(_upd_ir, "_r", None) if _upd_ir else None
        if _upd is not None and _upd_redis is not None:
            from yashigani.agents.user_plane_reconciler import reconcile_user_plane_from_durable
            _ua, _mem, _wf = await reconcile_user_plane_from_durable(_upd_redis, _upd)
            if _ua or _mem or _wf:
                _logging.getLogger("yashigani.backoffice.lifespan").warning(
                    "USER-PLANE-RECONCILE: restored %d agents, %d memories, %d workflows "
                    "from Postgres into Redis db/3", _ua, _mem, _wf,
                )
            else:
                _logging.getLogger("yashigani.backoffice.lifespan").info(
                    "USER-PLANE-RECONCILE: Redis db/3 already in sync (0 entities restored)"
                )
        else:
            _logging.getLogger("yashigani.backoffice.lifespan").warning(
                "USER-PLANE-RECONCILE: skipped — user_plane_durable or Redis client not wired"
            )
    except Exception as _upd_rec_exc:
        _logging.getLogger("yashigani.backoffice.lifespan").error(
            "USER-PLANE-RECONCILE: startup reconcile FAILED (%s) — user agents/memories/"
            "workflows may be absent from Redis until re-created", _upd_rec_exc
        )

    yield

    # Shutdown
    if scheduler is not None:
        scheduler.shutdown(wait=False)
    # v2.25.2 — drain + stop the DB audit sink so in-flight events flush, and
    # stop the daily checkpoint scheduler.  Both are best-effort + never raise.
    try:
        from yashigani.audit.sinks import stop_postgres_audit_sink
        stop_postgres_audit_sink(backoffice_state.db_audit_sink)
    except Exception:
        pass
    _ckpt = getattr(backoffice_state, "audit_checkpoint_scheduler", None)
    if _ckpt is not None:
        try:
            _ckpt.stop(wait=False)
        except Exception:
            pass


def create_backoffice_app() -> FastAPI:
    app = FastAPI(
        title="Yashigani Backoffice",
        version="2.1.0",
        # Disabled at root — schema and docs are mounted at /admin/ paths below,
        # behind admin session auth (v2.23.4: re-enable OpenAPI behind auth).
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
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
        # X-Frame-Options: DENY — emitted by Caddy (header @not_embed); removed
        # here to prevent duplicate headers (LAURA-411-006).
        # X-XSS-Protection removed — deprecated, removed from modern browsers, can
        # introduce vulns; CSP (below) is the correct control (LAURA-411-005).
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "no-referrer"
        # ZAP 10015/10049: Authenticated/sensitive dynamic responses must not be
        # stored in any cache.  Fingerprinted static assets (/static/*) are
        # intentionally excluded — they carry content-hashed filenames and are
        # safe to cache.
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        # CSP: strict for all pages — no inline scripts or styles allowed.
        # ASVS 3.4.3: object-src 'none' + base-uri 'none'; 3.4.7: report-uri.
        # N2 (2.25.5): some routes (ReDoc) need a scoped CSP that adds
        # worker-src blob: and style-src 'unsafe-inline' for Redoc's Web Worker
        # and Shadow DOM inline styles.  Those routes set their CSP directly on
        # the response.  If a per-route CSP is already present, preserve it
        # rather than overwriting it with the strict default.
        _strict_csp = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; report-uri /admin/csp-report; report-to default"
        if "content-security-policy" not in response.headers:
            response.headers["Content-Security-Policy"] = _strict_csp
        # Permissions-Policy: resolve per admin identity (3.0).
        # Resolve from the capability policy store; fall back silently if the
        # store is not yet wired (e.g. dev/test without Redis).
        from yashigani.backoffice.state import backoffice_state  # noqa: PLC0415
        _cap_store = getattr(backoffice_state, "capability_policy_store", None)
        if _cap_store is not None:
            try:
                _pp_email: str | None = None
                _session_token = request.cookies.get("__Host-yashigani_admin_session")
                if _session_token and backoffice_state.session_store is not None:
                    _sess = backoffice_state.session_store.get(_session_token)
                    if _sess is not None:
                        _pp_email = _sess.account_id
                from yashigani.capability_policy.resolver import resolve_policy as _resolve_cap
                from yashigani.capability_policy.header import render_permissions_policy as _render_pp
                _resolved = _resolve_cap(
                    _pp_email,
                    backoffice_state.rbac_store,
                    _cap_store,
                )
                response.headers["Permissions-Policy"] = _render_pp(_resolved)
            except Exception as _pp_exc:
                import logging as _pplog
                _pplog.getLogger(__name__).debug(
                    "cap_policy: backoffice security_headers failed: %s", _pp_exc
                )
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
        # LU-AMEND-02/03: manifest YAML may be up to 1 MB (hard limit in service);
        # give ceremony endpoint 1.1 MB to accommodate the JSON envelope overhead.
        ("/admin/manifest-registrations/ceremony", 1_100 * 1024),
        # Manifest list/show are GET-only; cap any accidental POST body at 1 kB.
        ("/admin/manifest-registrations", 1 * 1024),
        ("/admin/users", 4 * 1024),  # username + opt email
        ("/admin/license", 4 * 1024),  # confirm flag or small LIC
        ("/api/v1/license", 256),  # status GET only, no body
        ("/api/v1/admin/secrets", 256),  # secret name only (ASVS 4.3.1)
        ("/api/v1/admin/auth/hibp", 512),  # HIBP key (UUID ≤128 + envelope)
        ("/api/v1/admin/pki", 256),        # PKI rotate body (service name in URL, no body)
        ("/admin/ratelimit", 8 * 1024),
        ("/admin/api/permissions", 16 * 1024),
        ("/admin/api/capability-policy", 8 * 1024),
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
        # 4.0 Phase 2: user document upload cap.  Caddy also enforces 10 MB;
        # this middleware is belt-and-braces BEFORE the upload handler runs.
        # 4.0 Phase 2 JSON upload: the body contains the file as base64
        # (content_base64 field). base64 inflates by ~4/3, so a 10 MB file
        # sends ~13.3 MB of JSON. Set the pre-check to 14 MB to give headroom.
        # The handler enforces the decoded 10 MB limit post-decode.
        ("/user/documents", 14 * 1024 * 1024),  # 14 MB — covers base64 of 10 MB file
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

    # YSG-RISK-122 self-heal: bounded lazy reconnect for RBAC/agent-registry/
    # permission-store/budget Redis clients that failed to connect at startup
    # (e.g. k8s boot-order race — yashigani-backoffice scheduled before
    # yashigani-redis-0, see backoffice/redis_selfheal.py docstring for full
    # context). Runs before every /admin/* request, ahead of routing (every
    # `@app.middleware("http")` function here runs before call_next() reaches
    # the router, regardless of registration order relative to its siblings)
    # — so a successful reconnect is visible to the route handler on the SAME
    # request that triggered it. No-ops (pure None-checks, zero Redis
    # round-trips) once the stack is healthy, and is bounded by a per-stack
    # cooldown while unhealthy so an outage cannot turn into a reconnect storm.
    @app.middleware("http")
    async def redis_selfheal_middleware(request: Request, call_next):
        if request.url.path.startswith("/admin"):
            from yashigani.backoffice.redis_selfheal import maybe_selfheal
            await maybe_selfheal()
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

    # ── Yashigani 4.0 shared front-end layer (additive) ─────────────────────
    # The hardened classes-only / Trusted-Types / safe-render layer that the
    # 4.0 user UI (Phase 2) and the rebuilt admin UI (Phase 6) import. JS/CSS
    # are served from the /static/ui4/ mount above; this route serves the
    # shared-layer canary self-test page (safe-render + XSS / split-chunk /
    # decode HARD-contract). Admin-gated — it is a verification surface, not an
    # end-user page. Production CSP/Trusted-Types headers are Su's Caddy domain
    # (feat/4.0-csp-vendoring); the canary carries its own CSP meta so the TT
    # pipeline is exercised even before those headers land.
    _ui4_canary = _static_dir / "ui4" / "canary" / "canary.html"
    if _ui4_canary.exists():
        from yashigani.backoffice.middleware import (
            require_admin_session as _require_admin_session_ui4,
        )

        @app.get("/ui4/canary", include_in_schema=False)
        async def ui4_canary_page(
            session=Depends(_require_admin_session_ui4),  # noqa: ARG001
        ) -> HTMLResponse:
            return HTMLResponse(_ui4_canary.read_text(encoding="utf-8"))

    # ── Yashigani 4.0 user-facing app (Phase 2) — OpenWebUI replacement ──────
    # The user-tier Lit app served at /chat (assets under /static/ui4/). Built on
    # the shared layer above. A lightweight session-cookie pre-flight avoids
    # serving the SPA shell to unauthenticated clients (mirrors the /admin/ shell
    # check, ASVS V1.4.1) — cryptographic session validation happens on every
    # subsequent /user/* and /v1/* API call. Production CSP/Trusted-Types headers
    # are Su's Caddy domain (feat/4.0-csp-vendoring); the page carries its own CSP
    # meta so the safe-render/TT pipeline is enforced even before those land.
    _ui4_chat = _static_dir / "ui4" / "user" / "chat.html"
    if _ui4_chat.exists():

        @app.get("/chat", include_in_schema=False)
        async def ui4_user_chat_page(request: Request):
            if not request.cookies.get("__Host-yashigani_session"):
                return RedirectResponse(url="/login?next=/chat", status_code=302)
            return HTMLResponse(_ui4_chat.read_text(encoding="utf-8"))

    # ── Yashigani 4.0 ADMIN app — Lit admin is now the primary /admin/ UI ───────
    # Phase 6 flip: the new Lit admin is canonical at /admin/. The old vanilla-JS
    # admin (dashboard.html) is available as a fallback at /admin-legacy/ during
    # the live-verify transition (do NOT delete yet). /admin4/ now redirects to
    # /admin/ for back-compat with any bookmarked links from Wave-1 testing.
    #
    # Assets under /static/ui4/; page carries its own strict CSP + Trusted-Types
    # meta so the safe-render/TT pipeline is enforced independently of Caddy.
    # Admin-session-gated by a lightweight cookie pre-flight (ASVS V1.4.1);
    # cryptographic session validation happens on every subsequent /dashboard/*
    # and /admin/* API call (SessionStore.get()).
    _ui4_admin = _static_dir / "ui4" / "admin" / "admin.html"
    if _ui4_admin.exists():

        @app.get("/admin/", include_in_schema=False)
        async def ui4_admin_page(request: Request):
            # 4.0: Lit admin is primary at /admin/. Cookie pre-flight mirrors
            # the old admin_dashboard_page check (ASVS V1.4.1).
            _admin_cookies = (
                "__Host-yashigani_admin_session",
                "__Host-yashigani_session",
            )
            if not any(request.cookies.get(k) for k in _admin_cookies):
                return RedirectResponse(url="/admin/login?next=/admin/", status_code=302)

            # YSG-RISK-176(admin-shell): a session cookie's mere PRESENCE used
            # to be sufficient to receive the 200 admin shell — including a
            # perfectly valid USER-tier session. Every underlying /admin/*
            # API call already correctly 403s for a non-admin caller
            # (real per-action authz was never bypassed), but the SHELL
            # itself 200'd for any authenticated session — enumeration-only,
            # but still confirms the admin UI's existence/asset surface to a
            # caller who should not be able to tell. Resolve the session and
            # require admin tier BEFORE serving the shell, mirroring
            # middleware.require_admin_session's tier check exactly (same
            # account_tier == "admin" condition, including the
            # admin_password_change_required tier, which is also correctly
            # denied here since it is != "admin").
            from yashigani.backoffice.middleware import _resolve_token, get_session_store

            token = _resolve_token(request)
            store = get_session_store()
            session = store.get(token) if token else None
            if session is None or session.account_tier != "admin":
                return JSONResponse(
                    status_code=403,
                    content={"error": "insufficient_tier"},
                )

            return HTMLResponse(_ui4_admin.read_text(encoding="utf-8"))

        @app.get("/admin4/", include_in_schema=False)
        async def ui4_admin4_alias(request: Request):
            # 4.0: /admin4/ was the Wave-1 parallel route. Now redirects to the
            # canonical /admin/ — preserves bookmarks from the transition period.
            return RedirectResponse(url="/admin/", status_code=302)

    # ── Auth-gated OpenAPI schema + Swagger UI (v2.23.4) ────────────────────
    #
    # OpenAPI schema and Swagger/ReDoc UIs are NOT served at the root
    # (openapi_url=None above).  Instead they live under /admin/ so they
    # sit behind the existing admin-area authentication posture:
    #
    #   GET /admin/openapi.json  — raw OpenAPI 3.x JSON (admin session required)
    #   GET /admin/api-docs      — Swagger UI (admin session required)
    #   GET /admin/api-redoc     — ReDoc UI   (admin session required)
    #
    # Swagger UI JS+CSS are self-hosted from /static/swagger-ui/ (downloaded
    # from swagger-ui-dist@5.32.6) to satisfy strict-CSP (script-src 'self').
    # No cdn.jsdelivr.net or any third-party CDN is loaded.
    #
    # Auth dependency: yashigani.backoffice.middleware.require_admin_session —
    # same session-store-validated dependency used on all /admin/* API routes.
    # Unauthenticated requests → 401 (or 403 if wrong tier).
    # The uniform_admin_404_as_401 middleware also masks routing 404 as 401.
    from yashigani.backoffice.middleware import require_admin_session

    @app.get(
        "/admin/openapi.json",
        include_in_schema=False,
        dependencies=[Depends(require_admin_session)],
    )
    async def admin_openapi_schema():
        """Serve the OpenAPI schema behind admin session auth."""
        return JSONResponse(app.openapi())

    @app.get("/admin/api-docs", include_in_schema=False)
    async def admin_swagger_ui(
        session=Depends(require_admin_session),  # noqa: ARG001
    ) -> HTMLResponse:
        """Swagger UI — CSP-clean, no inline script (N2 fix).

        Assets are self-hosted from /static/swagger-ui/ (no CDN).
        Init logic lives in swagger-ui-init.js (same-origin), replacing the
        inline <script>const ui = SwaggerUIBundle({...})</script> that
        FastAPI's get_swagger_ui_html() emits and that strict CSP blocks.
        """
        return HTMLResponse(
            _swagger_ui_html(
                openapi_url="/admin/openapi.json",
                title="Yashigani Backoffice — API Reference",
                swagger_js_url="/static/swagger-ui/swagger-ui-bundle.js",
                swagger_css_url="/static/swagger-ui/swagger-ui.css",
                swagger_init_js_url="/static/swagger-ui/swagger-ui-init.js",
                favicon_url="/static/swagger-ui/favicon.png",
            )
        )

    @app.get("/admin/api-redoc", include_in_schema=False)
    async def admin_redoc_ui(
        session=Depends(require_admin_session),  # noqa: ARG001
    ) -> HTMLResponse:
        """ReDoc UI — CSP-clean, no inline script or style (N2 fix).

        Assets are self-hosted from /static/swagger-ui/ (no CDN).
        The <redoc spec-url="..."> web-component attribute replaces any inline
        init call.  The response carries a scoped Content-Security-Policy that
        adds 'worker-src blob: child-src blob:' because Redoc spawns a Web
        Worker internally via blob: URL.  All other admin routes retain the
        strict CSP unchanged.
        """
        return _redoc_html(
            openapi_url="/admin/openapi.json",
            title="Yashigani Backoffice — API Reference (ReDoc)",
            redoc_js_url="/static/swagger-ui/redoc.standalone.js",
            favicon_url="/static/swagger-ui/favicon.png",
        )

    # Admin UI — HTML pages
    _templates_dir = pathlib.Path(__file__).parent / "templates"
    if _templates_dir.exists():
        _templates = Jinja2Templates(directory=str(_templates_dir))
        # Single source of truth for the displayed version — no hardcoded
        # strings in templates. Bump yashigani.__version__ (== pyproject) only.
        from yashigani import __version__ as _ysg_version
        _templates.env.globals["yashigani_version"] = _ysg_version

        @app.get("/login", include_in_schema=False)
        async def user_login_page(request: Request):
            return _templates.TemplateResponse(request, "user_login.html")

        @app.get("/admin/login", include_in_schema=False)
        async def admin_login_page(request: Request):
            return _templates.TemplateResponse(request, "login.html")

        # 4.0: old vanilla-JS admin is now the LEGACY fallback at /admin-legacy/.
        # The new Lit admin is at /admin/ (registered above in the ui4_admin block).
        # Keep this route reachable during the live-verify transition; delete after
        # Wave-2 sign-off. Same session pre-flight as before (ASVS V1.4.1).
        @app.get("/admin-legacy/", include_in_schema=False)
        async def admin_legacy_page(request: Request):
            # ASVS V1.4.1: cookie pre-flight before serving the SPA shell.
            # Cryptographic validation happens on every /dashboard/* + /admin/* API call.
            _admin_cookies = (
                "__Host-yashigani_admin_session",
                "__Host-yashigani_session",
            )
            if not any(request.cookies.get(k) for k in _admin_cookies):
                return RedirectResponse(
                    url="/admin/login?next=/admin-legacy/",
                    status_code=302,
                )
            return _templates.TemplateResponse(request, "dashboard.html")

    # Routers
    app.include_router(auth_router, prefix="/auth", tags=["auth"])
    app.include_router(dashboard_router, prefix="/dashboard", tags=["dashboard"])
    app.include_router(accounts_router, prefix="/admin/accounts", tags=["admin-accounts"])
    app.include_router(users_router, prefix="/admin/users", tags=["user-accounts"])
    app.include_router(kms_router, prefix="/admin/kms", tags=["kms"])
    # YSG-RISK-142: audit_sinks_router MUST be registered BEFORE audit_router.
    # audit_sinks_router carries literal full paths (e.g.
    # POST /admin/audit/siem/config/test); audit.py's audit_router (mounted
    # with prefix /admin/audit) registers a path-PARAM route
    # POST /siem/{name}/test that is the same segment depth. Starlette/FastAPI
    # matches routes in registration order across the whole app, so whichever
    # router is added first "wins" a same-depth collision — with audit_router
    # first, POST /admin/audit/siem/config/test silently resolved to
    # test_siem_target(name="config") instead of the intended test_siem()
    # handler, making the SIEM-backend-config test endpoint unreachable.
    # Registering the literal-path router first restores the intended match;
    # the /siem/{name}/test named-target-test route in audit.py still matches
    # for every OTHER name value.
    app.include_router(audit_sinks_router, tags=["audit-sinks"])
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
    # OPA policy viewer (read-only) — lists/serves the Rego modules loaded in OPA
    from yashigani.backoffice.routes.policies import router as policies_router
    app.include_router(policies_router, prefix="/admin/policies", tags=["policies"])
    # #25 — dual-admin cloud-LLM risk-accepted override (propose/approve/revoke/status)
    from yashigani.backoffice.routes.cloud_override import router as cloud_override_router
    app.include_router(cloud_override_router, prefix="/admin/cloud-override", tags=["cloud-override"])
    app.include_router(alerts_router, prefix="/admin/alerts", tags=["alerts"])
    app.include_router(agent_bundles_router, prefix="/admin/agent-bundles", tags=["agent-bundles"])
    # v1.0 — Budget admin API
    from yashigani.backoffice.routes.budget import router as budget_router

    app.include_router(budget_router, tags=["budget"])

    # v2.1 — Model alias management + Sensitivity patterns
    app.include_router(models_router, prefix="/admin/models", tags=["models"])
    app.include_router(sensitivity_router, prefix="/admin/sensitivity", tags=["sensitivity"])
    # v2.26 — Document Enforcement admin surface (ships dark; flag-gated routes)
    app.include_router(documents_router, prefix="/admin/documents", tags=["documents"])
    # 3.0 — Capability-envelope re-approval admin surface (YSG-RISK-060)
    app.include_router(
        envelope_reapproval_router, prefix="/admin/mcp/envelopes", tags=["mcp-envelopes"]
    )
    # 4.0 — MCP Server Registry admin surface (list + import ceremony)
    app.include_router(
        mcp_servers_router, prefix="/admin/mcp/servers", tags=["mcp-servers"]
    )
    # v2.1 — SSO / OIDC login flow (no auth required — serves anonymous users)
    app.include_router(sso_router, prefix="/auth", tags=["sso"])

    # v2.2 — PII detection admin API
    from yashigani.backoffice.routes.pii import router as pii_router

    app.include_router(pii_router, prefix="/admin/pii", tags=["pii"])

    # 4.0 LAURA-V400-R2-001 — Dual-admin data-protection maker-checker
    app.include_router(
        dp_weaken_router,
        prefix="/admin/data-protection",
        tags=["data-protection"],
    )

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

    # v2.23.4 — Gap 4: user self-service Bearer issuance (/me/api-key*)
    # Routes carry /me/ prefix defined in the router itself (no extra prefix needed).
    app.include_router(me_router, tags=["me"])

    # v2.24.1 — LU-AMEND-02/03: manifest registration ledger + ceremony record
    # Routes carry /admin/manifest-registrations/ paths defined in the router itself.
    app.include_router(manifest_history_router, tags=["manifest-registry"])

    # v2.24.1 — admin-surfaces-all-runtime-settings: runtime settings admin API
    app.include_router(
        runtime_settings_router,
        prefix="/admin/runtime-settings",
        tags=["runtime-settings"],
    )

    # v0.9.0 — Phase 6: WebAuthn/Passkeys
    # webauthn_router carries its own full path segments (no prefix stripping needed)
    app.include_router(webauthn_router, tags=["webauthn"])
    # v0.9.0 — Phase 7: Operator Visibility
    app.include_router(events_router, prefix="/admin/events", tags=["events"])
    app.include_router(audit_search_router, prefix="/admin/audit", tags=["audit-search"])
    # v2.25.5 — R13: RBAC group source paths + HTTP method catalogue
    app.include_router(rbac_sources_router, prefix="/admin/rbac", tags=["rbac"])
    # v2.25.5 — R26: version check (opt-in egress)
    app.include_router(version_check_router, prefix="/admin/version", tags=["version"])
    # fix/medlow-findings — cloud provider API key management (KMS-backed)
    app.include_router(cloud_keys_router, tags=["cloud-keys"])

    # 3.0 — admin-configurable browser Permissions-Policy
    app.include_router(
        capability_policy_router,
        prefix="/admin/api/capability-policy",
        tags=["capability-policy"],
    )

    # 3.1 Phase 8 — unified permission grant admin API
    app.include_router(
        permissions_router,
        prefix="/admin/api/permissions",
        tags=["permissions"],
    )

    # 4.0 Letta agent capabilities — /user/agents, /user/memories, /user/skills
    # (RISK-097/108 scope-intersection; BOLA-enforced; require_user_session).
    #
    # PRECEDENCE (4.0 agent-builder): this router is included BEFORE user_ui_router
    # so that GET /user/agents resolves to the USER-CREATED agent list (ua_id
    # shape) consumed by the agent-builder surfaces — NOT the older Phase-2
    # registry-agents stub in user_ui.py (which shares the same path). FastAPI is
    # first-match-wins, so order is the deconfliction. The chat surface sources
    # its "agents to chat with" from GET /user/models (which returns both models
    # and registry agents), so it does not depend on the shadowed stub.
    from yashigani.backoffice.routes.user_agents import router as _user_agents_router
    app.include_router(_user_agents_router, tags=["user-agents"])

    # 4.0 Phase 2 — user-plane routes (OWUI replacement; RISK-100/112)
    # /chat + /agents + /builder + /workflows pages + /user/* data endpoints. All enforce
    # require_user_session. Mounted without a prefix so routes carry their own
    # /chat and /user/ paths. (NB: its GET /user/agents registry stub is now
    # shadowed by the agent-builder router above — see precedence note.)
    app.include_router(user_ui_router, tags=["user-ui"])

    # 4.0 Chat persistence — conversation + message CRUD (BOLA-enforced via
    # account_id scoping on every per-conversation query).
    app.include_router(user_conversations_router, tags=["user-conversations"])

    # 4.0 no-code workflow composer + run history (single router) —
    # POST /user/workflows/generate, POST/GET/PATCH/DELETE /user/workflows/{wf_id},
    # GET /user/workflows/{id}/runs. require_user_session + BOLA (EU AI Act Art.14 HITL);
    # runs read the WorkflowScheduler's Redis DB 6 (503 if scheduler unavailable).
    app.include_router(user_workflows_router, tags=["user-workflows"])

    # 4.0 admin workflow-oversight — GET/PATCH /admin/workflows/{wf_id}
    # Cross-user read + disable.  AdminSession on GETs; StepUpAdminSession on PATCH.
    # EU AI Act Art.14 HITL: disabling a governed workflow is a consequential action.
    app.include_router(admin_workflows_router, tags=["admin-workflows"])

    # 4.1 Phase B — Agent Policy Templates admin surface.
    # Routes carry their own /admin/agent-policies/ paths (no prefix stripping).
    # Step-up (StepUpAdminSession) on mutating ops; SPIFFE-gated per service_identities ACL.
    app.include_router(agent_policies_router, tags=["agent-policies"])

    # 4.0 Phase 2 — user-plane CSP violation report endpoint (Su's report-uri target).
    # Su's Caddy config for /chat and /user/* will set:
    #   report-uri /api/v1/csp-report
    # Unauthenticated — browsers cannot attach cookies to CSP report POSTs.
    # Same posture as the existing /admin/csp-report (already mounted at /admin).
    from yashigani.backoffice.routes.csp_report import router as _user_csp_report_router
    app.include_router(_user_csp_report_router, prefix="/api/v1", tags=["csp"])

    # LAURA-2255-007 (2026-06-14): declare AdminSessionCookie security scheme in the
    # OpenAPI schema and annotate all /scim/v2/* paths with the scheme reference.
    # Previously SCIM routes showed security:[] — they always required an admin session
    # but the requirement was invisible in the schema.  This is a cosmetic (schema-only)
    # fix; the actual enforcement is unchanged (require_admin_session dependency).
    _orig_openapi = app.openapi

    def _openapi_with_scim_security() -> dict:
        schema = _orig_openapi()
        # Inject the AdminSessionCookie security scheme into components once.
        components = schema.setdefault("components", {})
        security_schemes = components.setdefault("securitySchemes", {})
        security_schemes.setdefault("AdminSessionCookie", {
            "type": "apiKey",
            "in": "cookie",
            "name": "__Host-yashigani_admin_session",
            "description": (
                "Yashigani admin session cookie. Issued by POST /auth/session "
                "(admin-tier credentials + TOTP). All /admin/* and /scim/v2/* "
                "endpoints require this cookie."
            ),
        })
        # Add the security requirement to all SCIM paths.
        scim_security = [{"AdminSessionCookie": []}]
        for path, path_item in schema.get("paths", {}).items():
            if path.startswith("/scim/v2/"):
                for _method, operation in path_item.items():
                    if isinstance(operation, dict):
                        operation.setdefault("security", scim_security)
        # Cache the augmented schema so subsequent calls don't re-compute.
        app.openapi_schema = schema
        return schema

    app.openapi = _openapi_with_scim_security  # type: ignore[method-assign]

    return app
