"""
Yashigani Gateway — Reverse proxy for MCP servers and agentic AI systems.

Traffic flow:
  Client → [AuthN/Z] → [Inspection pipeline] → [OPA request check] → MCP server
                                 ↑                                          ↓
                        Credential masking via CHS          [Response inspection]
                        before any AI classifier call       [PII detection]
                                                            [OPA response check]
                                                                    ↓
                                                             Client (or 403/503)

All inbound requests are:
1. Authenticated via session cookie or API key
2. Inspected for credential exfiltration and prompt injection
3. Policy-checked via OPA on request leg (never cloud-delegated)
4. Forwarded to the upstream MCP server or discarded

Responses from MCP servers are:
5. Inspected by ResponseInspectionPipeline (when configured)
6. PII-scanned (when configured)
7. Policy-checked via OPA on response leg (GAP-002 / YSG-RISK-067 / v2.24.1)
8. Delivered to client or blocked (403 policy deny / 503 OPA unreachable)

Audit events are written for every request regardless of disposition.

Last updated: 2026-05-25T00:00:00+00:00
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import math
import os
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from yashigani.auth.spiffe import require_spiffe_id
from yashigani.pki.client import internal_httpx_client
from yashigani.audit.schema import PIIDetectedEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal service-mesh Bearer token
#
# YASHIGANI_INTERNAL_BEARER is a per-install-rotated secret that grants
# service-to-service identity (Open WebUI, in-mesh agents). It MUST be set
# by the installer (docker/secrets/yashigani_internal_bearer).  A missing or
# empty value fails closed at import time so a misconfigured deployment
# surfaces immediately rather than silently accepting any Bearer value.
#
# Use hmac.compare_digest() at every comparison site to avoid timing leaks.
# ---------------------------------------------------------------------------

def _load_internal_bearer() -> str:
    """Read YASHIGANI_INTERNAL_BEARER from env; raise RuntimeError if absent."""
    _val = os.environ.get("YASHIGANI_INTERNAL_BEARER", "")
    if not _val:
        raise RuntimeError(
            "YASHIGANI_INTERNAL_BEARER is not set. "
            "The gateway cannot start without a per-install internal service token. "
            "See docker/secrets/yashigani_internal_bearer."
        )
    return _val


# Cached at module load — fails fast if env-var is absent.
_INTERNAL_BEARER: str = _load_internal_bearer()


def _internal_bearer() -> str:
    """Return the cached internal Bearer constant."""
    return _INTERNAL_BEARER


_HOP_BY_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})


def _content_hash(content: str) -> str:
    """SHA-256 hex digest of a string — used for privacy-safe hashing."""
    return hashlib.sha256(content.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Gateway configuration
# ---------------------------------------------------------------------------

@dataclass
class GatewayConfig:
    upstream_base_url: str              # Target MCP server URL
    opa_url: str = "https://policy:8181"
    opa_policy_path: str = "/v1/data/yashigani/allow"
    request_timeout_seconds: float = 30.0
    max_request_body_bytes: int = 4 * 1024 * 1024  # 4 MB
    strip_response_headers: frozenset = frozenset()


# ---------------------------------------------------------------------------
# Gateway application factory
# ---------------------------------------------------------------------------

def create_gateway_app(
    config: GatewayConfig,
    inspection_pipeline=None,
    auth_service=None,
    chs=None,
    audit_writer=None,
    rate_limiter=None,
    rbac_store=None,
    agent_registry=None,
    jwt_inspector=None,
    endpoint_rate_limiter=None,
    response_cache=None,
    fasttext_backend=None,
    inference_logger=None,
    anomaly_detector=None,
    response_inspection_pipeline=None,  # v0.9.0 — ResponseInspectionPipeline | None
    extra_routers=None,  # v2.0 — additional routers to mount BEFORE catch-all
    ddos_protector=None,  # v2.2 — DDoSProtector | None
    pii_detector=None,   # v2.2 — PiiDetector | None
) -> FastAPI:
    """
    Create the Yashigani gateway FastAPI application.

    Parameters are injected at startup from the main application entrypoint.
    """
    _state = {
        "config": config,
        "inspection_pipeline": inspection_pipeline,
        "response_inspection_pipeline": response_inspection_pipeline,  # v0.9.0
        "auth_service": auth_service,
        "chs": chs,
        "audit_writer": audit_writer,
        "rate_limiter": rate_limiter,
        "rbac_store": rbac_store,
        "agent_registry": agent_registry,
        "jwt_inspector": jwt_inspector,
        "endpoint_rate_limiter": endpoint_rate_limiter,
        "response_cache": response_cache,
        "fasttext_backend": fasttext_backend,
        "inference_logger": inference_logger,
        "anomaly_detector": anomaly_detector,
        "ddos_protector": ddos_protector,  # v2.2
        "pii_detector": pii_detector,      # v2.2
        "http_client": None,
    }

    @asynccontextmanager
    async def _lifespan(app: FastAPI):
        # Layer B: load the per-install caddy_internal_hmac secret.
        # Must be the FIRST thing in startup so the module-level _caddy_secret
        # is populated before any request reaches CaddyVerifiedMiddleware.
        # Raises RuntimeError → uvicorn exits non-zero if secret is missing
        # (fail-closed per SOP 1 / CLAUDE.md §3).
        from yashigani.auth.caddy_verified import load_caddy_secret as _load_caddy_secret
        _load_caddy_secret()

        # Startup: create shared HTTP client for upstream proxying
        _state["http_client"] = httpx.AsyncClient(
            base_url=config.upstream_base_url,
            timeout=config.request_timeout_seconds,
            follow_redirects=False,
        )
        # Create Postgres async pool on the running event loop
        if os.environ.get("_YASHIGANI_DB_READY") == "1":
            try:
                from yashigani.db import create_pool
                await create_pool()
                logger.info("Postgres async pool created (lifespan)")
            except Exception as exc:
                logger.warning("Postgres pool creation failed in lifespan: %s", exc)
        yield
        # Shutdown: close the HTTP client and DB pool
        client = _state["http_client"]
        if client:
            await client.aclose()
        try:
            from yashigani.db import close_pool
            await close_pool()
        except Exception:
            pass

    app = FastAPI(
        title="Yashigani Gateway",
        version="2.1.0",
        # Disabled at root — schema and docs are mounted at explicit paths below,
        # behind identity auth (v2.23.4: re-enable OpenAPI behind auth).
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=_lifespan,
    )

    # Security headers
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # Internal health check — used by Caddy and container health probe
    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    # Internal Prometheus metrics endpoint — Caddy-gated with SPIFFE URI ACL.
    # EX-231-08 (v2.23.1): Prometheus must scrape via Caddy's :8444 internal
    # listener; Caddy validates the peer cert and sets X-SPIFFE-ID from the
    # URI SAN. require_spiffe_id enforces the allowlist from
    # service_identities.yaml endpoint_acls.
    @app.get(
        "/internal/metrics",
        dependencies=[Depends(require_spiffe_id("/internal/metrics"))],
    )
    async def internal_metrics():
        from fastapi.responses import PlainTextResponse
        try:
            from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
            return PlainTextResponse(
                generate_latest().decode("utf-8"),
                media_type=CONTENT_TYPE_LATEST,
            )
        except ImportError:
            return PlainTextResponse("# prometheus_client not installed\n")

    # Mount extra routers BEFORE the catch-all (e.g. /v1/* OpenAI-compat)
    for _router in (extra_routers or []):
        app.include_router(_router)

    # ── Auth-gated OpenAPI schema + Swagger UI (v2.23.4) ────────────────────
    #
    # OpenAPI schema and Swagger UI are gated behind identity resolution —
    # the same Bearer/X-Forwarded-User check used for /v1/* routes.
    # Anonymous requests (no resolved identity) → 401.
    # Mounted BEFORE the catch-all so they are not proxied upstream.
    #
    #   GET /openapi.json — raw OpenAPI 3.x JSON (requires valid Bearer)
    #   GET /docs         — Swagger UI        (requires valid Bearer)
    #
    # Swagger UI JS+CSS are self-hosted from /static/swagger-ui/
    # (swagger-ui-dist@5.32.6) — no CDN dependency, satisfies no-inline-js rule.
    import pathlib as _pathlib
    _gw_static_dir = _pathlib.Path(__file__).parent / "static"
    if _gw_static_dir.exists():
        from fastapi.staticfiles import StaticFiles as _StaticFiles
        app.mount("/static", _StaticFiles(directory=str(_gw_static_dir)), name="gw-static")

    def _require_gateway_identity(request: Request) -> dict:
        """FastAPI dependency: resolve identity like /v1/* routes.

        Reuses _resolve_identity from openai_router — same Bearer / SSO logic.
        Raises HTTP 401 when no identity resolves.
        """
        from yashigani.gateway.openai_router import _resolve_identity as _ri
        identity = _ri(request)
        if identity is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "authentication_required"},
            )
        return identity

    @app.get(
        "/openapi.json",
        include_in_schema=False,
        dependencies=[Depends(_require_gateway_identity)],
    )
    async def gateway_openapi_schema() -> JSONResponse:
        """Serve the OpenAPI schema behind identity auth."""
        return JSONResponse(app.openapi())

    @app.get("/docs", include_in_schema=False)
    async def gateway_swagger_ui(
        identity: dict = Depends(_require_gateway_identity),  # noqa: ARG001
    ) -> HTMLResponse:
        """Swagger UI — gated behind identity resolution (Bearer / SSO).

        Assets self-hosted from /static/swagger-ui/ (no CDN).
        """
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title="Yashigani Gateway — API Reference",
            swagger_js_url="/static/swagger-ui/swagger-ui-bundle.js",
            swagger_css_url="/static/swagger-ui/swagger-ui.css",
        )

    # Catch-all reverse proxy route
    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    async def proxy_request(path: str, request: Request) -> Response:
        return await _handle_request(request, path, _state)

    return app


# ---------------------------------------------------------------------------
# Core request handler
# ---------------------------------------------------------------------------

class _NullSpan:
    """No-op OTEL span context manager used when the tracer is unavailable."""
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def set_attribute(self, *args): pass


async def _handle_request(request: Request, path: str, state: dict) -> Response:
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    cfg: GatewayConfig = state["config"]
    audit_writer = state["audit_writer"]

    start = time.monotonic()

    # ── OTEL span — wraps the full request lifecycle ────────────────────────
    try:
        from yashigani.tracing import get_tracer, current_trace_id
        _tracer = get_tracer()
    except Exception:
        logger.debug("proxy: tracer import or initialisation failed", exc_info=True)
        _tracer = None

    with (_tracer.start_as_current_span("gateway-request") if _tracer else _NullSpan()) as _root_span:
        _root_span.set_attribute("http.method", request.method)
        _root_span.set_attribute("http.target", path)
        _root_span.set_attribute("yashigani.request_id", request_id)

        response = await _proxy_request_body(
            request, path, state, _tracer, _root_span, request_id, cfg, audit_writer, start
        )
        _root_span.set_attribute("http.status_code", response.status_code)
        return response


async def _proxy_request_body(
    request: Request,
    path: str,
    state: dict,
    _tracer,
    _root_span,
    request_id: str,
    cfg: GatewayConfig,
    audit_writer,
    start: float,
) -> Response:
    """Main proxy logic — called inside the root OTEL span from _handle_request."""
    try:
        from yashigani.tracing import current_trace_id
    except Exception:
        def current_trace_id() -> str:  # type: ignore[misc]
            return ""

    # Agent routing — intercept /agents/* before rate limiting and inspection.
    # AgentAuthMiddleware (added via add_middleware) has already run and set
    # request.state.caller_type when auth succeeded.
    norm_path = path if path.startswith("/") else "/" + path
    if norm_path.startswith("/agents/"):
        from yashigani.gateway.agent_router import route_agent_call
        return await route_agent_call(request, norm_path, state)

    # 0. DDoS protection — per-IP connection counting (v2.2)
    # record() is called before check() so the counter is always incremented
    # (preventing evasion via check-without-record).  /healthz and metrics
    # paths are exempt (see DDoSProtector._EXEMPT_PATHS).
    ddos_protector = state.get("ddos_protector")
    if ddos_protector is not None:
        _ddos_ip = _get_client_ip(request)
        ddos_protector.record(_ddos_ip, norm_path)
        if not ddos_protector.check(_ddos_ip, norm_path):
            try:
                from yashigani.metrics.registry import ratelimit_violations_total
                ratelimit_violations_total.labels(dimension="ddos_per_ip").inc()
            except Exception:
                logger.debug("proxy: metric increment failed for ddos_per_ip", exc_info=True)
            logger.warning(
                "DDoS threshold exceeded for ip=%s path=%s request_id=%s",
                _ddos_ip,
                norm_path,
                request_id,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "CONNECTION_LIMIT_EXCEEDED",
                    "detail": "Too many requests from this IP address.",
                    "request_id": request_id,
                },
                headers={
                    "X-Yashigani-Request-Id": request_id,
                    "Retry-After": str(ddos_protector.window_seconds),
                },
            )

    # 0b. Rate limiting — before any expensive processing
    rate_limiter = state["rate_limiter"]
    if rate_limiter is not None:
        client_ip = _get_client_ip(request)
        agent_id_rl = request.headers.get("x-yashigani-agent-id", "unknown")
        session_id_rl = request.cookies.get("__Host-yashigani_session", "")
        user_email_rl = request.headers.get("x-yashigani-user-id", "")

        # Apply per-role rate limit override: use the most permissive (highest) RPS
        # across all groups the user belongs to that have an override configured.
        rbac_store_rl = state.get("rbac_store")
        if rbac_store_rl is not None and user_email_rl:
            try:
                user_groups = rbac_store_rl.get_user_groups(user_email_rl)
                best_rps = None
                best_burst = None
                for grp in user_groups:
                    if grp.rate_limit_override is not None:
                        ovr = grp.rate_limit_override
                        if best_rps is None or ovr.per_session_rps > best_rps:
                            best_rps = ovr.per_session_rps
                            best_burst = ovr.per_session_burst
                if best_rps is not None:
                    rate_limiter.set_session_override(
                        session_id=session_id_rl,
                        per_session_rps=best_rps,
                        per_session_burst=best_burst,
                    )
            except Exception as exc:
                logger.debug("RBAC rate limit override lookup failed: %s", exc)

        rl_result = rate_limiter.check(client_ip, agent_id_rl, session_id_rl, user_email_rl)
        if not rl_result.allowed:
            retry_sec = max(1, rl_result.retry_after_ms // 1000)
            try:
                from yashigani.metrics.registry import ratelimit_violations_total
                ratelimit_violations_total.labels(dimension=rl_result.dimension).inc()
            except Exception:
                logger.debug("proxy: metric increment failed for ratelimit_violations_total", exc_info=True)
            # Per-user breach: increment dedicated metric + emit admin-alert audit event.
            if rl_result.dimension == "user" and user_email_rl:
                _admin_alert_user_rate_limit(
                    audit_writer=state["audit_writer"],
                    request_id=request_id,
                    result=rl_result,
                    user_id=user_email_rl,
                    agent_id=agent_id_rl,
                    session_id=session_id_rl,
                    rate_limiter=rate_limiter,
                )
            _audit_rate_limit(
                audit_writer=state["audit_writer"],
                request_id=request_id,
                result=rl_result,
                client_ip=client_ip,
                agent_id=agent_id_rl,
                session_id=session_id_rl,
                rate_limiter=rate_limiter,
            )
            # Redis-unavailable in fail-closed mode → 503 Service Unavailable.
            # All other rate-limit violations (token bucket exhausted) → 429.
            if rl_result.dimension == "redis_unavailable":
                return JSONResponse(
                    status_code=503,
                    content={
                        "error": "SERVICE_TEMPORARILY_UNAVAILABLE",
                        "message": (
                            f"The system is recovering. Please retry in "
                            f"{retry_sec} seconds. If the problem persists, "
                            "contact your administrator."
                        ),
                        "detail": "Rate limiter backend unavailable; request rejected (fail-closed mode).",
                        "request_id": request_id,
                        "retry_after_seconds": retry_sec,
                    },
                    headers={
                        "X-Yashigani-Request-Id": request_id,
                        "Retry-After": str(retry_sec),
                    },
                )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "RATE_LIMIT_EXCEEDED",
                    "dimension": rl_result.dimension,
                    "request_id": request_id,
                    "retry_after_seconds": retry_sec,
                },
                headers={
                    "X-Yashigani-Request-Id": request_id,
                    "Retry-After": str(retry_sec),
                    "X-RateLimit-Remaining": str(rl_result.remaining),
                },
            )

    # 0c. Per-endpoint rate limiting — Phase 5
    ep_rl = state.get("endpoint_rate_limiter")
    if ep_rl is not None:
        ep_result = ep_rl.check(norm_path)
        if not ep_result.allowed:
            try:
                from yashigani.metrics.registry import endpoint_ratelimit_violations_total
                endpoint_ratelimit_violations_total.labels(path=ep_result.endpoint_hash[:8]).inc()
            except Exception:
                logger.debug("proxy: metric increment failed for endpoint_ratelimit_violations_total", exc_info=True)
            return JSONResponse(
                status_code=429,
                content={
                    "error": "ENDPOINT_RATE_LIMIT_EXCEEDED",
                    "endpoint": norm_path,
                    "request_id": request_id,
                    "retry_after_seconds": ep_result.retry_after_seconds,
                },
                headers={
                    "X-Yashigani-Request-Id": request_id,
                    "Retry-After": str(ep_result.retry_after_seconds),
                },
            )

    # 0d. JWT introspection — Phase 7
    # Only validates if a Bearer token is present; requests without one pass through
    # and are governed by OPA policy (which may reject them).
    auth_header = request.headers.get("authorization", "")
    jwt_claims: dict = {}
    if auth_header.startswith("Bearer ") and state.get("jwt_inspector") is not None:
        token = auth_header[len("Bearer "):]
        # Skip JWT validation for internal service keys (Open WebUI, etc.)
        if hmac.compare_digest(token, _internal_bearer()):
            jwt_claims = {"sub": "internal", "iss": "yashigani"}
        else:
            jwt_result = await state["jwt_inspector"].inspect(
                token=token,
                tenant_id=request.headers.get("x-yashigani-tenant-id", "00000000-0000-0000-0000-000000000000"),
            )
            if not jwt_result.valid:
                return JSONResponse(
                    status_code=401,
                    content={"error": "JWT_INVALID", "detail": jwt_result.error, "request_id": request_id},
                    headers={"X-Yashigani-Request-Id": request_id},
                )
            jwt_claims = jwt_result.claims

    # 1. Read and size-check the request body
    try:
        body_bytes = await request.body()
    except Exception:
        return _error_response(request_id, 400, "BODY_READ_ERROR")

    if len(body_bytes) > cfg.max_request_body_bytes:
        _audit_request(audit_writer, request_id, "BLOCKED", "body_too_large", request, path)
        return _error_response(request_id, 413, "REQUEST_BODY_TOO_LARGE")

    # 2. Extract session / API key identity
    session_id, agent_id, user_id = _extract_identity(request)
    # Prefer JWT sub over header-provided user_id
    if jwt_claims.get("sub"):
        user_id = jwt_claims["sub"]
    # Internal service identity (Open WebUI, etc.)
    if jwt_claims.get("iss") == "yashigani" and jwt_claims.get("sub") == "internal":
        agent_id = agent_id or "internal"
        session_id = session_id or "internal"

    # Annotate root span with identity and model (low-cardinality values only)
    _root_span.set_attribute("yashigani.agent_id", agent_id)
    _root_span.set_attribute("yashigani.user_id", user_id)
    try:
        import json as _json
        _body_obj = _json.loads(body_bytes) if body_bytes else {}
        _model = _body_obj.get("model", "")
        if _model:
            _root_span.set_attribute("llm.model", _model)
    except Exception:
        pass

    # 3. Run inspection pipeline (if configured)
    pipeline = state["inspection_pipeline"]
    forwarded_body = body_bytes

    if pipeline is not None and body_bytes:
        raw_query = _decode_body_safe(body_bytes)
        if raw_query:
            result = pipeline.process(
                raw_query=raw_query,
                session_id=session_id,
                agent_id=agent_id,
                user_id=user_id,
            )

            if result.action == "DISCARDED":
                _audit_request(
                    audit_writer, request_id, "DISCARDED",
                    result.classification, request, path,
                    confidence=result.confidence,
                )
                # Return user alert as the response — query never forwarded
                return JSONResponse(
                    status_code=200,
                    content=result.user_alert,
                    headers={"X-Yashigani-Request-Id": request_id},
                )

            if result.action == "SANITIZED" and result.clean_query is not None:
                forwarded_body = result.clean_query.encode("utf-8", errors="replace")

    # 3b. PII detection on request body
    # The catch-all proxy forwards to a configured upstream (MCP server or similar).
    # We always apply the configured PII mode on both request and response bodies.
    # Since traffic destination is determined by GatewayConfig.upstream_base_url (an
    # admin-configured value), we cannot classify it as local/cloud at runtime here.
    # We apply the full mode (LOG/REDACT/BLOCK) as configured.
    pii_detected_on_request = False
    pii_detector = state.get("pii_detector")
    if pii_detector is not None and forwarded_body:
        _req_body_text = _decode_body_safe(forwarded_body)
        if _req_body_text:
            _req_pii_text, _req_pii_result = pii_detector.process(_req_body_text)
            if _req_pii_result.detected:
                pii_detected_on_request = True
                pii_types = [f.pii_type.value for f in _req_pii_result.findings]
                logger.info(
                    "PII detected on proxy request path=%s request_id=%s types=%s action=%s",
                    path, request_id, pii_types, _req_pii_result.action_taken,
                )
                if audit_writer is not None:
                    try:
                        audit_writer.write(
                            PIIDetectedEvent(
                                request_id=request_id,
                                direction="request",
                                pii_types=pii_types,
                                action_taken=_req_pii_result.action_taken,
                                destination="upstream",
                                finding_count=len(_req_pii_result.findings),
                            )
                        )
                    except Exception as _exc:
                        logger.warning("PII audit write failed (request_id=%s): %s", request_id, _exc)

                if _req_pii_result.action_taken == "blocked":
                    _audit_request(audit_writer, request_id, "BLOCKED", "pii_detected", request, path)
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "pii_detected",
                            "detail": (
                                "Request blocked: PII detected and PII mode is BLOCK. "
                                "Configure PII mode via the admin panel."
                            ),
                            "pii_types": pii_types,
                            "request_id": request_id,
                        },
                        headers={"X-Yashigani-Request-Id": request_id},
                    )
                if _req_pii_result.action_taken == "redacted":
                    forwarded_body = _req_pii_text.encode("utf-8", errors="replace")

    # 4. OPA policy check
    with (_tracer.start_as_current_span("opa-check") if _tracer else _NullSpan()) as _opa_span:
        _opa_span.set_attribute("opa.path", path)
        _opa_span.set_attribute("yashigani.agent_id", agent_id)
        opa_allowed = await _opa_check(cfg, request, path, session_id, agent_id, user_id)
        _opa_span.set_attribute("opa.allowed", opa_allowed)
    if not opa_allowed:
        _audit_request(audit_writer, request_id, "DENIED", "opa_policy", request, path)
        return _error_response(request_id, 403, "POLICY_DENIED")

    # 4b. Response cache — only on CLEAN forwarded requests (Phase 6)
    tenant_id = request.headers.get("x-yashigani-tenant-id", "platform")
    response_cache = state.get("response_cache")
    if response_cache is not None and forwarded_body:
        cached = response_cache.get(tenant_id, forwarded_body)
        if cached is not None:
            trace_id = ""
            try:
                trace_id = current_trace_id()
            except Exception:
                logger.debug("proxy: trace ID retrieval failed for cache-hit response", exc_info=True)
            resp_headers = {"X-Yashigani-Request-Id": request_id, "X-Cache": "HIT"}
            if trace_id:
                resp_headers["X-Trace-Id"] = trace_id
            return Response(
                content=cached,
                status_code=200,
                headers=resp_headers,
                media_type="application/json",
            )

    # 5. Forward to upstream MCP server
    client: httpx.AsyncClient = state["http_client"]
    with (_tracer.start_as_current_span("upstream-llm-call") if _tracer else _NullSpan()) as _up_span:
        _up_span.set_attribute("http.method", request.method)
        _up_span.set_attribute("http.target", path)
        _up_span.set_attribute("yashigani.agent_id", agent_id)
        upstream_response = await _forward(client, request, path, forwarded_body, request_id)
        _up_span.set_attribute("http.status_code", upstream_response.status_code)

    # 5a. Response inspection — v0.9.0 F-01
    # Inspect the upstream response for indirect prompt injection before
    # returning it to the agent. Raw body is never stored; only a hash.
    response_verdict: Optional[str] = None
    # F-T10-001: 1.0 = clean pass (no inspection or skipped); overwritten below.
    proxy_inspection_confidence: float = 1.0
    resp_pipeline = state.get("response_inspection_pipeline")
    if resp_pipeline is not None:
        resp_body_text = _decode_body_safe(upstream_response.content)
        if resp_body_text:
            resp_content_type = upstream_response.headers.get("content-type", "")
            resp_result = resp_pipeline.inspect(
                response_body=resp_body_text,
                content_type=resp_content_type,
                request_id=request_id,
                session_id=session_id,
                agent_id=agent_id,
            )
            if not resp_result.skipped:
                response_verdict = resp_result.verdict
                # F-T10-001: capture inspection confidence for operator UI.
                # isfinite guard + clamp — see openai_router.py comment for rationale.
                _raw_conf = float(resp_result.confidence)
                proxy_inspection_confidence = max(0.0, min(1.0, _raw_conf)) if math.isfinite(_raw_conf) else 0.0
            if resp_result.verdict == "BLOCKED":
                elapsed_ms = int((time.monotonic() - start) * 1000)
                _audit_request(
                    audit_writer, request_id, "BLOCKED", "response_injection",
                    request, path,
                    upstream_status=upstream_response.status_code,
                    elapsed_ms=elapsed_ms,
                    confidence=resp_result.confidence,
                    response_inspection_verdict=resp_result.verdict,
                )
                return JSONResponse(
                    status_code=502,
                    content={
                        "error": "UPSTREAM_RESPONSE_BLOCKED",
                        "detail": "The upstream response was blocked by Yashigani response inspection.",
                        "request_id": request_id,
                    },
                    headers={
                        "X-Yashigani-Request-Id": request_id,
                        "X-Yashigani-Response-Verdict": resp_result.verdict,
                    },
                )

    # 5b_pii. PII detection on response body
    pii_detected_on_response = False
    _upstream_content = upstream_response.content
    if pii_detector is not None and _upstream_content:
        _resp_body_text = _decode_body_safe(_upstream_content)
        if _resp_body_text:
            _resp_pii_text, _resp_pii_result = pii_detector.process(_resp_body_text)
            if _resp_pii_result.detected:
                pii_detected_on_response = True
                pii_resp_types = [f.pii_type.value for f in _resp_pii_result.findings]
                logger.info(
                    "PII detected in proxy response path=%s request_id=%s types=%s action=%s",
                    path, request_id, pii_resp_types, _resp_pii_result.action_taken,
                )
                if audit_writer is not None:
                    try:
                        audit_writer.write(
                            PIIDetectedEvent(
                                request_id=request_id,
                                direction="response",
                                pii_types=pii_resp_types,
                                action_taken=_resp_pii_result.action_taken,
                                destination="upstream",
                                finding_count=len(_resp_pii_result.findings),
                            )
                        )
                    except Exception as _exc:
                        logger.warning("PII audit write failed (request_id=%s): %s", request_id, _exc)

                if _resp_pii_result.action_taken == "redacted":
                    _upstream_content = _resp_pii_text.encode("utf-8", errors="replace")
                # BLOCK: add header warning, do not suppress — response already generated

    # 5c-opa. Response-leg OPA check (GAP-002 close).
    # After response inspection and PII detection, query OPA to decide whether
    # this caller's sensitivity ceiling permits receiving the upstream content.
    # Fail-closed: OPA unreachable → 503.  OPA deny → 403.
    # No OPA in dev opt-in mode (YASHIGANI_OPA_OPTIONAL=true + non-production).
    _opa_resp_result = await _opa_proxy_response_check(
        cfg=cfg,
        request=request,
        path=path,
        session_id=session_id,
        agent_id=agent_id,
        user_id=user_id,
        response_sensitivity=_proxy_response_sensitivity(resp_pipeline, upstream_response.content, session_id, agent_id, request_id),
        pii_detected=pii_detected_on_response,
        request_id=request_id,
        audit_writer=audit_writer,
    )
    if not _opa_resp_result.get("allow", False):
        _opa_deny_reason = _opa_resp_result.get("reason", "opa_denied")
        _http_status = 503 if "unreachable" in _opa_deny_reason or "not_configured" in _opa_deny_reason else 403
        return JSONResponse(
            status_code=_http_status,
            content={
                "error": "MCP_RESPONSE_BLOCKED_BY_OPA",
                "detail": "The upstream MCP response was blocked by Yashigani policy.",
                "reason": _opa_deny_reason,
                "request_id": request_id,
            },
            headers={"X-Yashigani-Request-Id": request_id},
        )

    elapsed_ms = int((time.monotonic() - start) * 1000)
    _audit_request(
        audit_writer, request_id, "FORWARDED", "clean", request, path,
        upstream_status=upstream_response.status_code,
        elapsed_ms=elapsed_ms,
        response_inspection_verdict=response_verdict,
    )

    try:
        from yashigani.metrics.registry import (
            gateway_requests_total,
            gateway_request_duration_seconds,
            gateway_upstream_status_total,
        )
        agent_id_m = request.headers.get("x-yashigani-agent-id", "unknown")
        gateway_requests_total.labels(method=request.method, action="FORWARDED", agent_id=agent_id_m).inc()
        gateway_request_duration_seconds.labels(method=request.method, action="FORWARDED").observe(elapsed_ms / 1000)
        gateway_upstream_status_total.labels(status_code=str(upstream_response.status_code)).inc()
    except Exception:
        logger.debug("proxy: metric increment failed for gateway forwarded-request counters", exc_info=True)

    # 5b. Store clean 2xx responses in cache (Phase 6)
    if (
        response_cache is not None
        and forwarded_body
        and 200 <= upstream_response.status_code < 300
    ):
        cache_ttl = int(request.headers.get("x-yashigani-cache-ttl", "300"))
        response_cache.set(tenant_id, forwarded_body, upstream_response.content, ttl=cache_ttl)

    # 5c. Inference payload logging + anomaly detection (Phases 1+2)
    inference_logger = state.get("inference_logger")
    if inference_logger is not None and forwarded_body:
        anomaly_detector = state.get("anomaly_detector")
        if anomaly_detector is not None:
            asyncio.ensure_future(
                anomaly_detector.record(tenant_id=tenant_id, payload_bytes=len(forwarded_body))
            )
        asyncio.ensure_future(
            inference_logger.log(
                tenant_id=tenant_id,
                session_id=session_id,
                payload=forwarded_body,
                upstream_status=upstream_response.status_code,
                elapsed_ms=elapsed_ms,
            )
        )

    # 5d. Attach trace ID to response (Phase 9)
    # Use _upstream_content which may have been redacted by PII filtering above.
    response = _build_response(upstream_response, request_id, content_override=_upstream_content)
    try:
        trace_id = current_trace_id()
        if trace_id:
            response.headers["X-Trace-Id"] = trace_id
    except Exception:
        logger.debug("proxy: trace ID retrieval failed for forwarded response header", exc_info=True)

    # 5e. Attach response inspection verdict header when present (v0.9.0)
    if response_verdict is not None:
        response.headers["X-Yashigani-Response-Verdict"] = response_verdict

    # 5e-T10. F-T10-001: Generated-content disclaimer + inspection confidence.
    # X-Yashigani-Generated-Content is always true for proxy responses — the
    # upstream (MCP server, LLM, tool) produces content that downstream consumers
    # should not treat as ground truth without verification.
    response.headers["X-Yashigani-Generated-Content"] = "true"
    response.headers["X-Yashigani-Response-Inspection-Confidence"] = (
        f"{proxy_inspection_confidence:.4f}"
    )

    # 5f. PII detection header (v2.2)
    _pii_any = pii_detected_on_request or pii_detected_on_response
    response.headers["X-Yashigani-PII-Detected"] = "true" if _pii_any else "false"

    return response


# ---------------------------------------------------------------------------
# OPA policy check
# ---------------------------------------------------------------------------

async def _opa_check(
    cfg: GatewayConfig,
    request: Request,
    path: str,
    session_id: str,
    agent_id: str,
    user_id: str,
) -> bool:
    """
    Query OPA for an allow/deny decision.
    OPA is always local — never a cloud call (ASVS V4.2).
    On any OPA error: deny (fail-closed).
    """
    import json

    input_doc = {
        "method": request.method,
        "path": path,
        "session_id": session_id,
        "agent_id": agent_id,
        "user_id": user_id,
        # session.email is consumed by rbac.rego allow_rbac
        "session": {"email": user_id},
        "request": {"method": request.method, "path": path},
        "headers": {
            k: v for k, v in request.headers.items()
            if k.lower() not in ("authorization", "cookie")
        },
    }

    try:
        async with internal_httpx_client(timeout=5.0) as client:
            resp = await client.post(
                cfg.opa_url + cfg.opa_policy_path,
                json={"input": input_doc},
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            # OPA returns {"result": true} or {"result": false}
            return bool(data.get("result", False))
    except Exception as exc:
        logger.error(
            "OPA check failed for path '%s' (request_id=%s): %s — denying (fail-closed)",
            path, session_id, exc,
        )
        return False  # fail-closed


# ---------------------------------------------------------------------------
# Response-leg OPA helpers (GAP-002)
# ---------------------------------------------------------------------------


def _proxy_response_sensitivity(
    resp_pipeline,
    content: bytes,
    session_id: str,
    agent_id: str,
    request_id: str,
) -> str:
    """
    Derive response sensitivity for OPA input.

    When the ResponseInspectionPipeline is configured and the content is
    non-empty, attempt to classify response sensitivity.  Fall back to
    "PUBLIC" when pipeline is absent (default per YSG-RISK-057) or when
    classification fails.

    Returns one of PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED.
    """
    if resp_pipeline is None or not content:
        return "PUBLIC"
    try:
        text = _decode_body_safe(content)
        if not text:
            return "PUBLIC"
        result = resp_pipeline.inspect(
            response_body=text,
            content_type="",
            request_id=request_id,
            session_id=session_id,
            agent_id=agent_id,
        )
        # ResponseInspectionResult.response_sensitivity is populated by
        # ResponseInspectionPipeline when a SensitivityClassifier is wired.
        # Attribute is absent on older pipeline versions — getattr is safe.
        sens = getattr(result, "response_sensitivity", None)
        if sens and isinstance(sens, str) and sens in {"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}:
            return sens
    except Exception as exc:
        logger.debug(
            "proxy: response sensitivity classification failed (request_id=%s): %s",
            request_id, exc,
        )
    return "PUBLIC"


async def _opa_proxy_response_check(
    cfg: GatewayConfig,
    request: Request,
    path: str,
    session_id: str,
    agent_id: str,
    user_id: str,
    response_sensitivity: str,
    pii_detected: bool,
    request_id: str,
    audit_writer,
) -> dict:
    """
    Query OPA proxy_response_decision for the catch-all proxy response leg.

    Returns {"allow": bool, "reason": str}.

    Fail-closed: OPA unreachable or not configured (without dev opt-in) →
    {"allow": False, "reason": "opa_unreachable"} or "opa_not_configured".

    Dev opt-in: YASHIGANI_OPA_OPTIONAL=true + non-production → allow without
    policy check.

    GAP-002 / ASVS V4.1.3 / Iris GAP-002 / YSG-RISK-067 / v2.24.1.
    """
    from yashigani.audit.schema import McpResponseBlockedByOpaEvent, ProxyOpaResponseCheckFailedEvent

    _ysg_env = os.getenv("YASHIGANI_ENV", "").strip().lower()
    _opa_optional = os.getenv("YASHIGANI_OPA_OPTIONAL", "false").strip().lower() == "true"

    if not cfg.opa_url:
        if _opa_optional and _ysg_env != "production":
            logger.warning(
                "OPA not configured (YASHIGANI_OPA_OPTIONAL=true, env=%s) — "
                "allowing proxy response without policy check (dev opt-in)",
                _ysg_env,
            )
            return {"allow": True, "reason": "opa_not_configured_dev_opt_in"}
        logger.error(
            "OPA not configured and fail-closed triggered for proxy response-leg "
            "(env=%s, opa_optional=%s)",
            _ysg_env, _opa_optional,
        )
        if audit_writer is not None:
            try:
                audit_writer.write(ProxyOpaResponseCheckFailedEvent(
                    request_id=request_id,
                    identity_id=user_id or agent_id or "anonymous",
                    reason="opa_not_configured",
                    outcome="not_configured",
                ))
            except Exception as _aw_exc:
                logger.warning("Audit write failed for ProxyOpaResponseCheckFailedEvent: %s", _aw_exc)
        return {"allow": False, "reason": "opa_not_configured"}

    # Build principal doc from available identity signals in proxy.
    # The catch-all proxy does not have a full identity registry lookup;
    # we use the identity extracted by _extract_identity + JWT claims.
    principal_doc = {
        "status": "active",
        "kind": "service" if (agent_id and agent_id != "anonymous") else "human",
        "sensitivity_ceiling": "RESTRICTED",  # conservative default; real ceiling gated by request-leg OPA
    }
    # Internal mesh bearer → sensitivity_ceiling matches internal identity
    _auth = request.headers.get("authorization", "")
    if _auth.startswith("Bearer ") and hmac.compare_digest(_auth[7:], _INTERNAL_BEARER):
        principal_doc["kind"] = "service"
        principal_doc["sensitivity_ceiling"] = "RESTRICTED"

    opa_input = {
        "principal": principal_doc,
        "response_sensitivity": response_sensitivity,
        "response_pii_detected": pii_detected,
        "request_path": path,
    }

    try:
        async with internal_httpx_client(timeout=5.0) as client:
            resp = await client.post(
                cfg.opa_url.rstrip("/") + "/v1/data/yashigani/v1/proxy_response_decision",
                json={"input": opa_input},
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
            opa_allow = bool(result.get("allow", True))
            opa_reason = result.get("reason", "ok")

            if not opa_allow:
                if audit_writer is not None:
                    try:
                        audit_writer.write(McpResponseBlockedByOpaEvent(
                            request_id=request_id,
                            identity_id=user_id or agent_id or "anonymous",
                            identity_kind=principal_doc["kind"],
                            request_path=path,
                            response_sensitivity=response_sensitivity,
                            pii_detected=pii_detected,
                            deny_reason=opa_reason,
                            action="denied",
                        ))
                    except Exception as _aw_exc:
                        logger.warning(
                            "Audit write failed for McpResponseBlockedByOpaEvent: %s", _aw_exc
                        )
            return {"allow": opa_allow, "reason": opa_reason}

    except Exception as exc:
        exc_class = type(exc).__name__
        logger.error(
            "OPA proxy response check FAILED — denying (fail-closed zero-trust). "
            "exc_class=%s exc=%s. OPA must be restored to re-enable proxy response delivery.",
            exc_class, exc,
        )
        if audit_writer is not None:
            try:
                audit_writer.write(ProxyOpaResponseCheckFailedEvent(
                    request_id=request_id,
                    identity_id=user_id or agent_id or "anonymous",
                    reason="opa_exception",
                    outcome="exception",
                    exc_class=exc_class,
                    exc_str=str(exc)[:256],
                ))
            except Exception as _aw_exc:
                logger.warning(
                    "Audit write failed for ProxyOpaResponseCheckFailedEvent: %s", _aw_exc
                )
        return {"allow": False, "reason": "opa_unreachable"}


# ---------------------------------------------------------------------------
# Upstream forwarding
# ---------------------------------------------------------------------------

async def _forward(
    client: httpx.AsyncClient,
    request: Request,
    path: str,
    body: bytes,
    request_id: str,
) -> httpx.Response:
    # Build forwarded headers — strip hop-by-hop, inject trace ID
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP_HEADERS
        and k.lower() != "host"
    }
    headers["X-Yashigani-Request-Id"] = request_id
    headers["X-Forwarded-For"] = _get_client_ip(request)

    query_string = request.url.query
    url = path + ("?" + query_string if query_string else "")

    return await client.request(
        method=request.method,
        url=url,
        content=body,
        headers=headers,
    )


def _build_response(
    upstream: httpx.Response,
    request_id: str,
    content_override: Optional[bytes] = None,
) -> Response:
    headers = {
        k: v for k, v in upstream.headers.items()
        if k.lower() not in _HOP_BY_HOP_HEADERS
    }
    headers["X-Yashigani-Request-Id"] = request_id

    return Response(
        content=content_override if content_override is not None else upstream.content,
        status_code=upstream.status_code,
        headers=headers,
        media_type=upstream.headers.get("content-type"),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_identity(request: Request) -> tuple[str, str, str]:
    """Extract session_id, agent_id, user_id from request headers/cookies."""
    session_id = request.cookies.get("__Host-yashigani_session", "")
    if not session_id:
        # API key or Bearer token — use a hash as the session_id handle
        auth = request.headers.get("authorization", "")
        session_id = hashlib.sha256(auth.encode()).hexdigest()[:16] if auth else "anonymous"

    agent_id = request.headers.get("x-yashigani-agent-id", "unknown")
    user_id = request.headers.get("x-yashigani-user-id", "unknown")
    return session_id, agent_id, user_id


def _decode_body_safe(body: bytes) -> Optional[str]:
    """Attempt to decode body as UTF-8 text for inspection. Returns None for binary."""
    try:
        return body.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None


def _parse_trusted_proxy_cidrs() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Parse TRUSTED_PROXY_CIDRS from the environment.

    Format: comma-separated CIDR strings, e.g.
        TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

    Defaults to loopback only (127.0.0.1/32 and ::1/128).  This is the
    safe fail-closed default: without explicit configuration, only
    connections where the immediate peer is localhost are trusted to
    carry a reliable XFF chain.  Deployments behind a load-balancer or
    Caddy reverse proxy MUST set TRUSTED_PROXY_CIDRS to include the
    proxy's address range so that the real client IP is extracted
    correctly from XFF.
    """
    raw = os.environ.get("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128")
    cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            cidrs.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            logger.warning(
                "proxy: TRUSTED_PROXY_CIDRS contains invalid CIDR %r — ignoring", token
            )
    if not cidrs:
        # If the entire env var is malformed, fail closed to loopback only
        logger.error(
            "proxy: TRUSTED_PROXY_CIDRS produced no valid CIDRs after parsing; "
            "falling back to loopback-only trust boundary"
        )
        cidrs = [
            ipaddress.ip_network("127.0.0.1/32"),
            ipaddress.ip_network("::1/128"),
        ]
    return cidrs


# Module-level cache — parsed once at import time so hot paths pay no cost.
# Re-read via _parse_trusted_proxy_cidrs() in tests that need to inject values.
_TRUSTED_PROXY_CIDRS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = (
    _parse_trusted_proxy_cidrs()
)


def _get_client_ip(request: Request) -> str:
    """
    Resolve the real client IP using a trusted-proxy-boundary walk.

    CWE-345 mitigation (V232-NEG03 / LAURA-2026-04-29-006):
    The old implementation trusted the FIRST (leftmost) IP in the
    X-Forwarded-For chain, which an attacker can prepend at will:

        XFF: <spoofed>,<real-client>,<proxy>

    The correct algorithm walks the chain RIGHT-TO-LEFT, skipping IPs
    that belong to trusted proxy CIDRs (TRUSTED_PROXY_CIDRS env var).
    The first IP that is NOT in a trusted CIDR is the real client.  If
    the entire chain is trusted (e.g. all internal hops) the leftmost
    remaining entry is used.  If the chain is empty, the TCP peer
    address is used — which is always authoritative for the immediate
    hop.
    """
    forwarded_for = request.headers.get("x-forwarded-for", "")
    peer_addr = request.client.host if request.client else "unknown"

    if not forwarded_for:
        return peer_addr

    # Split and strip whitespace from each entry
    hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
    if not hops:
        return peer_addr

    trusted_cidrs = _TRUSTED_PROXY_CIDRS

    # Walk right-to-left; stop at first non-trusted IP
    for hop in reversed(hops):
        try:
            addr = ipaddress.ip_address(hop)
        except ValueError:
            # Malformed entry — treat as untrusted (fail closed)
            logger.debug(
                "proxy: _get_client_ip: malformed XFF hop %r — treating as real client", hop
            )
            return hop
        if not any(addr in cidr for cidr in trusted_cidrs):
            return hop

    # Every entry in the chain was a trusted proxy — the leftmost is as
    # close to the real client as we can get from this chain.
    return hops[0]


def _error_response(request_id: str, status_code: int, error_code: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": error_code, "request_id": request_id},
        headers={"X-Yashigani-Request-Id": request_id},
    )


def _admin_alert_user_rate_limit(
    audit_writer,
    request_id: str,
    result,
    user_id: str,
    agent_id: str,
    session_id: str,
    rate_limiter,
) -> None:
    """
    Emit per-user rate limit breach signals:
      1. Prometheus metric yashigani_user_rate_limit_violations_total{user_id_hash=...}
         — in-stack monitoring; Grafana alert fires when this exceeds threshold.
      2. Audit event USER_RATE_LIMIT_EXCEEDED — Wazuh-routable push alert for
         customers with SIEM configured for outbound notification.

    user_id is hashed (SHA-256[:16]) before appearing in any metric label or
    external-facing surface.  The full user_id is included only in the audit
    event body which is admin-only.
    """
    user_id_hash = hashlib.sha256(user_id.encode()).hexdigest()[:16]
    # 1. Prometheus — hashed label, safe for public metric scrape
    try:
        from yashigani.metrics.registry import user_ratelimit_violations_total
        user_ratelimit_violations_total.labels(user_id_hash=user_id_hash).inc()
    except Exception:
        logger.debug("proxy: metric increment failed for user_ratelimit_violations_total", exc_info=True)

    # 2. Audit event — full user_id stays in admin-only audit chain
    if audit_writer is None:
        return
    try:
        from yashigani.audit.schema import UserRateLimitExceededEvent
        cfg = rate_limiter.current_config() if rate_limiter is not None else None
        limit_rps = cfg.per_user_rps if cfg is not None else 0.0
        event = UserRateLimitExceededEvent(
            request_id=request_id,
            user_id_hash=user_id_hash,
            rps_observed=0.0,   # token bucket does not expose instantaneous rate;
                                # 0.0 signals "bucket exhausted" without a precise reading
            limit_rps=limit_rps,
            retry_after_ms=result.retry_after_ms,
            agent_id=agent_id,
            session_id_prefix=session_id[:8] if session_id else "",
        )
        audit_writer.write(event)
    except Exception as exc:
        logger.error("Failed to write user rate limit admin alert audit event: %s", exc)


def _audit_rate_limit(
    audit_writer,
    request_id: str,
    result,
    client_ip: str,
    agent_id: str,
    session_id: str,
    rate_limiter,
) -> None:
    if audit_writer is None:
        return
    try:
        from yashigani.audit.schema import RateLimitViolationEvent
        rpi = 0.0
        multiplier = 1.0
        try:
            rpi = rate_limiter._monitor.get_metrics().pressure_index if rate_limiter._monitor else 0.0
            multiplier = rate_limiter.current_rpi_multiplier()
        except Exception:
            logger.debug("proxy: RPI/multiplier retrieval failed for rate limit audit event", exc_info=True)
        event = RateLimitViolationEvent(
            account_tier="system",
            request_id=request_id,
            dimension=result.dimension,
            client_ip_hash=_content_hash(client_ip)[:16],
            agent_id=agent_id,
            session_id_prefix=session_id[:8] if session_id else "",
            retry_after_ms=result.retry_after_ms,
            rpi_at_time=rpi,
            rpi_multiplier=multiplier,
        )
        audit_writer.write(event)
    except Exception as exc:
        logger.error("Failed to write rate limit audit event: %s", exc)


def _audit_request(
    audit_writer,
    request_id: str,
    action: str,
    reason: str,
    request: Request,
    path: str,
    upstream_status: Optional[int] = None,
    elapsed_ms: Optional[int] = None,
    confidence: Optional[float] = None,
    response_inspection_verdict: Optional[str] = None,  # v0.9.0
) -> None:
    if audit_writer is None:
        return
    try:
        from yashigani.audit.schema import GatewayRequestEvent
        event = GatewayRequestEvent(
            account_tier="system",
            request_id=request_id,
            method=request.method,
            path=path,
            action=action,
            reason=reason,
            upstream_status=upstream_status,
            elapsed_ms=elapsed_ms,
            confidence_score=confidence,
            response_inspection_verdict=response_inspection_verdict,
        )
        audit_writer.write(event)
    except Exception as exc:
        logger.error("Failed to write gateway audit event: %s", exc)
