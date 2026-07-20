"""
Yashigani Gateway — MCP runtime call router.

Handles inbound MCP JSON-RPC calls from agents to onboarded MCP servers.

Route: POST /mcp/{agent_name}

Flow:
  1. Registry lookup — 404 if agent_name unknown.
  2. Strip X-Forwarded-*/X-Real-IP/X-Posture headers (posture is channel-derived).
  3. Derive posture mcp-b via McpHttpTransport.derive_posture() (HTTP channel).
  4. Parse JSON-RPC body (capped at MCP_BODY_SIZE_LIMIT_BYTES; 413 on exceed).
  5. tools/call: broker.enforce(ctx) → on allow, McpHttpTransport.forward().
  6. initialize / tools/list / notifications: forward through transport WITH gateway
     JWT (gateway attaches a session-level JWT so the server trusts the gateway).
  7. Deny → 403 with deny_reason.  Unknown method → forward (pass-through).

G-ORCH-OPA-1 (egress gate — v3.1):
  For tools/call, AFTER step 5 returns an upstream result:
    a. Run ResponseInspectionPipeline (if configured) to obtain result_sensitivity
       and injection verdict.  The PII flag is derived from the inspection verdict.
    b. Call broker.enforce_result(ctx, result_sensitivity, pii_detected) — an
       additional, independent OPA decision layer on top of the content-filter.
    c. If EgressDecision.allow is False → WITHHOLD the result; return 403 with
       the self-describing deny contract (deny_reason, code, user_message).
       The raw upstream result is never returned to the caller on deny.
    d. Fail-closed: any error in the egress decision path withholds the result.

  Caller sensitivity ceiling (G-ORCH-OPA-1 / Option A — v3.1):
    ctx.caller_sensitivity_ceiling is populated from the identity registry at
    call time (Option A: registry lookup keyed by identity_id from X-Yashigani-Identity-Id — 4.1 SEC-GAP-1).
    The identity registry is passed from the proxy (openai_router._state) so no
    new store is introduced.

    Lookup: identity_registry.get_by_slug(user_id) → identity dict →
      identity.get("sensitivity_ceiling", "PUBLIC").  If the registry is absent
      or the user_id is not found, ctx.caller_sensitivity_ceiling remains None
      → OPA fails-closed (invalid_or_missing_caller_ceiling) — this is correct
      for unauthenticated or registry-unavailable paths.

    The normal gateway-mediated path (Caddy forward_auth + identity registry
    configured) sets a real ceiling so legitimate results are allowed.

Security:
  - Posture is ALWAYS derived from the channel (mcp-b for HTTP), never from headers.
  - X-Forwarded-For / X-Real-IP / X-Posture headers are stripped before any
    posture derivation.
  - 403 response bodies do NOT include internal error details — only deny_reason.
  - All errors are fail-closed (deny + 403/502/404 as appropriate).
  - Body size is capped at MCP_BODY_SIZE_LIMIT_BYTES (default 1 MiB) — 413 on exceed.

v1 session-affinity constraint:
  The MCP protocol is session-oriented: initialize → tools/call depend on subprocess
  session state held inside the bridge container.  v1 ships one bridge container per
  onboarded server (single-replica bridge).  This is safe because every call to the
  same /mcp/{agent_name} path hits the same bridge subprocess.

  Horizontally scaling a bridge to N replicas breaks under MCP session semantics
  (session state is in one subprocess; N-1 replicas have no state for that session).
  v2 design item: Mcp-Session-Id affinity routing OR stateless-HTTP-native MCP servers.

  DO NOT add a second replica for any bridge deployment without implementing session
  affinity at the load-balancer layer first.

v2.25.0 / P3 gateway integration.
v3.1 / G-ORCH-OPA-1 egress hardening.
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import uuid
from typing import Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from yashigani.mcp._types import McpCallContext, McpPosture, PostureBinding
from yashigani.mcp._transport_http import McpHttpTransport, HttpTransportError

logger = logging.getLogger(__name__)


def _mesh_caller_is_internal(request: Request) -> bool:
    """Return True iff the request proves internal mesh identity.

    YSG-RISK-108 / T-3 + T-4 trust gate.

    The per-install YASHIGANI_INTERNAL_BEARER is present on ALL legitimate
    mesh callers (orchestrator self-calls, OWUI, 4.0 native chat path).
    Only when this token is verified should identity-forwarding headers
    (X-Yashigani-Identity-Id, X-Yashigani-Orchestration-Depth/Principal)
    be trusted.  4.1 SEC-GAP-1: X-Forwarded-User removed from the trusted set.

    An anonymous caller on port :8081 cannot know the per-install bearer —
    so any identity header without it is a header-spoof attempt.

    Fail-closed: if the bearer import fails (e.g. circular-import guard at
    test time), returns False — no identity promoted, no escalation.
    """
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return False
    key = auth[7:]
    if not key:
        return False
    try:
        from yashigani.gateway.openai_router import _INTERNAL_BEARER  # noqa: PLC0415
        return hmac.compare_digest(
            key.encode("ascii"),
            _INTERNAL_BEARER.encode("ascii"),
        )
    except Exception:
        return False

# Fix-3 (Laura ship-blocker): body size cap — defense in depth at the router layer.
# The bridge enforces the same cap independently (see _bridge.py _BRIDGE_BODY_LIMIT).
# 1 MiB is generous for any valid MCP JSON-RPC payload; larger bodies are almost
# certainly abuse.  Configurable via env for integration tests that need a tighter cap.
MCP_BODY_SIZE_LIMIT_BYTES: int = int(
    os.environ.get("YASHIGANI_MCP_MAX_BODY_BYTES", str(1 * 1024 * 1024))
)

# Headers that must be stripped before posture derivation.
# Posture is derived from the physical channel, never from forwarded headers.
_STRIP_HEADERS = frozenset({
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "x-posture",
    "x-forwarded-user",        # stripped from downstream MCP call; no longer used for authz (4.1)
    "x-yashigani-identity-id", # stripped from downstream MCP call; identity resolved at boundary
})

# Methods that require tools/call enforcement gate
_GATED_METHODS = frozenset({"tools/call"})

# Methods that are MCP session management — forwarded without tools-gating
# but still with a gateway JWT attached
_SESSION_METHODS = frozenset({
    "initialize",
    "initialized",          # client notification after initialize
    "tools/list",
    "prompts/list",
    "resources/list",
    "ping",
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/progress",
    "notifications/message",
    "notifications/resources/list_changed",
    "notifications/resources/updated",
    "notifications/tools/list_changed",
    "notifications/prompts/list_changed",
})


async def dispatch_mcp_call(
    agent_name: str,
    request: Request,
    registry: object,  # McpBrokerRegistry — typed as object to avoid circular imports
    response_inspection_pipeline: Optional[object] = None,  # ResponseInspectionPipeline | None
    identity_registry: Optional[object] = None,  # IdentityRegistry | None — for ceiling lookup
    agent_registry: Optional[object] = None,  # AgentRegistry | None — 3.1 Phase 3 tool permit
    audit_writer: Optional[object] = None,  # AuditLogWriter | None — YSG-RISK-108 mesh audit
    document_pipeline: Optional[object] = None,  # DocumentInspectionPipeline | None — RESTART-013 gap #1
    opa_url: str = "",  # RESTART-013 gap #1 — needed by the document bridge's OPA decision
) -> Response:
    """
    Core MCP call handler.  Called DIRECTLY from the proxy catch-all AFTER the
    rate-limiter, DDoSProtector, and JWT introspection pipeline have already run.

    This function is NOT mounted as an extra_router.  It is invoked from
    _proxy_request_body() in proxy.py when the path matches /mcp/<agent_name>.
    That path means every MCP call is subject to the same rate-limiting,
    DDoS protection, and body-size checks as any other proxied request.

    The mcp_info_router (JWKS + /mcp/health) IS still mounted as an extra_router
    because those endpoints are public (no auth / no rate-limit needed —
    upstream verifiers need unconditional JWKS access).

    Parameters
    ----------
    agent_name:
        Path component extracted by the catch-all dispatcher — NEVER from body.
    request:
        The inbound FastAPI Request (headers + body already read by caller).
    registry:
        McpBrokerRegistry instance.
    response_inspection_pipeline:
        Optional ResponseInspectionPipeline instance.  When provided, the
        G-ORCH-OPA-1 egress gate runs the inspection pipeline over the
        upstream result to derive result_sensitivity and pii_detected before
        calling broker.enforce_result().  When None, result_sensitivity
        defaults to "PUBLIC" and pii_detected to False.  Both cases still
        invoke broker.enforce_result() — the OPA gate always runs.
    identity_registry:
        Optional IdentityRegistry instance.  When provided, the caller's
        sensitivity_ceiling is looked up from the registry (keyed by the
        X-Yashigani-Identity-Id — 4.1 SEC-GAP-1) and set on McpCallContext.caller_sensitivity_ceiling
        before the G-ORCH-OPA-1 egress enforce_result() call.  When absent,
        ctx.caller_sensitivity_ceiling remains None → OPA fails-closed.
        Passed from the proxy (openai_router._state.identity_registry) —
        no new store introduced (Option A / G-ORCH-OPA-1).
    agent_registry:
        Optional AgentRegistry instance.  When provided, the caller's
        ``allowed_tools`` list is looked up from the identity registry (keyed
        by caller_agent_id slug) and set on McpCallContext.caller_allowed_tools
        before broker.enforce().  When absent or caller not found, no per-caller
        tool restriction applies.  3.1 Phase 3 — tool allow-list enforcement.
    audit_writer:
        Optional AuditLogWriter instance.  When provided, mesh identity-header
        rejection events (YSG-RISK-108 T-3/T-4) are emitted to the tamper-
        evident audit chain.  When absent, rejections are logged only (WARNING).
    document_pipeline:
        Optional DocumentInspectionPipeline instance (RESTART-013 gap #1).
        When provided, EVERY ``tools/call`` runs its ``arguments`` (outbound,
        before forwarding to upstream) AND its upstream ``result`` (inbound,
        before returning to the caller) through
        ``documents/mcp_document_bridge.enforce_mcp_document_payload`` — the
        SAME OPA-decided REDACT/PSEUDONYMIZE/BLOCK decision the generic proxy
        egress (``gateway/proxy.py`` step 4d) uses. When ``None`` (the
        default — document enforcement is opt-in, see
        ``documents.proxy_modeb.is_modeb_proxy_active()``), MCP tool-call
        content is NOT inspected for document enforcement at all (unchanged
        pre-RESTART-013 behaviour) — the existing G-ORCH-OPA-1 response
        inspection (PII/injection classifier) and ``broker.enforce()``/
        ``enforce_result()`` OPA gates are untouched either way.
    opa_url:
        The OPA base URL (``cfg.opa_url`` in proxy.py) the document bridge
        needs to evaluate ``policy/document.rego``. Only used when
        ``document_pipeline`` is not None.
    """
    return await _handle_mcp_call_inner(
        agent_name=agent_name,
        request=request,
        registry=registry,
        response_inspection_pipeline=response_inspection_pipeline,
        identity_registry=identity_registry,
        agent_registry=agent_registry,
        audit_writer=audit_writer,
        document_pipeline=document_pipeline,
        opa_url=opa_url,
    )


async def _handle_mcp_call_inner(
    agent_name: str,
    request: Request,
    registry: object,
    response_inspection_pipeline: Optional[object] = None,  # ResponseInspectionPipeline | None
    identity_registry: Optional[object] = None,  # IdentityRegistry | None
    agent_registry: Optional[object] = None,  # AgentRegistry | None — 3.1 Phase 3
    audit_writer: Optional[object] = None,  # AuditLogWriter | None — YSG-RISK-108
    document_pipeline: Optional[object] = None,  # DocumentInspectionPipeline | None — RESTART-013 gap #1
    opa_url: str = "",  # RESTART-013 gap #1
) -> Response:
    """
    Core MCP call processing logic — shared by dispatch_mcp_call (catch-all path)
    and create_mcp_call_router (unit-test / standalone path).

    agent_name is the path component — NEVER read from the request body.
    """
    # ── YSG-RISK-108 / T-3 + T-4 — Mesh port identity-header trust gate ─────
    #
    # Runs BEFORE any resource lookup so that spoof attempts against any path
    # (including non-existent agents that would 404) are caught and audited.
    #
    # Identity-forwarding headers (X-Yashigani-Identity-Id, X-Yashigani-Orchestration-*)
    # are ONLY trusted if the caller proves internal mesh identity via:
    # 4.1 SEC-GAP-1: X-Forwarded-User removed; X-Yashigani-Identity-Id is the
    # canonical identity rail.
    #   (a) YASHIGANI_INTERNAL_BEARER — present on ALL legitimate mesh callers
    #       (orchestrator self-calls, OWUI, 4.0 native chat path), OR
    #   (b) X-Caddy-Verified-Secret — present on requests proxied through Caddy
    #       (SSO/API path via port 8080; Caddy strips inbound copies at the edge).
    #
    # An anonymous caller on port :8081 presenting identity headers without
    # proving either (a) or (b) is a header-spoof attempt (T-3 / T-4).
    # The header is stripped and the caller is treated as anonymous ("unknown").
    # A HIGH-severity audit event is emitted to the tamper-evident chain.
    from yashigani.auth.caddy_verified import validate_caddy_secret as _validate_caddy
    _caller_is_internal = _mesh_caller_is_internal(request)
    _caller_is_caddy = _validate_caddy(
        request.headers.get("x-caddy-verified-secret", "")
    )
    _caller_is_trusted = _caller_is_internal or _caller_is_caddy

    # T-3: X-Yashigani-Identity-Id trust gate (4.1 SEC-GAP-1 — replaces X-Forwarded-User)
    # Open WebUI is removed in 4.x; the native identity rail is X-Yashigani-Identity-Id.
    # Caddy STRIPS client-supplied X-Yashigani-Identity-Id at the public edge, so
    # any value in the header on an untrusted path is a spoof attempt.
    _iid_raw = request.headers.get("x-yashigani-identity-id", "").strip()
    if _iid_raw and not _caller_is_trusted:
        logger.warning(
            "mcp-runtime: YSG-RISK-108/T-3: unauthenticated caller on mesh port "
            "presented X-Yashigani-Identity-Id=%r without internal bearer or Caddy secret — "
            "stripped; caller treated as anonymous. path=%r",
            _iid_raw[:64],
            str(request.url.path)[:128],
        )
        if audit_writer is not None:
            try:
                from yashigani.audit.schema import MeshIdentityHeaderRejectedEvent
                audit_writer.write(MeshIdentityHeaderRejectedEvent(
                    path=str(request.url.path)[:256],
                    method=request.method,
                    rejected_header="x-yashigani-identity-id",
                    claimed_value_truncated=_iid_raw[:64],
                ))
            except Exception as _ae:
                logger.error(
                    "mcp-runtime: failed to write MESH_IDENTITY_HEADER_REJECTED event: %s", _ae
                )
        _iid_raw = ""  # strip — caller is anonymous

    # T-4: Orchestration-depth promotion gate
    # Priority 1: AgentAuthMiddleware sets agent_id on request.state for /agents/ paths.
    # Priority 2: X-Yashigani-Orchestration-Depth marks a gateway orchestrator self-call,
    #   BUT only when the caller has proven internal mesh identity.
    _caller_agent_id: Optional[str] = getattr(request.state, "agent_id", None)
    if not _caller_agent_id:
        _depth_hdr = request.headers.get("x-yashigani-orchestration-depth")
        if _depth_hdr is not None:
            if _caller_is_trusted:
                _caller_agent_id = "gateway:orchestrator"
            else:
                logger.warning(
                    "mcp-runtime: YSG-RISK-108/T-4: unauthenticated caller on mesh port "
                    "presented X-Yashigani-Orchestration-Depth=%r without internal bearer "
                    "or Caddy secret — NOT promoted to gateway:orchestrator. path=%r",
                    str(_depth_hdr)[:16],
                    str(request.url.path)[:128],
                )
                if audit_writer is not None:
                    try:
                        from yashigani.audit.schema import MeshOrchDepthForgedEvent
                        audit_writer.write(MeshOrchDepthForgedEvent(
                            path=str(request.url.path)[:256],
                            method=request.method,
                            depth_value_truncated=str(_depth_hdr)[:16],
                        ))
                    except Exception as _ae:
                        logger.error(
                            "mcp-runtime: failed to write MESH_ORCH_DEPTH_FORGED event: %s", _ae
                        )

    # ── v4.1 Phase 2a (LU-MCP-A1) — identity.verified derivation ───────────
    #
    # True ONLY when BOTH hold:
    #   (a) the caller proved the per-install Caddy HMAC (X-Caddy-Verified-
    #       Secret validated — Option C AND-coupling), AND
    #   (b) an x-spiffe-id header is present — Caddy sets it strip-then-set
    #       from the VERIFIED peer leaf's SPIFFE URI SAN (require_and_verify),
    #       and SpiffePeerCertMiddleware strips it when (a) fails.
    # Never derived from hostname (instance-leaf SANs are loopback-only) and
    # never from a client header alone: without the HMAC the header is treated
    # as a forge attempt.  Fail-closed default: False.
    _identity_verified = _caller_is_caddy and bool(
        request.headers.get("x-spiffe-id", "").strip()
    )

    # ── 1. Registry lookup ────────────────────────────────────────────────
    entry = registry.get(agent_name)  # type: ignore[attr-defined]
    if entry is None:
        logger.info("mcp-runtime: agent_name=%r not in registry — 404", agent_name)
        return JSONResponse(
            status_code=404,
            content={"error": "MCP_SERVER_NOT_FOUND", "agent_name": agent_name},
        )

    broker, server_cfg = entry

    # ── 2. Read + strip forwarding headers (posture is channel-derived) ───
    # Build a sanitised header dict — the XFF headers are removed so
    # nothing downstream can misread them for posture.
    _raw_headers = dict(request.headers)
    stripped_headers = {
        k: v for k, v in _raw_headers.items()
        if k.lower() not in _STRIP_HEADERS
    }

    # ── 3. Derive posture (always mcp-b for HTTP channel) ─────────────────
    transport_descriptor = McpHttpTransport(
        upstream_url=server_cfg.upstream_url,
        is_relay=False,
    )
    posture, posture_binding = transport_descriptor.derive_posture()
    # Verify invariant: HTTP channel must yield mcp-b
    if posture != McpPosture.MCP_B:
        logger.error(
            "mcp-runtime: unexpected posture=%r for HTTP channel (expected mcp-b) "
            "agent=%r — denying fail-closed",
            posture.value, agent_name,
        )
        return JSONResponse(
            status_code=403,
            content={"error": "POSTURE_INVARIANT_VIOLATION"},
        )

    # ── 4. Read body with size cap, then parse JSON ────────────────────────
    # Fix-3 (Laura ship-blocker): cap body before json.loads to prevent memory
    # exhaustion via a single multi-MiB JSON payload.  Defense in depth — the
    # bridge enforces the same cap independently.
    try:
        body_bytes = await request.body()
    except Exception as exc:
        logger.warning("mcp-runtime: body read error agent=%r: %s", agent_name, exc)
        return JSONResponse(status_code=400, content={"error": "BODY_READ_ERROR"})

    if len(body_bytes) > MCP_BODY_SIZE_LIMIT_BYTES:
        logger.warning(
            "mcp-runtime: body too large agent=%r size=%d limit=%d — 413",
            agent_name, len(body_bytes), MCP_BODY_SIZE_LIMIT_BYTES,
        )
        return JSONResponse(
            status_code=413,
            content={
                "error": "REQUEST_ENTITY_TOO_LARGE",
                "detail": f"Body exceeds {MCP_BODY_SIZE_LIMIT_BYTES} bytes",
            },
        )

    try:
        body_str = body_bytes.decode("utf-8")
        msg = json.loads(body_str)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning("mcp-runtime: invalid JSON body agent=%r: %s", agent_name, exc)
        return JSONResponse(
            status_code=400,
            content={"error": "INVALID_JSON"},
        )

    method = msg.get("method", "")
    params = msg.get("params") or {}
    msg_id = msg.get("id")  # None for notifications
    is_notification = msg_id is None

    # ── Identity settled above (top-of-function gate, YSG-RISK-108) ──────────
    # 4.1 SEC-GAP-1: identity_id comes from request.state.ysg_principal (set by
    # the proxy.py boundary resolver or openai_router) as the authoritative source.
    # Falls back to the trust-gated X-Yashigani-Identity-Id header (_iid_raw).
    # Never falls back to email or slug (Open WebUI removed in 4.x).
    _rp_mcp = getattr(request.state, "ysg_principal", None)
    user_id = (
        _rp_mcp.identity_id
        if _rp_mcp is not None
        else (_iid_raw or "unknown")
    )
    call_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())

    # G-ORCH-OPA-1: look up the caller's sensitivity_ceiling from the identity
    # registry (keyed by identity_id = idnt_{12hex}).
    # 4.1 SEC-GAP-1: use identity_registry.get(identity_id) directly since user_id
    # is now the canonical idnt_ key — no get_by_slug slug resolution needed.
    #
    # Fail-closed: if the registry is absent, or user_id is "unknown", or the
    # identity is not found, caller_sensitivity_ceiling stays None → OPA denies
    # with invalid_or_missing_caller_ceiling.  This is intentional: an
    # unauthenticated or registry-unavailable path must not allow result delivery.
    caller_sensitivity_ceiling: Optional[str] = None
    if identity_registry is not None and user_id != "unknown":
        try:
            identity_rec = identity_registry.get(user_id)  # type: ignore[attr-defined]
            if identity_rec is not None:
                # identity_rec is either an IdentityRecord dataclass or a dict
                # (Redis-backed registry returns a dict from get()).
                if hasattr(identity_rec, "sensitivity_ceiling"):
                    caller_sensitivity_ceiling = identity_rec.sensitivity_ceiling
                elif isinstance(identity_rec, dict):
                    caller_sensitivity_ceiling = identity_rec.get("sensitivity_ceiling")
        except Exception as reg_exc:
            # Registry lookup failure → leave ceiling None (fail-closed).
            logger.warning(
                "mcp-runtime: [G-ORCH-OPA-1] identity registry lookup failed "
                "for user_id=%r: %s — ceiling stays None (fail-closed)",
                user_id, reg_exc,
            )

    # 3.1 Phase 3 — resolve the caller's allowed_tools list from the identity
    # registry.  Lookup path:
    #   caller_agent_id (slug) → identity_registry.get_by_slug() → allowed_tools
    # Fallback: identity_registry.get(caller_agent_id) if get_by_slug misses.
    # "gateway:orchestrator" is exempt (unrestricted — skip lookup).
    # When caller_agent_id is None or identity_registry is absent, no restriction.
    caller_allowed_tools: Optional[list[str]] = None
    if (
        _caller_agent_id is not None
        and _caller_agent_id != "gateway:orchestrator"
        and identity_registry is not None
    ):
        try:
            # Primary: look up by slug (caller_agent_id is usually the slug/name)
            _caller_rec = identity_registry.get_by_slug(  # type: ignore[attr-defined]
                _caller_agent_id
            )
            if _caller_rec is None:
                # Fallback: look up by raw ID
                _caller_rec = identity_registry.get(  # type: ignore[attr-defined]
                    _caller_agent_id
                )
            if _caller_rec is not None:
                # IdentityRecord dataclass or dict from Redis-backed registry
                if hasattr(_caller_rec, "allowed_tools"):
                    _at = _caller_rec.allowed_tools
                elif isinstance(_caller_rec, dict):
                    _at = _caller_rec.get("allowed_tools")
                else:
                    _at = None
                # Only use it if it's a non-empty list — empty list = no restriction
                if _at:
                    caller_allowed_tools = list(_at)
        except Exception as _at_exc:
            # Lookup failure → no per-caller restriction (fail-open for tools
            # lookup specifically; the connection deny-by-default still applies).
            logger.warning(
                "mcp-runtime: [P3] caller allowed_tools lookup failed "
                "caller=%r: %s — no per-caller tool restriction applied",
                _caller_agent_id, _at_exc,
            )

    # ── 5. Route by method ────────────────────────────────────────────────
    if method in _GATED_METHODS:
        # tools/call — full broker.enforce() pipeline
        tool_name = params.get("name") if isinstance(params, dict) else None
        tool_args = params.get("arguments") if isinstance(params, dict) else None

        ctx = McpCallContext(
            tenant_id=server_cfg.tenant_id,
            agent_name=agent_name,
            user_id=user_id,
            posture=posture,
            posture_binding=posture_binding,
            action="mcp.tools.call",
            tool_name=tool_name,
            tool_args_redacted=tool_args,
            call_id=call_id,
            request_id=request_id,
            server_id=agent_name,
            # v4.0 Item B — stable mcp_id from server config (keyed in grants).
            # Empty string when mcp_id not yet minted (pre-4.0 or no Redis);
            # _check_connection_permit() falls back to server_id / agent_name.
            mcp_id=server_cfg.mcp_id,
            # v4.1 Phase 2a (LU-MCP-A1/A2): transport-derived verification flag
            # + the target instance's leaf fingerprint (durable registry /
            # onboard transaction).  Both flow into the OPA input
            # (identity.verified + target.cert_fingerprint).
            identity_verified=_identity_verified,
            target_cert_fingerprint=getattr(server_cfg, "cert_fingerprint", "") or "",
            # G-ORCH-OPA-1 / Option A: populate from identity registry lookup.
            # None when registry absent or user not found → fail-closed at egress.
            caller_sensitivity_ceiling=caller_sensitivity_ceiling,
            # 3.1 Phase 1 — caller identity for OPA input.
            caller_agent_id=_caller_agent_id,
            # 3.1 Phase 3 — per-caller tool allow-list (None = no restriction).
            caller_allowed_tools=caller_allowed_tools,
        )

        try:
            decision = await broker.enforce(ctx)  # type: ignore[attr-defined]
        except Exception as exc:
            logger.error(
                "mcp-runtime: broker.enforce raised unexpectedly agent=%r call_id=%s: %s",
                agent_name, call_id, exc,
            )
            return JSONResponse(
                status_code=502,
                content={"error": "BROKER_ERROR"},
            )

        if not decision.allow:
            logger.info(
                "mcp-runtime: OPA denied agent=%r method=%r tool=%r reason=%s",
                agent_name, method, tool_name, decision.deny_reason,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "MCP_TOOL_CALL_DENIED",
                    "deny_reason": decision.deny_reason,
                },
            )

        # ── RESTART-013 gap #1 — document enforcement on the OUTBOUND leg ──
        # (agent → tool arguments), AFTER the call is authorized (no point
        # inspecting content of a call that would be denied anyway) but
        # BEFORE it is forwarded to the upstream MCP server. This is the
        # FIRST place in the whole codebase a file inside an MCP tool-call
        # argument is ever extracted/matched/redacted/tokenized — previously
        # proxy.py's step 4d (the only document_pipeline call site) was
        # unreachable from /mcp/<agent_name> traffic (step 4c returns first).
        if document_pipeline is not None and isinstance(tool_args, dict) and tool_args:
            from yashigani.documents.mcp_document_bridge import (
                enforce_mcp_document_payload,
            )
            _doc_identity_id = user_id if user_id and user_id != "unknown" else ""
            try:
                _doc_outcome = await enforce_mcp_document_payload(
                    document_pipeline,  # type: ignore[arg-type]
                    opa_url=opa_url,
                    payload=tool_args,
                    request_id=request_id,
                    identity_id=_doc_identity_id,
                    tenant=server_cfg.tenant_id,
                    surface="mcp-tool-call",
                )
            except Exception as exc:
                # Fail-closed: the document bridge itself is designed to never
                # raise (see its own module docstring), but an unexpected
                # fault here must still withhold rather than silently forward
                # an uninspected document to an external MCP server.
                logger.error(
                    "mcp-runtime: [RESTART-013] document bridge raised on "
                    "tool-call arguments agent=%r call_id=%s: %s",
                    agent_name, call_id, exc,
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "MCP_DOCUMENT_ENFORCEMENT_ERROR",
                        "deny_reason": "mcp_document_enforcement_error",
                    },
                )
            if _doc_outcome.blocked:
                logger.info(
                    "mcp-runtime: [RESTART-013] document enforcement BLOCKED "
                    "tool-call arguments agent=%r call_id=%s tool=%r reason=%s",
                    agent_name, call_id, tool_name, _doc_outcome.block_reason,
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "MCP_DOCUMENT_BLOCKED",
                        "deny_reason": _doc_outcome.block_reason,
                        "code": "DOCUMENT_BLOCKED",
                        "user_message": (
                            "A file in this tool call was held by Yashigani "
                            "document enforcement and not forwarded."
                        ),
                    },
                )
            if _doc_outcome.transformed:
                # tool_args was mutated in place (same dict object nested
                # inside msg["params"]["arguments"]) — re-serialise the
                # request body so the transformed bytes (not the original
                # cleartext) are what actually reaches the upstream server.
                body_str = json.dumps(msg)

        # Allowed — forward to the bridge with the issued JWT
        try:
            async with McpHttpTransport(
                upstream_url=server_cfg.upstream_url,
                is_relay=False,
            ) as transport:
                upstream_response = await transport.forward(
                    mcp_request_json=body_str,
                    gateway_jwt=decision.issued_jwt,
                )
        except HttpTransportError as exc:
            logger.error(
                "mcp-runtime: upstream transport error agent=%r call_id=%s: %s",
                agent_name, call_id, exc,
            )
            return JSONResponse(
                status_code=502,
                content={"error": "UPSTREAM_UNREACHABLE"},
            )
        except Exception as exc:
            logger.error(
                "mcp-runtime: unexpected forward error agent=%r call_id=%s: %s",
                agent_name, call_id, exc,
            )
            return JSONResponse(
                status_code=502,
                content={"error": "UPSTREAM_ERROR"},
            )

        # ── RESTART-013 gap #1 — document enforcement on the INBOUND leg ───
        # (tool → agent result), BEFORE the G-ORCH-OPA-1 inspection below so
        # the sensitivity classifier + broker.enforce_result() ever see the
        # ALREADY-redacted/tokenized content (never MORE raw PII than
        # necessary reaches a second classifier). Runs on the whole parsed
        # JSON-RPC response object (envelope fields like "jsonrpc"/"id" are
        # short strings and are never mistaken for a document candidate — see
        # documents/mcp_document_bridge.py's payload-schema-agnostic walk).
        if document_pipeline is not None and upstream_response:
            from yashigani.documents.mcp_document_bridge import (
                enforce_mcp_document_payload,
            )
            try:
                _resp_obj = json.loads(upstream_response)
            except (json.JSONDecodeError, ValueError):
                _resp_obj = None
            if _resp_obj is not None:
                _doc_identity_id = user_id if user_id and user_id != "unknown" else ""
                try:
                    _doc_resp_outcome = await enforce_mcp_document_payload(
                        document_pipeline,  # type: ignore[arg-type]
                        opa_url=opa_url,
                        payload=_resp_obj,
                        request_id=request_id,
                        identity_id=_doc_identity_id,
                        tenant=server_cfg.tenant_id,
                        surface="mcp-tool-call",
                    )
                except Exception as exc:
                    logger.error(
                        "mcp-runtime: [RESTART-013] document bridge raised on "
                        "tool-call result agent=%r call_id=%s: %s",
                        agent_name, call_id, exc,
                    )
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "MCP_DOCUMENT_ENFORCEMENT_ERROR",
                            "deny_reason": "mcp_document_enforcement_error",
                        },
                    )
                if _doc_resp_outcome.blocked:
                    logger.info(
                        "mcp-runtime: [RESTART-013] document enforcement "
                        "BLOCKED tool-call result agent=%r call_id=%s tool=%r "
                        "reason=%s",
                        agent_name, call_id, tool_name, _doc_resp_outcome.block_reason,
                    )
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "MCP_DOCUMENT_BLOCKED",
                            "deny_reason": _doc_resp_outcome.block_reason,
                            "code": "DOCUMENT_BLOCKED",
                            "user_message": (
                                "A file returned by this tool call was held "
                                "by Yashigani document enforcement and not "
                                "delivered."
                            ),
                        },
                    )
                if _doc_resp_outcome.transformed:
                    upstream_response = json.dumps(_resp_obj)

        # ── G-ORCH-OPA-1 egress gate ──────────────────────────────────────
        #
        # Step 1: run the ResponseInspectionPipeline (when configured) to
        #   derive result_sensitivity and a PII flag.  This is the SAME
        #   inspection that runs on LLM responses (proxy.py / orchestrator.py)
        #   applied to MCP tool results.  Do NOT run a second classifier.
        #
        # Step 2: call broker.enforce_result() — an independent OPA decision
        #   layer on top of the content-filter.  Fail-closed: any exception
        #   in either step withholds the result.
        #
        # ctx.caller_sensitivity_ceiling is set above from the identity registry
        # lookup (Option A / G-ORCH-OPA-1).  When set, OPA compares the result
        # sensitivity against the caller's ceiling and allows/denies accordingly.
        # When None (registry absent or user not found), OPA fails-closed.
        result_sensitivity = "PUBLIC"
        pii_detected = False
        inspection_blocked = False

        try:
            if response_inspection_pipeline is not None and upstream_response:
                resp_insp = response_inspection_pipeline.inspect(  # type: ignore[union-attr]
                    response_body=upstream_response,
                    content_type="application/json",
                    request_id=request_id,
                    session_id=user_id,
                    agent_id=agent_name,
                )
                # ResponseInspectionResult.response_sensitivity is the
                # content-sensitivity label from the sensitivity_classifier.
                result_sensitivity = getattr(resp_insp, "response_sensitivity", "PUBLIC") or "PUBLIC"
                # Map inspection verdict to pii_detected flag for the OPA input.
                # BLOCKED verdict = content filter withheld the result entirely;
                # treat as pii_detected=True so OPA also denies (belt-and-suspenders).
                verdict = getattr(resp_insp, "verdict", "CLEAN")
                if verdict == "BLOCKED":
                    inspection_blocked = True
                    pii_detected = True
                elif verdict == "FLAGGED":
                    pii_detected = True
        except Exception as exc:
            # Fail-closed: inspection failure withholds the result.
            logger.error(
                "mcp-runtime: [G-ORCH-OPA-1] inspection error agent=%r call_id=%s: %s "
                "— fail-closed withhold",
                agent_name, call_id, exc,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "MCP_EGRESS_INSPECTION_ERROR",
                    "deny_reason": "inspection_error",
                },
            )

        if inspection_blocked:
            # Content filter already blocked it — don't bother with OPA.
            logger.info(
                "mcp-runtime: [G-ORCH-OPA-1] inspection BLOCKED agent=%r call_id=%s "
                "tool=%r — result withheld",
                agent_name, call_id, tool_name,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "MCP_EGRESS_BLOCKED",
                    "deny_reason": "response_inspection_blocked",
                    "code": "MCP_RESPONSE_INSPECTION_BLOCKED",
                    "user_message": (
                        "The tool result was withheld because the content "
                        "filter detected a potential injection in the response."
                    ),
                },
            )

        # OPA egress decision (always runs, independent of inspection).
        try:
            egress = await broker.enforce_result(  # type: ignore[attr-defined]
                ctx=ctx,
                result_sensitivity=result_sensitivity,
                pii_detected=pii_detected,
            )
        except Exception as exc:
            # Fail-closed: any error in the OPA egress path withholds result.
            logger.error(
                "mcp-runtime: [G-ORCH-OPA-1] enforce_result raised agent=%r call_id=%s: %s "
                "— fail-closed withhold",
                agent_name, call_id, exc,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "MCP_EGRESS_ERROR",
                    "deny_reason": "egress_decision_error",
                },
            )

        if not egress.allow:
            logger.info(
                "mcp-runtime: [G-ORCH-OPA-1] egress DENIED agent=%r call_id=%s "
                "tool=%r reason=%s code=%s",
                agent_name, call_id, tool_name, egress.deny_reason, egress.code,
            )
            # Return the self-describing deny contract.  The raw upstream result
            # is NEVER included in this response — it is withheld entirely.
            return JSONResponse(
                status_code=403,
                content={
                    "error": "MCP_EGRESS_DENIED",
                    "deny_reason": egress.deny_reason,
                    "code": egress.code,
                    "user_message": egress.user_message,
                    "policy_id": egress.policy_id,
                },
            )

        return Response(
            content=upstream_response.encode("utf-8"),
            status_code=200,
            media_type="application/json",
        )

    elif method in _SESSION_METHODS or is_notification:
        # Session management or notification — forward through with a
        # session-level gateway JWT (so the MCP server trusts the gateway).
        # No tools-gating enforce() — these are protocol-level messages.
        ctx_session = McpCallContext(
            tenant_id=server_cfg.tenant_id,
            agent_name=agent_name,
            user_id=user_id,
            posture=posture,
            posture_binding=posture_binding,
            action=f"mcp.session.{method.replace('/', '.').replace('-', '_')}",
            call_id=call_id,
            request_id=request_id,
            server_id=agent_name,
            # v4.0 Item B — stable mcp_id for session context (informational).
            mcp_id=server_cfg.mcp_id,
            # v4.1 Phase 2a — informational on session messages (no enforce()),
            # kept consistent with the gated ctx above.
            identity_verified=_identity_verified,
            target_cert_fingerprint=getattr(server_cfg, "cert_fingerprint", "") or "",
            # 3.1 Phase 1 — caller identity for session context (informational).
            caller_agent_id=_caller_agent_id,
        )

        # Issue a session-level JWT directly (no OPA gate for session messages)
        try:
            issuer = broker._issuer  # type: ignore[attr-defined]
            session_jwt = issuer.issue(
                user_id=user_id,
                agent_name=agent_name,
                posture=posture.value,
                posture_binding=posture_binding.to_dict(),
                action=ctx_session.action,
                call_id=call_id,
            )
        except Exception as exc:
            logger.error(
                "mcp-runtime: session JWT issuance failed agent=%r: %s", agent_name, exc
            )
            return JSONResponse(
                status_code=502,
                content={"error": "SESSION_JWT_ERROR"},
            )

        if is_notification:
            # Notification: forward + return 202 without waiting for a response
            try:
                async with McpHttpTransport(
                    upstream_url=server_cfg.upstream_url,
                    is_relay=False,
                ) as transport:
                    # For notifications we still use forward() which issues an HTTP
                    # POST — the bridge returns 202 and we mirror that.
                    upstream_response = await transport.forward(
                        mcp_request_json=body_str,
                        gateway_jwt=session_jwt,
                    )
            except HttpTransportError as exc:
                logger.warning(
                    "mcp-runtime: notification forward failed agent=%r: %s (non-fatal)",
                    agent_name, exc,
                )
                # Non-fatal for notifications — the bridge should return 202
                # but if the bridge is down we still return 202 to the client
            return Response(status_code=202)

        else:
            # Non-gated request (initialize, tools/list, etc.) — forward with JWT
            try:
                async with McpHttpTransport(
                    upstream_url=server_cfg.upstream_url,
                    is_relay=False,
                ) as transport:
                    upstream_response = await transport.forward(
                        mcp_request_json=body_str,
                        gateway_jwt=session_jwt,
                    )
            except HttpTransportError as exc:
                logger.error(
                    "mcp-runtime: session forward error agent=%r method=%r: %s",
                    agent_name, method, exc,
                )
                return JSONResponse(
                    status_code=502,
                    content={"error": "UPSTREAM_UNREACHABLE"},
                )
            except Exception as exc:
                logger.error(
                    "mcp-runtime: unexpected session forward error agent=%r method=%r: %s",
                    agent_name, method, exc,
                )
                return JSONResponse(
                    status_code=502,
                    content={"error": "UPSTREAM_ERROR"},
                )

            return Response(
                content=upstream_response.encode("utf-8"),
                status_code=200,
                media_type="application/json",
            )

    else:
        # Unknown method — pass through (forward with a session JWT)
        logger.debug(
            "mcp-runtime: unknown method=%r agent=%r — pass-through", method, agent_name
        )
        try:
            issuer = broker._issuer  # type: ignore[attr-defined]
            passthru_jwt = issuer.issue(
                user_id=user_id,
                agent_name=agent_name,
                posture=posture.value,
                posture_binding=posture_binding.to_dict(),
                action=f"mcp.passthrough.{method.replace('/', '.') or 'unknown'}",
                call_id=call_id,
            )
            async with McpHttpTransport(
                upstream_url=server_cfg.upstream_url,
                is_relay=False,
            ) as transport:
                upstream_response = await transport.forward(
                    mcp_request_json=body_str,
                    gateway_jwt=passthru_jwt,
                )
            return Response(
                content=upstream_response.encode("utf-8"),
                status_code=200,
                media_type="application/json",
            )
        except Exception as exc:
            logger.error(
                "mcp-runtime: pass-through error agent=%r method=%r: %s",
                agent_name, method, exc,
            )
            return JSONResponse(
                status_code=502,
                content={"error": "UPSTREAM_ERROR"},
            )


def create_mcp_call_router(
    registry: object,
    response_inspection_pipeline: Optional[object] = None,
    identity_registry: Optional[object] = None,
    document_pipeline: Optional[object] = None,  # RESTART-013 gap #1
    opa_url: str = "",  # RESTART-013 gap #1
) -> APIRouter:  # McpBrokerRegistry
    """
    Create the MCP call APIRouter.

    NOTE (Fix-1): this router is NO LONGER mounted as an extra_router in the gateway.
    Instead, proxy.py intercepts /mcp/<agent_name> in the catch-all dispatch path
    (after rate-limiter + DDoSProtector) and calls dispatch_mcp_call() directly.

    This router is preserved for:
    - Unit tests that mount it directly (TestMcpRuntimeRouter).
    - Future use in standalone deployments where the full gateway middleware is absent.

    Parameters
    ----------
    registry:
        McpBrokerRegistry instance — maps agent_name → (broker, server_config).
        Typed as object to avoid circular imports.
    response_inspection_pipeline:
        Optional ResponseInspectionPipeline for the G-ORCH-OPA-1 egress gate.
        When None, result_sensitivity defaults to "PUBLIC" and pii_detected
        to False (but the OPA egress gate still always runs).
    identity_registry:
        Optional IdentityRegistry instance.  When provided, caller sensitivity
        ceilings are looked up for the G-ORCH-OPA-1 egress gate.
        When None, ctx.caller_sensitivity_ceiling stays None → fail-closed deny.
    document_pipeline / opa_url:
        RESTART-013 gap #1 — see ``dispatch_mcp_call``'s docstring for the
        full explanation. Optional; None/empty preserves pre-existing
        behaviour (no document inspection on MCP traffic).
    """
    mcp_call_router = APIRouter()

    @mcp_call_router.post("/mcp/{agent_name}")
    async def handle_mcp_call(agent_name: str, request: Request) -> Response:
        """
        Inbound MCP JSON-RPC call — delegates to _handle_mcp_call_inner.

        agent_name is the path parameter — NEVER read from the request body.
        """
        return await _handle_mcp_call_inner(
            agent_name=agent_name,
            request=request,
            registry=registry,
            response_inspection_pipeline=response_inspection_pipeline,
            identity_registry=identity_registry,
            document_pipeline=document_pipeline,
            opa_url=opa_url,
        )

    return mcp_call_router
