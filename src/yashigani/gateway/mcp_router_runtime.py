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
    call time (Option A: registry lookup keyed by user_id from X-Forwarded-User).
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
    "x-forwarded-user",  # stripped from downstream MCP call; preserved for identity resolution
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
        X-Forwarded-User slug) and set on McpCallContext.caller_sensitivity_ceiling
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
    """
    return await _handle_mcp_call_inner(
        agent_name=agent_name,
        request=request,
        registry=registry,
        response_inspection_pipeline=response_inspection_pipeline,
        identity_registry=identity_registry,
        agent_registry=agent_registry,
    )


async def _handle_mcp_call_inner(
    agent_name: str,
    request: Request,
    registry: object,
    response_inspection_pipeline: Optional[object] = None,  # ResponseInspectionPipeline | None
    identity_registry: Optional[object] = None,  # IdentityRegistry | None
    agent_registry: Optional[object] = None,  # AgentRegistry | None — 3.1 Phase 3
) -> Response:
    """
    Core MCP call processing logic — shared by dispatch_mcp_call (catch-all path)
    and create_mcp_call_router (unit-test / standalone path).

    agent_name is the path component — NEVER read from the request body.
    """
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

    # Resolve identity from the gateway-injected header (Caddy forward_auth)
    # X-Forwarded-User is stripped from downstream but available in inbound headers.
    user_id = _raw_headers.get("x-forwarded-user", "").strip() or "unknown"
    call_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())

    # 3.1 Phase 1 — resolve the calling agent's identity for the OPA input.
    #
    # Priority 1: AgentAuthMiddleware sets request.state.agent_id for requests
    #   authenticated via the agent PSK pathway (X-Yashigani-Caller-Agent-Id +
    #   Authorization: Bearer <PSK>).  This is the normal agent→MCP path.
    #
    # Priority 2: X-Yashigani-Orchestration-Depth header marks a gateway
    #   orchestrator self-call (see orchestrator._self_call_headers).  The
    #   reserved identity "gateway:orchestrator" is used so OPA policies can
    #   distinguish internal-gateway MCP hops from external agent hops.
    #
    # Priority 3: None — caller is unauthenticated or not yet identified.
    #   Phase 1 is additive: unbound policies treat an absent caller as no-op.
    _caller_agent_id: Optional[str] = getattr(request.state, "agent_id", None)
    if not _caller_agent_id:
        if _raw_headers.get("x-yashigani-orchestration-depth") is not None:
            _caller_agent_id = "gateway:orchestrator"

    # G-ORCH-OPA-1 / Option A: look up the caller's sensitivity_ceiling from
    # the identity registry (keyed by the X-Forwarded-User slug).  This is the
    # SAME registry the openai_router uses for identity resolution — no new store.
    # Result is set on McpCallContext.caller_sensitivity_ceiling before the egress
    # enforce_result() call.
    #
    # Fail-closed: if the registry is absent, or user_id is "unknown", or the
    # slug is not found, caller_sensitivity_ceiling stays None → OPA denies
    # with invalid_or_missing_caller_ceiling.  This is intentional: an
    # unauthenticated or registry-unavailable path must not allow result delivery.
    caller_sensitivity_ceiling: Optional[str] = None
    if identity_registry is not None and user_id != "unknown":
        try:
            identity_rec = identity_registry.get_by_slug(user_id)  # type: ignore[attr-defined]
            if identity_rec is not None:
                # identity_rec is either an IdentityRecord dataclass or a dict
                # (Redis-backed registry returns a dict from get_by_slug).
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
        )

    return mcp_call_router
