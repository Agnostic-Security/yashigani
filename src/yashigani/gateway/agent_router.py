"""
Yashigani Gateway — Agent-to-agent request router.

Called after AgentAuthMiddleware has authenticated the caller.
Looks up the target agent in the registry and proxies the request
to its configured upstream_url.

Path format: /agents/{target_agent_id}/{remainder_path}

Writes AGENT_CALL_ALLOWED, AGENT_CALL_DENIED_RBAC, AGENT_NOT_FOUND, or
AGENT_RESPONSE_BLOCKED_BY_OPA audit events. Updates Prometheus agent metrics.

OPA enforcement (ASVS V4.2 — local policy only, fail-closed):
  - Request leg: queries OPA at /v1/data/yashigani/agent_call_allowed.
    On deny or OPA unreachable: returns HTTP 403 + AgentCallDeniedRBACEvent.
  - Response leg (v2.24.1 — GAP-3 / SEC-5): after receiving the upstream
    response, classifies response-content sensitivity and queries OPA at
    /v1/data/yashigani/agent_response_decision.
    On deny: returns HTTP 403 + AgentResponseBlockedByOpaEvent (fail-closed).
    Closes the asymmetry between /v1/* (had response-OPA-check) and /agents/*
    (did not).  Symmetric to openai_router._opa_response_check.
"""
from __future__ import annotations

import logging
import time

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse

import types as _types

from yashigani.pki.client import internal_httpx_client
from yashigani.gateway._client_enforce import evaluate_client_policies


def _agent_cp_deny(audit_writer, caller_agent_id, direction, ce_result):
    """Audit a client-policy denial on the agent path (#16). Best-effort."""
    if audit_writer is None:
        return
    deny = list(ce_result.get("deny", []) or [])
    failclosed = {"client_enforce_unavailable", "client_enforce_undefined", "client_enforce_not_configured"}
    try:
        from yashigani.audit.schema import ClientPolicyDeniedEvent, ClientPolicyCheckFailedEvent
        if set(deny) & failclosed:
            audit_writer.write(ClientPolicyCheckFailedEvent(
                reason=next(iter(set(deny) & failclosed)), outcome="fail_closed", direction=direction))
        else:
            audit_writer.write(ClientPolicyDeniedEvent(
                identity_id=caller_agent_id, scope_kind="agent", scope_id=caller_agent_id,
                direction=direction, deny_codes=deny))
    except Exception:  # pragma: no cover — audit must never break the request
        pass

logger = logging.getLogger(__name__)

_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})

_OPA_AGENT_ALLOWED_PATH = "/v1/data/yashigani/agent_call_allowed"

# LAURA-OPA-001 (2.25.2): path-traversal confused-deputy guard.
# httpx collapses dot-segments ("/do/../admin" -> "/admin") on the wire per
# RFC-3986, while the OPA gate matched the UN-collapsed path with literal
# startswith — so an agent scoped to "/do/**" could reach "/admin". We reject
# any remainder_path that contains a traversal sequence (raw or percent-encoded,
# single- or double-encoded) BEFORE building the OPA input AND before forwarding,
# so OPA evaluates a path byte-identical to what httpx forwards (no parser
# differential). Fail-closed: ambiguous/encoded paths are rejected, not silently
# normalised. Mirrors the agents.rego _agent_path_safe guard.
_TRAVERSAL_TOKENS = (
    "../", "..\\",
    "%2e", "%2f", "%5c",            # encoded dot / forward-slash / back-slash
    "%252e", "%252f", "%255c",      # double-encoded
)


def _is_path_traversal(remainder_path: str) -> bool:
    """True if remainder_path contains any dot-segment or encoded traversal token.

    Case-insensitive on the encoded forms. Also rejects a bare/ trailing ".."
    segment that the substring check would otherwise miss.
    """
    lowered = remainder_path.lower()
    if any(tok in lowered for tok in _TRAVERSAL_TOKENS):
        return True
    # bare ".." or a trailing "/.." segment
    if remainder_path == ".." or remainder_path.endswith("/.."):
        return True
    return False
# v2.24.1 — GAP-3 / SEC-5: response-leg OPA check
_OPA_AGENT_RESPONSE_PATH = "/v1/data/yashigani/agent_response_decision"


async def route_agent_call(request: Request, path: str, state: dict) -> Response:
    """
    Handle an authenticated agent-to-agent request.

    Steps:
    1. Parse target_agent_id and remainder_path from path
    2. Look up target agent in registry — must be active
    3. If not found / inactive: return 404 + AGENT_NOT_FOUND audit event
    4. Look up caller agent in registry to get caller's groups
    5. Query OPA for agent_call_allowed — fail-closed on error
    6. If OPA denies: return 403 + AGENT_CALL_DENIED_RBAC audit event
    7. Forward request to upstream_url/remainder_path
    8. Write AGENT_CALL_ALLOWED audit event and update Prometheus metrics
    9. Return upstream response to caller (strip hop-by-hop headers)
    """
    registry = state.get("agent_registry")
    audit_writer = state.get("audit_writer")
    config = state.get("config")

    # Normalise path to always start with /
    if not path.startswith("/"):
        path = "/" + path

    # Parse /agents/{target_agent_id}/{remainder}
    prefix = "/agents/"
    if not path.startswith(prefix):
        return JSONResponse(status_code=400, content={"error": "INVALID_AGENT_PATH"})

    remainder = path[len(prefix):]
    parts = remainder.split("/", 1)
    target_agent_id = parts[0]
    remainder_path = "/" + parts[1] if len(parts) > 1 else "/"

    caller_agent_id = getattr(request.state, "agent_id", "unknown")

    # LAURA-OPA-001: reject path traversal BEFORE OPA evaluation and forwarding.
    # The path OPA sees must be byte-identical to what httpx forwards; rejecting
    # traversal up front eliminates the parser differential (fail-closed).
    if _is_path_traversal(remainder_path):
        logger.warning(
            "route_agent_call: path traversal rejected (caller=%s target=%s remainder=%r)",
            caller_agent_id, target_agent_id, remainder_path,
        )
        _write_denied_rbac_audit(
            audit_writer=audit_writer,
            caller_agent_id=caller_agent_id,
            target_agent_id=target_agent_id,
            path=path,
            opa_reason="path_traversal_attempt",
        )
        try:
            from yashigani.metrics.registry import agent_calls_total
            agent_calls_total.labels(
                caller_agent_id=caller_agent_id,
                target_agent_id=target_agent_id,
                outcome="denied_rbac",
            ).inc()
        except Exception:
            logger.debug(
                "agent_router: metric increment failed for agent_calls_total "
                "(path_traversal)", exc_info=True,
            )
        return JSONResponse(
            status_code=403,
            content={
                "error": "AGENT_CALL_DENIED",
                "reason": "path_traversal_attempt",
                "target_agent_id": target_agent_id,
            },
        )

    # Registry must be available
    if registry is None:
        logger.error("route_agent_call: agent_registry not in state")
        return JSONResponse(
            status_code=503,
            content={"error": "AGENT_REGISTRY_UNAVAILABLE"},
        )

    # Look up target agent — must exist and be active
    target_agent = registry.get(target_agent_id)
    if target_agent is None or target_agent.get("status") != "active":
        _write_not_found_audit(
            audit_writer=audit_writer,
            caller_agent_id=caller_agent_id,
            target_agent_id=target_agent_id,
            path=path,
        )
        return JSONResponse(
            status_code=404,
            content={
                "error": "AGENT_NOT_FOUND",
                "target_agent_id": target_agent_id,
            },
        )

    # Look up caller agent to get their RBAC groups
    caller_agent = registry.get(caller_agent_id) or {}
    caller_groups = caller_agent.get("groups", [])

    # ── OPA enforcement (fail-closed) ─────────────────────────────────────────
    opa_url = config.opa_url if config is not None else "https://policy:8181"
    opa_input = {
        "principal": {
            "type": "agent",
            "agent_id": caller_agent_id,
            "groups": caller_groups,
        },
        "target_agent": {
            "agent_id": target_agent_id,
            "allowed_caller_groups": target_agent.get("allowed_caller_groups", []),
            "allowed_paths": target_agent.get("allowed_paths", []),
        },
        "request": {
            "method": request.method,
            "remainder_path": remainder_path,
        },
    }

    opa_allowed, opa_reason = await _opa_agent_check(opa_url, opa_input)

    if not opa_allowed:
        _write_denied_rbac_audit(
            audit_writer=audit_writer,
            caller_agent_id=caller_agent_id,
            target_agent_id=target_agent_id,
            path=path,
            opa_reason=opa_reason,
        )
        try:
            from yashigani.metrics.registry import agent_calls_total
            agent_calls_total.labels(
                caller_agent_id=caller_agent_id,
                target_agent_id=target_agent_id,
                outcome="denied_rbac",
            ).inc()
        except Exception:
            logger.debug("agent_router: metric increment failed for agent_calls_total (denied_rbac)", exc_info=True)
        return JSONResponse(
            status_code=403,
            content={
                "error": "AGENT_CALL_DENIED",
                "reason": opa_reason,
                "target_agent_id": target_agent_id,
            },
        )

    # ── Client-policy enforcement — INGRESS (#16, agent scope) ──
    # After the agent_call_allowed gate; deny-only, fail-closed; no-op if unbound.
    _ce_in = await evaluate_client_policies(
        _types.SimpleNamespace(opa_url=opa_url), "agent", caller_agent_id, "ingress",
        {"identity": {"agent": caller_agent_id, "groups": caller_groups},
         "request": {"path": path, "method": request.method},
         "target_agent": {"agent_id": target_agent_id}},
    )
    if not _ce_in.get("allow", False):
        _ce_reason = (",".join(_ce_in.get("deny", []) or ["client_policy_denied"])).encode("ascii", "replace").decode("ascii")
        logger.warning("CLIENT-POLICY DENIED agent ingress: caller=%s target=%s deny=%s",
                       caller_agent_id, target_agent_id, _ce_reason)
        _agent_cp_deny(audit_writer, caller_agent_id, "ingress", _ce_in)
        return JSONResponse(
            status_code=403,
            content={"error": "CLIENT_POLICY_DENIED", "reason": _ce_reason,
                     "target_agent_id": target_agent_id},
            headers={"X-Yashigani-Client-Policy-Reason": _ce_reason},
        )

    upstream_url = target_agent["upstream_url"]

    # Forward request to upstream
    start = time.monotonic()
    try:
        body = await request.body()
        # Build forwarded headers — strip hop-by-hop and host; inject trace headers
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in _HOP_BY_HOP and k.lower() != "host"
        }
        headers["X-Yashigani-Caller-Agent-Id"] = caller_agent_id
        headers["X-Yashigani-Request-Id"] = getattr(request.state, "request_id", "")

        async with httpx.AsyncClient(timeout=30.0) as client:
            upstream_resp = await client.request(
                method=request.method,
                url=upstream_url.rstrip("/") + remainder_path,
                content=body,
                headers=headers,
            )
    except Exception as exc:
        logger.error(
            "route_agent_call: upstream unreachable for %s → %s%s: %s",
            caller_agent_id, target_agent_id, remainder_path, exc,
        )
        return JSONResponse(
            status_code=502,
            content={
                "error": "AGENT_UPSTREAM_UNREACHABLE",
                "detail": "Upstream agent is unreachable. Check agent health and network connectivity.",
                "target_agent_id": target_agent_id,
            },
        )

    elapsed_ms = int((time.monotonic() - start) * 1000)

    # Prometheus metrics
    try:
        from yashigani.metrics.registry import (
            agent_calls_total,
            agent_call_duration_seconds,
        )
        agent_calls_total.labels(
            caller_agent_id=caller_agent_id,
            target_agent_id=target_agent_id,
            outcome="allowed",
        ).inc()
        agent_call_duration_seconds.labels(
            caller_agent_id=caller_agent_id,
            target_agent_id=target_agent_id,
        ).observe(elapsed_ms / 1000)
    except Exception:
        logger.debug("agent_router: metric increment failed for agent_calls_total/agent_call_duration_seconds (allowed)", exc_info=True)

    # ── Response-leg OPA check (v2.24.1 — GAP-3 / SEC-5) ─────────────────────
    # Classify response-content sensitivity and query OPA.  Fail-closed on
    # any OPA error.  Symmetric to openai_router._opa_response_check.
    # Only runs when OPA URL is configured (same guard as /v1/* path).
    opa_url = config.opa_url if config is not None else "https://policy:8181"
    response_sensitivity_value = "PUBLIC"
    response_pii_detected = False

    # Attempt sensitivity classification of the response body
    response_inspection_pipeline = state.get("response_inspection_pipeline")
    if response_inspection_pipeline is not None and upstream_resp.content:
        try:
            resp_ct = upstream_resp.headers.get("content-type", "application/octet-stream")
            resp_body_text = upstream_resp.text
            resp_insp = response_inspection_pipeline.inspect(
                response_body=resp_body_text,
                content_type=resp_ct,
                request_id=getattr(request.state, "request_id", caller_agent_id),
                session_id=caller_agent_id,
                agent_id=caller_agent_id,
            )
            if not resp_insp.skipped:
                response_sensitivity_value = resp_insp.response_sensitivity
        except Exception as exc:
            logger.warning(
                "route_agent_call: response inspection failed "
                "(caller=%s → target=%s): %s",
                caller_agent_id, target_agent_id, exc,
            )

    # OPA response-leg check — fail-closed
    if opa_url:
        caller_sensitivity_ceiling = caller_agent.get("sensitivity_ceiling", "RESTRICTED")
        resp_opa_input = {
            "caller": {
                "agent_id": caller_agent_id,
                "groups": caller_groups,
                "sensitivity_ceiling": caller_sensitivity_ceiling,
            },
            "target_agent": {
                "agent_id": target_agent_id,
            },
            "response_sensitivity": response_sensitivity_value,
            "response_pii_detected": response_pii_detected,
        }
        resp_opa_allowed, resp_opa_reason = await _opa_agent_response_check(
            opa_url, resp_opa_input
        )
        if not resp_opa_allowed:
            logger.warning(
                "route_agent_call: OPA BLOCKED response delivery "
                "(caller=%s → target=%s) response_sensitivity=%s reason=%s",
                caller_agent_id, target_agent_id,
                response_sensitivity_value, resp_opa_reason,
            )
            if audit_writer is not None:
                try:
                    from yashigani.audit.schema import AgentResponseBlockedByOpaEvent
                    audit_writer.write(AgentResponseBlockedByOpaEvent(
                        caller_agent_id=caller_agent_id,
                        target_agent_id=target_agent_id,
                        response_sensitivity=response_sensitivity_value,
                        deny_reason=resp_opa_reason,
                        request_id=getattr(request.state, "request_id", ""),
                        pii_detected=response_pii_detected,
                    ))
                except Exception as exc:
                    logger.error(
                        "route_agent_call: failed to write AgentResponseBlockedByOpaEvent: %s",
                        exc,
                    )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "AGENT_RESPONSE_BLOCKED",
                    "reason": resp_opa_reason,
                    "target_agent_id": target_agent_id,
                },
                headers={
                    "X-Yashigani-OPA-Response-Reason": resp_opa_reason,
                },
            )

    # ── Client-policy enforcement — EGRESS (#16, agent scope) ──
    # After the core response-leg OPA gate; deny-only, fail-closed; no-op if unbound.
    _ce_eg = await evaluate_client_policies(
        _types.SimpleNamespace(opa_url=opa_url), "agent", caller_agent_id, "egress",
        {"identity": {"agent": caller_agent_id, "groups": caller_groups},
         "request": {"path": path, "method": request.method},
         "target_agent": {"agent_id": target_agent_id},
         "response_sensitivity": response_sensitivity_value},
    )
    if not _ce_eg.get("allow", False):
        _ce_eg_reason = (",".join(_ce_eg.get("deny", []) or ["client_policy_denied"])).encode("ascii", "replace").decode("ascii")
        logger.warning("CLIENT-POLICY BLOCKED agent egress: caller=%s target=%s deny=%s",
                       caller_agent_id, target_agent_id, _ce_eg_reason)
        _agent_cp_deny(audit_writer, caller_agent_id, "egress", _ce_eg)
        return JSONResponse(
            status_code=403,
            content={"error": "CLIENT_POLICY_DENIED", "reason": _ce_eg_reason,
                     "target_agent_id": target_agent_id},
            headers={"X-Yashigani-Client-Policy-Reason": _ce_eg_reason},
        )

    # Audit event
    if audit_writer is not None:
        try:
            from yashigani.audit.schema import AgentCallAllowedEvent
            audit_writer.write(AgentCallAllowedEvent(
                caller_agent_id=caller_agent_id,
                target_agent_id=target_agent_id,
                path=path,
                remainder_path=remainder_path,
                pipeline_action="forwarded",
                classification="CLEAN",
            ))
        except Exception as exc:
            logger.error("route_agent_call: failed to write allowed audit event: %s", exc)

    # Build response — strip hop-by-hop headers
    resp_headers = {
        k: v for k, v in upstream_resp.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=resp_headers,
        media_type=upstream_resp.headers.get("content-type"),
    )


# ---------------------------------------------------------------------------
# OPA agent response-leg check (v2.24.1 — GAP-3 / SEC-5)
# ---------------------------------------------------------------------------

async def _opa_agent_response_check(opa_url: str, opa_input: dict) -> tuple[bool, str]:
    """
    Query OPA agent_response_decision for allow/deny on response delivery.

    Fail-closed: any OPA error → (False, "opa_unreachable").
    Mirrors openai_router._opa_response_check for /v1/*.

    Returns (allowed: bool, reason: str).
    """
    try:
        async with internal_httpx_client(timeout=5.0) as client:
            resp = await client.post(
                opa_url.rstrip("/") + _OPA_AGENT_RESPONSE_PATH,
                json={"input": opa_input},
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            result = data.get("result", {})
            allowed = bool(result.get("allow", False))
            reason = result.get("reason", "opa_denied")
            return allowed, reason
    except Exception as exc:
        logger.error(
            "route_agent_call: OPA response check FAILED — denying (fail-closed). "
            "caller=%s → target=%s exc=%s",
            opa_input.get("caller", {}).get("agent_id", "unknown"),
            opa_input.get("target_agent", {}).get("agent_id", "unknown"),
            exc,
        )
        return False, "opa_unreachable"


# ---------------------------------------------------------------------------
# OPA agent call check
# ---------------------------------------------------------------------------

async def _opa_agent_check(opa_url: str, opa_input: dict) -> tuple[bool, str]:
    """
    Query OPA for agent_call_allowed decision.
    Returns (allowed: bool, reason: str).
    Fail-closed: any OPA error returns (False, "opa_unreachable").
    """
    try:
        async with internal_httpx_client(timeout=5.0) as client:
            resp = await client.post(
                opa_url.rstrip("/") + _OPA_AGENT_ALLOWED_PATH,
                json={"input": opa_input},
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            allowed = bool(data.get("result", False))
            if allowed:
                return True, ""
            # Try to get deny reason
            return False, "opa_denied"
    except Exception as exc:
        logger.error(
            "route_agent_call: OPA unreachable for agent check "
            "(caller=%s → target=%s): %s — denying (fail-closed)",
            opa_input.get("principal", {}).get("agent_id", "unknown"),
            opa_input.get("target_agent", {}).get("agent_id", "unknown"),
            exc,
        )
        return False, "opa_unreachable"


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------

def _write_not_found_audit(
    audit_writer,
    caller_agent_id: str,
    target_agent_id: str,
    path: str,
) -> None:
    if audit_writer is None:
        return
    try:
        from yashigani.audit.schema import AgentNotFoundEvent
        audit_writer.write(AgentNotFoundEvent(
            caller_agent_id=caller_agent_id,
            target_agent_id_requested=target_agent_id,
            path=path,
        ))
    except Exception as exc:
        logger.error("route_agent_call: failed to write not-found audit event: %s", exc)


def _write_denied_rbac_audit(
    audit_writer,
    caller_agent_id: str,
    target_agent_id: str,
    path: str,
    opa_reason: str,
) -> None:
    if audit_writer is None:
        return
    try:
        from yashigani.audit.schema import AgentCallDeniedRBACEvent
        audit_writer.write(AgentCallDeniedRBACEvent(
            caller_agent_id=caller_agent_id,
            target_agent_id=target_agent_id,
            path=path,
            opa_reason=opa_reason,
        ))
    except Exception as exc:
        logger.error("route_agent_call: failed to write denied-rbac audit event: %s", exc)
