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
import os
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

# #47 / G-NEW-5 / R3 — signed orchestration-principal claim header.  The gateway
# SIGNS this on forward (ES384, bound to the caller SPIFFE) and VERIFIES it on
# re-entry (SPIFFE-bound + jti replay-deduped), replacing the old TRUSTED header
# ``X-Yashigani-Caller-Agent-Id`` as the trust source for the OPA principal.
_PRINCIPAL_HEADER = "X-Yashigani-Orchestration-Principal"

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

    # ── #47 / G-NEW-5 / R3 — verify the orchestration principal (signed claim) ──
    # The authenticated caller (caller_agent_id, proven by PSK in AgentAuth) is
    # the PRESENTING workload on this hop.  Its SPIFFE identity binds any inbound
    # signed principal claim:
    #   * No claim header  → FIRST hop: the immediate caller IS the principal,
    #     and the gateway will MINT a fresh signed claim on forward.
    #   * Valid claim       → a RELAY hop: the verified principal_agent_id (bound
    #     to THIS caller's SPIFFE, not replayed) becomes the principal — a
    #     verified fact, not a trusted header.
    #   * Present-but-invalid (bad sig / wrong SPIFFE / expired / replayed) →
    #     FAIL-CLOSED 403 + audit (no silent trust).
    principal_agent_id = caller_agent_id
    principal_verified = False
    _principal_verifier = state.get("principal_verifier")
    _principal_tenant = state.get("principal_tenant_id", "default")
    _inbound_principal = request.headers.get(_PRINCIPAL_HEADER.lower(), "").strip()
    if _inbound_principal and _principal_verifier is not None:
        from yashigani.gateway.principal_token import (
            PrincipalClaimError,
            caller_spiffe_uri,
        )
        presenting_spiffe = caller_spiffe_uri(_principal_tenant, caller_agent_id)
        try:
            _claim = _principal_verifier.verify(
                _inbound_principal, presenting_spiffe=presenting_spiffe
            )
            principal_agent_id = _claim.get("principal_agent_id", caller_agent_id)
            principal_verified = True
        except PrincipalClaimError as exc:
            logger.warning(
                "route_agent_call: signed principal REJECTED (caller=%s target=%s): %s",
                caller_agent_id, target_agent_id, exc,
            )
            _write_denied_rbac_audit(
                audit_writer=audit_writer,
                caller_agent_id=caller_agent_id,
                target_agent_id=target_agent_id,
                path=path,
                opa_reason="principal_claim_unverifiable",
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
                    "agent_router: metric increment failed (principal_claim_unverifiable)",
                    exc_info=True,
                )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "AGENT_CALL_DENIED",
                    "reason": "principal_claim_unverifiable",
                    "target_agent_id": target_agent_id,
                },
            )

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

    # Look up the PRINCIPAL agent to get their RBAC groups.  The principal is the
    # VERIFIED orchestration principal (#47/G-NEW-5) — equal to the immediate
    # caller on the first hop, or the signed-and-verified upstream principal on a
    # relay hop.  Groups are resolved from the registry by the principal id, so
    # authority derives from the registry at adjudication time (not from the
    # claim's self-asserted groups).
    principal_agent = registry.get(principal_agent_id) or {}
    caller_groups = principal_agent.get("groups", [])

    # ── 3.1 Phase 4 — connection allow-list (agent→agent) ────────────────────
    # Deny-by-default: only target agents with an org-level AGENT grant are
    # reachable.  Group narrowing: a group grant of allow=False prevents the
    # principal's group from reaching the target even if the org allows it.
    # Runs BEFORE OPA so unlisted agents are denied before the OPA query fires.
    # Mirrors the MCP broker's _check_connection_permit pattern.
    #
    # principal_scope="agent", principal_id=principal_agent_id: agent-scope
    # grants (per-caller-agent narrowing) are now enforced by the principal tier.
    # Admins can create "agent-A may NOT call agent-B" grants independent of
    # the org-level allow.
    #
    # 3.2 TODO: when the agent egress-proxy transport lands, a parallel
    # resolve_boolean_grant(EXTERNAL_API, host, ...) call belongs here (or in
    # the transport layer) using the same _agent_perm_store and _ag_org_id.
    _agent_perm_store = state.get("permission_store")
    if _agent_perm_store is None:
        _a_env = os.environ.get("YASHIGANI_ENV", "").lower().strip()
        if _a_env in {"production", "staging"}:
            logger.error(
                "agent-router: [Phase4] permission_store unavailable in %r env — "
                "DENYING agent→agent call fail-closed. caller=%s target=%s",
                _a_env, caller_agent_id, target_agent_id,
            )
            _write_denied_rbac_audit(
                audit_writer=audit_writer,
                caller_agent_id=caller_agent_id,
                target_agent_id=target_agent_id,
                path=path,
                opa_reason="permission_store_unavailable",
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "AGENT_CALL_DENIED",
                    "reason": "permission_store_unavailable",
                    "target_agent_id": target_agent_id,
                },
            )
        # Dev/test: no permission store → no-op (backwards-compatible)
    else:
        from yashigani.permissions import ResourceType as _AgRT
        from yashigani.permissions import resolve_boolean_grant as _ag_resolve
        _ag_org_id = os.environ.get("YASHIGANI_ORG_ID", "default").strip() or "default"
        _ag_allowed = _ag_resolve(
            _AgRT.AGENT,
            target_agent_id,
            org_id=_ag_org_id,
            group_ids=caller_groups,           # VERIFIED principal's groups
            principal_scope="agent",           # caller is always an agent on this path
            principal_id=principal_agent_id,   # VERIFIED orchestration principal agent_id
            store=_agent_perm_store,
        )
        if not _ag_allowed:
            logger.info(
                "agent-router: [Phase4] connection not permitted caller=%s → target=%s "
                "(no AGENT grant for org=%s groups=%s)",
                caller_agent_id, target_agent_id, _ag_org_id, caller_groups,
            )
            _write_denied_rbac_audit(
                audit_writer=audit_writer,
                caller_agent_id=caller_agent_id,
                target_agent_id=target_agent_id,
                path=path,
                opa_reason="agent_not_permitted",
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
                    "(agent_not_permitted)", exc_info=True,
                )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "AGENT_CALL_DENIED",
                    "reason": "agent_not_permitted",
                    "target_agent_id": target_agent_id,
                },
            )

    # ── OPA enforcement (fail-closed) ─────────────────────────────────────────
    opa_url = config.opa_url if config is not None else "https://policy:8181"
    opa_input = {
        "principal": {
            "type": "agent",
            # The VERIFIED orchestration principal feeds OPA as a verified fact.
            "agent_id": principal_agent_id,
            "groups": caller_groups,
            # Provenance: True when bound to a signed, SPIFFE-bound, non-replayed
            # claim; False on the first hop (the gateway is the asserting
            # authority and mints the signed claim on forward).
            "verified": principal_verified,
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
        # Build forwarded headers — strip hop-by-hop and host; inject trace headers.
        # CRITICAL (#47/G-NEW-5): strip any inbound principal header so a caller
        # cannot smuggle a forged claim through to the upstream — the gateway is
        # the SOLE asserting authority and re-mints the claim below.
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in _HOP_BY_HOP and k.lower() != "host"
            and k.lower() != _PRINCIPAL_HEADER.lower()
        }
        headers["X-Yashigani-Caller-Agent-Id"] = caller_agent_id
        headers["X-Yashigani-Request-Id"] = getattr(request.state, "request_id", "")

        # ── #47 / G-NEW-5 / R3 — SIGN the orchestration principal on forward ──
        # The gateway (asserting authority) signs the VERIFIED principal bound to
        # the TARGET workload's SPIFFE identity — the workload that will PRESENT
        # the claim if it makes an onward call.  The downstream hop verifies the
        # signature and binds it to its own SPIFFE, so it cannot forge or replay a
        # principal it was not issued.  Fail-closed: if signing is unavailable we
        # do NOT forward a bare trusted principal — we reject (no silent
        # downgrade to the confused-deputy header).
        _principal_signer = state.get("principal_signer")
        if _principal_signer is not None:
            from yashigani.gateway.principal_token import (
                PrincipalClaimError,
                caller_spiffe_uri,
            )
            try:
                target_spiffe = caller_spiffe_uri(_principal_tenant, target_agent_id)
                headers[_PRINCIPAL_HEADER] = _principal_signer.sign(
                    principal_agent_id=principal_agent_id,
                    caller_spiffe=target_spiffe,
                    caller_groups=caller_groups,
                )
            except PrincipalClaimError as exc:
                logger.error(
                    "route_agent_call: principal signing failed (caller=%s target=%s): %s "
                    "— fail-closed (not forwarding a bare trusted principal)",
                    caller_agent_id, target_agent_id, exc,
                )
                return JSONResponse(
                    status_code=500,
                    content={
                        "error": "AGENT_PRINCIPAL_SIGN_FAILED",
                        "target_agent_id": target_agent_id,
                    },
                )

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
        # FIND-3.1-INT-AGENT-AUDIT: emit audit on upstream failure so OWASP A09
        # logging is satisfied.  Best-effort — audit must never break the 502.
        if audit_writer is not None:
            try:
                import httpx as _httpx
                from yashigani.audit.schema import AgentUpstreamUnreachableEvent
                _error_type = (
                    "timeout" if isinstance(exc, _httpx.TimeoutException)
                    else "connect_error" if isinstance(exc, _httpx.ConnectError)
                    else "unknown"
                )
                audit_writer.write(AgentUpstreamUnreachableEvent(
                    caller_agent_id=caller_agent_id,
                    target_agent_id=target_agent_id,
                    remainder_path=remainder_path,
                    request_id=getattr(request.state, "request_id", ""),
                    error_type=_error_type,
                ))
            except Exception:  # pragma: no cover — audit must never break the request
                pass
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
        # Use the VERIFIED principal's ceiling (the authoritative subject of the
        # call chain; #47/G-NEW-5).  Equal to the immediate caller on the first
        # hop, or the verified upstream principal on a relay hop.
        caller_sensitivity_ceiling = principal_agent.get("sensitivity_ceiling", "RESTRICTED")
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
