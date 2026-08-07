# Last updated: 2026-07-06T00:00:00+00:00
"""
General egress evaluation proxy — v4.1.

Egress analogue of /auth/verify-mcp + broker M4 content filter.  Every
sidecar-wrapped system's outbound body traverses this endpoint before reaching
the network — the same way ingress bodies traverse the broker's M4 content
filter.

Ingress flow:  [wrapped-system] → Caddy :NNNN (mTLS stamp)
               → /auth/verify-mcp (authz gate, no body)
               → broker M4 filter (body inspection)
               → upstream MCP tool

Egress flow:   [wrapped-system] → Caddy :18790/{prefix}/* (mTLS stamp + HMAC)
               → gateway /egress/eval/{prefix}/{path} (body seen here)
               → inspect: secret_detector (Layer 0) + M4 injection check
               → OPA mcp_response_decision (fail-closed, default-DENY)
               → on ALLOW: Caddy :18790/deliver/{prefix}/{path}
               → final destination (Slack, Telegram, …)

Codegen interface (wired into sidecar-wraps by Captain):
  Endpoint:  POST|GET|PUT … https://gateway:8080/egress/eval/{prefix}/{path}
  Auth:      mTLS through Caddy (stamps X-SPIFFE-ID from verified peer cert
             URI SAN) + X-Caddy-Verified-Secret Layer B HMAC
  Body:      the outbound payload (verbatim — gateway sees it here)
  Response:  200 + upstream body on ALLOW
             403 + {"error": reason, "message": user_msg} on DENY
             403 + {"error": "missing_caller_identity"} when X-SPIFFE-ID absent
             502 + {"error": "egress_forward_failed"} on upstream error

Sensitivity ceiling:
  Per-prefix (YSG-RISK-170, chat-path repair 2026-07-30): ``_EGRESS_CEILING_BY_PREFIX``
  maps the ``llm`` prefix — the agent's OWN reasoning/completion self-call to
  the fully-internal ``gateway-inference`` destination (bundles/*-egress.yaml
  mark it a "Reserved internal class", never internet-facing) — to
  ``_EGRESS_LLM_CEILING = "RESTRICTED"`` (i.e. no artificial cap beyond this
  gate's own classifier maximum). Every other prefix (``slack``,
  ``slack-hooks``, ``telegram``, and any future prefix) keeps
  ``_EGRESS_EXTERNAL_CEILING = "PUBLIC"`` — correct for genuinely external
  notification destinations. Applying PUBLIC uniformly to the ``llm`` prefix
  previously false-DENYed an agent's own trivial self-call the instant the M4
  injection-pattern heuristic produced a false positive on ordinary
  system-prompt/tool-schema text (confirmed live: openclaw's embedded agent
  403'd on "Please reply with a one-sentence greeting" with
  ``result_sensitivity_exceeds_caller_ceiling``, surfaced to the user as a
  masked 500). The independent hard PII/secrets gate (``mcp.rego``'s
  ``pii_detected`` check) is UNCHANGED and still denies regardless of ceiling
  — this fix does not weaken genuine DLP enforcement, only corrects a ceiling
  meant for external egress that was misapplied to an internal self-call class.

Design notes:
  * No second filter: the exact same ``filter_description()`` + ``scan_secrets()``
    pipeline from broker.py runs here.  One filter, both directions (ingress
    checked at broker M4; egress checked here before OPA).
  * over_char_cap alone does NOT make a body RESTRICTED — large clean
    notification payloads (e.g. Slack Block Kit) are legitimate traffic.
    Only ``reject_reason.startswith("injection_pattern")`` triggers the
    RESTRICTED classification.
  * Body is NEVER stored in audit records — only the SHA-256 hash.
  * Fail-closed: any OPA error (timeout, unreachable, undefined rule) →
    EgressDecision.allow=False → 403 returned.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from yashigani.mcp._content_filter import filter_description
from yashigani.inspection.secret_detector import scan as scan_secrets
from yashigani.mcp._opa import query_mcp_response_decision
from yashigani.pki.client import internal_httpx_client

logger = logging.getLogger(__name__)

# External notification services (Slack, Telegram) have a PUBLIC sensitivity
# ceiling.  Any body classified above PUBLIC is withheld.
_EGRESS_EXTERNAL_CEILING = "PUBLIC"

# YSG-RISK-170: the "llm" prefix is a Reserved internal class (agent's own
# reasoning self-call to gateway-inference — see module docstring). RESTRICTED
# is the top of the rank scale in policy/mcp.rego (_result_ceiling_rank), so
# using it here means "no artificial ceiling cap for this class" while the
# SEPARATE hard PII/secrets gate (mcp.rego pii_detected check) remains fully
# enforced regardless.
_EGRESS_LLM_CEILING = "RESTRICTED"

_EGRESS_CEILING_BY_PREFIX: dict[str, str] = {
    "llm": _EGRESS_LLM_CEILING,
}


def _egress_ceiling_for_prefix(prefix: str) -> str:
    """Resolve the caller sensitivity ceiling for this egress prefix (RISK-170)."""
    return _EGRESS_CEILING_BY_PREFIX.get(prefix, _EGRESS_EXTERNAL_CEILING)

# Headers that must not be forwarded from gateway to the Caddy deliver path.
_STRIP_FORWARD_HEADERS = frozenset({
    "host",
    "x-spiffe-id",
    "x-caddy-verified-secret",
    "x-yashigani-verified-spiffe",
    "x-yashigani-mcp-caller",
    "content-length",        # httpx recomputes from body
    "transfer-encoding",     # httpx handles framing
})


@dataclass
class EgressProxyState:
    opa_url: str = ""
    audit_writer: Any = field(default=None, repr=False)
    caddy_egress_base: str = "https://caddy:18790"
    egress_limit_enforcer: Any = field(default=None, repr=False)


_state = EgressProxyState()
router = APIRouter()


def configure(
    *,
    opa_url: str,
    audit_writer: Any,
    caddy_egress_base: str = "",
    egress_limit_enforcer: Any = None,
) -> None:
    """
    Wire the egress proxy state.  Called from gateway entrypoint.py lifespan.

    ``caddy_egress_base`` is taken from the YASHIGANI_CADDY_EGRESS_BASE env
    var when not passed explicitly; falls back to ``"https://caddy:18790"``.

    ``egress_limit_enforcer`` is an optional
    :class:`~yashigani.gateway.egress_limit.EgressLimitEnforcer` instance.
    When supplied, every request through ``/egress/eval`` is counted and
    checked against the per-instance cap BEFORE body inspection and OPA.
    When ``None``, the limiter is skipped (graceful degradation on Redis
    unavailability during startup — cap is wired in entrypoint.py with a
    try/except so Redis failure only disables the limiter, it does not abort
    the gateway).
    """
    _state.opa_url = opa_url
    _state.audit_writer = audit_writer
    _state.caddy_egress_base = (
        caddy_egress_base
        or os.getenv("YASHIGANI_CADDY_EGRESS_BASE", "https://caddy:18790")
    )
    _state.egress_limit_enforcer = egress_limit_enforcer
    logger.info(
        "egress-eval: configured opa_url=%s caddy_egress_base=%s "
        "egress_limit_enforcer=%s",
        opa_url,
        _state.caddy_egress_base,
        "enabled" if egress_limit_enforcer is not None else "disabled",
    )


# ---------------------------------------------------------------------------
# Egress evaluation endpoint
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# _inspectable_payload — YSG-RISK-200 (2026-08-07)
#
# The egress inspector scanned the WHOLE transport envelope. Every
# OpenAI-compatible response carries a random correlation id (`chatcmpl-<hex>`),
# and `entropy_blob` fires on it once the drawn characters push Shannon entropy
# past the floor. Measured false-positive rate on synthetic ids: 10.2% at 12 hex,
# 30.8% at 17, 79.8% at uuid length. The consequence was a per-request coin flip:
# `pii_detected` -> result_sensitivity=RESTRICTED -> OPA deny
# `pii_detected_in_result` -> the agent's LLM backend 403s -> 500 -> gateway
# reports 502 `agent_unreachable`. That presented as flaky networking and outran
# three campaigns; `@letta` (uuid-style ids) failed 3/3 while `@agent_langflow`
# (short ids) mostly worked.
#
# Fix: inspect what a human wrote or a model produced — message content — not the
# structural envelope the transport generated. Structural identifiers, timestamps
# and token counters carry no user data by construction, so excluding them cannot
# lose a real secret; a secret that appears ONLY in a `chatcmpl-` id and nowhere in
# any content field is not a data path that exists.
#
# Deliberately NOT done: raising the entropy threshold. That would weaken real
# secret detection everywhere to paper over one field. Nor a fourth per-shape
# guard — YSG-RISK-173 already added three (slash-enumeration, word-check,
# reassembly windowing) and this is the second shape to slip past them in one
# release; guarding shapes one at a time does not converge.
#
# Fail-closed: anything that is not a recognisable envelope is scanned whole.
# ---------------------------------------------------------------------------
_OPENAI_TOP_STRUCTURAL = frozenset({"id", "object", "created", "model", "system_fingerprint"})
_OPENAI_CHOICE_STRUCTURAL = frozenset({"index", "finish_reason", "logprobs"})
_OPENAI_MESSAGE_STRUCTURAL = frozenset({"role"})


def _inspectable_payload(body_text: str, prefix: str = "") -> str:
    """Return the inspectable text for an outbound body.

    YSG-RISK-200: the egress inspector scanned the whole transport envelope, so
    the random ``chatcmpl-<hex>`` correlation id tripped ``entropy_blob`` on
    10-80% of responses (by id length) and denied the agent's own LLM call.

    SCOPE (Tom, pre-push review 2026-08-07 — this is the fix to the first fix):
    the first version excluded a set of key NAMES at ANY depth, for EVERY egress
    prefix. That was a genuine new DLP bypass: a secret nested under one of those
    names in a Slack/Telegram-bound body skipped the scanner entirely. Proven:
    ``{"metadata": {"id": "AKIA..."}}`` scanned is_secret=True on the raw body and
    False through the helper.

    Now: stripping applies ONLY to the ``llm`` prefix (the agent's own internal
    self-call, the only class with the id false-positive) AND only at the exact
    POSITIONS the OpenAI envelope defines — top level, ``choices[*]``,
    ``choices[*].message`` role, and numeric ``usage``. A key called ``id``
    anywhere else is inspected like any other content. Every other prefix
    (slack, slack-hooks, telegram, and any future external destination) is
    scanned verbatim, exactly as before this change.

    Fail-closed everywhere: unknown prefix, unparseable body, unexpected shape,
    or nothing extracted -> return the full body.
    """
    if prefix != "llm" or not body_text:
        return body_text
    try:
        import json

        doc = json.loads(body_text)
    except Exception:
        return body_text
    if not isinstance(doc, dict):
        return body_text
    # Only a recognisable OpenAI-shaped envelope qualifies.
    if "choices" not in doc or not isinstance(doc.get("choices"), list):
        return body_text

    parts: list[str] = []

    def _emit(value: object) -> None:
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            for v in value.values():
                _emit(v)
        elif isinstance(value, list):
            for v in value:
                _emit(v)

    for k, v in doc.items():
        if k in _OPENAI_TOP_STRUCTURAL:
            continue
        if k == "usage":
            continue  # numeric counters only
        if k == "choices":
            for choice in v:
                if not isinstance(choice, dict):
                    _emit(choice)
                    continue
                for ck, cv in choice.items():
                    if ck in _OPENAI_CHOICE_STRUCTURAL:
                        continue
                    if ck in ("message", "delta") and isinstance(cv, dict):
                        for mk, mv in cv.items():
                            if mk in _OPENAI_MESSAGE_STRUCTURAL:
                                continue
                            _emit(mv)
                    else:
                        _emit(cv)
            continue
        _emit(v)

    if not parts:
        return body_text
    return "\n".join(parts)


@router.api_route(
    "/egress/eval/{prefix}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
async def egress_eval(
    request: Request,
    prefix: str,
    path: str,
) -> Response:
    """
    General egress body inspection + OPA gate before final delivery.

    Caller identity is read from ``X-SPIFFE-ID``, stamped by Caddy from the
    verified peer-cert URI SAN.  The stamp is forge-proof: Caddy runs after
    TLS, ``request_header`` bare-SET overwrites any client-supplied value, and
    ``CaddyVerifiedMiddleware`` + ``SpiffePeerCertMiddleware`` Option C only
    trust the header when ``X-Caddy-Verified-Secret`` validates.

    Steps:
    1. Extract caller SPIFFE from ``X-SPIFFE-ID``.
    2. Read request body.
    3. Inspect: ``scan_secrets()`` (Layer 0 DLP) + ``filter_description()``
       (M4 injection pattern check only — size-cap rejection is NOT RESTRICTED).
    4. Derive ``result_sensitivity`` + ``pii_detected``.
    5. Call ``query_mcp_response_decision()`` (OPA, fail-closed).
    6. DENY → 403 + audit (body withheld, never stored).
    7. ALLOW → forward to ``caddy:18790/deliver/{prefix}/{path}`` via
       ``internal_httpx_client()`` (gateway mesh cert).
    """
    t0 = time.monotonic()

    # ── 1. Caller identity ──────────────────────────────────────────────────
    caller_spiffe = request.headers.get("x-spiffe-id", "").strip()
    if not caller_spiffe:
        logger.warning(
            "egress-eval: missing x-spiffe-id prefix=%s path=%s", prefix, path
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": "missing_caller_identity",
                "message": "No caller identity presented.",
            },
        )

    # ── 1b. Per-instance egress rate/budget cap (FLAG-3) ────────────────────
    # Enforces YASHIGANI_EGRESS_LIMIT_CALLS per YASHIGANI_EGRESS_LIMIT_WINDOW_SECONDS
    # for every agent that routes LLM calls through /egress/eval (langflow,
    # letta, openclaw).  Keyed on SHA-256(caller_spiffe) — per-instance, same
    # hash as OPA's _spiffe_hash in mcp.rego:649.
    #
    # Mode=cap (default): over-limit → 429, fail-closed on Redis error.
    # Mode=monitor:       over-limit → log warning but allow, Redis error → allow.
    #
    # Placed BEFORE body read so the 429 is cheap (no I/O for the body) and
    # so that an instance flooding the gateway with egress calls cannot force
    # expensive body + OPA processing on every request.
    if _state.egress_limit_enforcer is not None:
        _rl_result = _state.egress_limit_enforcer.check_and_record(caller_spiffe)
        if not _rl_result.allowed:
            logger.warning(
                "egress-eval: rate cap DENY caller=%s count=%d/%d "
                "key=%s retry_after_s=%d mode=%s prefix=%s path=%s",
                caller_spiffe,
                _rl_result.count,
                _rl_result.limit,
                _rl_result.rate_limit_key,
                _rl_result.retry_after_s,
                _rl_result.mode,
                prefix,
                path,
            )
            _emit_deny_audit(
                caller_spiffe=caller_spiffe,
                prefix=prefix,
                result_sensitivity="PUBLIC",  # pre-inspection — unknown; use default
                pii_detected=False,
                deny_reason="egress_rate_limit_exceeded",
                elapsed_ms=int((time.monotonic() - t0) * 1000),
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "egress_rate_limit_exceeded",
                    "message": (
                        "Egress LLM call rate limit exceeded for this instance. "
                        f"Limit: {_rl_result.limit} calls per "
                        f"{_state.egress_limit_enforcer.window_seconds}s window."
                    ),
                },
                headers={"Retry-After": str(_rl_result.retry_after_s)},
            )

    # ── 2. Body ─────────────────────────────────────────────────────────────
    body_bytes = await request.body()
    try:
        body_text = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        body_text = ""

    # ── 3. Inspection pipeline ───────────────────────────────────────────────
    pii_detected: bool = False
    injection_detected: bool = False

    try:
        secret_verdict = scan_secrets(_inspectable_payload(body_text, prefix))
        pii_detected = bool(secret_verdict.is_secret)
    except Exception as exc:
        logger.error("egress-eval: secret_detector failed: %s — treating as PII", exc)
        pii_detected = True  # fail-closed

    try:
        filter_result = filter_description(body_text)
        # Only injection patterns upgrade sensitivity — size-cap alone is NOT
        # a signal that the body carries dangerous content.
        injection_detected = (
            filter_result.rejected
            and filter_result.reject_reason.startswith("injection_pattern")
        )
    except Exception as exc:
        logger.error("egress-eval: content_filter failed: %s — treating as injection", exc)
        injection_detected = True  # fail-closed

    # ── 4. Sensitivity classification ────────────────────────────────────────
    result_sensitivity = (
        "RESTRICTED" if (pii_detected or injection_detected) else "PUBLIC"
    )

    # ── 5. OPA decision (fail-closed) ────────────────────────────────────────
    # v4.1 unified-sidecar Phase 1 (Lu M1 / Laura L-US-1): the prefix rides
    # FIRST-CLASS as input.egress.prefix — OPA applies the closed-world
    # (caller, prefix) grant model keyed on the EXACT presented SPIFFE.
    # tool_name/agent_name are audit context ONLY (agent_name is
    # name-collapsed by design and never authorises — the grant key is the
    # full per-instance SPIFFE URI).
    opa_result = await query_mcp_response_decision(
        opa_url=_state.opa_url,
        caller_spiffe=caller_spiffe,
        caller_sensitivity_ceiling=_egress_ceiling_for_prefix(prefix),
        caller_groups=[],
        result_sensitivity=result_sensitivity,
        pii_detected=pii_detected,
        tool_name=f"egress:{prefix}",
        agent_name=_agent_name_from_spiffe(caller_spiffe),
        egress_prefix=prefix,
    )

    elapsed_ms = int((time.monotonic() - t0) * 1000)

    if not opa_result.allow:
        _emit_deny_audit(
            caller_spiffe=caller_spiffe,
            prefix=prefix,
            result_sensitivity=result_sensitivity,
            pii_detected=pii_detected,
            deny_reason=opa_result.deny_reason,
            elapsed_ms=elapsed_ms,
        )
        logger.warning(
            "egress-eval: DENY caller=%s prefix=%s reason=%s "
            "sensitivity=%s pii=%s elapsed_ms=%d",
            caller_spiffe,
            prefix,
            opa_result.deny_reason,
            result_sensitivity,
            pii_detected,
            elapsed_ms,
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": opa_result.deny_reason,
                "message": opa_result.user_message or "Egress denied by policy.",
            },
        )

    # ── 6. Forward to Caddy deliver path ─────────────────────────────────────
    query = request.url.query
    deliver_path = f"/deliver/{prefix}/{path}"
    if query:
        deliver_path = f"{deliver_path}?{query}"
    deliver_url = f"{_state.caddy_egress_base.rstrip('/')}{deliver_path}"

    forward_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in _STRIP_FORWARD_HEADERS
    }

    try:
        async with internal_httpx_client() as mesh_client:
            upstream_resp = await mesh_client.request(
                method=request.method,
                url=deliver_url,
                content=body_bytes,
                headers=forward_headers,
                timeout=30.0,
            )
    except Exception as exc:
        logger.error(
            "egress-eval: forward failed caller=%s url=%s error=%s",
            caller_spiffe,
            deliver_url,
            exc,
        )
        return JSONResponse(
            status_code=502,
            content={
                "error": "egress_forward_failed",
                "message": "Upstream delivery failed.",
            },
        )

    logger.info(
        "egress-eval: ALLOW caller=%s prefix=%s upstream_status=%d elapsed_ms=%d",
        caller_spiffe,
        prefix,
        upstream_resp.status_code,
        elapsed_ms,
    )

    # Relay upstream response verbatim; strip hop-by-hop headers.
    relay_headers = {
        k: v
        for k, v in upstream_resp.headers.items()
        if k.lower() not in {"transfer-encoding", "connection", "keep-alive"}
    }
    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=relay_headers,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _agent_name_from_spiffe(spiffe: str) -> str:
    """
    Extract a short agent-name slug from a SPIFFE URI for audit context.

    Examples::

        "spiffe://yashigani.internal/openclaw"
          → "openclaw"
        "spiffe://yashigani.internal/agents/default/letta/nhi_abc123"
          → "letta"

    Falls back to the full URI on parse failure; never raises.
    """
    try:
        rest = spiffe.split("//", 1)[-1]          # "yashigani.internal/openclaw"
        parts = rest.split("/", 1)[-1].split("/")  # ["openclaw"] or ["agents", "default", "letta", "nhi_abc"]
        if parts[0] == "agents" and len(parts) >= 3:
            return parts[2]
        return parts[0]
    except Exception:
        return spiffe


def _emit_deny_audit(
    *,
    caller_spiffe: str,
    prefix: str,
    result_sensitivity: str,
    pii_detected: bool,
    deny_reason: str,
    elapsed_ms: int,
) -> None:
    """
    Emit an ``OPA_DECISION_ON_MCP`` audit event for an egress denial.

    Body is NEVER stored — this record contains only classification metadata.
    Synchronous (mirrors broker._audit_writer.write pattern).

    v4.1 Phase 1 (Lu M1): the record carries the FULL caller SPIFFE URI
    (``caller_spiffe``) so grant denials (deny_reason
    ``egress:caller_not_granted_prefix``) are attributable to the exact
    instance — ``agent_name`` is name-collapsed and insufficient alone.
    """
    if _state.audit_writer is None:
        logger.warning(
            "egress-eval: audit_writer not configured — deny not audited "
            "caller=%s reason=%s",
            caller_spiffe,
            deny_reason,
        )
        return

    try:
        from yashigani.audit.schema import AccountTier, OpaDecisionOnMcpEvent  # noqa: PLC0415
        event = OpaDecisionOnMcpEvent(
            account_tier=AccountTier.SYSTEM,
            agent_name=_agent_name_from_spiffe(caller_spiffe),
            caller_spiffe=caller_spiffe,
            tool_name=f"egress:{prefix}",
            decision="deny",
            deny_reason=f"egress:{deny_reason}",
            elapsed_ms=elapsed_ms,
        )
        _state.audit_writer.write(event)
    except Exception as exc:
        logger.error(
            "egress-eval: audit emit failed caller=%s reason=%s error=%s",
            caller_spiffe,
            deny_reason,
            exc,
        )
