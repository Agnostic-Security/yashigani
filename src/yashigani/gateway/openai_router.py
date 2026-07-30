"""
Yashigani Gateway — OpenAI-compatible API router (/v1/*).

Provides /v1/chat/completions and /v1/models endpoints that Open WebUI
and other OpenAI-compatible clients can use. All requests go through the
full Yashigani pipeline: identity resolution, sensitivity scan, complexity
scoring, budget enforcement, OE routing, PII filtering, and audit.

v2.23.2 (F-T10-001): Overreliance UX controls.
  Every LLM response now carries:
  - ``X-Yashigani-Generated-Content: true`` — informs operator UIs that the
    response body is AI-generated content, enabling badge/disclaimer rendering.
  - ``X-Yashigani-Response-Inspection-Confidence`` — float [0.0–1.0]; the
    response-inspection pipeline confidence score.  "1.0" when inspection is
    disabled or skipped (clean-pass default).  Operator UIs render a low-
    confidence badge when this value is below the configured threshold.
  - ``X-Yashigani-Low-Confidence-Stepup: required`` — emitted when the
    response-inspection confidence falls below YASHIGANI_LOW_CONFIDENCE_STEPUP_THRESHOLD
    (default 0.50) **and** the sensitivity level is CONFIDENTIAL or RESTRICTED.
    The operator UI intercept is expected to surface a "verify before acting"
    prompt.  This closes OWASP Agentic AI T10 (Overreliance) gap F-T10-001.

  ASVS mapping: V13.2.6 (LLM output handling); OWASP Agentic AI T10 Overreliance.

v1.0: Buffered responses only (Decision 13). Full response collected
before delivery to enable response inspection and token counting.

v2.2: Streaming support added. When ``body.stream == True`` and
``YASHIGANI_STREAMING_ENABLED=true`` (default), requests are forwarded
to Ollama with ``stream=true`` and responses are yielded as SSE chunks
via FastAPI ``StreamingResponse``.

v2.2: PII detection wired into both the request path (before forwarding)
and the response path (before delivery). PII filtering is ON by default
for all traffic — local and cloud. Cloud bypass is OFF by default; admins
must explicitly enable it via the admin panel.

Streaming limitations
---------------------
- Budget headers (``X-Yashigani-Budget-*``) are NOT sent on streaming
  responses. HTTP headers must be committed before the body starts; token
  counts are only available from the final Ollama chunk. Budget accounting
  is still recorded internally — clients that need budget state should poll
  the budget API or use a non-streaming request.
- Agent routing (``@agent`` model prefix) always uses the buffered path
  regardless of the ``stream`` flag, because agent upstreams may not
  support SSE.
- PII mode=log: streaming responses are allowed (request-path PII only).
  PII mode=block|redact: streaming is force-disabled to enable full
  response-path inspection. This adds ~2-3s latency but ensures PII
  cannot leak through streamed responses.
"""
# Last updated: 2026-06-09T00:00:00+00:00
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import math
import os
import re
import threading
import time
import uuid
from typing import Optional

from fastapi import APIRouter, Request, HTTPException, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from yashigani.pki.client import internal_httpx_client
from yashigani.metrics.registry import _C as _metric_counter
from yashigani.audit.schema import (
    ClientPolicyCheckFailedEvent,
    ClientPolicyDeniedEvent,
    EncodedPayloadDetectedEvent,
    OpaResponseCheckFailedEvent,
    OrchestrationBrainReasoningRelaxedEvent,
    PIIDetectedEvent,
    PoolBackendUnavailableEvent,
    ResponseInjectionDetectedEvent,
    StreamTerminatedEvent,
)
from yashigani.gateway._client_enforce import evaluate_client_policies, scope_kind_for

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from yashigani.models.effective import EffectiveModels

logger = logging.getLogger(__name__)


def _client_enforce_input(identity, request_path, route_reason="", provider="", model=""):
    """Build the clients-contract input doc shared by ingress + egress (#16)."""
    ident = identity or {}
    return {
        "identity": {
            "agent": ident.get("identity_id", ""),
            "role": ident.get("kind", ""),
            "clearance": ident.get("sensitivity_ceiling", ""),
            "groups": ident.get("groups", []),
        },
        "request": {"path": request_path, "method": "POST"},
        "routing_decision": {"route": route_reason, "provider": provider, "model": model},
    }


def _audit_client_policy(direction, identity_id, scope_kind, scope_id, ce_result):
    """Audit a client-policy denial / fail-closed, mirroring the OPA-check events."""
    aw = _state.audit_writer
    if aw is None:
        return
    deny = ce_result.get("deny", []) or []
    failclosed = {"client_enforce_unavailable", "client_enforce_undefined", "client_enforce_not_configured"}
    try:
        if set(deny) & failclosed:
            aw.write(ClientPolicyCheckFailedEvent(
                reason=next(iter(set(deny) & failclosed)), outcome="fail_closed", direction=direction,
            ))
        else:
            aw.write(ClientPolicyDeniedEvent(
                identity_id=identity_id, scope_kind=scope_kind, scope_id=scope_id,
                direction=direction, deny_codes=list(deny),
            ))
    except Exception:  # pragma: no cover — audit must never break the request path
        pass

# ---------------------------------------------------------------------------
# OWUI-friendly deny messages (R2 — fix/2.25.5-owui-deny-message)
#
# Open WebUI renders the upstream ``error.message`` field directly in the
# chat UI.  Machine-code reasons from OPA (e.g. "identity_not_active",
# "sensitivity_ceiling_exceeded") surface as raw opaque strings.  This map
# translates every OPA + internal reason code to a concise, layman-readable
# sentence that OWUI will display to the end user.
#
# Rules:
#   • Never leak internal identifiers (identity IDs, policy names, stack traces).
#   • Keep messages under ~120 chars so they fit the OWUI error pill.
#   • Always explain WHAT was blocked and WHO to ask for help.
# ---------------------------------------------------------------------------
_DENY_MESSAGES: dict[str, str] = {
    # v1 ingress (OPA v1_routing.rego `reason`)
    "identity_not_active":
        "Your account is not active. Contact an administrator to restore access.",
    "model_not_allowed":
        "You are not allocated this model. Ask an administrator to grant access.",
    "routing_unsafe_sensitive_to_cloud":
        "This request contains sensitive content and cannot be sent to a cloud provider. Contact an administrator to adjust your routing policy.",
    "sensitivity_ceiling_exceeded":
        "This request exceeds your data classification clearance level. Contact an administrator.",
    "model_not_allocated":
        "You are not allocated this model. Ask an administrator to grant access.",
    # response-path (OPA v1_routing.rego `response_reason`)
    "denied_default_deny":
        "Your request was denied by policy. Contact an administrator for details.",
    "invalid_identity_ceiling":
        "Your account's data classification clearance does not permit this response. Contact an administrator.",
    "response_sensitivity_exceeds_ceiling":
        "The response contains content that exceeds your data classification clearance level. Contact an administrator.",
    "response_blocked_by_inspection":
        "The response was blocked by the security inspection policy. Contact an administrator.",
    # OPA infrastructure
    "opa_unreachable":
        "The security policy service is temporarily unavailable. Please try again shortly.",
    "opa_response_check_failed":
        "The security policy service is temporarily unavailable. Please try again shortly.",
    "opa_not_configured":
        "Gateway security policy is not configured. Contact an administrator.",
    "response_policy_denied":
        "Your request was denied by the response policy. Contact an administrator.",
    "policy_denied":
        "Your request was denied by policy. Contact an administrator for details.",
    # PII
    "pii_detected":
        "Your message contains sensitive personal data that cannot be sent to this provider. Remove the personal information and try again.",
    "pii_detected_encoded":
        "Your message contains encoded personal data that cannot be safely redacted. Remove the personal information and try again.",
    # client-policy
    "client_policy_denied":
        "Your request was denied by an access policy assigned to your account. Contact an administrator.",
    # pool / agent
    "pool_limit_exceeded":
        "The maximum number of concurrent sessions for this agent has been reached. Please try again shortly.",
    "pool_backend_unavailable":
        "The agent's container backend is temporarily unavailable. Contact an administrator.",
    # 3.1 Phase 6 — cloud-model deny-by-default gate (INV-1 + INV-2)
    "cloud_model_not_granted":
        "Access to this cloud model is not permitted. Contact an administrator to enable cloud model access.",
    "cloud_model_opa_coupling_failed":
        "The data-protection policy for this cloud model could not be verified. Contact an administrator.",
    "cloud_model_no_opa_policy_ref":
        "The data-protection policy for this cloud model is not configured. Contact an administrator.",
}

_GENERIC_DENY = "Your request was denied by policy. Contact an administrator for details."


def _deny_message(reason: str) -> str:
    """Return a human-readable deny message for chat display.

    Falls back to the generic message for any reason code not in the table.
    Never leaks the raw reason code into the returned string.
    """
    return _DENY_MESSAGES.get(reason, _GENERIC_DENY)


def _agent_token_secrets_root():
    """Root directory for per-bundled-agent gateway token files
    (V232-CSCAN-01a resolve-and-confine guard). Returns a pathlib.Path.

    YSG-RISK-160: resolved via YASHIGANI_SECRETS_DIR (default /run/secrets) —
    was a bare ``Path("/run/secrets")`` literal with no override, the same
    convention-bypass class as YSG-RISK-150 (and inconsistent with
    ``_load_token_role_map``'s ``_secrets_dir`` in this same module, which
    already honoured the env var). Resolved at call time (not import time)
    so tests can monkeypatch YASHIGANI_SECRETS_DIR without a module reload.
    """
    from pathlib import Path as _Path

    return _Path(os.environ.get("YASHIGANI_SECRETS_DIR", "/run/secrets")).resolve()


# ---------------------------------------------------------------------------
# LAURA-411-002 / Ava FINDING-1: model input validation + normalization helpers
# ---------------------------------------------------------------------------

# LAURA-412-002 (layer 1): compiled ASCII-only positive allowlist for model strings.
# Any char outside [a-zA-Z0-9._:/@-] is rejected, closing the ENTIRE class of
# bypass vectors regardless of position:
#   • Printable non-set chars: |#!~<\ and any other symbol not listed
#   • All Unicode Cf/whitespace/control chars: ZWSP (U+200B), ZWNJ (U+200C),
#     ZWJ (U+200D), BOM (U+FEFF), Word-Joiner (U+2060), Invisible-Sep (U+2063),
#     NUL (\x00), embedded newlines (\n, \r)
# re.ASCII ensures the char-class [a-zA-Z0-9] is strictly 7-bit ASCII; no
# Unicode letter/digit will match.  \Z (not $) anchors the end to prevent
# a trailing \n from slipping through (Python's $ matches before a terminal \n).
# @ appears in the allowlist for digest formats (model@sha256:…) and — since
# YSG-RISK-158 — as the FIRST character for agent-call handles, validated
# below by _AGENT_CALL_VALID_RE (see _validate_model_string).
_MODEL_VALID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/@-]*\Z", re.ASCII)

# YSG-RISK-158: agent-call handles ("@agent-name") were previously EXEMPTED
# from _validate_model_string entirely at the call site (openai_router.py,
# `if body.model and not is_agent_call ...`), because _MODEL_VALID_RE anchors
# the first character to [a-zA-Z0-9] — an "@"-prefixed string always failed
# that regex. Skipping validation for ANY string starting with "@" let a
# caller smuggle URL-scheme forms, path-traversal sequences, null-sentinel
# literals, or Unicode Cf/control chars past every LAURA-412-002 defense —
# agent-call spoofing. Fix: validate the @-prefixed form HERE, in the
# validator, with the same charset applied to the remainder after "@"
# (non-empty), instead of bypassing validation at the call site.
_AGENT_CALL_VALID_RE = re.compile(r"^@[a-zA-Z0-9][a-zA-Z0-9._:/@-]*\Z", re.ASCII)


def _validate_model_string(model: str) -> Optional[str]:
    """Return an error-reason string if *model* is an invalid input, else None.

    LAURA-412-002: POSITIVE VALIDATION replaces the prior denylist as the
    primary gate.  Any model string that does not match the strict ASCII
    allowlist ``^[a-zA-Z0-9][a-zA-Z0-9._:/@-]*\\Z`` is rejected with
    ``invalid_model``.  This closes the ENTIRE class of bypass vectors at once:
      • Printable non-set chars (|#!~<\\)
      • All Unicode Cf/whitespace/control chars (ZWSP, ZWNJ, ZWJ, BOM,
        Word-Joiner, Invisible-Sep, NUL \\x00, embedded \\n/\\r)
      • Any combination thereof, regardless of position in the string

    Legacy explicit checks are kept AHEAD of positive validation so that
    existing tests retain their specific error codes and for clarity when
    the permission store is absent (the explicit-deny gate cannot fire):
      • URL-scheme forms (http://, https://, //, ftp://, any ://)
      • Path-traversal patterns (../, ..\\\\)
      • Null-sentinel literals (``"null"``, ``"none"``, ``"undefined"``)
      • Empty strings (after strip)

    Called before RBAC deny and optimisation so that no bypass variant can
    reach the silent local-default fallback.
    """
    s = (model or "").strip()
    if not s:
        return "empty_model"
    s_lower = s.lower()
    # Explicit URL-scheme rejection (kept for backward-compat error code +
    # for deployments where permission_store is None and layer 2 cannot fire).
    for prefix in ("http://", "https://", "//", "ftp://"):
        if s_lower.startswith(prefix):
            return "url_not_allowed"
    # LAURA-412-001: reject ANY ://-scheme form (e.g. openai://gpt-4o).
    if "://" in s_lower:
        return "url_not_allowed"
    if "../" in s or "..\\" in s or s.startswith("/") or s.startswith(".."):
        return "path_traversal_not_allowed"
    if s_lower in ("null", "none", "undefined"):
        return "null_not_allowed"
    # YSG-RISK-158: agent-call handles ("@agent-name") go through the SAME
    # gate — the URL-scheme/path-traversal/null-sentinel checks above already
    # ran unconditionally against the full string (including the "@"), so an
    # agent-call payload like "@http://evil" or "@../../etc/passwd" is caught
    # above exactly like an ordinary model string would be. Only the final
    # charset check needs an @-aware branch, because _MODEL_VALID_RE anchors
    # the first character to alnum.
    if s.startswith("@"):
        if not _AGENT_CALL_VALID_RE.match(s):
            return "invalid_model"
        return None
    # LAURA-412-002 (layer 1): positive allowlist — reject anything outside
    # the ASCII-safe model-name charset.
    if not _MODEL_VALID_RE.match(s):
        return "invalid_model"
    return None


def _fetch_ollama_models_sync(
    ollama_url: str,
    timeout: float = 3.0,
) -> list[dict] | None:
    """Fetch the installed model list from Ollama /api/tags (synchronous).

    Called once at gateway startup (via the entrypoint) before
    configure_openai_router() so that _is_known_model() can gate genuinely-
    unknown models with HTTP 422 while recognising every model that Ollama
    actually has installed.

    Returns:
        list[dict]: raw model dicts from the API response on success.
        None: on ANY error (connection refused, timeout, JSON parse failure).
              None signals _is_known_model() to be *permissive* — the backend
              itself will reject a genuinely unknown model, so the gateway must
              never brick itself because its model list is temporarily unavailable.
    """
    # F-001 class: use the internal mesh mTLS transport for https ollama fronts
    # (Mac Metal / mTLS installs), NOT bare httpx. ollama_get_json() presents this
    # service's leaf + trusts the internal CA and returns None on any error, which
    # is exactly the permissive-fallback contract this function needs.
    from yashigani.inspection._ollama_transport import ollama_get_json
    data = ollama_get_json(ollama_url, "/api/tags", timeout=timeout)
    if data is None:
        logger.warning(
            "gateway: could not fetch ollama model list from %s/api/tags — "
            "available_models=None; _is_known_model will be permissive until a "
            "gateway reload populates the list",
            ollama_url,
        )
        return None
    models: list[dict] = data.get("models") or []
    logger.info(
        "gateway: ollama model list fetched — %d model(s) from %s/api/tags",
        len(models), ollama_url,
    )
    return models


def _is_known_model(
    model: str,
    alias_store,
    available_models: list | None,
) -> bool:
    """True if *model* is a known alias, installed local model, or cloud-provider-
    qualified model (``openai:X`` / ``anthropic:X``).

    LAURA-411-002 / Ava FINDING-1 (part b): an unresolvable model must return
    HTTP 422 rather than silently falling back to the local default (qwen2.5:3b).

    ``available_models`` semantics:
      - ``None`` : startup fetch of /api/tags failed (backend unreachable at boot).
                   Treat as "unknown list" → permissive; let the backend arbitrate.
      - ``[]``   : fetched successfully; ollama reported no installed models.
                   Strict gate applies (or minimally-configured path if alias_store
                   is also absent).
      - ``[...]``: populated list; strict gate applies.

    Permissive (True) when alias_store is also absent (minimally-configured /
    test deployments) so those environments do not receive false 422s.
    """
    if not model:
        return False
    # LAURA-412-001: canonicalize via normalize_model_for_deny so that the
    # cloud-provider prefix check and the local-model equality check both
    # operate on the same canonical form that the DENY lookup uses.  This
    # prevents a model being "known" under one form (e.g. "openai::gpt-4o")
    # while the DENY lookup misses it because the stored grant key is the
    # canonical "openai:gpt-4o".
    from yashigani.models.effective import normalize_model_for_deny as _norm_for_known
    norm = _norm_for_known(model)
    if not norm:
        return False

    # 1. Cloud provider-qualified: ``provider:model`` where provider is known.
    #    We trust the cloud provider to reject an unrecognised model name.
    #    Operating on the canonical norm ensures openai::gpt-4o and
    #    openai:gpt-4o. both canonicalize to openai:gpt-4o before this check.
    if ":" in norm:
        provider_prefix = norm.split(":", 1)[0]
        if provider_prefix in _CLOUD_PROVIDER_CONFIG:
            return True

    # 2. Alias store (configured aliases: "smart", "fast", "gpt-4o", …).
    #    Try the original case first then the normalized canonical form.
    if alias_store is not None:
        try:
            if (
                alias_store.get(model) is not None
                or (norm != model and alias_store.get(norm) is not None)
            ):
                return True
        except Exception:
            # Store blip → assume known to avoid false 422 on transient errors.
            return True

    # 3. Available (installed Ollama) models.
    # BUG-B FIX (4.1.2): _state.available_models stores dicts keyed "id"
    # (populated via the Ollama /api/tags response); "name" is absent, so
    # all local models wrongly missed this check → 422 model_not_found.
    for m in available_models or []:
        name = (m.get("name") or m.get("id") or "").lower()
        if name and name == norm:
            return True

    # 4. Permissive fallback rules (checked after the list scan so a loaded list
    #    always gates correctly).
    #
    #    a) available_models is None → startup fetch of /api/tags failed.
    #       We cannot distinguish "model exists" from "model unknown" so we permit
    #       and let the backend (Ollama) return its own 404.  This prevents the
    #       gateway from bricking itself when the inference backend is slow to start.
    if available_models is None:
        return True

    #    b) No alias_store AND empty available_models → minimally-configured or
    #       test deployment; skip the gate to avoid false 422s.
    if alias_store is None and not available_models:
        return True

    return False


# ---------------------------------------------------------------------------
# LAURA-411-004 (Info): routing-telemetry headers gate
# ---------------------------------------------------------------------------

def _routing_telemetry_enabled() -> bool:
    """True when routing-telemetry headers should be included in /v1/* responses.

    LAURA-411-004: ``x-yashigani-route-reason``, ``x-yashigani-routed-via``,
    ``x-yashigani-sensitivity``, and ``x-yashigani-complexity`` expose internal
    routing decisions to every caller.  These are now gated behind
    ``YASHIGANI_ROUTING_TELEMETRY=true`` (default OFF).

    ``x-yashigani-model`` and ``x-yashigani-generated-content`` are always
    present — the UI depends on them.
    """
    return os.getenv("YASHIGANI_ROUTING_TELEMETRY", "false").strip().lower() == "true"


# ---------------------------------------------------------------------------
# OPA fail-closed Prometheus counter (Path 1 + Path 3)
#
# yashigani_opa_response_check_failures_total — increments whenever the
# OPA response-check path (or opa_not_configured guard) fires a deny because
# OPA is unreachable/erroring or not configured.
#
# Alert on sustained rate: an OPA outage causes request denials; operators
# must restore OPA connectivity.  This is intentional zero-trust behaviour
# per feedback_zero_trust_default.md.
# ---------------------------------------------------------------------------
opa_response_check_failures_total = _metric_counter(
    "yashigani_opa_response_check_failures_total",
    "OPA response-check failures resulting in fail-closed deny. "
    "Labels: outcome=exception|not_configured, reason=<exception class or 'opa_not_configured'>. "
    "Alert on sustained rate — OPA outage = request denials (intentional zero-trust fail-closed).",
    ["outcome", "reason"],
)

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


# ---------------------------------------------------------------------------
# 4.1 SEC-GAP-1: Track C (F-B) — per-user identity via X-Yashigani-Identity-Id.
#
# The 3.x X-OpenWebUI-User-Email forwarding path has been removed.  Identity on
# the internal-bearer path is now resolved ONLY from X-Yashigani-Identity-Id
# (idnt_ PK).  X-Forwarded-User / email / slug derivation paths are gone.
# Fail-closed: no valid UID header on the forwarder path → service "internal"
# identity (RESTRICTED).  No phantom owui-users default identity.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 4.0 native WebUI trusted-forwarder header (LAURA-4.0-S1-001 close / identity_id contract)
# ---------------------------------------------------------------------------
# The 4.0 backoffice chat proxy resolves the caller's Yashigani identity_id
# from the identity registry (keyed on session.account_id via the
# identity:account:{account_id} Redis index) and forwards it as this header.
#
# Contract:
#   - Value: idnt_ PK string (e.g. "idnt_abc123")
#   - Trust boundary: honoured ONLY on the internal-bearer path (p2_forwarder
#     or _INTERNAL_BEARER).  4.1 SEC-GAP-1: X-OpenWebUI-User-Email path removed.
#   - Caddy MUST strip this header at the public edge (Su's Caddyfile task).
#   - If the header is present but the identity cannot be resolved: fail-closed
#     (HTTP 403), do NOT fall back to a default/unauthenticated principal.
# ---------------------------------------------------------------------------
_YASHIGANI_IDENTITY_ID_HEADER = "x-yashigani-identity-id"


def _resolve_yashigani_identity_id_header(request: "Request") -> "Optional[dict]":
    """Resolve identity from X-Yashigani-Identity-Id header on the trusted path.

    CALLED ONLY from the internal-bearer fast-path (p2_forwarder or
    _INTERNAL_BEARER branch) — i.e. the request is already proven to come
    from the trusted backoffice forwarder.

    Returns:
        identity dict (with _identity_id_header marker) when the idnt_ key is
        found in the registry.
        None when the header is absent (fall through to other resolvers).

    Raises:
        HTTPException(403) when the header is present but the identity is not
        found or the value is malformed.  Fail-closed: we NEVER fall back to
        a lower-privilege path when the caller explicitly supplied an idnt_ key
        that doesn't resolve — that is a bug in the forwarder, not a graceful
        degradation scenario.
        HTTPException(503) when the header is present but the identity registry
        is unavailable.
    """
    from fastapi import HTTPException as _HTTPException

    identity_id = request.headers.get(_YASHIGANI_IDENTITY_ID_HEADER, "").strip()
    if not identity_id:
        return None  # header absent — let caller fall through to email/API-key path

    # Validate format: must start with "idnt_" prefix to distinguish from
    # slugs, emails, or other values that could be injected.
    if not identity_id.startswith("idnt_"):
        logger.warning(
            "_resolve_yashigani_identity_id_header: malformed identity_id %r — "
            "expected idnt_ prefix; rejecting (fail-closed)",
            identity_id,
        )
        raise _HTTPException(
            status_code=403,
            detail={
                "error": "IDENTITY_ID_MALFORMED",
                "message": (
                    "X-Yashigani-Identity-Id value is malformed. "
                    "Contact your administrator."
                ),
            },
        )

    if _state.identity_registry is None:
        logger.error(
            "_resolve_yashigani_identity_id_header: identity_id %r forwarded but "
            "identity_registry is unavailable — fail-closed 503",
            identity_id,
        )
        raise _HTTPException(
            status_code=503,
            detail={
                "error": "IDENTITY_REGISTRY_UNAVAILABLE",
                "message": "Identity registry unavailable. Try again shortly.",
            },
        )

    try:
        identity = _state.identity_registry.get(identity_id)
    except Exception as exc:
        logger.error(
            "_resolve_yashigani_identity_id_header: registry lookup for %r raised %s — "
            "fail-closed 503",
            identity_id, exc,
        )
        raise _HTTPException(
            status_code=503,
            detail={
                "error": "IDENTITY_REGISTRY_ERROR",
                "message": "Identity registry error. Contact your administrator.",
            },
        )

    if identity is None:
        logger.warning(
            "_resolve_yashigani_identity_id_header: identity %r not found in registry — "
            "fail-closed 403 (no fallback to email/anonymous path)",
            identity_id,
        )
        raise _HTTPException(
            status_code=403,
            detail={
                "error": "IDENTITY_NOT_FOUND",
                "message": (
                    "Your Yashigani identity could not be resolved. "
                    "Contact your administrator."
                ),
            },
        )

    identity = dict(identity)
    identity["_yashigani_identity_header"] = True
    return identity


# (4.1 SEC-GAP-1: _load_owui_slug_map, _OWUI_SLUG_MAP, _baseline_owui_identity,
#  and _resolve_owui_forwarded_user removed.  Identity resolved from
#  X-Yashigani-Identity-Id only; no email/slug derivation in the authz path.)


# ---------------------------------------------------------------------------
# Admin-configurable: GET /v1/models visibility for service accounts.
#
# OPA classifies service-account principals (e.g. Open WebUI, which calls with
# the shared internal bearer) as RESTRICTED — they see only their allowed_models
# allowlist, empty by default (FINDING-59-01 topology-disclosure hardening).
# Without a way to relax that, the OWUI model picker is empty in simple
# deployments. This runtime setting (gateway.models.service_account_full_list,
# editable in the admin Runtime Settings panel; default OFF) lets an operator
# grant service accounts the FULL list (models + agents + service identities).
# Read live from the DB-backed runtime_settings table, cached 30s. Fail-secure:
# any error -> False (restricted).
# ---------------------------------------------------------------------------
_SA_FULL_LIST_CACHE: dict = {"value": False, "ts": 0.0}
_SA_FULL_LIST_TTL = 30.0


def _service_account_full_list_enabled() -> bool:
    """True iff the operator has enabled the full /v1/models list for service
    accounts via the gateway.models.service_account_full_list runtime setting."""
    import time as _t
    now = _t.monotonic()
    if now - _SA_FULL_LIST_CACHE["ts"] < _SA_FULL_LIST_TTL:
        return _SA_FULL_LIST_CACHE["value"]
    value = False
    try:
        import psycopg2, json as _json
        from yashigani.runtime_settings.keys import KEY_MODELS_SERVICE_ACCOUNT_FULL_LIST as _K
        dsn = os.getenv("YASHIGANI_DB_DSN", "")
        if dsn and "${POSTGRES_PASSWORD}" not in dsn:
            conn = psycopg2.connect(dsn, connect_timeout=5)
            conn.autocommit = True
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT value FROM runtime_settings WHERE key = %s", (_K,))
                    row = cur.fetchone()
                if row:
                    raw = row[0]
                    # value is jsonb: psycopg2 may hand back a native python type
                    # (bool/int/str) OR a json string depending on adapters — handle both.
                    if isinstance(raw, (bytes, bytearray)):
                        raw = raw.decode()
                    if isinstance(raw, str):
                        raw = _json.loads(raw)
                    value = bool(raw)
            finally:
                conn.close()
    except Exception as _exc:  # fail-secure: restricted on any error
        logger.debug("service_account_full_list read failed (%s) — restricted", _exc)
        value = False
    _SA_FULL_LIST_CACHE["value"] = value
    _SA_FULL_LIST_CACHE["ts"] = now
    return value

def is_orchestration_self_call(request) -> bool:
    """True when this request is an in-flight orchestration sub-hop.

    The executor (orchestrator.py) stamps X-Yashigani-Orchestration-Depth on
    every gateway self-call.  A present header (depth >= 1) means we are already
    inside an orchestration loop, so the /v1 handler must NOT re-enter the
    executor — it must run the hop as a normal chat/agent call.  This is the
    guard that makes the self-call loop terminate (build sheet §3.1/§6).
    """
    return bool(request.headers.get("x-yashigani-orchestration-depth"))


def is_auto_orchestrate_model(model: str) -> bool:
    """True when the requested model is in the YASHIGANI_ORCH_AUTO_MODELS list.

    YASHIGANI_ORCH_AUTO_MODELS is a comma-separated list of model ids (or
    virtual names) for which the gateway auto-fires the qwen-brain orchestration
    executor, even when the client does NOT set orchestrate=true.  This is the
    OWUI-facing wiring for the cloud-9 demo: OWUI sends a plain chat request
    with model="cloud9-orchestrate" (a virtual name in the OWUI model selector);
    the gateway promotes it to orchestration and substitutes the real brain model
    (YASHIGANI_ORCH_BRAIN_MODEL, default qwen2.5:3b).  The caller never sees the
    brain model — they address the virtual name.

    SECURITY NOTE: the same seed-prompt adjudication and every-hop OPA gate apply
    identically to auto-triggered orchestration.  The auto-trigger is not an auth
    bypass: it is a routing convenience that sets body.orchestrate=True for a
    pre-approved set of virtual model names.  Identity, sensitivity, OPA ingress,
    per-hop egress, and ResponseInspection all fire as normal.  The model name
    itself is resolved to the configured brain model before any downstream hop.
    """
    raw = os.environ.get("YASHIGANI_ORCH_AUTO_MODELS", "").strip()
    if not raw or not model:
        return False
    names = {m.strip().lower() for m in raw.split(",") if m.strip()}
    return (model or "").strip().lower() in names


# ---------------------------------------------------------------------------
# G-ORCH-OPA-3 — brain-REASONING-leg marker (server-minted, UNFORGEABLE).
#
# Problem: when @letta is the orchestrating brain, its OWN reasoning *about* a
# security task ("test the boundaries / threat-model / cloud 9") trips the
# response classifier (0.95–1.0) → the response-leg OPA gate 403s → the loop
# finalizes gracefully and the requested threat-model cognition is SUPPRESSED.
# But the brain→LLM (A→L) leg is the orchestrator's OWN cognition — it is
# consumed ONLY by the gateway loop to pick the next GATED hop, never delivered
# to a human and never used as a tool result.  We therefore "evaluate-not-
# suppress" that ONE leg: compute the verdict + OPA decision and AUDIT them
# (relaxation_applied=true), but relax only the 403/substitute ACTION.
#
# THE MARKER IS NOT A HEADER.  letta calls the gateway's LLM endpoint
# autonomously via OPENAI_API_BASE with a static internal bearer + static model;
# it adds no per-request headers and cannot be trusted to.  So the marker is
# PROCESS-LOCAL gateway state: the executor brackets each brain round-trip
# (`_letta_send`) with begin()/end() on a counter held in THIS module.  letta
# cannot read, set, clear, or forge that counter — it is not derived from model
# name, content, or any letta-controllable input.  The inbound LLM call that
# arrives WHILE a brain round-trip is open, from the internal-bearer identity,
# on the brain model, IS the brain-reasoning leg.
#
# CONCURRENCY / MISLABEL SAFETY: a concurrent NON-brain letta chat whose LLM
# call happens to overlap an open brain round-trip could be mislabelled as a
# reasoning leg and have its 403-action relaxed.  This is NOT exploitable: the
# load-bearing leak guard (condition 4) routes ANY relaxed completion that
# parses to a final/prose answer back through the STANDARD (non-relaxed) egress
# gate before it can reach a human.  A relaxed completion may only ever resolve
# to a `call_tool` decision re-entering the full gate.  Mislabelling can at most
# let an INTERNAL reasoning turn through to the brain loop — never to a user.
# ---------------------------------------------------------------------------
# Brain model id letta uses for its own reasoning (compose: LETTA_LLM_MODEL).
# The marker requires BOTH an open round-trip AND this model, so an unrelated
# internal-bearer caller on a different model is never relaxed.
_BRAIN_REASONING_MODEL = os.environ.get("LETTA_LLM_MODEL", "qwen2.5:3b").strip()
_brain_reasoning_lock = threading.Lock()
_brain_reasoning_active = 0  # count of open brain round-trips (supports nesting)
# Set True when a would-have-blocked verdict was RELAXED while a round-trip was
# open; read+reset by brain_reasoning_leg_end so the executor learns the brain
# turn it just ran was relaxed (condition 4 — route a relaxed final through the
# NON-relaxed gate before it can reach the user).
_brain_reasoning_relaxed_pending = False


def brain_reasoning_leg_begin() -> None:
    """Open a brain-reasoning round-trip (called by the executor around _letta_send).

    Increments the process-local active counter.  letta cannot reach this state;
    it is the SERVER minting the scope marker, never inferred from letta input.
    """
    global _brain_reasoning_active, _brain_reasoning_relaxed_pending
    with _brain_reasoning_lock:
        _brain_reasoning_active += 1
        # Clear any stale relaxation flag at the start of a fresh round-trip.
        if _brain_reasoning_active == 1:
            _brain_reasoning_relaxed_pending = False


def brain_reasoning_leg_end() -> bool:
    """Close a brain-reasoning round-trip; return True iff it was RELAXED.

    Always called (even on error).  The boolean lets the executor route a relaxed
    final/prose answer back through the NON-relaxed egress gate (condition 4).
    """
    global _brain_reasoning_active, _brain_reasoning_relaxed_pending
    with _brain_reasoning_lock:
        if _brain_reasoning_active > 0:
            _brain_reasoning_active -= 1
        relaxed = _brain_reasoning_relaxed_pending
        if _brain_reasoning_active == 0:
            _brain_reasoning_relaxed_pending = False
        return relaxed


def _mark_brain_reasoning_relaxed() -> None:
    """Record that a would-have-blocked verdict was relaxed on the current leg."""
    global _brain_reasoning_relaxed_pending
    with _brain_reasoning_lock:
        _brain_reasoning_relaxed_pending = True


def _brain_reasoning_active_now() -> bool:
    with _brain_reasoning_lock:
        return _brain_reasoning_active > 0


def is_brain_reasoning_leg(identity, model: str) -> bool:
    """True iff this inbound /v1 call is letta's OWN reasoning (A→L) leg.

    ALL of the following must hold — every condition is SERVER-determined, none
    is letta-controllable:
      • a brain round-trip is currently open (process-local counter > 0), AND
      • the caller is the internal-bearer service identity (mesh-port only), AND
      • the requested model is the configured brain model.

    A normal chat caller, an external caller, or any call when no brain round-trip
    is open returns False → the response gate runs BYTE-FOR-BYTE unchanged.
    """
    if not _brain_reasoning_active_now():
        return False
    if not identity or identity.get("identity_id") != "internal":
        return False
    return (model or "").strip() == _BRAIN_REASONING_MODEL


router = APIRouter(prefix="/v1", tags=["openai-compat"])


# ── Request/Response Models ──────────────────────────────────────────────


# ── Tool-calling schema (orchestration, 2.25.4) ──────────────────────────
# OpenAI-compatible function-tool shapes.  All additive + Optional so plain
# chat callers (Open WebUI) are byte-for-byte unchanged when `tools` is absent.
# Build sheet §1.1/§1.2 (orchestration-buildsheet-20260610).


class ToolCallFunction(BaseModel):
    name: str
    # JSON-encoded string per OpenAI semantics.  The orchestrator/Ollama
    # translation layer (orchestrator.py) serialises Ollama's object form here.
    arguments: str = ""


class ToolCall(BaseModel):
    id: str
    type: str = "function"
    function: ToolCallFunction


class ToolDef(BaseModel):
    type: str = "function"
    function: dict  # {name, description, parameters: JSON-Schema}


class ChatMessage(BaseModel):
    # system | user | assistant | tool  (+"tool" now valid)
    role: str = Field(description="Role: system, user, assistant, tool")
    # Nullable: assistant tool-call turns carry content=null.  Audit/PII code
    # joins with `if m.content` so None is treated as "" (build sheet §1.1 note).
    # OpenClaw and other clients (anthropic SDK compat) send content as a list of
    # content blocks: [{"type": "text", "text": "..."}].  Accept both forms and
    # flatten to str so downstream code stays unchanged.
    content: Optional[str | list] = Field(default=None, description="Message content")
    name: Optional[str] = None
    # assistant → requests tool calls
    tool_calls: Optional[list[ToolCall]] = None
    # role:"tool" → which assistant tool_call this message answers
    tool_call_id: Optional[str] = None

    def model_post_init(self, __context) -> None:
        """Flatten list-format content blocks to a plain string."""
        if isinstance(self.content, list):
            parts = []
            for block in self.content:
                if isinstance(block, dict):
                    # {"type": "text", "text": "..."} — the common case
                    parts.append(block.get("text") or block.get("content") or "")
                elif isinstance(block, str):
                    parts.append(block)
            self.content = "\n".join(p for p in parts if p) or None


class ChatCompletionRequest(BaseModel):
    model: str = Field(description="Model name or alias")
    messages: list[ChatMessage]
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    top_p: Optional[float] = None
    stream: bool = False
    # Yashigani extensions
    force_local: Optional[bool] = None
    force_cloud: Optional[bool] = None
    # ── Orchestration (2.25.4, build sheet §1.2) ──────────────────────────
    tools: Optional[list[ToolDef]] = None
    # "auto" | "none" | "required" | {"type":"function","function":{"name":...}}
    tool_choice: Optional[str | dict] = None
    # Yashigani opt-in orchestration flag (§3.5 routing).  When tools is present
    # OR orchestrate is True, /v1/chat/completions delegates to run_orchestration.
    orchestrate: Optional[bool] = None


class ChatCompletionChoice(BaseModel):
    index: int = 0
    message: ChatMessage
    # finish_reason gains "tool_calls" for assistant turns that request tools.
    finish_reason: str = "stop"


class CompletionUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatCompletionResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: list[ChatCompletionChoice]
    usage: CompletionUsage


class ModelInfo(BaseModel):
    id: str
    object: str = "model"
    created: int = 0
    owned_by: str = "yashigani"


class ModelListResponse(BaseModel):
    object: str = "list"
    data: list[ModelInfo]


# ── Embeddings models ─────────────────────────────────────────────────────

class EmbeddingRequest(BaseModel):
    """OpenAI-compatible embeddings request body."""
    model: str = Field(description="Model name or alias to use for embeddings")
    input: str | list[str] = Field(description="Text(s) to embed")
    encoding_format: Optional[str] = None  # "float" (default) or "base64"
    dimensions: Optional[int] = None       # returned vector size (provider-dependent)
    user: Optional[str] = None             # end-user identifier (OpenAI passthrough)


class EmbeddingObject(BaseModel):
    """Single embedding result (OpenAI shape)."""
    object: str = "embedding"
    embedding: list[float]
    index: int = 0


class EmbeddingUsage(BaseModel):
    prompt_tokens: int = 0
    total_tokens: int = 0


class EmbeddingResponse(BaseModel):
    object: str = "list"
    data: list[EmbeddingObject]
    model: str
    usage: EmbeddingUsage


# ── State (injected at startup) ─────────────────────────────────────────

class OpenAIRouterState:
    """Mutable state injected by the gateway entrypoint at startup."""

    def __init__(self):
        self.identity_registry = None
        self.sensitivity_classifier = None
        self.complexity_scorer = None
        self.budget_enforcer = None
        self.token_counter = None
        self.audit_writer = None
        self.optimization_engine = None
        self.ollama_url: str = "http://ollama:11434"
        self.default_model: str = "qwen2.5:3b"
        self.available_models: list[dict] | None = None  # None=fetch-failed/permissive; []=fetched-empty; [...]= populated
        self.agent_registry = None
        # Track B1 (model-RBAC): durable allocation store + alias store, read on
        # the request path to compute effective-allowed-models for the caller.
        self.model_allocation_store = None   # ModelAllocationStore | None
        self.model_alias_store = None        # ModelAliasStore | None
        self.response_inspection_pipeline = None
        self.ddos_protector = None  # v2.2 — DDoSProtector | None
        # FINDING-V412-RESTART-013 gap #6: DocumentInspectionPipeline | None.
        # Same singleton instance entrypoint.py builds and hands to
        # create_gateway_app()'s state["document_pipeline"] (proxy egress +
        # gateway/mcp_router_runtime.py's /mcp/<agent_name> HTTP entrypoint).
        # Mirrored here so the chat->MCP tool-dispatch path
        # (gateway/orchestrator.py:_execute_mcp_tool) — which has NO access to
        # proxy.py's per-request `state` dict, only this module-level
        # singleton — can also invoke document REDACT/PSEUDONYMIZE/BLOCK
        # enforcement on tool-call arguments before they leave the ring-fence.
        # None (default/dark, mode-B-proxy opt-in flag off) preserves the
        # exact pre-fix behaviour: MCP chat-tool-call traffic is untouched.
        self.document_pipeline = None
        # v2.2 — streaming
        self.streaming_enabled: bool = True
        self.streaming_inspect_interval: int = 200
        # v2.2 — PII detection
        self.pii_detector = None          # PiiDetector | None
        self.pii_cloud_bypass: bool = False  # True = skip PII for cloud-routed requests
        # OPA policy enforcement
        self.opa_url: str = "https://policy:8181"
        # Content relay detection (agent-to-agent laundering)
        self.content_relay_detector = None
        # v2.4.1 — PoolManager for container-per-identity dispatch
        self.pool_manager = None          # PoolManager | None
        # 4.0 Phase 3 — P1/P2 token role map (RISK-108 / FIND-3.1-AGENT-BEARER-
        # IMPERSONATION).  Maps plaintext_token → (role_class, identity_id) for
        # fast hmac.compare_digest on every request.
        #
        # Role classes:
        #   "p2_forwarder"   — backoffice/chat trusted forwarder; sets X-Yashigani-Identity-Id
        #   "p2_orchestrator"— Gateway orchestrator self-call; may set X-Yashigani-
        #                      Orchestration-Principal
        #   "p1_agent"       — Bundled agent (Letta, Langflow, OpenClaw); resolves as
        #                      the named agent identity — CANNOT set P2 headers
        #   "p1_nhi"         — User-built NHI; resolves as nhi_{id} identity — CANNOT
        #                      set P2 headers
        #
        # The map is populated at lifespan startup by configure_openai_router()
        # from per-service secret files (Su/compose) and from
        # AgentRegistry.get_nhi_token_map() for active NHIs.
        #
        # BACKWARD COMPAT: YASHIGANI_INTERNAL_BEARER is still loaded at module
        # import time into _INTERNAL_BEARER (above).  If no dedicated per-service
        # tokens are configured, ALL token lookups fall through to the existing
        # hmac.compare_digest(_INTERNAL_BEARER) path (unchanged 3.x behaviour).
        # Once Su lands the per-service token split in install.sh + compose, the
        # OWUI forwarder and orchestrator tokens get their own map entries and
        # _INTERNAL_BEARER can be revoked.
        self.token_role_map: dict[str, tuple[str, str]] = {}
        # Cloud key resolution: KMS provider + per-provider short-TTL cache.
        # Cache entry: {"value": str | None, "ts": float}; TTL = 60 s so a
        # newly-set key takes effect within one minute without a restart.
        # The env-var fallback (OPENAI_API_KEY / ANTHROPIC_API_KEY) keeps
        # existing Helm/env-only deployments working unchanged.
        self.kms_provider = None   # KSMProvider | None
        self._cloud_key_cache: dict[str, dict] = {}  # provider -> {value, ts}
        # 3.1 Phase 6+7 — cloud-model deny-by-default gate + strict dial.
        # permission_store: PermissionStore | None — resolves boolean grants for
        #   blast-radius resource types (cloud_model, mcp_server, agent, external_api).
        # permission_strict: when True (YASHIGANI_PERMISSION_STRICT=true), local
        #   Ollama models also require an explicit grant (deny-unless-permitted for ALL
        #   models).  Default False so local-LLM usage works out of the box.
        self.permission_store = None
        self.permission_strict: bool = (
            os.environ.get("YASHIGANI_PERMISSION_STRICT", "false").strip().lower() == "true"
        )
        # W3-008: RBAC store for group membership backfill.
        # The identity registry stores groups only as set at REGISTRATION time.
        # Memberships granted later via RBAC add_member live solely in
        # rbac:user:{identity_id} in the RBAC store and are never written back to
        # the registry record.  Wired here so chat_completions can call
        # get_user_groups() to union the complete set before any group-tier check.
        self.rbac_store = None   # RBACStore | None
        # F-T10-001: low-confidence step-up threshold.  When response-inspection
        # confidence falls below this value AND sensitivity >= CONFIDENTIAL,
        # X-Yashigani-Low-Confidence-Stepup: required is added to the response.
        # Guard: empty or non-numeric env var must not crash module load.
        _thresh_raw = os.getenv("YASHIGANI_LOW_CONFIDENCE_STEPUP_THRESHOLD", "0.50")
        try:
            self.low_confidence_stepup_threshold: float = float(_thresh_raw)
        except ValueError:
            logger.warning(
                "YASHIGANI_LOW_CONFIDENCE_STEPUP_THRESHOLD is not a valid float "
                "(got %r); using default 0.50",
                _thresh_raw,
            )
            self.low_confidence_stepup_threshold = 0.50


_state = OpenAIRouterState()

# ---------------------------------------------------------------------------
# Cloud provider configuration: API endpoint URL, key env-var fallback,
# request body/response body adapters.
#
# OpenAI uses the OpenAI-compatible /v1/chat/completions API (JSON same shape
# as our request body).  Anthropic uses a different messages API — we translate
# to their format here and normalise the response back to the OpenAI shape so
# downstream code is unaffected.
#
# Key resolution order (per request / per provider, with 60 s TTL):
#   1. kms_provider.get_secret("{provider}_api_key")  — UI-set key (KMS)
#   2. os.environ.get("{PROVIDER}_API_KEY")           — env-var / Helm fallback
#   3. None → HTTPException(503)
#
# A restart is NOT required when a key is changed via the admin UI.  The
# 60-second TTL cache (per provider) bounds the propagation delay.
# ---------------------------------------------------------------------------
_CLOUD_PROVIDER_CONFIG: dict[str, dict] = {
    "openai": {
        "kms_key": "openai_api_key",
        "env_var": "OPENAI_API_KEY",
        "base_url": os.getenv("YASHIGANI_OPENAI_BASE_URL", "https://api.openai.com"),
    },
    "anthropic": {
        "kms_key": "anthropic_api_key",
        "env_var": "ANTHROPIC_API_KEY",
        "base_url": os.getenv("YASHIGANI_ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
    },
}

_CLOUD_KEY_TTL: float = 60.0  # seconds

# ---------------------------------------------------------------------------
# Cloud embedding model configuration (per-provider).
#
# Most cloud LLM providers have a SEPARATE dedicated embedding model (e.g.
# OpenAI text-embedding-3-small) that is NOT a chat model. We therefore cannot
# simply forward the caller's model name when routing to cloud.
#
# Resolution order per provider:
#   1. YASHIGANI_<PROVIDER>_EMBEDDING_MODEL env var (operator override)
#   2. _CLOUD_EMBEDDING_DEFAULTS[provider] built-in default
#   3. None → provider has no embedding API → fall back to local Ollama
#
# Anthropic has no public embeddings API as of the knowledge cutoff; its entry
# is None → any cloud-routed embeddings request for an Anthropic-hosted model
# falls back to the local Ollama embedder automatically.
# ---------------------------------------------------------------------------
_CLOUD_EMBEDDING_DEFAULTS: dict[str, Optional[str]] = {
    "openai": "text-embedding-3-small",
    "anthropic": None,  # Anthropic has no embeddings API → Ollama fallback
}


def _get_cloud_embedding_model(provider: str) -> Optional[str]:
    """Return the embedding model to use for a cloud provider.

    Reads YASHIGANI_<PROVIDER>_EMBEDDING_MODEL from env (operator override),
    then falls back to the built-in default. Returns None when the provider
    has no embeddings API (e.g. Anthropic) — callers must then fall back to
    the local Ollama embedder.
    """
    env_var = f"YASHIGANI_{provider.upper()}_EMBEDDING_MODEL"
    env_val = os.getenv(env_var, "").strip()
    if env_val:
        return env_val
    return _CLOUD_EMBEDDING_DEFAULTS.get(provider)  # may be None


def _get_cloud_api_key(provider: str) -> Optional[str]:
    """Resolve the API key for a cloud provider.

    Reads from KMS with a 60 s per-provider TTL cache, then falls back to the
    environment variable.  Never logs the key value.

    Returns None if no key is available (KMS miss + env var absent).
    """
    cfg = _CLOUD_PROVIDER_CONFIG.get(provider)
    if cfg is None:
        return None

    now = time.monotonic()
    cache_entry = _state._cloud_key_cache.get(provider, {})
    if now - cache_entry.get("ts", 0.0) < _CLOUD_KEY_TTL:
        return cache_entry.get("value")

    key: Optional[str] = None

    # 1. KMS — preferred when the admin has set the key via the UI.
    if _state.kms_provider is not None:
        try:
            val = _state.kms_provider.get_secret(cfg["kms_key"])
            if val:
                key = val
        except Exception as exc:
            # KeyNotFoundError = key not set in KMS yet — not an error.
            logger.debug(
                "_get_cloud_api_key: KMS miss for provider=%s kms_key=%s (%s)",
                provider, cfg["kms_key"], type(exc).__name__,
            )

    # 2. Env-var fallback — for Helm / docker-compose env-based deployments.
    if not key:
        key = os.environ.get(cfg["env_var"]) or None

    # Cache the resolved value (including None — so a missing key does not
    # hammer KMS on every request while the TTL runs).
    _state._cloud_key_cache[provider] = {"value": key, "ts": now}
    return key


def configure(
    identity_registry=None,
    sensitivity_classifier=None,
    complexity_scorer=None,
    budget_enforcer=None,
    token_counter=None,
    optimization_engine=None,
    audit_writer=None,
    ollama_url: str = "http://ollama:11434",
    default_model: str = "qwen2.5:3b",
    available_models: list[dict] | None = None,
    agent_registry=None,
    response_inspection_pipeline=None,
    ddos_protector=None,  # v2.2 — DDoSProtector | None
    pii_detector=None,    # v2.2 — PiiDetector | None
    pii_cloud_bypass: bool = False,  # v2.2 — True = skip PII for cloud-routed requests
    opa_url: str = "https://policy:8181",
    content_relay_detector=None,
    pool_manager=None,    # v2.4.1 — PoolManager | None
    model_allocation_store=None,  # Track B1 — ModelAllocationStore | None
    model_alias_store=None,       # Track B1 — ModelAliasStore | None
    kms_provider=None,            # KSMProvider | None — for cloud API key resolution
    permission_store=None,        # 3.1 Phase 6 — PermissionStore | None (cloud-model gate)
    rbac_store=None,              # W3-008 — RBACStore | None (group membership backfill)
    document_pipeline=None,       # FINDING-V412-RESTART-013 gap #6 — DocumentInspectionPipeline | None
) -> None:
    """Configure the OpenAI router with dependencies. Called once at startup.

    Zero-trust startup validation (Path 3 — ASVS V14.5.*):
    In production (YASHIGANI_ENV=production), OPA is mandatory.  If opa_url is
    empty the gateway REFUSES to start rather than silently serving with no
    policy enforcement.  In development mode the same fail-closed behaviour
    applies UNLESS YASHIGANI_OPA_OPTIONAL=true is explicitly set.

    Operator runbook:
      Set YASHIGANI_OPA_URL to the reachable OPA endpoint.
      In dev-only environments with no OPA, set YASHIGANI_OPA_OPTIONAL=true.
    """
    _state.identity_registry = identity_registry
    _state.sensitivity_classifier = sensitivity_classifier
    _state.complexity_scorer = complexity_scorer
    _state.budget_enforcer = budget_enforcer
    _state.token_counter = token_counter
    _state.optimization_engine = optimization_engine
    _state.audit_writer = audit_writer
    _state.ollama_url = ollama_url
    _state.default_model = default_model
    _state.available_models = available_models  # preserve None (fetch-failed) vs [] (fetched-empty) vs [...] (populated)
    _state.agent_registry = agent_registry
    _state.response_inspection_pipeline = response_inspection_pipeline
    _state.ddos_protector = ddos_protector
    _state.pii_detector = pii_detector
    _state.pii_cloud_bypass = pii_cloud_bypass
    _state.opa_url = opa_url
    _state.content_relay_detector = content_relay_detector
    _state.pool_manager = pool_manager  # v2.4.1
    _state.model_allocation_store = model_allocation_store  # Track B1
    _state.model_alias_store = model_alias_store            # Track B1
    _state.kms_provider = kms_provider                      # cloud API key resolution
    _state._cloud_key_cache = {}                            # reset cache on reconfigure
    _state.permission_store = permission_store              # 3.1 Phase 6 — cloud-model gate
    _state.permission_strict = (
        os.environ.get("YASHIGANI_PERMISSION_STRICT", "false").strip().lower() == "true"
    )
    _state.rbac_store = rbac_store                         # W3-008 — group backfill
    _state.document_pipeline = document_pipeline           # RESTART-013 gap #6

    # ── 4.0 Phase 3 — P1/P2 token role map (RISK-108) ──────────────────────
    # Populate from YASHIGANI_TOKEN_ROLE_MAP env var (JSON dict for dev/test):
    #   {"<plaintext_token>": ["p1_agent", "agent__letta"]}
    # In production this is populated from per-service secret files by install.sh.
    # NHI tokens are added from AgentRegistry.get_nhi_token_map() if the registry
    # is available at configure time (may also be refreshed at NHI approval).
    _load_token_role_map(agent_registry)

    # ── Zero-trust OPA startup validation (Path 3) ─────────────────────────
    # OPA is mandatory in production.  In development mode, fail-closed by
    # default; opt into fail-open with YASHIGANI_OPA_OPTIONAL=true (explicit,
    # auditable opt-in only — never the default).
    if not opa_url:
        _ysg_env = os.getenv("YASHIGANI_ENV", "").strip().lower()
        _opa_optional = os.getenv("YASHIGANI_OPA_OPTIONAL", "false").strip().lower() == "true"
        if _ysg_env == "production":
            raise RuntimeError(
                "YASHIGANI_OPA_URL is required in production (YASHIGANI_ENV=production). "
                "The gateway cannot start without OPA policy enforcement. "
                "Set YASHIGANI_OPA_URL to the reachable OPA endpoint. "
                "This is a zero-trust fail-closed guard — ASVS V14.5.* / feedback_zero_trust_default.md."
            )
        elif _opa_optional:
            logger.warning(
                "YASHIGANI_OPA_URL is not set and YASHIGANI_OPA_OPTIONAL=true — "
                "OPA policy enforcement is DISABLED for this deployment. "
                "All /v1/* requests will be ALLOWED without policy check. "
                "This is only permitted in non-production environments. "
                "YASHIGANI_ENV=%s",
                _ysg_env or "(not set)",
            )
        else:
            raise RuntimeError(
                "YASHIGANI_OPA_URL is not set. The gateway will not start without OPA policy "
                "enforcement (fail-closed by default). "
                "In development/test environments, set YASHIGANI_OPA_OPTIONAL=true to "
                "explicitly opt into running without OPA. "
                "In production, set YASHIGANI_OPA_URL to the reachable OPA endpoint. "
                "YASHIGANI_ENV=%s" % (_ysg_env or "(not set)",)
            )
    # F-T10-001: low-confidence step-up threshold (env-configurable).
    # Guard: empty or non-numeric env var must not crash configure().
    _thresh_raw = os.getenv("YASHIGANI_LOW_CONFIDENCE_STEPUP_THRESHOLD", "0.50")
    try:
        _state.low_confidence_stepup_threshold = float(_thresh_raw)
    except ValueError:
        logger.warning(
            "YASHIGANI_LOW_CONFIDENCE_STEPUP_THRESHOLD is not a valid float "
            "(got %r); using default 0.50",
            _thresh_raw,
        )
        _state.low_confidence_stepup_threshold = 0.50

    # v2.2 — streaming config from environment
    _state.streaming_enabled = (
        os.getenv("YASHIGANI_STREAMING_ENABLED", "true").lower() == "true"
    )
    _state.streaming_inspect_interval = int(
        os.getenv("YASHIGANI_STREAMING_INSPECT_INTERVAL", "200")
    )

    logger.info(
        "OpenAI router configured (default_model=%s, response_inspection=%s, "
        "streaming=%s, inspect_interval=%d, pii=%s, pii_cloud_bypass=%s)",
        default_model,
        "enabled" if response_inspection_pipeline is not None else "disabled",
        "enabled" if _state.streaming_enabled else "disabled",
        _state.streaming_inspect_interval,
        "enabled" if pii_detector is not None else "disabled",
        pii_cloud_bypass,
    )


# ── Audit adapters ──────────────────────────────────────────────────────


def _make_streaming_audit_adapter(audit_writer):
    """Return a Callable[[str, dict], None] that bridges the
    StreamingInspector ``on_audit(name, data)`` convention to
    ``AuditLogWriter.write(AuditEvent)``.

    Returns None when audit_writer is None (StreamingInspector treats None
    as a no-op).

    Iris FINDING-004: AuditLogWriter has no __call__; callers must use .write().
    """
    if audit_writer is None:
        return None

    def _adapter(name: str, data: dict) -> None:
        if name == "STREAM_TERMINATED":
            audit_writer.write(
                StreamTerminatedEvent(
                    trigger=data.get("trigger", ""),
                    request_id=data.get("request_id", ""),
                    session_id=data.get("session_id", ""),
                    agent_id=data.get("agent_id", ""),
                    accumulated_chars=int(data.get("accumulated_chars", 0)),
                )
            )
        # Unknown event names are silently dropped — the adapter is
        # intentionally narrow.  New streaming event types should get their
        # own EventType + dataclass and a branch here.

    return _adapter


# ── PII helpers ─────────────────────────────────────────────────────────


def _pii_audit(request_id: str, direction: str, pii_result, action: str, destination: str) -> None:
    """Write a PII detection audit event if an audit_writer is configured.

    F-RT1: records ``matched_views`` so an encoded-then-decoded hit is visible
    in the audit sink (e.g. ["base64"] means the PII was caught only after
    decoding — it would have been a silent pass before the decode stage).
    """
    if _state.audit_writer is None:
        return
    try:
        pii_types = [f.pii_type.value for f in pii_result.findings]
        matched_views = sorted(getattr(pii_result, "matched_views", None) or [])
        _state.audit_writer.write(
            PIIDetectedEvent(
                request_id=request_id,
                direction=direction,
                pii_types=pii_types,
                action_taken=action,
                destination=destination,
                finding_count=len(pii_result.findings),
                matched_views=matched_views,
            )
        )
    except Exception as exc:
        logger.warning("PII audit write failed (request_id=%s): %s", request_id, exc)


def _audit_brain_reasoning_relaxation(
    *, request_id: str, identity_id: str, verdict: str, confidence: float,
    content: str, opa_reason: str, sensitivity: str,
) -> None:
    """G-ORCH-OPA-3 — record a RELAXED brain-reasoning-leg response-OPA block.

    Writes an OrchestrationBrainReasoningRelaxedEvent with relaxation_applied=True
    so a would-have-blocked reasoning turn is ALWAYS greppable.  Raw content is
    never stored — only its SHA-256 hash.  Never raises (audit must not break the
    relaxation path).
    """
    if _state.audit_writer is None:
        return
    try:
        content_hash = hashlib.sha256((content or "").encode("utf-8")).hexdigest()
        _state.audit_writer.write(
            OrchestrationBrainReasoningRelaxedEvent(
                request_id=request_id,
                identity_id=identity_id,
                session_id=identity_id,
                verdict=verdict,
                confidence=float(confidence),
                content_hash=content_hash,
                opa_reason=opa_reason,
                sensitivity=sensitivity,
                relaxation_applied=True,
            )
        )
    except Exception as exc:
        logger.warning(
            "G-ORCH-OPA-3 relaxation audit write failed (request_id=%s): %s",
            request_id, exc,
        )


def _encoded_payload_audit(
    request_id: str, direction: str, destination: str, pii_result
) -> None:
    """Emit an ENCODED_PAYLOAD_DETECTED audit event (F-RT1 silent-pass guard).

    Called when the decode stage flagged a long, encoded-looking, high-entropy
    blob that could NOT be decoded to plaintext.  Even with no PII match this
    leaves an audit record — closing the worst part of F-RT1 (the silent pass).
    Raw payload is never logged — only masked token shapes + a count.
    """
    if _state.audit_writer is None:
        return
    if not getattr(pii_result, "suspicious_blob", False):
        return
    try:
        masked = list(getattr(pii_result, "suspicious_tokens", None) or [])
        _state.audit_writer.write(
            EncodedPayloadDetectedEvent(
                request_id=request_id,
                direction=direction,
                destination=destination,
                high_entropy=True,
                oversize=any(t.startswith("oversize(") for t in masked),
                token_count=len(masked),
                masked_tokens=masked,
            )
        )
        logger.warning(
            "F-RT1: encoded high-entropy blob present (request_id=%s direction=%s "
            "tokens=%s) — audited, no plaintext PII match",
            request_id, direction, masked,
        )
    except Exception as exc:
        logger.warning("Encoded-payload audit write failed (request_id=%s): %s", request_id, exc)


def _normalize_alias(name: str) -> str:
    """Derive the same @-handle slug backoffice/routes/user_agents.py does.

    YSG-RISK-168 (chat-path repair): the mention-menu @-handle offered to
    users is `_normalize_alias(agent.name)` (see
    backoffice/routes/user_agents.py::_normalize_alias — CANONICAL definition,
    kept identical here to compare handles on both sides of the global
    agent-registry lookup below without a cross-package import). Lowercase,
    collapses non-alphanumeric runs to a single underscore, strips leading/
    trailing underscores, prepends 'a' if the result starts with a digit,
    truncated to 63 chars. Any change here MUST be mirrored in
    user_agents.py's copy (and vice versa) — they must stay byte-identical.
    """
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower().strip())
    slug = slug.strip("_")
    if not slug:
        slug = "agent"
    if slug[0].isdigit():
        slug = "a" + slug
    return slug[:63]


def _sse_from_completion(
    completion: dict,
    headers: dict,
    verdict_tail: Optional[dict] = None,
) -> StreamingResponse:
    """Wrap a buffered OpenAI chat-completion dict as a single-chunk SSE stream.

    F-STREAM (2026-06-09): Open WebUI (and any OpenAI-compatible client) sends
    ``stream:true``.  When OPA policies are active (always, in real deployments)
    or PII block/redact is on, the gateway force-disables streaming and buffers
    the full response for inspection — but it must still answer a ``stream:true``
    request with ``text/event-stream``, or OWUI's SSE reader renders nothing
    ("perpetual thinking" → "Failed to fetch").

    OpenAI semantics: a stream:true request ALWAYS returns SSE, even if the body
    was produced via a single buffered upstream call.  To match the canonical
    OpenAI streaming framing that browser SSE clients (incl. Open WebUI) expect,
    we emit THREE ``chat.completion.chunk`` frames:
      1. ``delta={"role":"assistant"}``  — opens the message (no content yet)
      2. ``delta={"content": <full text>}`` — the full assistant text
      3. ``delta={}, finish_reason=<reason>`` — closes the message
    followed by the ``data: [DONE]`` sentinel.  Splitting role/content/finish
    into separate frames (rather than one fat frame) is what real OpenAI does and
    avoids frontend SSE parsers that reject a role+content+finish_reason combined
    in a single opening delta.  The buffered inspection (OPA / PII) has already
    run before we reach here, so no content escapes un-inspected.
    """
    choice = (completion.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    cid = completion.get("id", "")
    created = completion.get("created", 0)
    model = completion.get("model", "")
    index = choice.get("index", 0)
    content = message.get("content", "")
    role = message.get("role", "assistant")
    finish_reason = choice.get("finish_reason", "stop")

    def _frame(delta: dict, finish):
        return {
            "id": cid,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [
                {"index": index, "delta": delta, "finish_reason": finish}
            ],
        }

    def _gen():
        # 1) open with role
        yield f"data: {json.dumps(_frame({'role': role}, None))}\n\n"
        # 2) full content in a single content delta
        yield f"data: {json.dumps(_frame({'content': content}, None))}\n\n"
        # 3) close with finish_reason and empty delta
        yield f"data: {json.dumps(_frame({}, finish_reason))}\n\n"
        # 4) optional out-of-band structured verdict tail (RISK-105 anti-spoofing).
        #    Emitted BEFORE [DONE] so the SSE client can capture it in the same
        #    stream read loop.  Fields: blocked / user_alert / decision_codes.
        #    The 4.0 UI sse.js reads these as `structuredTail` and passes them to
        #    onMessageDone(fullText, structuredTail) → ys-verdict-banner renders them
        #    as TRUSTED-CHROME, NEVER by scanning message text (spec §4.2).
        #    NEVER for OPA/client-policy pre-stream blocks — those return HTTP 403
        #    JSONResponse before this function is called.
        if verdict_tail:
            yield f"data: {json.dumps(verdict_tail)}\n\n"
        yield "data: [DONE]\n\n"

    # SSE-specific headers; merge the caller's X-Yashigani-* headers on top.
    sse_headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",  # disable Nginx/Caddy buffering
    }
    sse_headers.update(headers)
    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers=sse_headers,
    )


# ── Endpoints ────────────────────────────────────────────────────────────


@router.post("/chat/completions", response_model=ChatCompletionResponse)
async def chat_completions(body: ChatCompletionRequest, request: Request):
    """
    OpenAI-compatible chat completions endpoint.

    Full pipeline:
    1. Identity resolution (API key or SSO headers)
    2. Sensitivity scan on input
    3. Complexity scoring
    4. Budget check
    5. Route to backend (local Ollama or cloud)
    6a. [streaming] Forward with stream=true; inspect chunks via StreamingInspector;
        return StreamingResponse. Budget headers skipped (see module docstring).
    6b. [buffered]  Buffer full response (legacy path, v1.0 Decision 13).
    7. Response inspection (buffered path only — streaming uses StreamingInspector)
    8. Token counting + budget recording
    9. Audit event
    10. Return response with budget headers (buffered path only)
    """
    request_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    start_time = time.time()

    # ── 0. DDoS protection — per-IP connection counting (v2.2) ───────────
    if _state.ddos_protector is not None:
        # CWE-345 fix (V232-NEG03 / LAURA-2026-04-29-006): use the
        # trusted-proxy-boundary resolver instead of trusting XFF[0].
        from yashigani.gateway.proxy import _get_client_ip as _resolve_ip
        _client_ip = _resolve_ip(request)
        _state.ddos_protector.record(_client_ip, "/v1/chat/completions")
        if not _state.ddos_protector.check(_client_ip, "/v1/chat/completions"):
            logger.warning(
                "DDoS threshold exceeded for ip=%s request_id=%s (openai router)",
                _client_ip,
                request_id,
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "CONNECTION_LIMIT_EXCEEDED",
                    "detail": "Too many requests from this IP address.",
                    "request_id": request_id,
                },
            )

    # ── 1. Identity resolution ────────────────────────────────────────
    identity = _resolve_identity(request)
    identity_id = identity.get("identity_id", "anonymous") if identity else "anonymous"

    # ── 1b. Anonymous-caller reject (Path 2 — ASVS V14.5.* / zero-trust) ─
    # OPA is an AUTHORISATION layer for AUTHENTICATED principals.  Anonymous
    # callers must be rejected HERE — before OPA is reached — so that OPA
    # never evaluates unauthenticated requests (correct separation of concerns).
    #
    # The yashigani-internal Bearer (YASHIGANI_INTERNAL_BEARER env-var) resolves
    # to identity_id="internal", kind="service" — NOT anonymous — so in-mesh
    # Open WebUI traffic is unaffected by this guard.
    #
    # Callers that lack an API key, a valid SSO header, or the internal Bearer
    # receive HTTP 401 here, before any downstream processing occurs.
    if identity is None:
        logger.warning(
            "Anonymous /v1/chat/completions caller rejected (request_id=%s) — "
            "zero-trust fail-closed (Path 2)",
            request_id,
        )
        # LAURA-411-004: generic OpenAI-format 401 — no internal header names or
        # auth-architecture details in the response body. Full reason in server log only.
        raise HTTPException(
            status_code=401,
            detail={
                "error": {
                    "message": "Authentication required",
                    "type": "authentication_error",
                    "code": "unauthorized",
                },
            },
        )

    # ── 1b-2. W3-008: RBAC group membership backfill ─────────────────────────
    # The identity registry persists `groups` only at REGISTRATION time.  Group
    # memberships added later via RBAC add_member are stored exclusively in
    # `rbac:user:{identity_id}` (Redis SADD) and are NEVER written back into
    # `identity:reg:{identity_id}`.  Without backfill every group-tier check in
    # this function (Layer 2 cloud gate, W3-007, LAURA-411-001 deny probe, perm
    # gate) iterates an empty list — silently over-blocking group-grantees
    # (power_user → 422) AND silently failing-open on group-deny grants.
    #
    # Backfill logic (human/user principals only):
    #   1. Call rbac_store.get_user_groups(identity_id) — reads rbac:user:{id}
    #      in Redis, which is authoritative for post-registration membership.
    #   2. Union the RBAC set with the reg-record set (preserves reg-record
    #      groups; dedupes; does not drop any existing membership).
    #   3. Shallow-copy the identity dict before mutating so the registry's
    #      cached dict is never modified in place.
    #
    # Fail-safe: if the rbac store is unavailable (None or raises), keep the
    # reg-record groups and log a warning.  This is intentionally NOT fail-
    # closed (a store blip must not hard-block ALL users); the group-tier gates
    # below already have their own fail-closed behaviour for missing grants.
    #
    # Service/agent/internal identities (kind ∉ {"human","user"}) legitimately
    # have groups=[] and are NOT backfilled — their access is controlled via
    # org-level grants, not group membership.
    if _state.rbac_store is not None and identity is not None:
        _w3008_kind = identity.get("kind", "")
        if _w3008_kind in ("human", "user"):
            _w3008_iid = identity.get("identity_id")
            if _w3008_iid:
                try:
                    _w3008_rbac_groups = _state.rbac_store.get_user_groups(_w3008_iid)
                    _w3008_rbac_gids: set[str] = {g.id for g in _w3008_rbac_groups}
                    _w3008_reg_gids: set[str] = set(identity.get("groups") or [])
                    _w3008_all_gids = _w3008_reg_gids | _w3008_rbac_gids
                    if _w3008_all_gids != _w3008_reg_gids:
                        # New memberships found — shallow-copy identity before mutating
                        identity = dict(identity)
                        identity["groups"] = list(_w3008_all_gids)
                        logger.debug(
                            "W3-008: backfilled groups for %s: reg=%s rbac=%s final=%s",
                            _w3008_iid,
                            sorted(_w3008_reg_gids),
                            sorted(_w3008_rbac_gids),
                            sorted(_w3008_all_gids),
                        )
                except Exception as _w3008_exc:
                    logger.warning(
                        "W3-008: RBAC group backfill failed for %s: %s — "
                        "keeping reg-record groups (fail-safe, not fail-closed)",
                        _w3008_iid, _w3008_exc,
                    )

    # ── 1c. Orchestration delegation (2.25.4, build sheet §3.1/§3.5) ──────
    # When the caller supplies `tools` (or opts in via `orchestrate=true`), the
    # request is a tool-calling orchestration, not a plain chat.  Delegate to the
    # gateway-side ReAct executor, which runs every tool hop as a self-call that
    # re-enters THIS full pipeline (OPA ingress + egress + ResponseInspection per
    # hop, §0.1 invariant).  Orchestration self-calls do NOT carry `tools`, so
    # they take the normal path below — there is no recursion through this branch.
    #
    # PHASE 2 (Design A, build sheet §4.2): when the user names @letta as the
    # ORCHESTRATING BRAIN with orchestration intent (it names other @agents/@models
    # or the MCP), letta drives the loop but the gateway is STILL the executor —
    # every tool letta names runs through the SAME gated self-call path.  Letta has
    # no network route to upstreams (UA-10 bridge isolation), so the gateway is the
    # only path.  is_letta_orchestration() promotes the call to the executor with
    # brain="letta"; a bare "@letta hello" stays a normal single-hop agent chat.
    # IMPORTANT: orchestration must NOT fire on the mere PRESENCE of `tools`.  An
    # agent framework whose LLM backend IS this gateway (e.g. letta:
    # OPENAI_API_BASE=http://gateway:8081/v1) sends its own `tools` on every plain
    # completion call — those are normal chat completions, not user-initiated
    # orchestration.  So the qwen-brain executor fires only on the EXPLICIT
    # `orchestrate=true` opt-in (build-sheet §3.5; all Phase-1 callers set it), and
    # the letta-brain executor fires only when @letta is named as the orchestrating
    # brain with orchestration intent.  A letta LLM-backend call carries neither,
    # so it correctly takes the normal chat path below.
    if not is_orchestration_self_call(request):
        from yashigani.gateway.letta_brain import is_letta_orchestration
        letta_brain = is_letta_orchestration(body.model, body)
        # YASHIGANI_ORCH_AUTO_MODELS: virtual model names that auto-trigger
        # the qwen-brain orchestration executor from a plain OWUI chat request.
        # The model field is rewritten to the brain model before the executor
        # runs (body.model is mutated in-place so every downstream reference
        # sees the real model; the original virtual name is logged for audit).
        auto_orch = (not letta_brain and not body.orchestrate
                     and is_auto_orchestrate_model(body.model))
        if auto_orch:
            import os as _os  # noqa: PLC0415  — local import avoids scope shadow
            brain_model = (_os.environ.get("YASHIGANI_ORCH_BRAIN_MODEL", "")
                           .strip()) or "qwen2.5:3b"
            logger.info(
                "orchestration: auto-trigger for model=%r → brain=%s (YASHIGANI_ORCH_AUTO_MODELS)",
                body.model, brain_model,
            )
            body = body.model_copy(update={"model": brain_model, "orchestrate": True})
        if body.orchestrate or letta_brain:
            from yashigani.gateway.orchestrator import run_orchestration
            return await run_orchestration(
                body=body,
                identity=identity,
                request=request,
                request_id=request_id,
                brain="letta" if letta_brain else "qwen",
            )

    # ── 1d. Brain-REASONING-leg detection (G-ORCH-OPA-3, server-minted) ──
    # Computed ONCE here from server-only state (the process-local brain
    # round-trip counter + the internal-bearer identity + the brain model).  It
    # is NOT derived from any letta-controllable input.  When False, every gate
    # below behaves BYTE-FOR-BYTE as before; the marker is consulted at exactly
    # ONE place — the response-leg OPA action (step 8c) — to relax the 403/
    # substitute ACTION while STILL evaluating + auditing the verdict.
    brain_reasoning_leg = is_brain_reasoning_leg(identity, body.model)
    # Set True ONLY when a would-have-blocked verdict was relaxed on this leg —
    # surfaced as a response header so the brain loop can route a relaxed
    # final/prose answer back through the NON-relaxed gate (condition 4).
    brain_reasoning_relaxed = False

    # ── 2. Extract prompt text for classification ─────────────────────
    prompt_text = "\n".join(m.content for m in body.messages if m.content)

    # ── 2b. Content relay detection (agent-to-agent laundering) ──────
    if _state.content_relay_detector and prompt_text:
        try:
            relay_result = _state.content_relay_detector.check_request(prompt_text)
            if relay_result.relay_detected:
                logger.warning(
                    "CONTENT RELAY DETECTED: request_id=%s identity=%s "
                    "matching_windows=%d source_agent=%s confidence=%.2f",
                    request_id, identity_id, relay_result.matching_windows,
                    relay_result.source_agent, relay_result.confidence,
                )
                # Do not block — flag via header and audit. The sensitivity
                # scan and OPA check downstream will still evaluate the content.
        except Exception as exc:
            logger.warning("Content relay check failed: %s", exc)

    # ── 3. Sensitivity scan ───────────────────────────────────────────
    # F-RT1 (red-team verified 2026-05-30): classify the decoded views, not just
    # the raw prompt.  base64("SSN 123-45-6789") and friends are normalised to
    # plaintext first so an encoded payload elevates the sensitivity level (and
    # therefore the OPA ceiling) exactly as the plaintext would.  classify_decoded
    # is a superset of classify for non-encoded text (raw view alone decides).
    sensitivity_level = "PUBLIC"
    sensitivity_triggers = []
    s_result = None
    if _state.sensitivity_classifier:
        s_result = _state.sensitivity_classifier.classify_decoded(prompt_text)
        # R14/R15 (v2.25.5): SensitivityResult.level is int (not SensitivityLevel enum).
        # Calling .value on an int raises AttributeError.  Convert via the legacy-string map
        # so all downstream consumers (string comparisons, HTTP headers, OPA, audit) get
        # the expected "PUBLIC"/"INTERNAL"/"CONFIDENTIAL"/"RESTRICTED" label.
        from yashigani.optimization.sensitivity_classifier import _LEVEL_TO_LEGACY_STRING
        sensitivity_level = _LEVEL_TO_LEGACY_STRING.get(int(s_result.level), "RESTRICTED")
        sensitivity_triggers = s_result.triggers
    if s_result is None:
        from yashigani.optimization.sensitivity_classifier import SensitivityLevel, SensitivityResult
        s_result = SensitivityResult(level=SensitivityLevel.PUBLIC)

    # ── 4. Complexity scoring ─────────────────────────────────────────
    complexity_level = "MEDIUM"
    token_estimate = len(prompt_text) // 4
    c_result = None
    if _state.complexity_scorer:
        c_result = _state.complexity_scorer.score(prompt_text, token_estimate)
        complexity_level = c_result.level.value
    if c_result is None:
        from yashigani.optimization.complexity_scorer import ComplexityLevel, ComplexityResult
        c_result = ComplexityResult(level=ComplexityLevel.MEDIUM, token_count=token_estimate, heuristic_score=0.0, reasons=[])

    # ── 5. Budget check ───────────────────────────────────────────────
    budget_signal = "normal"
    budget_pct = 0
    budget_used = 0
    budget_total = 0
    if _state.budget_enforcer and identity:
        from yashigani.billing.budget_enforcer import BudgetState
        allocation = _state.budget_enforcer.get_allocation(identity_id, "cloud")
        # YSG-RISK-144: check_hierarchy (not check) — the documented
        # individual<=group<=org invariant was never enforced because the
        # per-request path only ever checked the identity's OWN allocation.
        # An identity within its own budget but over its group/org cap was
        # never denied/degraded. group_ids/org_id come straight off the
        # already-resolved identity dict (identity registry populates both).
        budget_state = _state.budget_enforcer.check_hierarchy(
            identity_id, "cloud", budget_total=allocation,
            group_ids=identity.get("groups") or [],
            org_id=identity.get("org_id", "") or "",
        )
        budget_signal = budget_state.signal.value
        budget_pct = budget_state.pct
        budget_used = budget_state.used
        budget_total = budget_state.total
    else:
        from yashigani.billing.budget_enforcer import BudgetSignal, BudgetState
        budget_state = BudgetState(identity_id=identity_id, provider="cloud", used=0, total=0, signal=BudgetSignal.NORMAL, pct=0)

    # ── 6. Route decision ──────────────────────────────────────────────
    selected_model = body.model or _state.default_model
    # W3-007 (LAURA-V250-W3-007): resolved cloud target from alias pre-resolution.
    # Set inside the body.model validation block below; consumed by the Layer 2
    # extension and the LAURA-411-001 extension later in this function.
    _w3007_resolved_cloud_target: str | None = None

    # Agent routing: if model starts with @, forward to the agent's upstream
    is_agent_call = selected_model.startswith("@")

    # ── LAURA-411-002 / Ava FINDING-1: model input validation + normalization ──
    # Runs BEFORE RBAC deny and optimisation so URL/path/null variants cannot
    # bypass the deny check by triggering the silent local-default fallback.
    #
    # YSG-RISK-158: agent calls (@-prefix) are NO LONGER exempted from
    # _validate_model_string itself — the @-prefix exemption now lives INSIDE
    # the validator (see _validate_model_string / _AGENT_CALL_VALID_RE), so an
    # agent-call payload gets the SAME positive-validation gate (URL-scheme,
    # path-traversal, null-sentinel, ASCII charset) as any other model string.
    # Only brain-reasoning-leg (server-minted, no user-supplied value) and an
    # absent body.model (explicit default-model path — preserved per brief)
    # skip validation entirely.
    if body.model and not brain_reasoning_leg:
        _mv_err = _validate_model_string(body.model)
        if _mv_err is not None:
            logger.warning(
                "LAURA-411-002: invalid model string %r from identity=%s (%s) → 422",
                body.model, identity_id, _mv_err,
            )
            return JSONResponse(
                status_code=422,
                content={
                    "error": {
                        "message": f"The model name is invalid ({_mv_err}).",
                        "type": "invalid_request_error",
                        "code": "model_not_found",
                    }
                },
            )
    # Normalization + known-model gating stay agent-call-exempt: an @-handle
    # is an agent identifier resolved via agent_registry, not an LLM model
    # name, so provider/model normalization and the alias/installed-model
    # allowlist check below do not apply to it.
    if body.model and not is_agent_call and not brain_reasoning_leg:
        # Normalize: lowercase + provider/model → provider:model.
        # The normalized form flows through optimisation and RBAC;
        # body.model (original) is retained for audit/logging.
        from yashigani.models.effective import normalize_model_for_deny as _norm_model_fn
        _norm = _norm_model_fn(body.model)
        if _norm and _norm != selected_model:
            logger.debug(
                "LAURA-411-002: model normalized %r → %r",
                body.model, _norm,
            )
            selected_model = _norm

        # Part (b): reject models that resolve to no known alias or installed
        # model → HTTP 422 model_not_found instead of silent fallback to
        # qwen2.5:3b.  Skipped when alias_store and available_models are both
        # absent (minimally-configured / test deployments).
        if not _is_known_model(
            selected_model,
            _state.model_alias_store,
            _state.available_models,
        ):
            logger.warning(
                "LAURA-411-002: unknown model %r (normalized: %r) from identity=%s → 422",
                body.model, selected_model, identity_id,
            )
            return JSONResponse(
                status_code=422,
                content={
                    "error": {
                        "message": (
                            f"The model '{body.model}' is not available. "
                            "Contact an administrator to check the model name."
                        ),
                        "type": "invalid_request_error",
                        "code": "model_not_found",
                    }
                },
            )

        # W3-007 (LAURA-V250-W3-007): Pre-resolve alias to its canonical cloud target.
        # Layer 2 (below) gates on ":" in selected_model — a plain alias name has no
        # colon and is therefore skipped, allowing an alias that resolves to a cloud
        # model to bypass the cloud RBAC gate entirely (PoC: model="smart" resolves to
        # "anthropic:claude-sonnet-4-6"; no Anthropic API key → local fallback;
        # _perm_is_cloud=False → cloud gate never fires → LAURA-411-001 checks "smart"
        # literal — no deny grant for that name → 200 with qwen content).
        #
        # Fix: resolve the alias here so _w3007_resolved_cloud_target carries the
        # resolved cloud canonical.  Both the Layer 2 extension and the LAURA-411-001
        # extension below then enforce the RESOLVED model's permission requirements
        # regardless of whether the caller supplied an alias name or a direct string.
        if _state.model_alias_store is not None:
            try:
                _w3007_alias_cfg = _state.model_alias_store.get(selected_model)
                if _w3007_alias_cfg is not None:
                    _w3007_alias_canonical = (
                        f"{_w3007_alias_cfg.provider}:{_w3007_alias_cfg.model}"
                    )
                    # Defence-in-depth: validate the resolved canonical through Layer 1.
                    # Admin-stored aliases are trusted, but any alias whose resolved
                    # provider:model fails validation is rejected rather than silently
                    # smuggled through the cloud RBAC gate.
                    if _validate_model_string(_w3007_alias_canonical) is None:
                        if _w3007_alias_cfg.provider in _CLOUD_PROVIDER_CONFIG:
                            _w3007_resolved_cloud_target = _w3007_alias_canonical
            except Exception:  # noqa: BLE001 — store blip; treat as no cloud alias
                pass

        # LAURA-412-002 (layer 2): No silent local fallback for cloud-prefixed
        # models that are not recognized/granted.
        #
        # ROOT CAUSE closed: _is_known_model() returns True for ANY model whose
        # canonical prefix is in _CLOUD_PROVIDER_CONFIG (e.g. "openai:anything").
        # After _resolve_alias, a cloud-prefixed string with no "/" falls through
        # as ("ollama", model, False) → selected_provider="ollama" → the 6a-perm
        # cloud gate (_perm_is_cloud=False) never fires → LAURA-411-001's
        # explicit-deny lookup uses the CANONICAL key so a junk suffix
        # ("openai:gpt-4oAAAA") never matches the stored grant ("openai:gpt-4o")
        # → no deny → silent qwen2.5:3b fallback → 200.
        #
        # FIX: if the canonical model has a known cloud provider prefix, it MUST
        # have either (a) an alias-store entry (resolves to a real provider/model)
        # OR (b) a permission grant (allow or deny — any grant proves the admin
        # configured this model) at org/user/group level.  If neither → 422.
        #
        # PRESERVE: power_user with a GRANTED openai:gpt-4o on a keyless demo
        # stack still gets a 200 via local-fallback because a grant EXISTS for the
        # exact canonical model → _412_has_grant=True → gate passes → 6a-perm and
        # LAURA-411-001 handle allow/deny correctly.
        #
        # SKIPPED when permission_store is None (no grant system configured) —
        # consistent with 6a-perm and LAURA-411-001 gates that also require it.
        if ":" in selected_model and _state.permission_store is not None:
            _412_prefix = selected_model.split(":", 1)[0]
            if _412_prefix in _CLOUD_PROVIDER_CONFIG:
                # Check for a known alias (resolves this exact canonical string)
                _412_alias_known = False
                if _state.model_alias_store is not None:
                    try:
                        _412_alias_known = _state.model_alias_store.get(selected_model) is not None
                    except Exception:  # noqa: BLE001 — store blip; treat as unknown
                        _412_alias_known = False
                _412_has_grant = _412_alias_known
                if not _412_has_grant:
                    from yashigani.permissions import ResourceType as _RT_412
                    from yashigani.permissions import DEFAULT_ORG_ID as _ORG_412
                    try:
                        # Org level — primary tier for cloud_model grants
                        if _state.permission_store.get_boolean_grant(
                            _RT_412.CLOUD_MODEL, "org", _ORG_412, selected_model
                        ) is not None:
                            _412_has_grant = True
                        # User level
                        if not _412_has_grant and identity:
                            _412_kind = identity.get("kind", "")
                            _412_uid = (
                                identity.get("identity_id")
                                if _412_kind in ("human", "user") else None
                            )
                            if _412_uid and _state.permission_store.get_boolean_grant(
                                _RT_412.CLOUD_MODEL, "user", _412_uid, selected_model
                            ) is not None:
                                _412_has_grant = True
                        # Group level
                        if not _412_has_grant and identity:
                            for _412_gid in (identity.get("groups") or []):
                                if _state.permission_store.get_boolean_grant(
                                    _RT_412.CLOUD_MODEL, "group", str(_412_gid), selected_model
                                ) is not None:
                                    _412_has_grant = True
                                    break
                    except Exception as _412_exc:  # noqa: BLE001
                        # Fail-closed: grant-check failure → unknown grant → 422
                        logger.warning(
                            "LAURA-412-002: permission store check failed (%s) — "
                            "fail-closed, treating cloud-prefixed model %r as ungranted",
                            _412_exc, selected_model,
                        )
                        _412_has_grant = False
                if not _412_has_grant:
                    logger.warning(
                        "LAURA-412-002: cloud-prefixed model %r (canonical: %r, "
                        "provider: %s) has no alias or permission grant — "
                        "422 (no silent local fallback). LAURA-412.",
                        body.model, selected_model, _412_prefix,
                    )
                    return JSONResponse(
                        status_code=422,
                        content={
                            "error": {
                                "message": (
                                    f"The model '{body.model}' is not available. "
                                    "Contact an administrator to check the model name."
                                ),
                                "type": "invalid_request_error",
                                "code": "model_not_found",
                            }
                        },
                    )

        # W3-007 (Layer 2 extension — LAURA-V250-W3-007): alias→cloud RBAC gate.
        # Fires when selected_model is an alias resolving to a cloud model (e.g.
        # "smart" → "anthropic:claude-sonnet-4-6").  The Layer 2 block above only
        # fires when ":" is in selected_model; a bare alias name has no colon →
        # the existing check was skipped → resolved cloud target never checked →
        # bypass (PoC: 200 with local fallback content).
        #
        # Logic mirrors Layer 2: ANY grant (allow OR deny) for the resolved cloud
        # target proves the admin configured this model → gate passes and LAURA-411-001
        # below handles explicit-deny.  NO grant → 422 (no silent local fallback).
        # PRESERVE: a user granted the resolved cloud model still gets the by-design
        # local-fallback 200 on a keyless demo stack (grant found → gate passes).
        # Local-target aliases (e.g. fast→qwen2.5:3b, provider=ollama) have
        # _w3007_resolved_cloud_target=None → this block is skipped entirely.
        if _w3007_resolved_cloud_target is not None and _state.permission_store is not None:
            _w3007_target = _w3007_resolved_cloud_target
            _w3007_prefix = _w3007_target.split(":", 1)[0]
            _w3007_alias_known = False
            if _state.model_alias_store is not None:
                try:
                    _w3007_alias_known = (
                        _state.model_alias_store.get(_w3007_target) is not None
                    )
                except Exception:  # noqa: BLE001 — store blip; treat as unknown
                    _w3007_alias_known = False
            _w3007_has_grant = _w3007_alias_known
            if not _w3007_has_grant:
                from yashigani.permissions import ResourceType as _RT_W3007
                from yashigani.permissions import DEFAULT_ORG_ID as _ORG_W3007
                try:
                    # Org level
                    if _state.permission_store.get_boolean_grant(
                        _RT_W3007.CLOUD_MODEL, "org", _ORG_W3007, _w3007_target
                    ) is not None:
                        _w3007_has_grant = True
                    # User level
                    if not _w3007_has_grant and identity:
                        _w3007_kind = identity.get("kind", "")
                        _w3007_uid = (
                            identity.get("identity_id")
                            if _w3007_kind in ("human", "user") else None
                        )
                        if _w3007_uid and _state.permission_store.get_boolean_grant(
                            _RT_W3007.CLOUD_MODEL, "user", _w3007_uid, _w3007_target
                        ) is not None:
                            _w3007_has_grant = True
                    # Group level
                    if not _w3007_has_grant and identity:
                        for _w3007_gid in (identity.get("groups") or []):
                            if _state.permission_store.get_boolean_grant(
                                _RT_W3007.CLOUD_MODEL, "group", str(_w3007_gid), _w3007_target
                            ) is not None:
                                _w3007_has_grant = True
                                break
                except Exception as _w3007_exc:  # noqa: BLE001
                    # Fail-closed: permission check failure → treat as ungranted → 422
                    logger.warning(
                        "W3-007: alias→cloud permission check failed (%s) for "
                        "alias=%r → resolved=%r — fail-closed (422)",
                        _w3007_exc, body.model, _w3007_target,
                    )
                    _w3007_has_grant = False
            if not _w3007_has_grant:
                logger.warning(
                    "W3-007 DENIED (Layer 2 ext): alias=%r → resolved=%r "
                    "(provider=%s) has no permission grant for identity=%s — "
                    "422. LAURA-V250-W3-007.",
                    body.model, _w3007_target, _w3007_prefix, identity_id,
                )
                return JSONResponse(
                    status_code=422,
                    content={
                        "error": {
                            "message": (
                                f"The model '{body.model}' is not available. "
                                "Contact an administrator to check the model name."
                            ),
                            "type": "invalid_request_error",
                            "code": "model_not_found",
                        }
                    },
                )

    agent_upstream = None
    agent_protocol = "openai"
    if is_agent_call and not _state.agent_registry:
        # YSG-RISK-129: is_agent_call=True but the agent_registry dependency
        # itself is unavailable (e.g. Redis-backed registry down/not yet
        # initialized). Without this guard, agent_upstream stays None, the
        # resolution block below is skipped entirely (its own `if not
        # agent_upstream: return 404` guard at the end of that block never
        # runs because the block is gated on `_state.agent_registry` too),
        # AND — further down — BOTH the `if is_agent_call and agent_upstream`
        # buffered-agent branch and the `if not is_agent_call` cloud/local
        # branch are skipped, falling straight through with `assistant_content`
        # / `backend_body` never assigned → UnboundLocalError instead of a
        # clean error. Fail closed here with a well-formed 503 immediately.
        logger.error(
            "Agent call %s received but agent_registry is unavailable "
            "(backend dependency down) request_id=%s",
            selected_model, request_id,
        )
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "message": "Agent registry is temporarily unavailable. Please try again shortly.",
                    "type": "agent_error",
                    "agent": selected_model,
                    "code": "agent_registry_unavailable",
                }
            },
        )
    if is_agent_call and _state.agent_registry:
        agent_name = selected_model[1:]  # strip @

        # ── v4.0: Per-user @-handle resolution ────────────────────────────────
        # Check the calling user's alias namespace BEFORE the global registry.
        # ua:alias:{identity_id} is a Redis hash: {alias → ua_id}.
        # BOLA: the lookup key is derived from the validated identity_id, not
        # the user-supplied model string — a caller can only address their own
        # entities even if they guess another user's alias.
        if identity and identity_id and identity_id != "internal":
            _ua_meta: dict | None = None
            try:
                _r_ua = _state.agent_registry._r
                _ua_id_raw = _r_ua.hget(f"ua:alias:{identity_id}", agent_name)
                if _ua_id_raw is not None:
                    _ua_id = (
                        _ua_id_raw.decode()
                        if isinstance(_ua_id_raw, bytes)
                        else _ua_id_raw
                    )
                    _raw_meta = _r_ua.hgetall(f"ua:meta:{_ua_id}")
                    if _raw_meta:
                        _decoded = {
                            (k.decode() if isinstance(k, bytes) else k): (
                                v.decode() if isinstance(v, bytes) else v
                            )
                            for k, v in _raw_meta.items()
                        }
                        if _decoded.get("account_id") == identity_id:
                            _ua_meta = _decoded
                            _ua_meta["_ua_id"] = _ua_id
                        else:
                            # Stale alias index entry — BOLA: deny and log
                            logger.warning(
                                "UA @-handle stale alias: handle=%r identity=%s "
                                "meta.account_id=%s — denying",
                                agent_name,
                                identity_id,
                                _decoded.get("account_id"),
                            )
                            return JSONResponse(
                                status_code=404,
                                content={
                                    "error": {
                                        "message": (
                                            f"Agent {selected_model} not found"
                                        ),
                                        "type": "agent_error",
                                        "code": "agent_not_found",
                                    }
                                },
                            )
            except Exception as _uam_exc:
                logger.warning(
                    "Per-user @-handle lookup failed for %r identity=%s: %s",
                    agent_name,
                    identity_id,
                    _uam_exc,
                )
                _ua_meta = None

            if _ua_meta is not None:
                _ua_kind = _ua_meta.get("kind", "agent")

                if _ua_kind == "persona":
                    # ── Route to the caller's per-user Letta container ──────
                    if _state.pool_manager is None:
                        return JSONResponse(
                            status_code=503,
                            content={
                                "error": {
                                    "message": (
                                        f"Persona {selected_model} requires the Letta "
                                        "per-user pool (feat/4.0-agent-isolation). "
                                        "Pool manager is not available in this deployment."
                                    ),
                                    "type": "agent_error",
                                    "agent": selected_model,
                                    "code": "letta_pool_unavailable",
                                }
                            },
                        )
                    try:
                        from yashigani.gateway.letta_client import (
                            LettaClientPool as _PerUserLCPool,
                        )
                        _lcp = _PerUserLCPool(_state.pool_manager)
                        _lc_client, _lc_base, _lc_agent_id = await _lcp.for_user(
                            identity_id
                        )
                        # Use the agent's specific letta_agent_id if provisioned;
                        # otherwise use the default per-user agent.
                        _specific_lid = _ua_meta.get("letta_agent_id", "")
                        if _specific_lid:
                            _lc_agent_id = _specific_lid

                        # Build messages, injecting persona context as system message
                        _ua_messages: list[dict] = [
                            {"role": m.role, "content": m.content or ""}
                            for m in body.messages
                        ]
                        _persona_system = ""
                        try:
                            _pers = json.loads(_ua_meta.get("personality", "{}"))
                            _persona_system = (
                                _pers.get("system_prompt", "")
                                or _pers.get("persona", "")
                            )
                        except Exception:
                            pass
                        if _persona_system:
                            _ua_messages = [
                                {"role": "system", "content": _persona_system},
                                *_ua_messages,
                            ]

                        _asst_text = ""
                        try:
                            async with _lc_client:
                                _lc_resp = await _lc_client.post(
                                    f"{_lc_base}/v1/agents/{_lc_agent_id}/messages",
                                    json={
                                        "messages": _ua_messages,
                                        "streaming": False,
                                    },
                                )
                            if _lc_resp.status_code != 200:
                                raise RuntimeError(
                                    f"Letta per-user HTTP {_lc_resp.status_code}: "
                                    f"{_lc_resp.text[:200]}"
                                )
                            _lc_data = _lc_resp.json()
                            for _lc_msg in _lc_data.get("messages", []):
                                if (
                                    _lc_msg.get("message_type")
                                    == "assistant_message"
                                ):
                                    _asst_text = _lc_msg.get("content", "")
                                    break
                            if not _asst_text:
                                _parts = [
                                    _lc_msg.get("content", "")
                                    for _lc_msg in _lc_data.get("messages", [])
                                    if _lc_msg.get("content")
                                    and _lc_msg.get("message_type")
                                    not in (
                                        "system_message",
                                        "tool_call_message",
                                    )
                                ]
                                _asst_text = (
                                    "\n".join(_parts)
                                    if _parts
                                    else "Persona returned no text."
                                )
                        except Exception as _pe:
                            logger.exception(
                                "Letta persona %s failed for identity=%s",
                                selected_model,
                                identity_id,
                            )
                            return JSONResponse(
                                status_code=502,
                                content={
                                    "error": {
                                        "message": (
                                            f"Persona {selected_model} unreachable"
                                        ),
                                        "type": "agent_error",
                                        "agent": selected_model,
                                        "code": "agent_unreachable",
                                    }
                                },
                                headers={"X-Yashigani-Agent-Error": "true"},
                            )

                        return JSONResponse(
                            content={
                                "id": f"chatcmpl-persona-{uuid.uuid4().hex[:8]}",
                                "object": "chat.completion",
                                "model": selected_model,
                                "choices": [
                                    {
                                        "index": 0,
                                        "message": {
                                            "role": "assistant",
                                            "content": _asst_text,
                                        },
                                        "finish_reason": "stop",
                                    }
                                ],
                                "usage": {
                                    "prompt_tokens": 0,
                                    "completion_tokens": 0,
                                    "total_tokens": 0,
                                },
                            },
                            headers={
                                "X-Yashigani-Agent": selected_model,
                                "X-Yashigani-Route-Reason": (
                                    f"user_persona:{agent_name}"
                                ),
                            },
                        )
                    except (ImportError, Exception) as _persona_exc:
                        if isinstance(_persona_exc, ImportError):
                            logger.error(
                                "LettaClientPool import failed for persona routing: %s",
                                _persona_exc,
                            )
                            return JSONResponse(
                                status_code=503,
                                content={
                                    "error": {
                                        "message": "Letta client not available.",
                                        "type": "agent_error",
                                        "code": "letta_pool_unavailable",
                                    }
                                },
                            )
                        # Already returned from the inner try (or re-raised); log
                        logger.exception(
                            "Persona routing outer exception for %s", selected_model
                        )
                        return JSONResponse(
                            status_code=502,
                            content={
                                "error": {
                                    "message": (
                                        f"Persona {selected_model} routing failed"
                                    ),
                                    "type": "agent_error",
                                    "code": "agent_unreachable",
                                }
                            },
                        )

                elif _ua_kind == "agent":
                    # ── Route via NHI in agent_registry ────────────────────
                    _nhi_id = _ua_meta.get("nhi_id", "")
                    if not _nhi_id:
                        return JSONResponse(
                            status_code=503,
                            content={
                                "error": {
                                    "message": (
                                        f"User agent {selected_model!r} has not been "
                                        "instantiated. Call POST "
                                        "/user/agents/{id}/run first."
                                    ),
                                    "type": "agent_error",
                                    "agent": selected_model,
                                    "code": "agent_not_instantiated",
                                }
                            },
                        )
                    _nhi_entry = _state.agent_registry.get(_nhi_id)
                    if _nhi_entry is None or _nhi_entry.get("status") != "active":
                        return JSONResponse(
                            status_code=404,
                            content={
                                "error": {
                                    "message": (
                                        f"Agent {selected_model} not found or not active"
                                    ),
                                    "type": "agent_error",
                                    "agent": selected_model,
                                    "code": "agent_not_found",
                                }
                            },
                        )
                    # Ceiling: NHI must be approved (svid_issued=1) before
                    # gateway invocations are accepted.
                    _svid = _nhi_entry.get("svid_issued", "0")
                    if _svid in (False, "0", 0):
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": {
                                    "message": "NHI pending approval",
                                    "type": "agent_error",
                                    "agent": selected_model,
                                    "code": "NHI_PENDING_APPROVAL",
                                }
                            },
                        )
                    _nhi_url = _nhi_entry.get("upstream_url", "")
                    if _nhi_url.startswith("pool://"):
                        _nhi_image = _nhi_url[len("pool://"):]
                        if _state.pool_manager is None:
                            return JSONResponse(
                                status_code=502,
                                content={
                                    "error": {
                                        "message": (
                                            f"Agent {selected_model} requires container "
                                            "pool but PoolManager is unavailable"
                                        ),
                                        "type": "agent_error",
                                        "agent": selected_model,
                                        "code": "pool_backend_unavailable",
                                    }
                                },
                                headers={"X-Yashigani-Agent-Error": "true"},
                            )
                        try:
                            from yashigani.pool.manager import (
                                PoolLimitExceeded as _NhiPoolLimitExceeded,
                            )
                            _nhi_ci = _state.pool_manager.get_or_create(
                                identity_id=identity_id,
                                service_slug=f"nhi_{_nhi_id}",
                                image=_nhi_image,
                            )
                            agent_upstream = f"http://{_nhi_ci.endpoint}"
                        except _NhiPoolLimitExceeded as _ple:
                            return JSONResponse(
                                status_code=402,
                                content={
                                    "error": "pool_limit_exceeded",
                                    "limit": (
                                        _state.pool_manager._limits.total_concurrent
                                    ),
                                    "current": _state.pool_manager.count(identity_id),
                                },
                            )
                        except Exception as _npe:
                            logger.error(
                                "NHI pool dispatch failed agent=%s nhi=%s: %s",
                                agent_name,
                                _nhi_id,
                                _npe,
                            )
                            return JSONResponse(
                                status_code=502,
                                content={
                                    "error": {
                                        "message": (
                                            f"Agent {selected_model} container "
                                            "backend failed"
                                        ),
                                        "type": "agent_error",
                                        "code": "pool_backend_unavailable",
                                    }
                                },
                                headers={"X-Yashigani-Agent-Error": "true"},
                            )
                    elif _nhi_url:
                        agent_upstream = _nhi_url
                    else:
                        # NHI registered but no upstream_url yet
                        return JSONResponse(
                            status_code=503,
                            content={
                                "error": {
                                    "message": (
                                        f"User agent {selected_model} is registered "
                                        "but not yet provisioned (no upstream URL). "
                                        "Container provisioning may be in progress."
                                    ),
                                    "type": "agent_error",
                                    "code": "agent_not_provisioned",
                                }
                            },
                        )
                    agent_protocol = _nhi_entry.get("protocol", "openai")
                    # agent_upstream is now set; skip the global registry loop below

                else:
                    # Unknown kind — treat as not found
                    return JSONResponse(
                        status_code=404,
                        content={
                            "error": {
                                "message": (
                                    f"Agent {selected_model} not found"
                                ),
                                "type": "agent_error",
                                "code": "agent_not_found",
                            }
                        },
                    )
        # ──────────────────────────────────────────────────────────────────────

        # Global registry lookup — only if per-user resolution did not resolve
        if not agent_upstream:
            # YSG-RISK-168: compare NORMALIZED handles on both sides, not a raw
            # exact match. backoffice/routes/user_agents.py::list_user_mentions()
            # derives the mention-menu @-handle via _normalize_alias(agent.name)
            # — e.g. registry name "agent__langflow" (double underscore) becomes
            # the offered handle "agent_langflow" (single underscore, collapsed
            # by the alphanumeric-run normaliser). A caller addressing the ONLY
            # handle the UI ever offers them would exact-match-fail here and
            # 404. Normalizing both sides lets either the mention-menu handle
            # or the raw registry name resolve to the same agent.
            _agent_name_norm = _normalize_alias(agent_name)
            for agent in _state.agent_registry.list_all():
                if (
                    _normalize_alias(agent.get("name", "")) == _agent_name_norm
                    and agent.get("status") == "active"
                ):
                    stored_url = agent.get("upstream_url", "")
                    agent_protocol = agent.get("protocol", "openai")

                    # v2.4.1 — Pool-managed agent: upstream_url stored as pool://<image>
                    # Resolve to a per-identity container endpoint via PoolManager.
                    if stored_url.startswith("pool://"):
                        pool_image = stored_url[len("pool://"):]
                        if _state.pool_manager is None:
                            logger.error(
                                "Pool-managed agent %s requested but PoolManager is unavailable",
                                agent_name,
                            )
                            if _state.audit_writer is not None:
                                try:
                                    _state.audit_writer.write(PoolBackendUnavailableEvent(
                                        request_id=request_id,
                                        identity_id=identity_id,
                                        agent_name=agent_name,
                                        reason="pool_manager_none",
                                    ))
                                except Exception:
                                    pass
                            return JSONResponse(
                                status_code=502,
                                content={
                                    "error": {
                                        "message": f"Agent {selected_model} requires container pool but PoolManager is unavailable",
                                        "type": "agent_error",
                                        "agent": selected_model,
                                        "code": "pool_backend_unavailable",
                                    }
                                },
                                headers={"X-Yashigani-Agent-Error": "true"},
                            )

                        try:
                            from yashigani.pool.manager import PoolLimitExceeded
                            container_info = _state.pool_manager.get_or_create(
                                identity_id=identity_id,
                                service_slug=agent_name,
                                image=pool_image,
                            )
                            agent_upstream = f"http://{container_info.endpoint}"
                            logger.info(
                                "Pool dispatch: agent=%s identity=%s container=%s endpoint=%s",
                                agent_name, identity_id,
                                container_info.container_name, container_info.endpoint,
                            )
                        except PoolLimitExceeded as _ple:
                            logger.warning(
                                "Pool limit exceeded for identity=%s agent=%s: %s",
                                identity_id, agent_name, _ple,
                            )
                            return JSONResponse(
                                status_code=402,
                                content={
                                    "error": "pool_limit_exceeded",
                                    "limit": _state.pool_manager._limits.total_concurrent,
                                    "current": _state.pool_manager.count(identity_id),
                                },
                            )
                        except Exception as _pool_exc:
                            logger.error(
                                "Pool backend error for agent=%s identity=%s: %s",
                                agent_name, identity_id, _pool_exc,
                            )
                            if _state.audit_writer is not None:
                                try:
                                    _state.audit_writer.write(PoolBackendUnavailableEvent(
                                        request_id=request_id,
                                        identity_id=identity_id,
                                        agent_name=agent_name,
                                        reason=type(_pool_exc).__name__,
                                    ))
                                except Exception:
                                    pass
                            return JSONResponse(
                                status_code=502,
                                content={
                                    "error": {
                                        "message": f"Agent {selected_model} container backend failed",
                                        "type": "agent_error",
                                        "agent": selected_model,
                                        "code": "pool_backend_unavailable",
                                    }
                                },
                                headers={"X-Yashigani-Agent-Error": "true"},
                            )
                    else:
                        # Normal externally-deployed agent — backward compatible path.
                        agent_upstream = stored_url
                    break

        if not agent_upstream:
            return JSONResponse(
                status_code=404,
                content={
                    "error": {
                        "message": f"Agent {selected_model} not found or not active",
                        "type": "agent_error",
                        "agent": selected_model,
                        "code": "agent_not_found",
                    }
                },
            )

    # ── Track B1 (model-RBAC): compute the caller's EFFECTIVE allowed-models ──
    # once, BEFORE optimisation, and reuse it for (a) the OPA model_allowed check
    # and (b) the optimiser-binding re-check below. effective.allowed carries both
    # the alias names AND the concrete models behind allocated aliases, so it
    # matches whatever form (alias or concrete) the optimiser ultimately selects.
    _effective = _effective_allowed_models(identity) if not is_agent_call else None
    _eff_opa_list = _effective.to_opa_allowed_models() if _effective is not None else None

    # ── LAURA-B1-OBS-A: EXPLICIT-pin deny is VISIBLE (403), not silent-substitute ─
    # Two distinct intents must be distinguished, and only ONE may be silently
    # rerouted by the OBS-1 fallback:
    #   • EXPLICIT request — the caller PINNED a concrete model in the request body
    #     (``body.model`` truthy) that they are NOT allocated.  A security product
    #     MUST be honest: deny VISIBLY with 403 model_not_allocated, byte-for-byte
    #     the same verdict the orchestrate-seed path returns.  Silently serving an
    #     allocated substitute (HTTP 200) would MASK enforcement.
    #   • OPTIMISER/DEFAULT AUTO-selection — the caller did NOT pin a model
    #     (``body.model`` falsy → the global default was used) OR the optimiser
    #     later re-selects a model (P1 local pin, budget reroute, …).  Here the
    #     caller never asked for the denied model, so the OBS-1 fallback below
    #     substitutes a model they ARE allocated (preserved, no 403).
    # The discriminator is purely "did the CALLER pin the model" (``body.model``),
    # which is forgery-proof: it is the caller's own request body, and a deny only
    # ever REMOVES access — no over-grant.  The security bar is unchanged: no
    # non-allocated model is ever served on EITHER branch (auto-path falls back to
    # an allocated model or is denied by the alloc-bind re-check downstream).
    # brain_reasoning_leg stays exempt (server-minted, holds no allocation) exactly
    # as the alloc-bind re-check below.
    if (
        body.model  # caller PINNED a model explicitly (vs default/auto)
        and not is_agent_call
        and not brain_reasoning_leg
        and _effective is not None
    ):
        _pinned_denied = _effective.is_model_denied(body.model)
        if not _pinned_denied and _state.optimization_engine is not None:
            # Resolve the pinned alias to its concrete model and re-check, so a
            # pin of an ALIAS whose concrete is denied is also caught (mirrors the
            # downstream alloc-bind, which runs on the resolved concrete).
            try:
                _, _pinned_concrete, _ = _state.optimization_engine._resolve_alias(body.model)
                _pinned_denied = _effective.is_model_denied(_pinned_concrete)
            except Exception as exc:  # noqa: BLE001 — never fail-open the route
                logger.warning(
                    "B1-OBS-A pinned-alias resolution failed (%s) — relying on "
                    "name-level + downstream alloc-bind checks", exc,
                )
        if _pinned_denied:
            logger.warning(
                "MODEL-RBAC DENIED (explicit-pin, B1-OBS-A): identity=%s "
                "pinned=%s NOT allocated — visible 403 (no silent substitute)",
                identity_id, body.model,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        # R2: human-readable message so OWUI displays it in chat.
                        "message": _deny_message("model_not_allocated"),
                        "type": "policy_denied",
                        "code": "model_not_allocated",
                    }
                },
                headers={"X-Yashigani-OPA-Reason": "model_not_allocated"},
            )

    if _state.optimization_engine and _state.sensitivity_classifier and _state.complexity_scorer and not is_agent_call:
        # LAURA-B1-OBS-1: if the engine's global local default would be DENIED to
        # this caller (restricted/gated), resolve a LOCAL model the caller IS
        # allocated and hand it to the optimiser as the local-fallback substitute.
        # None ⇒ caller is entitled to the global default (legacy behaviour); None
        # ALSO when no allowed local model exists ⇒ the optimiser keeps the (denied)
        # global default so the alloc-bind re-check below DENIES the truly-
        # unallocated request (deny-by-default preserved, no over-grant).
        _allowed_local_default = None
        if _effective is not None:
            try:
                _allowed_local_default = _effective.pick_allowed_local_default(
                    _state.model_alias_store,
                    _state.optimization_engine._default_model,
                )
            except Exception as exc:  # noqa: BLE001 — never fail-open the route
                logger.warning(
                    "B1-OBS-1 allowed-local-default resolution failed (%s) — "
                    "using global default", exc,
                )
                _allowed_local_default = None
        decision = _state.optimization_engine.route(
            requested_model=selected_model,
            sensitivity=s_result,
            complexity=c_result,
            budget=budget_state,
            force_local=body.force_local or False,
            force_cloud=body.force_cloud or False,
            allowed_local_default=_allowed_local_default,
        )
        selected_provider = decision.provider
        selected_model = decision.model
        route_reason = f"{decision.rule}:{decision.reason}"
    else:
        # Fallback: simplified routing if OE not available
        selected_provider = "ollama"
        route_reason = "fallback_local"
        if sensitivity_level in ("CONFIDENTIAL", "RESTRICTED"):
            route_reason = "sensitivity_local"

    # ── 6a-perm. Cloud-model deny-by-default gate (Phase 6+7 / INV-1 + INV-2) ──
    #
    # Phase 6 — INV-1 (deny by default for blast-radius types):
    #   Cloud providers are deny-by-default.  A request routed to ANY cloud
    #   provider (openai / anthropic) MUST have an explicit org-level cloud_model
    #   grant for the resolved model.  No grant → 403, fail-closed.
    #
    # Phase 6 — INV-2 (OPA coupling):
    #   A cloud_model grant carries a mandatory opa_policy_ref.  At runtime, the
    #   referenced OPA data-protection policy is traversed.  If the policy is
    #   absent/unresolvable the cloud call is DENIED (never sent in the clear).
    #   INV-2 is enforced at write time (store.set_boolean_grant) AND here at
    #   runtime as a belt-and-braces guard.
    #
    # Phase 7 — strict dial (YASHIGANI_PERMISSION_STRICT=true, default OFF):
    #   When strict mode is on, LOCAL Ollama models also require an explicit
    #   cloud_model grant (deny-unless-permitted for ALL models).  Default OFF
    #   so out-of-the-box local-LLM usage works without any grant configuration.
    #
    # Exemptions — must NOT be gated:
    #   • Agent calls (is_agent_call=True) — use their own MCP/auth path.
    #   • Brain-reasoning leg (brain_reasoning_leg=True) — server-minted, UNFORGEABLE;
    #     internal cognition, never delivered to a user; holds no allocation.
    #
    # Anti-masquerade: classification is derived solely from selected_provider
    # (server-resolved, never from caller input) — _CLOUD_PROVIDER_CONFIG contains
    # only "openai"/"anthropic"; "ollama" and "agent" are always local.
    _perm_is_cloud = selected_provider in _CLOUD_PROVIDER_CONFIG
    _perm_needs_check = (
        not is_agent_call
        and not brain_reasoning_leg
        and _state.permission_store is not None
        and (_perm_is_cloud or _state.permission_strict)
    )

    if _perm_needs_check:
        from yashigani.permissions import resolve_boolean_grant as _resolve_grant
        from yashigani.permissions import ResourceType as _RT
        from yashigani.permissions import DEFAULT_ORG_ID as _PERM_ORG_ID

        _perm_org_id = _PERM_ORG_ID
        _perm_groups: list = identity.get("groups", []) if identity else []
        # User-level grants for narrowing — only for human/user principals.
        # Service/agent/gateway identities use org+group tiers only.
        _perm_kind = identity.get("kind", "") if identity else ""
        # 4.1 SEC-GAP-1: key on identity_id (idnt_{12hex}) not email.
        _perm_user_id: Optional[str] = (
            identity.get("identity_id")
            if _perm_kind in ("human", "user") else None
        ) if identity else None

        _perm_allowed = _resolve_grant(
            _RT.CLOUD_MODEL,
            selected_model,
            org_id=_perm_org_id,
            group_ids=_perm_groups,
            principal_scope="user" if _perm_user_id else None,
            principal_id=_perm_user_id,
            store=_state.permission_store,
        )
        if not _perm_allowed:
            _perm_deny_reason = "cloud_model_not_granted"
            logger.warning(
                "PERM DENIED (cloud-model gate INV-1): provider=%s model=%s "
                "identity=%s org=%s%s — no org grant",
                selected_provider, selected_model, identity_id, _perm_org_id,
                " [strict-dial: local model]" if not _perm_is_cloud else "",
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": _deny_message(_perm_deny_reason),
                        "type": "policy_denied",
                        "code": _perm_deny_reason,
                    }
                },
                headers={"X-Yashigani-Permission-Reason": _perm_deny_reason},
            )

        # INV-2 coupling: cloud models only.  Local models in strict mode do NOT
        # require an OPA data-protection policy (no egress risk).
        if _perm_is_cloud:
            # Read the org-level grant to retrieve the mandatory opa_policy_ref.
            _org_grant = _state.permission_store.get_boolean_grant(
                _RT.CLOUD_MODEL, "org", _perm_org_id, selected_model
            )
            _opa_ref = (_org_grant.opa_policy_ref or "").strip() if _org_grant else ""

            if not _opa_ref:
                # Belt-and-braces: INV-2 should have been enforced at write time,
                # but defend here too (fail-closed).
                logger.error(
                    "PERM DENIED (INV-2 runtime): cloud_model grant for model=%s "
                    "(org=%s) missing opa_policy_ref — fail-closed",
                    selected_model, _perm_org_id,
                )
                _perm_deny_reason = "cloud_model_no_opa_policy_ref"
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": {
                            "message": _deny_message(_perm_deny_reason),
                            "type": "policy_denied",
                            "code": _perm_deny_reason,
                        }
                    },
                    headers={"X-Yashigani-Permission-Reason": _perm_deny_reason},
                )

            # Traverse the OPA data-protection policy (INV-2 runtime gate).
            _opa_dp_result = await _opa_cloud_model_policy_check(
                _opa_ref,
                identity=identity,
                model=selected_model,
                provider=selected_provider,
                sensitivity_level=sensitivity_level,
            )
            if not _opa_dp_result.get("allow", False):
                _perm_deny_reason = "cloud_model_opa_coupling_failed"
                logger.warning(
                    "PERM DENIED (INV-2 OPA coupling): provider=%s model=%s "
                    "policy_ref=%s identity=%s reason=%s — cloud call blocked",
                    selected_provider, selected_model, _opa_ref, identity_id,
                    _opa_dp_result.get("reason", "unknown"),
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": {
                            "message": _deny_message(_perm_deny_reason),
                            "type": "policy_denied",
                            "code": _perm_deny_reason,
                        }
                    },
                    headers={"X-Yashigani-Permission-Reason": _perm_deny_reason},
                )

    # ── LAURA-411-001: explicit DENY on requested model — routing-independent ──────
    # The gate above (6a-perm) only fires when selected_provider is a configured cloud
    # provider (openai/anthropic) or permission_strict is on.  When no cloud key is
    # configured, selected_provider becomes "ollama" → _perm_is_cloud=False →
    # _perm_needs_check=False → an explicit user/group DENY grant on the originally-
    # requested model name (e.g. perm:grant:cloud_model:user:{uid}:openai:gpt-4o =
    # {allow:false}) is silently skipped and the request is served via Ollama.
    #
    # This gate checks ONLY the user/group tiers for an explicit allow=False on
    # body.model.  It deliberately does NOT consult the org-level ceiling: a missing
    # org grant for a cloud model on a local-only stack is expected and MUST NOT block
    # local fallback (that would break every non-cloud Ollama deployment).  Only an
    # explicit per-user or per-group DENY triggers this path.
    #
    # MUST NOT fire when: agent call, brain-reasoning leg, perm_needs_check already ran
    # (cloud or strict path already handled it), no permission_store, or body.model empty.
    if (
        body.model
        and not is_agent_call
        and not brain_reasoning_leg
        and not _perm_needs_check          # cloud gate already ran — don't double-check
        and _state.permission_store is not None
    ):
        from yashigani.permissions import ResourceType as _RT_411
        _411_kind = identity.get("kind", "") if identity else ""
        _411_uid: Optional[str] = (
            identity.get("identity_id")
            if _411_kind in ("human", "user") else None
        ) if identity else None
        _411_groups: list = identity.get("groups", []) if identity else []
        _411_explicit_deny = False
        # BUG-A FIX (4.1.2): normalize body.model before deny-grant lookup so
        # that "openai/gpt-4o", "OPENAI/GPT-4O", and "openai:gpt-4o" all
        # resolve to the canonical key used when the grant was stored.
        # normalize_model_for_deny already imported inline at ~1634 for routing;
        # import again locally to keep the fix self-contained.
        from yashigani.models.effective import normalize_model_for_deny as _norm_deny_fn
        _411_model_key = _norm_deny_fn(body.model) or body.model
        try:
            if _411_uid:
                _411_ug = _state.permission_store.get_boolean_grant(
                    _RT_411.CLOUD_MODEL, "user", _411_uid, _411_model_key
                )
                if _411_ug is not None and not _411_ug.allow:
                    _411_explicit_deny = True
            if not _411_explicit_deny:
                for _411_gid in _411_groups:
                    _411_gg = _state.permission_store.get_boolean_grant(
                        _RT_411.CLOUD_MODEL, "group", _411_gid, _411_model_key
                    )
                    if _411_gg is not None and not _411_gg.allow:
                        _411_explicit_deny = True
                        break
            # W3-007 (LAURA-411-001 extension): also probe the RESOLVED cloud target.
            # If body.model is an alias pointing to a cloud model, a DENY grant on the
            # resolved canonical (e.g. deny on anthropic:claude-sonnet-4-6) must block
            # the alias too — deny follows the resolved target, not just the alias name.
            # Without this, a caller denied the resolved cloud model could still use its
            # alias to route through (the alias name has no matching deny grant).
            if not _411_explicit_deny and _w3007_resolved_cloud_target:
                _w3007_deny_key = _w3007_resolved_cloud_target
                if _411_uid:
                    _w3007_ug = _state.permission_store.get_boolean_grant(
                        _RT_411.CLOUD_MODEL, "user", _411_uid, _w3007_deny_key
                    )
                    if _w3007_ug is not None and not _w3007_ug.allow:
                        _411_explicit_deny = True
                if not _411_explicit_deny:
                    for _w3007_gid in _411_groups:
                        _w3007_gg = _state.permission_store.get_boolean_grant(
                            _RT_411.CLOUD_MODEL, "group", _w3007_gid, _w3007_deny_key
                        )
                        if _w3007_gg is not None and not _w3007_gg.allow:
                            _411_explicit_deny = True
                            break
        except Exception as _411_exc:
            logger.error(
                "PERM (LAURA-411-001) requested-model DENY probe failed: %s — "
                "fail-closed (denying request)", _411_exc,
            )
            _411_explicit_deny = True  # fail-closed per SOP 1

        if _411_explicit_deny:
            _411_deny_reason = "cloud_model_not_granted"
            logger.warning(
                "PERM DENIED (LAURA-411-001): provider=%s routed-model=%s "
                "requested=%s identity=%s — explicit DENY on requested model "
                "blocks Ollama fallback",
                selected_provider, selected_model, body.model, identity_id,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": _deny_message(_411_deny_reason),
                        "type": "policy_denied",
                        "code": _411_deny_reason,
                    }
                },
                headers={"X-Yashigani-Permission-Reason": _411_deny_reason},
            )

    # ── Track B1: BIND the FINALLY-SELECTED model to the allocation ──────
    # Runs on the model that will ACTUALLY be served (after optimisation OR the
    # fallback path), so the optimiser cannot escape the allocation by
    # re-selecting a model the caller is not allocated. Denies when the model is
    # outside a restricted caller's allowlist OR is globally allocation-gated and
    # not allocated to this caller (so a user NOT in the allocated group is denied
    # a model allocated only to that group). Fail-closed, deny-by-default.
    #
    # MUST-FIX-1 (Iris BLOCKER — B1 breaks orchestration): EXEMPT the server-
    # determined brain/internal cognition leg from this alloc-bind re-check.  The
    # letta brain's A→L reasoning hop arrives as a FRESH inbound request from
    # the `internal` service identity (groups[], no org, allowed_models[]) on the
    # brain model (LETTA_LLM_MODEL=qwen2.5:3b).  That model is allocation-gated the
    # instant any alias resolving to it is allocated to some group → `internal`
    # holds no allocation → is_model_denied() returns True → the brain's cognition
    # leg 403s → orchestration dies.  The exemption opens NO bypass for real users:
    # ``brain_reasoning_leg`` is SERVER-MINTED + UNFORGEABLE — it requires a
    # process-local brain round-trip to be OPEN *and* the internal-bearer identity
    # *and* the brain model (is_brain_reasoning_leg, line 1104) — letta cannot read,
    # set, or forge the round-trip counter.
    #
    # SECURITY — LAURA-B1R-001 (model-hop bypass, v2.25.4): the exemption is the
    # SERVER-MINTED brain-reasoning leg ONLY.  It MUST NOT include the
    # ``_orchestration_self_call`` identity flag: a principal-bearing orchestration
    # self-call (a model/agent TOOL HOP) resolves to the REAL caller's identity
    # WITH their real allocations, so the real caller's allocation MUST be enforced
    # on the hop.  Exempting on ``_orchestration_self_call`` let a model tool-hop
    # reach a non-allocated model (fastuser → model__qwen2_5_3b → served).  We now
    # gate the hop too: only the genuine internal-identity brain leg (which carries
    # NO principal) is exempt; the model hop re-enters here and is DENIED if the
    # real caller is not allocated the concrete model.  The raw client header
    # X-Yashigani-Orchestration-Depth (is_orchestration_self_call) is NEVER
    # consulted — it is forgeable.  Real external/user traffic carries no
    # server-minted marker, so this re-check runs BYTE-FOR-BYTE unchanged for them.
    _model_rbac_exempt = brain_reasoning_leg
    if (
        _effective is not None
        and not _model_rbac_exempt
        and _effective.is_model_denied(selected_model)
    ):
        logger.warning(
            "MODEL-RBAC DENIED (alloc-bind): identity=%s requested=%s served=%s "
            "NOT permitted (allowed=%s gated=%s restricted=%s) — denying",
            identity_id, body.model, selected_model,
            sorted(_effective.allowed), sorted(_effective.gated), _effective.has_restriction,
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    # R2: human-readable message so OWUI displays it in chat.
                    "message": _deny_message("model_not_allocated"),
                    "type": "policy_denied",
                    "code": "model_not_allocated",
                }
            },
            headers={"X-Yashigani-OPA-Reason": "model_not_allocated"},
        )

    # ── 6a. OPA policy check (v2.2 — all /v1 traffic) ─────────────────
    # Evaluates v1_routing.rego: identity active, model allowed, routing
    # safety (CONFIDENTIAL never to untrusted cloud), sensitivity ceiling.
    # Fail-closed: any OPA error → deny. Track B1: feed the effective
    # allowed-models so OPA's model_allowed denies non-allocated models too.
    opa_decision = await _opa_v1_check(
        identity=identity,
        selected_model=selected_model,
        selected_provider=selected_provider if not is_agent_call else "agent",
        sensitivity_level=sensitivity_level,
        route_reason=route_reason,
        request_path="/v1/chat/completions",
        effective_allowed_models=_eff_opa_list,
    )
    if not opa_decision.get("allow", False):
        opa_reason = opa_decision.get("reason", "policy_denied")
        logger.warning(
            "OPA DENIED /v1 request: identity=%s model=%s reason=%s",
            identity_id, selected_model, opa_reason,
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    # R2: human-readable message so OWUI displays it in chat.
                    "message": _deny_message(opa_reason),
                    "type": "policy_denied",
                    "code": opa_reason,
                }
            },
            headers={"X-Yashigani-OPA-Reason": opa_reason},
        )

    # ── 6a-model. OPA model_allowed backstop (belt-and-braces, v2.25.4) ──
    # The gate above checks only opa_decision["allow"] (allow_v1 = identity
    # active).  It does NOT consult opa_decision["model_allowed"], so before
    # this the alloc-bind re-check above was the SOLE model-RBAC enforcement
    # point at /v1 — a single point that the Laura+Iris bypass disabled by
    # forging the orchestration-depth header.  We now ALSO enforce OPA's
    # independent positive-allowlist verdict here, making effective.py's
    # docstring ("OPA enforces the positive allowlist") actually true and
    # giving a SECOND enforcement layer behind the alloc-bind.
    #
    # The OPA input already carries the effective allowed_models (B1,
    # effective_allowed_models=_eff_opa_list above), so model_allowed is the
    # true positive-allowlist decision for this caller.
    #
    # Same exemption as the alloc-bind: the SERVER-MINTED brain-reasoning leg
    # ONLY (internal holds no allocation → the brain model is gated for it).  A
    # principal-bearing model tool-hop is NOT exempt — the real caller's
    # allocation is enforced.  The forgeable depth header is NEVER consulted.
    if (
        not _model_rbac_exempt
        and not opa_decision.get("model_allowed", False)
    ):
        logger.warning(
            "OPA DENIED /v1 request (model_allowed backstop): identity=%s "
            "model=%s served=%s — model not in positive allowlist",
            identity_id, body.model, selected_model,
        )
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    # R2: human-readable message so OWUI displays it in chat.
                    "message": _deny_message("model_not_allocated"),
                    "type": "policy_denied",
                    "code": "model_not_allocated",
                }
            },
            headers={"X-Yashigani-OPA-Reason": "model_not_allocated"},
        )

    # ── 6a-bind. Client-policy enforcement — INGRESS (#16, OPA Phase 2) ──
    # Runs STRICTLY AFTER the core _opa_v1_check gate above so it can only ADD
    # denials, never remove one. Fail-closed (evaluate_client_policies denies on
    # any OPA error/undefined). No-op for callers with no bound policies.
    _ce_scope_kind = scope_kind_for(identity.get("kind") if identity else None)
    _ce_in = await evaluate_client_policies(
        _state, _ce_scope_kind, identity_id, "ingress",
        _client_enforce_input(identity, "/v1/chat/completions", route_reason=route_reason,
                              provider=selected_provider, model=selected_model),
    )
    if not _ce_in.get("allow", False):
        _ce_reason = (",".join(_ce_in.get("deny", []) or ["client_policy_denied"])).encode("ascii", "replace").decode("ascii")
        logger.warning("CLIENT-POLICY DENIED /v1 ingress: identity=%s scope=%s:%s deny=%s",
                       identity_id, _ce_scope_kind, identity_id, _ce_reason)
        _audit_client_policy("ingress", identity_id, _ce_scope_kind, identity_id, _ce_in)
        return JSONResponse(
            status_code=403,
            # R2: human-readable message so OWUI displays it in chat.
            # _ce_reason is a comma-joined set of machine deny codes; it is kept
            # in `code` for operator tooling but never shown to the end user.
            content={"error": {"message": _deny_message("client_policy_denied"),
                               "type": "client_policy_denied", "code": _ce_reason}},
            headers={"X-Yashigani-Client-Policy-Reason": _ce_reason},
        )

    # ── 6b. PII detection on request ──────────────────────────────────
    #
    # Runs AFTER routing so we know the destination (local vs cloud).
    # Local (Ollama) traffic: LOG only regardless of configured mode — data
    # stays on-premises so blocking is unnecessary and would degrade UX.
    # Cloud traffic: respect configured mode (LOG / REDACT / BLOCK).
    # Cloud bypass flag allows admins to skip PII filtering for cloud-routed
    # requests (explicit opt-in; default OFF).
    pii_detected_on_request = False
    destination = "local" if selected_provider == "ollama" else "cloud"

    if _state.pii_detector is not None and prompt_text:
        _run_pii = True
        if destination == "cloud" and _state.pii_cloud_bypass:
            _run_pii = False
            logger.debug(
                "PII filtering skipped for cloud-routed request (bypass enabled) request_id=%s",
                request_id,
            )

        if _run_pii:
            # F-RT1: decode-before-classify.  process_decoded() scans the raw
            # prompt AND every decoded view (base64/hex/url/rot13, bounded
            # nested), so an encoded SSN/credit-card is caught where the old
            # raw-only process() let it through silently.
            if destination == "local":
                # Local: detect only — never block, never redact (data is on-premises)
                _text, _pii_result = _state.pii_detector.process_decoded(prompt_text)
                # F-RT1 silent-pass guard: audit an undecodable encoded blob even
                # with no plaintext PII match.
                _encoded_payload_audit(request_id, "request", destination, _pii_result)
                if _pii_result.detected:
                    pii_detected_on_request = True
                    logger.info(
                        "PII detected on local request request_id=%s types=%s views=%s — log only (local)",
                        request_id,
                        [f.pii_type.value for f in _pii_result.findings],
                        sorted(_pii_result.matched_views),
                    )
                    _pii_audit(request_id, "request", _pii_result, "logged", destination)
            else:
                # Cloud: apply configured mode
                _text, _pii_result = _state.pii_detector.process_decoded(prompt_text)
                _encoded_payload_audit(request_id, "request", destination, _pii_result)
                if _pii_result.detected:
                    pii_detected_on_request = True
                    logger.info(
                        "PII detected on cloud request request_id=%s types=%s views=%s action=%s",
                        request_id,
                        [f.pii_type.value for f in _pii_result.findings],
                        sorted(_pii_result.matched_views),
                        _pii_result.action_taken,
                    )
                    _pii_audit(request_id, "request", _pii_result, _pii_result.action_taken, destination)

                    if _pii_result.action_taken == "blocked":
                        # R2: return OpenAI error schema so OWUI displays the
                        # human-readable message in chat (not FastAPI's {"detail":…}).
                        return JSONResponse(
                            status_code=status.HTTP_403_FORBIDDEN,
                            content={
                                "error": {
                                    "message": _deny_message("pii_detected"),
                                    "type": "pii_blocked",
                                    "code": "pii_detected",
                                    # Operator/diagnostic fields — not shown in OWUI chat.
                                    "pii_types": [f.pii_type.value for f in _pii_result.findings],
                                    "matched_views": sorted(_pii_result.matched_views),
                                    "request_id": request_id,
                                }
                            },
                            headers={"X-Yashigani-Request-Id": request_id},
                        )

                    if _pii_result.action_taken == "redacted":
                        # Redact each message individually so per-message offsets remain
                        # valid, then update prompt_text for downstream logging.
                        # F-RT1: use process_decoded per message.  An encoded-only hit
                        # cannot be redacted in place — process_decoded escalates such a
                        # message's action_taken to "blocked"; refuse the request rather
                        # than forward an un-redactable encoded secret.
                        for _msg in body.messages:
                            if _msg.content:
                                _msg_redacted, _msg_res = _state.pii_detector.process_decoded(_msg.content)
                                if _msg_res.action_taken == "blocked":
                                    # R2: return OpenAI error schema so OWUI displays
                                    # the human-readable message in chat.
                                    return JSONResponse(
                                        status_code=status.HTTP_403_FORBIDDEN,
                                        content={
                                            "error": {
                                                "message": _deny_message("pii_detected_encoded"),
                                                "type": "pii_blocked",
                                                "code": "pii_detected_encoded",
                                                "matched_views": sorted(_msg_res.matched_views),
                                                "request_id": request_id,
                                            }
                                        },
                                        headers={"X-Yashigani-Request-Id": request_id},
                                    )
                                _msg.content = _msg_redacted
                        prompt_text = "\n".join(
                            m.content for m in body.messages if m.content
                        )

    # ── 7. Forward to backend ─────────────────────────────────────────
    #
    # Streaming path: body.stream == True AND streaming enabled AND not an
    # agent call (agents may not support SSE and always use the buffered path).
    #
    # Budget headers (X-Yashigani-Budget-*) cannot be sent on streaming
    # responses — headers are committed before the body begins and token
    # counts are only available from the final upstream chunk. Budget
    # accounting is still recorded after stream end via the usage_callback.
    use_streaming = (
        body.stream
        and _state.streaming_enabled
        and not is_agent_call
    )

    # OPA enforcement: stream=false when OPA policies are active.
    # All response content must be inspected before delivery to the user
    # (human or non-human). Streaming bypasses response-path OPA checks.
    if use_streaming and _state.opa_url:
        use_streaming = False
        logger.info("Streaming disabled: OPA policies active — response inspection required")

    # PII block/redact modes require full response inspection — force buffered
    if use_streaming and _state.pii_detector is not None:
        from yashigani.pii.detector import PiiMode
        if _state.pii_detector.mode in (PiiMode.BLOCK, PiiMode.REDACT):
            use_streaming = False
            logger.info("Streaming disabled: PII mode=%s requires buffered response inspection", _state.pii_detector.mode.value)

    # YSG-RISK-129: assistant_content/backend_body are only ever assigned
    # inside individual success-path branches of the try block below (agent
    # letta/langflow/openai-compat, cloud openai/anthropic, local ollama).
    # Every branch either assigns them, returns a JSONResponse directly, or
    # raises (propagating out of this function immediately via the except
    # clauses below). Initializing them to None here — rather than leaving
    # them undefined — turns "some future/edge branch falls through without
    # assigning or returning/raising" from an UnboundLocalError crash into a
    # detectable, fail-closed state that the guard right after the try/except
    # converts into a clean 502.
    assistant_content: str | None = None
    backend_body: dict | None = None

    try:
        import httpx

        if use_streaming:
            # ── 7a. Streaming path ─────────────────────────────────────
            from yashigani.gateway.streaming import StreamingInspector, stream_response

            ollama_body = {
                "model": selected_model,
                "messages": [{"role": m.role, "content": m.content or ""} for m in body.messages],
                "stream": True,
            }
            if body.temperature is not None:
                ollama_body["temperature"] = body.temperature

            # Resolve session/agent IDs for the inspector's audit events
            stream_session_id = (
                identity.get("identity_id", request_id) if identity else request_id
            )
            stream_agent_id = (
                identity.get("slug", "openai-router") if identity else "openai-router"
            )

            inspector = StreamingInspector(
                sensitivity_classifier=_state.sensitivity_classifier,
                inspect_interval=_state.streaming_inspect_interval,
                request_id=request_id,
                session_id=stream_session_id,
                agent_id=stream_agent_id,
                on_audit=_make_streaming_audit_adapter(_state.audit_writer),
            )

            # Token accounting — called once after stream end
            _stream_prompt_tokens = [0]
            _stream_completion_tokens = [0]

            def _usage_callback(pt: int, ct: int) -> None:
                _stream_prompt_tokens[0] = pt
                _stream_completion_tokens[0] = ct
                _total = pt + ct
                if _state.budget_enforcer and selected_provider != "ollama" and identity:
                    try:
                        # YSG-RISK-144: pass group_ids/org_id so the group and
                        # org counters actually accumulate usage — previously
                        # omitted, meaning check_hierarchy's group/org lookups
                        # would always read 0 usage regardless of configured caps.
                        _state.budget_enforcer.record(
                            identity_id=identity_id,
                            provider=selected_provider,
                            tokens=_total,
                            group_ids=identity.get("groups") or [],
                            org_id=identity.get("org_id", "") or "",
                        )
                    except Exception as _exc:
                        logger.warning("Streaming budget recording failed: %s", _exc)

            # Open a persistent streaming connection to Ollama.  The client must
            # stay alive for the duration of the generator, so we wrap the
            # response in a local async generator that owns the client lifetime.
            async def _sse_generator():
                # F-001 (chat-stream seam): bare httpx.AsyncClient has no SSL
                # context → CERTIFICATE_VERIFY_FAILED when ollama_url is
                # https://caddy:11435/ollama (Mac Metal / mTLS-Ollama front).
                # Route through ollama_async_client (same fix as model-list).
                from yashigani.inspection._ollama_transport import (  # noqa: PLC0415
                    ollama_async_client as _ollama_ac_sse,
                )
                async with _ollama_ac_sse(_state.ollama_url, timeout=120.0) as _client:
                    try:
                        async with _client.stream(
                            "POST",
                            f"{_state.ollama_url}/api/chat",
                            json=ollama_body,
                        ) as _upstream:
                            if _upstream.status_code != 200:
                                err_text = await _upstream.aread()
                                logger.error(
                                    "Streaming upstream error %d request_id=%s: %s",
                                    _upstream.status_code, request_id,
                                    err_text[:200],
                                )
                                # Emit a JSON error chunk so the client gets something
                                import json as _json
                                yield (
                                    f"data: {_json.dumps({'error': 'upstream_error', 'request_id': request_id})}\n\n"
                                )
                                yield "data: [DONE]\n\n"
                                return

                            async for chunk in stream_response(
                                _upstream,
                                inspector,
                                request_id,
                                selected_model,
                                usage_callback=_usage_callback,
                            ):
                                yield chunk
                    except httpx.ConnectError:
                        logger.error(
                            "Streaming connect error request_id=%s", request_id
                        )
                        yield (
                            "data: "
                            '{"error":"upstream_unavailable",'
                            f'"request_id":"{request_id}"}}\n\n'
                        )
                        yield "data: [DONE]\n\n"

            # LAURA-411-004: routing-telemetry headers gated behind flag.
            # Always present: Request-Id, Model, Generated-Content, PII, Confidence.
            # Debug-only (YASHIGANI_ROUTING_TELEMETRY=true): Route-Reason, Routed-Via,
            # Sensitivity, Complexity.
            _stream_headers: dict[str, str] = {
                "X-Yashigani-Request-Id": request_id,
                "X-Yashigani-Model": selected_model,
                # Budget headers intentionally omitted — see module docstring.
                # PII header reflects request-path scan only (response is streamed).
                "X-Yashigani-PII-Detected": "true" if pii_detected_on_request else "false",
                # F-T10-001: generated-content disclaimer always present.
                # Confidence defaults to 1.0 on streaming (response body not
                # yet available when headers are committed); StreamingInspector
                # flags anomalies in-band via SSE event field, not via header.
                "X-Yashigani-Generated-Content": "true",
                "X-Yashigani-Response-Inspection-Confidence": "1.0000",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",  # disable Nginx/Caddy buffering
            }
            if _routing_telemetry_enabled():
                _stream_headers["X-Yashigani-Routed-Via"] = selected_provider
                _stream_headers["X-Yashigani-Route-Reason"] = (
                    route_reason.encode("ascii", "replace").decode("ascii")
                )
                _stream_headers["X-Yashigani-Sensitivity"] = sensitivity_level
                _stream_headers["X-Yashigani-Complexity"] = complexity_level
            return StreamingResponse(
                _sse_generator(),
                media_type="text/event-stream",
                headers=_stream_headers,
            )

        # ── 7b. Buffered path (agent calls + stream=False + streaming disabled) ──
        if is_agent_call and agent_upstream:
            agent_messages = [{"role": m.role, "content": m.content or ""} for m in body.messages]

            if agent_protocol == "letta":
                from yashigani.gateway.letta_client import letta_chat
                try:
                    agent_resp = await letta_chat(
                        base_url=agent_upstream,
                        messages=agent_messages,
                        timeout=120.0,
                    )
                    choices = agent_resp.get("choices", [])
                    assistant_content = choices[0].get("message", {}).get("content", "") if choices else ""
                    backend_body = agent_resp
                    route_reason = f"agent:{selected_model[1:]}:letta"
                except Exception as exc:
                    # V232-CSCAN-01e: log full exception server-side; safe message to caller.
                    logger.exception("Letta agent %s failed", selected_model)
                    return JSONResponse(
                        status_code=502,
                        content={
                            "error": {
                                "message": f"Agent {selected_model} (Letta) unreachable",
                                "type": "agent_error",
                                "agent": selected_model,
                                "code": "agent_unreachable",
                            }
                        },
                        headers={"X-Yashigani-Agent-Error": "true"},
                    )
            elif agent_protocol == "langflow":
                from yashigani.gateway.langflow_client import langflow_chat
                try:
                    agent_resp = await langflow_chat(
                        base_url=agent_upstream,
                        messages=agent_messages,
                        timeout=120.0,
                    )
                    choices = agent_resp.get("choices", [])
                    assistant_content = choices[0].get("message", {}).get("content", "") if choices else ""
                    backend_body = agent_resp
                    route_reason = f"agent:{selected_model[1:]}:langflow"
                except Exception as exc:
                    # V232-CSCAN-01e: log full exception server-side; safe message to caller.
                    logger.exception("Langflow agent %s failed", selected_model)
                    return JSONResponse(
                        status_code=502,
                        content={
                            "error": {
                                "message": f"Agent {selected_model} (Langflow) unreachable",
                                "type": "agent_error",
                                "agent": selected_model,
                                "code": "agent_unreachable",
                            }
                        },
                        headers={"X-Yashigani-Agent-Error": "true"},
                    )
            else:
                # OpenAI-compatible /v1/chat/completions
                # Use the agent's own model name (e.g., "openclaw" for OpenClaw)
                agent_name_lower = selected_model[1:].lower()
                agent_model = agent_name_lower if agent_name_lower in ("openclaw",) else _state.default_model
                agent_body = {
                    "model": agent_model,
                    "messages": agent_messages,
                    "stream": False,
                }
                if body.temperature is not None:
                    agent_body["temperature"] = body.temperature

                # Read agent auth token from env var or secrets file
                import os
                agent_headers: dict[str, str] = {"Content-Type": "application/json"}
                # Check env var first (e.g., OPENCLAW_GATEWAY_TOKEN), then secrets file
                env_token = os.getenv(f"{agent_name_lower.upper()}_GATEWAY_TOKEN", "")
                if not env_token:
                    # V232-CSCAN-01a: resolve-and-confine before touching the filesystem.
                    # agent_name_lower comes from the registry (admin-registered) and is
                    # constrained by AgentRegisterRequest.name pattern='^[a-z][a-z0-9_-]{0,63}$',
                    # but we guard here too as defence-in-depth against pre-existing registry
                    # entries that predate the pattern constraint (CWE-22).
                    # YSG-RISK-160: secrets root now honours YASHIGANI_SECRETS_DIR
                    # (see _agent_token_secrets_root() docstring).
                    _secrets_root = _agent_token_secrets_root()
                    _token_path = (_secrets_root / f"{agent_name_lower}_token").resolve()
                    if not _token_path.is_relative_to(_secrets_root):
                        logger.warning(
                            "V232-CSCAN-01a: agent %r produced an out-of-bounds token path %r — skipping",
                            agent_name_lower, str(_token_path),
                        )
                    elif _token_path.exists():
                        env_token = _token_path.read_text().strip()
                if env_token:
                    agent_headers["Authorization"] = f"Bearer {env_token}"

                # YSG-RISK-139: registered upstreams under the v4.1 unified-sidecar
                # dispatch repoint (§2.5) are the agent's Caddy INGRESS front —
                # https://caddy:<mesh_port>/agents/<tenant>/<system> on compose,
                # https://yashigani-caddy-mesh:<mesh_port>/agents/<tenant>/<system>
                # on k8s (install.sh register_agent_bundles / k8s_register_agent_bundles).
                # That front terminates mTLS require_and_verify with a leaf signed by
                # the INTERNAL CA — a bare httpx.AsyncClient only trusts the public/
                # certifi CA bundle and fails the handshake with
                # CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate
                # (openclaw's only path in this generic branch; letta/langflow have
                # their own dedicated clients above which already use
                # agent_dispatch_client()). Detect a mesh ingress front by the
                # portable /agents/<tenant>/<system> path signature (hostname differs
                # between compose and k8s; the path does not) and present the
                # internal-PKI mesh leaf via the SAME single-source client the
                # letta/langflow branches use. Genuine externally-deployed
                # OpenAI-compatible agents (AgentRegisterRequest.upstream_url, no
                # /agents/ path) are unaffected and keep the public-CA-trusting
                # bare client.
                from urllib.parse import urlparse as _urlparse
                _is_mesh_agent_front = _urlparse(agent_upstream).path.startswith("/agents/")
                if _is_mesh_agent_front:
                    from yashigani.gateway._dispatch_client import agent_dispatch_client
                    _agent_http_client_cm = agent_dispatch_client(timeout=120.0)
                else:
                    _agent_http_client_cm = httpx.AsyncClient(timeout=120.0)

                try:
                    async with _agent_http_client_cm as client:
                        resp = await client.post(
                            f"{agent_upstream}/v1/chat/completions",
                            json=agent_body,
                            headers=agent_headers,
                        )
                except Exception as exc:
                    # V232-CSCAN-01e: log full exception server-side; safe message to caller.
                    logger.exception("Agent %s unreachable", selected_model)
                    return JSONResponse(
                        status_code=502,
                        content={
                            "error": {
                                "message": f"Agent {selected_model} unreachable",
                                "type": "agent_error",
                                "agent": selected_model,
                                "code": "agent_unreachable",
                            }
                        },
                        headers={"X-Yashigani-Agent-Error": "true"},
                    )

                if resp.status_code != 200:
                    logger.error("Agent %s returned HTTP %d: %s", selected_model, resp.status_code, resp.text[:200])
                    return JSONResponse(
                        status_code=502,
                        content={
                            "error": {
                                "message": f"Agent {selected_model} returned HTTP {resp.status_code}",
                                "type": "agent_error",
                                "agent": selected_model,
                                "code": "agent_upstream_error",
                                "upstream_status": resp.status_code,
                            }
                        },
                        headers={"X-Yashigani-Agent-Error": "true"},
                    )
                else:
                    agent_resp = resp.json()
                    choices = agent_resp.get("choices", [])
                    assistant_content = choices[0].get("message", {}).get("content", "") if choices else ""
                    backend_body = agent_resp
                    route_reason = f"agent:{selected_model[1:]}"

        if not is_agent_call:
            if selected_provider in _CLOUD_PROVIDER_CONFIG:
                # ── 7b-cloud. Cloud provider call (OpenAI / Anthropic) ────────
                # Resolve API key from KMS (TTL-cached, per-request) then env-var.
                # Never log the key value.
                cloud_api_key = _get_cloud_api_key(selected_provider)
                if not cloud_api_key:
                    logger.error(
                        "Cloud provider %r selected but no API key available "
                        "(KMS miss and env-var absent) request_id=%s",
                        selected_provider, request_id,
                    )
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail=(
                            f"Cloud provider '{selected_provider}' is not configured. "
                            "Set the API key via the admin UI (Cloud Provider API Keys) "
                            f"or the {_CLOUD_PROVIDER_CONFIG[selected_provider]['env_var']} "
                            "environment variable."
                        ),
                    )

                cloud_cfg = _CLOUD_PROVIDER_CONFIG[selected_provider]
                messages_payload = [
                    {"role": m.role, "content": m.content or ""}
                    for m in body.messages
                ]

                if selected_provider == "openai":
                    # OpenAI-compatible /v1/chat/completions
                    cloud_body: dict = {
                        "model": selected_model,
                        "messages": messages_payload,
                        "stream": False,
                    }
                    if body.temperature is not None:
                        cloud_body["temperature"] = body.temperature
                    if body.max_tokens is not None:
                        cloud_body["max_tokens"] = body.max_tokens

                    cloud_headers = {
                        "Authorization": f"Bearer {cloud_api_key}",
                        "Content-Type": "application/json",
                    }

                    async with httpx.AsyncClient(timeout=120.0) as client:
                        resp = await client.post(
                            f"{cloud_cfg['base_url']}/v1/chat/completions",
                            json=cloud_body,
                            headers=cloud_headers,
                        )

                    if resp.status_code != 200:
                        logger.error(
                            "OpenAI upstream error %d request_id=%s",
                            resp.status_code, request_id,
                        )
                        raise HTTPException(
                            status_code=status.HTTP_502_BAD_GATEWAY,
                            detail="Cloud provider error. Try again or contact your administrator.",
                        )

                    resp_json = resp.json()
                    choices = resp_json.get("choices", [])
                    assistant_content = (
                        choices[0].get("message", {}).get("content", "") if choices else ""
                    )
                    # Normalise to Ollama-compatible shape for downstream code.
                    backend_body = {
                        "model": selected_model,
                        "message": {"role": "assistant", "content": assistant_content},
                        "done": True,
                        "prompt_eval_count": resp_json.get("usage", {}).get("prompt_tokens", 0),
                        "eval_count": resp_json.get("usage", {}).get("completion_tokens", 0),
                    }

                elif selected_provider == "anthropic":
                    # Anthropic Messages API — different wire format.
                    # Extract system message (if any) and user/assistant turns.
                    system_text = ""
                    anthropic_messages = []
                    for m in body.messages:
                        if m.role == "system":
                            system_text = m.content or ""
                        else:
                            anthropic_messages.append(
                                {"role": m.role, "content": m.content or ""}
                            )

                    anthropic_body: dict = {
                        "model": selected_model,
                        "messages": anthropic_messages,
                        "max_tokens": body.max_tokens or 1024,
                    }
                    if system_text:
                        anthropic_body["system"] = system_text
                    if body.temperature is not None:
                        anthropic_body["temperature"] = body.temperature

                    cloud_headers = {
                        "x-api-key": cloud_api_key,
                        "anthropic-version": "2023-06-01",
                        "Content-Type": "application/json",
                    }

                    async with httpx.AsyncClient(timeout=120.0) as client:
                        resp = await client.post(
                            f"{cloud_cfg['base_url']}/v1/messages",
                            json=anthropic_body,
                            headers=cloud_headers,
                        )

                    if resp.status_code != 200:
                        logger.error(
                            "Anthropic upstream error %d request_id=%s",
                            resp.status_code, request_id,
                        )
                        raise HTTPException(
                            status_code=status.HTTP_502_BAD_GATEWAY,
                            detail="Cloud provider error. Try again or contact your administrator.",
                        )

                    resp_json = resp.json()
                    # Anthropic response: {"content": [{"type":"text","text":"..."}], ...}
                    content_blocks = resp_json.get("content", [])
                    assistant_content = " ".join(
                        b.get("text", "") for b in content_blocks if b.get("type") == "text"
                    )
                    usage = resp_json.get("usage", {})
                    # Normalise to Ollama-compatible shape for downstream code.
                    backend_body = {
                        "model": selected_model,
                        "message": {"role": "assistant", "content": assistant_content},
                        "done": True,
                        "prompt_eval_count": usage.get("input_tokens", 0),
                        "eval_count": usage.get("output_tokens", 0),
                    }

                else:
                    # Unreachable: _CLOUD_PROVIDER_CONFIG only contains "openai"/"anthropic".
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Unknown cloud provider: {selected_provider!r}",
                    )

            else:
                # ── 7b-local. Standard Ollama routing (buffered) ──────────────
                ollama_body = {
                    "model": selected_model,
                    "messages": [{"role": m.role, "content": m.content or ""} for m in body.messages],
                    "stream": False,
                }
                if body.temperature is not None:
                    ollama_body["temperature"] = body.temperature

                # F-001 (chat-nonstream seam): bare httpx.AsyncClient has no
                # SSL context → fails when ollama_url is https:// (Mac Metal /
                # mTLS-Ollama).  Route through ollama_async_client.
                from yashigani.inspection._ollama_transport import (  # noqa: PLC0415
                    ollama_async_client as _ollama_ac_chat,
                )
                async with _ollama_ac_chat(_state.ollama_url, timeout=120.0) as client:
                    resp = await client.post(
                        f"{_state.ollama_url}/api/chat",
                        json=ollama_body,
                    )

                if resp.status_code != 200:
                    raise HTTPException(
                        status_code=resp.status_code,
                        detail=f"Backend error: {resp.text[:200]}",
                    )

                backend_body = resp.json()
                assistant_content = backend_body.get("message", {}).get("content", "")

    except httpx.ConnectError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Local model unavailable. Ollama may be starting up.",
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Backend call failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Backend communication error",
        )

    # YSG-RISK-129: fail-closed backstop. The try block above either assigns
    # assistant_content/backend_body on a success path, returns a JSONResponse
    # directly, or raises HTTPException (which exits the function immediately
    # via the except clauses above and never reaches this line). Reaching here
    # with either variable still None means some branch fell through without
    # assigning, returning, or raising — treat that as a backend failure and
    # respond cleanly instead of crashing downstream with UnboundLocalError.
    if assistant_content is None or backend_body is None:
        logger.error(
            "chat_completions: no backend branch produced a response "
            "(request_id=%s, is_agent_call=%s, agent_upstream=%r, "
            "selected_provider=%s) — fail-closed 502",
            request_id, is_agent_call, agent_upstream, selected_provider,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Backend communication error",
        )

    # ── 7b. Response inspection ───────────────────────────────────────
    # Inspect assistant_content as plain text — we care about what the model
    # *said*, not the JSON envelope wrapping it. Using "text/plain" ensures
    # the exempt_content_types list cannot inadvertently skip this check.
    response_verdict = "clean"
    # F-T10-001: default to 1.0 (no inspection = clean pass, full confidence).
    # When inspection runs this is overwritten with the actual pipeline score.
    response_inspection_confidence: float = 1.0
    # v2.24.1 — GAP-3 / SEC-5: response-CONTENT sensitivity.
    # When pipeline is enabled and not skipped, this is set from the pipeline's
    # sensitivity classification of the response body.  When pipeline is off
    # (default, YSG-RISK-057) it stays None so _opa_response_check falls back
    # to prompt sensitivity (explicitly documented fallback per the updated
    # v1_routing.rego MAX(prompt_sensitivity, response_sensitivity) rule).
    response_content_sensitivity: Optional[str] = None
    if _state.response_inspection_pipeline is not None and assistant_content:
        try:
            # session_id and agent_id are best-effort from identity; fall back
            # to request_id so the audit event is always correlated.
            resp_session_id = identity.get("identity_id", request_id) if identity else request_id
            resp_agent_id = identity.get("slug", "openai-router") if identity else "openai-router"

            # YSG-RISK-113: .inspect() is a SYNCHRONOUS blocking classifier
            # call (Ollama et al.). Run off the event loop so a slow/dead
            # backend cannot starve /healthz and every other coroutine on
            # this worker (DoS class — see risk register).
            resp_result = await asyncio.to_thread(
                _state.response_inspection_pipeline.inspect,
                response_body=assistant_content,
                content_type="text/plain",
                request_id=request_id,
                session_id=resp_session_id,
                agent_id=resp_agent_id,
            )
            if not resp_result.skipped:
                response_verdict = resp_result.verdict.lower()
                # v2.24.1 — GAP-3: capture response-content sensitivity from pipeline
                response_content_sensitivity = resp_result.response_sensitivity
                # F-T10-001: capture inspection confidence for operator UI badge.
                # Clamp to [0.0, 1.0] with explicit isfinite guard.  Python's
                # min/max do not propagate NaN reliably (max(0.0, min(1.0, NaN))
                # returns 1.0, not 0.0), so we must check isfinite first.
                # A broken classifier returning NaN/Inf is treated as 0.0
                # (minimum confidence), ensuring step-up fires conservatively.
                _raw_conf = float(resp_result.confidence)
                response_inspection_confidence = max(0.0, min(1.0, _raw_conf)) if math.isfinite(_raw_conf) else 0.0

            if resp_result.verdict == "BLOCKED":
                logger.warning(
                    "Response inspection BLOCKED for request_id=%s confidence=%.2f",
                    request_id,
                    resp_result.confidence,
                )
                # Write audit event for the block
                if _state.audit_writer:
                    try:
                        _af = resp_result.audit_fields
                        _state.audit_writer.write(
                            ResponseInjectionDetectedEvent(
                                verdict=_af.get("verdict", ""),
                                request_id=_af.get("request_id", ""),
                                session_id=_af.get("session_id", ""),
                                agent_id=_af.get("agent_id", ""),
                                confidence_score=float(_af.get("confidence_score", 0.0)),
                                action_taken=_af.get("action_taken", ""),
                                content_type=_af.get("content_type", ""),
                                response_content_hash=_af.get("response_content_hash", ""),
                                classifier_only_mode=bool(_af.get("classifier_only_mode", False)),
                            )
                        )
                    except Exception as _exc:
                        logger.warning("Audit write failed for response block: %s", _exc)
                # Do NOT suppress the response — the content is already generated
                # and withholding it creates a confusing UX (empty assistant turn).
                # The BLOCKED verdict is surfaced via header so downstream
                # systems (e.g. Open WebUI plugins) can act on it.
        except Exception as exc:
            logger.warning("Response inspection raised unexpectedly: %s", exc)

    # ── 7b-ii. Always-on MCP/agent result injection pattern scan (I5 invariant) ──
    # INDEPENDENT of YASHIGANI_INSPECT_RESPONSES — MCP/agent results are UNTRUSTED.
    # The full ResponseInspectionPipeline is optional (performance toggle, YSG-RISK-057),
    # but injection pattern detection on untrusted agent results is MANDATORY.
    # Closes LAURA-30-002 / I5 invariant violation.
    if response_verdict == "clean" and assistant_content:
        try:
            from yashigani.mcp._content_filter import _COMPILED_PATTERN as _inj_pattern
            import unicodedata as _unicodedata
            _scan_text = _unicodedata.normalize("NFKC", assistant_content)
            if _inj_pattern.search(_scan_text):
                _inj_layman_msg = (
                    "Your request was blocked because the agent's response contained "
                    "content that attempted to override your AI assistant's instructions. "
                    "This is a security protection. Please contact your administrator if you "
                    "believe this is an error."
                )
                logger.warning(
                    "LAURA-30-002: agent result injection pattern detected request_id=%s "
                    "— BLOCKING delivery (always-on I5 gate)",
                    request_id,
                )
                if _state.audit_writer:
                    try:
                        _inj_hash = hashlib.sha256(
                            assistant_content.encode("utf-8", errors="replace")
                        ).hexdigest()
                        _state.audit_writer.write(
                            ResponseInjectionDetectedEvent(
                                verdict="BLOCKED",
                                request_id=request_id,
                                session_id=identity.get("identity_id", request_id) if identity else request_id,
                                agent_id=identity.get("slug", "agent-result") if identity else "agent-result",
                                confidence_score=0.95,
                                action_taken="blocked_injection_pattern",
                                content_type="text/plain",
                                response_content_hash=_inj_hash,
                                classifier_only_mode=True,
                            )
                        )
                    except Exception as _audit_exc:
                        logger.warning("Audit write failed for injection block: %s", _audit_exc)
                response_verdict = "blocked"
                response_inspection_confidence = 0.95
                assistant_content = _inj_layman_msg
        except Exception as _inj_exc:
            # Fail-closed: if the scan itself errors, block to avoid delivering
            # potentially unsafe content.
            logger.error(
                "LAURA-30-002: injection scan raised %s — fail-closed block", _inj_exc
            )
            response_verdict = "blocked"
            assistant_content = (
                "Your request was blocked due to a safety check error. "
                "Please contact your administrator."
            )

    # ── 7c. PII detection on response (buffered path only) ────────────
    #
    # Runs AFTER response inspection so any injection-flagged content is
    # already handled. Local vs cloud destination logic mirrors request path:
    # local traffic is LOG-only; cloud traffic respects configured mode.
    # BLOCK on response: we cannot suppress content already generated (same
    # reasoning as response_inspection BLOCKED above). We add a warning header
    # and audit the event, but the response is still delivered.
    pii_detected_on_response = False

    if _state.pii_detector is not None and assistant_content:
        _resp_run_pii = True
        if destination == "cloud" and _state.pii_cloud_bypass:
            _resp_run_pii = False

        if _resp_run_pii:
            # F-RT1: decode-before-classify on the response leg too, so an
            # encoded PII value echoed back by the model is caught.  This feeds
            # pii_detected_on_response, which feeds the response-leg OPA check
            # (sensitivity_exceeds_ceiling) — the leg that actually enforces on
            # LOCAL routing.
            if destination == "local":
                _resp_text, _resp_pii = _state.pii_detector.process_decoded(assistant_content)
                _encoded_payload_audit(request_id, "response", destination, _resp_pii)
                if _resp_pii.detected:
                    pii_detected_on_response = True
                    logger.info(
                        "PII detected in local response request_id=%s types=%s views=%s — log only (local)",
                        request_id,
                        [f.pii_type.value for f in _resp_pii.findings],
                        sorted(_resp_pii.matched_views),
                    )
                    _pii_audit(request_id, "response", _resp_pii, "logged", destination)
            else:
                _resp_text, _resp_pii = _state.pii_detector.process_decoded(assistant_content)
                _encoded_payload_audit(request_id, "response", destination, _resp_pii)
                if _resp_pii.detected:
                    pii_detected_on_response = True
                    logger.info(
                        "PII detected in cloud response request_id=%s types=%s views=%s action=%s",
                        request_id,
                        [f.pii_type.value for f in _resp_pii.findings],
                        sorted(_resp_pii.matched_views),
                        _resp_pii.action_taken,
                    )
                    _pii_audit(request_id, "response", _resp_pii, _resp_pii.action_taken, destination)

                    # process_decoded REDACT returns redacted raw text; encoded-only
                    # hits escalate action_taken to "blocked".  We cannot suppress a
                    # response that is already generated (same reasoning as the
                    # response-inspection BLOCKED branch), so on encoded-only hits we
                    # keep the content but rely on pii_detected_on_response → the
                    # response-leg OPA check to deny delivery.
                    if _resp_pii.action_taken == "redacted":
                        # Update assistant_content; step 9 will build the response
                        # with the redacted text automatically.
                        assistant_content = _resp_text
                    # BLOCK mode (or encoded-only escalation): log warning, add header,
                    # do not suppress response — OPA response-leg decides delivery.
                    elif _resp_pii.action_taken == "blocked":
                        logger.warning(
                            "PII detected in response (BLOCK/encoded mode) — adding warning "
                            "header, response not suppressed; OPA response-leg enforces. "
                            "request_id=%s views=%s",
                            request_id, sorted(_resp_pii.matched_views),
                        )

    # ── 8. Token counting + budget recording ─────────────────────────
    input_tokens = backend_body.get("prompt_eval_count", token_estimate)
    output_tokens = backend_body.get("eval_count", len(assistant_content) // 4)
    total_tokens = input_tokens + output_tokens

    # Record token usage in budget system
    if _state.budget_enforcer and selected_provider != "ollama":
        try:
            # YSG-RISK-144: pass group_ids/org_id — see streaming _usage_callback
            # above for why (group/org counters were never incremented before).
            _state.budget_enforcer.record(
                identity_id=identity_id,
                provider=selected_provider,
                tokens=total_tokens,
                group_ids=(identity.get("groups") or []) if identity else [],
                org_id=(identity.get("org_id", "") or "") if identity else "",
            )
        except Exception as exc:
            logger.warning("Budget recording failed: %s", exc)

    # ── 8c. OPA response-path enforcement ──────────────────────────────
    # Check if the caller is authorised to receive this response based on
    # the detected sensitivity level. Defence-in-depth: even if routing was
    # allowed, the RESPONSE content may have a higher sensitivity than expected.
    #
    # Path 2 (ASVS V14.5.*): identity is guaranteed non-None here — the
    # anonymous-caller reject at step 1b raised HTTP 401 before we reached
    # this point.  The `and identity` guard is removed; `_opa_response_check`
    # handles None identity defensively regardless.
    if _state.opa_url:
        # v2.24.1 — GAP-3 / SEC-5: when response inspection pipeline ran and
        # classified response content, use that as response_sensitivity.
        # When pipeline is off (default), pass None so OPA falls back to
        # prompt sensitivity via the MAX() rule in v1_routing.rego.
        resp_opa = await _opa_response_check(
            identity=identity,
            response_sensitivity=response_content_sensitivity,
            prompt_sensitivity=sensitivity_level,
            response_verdict=response_verdict,
            pii_detected=pii_detected_on_response,
        )
        # Fail-closed (False default): an absent "allow" key means OPA returned an
        # undefined result (e.g. bundle partially loaded). Treat as DENY per
        # v2.23.4 fail-closed posture — closes LAURA-V243-001 / YSG-RISK-071.
        if not resp_opa.get("allow", False):
            resp_opa_reason = resp_opa.get("reason", "response_policy_denied")
            # ── G-ORCH-OPA-3: evaluate-AND-LOG on the brain-REASONING leg ───
            # When (and ONLY when) this is the server-minted brain-reasoning
            # leg, the would-have-blocked verdict is STILL computed (above) and
            # AUDITED here with relaxation_applied=true, but the 403/substitute
            # ACTION is relaxed so the brain can complete its OWN cognition.
            # The completion never reaches a human directly: it returns to the
            # gateway loop, which re-gates the next hop, and (condition 4) any
            # final/prose answer the brain emits goes back through THIS gate
            # NON-relaxed before delivery.  For NON-marked traffic this branch
            # is never taken and the gate is byte-for-byte unchanged.
            if brain_reasoning_leg:
                brain_reasoning_relaxed = True
                _mark_brain_reasoning_relaxed()
                _audit_brain_reasoning_relaxation(
                    request_id=request_id,
                    identity_id=identity_id,
                    verdict=response_verdict,
                    confidence=response_inspection_confidence,
                    content=assistant_content,
                    opa_reason=resp_opa_reason,
                    sensitivity=sensitivity_level,
                )
                logger.warning(
                    "G-ORCH-OPA-3: response-leg OPA would-block RELAXED for brain-"
                    "reasoning leg (evaluate-and-log): identity=%s verdict=%s "
                    "reason=%s relaxation_applied=true request_id=%s",
                    identity_id, response_verdict, resp_opa_reason, request_id,
                )
                # Fall through: deliver the reasoning completion to the brain
                # loop (NOT to a human).  Stamp a header so the leg is greppable
                # in transport too.  Do NOT 403.
            else:
                logger.warning(
                    "OPA BLOCKED response delivery: identity=%s sensitivity=%s reason=%s",
                    identity_id, sensitivity_level, resp_opa_reason,
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": {
                            # R2: human-readable message so OWUI displays it in chat.
                            "message": _deny_message(resp_opa_reason),
                            "type": "response_policy_denied",
                            "code": resp_opa_reason,
                        }
                    },
                    headers={
                        "X-Yashigani-Request-Id": request_id,
                        "X-Yashigani-OPA-Response-Reason": resp_opa_reason,
                    },
                )

    # ── 8b-bind. Client-policy enforcement — EGRESS (#16, OPA Phase 2) ──
    # Runs AFTER the core response-OPA gate; deny-only, fail-closed; no-op when
    # the caller has no bound egress policies.
    _ce_eg_kind = scope_kind_for(identity.get("kind") if identity else None)
    _ce_eg = await evaluate_client_policies(
        _state, _ce_eg_kind, identity_id, "egress",
        _client_enforce_input(identity, "/v1/chat/completions", model=selected_model),
    )
    if not _ce_eg.get("allow", False):
        _ce_eg_reason = (",".join(_ce_eg.get("deny", []) or ["client_policy_denied"])).encode("ascii", "replace").decode("ascii")
        logger.warning("CLIENT-POLICY BLOCKED /v1 egress: identity=%s deny=%s", identity_id, _ce_eg_reason)
        _audit_client_policy("egress", identity_id, _ce_eg_kind, identity_id, _ce_eg)
        return JSONResponse(
            status_code=403,
            # R2: human-readable message so OWUI displays it in chat.
            content={"error": {"message": _deny_message("client_policy_denied"),
                               "type": "client_policy_denied", "code": _ce_eg_reason}},
            headers={"X-Yashigani-Request-Id": request_id,
                     "X-Yashigani-Client-Policy-Reason": _ce_eg_reason},
        )

    # ── 9. Build response ─────────────────────────────────────────────
    elapsed_ms = int((time.time() - start_time) * 1000)

    response = ChatCompletionResponse(
        id=request_id,
        created=int(time.time()),
        model=selected_model,
        choices=[
            ChatCompletionChoice(
                message=ChatMessage(role="assistant", content=assistant_content),
            )
        ],
        usage=CompletionUsage(
            prompt_tokens=input_tokens,
            completion_tokens=output_tokens,
            total_tokens=total_tokens,
        ),
    )

    # ── 10. Return with budget + PII headers ─────────────────────────
    # LAURA-411-004: routing-telemetry headers gated behind flag (default OFF).
    # Always present: Request-Id, Model, Elapsed-Ms, Verdict, PII, Generated-Content,
    # Inspection-Confidence.
    # Debug-only (YASHIGANI_ROUTING_TELEMETRY=true): Routed-Via, Route-Reason,
    # Sensitivity, Complexity.
    _pii_detected_any = pii_detected_on_request or pii_detected_on_response
    headers = {
        "X-Yashigani-Request-Id": request_id,
        "X-Yashigani-Model": selected_model,
        "X-Yashigani-Elapsed-Ms": str(elapsed_ms),
        "X-Yashigani-Response-Verdict": response_verdict,
        "X-Yashigani-PII-Detected": "true" if _pii_detected_any else "false",
        # F-T10-001: Overreliance UX controls — present on every LLM response.
        # Operator UIs use these to render generated-content badges and
        # low-confidence warnings (OWASP Agentic AI T10).
        "X-Yashigani-Generated-Content": "true",
        "X-Yashigani-Response-Inspection-Confidence": f"{response_inspection_confidence:.4f}",
    }
    if _routing_telemetry_enabled():
        headers["X-Yashigani-Routed-Via"] = selected_provider
        headers["X-Yashigani-Route-Reason"] = (
            route_reason.encode("ascii", "replace").decode("ascii")
        )
        headers["X-Yashigani-Sensitivity"] = sensitivity_level
        headers["X-Yashigani-Complexity"] = complexity_level
    # G-ORCH-OPA-3: signal a relaxed brain-reasoning turn so the orchestration
    # loop routes any relaxed final/prose answer through the NON-relaxed egress
    # gate (the load-bearing leak guard, condition 4).  Present ONLY on a leg
    # that was actually relaxed; absent on all normal traffic.
    if brain_reasoning_relaxed:
        headers["X-Yashigani-Brain-Reasoning-Relaxed"] = "true"
    # F-T10-001: low-confidence step-up signal.
    # Emitted when inspection confidence is below threshold AND the prompt
    # sensitivity is CONFIDENTIAL or RESTRICTED — the combination that most
    # warrants human verification before acting on the response.
    _high_sensitivity = sensitivity_level in ("CONFIDENTIAL", "RESTRICTED")
    if (
        response_inspection_confidence < _state.low_confidence_stepup_threshold
        and _high_sensitivity
    ):
        headers["X-Yashigani-Low-Confidence-Stepup"] = "required"
    if budget_total > 0:
        headers["X-Yashigani-Budget-Used"] = str(budget_used)
        headers["X-Yashigani-Budget-Total"] = str(budget_total)
        headers["X-Yashigani-Budget-Pct"] = str(budget_pct)

    # ── #16 step 9. Client-policy obligations (allow-path directives) ──
    # audit_* / redact_* obligations from bound client policies are surfaced here
    # so they are NEVER silently ignored: logged + conveyed to the caller/operator
    # UI via header. (Content-mutation redaction routing through the PII redactor
    # is a tracked follow-up; the directive itself is always recorded.)
    _client_obligations = sorted(set(
        (_ce_in.get("obligations") or []) + (_ce_eg.get("obligations") or [])
    ))
    if _client_obligations:
        headers["X-Yashigani-Client-Obligations"] = ",".join(_client_obligations).encode(
            "ascii", "replace").decode("ascii")
        logger.info("client-policy obligations for %s: %s", identity_id, _client_obligations)

    # F-STREAM: a stream:true request must always be answered as SSE, even when
    # streaming was force-disabled (OPA active / PII block|redact) and the body
    # was produced via the buffered path.  This single return point covers clean
    # success, PII-redacted success, and agent-call success — all funnel here.
    _completion = response.model_dump()
    if body.stream:
        # RISK-105 anti-spoofing: when response inspection blocked the response
        # (response_verdict == "blocked"), emit a structured out-of-band verdict
        # tail frame so the 4.0 UI can render ys-verdict-banner from TRUSTED-CHROME
        # fields — never by scanning the message text for a sentinel string.
        #
        # Scope: this covers ONLY in-stream blocks (response inspection, injection
        # detection) that reach this return point.  Pre-stream OPA / client-policy
        # blocks return JSONResponse(403) earlier in the handler and never reach
        # here; those are handled by the UI's onError callback from a non-200 HTTP.
        _verdict_tail: Optional[dict] = None
        if response_verdict == "blocked":
            _verdict_tail = {
                "blocked": True,
                "user_alert": {
                    "user_message": (
                        "This response was held by the Yashigani security policy. "
                        "Contact an administrator for details."
                    ),
                    "policy_id": "RISK-105",
                },
                "decision_codes": [],
            }
        return _sse_from_completion(_completion, headers, verdict_tail=_verdict_tail)

    return JSONResponse(
        content=_completion,
        headers=headers,
    )


@router.post("/embeddings", response_model=EmbeddingResponse)
async def create_embeddings(body: EmbeddingRequest, request: Request):
    """
    OpenAI-compatible embeddings endpoint.

    Pipeline (mirrors /v1/chat/completions):
    1. Identity resolution + anonymous-caller reject (401)
    2. Sensitivity classification of input text(s) — SAME classifier as chat
    3. OPA ingress policy check (fail-closed)
    4. Sensitivity × routing gate: sensitive input + cloud provider → refuse
       (routing_unsafe_sensitive_to_cloud, same code as chat path via OPA)
    5. Provider routing:
       a. Ollama local  → POST <ollama_url>/api/embed (native multi-input API)
          or /v1/embeddings (OpenAI-compat — TO BE CONFIRMED on live stack)
       b. Cloud (OpenAI) → POST <base_url>/v1/embeddings with embedding model
       c. Cloud (Anthropic) → no embeddings API; fall back to Ollama + log
    6. Normalise response to OpenAI embeddings shape
    7. Audit via GatewayRequestEvent

    Security invariants:
    - Sensitive text (CONFIDENTIAL/RESTRICTED) MUST NOT egress to cloud for
      embedding — archival memory stored via cloud embedder would leak to the
      provider. This is the key gate for Letta archival memory.
    - OPA denial from routing_unsafe_sensitive_to_cloud is the same code path
      as chat; the OPA v1_routing.rego `routing_safe` rule covers both.

    Uncertainty (flag for live stack verification):
    - Ollama < 0.5.0 may not expose /v1/embeddings (OpenAI-compat path).
      We use /api/embed (native, available from Ollama 0.1.x); if that also
      errors the caller gets 503.  Confirm the installed Ollama version exposes
      /api/embed on the live 3.1 stack.
    - Letta archival-memory embedding model: Letta may send any model name;
      this handler resolves the provider from the model name just like chat,
      so the model name Letta is configured to use must exist in Ollama or
      match a cloud-routing alias.
    """
    from yashigani.audit.schema import GatewayRequestEvent

    request_id = f"embed-{uuid.uuid4().hex[:12]}"
    start_time = time.time()

    # ── 1. Identity resolution ────────────────────────────────────────
    identity = _resolve_identity(request)
    identity_id = identity.get("identity_id", "anonymous") if identity else "anonymous"

    if identity is None:
        logger.warning(
            "Anonymous /v1/embeddings caller rejected (request_id=%s) — "
            "zero-trust fail-closed",
            request_id,
        )
        # LAURA-411-004: generic OpenAI-format 401 — no internal header names or
        # auth-architecture details in the response body. Full reason in server log only.
        raise HTTPException(
            status_code=401,
            detail={
                "error": {
                    "message": "Authentication required",
                    "type": "authentication_error",
                    "code": "unauthorized",
                },
            },
        )

    # ── 2. Normalise input to a single classification string ──────────
    # Classify the concatenation of all inputs so a multi-input request is
    # gated on its strictest member. We do NOT forward the raw inputs to
    # the classifier one-by-one (that would miss cross-input context and
    # be slower). The routing gate below uses this single level.
    raw_input = body.input
    if isinstance(raw_input, list):
        input_texts: list[str] = [t for t in raw_input if t]
        classification_text = " ".join(input_texts)
    else:
        input_texts = [raw_input] if raw_input else []
        classification_text = raw_input or ""

    # ── 3. Sensitivity classification ─────────────────────────────────
    sensitivity_level = "PUBLIC"
    s_result = None
    if _state.sensitivity_classifier and classification_text:
        s_result = _state.sensitivity_classifier.classify_decoded(classification_text)
        from yashigani.optimization.sensitivity_classifier import _LEVEL_TO_LEGACY_STRING
        sensitivity_level = _LEVEL_TO_LEGACY_STRING.get(int(s_result.level), "RESTRICTED")
    if s_result is None:
        from yashigani.optimization.sensitivity_classifier import SensitivityLevel, SensitivityResult
        s_result = SensitivityResult(level=SensitivityLevel.PUBLIC)

    # ── 4. Route decision ─────────────────────────────────────────────
    selected_model = body.model or _state.default_model
    selected_provider = "ollama"  # safe default
    route_reason = "embedding_local"

    if _state.optimization_engine and _state.sensitivity_classifier and _state.complexity_scorer:
        # Reuse the optimisation engine — embeddings use a minimal complexity
        # stub (no token count / heuristic) so the engine sees a MEDIUM budget.
        from yashigani.optimization.complexity_scorer import ComplexityLevel, ComplexityResult
        stub_complexity = ComplexityResult(
            level=ComplexityLevel.MEDIUM,
            token_count=len(classification_text) // 4,
            heuristic_score=0.0,
            reasons=[],
        )
        from yashigani.billing.budget_enforcer import BudgetSignal, BudgetState
        stub_budget = BudgetState(
            identity_id=identity_id, provider="cloud",
            used=0, total=0, signal=BudgetSignal.NORMAL, pct=0,
        )
        try:
            decision = _state.optimization_engine.route(
                requested_model=selected_model,
                sensitivity=s_result,
                complexity=stub_complexity,
                budget=stub_budget,
                force_local=False,
                force_cloud=False,
            )
            selected_provider = decision.provider
            selected_model = decision.model
            route_reason = f"embedding:{decision.rule}:{decision.reason}"
        except Exception as _route_exc:
            logger.warning(
                "Embeddings route decision failed (%s) — falling back to ollama",
                _route_exc,
            )
            selected_provider = "ollama"
            route_reason = "embedding_local_fallback"
    else:
        selected_provider = "ollama"
        route_reason = "embedding_local"
        if sensitivity_level in ("CONFIDENTIAL", "RESTRICTED"):
            route_reason = "embedding_sensitivity_local"

    # ── 5. OPA ingress check ──────────────────────────────────────────
    opa_decision = await _opa_v1_check(
        identity=identity,
        selected_model=selected_model,
        selected_provider=selected_provider,
        sensitivity_level=sensitivity_level,
        route_reason=route_reason,
        request_path="/v1/embeddings",
    )
    if not opa_decision.get("allow", False):
        opa_reason = opa_decision.get("reason", "policy_denied")
        logger.warning(
            "OPA DENIED /v1/embeddings: identity=%s model=%s reason=%s",
            identity_id, selected_model, opa_reason,
        )
        # Audit the deny
        if _state.audit_writer is not None:
            try:
                elapsed_ms = int((time.time() - start_time) * 1000)
                _state.audit_writer.write(
                    GatewayRequestEvent(
                        request_id=request_id,
                        method="POST",
                        path="/v1/embeddings",
                        action="DENIED",
                        reason=opa_reason,
                        elapsed_ms=elapsed_ms,
                    )
                )
            except Exception as _ae:
                logger.warning("Embeddings OPA-deny audit write failed: %s", _ae)
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": _deny_message(opa_reason),
                    "type": "policy_denied",
                    "code": opa_reason,
                }
            },
            headers={"X-Yashigani-OPA-Reason": opa_reason},
        )

    # ── 6. Sensitive-to-cloud gate (belt-and-braces, independent of OPA) ─
    # OPA's routing_safe rule already covers this via v1_routing.rego, but we
    # apply it explicitly here too so a misconfigured OPA bundle (which might
    # return allow=True with routing_safe=False) cannot silently egress sensitive
    # archival-memory embeddings to cloud. The check is: if the resolved
    # provider is a cloud provider AND sensitivity >= CONFIDENTIAL, refuse.
    # This mirrors the OPA reason code so the client error is identical.
    _SENSITIVE_LEVELS = {"CONFIDENTIAL", "RESTRICTED"}
    if selected_provider in _CLOUD_PROVIDER_CONFIG and sensitivity_level in _SENSITIVE_LEVELS:
        logger.warning(
            "EMBEDDINGS routing_unsafe_sensitive_to_cloud: identity=%s "
            "sensitivity=%s provider=%s — refusing (fail-closed)",
            identity_id, sensitivity_level, selected_provider,
        )
        if _state.audit_writer is not None:
            try:
                elapsed_ms = int((time.time() - start_time) * 1000)
                _state.audit_writer.write(
                    GatewayRequestEvent(
                        request_id=request_id,
                        method="POST",
                        path="/v1/embeddings",
                        action="DENIED",
                        reason="routing_unsafe_sensitive_to_cloud",
                        elapsed_ms=elapsed_ms,
                    )
                )
            except Exception as _ae:
                logger.warning("Embeddings routing-unsafe audit write failed: %s", _ae)
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": _deny_message("routing_unsafe_sensitive_to_cloud"),
                    "type": "policy_denied",
                    "code": "routing_unsafe_sensitive_to_cloud",
                }
            },
            headers={"X-Yashigani-OPA-Reason": "routing_unsafe_sensitive_to_cloud"},
        )

    # ── 7. Forward to backend ─────────────────────────────────────────
    try:
        import httpx as _httpx

        embedding_data: list[dict] = []
        prompt_tokens = 0
        actual_model = selected_model

        if selected_provider in _CLOUD_PROVIDER_CONFIG:
            # ── 7a. Cloud provider ────────────────────────────────────
            cloud_embedding_model = _get_cloud_embedding_model(selected_provider)

            if cloud_embedding_model is None:
                # Provider has no embeddings API (e.g. Anthropic) → fall back to Ollama.
                logger.info(
                    "Cloud provider %r has no embeddings API — falling back to "
                    "local Ollama embedder (request_id=%s)",
                    selected_provider, request_id,
                )
                selected_provider = "ollama"
                route_reason += ":no_cloud_embeddings_fallback_local"
                # Fall through to the Ollama branch below (no early return).
            else:
                cloud_api_key = _get_cloud_api_key(selected_provider)
                if not cloud_api_key:
                    logger.error(
                        "Cloud provider %r selected for embeddings but no API key "
                        "(KMS miss and env-var absent) request_id=%s",
                        selected_provider, request_id,
                    )
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail=(
                            f"Cloud provider '{selected_provider}' is not configured. "
                            "Set the API key via the admin UI or the "
                            f"{_CLOUD_PROVIDER_CONFIG[selected_provider]['env_var']} "
                            "environment variable."
                        ),
                    )

                cloud_cfg = _CLOUD_PROVIDER_CONFIG[selected_provider]
                actual_model = cloud_embedding_model

                if selected_provider == "openai":
                    cloud_body: dict = {"model": actual_model, "input": raw_input}
                    if body.encoding_format:
                        cloud_body["encoding_format"] = body.encoding_format
                    if body.dimensions:
                        cloud_body["dimensions"] = body.dimensions
                    if body.user:
                        cloud_body["user"] = body.user

                    cloud_headers = {
                        "Authorization": f"Bearer {cloud_api_key}",
                        "Content-Type": "application/json",
                    }

                    async with _httpx.AsyncClient(timeout=60.0) as _client:
                        resp = await _client.post(
                            f"{cloud_cfg['base_url']}/v1/embeddings",
                            json=cloud_body,
                            headers=cloud_headers,
                        )

                    if resp.status_code != 200:
                        logger.error(
                            "OpenAI embeddings upstream error %d request_id=%s: %s",
                            resp.status_code, request_id, resp.text[:200],
                        )
                        raise HTTPException(
                            status_code=status.HTTP_502_BAD_GATEWAY,
                            detail="Cloud provider error. Try again or contact your administrator.",
                        )

                    resp_json = resp.json()
                    embedding_data = resp_json.get("data", [])
                    usage = resp_json.get("usage", {})
                    prompt_tokens = usage.get("prompt_tokens", 0)
                    actual_model = resp_json.get("model", actual_model)

                else:
                    # Unreachable: only openai has a non-None cloud_embedding_model
                    # in _CLOUD_EMBEDDING_DEFAULTS; but guard for future additions.
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail=f"Unknown cloud provider for embeddings: {selected_provider!r}",
                    )

        if selected_provider == "ollama":
            # ── 7b. Ollama local embeddings ───────────────────────────
            # Ollama exposes two endpoints:
            #   /api/embeddings  — legacy single-input (model + prompt)
            #   /api/embed       — v0.5.x multi-input (model + input: str|list)
            # We prefer /api/embed (accepts both str and list natively).
            # If the installed Ollama does not expose /api/embed (< 0.5.x),
            # callers will receive 404 from Ollama which surfaces as 502 here.
            # VERIFY on live 3.1 stack: `curl http://ollama:11434/api/embed`
            # returns 405 (Method Not Allowed, not 404) on 0.5.x when GET is used.
            # Use POST with model+input.
            ollama_body: dict = {
                "model": selected_model,
                "input": raw_input,  # Ollama /api/embed accepts str or list[str]
            }
            # F-001 (embed seam): bare httpx.AsyncClient has no SSL context →
            # fails when ollama_url is https:// (Mac Metal / mTLS-Ollama front).
            # Route through ollama_async_client (same fix as model-list / chat).
            from yashigani.inspection._ollama_transport import (  # noqa: PLC0415
                ollama_async_client as _ollama_ac_embed,
            )
            async with _ollama_ac_embed(_state.ollama_url, timeout=60.0) as _client:
                resp = await _client.post(
                    f"{_state.ollama_url}/api/embed",
                    json=ollama_body,
                )

            if resp.status_code != 200:
                logger.error(
                    "Ollama embeddings error %d request_id=%s: %s",
                    resp.status_code, request_id, resp.text[:200],
                )
                raise HTTPException(
                    status_code=resp.status_code,
                    detail=f"Embedding backend error: {resp.text[:200]}",
                )

            resp_json = resp.json()
            # Ollama /api/embed returns {"model": ..., "embeddings": [[...], ...]}
            # (list of float-lists, one per input item).
            # Ollama /api/embeddings (legacy single) returns {"embedding": [...]}
            raw_embeddings = resp_json.get("embeddings") or []
            if not raw_embeddings and "embedding" in resp_json:
                # Legacy single-input shape fallback
                raw_embeddings = [resp_json["embedding"]]
            embedding_data = [
                {"object": "embedding", "embedding": vec, "index": i}
                for i, vec in enumerate(raw_embeddings)
            ]
            actual_model = resp_json.get("model", selected_model)
            # Ollama does not report token counts for embeddings; estimate
            prompt_tokens = len(classification_text) // 4

    except _httpx.ConnectError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Embedding backend unavailable. Ollama may be starting up.",
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Embeddings backend call failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Embedding backend communication error",
        )

    # ── 8. Build OpenAI-compatible response ───────────────────────────
    elapsed_ms = int((time.time() - start_time) * 1000)
    embedding_objects = [
        EmbeddingObject(
            embedding=item.get("embedding", []) if isinstance(item, dict) else item,
            index=item.get("index", i) if isinstance(item, dict) else i,
        )
        for i, item in enumerate(embedding_data)
    ]
    response = EmbeddingResponse(
        data=embedding_objects,
        model=actual_model,
        usage=EmbeddingUsage(
            prompt_tokens=prompt_tokens,
            total_tokens=prompt_tokens,
        ),
    )

    # ── 9. Audit ──────────────────────────────────────────────────────
    if _state.audit_writer is not None:
        try:
            _state.audit_writer.write(
                GatewayRequestEvent(
                    request_id=request_id,
                    method="POST",
                    path="/v1/embeddings",
                    action="FORWARDED",
                    reason=route_reason,
                    elapsed_ms=elapsed_ms,
                )
            )
        except Exception as _ae:
            logger.warning("Embeddings audit write failed: %s", _ae)

    # LAURA-411-004: routing-telemetry headers gated (same gate as /v1/chat/completions).
    _emb_headers: dict[str, str] = {
        "X-Yashigani-Request-Id": request_id,
        "X-Yashigani-Model": actual_model,
        "X-Yashigani-Elapsed-Ms": str(elapsed_ms),
    }
    if _routing_telemetry_enabled():
        _emb_headers["X-Yashigani-Routed-Via"] = selected_provider
        _emb_headers["X-Yashigani-Route-Reason"] = (
            route_reason.encode("ascii", "replace").decode("ascii")
        )
        _emb_headers["X-Yashigani-Sensitivity"] = sensitivity_level
    return JSONResponse(
        content=response.model_dump(),
        headers=_emb_headers,
    )


@router.get("/models", response_model=ModelListResponse)
async def list_models(request: Request):
    """List available models (for Open WebUI model picker).

    AUTH REQUIRED. QA #59 / FINDING-59-01 (2026-04-29): unauthenticated
    callers were receiving the full Ollama model list + every active service
    identity slug + every active agent slug — internal-topology disclosure
    (OWASP API9 Improper Inventory Management, A01 Broken Access Control).
    Caddy's `/v1/*` block does not gate via `forward_auth`; the gate is here.
    Open WebUI carries the admin session cookie (it lives at /chat/* behind
    the same Caddy auth) so the picker still populates after login. MCP
    clients that hit `/v1/models` directly must present a valid Bearer
    token or X-Yashigani-Identity-Id (SSO via Caddy) to enumerate.

    v2.24.1 — GAP-001 (Iris audit): OPA evaluation added after identity
    resolution.  Human/admin principals receive full list; service-account
    principals receive RESTRICTED list (their allowed_models only, or all
    if allowed_models is empty).  OPA unreachable → 503 fail-closed.
    OPA deny → 403.  Audit event MODELS_LIST_REQUESTED on every call.
    ASVS V4.1.1 / OWASP API9 / Iris GAP-001 / YSG-RISK-066.
    """
    from yashigani.audit.schema import ModelsListRequestedEvent

    identity = _resolve_identity(request)
    if not identity:
        # LAURA-411-004: generic OpenAI-format 401 — no internal header names or
        # auth-architecture details in the response body. Full reason in server log only.
        raise HTTPException(
            status_code=401,
            detail={
                "error": {
                    "message": "Authentication required",
                    "type": "authentication_error",
                    "code": "unauthorized",
                },
            },
        )

    # GAP-001: OPA evaluation — is this principal allowed to enumerate models?
    opa_result = await _opa_models_check(identity)
    identity_id = identity.get("identity_id", "unknown") if identity else "anonymous"
    identity_kind = identity.get("kind", "unknown") if identity else "unknown"

    if not opa_result.get("allow", False):
        # Fail-closed: OPA deny or OPA unreachable
        opa_reason = opa_result.get("reason", "opa_denied")
        http_status = 503 if "unreachable" in opa_reason or "not_configured" in opa_reason else 403
        if _state.audit_writer:
            try:
                _state.audit_writer.write(ModelsListRequestedEvent(
                    identity_id=identity_id,
                    identity_kind=identity_kind,
                    opa_filter="denied",
                    model_count=0,
                    action="denied",
                ))
            except Exception as _aw_exc:
                logger.warning("Audit write failed for ModelsListRequestedEvent deny: %s", _aw_exc)
        raise HTTPException(
            status_code=http_status,
            detail={
                "error": "MODELS_LIST_DENIED",
                "detail": (
                    "OPA policy denied model enumeration for this principal. "
                    f"Reason: {opa_reason}"
                ),
            },
        )

    opa_filter = opa_result.get("filter", "restricted")
    # Admin override: operators can grant service accounts the FULL list (so the
    # Open WebUI model picker populates) via the gateway.models.service_account_full_list
    # runtime setting (admin Runtime Settings panel; default OFF). Only ever
    # WIDENS a restricted service-account listing — never affects human/admin
    # (already full) or a hard deny. Restores the FINDING-59-01 "picker populates
    # after login" behaviour for OWUI deployments.
    if opa_filter == "restricted" and _service_account_full_list_enabled():
        opa_filter = "full"
    # Identify allowed_models for service-account RESTRICTED filter.
    # Three states:
    #   opa_filter == "full"         → no restriction (None sentinel OK)
    #   opa_filter == "restricted"   → service account
    #     allowed_models non-empty   → allow only those models
    #     allowed_models empty       → block all models (empty set → no match)
    #
    # NOTE: None means "full access allowed" (set below only when filter=full).
    # An empty frozenset means "explicitly no models allowed" (service account
    # with empty allowed_models list).  This is intentionally fail-secure:
    # service accounts with no explicit model allowlist see an empty response.
    allowed_models_set: Optional[frozenset] = None
    if opa_filter == "restricted":
        am = (identity.get("allowed_models", []) if identity else [])
        # Use frozenset whether empty or not — empty frozenset = no models allowed.
        allowed_models_set = frozenset(am)

    models = []

    # Add local Ollama models — exposed on full filter; for restricted filter,
    # only models in allowed_models_set (if set is non-empty).
    try:
        # F-001 (model-list seam): bare httpx.AsyncClient has no SSL context and
        # fails CERTIFICATE_VERIFY_FAILED when ollama_url is
        # https://caddy:11435/ollama (Mac Metal / any mTLS-Ollama front).
        # Route through ollama_async_client so the internal PKI context is loaded
        # for https URLs; plain http://ollama:11434 falls through unchanged.
        from yashigani.inspection._ollama_transport import (  # noqa: PLC0415
            ollama_async_client as _ollama_async_client,
        )
        async with _ollama_async_client(_state.ollama_url, timeout=5.0) as client:
            resp = await client.get(f"{_state.ollama_url.rstrip('/')}/api/tags")
            if resp.status_code == 200:
                for m in resp.json().get("models", []):
                    model_name = m.get("name", "")
                    if opa_filter == "full" or (allowed_models_set is not None and model_name in allowed_models_set):
                        models.append(ModelInfo(
                            id=model_name,
                            created=0,
                            owned_by="ollama (local)",
                        ))
    except Exception as exc:
        logger.warning("Failed to fetch Ollama models: %s", exc)

    # Add configured service identities as "models" (for @mention invocation)
    # Only exposed on full filter — topology not visible to service accounts.
    if opa_filter == "full" and _state.identity_registry:
        from yashigani.identity import IdentityKind
        for svc in _state.identity_registry.list_active(kind=IdentityKind.SERVICE):
            models.append(ModelInfo(
                id=f"@{svc['slug']}",
                created=0,
                owned_by=f"yashigani ({svc['name']})",
            ))

    # Add registered agents as selectable models (for @agent invocation in Open WebUI)
    # Only exposed on full filter — agent topology not visible to service accounts.
    if opa_filter == "full" and _state.agent_registry:
        try:
            for agent in _state.agent_registry.list_all():
                if agent.get("status") == "active":
                    agent_name = agent.get("name", "")
                    models.append(ModelInfo(
                        id=f"@{agent_name}",
                        created=0,
                        owned_by=f"yashigani-agent ({agent_name})",
                    ))
        except Exception as exc:
            logger.warning("Failed to list agents for models: %s", exc)

    # Add any statically configured models
    for m in (_state.available_models or []):
        model_id = m.get("id", "")
        if opa_filter == "full" or (allowed_models_set is not None and model_id in allowed_models_set):
            models.append(ModelInfo(
                id=model_id,
                created=0,
                owned_by=m.get("provider", "yashigani"),
            ))

    # Add virtual orchestration models from YASHIGANI_ORCH_AUTO_MODELS.
    # These are placeholder model names that auto-trigger the qwen-brain executor
    # when selected in OWUI's model picker.  They appear in the full list only
    # (same visibility rule as agents) so users see them but service accounts
    # that enumerate the model list for routing decisions do not.
    if opa_filter == "full":
        _auto_raw = os.environ.get("YASHIGANI_ORCH_AUTO_MODELS", "").strip()
        for _vname in (_auto_raw.split(",") if _auto_raw else []):
            _vname = _vname.strip()
            if _vname and not any(m.id == _vname for m in models):
                models.append(ModelInfo(
                    id=_vname,
                    created=0,
                    owned_by="yashigani-orchestration",
                ))

    # Audit: MODELS_LIST_REQUESTED with count of models returned.
    # Count only — no model names stored (prevents log-based topology disclosure).
    if _state.audit_writer:
        try:
            _state.audit_writer.write(ModelsListRequestedEvent(
                identity_id=identity_id,
                identity_kind=identity_kind,
                opa_filter=opa_filter,
                model_count=len(models),
                action="allowed",
            ))
        except Exception as _aw_exc:
            logger.warning("Audit write failed for ModelsListRequestedEvent allow: %s", _aw_exc)

    return ModelListResponse(data=models)


# ── Helpers ──────────────────────────────────────────────────────────────


def _load_token_role_map(agent_registry=None) -> None:
    """Populate ``_state.token_role_map`` from env + per-agent secret files + NHI registry.

    Called once at ``configure()`` time (SOP 1).  Safe to call again after
    NHI approval to refresh without restarting the gateway.

    Token role map entry format: ``{plaintext_token: (role_class, identity_id)}``

    Role classes: "p2_forwarder" | "p2_orchestrator" | "p1_agent" | "p1_nhi"

    Per-agent secret files (4.0 Phase 3 — RISK-108):
    Each bundled P1 agent (Letta, Langflow, …) has a per-service token file under
    ``YASHIGANI_SECRETS_DIR`` (default ``/run/secrets``).  The gateway mounts
    ``./secrets:/run/secrets:ro`` so every generated token file is available.
    """
    new_map: dict[str, tuple[str, str]] = {}

    # Dev/test env-var injection: YASHIGANI_TOKEN_ROLE_MAP (JSON)
    # Format: {"<token>": ["<role>", "<identity_id>"]}
    raw = os.environ.get("YASHIGANI_TOKEN_ROLE_MAP", "").strip()
    if raw:
        try:
            env_entries = json.loads(raw)
            for tok, pair in env_entries.items():
                if isinstance(pair, (list, tuple)) and len(pair) == 2:
                    new_map[tok] = (str(pair[0]), str(pair[1]))
                    logger.debug("token_role_map: loaded role=%s id=%s from env", pair[0], pair[1])
        except Exception as exc:
            logger.error(
                "YASHIGANI_TOKEN_ROLE_MAP parse error (ignoring) — "
                "P1/P2 split will fall through to _INTERNAL_BEARER path: %s", exc,
            )

    # Per-agent secret files: bundled P1 agents (Langflow, Letta, …)
    # Each entry: (secret_filename, role_class, identity_id)
    # 4.0 Phase 3 — RISK-108 / impersonation prevention.
    _PER_AGENT_SECRET_FILES: list[tuple[str, str, str]] = [
        # Langflow — P1 bundled agent; resolves as agent__langflow identity.
        # Token generated by install.sh (langflow_yashigani_token secret).
        ("langflow_yashigani_token", "p1_agent", "agent__langflow"),
    ]
    _secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
    for secret_name, role_class, identity_id in _PER_AGENT_SECRET_FILES:
        secret_path = os.path.join(_secrets_dir, secret_name)
        try:
            with open(secret_path, "r", encoding="utf-8") as fh:
                tok = fh.read().strip()
            if tok:
                new_map[tok] = (role_class, identity_id)
                logger.info(
                    "token_role_map: loaded %s → role=%s id=%s from secret %s",
                    secret_name, role_class, identity_id, secret_path,
                )
            else:
                logger.warning(
                    "token_role_map: secret file %s is empty — "
                    "%s will not be resolvable as %s",
                    secret_path, identity_id, role_class,
                )
        except FileNotFoundError:
            logger.warning(
                "token_role_map: secret file %s not found — "
                "%s will not be resolvable as %s (normal before first install)",
                secret_path, identity_id, role_class,
            )
        except Exception as exc:
            logger.error(
                "token_role_map: error reading secret file %s — "
                "%s will not be resolvable as %s: %s",
                secret_path, identity_id, role_class, exc,
            )

    # NHI tokens from the registry (fast plaintext lookup, db/4 index)
    if agent_registry is not None:
        try:
            nhi_map = agent_registry.get_nhi_token_map()  # {plaintext_token: nhi_id}
            for tok, nhi_id in nhi_map.items():
                new_map[tok] = ("p1_nhi", nhi_id)
                logger.debug("token_role_map: loaded p1_nhi entry for %s", nhi_id)
        except Exception as exc:
            logger.warning(
                "token_role_map: NHI registry load failed — NHIs will not be resolvable: %s", exc
            )

    _state.token_role_map = new_map
    n_env = sum(1 for _tok, v in new_map.items() if v[0] not in ("p1_nhi", "p1_agent"))
    n_agents = sum(1 for v in new_map.values() if v[0] == "p1_agent")
    n_nhi = sum(1 for v in new_map.values() if v[0] == "p1_nhi")
    logger.info(
        "token_role_map: loaded %d entries (env=%d p1_agent=%d p1_nhi=%d)",
        len(new_map), n_env, n_agents, n_nhi,
    )


def _resolve_caller_role(bearer_token: str) -> Optional[tuple[str, str]]:
    """Map a bearer token to its (role_class, identity_id) from ``_state.token_role_map``.

    Uses ``hmac.compare_digest`` for constant-time comparison to avoid timing leaks.

    Returns ``None`` if the token is not in the role map — callers then fall
    through to the existing ``_INTERNAL_BEARER`` comparison path (backward compat).

    Raises ``HTTPException(401)`` only when called from the enforcement path in
    ``_resolve_identity`` — this function itself returns None on miss.
    """
    for tok, (role, identity_id) in _state.token_role_map.items():
        if hmac.compare_digest(bearer_token, tok):
            return role, identity_id
    return None


def _emit_agent_header_stripped(
    stripped_header: str,
    caller_token_role: str,
    agent_identity_id: str,
) -> None:
    """Emit AGENT_HEADER_STRIPPED security event to the audit chain (RISK-108).

    This is the regression canary: any appearance in the audit chain means
    an agent made an impersonation attempt.  Laura's regression probe checks
    for this event without needing a live exploit.
    """
    if _state.audit_writer is None:
        return
    try:
        from yashigani.audit.schema import AgentHeaderStrippedEvent
        _state.audit_writer.write(AgentHeaderStrippedEvent(
            caller_token_role=caller_token_role,
            stripped_header=stripped_header,
            agent_identity_id=agent_identity_id,
        ))
    except Exception as exc:
        logger.warning("AGENT_HEADER_STRIPPED audit write failed: %s", exc)


def _resolve_nhi_identity(nhi_id: str) -> Optional[dict]:
    """Return the NHI identity dict from AgentRegistry, or None if not found.

    The OPA input for NHI hops uses ``input.identity`` (R9 — preserve existing
    field name) with additional NHI-specific fields (``kind="nhi"``,
    ``allowed_tools``, ``budget_cap``, ``on_behalf_of`` from delegated ctx).
    """
    if _state.agent_registry is None:
        return None
    try:
        nhi = _state.agent_registry.get(nhi_id)
        if nhi is None or nhi.get("kind") != "nhi":
            return None
        if not nhi.get("svid_issued"):
            # NHI pending admin approval — fail-closed (403 in the caller)
            logger.warning(
                "_resolve_nhi_identity: NHI %s has svid_issued=False — pending approval",
                nhi_id,
            )
            return None
        # Build an identity dict matching the OPA input contract (R9: input.identity)
        return {
            "identity_id": nhi_id,
            "kind": "nhi",
            "status": nhi.get("status", "active"),
            "groups": [],
            "allowed_models": nhi.get("allowed_models", []),
            "allowed_paths": nhi.get("allowed_paths", []),
            "allowed_tools": nhi.get("allowed_tools", []),
            "sensitivity_ceiling": nhi.get("sensitivity_ceiling", "PUBLIC"),
            "budget_cap": nhi.get("budget_cap", {}),
            "owner_identity_id": nhi.get("owner_identity_id", ""),
            "template_id": nhi.get("template_id", ""),
            "spiffe_id": nhi.get("spiffe_id", ""),
            "_is_nhi": True,   # fast discriminator for downstream code
        }
    except Exception as exc:
        logger.error("_resolve_nhi_identity: registry lookup failed for %s: %s", nhi_id, exc)
        return None


def _resolve_identity(request: Request) -> Optional[dict]:
    """
    Resolve identity from request.

    Priority (4.1 SEC-GAP-1):
    1. yashigani-internal Bearer token (mesh-port internal service calls)
       → X-Yashigani-Identity-Id for per-user on forwarder path
    2. request.state.ysg_principal (pre-resolved by proxy.py boundary block
       from X-Yashigani-Identity-Id for SSO/browser-session path via Caddy)
    3. Authorization: Bearer <api_key> (registry lookup)

    X-Forwarded-User / X-OpenWebUI-User-Email paths REMOVED in 4.1.
    Fail-closed: no bearer + no pre-resolved UID + no api-key → returns None → 401.

    The yashigani-internal check is intentionally placed BEFORE the
    identity_registry null-guard so that the hardcoded internal
    token resolves even when the identity registry is temporarily
    unavailable (e.g. Redis not yet reachable at startup).  Network
    isolation on the data bridge / K8s NetworkPolicy is the transport-
    layer guard for this token; it must never be reachable from the
    public-facing port.
    """
    # Fast path: service-to-service token resolution.
    # Priority 1: P1/P2 role map (per-service tokens, 4.0 Phase 3).
    #             Populated from YASHIGANI_TOKEN_ROLE_MAP env and NHI registry.
    # Priority 2: Shared _INTERNAL_BEARER (backward compat for 3.x deployments).
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        key = auth[7:]

        # ── P1/P2 role map path (4.0 Phase 3 — RISK-108) ──────────────────
        # When per-service tokens are configured, route each token to its role.
        role_entry = _resolve_caller_role(key)
        if role_entry is not None:
            role_class, token_identity_id = role_entry

            if role_class == "p2_orchestrator":
                # P2 orchestrator: same logic as the existing internal-bearer
                # orchestration-principal path (preserves brain-marker invariant).
                orch_principal = request.headers.get("x-yashigani-orchestration-principal", "").strip()
                if orch_principal and _state.identity_registry is not None:
                    try:
                        real = _state.identity_registry.get_by_slug(orch_principal)
                    except Exception:
                        real = None
                    if real:
                        real = dict(real)
                        real["_orchestration_self_call"] = True
                        return real
                return {"identity_id": "internal", "status": "active", "kind": "service",
                        "groups": [], "allowed_models": [], "sensitivity_ceiling": "RESTRICTED",
                        "_orchestration_self_call": bool(orch_principal)}

            elif role_class == "p2_forwarder":
                # P2 forwarder: backoffice/OWUI trusted-forwarder path.
                # Strip any orchestration-principal header (forwarder is not the brain).
                orch_hdr = request.headers.get("x-yashigani-orchestration-principal", "")
                if orch_hdr:
                    _emit_agent_header_stripped(
                        "x-yashigani-orchestration-principal", role_class, token_identity_id
                    )
                # 4.1 SEC-GAP-1: X-Yashigani-Identity-Id only — no email/slug path.
                # _resolve_yashigani_identity_id_header raises 403/503 on failure so
                # control NEVER falls through when the idnt_ header is present
                # (fail-closed per LAURA-4.0-S1-001).
                yashigani_identity = _resolve_yashigani_identity_id_header(request)
                if yashigani_identity is not None:
                    return yashigani_identity
                # No UID header → service internal (RESTRICTED), no phantom default.
                return {"identity_id": "internal", "status": "active", "kind": "service",
                        "groups": [], "allowed_models": [], "sensitivity_ceiling": "RESTRICTED"}

            elif role_class in ("p1_agent", "p1_nhi"):
                # P1 agent/NHI: resolve as OWN identity only.
                # Strip any P2 impersonation headers and emit security event.
                # 4.1 SEC-GAP-1: X-OpenWebUI-User-Email check removed; strip
                # X-Yashigani-Identity-Id + orchestration-principal only.
                orch_hdr = request.headers.get("x-yashigani-orchestration-principal", "")
                identity_id_hdr = request.headers.get(_YASHIGANI_IDENTITY_ID_HEADER, "")
                if orch_hdr:
                    _emit_agent_header_stripped(
                        "x-yashigani-orchestration-principal", role_class, token_identity_id
                    )
                if identity_id_hdr:
                    _emit_agent_header_stripped(
                        _YASHIGANI_IDENTITY_ID_HEADER, role_class, token_identity_id
                    )

                if role_class == "p1_nhi":
                    nhi_identity = _resolve_nhi_identity(token_identity_id)
                    if nhi_identity is None:
                        # NHI pending approval or not found — fail-closed
                        raise HTTPException(
                            status_code=403,
                            detail={"error": "NHI_PENDING_APPROVAL",
                                    "message": "NHI identity not yet approved or not found."},
                        )
                    return nhi_identity

                # p1_agent: resolve as a named agent identity from registry
                if _state.agent_registry is not None:
                    try:
                        agent = _state.agent_registry.get(token_identity_id)
                        if agent is not None:
                            return {
                                "identity_id": token_identity_id,
                                "kind": "agent",
                                "status": agent.get("status", "active"),
                                "groups": agent.get("groups", []),
                                "allowed_models": [],
                                "allowed_paths": agent.get("allowed_paths", []),
                                "sensitivity_ceiling": "INTERNAL",
                            }
                    except Exception as exc:
                        logger.warning(
                            "_resolve_identity: p1_agent registry lookup failed for %s: %s",
                            token_identity_id, exc,
                        )
                # Fallback: generic P1 agent identity (no elevated privilege)
                return {"identity_id": token_identity_id, "kind": "agent",
                        "status": "active", "groups": [], "allowed_models": [],
                        "sensitivity_ceiling": "INTERNAL"}

        # ── Shared _INTERNAL_BEARER path (backward compat) ─────────────────
        if hmac.compare_digest(key, _INTERNAL_BEARER):
            # Internal service-to-service calls (Open WebUI, agents)
            # Treated as authenticated internal identity — same OPA rules apply.
            #
            # ── Orchestration confused-deputy guard (build sheet §6 / §7.2) ──
            # When an orchestration self-call carries X-Yashigani-Orchestration-
            # Principal, OPA must evaluate the REAL caller's authorisation, not the
            # internal service account.  We resolve that principal from the registry
            # so every per-hop ingress/egress OPA decision (§0.1) names the true
            # identity.  The header is only honoured on the internal-bearer path
            # (mesh port 8081, network-isolated), so an external caller cannot set
            # it to impersonate another principal.  Fail-closed: an unknown/empty
            # principal falls back to the internal service identity (no privilege
            # escalation — internal is RESTRICTED).
            orch_principal = request.headers.get("x-yashigani-orchestration-principal", "").strip()
            if orch_principal and _state.identity_registry is not None:
                try:
                    real = _state.identity_registry.get_by_slug(orch_principal)
                except Exception:  # registry blip — fall back to internal
                    real = None
                if real:
                    real = dict(real)
                    real["_orchestration_self_call"] = True
                    return real

            # ── Track C (F-B): trusted-forwarder per-user resolution ──
            # 4.1 SEC-GAP-1: X-Yashigani-Identity-Id ONLY (idnt_ PK).
            #   The backoffice chat proxy forwards the idnt_ PK directly.
            #   Fail-closed: header present but not in registry → 403 (no fallback).
            #   X-OpenWebUI-User-Email / X-Forwarded-User paths removed.
            # ORDERING: runs AFTER orchestration-principal check. Brain/in-mesh agent
            # self-calls carry neither header; they fall through to `internal`.
            # SPOOFING DEFENSE: only inside the proven-internal-bearer branch.
            yashigani_identity = _resolve_yashigani_identity_id_header(request)
            if yashigani_identity is not None:
                return yashigani_identity

            return {"identity_id": "internal", "status": "active", "kind": "service",
                    "groups": [], "allowed_models": [], "sensitivity_ceiling": "RESTRICTED",
                    "_orchestration_self_call": bool(orch_principal)}

    if not _state.identity_registry:
        return None

    # ── 4.1 SEC-GAP-1 — boundary-resolver pre-populated ysg_principal ──────────
    # proxy.py boundary resolver runs as middleware and sets
    # request.state.ysg_principal when X-Yashigani-Identity-Id is present and
    # trusted-internal (Caddy strips external copies at the edge).  Use it first;
    # this covers the browser-session SSO path without touching email/slug.
    # Fail-closed: the boundary resolver already rejected malformed/unknown ids
    # with 403/401, so ysg_principal is only set when identity is confirmed valid.
    _rp_oir = getattr(getattr(request, "state", None), "ysg_principal", None)
    if _rp_oir is not None:
        try:
            _oir_identity = _state.identity_registry.get(_rp_oir.identity_id)
        except Exception as _oir_exc:
            logger.warning(
                "_resolve_identity: registry get for pre-resolved principal %r raised %s",
                _rp_oir.identity_id, _oir_exc,
            )
            _oir_identity = None
        if _oir_identity is not None:
            return _oir_identity
        # principal was pre-resolved but registry blip prevented dict fetch —
        # fall through to API-key auth rather than fail-open with partial data

    # 4.1 SEC-GAP-1: X-Forwarded-User / slug-based SSO path removed.
    # SSO identity now flows exclusively via X-Yashigani-Identity-Id (idnt_ PK),
    # pre-resolved by proxy.py 0b boundary block into request.state.ysg_principal
    # (handled above).  No X-Forwarded-User / get_by_slug() on this path.
    # Fail-closed: no valid UID pre-resolution → falls through to API-key auth
    # below; no bearer + no api-key → returns None → 401.

    # API key (registry lookup)
    if auth.startswith("Bearer "):
        key = auth[7:]
        if key:
            identity = _state.identity_registry.get_by_api_key(key)
            if identity is None:
                return None
            # V10.3.5 — sender-constrained token check (LF-SPIFFE-FORGE fix).
            # When the identity has a bound_spiffe_uri set, the bearer key is
            # SPIFFE-URI-bound.  The SPIFFE URI is resolved in priority order:
            #
            #   1. X-SPIFFE-ID-Peer-Cert (set by SpiffePeerCertMiddleware from
            #      the actual TLS handshake peer cert URI SAN — cannot be forged
            #      by the client even on a direct-to-gateway connection).
            #   2. X-SPIFFE-ID (set by Caddy from the peer cert when the request
            #      is routed through Caddy; Caddy strips any inbound value first).
            #
            # The Caddy path (2) is the normal path for external callers.
            # The direct-gateway path (1) covers internal-mesh peers that bypass
            # Caddy — those connections must present their OWN cert, so the
            # middleware extracts the real URI from the handshake.
            #
            # LF-SPIFFE-FORGE threat: a compromised internal peer connects
            # directly to gateway:8080 and sets X-SPIFFE-ID: <stolen bound_uri>.
            # Without the middleware, only check (2) runs and the stolen header
            # passes.  With the middleware, check (1) runs first — the peer's
            # OWN cert URI SAN (e.g. spiffe://…/wazuh-agent) replaces the
            # forged header, and the binding check rejects the mismatch.
            #
            # If no binding is set (empty string) the check is skipped —
            # community agents and Open WebUI internal traffic are unaffected.
            bound_uri = identity.get("bound_spiffe_uri", "")
            if bound_uri:
                # Prefer the server-extracted cert URI (cryptographically bound).
                peer_cert_uri = request.headers.get("x-spiffe-id-peer-cert", "")
                presented_uri = peer_cert_uri if peer_cert_uri else request.headers.get("X-SPIFFE-ID", "")
                if presented_uri != bound_uri:
                    # Fail-closed: stolen/replayed token without matching cert.
                    import logging as _logging
                    _logging.getLogger(__name__).warning(
                        "V10.3.5 LF-SPIFFE-FORGE: SPIFFE-URI mismatch for identity %s — "
                        "bound=%r presented=%r (peer_cert=%r x-spiffe-id=%r) — rejecting",
                        identity.get("identity_id"), bound_uri, presented_uri,
                        peer_cert_uri,
                        request.headers.get("X-SPIFFE-ID", ""),
                    )
                    return None
            return identity

    return None


def _effective_allowed_models(identity: dict | None) -> "EffectiveModels":
    """Compute the caller's EFFECTIVE allowed-models (Track B1 model-RBAC).

    Combines the identity's own ``allowed_models`` with the models allocated to
    its org / groups / user via the durable allocation store, expanding each
    allocated alias to {alias name, concrete model}. Returns an EffectiveModels
    with deny-by-default / fail-closed semantics (see models.effective).

    Resolved once per request and reused for BOTH the OPA input AND the
    optimiser-binding re-check, so the two cannot disagree.
    """
    from yashigani.models.effective import resolve_effective_allowed_models
    # getattr-guard: a partially-configured _state (e.g. allocation stores not
    # wired in a minimal test/dev harness) degrades to "no allocation enforcement"
    # rather than crashing the request path — the resolver already treats a None
    # alloc_store as own-allowed_models only (fail-safe, never fail-open).
    return resolve_effective_allowed_models(
        identity,
        getattr(_state, "model_allocation_store", None),
        getattr(_state, "model_alias_store", None),
    )


def model_denied_for_caller(
    identity: dict | None,
    model: str,
    *,
    brain_leg: bool = False,
) -> tuple[bool, "EffectiveModels"]:
    """THE gateway-side model-RBAC CHOKE POINT (Track B1 — single authority).

    Every model-selection path in the gateway — chat egress, orchestration-seed
    brain choice, tool-catalog projection, and the model-tool hop — consults THIS
    one function to decide whether a (caller, model) pair is denied.  It pulls the
    live allocation + alias stores from ``_state`` and delegates to
    ``models.effective.model_denied_for_caller`` (the cross-module authority).

    ``brain_leg`` MUST be the SERVER-MINTED ``is_brain_reasoning_leg`` marker only
    (process-local round-trip + internal identity + brain model).  It is the lone
    exemption: the internal cognition leg holds no allocation and would otherwise
    be denied the gated brain model.  A principal-bearing orchestration self-call
    (a model/agent tool hop) is NEVER passed brain_leg=True — it carries the real
    caller's allocations, which are enforced.  Fail-closed; never raises.
    """
    from yashigani.models.effective import model_denied_for_caller as _authority
    return _authority(
        identity,
        model,
        _state.model_allocation_store,
        _state.model_alias_store,
        brain_leg=brain_leg,
    )


async def _opa_cloud_model_policy_check(
    policy_ref: str,
    *,
    identity: dict | None,
    model: str,
    provider: str,
    sensitivity_level: str,
) -> dict:
    """INV-2 runtime coupling: traverse the OPA data-protection policy referenced
    by a cloud_model grant's opa_policy_ref (Phase 6 / 3.1).

    Fail-closed: returns {"allow": False} on any error, missing OPA path, empty
    policy result, or invalid policy_ref.  A grant with a valid opa_policy_ref
    pointing at an OPA bundle path that evaluates to {"allow": true} is the ONLY
    passing case.

    Dev opt-in: when YASHIGANI_OPA_OPTIONAL=true (non-production) and OPA is not
    configured, the coupling check is bypassed so local dev works without a full
    OPA bundle (consistent with _opa_v1_check dev-opt-in handling).

    policy_ref format: "yashigani/cloud_model/gpt4o"
        → OPA path: {opa_url}/v1/data/yashigani/cloud_model/gpt4o
    """
    import re as _re

    if not _state.opa_url:
        _ysg_env = os.getenv("YASHIGANI_ENV", "").strip().lower()
        _opa_optional = os.getenv("YASHIGANI_OPA_OPTIONAL", "false").strip().lower() == "true"
        if _opa_optional and _ysg_env != "production":
            logger.warning(
                "cloud_model OPA coupling skipped — OPA not configured "
                "(YASHIGANI_OPA_OPTIONAL=true, env=%s)",
                _ysg_env,
            )
            return {"allow": True, "reason": "opa_not_configured_dev_opt_in"}
        return {"allow": False, "reason": "opa_not_configured"}

    # Sanitise policy_ref to prevent path traversal / injection.
    # Valid chars: alphanumeric, underscore, hyphen, forward-slash.
    if not policy_ref or not _re.match(r'^[a-zA-Z0-9_/\-]+$', policy_ref.strip()):
        logger.warning(
            "cloud_model OPA coupling: invalid policy_ref %r — fail-closed", policy_ref,
        )
        return {"allow": False, "reason": "invalid_policy_ref"}

    opa_input = {
        "identity": {
            "status": identity.get("status", "active") if identity else "anonymous",
            "kind": identity.get("kind", "unknown") if identity else "unknown",
            "groups": identity.get("groups", []) if identity else [],
            "sensitivity_ceiling": (
                identity.get("sensitivity_ceiling", "RESTRICTED") if identity else "RESTRICTED"
            ),
        },
        "model": model,
        "provider": provider,
        "sensitivity": sensitivity_level,
    }

    policy_path = policy_ref.strip("/")
    try:
        async with internal_httpx_client(timeout=5.0) as client:
            resp = await client.post(
                _state.opa_url.rstrip("/") + f"/v1/data/{policy_path}",
                json={"input": opa_input},
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
            if not result:
                # Empty result: OPA path does not exist in the bundle → fail-closed.
                logger.warning(
                    "cloud_model OPA coupling: policy_ref=%r resolved to empty result "
                    "(path not defined in OPA bundle) — fail-closed",
                    policy_ref,
                )
                return {"allow": False, "reason": "policy_not_found"}
            allowed = bool(result.get("allow", False))
            return {
                "allow": allowed,
                "reason": result.get("reason", "policy_evaluated"),
            }
    except Exception as exc:
        logger.error(
            "cloud_model OPA coupling: policy check failed (ref=%r): %s — fail-closed",
            policy_ref, exc,
        )
        return {"allow": False, "reason": "opa_unreachable"}


async def _opa_v1_check(
    identity: dict | None,
    selected_model: str,
    selected_provider: str,
    sensitivity_level: str,
    route_reason: str,
    request_path: str,
    effective_allowed_models: list[str] | None = None,
) -> dict:
    """
    Query OPA v1_routing policy for allow/deny + reason.

    Input matches v1_routing.rego schema:
      input.identity          — identity record
      input.routing_decision  — provider, model, sensitivity, route, rule
      input.request           — path, method
      input.trusted_cloud_providers — list of trusted providers (from config)

    Returns {"allow": bool, "reason": str} or deny on any error (fail-closed).

    Path 3 (ASVS V14.5.*): if OPA is not configured, deny unconditionally.
    The startup guard in configure() prevents reaching this branch in production
    without YASHIGANI_OPA_URL.  In dev with YASHIGANI_OPA_OPTIONAL=true the
    guard was bypassed with explicit operator consent — we still deny here so
    that accidental calls to _opa_v1_check with no opa_url surface clearly.
    """
    if not _state.opa_url:
        _ysg_env = os.getenv("YASHIGANI_ENV", "").strip().lower()
        _opa_optional = os.getenv("YASHIGANI_OPA_OPTIONAL", "false").strip().lower() == "true"
        if _opa_optional and _ysg_env != "production":
            # Explicit dev-mode opt-in only (non-production + YASHIGANI_OPA_OPTIONAL=true)
            logger.warning(
                "OPA not configured (YASHIGANI_OPA_OPTIONAL=true, env=%s) — "
                "allowing request without policy check (dev opt-in)",
                _ysg_env,
            )
            # Dev-opt-in: OPA is intentionally bypassed, so EVERY sub-decision is
            # bypassed consistently — including model_allowed.  Without this, the
            # B1 model_allowed backstop (which reads opa_decision["model_allowed"])
            # would fail-closed on the .get(...,False) default and 403 every dev
            # request even though policy was deliberately skipped.  Production never
            # reaches this branch (startup guard requires YASHIGANI_OPA_URL).
            return {"allow": True, "reason": "opa_not_configured_dev_opt_in",
                    "model_allowed": True, "routing_safe": True,
                    "sensitivity_allowed": True}
        logger.error(
            "OPA not configured and fail-closed triggered (env=%s, opa_optional=%s)",
            _ysg_env, _opa_optional,
        )
        opa_response_check_failures_total.labels(
            outcome="not_configured", reason="opa_not_configured"
        ).inc()
        return {"allow": False, "reason": "opa_not_configured"}

    # Track B1: when the caller has an effective-allowed-models set computed from
    # allocations, it OVERRIDES the identity's own allowed_models in the OPA input
    # so `model_allowed` denies any model outside the union of own + allocated.
    # None means "not computed" → fall back to the identity's own list (unchanged
    # behaviour for callers/paths with no allocation enforcement).
    if effective_allowed_models is not None:
        _allowed_models_doc = effective_allowed_models
    else:
        _allowed_models_doc = identity.get("allowed_models", []) if identity else []

    identity_doc = {
        "status": identity.get("status", "active") if identity else "anonymous",
        "kind": identity.get("kind", "unknown") if identity else "unknown",
        "groups": identity.get("groups", []) if identity else [],
        "allowed_models": _allowed_models_doc,
        "sensitivity_ceiling": identity.get("sensitivity_ceiling", "RESTRICTED") if identity else "PUBLIC",
    }

    routing_doc = {
        "provider": selected_provider,
        "model": selected_model,
        "sensitivity": sensitivity_level,
        "route": "cloud" if selected_provider not in ("ollama", "agent") else "local",
        "rule": route_reason,
    }

    opa_input = {
        "identity": identity_doc,
        "routing_decision": routing_doc,
        "request": {"path": request_path, "method": "POST"},
        "trusted_cloud_providers": [p.strip() for p in os.getenv("YASHIGANI_TRUSTED_CLOUD_PROVIDERS", "").split(",") if p.strip()],
    }

    try:
        async with internal_httpx_client(timeout=5.0) as client:
            resp = await client.post(
                _state.opa_url.rstrip("/") + "/v1/data/yashigani/v1/decision",
                json={"input": opa_input},
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
            return {
                "allow": bool(result.get("allow", False)),
                # Fail-closed on undefined sub-decisions (OPA-003/004 class):
                # on a bundle-mismatch these fields are absent and must NOT
                # default permissive. Matches proxy.py:1127 + v1_routing.rego
                # default-deny.
                "model_allowed": bool(result.get("model_allowed", False)),
                "routing_safe": bool(result.get("routing_safe", False)),
                "sensitivity_allowed": bool(result.get("sensitivity_allowed", False)),
                "reason": result.get("reason", "unknown"),
            }
    except Exception as exc:
        logger.error("OPA v1 check failed: %s — denying (fail-closed)", exc)
        return {"allow": False, "reason": "opa_unreachable"}


_SENSITIVITY_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}


def _stricter_sensitivity(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """Return the higher-ranked (stricter) of two sensitivity labels.

    Used to combine the LLM inspector's response sensitivity with the
    deterministic classifier's verdict so the OPA ceiling check sees the
    strictest signal (LAURA-ORCH leakfix).  None is treated as the lowest rank
    (absence of signal never lowers the floor below the other input).
    """
    ra = _SENSITIVITY_RANK.get((a or "").upper(), -1)
    rb = _SENSITIVITY_RANK.get((b or "").upper(), -1)
    if ra < 0 and rb < 0:
        return a if a is not None else b
    return a if ra >= rb else b


async def gate_relaxed_final(
    *, identity: dict | None, final_text: str, prompt_sensitivity: str,
) -> tuple[bool, str]:
    """G-ORCH-OPA-3 condition 4 — re-gate a RELAXED brain final through the
    STANDARD (NON-relaxed) response egress gate before it can reach the user.

    A relaxed brain-reasoning turn may have parsed to a ``final`` answer.  That
    answer must NOT be delivered to the human on the relaxed verdict — it must be
    re-adjudicated by the same response inspection + OPA response gate that normal
    chat traffic faces, with NO relaxation.  This is THE leak guard.

    Returns ``(allow, text)``:
      • allow=True  → the final passed the non-relaxed gate; deliver ``text``.
      • allow=False → the gate would block; ``text`` is a neutral substitute
        notice (the raw reasoning is SUPPRESSED, never delivered).

    Runs entirely outside any open brain round-trip (the executor calls this AFTER
    the round-trip closed), so ``is_brain_reasoning_leg`` is False here and the
    gate behaves exactly as for external traffic — fail-closed.
    """
    request_id = f"relaxed-final-{uuid.uuid4().hex[:12]}"
    # 1) Response inspection on the candidate final text (non-relaxed).
    response_verdict = "clean"
    response_content_sensitivity: Optional[str] = None
    if _state.response_inspection_pipeline is not None and final_text:
        try:
            rid = identity.get("identity_id", request_id) if identity else request_id
            aid = identity.get("slug", "orchestrator") if identity else "orchestrator"
            # YSG-RISK-113: offload the blocking classifier call — see the
            # chat_completions call site above for the full rationale.
            resp_result = await asyncio.to_thread(
                _state.response_inspection_pipeline.inspect,
                response_body=final_text, content_type="text/plain",
                request_id=request_id, session_id=rid, agent_id=aid,
            )
            if not resp_result.skipped:
                response_verdict = resp_result.verdict.lower()
                response_content_sensitivity = resp_result.response_sensitivity
        except Exception as exc:
            # Fail-closed: an inspection error on a relaxed final must NOT pass.
            logger.warning("gate_relaxed_final: inspection raised (%s) — denying", exc)
            return False, (
                "[BLOCKED BY YASHIGANI RESPONSE INSPECTION] The orchestrator's final "
                "answer could not be cleared for delivery and was withheld.")
    # 1a) DETERMINISTIC secret/credential PRE-FLOOR (LAURA-ORCH leakfix).
    #     The classifier floor below (1b) catches sensitivity by CLASS (SSN,
    #     credit card, sk- keys) but MISSED a verbatim AWS_SECRET_ACCESS_KEY
    #     (no 40-char AWS pattern in its regex set; the suspicious-blob guard
    #     misses because trailing "KEY=" breaks the bare 40-char token) and is
    #     entirely defeated by a SPLIT-TOKEN payload ("First wJalr... then a
    #     slash then K7MDENG ..."), which classifies PUBLIC on every layer
    #     including ollama.  Both were live-proven by Laura.  The deterministic
    #     secret detector (pure-python, no LLM, fail-closed) normalises +
    #     de-obfuscates split forms, reassembles, and tests known key formats +
    #     an entropy floor.  A hit FORCES response_verdict="blocked" REGARDLESS
    #     of the LLM inspector verdict AND regardless of the caller's ceiling —
    #     deterministic, not ceiling-gated.  This is the headline leak-closure.
    if final_text:
        try:
            from yashigani.inspection import scan_secrets
            secret_verdict = scan_secrets(final_text)
        except Exception as exc:
            # Fail-closed: a scan error on a candidate final must NOT pass.
            logger.warning(
                "gate_relaxed_final: secret detector raised (%s) — denying "
                "(fail-closed)", exc)
            return False, (
                "[BLOCKED BY YASHIGANI RESPONSE INSPECTION] The orchestrator's "
                "final answer could not be cleared for delivery and was withheld.")
        if secret_verdict.is_secret:
            logger.warning(
                "gate_relaxed_final: DETERMINISTIC secret detector BLOCKED egress "
                "— detector=%s reassembled=%s span_hash=%s (ollama-inspector "
                "verdict was '%s'; deterministic block overrides it)",
                secret_verdict.detector, secret_verdict.reassembled,
                secret_verdict.span_hash, response_verdict)
            try:
                _metric_counter(
                    "yashigani_orchestration_secret_blocks_total",
                    "Deterministic secret-detector blocks on orchestration finals "
                    "(distinct from the ollama inspector). detector labels which "
                    "format/heuristic fired; reassembled=1 for split-token defeats.",
                    ["detector", "reassembled"],
                ).labels(
                    detector=secret_verdict.detector or "unknown",
                    reassembled=str(secret_verdict.reassembled).lower(),
                ).inc()
            except Exception:  # noqa: BLE001 — metric must never break the gate
                pass
            return False, (
                "[BLOCKED BY YASHIGANI RESPONSE INSPECTION] The orchestrator's "
                "final answer contained credential material and was withheld; "
                "the raw content was not delivered.")
    # 1b) DETERMINISTIC content-sensitivity floor (LAURA-ORCH leakfix, N2 pattern).
    #     The ResponseInspectionPipeline above is an LLM inspector — it is
    #     NON-deterministic and MISSES a secret on ~10-15% of finals, which is
    #     precisely how a verbatim AWS_SECRET_ACCESS_KEY reached the user even with
    #     the gate running.  So in ADDITION we run the REGEX layer of the sensitivity
    #     classifier over the final text and feed OPA the STRICTER of
    #     {inspection-sensitivity, regex-classified-sensitivity}.  A final carrying a
    #     known-pattern credential (API key, SSN, credit card, OFFICIAL-SENSITIVE,
    #     etc.) classifies CONFIDENTIAL/RESTRICTED deterministically → OPA denies →
    #     suppressed, independent of the LLM inspector.
    #
    #     B6 FIX (2.25.5): previously called classify_decoded() (full 3-layer
    #     pipeline including Ollama).  The Ollama layer is an INGRESS classifier
    #     trained on user prompts; running it on outbound prose summaries of CLEAN
    #     tool results caused false-positive RESTRICTED classifications (e.g.
    #     qwen2.5:3b marks "The tool returned: [query result]" as RESTRICTED), which
    #     forced response_verdict="blocked" on every clean orchestration final.
    #     The fix: use ONLY the REGEX layer here — it detects real credentials
    #     deterministically and produces zero false-positives on plain prose.  The
    #     scan_secrets() check (step 1a) already covers high-entropy key formats
    #     missed by the regex set.  The combined (regex + scan_secrets) floor is
    #     equivalent to the previous intent, without the Ollama false-positive.
    #
    #     INJECTION DEFENCE IS UNCHANGED: the cloud-9 / SYSTEM-OVERRIDE exfil
    #     payloads contain literal API-key patterns (sk-... etc.) that fire the
    #     regex CONFIDENTIAL/RESTRICTED → still blocked deterministically.
    if final_text and _state.sensitivity_classifier is not None:
        try:
            _regex_triggers: list[str] = []
            classified = _state.sensitivity_classifier._scan_regex(
                final_text, _regex_triggers).name
        except Exception as exc:
            # Fail-closed: a scan error on a candidate final must NOT pass.
            logger.warning(
                "gate_relaxed_final: regex classify raised (%s) — treating "
                "final as RESTRICTED (fail-closed)", exc)
            classified = "RESTRICTED"
        response_content_sensitivity = _stricter_sensitivity(
            response_content_sensitivity, classified)
        # A brain final that regex-classifies CONFIDENTIAL/RESTRICTED contains a
        # hard credential pattern.  Force a BLOCKED verdict so the response gate
        # denies deterministically.
        if classified in ("CONFIDENTIAL", "RESTRICTED"):
            logger.warning(
                "gate_relaxed_final: final regex-classifies %s — "
                "BLOCKING egress of sensitive orchestration final (triggers=%s)",
                classified, _regex_triggers)
            response_verdict = "blocked"
    # 1c) Deterministic block before OPA.  If step 1a (scan_secrets) or step 1b
    #     (regex classifier) forced response_verdict="blocked", deny immediately
    #     — independently of whether OPA is configured.  This ensures that
    #     hard-pattern credentials are blocked even in YASHIGANI_OPA_OPTIONAL=true
    #     deployments and in unit tests where OPA is not running.  This is the
    #     single authoritative block point for deterministic denials.
    if response_verdict == "blocked":
        return False, (
            "[BLOCKED BY YASHIGANI RESPONSE INSPECTION] The orchestrator's final "
            "answer was identified as sensitive and was withheld; "
            "the raw content was not delivered.")
    # 2) OPA response-leg gate (non-relaxed) — fail-closed on absent allow.
    if _state.opa_url:
        resp_opa = await _opa_response_check(
            identity=identity,
            response_sensitivity=response_content_sensitivity,
            prompt_sensitivity=prompt_sensitivity,
            response_verdict=response_verdict,
            pii_detected=False,
        )
        if not resp_opa.get("allow", False):
            reason = resp_opa.get("reason", "response_policy_denied")
            logger.warning(
                "gate_relaxed_final: relaxed brain final BLOCKED by non-relaxed "
                "response gate reason=%s — substituting neutral notice", reason)
            return False, (
                "[BLOCKED BY YASHIGANI POLICY] The orchestrator's final answer was "
                f"withheld by the response policy ({reason}); the raw content was "
                "not delivered.")
    return True, final_text


async def _opa_response_check(
    identity: dict | None,
    response_sensitivity: Optional[str],
    response_verdict: str,
    pii_detected: bool,
    prompt_sensitivity: Optional[str] = None,
) -> dict:
    """
    Query OPA v1_routing response_decision for allow/deny on response delivery.

    Checks whether the caller's sensitivity ceiling permits receiving
    content at the detected sensitivity level.

    v2.24.1 — GAP-3 / SEC-5:
        `response_sensitivity` is the response-CONTENT sensitivity (from the
        ResponseInspectionPipeline).  It may be None when the pipeline is
        disabled (default per YSG-RISK-057).
        `prompt_sensitivity` is the REQUEST (prompt) sensitivity from step 3.
        OPA receives both; v1_routing.rego evaluates MAX(prompt, response)
        — the stricter of the two.
        When response_sensitivity is None (pipeline off), it is omitted from
        the OPA input document, and the Rego rule falls back to prompt-only
        check (backward-compatible with pre-v2.24.1 callers).

    Zero-trust fail-closed behaviour (ASVS V8.* + V14.5.*):

    When OPA responds with allow: False  → audit event written, request denied.
    When OPA is unreachable / errors     → audit event written, REQUEST DENIED
                                           (fail-closed), Prometheus counter
                                           increments.  OPA outage = response
                                           delivery outage (intentional).
    When OPA is not configured           → REQUEST DENIED (fail-closed) unless
                                           YASHIGANI_OPA_OPTIONAL=true in a
                                           non-production YASHIGANI_ENV.

    Operator runbook:
      Alert on yashigani_opa_response_check_failures_total rate.
      An OPA outage causes response-delivery denials until OPA recovers.
      This is the CORRECT behaviour for a zero-trust system per
      feedback_zero_trust_default.md.  Do not bypass — fix OPA instead.

    NOTE: The previous docstring stated "allow on any error (fail-open)".
    That was incorrect.  This function is fail-closed since v2.23.4.
    """
    if not _state.opa_url:
        _ysg_env = os.getenv("YASHIGANI_ENV", "").strip().lower()
        _opa_optional = os.getenv("YASHIGANI_OPA_OPTIONAL", "false").strip().lower() == "true"
        if _opa_optional and _ysg_env != "production":
            logger.warning(
                "OPA not configured (YASHIGANI_OPA_OPTIONAL=true, env=%s) — "
                "allowing response without policy check (dev opt-in)",
                _ysg_env,
            )
            return {"allow": True, "reason": "opa_not_configured_dev_opt_in"}
        logger.error(
            "OPA response check: OPA not configured — denying (fail-closed) "
            "(env=%s, opa_optional=%s)",
            _ysg_env, _opa_optional,
        )
        opa_response_check_failures_total.labels(
            outcome="not_configured", reason="opa_not_configured"
        ).inc()
        if _state.audit_writer:
            try:
                _state.audit_writer.write(
                    OpaResponseCheckFailedEvent(
                        reason="opa_not_configured",
                        outcome="not_configured",
                        identity_id=identity.get("identity_id", "unknown") if identity else "anonymous",
                        response_sensitivity=str(response_sensitivity),
                        action="denied_fail_closed",
                    )
                )
            except Exception as _aw_exc:
                logger.warning("Audit write failed for OPA not-configured event: %s", _aw_exc)
        return {"allow": False, "reason": "opa_not_configured"}

    identity_doc = {
        "status": identity.get("status", "active") if identity else "anonymous",
        "kind": identity.get("kind", "unknown") if identity else "unknown",
        "sensitivity_ceiling": identity.get("sensitivity_ceiling", "RESTRICTED") if identity else "PUBLIC",
    }

    # v2.24.1 — GAP-3 / SEC-5: include both prompt and response sensitivity.
    # When response_sensitivity is None (pipeline off), OPA receives
    # prompt_sensitivity as the effective value — explicitly set for clarity.
    # When prompt_sensitivity is None (legacy callers), it is omitted from
    # the OPA input doc; v1_routing.rego falls back to response_sensitivity only
    # (backward-compatible with pre-v2.24.1 callers).
    _effective_response_sensitivity = response_sensitivity if response_sensitivity is not None else prompt_sensitivity
    opa_input: dict = {
        "identity": identity_doc,
        "response_sensitivity": _effective_response_sensitivity,
        "response_verdict": response_verdict,
        "pii_detected": pii_detected,
    }
    if prompt_sensitivity is not None:
        opa_input["prompt_sensitivity"] = prompt_sensitivity

    try:
        async with internal_httpx_client(timeout=5.0) as client:
            resp = await client.post(
                _state.opa_url.rstrip("/") + "/v1/data/yashigani/v1/response_decision",
                json={"input": opa_input},
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
            return {
                # Fail-closed (False default): if OPA returns HTTP 200 with body
                # {"result": {}} (undefined rule — bundle mismatch or partial load),
                # the absent "allow" key must resolve to DENY, not ALLOW. The Rego
                # rule always sets allow explicitly in normal operation so this has
                # no impact when OPA is healthy. Closes LAURA-V243-001 / YSG-RISK-071.
                "allow": bool(result.get("allow", False)),
                "reason": result.get("reason", "ok"),
            }
    except Exception as exc:
        # Path 1 (ASVS V8.* + V14.5.*): fail-closed on any OPA error.
        # Previous behaviour was fail-open (allow: True) with a misleading
        # comment "the audit trail captures the violation" — the audit was
        # NEVER written (OPA was unreachable).  Fixed in v2.23.4.
        exc_class = type(exc).__name__
        logger.error(
            "OPA response check FAILED — denying (fail-closed zero-trust). "
            "exc_class=%s exc=%s. OPA must be restored to re-enable response delivery. "
            "Alert on yashigani_opa_response_check_failures_total.",
            exc_class, exc,
        )
        opa_response_check_failures_total.labels(
            outcome="exception", reason=exc_class
        ).inc()
        if _state.audit_writer:
            try:
                _state.audit_writer.write(
                    OpaResponseCheckFailedEvent(
                        reason="opa_exception",
                        outcome="exception",
                        exc_class=exc_class,
                        exc_str=str(exc)[:256],
                        identity_id=identity.get("identity_id", "unknown") if identity else "anonymous",
                        response_sensitivity=str(response_sensitivity),
                        action="denied_fail_closed",
                    )
                )
            except Exception as _aw_exc:
                logger.warning("Audit write failed for OPA exception event: %s", _aw_exc)
        return {"allow": False, "reason": "opa_response_check_failed"}


async def _opa_models_check(identity: dict | None) -> dict:
    """
    Query OPA models_list_decision for GET /v1/models.

    Returns {"allow": bool, "filter": str, "reason": str}.
    "filter" is one of "full" | "restricted" | "denied".

    Fail-closed: OPA unreachable or not configured → deny (no topology
    enumeration without policy).

    Dev opt-in: YASHIGANI_OPA_OPTIONAL=true + non-production env →
    allow with filter="full" (mirrors _opa_v1_check dev mode).

    GAP-001 / ASVS V4.1.1 / OWASP API9 / Iris GAP-001 / YSG-RISK-066.
    """
    if not _state.opa_url:
        _ysg_env = os.getenv("YASHIGANI_ENV", "").strip().lower()
        _opa_optional = os.getenv("YASHIGANI_OPA_OPTIONAL", "false").strip().lower() == "true"
        if _opa_optional and _ysg_env != "production":
            logger.warning(
                "OPA not configured (YASHIGANI_OPA_OPTIONAL=true, env=%s) — "
                "allowing /v1/models without policy check (dev opt-in)",
                _ysg_env,
            )
            return {"allow": True, "filter": "full", "reason": "opa_not_configured_dev_opt_in"}
        logger.error(
            "OPA not configured and fail-closed triggered for /v1/models (env=%s, opa_optional=%s)",
            _ysg_env, _opa_optional,
        )
        opa_response_check_failures_total.labels(
            outcome="not_configured", reason="opa_not_configured"
        ).inc()
        return {"allow": False, "filter": "denied", "reason": "opa_not_configured"}

    identity_doc = {
        "status": identity.get("status", "active") if identity else "anonymous",
        "kind": identity.get("kind", "unknown") if identity else "unknown",
        "sensitivity_ceiling": (
            identity.get("sensitivity_ceiling", "RESTRICTED") if identity else "PUBLIC"
        ),
    }

    opa_input = {"identity": identity_doc}

    try:
        async with internal_httpx_client(timeout=5.0) as client:
            resp = await client.post(
                _state.opa_url.rstrip("/") + "/v1/data/yashigani/v1/models_list_decision",
                json={"input": opa_input},
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
            return {
                "allow": bool(result.get("allow", False)),
                "filter": result.get("filter", "denied"),
                "reason": result.get("reason", "unknown"),
            }
    except Exception as exc:
        logger.error("OPA models check failed: %s — denying (fail-closed)", exc)
        opa_response_check_failures_total.labels(
            outcome="exception", reason=type(exc).__name__
        ).inc()
        return {"allow": False, "filter": "denied", "reason": "opa_unreachable"}
