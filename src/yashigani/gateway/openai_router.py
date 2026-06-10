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

import hashlib
import hmac
import json
import logging
import math
import os
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
# Track C (F-B) — per-user identity through Open WebUI.
#
# THE GAP: Open WebUI (OWUI) authenticates to the gateway's internal mesh port
# (8081) with the shared `yashigani_internal_bearer`. Historically the resolver
# mapped that bearer to a flat `internal` service identity (RESTRICTED, empty
# allowed_models) BEFORE any per-user path, so every OWUI user shared one
# identity and per-user/group/org RBAC (models, agents, sensitivity ceiling)
# NEVER applied to OWUI traffic.
#
# THE FIX (trusted-forwarder model): the internal bearer establishes OWUI as a
# TRUSTED FORWARDER — exactly the same trust anchor already used for the
# orchestration-principal header. When (and ONLY when) a request carries the
# internal bearer, the gateway honours OWUI's forwarded-user headers
# (X-OpenWebUI-User-Email etc., emitted when ENABLE_FORWARD_USER_INFO_HEADERS=
# true on the OWUI service) and resolves the ACTUAL per-user Yashigani identity.
#
# MAPPING (email -> Yashigani identity), in priority order:
#   1. The forwarded email's local-part is matched as an identity SLUG
#      (alice@corp.example -> slug "alice"); if a registered identity exists,
#      that identity (with its own groups/allowed_models/sensitivity_ceiling)
#      is used. Operators provision OWUI users by creating a Yashigani identity
#      whose slug equals the user's email local-part.
#   2. Optionally, an explicit slug override map (YASHIGANI_OWUI_SLUG_MAP, JSON
#      object "email": "slug") lets an operator pin specific emails to slugs.
#   3. No match / missing / malformed email -> the configurable baseline
#      OWUI-users default identity (YASHIGANI_OWUI_DEFAULT_SLUG, default
#      "owui-users"). If that slug is not registered either, fall back to a
#      synthetic baseline-RESTRICTED identity (NEVER a higher privilege).
#
# SPOOFING DEFENSE (load-bearing): the forwarded-user header is honoured ONLY
# under the internal bearer. A direct/external caller WITHOUT the bearer can set
# X-OpenWebUI-User-* freely and it is IGNORED — the resolver never consults it
# off the internal-bearer path. Caddy also strips inbound X-OpenWebUI-User-* /
# X-Forwarded-User on the public path (defence in depth). Fail-closed: under the
# bearer, an unmatched/missing/malformed forwarded user resolves to the
# baseline-restricted default, NEVER to elevated privilege.
# ---------------------------------------------------------------------------
_OWUI_FORWARD_ENABLED: bool = (
    os.environ.get("YASHIGANI_OWUI_FORWARD_USER", "true").strip().lower() == "true"
)
_OWUI_DEFAULT_SLUG: str = os.environ.get(
    "YASHIGANI_OWUI_DEFAULT_SLUG", "owui-users"
).strip()
_OWUI_USER_EMAIL_HEADER = "x-openwebui-user-email"


def _load_owui_slug_map() -> dict[str, str]:
    """Parse YASHIGANI_OWUI_SLUG_MAP (JSON object email->slug). Fail-safe: {}."""
    raw = os.environ.get("YASHIGANI_OWUI_SLUG_MAP", "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return {str(k).strip().lower(): str(v).strip() for k, v in parsed.items() if v}
    except Exception as exc:  # malformed map must not break startup
        logger.warning("YASHIGANI_OWUI_SLUG_MAP is not valid JSON (%s) — ignoring", exc)
    return {}


_OWUI_SLUG_MAP: dict[str, str] = _load_owui_slug_map()


def _baseline_owui_identity() -> dict:
    """Synthetic fail-closed baseline for OWUI users with no registered identity.

    RESTRICTED ceiling, empty allowed_models — strictly the LOWEST privilege.
    Used only when neither the per-user slug NOR the configured default slug
    resolves to a registered identity. kind="service" keeps it out of the
    end-user seat count while still being subject to OPA RBAC. It is NEVER the
    `internal` identity_id, so the brain-reasoning marker cannot be tripped by
    an OWUI user (that marker keys on identity_id == "internal").
    """
    return {
        "identity_id": _OWUI_DEFAULT_SLUG or "owui-users",
        "status": "active",
        "kind": "service",
        "groups": ["owui-users"],
        "allowed_models": [],
        "sensitivity_ceiling": "RESTRICTED",
        "_owui_forwarded": True,
        "_owui_baseline": True,
    }


def _resolve_owui_forwarded_user(request: Request) -> Optional[dict]:
    """Resolve the ACTUAL OWUI user identity from forwarded headers.

    CALLED ONLY from the internal-bearer fast-path — i.e. the request is already
    proven to come from the trusted forwarder (OWUI). The forwarded-user header
    is therefore trustworthy at this point and never consulted elsewhere, which
    is the whole spoofing defence.

    Returns a registered identity dict (per-user RBAC applies) when the email
    maps to one; otherwise the configured default-slug identity; otherwise the
    synthetic baseline-RESTRICTED identity. NEVER returns None and NEVER returns
    a privilege higher than the matched identity — fail-closed by construction.
    Returns None only to signal "no forwarded user present" so the caller can
    fall through to the flat `internal` service identity (preserves the
    orchestration / brain path, which carries NO forwarded-user header).
    """
    if not _OWUI_FORWARD_ENABLED:
        return None
    email = request.headers.get(_OWUI_USER_EMAIL_HEADER, "").strip()
    if not email:
        # No forwarded user -> not an OWUI per-user call (e.g. brain self-call,
        # in-mesh agent). Caller falls back to flat `internal`.
        return None
    email_l = email.lower()

    # Registry unavailable -> fail-closed to baseline (NEVER internal/elevated).
    if _state.identity_registry is None:
        logger.warning(
            "OWUI forwarded user %r present but identity_registry unavailable — "
            "baseline-RESTRICTED", email,
        )
        return _baseline_owui_identity()

    # Resolve candidate slug: explicit map override first, else email local-part.
    slug = _OWUI_SLUG_MAP.get(email_l)
    if not slug:
        local_part = email_l.split("@", 1)[0]
        # Sanitise to the slug charset to avoid odd lookups; empty -> default.
        slug = "".join(ch for ch in local_part if ch.isalnum() or ch in "-_.").strip(".")

    identity = None
    if slug:
        try:
            identity = _state.identity_registry.get_by_slug(slug)
        except Exception as exc:  # registry blip — fail-closed to baseline
            logger.warning("OWUI slug lookup failed for %r (%s) — baseline", slug, exc)
            identity = None

    if identity:
        identity = dict(identity)
        identity["_owui_forwarded"] = True
        identity["_owui_email"] = email
        return identity

    # No per-user match -> configured default-slug identity if registered.
    if _OWUI_DEFAULT_SLUG:
        try:
            default_ident = _state.identity_registry.get_by_slug(_OWUI_DEFAULT_SLUG)
        except Exception:
            default_ident = None
        if default_ident:
            default_ident = dict(default_ident)
            default_ident["_owui_forwarded"] = True
            default_ident["_owui_email"] = email
            default_ident["_owui_default"] = True
            return default_ident

    # Nothing registered -> synthetic baseline-RESTRICTED.
    logger.info(
        "OWUI user %r mapped to baseline (no identity for slug %r, no default %r)",
        email, slug, _OWUI_DEFAULT_SLUG,
    )
    return _baseline_owui_identity()


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
    content: Optional[str] = Field(default=None, description="Message content")
    name: Optional[str] = None
    # assistant → requests tool calls
    tool_calls: Optional[list[ToolCall]] = None
    # role:"tool" → which assistant tool_call this message answers
    tool_call_id: Optional[str] = None


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
        self.available_models: list[dict] = []
        self.agent_registry = None
        self.response_inspection_pipeline = None
        self.ddos_protector = None  # v2.2 — DDoSProtector | None
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
    _state.available_models = available_models or []
    _state.agent_registry = agent_registry
    _state.response_inspection_pipeline = response_inspection_pipeline
    _state.ddos_protector = ddos_protector
    _state.pii_detector = pii_detector
    _state.pii_cloud_bypass = pii_cloud_bypass
    _state.opa_url = opa_url
    _state.content_relay_detector = content_relay_detector
    _state.pool_manager = pool_manager  # v2.4.1

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


def _sse_from_completion(completion: dict, headers: dict) -> StreamingResponse:
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
        raise HTTPException(
            status_code=401,
            detail={
                "error": "AUTHENTICATION_REQUIRED",
                "detail": (
                    "POST /v1/chat/completions requires an authenticated identity. "
                    "Provide Authorization: Bearer <api_key> or authenticate via "
                    "the SSO flow (X-Forwarded-User header from Caddy)."
                ),
                "request_id": request_id,
            },
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
        sensitivity_level = s_result.level.value
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
        budget_state = _state.budget_enforcer.check(
            identity_id, "cloud", budget_total=allocation,
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

    # Agent routing: if model starts with @, forward to the agent's upstream
    is_agent_call = selected_model.startswith("@")
    agent_upstream = None
    agent_protocol = "openai"
    if is_agent_call and _state.agent_registry:
        agent_name = selected_model[1:]  # strip @
        for agent in _state.agent_registry.list_all():
            if agent.get("name") == agent_name and agent.get("status") == "active":
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

    if _state.optimization_engine and _state.sensitivity_classifier and _state.complexity_scorer and not is_agent_call:
        decision = _state.optimization_engine.route(
            requested_model=selected_model,
            sensitivity=s_result,
            complexity=c_result,
            budget=budget_state,
            force_local=body.force_local or False,
            force_cloud=body.force_cloud or False,
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

    # ── 6a. OPA policy check (v2.2 — all /v1 traffic) ─────────────────
    # Evaluates v1_routing.rego: identity active, model allowed, routing
    # safety (CONFIDENTIAL never to untrusted cloud), sensitivity ceiling.
    # Fail-closed: any OPA error → deny.
    opa_decision = await _opa_v1_check(
        identity=identity,
        selected_model=selected_model,
        selected_provider=selected_provider if not is_agent_call else "agent",
        sensitivity_level=sensitivity_level,
        route_reason=route_reason,
        request_path="/v1/chat/completions",
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
                    "message": f"Request denied by policy: {opa_reason}",
                    "type": "policy_denied",
                    "code": opa_reason,
                }
            },
            headers={"X-Yashigani-OPA-Reason": opa_reason},
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
            content={"error": {"message": f"Request denied by client policy: {_ce_reason}",
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
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail={
                                "error": "pii_detected",
                                "detail": (
                                    "Request blocked: PII detected and PII mode is BLOCK "
                                    "for cloud-routed requests. Configure PII mode to REDACT "
                                    "or enable cloud bypass via the admin panel."
                                ),
                                "pii_types": [f.pii_type.value for f in _pii_result.findings],
                                # F-RT1: surface that an encoded payload was the trigger.
                                "matched_views": sorted(_pii_result.matched_views),
                                "request_id": request_id,
                            },
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
                                    raise HTTPException(
                                        status_code=status.HTTP_403_FORBIDDEN,
                                        detail={
                                            "error": "pii_detected_encoded",
                                            "detail": (
                                                "Request blocked: PII detected inside an "
                                                "encoded payload that cannot be redacted in "
                                                "place. Send the request without encoding or "
                                                "enable cloud bypass via the admin panel."
                                            ),
                                            "matched_views": sorted(_msg_res.matched_views),
                                            "request_id": request_id,
                                        },
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
                        _state.budget_enforcer.record(
                            identity_id=identity_id,
                            provider=selected_provider,
                            tokens=_total,
                        )
                    except Exception as _exc:
                        logger.warning("Streaming budget recording failed: %s", _exc)

            # Open a persistent streaming connection to Ollama.  The client must
            # stay alive for the duration of the generator, so we wrap the
            # response in a local async generator that owns the client lifetime.
            async def _sse_generator():
                async with httpx.AsyncClient(timeout=120.0) as _client:
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

            return StreamingResponse(
                _sse_generator(),
                media_type="text/event-stream",
                headers={
                    "X-Yashigani-Request-Id": request_id,
                    "X-Yashigani-Routed-Via": selected_provider,
                    "X-Yashigani-Route-Reason": route_reason.encode("ascii", "replace").decode("ascii"),
                    "X-Yashigani-Model": selected_model,
                    "X-Yashigani-Sensitivity": sensitivity_level,
                    "X-Yashigani-Complexity": complexity_level,
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
                },
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
                from pathlib import Path as _Path
                agent_headers: dict[str, str] = {"Content-Type": "application/json"}
                # Check env var first (e.g., OPENCLAW_GATEWAY_TOKEN), then secrets file
                env_token = os.getenv(f"{agent_name_lower.upper()}_GATEWAY_TOKEN", "")
                if not env_token:
                    # V232-CSCAN-01a: resolve-and-confine before touching the filesystem.
                    # agent_name_lower comes from the registry (admin-registered) and is
                    # constrained by AgentRegisterRequest.name pattern='^[a-z][a-z0-9_-]{0,63}$',
                    # but we guard here too as defence-in-depth against pre-existing registry
                    # entries that predate the pattern constraint (CWE-22).
                    _secrets_root = _Path("/run/secrets").resolve()
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

                try:
                    async with httpx.AsyncClient(timeout=120.0) as client:
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
            # Standard Ollama routing (buffered)
            ollama_body = {
                "model": selected_model if not is_agent_call else _state.default_model,
                "messages": [{"role": m.role, "content": m.content or ""} for m in body.messages],
                "stream": False,
            }
            if body.temperature is not None:
                ollama_body["temperature"] = body.temperature

            async with httpx.AsyncClient(timeout=120.0) as client:
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

            resp_result = _state.response_inspection_pipeline.inspect(
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
            _state.budget_enforcer.record(
                identity_id=identity_id,
                provider=selected_provider,
                tokens=total_tokens,
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
                            "message": f"Response blocked by policy: {resp_opa_reason}",
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
            content={"error": {"message": f"Response blocked by client policy: {_ce_eg_reason}",
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
    _pii_detected_any = pii_detected_on_request or pii_detected_on_response
    headers = {
        "X-Yashigani-Request-Id": request_id,
        "X-Yashigani-Routed-Via": selected_provider,
        "X-Yashigani-Route-Reason": route_reason.encode("ascii", "replace").decode("ascii"),
        "X-Yashigani-Model": selected_model,
        "X-Yashigani-Sensitivity": sensitivity_level,
        "X-Yashigani-Complexity": complexity_level,
        "X-Yashigani-Elapsed-Ms": str(elapsed_ms),
        "X-Yashigani-Response-Verdict": response_verdict,
        "X-Yashigani-PII-Detected": "true" if _pii_detected_any else "false",
        # F-T10-001: Overreliance UX controls — present on every LLM response.
        # Operator UIs use these to render generated-content badges and
        # low-confidence warnings (OWASP Agentic AI T10).
        "X-Yashigani-Generated-Content": "true",
        "X-Yashigani-Response-Inspection-Confidence": f"{response_inspection_confidence:.4f}",
    }
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
        return _sse_from_completion(_completion, headers)

    return JSONResponse(
        content=_completion,
        headers=headers,
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
    token or X-Forwarded-User header to enumerate.

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
        raise HTTPException(
            status_code=401,
            detail={
                "error": "AUTHENTICATION_REQUIRED",
                "detail": (
                    "GET /v1/models requires an authenticated identity. "
                    "Provide Authorization: Bearer <api_key> or authenticate "
                    "via the admin SSO flow."
                ),
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
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{_state.ollama_url}/api/tags")
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
    for m in _state.available_models:
        model_id = m.get("id", "")
        if opa_filter == "full" or (allowed_models_set is not None and model_id in allowed_models_set):
            models.append(ModelInfo(
                id=model_id,
                created=0,
                owned_by=m.get("provider", "yashigani"),
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


def _resolve_identity(request: Request) -> Optional[dict]:
    """
    Resolve identity from request.

    Priority:
    1. yashigani-internal Bearer token (mesh-port internal service calls)
    2. X-Forwarded-User header (SSO via Caddy)
    3. Authorization: Bearer <api_key> (registry lookup)

    The yashigani-internal check is intentionally placed BEFORE the
    identity_registry null-guard so that Open WebUI's hardcoded internal
    token resolves even when the identity registry is temporarily
    unavailable (e.g. Redis not yet reachable at startup).  Network
    isolation on the data bridge / K8s NetworkPolicy is the transport-
    layer guard for this token; it must never be reachable from the
    public-facing port.
    """
    # Fast path: hardcoded internal service-to-service token (Open WebUI,
    # in-mesh agents).  Must be checked before identity_registry to avoid
    # a 401 when the registry Redis is slow to start.
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        key = auth[7:]
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

            # ── Track C (F-B): OWUI trusted-forwarder per-user resolution ──
            # The internal bearer establishes OWUI as a TRUSTED FORWARDER. Only
            # here — having proven the bearer — do we honour OWUI's forwarded
            # user header (X-OpenWebUI-User-Email) and resolve the ACTUAL
            # per-user Yashigani identity so per-user/group/org RBAC applies.
            #
            # ORDERING: this runs AFTER the orchestration-principal check (which
            # is the brain/orchestration self-call path) and is gated on the
            # forwarded-user header being present. The brain reasoning leg and
            # in-mesh agent self-calls carry NO X-OpenWebUI-User-* header, so
            # they return None here and fall through to the flat `internal`
            # identity below — the brain-reasoning marker (keys on identity_id
            # == "internal") is preserved byte-for-byte.
            #
            # SPOOFING DEFENSE: because we are inside the proven-internal-bearer
            # branch, an external caller without the bearer never reaches this
            # code, so it can never set X-OpenWebUI-User-* to impersonate a user.
            owui_identity = _resolve_owui_forwarded_user(request)
            if owui_identity is not None:
                return owui_identity

            return {"identity_id": "internal", "status": "active", "kind": "service",
                    "groups": [], "allowed_models": [], "sensitivity_ceiling": "RESTRICTED",
                    "_orchestration_self_call": bool(orch_principal)}

    if not _state.identity_registry:
        return None

    # SSO headers (from Caddy)
    forwarded_user = request.headers.get("X-Forwarded-User")
    if forwarded_user:
        identity = _state.identity_registry.get_by_slug(forwarded_user)
        if identity:
            return identity

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


async def _opa_v1_check(
    identity: dict | None,
    selected_model: str,
    selected_provider: str,
    sensitivity_level: str,
    route_reason: str,
    request_path: str,
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
            return {"allow": True, "reason": "opa_not_configured_dev_opt_in"}
        logger.error(
            "OPA not configured and fail-closed triggered (env=%s, opa_optional=%s)",
            _ysg_env, _opa_optional,
        )
        opa_response_check_failures_total.labels(
            outcome="not_configured", reason="opa_not_configured"
        ).inc()
        return {"allow": False, "reason": "opa_not_configured"}

    identity_doc = {
        "status": identity.get("status", "active") if identity else "anonymous",
        "kind": identity.get("kind", "unknown") if identity else "unknown",
        "groups": identity.get("groups", []) if identity else [],
        "allowed_models": identity.get("allowed_models", []) if identity else [],
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
            resp_result = _state.response_inspection_pipeline.inspect(
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
    #     the gate running.  So in ADDITION we run the SAME deterministic
    #     sensitivity classifier the chat INGRESS leg uses (classify_decoded, which
    #     fail-closes to RESTRICTED) over the final text, and feed OPA the STRICTER
    #     of {inspection-sensitivity, deterministic-classified-sensitivity}.  A
    #     final carrying a credential classifies CONFIDENTIAL/RESTRICTED every time
    #     → OPA denies on the sensitivity ceiling → suppressed deterministically,
    #     independent of the inspector's verdict.  This mirrors the chat path, whose
    #     403 on the same secret comes from the deterministic classifier, not the
    #     LLM inspector.
    if final_text and _state.sensitivity_classifier is not None:
        try:
            classified = _state.sensitivity_classifier.classify_decoded(
                final_text).level.value
        except Exception as exc:
            # Fail-closed: an unclassifiable final must NOT pass on a clean verdict.
            logger.warning(
                "gate_relaxed_final: content classify raised (%s) — treating "
                "final as RESTRICTED (fail-closed)", exc)
            classified = "RESTRICTED"
        response_content_sensitivity = _stricter_sensitivity(
            response_content_sensitivity, classified)
        # A brain final that deterministically classifies CONFIDENTIAL/RESTRICTED
        # carries sensitive content (a secret, key, credential).  Such content must
        # NOT egress in an orchestration final REGARDLESS of the caller's ceiling —
        # the privileged internal-bearer service identity has a RESTRICTED ceiling,
        # so the ceiling check alone would admit it.  Force a BLOCKED verdict so the
        # response gate denies deterministically (the OPA response_decision denies
        # on response_verdict=="blocked").  This is the deterministic leak-closure:
        # it does not depend on the non-deterministic LLM inspector agreeing.
        if classified in ("CONFIDENTIAL", "RESTRICTED"):
            logger.warning(
                "gate_relaxed_final: final classifies %s (deterministic) — "
                "BLOCKING egress of sensitive orchestration final", classified)
            response_verdict = "blocked"
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
