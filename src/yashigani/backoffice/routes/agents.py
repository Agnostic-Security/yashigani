"""
Yashigani Backoffice — Agent registry admin routes.

All routes require an active admin session.
The plaintext PSK token is returned ONCE on register and rotate operations
and is never stored or re-derivable after that point.

After every mutation (register/update/deactivate/token rotate), the combined
RBAC + agent data document is pushed to OPA. Push failure is non-fatal for
the mutation — it is logged but does not roll back the registry change.

Routes:
  GET    /admin/agents                          — list all agents (AgentRegistry — service/machine agents)
  POST   /admin/agents                          — register new agent
  GET    /admin/agents/{agent_id}               — get agent detail
  PUT    /admin/agents/{agent_id}               — update agent fields
  DELETE /admin/agents/{agent_id}               — deactivate (soft delete)
  POST   /admin/agents/{agent_id}/token/rotate  — rotate PSK, return new token once
  POST   /admin/agents/{agent_id}/cert/rotate   — svid-sidecar self-rotation: re-mint
                                                  the caller's OWN per-instance leaf
                                                  (mTLS SPIFFE-gated, NO admin session —
                                                  v4.1 Phase 1, Nico Q1 must-fix #7)

  GET    /admin/identities                      — list HUMAN identities from IdentityRegistry
                                                  (v2.23.4 F4 fix — surfaces local-auth users who
                                                  have logged in at least once and been auto-registered
                                                  via da6de8b; also lists SSO-registered identities)

Last updated: 2026-07-06T00:00:00+00:00 (v4.1 Phase 1 — cert/rotate, Nico Q1)
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from yashigani.backoffice._ssrf import assert_safe_outbound_url

# ---------------------------------------------------------------------------
# AVA-2026-04-29-001 — Stored XSS: reject HTML tags in free-text agent fields
# (ASVS v5 V5.3.3 | CWE-79 | WSTG-INPV-02)
#
# The dashboard.js render layer uses escapeHtml() on agent name (defence-in-depth),
# but the API must reject stored XSS payloads before they reach the registry.
# Any value containing an HTML tag open sequence is rejected with HTTP 422.
# This closes the attack regardless of future render-layer changes.
#
# AVA-C006 — Protocol-URI bypass (ASVS v5 V5.3.3 | CWE-79 | OWASP A03):
# The original pattern only blocked angle-bracket HTML tags. A value such as
# `javascript:alert(1)` passes the angle-bracket check but executes if the UI
# ever renders agent names inside <a href="..."> attributes. Extend to
# case-insensitively match javascript:, data:, and vbscript: prefixes.
# ---------------------------------------------------------------------------
_HTML_TAG_RE = re.compile(r"(?i)(?:javascript:|data:|vbscript:|<[a-zA-Z/!])")

from yashigani.auth.spiffe import require_spiffe_id
from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SSRF guard for Open WebUI outbound calls — centralised HttpClient
# (YSG-RISK-007.A #3ax / yashigani-retro#95 OWASP A10 / API7)
# ---------------------------------------------------------------------------
# Replaces the hand-rolled _assert_safe_owui_url helper with the centralised
# HttpClient. The OWUI URL is admin-configured (OWUI_API_URL env var) and is
# typically an internal Docker-network address (http://open-webui:8080) so:
#   - allow_http=True   — internal mesh; HTTPS not available by default.
#   - allowlist driven by YASHIGANI_OWUI_HOSTNAMES (same env as before).
#   - Scheme still restricted to http/https (not file/gopher/etc).
#   - Hard-blocks: loopback, link-local, IMDS — inherited from HttpClient.
#
# The hand-rolled _assert_safe_owui_url is removed; all SSRF enforcement
# is now centralised in HttpClient._check_policy().
# ---------------------------------------------------------------------------

_OWUI_HTTP_CLIENT = None  # lazy-initialised on first use


def _owui_http_client():
    """Return a singleton HttpClient scoped to the OWUI allowlist."""
    global _OWUI_HTTP_CLIENT
    if _OWUI_HTTP_CLIENT is None:
        from yashigani.net import HttpClient

        raw_allowlist = os.getenv(
            "YASHIGANI_OWUI_HOSTNAMES",
            "open-webui,127.0.0.1,localhost",
        )
        allowlist = [h.strip() for h in raw_allowlist.split(",") if h.strip()]
        _OWUI_HTTP_CLIENT = HttpClient(
            allowlist=allowlist,
            allow_http=True,  # OWUI runs on plain HTTP inside the Docker mesh
            timeout_s=10.0,
        )
    return _OWUI_HTTP_CLIENT


router = APIRouter()


# ---------------------------------------------------------------------------
# SSRF / scheme allowlist for agent upstream_url (TM-V231-004, Pentest #95 2026-04-29)
# ---------------------------------------------------------------------------


def _assert_safe_upstream_url(url: str) -> str:
    """Assert that ``url`` is safe to store as an agent's upstream_url.

    Delegates to the shared SSRF guard (backoffice/_ssrf.py — FIND-3.0-001).
    Pentest #95 (TM-V231-004): previously hand-rolled inline; extracted into a
    shared helper so that every admin-configurable outbound URL (agents,
    SIEM endpoint, …) uses one tested guard.

    Allowed: http/https, public-routable hosts, or hosts in YASHIGANI_AGENT_UPSTREAM_HOSTNAMES.
    Rejected: non-http(s) scheme, loopback, link-local/IMDS, RFC-1918, multicast, reserved.

    Returns the URL unchanged on PASS. Raises ValueError on any violation
    (Pydantic v2 turns this into HTTP 422 with the structured error body).
    """
    return assert_safe_outbound_url(
        url,
        allowlist_env="YASHIGANI_AGENT_UPSTREAM_HOSTNAMES",
        label="upstream_url",
    )


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class AgentRegisterRequest(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_-]{0,63}$",
        description=(
            "Agent slug: lowercase letter, then lowercase alphanumeric, underscore, or hyphen. "
            "Max 64 chars. No path traversal chars permitted (V232-CSCAN-01a / CWE-22)."
        ),
    )
    # v2.4.1: upstream_url is Optional when pool_image is set.
    # For externally-deployed agents (today's behaviour), upstream_url is required.
    # For pool-managed agents, caller may either:
    #   (a) Set pool_image only — upstream_url is synthesised as pool://<image>.
    #   (b) Set both pool_image and upstream_url="pool://<image>" (must match).
    # A request with neither upstream_url nor pool_image is rejected (HTTP 422).
    upstream_url: Optional[str] = Field(default=None, min_length=1, max_length=512)
    protocol: str = Field(default="openai", description="Agent protocol: openai, letta, or langflow")
    groups: list[str] = Field(default_factory=list)
    allowed_caller_groups: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(
        default_factory=list,
        description="Optional CIDR allowlist. Empty = no IP restriction. E.g. ['10.0.0.0/8', '192.168.1.100/32']",
    )
    # v2.4.1 — PoolManager support.
    # When pool_image is set the agent is pool-managed: Yashigani will
    # create a per-identity container for each caller using this image.
    # The upstream_url MUST be absent or set to pool://<image> for consistency.
    # Tier limits (LicenseLimitExceeded -> 402) still apply.
    pool_image: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=512,
        description=(
            "Docker/OCI image for pool-managed agents. "
            "When set, upstream_url is synthesised as pool://<image> and "
            "Yashigani spawns a per-identity container at dispatch time. "
            "Leave unset for externally-deployed agents (today's behaviour)."
        ),
    )

    @field_validator("name")
    @classmethod
    def _reject_html_in_name(cls, v: str) -> str:
        """Reject HTML tags and protocol URIs in agent name (AVA-2026-04-29-001 / AVA-C006, ASVS V5.3.3, CWE-79)."""
        if _HTML_TAG_RE.search(v):
            raise ValueError(
                "agent name must not contain HTML tags or protocol URIs -- "
                "strip markup and use plain text (CWE-79 / AVA-2026-04-29-001 / AVA-C006)"
            )
        return v

    @field_validator("upstream_url")
    @classmethod
    def _validate_upstream_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        # pool:// is a synthetic internal scheme for pool-managed agents.
        # It is NOT an SSRF target -- the gateway resolves it via PoolManager.
        if v.startswith("pool://"):
            return v
        return _assert_safe_upstream_url(v)


# Pydantic v2: rebuild model so Optional type hints (with __future__ annotations)
# are correctly resolved at import time.
AgentRegisterRequest.model_rebuild()


class AgentUpdateRequest(BaseModel):
    name: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_-]{0,63}$",
        description=(
            "Agent slug: lowercase letter, then lowercase alphanumeric, underscore, or hyphen. "
            "Max 64 chars. No path traversal chars permitted (V232-CSCAN-01a / CWE-22)."
        ),
    )
    upstream_url: Optional[str] = Field(default=None, min_length=1, max_length=512)
    groups: Optional[list[str]] = None
    allowed_caller_groups: Optional[list[str]] = None
    allowed_paths: Optional[list[str]] = None
    allowed_cidrs: Optional[list[str]] = None

    @field_validator("name")
    @classmethod
    def _reject_html_in_name(cls, v: Optional[str]) -> Optional[str]:
        """Reject HTML tags and protocol URIs in agent name (AVA-2026-04-29-001 / AVA-C006, ASVS V5.3.3, CWE-79)."""
        if v is not None and _HTML_TAG_RE.search(v):
            raise ValueError(
                "agent name must not contain HTML tags or protocol URIs — "
                "strip markup and use plain text (CWE-79 / AVA-2026-04-29-001 / AVA-C006)"
            )
        return v

    @field_validator("upstream_url")
    @classmethod
    def _validate_upstream_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _assert_safe_upstream_url(v)


class AgentDeactivateRequest(BaseModel):
    reason: str = Field(default="", max_length=256)


class AgentResponse(BaseModel):
    agent_id: str
    name: str
    upstream_url: str
    status: str
    created_at: str
    last_seen_at: str
    groups: list
    allowed_caller_groups: list
    allowed_paths: list
    allowed_cidrs: list = Field(default_factory=list)
    # v0.9.0 — token rotation metadata (F-09)
    token_last_rotated: str = Field(default="")
    token_rotation_schedule: str = Field(default="")
    # 4.0 admin-UI surfacing (additive, backward-compatible). The registry already
    # decodes these (see registry._decode_agent); previously _to_response dropped
    # them so the admin SPA could not distinguish service agents from NHIs /
    # governed Langflow callees, nor show SVID/cert status. Defaults keep the
    # shape stable for pre-4.0 ("agent") entries which have no NHI block.
    #   kind         — "agent" | "nhi" | "persona" (callees register as kind="agent"
    #                  with the "user_agent_callee" group, see user_agents.commit_agent_template)
    #   svid_issued  — None for non-NHI; bool for NHI (admin-approval gate, RISK-097)
    #   spiffe_id    — minted SPIFFE id once an NHI SVID is approved
    #   owner_identity_id / template_id — NHI/callee lineage (which user/template)
    kind: str = Field(default="agent")
    svid_issued: Optional[bool] = Field(default=None)
    spiffe_id: str = Field(default="")
    owner_identity_id: str = Field(default="")
    template_id: str = Field(default="")


class AgentRegisterResponse(AgentResponse):
    # Token is only present on creation and rotation — never stored
    token: str = Field(description="Plaintext PSK token. Store immediately — never shown again.")
    quick_start: dict = Field(
        default_factory=dict,
        description="Copy-paste integration snippets for curl, Python, and health check.",
    )


class AgentRotateResponse(BaseModel):
    agent_id: str
    token: str = Field(description="New plaintext PSK token. Store immediately — never shown again.")
    quick_start: dict = Field(default_factory=dict)


class AgentCertRotateResponse(BaseModel):
    """Response for POST /admin/agents/{agent_id}/cert/rotate (v4.1 Phase 1, Nico Q1).

    Field names ``cert_pem`` / ``key_pem`` are the rotate.sh contract
    (docker/svid-sidecar/rotate.sh — grep-based extraction, do not rename).
    ``cert_pem`` is the leaf + intermediate bundle, byte-identical in shape to
    the install-time /init/client.crt.
    """
    agent_id: str
    spiffe_id: str
    cert_pem: str = Field(description="New leaf cert PEM bundle (leaf + intermediate).")
    key_pem: str = Field(description="New private key PEM. Delivered once over mTLS.")
    cert_not_after: str = Field(default="", description="ISO-8601 expiry of the new leaf.")


class AgentQuickStartResponse(BaseModel):
    agent_id: str
    quick_start: dict = Field(
        description="Copy-paste integration snippets (token placeholder — use your stored token)."
    )


class IdentityResponse(BaseModel):
    """
    Lightweight response model for a HUMAN identity in the IdentityRegistry.

    Returned by GET /admin/identities.  Only fields meaningful for the admin
    panel are included — the full registry record has many agent-oriented fields
    (system_prompt, capabilities, etc.) that are empty for auto-registered HUMAN
    identities created by local-auth login.
    """
    identity_id: str
    kind: str
    name: str
    slug: str
    description: str = Field(default="")
    status: str
    created_at: str
    last_seen_at: str = Field(default="")


# Pydantic v2: rebuild so Optional hints (with __future__ annotations) resolve.
AgentResponse.model_rebuild()
AgentRegisterResponse.model_rebuild()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_registry():
    reg = backoffice_state.agent_registry
    if reg is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent registry unavailable",
        )
    return reg


def _get_identity_registry():
    """Return identity_registry or raise 503 if not initialised (community-tier)."""
    reg = getattr(backoffice_state, "identity_registry", None)
    if reg is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "identity_registry_unavailable",
                "message": "Identity registry not available on this deployment tier.",
            },
        )
    return reg


def _to_response(agent: dict) -> AgentResponse:
    return AgentResponse(
        agent_id=agent["agent_id"],
        name=agent["name"],
        upstream_url=agent["upstream_url"],
        status=agent["status"],
        created_at=agent["created_at"],
        last_seen_at=agent["last_seen_at"],
        groups=agent["groups"],
        allowed_caller_groups=agent["allowed_caller_groups"],
        allowed_paths=agent["allowed_paths"],
        allowed_cidrs=agent.get("allowed_cidrs", []),
        token_last_rotated=agent.get("token_last_rotated", ""),
        token_rotation_schedule=agent.get("token_rotation_schedule", ""),
        # 4.0 admin-UI fields (additive). NHI-only fields default sensibly for
        # plain "agent" entries that have no NHI block in the registry decode.
        kind=agent.get("kind", "agent"),
        svid_issued=agent.get("svid_issued"),
        spiffe_id=agent.get("spiffe_id", ""),
        owner_identity_id=agent.get("owner_identity_id", ""),
        template_id=agent.get("template_id", ""),
    )


def _build_quick_start(agent_id: str, token: str) -> dict:
    """Build copy-paste integration snippets shown once on agent registration / token rotation."""
    gw = "<your-gateway-url>"
    return {
        "curl": (
            f"curl -X POST https://{gw}/mcp \\\n"
            f"  -H 'Authorization: Bearer {token}' \\\n"
            f"  -H 'Content-Type: application/json' \\\n"
            f'  -d \'{{"jsonrpc":"2.0","method":"tools/list","id":1}}\''
        ),
        "python_httpx": (
            f"import httpx\n"
            f"client = httpx.Client(\n"
            f"    base_url='https://{gw}',\n"
            f"    headers={{'Authorization': 'Bearer {token}'}}\n"
            f")\n"
            f'resp = client.post(\'/mcp\', json={{"jsonrpc":"2.0","method":"tools/list","id":1}})\n'
            f"print(resp.json())"
        ),
        "health_check": (f"curl https://{gw}/health -H 'Authorization: Bearer {token}'"),
        "note": (
            f"Replace '{gw}' with your actual gateway URL. Token shown once — store it securely. Agent ID: {agent_id}"
        ),
    }


async def _push_openwebui_model(agent_name: str, upstream_url: str) -> None:
    """
    Register agent as a selectable model in Open WebUI via its REST API.
    Non-fatal: logs on failure. Idempotent — skips if already exists.

    DNS-rebinding defence (extend-pr-112-owui-wrap / OWASP API7 / issue #91):
    OWUI hostnames are admin-configurable and can be attacker-influenced via
    licence-key compromise or admin-account takeover (TA-3 insider). The prior
    implementation ran a pre-flight _check_policy() and then made outbound
    requests via urllib.request.urlopen() — leaving a DNS-rebinding window
    between the policy check and the TCP connect. This version replaces
    urllib.request entirely with pinned_resolver, which resolves the OWUI
    hostname once, verifies the IP, and pins the transport for all requests
    inside the context block. Subsequent DNS changes cannot redirect the
    connection to an internal address.

    SSRF guard chain:
      1. _owui_http_client()._check_policy() — scheme + allowlist pre-flight
         (kept for non-async callers that may inspect policy without connecting)
      2. pinned_resolver(...) — resolves, verifies, pins IP; replaces urllib

    Every successful pin emits SSRF_PINNED_RESOLVER_USED at DEBUG level
    (emitted internally by pinned_resolver).
    """
    try:
        import time as _time
        import jwt as _pyjwt
        from urllib.parse import urlparse as _urlparse

        from yashigani.net import BlockedByPolicy
        from yashigani.net.pinned_resolver import pinned_resolver

        raw_owui_url = os.getenv("OWUI_API_URL", "http://open-webui:8080")

        # Pre-flight: scheme + allowlist check (fast path before DNS lookup).
        try:
            _owui_http_client()._check_policy(raw_owui_url)
        except BlockedByPolicy as _bp_exc:
            raise RuntimeError(f"owui_url_blocked: {_bp_exc} (CWE-918, YSG-RISK-007.A)") from _bp_exc

        owui_url = raw_owui_url
        parsed_owui = _urlparse(owui_url)
        owui_hostname = parsed_owui.hostname or ""
        owui_port = parsed_owui.port or (443 if parsed_owui.scheme == "https" else 80)

        # Build OWUI allowlist from env — same source as _owui_http_client().
        raw_allowlist = os.getenv(
            "YASHIGANI_OWUI_HOSTNAMES",
            "open-webui,127.0.0.1,localhost",
        )
        owui_allowlist = [h.strip() for h in raw_allowlist.split(",") if h.strip()]

        owui_secret = os.getenv("OWUI_SECRET_KEY")
        if not owui_secret:
            # Fail-closed: OWUI integration requires an explicit secret. The
            # installer generates this; refusing to fall back to a literal
            # default prevents compose-without-installer deployments from
            # shipping a publicly-known JWT signing key. See Compliance P0-1
            # (YCS-20260423-v2.23.1-OWASP-3X).
            raise RuntimeError(
                "OWUI_SECRET_KEY is not set — cannot authenticate to Open WebUI. "
                "Run install.sh to generate, or export it manually in the backoffice env."
            )

        # Generate a JWT for Open WebUI API auth.
        # Open WebUI itself uses PyJWT with WEBUI_SECRET_KEY — we use the same
        # library here (already an explicit dep; see gateway/jwt_inspector.py)
        # rather than hand-rolling HMAC/base64. Defence-in-depth: PyJWT has a
        # security track record, validates header shape, and avoids any
        # chance of alg-confusion from hand-rolled JSON encoding. Internal
        # P2 observation (re-audit reference held in compliance archive).
        payload_data = {
            "id": "00000000-0000-0000-0000-000000000000",
            "sub": "admin",
            "role": "admin",
            "exp": int(_time.time()) + 300,
        }
        owui_jwt = _pyjwt.encode(payload_data, owui_secret, algorithm="HS256")
        # PyJWT ≥2 returns str; older returned bytes. Normalise.
        if isinstance(owui_jwt, bytes):
            owui_jwt = owui_jwt.decode()

        model_id = "@" + agent_name
        req_headers = {
            "Authorization": f"Bearer {owui_jwt}",
            "Content-Type": "application/json",
        }

        # All outbound OWUI requests go through the pinned-resolver transport.
        # DNS is resolved and verified once at context entry; every HTTP call
        # inside the block uses the cached IP — DNS changes mid-block are ignored.
        # verify=use_tls: False for http:// (OWUI on plain HTTP inside Docker mesh);
        # httpx will not attempt TLS for http:// URLs regardless of the flag value.
        # True for https:// deployments — certificate validation is preserved.
        use_tls = parsed_owui.scheme == "https"
        async with pinned_resolver(
            owui_hostname,
            port=owui_port,
            allowlist=owui_allowlist,
            verify=use_tls,
            timeout_s=10.0,
        ) as session:
            # Check if model already exists
            check_resp = await session.get(
                f"{owui_url}/api/v1/models/{model_id}",
                headers=req_headers,
            )
            if check_resp.status_code == 200:
                logger.info("Open WebUI: model %s already exists", model_id)
                return
            if check_resp.status_code != 404:
                logger.warning(
                    "Open WebUI: model check returned unexpected status %s",
                    check_resp.status_code,
                )

            # Create model
            create_body = {
                "id": model_id,
                "name": agent_name + " Agent",
                "base_model_id": os.getenv("OLLAMA_MODEL", "qwen2.5:3b"),
                "meta": {
                    "description": f"Yashigani agent: {agent_name} @ {upstream_url}",
                    "profile_image_url": "",
                    "capabilities": {"usage": True},
                },
                "params": {},
                "is_active": True,
            }
            create_resp = await session.post(
                f"{owui_url}/api/v1/models/create",
                headers=req_headers,
                json=create_body,
            )
            if create_resp.status_code in (200, 201):
                logger.info("Open WebUI: registered model %s via pinned-resolver", model_id)
            else:
                logger.warning(
                    "Open WebUI: model create returned status %s",
                    create_resp.status_code,
                )
    except Exception as exc:
        logger.warning("_push_openwebui_model failed: %s", exc)


def _push_opa() -> None:
    """
    Push the combined RBAC + agent data to OPA after a registry mutation.
    Non-fatal: logs on failure but never raises.
    """
    try:
        from yashigani.rbac.opa_push import push_rbac_data

        rbac_store = backoffice_state.rbac_store
        if rbac_store is None:
            logger.warning("_push_opa: rbac_store not available — skipping OPA push")
            return
        push_rbac_data(
            store=rbac_store,
            opa_url=backoffice_state.opa_url,
            agent_registry=backoffice_state.agent_registry,
        )
    except Exception as exc:
        logger.error("_push_opa: OPA push failed after agent mutation: %s", exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/admin/agents", response_model=list[AgentResponse])
async def list_agents(session: AdminSession):
    registry = _get_registry()
    return [_to_response(a) for a in registry.list_all()]


@router.post(
    "/admin/agents",
    response_model=AgentRegisterResponse,
    status_code=201,
    dependencies=[Depends(require_spiffe_id("/admin/agents"))],
)
async def register_agent(
    body: AgentRegisterRequest,
    session: StepUpAdminSession,
):
    registry = _get_registry()
    audit = backoffice_state.audit_writer

    # GROUP-4-1 / LAURA-LIMIT-AGENTS-01: agent limit is enforced atomically
    # inside registry.register() via a Lua script (SCARD -> check -> HSET+SADD).
    # The previous non-atomic pre-check (check_agent_limit(registry.count()))
    # had a TOCTOU race and is removed here. LicenseLimitExceeded is raised by
    # the Lua path on breach and caught below.
    from yashigani.licensing.enforcer import LicenseLimitExceeded

    # v2.4.1 -- pool_image support: synthesise upstream_url and validate consistency.
    # Rule:
    #   pool_image=None, upstream_url=str  -> externally-deployed agent (status quo)
    #   pool_image=str,  upstream_url=None -> synthesise pool://<image>
    #   pool_image=str,  upstream_url="pool://<image>" (matches) -> OK
    #   pool_image=str,  upstream_url=<anything else> -> HTTP 422
    #   pool_image=None, upstream_url=None -> HTTP 422 (nothing to register)
    if body.pool_image is None and body.upstream_url is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "upstream_url_required",
                "message": "upstream_url is required when pool_image is not set.",
            },
        )

    effective_upstream_url: str
    if body.pool_image is not None:
        expected_pool_url = f"pool://{body.pool_image}"
        if body.upstream_url is not None and body.upstream_url != expected_pool_url:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "pool_url_mismatch",
                    "message": (
                        f"When pool_image is set, upstream_url must be "
                        f"'pool://{body.pool_image}' (got {body.upstream_url!r}). "
                        "Either omit upstream_url or set it to the pool:// form."
                    ),
                },
            )
        effective_upstream_url = expected_pool_url
    else:
        effective_upstream_url = body.upstream_url  # type: ignore[assignment]

    try:
        agent_id, plaintext_token = registry.register(
            name=body.name,
            upstream_url=effective_upstream_url,
            groups=body.groups,
            allowed_caller_groups=body.allowed_caller_groups,
            allowed_paths=body.allowed_paths,
            allowed_cidrs=body.allowed_cidrs,
            protocol=body.protocol,
        )
    except LicenseLimitExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={"error": "agent_limit_exceeded", "limit": exc.max_val, "current": exc.current},
        )

    agent = registry.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=500, detail="Agent created but not retrievable")

    # Audit. Use session.account_id (mirrors users.py pattern) — Session
    # dataclass has no `username` attribute; the previous `session.username`
    # reference silently failed and AGENT_REGISTERED events never landed in
    # the audit log (QA Wave 2 Issue B).
    if audit is not None:
        try:
            from yashigani.audit.schema import AgentRegisteredEvent

            audit.write(
                AgentRegisteredEvent(
                    agent_id=agent_id,
                    agent_name=body.name,
                    upstream_url=effective_upstream_url,
                    groups=body.groups,
                    allowed_caller_groups=body.allowed_caller_groups,
                    allowed_paths=body.allowed_paths,
                    admin_account=session.account_id,
                )
            )
        except Exception as exc:
            logger.error("Failed to write AgentRegisteredEvent: %s", exc)

    _push_opa()
    # Pool-managed agents have no real upstream URL; skip OWUI model push.
    if not effective_upstream_url.startswith("pool://"):
        await _push_openwebui_model(body.name, effective_upstream_url)

    return AgentRegisterResponse(
        agent_id=agent_id,
        name=agent["name"],
        upstream_url=agent["upstream_url"],
        status=agent["status"],
        created_at=agent["created_at"],
        last_seen_at=agent["last_seen_at"],
        groups=agent["groups"],
        allowed_caller_groups=agent["allowed_caller_groups"],
        allowed_paths=agent["allowed_paths"],
        allowed_cidrs=agent.get("allowed_cidrs", []),
        token=plaintext_token,
        quick_start=_build_quick_start(agent_id, plaintext_token),
    )


@router.get("/admin/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    session: AdminSession,
):
    registry = _get_registry()
    agent = registry.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _to_response(agent)


@router.put(
    "/admin/agents/{agent_id}",
    response_model=AgentResponse,
    dependencies=[Depends(require_spiffe_id("/admin/agents"))],
)
async def update_agent(
    agent_id: str,
    body: AgentUpdateRequest,
    session: StepUpAdminSession,
):
    registry = _get_registry()
    audit = backoffice_state.audit_writer

    # Verify agent exists
    existing = registry.get(agent_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Build update kwargs — only include fields actually provided
    updates: dict[str, Any] = {}
    changed_fields = []
    if body.name is not None:
        updates["name"] = body.name
        changed_fields.append("name")
    if body.upstream_url is not None:
        updates["upstream_url"] = body.upstream_url
        changed_fields.append("upstream_url")
    if body.groups is not None:
        updates["groups"] = body.groups
        changed_fields.append("groups")
    if body.allowed_caller_groups is not None:
        updates["allowed_caller_groups"] = body.allowed_caller_groups
        changed_fields.append("allowed_caller_groups")
    if body.allowed_paths is not None:
        updates["allowed_paths"] = body.allowed_paths
        changed_fields.append("allowed_paths")
    if body.allowed_cidrs is not None:
        updates["allowed_cidrs"] = body.allowed_cidrs
        changed_fields.append("allowed_cidrs")

    if updates:
        registry.update(agent_id, **updates)

    # Audit
    if audit is not None and changed_fields:
        try:
            from yashigani.audit.schema import AgentUpdatedEvent

            audit.write(
                AgentUpdatedEvent(
                    agent_id=agent_id,
                    changed_fields=changed_fields,
                    admin_account=session.account_id,
                )
            )
        except Exception as exc:
            logger.error("Failed to write AgentUpdatedEvent: %s", exc)

    if updates:
        _push_opa()

    updated = registry.get(agent_id)
    return _to_response(updated)


@router.delete(
    "/admin/agents/{agent_id}",
    status_code=204,
    dependencies=[Depends(require_spiffe_id("/admin/agents"))],
)
async def deactivate_agent(
    agent_id: str,
    session: StepUpAdminSession,
    body: Optional[AgentDeactivateRequest] = None,
):
    registry = _get_registry()
    audit = backoffice_state.audit_writer

    existing = registry.get(agent_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if existing.get("status") == "inactive":
        raise HTTPException(status_code=409, detail="Agent already inactive")

    reason = (body.reason if body else "") or ""
    registry.deactivate(agent_id)

    # v4.1 Phase 1a GAP-4 — NHI deactivate revokes the runtime-manifest
    # identity entry so the OPA baseline push / sidecar binding check fails
    # the instance immediately (not at cert expiry). Best-effort: a missing
    # manifest/entry is logged by the issuer, never blocks deactivation.
    if existing.get("kind") == "nhi":
        try:
            from pathlib import Path as _Path
            from yashigani.pki.issuer import IssuerPaths, revoke_agent_identity

            _pki_paths = IssuerPaths(
                secrets_dir=_Path(os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")),
                manifest_path=_Path(os.getenv(
                    "YASHIGANI_SERVICE_MANIFEST_PATH",
                    "/etc/yashigani/service_identities.yaml",
                )),
            )
            revoke_agent_identity(
                _pki_paths,
                tenant_id=existing.get("owner_identity_id", "tenant"),
                agent_name=existing.get("name", agent_id),
                instance_id=agent_id,
            )
        except Exception as exc:
            logger.error(
                "NHI deactivate: runtime-manifest revocation failed for %s "
                "(deactivation itself succeeded — registry indexes cleared): %s",
                agent_id, exc,
            )

    # Audit
    if audit is not None:
        try:
            from yashigani.audit.schema import AgentDeactivatedEvent

            audit.write(
                AgentDeactivatedEvent(
                    agent_id=agent_id,
                    admin_account=session.account_id,
                    reason=reason,
                )
            )
        except Exception as exc:
            logger.error("Failed to write AgentDeactivatedEvent: %s", exc)

    _push_opa()


@router.post(
    "/admin/agents/{agent_id}/token/rotate",
    response_model=AgentRotateResponse,
    dependencies=[Depends(require_spiffe_id("/admin/agents"))],
)
async def rotate_agent_token(
    agent_id: str,
    session: StepUpAdminSession,
):
    registry = _get_registry()
    audit = backoffice_state.audit_writer

    existing = registry.get(agent_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    plaintext_token = registry.rotate_token(agent_id)

    # Audit
    if audit is not None:
        try:
            from yashigani.audit.schema import AgentTokenRotatedEvent

            audit.write(
                AgentTokenRotatedEvent(
                    agent_id=agent_id,
                    admin_account=session.account_id,
                )
            )
        except Exception as exc:
            logger.error("Failed to write AgentTokenRotatedEvent: %s", exc)

    _push_opa()

    return AgentRotateResponse(
        agent_id=agent_id,
        token=plaintext_token,
        quick_start=_build_quick_start(agent_id, plaintext_token),
    )


# ---------------------------------------------------------------------------
# v4.1 Phase 1 — POST /admin/agents/{agent_id}/cert/rotate
# (Nico Q1 — unified-sidecar review must-fix #7, BLOCKER)
#
# The svid-sidecar (docker/svid-sidecar/rotate.sh:180) POSTs here over mTLS
# when < RENEWAL_THRESHOLD_FRAC of the leaf lifetime remains.  The endpoint
# was ACL'd (service_identities.yaml:398-404) and documented
# (Dockerfile.svid-sidecar) since 4.0 Phase 0 but never implemented —
# continuously-running bundled agents hard-failed at leaf expiry (≤90d).
#
# Design (per the review synthesis):
#   * Key off the PRESENTED cert's FULL per-instance SPIFFE — NOT the
#     {agent_id} path param / sidecar AGENT_ID env, which is the bare server
#     name (codegen.py) and ambiguous across tenants/instances.  The path
#     param is only cross-checked by the ACL gate
#     (verify_spiffe_matches_agent_id).
#   * Re-mint with the SAME instance_id (nhi_id) + the registry-CURRENT
#     scope_hash / image_digest from the durable approval record.
#   * DENY (409) if the tool surface CHANGED since approval — a changed
#     surface must go through re-approval; silently re-binding it at rotation
#     would bypass change-prevention (GAP-2).
#   * No admin session: possession of the CURRENT (unexpired, unrevoked)
#     agent leaf is the rotation credential, enforced by the mTLS listener +
#     the SPIFFE ACL gate.  Only the agent's own identity passes the gate for
#     its own {agent_id}; exact-id callers (caddy/backoffice) never parse as
#     agent SPIFFEs and are refused below.
# ---------------------------------------------------------------------------

_CERT_ROTATE_ACL_PATH = "/admin/agents/*/cert/rotate"


def _rotate_pki_paths():
    """IssuerPaths from the live env (same wiring as approve/deactivate)."""
    from pathlib import Path as _Path
    from yashigani.pki.issuer import IssuerPaths

    return IssuerPaths(
        secrets_dir=_Path(os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")),
        manifest_path=_Path(os.getenv(
            "YASHIGANI_SERVICE_MANIFEST_PATH",
            "/etc/yashigani/service_identities.yaml",
        )),
    )


def _runtime_manifest_agent_entry(pki_paths: Any, entry_name: str) -> Optional[dict]:
    """Return the runtime-manifest entry for *entry_name*, or None when absent.

    The runtime manifest (mint_agent_leaf appends; revoke_agent_identity flips
    ``revoked``) is the durable record of EVERY minted agent identity —
    including install.sh CLI mints that have no registry/envelope row.
    Fail-closed: an unreadable manifest raises 503 (we cannot prove the
    identity is still live, so we refuse to re-mint).
    """
    import yaml as _yaml

    runtime_path = pki_paths.runtime_manifest
    if not runtime_path.exists():
        return None
    try:
        doc = _yaml.safe_load(runtime_path.read_text()) or {}
    except Exception as exc:
        logger.error("cert-rotate: runtime manifest unreadable at %s: %s", runtime_path, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "runtime_manifest_unreadable",
                "message": "Agent identity manifest unreadable — rotation refused (fail-closed).",
            },
        )
    for entry in doc.get("agent_identities") or []:
        if isinstance(entry, dict) and entry.get("name") == entry_name:
            return entry
    return None


def _deny_surface_changed(spiffe_id: str, approved: str, current: str) -> HTTPException:
    logger.warning(
        "cert-rotate: DENIED — tool surface changed since approval for %s "
        "(approved=%s current=%s). Re-approval required.",
        spiffe_id, approved[:24], current[:24],
    )
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "error": "surface_changed_reapproval_required",
            "message": (
                "The agent's tool surface changed since it was approved. "
                "Rotation would re-bind an unapproved surface (change-prevention "
                "bypass). Re-approve the agent (admin approval flow) to mint a "
                "new identity; the current cert stays valid until its expiry."
            ),
        },
    )


@router.post(
    "/admin/agents/{agent_id}/cert/rotate",
    response_model=AgentCertRotateResponse,
)
async def rotate_agent_cert(
    agent_id: str,
    caller_spiffe: str = Depends(require_spiffe_id(_CERT_ROTATE_ACL_PATH)),
):
    """Re-mint the CALLING agent's own leaf cert (svid-sidecar rotation).

    Identity is the presented client cert's SPIFFE URI (Caddy/middleware
    validated) — the ``agent_id`` path param is only the ACL-gate cross-check.
    """
    from yashigani.identity.trust_domain import parse_agent_spiffe_uri
    from yashigani.pki.binding import tool_surface_hash
    from yashigani.pki.issuer import IssuerPaths, mint_agent_leaf

    parsed = parse_agent_spiffe_uri(caller_spiffe)
    if parsed is None:
        # caddy/backoffice pass the ACL's exact-id list but carry no agent
        # identity — there is nothing they could rotate "as themselves".
        # Admin-initiated re-issuance is the approve flow, not this endpoint.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "cert_rotate_requires_agent_identity",
                "message": (
                    "Only an agent's own svid-sidecar identity may rotate its "
                    "cert. Use the admin approval flow to (re-)issue agent "
                    "identities."
                ),
            },
        )
    tenant_id, agent_name, instance_id = parsed

    pki_paths = _rotate_pki_paths()
    entry_name = IssuerPaths.agent_entry_name(tenant_id, agent_name, instance_id)

    # 1. Durable identity record — runtime manifest (covers CLI-minted bundled
    #    agents too).  Fail-closed on absent or revoked entries.
    entry = _runtime_manifest_agent_entry(pki_paths, entry_name)
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "identity_not_provisioned",
                "message": "No minted identity record exists for this SPIFFE ID.",
            },
        )
    if entry.get("revoked"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "identity_revoked",
                "message": "This agent identity is revoked — rotation refused.",
            },
        )
    entry_spiffe = entry.get("spiffe_id", "")
    if entry_spiffe and entry_spiffe != caller_spiffe:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "spiffe_identity_mismatch",
                "message": "Presented SPIFFE ID does not match the minted identity record.",
            },
        )

    # 2. Approval record + change-prevention (GAP-2).  Instanced identities
    #    (3-segment SPIFFE) MUST have a durable approval record; the
    #    registry-CURRENT scope_hash / image_digest are re-bound at mint.
    scope_hash = ""
    image_digest = ""
    if instance_id:
        reg = backoffice_state.agent_registry
        nhi = reg.get(instance_id) if reg is not None else None
        if nhi is not None:
            # 2a. Registry NHI (approve_nhi_svid / user_agents instantiate path).
            if nhi.get("kind") != "nhi" or not nhi.get("svid_issued"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "identity_not_approved",
                        "message": "Agent has no approved SVID — rotation refused.",
                    },
                )
            if nhi.get("status") != "active":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "identity_not_active",
                        "message": "Agent is not active — rotation refused.",
                    },
                )
            if nhi.get("spiffe_id", "") != caller_spiffe:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "spiffe_identity_mismatch",
                        "message": "Presented SPIFFE ID does not match the registry record.",
                    },
                )
            approved_scope = nhi.get("scope_hash") or ""
            current_scope = tool_surface_hash(nhi.get("allowed_tools") or [])
            if approved_scope and current_scope != approved_scope:
                raise _deny_surface_changed(caller_spiffe, approved_scope, current_scope)
            scope_hash = approved_scope or current_scope
            image_digest = nhi.get("image_digest") or ""
        else:
            # 2b. MCP-onboarded instance (mcp_onboard approve transaction) —
            #     the ACTIVE capability envelope is the durable approval record.
            from yashigani.backoffice.routes.mcp_servers import (
                _durable_registry_store,
                _envelope_service,
            )

            svc = _envelope_service()  # raises 503 when the DB pool is down
            rec = await svc.get_active_envelope(f"{tenant_id}:{agent_name}")
            if rec is None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "identity_record_not_found",
                        "message": (
                            "No durable approval record exists for this "
                            "per-instance identity — rotation refused (fail-closed)."
                        ),
                    },
                )
            if (
                not rec.svid_issued
                or rec.svid_instance_id != instance_id
                or rec.svid_spiffe_id != caller_spiffe
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "identity_superseded_reapproval_required",
                        "message": (
                            "Presented identity does not match the active approval "
                            "record (server re-onboarded or SVID superseded). "
                            "Re-approve to mint a fresh identity."
                        ),
                    },
                )
            # Change-prevention: current_surface_hash advances on triage
            # re-pins; surface_set_hash is the approved set.  Drift ⇒ deny.
            if (
                rec.current_surface_hash
                and rec.surface_set_hash
                and rec.current_surface_hash != rec.surface_set_hash
            ):
                raise _deny_surface_changed(
                    caller_spiffe, rec.surface_set_hash, rec.current_surface_hash
                )
            # Registry-CURRENT surface — same computation as the approve mint
            # (mcp_onboard.py: tool_surface_hash(sorted(env.tools.keys()))).
            scope_hash = tool_surface_hash(sorted(rec.envelope.tools.keys()))
            store = _durable_registry_store()
            descriptor = store.get(tenant_id, agent_name) if store is not None else None
            if descriptor is not None:
                image_digest = descriptor.get("image_digest", "") or ""
                baseline = store.get_baseline(tenant_id, agent_name)
                baseline_hash = (baseline or {}).get("surface_hash", "")
                if baseline_hash and baseline_hash != scope_hash:
                    raise _deny_surface_changed(caller_spiffe, baseline_hash, scope_hash)
            else:
                logger.warning(
                    "cert-rotate: durable broker registry unavailable for %s — "
                    "re-minting with image_digest='' (binding covers the tool "
                    "surface only; see pki/binding.py).",
                    caller_spiffe,
                )
    # Legacy 2-segment identities (install.sh CLI mints — bundled agents):
    # no registry/envelope record exists by design; the runtime-manifest check
    # above is the authorisation record.  scope_hash/image_digest stay "" —
    # byte-identical re-mint of the legacy identity (no binding extension),
    # matching the original CLI issuance.

    # 3. Re-mint — same instance_id, registry-current binding inputs.
    try:
        new_spiffe = mint_agent_leaf(
            pki_paths,
            tenant_id=tenant_id,
            agent_name=agent_name,
            instance_id=instance_id,
            scope_hash=scope_hash,
            image_digest=image_digest,
            approved_by=f"svid-rotation:{caller_spiffe}",
            audit_writer=backoffice_state.audit_writer,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("cert-rotate: mint_agent_leaf FAILED for %s: %s", caller_spiffe, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "pki_mint_failed",
                "message": "Leaf re-issuance failed — existing cert remains valid until expiry.",
            },
        )

    if new_spiffe != caller_spiffe:
        # Invariant: same (tenant, name, instance) must reproduce the same
        # SPIFFE URI.  A mismatch means trust-domain drift — never hand out
        # a cert for a different identity than the caller presented.
        logger.error(
            "cert-rotate: minted SPIFFE %r != presented %r — trust-domain drift? "
            "Response withheld (fail-closed).", new_spiffe, caller_spiffe,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "identity_mismatch_after_mint"},
        )

    cert_pem = pki_paths.agent_cert(tenant_id, agent_name, instance_id).read_text()
    key_pem = pki_paths.agent_key(tenant_id, agent_name, instance_id).read_text()

    cert_not_after = ""
    try:
        from cryptography import x509 as _x509

        cert_not_after = _x509.load_pem_x509_certificates(
            cert_pem.encode()
        )[0].not_valid_after_utc.isoformat()
    except Exception as exc:  # pragma: no cover — informational field only
        logger.warning("cert-rotate: could not parse new cert not_after: %s", exc)

    logger.info(
        "cert-rotate: re-minted leaf for %s (agent_id path=%r, not_after=%s)",
        caller_spiffe, agent_id, cert_not_after,
    )

    return AgentCertRotateResponse(
        agent_id=agent_id,
        spiffe_id=new_spiffe,
        cert_pem=cert_pem,
        key_pem=key_pem,
        cert_not_after=cert_not_after,
    )


@router.get("/admin/agents/{agent_id}/quickstart", response_model=AgentQuickStartResponse)
async def get_agent_quickstart(
    agent_id: str,
    session: AdminSession,
):
    """Return copy-paste integration snippets for the agent detail page.

    The token placeholder ``<your-token>`` is used in place of the actual
    token, which is only available at registration / rotation time.
    """
    registry = _get_registry()
    agent = registry.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return AgentQuickStartResponse(
        agent_id=agent_id,
        quick_start=_build_quick_start(agent_id, "<your-token>"),
    )


# ---------------------------------------------------------------------------
# v2.23.4 F4 — GET /admin/identities
# Surfaces HUMAN identities from IdentityRegistry.  Local-auth users who
# have logged in at least once are auto-registered by da6de8b; SSO users are
# registered by sso.py on first OIDC/SAML callback.
#
# Separate from GET /admin/agents (AgentRegistry — service/machine agents)
# because the two registries have different schemas and lifecycle semantics.
# The admin panel can call both endpoints to give operators a complete picture
# of all authenticated principals: service agents + HUMAN users.
# ---------------------------------------------------------------------------


@router.get("/admin/identities", response_model=list[IdentityResponse])
async def list_identities(
    session: AdminSession,
    kind: Optional[str] = None,
):
    """
    List identities from the IdentityRegistry.

    Optional ``kind`` filter: ``human`` | ``service``.  Defaults to all.
    Returns 503 if the identity registry is not available (community-tier).
    """
    from yashigani.identity.registry import IdentityKind

    registry = _get_identity_registry()

    kind_filter: Optional[IdentityKind] = None
    if kind is not None:
        try:
            kind_filter = IdentityKind(kind.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "invalid_kind",
                    "message": f"Unknown kind {kind!r}. Valid values: human, service.",
                },
            )

    identities = registry.list_all(kind=kind_filter)
    return [
        IdentityResponse(
            identity_id=ident["identity_id"],
            kind=ident["kind"],
            name=ident["name"],
            slug=ident["slug"],
            description=ident.get("description", ""),
            status=ident["status"],
            created_at=ident.get("created_at", ""),
            last_seen_at=ident.get("last_seen_at", ""),
        )
        for ident in identities
    ]


# ---------------------------------------------------------------------------
# NHI SVID approval (4.0 Phase 3 — RISK-097 / admin-approval-gated SVID)
#
# POST /admin/nhi/{nhi_id}/approve
#
# Requires StepUpAdminSession (ASVS V6.8.4 — step-up TOTP for high-value ops).
#
# Flow (BUG-A v4.1 Phase 0 — mint BEFORE approve, fail-closed):
#   1. Validate nhi_id refers to a registered NHI (kind="nhi").
#   2. Call mint_agent_leaf() to issue the PKI leaf cert (internal-CA mode).
#      Fail-closed: mint failure → NhiSvidIssuanceFailedEvent audit + 502;
#      svid_issued is NOT set and the NHI stays NHI_PENDING_APPROVAL.
#   3. Call registry.approve_svid(nhi_id) — sets svid_issued=1, adds to active index.
#   4. Emit NhiSvidApprovedEvent to the tamper-evident audit hash-chain.
#   5. Return {nhi_id, spiffe_id, approved: True}.
#
# Fail-closed: unknown nhi_id or non-NHI kind → 404; PKI mint failure → 502.
# ---------------------------------------------------------------------------


@router.post("/admin/nhi/{nhi_id}/approve", status_code=200)
async def approve_nhi_svid(
    nhi_id: str,
    session: StepUpAdminSession,
):
    """Admin-approve an NHI SVID (step-up required, RISK-097).

    Issues a PKI leaf cert for the NHI's SPIFFE identity FIRST, then
    transitions svid_issued=False → True in the agent registry so the NHI
    can be resolved by the gateway (``_resolve_nhi_identity`` checks this flag).
    Fail-closed: if the mint fails, svid_issued is NOT set, a
    ``NhiSvidIssuanceFailedEvent`` is written to the audit chain, and the
    request fails with 502 (BUG-A, v4.1 Phase 0).

    Without approval, the NHI cannot run — the gateway returns 403
    ``NHI_PENDING_APPROVAL`` on every invocation (fail-closed).

    Emits ``NhiSvidApprovedEvent`` to the tamper-evident audit chain.
    Step-up TOTP is required (ASVS V6.8.4).
    """
    registry = _get_registry()

    # Validate: must be a registered NHI
    nhi = registry.get(nhi_id)
    if nhi is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "nhi_not_found", "message": f"No NHI found with id {nhi_id!r}."},
        )
    if nhi.get("kind") != "nhi":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "not_an_nhi",
                "message": f"{nhi_id!r} is registered as kind={nhi.get('kind')!r}, not 'nhi'.",
            },
        )

    # 2. PKI: mint agent leaf cert FIRST (fail-closed — BUG-A, v4.1 Phase 0).
    #    svid_issued is only ever set AFTER a real leaf cert exists on disk.
    #    (registry.approve_svid docstring: "Called ... after the PKI leaf cert
    #    is issued" — the previous best-effort order violated that contract and
    #    left registries claiming issued SVIDs with no cert on disk.)
    spiffe_id: str = nhi.get("spiffe_id", "")
    try:
        from pathlib import Path
        from yashigani.pki.issuer import IssuerPaths, mint_agent_leaf

        _secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
        _manifest_path = os.getenv(
            "YASHIGANI_SERVICE_MANIFEST_PATH",
            "/etc/yashigani/service_identities.yaml",
        )
        pki_paths = IssuerPaths(
            secrets_dir=Path(_secrets_dir),
            manifest_path=Path(_manifest_path),
        )
        tenant_id = nhi.get("owner_identity_id", "tenant")
        agent_name = nhi.get("name", nhi_id)
        # v4.1 Phase 1a GAP-2 — change-prevention baseline. scope_hash is
        # stored at register_nhi time (instantiate path); for entries
        # registered before that field existed, recompute from the SAME
        # canonical encoding over the registry's allowed_tools.
        from yashigani.pki.binding import tool_surface_hash
        scope_hash = nhi.get("scope_hash") or tool_surface_hash(
            nhi.get("allowed_tools") or []
        )
        # OCI image digest pinned at approve time. Populated by PoolManager
        # once the pool pins digests; "" (unpinned) is recorded honestly —
        # the binding then covers the tool surface only (see pki/binding.py).
        image_digest = nhi.get("image_digest") or ""
        spiffe_id = mint_agent_leaf(
            pki_paths,
            tenant_id=tenant_id,
            agent_name=agent_name,
            # GAP-1 — per-instance identity: nhi_id becomes the instance
            # segment in BOTH the SPIFFE URI and the cert/key file names.
            instance_id=nhi_id,
            scope_hash=scope_hash,
            image_digest=image_digest,
            approved_by=session.account_id,
            audit_writer=backoffice_state.audit_writer,
        )
        # Persist the minted SPIFFE ID back to the registry entry
        registry.update(nhi_id, spiffe_id=spiffe_id)
        logger.info(
            "NHI approve: mint_agent_leaf succeeded nhi_id=%s spiffe_id=%s",
            nhi_id, spiffe_id,
        )
    except Exception as exc:
        # Fail-closed: the approval is ABORTED — svid_issued stays 0, the NHI
        # remains NHI_PENDING_APPROVAL at the gateway. A registry that claims
        # issued with no cert on disk is unacceptable (BUG-A, v4.1 Phase 0).
        logger.error(
            "NHI approve: mint_agent_leaf FAILED for nhi_id=%s — approval aborted, "
            "svid_issued NOT set (fail-closed). Fix the PKI issuer and re-approve. "
            "Error: %s",
            nhi_id, exc,
        )
        aw_fail = backoffice_state.audit_writer
        if aw_fail is not None:
            try:
                from yashigani.audit.schema import NhiSvidIssuanceFailedEvent
                aw_fail.write(NhiSvidIssuanceFailedEvent(
                    approver_account=session.account_id,
                    nhi_id=nhi_id,
                    spiffe_id=spiffe_id,
                    error_type=type(exc).__name__,
                ))
            except Exception as audit_exc:
                logger.error(
                    "NhiSvidIssuanceFailedEvent audit write failed (nhi_id=%s): %s",
                    nhi_id, audit_exc,
                )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "svid_issuance_failed",
                "message": (
                    "PKI leaf cert issuance failed — approval aborted (fail-closed). "
                    "svid_issued was NOT set; the NHI remains pending. "
                    "Check backoffice logs and re-approve once the PKI issuer is healthy."
                ),
            },
        )

    # 3. Approve: set svid_issued=1 + add to active index (mint succeeded above)
    try:
        registry.approve_svid(nhi_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "nhi_not_found", "message": str(exc)},
        )

    # 4. Audit: emit NhiSvidApprovedEvent to the tamper-evident hash-chain
    aw = backoffice_state.audit_writer
    if aw is not None:
        try:
            from yashigani.audit.schema import NhiSvidApprovedEvent
            aw.write(NhiSvidApprovedEvent(
                approver_account=session.account_id,
                nhi_id=nhi_id,
                spiffe_id=spiffe_id,
                step_up_verified=True,
            ))
        except Exception as exc:
            logger.warning("NhiSvidApprovedEvent audit write failed (nhi_id=%s): %s", nhi_id, exc)

    logger.info(
        "NHI SVID approved nhi_id=%s approver=%s spiffe_id=%r",
        nhi_id, session.account_id, spiffe_id,
    )

    return {
        "nhi_id": nhi_id,
        "approved": True,
        "spiffe_id": spiffe_id,
        "message": (
            "NHI SVID approved. The NHI is now resolvable by the gateway. "
            "Restart or reload the gateway token-role-map to pick up the new NHI token "
            "(GET /internal/nhi/refresh on the gateway internal port, or restart gateway)."
        ),
    }
