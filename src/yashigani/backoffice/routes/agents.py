"""
Yashigani Backoffice — Agent registry admin routes.

All routes require an active admin session.
The plaintext PSK token is returned ONCE on register and rotate operations
and is never stored or re-derivable after that point.

After every mutation (register/update/deactivate/token rotate), the combined
RBAC + agent data document is pushed to OPA. Push failure is non-fatal for
the mutation — it is logged but does not roll back the registry change.

Routes:
  GET    /admin/agents                          — list all agents
  POST   /admin/agents                          — register new agent
  GET    /admin/agents/{agent_id}               — get agent detail
  PUT    /admin/agents/{agent_id}               — update agent fields
  DELETE /admin/agents/{agent_id}               — deactivate (soft delete)
  POST   /admin/agents/{agent_id}/token/rotate  — rotate PSK, return new token once

Last updated: 2026-05-08T00:00:00+01:00
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl, field_validator

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

_OWUI_HTTP_CLIENT = None   # lazy-initialised on first use


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
            allow_http=True,    # OWUI runs on plain HTTP inside the Docker mesh
            timeout_s=10.0,
        )
    return _OWUI_HTTP_CLIENT


router = APIRouter()


# ---------------------------------------------------------------------------
# SSRF / scheme allowlist for agent upstream_url (TM-V231-004, Pentest #95 2026-04-29)
# ---------------------------------------------------------------------------

def _assert_safe_upstream_url(url: str) -> str:
    """Assert that ``url`` is safe to store as an agent's upstream_url.

    Pentest #95 (TM-V231-004): the prior validator was just `Field(min_length=1,
    max_length=512)`. An authenticated admin could register an agent with
    ``file:///etc/passwd``, ``gopher://redis:6380/``, ``http://169.254.169.254/``
    (cloud metadata SSRF), or any internal-service URL. OPA's identity-active
    gate at invocation time was the only compensating control, and that gate
    is bypassable by an admin who can also activate the caller identity
    (TA-3 insider). Admin-trust-boundary SSRF is admin-trust-boundary SSRF.

    Allowed:
      - Scheme: http or https ONLY. Anything else (file, gopher, ftp, dict,
        ldap, jar, ws, ...) is rejected outright.
      - Host: must NOT be a loopback / link-local / multicast / cloud-metadata
        IP. The link-local 169.254.169.254 is the AWS/GCP/Azure metadata
        endpoint and is the primary SSRF target.
      - Optional internal-service allowlist via ``YASHIGANI_AGENT_UPSTREAM_HOSTNAMES``
        (comma-separated, case-insensitive). Hosts in the allowlist are
        permitted to be RFC 1918 / loopback / Docker-bridge — needed so
        operators can run agents like ``yashigani-letta`` or ``openclaw`` on
        the internal mesh. Empty default — operator MUST explicitly allow
        internal hosts to permit them.

    Returns the URL unchanged on PASS. Raises ValueError on any violation
    (Pydantic v2 turns this into HTTP 422 with the structured error body).
    """
    import ipaddress
    import socket

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()

    if scheme not in ("http", "https"):
        raise ValueError(
            f"upstream_url scheme {scheme!r} not allowed — only http and https "
            f"are accepted (CWE-918 / TM-V231-004)"
        )

    if not host:
        raise ValueError(
            f"upstream_url has no hostname (parsed from {url!r}) — agent upstreams "
            "must be addressable HTTP(S) endpoints"
        )

    raw_allowlist = os.getenv("YASHIGANI_AGENT_UPSTREAM_HOSTNAMES", "")
    internal_allowed = {h.strip().lower() for h in raw_allowlist.split(",") if h.strip()}
    if host in internal_allowed:
        return url  # Operator explicitly allowed this internal host.

    # For everything else: refuse SSRF-prone IPs. Resolve hostname to IP if
    # given a name; if resolution fails, refuse (we don't store URLs that
    # can't be resolved at registration time).
    try:
        addrinfo = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addrs = {info[4][0] for info in addrinfo}
    except (socket.gaierror, socket.herror):
        # Hostname doesn't resolve — could be intentional (e.g., DNS not yet
        # populated for a service that's about to come up). Fall through to
        # the literal-IP check below; if `host` is itself a literal IP we
        # check it directly.
        addrs = {host}

    for addr_str in addrs:
        try:
            ip = ipaddress.ip_address(addr_str)
        except ValueError:
            continue  # not an IP literal, skip
        if ip.is_loopback:
            raise ValueError(
                f"upstream_url host {host!r} resolves to loopback {addr_str} — "
                "loopback addresses are SSRF targets; add the hostname to "
                "YASHIGANI_AGENT_UPSTREAM_HOSTNAMES if intentional "
                "(CWE-918 / TM-V231-004)"
            )
        if ip.is_link_local:
            # 169.254.169.254 is the cloud-metadata endpoint — primary SSRF target.
            raise ValueError(
                f"upstream_url host {host!r} resolves to link-local {addr_str} — "
                "link-local addresses (incl. cloud metadata 169.254.169.254) "
                "are SSRF targets and never valid for agent upstreams "
                "(CWE-918 / TM-V231-004)"
            )
        if ip.is_multicast:
            raise ValueError(
                f"upstream_url host {host!r} resolves to multicast {addr_str} — "
                "multicast addresses are not valid HTTP(S) endpoints"
            )
        if ip.is_private:
            raise ValueError(
                f"upstream_url host {host!r} resolves to RFC 1918 private "
                f"{addr_str} — private addresses are SSRF-prone; add the "
                "hostname to YASHIGANI_AGENT_UPSTREAM_HOSTNAMES if "
                "intentional (CWE-918 / TM-V231-004)"
            )
        if ip.is_reserved:
            raise ValueError(
                f"upstream_url host {host!r} resolves to reserved {addr_str} "
                "(CWE-918 / TM-V231-004)"
            )

    return url


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
    upstream_url: str = Field(min_length=1, max_length=512)
    protocol: str = Field(default="openai", description="Agent protocol: openai, letta, or langflow")
    groups: list[str] = Field(default_factory=list)
    allowed_caller_groups: list[str] = Field(default_factory=list)
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(
        default_factory=list,
        description="Optional CIDR allowlist. Empty = no IP restriction. E.g. ['10.0.0.0/8', '192.168.1.100/32']",
    )

    @field_validator("name")
    @classmethod
    def _reject_html_in_name(cls, v: str) -> str:
        """Reject HTML tags and protocol URIs in agent name (AVA-2026-04-29-001 / AVA-C006, ASVS V5.3.3, CWE-79)."""
        if _HTML_TAG_RE.search(v):
            raise ValueError(
                "agent name must not contain HTML tags or protocol URIs — "
                "strip markup and use plain text (CWE-79 / AVA-2026-04-29-001 / AVA-C006)"
            )
        return v

    @field_validator("upstream_url")
    @classmethod
    def _validate_upstream_url(cls, v: str) -> str:
        return _assert_safe_upstream_url(v)


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


class AgentQuickStartResponse(BaseModel):
    agent_id: str
    quick_start: dict = Field(description="Copy-paste integration snippets (token placeholder — use your stored token).")


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
    )


def _build_quick_start(agent_id: str, token: str) -> dict:
    """Build copy-paste integration snippets shown once on agent registration / token rotation."""
    gw = "<your-gateway-url>"
    return {
        "curl": (
            f"curl -X POST https://{gw}/mcp \\\n"
            f"  -H 'Authorization: Bearer {token}' \\\n"
            f"  -H 'Content-Type: application/json' \\\n"
            f"  -d '{{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}}'"
        ),
        "python_httpx": (
            f"import httpx\n"
            f"client = httpx.Client(\n"
            f"    base_url='https://{gw}',\n"
            f"    headers={{'Authorization': 'Bearer {token}'}}\n"
            f")\n"
            f"resp = client.post('/mcp', json={{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}})\n"
            f"print(resp.json())"
        ),
        "health_check": (
            f"curl https://{gw}/health -H 'Authorization: Bearer {token}'"
        ),
        "note": (
            f"Replace '{gw}' with your actual gateway URL. "
            f"Token shown once — store it securely. Agent ID: {agent_id}"
        ),
    }


def _push_openwebui_model(agent_name: str, upstream_url: str) -> None:
    """
    Register agent as a selectable model in Open WebUI via its REST API.
    Non-fatal: logs on failure. Idempotent — skips if already exists.

    SSRF guard: OWUI_API_URL is validated through the centralised HttpClient
    before any outbound request is issued (yashigani-retro#95 / OWASP A10 / API7).
    The prior hand-rolled helper has been removed; policy is now enforced by
    HttpClient._check_policy() via _owui_http_client().
    """
    try:
        import json
        import urllib.request
        import urllib.error
        from yashigani.net import BlockedByPolicy

        raw_owui_url = os.getenv("OWUI_API_URL", "http://open-webui:8080")
        try:
            _owui_http_client()._check_policy(raw_owui_url)
        except BlockedByPolicy as _bp_exc:
            raise RuntimeError(
                f"owui_url_blocked: {_bp_exc} (CWE-918, YSG-RISK-007.A)"
            ) from _bp_exc
        owui_url = raw_owui_url
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
        import time as _time
        import jwt as _pyjwt
        payload_data = {
            "id": "00000000-0000-0000-0000-000000000000",
            "sub": "admin",
            "role": "admin",
            "exp": int(_time.time()) + 300,
        }
        token = _pyjwt.encode(payload_data, owui_secret, algorithm="HS256")
        # PyJWT ≥2 returns str; older returned bytes. Normalise.
        if isinstance(token, bytes):
            token = token.decode()

        model_id = "@" + agent_name
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # Check if model already exists
        try:
            req = urllib.request.Request(
                f"{owui_url}/api/v1/models/{model_id}",
                headers=headers,
            )
            urllib.request.urlopen(req, timeout=5)
            logger.info("Open WebUI: model %s already exists", model_id)
            return
        except urllib.error.HTTPError as e:
            if e.code != 404:
                logger.warning("Open WebUI: model check failed (%s)", e.code)

        # Create model
        body = json.dumps({
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
        }).encode()

        req = urllib.request.Request(
            f"{owui_url}/api/v1/models/create",
            data=body,
            headers=headers,
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
        logger.info("Open WebUI: registered model %s via API", model_id)
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


@router.post("/admin/agents", response_model=AgentRegisterResponse, status_code=201)
async def register_agent(
    body: AgentRegisterRequest,
    session: StepUpAdminSession,
):
    registry = _get_registry()
    audit = backoffice_state.audit_writer

    # GROUP-4-1 / LAURA-LIMIT-AGENTS-01: agent limit is enforced atomically
    # inside registry.register() via a Lua script (SCARD → check → HSET+SADD).
    # The previous non-atomic pre-check (check_agent_limit(registry.count()))
    # had a TOCTOU race and is removed here. LicenseLimitExceeded is raised by
    # the Lua path on breach and caught below.
    from yashigani.licensing.enforcer import LicenseLimitExceeded
    try:
        agent_id, plaintext_token = registry.register(
            name=body.name,
            upstream_url=body.upstream_url,
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
            audit.write(AgentRegisteredEvent(
                agent_id=agent_id,
                agent_name=body.name,
                upstream_url=body.upstream_url,
                groups=body.groups,
                allowed_caller_groups=body.allowed_caller_groups,
                allowed_paths=body.allowed_paths,
                admin_account=session.account_id,
            ))
        except Exception as exc:
            logger.error("Failed to write AgentRegisteredEvent: %s", exc)

    _push_opa()
    _push_openwebui_model(body.name, body.upstream_url)

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


@router.put("/admin/agents/{agent_id}", response_model=AgentResponse)
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
            audit.write(AgentUpdatedEvent(
                agent_id=agent_id,
                changed_fields=changed_fields,
                admin_account=session.account_id,
            ))
        except Exception as exc:
            logger.error("Failed to write AgentUpdatedEvent: %s", exc)

    if updates:
        _push_opa()

    updated = registry.get(agent_id)
    return _to_response(updated)


@router.delete("/admin/agents/{agent_id}", status_code=204)
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

    # Audit
    if audit is not None:
        try:
            from yashigani.audit.schema import AgentDeactivatedEvent
            audit.write(AgentDeactivatedEvent(
                agent_id=agent_id,
                admin_account=session.account_id,
                reason=reason,
            ))
        except Exception as exc:
            logger.error("Failed to write AgentDeactivatedEvent: %s", exc)

    _push_opa()


@router.post("/admin/agents/{agent_id}/token/rotate", response_model=AgentRotateResponse)
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
            audit.write(AgentTokenRotatedEvent(
                agent_id=agent_id,
                admin_account=session.account_id,
            ))
        except Exception as exc:
            logger.error("Failed to write AgentTokenRotatedEvent: %s", exc)

    _push_opa()

    return AgentRotateResponse(
        agent_id=agent_id,
        token=plaintext_token,
        quick_start=_build_quick_start(agent_id, plaintext_token),
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
