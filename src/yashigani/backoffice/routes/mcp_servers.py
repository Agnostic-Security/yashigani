"""
Yashigani Backoffice — MCP Server Registry admin routes (4.0).

Admin surface for the MCP server registry: listing registered servers and
importing (seeding) new ones through the governed capability-envelope ceremony.

Endpoints (prefix /admin/mcp/servers):
  GET  /               — list active registered MCP servers (with tool summary)
  POST /import         — import/seed a new MCP server (step-up gated)

Import ceremony (POST /import):
  1. Receives server_id + upstream_url (+ optional topology/egress_posture).
  2. Fetches tools/list from the upstream URL via JSON-RPC.
  3. Projects the raw tool surface into a ServerEnvelope (structural analysis).
  4. Calls CapabilityEnvelopeService.mint_envelope() — writes the FIRST
     approved envelope version (v1) for this server.  Step-up gated: the admin
     must have a fresh TOTP in the session before import can mutate state.
  5. Returns the new envelope id and tool_count so the caller can verify.

Demo-mode use: populate-demo.py calls POST /admin/mcp/servers/import with
  server_id="cloud9-demo", upstream_url="http://demo-mcp:8000"
to seed the cloud-9 demo MCP server's initial approved envelope on first deploy.
The server MUST also be listed in YASHIGANI_MCP_SERVERS (set by install.sh in
demo mode) so the broker registry picks it up at gateway startup.

Security properties:
  * GET is admin-session gated (AdminSession) — read-only, no secrets exposed.
  * POST /import requires StepUpAdminSession (fresh TOTP) — mutating.
  * server_id and upstream_url are validated (length, scheme) before use.
  * The tools/list HTTP call is made BY THE BACKOFFICE PROCESS (not the client).
    The operator supplies the server URL; the backoffice fetches from it.  This
    is operator-controlled egress (admin must already own the network), not SSRF.
    Allowed schemes: http/https only; localhost/internal URLs are accepted in demo
    mode (the demo MCP runs inside the compose network).
  * The envelope is operator-signed with the admin's account_id.

Last updated: 2026-06-30T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
import re
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, field_validator

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope
from yashigani.mcp.envelope_service import (
    TOPOLOGY_EXTERNAL_RELAY,
    TOPOLOGY_RING_FENCED,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _install_tenant() -> str:
    """Resolve this install's tenant id."""
    return os.environ.get("YASHIGANI_TENANT_ID", "default").strip() or "default"


def _envelope_service():
    """Return a CapabilityEnvelopeService over the live asyncpg pool, or raise 503."""
    try:
        from yashigani.db import get_pool
        from yashigani.mcp.envelope_service import CapabilityEnvelopeService
        return CapabilityEnvelopeService(get_pool())
    except Exception as exc:
        logger.warning("mcp-servers: envelope service unavailable (%s)", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "envelope_service_unavailable",
                "message": "Capability-envelope durable store not initialised (DB pool unavailable).",
            },
        )


def _tool_summary(rec) -> dict:
    """Compact, JSON-safe view of one active EnvelopeRecord for the registry list."""
    tools = []
    for tk, t in sorted(rec.envelope.tools.items()):
        tools.append({
            "tool_key": tk,
            "effect_classes": sorted(e.value for e in t.effect_classes),
        })
    return {
        "server_id": rec.server_id,
        "provenance_id": rec.provenance_id,
        "envelope_version": rec.envelope_version,
        "status": rec.status,
        "egress_posture": rec.egress_posture,
        "topology": rec.topology,
        "tool_count": len(rec.envelope.tools),
        "tools": tools,
        "approved_by": rec.approved_by_operator_identity,
        "approved_at": rec.approved_at.isoformat() if rec.approved_at else None,
    }


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

_SAFE_SERVER_ID_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,62}$')
_UPSTREAM_SCHEME_RE = re.compile(r'^https?://')


class ImportMcpServerRequest(BaseModel):
    """Request body for POST /admin/mcp/servers/import."""

    server_id: str
    """Stable identifier for this MCP server (e.g. 'cloud9-demo', 'filesystem-mcp').
    Must be URL-safe and match the agent_name in YASHIGANI_MCP_SERVERS."""

    upstream_url: str
    """HTTP/HTTPS URL of the MCP server (e.g. 'http://demo-mcp:8000').
    The backoffice will call tools/list on this URL to discover the tool surface."""

    topology: str = TOPOLOGY_RING_FENCED
    """Topology class: 'ring_fenced' (isolated compose network) or
    'external_relay' (public/cloud endpoint).  Drives the egress posture."""

    egress_posture: str = "NONE"
    """Egress posture declaration: 'NONE', 'CONTROLLED', or 'OPEN'.
    Operators must declare the correct posture at import time; it is part of the
    signed envelope and used by the drift-triage gate."""

    display_name: Optional[str] = None
    """Optional human-readable display name (for UI labels)."""

    @field_validator("server_id")
    @classmethod
    def validate_server_id(cls, v: str) -> str:
        if not _SAFE_SERVER_ID_RE.match(v):
            raise ValueError(
                "server_id must be 1–63 chars, start with alphanumeric, "
                "and contain only alphanumerics, hyphens, and underscores"
            )
        return v

    @field_validator("upstream_url")
    @classmethod
    def validate_upstream_url(cls, v: str) -> str:
        if not _UPSTREAM_SCHEME_RE.match(v):
            raise ValueError("upstream_url must start with http:// or https://")
        if len(v) > 2048:
            raise ValueError("upstream_url too long (max 2048 chars)")
        return v

    @field_validator("topology")
    @classmethod
    def validate_topology(cls, v: str) -> str:
        if v not in (TOPOLOGY_RING_FENCED, TOPOLOGY_EXTERNAL_RELAY):
            raise ValueError(
                f"topology must be '{TOPOLOGY_RING_FENCED}' or '{TOPOLOGY_EXTERNAL_RELAY}'"
            )
        return v

    @field_validator("egress_posture")
    @classmethod
    def validate_egress_posture(cls, v: str) -> str:
        allowed = {"NONE", "CONTROLLED", "OPEN"}
        if v not in allowed:
            raise ValueError(f"egress_posture must be one of {sorted(allowed)}")
        return v


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/")
async def list_registered_servers(session: AdminSession):
    """List all active (approved) MCP servers registered in this install.

    Returns the admin-facing registry view: one entry per registered server,
    showing the approved capability envelope (tool set + effect classes + posture).
    Only active envelopes are returned; blocked/superseded versions are not shown.
    404-like empty list is normal when no servers have been imported yet.

    Security: AdminSession required — no step-up (read-only, no secrets exposed)."""
    svc = _envelope_service()
    tenant = _install_tenant()
    try:
        records = await svc.list_active(tenant)
    except Exception as exc:
        envelope, _ = safe_error_envelope(exc, public_message="registry list failed")
        raise HTTPException(status_code=500, detail=envelope)

    return {
        "tenant_id": tenant,
        "servers": [_tool_summary(r) for r in records],
        "count": len(records),
    }


@router.post("/import")
async def import_mcp_server(
    body: ImportMcpServerRequest,
    session: StepUpAdminSession,
):
    """Import (onboard) a new MCP server through the governed capability-envelope ceremony.

    Step-up gated: the admin must have a fresh TOTP stamp in their session.
    On success, the server's tool surface is fetched from upstream_url, projected
    into a typed ServerEnvelope, and minted as version 1 (the ORIGINAL approved
    baseline). Subsequent tool-surface refreshes are triage'd against this baseline.

    Idempotent on the SAME surface: re-importing the same server with the same
    tool surface mints a new envelope version (the previous is superseded). This
    is by-design — the operator explicitly re-approved the surface.

    The server must also appear in YASHIGANI_MCP_SERVERS for the broker registry
    to pick it up at gateway startup (install.sh handles this in demo mode).

    Returns: {server_id, provenance_id, envelope_id, tool_count, tools []}
    """
    from yashigani.mcp._envelope import project_surface, surface_set_hash

    # 1. Fetch tools/list from the upstream.
    rpc = {
        "jsonrpc": "2.0",
        "id": "import-ceremony",
        "method": "tools/list",
        "params": {},
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                body.upstream_url,
                json=rpc,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            raw_result = resp.json().get("result") or {}
            raw_tools: list = raw_result.get("tools") or []
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={
                "error": "upstream_timeout",
                "message": f"MCP server at {body.upstream_url} did not respond within 15 s.",
            },
        )
    except httpx.HTTPStatusError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "upstream_error",
                "message": f"MCP tools/list returned HTTP {exc.response.status_code}.",
            },
        )
    except Exception as exc:
        envelope, _ = safe_error_envelope(exc, public_message="tools/list fetch failed")
        raise HTTPException(status_code=502, detail=envelope)

    if not raw_tools:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "no_tools_returned",
                "message": (
                    "The MCP server returned an empty tools/list. "
                    "Ensure the server is running and returns at least one tool."
                ),
            },
        )

    # 2. Project the raw surface into a typed capability envelope.
    tenant = _install_tenant()
    provenance_id = f"{tenant}:{body.server_id}"
    env = project_surface(
        provenance_id=provenance_id,
        tenant_id=tenant,
        raw_tools=raw_tools,
        egress_posture=body.egress_posture,
    )

    # 3. Mint the initial approved envelope (v1 / import ceremony).
    svc = _envelope_service()
    try:
        new_id = await svc.mint_envelope(
            env,
            server_id=body.server_id,
            operator_identity=session.account_id,
            topology=body.topology,
        )
    except Exception as exc:
        envelope, _ = safe_error_envelope(exc, public_message="envelope mint failed")
        raise HTTPException(status_code=500, detail=envelope)

    tool_names = sorted(env.tools.keys())
    logger.info(
        "mcp-servers: imported server_id=%r provenance=%r tools=%d envelope_id=%d "
        "by admin=%s",
        body.server_id, provenance_id, len(tool_names), new_id, session.account_id,
    )

    return {
        "server_id": body.server_id,
        "provenance_id": provenance_id,
        "envelope_id": new_id,
        "tool_count": len(tool_names),
        "tools": tool_names,
        "topology": body.topology,
        "egress_posture": body.egress_posture,
        "approved_by": session.account_id,
    }
