"""
Yashigani Backoffice — MCP Server Registry admin routes (4.0).

Admin surface for the MCP server registry: listing registered servers and
importing (seeding) new ones through the governed capability-envelope ceremony.

Endpoints (prefix /admin/mcp/servers):
  GET    /                    — list active registered MCP servers (with tool summary)
  POST   /import              — import/seed a new MCP server (step-up gated)
  DELETE /{server_id}         — decommission a ring_fenced MCP server (step-up
                                 gated) — FINDING-V412-ONBOARDING-ROBUSTNESS #4.
                                 See mcp_onboard.py run_decommission_transaction
                                 for the full reversal (envelope deactivation,
                                 broker-route removal, durable-registry
                                 cleanup, SVID leaf revocation). Idempotent;
                                 component-isolated to this server_id only.

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
    The operator supplies the server URL; the backoffice fetches from it. This
    is operator-controlled egress by design (an operator-chosen internal MCP
    server on the compose/mesh network is a legitimate target — e.g. demo mode
    imports 'http://demo-mcp:8000'), so upstream_url is NOT allowlisted and
    RFC-1918/private-mesh hosts are accepted. It is NOT blanket-exempt from
    SSRF, though: codescan #1 (mustui triage 2026-07-20) proved the pre-fix
    code let upstream_url reach cloud-metadata (IMDS) and loopback targets —
    a blind-SSRF/internal-recon primitive. upstream_url is now gated by
    assert_no_imds_or_loopback_url() (yashigani.alerts._url_guard) at both
    the Pydantic field-validator (config-write time, fail 422 before any
    fetch) and again immediately before the httpx call (defence-in-depth) —
    same two-checkpoint pattern as the Slack/Teams webhook guard
    (V232-CSCAN-01b), narrowed to IMDS/loopback only (no vendor allowlist, no
    blanket private-range block) so internal MCP deployments keep working.
  * The envelope is operator-signed with the admin's account_id.

Last updated: 2026-07-20T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, field_validator

from yashigani.alerts._url_guard import WebhookUrlForbidden, assert_no_imds_or_loopback_url
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


def _durable_registry_store():
    """Return a DurableMcpRegistryStore over Redis db/3, or None (dev/test).

    v4.1 Phase 2a (Iris SEAM-1d-07): the approve transaction writes the broker
    descriptor here; the gateway McpBrokerRegistry lazily loads it so the
    onboarded MCP routes without a gateway reboot.  Shares Redis db/3 with the
    gateway's PermissionStore / McpIdStore (same instance, different prefix).

    Degrades to None when Redis is unreachable — run_approve_transaction then
    fail-closes in production/staging and warn-skips in dev/test.
    """
    try:
        import redis as _redis  # noqa: PLC0415
        from yashigani.gateway._redis_url import build_redis_url  # noqa: PLC0415
        from yashigani.mcp._durable_registry import DurableMcpRegistryStore  # noqa: PLC0415

        _use_tls = os.getenv("REDIS_USE_TLS", "true").lower() == "true"
        _secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
        url = build_redis_url(
            3,
            use_tls=_use_tls,
            secrets_dir=_secrets_dir,
            client_cert_name="backoffice_client",
        )
        client = _redis.from_url(url, decode_responses=False)
        client.ping()
        return DurableMcpRegistryStore(client)
    except Exception as exc:  # noqa: BLE001 — availability is enforced downstream
        logger.warning(
            "mcp-servers: durable broker-registry store unavailable (%s) — "
            "run_approve_transaction will fail closed in production/staging "
            "(SEAM-1d-07)", exc,
        )
        return None


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
# Day-one-poison screen (YSG-RISK-076 / DP-Y-003 §3.4)
# ---------------------------------------------------------------------------

def _screen_tools(server_id: str, raw_tools: list[dict]) -> dict:
    """Run the M4 content filter + semantic-intent sidecar over the raw
    tools/list surface (DP-Y-003 §3.4 import-time screening).

    Returns ``sidecar_scan_verdict`` — the JSON blob recorded on the envelope
    row.  It captures the filter results (tool count, schema count, any
    rejections, any truncations, classifier verdict) so the audit chain holds
    a complete record of what the operator reviewed.

    YSG-RISK-076: wired the day-one-poison screen into the 4.0 import path
    (POST /admin/mcp/servers/import).  In 3.1.1 this was ``envelope_import.py``
    which was rewritten into ``mcp_servers.py`` without carrying the screen.

    CT-1 (honesty invariant, DP-Y-003 §3.4): ``sidecar_used``,
    ``classifier_status``, and ``filter_version`` are derived from whether the
    classifier ACTUALLY evaluated each screened item — not from whether the
    sidecar object exists.  Status values:
      * ``"ran"``               — classifier ran on all items eligible for evaluation.
      * ``"disabled_by_flag"``  — YASHIGANI_SEMANTIC_INTENT_SIDECAR flag was OFF.
      * ``"unavailable_error"`` — sidecar object present + flag ON, but evaluate()
                                  errored for ≥1 eligible item (partial ≠ success).
      * ``"not_configured"``    — no sidecar object wired at startup (safe degrade).

    CT-3 (§3.4 scope): tool descriptions AND canonicalised parameter schemas
    (``inputSchema``) are screened via the same filter_description_v2 pipeline.

    Human-in-the-loop (EU AI Act Art.14, DP-Y-003 §3.4): the classifier never
    holds authority alone — a sidecar flag does NOT auto-reject the surface.
    The operator review and approval step remains mandatory.
    """
    from yashigani.mcp._content_filter import build_catalogue
    from yashigani.inspection.semantic_intent import sidecar_enabled

    tenant_id = _install_tenant()
    sidecar = backoffice_state.semantic_intent_sidecar  # SemanticIntentSidecar | None

    # CT-3 (§3.4 scope): canonicalise and screen the inputSchema of each tool.
    # Schemas are passed as additional screening items keyed "schema:<tool_name>".
    schema_items: list[dict] = []
    for raw in raw_tools:
        name = str(raw.get("name") or "")
        schema = raw.get("inputSchema")
        if schema and isinstance(schema, dict):
            schema_items.append({
                "name": f"schema:{name}",
                "content": json.dumps(schema, ensure_ascii=False, separators=(",", ":")),
            })

    catalogue = build_catalogue(
        tenant_id=tenant_id,
        server_id=server_id,
        raw_tools=raw_tools,
        raw_prompts=schema_items,   # CT-3: includes per-tool schemas
        sidecar=sidecar,
    )

    # Collect rejection / truncation / sidecar-escalation stats.
    rejected_tools: list[str] = []
    truncated_tools: list[str] = []
    passed_tools: list[str] = []
    sidecar_escalated: list[str] = []

    for td in catalogue.tools:
        if getattr(td.filter_result, "rejected", False):
            rejected_tools.append(td.tool_name)
            reject_reason = getattr(td.filter_result, "reject_reason", "") or ""
            if reject_reason.startswith("semantic_intent"):
                sidecar_escalated.append(td.tool_name)
        elif len(td.safe_description) < len(str(
            next(
                (r.get("description", "") for r in raw_tools if r.get("name") == td.tool_name),
                "",
            )
        )):
            truncated_tools.append(td.tool_name)
        else:
            passed_tools.append(td.tool_name)

    # CT-3: collect schema rejection stats.
    schema_rejected: list[str] = []
    for pd in catalogue.prompts:
        if pd.filter_result.rejected:
            schema_rejected.append(pd.prompt_name)

    # CT-1 (honesty invariant): derive classifier attestation from FilterResult
    # evaluation markers, NOT from sidecar object existence.
    def _heuristic_only_rejected(fr) -> bool:
        return bool(fr.rejected) and (fr.reject_reason or "") != "semantic_intent"

    def _sidecar_annotated(fr) -> bool:
        return fr.semantic_intent_score is not None

    if sidecar is None:
        classifier_status = "not_configured"
        sidecar_used = False
        filter_ver = "v2_heuristic"
    elif not sidecar_enabled():
        classifier_status = "disabled_by_flag"
        sidecar_used = False
        filter_ver = "v2_heuristic"
    else:
        all_results = (
            [td.filter_result for td in catalogue.tools]
            + [pd.filter_result for pd in catalogue.prompts]
        )
        eligible = [fr for fr in all_results if not _heuristic_only_rejected(fr)]
        evaluated = [fr for fr in eligible if _sidecar_annotated(fr)]

        if len(eligible) == 0:
            classifier_status = "ran"
            sidecar_used = False
            filter_ver = "v2_heuristic"
        elif len(evaluated) == len(eligible):
            classifier_status = "ran"
            sidecar_used = True
            filter_ver = "v2_semantic"
        else:
            classifier_status = "unavailable_error"
            sidecar_used = False
            filter_ver = "v2_heuristic"

    verdict: dict = {
        "sidecar_used": sidecar_used,
        "classifier_status": classifier_status,
        "filter_version": filter_ver,
        "tool_count": len(raw_tools),
        "schema_count": len(schema_items),
        "passed": len(passed_tools),
        "rejected": len(rejected_tools),
        "truncated": len(truncated_tools),
    }
    if rejected_tools:
        verdict["rejected_tools"] = rejected_tools
    if truncated_tools:
        verdict["truncated_tools"] = truncated_tools
    if sidecar_escalated:
        verdict["sidecar_escalations"] = sidecar_escalated
    if schema_rejected:
        verdict["schema_rejected"] = schema_rejected

    # Suspicious-content flag: surface to the operator at import time.
    # Human still decides — this flag does NOT auto-block.
    verdict["suspicious_content_flagged"] = bool(
        rejected_tools or sidecar_escalated or schema_rejected
    )

    if classifier_status in ("disabled_by_flag", "not_configured"):
        logger.info(
            "mcp-import: semantic-intent classifier %s for server=%r "
            "— heuristic-only screening applied (DP-Y-003 §3.4 degraded mode)",
            classifier_status, server_id,
        )
    elif classifier_status == "unavailable_error":
        logger.warning(
            "mcp-import: sidecar enabled+present but evaluate() errored for "
            "≥1 eligible item — recording unavailable_error in verdict (server=%r)",
            server_id,
        )

    if rejected_tools:
        logger.warning(
            "mcp-import: M4 filter rejected %d tool description(s) for server=%r: %s "
            "— operator is importing with sanitised surface",
            len(rejected_tools), server_id, rejected_tools,
        )
    if schema_rejected:
        logger.warning(
            "mcp-import: M4 filter rejected %d schema item(s) for server=%r: %s",
            len(schema_rejected), server_id, schema_rejected,
        )

    return verdict


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

    manifest_yaml: Optional[str] = None
    """v4.1 Phase 1c — Shape-C manifest (YAML text) for the approve
    transaction.  REQUIRED for ring_fenced topology: the import ceremony now
    provisions the wrap atomically (per-instance leaf + Caddy front + reload
    + durable registry) — 'DB row only' onboarding no longer exists for
    ring-fenced servers.  metadata.name must equal server_id and
    metadata.tenant_id must equal this install's tenant.  external_relay
    (remote/cloud endpoint — no local container, nothing to wrap) does not
    take a manifest."""

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
        # codescan #1 (mustui triage 2026-07-20): block IMDS/loopback SSRF
        # targets at config-write time, before any fetch is attempted. Does
        # NOT block RFC-1918/private-mesh hosts — internal MCP servers are a
        # legitimate, by-design target for this field.
        try:
            assert_no_imds_or_loopback_url(v)
        except WebhookUrlForbidden as exc:
            raise ValueError(f"upstream_url rejected: {exc.reason}") from exc
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

    # 1a. codescan #1 (mustui triage 2026-07-20): re-validate upstream_url
    #     immediately before the outbound fetch — last-line-of-defence in
    #     case the config-write-time field_validator was somehow bypassed
    #     (same two-checkpoint pattern as slack_sink.py/teams_sink.py).
    try:
        assert_no_imds_or_loopback_url(body.upstream_url)
    except WebhookUrlForbidden as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "upstream_url_forbidden",
                "message": f"upstream_url rejected: {exc.reason}",
            },
        )

    # 1b. Fetch tools/list from the upstream.
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

    # 2. Day-one-poison screen (YSG-RISK-076 / DP-Y-003 §3.4).
    #    Run BEFORE minting so the verdict is recorded on the envelope and
    #    visible to the operator at import time.  Human still decides — a flag
    #    does NOT auto-reject (EU AI Act Art.14 / DP-Y-003 §3.4).
    #    Degrades safely: when YASHIGANI_SEMANTIC_INTENT_SIDECAR is not
    #    configured, classifier_status="not_configured" is recorded — the import
    #    is NOT silently passed as clean.
    scan_verdict = _screen_tools(body.server_id, raw_tools)

    # 3. Project the raw surface into a typed capability envelope.
    tenant = _install_tenant()
    provenance_id = f"{tenant}:{body.server_id}"
    env = project_surface(
        provenance_id=provenance_id,
        tenant_id=tenant,
        raw_tools=raw_tools,
        egress_posture=body.egress_posture,
    )

    # 4. Approve.
    #
    # v4.1 Phase 1c (SYNTHESIS.md Issue-1 step 6 — "approve = transaction"):
    # ring_fenced servers are onboarded through the ATOMIC transaction —
    # mint per-instance leaf → codegen the Caddy-front wrap → write artifacts
    # → caddy reload → durable envelope INSERT (the commit point, carrying
    # svid_issued=True only because a real cert now exists).  Any step
    # failure rolls back everything (fail-closed; no partial onboarding, no
    # BUG-A false svid evidence).  'DB row only' no longer exists for
    # ring-fenced topology.
    #
    # external_relay (remote/cloud endpoint) has no local container: there is
    # no ringfence bridge, no shim and nothing to wrap — the envelope row
    # (with svid_issued=False, honestly) remains the whole ceremony.
    svc = _envelope_service()
    onboard_result = None
    if body.topology == TOPOLOGY_RING_FENCED:
        if not body.manifest_yaml:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "manifest_required",
                    "message": (
                        "ring_fenced imports require manifest_yaml: the approve "
                        "ceremony provisions the per-instance leaf and Caddy-front "
                        "wrap atomically (v4.1 Phase 1c). Supply the Shape-C "
                        "manifest for this server."
                    ),
                },
            )
        from yashigani.backoffice.mcp_onboard import (
            McpOnboardError,
            run_approve_transaction,
        )
        try:
            onboard_result = await run_approve_transaction(
                manifest_yaml=body.manifest_yaml,
                server_id=body.server_id,
                tenant_id=tenant,
                env=env,
                topology=body.topology,
                sidecar_scan_verdict=scan_verdict,
                operator_identity=session.account_id,
                envelope_service=svc,
                audit_writer=backoffice_state.audit_writer,
                # v4.1 Phase 2a (SEAM-1d-07): durable broker registry — the
                # gateway lazily registers the onboarded MCP; /mcp/<server>
                # routes without a gateway reboot.  None → the transaction
                # fail-closes in production/staging, warn-skips in dev/test.
                registry_store=_durable_registry_store(),
            )
        except McpOnboardError as exc:
            raise HTTPException(
                status_code=exc.http_status,
                detail={
                    "error": "onboard_transaction_failed",
                    "failed_step": exc.step,
                    "message": str(exc),
                },
            )
        new_id = onboard_result.envelope_id
    else:
        try:
            new_id = await svc.mint_envelope(
                env,
                server_id=body.server_id,
                operator_identity=session.account_id,
                topology=body.topology,
                sidecar_scan_verdict=scan_verdict,  # YSG-RISK-076: persist screen verdict
            )
        except Exception as exc:
            envelope, _ = safe_error_envelope(exc, public_message="envelope mint failed")
            raise HTTPException(status_code=500, detail=envelope)

    tool_names = sorted(env.tools.keys())
    suspicious = scan_verdict.get("suspicious_content_flagged", False)
    logger.info(
        "mcp-servers: imported server_id=%r provenance=%r tools=%d envelope_id=%d "
        "by admin=%s screen=%s suspicious=%s wrap=%s",
        body.server_id, provenance_id, len(tool_names), new_id, session.account_id,
        scan_verdict.get("classifier_status"), suspicious,
        (onboard_result.spiffe_id if onboard_result else "n/a"),
    )
    if suspicious:
        logger.warning(
            "mcp-servers: day-one-poison screen FLAGGED suspicious content on "
            "server=%r — operator review required before trusting this surface",
            body.server_id,
        )

    response = {
        "server_id": body.server_id,
        "provenance_id": provenance_id,
        "envelope_id": new_id,
        "tool_count": len(tool_names),
        "tools": tool_names,
        "topology": body.topology,
        "egress_posture": body.egress_posture,
        "approved_by": session.account_id,
        "sidecar_scan_verdict": scan_verdict,            # YSG-RISK-076: surface for operator
        "suspicious_content_flagged": suspicious,         # day-one-poison screen result
    }
    if onboard_result is not None:
        # v4.1 Phase 1c — wrap provisioning evidence (per-instance identity +
        # written artifacts). svid_issued=True is backed by the cert on disk.
        response["svid"] = {
            "instance_id": onboard_result.instance_id,
            "spiffe_id": onboard_result.spiffe_id,
            "svid_issued": True,
        }
        response["artifacts"] = onboard_result.artifact_paths
        # FINDING-V412-ONBOARDING-ROBUSTNESS #5 (Tom, 2026-07-21): this
        # ceremony registers the capability envelope + broker route but does
        # NOT start the agent's container — backoffice has no docker/podman
        # socket access by design (LAURA-30-001 / YSG-RISK-080, the same
        # boundary #4's decommission `container_teardown` field documents).
        # `deploy` surfaces the exact scoped command the operator runs next,
        # closing the "what do I do now" documentation gap without backoffice
        # ever touching the container layer itself.
        response["deploy"] = onboard_result.deploy_hint
    return response


# ---------------------------------------------------------------------------
# Decommission — FINDING-V412-ONBOARDING-ROBUSTNESS #4
# ---------------------------------------------------------------------------

_VALID_TEARDOWN_MODES = frozenset({"keep", "nuke"})


@router.delete("/{server_id}")
async def decommission_mcp_server(
    server_id: str,
    session: StepUpAdminSession,
    mode: str = "keep",
):
    """Decommission (cleanly remove) a ring_fenced MCP server.

    Step-up gated (destructive, matching POST /import's own gate): the admin
    must have a fresh TOTP stamp in their session.

    Reverses the approve transaction end to end (see mcp_onboard.py
    run_decommission_transaction docstring for the full step sequence and
    ordering rationale):
      * the capability envelope is transitioned active -> decommissioned
        (deny-first: /auth/verify-mcp starts denying immediately, before any
        other cleanup runs);
      * the durable broker-registry descriptor + OPA grant/baseline/egress
        grant are deleted (Redis db/3) and the egress-grants revocation is
        pushed live;
      * the broker route is unregistered (Caddy drops the per-instance wrap);
      * the per-instance SVID leaf cert/key and svid-init staging files are
        removed;
      * the runtime-relevant codegen artifacts (compose override / helm
        values) are unlinked.

    Component-isolated: every step above is keyed on (tenant_id, server_id)
    ONLY — no other agent or core service is ever touched. Idempotent: safe
    to call repeatedly, including for a server_id that was never onboarded
    or was already decommissioned (returns 200 with
    ``already_decommissioned: true`` rather than 404/409).

    ``mode`` ("keep" | "nuke", default "keep") selects which command
    guidance the response's ``container_teardown`` field carries for the
    CONTAINER + VOLUME layer. Backoffice performs NO container-level action
    itself — it has no docker/podman socket access by design (LAURA-30-001 /
    YSG-RISK-080; see docker-compose.yml's backoffice service comment). The
    operator (or install.sh) runs the returned scoped compose/helm command.

    Returns: {server_id, tenant_id, already_decommissioned, steps,
    artifacts_removed, svid, container_teardown}
    """
    if mode not in _VALID_TEARDOWN_MODES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_mode",
                "message": "mode must be one of %s" % sorted(_VALID_TEARDOWN_MODES),
            },
        )

    from yashigani.backoffice.mcp_onboard import McpOnboardError, run_decommission_transaction

    svc = _envelope_service()
    tenant = _install_tenant()

    try:
        result = await run_decommission_transaction(
            tenant_id=tenant,
            server_id=server_id,
            operator_identity=session.account_id,
            envelope_service=svc,
            audit_writer=backoffice_state.audit_writer,
            registry_store=_durable_registry_store(),
            container_teardown_mode=mode,
        )
    except McpOnboardError as exc:
        raise HTTPException(
            status_code=exc.http_status,
            detail={
                "error": "decommission_transaction_failed",
                "failed_step": exc.step,
                "message": str(exc),
            },
        )

    logger.info(
        "mcp-servers: decommissioned server_id=%r tenant=%r by admin=%s "
        "mode=%s already_decommissioned=%s steps=%s",
        server_id, tenant, session.account_id, mode,
        result.already_decommissioned, result.steps,
    )

    return {
        "server_id": result.server_id,
        "tenant_id": result.tenant_id,
        "already_decommissioned": result.already_decommissioned,
        "steps": result.steps,
        "artifacts_removed": result.artifact_paths_removed,
        "svid": {
            "instance_id": result.instance_id,
            "spiffe_id": result.spiffe_id,
        },
        "container_teardown": result.container_teardown,
    }
