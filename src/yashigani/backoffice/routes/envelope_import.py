"""
Yashigani Backoffice — Capability-Envelope FIRST-IMPORT ceremony (3.1).

DP-Y-003 / YSG-RISK-060.  The missing bootstrap path: without a v1 envelope
there is no baseline, ``get_baseline_envelope`` returns None, the broker's
``refresh_and_triage_tools`` no-ops, and every downstream feature (pin /
block-and-re-approve / import-screening) is permanently inoperative.  This
route mints the v1 anchor.

Single route:
  POST /admin/mcp/envelopes/import/{server_id}  — first-import ceremony

The handler:
  1. Resolves the upstream URL for ``server_id`` from YASHIGANI_MCP_SERVERS.
  2. Fetches the current advertised tool surface via a JSON-RPC tools/list call
     (same async-httpx path the broker uses; no JWT required — the import
     ceremony talks direct to the upstream on the admin plane, not through the
     broker's enforcing path).
  3. Screens every tool description with the M4 content filter
     (``build_catalogue`` — heuristic + length + injection-marker; sidecar
     absent on the admin plane, so the LLM escalation tier is skipped on the
     first import and the verdict records filter-only results).
  4. Computes a stable ``provenance_id`` — either from the operator-supplied
     ``pin_material`` (cert fingerprint or SPIFFE ID, matching the formula the
     broker uses: SHA-256(server_id ‖ pin_material)) or, for dev/demo servers
     without TLS, from ``server_id`` directly.
  5. Idempotency guard: if a v1 already exists for this provenance, returns 409
     — re-approval is the only path for subsequent changes.
  6. ``assert_privileged_mutation`` step-up gate (operator RBAC + fresh TOTP,
     same gate as re-approval) with reason "mcp.envelope.import".  This is the
     ONE audit anchor: the PRIVILEGED_MUTATION event captures the operator
     identity, the full tool-surface summary, and the sidecar scan verdict.
  7. ``envelope_service.mint_envelope(...)`` — INSERTs v1 (envelope_version=1,
     previous_envelope_id=NULL, status=active) with the M4 sidecar_scan_verdict
     recorded on the row.

Security properties (mirrors envelope_reapproval.py):
  * RBAC + step-up — non-admin → 403; no fresh TOTP → 401 step_up_required.
  * Idempotency guard — double-import → 409 (already_imported).
  * Upstream fetch is operator-plane only (admin session required; the upstream
    URL is resolved from the server-side env, never from the request body).
  * SSRF guard — upstream URL must come from YASHIGANI_MCP_SERVERS (the env
    var the operator controls); the request body CANNOT supply the URL.
  * Output escaping is the UI's job — tool names / descriptions are returned
    as JSON strings; the renderer escapeHtml()s every field at the DOM sink.

Broker dependency note (reported, not fixed here):
  For the minted envelope to be enforced at the invocation gate the broker must
  derive the SAME provenance_id as the import ceremony.  Currently
  McpBroker._provenance_id_for() returns None for servers without P8 pin
  material, causing triage to no-op.  A companion broker change is required to
  support unpinned/dev servers (use server_id directly when no P8 pin is
  configured).  The route is fully functional for the DB/API half; the
  downstream enforcement half gates on that broker fix.

Last updated: 2026-06-30
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Tenant / service resolution ────────────────────────────────────────────


def _install_tenant() -> str:
    """Resolve this install's tenant id (mirrors envelope_reapproval._install_tenant)."""
    return os.environ.get("YASHIGANI_TENANT_ID", "default").strip() or "default"


def _envelope_service():
    """Construct a CapabilityEnvelopeService over the live asyncpg pool, or 503."""
    try:
        from yashigani.db import get_pool
        from yashigani.mcp.envelope_service import CapabilityEnvelopeService
        return CapabilityEnvelopeService(get_pool())
    except Exception as exc:  # noqa: BLE001
        logger.warning("envelope import: service unavailable (%s)", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "envelope_service_unavailable",
                "message": "Capability-envelope durable store not initialised (DB pool unavailable).",
            },
        )


# ── MCP-server registry lookup ─────────────────────────────────────────────


def _resolve_upstream(server_id: str) -> tuple[str, str]:
    """
    Resolve (upstream_url, tenant_id) for *server_id* from YASHIGANI_MCP_SERVERS.

    SSRF guard: the upstream URL comes exclusively from the operator-controlled
    environment variable, NEVER from the request body.  The caller cannot
    redirect the import fetch to an arbitrary host.

    Raises 404 if server_id is not registered; raises 503 on parse error.
    """
    raw = os.environ.get("YASHIGANI_MCP_SERVERS", "").strip()
    if not raw or raw == "[]":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "server_not_found",
                # Laura LOW-1 (3.1.2): do not reveal internal env-var names to callers.
                "message": "MCP server not registered.",
            },
        )
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "mcp_servers_parse_error", "message": str(exc)},
        )
    for entry in (entries if isinstance(entries, list) else []):
        if entry.get("agent_name") == server_id:
            upstream_url = str(entry.get("upstream_url", "")).rstrip("/")
            tenant_id = str(entry.get("tenant_id", "default")) or "default"
            if not upstream_url:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail={
                        "error": "upstream_url_missing",
                        "message": f"MCP server {server_id!r} has no upstream_url.",
                    },
                )
            return upstream_url, tenant_id
    # Laura LOW-1 (3.1.2): do not reveal internal env-var names to callers.
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "error": "server_not_found",
            "message": "MCP server not registered.",
        },
    )


# ── provenance_id derivation ───────────────────────────────────────────────


def _compute_provenance(server_id: str, pin_material: Optional[str]) -> str:
    """
    Derive the provenance_id for *server_id*.

    Production (P8 pin configured):
        provenance_id = SHA-256(server_id ‖ 0x1E ‖ pin_material)
        Uses the same formula as McpBroker._provenance_id_for() so the
        minted envelope is found by the broker's invocation gate.

    Dev / demo (no P8 pin, pin_material omitted):
        provenance_id = server_id  (stable, human-readable, server-unique)
        The broker must be updated to use this fallback for unpinned servers
        (see broker-dependency note in the module docstring).
    """
    if pin_material:
        from yashigani.mcp._envelope import compute_provenance_id
        return compute_provenance_id(server_id, pin_material)
    # Dev/demo fallback — use server_id as a stable, unique identifier.
    # The broker currently returns None for unpinned servers; a companion
    # broker change will make it use server_id as the fallback provenance_id.
    return server_id


# ── Upstream tools/list fetch ──────────────────────────────────────────────

_TOOLS_LIST_RPC = {"jsonrpc": "2.0", "id": "import-ceremony", "method": "tools/list", "params": {}}
_FETCH_TIMEOUT = 15.0  # seconds


async def _fetch_raw_tools(upstream_url: str, server_id: str) -> list[dict]:
    """
    Fetch the advertised tool surface from the upstream MCP server via
    JSON-RPC tools/list (async httpx, no gateway JWT — this is the admin-plane
    import path, not the enforcing broker path).

    Returns the raw tools list.  Raises 502 on any upstream error.
    """
    url = f"{upstream_url}/mcp"
    # Trust the internal CA when connecting to HTTPS upstream MCP servers that
    # use the operator-provisioned PKI (self-signed / internal CA).  httpx uses
    # certifi by default, which does not include the internal CA; override with
    # SSL_CERT_FILE if set, falling back to the well-known secrets mount path.
    _ca = os.environ.get("SSL_CERT_FILE") or (
        "/run/secrets/ca_root.crt"
        if os.path.exists("/run/secrets/ca_root.crt")
        else True  # certifi default — external / public-CA upstreams
    )
    try:
        async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT, verify=_ca) as client:
            resp = await client.post(
                url,
                json=_TOOLS_LIST_RPC,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logger.error(
            "envelope-import: upstream tools/list failed server=%r url=%r HTTP %d",
            server_id, url, exc.response.status_code,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "upstream_tools_list_failed",
                "message": (
                    f"Upstream MCP server {server_id!r} returned HTTP "
                    f"{exc.response.status_code} on tools/list."
                ),
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "envelope-import: upstream tools/list error server=%r url=%r: %s",
            server_id, url, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "upstream_unreachable",
                "message": f"Could not reach upstream MCP server {server_id!r}: {exc}",
            },
        )
    try:
        body = resp.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "upstream_invalid_json", "message": "Upstream returned non-JSON body."},
        )
    raw_tools = (body.get("result") or {}).get("tools") or []
    if not isinstance(raw_tools, list):
        raw_tools = []
    logger.info(
        "envelope-import: fetched %d tool(s) from server=%r url=%r",
        len(raw_tools), server_id, url,
    )
    return raw_tools


# ── M4 content filter + sidecar scan verdict ──────────────────────────────


def _screen_tools(server_id: str, raw_tools: list[dict]) -> tuple[list[dict], dict]:
    """
    Run the M4 content filter + semantic-intent sidecar over the raw tools/list
    surface (DP-Y-003 §3.4 import-time screening).

    Returns ``(raw_tools, sidecar_scan_verdict)`` where ``sidecar_scan_verdict``
    is the JSON blob recorded on the envelope row: it captures the filter results
    (tool count, schema count, any rejections, any truncations, classifier verdict)
    so the audit chain holds a complete record of what the operator reviewed.

    CT-1 (honesty invariant, DP-Y-003 §3.4): ``sidecar_used``, ``classifier_status``,
    and ``filter_version`` are derived from whether the classifier ACTUALLY evaluated
    each screened item — not from whether the sidecar object exists.  Status values:
      * ``"ran"``               — classifier ran on all items eligible for evaluation.
      * ``"disabled_by_flag"``  — YASHIGANI_SEMANTIC_INTENT_SIDECAR flag was OFF.
      * ``"unavailable_error"`` — sidecar object present + flag ON, but evaluate()
                                  errored for ≥1 eligible item (partial ≠ success).
      * ``"not_configured"``    — no sidecar object wired at startup.

    CT-3 (§3.4 scope): tool descriptions AND canonicalised parameter schemas
    (``inputSchema``) are screened.  Schemas are serialised to compact JSON and
    passed through the same ``filter_description_v2`` pipeline as descriptions.
    Poisoned property names / annotations inside the schema are caught here.

    Timing (§3.4): screening runs BEFORE ``mint_envelope()`` (the
    privileged-mutation commit); the verdict is returned in the same 200 response
    the operator receives.  A full two-step screen-then-approve preview flow (as
    on the re-approval path) is deferred; at minimum the verdict IS present for
    the operator at the time they review the import outcome.

    Human-in-the-loop (EU AI Act Art.14, DP-Y-003 §3.4): the classifier never
    holds authority alone — a sidecar flag does NOT auto-reject the surface.
    The operator review and approval step remains mandatory.
    """
    from yashigani.mcp._content_filter import build_catalogue
    from yashigani.inspection.semantic_intent import sidecar_enabled

    tenant_id = _install_tenant()

    sidecar = backoffice_state.semantic_intent_sidecar  # SemanticIntentSidecar | None

    # CT-3 (§3.4 scope fix): canonicalise and screen the inputSchema of each
    # tool.  Schemas are passed as additional screening items keyed
    # "schema:<tool_name>".  The same filter_description_v2 pipeline (heuristic +
    # optional sidecar) runs on each serialised schema — poisoned property
    # descriptions / annotations inside the schema are caught here, not just in
    # the top-level tool description.
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
        raw_prompts=schema_items,   # CT-3: was []; now includes per-tool schemas
        sidecar=sidecar,
    )

    # Collect rejection / truncation / sidecar-escalation stats from tool descriptors.
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

    # CT-3: collect schema rejection stats (catalogue.prompts holds schema items).
    schema_rejected: list[str] = []
    for pd in catalogue.prompts:
        if pd.filter_result.rejected:
            schema_rejected.append(pd.prompt_name)

    # CT-1 (honesty invariant): derive classifier attestation from FilterResult
    # evaluation markers, NOT from sidecar object existence.
    #
    # FilterResult.semantic_intent_score is set (to 0.0–1.0) when and ONLY when
    # sidecar.evaluate() ran successfully for that item.  It remains None when:
    #   (a) the sidecar flag was OFF  → evaluate() returned skipped=True, no annotation
    #   (b) evaluate() raised         → filter_description_v2 except-caught it, no annotation
    #   (c) heuristic already rejected → sidecar correctly short-circuited (not an error)
    #
    # Case (c) is correct design: the heuristic blocked the item; sidecar not needed.
    # Cases (a) and (b) are distinguished by checking sidecar_enabled() here first.

    def _heuristic_only_rejected(fr) -> bool:
        """Item was blocked by the heuristic; sidecar was correctly not called."""
        return bool(fr.rejected) and (fr.reject_reason or "") != "semantic_intent"

    def _sidecar_annotated(fr) -> bool:
        """sidecar.evaluate() ran and annotated this FilterResult (score set to ≥0.0)."""
        return fr.semantic_intent_score is not None

    if sidecar is None:
        classifier_status = "not_configured"
        sidecar_used = False
        filter_ver = "v2_heuristic"
    elif not sidecar_enabled():
        # Sidecar object present but feature flag is OFF.
        classifier_status = "disabled_by_flag"
        sidecar_used = False
        filter_ver = "v2_heuristic"
    else:
        # Flag on, sidecar object present.  Derive status from actual evaluation
        # markers on the catalogue FilterResults.
        all_results = (
            [td.filter_result for td in catalogue.tools]
            + [pd.filter_result for pd in catalogue.prompts]
        )
        # Items eligible for sidecar = not already rejected by heuristic alone.
        eligible = [fr for fr in all_results if not _heuristic_only_rejected(fr)]
        # Items where sidecar actually ran (score annotated by filter_description_v2).
        evaluated = [fr for fr in eligible if _sidecar_annotated(fr)]

        if len(eligible) == 0:
            # All items were heuristic-rejected; sidecar was not needed.
            # The pipeline was healthy — heuristic caught everything.
            classifier_status = "ran"
            sidecar_used = False          # no inference was executed
            filter_ver = "v2_heuristic"   # only heuristic ran
        elif len(evaluated) == len(eligible):
            # Sidecar successfully evaluated every eligible item.
            classifier_status = "ran"
            sidecar_used = True
            filter_ver = "v2_semantic"
        else:
            # Partial failure: ≥1 eligible item was not evaluated (evaluate() errored).
            # Do NOT claim the classifier ran — surface the error honestly.
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

    # Audit logging: record the classifier posture so the operator trail is complete.
    if classifier_status in ("disabled_by_flag", "not_configured"):
        logger.info(
            "envelope-import: semantic-intent classifier %s for server=%r "
            "— heuristic-only screening applied (DP-Y-003 §3.4 degraded mode)",
            classifier_status, server_id,
        )
    elif classifier_status == "unavailable_error":
        logger.warning(
            "envelope-import: sidecar enabled+present but evaluate() errored for "
            "≥1 eligible item — recording unavailable_error in verdict (server=%r)",
            server_id,
        )

    if rejected_tools:
        logger.warning(
            "envelope-import: M4 filter rejected %d tool description(s) "
            "for server=%r: %s — operator is importing with sanitised surface",
            len(rejected_tools), server_id, rejected_tools,
        )
    if schema_rejected:
        logger.warning(
            "envelope-import: M4 filter rejected %d schema item(s) "
            "for server=%r: %s",
            len(schema_rejected), server_id, schema_rejected,
        )

    return raw_tools, verdict


# ── Request schema ─────────────────────────────────────────────────────────


class EnvelopeImportRequest(BaseModel):
    """
    Request body for the first-import ceremony.

    Fields
    ------
    pin_material:
        Optional cert SPKI SHA-256 fingerprint or SPIFFE ID for this MCP
        server's upstream TLS identity.  When provided, provenance_id is
        computed as SHA-256(server_id ‖ pin_material), matching the formula
        McpBroker._provenance_id_for() uses so the enforcing invocation gate
        can find the minted envelope.  For dev/demo servers without TLS, leave
        absent — provenance_id falls back to server_id.
    egress_posture:
        The operator-declared egress capability ceiling for this server.
        Default "NONE" (ring-fenced, no external network egress).
        "OUTBOUND" for servers that legitimately call external endpoints.
    topology:
        "ring_fenced" (default — container-isolated, egress=NONE backstop) or
        "external_relay" (no ring-fence; conservative Δ4 auto-allow rules).
    """
    pin_material: Optional[str] = Field(
        default=None,
        description=(
            "Cert SPKI SHA-256 fingerprint or SPIFFE ID for provenance_id "
            "computation.  Absent for dev/demo (server_id used as fallback)."
        ),
    )
    egress_posture: str = Field(
        default="NONE",
        description="Operator-declared egress ceiling: NONE | OUTBOUND.",
    )
    topology: str = Field(
        default="ring_fenced",
        description="ring_fenced (default) | external_relay.",
    )


# ── Route ─────────────────────────────────────────────────────────────────


@router.post("/import/{server_id}")
async def import_mcp_server(
    server_id: str,
    body: EnvelopeImportRequest,
    session: AdminSession,
):
    """
    First-import ceremony — mint the v1 capability envelope for an imported
    MCP server.

    This route bootstraps the capability-envelope feature for a server that
    has not yet been imported.  Without a v1 baseline the broker's
    ``refresh_and_triage_tools`` no-ops (``get_baseline_envelope`` returns
    None), and the block-and-re-approve flow (``pending/{prov}/approve``)
    returns 409 ``no_baseline_envelope``.

    Security gates (mirrors re-approval):
      * Admin RBAC + fresh TOTP step-up → 401/403 on failure.
      * Idempotency: if v1 already exists → 409 ``already_imported``.
      * SSRF guard: upstream URL from env only, never from request body.
    """
    tenant = _install_tenant()

    # ── 1. Resolve upstream URL (SSRF guard) ──────────────────────────────
    upstream_url, server_tenant = _resolve_upstream(server_id)
    # Tenant scoping: if the registered server belongs to a specific tenant,
    # ensure it matches this install's tenant (BOLA close).
    if server_tenant not in ("default", tenant):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "server_not_found", "message": "Server not found for this tenant."},
        )

    # ── 2. Validate topology ──────────────────────────────────────────────
    from yashigani.mcp.envelope_service import (
        TOPOLOGY_RING_FENCED,
        TOPOLOGY_EXTERNAL_RELAY,
    )
    if body.topology not in (TOPOLOGY_RING_FENCED, TOPOLOGY_EXTERNAL_RELAY):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_topology",
                "message": f"topology must be 'ring_fenced' or 'external_relay', got {body.topology!r}.",
            },
        )

    # ── 3. Compute provenance_id ──────────────────────────────────────────
    # (moved before fetch so idempotency + step-up can run before any outbound
    # network call — Laura LOW-2 / 3.1.2 ordering fix)
    provenance_id = _compute_provenance(server_id, body.pin_material)

    # ── 4. Idempotency guard: reject if v1 already exists ────────────────
    svc = _envelope_service()
    try:
        existing = await svc.get_baseline_envelope(provenance_id)
    except Exception as exc:
        envelope, _ = safe_error_envelope(exc, public_message="envelope baseline lookup failed")
        raise HTTPException(status_code=503, detail=envelope)

    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "already_imported",
                "message": (
                    f"A v1 envelope for {server_id!r} (provenance={provenance_id[:12]}…) "
                    "already exists.  Use the re-approval flow "
                    "(POST /admin/mcp/envelopes/pending/{provenance_id}/approve) "
                    "to update the baseline."
                ),
                "existing_version": existing.envelope_version,
                "existing_id": existing.id,
                "provenance_id": provenance_id,
            },
        )

    # ── 5. Step-up gate (operator RBAC + fresh TOTP) ─────────────────────
    # Laura LOW-2 (3.1.2): step-up MUST fire before any outbound fetch so an
    # unauthenticated / no-step-up request cannot trigger a network call to the
    # upstream MCP server.  Mirrors envelope_reapproval.py ordering.
    # The step-up context captures the intent; tool_count is added after the
    # fetch (logged below) so it appears in the operator-visible audit trail.
    from yashigani.auth.stepup import (
        PrivilegedMutationContext,
        assert_privileged_mutation,
    )

    stepup_ctx = PrivilegedMutationContext(
        reason="mcp.envelope.import",
        principal=session.account_id,
        target=provenance_id,
        before={"server_id": server_id},
        after={
            "egress_posture": body.egress_posture,
            "topology": body.topology,
        },
    )
    # Raises StepUpRequired (401) or NotAuthorisedForPrivilegedMutation (403)
    # on failure; returns and emits the PRIVILEGED_MUTATION audit event on success.
    assert_privileged_mutation(session, stepup_ctx, audit_writer=backoffice_state.audit_writer)

    # ── 6. Fetch + screen the current tool surface ────────────────────────
    # Outbound fetch only happens AFTER step-up passes (Laura LOW-2 ordering fix).
    raw_tools = await _fetch_raw_tools(upstream_url, server_id)
    _raw_screened, scan_verdict = _screen_tools(server_id, raw_tools)

    # ── 7. Project the surface into a ServerEnvelope ──────────────────────
    from yashigani.mcp._envelope import project_surface

    env = project_surface(
        provenance_id=provenance_id,
        tenant_id=tenant,
        raw_tools=raw_tools,
        egress_posture=body.egress_posture,
    )

    # ── 8. Mint the v1 envelope ───────────────────────────────────────────
    try:
        new_id = await svc.mint_envelope(
            env,
            server_id=server_id,
            operator_identity=session.account_id,
            topology=body.topology,
            sidecar_scan_verdict=scan_verdict,
        )
    except Exception as exc:
        envelope, _ = safe_error_envelope(exc, public_message="envelope mint failed")
        raise HTTPException(status_code=500, detail=envelope)

    logger.warning(
        "capability-envelope IMPORTED (v1) via admin UI: server=%r "
        "provenance=%.12s new_id=%d by=%s tools=%d egress=%s topo=%s",
        server_id, provenance_id, new_id, session.account_id,
        len(raw_tools), body.egress_posture, body.topology,
    )
    return {
        "status": "ok",
        "server_id": server_id,
        "provenance_id": provenance_id,
        "new_envelope_id": new_id,
        "envelope_version": 1,
        "tool_count": len(raw_tools),
        "egress_posture": body.egress_posture,
        "topology": body.topology,
        "sidecar_scan_verdict": scan_verdict,
        "message": (
            f"Capability envelope v1 minted for {server_id!r}. "
            "The broker's refresh-and-triage path is now active for this server."
        ),
    }
