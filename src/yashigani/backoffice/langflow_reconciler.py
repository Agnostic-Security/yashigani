"""
Yashigani Backoffice — Langflow flow-discovery reconciler (v4.1 Phase B / B3).

Design: AgnosticSecurity/Products/Yashigani/agent-admin-policy-templates-design-20260708.md §6

WHAT THIS DOES
--------------
Polls langflow's ``GET /api/v1/flows`` API and creates INERT pending registry
records for flows that were created in langflow's own UI (not through Yashigani's
governed builder path).

INERT means: no leaf minted, no egress grant written, no envelope issued.
The gateway already 403s any NHI without an explicit admin approval (fail-closed).
Discovered flows surface in the admin UI as "discovered — pending admin approval".

Identity and grant materialise ONLY on explicit admin actions:
  - Approve (NHI approve → mint_agent_leaf) for per-instance identity
  - Apply template (B1 /apply route) for egress grant
This is CREATE-NEVER compliant — nothing is auto-provisioned.

WHAT THIS DOES NOT DO
---------------------
- NEVER auto-widens the langflow union grant (Nico Q-N1 / Laura Q-R3 / §6.3).
  The langflow instance grant stays unchanged until an explicit admin approve+apply.
- NEVER issues a leaf, writes a grant, or mints an envelope automatically.
- Does NOT trust the langflow API: caps flow count (MAX_FLOWS=50) and per-flow
  body size (MAX_FLOW_BYTES=65536 — Laura F9 anti-flood).
- Auth: x-api-key via langflow_auth (F-G fix — auto_login → list/delete stale
  'yashigani-service' keys → create fresh; Laura constraint 2 one-key invariant).
  The previous YASHIGANI_INTERNAL_BEARER bearer approach was broken (langflow
  validates Bearer as a langflow JWT → 401).

GRAPH HASH (Nico Q-N3 / B5)
-----------------------------
graph_hash = SHA-256 of canonical JSON (flow graph with UI-position/viewport/
timestamp keys stripped, keys sorted, compact encoding).  Parser version recorded
for hash-stability across format changes.

This is drift-detection metadata ONLY:
  - Hash change → approval goes stale → re-approval required (mirrors change-
    prevention: cert-rotate deny, GAP-2).
  - NOT a leaf-binding input (leaf scope_hash = tool_surface_hash, unchanged).
  - NOT attestation — the hash covers structure, not runtime behaviour.

IDENTITY (Lu MF-6 / B5)
-------------------------
All audit events carry identity_basis="reconciler" (not "ringfence-position" —
this is a system/service action, not an admin action with mTLS identity).

LANGFLOW RESPONSE AS UNTRUSTED INPUT (Laura F9)
------------------------------------------------
- Cap flow count at MAX_FLOWS (50): excess flows are ignored and logged.
- Cap per-flow body at MAX_FLOW_BYTES (64KiB): flows with oversized bodies
  are skipped with a warning (oversized graph → canonical JSON truncated or
  skipped entirely).
- Flow names are stored raw (not HTML-sanitised at input): XSS defence is
  context-aware output encoding at the UI render layer (B4, agent-policies.js
  uses textContent exclusively).

Last updated: 2026-07-09T00:00:00+00:00
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants (Laura F9 — treat langflow as untrusted)
# ---------------------------------------------------------------------------

MAX_FLOWS = 50          # cap: more than this and we log + skip excess
MAX_FLOW_BYTES = 65536  # 64 KiB per-flow body size cap

# Keys to strip from the flow graph before canonical hashing (UI noise).
# Stripping produces a stable hash across UI-position/viewport edits.
_GRAPH_NOISE_KEYS = frozenset([
    "position", "positionAbsolute", "viewport", "width", "height",
    "selected", "dragging", "id", "ts", "updated_at", "created_at",
])

# Canonical-JSON parser version — increment when stripping logic changes so
# stored hashes can be re-computed and compared against the current version.
_GRAPH_PARSER_VERSION = 1


# ---------------------------------------------------------------------------
# Canonical-graph JSON (Nico Q-N3 / B5)
# ---------------------------------------------------------------------------

def _strip_noise_recursive(obj: Any) -> Any:
    """Recursively strip UI-noise keys from a flow graph object."""
    if isinstance(obj, dict):
        return {
            k: _strip_noise_recursive(v)
            for k, v in obj.items()
            if k not in _GRAPH_NOISE_KEYS
        }
    if isinstance(obj, list):
        return [_strip_noise_recursive(item) for item in obj]
    return obj


def compute_graph_hash(flow_data: dict) -> str:
    """Compute the canonical graph hash for a langflow flow (Nico Q-N3).

    Strips UI-position/viewport/timestamp keys from the flow graph data,
    sorts all dict keys, and produces a compact canonical JSON string.
    Returns SHA-256 as 'sha256:<hex>'.

    This is DRIFT-DETECTION METADATA ONLY — not attestation, not a
    leaf-binding input.
    """
    try:
        # Strip the top-level graph/data structure (langflow nests under "data")
        graph = flow_data.get("data") or flow_data
        stripped = _strip_noise_recursive(graph)
        canonical = json.dumps(stripped, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"
    except Exception as exc:  # noqa: BLE001
        logger.warning("langflow-reconciler: graph hash failed: %s — using empty hash", exc)
        return ""


# ---------------------------------------------------------------------------
# Registry record helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _build_inert_record(
    *,
    flow_id: str,
    flow_name: str,
    graph_hash: str,
    tenant_id: str,
    langflow_system: str,
) -> dict:
    """Build an INERT pending registry record for a discovered flow.

    INERT: no leaf issued, no grant written, no envelope created.
    Surfaces in admin UI as 'discovered — pending admin approval'.

    CREATE-NEVER: identity (leaf) and grant materialise ONLY on explicit
    admin approve + apply actions, never here.
    """
    return {
        # NHI shape (matches the agent registry NHI record format)
        "kind": "nhi",
        "agent_name": f"langflow-nhi-{flow_id[:16]}",   # stable slug from flow ID
        "tenant_id": tenant_id,
        # svid_issued=False: gateway 403s all unapproved NHIs fail-closed
        "svid_issued": False,
        "spiffe_id": "",     # not yet issued — materialises at admin approval
        # Discovery provenance
        "langflow_flow_id": flow_id,
        # Flow name stored raw (HTML encoding happens at UI render layer — B4)
        "langflow_flow_name": flow_name[:256],
        "template_id": "tmpl-langflow-created-default",
        "graph_hash": graph_hash,
        "graph_parser_version": _GRAPH_PARSER_VERSION,
        "langflow_instance": langflow_system,
        "discovered_at": _now_iso(),
        # Status for admin UI ("discovered" triggers the approval affordance)
        "approval_status": "pending",
    }


# ---------------------------------------------------------------------------
# Langflow API client (backoffice→langflow internal dispatch)
# ---------------------------------------------------------------------------

def _fetch_flows(langflow_url: str) -> list[dict]:
    """Fetch flows from langflow GET /api/v1/flows.

    Routes through the Caddy mesh front (YASHIGANI_LANGFLOW_INTERNAL_URL →
    https://caddy:9705/agents/default/langflow) using the backoffice mTLS
    leaf so Caddy's forward_auth gate (verify-mcp) admits the request
    as subject=backoffice toward server=langflow (§2.5 closed allowlist).

    Uses internal_httpx_sync_client (backoffice_client.crt mTLS identity)
    for the Caddy mesh dial — same trust anchor as the langflow_client
    dispatch path (TRACK1-F-04 wiring).

    Auth is x-api-key from langflow_auth (F-G fix): auto_login →
    list/delete stale 'yashigani-service' keys → create fresh key (Laura
    constraint 2).  The previous YASHIGANI_INTERNAL_BEARER bearer approach
    was broken: langflow validates Bearer as a langflow JWT → 401.

    Treat response as UNTRUSTED (Laura F9): per-flow body cap + count cap.
    The total-body pre-parse cap was removed (F-H): it fired on langflow
    1.9.2's ~3.7 MB of default flows (below the 13 MiB OOM guard kept here).

    Raises on HTTP error or network failure — caller logs and skips.
    """
    from yashigani.pki.client import internal_httpx_sync_client  # noqa: PLC0415
    from yashigani.backoffice.langflow_auth import get_langflow_api_headers  # noqa: PLC0415

    # F-H: transport-level OOM guard at a high ceiling so legitimate langflow
    # 1.9.2 default flows (~3.7 MB) are not rejected.  The per-flow body cap
    # (MAX_FLOW_BYTES = 64 KiB) and the flow count cap (MAX_FLOWS = 50) are
    # the PRIMARY Laura F9 anti-flood defences; this guard only protects
    # against pathological response sizes far above any real content.
    _OOM_GUARD_BYTES = 13 * 1024 * 1024  # 13 MiB

    url = langflow_url.rstrip("/") + "/api/v1/flows/"
    headers = {
        **get_langflow_api_headers(),
        "Accept": "application/json",
    }
    with internal_httpx_sync_client(timeout=10.0) as client:
        resp = client.get(url, headers=headers)
        resp.raise_for_status()
        raw = resp.content
        # OOM guard only — NOT a semantic flood cap (F-H: old 3.2 MB cap removed).
        if len(raw) > _OOM_GUARD_BYTES:
            logger.warning(
                "langflow-reconciler: response body %d bytes exceeds OOM guard "
                "%d bytes — ignoring entire response",
                len(raw),
                _OOM_GUARD_BYTES,
            )
            return []
        data = json.loads(raw)
        if not isinstance(data, list):
            logger.warning("langflow-reconciler: /api/v1/flows did not return a list — skipping")
            return []
        # Count cap (Laura F9 primary defence)
        if len(data) > MAX_FLOWS:
            logger.warning(
                "langflow-reconciler: %d flows returned; capping at %d (Laura F9)",
                len(data), MAX_FLOWS,
            )
            data = data[:MAX_FLOWS]
        return data


# ---------------------------------------------------------------------------
# Main reconciler entry point
# ---------------------------------------------------------------------------

def run_langflow_discovery(
    registry_store: Any,
    audit_writer: Any,
    tenant_id: str = "default",
    langflow_system: str = "langflow",
) -> dict:
    """Discover flows created in langflow's own UI and create INERT records.

    Called periodically (60s interval) by the backoffice background task.

    Returns a summary dict: {discovered, skipped_existing, skipped_oversized,
    skipped_error, no_grant_widen (always True)}.

    INVARIANT: this function NEVER widens the langflow union grant (Nico Q-N1).
    The langflow instance egress grant is never touched here.
    """
    stats = {
        "discovered": 0,
        "skipped_existing": 0,
        "skipped_oversized": 0,
        "skipped_error": 0,
        # B5: surfaced in logs/metrics — the union grant is never touched here
        "no_grant_widen": True,
    }

    # Langflow internal URL — read from env (the same pattern langflow_client.py uses)
    langflow_url = os.environ.get(
        "YASHIGANI_LANGFLOW_INTERNAL_URL",
        "http://langflow:7860",
    ).strip()

    # Fetch flows — auth via langflow_auth (F-G fix: x-api-key, not bearer)
    try:
        flows = _fetch_flows(langflow_url)
    except Exception as exc:  # noqa: BLE001
        logger.error("langflow-reconciler: flow fetch failed: %s", exc)
        return stats

    for flow in flows:
        if not isinstance(flow, dict):
            stats["skipped_error"] += 1
            continue

        flow_id = str(flow.get("id", "")).strip()
        if not flow_id:
            stats["skipped_error"] += 1
            continue

        # Per-flow body size cap (Laura F9: oversized graph → skip)
        try:
            flow_bytes = len(json.dumps(flow).encode("utf-8"))
        except Exception:  # noqa: BLE001
            flow_bytes = MAX_FLOW_BYTES + 1  # force skip

        if flow_bytes > MAX_FLOW_BYTES:
            logger.warning(
                "langflow-reconciler: flow %s body %d bytes exceeds cap %d — "
                "skipping (Laura F9)", flow_id[:32], flow_bytes, MAX_FLOW_BYTES,
            )
            stats["skipped_oversized"] += 1
            continue

        # Raw flow name — stored as-is; encoding at render layer (B4)
        flow_name = str(flow.get("name", "") or "").strip()

        # Stable agent_name slug for the registry record
        agent_name = f"langflow-nhi-{flow_id[:16]}"

        # Check if already registered (idempotent)
        try:
            existing = registry_store.get(tenant_id, agent_name)
        except Exception as exc:  # noqa: BLE001
            logger.warning("langflow-reconciler: registry lookup %s failed: %s", agent_name, exc)
            existing = None

        if existing is not None:
            # Already registered — check for graph drift
            existing_hash = existing.get("graph_hash", "")
            new_hash = compute_graph_hash(flow)
            if existing_hash and new_hash and existing_hash != new_hash:
                # Graph changed → mark approval stale (mirrors GAP-2 change-prevention)
                try:
                    existing["graph_hash"] = new_hash
                    existing["approval_status"] = "stale"
                    existing["graph_drifted_at"] = _now_iso()
                    registry_store.put(tenant_id, agent_name, existing)
                    logger.info(
                        "langflow-reconciler: flow %s graph_hash drifted — "
                        "approval marked stale (re-approval required)",
                        flow_id[:32],
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("langflow-reconciler: drift update failed: %s", exc)
            stats["skipped_existing"] += 1
            continue

        # New flow — compute graph hash and create INERT record
        graph_hash = compute_graph_hash(flow)
        record = _build_inert_record(
            flow_id=flow_id,
            flow_name=flow_name,
            graph_hash=graph_hash,
            tenant_id=tenant_id,
            langflow_system=langflow_system,
        )

        try:
            # INERT: write registry record ONLY — no leaf, no grant, no envelope
            registry_store.put(tenant_id, agent_name, record)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "langflow-reconciler: failed to write inert record for flow %s: %s",
                flow_id[:32], exc,
            )
            stats["skipped_error"] += 1
            continue

        # Audit: LANGFLOW_FLOW_DISCOVERED (drift-detection metadata only)
        if audit_writer is not None:
            try:
                from yashigani.audit.schema import LangflowFlowDiscoveredEvent  # noqa: PLC0415
                # Do NOT pass tenant_id here — the reconciler is a system/service
                # process, not a tenant-scoped action.  The default tenant_id=""
                # on LangflowFlowDiscoveredEvent maps to _NULL_TENANT_UUID in
                # PostgresSink._flush_batch, keeping it consistent with other
                # system audit events (IdentityStoreConflictEvent, SoD).
                # Passing the slug ("default") caused
                # "ERROR: invalid input syntax for type uuid: 'default'" every
                # ~60s because sinks.py set_config used the slug raw and the
                # RLS policy tried current_setting('app.tenant_id')::uuid.
                audit_writer.write(LangflowFlowDiscoveredEvent(
                    flow_id=flow_id,
                    flow_name_truncated=flow_name[:128],
                    graph_hash=graph_hash,
                    parser_version=_GRAPH_PARSER_VERSION,
                    langflow_instance=langflow_system,
                    # Lu disclosure (v4.1): egress is instance-level, not per-flow
                ))
            except Exception as audit_exc:  # noqa: BLE001
                logger.error("langflow-reconciler: audit write failed: %s", audit_exc)

        stats["discovered"] += 1
        logger.info(
            "langflow-reconciler: discovered flow %s (%r) — "
            "INERT record written (no grant, no leaf, no envelope — "
            "CREATE-NEVER compliant, gateway 403s unapproved NHIs fail-closed)",
            flow_id[:32], flow_name[:64],
        )

    logger.info(
        "langflow-reconciler: run complete — discovered=%d existing=%d "
        "oversized=%d error=%d no_grant_widen=%s",
        stats["discovered"], stats["skipped_existing"],
        stats["skipped_oversized"], stats["skipped_error"],
        stats["no_grant_widen"],
    )
    return stats


__all__ = [
    "run_langflow_discovery",
    "compute_graph_hash",
]
