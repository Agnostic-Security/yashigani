"""
Yashigani MCP — OPA data push for grants + baselines (v4.1 Phase 2b / Seam-3).

Problem (Lu Medium × Breaks-flow)
----------------------------------
``data.yashigani.mcp.grants[mcp_id][spiffe]`` and
``data.yashigani.mcp.baselines[mcp_id]`` live in OPA memory.  An OPA restart
wipes them — all subsequent ``mcp.tools.call`` invocations deny with
``no_per_instance_grant`` or ``capability_envelope_not_active`` until the data
is re-pushed.

Fix
---
At gateway startup (after ``build_registry_from_env``), build the combined MCP
data document from the durable broker-registry store (Redis db/3) and push it
to OPA at ``/v1/data/yashigani/mcp``.  This is orthogonal to the existing
RBAC push (``rbac/opa_push.py`` → ``/v1/data/yashigani``).

OPA partial PUT semantics (see https://www.openpolicyagent.org/docs/latest/rest-api/):
    PUT /v1/data/yashigani/mcp   replaces only the mcp sub-document and does
    NOT touch the rbac/agents sub-documents already present.  Both pushes are
    safe to run independently; no lock is needed.

Failure posture: any error is logged at WARNING and propagated — the caller
decides whether a push failure is fatal (startup) or best-effort (mutation).
The gateway startup path treats OPA-unreachable as non-fatal (OPA starts
concurrently) and will deny invocations until OPA has the data.

Last updated: 2026-07-08T00:00:00+00:00
"""
from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

_OPA_MCP_DATA_PATH = "/v1/data/yashigani/mcp"


def push_mcp_opa_data(opa_url: str, mcp_doc: dict) -> None:
    """PUT the MCP grants + baselines document to OPA.

    Replaces ``data.yashigani.mcp`` atomically without touching the rbac/agents
    sub-documents (OPA partial-replace semantics on a sub-path PUT).

    ``mcp_doc`` shape (produced by ``DurableMcpRegistryStore.build_mcp_opa_data``)::

        {
          "grants":    {mcp_id: {caller_spiffe: {tools: [...], actions: [...]}}},
          "baselines": {mcp_id: {surface_hash: "sha384:<hex>", tools: [...]}},
          "egress_grants": {spiffe: {tenant: ..., prefixes: [...]}},
        }

    Raises:
        httpx.HTTPStatusError  — OPA returned a non-2xx status.
        httpx.RequestError     — Network or connection error.
    """
    from yashigani.pki.client import internal_httpx_sync_client

    url = opa_url.rstrip("/") + _OPA_MCP_DATA_PATH
    with internal_httpx_sync_client(timeout=10.0) as client:
        resp = client.put(
            url,
            json=mcp_doc,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()

    n_grants = sum(len(v) for v in mcp_doc.get("grants", {}).values())
    n_baselines = len(mcp_doc.get("baselines", {}))
    n_egress = len(mcp_doc.get("egress_grants", {}))
    logger.info(
        "OPA MCP data pushed: %d instance grant(s) + %d baseline(s) + "
        "%d egress grant(s)",
        n_grants, n_baselines, n_egress,
    )


def push_egress_grants(opa_url: str, egress_grants_doc: dict) -> None:
    """PUT ONLY the ``egress_grants`` sub-document to OPA.

    v4.1 unified-sidecar Phase 1 (Lu M1).  Sub-path PUT
    (``/v1/data/yashigani/mcp/egress_grants``) replaces the egress_grants
    subtree WITHOUT touching grants/baselines (OPA partial-replace
    semantics) — used by:

      * the gateway startup path when the durable store is not wired (the
        full Seam-3 push does not run, but the transitional bundled-system
        seed must still land or pre-migration openclaw egress denies);
      * the backoffice approve transaction after commit (new grant live
        without waiting for a gateway restart) — and by any future
        offboard/revocation path (grant-absence in the re-pushed document IS
        the revocation — the kill switch, Nico Q3).

    ``egress_grants_doc`` MUST be the FULL egress_grants document
    (``yashigani.mcp._egress_grants.build_egress_grants_doc``) — pushing a
    partial dict would silently revoke every grant not included.

    Raises (caller decides fatal vs warn — deny-until-pushed is fail-closed):
        httpx.HTTPStatusError  — OPA returned a non-2xx status.
        httpx.RequestError     — Network or connection error.
    """
    from yashigani.pki.client import internal_httpx_sync_client

    url = opa_url.rstrip("/") + _OPA_MCP_DATA_PATH + "/egress_grants"
    with internal_httpx_sync_client(timeout=10.0) as client:
        resp = client.put(
            url,
            json=egress_grants_doc,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()

    logger.info(
        "OPA egress_grants pushed: %d grant(s) keyed on exact SPIFFE",
        len(egress_grants_doc),
    )


def push_and_verify_egress_grants(
    opa_url: str,
    egress_grants_doc: dict,
    must_be_absent: Optional[frozenset] = None,
) -> None:
    """Push ``egress_grants`` to OPA and verify the push landed.

    Fail-closed for revoke/narrow operations (Lu MF-2, Nico gaps 2/3, HIGH):
    after the PUT, reads back the ``egress_grants`` sub-document from OPA and
    asserts that every SPIFFE in ``must_be_absent`` is genuinely absent.  If
    the push fails OR the readback still contains a must-be-absent SPIFFE,
    raises ``RuntimeError`` — better to surface a hard error than to silently
    leave a stale ``allow`` in OPA.

    For add-only operations (``must_be_absent=None`` or empty), delegates
    directly to ``push_egress_grants`` (raises on push failure; no readback).

    Raises:
        httpx.HTTPStatusError  — OPA returned a non-2xx on push or readback.
        httpx.RequestError     — Network / connection error on push or readback.
        RuntimeError           — Readback unavailable OR must-be-absent SPIFFE
                                 still present after push.
    """
    push_egress_grants(opa_url, egress_grants_doc)  # raises on push failure

    if not must_be_absent:
        return  # add-only: no readback needed

    from yashigani.pki.client import internal_httpx_sync_client  # noqa: PLC0415

    readback_url = opa_url.rstrip("/") + _OPA_MCP_DATA_PATH + "/egress_grants"
    try:
        with internal_httpx_sync_client(timeout=10.0) as client:
            resp = client.get(
                readback_url,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            result_doc: dict = resp.json().get("result") or {}
    except Exception as exc:
        raise RuntimeError(
            "egress-grants: revoke verification readback failed — cannot "
            "confirm revocation landed in OPA; refusing to report success "
            "(fail-closed, Lu MF-2). Restore OPA connectivity and re-push. "
            "Underlying error: %s" % exc
        ) from exc

    still_present = [s for s in must_be_absent if s in result_doc]
    if still_present:
        raise RuntimeError(
            "egress-grants: revoke push readback shows %d must-be-absent "
            "SPIFFE(s) still present in OPA — stale allow; revocation did "
            "NOT land (fail-closed, Lu MF-2): %s"
            % (len(still_present), still_present)
        )

    logger.info(
        "egress-grants: revoke verification PASS — %d SPIFFE(s) confirmed "
        "absent from OPA egress_grants after push",
        len(must_be_absent),
    )


__all__ = ["push_and_verify_egress_grants", "push_egress_grants", "push_mcp_opa_data"]
