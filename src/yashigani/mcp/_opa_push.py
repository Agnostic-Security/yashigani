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

Last updated: 2026-07-06T00:00:00+00:00
"""
from __future__ import annotations

import logging
from typing import Any

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
    logger.info(
        "OPA MCP data pushed: %d instance grant(s) + %d baseline(s)",
        n_grants, n_baselines,
    )


__all__ = ["push_mcp_opa_data"]
