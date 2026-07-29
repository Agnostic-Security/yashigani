"""
Yashigani RBAC — OPA data push.

Pushes the rbac + agents data documents to OPA after every mutation so that
OPA's policy rules always have a consistent view of group membership,
resource patterns, and agent RBAC configuration.

The push is fire-and-forget from the caller's perspective:
  - Success is silent.
  - Non-2xx HTTP or network errors raise an exception — the caller is
    responsible for logging/auditing; the mutation itself already succeeded.

V50-022 (Tom, 2026-07-29) — SCOPED sub-path PUTs, NEVER a parent-path
replace:
    PUT {opa_url}/v1/data/yashigani/rbac    <- opa_doc directly
    PUT {opa_url}/v1/data/yashigani/agents  <- agent_doc directly

Previously this module PUT the PARENT path (``/v1/data/yashigani``) with a
body of ONLY ``{"rbac": ..., "agents": ...}``. OPA's Data API PUT-to-a-path
REPLACES the ENTIRE subtree at that path — a parent-path PUT with a partial
body silently WIPES every sibling sub-document OPA holds under
``data.yashigani.*`` that this module doesn't know about: ``mcp`` (grants/
baselines/egress_grants — mcp/_opa_push.py), ``document`` (documents/
opa_push.py), ``allocations`` (models/opa_push.py). Concretely: onboard an
MCP server (correctly, scopedly writes data.yashigani.mcp) -> an admin
creates/edits an RBAC group or grant (this module fires on EVERY RBAC
mutation) -> the onboarded server's grants/baselines vanish from OPA with
no error anywhere -> every subsequent tools/call denies
rbac_capability_envelope_not_active. Every writer under data.yashigani.*
MUST scope its PUT to its own sub-path — mirroring the convention
mcp/_opa_push.py already used correctly (see its own module docstring:
"PUT /v1/data/yashigani/mcp ... does NOT touch the rbac/agents sub-
documents"). This module was the one writer that had NOT followed that
convention; it now scopes to its own two sub-paths instead of the shared
parent, exactly like every other writer under data.yashigani.*.

Two separate PUTs are required — OPA's Data API PUT-to-a-path replaces
exactly that address; there is no way to write two disjoint sibling paths
(``rbac`` and ``agents``) in a single call without also being a parent-path
write (the very thing being fixed). Each raises independently on failure
(unchanged "raises on any push failure" contract callers already handle);
a failure on the SECOND PUT (agents) after the first (rbac) succeeded still
raises, so the caller's existing error handling is unaffected — the only
behavioural change is that this module no longer clobbers sibling
sub-documents it doesn't own.
"""
from __future__ import annotations

import logging

import httpx

from yashigani.pki.client import internal_httpx_sync_client
from yashigani.rbac.store import RBACStore

logger = logging.getLogger(__name__)

_OPA_RBAC_PATH = "/v1/data/yashigani/rbac"
_OPA_AGENTS_PATH = "/v1/data/yashigani/agents"


def push_rbac_data(
    store: RBACStore | None,
    opa_url: str,
    agent_registry=None,
    raw_document: dict | None = None,
) -> None:
    """
    Build the rbac + agents data documents from *store* (and optionally
    *agent_registry*) and PUT EACH to its OWN scoped OPA sub-path —
    ``/v1/data/yashigani/rbac`` and ``/v1/data/yashigani/agents`` — NEVER
    the parent ``/v1/data/yashigani`` (V50-022: a parent-path PUT silently
    wipes sibling sub-documents this module does not own — see module
    docstring).

    If *raw_document* is provided it is used directly as the ``rbac`` sub-
    document instead of calling ``store.to_opa_document()``.  This is used
    by the OPA Policy Assistant apply route which pushes a validated RBAC
    document without going through the local RBACStore.

    Resulting data shape (unchanged from before V50-022 — only the WRITE
    scoping changed, not the final data.yashigani.{rbac,agents} content):
        data.yashigani.rbac = {
            "groups": { "<id>": { ... }, ... },
            "user_groups": { "<email>": ["<id>", ...], ... }
        }
        data.yashigani.agents = {
            "<agent_id>": {
                "allowed_caller_groups": [...],
                "allowed_paths": [...]
            }, ...
        }

    Raises:
        httpx.HTTPStatusError  — OPA returned a non-2xx status on either PUT.
        httpx.RequestError     — Network or connection error on either PUT.
    """
    if raw_document is not None:
        opa_doc = raw_document
    else:
        assert store is not None, "push_rbac_data: store is required when raw_document is None"
        opa_doc = store.to_opa_document()

    # Build agents sub-document from registry (active agents only)
    agent_doc: dict = {}
    if agent_registry is not None:
        try:
            for agent in agent_registry.list_all():
                if agent.get("status") == "active":
                    agent_doc[agent["agent_id"]] = {
                        "allowed_caller_groups": agent.get("allowed_caller_groups", []),
                        "allowed_paths": agent.get("allowed_paths", []),
                        # Include caller's own groups so OPA can match them
                        "groups": agent.get("groups", []),
                    }
        except Exception as exc:
            logger.warning("push_rbac_data: failed to build agent document: %s", exc)

    rbac_url = opa_url.rstrip("/") + _OPA_RBAC_PATH
    agents_url = opa_url.rstrip("/") + _OPA_AGENTS_PATH
    # v2.23.2: OPA serves mTLS; use internal_httpx_sync_client (EX-231-01).
    # V50-022: TWO scoped sub-path PUTs, never one parent-path PUT — each
    # replaces ONLY its own address, leaving data.yashigani.mcp / .document /
    # .allocations (siblings this module does not own) untouched.
    with internal_httpx_sync_client(timeout=10.0) as client:
        rbac_response = client.put(
            rbac_url,
            json=opa_doc,
            headers={"Content-Type": "application/json"},
        )
        rbac_response.raise_for_status()

        agents_response = client.put(
            agents_url,
            json=agent_doc,
            headers={"Content-Type": "application/json"},
        )
        agents_response.raise_for_status()

    group_count = len(opa_doc.get("groups", {}))
    user_count = len(opa_doc.get("user_groups", {}))
    agent_count = len(agent_doc)
    logger.info(
        "OPA rbac+agents data pushed (scoped sub-paths, V50-022): %d groups, "
        "%d users with group assignments, %d active agents",
        group_count,
        user_count,
        agent_count,
    )
