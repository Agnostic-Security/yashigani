"""
Yashigani RBAC — OPA data push.

Pushes the full combined data document (rbac + agents) to OPA after every
mutation so that OPA's policy rules always have a consistent view of group
membership, resource patterns, and agent RBAC configuration.

The push is fire-and-forget from the caller's perspective:
  - Success is silent.
  - Non-2xx HTTP or network errors raise an exception — the caller is
    responsible for logging/auditing; the mutation itself already succeeded.

OPA Data API endpoint:
    PUT {opa_url}/v1/data/yashigani

This replaces the entire yashigani namespace atomically (rbac + agents).
"""
from __future__ import annotations

import logging

import httpx

from yashigani.pki.client import internal_httpx_sync_client
from yashigani.rbac.store import RBACStore

logger = logging.getLogger(__name__)

_OPA_DATA_PATH = "/v1/data/yashigani"


def push_rbac_data(
    store: RBACStore | None,
    opa_url: str,
    agent_registry=None,
    raw_document: dict | None = None,
) -> None:
    """
    Build the combined data document from *store* (and optionally *agent_registry*)
    and PUT it to OPA at /v1/data/yashigani atomically.

    If *raw_document* is provided it is used directly as the ``rbac`` sub-document
    instead of calling ``store.to_opa_document()``.  This is used by the OPA Policy
    Assistant apply route which pushes a validated RBAC document without going
    through the local RBACStore.

    The document shape expected by policy/:
        {
            "rbac": {
                "groups": { "<id>": { ... }, ... },
                "user_groups": { "<identity_id>": ["<id>", ...], ... }
            },
            "agents": {
                "<agent_id>": {
                    "allowed_caller_groups": [...],
                    "allowed_paths": [...]
                }, ...
            }
        }

    Raises:
        httpx.HTTPStatusError  — OPA returned a non-2xx status.
        httpx.RequestError     — Network or connection error.
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

    payload = {
        "rbac": opa_doc,
        "agents": agent_doc,
    }

    url = opa_url.rstrip("/") + _OPA_DATA_PATH
    # v2.23.2: OPA serves mTLS; use internal_httpx_sync_client (EX-231-01).
    with internal_httpx_sync_client(timeout=10.0) as client:
        response = client.put(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()

    group_count = len(opa_doc.get("groups", {}))
    user_count = len(opa_doc.get("user_groups", {}))
    agent_count = len(agent_doc)
    logger.info(
        "OPA data pushed: %d groups, %d users with group assignments, %d active agents",
        group_count,
        user_count,
        agent_count,
    )
