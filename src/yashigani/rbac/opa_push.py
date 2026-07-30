"""
Yashigani RBAC — OPA data push.

Pushes the rbac (+ optionally agents) data documents to OPA after every
mutation so that OPA's policy rules always have a consistent view of group
membership, resource patterns, and agent RBAC configuration.

The push is fire-and-forget from the caller's perspective:
  - Success is silent.
  - Non-2xx HTTP or network errors raise an exception — the caller is
    responsible for logging/auditing; the mutation itself already succeeded.

OPA Data API endpoints (sub-path PUTs — YSG-RISK-176):
    PUT {opa_url}/v1/data/yashigani/rbac
    PUT {opa_url}/v1/data/yashigani/agents   (only when agent_registry is given)

**YSG-RISK-176 (2026-07-30):** this module used to PUT the combined
``{"rbac": ..., "agents": ...}`` document straight to the **namespace ROOT**
(``PUT /v1/data/yashigani``). OPA's Data API PUT REPLACES the entire value at
the target path — a root-path PUT therefore wiped every OTHER sub-document
living under ``data.yashigani`` on every RBAC/agent-registry mutation *and*
on every backoffice startup re-sync (``app.py`` lifespan "OPA-PERSIST" block),
including ``data.yashigani.mcp`` (egress_grants, MCP grants/baselines — see
``yashigani.mcp._egress_grants``), ``data.yashigani.document`` and
``data.yashigani.allocations``. ``policy/clients_aggregate.rego``'s own
comment already documented this exact hazard as the reason ``client_bindings``
was deliberately given a SEPARATE top-level namespace
(``/v1/data/client_bindings``) — but ``mcp``/``document``/``allocations``
were left as sub-paths of the SAME root push_rbac_data replaces, so they were
never protected. Root cause of the 4/4-agent egress DENY regression
(``caller_not_granted_prefix``) after a backoffice restart: the lifespan
RBAC re-sync ran push_rbac_data, wiping the gateway's already-pushed
``egress_grants`` document. Fix: PUT rbac and agents to their OWN sub-paths
under ``data.yashigani`` (matching the pattern already used by
``models/opa_push.py`` → ``/v1/data/yashigani/allocations`` and
``documents/opa_push.py`` → ``/v1/data/yashigani/document``) so neither push
can ever clobber a sibling sub-document again. Bonus fix: this also closes a
latent bug where ``opa_assistant.py``'s ``apply_suggestion`` route (which
never passes ``agent_registry``) silently wiped ``data.yashigani.agents`` to
``{}`` on every RBAC-suggestion apply — the agents PUT is now skipped
entirely when ``agent_registry`` is not supplied, rather than pushing an
empty document over whatever was there.
"""
from __future__ import annotations

import logging

import httpx

from yashigani.pki.client import internal_httpx_sync_client
from yashigani.rbac.store import RBACStore

logger = logging.getLogger(__name__)

_OPA_DATA_PATH_RBAC = "/v1/data/yashigani/rbac"
_OPA_DATA_PATH_AGENTS = "/v1/data/yashigani/agents"


def push_rbac_data(
    store: RBACStore | None,
    opa_url: str,
    agent_registry=None,
    raw_document: dict | None = None,
) -> None:
    """
    Build the rbac data document from *store* (and, if *agent_registry* is
    given, the agents data document) and PUT each to its OWN sub-path under
    OPA's ``data.yashigani`` namespace (YSG-RISK-176 — see module docstring:
    a single combined PUT to the namespace ROOT used to silently wipe every
    OTHER sub-document living under ``data.yashigani``, e.g.
    ``data.yashigani.mcp.egress_grants``).

    If *raw_document* is provided it is used directly as the ``rbac`` sub-document
    instead of calling ``store.to_opa_document()``.  This is used by the OPA Policy
    Assistant apply route which pushes a validated RBAC document without going
    through the local RBACStore.

    When *agent_registry* is ``None`` (e.g. the OPA Policy Assistant apply
    route, which never passes it) the ``agents`` sub-path is NOT touched at
    all — pushing nothing is correct here; pushing an empty ``{}`` would wipe
    any agents document a *different* caller (``agents.py``'s ``_push_opa()``,
    ``rbac.py``'s ``_push()``) had previously pushed.

    Document shapes (each PUT to its own OPA sub-path):
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
        httpx.HTTPStatusError  — OPA returned a non-2xx status.
        httpx.RequestError     — Network or connection error.
    """
    if raw_document is not None:
        opa_doc = raw_document
    else:
        assert store is not None, "push_rbac_data: store is required when raw_document is None"
        opa_doc = store.to_opa_document()

    rbac_url = opa_url.rstrip("/") + _OPA_DATA_PATH_RBAC
    # v2.23.2: OPA serves mTLS; use internal_httpx_sync_client (EX-231-01).
    with internal_httpx_sync_client(timeout=10.0) as client:
        response = client.put(
            rbac_url,
            json=opa_doc,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()

    # Build + push the agents sub-document ONLY when a registry was supplied
    # — an absent registry means "this caller has no agents view to offer",
    # NOT "wipe the agents document" (YSG-RISK-176 bonus fix).
    agent_count = 0
    if agent_registry is not None:
        agent_doc: dict = {}
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

        agents_url = opa_url.rstrip("/") + _OPA_DATA_PATH_AGENTS
        with internal_httpx_sync_client(timeout=10.0) as client:
            response = client.put(
                agents_url,
                json=agent_doc,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
        agent_count = len(agent_doc)

    group_count = len(opa_doc.get("groups", {}))
    user_count = len(opa_doc.get("user_groups", {}))
    logger.info(
        "OPA data pushed: %d groups, %d users with group assignments, %d active agents "
        "(rbac + agents pushed as separate sub-paths — YSG-RISK-176)",
        group_count,
        user_count,
        agent_count,
    )
