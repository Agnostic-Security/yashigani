"""
Yashigani Gateway — shared type definitions.

ResolvedPrincipal
-----------------
Single typed container for the resolved identity at the gateway boundary.
Set on ``request.state.ysg_principal`` by the boundary resolver (openai_router,
mcp_router_runtime, or proxy._resolve_gateway_principal) **before** any rate
limiting, OPA adjudication, or permission-store lookup.

Every downstream consumer reads:
    rp = getattr(request.state, "ysg_principal", None)

If None, the resolver did not run (code-path gap) — the consumer must treat
this as an unresolved identity and DENY.

3.1 UID unification — replaces scattered ``x-yashigani-user-id`` header reads.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ResolvedPrincipal:
    """
    Immutable resolved-principal record written once per request at the
    gateway boundary.

    Fields
    ------
    identity_id:
        The canonical UID for authz/audit/rate-limiting.

        - Human users:      idnt_{12hex}  (from identity registry)
        - Agent principals: agnt_{12hex} (from agent registry)
        - Internal service: "internal"    (server-minted bearer)
        - Orchestrator:     "gateway:orchestrator"
        - Unresolved:       "anonymous"   (never trust; downstream must DENY)

    principal_scope:
        "user"  — human principal; user-tier grant narrowing fires.
        "agent" — agent principal; agent-tier grant narrowing fires.
        None    — no per-principal narrowing (org+group ceiling only).

    group_ids:
        List of group IDs resolved from the identity registry at boundary
        time.  Empty for agents and service identities.

    org_id:
        The principal's org (org ceiling for all permission checks).
        Defaults to YASHIGANI_ORG_ID / "default" in single-instance mode.

    kind:
        "human" | "agent" | "service" | "orchestrator"
        Mirrors identity_registry identity.get("kind").
    """

    identity_id: str                        # idnt_{12hex} | agnt_{12hex} | "internal"
    principal_scope: Optional[str]          # "user" | "agent" | None
    group_ids: list[str] = field(default_factory=list)
    org_id: str = "default"
    kind: str = "unknown"
