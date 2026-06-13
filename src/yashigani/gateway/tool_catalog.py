"""
Yashigani Gateway — RBAC-projected tool catalog for orchestration.

Build sheet §2 (orchestration-buildsheet-20260610).  Assembles the `tools` list
the gateway offers the orchestrator model from three sources, projected through
the caller's existing authorisation so the model can only ever NAME a tool it is
already allowed to use (assertion 3: the catalog is a projection of existing
authorisation; RBAC is enforced twice — projection here, and again at execution).

Sources:
  • @agents      — AgentRegistry.list_active() (Redis db/3).  One function tool
                   per active agent the caller's groups may reach:
                   ``agent__<slug>`` with a fixed ``{task}`` schema.
  • models       — additional models the caller may use as callees:
                   ``model__<sanitised-id>`` with the same ``{task}`` schema.
  • MCP tools    — tools/list from each onboarded MCP server (broker registry)
                   OR, in the Phase-1 demo wiring, the configured demo upstream:
                   ``mcp__<server>__<tool>`` with the server-declared schema.

The catalog returns BOTH the OpenAI tool-def list (offered to the model) and a
``name_map`` resolving each synthetic tool name back to its concrete target
(agent slug / model id / mcp server+tool+schema).  A name not in the map is
rejected by the executor (no SSRF surface — assertion / §7.4).

# Last updated: 2026-06-10T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Double-underscore separators keep the namespace parseable (build sheet §2.1).
_AGENT_PREFIX = "agent__"
_MODEL_PREFIX = "model__"
_MCP_PREFIX = "mcp__"

# Sanitise a model id (dots/colons/slashes) into a tool-name-safe token.
_SANITISE_RE = re.compile(r"[^a-z0-9_]+")

# The fixed minimal schema for agent/model callees — they are black-box chat
# callees; "task" is the user-turn content forwarded to them (§2.1).
_TASK_SCHEMA = {
    "type": "object",
    "properties": {"task": {"type": "string", "description": "The sub-task to delegate."}},
    "required": ["task"],
}


def sanitise_tool_token(raw: str) -> str:
    """Lower-case + collapse non [a-z0-9_] runs to '_' (e.g. qwen2.5:3b → qwen2_5_3b)."""
    return _SANITISE_RE.sub("_", raw.lower()).strip("_")


@dataclass
class CatalogEntry:
    """Resolution target for one catalog tool name."""

    kind: str          # "agent" | "model" | "mcp"
    # agent: the @slug to self-call.  model: the real model id.  mcp: server name.
    target: str
    # mcp only: the upstream tool name + the upstream JSON-RPC URL.
    mcp_tool: Optional[str] = None
    mcp_url: Optional[str] = None
    # The JSON-Schema offered to the model for this tool (for arg validation hints).
    parameters: dict = field(default_factory=dict)


@dataclass
class ToolCatalog:
    tools: list[dict]                       # OpenAI tool-def list offered to the model
    name_map: dict[str, CatalogEntry]       # tool-name → resolution target

    def __len__(self) -> int:
        return len(self.tools)


def _caller_groups(identity: Optional[dict]) -> set[str]:
    if not identity:
        return set()
    return {str(g) for g in (identity.get("groups") or [])}


def _agent_allowed_for_caller(agent: dict, caller_groups: set[str]) -> bool:
    """Agent tool appears iff caller groups ∩ allowed_caller_groups ≠ ∅ (§2.3).

    An agent that declares NO allowed_caller_groups is treated as unrestricted
    (matches the pre-orchestration agent-routing behaviour, where the OPA gate at
    execution time is the load-bearing check).  status must be active.
    """
    if agent.get("status") != "active":
        return False
    allowed = {str(g) for g in (agent.get("allowed_caller_groups") or [])}
    if not allowed:
        return True  # unrestricted agent; execution-time OPA still gates the hop
    return bool(caller_groups & allowed)


def _agent_tools(agent_registry, identity: Optional[dict],
                 name_map: dict[str, CatalogEntry]) -> list[dict]:
    out: list[dict] = []
    if agent_registry is None:
        return out
    caller_groups = _caller_groups(identity)
    try:
        agents = agent_registry.list_active()
    except Exception as exc:
        logger.warning("tool_catalog: agent list failed: %s", exc)
        return out
    for agent in agents:
        slug = agent.get("name", "")
        if not slug or not _agent_allowed_for_caller(agent, caller_groups):
            continue
        tool_name = f"{_AGENT_PREFIX}{slug}"
        protocol = agent.get("protocol", "openai")
        desc = agent.get("description") or (
            f"Delegate a sub-task to the '{slug}' agent ({protocol})."
        )
        out.append({
            "type": "function",
            "function": {"name": tool_name, "description": desc, "parameters": _TASK_SCHEMA},
        })
        name_map[tool_name] = CatalogEntry(kind="agent", target=slug, parameters=_TASK_SCHEMA)
    return out


def _model_tools(identity: Optional[dict], allowed_model_ids: list[str],
                 name_map: dict[str, CatalogEntry],
                 effective=None) -> list[dict]:
    """Project model-as-tool entries — RBAC-projected through the EFFECTIVE alloc.

    LAURA-B1R-001 (catalog projection gap): a model appears as a callable tool
    ONLY if the caller is ALLOCATED it under the SAME single model-RBAC authority
    the chat egress + orchestration seed use (``EffectiveModels.is_model_denied``,
    which folds in own allowed_models ∪ org/group/user allocations ∪ the global
    gated set).  Previously this used the identity's RAW ``allowed_models`` and
    treated empty == "all" — so an allocation-based caller (empty raw list) saw
    EVERY local model as a tool, including a gated model allocated only to another
    user/group (e.g. fastuser saw model__qwen2_5_3b).  A non-allocated model must
    NOT appear as a callable tool.  The execution-time alloc-bind on the model
    self-call is the load-bearing second gate (defence in depth, openai_router).

    ``effective`` is the caller's resolved ``EffectiveModels``; when None (no
    allocation enforcement wired) we fall back to the legacy raw-allowed_models
    projection so deployments with no model RBAC keep their behaviour.
    """
    out: list[dict] = []
    caller_allowed = {str(m) for m in (identity.get("allowed_models") or [])} if identity else set()
    for model_id in allowed_model_ids:
        if effective is not None:
            # Single authority: hide any model this caller would be DENIED.
            if effective.is_model_denied(model_id):
                continue
        elif caller_allowed and model_id not in caller_allowed:
            continue
        token = sanitise_tool_token(model_id)
        tool_name = f"{_MODEL_PREFIX}{token}"
        out.append({
            "type": "function",
            "function": {
                "name": tool_name,
                "description": f"Delegate a sub-task to the local model '{model_id}'.",
                "parameters": _TASK_SCHEMA,
            },
        })
        name_map[tool_name] = CatalogEntry(kind="model", target=model_id, parameters=_TASK_SCHEMA)
    return out


def _mcp_tools_from_upstream(server_name: str, upstream_url: str,
                             name_map: dict[str, CatalogEntry]) -> list[dict]:
    """Fetch tools/list from a JSON-RPC MCP upstream and project each tool.

    Phase-1 demo wiring: when YASHIGANI_MCP_SERVERS is empty (no broker), the
    orchestrator still needs a gated MCP hop for the headline.  We discover the
    upstream's tools via tools/list (read-only) and project them.  At EXECUTION
    time the orchestrator runs each MCP tool-call through an explicit OPA ingress
    decision + OPA egress decision (G-ORCH-OPA-1) + ResponseInspection — so the
    invariant holds even though the heavyweight JWT-bridge broker is not wired.
    """
    import httpx

    out: list[dict] = []
    rpc = {"jsonrpc": "2.0", "id": "catalog", "method": "tools/list", "params": {}}
    try:
        with httpx.Client(timeout=8.0) as client:
            resp = client.post(upstream_url, json=rpc,
                               headers={"Content-Type": "application/json"})
            resp.raise_for_status()
            tools = (resp.json().get("result", {}) or {}).get("tools", []) or []
    except Exception as exc:
        logger.warning("tool_catalog: MCP tools/list failed for %s (%s): %s",
                       server_name, upstream_url, exc)
        return out
    for t in tools:
        upstream_tool = t.get("name", "")
        if not upstream_tool:
            continue
        tool_name = f"{_MCP_PREFIX}{sanitise_tool_token(server_name)}__{sanitise_tool_token(upstream_tool)}"
        schema = t.get("inputSchema") or {"type": "object", "properties": {}}
        out.append({
            "type": "function",
            "function": {
                "name": tool_name,
                "description": t.get("description", f"MCP tool {upstream_tool} on {server_name}"),
                "parameters": schema,
            },
        })
        name_map[tool_name] = CatalogEntry(
            kind="mcp", target=server_name, mcp_tool=upstream_tool,
            mcp_url=upstream_url, parameters=schema,
        )
    return out


def build_tool_catalog(
    identity: Optional[dict],
    agent_registry,
    available_models: Optional[list[dict]] = None,
    default_model: str = "",
    effective=None,
) -> ToolCatalog:
    """Assemble the RBAC-projected catalog for one orchestration request (§2).

    Returns a ToolCatalog whose ``tools`` is offered to the orchestrator model and
    whose ``name_map`` the executor uses to resolve each tool-call back to a gated
    self-call target.  Sources that fail (registry down, MCP unreachable) degrade
    gracefully to fewer tools rather than failing the whole orchestration.

    ``effective`` is the caller's resolved ``EffectiveModels`` (Track B1).  When
    supplied, ``model__*`` tools are projected through the SINGLE model-RBAC
    authority so a non-allocated model never appears as a callable tool
    (LAURA-B1R-001).  When None, the legacy raw-allowed_models projection applies.
    """
    name_map: dict[str, CatalogEntry] = {}
    tools: list[dict] = []

    # 1) @agents
    tools.extend(_agent_tools(agent_registry, identity, name_map))

    # 2) models-as-tools.  Source the local model ids from available_models;
    #    fall back to the default model.  The orchestrator brain itself is also a
    #    model, but it is the caller, not a callee — callee models are still gated.
    model_ids: list[str] = []
    for m in (available_models or []):
        mid = m.get("id") or m.get("name") or ""
        # Only local/ollama models are projectable as callees in Phase 1.
        owned = (m.get("owned_by") or "").lower()
        if mid and ("ollama" in owned or "local" in owned or not owned):
            model_ids.append(mid)
    if not model_ids and default_model:
        model_ids = [default_model]
    tools.extend(_model_tools(identity, model_ids, name_map, effective=effective))

    # 3) MCP tools.
    #    Phase-1 demo wiring: when an explicit orchestration MCP upstream is
    #    configured (YASHIGANI_ORCH_MCP_SERVERS as JSON {name: url} OR the demo
    #    UPSTREAM_MCP_URL), project its tools.  When the heavyweight broker
    #    registry is populated in a later phase, this is where its tools/list
    #    projection would plug in (via dispatch_mcp_call, gated identically).
    mcp_servers = _resolve_mcp_servers()
    for server_name, upstream_url in mcp_servers.items():
        tools.extend(_mcp_tools_from_upstream(server_name, upstream_url, name_map))

    logger.info(
        "tool_catalog: built %d tool(s) for identity=%s (agents+models+mcp): %s",
        len(tools), identity.get("identity_id", "?") if identity else "anonymous",
        sorted(name_map.keys()),
    )
    return ToolCatalog(tools=tools, name_map=name_map)


def _resolve_mcp_servers() -> dict[str, str]:
    """Map orchestration MCP server-name → JSON-RPC URL for Phase-1 catalog/exec.

    Precedence:
      1. YASHIGANI_ORCH_MCP_SERVERS — JSON object {"<name>": "<url>", ...}.
      2. UPSTREAM_MCP_URL pointing at the demo upstream (http://demo-mcp:8000) →
         exposed as server name "demo".  This is the headline demo path.
    Empty / unset → no MCP tools (orchestration still works for agents/models).
    """
    raw = os.environ.get("YASHIGANI_ORCH_MCP_SERVERS", "").strip()
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                return {str(k): str(v) for k, v in obj.items()}
        except json.JSONDecodeError as exc:
            logger.warning("tool_catalog: YASHIGANI_ORCH_MCP_SERVERS invalid JSON: %s", exc)
    # In-container the demo upstream URL is exposed as YASHIGANI_UPSTREAM_URL
    # (compose maps the host-side UPSTREAM_MCP_URL → YASHIGANI_UPSTREAM_URL).
    # Read both so the demo path works whether the var is the in-container or the
    # host-side name.
    upstream = (os.environ.get("YASHIGANI_UPSTREAM_URL", "").strip()
                or os.environ.get("UPSTREAM_MCP_URL", "").strip())
    if upstream and "demo-mcp" in upstream:
        return {"demo": upstream}
    return {}
