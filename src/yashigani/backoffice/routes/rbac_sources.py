"""
Yashigani Backoffice — RBAC group source paths and HTTP method catalogue (R13).

Last updated: 2026-06-13T00:00:00+01:00

Routes:
  GET /admin/rbac/sources/paths    — available resource paths for dropdown pre-population
  GET /admin/rbac/sources/methods  — HTTP methods with plain-language descriptions

These endpoints let the UI pre-populate the RBAC group editor with real MCP
resource paths and plain-English method descriptions rather than requiring free-text
entry.

All routes require an admin session.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Catalogue: HTTP methods with plain-language descriptions
# ---------------------------------------------------------------------------

#: Canonical method descriptions surfaced to the UI.
#: Ordered by logical priority for display (full-access first, read-only last).
_METHOD_CATALOGUE: list[dict[str, str]] = [
    {
        "method": "*",
        "label": "All methods",
        "description": (
            "Permit any HTTP method — full access to the matched path(s). "
            "Use when you want to grant unrestricted access to an endpoint."
        ),
        "risk": "high",
    },
    {
        "method": "GET",
        "label": "Read",
        "description": (
            "Read-only access. Permits listing resources, fetching status, "
            "and retrieving tool/prompt/resource manifests. Does not allow "
            "creating, modifying, or deleting anything."
        ),
        "risk": "low",
    },
    {
        "method": "POST",
        "label": "Create / invoke",
        "description": (
            "Create new resources or invoke operations (e.g. calling a tool, "
            "starting a session, submitting a request). Most MCP tool calls "
            "use POST."
        ),
        "risk": "medium",
    },
    {
        "method": "PUT",
        "label": "Update (replace)",
        "description": (
            "Replace an existing resource in full. Used for configuration "
            "updates where the entire object is overwritten."
        ),
        "risk": "medium",
    },
    {
        "method": "PATCH",
        "label": "Update (partial)",
        "description": (
            "Partially modify an existing resource. Used for incremental "
            "configuration changes."
        ),
        "risk": "medium",
    },
    {
        "method": "DELETE",
        "label": "Delete",
        "description": (
            "Permanently remove a resource. High-impact: deleted resources "
            "cannot be recovered unless a backup exists."
        ),
        "risk": "high",
    },
    {
        "method": "HEAD",
        "label": "Head check",
        "description": (
            "Retrieve HTTP headers without a response body. Equivalent to "
            "GET for access-control purposes."
        ),
        "risk": "low",
    },
    {
        "method": "OPTIONS",
        "label": "Options / CORS preflight",
        "description": (
            "Used by browsers for CORS preflight checks. Rarely needs to be "
            "constrained explicitly."
        ),
        "risk": "low",
    },
]


# ---------------------------------------------------------------------------
# Catalogue: well-known MCP path prefixes
# ---------------------------------------------------------------------------

#: Well-known path prefixes available in Yashigani's MCP gateway.
#: Sourced from the MCP specification and Yashigani's manifest catalogue.
_WELL_KNOWN_PATH_PREFIXES: list[dict[str, Any]] = [
    # MCP core protocol
    {
        "path": "**",
        "glob": "**",
        "label": "All paths (unrestricted)",
        "description": "Matches every path — grants access to the entire gateway.",
        "category": "global",
        "risk": "high",
    },
    {
        "path": "/tools/**",
        "glob": "/tools/**",
        "label": "All tools",
        "description": "Matches all MCP tool endpoints (list + call).",
        "category": "mcp-core",
        "risk": "medium",
    },
    {
        "path": "/tools/list",
        "glob": "/tools/list",
        "label": "Tool list",
        "description": "List available tools. Read-only capability discovery.",
        "category": "mcp-core",
        "risk": "low",
    },
    {
        "path": "/tools/call",
        "glob": "/tools/call",
        "label": "Tool call",
        "description": "Invoke any tool. High-impact: executes arbitrary tool operations.",
        "category": "mcp-core",
        "risk": "high",
    },
    {
        "path": "/resources/**",
        "glob": "/resources/**",
        "label": "All resources",
        "description": "Matches all MCP resource endpoints (list + read + subscribe).",
        "category": "mcp-core",
        "risk": "medium",
    },
    {
        "path": "/resources/list",
        "glob": "/resources/list",
        "label": "Resource list",
        "description": "List available resources. Read-only capability discovery.",
        "category": "mcp-core",
        "risk": "low",
    },
    {
        "path": "/resources/read",
        "glob": "/resources/read",
        "label": "Resource read",
        "description": "Read a specific resource by URI.",
        "category": "mcp-core",
        "risk": "medium",
    },
    {
        "path": "/resources/subscribe",
        "glob": "/resources/subscribe",
        "label": "Resource subscribe",
        "description": "Subscribe to resource change notifications.",
        "category": "mcp-core",
        "risk": "low",
    },
    {
        "path": "/prompts/**",
        "glob": "/prompts/**",
        "label": "All prompts",
        "description": "Matches all MCP prompt endpoints (list + get).",
        "category": "mcp-core",
        "risk": "low",
    },
    {
        "path": "/prompts/list",
        "glob": "/prompts/list",
        "label": "Prompt list",
        "description": "List available prompts.",
        "category": "mcp-core",
        "risk": "low",
    },
    {
        "path": "/prompts/get",
        "glob": "/prompts/get",
        "label": "Prompt get",
        "description": "Retrieve a specific prompt by name.",
        "category": "mcp-core",
        "risk": "low",
    },
    {
        "path": "/sampling/**",
        "glob": "/sampling/**",
        "label": "Sampling (LLM inference)",
        "description": (
            "LLM sampling endpoints. Grants permission to submit requests "
            "to the configured language model."
        ),
        "category": "mcp-core",
        "risk": "high",
    },
    # Yashigani-specific paths
    {
        "path": "/yashigani/**",
        "glob": "/yashigani/**",
        "label": "Yashigani gateway API (all)",
        "description": "All Yashigani-specific gateway control endpoints.",
        "category": "gateway",
        "risk": "high",
    },
    {
        "path": "/v1/**",
        "glob": "/v1/**",
        "label": "OpenAI-compatible API (all)",
        "description": "OpenAI-compatible v1 endpoints (chat/completions, models, etc.).",
        "category": "gateway",
        "risk": "medium",
    },
    {
        "path": "/v1/chat/**",
        "glob": "/v1/chat/**",
        "label": "Chat completions",
        "description": "OpenAI-compatible chat completion endpoints.",
        "category": "gateway",
        "risk": "high",
    },
    {
        "path": "/v1/models",
        "glob": "/v1/models",
        "label": "Model list",
        "description": "List available models via the OpenAI-compatible API.",
        "category": "gateway",
        "risk": "low",
    },
    {
        "path": "/health",
        "glob": "/health",
        "label": "Health check",
        "description": "Gateway liveness/readiness endpoint. Read-only.",
        "category": "gateway",
        "risk": "low",
    },
]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get(
    "/sources/paths",
    summary="R13: Available RBAC resource paths for dropdown pre-population",
    tags=["rbac"],
)
async def get_rbac_source_paths(session: AdminSession):
    """
    GET /admin/rbac/sources/paths

    Returns the available resource path patterns for RBAC group configuration.
    Includes well-known MCP paths plus any paths discovered from the active
    agent bundle manifests registered in this deployment.

    Each entry carries:
      - path / glob: the literal glob to use in allowed_resources
      - label: short human-readable name
      - description: plain-English explanation of what the path covers
      - category: grouping for UI display
      - risk: low / medium / high — helps operators choose minimal privilege

    Use the "glob" field as the path_glob value when creating/updating RBAC groups.
    """
    paths = list(_WELL_KNOWN_PATH_PREFIXES)

    # Augment with paths from registered agent bundle manifests if available.
    try:
        bundle_store = getattr(backoffice_state, "agent_bundle_store", None)
        if bundle_store is None:
            # Try to get bundles via agent_registry
            registry = backoffice_state.agent_registry
            if registry is not None:
                bundles = getattr(registry, "list_bundles", None)
                if callable(bundles):
                    for bundle in (bundles() or []):
                        for endpoint in getattr(bundle, "endpoints", []):
                            path_str = getattr(endpoint, "path", None)
                            if path_str and not any(
                                p["glob"] == path_str for p in paths
                            ):
                                paths.append({
                                    "path": path_str,
                                    "glob": path_str,
                                    "label": f"Agent: {path_str}",
                                    "description": (
                                        f"Path from registered agent bundle "
                                        f"'{getattr(bundle, 'name', 'unknown')}'."
                                    ),
                                    "category": "agent-bundle",
                                    "risk": "medium",
                                })
    except Exception as exc:
        logger.debug("rbac/sources/paths: bundle augmentation skipped: %s", exc)

    return {
        "count": len(paths),
        "paths": paths,
        "usage_note": (
            "Use the 'glob' field as the 'path_glob' value in RBAC group "
            "allowed_resources. Combine with a method (or '*') to grant "
            "access to specific operations."
        ),
    }


@router.get(
    "/sources/methods",
    summary="R13: HTTP methods with plain-language descriptions",
    tags=["rbac"],
)
async def get_rbac_source_methods(session: AdminSession):
    """
    GET /admin/rbac/sources/methods

    Returns all HTTP methods supported in RBAC resource patterns, with
    plain-language descriptions suitable for UI labels and tooltips.

    Each entry carries:
      - method: the literal value to use in the 'method' field
      - label: short human-readable name (e.g. "Read", "Create / invoke")
      - description: plain-English explanation of what the method permits
      - risk: low / medium / high — helps operators choose minimal privilege

    Use the "method" field as the 'method' value when creating/updating
    RBAC groups. Use '*' to permit all methods on a path.
    """
    return {
        "count": len(_METHOD_CATALOGUE),
        "methods": _METHOD_CATALOGUE,
        "allowed_values": [m["method"] for m in _METHOD_CATALOGUE],
        "usage_note": (
            "Use the 'method' field as the 'method' value in RBAC group "
            "allowed_resources. '*' grants all methods; prefer the most "
            "restrictive method your use-case requires."
        ),
    }
