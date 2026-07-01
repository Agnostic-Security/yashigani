"""
OPA Policy Assistant — Pre-validated Rego template library.

FIND-4.0-REGO-001 Plan B: the LLM's job is reduced to intent classification +
parameter extraction (JSON output — a task 3B models DO reliably), and we fill
a pre-validated Rego template. The result always compiles.

Each template:
  - name: str          — identifier used in LLM classifier output
  - description: str   — one-line description shown to the LLM classifier
  - params: dict       — required parameters with type hints and defaults
  - rego: str          — Rego source with {slug} + {param} substitution markers
  - example_nl: str    — representative NL that maps to this template

NOTE ON TEMPLATE SUBSTITUTION:
  render_template() uses str.replace() NOT str.format(). So:
  - Param markers use {param_name} and are substituted
  - Rego { } for rule bodies are single braces and are LEFT UNTOUCHED
    (they don't collide with any param marker unless the param name happens
    to be a Rego keyword, which is impossible by construction)
  - Do NOT use {{ }} in templates — those are literal double-braces, NOT escapes.

All Rego strings in this file have been validated against OPA v1.16.1
(opa check --v1-compatible, import rego.v1 syntax, deny-contains pattern).

Last updated: 2026-07-01
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Template dataclass
# ---------------------------------------------------------------------------

@dataclass
class RegoTemplate:
    name: str
    description: str
    example_nl: str
    params: dict[str, Any]         # {param_name: {"type": ..., "default": ..., "desc": ...}}
    rego: str                      # Rego source with {slug} and {param_name} markers


# ---------------------------------------------------------------------------
# Pre-validated Rego templates
# IMPORTANT: rule bodies use SINGLE braces { } — NOT double {{ }} —
# because render_template uses str.replace(), not str.format().
# ---------------------------------------------------------------------------

TEMPLATES: list[RegoTemplate] = [

    RegoTemplate(
        name="cloud_block",
        description="Block ALL requests when the routing decision sends them to a cloud provider.",
        example_nl="Block all requests routed to the cloud",
        params={},
        rego=(
            "package clients.{slug}\n"
            "\n"
            "import rego.v1\n"
            "\n"
            'deny contains "request_routed_to_cloud" if {\n'
            '    input.routing_decision.route == "cloud"\n'
            "}\n"
            "\n"
            "default allow := false\n"
            "\n"
            "allow if count(deny) == 0\n"
            "\n"
            'policy_id := "clients.{slug}.{slug}"\n'
            'user_message := "Blocked: requests must not be routed to external cloud providers."\n'
            "code := 403\n"
            'decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}\n'
        ),
    ),

    RegoTemplate(
        name="clearance_gate",
        description=(
            "Block requests when the caller's clearance level exactly equals a specific low level "
            "(e.g. PUBLIC). Use when only the clearance is the blocking condition."
        ),
        example_nl="Block requests from callers with PUBLIC clearance",
        params={
            "denied_clearance": {
                "type": "str",
                "default": "PUBLIC",
                "desc": "The clearance level to deny (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED)",
            }
        },
        rego=(
            "package clients.{slug}\n"
            "\n"
            "import rego.v1\n"
            "\n"
            'deny contains "clearance_not_permitted" if {\n'
            '    input.identity.clearance == "{denied_clearance}"\n'
            "}\n"
            "\n"
            "default allow := false\n"
            "\n"
            "allow if count(deny) == 0\n"
            "\n"
            'policy_id := "clients.{slug}.{slug}"\n'
            'user_message := "Blocked: your clearance level does not permit this request."\n'
            "code := 403\n"
            'decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}\n'
        ),
    ),

    RegoTemplate(
        name="clearance_cloud_block",
        description=(
            "Block requests when a caller with a specific clearance level tries to use a cloud route. "
            "Use when BOTH clearance AND cloud route are the conditions."
        ),
        example_nl="Block PUBLIC clearance users from routing requests to the cloud",
        params={
            "denied_clearance": {
                "type": "str",
                "default": "PUBLIC",
                "desc": "The clearance level to deny on cloud routes",
            }
        },
        rego=(
            "package clients.{slug}\n"
            "\n"
            "import rego.v1\n"
            "\n"
            'deny contains "clearance_blocked_from_cloud" if {\n'
            '    input.identity.clearance == "{denied_clearance}"\n'
            '    input.routing_decision.route == "cloud"\n'
            "}\n"
            "\n"
            "default allow := false\n"
            "\n"
            "allow if count(deny) == 0\n"
            "\n"
            'policy_id := "clients.{slug}.{slug}"\n'
            'user_message := "Blocked: your clearance level does not permit requests to be routed to cloud providers."\n'
            "code := 403\n"
            'decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}\n'
        ),
    ),

    RegoTemplate(
        name="group_allowlist",
        description="Allow only callers who are members of a specific group; block everyone else.",
        example_nl="Allow only users in the finance group",
        params={
            "required_group": {
                "type": "str",
                "default": "finance",
                "desc": "Group name that is allowed through",
            }
        },
        rego=(
            "package clients.{slug}\n"
            "\n"
            "import rego.v1\n"
            "\n"
            'deny contains "not_in_required_group" if {\n'
            '    not "{required_group}" in input.identity.groups\n'
            "}\n"
            "\n"
            "default allow := false\n"
            "\n"
            "allow if count(deny) == 0\n"
            "\n"
            'policy_id := "clients.{slug}.{slug}"\n'
            'user_message := "Blocked: access is restricted to members of the {required_group} group."\n'
            "code := 403\n"
            'decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}\n'
        ),
    ),

    RegoTemplate(
        name="model_denylist",
        description="Block requests when the model being used (routing_decision.model) is a specific denied model name.",
        example_nl="Block requests that use gpt-4",
        params={
            "denied_model": {
                "type": "str",
                "default": "gpt-4",
                "desc": "Model name to deny",
            }
        },
        rego=(
            "package clients.{slug}\n"
            "\n"
            "import rego.v1\n"
            "\n"
            '_denied_models := {"{denied_model}"}\n'
            "\n"
            'deny contains "model_not_permitted" if {\n'
            "    input.routing_decision.model in _denied_models\n"
            "}\n"
            "\n"
            "default allow := false\n"
            "\n"
            "allow if count(deny) == 0\n"
            "\n"
            'policy_id := "clients.{slug}.{slug}"\n'
            'user_message := "Blocked: the requested model is not permitted by policy."\n'
            "code := 403\n"
            'decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}\n'
        ),
    ),

    RegoTemplate(
        name="cost_cap",
        description="Block requests whose estimated cost (in USD) exceeds a numeric threshold.",
        example_nl="Block requests that would cost more than 5 dollars",
        params={
            "max_cost_usd": {
                "type": "float",
                "default": 5.0,
                "desc": "Maximum allowed estimated cost in USD (numeric, e.g. 5.0)",
            }
        },
        rego=(
            "package clients.{slug}\n"
            "\n"
            "import rego.v1\n"
            "\n"
            'deny contains "estimated_cost_exceeded" if {\n'
            "    input.request.estimated_cost_usd > {max_cost_usd}\n"
            "}\n"
            "\n"
            "default allow := false\n"
            "\n"
            "allow if count(deny) == 0\n"
            "\n"
            'policy_id := "clients.{slug}.{slug}"\n'
            'user_message := "Blocked: the estimated cost of this request exceeds the permitted limit."\n'
            "code := 403\n"
            'decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}\n'
        ),
    ),

    RegoTemplate(
        name="path_prefix_block",
        description="Block requests whose URL path starts with a specific prefix string.",
        example_nl="Block requests to paths starting with /internal",
        params={
            "path_prefix": {
                "type": "str",
                "default": "/internal",
                "desc": "URL path prefix to block (e.g. /internal, /admin)",
            }
        },
        rego=(
            "package clients.{slug}\n"
            "\n"
            "import rego.v1\n"
            "\n"
            'deny contains "path_prefix_blocked" if {\n'
            '    startswith(input.request.path, "{path_prefix}")\n'
            "}\n"
            "\n"
            "default allow := false\n"
            "\n"
            "allow if count(deny) == 0\n"
            "\n"
            'policy_id := "clients.{slug}.{slug}"\n'
            'user_message := "Blocked: access to this path is not permitted by policy."\n'
            "code := 403\n"
            'decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}\n'
        ),
    ),

    RegoTemplate(
        name="role_filter",
        description="Allow only a specific caller role (human/agent/service); block all others.",
        example_nl="Allow only human users; block agents and services",
        params={
            "allowed_role": {
                "type": "str",
                "default": "human",
                "desc": "The role to allow: human, agent, or service",
            }
        },
        rego=(
            "package clients.{slug}\n"
            "\n"
            "import rego.v1\n"
            "\n"
            'deny contains "role_not_permitted" if {\n'
            '    input.identity.role != "{allowed_role}"\n'
            "}\n"
            "\n"
            "default allow := false\n"
            "\n"
            "allow if count(deny) == 0\n"
            "\n"
            'policy_id := "clients.{slug}.{slug}"\n'
            'user_message := "Blocked: this endpoint is restricted to {allowed_role} callers."\n'
            "code := 403\n"
            'decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}\n'
        ),
    ),

    RegoTemplate(
        name="agent_cloud_model_block",
        description=(
            "Block requests when an agent (role=agent) tries to use a specific model via a cloud route. "
            "Use this when the description mentions agent identity AND a specific model AND cloud routing."
        ),
        example_nl="Block agents when routing to cloud using gpt-4",
        params={
            "denied_model": {
                "type": "str",
                "default": "gpt-4",
                "desc": "The model name to block for agents on cloud routes",
            }
        },
        rego=(
            "package clients.{slug}\n"
            "\n"
            "import rego.v1\n"
            "\n"
            'deny contains "agent_cloud_model_blocked" if {\n'
            '    input.identity.role == "agent"\n'
            '    input.routing_decision.route == "cloud"\n'
            '    input.routing_decision.model == "{denied_model}"\n'
            "}\n"
            "\n"
            "default allow := false\n"
            "\n"
            "allow if count(deny) == 0\n"
            "\n"
            'policy_id := "clients.{slug}.{slug}"\n'
            'user_message := "Blocked: agents are not permitted to use this model via cloud routing."\n'
            "code := 403\n"
            'decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}\n'
        ),
    ),

]

# Build lookup map
_TEMPLATE_MAP: dict[str, RegoTemplate] = {t.name: t for t in TEMPLATES}


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------

def render_template(template_name: str, slug: str, params: dict[str, Any]) -> str | None:
    """
    Fill a named template with the given slug and parameters.

    Returns the rendered Rego string, or None if the template is unknown.
    Applies defaults for any missing optional parameters.

    Uses str.replace() — NOT str.format() — so Rego {curly braces} in the
    template source are passed through unchanged.
    """
    tmpl = _TEMPLATE_MAP.get(template_name)
    if tmpl is None:
        return None

    # Merge defaults with provided params
    merged: dict[str, Any] = {}
    for pname, pspec in tmpl.params.items():
        if pname in params:
            merged[pname] = params[pname]
        elif "default" in pspec:
            merged[pname] = pspec["default"]
        else:
            return None  # required param missing with no default

    # Render: first apply {slug}, then apply {param} substitutions
    rego = tmpl.rego.replace("{slug}", slug)
    for pname, pval in merged.items():
        rego = rego.replace("{" + pname + "}", str(pval))

    return rego


def template_names_with_descriptions() -> list[dict]:
    """Return [{name, description, example_nl, params_summary}] for the LLM classifier."""
    result = []
    for t in TEMPLATES:
        params_summary = ", ".join(
            f"{k} ({v.get('type','str')})" for k, v in t.params.items()
        ) or "no parameters"
        result.append({
            "name": t.name,
            "description": t.description,
            "example_nl": t.example_nl,
            "params": params_summary,
        })
    return result
