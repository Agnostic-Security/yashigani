"""
OPA Policy Assistant — Natural language to Rego policy module generator.

Generates a complete, self-describing Rego module following the Yashigani
decision contract (clients.<slug> package, allow/deny set, policy_id /
user_message / code / decision fields). The output is validated server-side
by the caller via validate_rego_module before being presented to the admin.

SAFE: user description is passed as a separate user message; the system
prompt carries the fixed contract template. Raw LLM output is logged
server-side only — never returned to the client (LAURA-2255-004 pattern).

FIND-4.0-REGO-001 fix — TWO-PATH strategy:

  PRIMARY (Plan B): Template classification + parameter extraction.
    The LLM classifies the NL description into one of the pre-validated
    Rego templates (see rego_templates.py) and returns a small JSON of
    extracted parameters. The template is filled in — always compiles.
    This path is reliable for 3B models: JSON extraction is a constrained
    task they can do correctly.

  FALLBACK (Plan A): Freeform generation + self-repair loop.
    If the NL doesn't match a template (None / unknown template name), or
    template fill fails compile validation, the generator falls back to
    freeform Rego generation. On compile failure the exact OPA error +
    the broken Rego are fed back to the LLM for targeted repair (up to
    N=3 total attempts). Few-shot examples in the system prompt anchor
    the model on rego.v1 syntax.

The route handler owns the repair loop; this module owns the LLM calls.

Last updated: 2026-07-01
"""
from __future__ import annotations

import json
import logging
import re
from typing import Optional

import httpx

from yashigani.opa_assistant.rego_templates import (
    render_template,
    template_names_with_descriptions,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Few-shot examples for freeform fallback path
# Both examples validated against OPA v1.16.1 (rego.v1 mode)
# ---------------------------------------------------------------------------
_FEW_SHOT_EXAMPLES = """\
--- EXAMPLE 1 (copy this structure exactly) ---
package clients.clearance_cloud_block

import rego.v1

deny contains "public_clearance_blocked_from_cloud" if {
    input.identity.clearance == "PUBLIC"
    input.routing_decision.route == "cloud"
}

default allow := false

allow if count(deny) == 0

policy_id := "clients.clearance_cloud_block.clearance_cloud_block"
user_message := "Blocked: your clearance level does not permit requests to be routed to cloud providers."
code := 403
decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}

--- EXAMPLE 2 (copy this structure exactly) ---
package clients.finance_only

import rego.v1

deny contains "not_in_finance_group" if {
    not "finance" in input.identity.groups
}

default allow := false

allow if count(deny) == 0

policy_id := "clients.finance_only.finance_only"
user_message := "Blocked: access is restricted to members of the finance group."
code := 403
decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}
---"""

# Freeform generation prompt
_REGO_SYSTEM_PROMPT = """\
You are an OPA Rego policy author for the Yashigani AI security gateway. \
Generate a valid, complete Rego policy module from a natural language access \
control description.

MANDATORY OUTPUT STRUCTURE — use rego.v1 import (required for rego.v1 syntax):

  package clients.<slug>

  import rego.v1

  # --- your custom deny rules ---

  default allow := false
  allow if count(deny) == 0

  policy_id := "clients.<slug>.<slug>"
  user_message := "<plain English message shown to blocked callers>"
  code := 403
  decision := {"allow": allow, "deny": deny, "policy_id": policy_id, "user_message": user_message, "code": code}

AVAILABLE INPUT FIELDS (use what the policy needs):
  input.identity.role            "human" | "agent" | "service"
  input.identity.clearance       "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED"
  input.identity.groups[]        group membership strings
  input.identity.allowed_models[] permitted model names ([] = unrestricted)
  input.identity.tier            billing/risk tier string
  input.request.path             request path string
  input.request.method           HTTP verb string
  input.request.estimated_cost_usd  number
  input.routing_decision.route   "local" | "cloud"
  input.routing_decision.provider  provider name string
  input.routing_decision.model   model name string
  input.routing_decision.sensitivity  data sensitivity label

SYNTAX RULES (rego.v1 — violating these causes OPA compile errors):
  1. Package MUST be clients.<slug> exactly.
  2. Use deny contains "key" if { ... } style (rego.v1 partial-set rules).
     NEVER use deny[msg] { ... } — that is INVALID in rego.v1.
     NEVER use deny = {...} complete-rule style.
  3. Each deny key must be a unique string literal (e.g. "group_not_allowed").
  4. NEVER use := inside a rule body — use == for comparison.
  5. Set membership: use `not "value" in input.field` or `"value" in input.field`
     NOT `input.field[_] == "value"`.
  6. Numeric comparison: `input.request.estimated_cost_usd > 5` directly.
     Do NOT assign input fields to variables outside rule bodies.
  7. Multiple conditions in one rule body: put each on its own line, NO `and` keyword.
  8. `default allow := false` must appear BEFORE `allow if count(deny) == 0`.
  9. Output ONLY the Rego source. No markdown fences, no explanations, no prose.

VALID EXAMPLES (follow these exactly):

{examples}

Now generate a NEW policy for the description the user provides.
"""

_REGO_STRICT_SUFFIX = (
    "\n\nCRITICAL: Output ONLY Rego source code starting with 'package clients.'. "
    "No markdown, no prose, no code fences. Follow the examples above exactly."
)

# Template classification prompt
_CLASSIFIER_SYSTEM_PROMPT = """\
You are a policy classifier. Given a natural language description of an access control \
policy, identify which template from the list best matches it and extract the required \
parameters. Return ONLY a valid JSON object — no prose, no explanation.

Response format:
{"template": "<template_name or null if no template fits>", "params": {<param_name>: <value>}}

If no template fits, return: {"template": null, "params": {}}

AVAILABLE TEMPLATES:
{template_list}
"""

_REPAIR_SYSTEM_PROMPT = """\
You are an OPA Rego syntax fixer. The Rego module below FAILED to compile.
Your ONLY job: fix the syntax error and return the corrected complete Rego module.
Do NOT change the policy logic — only fix what the OPA compiler complained about.

VALID REGO SYNTAX REMINDERS (rego.v1):
  - deny contains "key" if { ... }   <- CORRECT
  - deny[msg] { ... }                <- INVALID in rego.v1 — do not use
  - deny = {...}                      <- INVALID — do not use
  - NEVER use := inside rule bodies — use == for equality tests
  - Multiple conditions: one per line, NO `and` keyword between them
  - Set membership: not "value" in input.field  (not input.field[_] == "value")
  - Numeric: input.request.estimated_cost_usd > 5  (direct, no variable assignment)
  - `default allow := false` before `allow if count(deny) == 0`

Output ONLY the corrected Rego source starting with 'package clients.'.
No markdown fences, no explanations, no prose.
"""


class RegoGenerator:
    """Generate a Rego policy module from natural language via Ollama.

    FIND-4.0-REGO-001:
    - Primary path: classify into a pre-validated template + extract params (JSON task)
    - Fallback: freeform Rego generation with few-shot examples + self-repair context
    - Default model: qwen2.5:3b (only model available on this deployment)
    - Temperature: 0.1 for deterministic output
    """

    def __init__(
        self,
        ollama_url: str = "http://ollama:11434",
        model: str = "qwen2.5:3b",
        timeout: float = 60.0,
    ) -> None:
        self._url = ollama_url.rstrip("/")
        self._model = model
        self._timeout = timeout

    async def generate(
        self,
        description: str,
        policy_slug: str = "custom",
        repair_context: Optional[tuple[str, str]] = None,
    ) -> dict:
        """
        Generate (or repair) a Rego module from a natural language description.

        On the initial call (repair_context=None):
          1. Try template-first path: classify + extract params → fill template.
          2. If template path fails, fall back to freeform LLM generation.

        On a repair call (repair_context=(error_msg, bad_rego)):
          - Build a repair prompt and generate corrected Rego directly (skips templates).

        Args:
            description:    NL description of the policy.
            policy_slug:    The policy slug (clients.<slug> package name).
            repair_context: Optional (error_message, invalid_rego) tuple. When
                            provided, this call is a repair attempt.

        Returns:
            {
                "rego": str | None,
                "valid": bool,        # True = structural check passed
                "error": str | None,
                "via_template": bool, # True if filled from a template
            }

        Note: raw LLM output is logged server-side only (LAURA-2255-004).
        """
        if repair_context is not None:
            # Repair path — skip template classification
            return await self._freeform_generate(
                description, policy_slug, repair_context=repair_context
            )

        # 1. Template-first path
        template_result = await self._template_path(description, policy_slug)
        if template_result is not None:
            return template_result

        # 2. Fallback: freeform generation
        logger.info(
            "RegoGenerator: template path did not match — falling back to freeform (slug=%r)",
            policy_slug,
        )
        return await self._freeform_generate(description, policy_slug, repair_context=None)

    # ------------------------------------------------------------------
    # Template-first path
    # ------------------------------------------------------------------

    async def _template_path(
        self, description: str, slug: str
    ) -> Optional[dict]:
        """
        Ask the LLM to classify the description into a template and extract params.

        Returns a result dict if a valid template was matched and rendered, or
        None if the LLM returned null template / unknown name / bad JSON.
        """
        template_list = "\n".join(
            f"  {t['name']}: {t['description']}\n"
            f"    example: \"{t['example_nl']}\"\n"
            f"    params: {t['params']}"
            for t in template_names_with_descriptions()
        )
        system = _CLASSIFIER_SYSTEM_PROMPT.replace("{template_list}", template_list)
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": description},
        ]

        try:
            raw = await self._post_chat(messages)
        except Exception as exc:
            logger.warning("RegoGenerator: template classifier failed: %s", exc)
            return None

        # Parse the JSON response
        classification = self._parse_classifier_json(raw)
        if classification is None:
            logger.info(
                "RegoGenerator: classifier returned non-JSON (raw logged server-side: %r)",
                raw[:200],
            )
            return None

        template_name = classification.get("template")
        if not template_name:
            logger.info("RegoGenerator: classifier returned null template — using freeform")
            return None

        params = classification.get("params", {})
        rego = render_template(template_name, slug, params)
        if rego is None:
            logger.warning(
                "RegoGenerator: template %r render failed (params=%r)", template_name, params
            )
            return None

        logger.info(
            "RegoGenerator: template %r matched, params=%r, slug=%r",
            template_name, params, slug,
        )
        return {"rego": rego, "valid": True, "error": None, "via_template": True}

    @staticmethod
    def _parse_classifier_json(raw: str) -> Optional[dict]:
        """Extract and parse the JSON object from the classifier response."""
        # Strip markdown fences
        text = raw.strip()
        if "```" in text:
            m = re.search(r"```(?:json)?\n?(.*?)```", text, re.DOTALL)
            if m:
                text = m.group(1).strip()

        # Find a JSON object anywhere in the text (model may add preamble)
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None

    # ------------------------------------------------------------------
    # Freeform generation path
    # ------------------------------------------------------------------

    async def _freeform_generate(
        self,
        description: str,
        slug: str,
        repair_context: Optional[tuple[str, str]] = None,
    ) -> dict:
        """Call the LLM for freeform Rego generation or repair."""
        if repair_context is not None:
            messages = self._build_repair_messages(repair_context)
        else:
            messages = self._build_generation_messages(description, slug)

        try:
            raw = await self._post_chat(messages)
        except httpx.TimeoutException:
            logger.error("RegoGenerator: Ollama timeout after %.1fs (model=%r)", self._timeout, self._model)
            return {"rego": None, "valid": False, "error": "ollama_timeout", "via_template": False}
        except httpx.HTTPStatusError as exc:
            logger.error("RegoGenerator: Ollama HTTP error: %s", exc)
            return {"rego": None, "valid": False,
                    "error": f"ollama_http_error:{exc.response.status_code}", "via_template": False}
        except Exception as exc:
            logger.error("RegoGenerator: Ollama error: %s", exc)
            return {"rego": None, "valid": False, "error": f"ollama_error:{exc}", "via_template": False}

        # Retry once with a stricter suffix if empty / non-Rego
        if not raw or "package" not in raw:
            logger.warning(
                "RegoGenerator: empty/non-Rego response (model=%r, len=%d) — retrying",
                self._model, len(raw),
            )
            retry_msgs = list(messages)
            if retry_msgs and retry_msgs[-1]["role"] == "user":
                retry_msgs[-1] = {
                    "role": "user",
                    "content": retry_msgs[-1]["content"] + _REGO_STRICT_SUFFIX,
                }
            try:
                raw = await self._post_chat(retry_msgs)
            except Exception as exc:
                return {"rego": None, "valid": False, "error": f"ollama_error_retry:{exc}", "via_template": False}

        if not raw or "package" not in raw:
            return {
                "rego": None,
                "valid": False,
                "error": "empty_llm_response: model returned no Rego after retry.",
                "via_template": False,
            }

        clean = self._strip_fences(raw)

        if "package" not in clean or "allow" not in clean:
            logger.warning(
                "RegoGenerator: missing required Rego structure — raw logged server-side: %r",
                raw[:200],
            )
            return {
                "rego": None,
                "valid": False,
                "error": "generated_text_missing_required_rego_structure",
                "via_template": False,
            }

        return {"rego": clean, "valid": True, "error": None, "via_template": False}

    # ------------------------------------------------------------------
    # Shared Ollama HTTP call
    # ------------------------------------------------------------------

    async def _post_chat(self, messages: list[dict]) -> str:
        async with httpx.AsyncClient(timeout=self._timeout) as c:
            r = await c.post(
                f"{self._url}/api/chat",
                json={
                    "model": self._model,
                    "messages": messages,
                    "stream": False,
                    "options": {"temperature": 0.1},
                },
            )
            r.raise_for_status()
            return r.json().get("message", {}).get("content", "").strip()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_generation_messages(self, description: str, slug: str) -> list[dict]:
        """Build the initial freeform generation prompt messages."""
        system = _REGO_SYSTEM_PROMPT.replace("{examples}", _FEW_SHOT_EXAMPLES)
        return [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": (
                    f"Policy slug: {slug}\n\n"
                    f"Description: {description}"
                ),
            },
        ]

    def _build_repair_messages(self, repair_context: tuple[str, str]) -> list[dict]:
        """Build the repair prompt messages given (error_message, invalid_rego)."""
        error_msg, invalid_rego = repair_context
        user_content = (
            f"OPA compilation error:\n{error_msg}\n\n"
            f"Invalid Rego that failed:\n```\n{invalid_rego}\n```\n\n"
            f"Return the corrected complete Rego module only."
        )
        return [
            {"role": "system", "content": _REPAIR_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

    @staticmethod
    def _strip_fences(raw: str) -> str:
        """Remove markdown code fences from LLM output."""
        if "```" not in raw:
            return raw
        m = re.search(r"```(?:rego|plaintext|opa|)\n(.*?)```", raw, re.DOTALL)
        if m:
            return m.group(1).strip()
        return "\n".join(
            line for line in raw.split("\n")
            if not line.strip().startswith("```")
        ).strip()
