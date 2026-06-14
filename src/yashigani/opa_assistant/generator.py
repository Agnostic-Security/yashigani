"""
OPA Policy Assistant — Natural language to RBAC JSON generator.
Uses internal Ollama (qwen2.5:3b) to generate RBAC data document suggestions.
Zero external API calls — air-gapped compatible.

LAURA-2255-004 / 30-007 hardening (2026-06-14):
- Uses the CHAT API (/api/chat) with separate system + user roles.
  The description is the user message; the RBAC schema is fixed in the system
  prompt. Injection via description cannot override system-prompt instructions.
- format:json ensures structured output.
- raw_response is logged server-side but NOT returned to callers; the route
  (opa_assistant.py) drops it before sending to the client.
- Current RBAC document is passed as a separate system message (data context),
  not concatenated into the instruction.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are an RBAC policy assistant for Yashigani Security Gateway. "
    "Convert natural language access control requirements into a valid RBAC data document.\n\n"
    "The output format is EXACTLY this JSON structure (no markdown, no explanation):\n"
    '{"groups": {"<group_id>": {"id": "<group_id>", "display_name": "<name>", '
    '"allowed_resources": [{"method": "GET", "path_glob": "/tools/list"}]}}, '
    '"user_groups": {"<user@example.com>": ["<group_id>"]}}\n\n'
    "Rules:\n"
    "- group_id: lowercase, hyphenated (e.g. 'engineering-team')\n"
    "- method: HTTP verb or '*' for any\n"
    "- path_glob: exact path, /prefix/**, or /prefix/*/suffix\n"
    "- Output ONLY the JSON object."
)


class OPAAssistantGenerator:
    """Generates RBAC document suggestions from natural language via Ollama."""

    def __init__(
        self,
        ollama_url: str = "http://ollama:11434",
        model: str = "qwen2.5:3b",
        timeout: float = 30.0,
    ) -> None:
        self._url = ollama_url.rstrip("/")
        self._model = model
        self._timeout = timeout

    async def generate(
        self,
        description: str,
        current_document: Optional[dict] = None,
    ) -> dict:
        """
        Generate an RBAC JSON suggestion from a natural language description.

        Returns:
            {
                "suggestion": dict | None,
                "valid": bool,
                "error": str | None,
            }

        Note: raw_response is intentionally NOT included in the return dict.
        The raw LLM output is logged server-side only (LAURA-2255-004).
        """
        # Build message list: system instruction + optional context + user request
        messages: list[dict] = [{"role": "system", "content": _SYSTEM_PROMPT}]

        if current_document:
            # Pass current RBAC document as a separate system context message
            # (data, not instructions — prevents injection via document content)
            ctx_content = (
                "Current RBAC document (use as context for modifications):\n"
                + json.dumps(current_document, indent=2)
            )
            messages.append({"role": "system", "content": ctx_content})

        # Description is the user message — isolated from the system prompt
        messages.append({"role": "user", "content": description})

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._url}/api/chat",
                    json={
                        "model": self._model,
                        "messages": messages,
                        "format": "json",
                        "stream": False,
                    },
                )
                resp.raise_for_status()
                raw = resp.json().get("message", {}).get("content", "").strip()
        except httpx.TimeoutException:
            logger.error("OPA assistant: Ollama timeout after %.1fs", self._timeout)
            return {"suggestion": None, "valid": False, "error": "ollama_timeout"}
        except httpx.HTTPStatusError as exc:
            logger.error("OPA assistant: Ollama HTTP error: %s", exc)
            return {"suggestion": None, "valid": False,
                    "error": f"ollama_http_error:{exc.response.status_code}"}
        except Exception as exc:
            logger.error("OPA assistant: Ollama error: %s", exc)
            return {"suggestion": None, "valid": False, "error": f"ollama_error:{exc}"}

        # Strip markdown code fences (defensive — format:json should prevent them)
        clean = raw
        if clean.startswith("```"):
            lines = clean.split("\n")
            inner = lines[1:] if len(lines) > 1 else lines
            if inner and inner[-1].strip() == "```":
                inner = inner[:-1]
            clean = "\n".join(inner).strip()

        try:
            suggestion = json.loads(clean)
        except json.JSONDecodeError as exc:
            # Log raw server-side only; never surface to caller
            logger.warning(
                "OPA assistant: JSON parse failed: %s | raw=%r (logged server-side only)",
                exc, raw[:300],
            )
            return {
                "suggestion": None,
                "valid": False,
                "error": f"json_parse_error: {exc}",
            }

        return {"suggestion": suggestion, "valid": True, "error": None}
