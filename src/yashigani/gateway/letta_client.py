"""
Letta (MemGPT) adapter for the Yashigani gateway.

Letta is a stateful agent with persistent memory. It exposes a REST API
on port 8283 but is NOT a drop-in OpenAI replacement. This adapter:
1. Creates a default Letta agent on first request (if none exists)
2. Routes messages via POST /v1/agents/{agent_id}/messages (native API)
3. Converts Letta's response format to OpenAI ChatCompletionResponse

fix/medlow-findings P1.5: the brain model used when creating the default agent is
now configurable via YASHIGANI_LETTA_BRAIN_MODEL (falls back to
"openai-proxy/qwen2.5:3b"). This is the model Letta uses for its OWN reasoning —
it must be reachable via Letta's OPENAI_API_BASE (which points to the gateway).
"""

import json
import logging
import os
import uuid

import httpx

logger = logging.getLogger(__name__)

# Cache the default agent ID after first creation
_default_agent_id: str | None = None


def _letta_brain_model() -> str:
    """Return the model Letta uses for its own reasoning (configurable at deploy time).

    Letta resolves this through its ``openai-proxy/`` provider prefix, which maps to
    the gateway's /v1 endpoint.  The concrete model name after the slash must exist in
    Ollama (pulled by the installer).  Installer default: qwen2.5:3b.
    """
    return os.getenv("YASHIGANI_LETTA_BRAIN_MODEL", "openai-proxy/qwen2.5:3b")


async def _ensure_agent(client: httpx.AsyncClient, base_url: str) -> str:
    """Get or create the default Letta agent. Returns agent_id."""
    global _default_agent_id
    if _default_agent_id:
        return _default_agent_id

    # Check if any agents exist — P1.5: handle non-200 list response gracefully.
    resp = await client.get(f"{base_url}/v1/agents/")
    if resp.status_code == 200:
        agents = resp.json()
        for agent in agents:
            if agent.get("name") == "yashigani-default":
                _default_agent_id = agent["id"]
                logger.info("Letta: found existing agent %s", _default_agent_id)
                return _default_agent_id
    elif resp.status_code != 404:
        # Non-404 error on list call: log and continue to create attempt;
        # surface a clear error if create also fails rather than swallowing.
        logger.warning(
            "Letta: agent list returned HTTP %s — proceeding to create: %s",
            resp.status_code, resp.text[:200],
        )

    brain_model = _letta_brain_model()
    # Create a new agent
    resp = await client.post(f"{base_url}/v1/agents/", json={
        "name": "yashigani-default",
        "memory_blocks": [
            {"label": "human", "value": "The user is interacting via the Yashigani AI security gateway."},
            {"label": "persona", "value": "I am a helpful AI assistant with persistent memory. I remember our conversations."},
        ],
        "model": brain_model,
        "embedding": "letta/letta-free",
    })

    if resp.status_code not in (200, 201):
        # P1.5: include the model name in the error so admins can distinguish
        # "model not found on Letta" (404 on model) vs "Letta unreachable" vs
        # other configuration issues.
        raise RuntimeError(
            f"Letta agent creation failed (model={brain_model!r}): "
            f"HTTP {resp.status_code} {resp.text[:300]}"
        )

    agent_data = resp.json()
    _default_agent_id = agent_data["id"]
    logger.info("Letta: created agent %s", _default_agent_id)
    return _default_agent_id


async def letta_chat(
    base_url: str,
    messages: list[dict],
    timeout: float = 120.0,
) -> dict:
    """
    Send messages to Letta and return an OpenAI-compatible response.

    Args:
        base_url: Letta upstream URL (e.g., http://letta:8283)
        messages: List of {"role": ..., "content": ...} dicts
        timeout: Request timeout in seconds

    Returns:
        OpenAI ChatCompletionResponse-shaped dict
    """
    async with httpx.AsyncClient(timeout=timeout) as client:
        agent_id = await _ensure_agent(client, base_url)

        # Send via native API (supports non-streaming)
        letta_messages = [
            {"role": m.get("role", "user"), "content": m.get("content", "")}
            for m in messages
        ]

        resp = await client.post(
            f"{base_url}/v1/agents/{agent_id}/messages",
            json={"messages": letta_messages, "streaming": False},
        )

        if resp.status_code != 200:
            raise RuntimeError(f"Letta message failed: {resp.status_code} {resp.text[:200]}")

        data = resp.json()

        # Extract assistant response from Letta format
        assistant_text = ""
        for msg in data.get("messages", []):
            if msg.get("message_type") == "assistant_message":
                assistant_text = msg.get("content", "")
                break

        if not assistant_text:
            # Fallback: concatenate all message contents
            parts = []
            for msg in data.get("messages", []):
                content = msg.get("content", "")
                if content and msg.get("message_type") not in ("system_message", "tool_call_message"):
                    parts.append(content)
            assistant_text = "\n".join(parts) if parts else "Letta agent returned no text."

        usage = data.get("usage", {})

    return {
        "id": f"chatcmpl-letta-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion",
        "model": "letta",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": assistant_text},
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
        },
    }
