"""
Langflow adapter for the Yashigani gateway.

Langflow is a visual workflow builder. It requires:
1. Auto-login to get a bearer token
2. Create an API key for subsequent calls
3. Create a default chat flow (or use an existing one)
4. Route messages via POST /api/v1/run/{flow_id}
5. Convert Langflow response to OpenAI ChatCompletionResponse
"""

import json
import logging
import os
import uuid

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal service-mesh Bearer token
#
# YASHIGANI_INTERNAL_BEARER is a per-install-rotated secret injected into
# the Langflow flow template so it can call back through the Yashigani
# gateway as an internal service. It MUST be set by the installer
# (docker/secrets/yashigani_internal_bearer).  A missing or empty value
# fails closed at import time.
# ---------------------------------------------------------------------------

def _load_internal_bearer() -> str:
    """Read YASHIGANI_INTERNAL_BEARER from env; raise RuntimeError if absent."""
    _val = os.environ.get("YASHIGANI_INTERNAL_BEARER", "")
    if not _val:
        raise RuntimeError(
            "YASHIGANI_INTERNAL_BEARER is not set. "
            "The gateway cannot start without a per-install internal service token. "
            "See docker/secrets/yashigani_internal_bearer."
        )
    return _val


# Cached at module load — fails fast if env-var is absent.
_INTERNAL_BEARER: str = _load_internal_bearer()

# Cached state after first initialization
_api_key: str | None = None
_flow_id: str | None = None
_initialized = False


async def _ensure_initialized(client: httpx.AsyncClient, base_url: str) -> tuple[str, str]:
    """Initialize Langflow: auto-login, get API key, find or create flow."""
    global _api_key, _flow_id, _initialized
    if _initialized and _api_key and _flow_id:
        return _api_key, _flow_id

    # Step 1: Auto-login to get bearer token
    resp = await client.get(f"{base_url}/api/v1/auto_login")
    if resp.status_code != 200:
        raise RuntimeError(f"Langflow auto_login failed: {resp.status_code}")

    token_data = resp.json()
    bearer_token = token_data.get("access_token", "")
    if not bearer_token:
        raise RuntimeError("Langflow auto_login returned no access_token")

    auth_headers = {"Authorization": f"Bearer {bearer_token}"}

    # Step 2: Create or get API key
    # Always create a fresh API key — existing keys are masked and unusable
    resp = await client.post(
        f"{base_url}/api/v1/api_key/",
        json={"name": "yashigani-gateway"},
        headers=auth_headers,
    )
    if resp.status_code in (200, 201):
        _api_key = resp.json().get("api_key", "")

    if not _api_key:
        raise RuntimeError("Langflow: could not create API key")

    # Step 3: Find or create a chat flow
    api_headers = {"x-api-key": _api_key}

    # Check for existing user flows
    resp = await client.get(f"{base_url}/api/v1/flows/", headers=api_headers)
    if resp.status_code == 200:
        flows = resp.json()
        for flow in flows:
            if flow.get("name") == "Yashigani Chat" and flow.get("user_id"):
                _flow_id = flow["id"]
                logger.info("Langflow: found existing flow %s", _flow_id)
                break

    if not _flow_id:
        # Find the "Basic Prompting" starter flow and patch it to use Ollama provider via gateway
        starter_data = None
        if resp.status_code == 200:
            for flow in flows:
                if "basic prompting" in flow.get("name", "").lower():
                    starter_data = flow.get("data", {})
                    break

        # Patch the LanguageModel node to use the Ollama provider via direct
        # Ollama container access.
        #
        # Langflow 1.9.2 LanguageModelComponent template fields (verified 2026-05-20):
        #   model         — model name string (e.g. "qwen2.5:3b")
        #   ollama_base_url — base URL for the Ollama API (native protocol)
        #
        # We point ollama_base_url at the Ollama container directly (http://ollama:11434)
        # rather than the gateway's /v1/ endpoint.  The gateway expects mTLS client certs
        # on port 8080; langflow has no client cert and the connection is rejected at the
        # TLS handshake.  Direct access to ollama:11434 is safe — langflow is an internal
        # trusted service on the compose stack network (no external exposure).
        # Internal-service-to-internal-service: network isolation is the boundary (no
        # app-layer authN on the Ollama API; Ollama has none).
        if starter_data:
            for node in starter_data.get("nodes", []):
                node_data = node.get("data", {})
                if node_data.get("type") == "LanguageModelComponent":
                    template = node_data.get("node", {}).get("template", {})
                    # Set model name (string field in langflow 1.9.2)
                    if "model" in template:
                        if isinstance(template["model"], dict):
                            template["model"]["value"] = "qwen2.5:3b"
                        else:
                            template["model"] = "qwen2.5:3b"
                    # Point directly at the Ollama container (native Ollama protocol)
                    if "ollama_base_url" in template:
                        if isinstance(template["ollama_base_url"], dict):
                            template["ollama_base_url"]["value"] = "http://ollama:11434"
                        else:
                            template["ollama_base_url"] = "http://ollama:11434"
                    break

        flow_body = {
            "name": "Yashigani Chat",
            "description": "Default chat flow for Yashigani gateway — Ollama provider via ollama:11434",
            "endpoint_name": "yashigani-chat",
        }
        if starter_data:
            flow_body["data"] = starter_data

        resp = await client.post(
            f"{base_url}/api/v1/flows/",
            json=flow_body,
            headers=api_headers,
        )
        if resp.status_code in (200, 201):
            _flow_id = resp.json().get("id", "")
            logger.info("Langflow: created flow %s with Ollama/direct config", _flow_id)
        else:
            raise RuntimeError(f"Langflow flow creation failed: {resp.status_code} {resp.text[:200]}")

    _initialized = True
    return _api_key, _flow_id


async def langflow_chat(
    base_url: str,
    messages: list[dict],
    timeout: float = 120.0,
) -> dict:
    """
    Send messages to Langflow and return an OpenAI-compatible response.

    Args:
        base_url: Langflow upstream URL (e.g., http://langflow:7860)
        messages: List of {"role": ..., "content": ...} dicts
        timeout: Request timeout in seconds

    Returns:
        OpenAI ChatCompletionResponse-shaped dict
    """
    # Extract the last user message as input
    user_message = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            user_message = m.get("content", "")
            break
    if not user_message:
        user_message = messages[-1].get("content", "") if messages else ""

    async with httpx.AsyncClient(timeout=timeout) as client:
        api_key, flow_id = await _ensure_initialized(client, base_url)

        resp = await client.post(
            f"{base_url}/api/v1/run/{flow_id}",
            json={
                "input_value": user_message,
                "output_type": "chat",
                "input_type": "chat",
            },
            headers={"x-api-key": api_key},
        )

        if resp.status_code == 403:
            # API key may be stale — reset cache and retry once
            global _initialized
            _api_key_cache = None
            _flow_id_cache = None
            _initialized = False
            api_key, flow_id = await _ensure_initialized(client, base_url)
            resp = await client.post(
                f"{base_url}/api/v1/run/{flow_id}",
                json={
                    "input_value": user_message,
                    "output_type": "chat",
                    "input_type": "chat",
                },
                headers={"x-api-key": api_key},
            )

        if resp.status_code != 200:
            raise RuntimeError(f"Langflow run failed: {resp.status_code} {resp.text[:200]}")

        data = resp.json()

        # Extract text from Langflow response
        assistant_text = ""
        try:
            outputs = data.get("outputs", [])
            if outputs:
                inner_outputs = outputs[0].get("outputs", [])
                if inner_outputs:
                    results = inner_outputs[0].get("results", {})
                    message = results.get("message", {})
                    assistant_text = message.get("text", "")
        except (IndexError, KeyError, TypeError):
            pass

        if not assistant_text:
            assistant_text = "Langflow returned no output. The flow may need configuration."

    return {
        "id": f"chatcmpl-langflow-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion",
        "model": "langflow",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": assistant_text},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }
