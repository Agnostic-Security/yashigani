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

SC-AGENT-003 (3.1): Replace the "letta/letta-free" cloud embedding handle with an
explicit embedding_config that points at the gateway's /v1/embeddings endpoint
(http://gateway:8081/v1).  The original handle resolves to embeddings.letta.com
(a cloud endpoint); our Letta container is network-isolated and cannot reach it,
causing every agent-creation to 502.
"""

import logging
import os
import uuid

import httpx

logger = logging.getLogger(__name__)

# Cache the default agent ID after first creation
_default_agent_id: str | None = None

# ---------------------------------------------------------------------------
# Embedding-dimension table (SC-AGENT-003)
# ---------------------------------------------------------------------------
# Letta's EmbeddingConfig requires the vector dimension at agent-creation time.
# When routing through the gateway's /v1/embeddings (backed by Ollama), the dim
# is determined by the model architecture — it does NOT change with quantisation.
#
# We maintain a small table of models the installer pulls so we can set the correct
# dim without a live probe at every cold-start.  If the operator changes the
# embedding model to one not in this table, _probe_embedding_dim() fires a single
# POST /v1/embeddings call to measure the actual dim and logs the result so the
# operator can add it here for future cold-starts.
#
# IMPORTANT: never hardcode 1536 for local models — that is OpenAI's dimension for
# text-embedding-3-small and is WRONG for all Ollama-served models.  A mismatch
# between the declared dim and the actual vector length causes Letta's pgvector
# store to reject passages silently or crash on archival-memory writes.
#
# Changing the embedding model or its dim for an existing agent INVALIDATES the
# agent's pgvector store.  Letta does not re-embed existing passages automatically.
# If you rotate the embedding model, delete the agent (or its passages) and let
# Letta recreate it so the store is rebuilt against the new dimension.
_OLLAMA_EMBEDDING_DIMS: dict[str, int] = {
    # qwen2.5:3b — hidden_size=2048 per the Qwen 2.5 3B architecture.
    # Confirmed: Ollama's /api/show model_info key "qwen2.model.embedding_length"
    # returns 2048 for this model.  Installer default.
    "qwen2.5:3b": 2048,
    # nomic-embed-text — dedicated embedding model, dim 768.
    "nomic-embed-text": 768,
    "nomic-embed-text:latest": 768,
    # all-minilm — dedicated embedding model, dim 384.
    "all-minilm": 384,
    "all-minilm:latest": 384,
}

# The gateway's internal mesh port for embedding calls (same as the LLM openai-proxy).
# Port 8081 is plain HTTP on the data bridge — no client certs required from Letta.
# Port 8080 is mTLS-only; Letta cannot present client certs (pg8000 constraint parity).
_GATEWAY_EMBED_ENDPOINT = "http://gateway:8081/v1"


def _letta_brain_model() -> str:
    """Return the model Letta uses for its own reasoning (configurable at deploy time).

    Letta resolves this through its ``openai-proxy/`` provider prefix, which maps to
    the gateway's /v1 endpoint.  The concrete model name after the slash must exist in
    Ollama (pulled by the installer).  Installer default: qwen2.5:3b.
    """
    return os.getenv("YASHIGANI_LETTA_BRAIN_MODEL", "openai-proxy/qwen2.5:3b")


def _letta_embedding_model() -> str:
    """Return the bare Ollama model name to use for Letta embeddings.

    Reads YASHIGANI_LETTA_EMBEDDING_MODEL (our env var, NOT Letta's silently-ignored
    LETTA_EMBEDDING_MODEL).  Defaults to the brain model's bare name (strips the
    'openai-proxy/' provider prefix that Letta uses for LLM routing).

    The returned name is passed directly to Ollama via the gateway's /v1/embeddings
    endpoint — it must exist in Ollama (i.e. be pulled by the installer).
    """
    explicit = os.getenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "").strip()
    if explicit:
        return explicit
    # Default: use the same model as the brain (already pulled).
    brain = _letta_brain_model()
    # Strip the "openai-proxy/" or any other "provider/" prefix.
    if "/" in brain:
        return brain.split("/", 1)[1]
    return brain


async def _probe_embedding_dim(client: httpx.AsyncClient, model: str) -> int:
    """Probe the gateway for the actual embedding dimension of *model*.

    Sends a minimal POST /v1/embeddings and counts the vector length returned.
    Used as a fallback when the model is not in _OLLAMA_EMBEDDING_DIMS.

    SC-AGENT-003: the gateway must be up (it is, since Letta depends_on gateway:
    healthy) before any agent-creation call.
    """
    try:
        resp = await client.post(
            f"{_GATEWAY_EMBED_ENDPOINT}/embeddings",
            json={"model": model, "input": "dim probe"},
            timeout=30.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            vectors = data.get("data", [])
            if vectors and isinstance(vectors[0].get("embedding"), list):
                dim = len(vectors[0]["embedding"])
                logger.info(
                    "SC-AGENT-003: probed embedding dim for model %r: %d "
                    "(add to _OLLAMA_EMBEDDING_DIMS to avoid probe on next cold-start)",
                    model, dim,
                )
                return dim
        logger.warning(
            "SC-AGENT-003: dim probe returned HTTP %s for model %r — falling back to 2048",
            resp.status_code, model,
        )
    except Exception as exc:
        logger.warning(
            "SC-AGENT-003: dim probe failed for model %r (%s) — falling back to 2048",
            model, exc,
        )
    return 2048  # safe fallback for qwen-family models


async def _letta_embedding_config(client: httpx.AsyncClient) -> dict:
    """Build the explicit embedding_config payload for a Letta create-agent call.

    Returns a plain dict matching Letta's EmbeddingConfig schema:
      embedding_endpoint_type: "openai"   (Letta uses the OpenAI client for this type)
      embedding_endpoint:      http://gateway:8081/v1
      embedding_model:         <bare ollama model name>
      embedding_dim:           <actual dim from table or live probe>
      embedding_chunk_size:    300  (Letta default)

    SC-AGENT-003: the cloud-endpoint handle "letta/letta-free" is replaced by this
    explicit config so Letta never tries to reach embeddings.letta.com.
    """
    model = _letta_embedding_model()
    dim = _OLLAMA_EMBEDDING_DIMS.get(model)
    if dim is None:
        logger.info(
            "SC-AGENT-003: model %r not in _OLLAMA_EMBEDDING_DIMS — probing gateway",
            model,
        )
        dim = await _probe_embedding_dim(client, model)
    return {
        "embedding_endpoint_type": "openai",
        "embedding_endpoint": _GATEWAY_EMBED_ENDPOINT,
        "embedding_model": model,
        "embedding_dim": dim,
        "embedding_chunk_size": 300,
    }


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
    # SC-AGENT-003: explicit embedding_config replaces "letta/letta-free" handle
    # (which resolves to the cloud endpoint https://embeddings.letta.com/ — unreachable
    # from our network-isolated Letta container).
    embedding_cfg = await _letta_embedding_config(client)
    # Create a new agent
    resp = await client.post(f"{base_url}/v1/agents/", json={
        "name": "yashigani-default",
        "memory_blocks": [
            {"label": "human", "value": "The user is interacting via the Yashigani AI security gateway."},
            {"label": "persona", "value": "I am a helpful AI assistant with persistent memory. I remember our conversations."},
        ],
        "model": brain_model,
        "embedding_config": embedding_cfg,
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
