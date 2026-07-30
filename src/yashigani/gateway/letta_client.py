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

4.0 Phase 3 (RISK-107): LettaClientPool replaces the module-global _default_agent_id
with a per-user pool. Each user gets their own Letta container (via PoolManager) and
their own Letta agent within that container. Cross-user memory bleed is closed at
both the container (separate process) and DB (schema-per-user) layers.

PINNED SEAM (Tom → Captain): LettaClientPool.for_user(identity_id) returns
(httpx.AsyncClient, base_url, agent_id). Tom's OpenAI router uses this seam to route
@letta messages. The seam signature is STABLE — do not change without Tom's sign-off.
"""

import logging
import os
import threading
import uuid
from typing import TYPE_CHECKING, Optional

import httpx

from yashigani.gateway._dispatch_client import agent_dispatch_client

if TYPE_CHECKING:
    from yashigani.pool.manager import PoolManager, CertMount

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-user Letta image (pinned digest — verified against Docker Hub)
# ---------------------------------------------------------------------------
# This MUST match the image in docker/docker-compose.yml letta service.
# Any version bump here requires a corresponding compose + Helm update.
_LETTA_IMAGE = (
    "docker.io/letta/letta:0.16.7"
    "@sha256:fb7bd2c94a8bb7badbcfdb78a334abe3c1a75b5ea59e177aeba2e6356f54f92c"
)
_LETTA_PORT = 8283

# Cache the default agent ID after first creation.
# DEPRECATED (4.0 — use LettaClientPool). Retained for backward-compat with any
# 3.0 call sites that still invoke letta_chat() directly during the migration.
# Will be removed once Tom wires all call sites to LettaClientPool.for_user().
_default_agent_id: str | None = None


def _letta_container_env(user_id: str) -> dict[str, str]:
    """Per-user Letta container environment (schema-per-user isolation, Option A).

    Each user's Letta container connects to a dedicated PostgreSQL schema:
        letta_<user_slug>   (user_slug = first 16 hex chars of UUID without dashes)

    This gives pgvector namespace isolation: agent A's embeddings cannot be read
    by agent B's container even if both connect to the same pgvector instance.

    The schema is created lazily on first activation (or by user onboarding flow).

    Per-user container env vars wired by install.sh / PoolManager:
      OPENAI_API_BASE      — gateway's internal mesh endpoint (plain HTTP on data bridge)
      OPENAI_API_KEY       — per-agent P1-only gateway token (from Docker secret)
      LETTA_PG_URI         — schema-scoped Postgres URI via letta-pgbouncer sidecar
      LETTA_REDIS_HOST/PORT — per-container embedded Redis (started by entrypoint shim)
      YASHIGANI_LETTA_USER_ID — for observability / log correlation
    """
    user_slug = user_id.replace("-", "")[:16]
    user_schema = f"letta_{user_slug}"

    # Read the Postgres password injected by install.sh.
    # In production this comes from a Docker secret (POSTGRES_PASSWORD env var).
    pg_password = os.getenv("POSTGRES_PASSWORD", "")
    # Per-user schema: search_path sets the active schema for this connection.
    pg_uri = (
        f"postgresql://yashigani_app:{pg_password}"
        f"@letta-pgbouncer:5432/letta"
        f"?options=-csearch_path%3D{user_schema}"
    )

    # The internal gateway bearer token (P1-only; injected as OPENAI_API_KEY for
    # Letta's OpenAI-compat client). In the sidecar design this is replaced by the
    # per-agent gateway token from the Docker secret — but the env var provides the
    # initialisation value for pre-sidecar deployments.
    internal_bearer = os.getenv("YASHIGANI_INTERNAL_BEARER", "")

    return {
        "OPENAI_API_BASE": "http://gateway:8081/v1",
        "OPENAI_API_KEY": internal_bearer,
        "LETTA_PG_URI": pg_uri,
        # Per-container Redis: entrypoint shim launches redis-server before startup.sh;
        # LETTA_REDIS_HOST=localhost tells startup.sh to use the pre-launched instance.
        "LETTA_REDIS_HOST": "localhost",
        "LETTA_REDIS_PORT": "6379",
        "YASHIGANI_LETTA_USER_ID": user_id,
    }


class LettaClientPool:
    """Per-user Letta container/agent pool.

    4.0 Phase 3 (RISK-107 closure):

    One Letta container per user identity. Containers are persistent (idle-timeout
    does NOT kill them; only user deactivation / admin offboard does). Memory is
    durable — the letta_data_<user_slug> volume persists between container restarts.

    Two-layer isolation:
      Container layer: each user runs in their own Letta process. A compromised
                       user's agent cannot write to another user's in-process state.
      DB layer:        each user's Letta connects to schema letta_<user_slug>.
                       Cross-schema reads require DBA access (accepted residual;
                       full DB-per-user is the Enterprise-tier option B config).

    Thread-safe. PoolManager manages container lifecycle; this class manages the
    Letta agent ID within each user's container.

    PINNED SEAM:
      for_user(identity_id) -> (httpx.AsyncClient, base_url: str, agent_id: str)
      Tom's OpenAI router calls this. Do not change the return type without Tom's
      sign-off and a corresponding update in openai_router.py.
    """

    def __init__(self, pool_manager: "PoolManager") -> None:
        self._pm = pool_manager
        # Per-user agent ID cache: user_id → Letta agent UUID.
        # Populated on first for_user() call; persists for the process lifetime.
        # The Letta container persists the agent in its DB — the cache is just
        # an in-process lookup to avoid redundant GET /v1/agents/ calls.
        self._agent_ids: dict[str, str] = {}
        self._lock = threading.Lock()

    def get_endpoint(self, user_id: str) -> str:
        """Return the Letta REST API base URL for this user's container.

        Creates the per-user container on first call (mode=persistent: idle-cleanup
        does not tear it down). The container's SVID must already be issued before
        get_or_create() proceeds — gated by agent.svid_state in the DB (Phase 3
        pre-flight: auto-issued for Letta as a platform system agent at user
        activation time, not user-configurable).

        Returns: base_url like ``http://172.18.0.5:8283``
        """
        from yashigani.identity.trust_domain import agent_spiffe_uri
        from yashigani.pool.manager import CertMount

        # Per-agent ringfence network: internal bridge, no internet egress.
        # Naming: ringfence_letta_<user_slug> (first 8 hex chars for readability).
        user_slug = user_id.replace("-", "")[:8]
        ringfence_net = f"ringfence_letta_{user_slug}"

        cert_mount = CertMount(
            # In the full sidecar design the sidecar manages the tmpfs volume;
            # host_*_path is empty. For pre-sidecar deployments (compose without
            # a sidecar) these are populated by install.sh per-user cert issuance.
            host_cert_path="",
            host_key_path="",
            host_ca_path="",
            container_cert_path="/run/secrets/svid/client.crt",
            container_key_path="/run/secrets/svid/client.key",
            container_ca_path="/run/secrets/svid/ca.crt",
            spiffe_identity=agent_spiffe_uri(user_id, "letta"),
        )

        container_info = self._pm.get_or_create(
            identity_id=user_id,
            service_slug="letta",
            image=_LETTA_IMAGE,
            env=_letta_container_env(user_id),
            port=_LETTA_PORT,
            networks=[ringfence_net, "caddy_internal"],
            cert_mount=cert_mount,
            mode="persistent",   # idle-cleanup MUST NOT tear down Letta containers
            # No ringfence_init_network here unless sidecar is wired for this user;
            # sidecar wiring is Phase 3 pre-flight (Su + install.sh scope).
        )
        return container_info.endpoint

    async def _ensure_agent_for_user(
        self,
        user_id: str,
        base_url: str,
        client: httpx.AsyncClient,
    ) -> str:
        """Get or create the Letta agent for this user. Returns agent_id.

        Thread-safe: the lock serialises first-creation for a given user_id.
        Subsequent calls return the cached agent_id without acquiring the lock.
        The Letta container persists the agent in its own DB; if the process
        restarts, the agent list GET finds the existing agent and populates
        _agent_ids from the container's persistent store.
        """
        # Fast path: already in cache.
        cached = self._agent_ids.get(user_id)
        if cached:
            return cached

        with self._lock:
            # Re-check under lock (concurrent first-creation race).
            cached = self._agent_ids.get(user_id)
            if cached:
                return cached

            embedding_cfg = await _letta_embedding_config(client)
            brain_model = _letta_brain_model()

            # Check for an existing agent in this user's container.
            resp = await client.get(f"{base_url}/v1/agents/")
            if resp.status_code == 200:
                for agent in resp.json():
                    if agent.get("name") == f"yashigani-{user_id[:8]}":
                        agent_id = agent["id"]
                        self._agent_ids[user_id] = agent_id
                        logger.info(
                            "LettaClientPool: found existing agent %s for user %s",
                            agent_id, user_id[:8],
                        )
                        return agent_id

            # Create a new per-user agent.
            resp = await client.post(f"{base_url}/v1/agents/", json={
                "name": f"yashigani-{user_id[:8]}",
                "memory_blocks": [
                    {
                        "label": "human",
                        "value": (
                            "The user is interacting via the Yashigani AI security gateway. "
                            f"User ID (internal): {user_id[:8]}..."
                        ),
                    },
                    {
                        "label": "persona",
                        "value": (
                            "I am a helpful AI assistant with persistent memory. "
                            "I remember our conversations and can recall context across sessions."
                        ),
                    },
                ],
                # YSG-RISK-1xx (chat-path repair, 2026-07-27): llm_config (full
                # object), not "model" (handle) — see _letta_llm_config() docstring.
                "llm_config": _letta_llm_config(brain_model),
                "embedding_config": embedding_cfg,
            })
            if resp.status_code not in (200, 201):
                raise RuntimeError(
                    f"LettaClientPool: agent creation failed for user {user_id[:8]} "
                    f"(model={brain_model!r}): HTTP {resp.status_code} {resp.text[:300]}"
                )
            agent_id = resp.json()["id"]
            self._agent_ids[user_id] = agent_id
            logger.info(
                "LettaClientPool: created agent %s for user %s",
                agent_id, user_id[:8],
            )
            return agent_id

    async def for_user(
        self,
        identity_id: str,
    ) -> tuple[httpx.AsyncClient, str, str]:
        """Resolve (client, base_url, agent_id) for the given user identity.

        PINNED SEAM — Tom's callers depend on this exact signature.

        Creates the per-user Letta container on first call (via PoolManager).
        Creates the per-user Letta agent in that container on first call.

        Returns:
            (client, base_url, agent_id)
            client:   a new AsyncClient; caller owns the lifetime. Use as an
                      async context manager or close explicitly.
            base_url: the Letta container REST endpoint (e.g. http://IP:8283).
            agent_id: the Letta agent UUID for this user's persistent memory agent.

        Usage (Tom's call site):
            client, base_url, agent_id = await pool.for_user(user_id)
            async with client:
                resp = await client.post(f"{base_url}/v1/agents/{agent_id}/messages", ...)
        """
        base_url = f"http://{self.get_endpoint(identity_id)}"
        client = httpx.AsyncClient(timeout=120.0)
        try:
            agent_id = await self._ensure_agent_for_user(identity_id, base_url, client)
        except Exception:
            await client.aclose()
            raise
        return (client, base_url, agent_id)

    async def letta_chat(
        self,
        user_id: str,
        messages: list[dict],
        timeout: float = 120.0,
    ) -> dict:
        """Send messages to this user's Letta agent; return OpenAI-format response.

        Convenience wrapper over for_user() for callers that don't need the raw
        (client, base_url, agent_id) triple. Manages the client lifetime internally.
        """
        base_url = f"http://{self.get_endpoint(user_id)}"
        async with httpx.AsyncClient(timeout=timeout) as client:
            agent_id = await self._ensure_agent_for_user(user_id, base_url, client)
            letta_messages = [
                {"role": m.get("role", "user"), "content": m.get("content", "")}
                for m in messages
            ]
            resp = await client.post(
                f"{base_url}/v1/agents/{agent_id}/messages",
                json={"messages": letta_messages, "streaming": False},
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Letta message failed for user {user_id[:8]}: "
                    f"{resp.status_code} {resp.text[:200]}"
                )
            data = resp.json()

        assistant_text = ""
        for msg in data.get("messages", []):
            if msg.get("message_type") == "assistant_message":
                assistant_text = msg.get("content", "")
                break
        if not assistant_text:
            parts = [
                msg.get("content", "")
                for msg in data.get("messages", [])
                if msg.get("content") and msg.get("message_type") not in (
                    "system_message", "tool_call_message"
                )
            ]
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
#
# YSG-RISK-169 (chat-path repair, 2026-07-30): this endpoint is written into
# the LETTA-SIDE llm_config/embedding_config — it must be reachable FROM
# LETTA'S OWN CONTAINER, not from the gateway process constructing the config.
# That reachability differs by deployment shape:
#
#   Per-user LettaClientPool containers (get_endpoint(); "persona" @-handles):
#     networks [ringfence_letta_<user>, caddy_internal] — caddy_internal
#     reaches gateway:8081 directly. _letta_container_env() sets the SAME
#     value as this container's own OPENAI_API_BASE. Unaffected by this fix.
#
#   Static system-wide `letta` compose service (used by the shared @letta
#     mention path via module-level _ensure_agent()/letta_chat()): networks
#     ringfence_letta_in + ringfence_letta_eg + letta_db ONLY (v4.1 unified-
#     sidecar split-ringfence) — it can reach egress-letta:9400 but NOT
#     gateway:8081 directly. Hardcoding gateway:8081 here left every
#     reasoning step failing inside Letta with
#     "LLMConnectionError: Failed to connect to OpenAI: Connection error"
#     (confirmed live via `docker logs letta`), surfaced to users as
#     "Agent @letta (Letta) unreachable".
#
# _GATEWAY_EMBED_ENDPOINT stays the per-user-pool-safe default (preserves
# existing behaviour for that path + the one-off _probe_embedding_dim() call
# below, which is made BY THE GATEWAY PROCESS itself and is unaffected by
# either topology). _ensure_agent() (static/system path) passes
# _LETTA_STATIC_LLM_ENDPOINT explicitly instead.
_GATEWAY_EMBED_ENDPOINT = "http://gateway:8081/v1"

# Matches docker-compose's own OPENAI_API_BASE for the static `letta` service
# and the "llm" egress-forwarder prefix wired in bundles/letta-egress.yaml —
# the only destination the static letta container's network can reach.
_LETTA_STATIC_LLM_ENDPOINT = "http://egress-letta:9400/llm/v1"


def _letta_brain_model() -> str:
    """Return the model Letta uses for its own reasoning (configurable at deploy time).

    Letta resolves this through its ``openai-proxy/`` provider prefix, which maps to
    the gateway's /v1 endpoint.  The concrete model name after the slash must exist in
    Ollama (pulled by the installer).  Installer default: qwen2.5:3b.
    """
    return os.getenv("YASHIGANI_LETTA_BRAIN_MODEL", "openai-proxy/qwen2.5:3b")


# ---------------------------------------------------------------------------
# LLM context-window table (YSG-RISK-1xx — see YASHIGANI_LETTA_BRAIN_MODEL fix)
# ---------------------------------------------------------------------------
# Mirrors _OLLAMA_EMBEDDING_DIMS below: Letta's LLMConfig requires a
# context_window at agent-creation time. Qwen2.5's published context length
# (Qwen2.5 technical report / Ollama library manifest) is 32768 tokens.
_OLLAMA_CONTEXT_WINDOWS: dict[str, int] = {
    "qwen2.5:3b": 32768,
}
# Conservative fallback for a brain model not yet in the table above.
_LLM_CONTEXT_WINDOW_FALLBACK = 8192


def _letta_llm_config(
    model: str | None = None,
    *,
    llm_endpoint: str = _GATEWAY_EMBED_ENDPOINT,
) -> dict:
    """Build the explicit llm_config payload for a Letta create-agent call.

    FIX (2026-07-27, chat-path repair): Letta 0.16.7's POST /v1/agents "model"
    field is a *handle* ("format: provider/model-name") that Letta resolves
    against its OWN provider catalog — NOT a free-form endpoint pointer. We
    never register an "openai-proxy" provider with Letta (by design: the
    docker-compose.yml comment for the letta service states "the gateway, not
    the Letta server defaults, owns the routing decision"), so every agent
    creation that sent bare ``"model": "openai-proxy/qwen2.5:3b"`` 404s with
    "Handle openai-proxy/qwen2.5:3b not found" — breaking @letta chat and the
    letta-as-orchestrating-brain (Design A) path.

    Letta's (deprecated-but-functional) ``llm_config`` field accepts a full
    LLMConfig object and bypasses handle resolution entirely — exactly the
    same trick SC-AGENT-003 already applied to embedding_config to dodge the
    unreachable "letta/letta-free" cloud handle. This mirrors that fix for the
    LLM side.

    ``llm_endpoint`` (YSG-RISK-169): the endpoint written into the config is
    dialled by LETTA ITSELF, not by the caller of this function — it MUST be
    reachable from the CALLING letta container's own network position, which
    differs by deployment shape (see _GATEWAY_EMBED_ENDPOINT module comment).
    Defaults to the per-user-pool-safe value; the static/system agent path
    (_ensure_agent()) passes _LETTA_STATIC_LLM_ENDPOINT explicitly.
    """
    brain_model = model if model is not None else _letta_brain_model()
    # Strip the "openai-proxy/" (or any other "provider/") prefix — Ollama
    # only knows the bare model name.
    bare = brain_model.split("/", 1)[1] if "/" in brain_model else brain_model
    context_window = _OLLAMA_CONTEXT_WINDOWS.get(bare, _LLM_CONTEXT_WINDOW_FALLBACK)
    return {
        "model": bare,
        "model_endpoint_type": "openai",
        "model_endpoint": llm_endpoint,
        "context_window": context_window,
        # Cosmetic only (Letta does not use this for routing when llm_config
        # is supplied) — keeps the original handle name visible in the UI.
        "handle": brain_model,
    }


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


async def _letta_embedding_config(
    client: httpx.AsyncClient,
    *,
    embedding_endpoint: str = _GATEWAY_EMBED_ENDPOINT,
) -> dict:
    """Build the explicit embedding_config payload for a Letta create-agent call.

    Returns a plain dict matching Letta's EmbeddingConfig schema:
      embedding_endpoint_type: "openai"   (Letta uses the OpenAI client for this type)
      embedding_endpoint:      <embedding_endpoint param — see below>
      embedding_model:         <bare ollama model name>
      embedding_dim:           <actual dim from table or live probe>
      embedding_chunk_size:    300  (Letta default)

    SC-AGENT-003: the cloud-endpoint handle "letta/letta-free" is replaced by this
    explicit config so Letta never tries to reach embeddings.letta.com.

    ``embedding_endpoint`` (YSG-RISK-169) is dialled by LETTA ITSELF later, not
    by ``client`` here (``client`` is only used for the ONE-OFF dimension probe
    below, made by the calling gateway process against its own reachable
    ``_GATEWAY_EMBED_ENDPOINT`` regardless of which deployment shape called
    this function). Defaults to the per-user-pool-safe value; the static/
    system agent path (_ensure_agent()) passes _LETTA_STATIC_LLM_ENDPOINT.
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
        "embedding_endpoint": embedding_endpoint,
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
    # YSG-RISK-169: this is the STATIC/system-wide letta service — pass the
    # egress-forwarder endpoint its own network can actually reach (see
    # _LETTA_STATIC_LLM_ENDPOINT module comment). Do NOT use the bare
    # _GATEWAY_EMBED_ENDPOINT default here — that is only reachable from the
    # per-user LettaClientPool containers' caddy_internal membership.
    embedding_cfg = await _letta_embedding_config(
        client, embedding_endpoint=_LETTA_STATIC_LLM_ENDPOINT,
    )
    # Create a new agent
    resp = await client.post(f"{base_url}/v1/agents/", json={
        "name": "yashigani-default",
        "memory_blocks": [
            {"label": "human", "value": "The user is interacting via the Yashigani AI security gateway."},
            {"label": "persona", "value": "I am a helpful AI assistant with persistent memory. I remember our conversations."},
        ],
        # YSG-RISK-1xx (chat-path repair, 2026-07-27): llm_config (full
        # object), not "model" (handle) — see _letta_llm_config() docstring.
        "llm_config": _letta_llm_config(brain_model, llm_endpoint=_LETTA_STATIC_LLM_ENDPOINT),
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
    # v4.1 §2.5: base_url is the letta Caddy ingress front
    # (https://caddy:9775/agents/default/letta) — present the gateway mesh
    # leaf.  (The per-user LettaClientPool dials pool containers directly and
    # is NOT fronted; its bare clients are intentionally unchanged.)
    async with agent_dispatch_client(timeout=timeout) as client:
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
