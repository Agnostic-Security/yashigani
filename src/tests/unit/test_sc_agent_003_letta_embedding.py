"""
SC-AGENT-003 — Letta embedding routed through gateway, not Letta cloud.

Root cause: "letta/letta-free" handle resolves to https://embeddings.letta.com/
(cloud).  Our Letta container is network-isolated → every create-agent 502.

Fix (3.1): replace the cloud handle with an explicit embedding_config pointing at
http://gateway:8081/v1 in both letta_client.py (_ensure_agent) and
letta_brain.py (_create_brain_agent).

Tests cover:
  LEMB-001 — _letta_embedding_config() returns gateway:8081/v1, type="openai"
  LEMB-002 — embedding_config in create-agent payload uses gateway endpoint, not cloud
  LEMB-003 — brain-agent create-agent payload uses gateway endpoint, not cloud
  LEMB-004 — dim from _OLLAMA_EMBEDDING_DIMS for known models (qwen2.5:3b != 1536)
  LEMB-005 — dim probe fires for unknown model and uses gateway /v1/embeddings
  LEMB-006 — _letta_embedding_model() defaults to brain model's bare name
  LEMB-007 — YASHIGANI_LETTA_EMBEDDING_MODEL env var overrides the model
  LEMB-008 — env-var rename: LETTA_LLM_MODEL / LETTA_EMBEDDING_MODEL are gone from
              docker-compose.yml (they were no-ops — real vars are
              LETTA_DEFAULT_LLM_HANDLE / LETTA_DEFAULT_EMBEDDING_HANDLE)

All tests run without a live stack (httpx mocked).

Last updated: 2026-06-19T00:00:00+00:00
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_httpx_client_mock(
    embed_resp: dict | None = None,
    agent_resp: dict | None = None,
    *,
    embed_status: int = 200,
    agent_status: int = 201,
):
    """Build an httpx.AsyncClient mock with canned GET/POST responses.

    POST to */v1/embeddings* → embed_resp (dim probe or create-agent detect).
    POST to */v1/agents/*    → agent_resp (create-agent).
    GET  to */v1/agents/*    → empty list (no pre-existing agents).
    """
    # GET /v1/agents/ — empty list
    get_resp = MagicMock()
    get_resp.status_code = 200
    get_resp.json.return_value = []

    # POST /v1/embeddings — dim probe
    probe_mock_resp = MagicMock()
    probe_mock_resp.status_code = embed_status
    probe_mock_resp.json.return_value = embed_resp or {
        "data": [{"object": "embedding", "embedding": [0.0] * 2048, "index": 0}],
        "model": "qwen2.5:3b",
        "usage": {"prompt_tokens": 2, "total_tokens": 2},
    }

    # POST /v1/agents/ — create-agent
    create_mock_resp = MagicMock()
    create_mock_resp.status_code = agent_status
    create_mock_resp.json.return_value = agent_resp or {"id": "test-agent-id-001"}
    create_mock_resp.text = ""

    captured_posts: list[dict] = []

    async def _mock_post(url: str, **kwargs):
        captured_posts.append({"url": url, "json": kwargs.get("json", {})})
        if "/v1/embeddings" in url:
            return probe_mock_resp
        return create_mock_resp

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=get_resp)
    mock_client.post = _mock_post
    mock_client.captured_posts = captured_posts

    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm, mock_client


# ---------------------------------------------------------------------------
# LEMB-001 — _letta_embedding_config() shape
# ---------------------------------------------------------------------------

class TestEmbeddingConfigShape:
    """LEMB-001: _letta_embedding_config returns a gateway-pointing config."""

    @pytest.mark.asyncio
    async def test_config_points_at_gateway_not_cloud(self, monkeypatch):
        """embedding_endpoint must be gateway:8081/v1, NOT embeddings.letta.com."""
        # Use a known model so no probe is needed.
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "qwen2.5:3b")
        from yashigani.gateway import letta_client

        mock_client = AsyncMock()
        cfg = await letta_client._letta_embedding_config(mock_client)

        assert "embeddings.letta.com" not in cfg.get("embedding_endpoint", ""), (
            "embedding_endpoint must NOT point at the Letta cloud: "
            f"{cfg.get('embedding_endpoint')!r}"
        )
        assert "gateway" in cfg.get("embedding_endpoint", ""), (
            f"embedding_endpoint must point at the gateway, got: "
            f"{cfg.get('embedding_endpoint')!r}"
        )
        assert "8081" in cfg.get("embedding_endpoint", ""), (
            "Must use the mesh port 8081 (not mTLS 8080): "
            f"{cfg.get('embedding_endpoint')!r}"
        )

    @pytest.mark.asyncio
    async def test_config_type_is_openai(self, monkeypatch):
        """embedding_endpoint_type must be 'openai' (Letta uses the OAI client for this)."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "qwen2.5:3b")
        from yashigani.gateway import letta_client

        mock_client = AsyncMock()
        cfg = await letta_client._letta_embedding_config(mock_client)

        assert cfg.get("embedding_endpoint_type") == "openai", (
            f"embedding_endpoint_type must be 'openai', got {cfg.get('embedding_endpoint_type')!r}"
        )

    @pytest.mark.asyncio
    async def test_config_chunk_size_is_300(self, monkeypatch):
        """embedding_chunk_size defaults to 300 (Letta default)."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "qwen2.5:3b")
        from yashigani.gateway import letta_client

        mock_client = AsyncMock()
        cfg = await letta_client._letta_embedding_config(mock_client)

        assert cfg.get("embedding_chunk_size") == 300, (
            f"embedding_chunk_size must be 300, got {cfg.get('embedding_chunk_size')!r}"
        )


# ---------------------------------------------------------------------------
# LEMB-002 — _ensure_agent create-agent payload
# ---------------------------------------------------------------------------

class TestEnsureAgentPayload:
    """LEMB-002: create-agent payload carries embedding_config not cloud handle."""

    @pytest.mark.asyncio
    async def test_no_cloud_handle_in_create_agent(self, monkeypatch):
        """The create-agent POST body must not contain 'letta/letta-free'."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "qwen2.5:3b")
        # Reset module-level cache so a fresh create-agent is triggered.
        import yashigani.gateway.letta_client as _m
        _m._default_agent_id = None

        cm, mock_client = _make_httpx_client_mock()

        with patch("httpx.AsyncClient", return_value=cm):
            agent_id = await _m._ensure_agent(mock_client, "http://letta:8283")

        assert agent_id == "test-agent-id-001"
        # Find the create-agent POST
        agent_posts = [
            p for p in mock_client.captured_posts if "/v1/agents/" in p["url"]
        ]
        assert agent_posts, "Expected at least one POST to /v1/agents/"
        payload = agent_posts[-1]["json"]

        assert payload.get("embedding") != "letta/letta-free", (
            "Cloud handle 'letta/letta-free' must NOT appear in the create-agent payload"
        )
        assert "embedding" not in payload or payload.get("embedding") is None, (
            f"'embedding' field (handle) must be absent or None; found: {payload.get('embedding')!r}"
        )

    @pytest.mark.asyncio
    async def test_embedding_config_in_create_agent_payload(self, monkeypatch):
        """The create-agent POST body must contain embedding_config pointing at gateway."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "qwen2.5:3b")
        import yashigani.gateway.letta_client as _m
        _m._default_agent_id = None

        cm, mock_client = _make_httpx_client_mock()

        with patch("httpx.AsyncClient", return_value=cm):
            await _m._ensure_agent(mock_client, "http://letta:8283")

        agent_posts = [
            p for p in mock_client.captured_posts if "/v1/agents/" in p["url"]
        ]
        payload = agent_posts[-1]["json"]
        embed_cfg = payload.get("embedding_config")

        assert embed_cfg is not None, (
            "embedding_config must be present in the create-agent payload"
        )
        assert "gateway" in embed_cfg.get("embedding_endpoint", ""), (
            f"embedding_endpoint must point at the gateway: {embed_cfg.get('embedding_endpoint')!r}"
        )
        assert embed_cfg.get("embedding_endpoint_type") == "openai", (
            f"embedding_endpoint_type must be 'openai': {embed_cfg.get('embedding_endpoint_type')!r}"
        )

    @pytest.mark.asyncio
    async def test_embedding_dim_not_1536_for_local_model(self, monkeypatch):
        """embedding_dim in the payload must NOT be 1536 (that's OpenAI's dim, wrong here)."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "qwen2.5:3b")
        import yashigani.gateway.letta_client as _m
        _m._default_agent_id = None

        cm, mock_client = _make_httpx_client_mock()

        with patch("httpx.AsyncClient", return_value=cm):
            await _m._ensure_agent(mock_client, "http://letta:8283")

        agent_posts = [
            p for p in mock_client.captured_posts if "/v1/agents/" in p["url"]
        ]
        payload = agent_posts[-1]["json"]
        embed_cfg = payload.get("embedding_config", {})
        dim = embed_cfg.get("embedding_dim")

        assert dim is not None, "embedding_dim must be set in embedding_config"
        assert dim != 1536, (
            f"embedding_dim must NOT be 1536 (that is OpenAI's dimension, wrong for "
            f"local Ollama models). Got: {dim}"
        )


# ---------------------------------------------------------------------------
# LEMB-003 — _create_brain_agent payload (letta_brain.py)
# ---------------------------------------------------------------------------

class TestBrainAgentPayload:
    """LEMB-003: _create_brain_agent also uses embedding_config not cloud handle."""

    @pytest.mark.asyncio
    async def test_brain_agent_no_cloud_handle(self, monkeypatch):
        """letta_brain._create_brain_agent must not use 'letta/letta-free'."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "qwen2.5:3b")
        from yashigani.gateway import letta_brain, tool_catalog

        # Minimal catalog
        cat = tool_catalog.ToolCatalog(tools=[], name_map={})
        captured_bodies: list[dict] = []

        create_resp = MagicMock()
        create_resp.status_code = 201
        create_resp.json.return_value = {"id": "brain-agent-001"}
        create_resp.text = ""

        probe_resp = MagicMock()
        probe_resp.status_code = 200
        probe_resp.json.return_value = {
            "data": [{"object": "embedding", "embedding": [0.0] * 2048, "index": 0}]
        }

        async def mock_post(url, **kwargs):
            captured_bodies.append({"url": url, "json": kwargs.get("json", {})})
            if "/v1/embeddings" in url:
                return probe_resp
            return create_resp

        mock_client = AsyncMock()
        mock_client.post = mock_post

        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=cm):
            agent_id = await letta_brain._create_brain_agent(
                "http://letta:8283", cat, timeout=30.0
            )

        assert agent_id == "brain-agent-001"
        agent_posts = [p for p in captured_bodies if "/v1/agents/" in p["url"]]
        assert agent_posts, "Expected POST to /v1/agents/"
        payload = agent_posts[-1]["json"]

        assert payload.get("embedding") != "letta/letta-free", (
            "Cloud handle 'letta/letta-free' must not appear in brain-agent payload"
        )
        embed_cfg = payload.get("embedding_config")
        assert embed_cfg is not None, "embedding_config must be present in brain-agent payload"
        assert "gateway" in embed_cfg.get("embedding_endpoint", ""), (
            f"Brain-agent embedding_endpoint must point at gateway: {embed_cfg!r}"
        )

    @pytest.mark.asyncio
    async def test_brain_agent_embedding_dim_not_1536(self, monkeypatch):
        """Brain-agent embedding_dim must not be 1536 (wrong for local Ollama models)."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "qwen2.5:3b")
        from yashigani.gateway import letta_brain, tool_catalog

        cat = tool_catalog.ToolCatalog(tools=[], name_map={})
        captured_bodies: list[dict] = []

        create_resp = MagicMock()
        create_resp.status_code = 201
        create_resp.json.return_value = {"id": "brain-agent-002"}
        create_resp.text = ""

        async def mock_post(url, **kwargs):
            captured_bodies.append({"url": url, "json": kwargs.get("json", {})})
            return create_resp

        mock_client = AsyncMock()
        mock_client.post = mock_post

        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=cm):
            await letta_brain._create_brain_agent("http://letta:8283", cat, timeout=30.0)

        agent_posts = [p for p in captured_bodies if "/v1/agents/" in p["url"]]
        payload = agent_posts[-1]["json"]
        embed_cfg = payload.get("embedding_config", {})
        dim = embed_cfg.get("embedding_dim")

        assert dim != 1536, (
            f"embedding_dim must not be 1536 (OpenAI dim, wrong for Ollama). Got: {dim}"
        )


# ---------------------------------------------------------------------------
# LEMB-004 — dim lookup from _OLLAMA_EMBEDDING_DIMS
# ---------------------------------------------------------------------------

class TestDimLookup:
    """LEMB-004: known models use the table, not a probe."""

    @pytest.mark.asyncio
    async def test_qwen25_3b_dim_is_2048_not_1536(self, monkeypatch):
        """qwen2.5:3b must resolve to dim=2048 from the table (never 1536)."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "qwen2.5:3b")
        from yashigani.gateway import letta_client

        mock_client = AsyncMock()
        # post should NOT be called — dim is in the table
        mock_client.post = AsyncMock(side_effect=AssertionError(
            "Should not probe gateway for a known model"
        ))

        cfg = await letta_client._letta_embedding_config(mock_client)

        assert cfg["embedding_dim"] == 2048, (
            f"qwen2.5:3b dim must be 2048, got {cfg['embedding_dim']}"
        )

    @pytest.mark.asyncio
    async def test_nomic_embed_text_dim_is_768(self, monkeypatch):
        """nomic-embed-text must resolve to dim=768 from the table."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "nomic-embed-text")
        from yashigani.gateway import letta_client

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=AssertionError(
            "Should not probe for a known model"
        ))

        cfg = await letta_client._letta_embedding_config(mock_client)

        assert cfg["embedding_dim"] == 768, (
            f"nomic-embed-text dim must be 768, got {cfg['embedding_dim']}"
        )

    @pytest.mark.asyncio
    async def test_all_minilm_dim_is_384(self, monkeypatch):
        """all-minilm must resolve to dim=384 from the table."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "all-minilm")
        from yashigani.gateway import letta_client

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=AssertionError(
            "Should not probe for a known model"
        ))

        cfg = await letta_client._letta_embedding_config(mock_client)

        assert cfg["embedding_dim"] == 384, (
            f"all-minilm dim must be 384, got {cfg['embedding_dim']}"
        )


# ---------------------------------------------------------------------------
# LEMB-005 — probe fires for unknown model
# ---------------------------------------------------------------------------

class TestDimProbe:
    """LEMB-005: unknown model triggers a live probe via POST /v1/embeddings."""

    @pytest.mark.asyncio
    async def test_unknown_model_triggers_probe(self, monkeypatch):
        """An unregistered model name must trigger _probe_embedding_dim()."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "llama3.2:3b")
        from yashigani.gateway import letta_client

        probe_called = []

        async def mock_post(url, **kwargs):
            probe_called.append(url)
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {
                "data": [{"object": "embedding", "embedding": [0.0] * 3072, "index": 0}]
            }
            return resp

        mock_client = AsyncMock()
        mock_client.post = mock_post

        cfg = await letta_client._letta_embedding_config(mock_client)

        assert probe_called, "Probe must have been called for an unknown model"
        assert "/v1/embeddings" in probe_called[0], (
            f"Probe must call /v1/embeddings, got: {probe_called[0]!r}"
        )
        assert cfg["embedding_dim"] == 3072, (
            f"Dim from probe must be used (3072), got {cfg['embedding_dim']}"
        )

    @pytest.mark.asyncio
    async def test_probe_failure_falls_back_to_2048(self, monkeypatch):
        """If the probe fails (network error), fallback dim=2048 is used."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "some-unknown-model")
        from yashigani.gateway import letta_client
        import httpx

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        cfg = await letta_client._letta_embedding_config(mock_client)

        assert cfg["embedding_dim"] == 2048, (
            f"Fallback dim must be 2048 on probe failure, got {cfg['embedding_dim']}"
        )

    @pytest.mark.asyncio
    async def test_probe_bad_status_falls_back_to_2048(self, monkeypatch):
        """If the probe returns a non-200, fallback dim=2048 is used."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "unknown-model:latest")
        from yashigani.gateway import letta_client

        bad_resp = MagicMock()
        bad_resp.status_code = 503
        bad_resp.json.return_value = {}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=bad_resp)

        cfg = await letta_client._letta_embedding_config(mock_client)

        assert cfg["embedding_dim"] == 2048


# ---------------------------------------------------------------------------
# LEMB-006 — _letta_embedding_model() default = brain model bare name
# ---------------------------------------------------------------------------

class TestEmbeddingModelDefault:
    """LEMB-006: _letta_embedding_model() strips the provider prefix from brain model."""

    def test_defaults_to_brain_model_bare_name(self, monkeypatch):
        """Without YASHIGANI_LETTA_EMBEDDING_MODEL, uses brain model's bare name."""
        monkeypatch.delenv("YASHIGANI_LETTA_EMBEDDING_MODEL", raising=False)
        monkeypatch.setenv("YASHIGANI_LETTA_BRAIN_MODEL", "openai-proxy/qwen2.5:3b")
        import yashigani.gateway.letta_client as _m
        # Note: the function reads env at call time — no reload needed
        model = _m._letta_embedding_model()
        assert model == "qwen2.5:3b", (
            f"Expected 'qwen2.5:3b' (stripped prefix), got {model!r}"
        )

    def test_defaults_strips_any_provider_prefix(self, monkeypatch):
        """Any 'provider/' prefix is stripped, not just 'openai-proxy/'."""
        monkeypatch.delenv("YASHIGANI_LETTA_EMBEDDING_MODEL", raising=False)
        monkeypatch.setenv("YASHIGANI_LETTA_BRAIN_MODEL", "custom-provider/llama3.2:3b")
        from yashigani.gateway import letta_client
        model = letta_client._letta_embedding_model()
        assert model == "llama3.2:3b", f"Expected 'llama3.2:3b', got {model!r}"

    def test_no_prefix_brain_model_returned_as_is(self, monkeypatch):
        """If the brain model has no '/', it is returned as-is."""
        monkeypatch.delenv("YASHIGANI_LETTA_EMBEDDING_MODEL", raising=False)
        monkeypatch.setenv("YASHIGANI_LETTA_BRAIN_MODEL", "qwen2.5:3b")
        from yashigani.gateway import letta_client
        model = letta_client._letta_embedding_model()
        assert model == "qwen2.5:3b"


# ---------------------------------------------------------------------------
# LEMB-007 — YASHIGANI_LETTA_EMBEDDING_MODEL env var override
# ---------------------------------------------------------------------------

class TestEmbeddingModelEnvOverride:
    """LEMB-007: YASHIGANI_LETTA_EMBEDDING_MODEL overrides the default."""

    def test_env_var_overrides_brain_model(self, monkeypatch):
        """When YASHIGANI_LETTA_EMBEDDING_MODEL is set, it wins over brain model default."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "nomic-embed-text")
        monkeypatch.setenv("YASHIGANI_LETTA_BRAIN_MODEL", "openai-proxy/qwen2.5:3b")
        from yashigani.gateway import letta_client
        model = letta_client._letta_embedding_model()
        assert model == "nomic-embed-text", (
            f"YASHIGANI_LETTA_EMBEDDING_MODEL env var must override brain model. "
            f"Got: {model!r}"
        )

    @pytest.mark.asyncio
    async def test_env_override_reflected_in_embedding_config(self, monkeypatch):
        """embedding_model in the payload must match YASHIGANI_LETTA_EMBEDDING_MODEL."""
        monkeypatch.setenv("YASHIGANI_LETTA_EMBEDDING_MODEL", "nomic-embed-text")
        from yashigani.gateway import letta_client

        mock_client = AsyncMock()
        # nomic-embed-text is in the table, so no probe
        mock_client.post = AsyncMock(side_effect=AssertionError("Should not probe"))

        cfg = await letta_client._letta_embedding_config(mock_client)

        assert cfg["embedding_model"] == "nomic-embed-text", (
            f"embedding_model in config must be 'nomic-embed-text', got {cfg['embedding_model']!r}"
        )
        assert cfg["embedding_dim"] == 768, (
            f"nomic-embed-text dim must be 768, got {cfg['embedding_dim']}"
        )


# ---------------------------------------------------------------------------
# LEMB-008 — docker-compose.yml env-var rename verification
# ---------------------------------------------------------------------------

class TestComposeEnvVarRename:
    """LEMB-008: LETTA_LLM_MODEL and LETTA_EMBEDDING_MODEL are gone from compose."""

    def test_bogus_letta_env_vars_removed_from_compose(self):
        """LETTA_LLM_MODEL and LETTA_EMBEDDING_MODEL must not appear as active
        (uncommented) env var assignments in docker-compose.yml.

        These were silently ignored by Letta 0.16.7 (real vars are
        LETTA_DEFAULT_LLM_HANDLE and LETTA_DEFAULT_EMBEDDING_HANDLE).
        Leaving them as uncommented values implies behaviour they don't have.
        """
        import pathlib
        compose_path = pathlib.Path(__file__).parents[3] / "docker" / "docker-compose.yml"
        assert compose_path.exists(), f"docker-compose.yml not found at {compose_path}"

        content = compose_path.read_text()
        lines = content.splitlines()

        violations = []
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip comment-only lines
            if stripped.startswith("#"):
                continue
            # Active (uncommented) assignment of the bogus vars.
            # Match the exact names — NOT prefixed by YASHIGANI_ (that is our correct var).
            if (stripped.startswith("LETTA_LLM_MODEL:")
                    or stripped.startswith("LETTA_EMBEDDING_MODEL:")):
                violations.append(f"  line {lineno}: {stripped!r}")

        assert not violations, (
            "LETTA_LLM_MODEL and LETTA_EMBEDDING_MODEL are no-op env vars in Letta 0.16.7 "
            "(Settings env_prefix='letta_' maps them to letta_llm_model / "
            "letta_embedding_model, which don't exist as Settings fields). "
            "They must not appear as active assignments.\n"
            "Found:\n" + "\n".join(violations)
        )

    def test_gateway_has_yashigani_letta_embedding_model(self):
        """YASHIGANI_LETTA_EMBEDDING_MODEL must be set in the gateway service block."""
        import pathlib
        compose_path = pathlib.Path(__file__).parents[3] / "docker" / "docker-compose.yml"
        content = compose_path.read_text()

        assert "YASHIGANI_LETTA_EMBEDDING_MODEL" in content, (
            "YASHIGANI_LETTA_EMBEDDING_MODEL must be declared in docker-compose.yml "
            "(under the gateway service block)"
        )

    def test_gateway_has_yashigani_letta_brain_model(self):
        """YASHIGANI_LETTA_BRAIN_MODEL must be set in the gateway service block."""
        import pathlib
        compose_path = pathlib.Path(__file__).parents[3] / "docker" / "docker-compose.yml"
        content = compose_path.read_text()

        assert "YASHIGANI_LETTA_BRAIN_MODEL" in content, (
            "YASHIGANI_LETTA_BRAIN_MODEL must be declared in docker-compose.yml"
        )
