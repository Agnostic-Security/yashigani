"""
Regression tests — YSG-RISK-169 (chat-path repair, 2026-07-30).

Root cause: gateway/letta_client.py's _letta_llm_config() / _letta_embedding_
config() hardcoded model_endpoint / embedding_endpoint to
"http://gateway:8081/v1" -- a value written into the LETTA-SIDE config that
must be reachable FROM LETTA'S OWN CONTAINER, not from the gateway process
constructing it.

The static, system-wide `letta` compose service (used by the shared @letta
mention path via _ensure_agent()/letta_chat()) sits on ringfence_letta_in +
ringfence_letta_eg + letta_db ONLY (v4.1 unified-sidecar split-ringfence) --
it can reach egress-letta:9400 but NOT gateway:8081 directly. Live-confirmed
via `docker logs letta`:

    Letta.letta.llm_api.openai_client - WARNING - [OpenAI] API connection
    error: Connection error.
    ... Agent loop stopped due to exception (exception_type=LLMConnectionError):
    INTERNAL_SERVER_ERROR: Failed to connect to OpenAI: Connection error.

which the gateway then surfaces to users as "Agent @letta (Letta)
unreachable" (502).

The separate per-user LettaClientPool containers ("persona" @-handles) DO
join caddy_internal and CAN reach gateway:8081 directly -- this fix must not
regress that path.
"""
from __future__ import annotations


class TestRisk169StaticAgentUsesReachableEndpoint:
    """_ensure_agent() (static/system @letta path) must configure Letta with
    the egress-letta forwarder endpoint, not the unreachable gateway:8081."""

    def test_letta_llm_config_default_still_gateway_for_pool_path(self):
        """Default (no override) must remain gateway:8081/v1 -- the per-user
        LettaClientPool path relies on this default and must not regress."""
        from yashigani.gateway import letta_client

        cfg = letta_client._letta_llm_config("openai-proxy/qwen2.5:3b")
        assert "gateway" in cfg["model_endpoint"] and "8081" in cfg["model_endpoint"], (
            f"Default llm_config endpoint must stay gateway:8081 (per-user "
            f"pool path relies on this): {cfg['model_endpoint']!r}"
        )

    def test_letta_llm_config_static_override_uses_egress_forwarder(self):
        """Explicit llm_endpoint override (used by the static/system path)
        must point at the reachable egress-letta forwarder."""
        from yashigani.gateway import letta_client

        cfg = letta_client._letta_llm_config(
            "openai-proxy/qwen2.5:3b",
            llm_endpoint=letta_client._LETTA_STATIC_LLM_ENDPOINT,
        )
        assert cfg["model_endpoint"] == "http://egress-letta:9400/llm/v1", (
            f"Static-path llm_config must use the egress-letta forwarder: "
            f"{cfg['model_endpoint']!r}"
        )

    async def test_ensure_agent_creates_with_egress_letta_endpoint(self):
        """_ensure_agent() (module-level, static system path) must build its
        create-agent payload with the egress-letta endpoint, not gateway:8081
        -- this is the exact live-observed regression."""
        import yashigani.gateway.letta_client as _m

        _m._default_agent_id = None
        captured: dict = {}

        class _FakeResp:
            def __init__(self, status_code, payload):
                self.status_code = status_code
                self._payload = payload
                self.text = ""

            def json(self):
                return self._payload

        class _FakeClient:
            async def get(self, url, *a, **kw):
                return _FakeResp(404, {})

            async def post(self, url, json=None, **kw):
                if "/v1/agents/" in url:
                    captured["payload"] = json
                    return _FakeResp(200, {"id": "agent-xyz"})
                return _FakeResp(200, {"data": [{"embedding": [0.0] * 2048}]})

        mock_client = _FakeClient()
        agent_id = await _m._ensure_agent(mock_client, "http://letta:8283")

        assert agent_id == "agent-xyz"
        payload = captured.get("payload") or {}
        llm_cfg = payload.get("llm_config", {})
        embed_cfg = payload.get("embedding_config", {})

        assert llm_cfg.get("model_endpoint") == "http://egress-letta:9400/llm/v1", (
            f"YSG-RISK-169 regression: _ensure_agent's llm_config.model_endpoint "
            f"must be the reachable egress-letta forwarder, got: "
            f"{llm_cfg.get('model_endpoint')!r}"
        )
        assert embed_cfg.get("embedding_endpoint") == "http://egress-letta:9400/llm/v1", (
            f"YSG-RISK-169 regression: _ensure_agent's embedding_config."
            f"embedding_endpoint must be the reachable egress-letta forwarder, "
            f"got: {embed_cfg.get('embedding_endpoint')!r}"
        )
