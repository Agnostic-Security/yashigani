"""
Regression tests — YSG-RISK-171 (chat-path repair, 2026-07-30).

Same root-cause class as YSG-RISK-169 (Letta): gateway/langflow_client.py's
_GATEWAY_MESH_BASE_URL constant is baked directly into the persisted
Langflow flow's OpenAIModel component (_configure_openai_component()) and
must be reachable FROM LANGFLOW'S OWN CONTAINER, not from the gateway
process constructing it.

The v4.1 unified-sidecar split-ringfence migration moved langflow onto
{ringfence_langflow_in, ringfence_langflow_eg} ONLY -- reachable exclusively
via egress-langflow:9400/llm/v1 (matching docker-compose's own
OPENAI_API_BASE for the langflow service, already correctly migrated).
_GATEWAY_MESH_BASE_URL was left hardcoded at the now-unreachable
"http://gateway:8081/v1".

Live-confirmed via `docker logs langflow` (after fixing YSG-RISK-168's
protocol mismatch, which unmasked this deeper bug):

    Error building Component OpenAI: Connection error.
    Task OpenAIModel-... Run 0 failed with exception: Error building Component OpenAI:
    Connection error.

surfaced to the gateway as "Langflow run failed: 500", then to the user as
a masked HTTP 500 (compounding YSG-RISK-167).
"""
from __future__ import annotations


class TestRisk171LangflowEgressForwarderEndpoint:
    """The OpenAIModel component baked into langflow's default flow must
    point at the reachable egress-forwarder, not the unreachable gateway
    mesh port."""

    def test_gateway_mesh_base_url_is_egress_forwarder(self):
        from yashigani.gateway import langflow_client

        assert langflow_client._GATEWAY_MESH_BASE_URL == "http://egress-langflow:9400/llm/v1", (
            "YSG-RISK-171 regression: _GATEWAY_MESH_BASE_URL must point at "
            "the reachable egress-langflow forwarder, not gateway:8081 "
            f"(got: {langflow_client._GATEWAY_MESH_BASE_URL!r})"
        )

    def test_configured_component_uses_reachable_endpoint(self):
        """_configure_openai_component() must bake the reachable endpoint
        into the flow node's openai_api_base field."""
        from yashigani.gateway import langflow_client

        fake_component = {
            "template": {
                "model_name": {"value": ""},
                "openai_api_base": {"value": ""},
                "api_key": {"value": ""},
                "stream": {"value": None},
            }
        }
        configured = langflow_client._configure_openai_component(fake_component)
        base = configured["template"]["openai_api_base"]["value"]
        assert base == "http://egress-langflow:9400/llm/v1", (
            f"Configured OpenAIModel component must use the reachable "
            f"egress-forwarder endpoint, got: {base!r}"
        )

    def test_lm_node_health_check_uses_reachable_endpoint(self):
        """_lm_node_is_healthy() must accept a node configured with the
        reachable endpoint as healthy (idempotent self-heal contract)."""
        from yashigani.gateway import langflow_client

        healthy_node = {
            "type": "OpenAIModel",
            "node": {
                "template": {
                    "openai_api_base": {"value": "http://egress-langflow:9400/llm/v1"},
                },
            },
        }
        assert langflow_client._lm_node_is_healthy(healthy_node), (
            "A node configured with the reachable egress-forwarder endpoint "
            "must be reported healthy"
        )

        stale_node = {
            "type": "OpenAIModel",
            "node": {
                "template": {
                    "openai_api_base": {"value": "http://gateway:8081/v1"},
                },
            },
        }
        assert not langflow_client._lm_node_is_healthy(stale_node), (
            "A node still configured with the OLD unreachable gateway:8081 "
            "endpoint must be reported UNHEALTHY so the self-heal path "
            "(_repair_flow_data) rewrites it"
        )
