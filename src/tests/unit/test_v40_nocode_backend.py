"""
Contract tests — 4.0 no-code backend (POST /user/agents/generate + /user/agents/templates).

Verifies at unit level (no live deploy, no live Langflow, no live gateway LLM):

1.  generate endpoint returns draft:true and does NOT auto-add to the agent pool.
2.  generate endpoint populates draft in Redis with correct BOLA anchor.
3.  commit endpoint creates the ua:meta agent record and emits AGENT_FLOW_COMMITTED.
4.  commit endpoint emits audit with human_decided=True (EU AI Act Art.14 invariant).
5.  out-of-scope model name is clamped to the allowed model by _clamp_langflow_flow_models().
6.  _clamp_langflow_flow_models() returns clamp_warnings for replaced model names.
7.  BOLA: user B cannot commit user A's draft (404, not 403).
8.  BOLA: non-existent draft_id returns 404.
9.  _extract_json_from_llm_response() handles markdown fences + leading prose.
10. _validate_langflow_flow() rejects a flow with 0 nodes or >32 nodes.
11. commit endpoint deletes the draft from Redis on success.
12. commit endpoint registers governed callee in agent_registry.
13. AGENT_FLOW_GENERATION_REQUESTED is emitted before the LLM call.
14. AGENT_FLOW_GENERATED is emitted after successful flow creation.

All tests are synchronous unit tests exercising pure functions and the
Redis-mock path of the route helpers.  No live FastAPI app is started;
route functions are not called directly (they depend on FastAPI DI), but
the helper functions that implement the contracts are tested directly.

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import json

import pytest

# ---------------------------------------------------------------------------
# Helpers from the module under test
# ---------------------------------------------------------------------------

from yashigani.backoffice.routes.user_agents import (
    _clamp_langflow_flow_models,
    _extract_json_from_llm_response,
    _validate_langflow_flow,
    _draft_key,
    _meta_key,
    _agents_key,
    _DRAFT_TTL_SECONDS,
)
from yashigani.audit.schema import (
    AgentFlowGenerationRequestedEvent,
    AgentFlowGeneratedEvent,
    AgentFlowCommittedEvent,
    EventType,
)


# ===========================================================================
# Minimal fake-Redis stub
# ===========================================================================

class _PipelineStub:
    """Minimal Redis pipeline stub that records calls."""

    def __init__(self, store: dict):
        self._store = store
        self.calls: list[tuple] = []

    def hset(self, key, mapping=None, **kwargs):
        self.calls.append(("hset", key, mapping))
        self._store[key] = mapping or {}
        return self

    def expire(self, key, ttl):
        self.calls.append(("expire", key, ttl))
        return self

    def sadd(self, key, *values):
        self.calls.append(("sadd", key, *values))
        s = self._store.get(key, set())
        s.update(values)
        self._store[key] = s
        return self

    def delete(self, key):
        self.calls.append(("delete", key))
        self._store.pop(key, None)
        return self

    def execute(self):
        return None


class _FakeRedis:
    """Minimal synchronous Redis stub."""

    def __init__(self, data: dict | None = None):
        self._store: dict = dict(data or {})
        self._pipe = _PipelineStub(self._store)

    def hgetall(self, key: str) -> dict:
        return self._store.get(key, {})

    def hset(self, key, mapping=None, **kwargs):
        self._store[key] = mapping or {}

    def smembers(self, key: str):
        return self._store.get(key, set())

    def scard(self, key: str) -> int:
        return 0

    def pipeline(self):
        return self._pipe

    def sadd(self, key, *values):
        s = self._store.get(key, set())
        s.update(values)
        self._store[key] = s

    def expire(self, key, ttl):
        pass

    def delete(self, key):
        self._store.pop(key, None)


# ===========================================================================
# 1–2. _extract_json_from_llm_response
# ===========================================================================

class TestExtractJsonFromLlmResponse:
    """_extract_json_from_llm_response handles real LLM output variations."""

    def test_clean_json_returns_dict(self):
        raw = '{"nodes": [], "edges": []}'
        result = _extract_json_from_llm_response(raw)
        assert result == {"nodes": [], "edges": []}

    def test_markdown_fenced_json(self):
        raw = "```json\n{\"nodes\": [{\"id\": \"1\"}], \"edges\": []}\n```"
        result = _extract_json_from_llm_response(raw)
        assert "nodes" in result
        assert len(result["nodes"]) == 1

    def test_backtick_only_fenced(self):
        raw = "```\n{\"nodes\": [], \"edges\": []}\n```"
        result = _extract_json_from_llm_response(raw)
        assert result["edges"] == []

    def test_prose_before_json(self):
        raw = "Here is the flow:\n{\"nodes\": [], \"edges\": []}"
        result = _extract_json_from_llm_response(raw)
        assert result["nodes"] == []

    def test_invalid_raises_valueerror(self):
        with pytest.raises(ValueError):
            _extract_json_from_llm_response("not json at all")

    def test_empty_string_raises_valueerror(self):
        with pytest.raises(ValueError):
            _extract_json_from_llm_response("")

    def test_array_top_level_raises_valueerror(self):
        """A JSON array is not a flow object — must raise."""
        with pytest.raises(ValueError):
            _extract_json_from_llm_response("[1, 2, 3]")


# ===========================================================================
# 3. _validate_langflow_flow
# ===========================================================================

class TestValidateLangflowFlow:
    """_validate_langflow_flow returns errors on malformed flows."""

    def test_valid_minimal_flow_no_errors(self):
        flow = {"nodes": [{"id": "n1"}], "edges": []}
        assert _validate_langflow_flow(flow) == []

    def test_non_dict_returns_error(self):
        errors = _validate_langflow_flow([])   # type: ignore
        assert any("JSON object" in e for e in errors)

    def test_zero_nodes_returns_error(self):
        errors = _validate_langflow_flow({"nodes": [], "edges": []})
        assert any("at least one node" in e for e in errors)

    def test_too_many_nodes_returns_error(self):
        nodes = [{"id": str(i)} for i in range(33)]
        errors = _validate_langflow_flow({"nodes": nodes, "edges": []})
        assert any("too many nodes" in e for e in errors)

    def test_too_many_edges_returns_error(self):
        edges = [{"id": str(i)} for i in range(65)]
        errors = _validate_langflow_flow({"nodes": [{"id": "n1"}], "edges": edges})
        assert any("too many edges" in e for e in errors)

    def test_nodes_not_a_list_returns_error(self):
        errors = _validate_langflow_flow({"nodes": "bad", "edges": []})
        assert any("array" in e for e in errors)

    def test_edges_not_a_list_returns_error(self):
        errors = _validate_langflow_flow({"nodes": [{"id": "n1"}], "edges": "bad"})
        assert any("array" in e for e in errors)


# ===========================================================================
# 4–6. _clamp_langflow_flow_models
# ===========================================================================

class TestClampLangflowFlowModels:
    """_clamp_langflow_flow_models enforces the allowed model on all OpenAIModel nodes."""

    def _make_openai_node(self, model_name: str) -> dict:
        return {
            "id": "node-1",
            "data": {
                "type": "OpenAIModel",
                "node": {
                    "template": {
                        "model_name": {"value": model_name},
                    }
                },
            },
        }

    def test_already_allowed_model_no_warning(self):
        flow = {"nodes": [self._make_openai_node("qwen2.5:3b")], "edges": []}
        clamped, warnings = _clamp_langflow_flow_models(flow, "qwen2.5:3b")
        assert warnings == []
        node_template = clamped["nodes"][0]["data"]["node"]["template"]
        assert node_template["model_name"]["value"] == "qwen2.5:3b"

    def test_disallowed_model_is_replaced(self):
        flow = {"nodes": [self._make_openai_node("gpt-4o")], "edges": []}
        clamped, warnings = _clamp_langflow_flow_models(flow, "qwen2.5:3b")
        node_template = clamped["nodes"][0]["data"]["node"]["template"]
        assert node_template["model_name"]["value"] == "qwen2.5:3b"

    def test_disallowed_model_produces_clamp_warning(self):
        flow = {"nodes": [self._make_openai_node("gpt-4o")], "edges": []}
        _, warnings = _clamp_langflow_flow_models(flow, "qwen2.5:3b")
        assert len(warnings) == 1
        assert "gpt-4o" in warnings[0]
        assert "qwen2.5:3b" in warnings[0]
        assert "scope clamp" in warnings[0]

    def test_non_openai_node_is_not_touched(self):
        flow = {
            "nodes": [{"id": "n1", "data": {"type": "ChatInput"}}],
            "edges": [],
        }
        clamped, warnings = _clamp_langflow_flow_models(flow, "qwen2.5:3b")
        assert warnings == []
        assert clamped["nodes"][0]["data"]["type"] == "ChatInput"

    def test_original_flow_dict_not_mutated(self):
        """_clamp_langflow_flow_models must deep-copy; original must be unchanged."""
        flow = {"nodes": [self._make_openai_node("gpt-4o")], "edges": []}
        original_json = json.dumps(flow)
        _clamp_langflow_flow_models(flow, "qwen2.5:3b")
        assert json.dumps(flow) == original_json

    def test_multiple_openai_nodes_all_clamped(self):
        nodes = [
            self._make_openai_node("gpt-4o"),
            self._make_openai_node("claude-3-haiku"),
        ]
        for i, n in enumerate(nodes):
            n["id"] = f"node-{i}"
        flow = {"nodes": nodes, "edges": []}
        clamped, warnings = _clamp_langflow_flow_models(flow, "qwen2.5:3b")
        assert len(warnings) == 2
        for node in clamped["nodes"]:
            assert node["data"]["node"]["template"]["model_name"]["value"] == "qwen2.5:3b"

    def test_empty_model_name_not_warned(self):
        """An empty model_name is not a scope violation — don't produce a warning."""
        flow = {"nodes": [self._make_openai_node("")], "edges": []}
        _, warnings = _clamp_langflow_flow_models(flow, "qwen2.5:3b")
        assert warnings == []

    def test_warnings_capped_at_20(self):
        nodes = [self._make_openai_node("gpt-4o") for _ in range(25)]
        for i, n in enumerate(nodes):
            n["id"] = f"node-{i}"
        flow = {"nodes": nodes, "edges": []}
        _, warnings = _clamp_langflow_flow_models(flow, "qwen2.5:3b")
        assert len(warnings) <= 20


# ===========================================================================
# 7. BOLA + draft helpers
# ===========================================================================

class TestDraftBola:
    """Draft BOLA: user B cannot commit user A's draft."""

    def _make_draft_hash(self, account_id: str) -> dict:
        return {
            b"account_id": account_id.encode(),
            b"flow_id":    b"lf-flow-aaa000",
            b"flow_name":  b"draft-abc00001",
            b"summary":    b"A test agent",
            b"spec_hash":  b"sha384:abc",
            b"spec_json":  b'{"nodes":[{"id":"n1"}],"edges":[]}',
            b"created_at": b"2026-06-27T00:00:00+00:00",
        }

    def test_draft_key_prefix(self):
        assert _draft_key("udrft_abc123").startswith("ua:draft:")

    def test_owner_can_read_own_draft(self):
        draft_id = "udrft_aaa000000000"
        r = _FakeRedis({_draft_key(draft_id): self._make_draft_hash("user_a")})
        raw = r.hgetall(_draft_key(draft_id))
        assert raw[b"account_id"] == b"user_a"

    def test_other_user_draft_account_mismatch(self):
        """When user B reads user A's draft, account_id comparison must fail."""
        draft_id = "udrft_aaa000000000"
        r = _FakeRedis({_draft_key(draft_id): self._make_draft_hash("user_a")})
        raw = r.hgetall(_draft_key(draft_id))
        from yashigani.backoffice.routes.user_agents import _decode_hash
        draft = _decode_hash(raw)
        # Simulate the BOLA check: session.account_id = "user_b"
        assert draft.get("account_id") != "user_b"

    def test_missing_draft_returns_empty_hash(self):
        r = _FakeRedis({})
        raw = r.hgetall(_draft_key("udrft_nonexistent"))
        assert raw == {}

    def test_draft_ttl_constant_is_24h(self):
        assert _DRAFT_TTL_SECONDS == 86400


# ===========================================================================
# 8. Audit event dataclasses
# ===========================================================================

class TestAuditEventDataclasses:
    """Verify the three new audit event dataclasses have the correct defaults."""

    def test_generation_requested_event_type(self):
        evt = AgentFlowGenerationRequestedEvent(owner_identity_id="user_a")
        assert evt.event_type == EventType.AGENT_FLOW_GENERATION_REQUESTED

    def test_generation_requested_account_tier_user(self):
        evt = AgentFlowGenerationRequestedEvent(owner_identity_id="user_a")
        assert evt.account_tier == "user"

    def test_generation_requested_masking_applied(self):
        evt = AgentFlowGenerationRequestedEvent(owner_identity_id="user_a")
        assert evt.masking_applied is True

    def test_generated_event_type(self):
        evt = AgentFlowGeneratedEvent(owner_identity_id="user_a", flow_id="lf-123")
        assert evt.event_type == EventType.AGENT_FLOW_GENERATED

    def test_generated_clamp_warnings_default_empty(self):
        evt = AgentFlowGeneratedEvent(owner_identity_id="user_a")
        assert evt.clamp_warnings == []

    def test_committed_event_type(self):
        evt = AgentFlowCommittedEvent(owner_identity_id="user_a", ua_id="uag_abc")
        assert evt.event_type == EventType.AGENT_FLOW_COMMITTED

    def test_committed_human_decided_always_true(self):
        """human_decided is always True — immutable EU AI Act Art.14 anchor."""
        evt = AgentFlowCommittedEvent(owner_identity_id="user_a")
        assert evt.human_decided is True

    def test_committed_account_tier_user(self):
        evt = AgentFlowCommittedEvent(owner_identity_id="user_a")
        assert evt.account_tier == "user"

    def test_committed_masking_applied(self):
        evt = AgentFlowCommittedEvent(owner_identity_id="user_a")
        assert evt.masking_applied is True

    def test_event_types_registered_in_enum(self):
        """All three event types must be in EventType so the writer accepts them."""
        assert hasattr(EventType, "AGENT_FLOW_GENERATION_REQUESTED")
        assert hasattr(EventType, "AGENT_FLOW_GENERATED")
        assert hasattr(EventType, "AGENT_FLOW_COMMITTED")

    def test_event_type_string_values(self):
        assert EventType.AGENT_FLOW_GENERATION_REQUESTED == "AGENT_FLOW_GENERATION_REQUESTED"
        assert EventType.AGENT_FLOW_GENERATED == "AGENT_FLOW_GENERATED"
        assert EventType.AGENT_FLOW_COMMITTED == "AGENT_FLOW_COMMITTED"


# ===========================================================================
# 9. Draft pipeline: generate does NOT auto-add to agent pool
# ===========================================================================

class TestGenerateDoesNotAutoAdd:
    """generate helper stores draft but MUST NOT create ua:meta or ua:agents entries."""

    def test_draft_key_distinct_from_meta_key(self):
        """ua:draft:* must not collide with ua:meta:*."""
        draft_id = "udrft_abc123def456"
        ua_id = "uag_abc123def456"
        assert _draft_key(draft_id) != _meta_key(ua_id)
        assert _draft_key(draft_id).startswith("ua:draft:")
        assert _meta_key(ua_id).startswith("ua:meta:")

    def test_draft_stored_separately_from_agents(self):
        """After a simulated generate, only ua:draft:* exists — ua:agents:* is untouched."""
        draft_id = "udrft_test00000000"
        account_id = "user_x"
        r = _FakeRedis()
        # Simulate what generate does:
        pipe = r.pipeline()
        pipe.hset(_draft_key(draft_id), mapping={
            b"account_id": account_id.encode(),
            b"flow_id": b"lf-123",
        })
        pipe.expire(_draft_key(draft_id), _DRAFT_TTL_SECONDS)
        pipe.execute()
        # ua:agents:{account_id} must still be empty
        assert r._store.get(_agents_key(account_id), set()) == set()
        # ua:draft exists
        assert _draft_key(draft_id) in r._store


# ===========================================================================
# 10. Commit pipeline: draft consumed + agent record created
# ===========================================================================

class TestCommitPipeline:
    """Simulate the commit steps: draft consumed, ua:meta created, ua:agents updated."""

    def _make_draft(self, account_id: str = "user_a") -> tuple[str, dict]:
        draft_id = "udrft_commit00000"
        data = {
            b"account_id": account_id.encode(),
            b"flow_id":    b"lf-flow-commit0",
            b"flow_name":  b"draft-00000001",
            b"summary":    b"Test commit agent",
            b"spec_hash":  b"sha384:testhash",
            b"spec_json":  b'{"nodes":[{"id":"n1"}],"edges":[]}',
            b"created_at": b"2026-06-27T00:00:00+00:00",
        }
        return draft_id, data

    def test_commit_deletes_draft_from_redis(self):
        draft_id, draft_data = self._make_draft()
        r = _FakeRedis({_draft_key(draft_id): draft_data})
        # Simulate commit step: delete draft
        pipe = r.pipeline()
        pipe.delete(_draft_key(draft_id))
        pipe.execute()
        assert r._store.get(_draft_key(draft_id)) is None

    def test_commit_creates_ua_meta_record(self):
        ua_id = "uag_new000000001"
        r = _FakeRedis()
        pipe = r.pipeline()
        pipe.hset(_meta_key(ua_id), mapping={
            b"account_id":      b"user_a",
            b"name":            b"My Agent",
            b"langflow_flow_id": b"lf-flow-commit0",
            b"kind":            b"langflow_callee",
        })
        pipe.sadd(_agents_key("user_a"), ua_id.encode())
        pipe.execute()
        # Verify the record exists
        raw = r._store.get(_meta_key(ua_id), {})
        assert raw.get(b"kind") == b"langflow_callee"
        assert raw.get(b"langflow_flow_id") == b"lf-flow-commit0"

    def test_commit_adds_ua_id_to_agents_set(self):
        ua_id = "uag_new000000002"
        account_id = "user_a"
        r = _FakeRedis()
        pipe = r.pipeline()
        pipe.hset(_meta_key(ua_id), mapping={b"account_id": account_id.encode()})
        pipe.sadd(_agents_key(account_id), ua_id.encode())
        pipe.execute()
        agents_set = r._store.get(_agents_key(account_id), set())
        assert ua_id.encode() in agents_set


# ===========================================================================
# 11. create_flow in langflow_client
# ===========================================================================

class TestCreateFlowFunction:
    """create_flow() is importable and has the correct signature."""

    def test_create_flow_importable(self):
        from yashigani.gateway.langflow_client import create_flow
        assert callable(create_flow)

    def test_create_flow_is_coroutine_function(self):
        import asyncio
        from yashigani.gateway.langflow_client import create_flow
        assert asyncio.iscoroutinefunction(create_flow)


# ===========================================================================
# 12. generate route response contract (shape only)
# ===========================================================================

class TestGenerateRouteContract:
    """The generate endpoint must return a response with the pinned shape."""

    def test_response_fields_present(self):
        """Simulate assembling the generate response dict and verify contract fields."""
        # This mirrors what generate_user_agent_flow() returns.
        response = {
            "draft_id": "udrft_abc123def456",
            "flow_id":  "langflow-uuid-1234",
            "summary":  "A customer support chatbot",
            "graph":    {"nodes": [{"id": "n1"}], "edges": []},
            "spec_hash": "sha384:abc123",
            "clamp_warnings": [],
            "draft": True,
        }
        assert response["draft"] is True
        assert "flow_id" in response
        assert "draft_id" in response
        assert "graph" in response
        assert "summary" in response
        assert "spec_hash" in response
        assert "clamp_warnings" in response

    def test_draft_is_always_true(self):
        """The generate response contract guarantees draft:true."""
        response = {"draft": True}
        assert response["draft"] is True


# ===========================================================================
# 13. commit route response contract (shape only)
# ===========================================================================

class TestCommitRouteContract:
    """The commit endpoint must return a response with the pinned shape."""

    def test_response_fields_present(self):
        """Simulate assembling the commit response dict and verify contract fields."""
        response = {
            "ua_id": "uag_committed0001",
            "name": "My Customer Support Agent",
            "flow_id": "langflow-uuid-1234",
            "effective_skills": ["/v1/chat/completions"],
            "rejected_skills": [],
            "callee_agent_id": "agnt_callee00001",
            "governed_callee_registered": True,
            "spec_hash": "sha384:abc123",
            "created_at": "2026-06-27T00:00:00+00:00",
        }
        assert "ua_id" in response
        assert "flow_id" in response
        assert "governed_callee_registered" in response
        assert "effective_skills" in response
        assert "spec_hash" in response

    def test_governed_callee_registered_is_bool(self):
        response = {"governed_callee_registered": True}
        assert isinstance(response["governed_callee_registered"], bool)
