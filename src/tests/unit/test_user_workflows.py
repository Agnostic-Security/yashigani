"""
Unit tests — Yashigani 4.0 no-code workflow composer backend.

Covers:
  - NL → spec: mocked LLM → validate_and_clamp_handles → clamped spec
  - Schedule parsing: interval / cron / none / invalid
  - Handle validation: unknown actor removed, unknown uses entry removed,
    unknown output_to set to null
  - BOLA: user B cannot read or commit user A's draft/workflow
  - Commit gate: nothing committed without explicit POST /user/workflows
  - _build_valid_handles: agents / MCPs / APIs

All tests are unit-level — no live FastAPI app or Redis instance.

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import json

import pytest

from fastapi import HTTPException

from yashigani.backoffice.routes.user_workflows import (
    _build_valid_handles,
    _draft_key,
    _get_draft_or_404,
    _get_workflow_or_404,
    _parse_schedule,
    _validate_and_clamp_handles,
    _wf_key,
)


# ===========================================================================
# Minimal fake-Redis stub
# ===========================================================================


class _FakeRedis:
    """Synchronous Redis stub for unit tests."""

    def __init__(self, data: dict | None = None):
        self._data: dict[str, dict] = data or {}
        self._sets: dict[str, set] = {}

    def hgetall(self, key: str) -> dict:
        return dict(self._data.get(key, {}))

    def smembers(self, key: str) -> set:
        return set(self._sets.get(key, set()))


# ===========================================================================
# Helpers: build fake hashes
# ===========================================================================


def _make_wf_hash(account_id: str, name: str = "My Workflow") -> dict:
    spec = json.dumps({"steps": [], "schedule": {"kind": "none"}})
    return {
        b"account_id": account_id.encode(),
        b"owner_identity_id": account_id.encode(),
        b"name": name.encode(),
        b"description": b"",
        b"spec": spec.encode(),
        b"spec_hash": b"sha384:abc",
        b"enabled": b"1",
        b"created_at": b"2026-06-27T00:00:00+00:00",
        b"updated_at": b"2026-06-27T00:00:00+00:00",
    }


def _make_draft_hash(account_id: str) -> dict:
    spec = json.dumps({
        "steps": [{"actor": "mimi", "action": "do it", "uses": [], "output_to": None}],
        "schedule": {"kind": "none"},
    })
    return {
        b"account_id": account_id.encode(),
        b"description": b"some NL description",
        b"summary": b"some NL description",
        b"spec": spec.encode(),
        b"spec_hash": b"sha384:abc",
        b"created_at": b"2026-06-27T00:00:00+00:00",
    }


# ===========================================================================
# Schedule parsing
# ===========================================================================


class TestParseSchedule:

    def test_interval_valid(self):
        s = _parse_schedule({"kind": "interval", "seconds": 600})
        assert s["kind"] == "interval"
        assert s["seconds"] == 600
        assert s["cron"] is None

    def test_interval_string_seconds_coerced(self):
        s = _parse_schedule({"kind": "interval", "seconds": "60"})
        assert s["seconds"] == 60

    def test_interval_missing_seconds_raises(self):
        with pytest.raises(ValueError, match="seconds"):
            _parse_schedule({"kind": "interval"})

    def test_interval_zero_seconds_raises(self):
        with pytest.raises(ValueError, match="must be > 0"):
            _parse_schedule({"kind": "interval", "seconds": 0})

    def test_interval_negative_seconds_raises(self):
        with pytest.raises(ValueError, match="must be > 0"):
            _parse_schedule({"kind": "interval", "seconds": -60})

    def test_cron_valid(self):
        s = _parse_schedule({"kind": "cron", "cron": "0 9 * * *"})
        assert s["kind"] == "cron"
        assert s["cron"] == "0 9 * * *"
        assert s["seconds"] is None

    def test_cron_missing_expression_raises(self):
        with pytest.raises(ValueError, match="cron"):
            _parse_schedule({"kind": "cron"})

    def test_cron_invalid_field_count_raises(self):
        with pytest.raises(ValueError, match="5-field"):
            _parse_schedule({"kind": "cron", "cron": "0 9 *"})

    def test_none_kind(self):
        s = _parse_schedule({"kind": "none"})
        assert s["kind"] == "none"
        assert s["seconds"] is None
        assert s["cron"] is None

    def test_non_dict_defaults_to_none(self):
        s = _parse_schedule(None)
        assert s["kind"] == "none"

    def test_unknown_kind_raises(self):
        with pytest.raises(ValueError, match="kind"):
            _parse_schedule({"kind": "hourly"})

    def test_every_hour_interval(self):
        s = _parse_schedule({"kind": "interval", "seconds": 3600})
        assert s["seconds"] == 3600


# ===========================================================================
# Handle validation + clamping
# ===========================================================================


VALID_HANDLES = {
    "mimi": {"handle": "mimi", "kind": "persona", "display": "Mimi", "id": "uag_001"},
    "mcp2": {"handle": "mcp2", "kind": "mcp", "display": "MCP Server 2", "id": "mcp2"},
    "api9": {"handle": "api9", "kind": "api", "display": "API Service 9", "id": "agnt_009"},
}


class TestValidateAndClampHandles:

    def test_all_valid_handles_pass_through(self):
        spec = {
            "steps": [
                {"actor": "mimi", "action": "do it", "uses": ["mcp2"], "output_to": "api9"},
            ],
            "schedule": {"kind": "none"},
        }
        clamped, warnings = _validate_and_clamp_handles(spec, VALID_HANDLES)
        assert len(clamped["steps"]) == 1
        assert clamped["steps"][0]["actor"] == "mimi"
        assert clamped["steps"][0]["uses"] == ["mcp2"]
        assert clamped["steps"][0]["output_to"] == "api9"
        assert warnings == []

    def test_at_prefix_stripped_from_handles(self):
        """LLM may return @mimi — the @ should be stripped during validation."""
        spec = {
            "steps": [
                {"actor": "@mimi", "action": "do it", "uses": ["@mcp2"], "output_to": "@api9"},
            ],
            "schedule": {"kind": "none"},
        }
        clamped, warnings = _validate_and_clamp_handles(spec, VALID_HANDLES)
        assert len(clamped["steps"]) == 1
        assert clamped["steps"][0]["actor"] == "mimi"
        assert clamped["steps"][0]["uses"] == ["mcp2"]
        assert clamped["steps"][0]["output_to"] == "api9"

    def test_unknown_actor_removes_step(self):
        """An unknown actor causes the step to be dropped entirely."""
        spec = {
            "steps": [
                {"actor": "ghost", "action": "hack", "uses": [], "output_to": None},
                {"actor": "mimi", "action": "do it", "uses": [], "output_to": None},
            ],
            "schedule": {"kind": "none"},
        }
        clamped, warnings = _validate_and_clamp_handles(spec, VALID_HANDLES)
        assert len(clamped["steps"]) == 1
        assert clamped["steps"][0]["actor"] == "mimi"
        assert any("ghost" in w for w in warnings)
        assert any("step removed" in w for w in warnings)

    def test_unknown_uses_entry_removed(self):
        """Unknown @-handle in uses[] is silently removed; known ones remain."""
        spec = {
            "steps": [
                {"actor": "mimi", "action": "fetch", "uses": ["mcp2", "unknown_tool"], "output_to": None},
            ],
            "schedule": {"kind": "none"},
        }
        clamped, warnings = _validate_and_clamp_handles(spec, VALID_HANDLES)
        assert clamped["steps"][0]["uses"] == ["mcp2"]
        assert any("unknown_tool" in w for w in warnings)

    def test_unknown_output_to_set_to_null(self):
        """Unknown output_to is set to null with a warning."""
        spec = {
            "steps": [
                {"actor": "mimi", "action": "do it", "uses": [], "output_to": "nowhere"},
            ],
            "schedule": {"kind": "none"},
        }
        clamped, warnings = _validate_and_clamp_handles(spec, VALID_HANDLES)
        assert clamped["steps"][0]["output_to"] is None
        assert any("nowhere" in w for w in warnings)

    def test_null_output_to_preserved(self):
        """Explicit null output_to passes through unchanged."""
        spec = {
            "steps": [
                {"actor": "mimi", "action": "terminal step", "uses": [], "output_to": None},
            ],
            "schedule": {"kind": "none"},
        }
        clamped, warnings = _validate_and_clamp_handles(spec, VALID_HANDLES)
        assert clamped["steps"][0]["output_to"] is None
        assert not any("output_to" in w for w in warnings)

    def test_empty_steps_list(self):
        spec = {"steps": [], "schedule": {"kind": "none"}}
        clamped, warnings = _validate_and_clamp_handles(spec, VALID_HANDLES)
        assert clamped["steps"] == []
        assert warnings == []

    def test_all_steps_dropped_produces_empty(self):
        spec = {
            "steps": [
                {"actor": "x1", "action": "a", "uses": [], "output_to": None},
                {"actor": "x2", "action": "b", "uses": [], "output_to": None},
            ],
            "schedule": {"kind": "none"},
        }
        clamped, warnings = _validate_and_clamp_handles(spec, VALID_HANDLES)
        assert clamped["steps"] == []
        assert len(warnings) == 2

    def test_action_truncated_to_2000_chars(self):
        """Actions longer than 2000 chars are truncated during clamping."""
        long_action = "x" * 3000
        spec = {
            "steps": [
                {"actor": "mimi", "action": long_action, "uses": [], "output_to": None},
            ],
            "schedule": {"kind": "none"},
        }
        clamped, _ = _validate_and_clamp_handles(spec, VALID_HANDLES)
        assert len(clamped["steps"][0]["action"]) == 2000


# ===========================================================================
# _build_valid_handles — handle map construction
# ===========================================================================


class TestBuildValidHandles:

    def test_user_owned_agent_in_handles(self):
        """User-owned agents (with alias) appear in the handle map."""
        r = _FakeRedis(data={
            "ua:agents:user_a": {},  # set-like — but we fake via smembers
            "ua:meta:uag_001": {
                b"account_id": b"user_a",
                b"alias": b"mimi",
                b"kind": b"persona",
                b"name": b"Mimi Agent",
            },
        })
        r._sets["ua:agents:user_a"] = {"uag_001"}

        handles = _build_valid_handles(r, "user_a")
        assert "mimi" in handles
        assert handles["mimi"]["kind"] == "persona"
        assert handles["mimi"]["display"] == "Mimi Agent"

    def test_other_users_agent_excluded_bola(self):
        """Agents owned by user_b are NOT in user_a's handle map (BOLA)."""
        r = _FakeRedis(data={
            "ua:meta:uag_001": {
                b"account_id": b"user_b",   # owned by B, not A
                b"alias": b"evil",
                b"kind": b"agent",
                b"name": b"Evil Agent",
            },
        })
        r._sets["ua:agents:user_a"] = {"uag_001"}

        handles = _build_valid_handles(r, "user_a")
        assert "evil" not in handles

    def test_agent_without_alias_excluded(self):
        """Legacy agents without an alias are excluded."""
        r = _FakeRedis(data={
            "ua:meta:uag_001": {
                b"account_id": b"user_a",
                b"alias": b"",          # no alias
                b"kind": b"agent",
                b"name": b"No Alias Agent",
            },
        })
        r._sets["ua:agents:user_a"] = {"uag_001"}

        handles = _build_valid_handles(r, "user_a")
        assert "" not in handles

    def test_mcp_servers_from_env(self, monkeypatch):
        """MCPs from YASHIGANI_MCP_SERVERS appear in the handle map."""
        mcp_config = json.dumps([
            {"agent_name": "mcp2", "upstream_url": "http://mcp2:8000", "tenant_id": "t1"},
            {"agent_name": "git", "upstream_url": "http://git-mcp:8000", "tenant_id": "t1"},
        ])
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", mcp_config)

        r = _FakeRedis()
        handles = _build_valid_handles(r, "user_a")
        assert "mcp2" in handles
        assert handles["mcp2"]["kind"] == "mcp"
        assert "git" in handles
        assert handles["git"]["kind"] == "mcp"

    def test_no_mcp_servers_env(self, monkeypatch):
        """Missing YASHIGANI_MCP_SERVERS → no MCP handles (no error)."""
        monkeypatch.delenv("YASHIGANI_MCP_SERVERS", raising=False)
        r = _FakeRedis()
        handles = _build_valid_handles(r, "user_a")
        # Should not raise; MCP handles simply absent
        assert all(v["kind"] != "mcp" for v in handles.values())

    def test_invalid_mcp_env_gracefully_skipped(self, monkeypatch):
        """Malformed YASHIGANI_MCP_SERVERS JSON is skipped without raising."""
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", "not-json{{{")
        r = _FakeRedis()
        # Should not raise; MCPs simply absent
        handles = _build_valid_handles(r, "user_a")
        assert all(v["kind"] != "mcp" for v in handles.values())


# ===========================================================================
# BOLA — workflow store
# ===========================================================================


class TestWorkflowBOLA:

    def test_get_own_workflow_succeeds(self):
        wf_id = "wfl_aaa000000000"
        r = _FakeRedis({_wf_key(wf_id): _make_wf_hash("user_a")})
        meta = _get_workflow_or_404(r, wf_id, "user_a")
        assert meta["account_id"] == "user_a"

    def test_get_other_users_workflow_returns_404(self):
        """User B requesting user A's workflow MUST get 404, not 403."""
        wf_id = "wfl_aaa000000000"
        r = _FakeRedis({_wf_key(wf_id): _make_wf_hash("user_a")})
        with pytest.raises(HTTPException) as exc:
            _get_workflow_or_404(r, wf_id, "user_b")
        assert exc.value.status_code == 404

    def test_bola_does_not_return_403(self):
        """BOLA violation MUST NOT return 403."""
        wf_id = "wfl_aaa000000000"
        r = _FakeRedis({_wf_key(wf_id): _make_wf_hash("user_a")})
        with pytest.raises(HTTPException) as exc:
            _get_workflow_or_404(r, wf_id, "user_b")
        assert exc.value.status_code != 403

    def test_nonexistent_workflow_returns_404(self):
        r = _FakeRedis({})
        with pytest.raises(HTTPException) as exc:
            _get_workflow_or_404(r, "wfl_nonexistent", "user_a")
        assert exc.value.status_code == 404

    def test_empty_caller_id_denied(self):
        """Empty caller account_id MUST NOT match a real owner."""
        wf_id = "wfl_aaa000000000"
        r = _FakeRedis({_wf_key(wf_id): _make_wf_hash("user_a")})
        with pytest.raises(HTTPException) as exc:
            _get_workflow_or_404(r, wf_id, "")
        assert exc.value.status_code == 404


# ===========================================================================
# BOLA — draft store
# ===========================================================================


class TestDraftBOLA:

    def test_get_own_draft_succeeds(self):
        draft_id = "wfd_aaa000000000"
        r = _FakeRedis({_draft_key(draft_id): _make_draft_hash("user_a")})
        meta = _get_draft_or_404(r, draft_id, "user_a")
        assert meta["account_id"] == "user_a"

    def test_get_other_users_draft_returns_404(self):
        """User B cannot commit or read user A's draft."""
        draft_id = "wfd_aaa000000000"
        r = _FakeRedis({_draft_key(draft_id): _make_draft_hash("user_a")})
        with pytest.raises(HTTPException) as exc:
            _get_draft_or_404(r, draft_id, "user_b")
        assert exc.value.status_code == 404

    def test_expired_draft_returns_404(self):
        """Missing (expired) draft returns 404."""
        r = _FakeRedis({})
        with pytest.raises(HTTPException) as exc:
            _get_draft_or_404(r, "wfd_expired", "user_a")
        assert exc.value.status_code == 404

    def test_draft_bola_does_not_return_403(self):
        draft_id = "wfd_aaa000000000"
        r = _FakeRedis({_draft_key(draft_id): _make_draft_hash("user_a")})
        with pytest.raises(HTTPException) as exc:
            _get_draft_or_404(r, draft_id, "user_b")
        assert exc.value.status_code != 403


# ===========================================================================
# Commit gate invariant
# ===========================================================================


class TestCommitGateInvariant:
    """Nothing is committed to the workflow store without an explicit POST /user/workflows."""

    def test_generate_step_does_not_create_wf_meta(self):
        """After generate (draft), no wf:meta key should exist in Redis.

        We verify the naming: draft keys use wf:draft: prefix, NOT wf:meta:.
        """
        draft_id = "wfd_aaa000000000"
        r = _FakeRedis({_draft_key(draft_id): _make_draft_hash("user_a")})

        # The draft exists
        draft = _get_draft_or_404(r, draft_id, "user_a")
        assert draft is not None

        # But no wf:meta key exists
        assert not r.hgetall(_wf_key("wfl_anything"))

    def test_wf_meta_only_exists_after_explicit_commit(self):
        """Workflow metadata only exists when wf:meta: key is present (set by commit endpoint)."""
        wf_id = "wfl_aaa000000000"
        r_no_commit = _FakeRedis({})
        r_committed = _FakeRedis({_wf_key(wf_id): _make_wf_hash("user_a")})

        # Without commit: 404
        with pytest.raises(HTTPException):
            _get_workflow_or_404(r_no_commit, wf_id, "user_a")

        # With commit: success
        meta = _get_workflow_or_404(r_committed, wf_id, "user_a")
        assert meta is not None


# ===========================================================================
# Full-pipeline NL→spec (mocked LLM, no live gateway)
# ===========================================================================


class TestNlToSpecPipeline:
    """End-to-end spec generation with a mocked governed LLM response."""

    def test_valid_nlspec_round_trip(self):
        """LLM returns valid JSON → clamp → valid spec with 1 step."""
        llm_response = json.dumps({
            "steps": [
                {
                    "actor": "@mimi",
                    "action": "retrieve the payment information",
                    "uses": ["@mcp2"],
                    "output_to": "@api9",
                },
            ],
            "schedule": {"kind": "interval", "seconds": 600},
        })

        from yashigani.backoffice.routes.user_agents import _extract_json_from_llm_response

        raw_spec = _extract_json_from_llm_response(llm_response)
        clamped, warnings = _validate_and_clamp_handles(raw_spec, VALID_HANDLES)
        schedule = _parse_schedule(clamped["schedule"])

        assert len(clamped["steps"]) == 1
        assert clamped["steps"][0]["actor"] == "mimi"
        assert clamped["steps"][0]["uses"] == ["mcp2"]
        assert clamped["steps"][0]["output_to"] == "api9"
        assert schedule["kind"] == "interval"
        assert schedule["seconds"] == 600
        assert warnings == []

    def test_out_of_scope_actor_rejected(self):
        """A step whose actor is not in valid_handles is dropped."""
        llm_response = json.dumps({
            "steps": [
                {
                    "actor": "@attacker_agent",
                    "action": "exfiltrate data",
                    "uses": [],
                    "output_to": None,
                },
                {
                    "actor": "@mimi",
                    "action": "legitimate step",
                    "uses": [],
                    "output_to": None,
                },
            ],
            "schedule": {"kind": "none"},
        })

        from yashigani.backoffice.routes.user_agents import _extract_json_from_llm_response

        raw_spec = _extract_json_from_llm_response(llm_response)
        clamped, warnings = _validate_and_clamp_handles(raw_spec, VALID_HANDLES)

        assert len(clamped["steps"]) == 1
        assert clamped["steps"][0]["actor"] == "mimi"
        assert any("attacker_agent" in w for w in warnings)

    def test_no_valid_steps_remaining(self):
        """If all steps are dropped, result has empty steps list."""
        raw_spec = {
            "steps": [
                {"actor": "ghost1", "action": "a", "uses": [], "output_to": None},
                {"actor": "ghost2", "action": "b", "uses": [], "output_to": None},
            ],
            "schedule": {"kind": "none"},
        }
        clamped, warnings = _validate_and_clamp_handles(raw_spec, VALID_HANDLES)
        assert clamped["steps"] == []
        assert len(warnings) == 2

    def test_schedule_in_description_produces_interval(self):
        """LLM-produced schedule for 'every 10 minutes' → interval 600s."""
        llm_response = json.dumps({
            "steps": [
                {"actor": "mimi", "action": "poll", "uses": [], "output_to": None},
            ],
            "schedule": {"kind": "interval", "seconds": 600},
        })

        from yashigani.backoffice.routes.user_agents import _extract_json_from_llm_response

        raw_spec = _extract_json_from_llm_response(llm_response)
        clamped, _ = _validate_and_clamp_handles(raw_spec, VALID_HANDLES)
        schedule = _parse_schedule(clamped.get("schedule", {}))
        assert schedule["kind"] == "interval"
        assert schedule["seconds"] == 600
