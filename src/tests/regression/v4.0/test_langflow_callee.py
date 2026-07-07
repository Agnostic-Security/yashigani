"""
Regression tests — Langflow optional-callee import integration (Phase 5 §C).

Verifies at config/structural level (no live deploy required):

1.  AgentRegistry._decode_agent() surfaces kind/sensitivity_ceiling/allowed_tools
    for a langflow hash, and applies backward-compat defaults for pre-4.0 entries.

2.  AgentRegistry.restore_from_durable() writes the correct Phase 5 caps
    (kind, sensitivity_ceiling, allowed_tools) into the Redis mapping.

3.  Gateway-only upstream proof: langflow's OPENAI_API_BASE in docker-compose.yml
    points at gateway:8081/v1 and NOT at any direct Ollama/LLM endpoint.

4.  Network isolation proof: the langflow service in docker-compose.yml joins ONLY
    langflow_isolated — NOT internet_egress, NOT data, NOT caddy_internal — so
    every model call re-enters the gateway (UA-10 / YSG-RISK-055 invariant).

5.  Phase 5 caps in install.sh: the case for langflow sets _name="agent__langflow",
    allowed_paths contains "/v1/chat/completions", sensitivity_ceiling="INTERNAL".

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import json
import os
import re
from typing import Any
from unittest.mock import MagicMock, call

import pytest

# ---------------------------------------------------------------------------
# Paths (resolved relative to the repo root, two levels above src/)
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
)
_COMPOSE_FILE = os.path.join(_REPO_ROOT, "docker", "docker-compose.yml")
_INSTALL_SH = os.path.join(_REPO_ROOT, "install.sh")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_compose() -> str:
    with open(_COMPOSE_FILE, "r", encoding="utf-8") as fh:
        return fh.read()


def _read_install_sh() -> str:
    with open(_INSTALL_SH, "r", encoding="utf-8") as fh:
        return fh.read()


def _b(s: str) -> bytes:
    return s.encode("utf-8")


def _make_langflow_redis_hash() -> dict:
    """Minimal Redis bytes-hash for an agent__langflow registry entry (Phase 5)."""
    return {
        b"name":                   b"agent__langflow",
        b"upstream_url":           b"http://langflow:7860",
        b"protocol":               b"openai",
        b"status":                 b"active",
        b"created_at":             b"2026-06-27T00:00:00+00:00",
        b"last_seen_at":           b"",
        b"groups":                 b'["langflow_callee"]',
        b"allowed_caller_groups":  b'["admin","user"]',
        b"allowed_paths":          b'["/v1/chat/completions"]',
        b"allowed_cidrs":          b"[]",
        b"kind":                   b"agent",
        b"sensitivity_ceiling":    b"INTERNAL",
        b"allowed_tools":          b"[]",
        b"token_last_rotated":     b"",
        b"token_rotation_schedule": b"",
    }


def _make_pre40_redis_hash() -> dict:
    """Pre-4.0 Redis hash: no kind/sensitivity_ceiling/allowed_tools keys."""
    return {
        b"name":                   b"langflow",  # old name, pre-4.0
        b"upstream_url":           b"http://langflow:7860",
        b"protocol":               b"langflow",
        b"status":                 b"active",
        b"created_at":             b"2025-01-01T00:00:00+00:00",
        b"last_seen_at":           b"",
        b"groups":                 b"[]",
        b"allowed_caller_groups":  b"[]",
        b"allowed_paths":          b"[]",
        b"allowed_cidrs":          b"[]",
        b"token_last_rotated":     b"",
        b"token_rotation_schedule": b"",
    }


# ---------------------------------------------------------------------------
# Pipeline stub for restore_from_durable
# ---------------------------------------------------------------------------

class _PipelineStub:
    """Minimal stub capturing calls made by restore_from_durable()."""

    def __init__(self):
        self.calls: list[tuple] = []

    def hset(self, key, mapping=None, **kwargs):
        self.calls.append(("hset", key, mapping))
        return self

    def set(self, key, value, **kwargs):
        self.calls.append(("set", key, value))
        return self

    def sadd(self, key, *values):
        self.calls.append(("sadd", key, *values))
        return self

    def srem(self, key, *values):
        self.calls.append(("srem", key, *values))
        return self

    def execute(self):
        return None


class _FakeRedis:
    """Minimal Redis stub wiring pipeline to _PipelineStub.

    AgentRegistry.__init__ calls scard() to read the current agent count.
    We stub it to return 0 so the constructor completes without a real Redis.
    """

    def __init__(self):
        self.pipe = _PipelineStub()

    def scard(self, key: str) -> int:  # called in AgentRegistry.__init__
        return 0

    def pipeline(self):
        return self.pipe


# ===========================================================================
# 1. _decode_agent — Phase 5 fields
# ===========================================================================


class TestDecodeAgentPhase5Fields:
    """AgentRegistry._decode_agent returns kind/sensitivity_ceiling/allowed_tools."""

    def _decode(self, raw: dict) -> dict:
        from yashigani.agents.registry import AgentRegistry
        return AgentRegistry._decode_agent("agnt_test000", raw)

    def test_decode_kind_is_agent(self):
        result = self._decode(_make_langflow_redis_hash())
        assert result["kind"] == "agent"

    def test_decode_sensitivity_ceiling_is_internal(self):
        result = self._decode(_make_langflow_redis_hash())
        assert result["sensitivity_ceiling"] == "INTERNAL"

    def test_decode_allowed_tools_is_empty_list(self):
        result = self._decode(_make_langflow_redis_hash())
        assert result["allowed_tools"] == []

    def test_decode_groups_contain_langflow_callee(self):
        result = self._decode(_make_langflow_redis_hash())
        assert "langflow_callee" in result["groups"]

    def test_decode_allowed_caller_groups(self):
        result = self._decode(_make_langflow_redis_hash())
        assert set(result["allowed_caller_groups"]) == {"admin", "user"}

    def test_decode_allowed_paths_constrained(self):
        result = self._decode(_make_langflow_redis_hash())
        assert result["allowed_paths"] == ["/v1/chat/completions"]

    def test_decode_upstream_url_points_at_langflow(self):
        result = self._decode(_make_langflow_redis_hash())
        assert result["upstream_url"] == "http://langflow:7860"

    def test_decode_name_is_agent_double_underscore_langflow(self):
        result = self._decode(_make_langflow_redis_hash())
        assert result["name"] == "agent__langflow"


# ===========================================================================
# 2. _decode_agent — backward compat for pre-4.0 entries
# ===========================================================================


class TestDecodeAgentBackwardCompat:
    """Pre-4.0 hash (no kind/sensitivity_ceiling/allowed_tools) → safe defaults."""

    def _decode(self, raw: dict) -> dict:
        from yashigani.agents.registry import AgentRegistry
        return AgentRegistry._decode_agent("agnt_old00000", raw)

    def test_missing_kind_defaults_to_agent(self):
        result = self._decode(_make_pre40_redis_hash())
        assert result["kind"] == "agent"

    def test_missing_sensitivity_ceiling_defaults_to_none(self):
        result = self._decode(_make_pre40_redis_hash())
        assert result["sensitivity_ceiling"] is None

    def test_missing_allowed_tools_defaults_to_empty_list(self):
        result = self._decode(_make_pre40_redis_hash())
        assert result["allowed_tools"] == []

    def test_empty_sensitivity_ceiling_bytes_returns_none(self):
        """Empty-string sensitivity_ceiling stored in Redis → None surfaced."""
        raw = {**_make_pre40_redis_hash(), b"sensitivity_ceiling": b""}
        result = self._decode(raw)
        assert result["sensitivity_ceiling"] is None


# ===========================================================================
# 3. restore_from_durable — Phase 5 mapping written into Redis
# ===========================================================================


class TestRestoreFromDurablePhase5:
    """restore_from_durable() writes kind/sensitivity_ceiling/allowed_tools."""

    def _run(self, agent_dict: dict, token_hash: str = "bcrypt-hash-placeholder"):
        from yashigani.agents.registry import AgentRegistry
        r = _FakeRedis()
        registry = AgentRegistry(r)
        registry.restore_from_durable(agent_dict, token_hash)
        return r.pipe

    def _langflow_agent_dict(self) -> dict:
        return {
            "agent_id": "agnt_lf00000001",
            "name": "agent__langflow",
            "upstream_url": "http://langflow:7860",
            "protocol": "openai",
            "status": "active",
            "created_at": "2026-06-27T00:00:00+00:00",
            "groups": ["langflow_callee"],
            "allowed_caller_groups": ["admin", "user"],
            "allowed_paths": ["/v1/chat/completions"],
            "allowed_cidrs": [],
            "kind": "agent",
            "sensitivity_ceiling": "INTERNAL",
            "allowed_tools": [],
        }

    def _get_hset_mapping(self, pipe: _PipelineStub) -> dict:
        for op, *args in pipe.calls:
            if op == "hset":
                return args[1]  # mapping kwarg
        return {}

    def test_hset_called(self):
        pipe = self._run(self._langflow_agent_dict())
        ops = [c[0] for c in pipe.calls]
        assert "hset" in ops

    def test_kind_written_to_mapping(self):
        pipe = self._run(self._langflow_agent_dict())
        mapping = self._get_hset_mapping(pipe)
        assert mapping.get(b"kind") == b"agent"

    def test_sensitivity_ceiling_written_to_mapping(self):
        pipe = self._run(self._langflow_agent_dict())
        mapping = self._get_hset_mapping(pipe)
        assert mapping.get(b"sensitivity_ceiling") == b"INTERNAL"

    def test_allowed_tools_written_to_mapping(self):
        pipe = self._run(self._langflow_agent_dict())
        mapping = self._get_hset_mapping(pipe)
        assert mapping.get(b"allowed_tools") == b"[]"

    def test_groups_written_to_mapping(self):
        pipe = self._run(self._langflow_agent_dict())
        mapping = self._get_hset_mapping(pipe)
        assert json.loads(mapping[b"groups"]) == ["langflow_callee"]

    def test_allowed_paths_written_to_mapping(self):
        pipe = self._run(self._langflow_agent_dict())
        mapping = self._get_hset_mapping(pipe)
        assert json.loads(mapping[b"allowed_paths"]) == ["/v1/chat/completions"]

    def test_pre40_agent_dict_kind_defaults_to_agent(self):
        """Missing kind in durable row → written as b'agent' (not b'')."""
        agent = {
            "agent_id": "agnt_pre4000001",
            "name": "langflow",
            "upstream_url": "http://langflow:7860",
            "protocol": "langflow",
            "status": "active",
            "created_at": "2025-01-01T00:00:00+00:00",
            "groups": [],
            "allowed_caller_groups": [],
            "allowed_paths": [],
            "allowed_cidrs": [],
        }
        pipe = self._run(agent)
        mapping = self._get_hset_mapping(pipe)
        assert mapping.get(b"kind") == b"agent"

    def test_pre40_agent_dict_ceiling_defaults_to_empty_bytes(self):
        """Missing sensitivity_ceiling in durable row → written as b''."""
        agent = {
            "agent_id": "agnt_pre4000001",
            "name": "langflow",
            "upstream_url": "http://langflow:7860",
            "protocol": "langflow",
            "status": "active",
            "created_at": "2025-01-01T00:00:00+00:00",
            "groups": [],
            "allowed_caller_groups": [],
            "allowed_paths": [],
            "allowed_cidrs": [],
        }
        pipe = self._run(agent)
        mapping = self._get_hset_mapping(pipe)
        assert mapping.get(b"sensitivity_ceiling") == b""


# ===========================================================================
# 4. Gateway-only upstream proof (compose config, no live deploy)
# ===========================================================================


class TestGatewayOnlyUpstreamProof:
    """OPENAI_API_BASE for langflow must point at gateway:8081/v1 only."""

    def test_langflow_openai_api_base_is_gateway(self):
        """Compose OPENAI_API_BASE for langflow must be http://gateway:8081/v1."""
        compose = _read_compose()
        # Extract langflow service section: from "  langflow:" to the next top-level service
        # Look for OPENAI_API_BASE: http://gateway:8081/v1 within the langflow block
        match = re.search(
            r"langflow:.*?OPENAI_API_BASE:\s*(http://\S+)",
            compose,
            re.DOTALL,
        )
        assert match is not None, "OPENAI_API_BASE not found in langflow service"
        base_url = match.group(1).strip()
        # v4.1 three-agent wrap (2026-07-07): the base URL dials langflow's
        # egress FORWARDER; the gateway hop moved behind /egress/eval →
        # /deliver/llm → gateway:8081 (governance in front, same surface).
        assert base_url == "http://egress-langflow:9400/llm/v1", (
            f"langflow OPENAI_API_BASE must dial its egress forwarder; got: {base_url}"
        )

    def test_langflow_openai_api_base_not_direct_ollama(self):
        """langflow OPENAI_API_BASE must NOT point directly at ollama:11434."""
        compose = _read_compose()
        match = re.search(
            r"langflow:.*?OPENAI_API_BASE:\s*(http://\S+)",
            compose,
            re.DOTALL,
        )
        assert match is not None, "OPENAI_API_BASE not found in langflow service"
        base_url = match.group(1).strip()
        assert "ollama" not in base_url, (
            f"langflow must NOT reach ollama directly; got: {base_url}"
        )

    def test_langflow_entrypoint_reads_per_agent_token(self):
        """Entrypoint shim must use langflow_yashigani_token (per-agent P1 token)."""
        compose = _read_compose()
        # Check that the per-agent token shim pattern is present anywhere in compose
        # (it belongs to the langflow service — verified by the token name itself).
        assert "OPENAI_API_KEY=$(cat /run/secrets/langflow_yashigani_token)" in compose, (
            "langflow entrypoint must read langflow_yashigani_token via cat shim"
        )


# ===========================================================================
# 5. Network isolation proof (langflow_isolated only, no internet_egress)
# ===========================================================================


def _extract_service_block(service_name: str) -> str:
    """Extract the body of a named top-level compose service (line-by-line).

    docker-compose.yml service blocks look like:
        ``  service-name:\n``  (2-space indent, no leading spaces on the name)
    followed by lines at 4+ spaces indentation until the next 2-space service.

    The extraction terminates when a line starts with exactly two spaces and is
    not a comment — i.e. the next top-level service or section header.
    """
    compose = _read_compose()
    lines = compose.split("\n")
    service_header = f"  {service_name}:"
    in_block = False
    block_lines: list[str] = []
    for line in lines:
        if line == service_header or line.startswith(service_header + " "):
            in_block = True
            continue
        if in_block:
            # A non-comment line at exactly 2-space indent ends the block
            if (
                len(line) >= 3
                and line[0] == " "
                and line[1] == " "
                and line[2] != " "
                and line[2] != "#"
            ):
                break
            block_lines.append(line)
    return "\n".join(block_lines)


class TestNetworkIsolationProof:
    """langflow must be on langflow_isolated only — no internet_egress."""

    def _langflow_block(self) -> str:
        return _extract_service_block("langflow")

    def test_langflow_joins_split_ringfences_only(self):
        # v4.1 three-agent wrap (2026-07-07): langflow moved OFF
        # langflow_isolated onto the §2.6 split ringfences. Parse the real
        # networks list (string-matching the block would pass on comments).
        import yaml as _yaml

        compose = _yaml.safe_load(_read_compose())
        nets = set(compose["services"]["langflow"].get("networks") or [])
        assert nets == {"ringfence_langflow_in", "ringfence_langflow_eg"}, (
            f"langflow must join exactly its split ringfences; got {sorted(nets)}"
        )

    def test_langflow_does_not_join_internet_egress(self):
        block = self._langflow_block()
        assert "internet_egress" not in block, (
            "langflow must NOT join internet_egress network (UA-10 / YSG-RISK-055)"
        )

    def test_langflow_does_not_join_data_network(self):
        block = self._langflow_block()
        # The `data` network is for gateway/backoffice → direct DB/cache access.
        # langflow must NOT be on `data` (would allow direct postgres/redis reach).
        # A data-network membership would appear as "      - data" in the networks: list.
        assert "- data\n" not in block and "- data\r\n" not in block, (
            "langflow must NOT join `data` network"
        )

    def test_langflow_yashigani_token_secret_declared(self):
        """Top-level secrets block must declare langflow_yashigani_token."""
        compose = _read_compose()
        assert "langflow_yashigani_token:" in compose, (
            "compose secrets block must declare langflow_yashigani_token"
        )

    def test_langflow_service_mounts_per_agent_token(self):
        """langflow service secrets section must reference langflow_yashigani_token."""
        block = self._langflow_block()
        assert "langflow_yashigani_token" in block, (
            "langflow service must mount langflow_yashigani_token secret"
        )


# ===========================================================================
# 6. install.sh Phase 5 caps proof (grep-level, no bash execution)
# ===========================================================================


class TestInstallShPhase5Caps:
    """install.sh must register langflow as agent__langflow with Phase 5 caps."""

    def test_agent_double_underscore_langflow_name(self):
        sh = _read_install_sh()
        assert '"agent__langflow"' in sh or "_name=\"agent__langflow\"" in sh, (
            "install.sh must register langflow as agent__langflow (double-underscore)"
        )

    def test_allowed_paths_chat_completions(self):
        sh = _read_install_sh()
        assert '"/v1/chat/completions"' in sh, (
            "install.sh must include /v1/chat/completions in langflow allowed_paths"
        )

    def test_sensitivity_ceiling_internal(self):
        sh = _read_install_sh()
        assert '"INTERNAL"' in sh, (
            "install.sh must set sensitivity_ceiling=INTERNAL for langflow"
        )

    def test_groups_langflow_callee(self):
        sh = _read_install_sh()
        assert '"langflow_callee"' in sh, (
            "install.sh must put langflow in groups=[langflow_callee]"
        )

    def test_allowed_caller_groups_admin_user(self):
        sh = _read_install_sh()
        assert '"admin"' in sh and '"user"' in sh, (
            "install.sh must include admin and user in allowed_caller_groups"
        )

    def test_langflow_yashigani_token_generated(self):
        sh = _read_install_sh()
        assert "langflow_yashigani_token" in sh, (
            "install.sh must generate langflow_yashigani_token secret"
        )

    def test_langflow_proto_openai_in_case(self):
        """Protocol for langflow case must be openai (OpenAI-compat endpoint)."""
        sh = _read_install_sh()
        # Find the langflow case block — expect _proto="openai"
        match = re.search(
            r'langflow\)[^\n]*_name="agent__langflow"[^\n]*_proto="(\w+)"',
            sh,
        )
        if match is None:
            # Try multiline case: proto on same line as name
            match = re.search(
                r'_name="agent__langflow".*?_proto="(\w+)"',
                sh,
                re.DOTALL,
            )
        assert match is not None, "Cannot find langflow case _proto in install.sh"
        assert match.group(1) == "openai", (
            f"langflow _proto must be 'openai', got: {match.group(1)}"
        )
