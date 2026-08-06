"""
Regression test -- v4.1.2 FIND-IRIS-DUP-AGENT (CRITICAL, batch-fix 2026-08-04).

install.sh --upgrade duplicate-registered bundled agents (langflow/letta)
instead of being idempotent: a fresh install showed exactly 2 /admin/agents
rows; after --upgrade, 4 existed (2 originals + 2 duplicates with fresh
agent_ids and fresh, unrevoked tokens). Live-reproduced via sha256 diff of
docker/secrets/{langflow,letta}_token before/after upgrade.

Root cause: install.sh's inline agent-bootstrap Python (compose exec
backoffice python3 -c '...') constructs its AgentRegistry with a redis-py
client built ``decode_responses=True``:

    _rc = _redis.from_url(_redis_url, decode_responses=True)
    registry = AgentRegistry(_rc)
    existing_names = {a.get("name", "") for a in registry.list_all()}
    if aname in existing_names:
        ...skip...

AgentRegistry._decode_agent() looked up HGETALL's returned dict using
bytes-literal keys only (``raw.get(b"name", b"")``). With
decode_responses=True, HGETALL returns a dict with STR keys ("name", not
b"name"), so every ``raw.get(b"name", b"")`` lookup missed and silently
fell back to the b"" default -> every agent decoded with name="" ->
existing_names was always {""} -> the idempotency check never matched a
real agent name -> every --upgrade re-registered from scratch.

Fix (src/yashigani/agents/registry.py, AgentRegistry._decode_agent):
normalise the raw hash's keys to str before lookup, so decoding is correct
regardless of the caller's redis-py decode_responses setting.

This test constructs a real AgentRegistry (fakeredis-backed) using
decode_responses=True -- the exact client construction install.sh's inline
script uses -- and proves the idempotency check that install.sh performs
(existing_names membership by real agent name) works correctly. Fails on
the pre-fix _decode_agent() (name decodes to "" instead of the real name);
passes post-fix.
"""
from __future__ import annotations

import fakeredis

from yashigani.agents.registry import AgentRegistry


class TestFindIrisDupAgentDecodeResponsesTolerance:
    def _make_registry(self, decode_responses: bool) -> AgentRegistry:
        r = fakeredis.FakeRedis(decode_responses=decode_responses)
        return AgentRegistry(r)

    def test_list_all_decodes_real_name_with_decode_responses_true(self):
        """The exact install.sh call shape: register once with a "normal"
        (decode_responses=False) client, then re-open the SAME underlying
        Redis data with a decode_responses=True client (as install.sh's
        inline bootstrap script does) and confirm list_all() surfaces the
        real agent name, not an empty string."""
        server = fakeredis.FakeServer()
        r = fakeredis.FakeRedis(server=server, decode_responses=False)
        registry_write = AgentRegistry(r)
        registry_write.register(
            name="agent__langflow",
            upstream_url="https://caddy:9705/agents/default/langflow",
            groups=["langflow_callee"],
            allowed_caller_groups=["admin", "user"],
            allowed_paths=["/v1/chat/completions"],
            protocol="langflow",
        )

        # Re-open with decode_responses=True — the exact client shape
        # install.sh's inline registration script constructs.
        r_decoded = fakeredis.FakeRedis(server=server, decode_responses=True)
        registry_read = AgentRegistry(r_decoded)

        existing_names = {a.get("name", "") for a in registry_read.list_all()}
        assert "agent__langflow" in existing_names, (
            "FIND-IRIS-DUP-AGENT: list_all() must decode the real agent name "
            "even when the caller's redis client uses decode_responses=True — "
            "pre-fix this set was always {''}, so install.sh's idempotency "
            "check (`if aname in existing_names`) never matched and every "
            "--upgrade re-registered a duplicate agent with a fresh token."
        )
        assert existing_names != {""}

    def test_idempotency_check_shape_matches_install_sh(self):
        """Reproduces install.sh's exact idempotency guard end-to-end: a
        second 'registration attempt' for an already-registered agent name
        must be recognised as a skip, not silently missed."""
        server = fakeredis.FakeServer()
        r = fakeredis.FakeRedis(server=server, decode_responses=False)
        registry_write = AgentRegistry(r)
        registry_write.register(
            name="letta",
            upstream_url="https://caddy:9775/agents/default/letta",
            groups=[], allowed_caller_groups=[], allowed_paths=[],
            protocol="letta",
        )

        r_decoded = fakeredis.FakeRedis(server=server, decode_responses=True)
        registry_read = AgentRegistry(r_decoded)

        # install.sh's exact guard, reproduced verbatim:
        aname = "letta"
        existing_names = {a.get("name", "") for a in registry_read.list_all()}
        would_skip = aname in existing_names
        assert would_skip, (
            "FIND-IRIS-DUP-AGENT: re-running the bootstrap for an already-"
            "registered agent name must be recognised as SKIP, not OK — "
            "otherwise every --upgrade mints a duplicate active agent row "
            "with a fresh, unrevoked token."
        )

    def test_decode_agent_tolerates_bytes_and_str_keys_directly(self):
        """Unit-level proof on _decode_agent itself, independent of fakeredis
        plumbing: both a bytes-keyed hash (decode_responses=False shape) and
        a str-keyed hash (decode_responses=True shape) must decode identically."""
        bytes_keyed = {
            b"name": b"agent__langflow",
            b"upstream_url": b"https://caddy:9705/agents/default/langflow",
            b"protocol": b"langflow",
            b"status": b"active",
            b"kind": b"agent",
            b"created_at": b"2026-08-04T00:00:00+00:00",
            b"last_seen_at": b"",
            b"groups": b"[]",
            b"allowed_caller_groups": b"[]",
            b"allowed_paths": b"[]",
            b"allowed_cidrs": b"[]",
            b"sensitivity_ceiling": b"",
            b"allowed_tools": b"[]",
        }
        str_keyed = {k.decode(): v.decode() for k, v in bytes_keyed.items()}

        decoded_bytes = AgentRegistry._decode_agent("agnt_test", bytes_keyed)
        decoded_str = AgentRegistry._decode_agent("agnt_test", str_keyed)

        assert decoded_bytes["name"] == "agent__langflow"
        assert decoded_str["name"] == "agent__langflow", (
            "FIND-IRIS-DUP-AGENT: _decode_agent must decode a str-keyed hash "
            "(decode_responses=True shape) identically to a bytes-keyed hash"
        )
        assert decoded_bytes == decoded_str
