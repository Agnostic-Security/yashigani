"""
Regression tests — BOLA enforcement on /user/agents and /user/memories.

Verifies that user A cannot read, modify, or delete user B's agents or
memory blocks (OWASP API3 / RISK-097).

All tests are unit-level: they exercise the route helper functions
directly, without needing a live FastAPI app or Redis instance.

Pattern:
  - ua:meta:{ua_id}.account_id = "user_a"
  - caller's session.account_id = "user_b"
  - every helper MUST raise HTTP 404 (not 403, to avoid disclosing existence)

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import json

import pytest

from yashigani.backoffice.routes.user_agents import (
    _get_agent_or_404,
    _get_block_or_404,
    _meta_key,
    _mem_meta_key,
)
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Minimal fake-Redis stub
# ---------------------------------------------------------------------------

class _FakeRedis:
    """Minimal synchronous Redis stub for BOLA unit tests."""

    def __init__(self, data: dict):
        self._data = data  # key -> bytes dict

    def hgetall(self, key: str) -> dict:
        return self._data.get(key, {})


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_agent_hash(account_id: str) -> dict:
    """Build a minimal ua:meta bytes dict owned by account_id."""
    return {
        b"account_id": account_id.encode(),
        b"name": b"test-agent",
        b"effective_skills": json.dumps([]).encode(),
        b"declared_skills": json.dumps([]).encode(),
        b"personality": json.dumps({}).encode(),
        b"letta_agent_id": b"",
        b"created_at": b"2026-06-27T00:00:00+00:00",
        b"updated_at": b"2026-06-27T00:00:00+00:00",
        b"description": b"",
    }


def _make_block_hash(account_id: str) -> dict:
    """Build a minimal ua:mem:meta bytes dict owned by account_id."""
    return {
        b"account_id": account_id.encode(),
        b"label": b"test-block",
        b"value": b"some memory value",
        b"letta_block_id": b"",
        b"created_at": b"2026-06-27T00:00:00+00:00",
        b"updated_at": b"2026-06-27T00:00:00+00:00",
    }


# ===========================================================================
# Agent BOLA tests
# ===========================================================================


class TestAgentBOLA:
    """BOLA invariant: user B cannot touch user A's agents."""

    def test_get_own_agent_succeeds(self):
        ua_id = "uag_aaa000000000"
        r = _FakeRedis({_meta_key(ua_id): _make_agent_hash("user_a")})
        meta = _get_agent_or_404(r, ua_id, "user_a")
        assert meta["account_id"] == "user_a"

    def test_get_other_users_agent_returns_404(self):
        """User B requesting user A's agent MUST get 404, not 403."""
        ua_id = "uag_aaa000000000"
        r = _FakeRedis({_meta_key(ua_id): _make_agent_hash("user_a")})
        with pytest.raises(HTTPException) as exc_info:
            _get_agent_or_404(r, ua_id, "user_b")
        assert exc_info.value.status_code == 404

    def test_get_nonexistent_agent_returns_404(self):
        """Non-existent agent MUST return 404."""
        r = _FakeRedis({})
        with pytest.raises(HTTPException) as exc_info:
            _get_agent_or_404(r, "uag_nonexistent", "user_a")
        assert exc_info.value.status_code == 404

    def test_bola_does_not_return_403(self):
        """BOLA violation MUST NOT return 403 (would disclose resource existence)."""
        ua_id = "uag_aaa000000000"
        r = _FakeRedis({_meta_key(ua_id): _make_agent_hash("user_a")})
        with pytest.raises(HTTPException) as exc_info:
            _get_agent_or_404(r, ua_id, "user_b")
        assert exc_info.value.status_code != 403

    def test_empty_account_id_returns_404(self):
        """Empty caller account_id MUST NOT match a real owner."""
        ua_id = "uag_aaa000000000"
        r = _FakeRedis({_meta_key(ua_id): _make_agent_hash("user_a")})
        with pytest.raises(HTTPException) as exc_info:
            _get_agent_or_404(r, ua_id, "")
        assert exc_info.value.status_code == 404

    def test_prefix_bypass_attempt_returns_404(self):
        """A caller with account_id that is a prefix of the owner's MUST be denied."""
        ua_id = "uag_aaa000000000"
        r = _FakeRedis({_meta_key(ua_id): _make_agent_hash("user_alice")})
        with pytest.raises(HTTPException) as exc_info:
            _get_agent_or_404(r, ua_id, "user_ali")
        assert exc_info.value.status_code == 404

    def test_id_traversal_attempt_returns_404(self):
        """A path-traversal-style ua_id with no matching hash returns 404."""
        r = _FakeRedis({})
        with pytest.raises(HTTPException):
            _get_agent_or_404(r, "../admin", "user_a")


# ===========================================================================
# Memory block BOLA tests
# ===========================================================================


class TestMemoryBOLA:
    """BOLA invariant: user B cannot touch user A's memory blocks."""

    def test_get_own_block_succeeds(self):
        bid = "umb_bbb000000000"
        r = _FakeRedis({_mem_meta_key(bid): _make_block_hash("user_a")})
        meta = _get_block_or_404(r, bid, "user_a")
        assert meta["account_id"] == "user_a"

    def test_get_other_users_block_returns_404(self):
        bid = "umb_bbb000000000"
        r = _FakeRedis({_mem_meta_key(bid): _make_block_hash("user_a")})
        with pytest.raises(HTTPException) as exc_info:
            _get_block_or_404(r, bid, "user_b")
        assert exc_info.value.status_code == 404

    def test_get_nonexistent_block_returns_404(self):
        r = _FakeRedis({})
        with pytest.raises(HTTPException) as exc_info:
            _get_block_or_404(r, "umb_nonexistent", "user_a")
        assert exc_info.value.status_code == 404

    def test_bola_block_does_not_return_403(self):
        bid = "umb_bbb000000000"
        r = _FakeRedis({_mem_meta_key(bid): _make_block_hash("user_a")})
        with pytest.raises(HTTPException) as exc_info:
            _get_block_or_404(r, bid, "user_b")
        assert exc_info.value.status_code != 403

    def test_empty_account_id_denied_for_block(self):
        bid = "umb_bbb000000000"
        r = _FakeRedis({_mem_meta_key(bid): _make_block_hash("user_a")})
        with pytest.raises(HTTPException) as exc_info:
            _get_block_or_404(r, bid, "")
        assert exc_info.value.status_code == 404
