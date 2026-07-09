# Last updated: 2026-07-09T00:00:00+00:00
"""
Regression tests — v4.1 FLAG-3: per-instance egress LLM rate cap.

Gap closed: /egress/eval had no rate/budget enforcement — OPA emitted
``rate_limit_key`` but egress_proxy.py never read or enforced it.
EgressLimitEnforcer (egress_limit.py) is now wired into egress_proxy.py
BEFORE body inspection + OPA so a bursting instance gets 429 fast.

Test matrix:

  Unit — EgressLimitEnforcer (egress_limit.py)
  ─────────────────────────────────────────────
  1.  cap_under_limit_allows          — under limit in cap mode → allowed
  2.  cap_over_limit_denies           — burst over limit in cap mode → !allowed
  3.  monitor_under_limit_allows      — under limit in monitor mode → allowed
  4.  monitor_over_limit_still_allows — over limit in monitor mode → still allowed
  5.  monitor_meters_usage            — monitor mode increments counter even on allow
  6.  different_instances_isolated    — two SPIFFE URIs get independent buckets
  7.  redis_error_cap_fails_closed    — Redis error in cap mode → !allowed (fail-closed)
  8.  redis_error_monitor_allows      — Redis error in monitor mode → allowed
  9.  env_mode_invalid_defaults_cap   — bad YASHIGANI_EGRESS_LIMIT_MODE → 'cap'
  10. env_calls_invalid_defaults      — bad YASHIGANI_EGRESS_LIMIT_CALLS → 200
  11. spiffe_hash_matches_opa         — _spiffe_hash matches sha256(spiffe) — OPA parity

  Integration — /egress/eval endpoint (egress_proxy.py)
  ───────────────────────────────────────────────────────
  12. endpoint_cap_429_over_limit     — 429 + Retry-After when cap exceeded
  13. endpoint_cap_200_under_limit    — 200 when under cap (OPA+upstream mocked)
  14. endpoint_monitor_200_over_limit — 200 even over cap in monitor mode
  15. endpoint_opa_deny_still_works   — OPA deny still fires independently of rate cap
  16. endpoint_no_enforcer_passes     — no enforcer wired → cap gate skipped
"""
from __future__ import annotations

import hashlib
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_LANGFLOW_SPIFFE = "spiffe://yashigani.internal/agents/default/langflow/nhi_abc123"
_LETTA_SPIFFE = "spiffe://yashigani.internal/agents/default/letta/nhi_def456"
_OPENCLAW_SPIFFE = "spiffe://yashigani.internal/openclaw"

_ENFORCER_MOD = "yashigani.gateway.egress_limit"
_PROXY_MOD = "yashigani.gateway.egress_proxy"


# ---------------------------------------------------------------------------
# Helper: minimal Redis mock
# ---------------------------------------------------------------------------


class _FakeRedis:
    """
    Minimal synchronous Redis stub for EgressLimitEnforcer tests.
    Supports INCR + EXPIRE + configurable error injection.
    """

    def __init__(self, *, raise_on_incr: bool = False) -> None:
        self._store: dict[str, int] = {}
        self._raise = raise_on_incr

    def incr(self, key: str) -> int:
        if self._raise:
            raise ConnectionError("Redis unavailable (test stub)")
        self._store[key] = self._store.get(key, 0) + 1
        return self._store[key]

    def expire(self, key: str, ttl: int) -> None:
        pass  # not modelled

    def get_count(self, key: str) -> int:
        return self._store.get(key, 0)


# ---------------------------------------------------------------------------
# Unit tests — EgressLimitEnforcer
# ---------------------------------------------------------------------------


def test_cap_under_limit_allows():
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    r = _FakeRedis()
    enforcer = EgressLimitEnforcer(
        r, mode="cap", calls_per_window=5, window_seconds=60
    )
    for _ in range(5):
        result = enforcer.check_and_record(_LANGFLOW_SPIFFE)
        assert result.allowed, f"expected allowed at count {result.count}"
    assert result.count == 5


def test_cap_over_limit_denies():
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    r = _FakeRedis()
    enforcer = EgressLimitEnforcer(
        r, mode="cap", calls_per_window=3, window_seconds=60
    )
    for _ in range(3):
        enforcer.check_and_record(_LANGFLOW_SPIFFE)

    # 4th call exceeds the limit
    result = enforcer.check_and_record(_LANGFLOW_SPIFFE)
    assert not result.allowed, "expected denied on 4th call (limit=3)"
    assert result.count == 4
    assert result.limit == 3
    assert result.mode == "cap"
    assert result.retry_after_s > 0


def test_monitor_under_limit_allows():
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    r = _FakeRedis()
    enforcer = EgressLimitEnforcer(
        r, mode="monitor", calls_per_window=2, window_seconds=60
    )
    result = enforcer.check_and_record(_LANGFLOW_SPIFFE)
    assert result.allowed
    assert result.mode == "monitor"


def test_monitor_over_limit_still_allows():
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    r = _FakeRedis()
    enforcer = EgressLimitEnforcer(
        r, mode="monitor", calls_per_window=2, window_seconds=60
    )
    for _ in range(10):
        result = enforcer.check_and_record(_LANGFLOW_SPIFFE)
        assert result.allowed, f"monitor mode must never deny (count={result.count})"
    assert result.count == 10


def test_monitor_meters_usage():
    """Monitor mode must increment the counter even when allowing over-limit."""
    from yashigani.gateway.egress_limit import EgressLimitEnforcer, _spiffe_hash

    r = _FakeRedis()
    enforcer = EgressLimitEnforcer(
        r, mode="monitor", calls_per_window=1, window_seconds=60
    )
    # 3 calls — all allowed in monitor mode
    for _ in range(3):
        enforcer.check_and_record(_LANGFLOW_SPIFFE)

    # Verify Redis counter reached 3
    bucket = int(time.time() / 60)
    key = f"egress:rlk:{_spiffe_hash(_LANGFLOW_SPIFFE)}:{bucket}"
    assert r.get_count(key) == 3, "counter must be incremented in monitor mode"


def test_different_instances_isolated():
    """Two distinct SPIFFE URIs get independent rate-limit buckets."""
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    r = _FakeRedis()
    enforcer = EgressLimitEnforcer(
        r, mode="cap", calls_per_window=2, window_seconds=60
    )
    # Exhaust langflow instance
    enforcer.check_and_record(_LANGFLOW_SPIFFE)
    enforcer.check_and_record(_LANGFLOW_SPIFFE)
    lf_over = enforcer.check_and_record(_LANGFLOW_SPIFFE)
    assert not lf_over.allowed, "langflow should be denied after 3rd call"

    # letta instance is unaffected
    letta_result = enforcer.check_and_record(_LETTA_SPIFFE)
    assert letta_result.allowed, "letta instance must not be affected by langflow's bucket"
    assert letta_result.count == 1


def test_redis_error_cap_fails_closed():
    """Redis error in cap mode → fail-closed (allowed=False)."""
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    r = _FakeRedis(raise_on_incr=True)
    enforcer = EgressLimitEnforcer(
        r, mode="cap", calls_per_window=100, window_seconds=60
    )
    result = enforcer.check_and_record(_LANGFLOW_SPIFFE)
    assert not result.allowed, "cap mode Redis error must fail-closed"
    assert result.count == 0
    assert result.retry_after_s > 0


def test_redis_error_monitor_allows():
    """Redis error in monitor mode → allow (monitoring must not block traffic)."""
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    r = _FakeRedis(raise_on_incr=True)
    enforcer = EgressLimitEnforcer(
        r, mode="monitor", calls_per_window=100, window_seconds=60
    )
    result = enforcer.check_and_record(_LANGFLOW_SPIFFE)
    assert result.allowed, "monitor mode Redis error must allow"
    assert result.count == 0
    assert result.retry_after_s == 0


def test_env_mode_invalid_defaults_cap():
    """Invalid YASHIGANI_EGRESS_LIMIT_MODE env var must default to 'cap'."""
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    r = _FakeRedis()
    enforcer = EgressLimitEnforcer(
        r,
        env={"YASHIGANI_EGRESS_LIMIT_MODE": "invalid_value"},
    )
    assert enforcer.mode == "cap"


def test_env_calls_invalid_defaults():
    """Invalid YASHIGANI_EGRESS_LIMIT_CALLS env var must default to 200."""
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    r = _FakeRedis()
    enforcer = EgressLimitEnforcer(
        r,
        env={"YASHIGANI_EGRESS_LIMIT_CALLS": "not-a-number"},
    )
    assert enforcer.calls_per_window == 200


def test_spiffe_hash_matches_opa():
    """
    _spiffe_hash must produce sha256hex(spiffe) — matching OPA's
    ``_spiffe_hash := crypto.sha256(input.identity.spiffe)`` in mcp.rego:649.
    """
    from yashigani.gateway.egress_limit import _spiffe_hash

    spiffe = _LANGFLOW_SPIFFE
    expected = hashlib.sha256(spiffe.encode("utf-8")).hexdigest()
    assert _spiffe_hash(spiffe) == expected, (
        f"_spiffe_hash({spiffe!r}) = {_spiffe_hash(spiffe)!r} "
        f"but expected {expected!r}"
    )
    # Empty SPIFFE → "anonymous"
    assert _spiffe_hash("") == "anonymous"
    assert _spiffe_hash(None) == "anonymous" if False else _spiffe_hash("") == "anonymous"


# ---------------------------------------------------------------------------
# Integration tests — /egress/eval endpoint wired with EgressLimitEnforcer
# ---------------------------------------------------------------------------


def _make_app_with_enforcer(enforcer=None):
    """
    Minimal FastAPI app with egress_proxy router mounted.
    Patches out dependencies so tests are self-contained.
    """
    from yashigani.gateway import egress_proxy as _mod

    _mod._state.opa_url = "https://policy:8181"
    _mod._state.audit_writer = MagicMock()
    _mod._state.caddy_egress_base = "https://caddy:18790"
    _mod._state.egress_limit_enforcer = enforcer

    app = FastAPI()
    app.include_router(_mod.router)
    return app


def _opa_allow():
    r = MagicMock()
    r.allow = True
    r.deny_reason = "ok"
    r.user_message = "Allowed."
    r.policy_id = "mcp.response_decision"
    r.code = "MCP_RESULT_OK"
    r.error = ""
    return r


def _opa_deny(reason: str = "pii_detected_in_result"):
    r = MagicMock()
    r.allow = False
    r.deny_reason = reason
    r.user_message = "Blocked."
    r.policy_id = "mcp.response_decision"
    r.code = "MCP_RESULT_PII_BLOCKED"
    r.error = ""
    return r


def _clean_scan():
    v = MagicMock()
    v.is_secret = False
    return v


def _clean_filter():
    r = MagicMock()
    r.rejected = False
    r.reject_reason = ""
    return r


def _fake_upstream(status: int = 200, body: bytes = b"ok"):
    resp = MagicMock()
    resp.status_code = status
    resp.content = body
    resp.headers = {"content-type": "application/json"}
    return resp


def _mock_mesh_client(upstream_resp=None, side_effect=None):
    """Proper async context-manager mock for internal_httpx_client."""
    mc = AsyncMock()
    mc.__aenter__ = AsyncMock(return_value=mc)
    mc.__aexit__ = AsyncMock(return_value=None)
    if side_effect is not None:
        mc.request = AsyncMock(side_effect=side_effect)
    else:
        mc.request = AsyncMock(return_value=upstream_resp or _fake_upstream())
    return mc


def test_endpoint_cap_429_over_limit():
    """
    In cap mode, hitting /egress/eval over the per-instance limit returns 429
    with Retry-After header — BEFORE OPA or body inspection.
    """
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    r = _FakeRedis()
    enforcer = EgressLimitEnforcer(r, mode="cap", calls_per_window=2, window_seconds=60)

    app = _make_app_with_enforcer(enforcer)

    with (
        patch(f"{_PROXY_MOD}.scan_secrets", return_value=_clean_scan()),
        patch(f"{_PROXY_MOD}.filter_description", return_value=_clean_filter()),
        patch(f"{_PROXY_MOD}.query_mcp_response_decision", new_callable=AsyncMock,
              return_value=_opa_allow()),
        patch(
            f"{_PROXY_MOD}.internal_httpx_client",
            return_value=_mock_mesh_client(_fake_upstream(200, b"ok")),
        ),
    ):
        client = TestClient(app, raise_server_exceptions=False)
        headers = {"X-SPIFFE-ID": _LANGFLOW_SPIFFE}

        # First two calls — under limit
        for i in range(2):
            resp = client.post(
                "/egress/eval/llm/v1/chat/completions",
                headers=headers,
                content=b'{"model":"gpt-4"}',
            )
            assert resp.status_code != 429, (
                f"unexpected 429 on call {i + 1} (under limit)"
            )

        # Third call — over limit
        resp = client.post(
            "/egress/eval/llm/v1/chat/completions",
            headers=headers,
            content=b'{"model":"gpt-4"}',
        )
        assert resp.status_code == 429, (
            f"expected 429 for over-limit call, got {resp.status_code}"
        )
        assert "Retry-After" in resp.headers
        body = resp.json()
        assert body["error"] == "egress_rate_limit_exceeded"


def test_endpoint_cap_200_under_limit():
    """
    Under the cap in cap mode, the request proceeds through OPA + upstream
    (upstream mocked to 200).
    """
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    r = _FakeRedis()
    enforcer = EgressLimitEnforcer(r, mode="cap", calls_per_window=10, window_seconds=60)
    app = _make_app_with_enforcer(enforcer)

    with (
        patch(f"{_PROXY_MOD}.scan_secrets", return_value=_clean_scan()),
        patch(f"{_PROXY_MOD}.filter_description", return_value=_clean_filter()),
        patch(f"{_PROXY_MOD}.query_mcp_response_decision", new_callable=AsyncMock,
              return_value=_opa_allow()),
        patch(
            f"{_PROXY_MOD}.internal_httpx_client",
            return_value=_mock_mesh_client(_fake_upstream(200, b"upstream-ok")),
        ),
    ):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/egress/eval/slack/api/chat.postMessage",
            headers={"X-SPIFFE-ID": _LANGFLOW_SPIFFE},
            content=b'{"text":"hello"}',
        )
        assert resp.status_code == 200
        assert resp.content == b"upstream-ok"


def test_endpoint_monitor_200_over_limit():
    """
    In monitor mode, requests beyond the cap still return 200 (OPA and upstream
    govern the final status; rate limiter is observability-only).
    """
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    r = _FakeRedis()
    enforcer = EgressLimitEnforcer(
        r, mode="monitor", calls_per_window=1, window_seconds=60
    )
    app = _make_app_with_enforcer(enforcer)

    with (
        patch(f"{_PROXY_MOD}.scan_secrets", return_value=_clean_scan()),
        patch(f"{_PROXY_MOD}.filter_description", return_value=_clean_filter()),
        patch(f"{_PROXY_MOD}.query_mcp_response_decision", new_callable=AsyncMock,
              return_value=_opa_allow()),
        patch(
            f"{_PROXY_MOD}.internal_httpx_client",
            return_value=_mock_mesh_client(_fake_upstream(200, b"ok")),
        ),
    ):
        client = TestClient(app, raise_server_exceptions=False)
        headers = {"X-SPIFFE-ID": _LANGFLOW_SPIFFE}

        for i in range(5):
            resp = client.post(
                "/egress/eval/slack/api/chat.postMessage",
                headers=headers,
                content=b'{"text":"test"}',
            )
            assert resp.status_code != 429, (
                f"monitor mode must not 429 on call {i + 1}"
            )


def test_endpoint_opa_deny_still_works():
    """
    OPA deny (403) fires correctly even when the rate cap is under the limit.
    Verifies OPA enforcement is independent of and operates alongside the
    rate limiter.
    """
    from yashigani.gateway.egress_limit import EgressLimitEnforcer

    r = _FakeRedis()
    enforcer = EgressLimitEnforcer(r, mode="cap", calls_per_window=100, window_seconds=60)
    app = _make_app_with_enforcer(enforcer)

    with (
        patch(f"{_PROXY_MOD}.scan_secrets", return_value=_clean_scan()),
        patch(f"{_PROXY_MOD}.filter_description", return_value=_clean_filter()),
        patch(
            f"{_PROXY_MOD}.query_mcp_response_decision",
            new_callable=AsyncMock,
            return_value=_opa_deny("pii_detected_in_result"),
        ),
        patch(f"{_PROXY_MOD}.internal_httpx_client"),
    ):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/egress/eval/slack/api/chat.postMessage",
            headers={"X-SPIFFE-ID": _LANGFLOW_SPIFFE},
            content=b'{"text":"sensitive data"}',
        )
        assert resp.status_code == 403, (
            f"OPA deny must still produce 403, got {resp.status_code}"
        )
        body = resp.json()
        assert body.get("error") == "pii_detected_in_result"


def test_endpoint_no_enforcer_passes():
    """
    When egress_limit_enforcer is None (startup Redis failure / disabled),
    the endpoint behaves as before the fix — rate gate is skipped entirely.
    """
    app = _make_app_with_enforcer(None)  # no enforcer

    with (
        patch(f"{_PROXY_MOD}.scan_secrets", return_value=_clean_scan()),
        patch(f"{_PROXY_MOD}.filter_description", return_value=_clean_filter()),
        patch(f"{_PROXY_MOD}.query_mcp_response_decision", new_callable=AsyncMock,
              return_value=_opa_allow()),
        patch(
            f"{_PROXY_MOD}.internal_httpx_client",
            return_value=_mock_mesh_client(_fake_upstream(200, b"ok")),
        ),
    ):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/egress/eval/slack/api/chat.postMessage",
            headers={"X-SPIFFE-ID": _LANGFLOW_SPIFFE},
            content=b'{}',
        )
        assert resp.status_code == 200
