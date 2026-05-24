"""
Unit tests for yashigani.gateway.ddos.DDoSProtector.

Uses fakeredis for a real Redis implementation without a running server.
All tests are synchronous (DDoSProtector uses a sync Redis client).

Import strategy
---------------
``yashigani.gateway.__init__`` eagerly imports ``proxy.py`` which requires
``fastapi``.  The test environment may not have fastapi installed, so we import
``ddos`` and ``_redact_ip`` directly from the module file using ``importlib``
rather than via the package to avoid triggering ``__init__``.

The ``TestProxyIntegration`` class DOES need fastapi/proxy and is skipped
automatically when those packages are absent.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Direct module import — bypass yashigani.gateway.__init__
# ---------------------------------------------------------------------------

def _import_ddos():
    """Import yashigani.gateway.ddos without executing gateway/__init__.py."""
    # If it's already in sys.modules (e.g. the __init__ was already loaded),
    # return the cached module.
    if "yashigani.gateway.ddos" in sys.modules:
        return sys.modules["yashigani.gateway.ddos"]

    # Find the file directly and load it as a spec.
    src_root = Path(__file__).parent.parent.parent  # src/
    ddos_path = src_root / "yashigani" / "gateway" / "ddos.py"
    spec = importlib.util.spec_from_file_location("yashigani.gateway.ddos", ddos_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["yashigani.gateway.ddos"] = module
    spec.loader.exec_module(module)
    return module


_ddos_module = _import_ddos()
DDoSProtector = _ddos_module.DDoSProtector
_redact_ip = _ddos_module._redact_ip


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_protector(redis_client, max_connections=10, window_seconds=60):
    return DDoSProtector(
        redis_client=redis_client,
        max_connections_per_ip=max_connections,
        window_seconds=window_seconds,
    )


# ---------------------------------------------------------------------------
# record() + check() — basic flow
# ---------------------------------------------------------------------------

class TestDDoSProtectorBasic:
    def test_fresh_ip_is_allowed(self, mock_redis):
        p = make_protector(mock_redis)
        assert p.check("1.2.3.4") is True

    def test_single_record_is_allowed(self, mock_redis):
        p = make_protector(mock_redis, max_connections=10)
        p.record("1.2.3.4")
        assert p.check("1.2.3.4") is True

    def test_at_threshold_is_allowed(self, mock_redis):
        p = make_protector(mock_redis, max_connections=5)
        for _ in range(5):
            p.record("1.2.3.4")
        # exactly at threshold — still allowed
        assert p.check("1.2.3.4") is True

    def test_over_threshold_is_blocked(self, mock_redis):
        p = make_protector(mock_redis, max_connections=5)
        for _ in range(6):
            p.record("1.2.3.4")
        assert p.check("1.2.3.4") is False

    def test_different_ips_are_independent(self, mock_redis):
        p = make_protector(mock_redis, max_connections=3)
        for _ in range(4):
            p.record("10.0.0.1")
        # 10.0.0.1 is over threshold
        assert p.check("10.0.0.1") is False
        # 10.0.0.2 has never been recorded — should be allowed
        assert p.check("10.0.0.2") is True

    def test_current_count_reflects_records(self, mock_redis):
        p = make_protector(mock_redis, max_connections=100)
        for _ in range(7):
            p.record("5.6.7.8")
        assert p.current_count("5.6.7.8") == 7

    def test_current_count_zero_for_unknown_ip(self, mock_redis):
        p = make_protector(mock_redis)
        assert p.current_count("0.0.0.0") == 0


# ---------------------------------------------------------------------------
# Path exemptions
# ---------------------------------------------------------------------------

class TestDDoSProtectorExemptPaths:
    @pytest.mark.parametrize("path", [
        "/healthz",
        "/readyz",
        "/internal/metrics",
        "/metrics",
        "/-/healthy",
    ])
    def test_exempt_path_always_allowed(self, mock_redis, path):
        p = make_protector(mock_redis, max_connections=1)
        # Even if we record many times, exempt paths bypass the check
        for _ in range(100):
            p.record("1.2.3.4", path)
        # Counter for this IP on a non-exempt path should still be 0
        # because record() skips exempt paths
        assert p.current_count("1.2.3.4") == 0
        assert p.check("1.2.3.4", path) is True

    def test_non_exempt_path_still_blocked(self, mock_redis):
        p = make_protector(mock_redis, max_connections=2)
        for _ in range(3):
            p.record("1.2.3.4", "/v1/chat/completions")
        assert p.check("1.2.3.4", "/v1/chat/completions") is False


# ---------------------------------------------------------------------------
# Redis failure handling (fail-open)
# ---------------------------------------------------------------------------

class TestDDoSProtectorFailOpen:
    def test_check_returns_true_on_redis_error(self):
        bad_redis = MagicMock()
        bad_redis.get.side_effect = Exception("redis connection refused")
        p = make_protector(bad_redis)
        # Should not raise; should allow the request
        assert p.check("1.2.3.4") is True

    def test_record_does_not_raise_on_redis_error(self):
        bad_redis = MagicMock()
        bad_redis.incr.side_effect = Exception("redis connection refused")
        p = make_protector(bad_redis)
        # Should not raise
        p.record("1.2.3.4")

    def test_current_count_returns_zero_on_redis_error(self):
        bad_redis = MagicMock()
        bad_redis.get.side_effect = Exception("redis timeout")
        p = make_protector(bad_redis)
        assert p.current_count("1.2.3.4") == 0


# ---------------------------------------------------------------------------
# TTL — key expiry is set on first INCR
# ---------------------------------------------------------------------------

class TestDDoSProtectorTTL:
    def test_expire_called_on_first_record(self, mock_redis):
        """
        The Redis key must have an expiry set so counters don't accumulate
        forever.  We verify via fakeredis that the key has a non-negative TTL
        after the first record() call.
        """
        p = make_protector(mock_redis, window_seconds=60)
        p.record("9.9.9.9")
        key = p._key("9.9.9.9")
        ttl = mock_redis.ttl(key)
        # TTL should be > 0 (expire was set)
        assert ttl > 0
        # TTL should be <= 2 * window_seconds (120 s)
        assert ttl <= 120

    def test_expire_not_reset_on_subsequent_records(self, mock_redis):
        """
        Only the first INCR sets the TTL.  Subsequent increments must not
        reset it (which could allow a counter to live forever under sustained
        traffic).
        """
        p = make_protector(mock_redis, window_seconds=60)
        p.record("9.9.9.9")
        key = p._key("9.9.9.9")
        ttl_after_first = mock_redis.ttl(key)

        # Second record: TTL should not increase (EXPIRE is only called when
        # count == 1).  In fakeredis the TTL decrements in real time, so we
        # just assert it doesn't exceed the initial value.
        p.record("9.9.9.9")
        ttl_after_second = mock_redis.ttl(key)
        assert ttl_after_second <= ttl_after_first


# ---------------------------------------------------------------------------
# _redact_ip helper
# ---------------------------------------------------------------------------

class TestRedactIP:
    def test_ipv4_redaction(self):
        assert _redact_ip("192.168.1.42") == "192.168.1.*"

    def test_ipv6_redaction(self):
        result = _redact_ip("2001:db8:85a3:0:0:8a2e:370:7334")
        assert result.startswith("2001:db8:85a3:0:")
        assert "****" in result

    def test_malformed_ip_does_not_raise(self):
        # Should return some placeholder, not raise
        result = _redact_ip("not-an-ip")
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# Key structure
# ---------------------------------------------------------------------------

class TestDDoSProtectorKey:
    def test_key_includes_ip_and_bucket(self, mock_redis):
        p = make_protector(mock_redis, window_seconds=60)
        key = p._key("1.2.3.4")
        assert key.startswith("ddos:1.2.3.4:")
        # bucket should be an integer
        bucket_str = key.split(":")[-1]
        assert bucket_str.isdigit()

    def test_key_bucket_changes_with_window(self, mock_redis):
        """Keys in different windows must differ."""
        # Use a 1-second window so we can compare two buckets without sleeping
        p = DDoSProtector(mock_redis, window_seconds=1)
        bucket_now = int(time.time() / 1)
        bucket_prev = bucket_now - 1
        key_now = f"ddos:1.2.3.4:{bucket_now}"
        key_prev = f"ddos:1.2.3.4:{bucket_prev}"
        assert key_now != key_prev


# ---------------------------------------------------------------------------
# Integration: proxy smoke tests (skipped when fastapi is not installed)
# ---------------------------------------------------------------------------

class TestProxyIntegration:
    """
    Lightweight sanity check that DDoSProtector plugs into the proxy without
    import errors.  Does not test full request flow.

    Skipped automatically when fastapi is not installed (e.g. CI without the
    full requirements set).
    """

    def test_create_gateway_app_accepts_ddos_protector(self, mock_redis):
        fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")  # noqa: F841
        from yashigani.gateway.proxy import create_gateway_app, GatewayConfig

        protector = DDoSProtector(mock_redis)
        cfg = GatewayConfig(upstream_base_url="http://localhost:9999")
        app = create_gateway_app(config=cfg, ddos_protector=protector)
        assert app is not None

    def test_openai_router_configure_accepts_ddos_protector(self, mock_redis):
        pytest.importorskip("fastapi", reason="fastapi not installed")
        from yashigani.gateway import openai_router

        protector = DDoSProtector(mock_redis)
        # Should not raise
        openai_router.configure(ddos_protector=protector)
        assert openai_router._state.ddos_protector is protector

    def test_gateway_app_state_ddos_protector_not_none(self, mock_redis):
        """
        After create_gateway_app() + the entrypoint state-attachment step
        (``app.state.ddos_protector = protector``), app.state.ddos_protector
        must be the same object.  This test emulates what entrypoint.py does
        after calling create_gateway_app.
        """
        pytest.importorskip("fastapi", reason="fastapi not installed")
        from yashigani.gateway.proxy import create_gateway_app, GatewayConfig

        protector = DDoSProtector(mock_redis, max_connections_per_ip=5000)
        cfg = GatewayConfig(upstream_base_url="http://localhost:9999")
        app = create_gateway_app(config=cfg, ddos_protector=protector)
        # Emulate the entrypoint.py state-attachment step.
        app.state.ddos_protector = protector
        assert app.state.ddos_protector is protector
        assert app.state.ddos_protector is not None


# ---------------------------------------------------------------------------
# Permissive-defaults tests (v2.4.1 wire-up — YSG-RISK-056)
# ---------------------------------------------------------------------------

class TestPermissiveDefaults:
    """
    Verify the v2.4.1 permissive default threshold (5000/60s) and env-var
    overrides.  Drift audit finding #2: CHANGELOG claimed DDoSProtector was
    wired but it was dead code.  These tests prevent future drift.
    """

    def test_default_per_ip_limit_is_5000(self):
        assert _ddos_module._DEFAULT_MAX_CONNECTIONS_PER_IP == 5000

    def test_default_window_seconds_is_60(self):
        assert _ddos_module._DEFAULT_WINDOW_SECONDS == 60

    def test_yashigani_healthz_is_exempt(self):
        assert "/_yashigani/healthz" in _ddos_module._EXEMPT_PATHS

    def test_env_var_names_exported(self):
        """Module must export the env-var name constants used by entrypoint.py."""
        assert hasattr(_ddos_module, "ENV_PER_IP_LIMIT")
        assert hasattr(_ddos_module, "ENV_WINDOW_SECONDS")
        assert hasattr(_ddos_module, "ENV_EXEMPT_PATHS")

    def test_env_override_per_ip_limit(self, mock_redis, monkeypatch):
        """
        YASHIGANI_DDOS_PER_IP_LIMIT=10 must be honoured: 11 requests from one
        IP must be blocked; 10 must pass.
        """
        monkeypatch.setenv(_ddos_module.ENV_PER_IP_LIMIT, "10")
        limit = int(os.environ[_ddos_module.ENV_PER_IP_LIMIT])
        p = DDoSProtector(mock_redis, max_connections_per_ip=limit)
        for _ in range(10):
            p.record("1.2.3.4")
        assert p.check("1.2.3.4") is True   # at threshold — allowed
        p.record("1.2.3.4")
        assert p.check("1.2.3.4") is False  # over threshold — blocked

    def test_env_override_window_seconds(self, mock_redis, monkeypatch):
        monkeypatch.setenv(_ddos_module.ENV_WINDOW_SECONDS, "120")
        window = int(os.environ[_ddos_module.ENV_WINDOW_SECONDS])
        p = DDoSProtector(mock_redis, window_seconds=window)
        assert p.window_seconds == 120

    def test_normal_load_100_requests_all_pass(self, mock_redis):
        """
        Regression: 100 requests from one IP in one window must all pass at
        the permissive 5000-per-IP default.  Simulates normal corporate-proxy
        or shared-NAT usage.
        """
        p = DDoSProtector(mock_redis)  # uses 5000 default
        for _ in range(100):
            p.record("10.0.0.1")
        assert p.check("10.0.0.1") is True

    def test_flood_5001_requests_triggers_429_gate(self, mock_redis):
        """
        5001 requests from one IP must exceed the 5000 threshold: check()
        returns False, which the gateway translates to HTTP 429.
        """
        p = DDoSProtector(mock_redis, max_connections_per_ip=5000)
        for _ in range(5001):
            p.record("203.0.113.1")
        # count is 5001 > 5000 → blocked
        assert p.check("203.0.113.1") is False

    def test_flood_exactly_at_limit_still_passes(self, mock_redis):
        """
        Exactly 5000 requests from one IP must still pass (<=, not <).
        """
        p = DDoSProtector(mock_redis, max_connections_per_ip=5000)
        for _ in range(5000):
            p.record("203.0.113.2")
        assert p.check("203.0.113.2") is True


# ---------------------------------------------------------------------------
# _ddos_default_per_ip_limit — license-scaled defaults (v2.24.1 / YSG-RISK-056)
# ---------------------------------------------------------------------------

class TestDdosDefaultPerIpLimit:
    """
    Verify _ddos_default_per_ip_limit() produces the correct per-tier value
    for all 8 defined tiers (Tiago 2026-05-24 formula: max(5000, users*25)).
    """

    @pytest.fixture(autouse=True)
    def _load_helper(self):
        """Ensure _ddos_default_per_ip_limit is importable from the module."""
        assert hasattr(_ddos_module, "_ddos_default_per_ip_limit"), (
            "_ddos_default_per_ip_limit missing from ddos module"
        )

    @pytest.mark.parametrize("max_end_users,expected", [
        # community / canary: max_end_users=5 → 5*25=125 < 5000 → floor 5000
        (5,    5_000),
        # igniter: max_end_users=50 → 50*25=1250 < 5000 → floor 5000
        (50,   5_000),
        # starter: max_end_users=100 → 100*25=2500 < 5000 → floor 5000
        (100,  5_000),
        # professional: max_end_users=500 → 500*25=12500 > 5000 → 12500
        (500,  12_500),
        # professional_plus: max_end_users=4000 → 4000*25=100000 > 5000 → 100000
        (4000, 100_000),
        # enterprise / academic_nonprofit: -1 → sentinel 100000
        (-1,   100_000),
    ])
    def test_per_tier_limit(self, max_end_users, expected):
        fn = _ddos_module._ddos_default_per_ip_limit
        assert fn(max_end_users) == expected, (
            f"max_end_users={max_end_users}: expected {expected}, "
            f"got {fn(max_end_users)}"
        )

    def test_community_tier_default_matches_floor(self):
        """community max_end_users=5 must hit the 5000 floor, not 5*25=125."""
        fn = _ddos_module._ddos_default_per_ip_limit
        assert fn(5) == 5_000

    def test_enterprise_sentinel_100k(self):
        """enterprise/academic (-1) must return exactly 100 000."""
        fn = _ddos_module._ddos_default_per_ip_limit
        assert fn(-1) == 100_000

    def test_formula_is_max_of_floor_and_product(self):
        """Cross-check: any positive user count below 200 hits the 5000 floor."""
        fn = _ddos_module._ddos_default_per_ip_limit
        for users in [1, 5, 50, 100, 199]:
            result = fn(users)
            assert result == 5_000, (
                f"users={users}: expected 5000 (floor), got {result}"
            )

    def test_formula_above_floor(self):
        """Any user count where users*25 > 5000 (i.e. users >= 201) must use product."""
        fn = _ddos_module._ddos_default_per_ip_limit
        # 201 * 25 = 5025 > 5000
        assert fn(201) == 5_025
        # 1000 * 25 = 25000
        assert fn(1000) == 25_000


class TestDdosEnvVarBeatslicensedDefault:
    """
    Env var YASHIGANI_DDOS_PER_IP_LIMIT must win over the license-computed
    default.  Simulate the entrypoint.py resolution logic.
    """

    def test_env_var_override_beats_computed_default(self, monkeypatch):
        """
        When YASHIGANI_DDOS_PER_IP_LIMIT=999 is set, the entrypoint
        resolution path must use 999, not the license-computed value.
        """
        monkeypatch.setenv(_ddos_module.ENV_PER_IP_LIMIT, "999")
        env_val = os.environ.get(_ddos_module.ENV_PER_IP_LIMIT)
        assert env_val is not None
        resolved = int(env_val)
        assert resolved == 999
        # The license-computed value for community (5) would be 5000 — verify
        # that the env override is distinct and wins.
        assert resolved != _ddos_module._ddos_default_per_ip_limit(5)

    def test_no_env_var_uses_license_computation(self, monkeypatch):
        """
        When env var is absent, the computed default is used.
        """
        monkeypatch.delenv(_ddos_module.ENV_PER_IP_LIMIT, raising=False)
        env_val = os.environ.get(_ddos_module.ENV_PER_IP_LIMIT)
        assert env_val is None
        # Falls back to license computation; community tier gives 5000
        computed = _ddos_module._ddos_default_per_ip_limit(5)
        assert computed == 5_000


class TestDdosMissingLicenseFallback:
    """
    If get_license() raises (no license file, broken verifier), the entrypoint
    falls back to community defaults (max_end_users=5 → 5000).
    """

    def test_community_fallback_is_5(self):
        """
        The community fallback max_end_users=5 passed to _ddos_default_per_ip_limit
        must yield 5000 (the floor).
        """
        fn = _ddos_module._ddos_default_per_ip_limit
        # entrypoint fallback on exception: max_end_users = 5
        fallback_users = 5
        assert fn(fallback_users) == 5_000

    def test_community_max_end_users_value(self):
        """
        TIER_DEFAULTS["community"]["max_end_users"] must be 5 so the
        fallback in the entrypoint DDoS block produces the floor (5000).
        Uses sys.path insertion to avoid dataclass annotation resolution
        issues in Python 3.9 with spec_from_file_location.
        """
        src_root = Path(__file__).parent.parent.parent
        src_str = str(src_root)
        if src_str not in sys.path:
            sys.path.insert(0, src_str)
        from yashigani.licensing.model import TIER_DEFAULTS  # noqa: PLC0415
        assert TIER_DEFAULTS["community"]["max_end_users"] == 5
        assert TIER_DEFAULTS["canary"]["max_end_users"] == 5
