"""
Tests for the login throttle's RFC 6585 Retry-After header + user-facing banner.

L-2 (v2.23.2 origin): throttled login responses must include:
  - HTTP 429 status code
  - Retry-After: <seconds> header (RFC 6585 §4)
  - JSON body with a customer-facing "banner" message
  - No internal jargon, no agent names, no internal IDs in banner text

LAURA-412-CRITICAL redesign (2026-07-19, fix/v412-auth-throttle-hardening):
  The throttle is now ACCOUNT-GATED (dual-bucket): a login attempt is only
  ever pre-auth-throttled if the SPECIFIC account being logged into
  (`username`) already has its own recorded failures.  The per-IP bucket is
  a severity MODIFIER only — it can never trigger a 429 on its own.  The
  GLOBAL (any-IP) bucket is REMOVED entirely.  Escalation is bounded at
  900s (15 min); the permanent-block tail is removed.

  Throttle schedule (bounded, index = level-1):
    Level 1:   30s  (after 3 consecutive per-account failures)
    Level 2:   60s
    Level 3:  180s
    Level 4:  450s
    Level 5:  900s  (CEILING — further failures refresh TTL, never escalate
                     further, never convert to a permanent block)

  See auth.py module docstring + project_v412_design_conflict_xrealip_podman_nat.md
  + testing_runs/yashigani/v412r4-podman-20260719/laura/laura-podman-pentest.md
  for the full root-cause history this redesign closes.

Last updated: 2026-07-19T00:00:00+00:00
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

SRC = Path(__file__).parent.parent.parent / "yashigani"
ROUTES_AUTH = SRC / "backoffice" / "routes" / "auth.py"


# ---------------------------------------------------------------------------
# Helpers — load the throttle helpers without importing FastAPI stack
# ---------------------------------------------------------------------------

def _get_source() -> str:
    return ROUTES_AUTH.read_text(encoding="utf-8")


def _parse_fn(name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    tree = ast.parse(_get_source())
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    pytest.fail(f"Function '{name}' not found in auth.py")


def _import_module_symbols():
    """
    Import only the throttle helpers from auth.py, stubbing out heavy deps.
    Raises ImportError → skip if the full FastAPI stack isn't installed.
    """
    try:
        import fastapi  # noqa: F401
        import redis  # noqa: F401
    except ImportError as exc:
        pytest.skip(f"FastAPI or redis not installed: {exc}")

    import importlib
    import importlib.util
    import sys
    import types

    stubs = {
        "yashigani.backoffice.middleware": types.ModuleType("stub_middleware"),
        "yashigani.backoffice.state": types.ModuleType("stub_state"),
        "yashigani.auth.totp": types.ModuleType("stub_totp"),
        "yashigani.auth.session": types.ModuleType("stub_session"),
        "yashigani.audit.schema": types.ModuleType("stub_audit_schema"),
        "yashigani.db.postgres": types.ModuleType("stub_pg"),
    }
    stubs["yashigani.backoffice.middleware"].AdminSession = object
    stubs["yashigani.backoffice.middleware"].AnySession = object
    stubs["yashigani.backoffice.middleware"].get_session_store = lambda: None
    stubs["yashigani.backoffice.middleware"]._SESSION_COOKIE = "session"
    stubs["yashigani.backoffice.middleware"].require_admin_session = lambda *a, **kw: None
    stubs["yashigani.backoffice.state"].backoffice_state = MagicMock()
    stubs["yashigani.auth.totp"].verify_totp = MagicMock()
    stubs["yashigani.auth.totp"].generate_provisioning = MagicMock()
    stubs["yashigani.auth.totp"].generate_recovery_code_set = MagicMock()
    stubs["yashigani.auth.session"]._mask_ip = lambda ip: ip
    stubs["yashigani.audit.schema"].AuthThrottleTriggeredEvent = MagicMock()
    stubs["yashigani.db.postgres"].tenant_transaction = MagicMock()

    old = {}
    for k, v in stubs.items():
        old[k] = sys.modules.get(k)
        sys.modules[k] = v

    spec = importlib.util.spec_from_file_location("auth_isolated_throttle", ROUTES_AUTH)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    finally:
        for k, v in old.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    return mod


# ---------------------------------------------------------------------------
# AST-level structural checks (no import of FastAPI required)
# ---------------------------------------------------------------------------

class TestRetryAfterStructural:
    """
    AST-level checks that the Retry-After header and banner are present
    in the throttle implementation without importing the full FastAPI stack.
    """

    def test_apply_auth_throttle_is_sync(self):
        """
        _apply_auth_throttle must be a plain def (not async def) since it
        raises HTTPException instead of awaiting asyncio.sleep().
        """
        fn = _parse_fn("_apply_auth_throttle")
        assert isinstance(fn, ast.FunctionDef), (
            "_apply_auth_throttle must be 'def' (sync), not 'async def' — "
            "it raises HTTPException immediately rather than sleeping"
        )

    def test_apply_auth_throttle_accepts_username_and_response_params(self):
        """
        _apply_auth_throttle must accept 'username' (the account-gating key,
        LAURA-412-CRITICAL) AND 'response' (for the Retry-After header).
        """
        fn = _parse_fn("_apply_auth_throttle")
        param_names = [arg.arg for arg in fn.args.args]
        assert "username" in param_names, (
            "_apply_auth_throttle must accept a 'username' parameter — the "
            f"account bucket is the sole gate (got: {param_names})"
        )
        assert "response" in param_names, (
            f"_apply_auth_throttle must accept a 'response' parameter (got: {param_names})"
        )

    def test_retry_after_header_present_in_source(self):
        source = _get_source()
        assert "Retry-After" in source, (
            "auth.py must set 'Retry-After' header on throttled responses (RFC 6585 §4)"
        )

    def test_banner_field_present_in_source(self):
        source = _get_source()
        assert '"banner"' in source or "'banner'" in source, (
            "Throttle 429 response must include a 'banner' key in the JSON detail"
        )

    def test_banner_text_references_wait_time(self):
        source = _get_source()
        assert "wait" in source.lower() or "try again" in source.lower(), (
            "Banner text must instruct the user to wait or try again later"
        )

    def test_no_asyncio_sleep_in_apply_throttle(self):
        fn = _parse_fn("_apply_auth_throttle")
        fn_src = ast.unparse(fn)
        assert "asyncio.sleep" not in fn_src, (
            "_apply_auth_throttle must not use asyncio.sleep — "
            "it raises HTTP 429 immediately (RFC 6585) instead of blocking the connection"
        )

    def test_http_429_raised_when_throttled(self):
        fn = _parse_fn("_apply_auth_throttle")
        fn_src = ast.unparse(fn)
        assert "HTTPException" in fn_src, (
            "_apply_auth_throttle must raise HTTPException (HTTP 429) when throttled"
        )
        assert "429" in fn_src or "HTTP_429_TOO_MANY_REQUESTS" in fn_src, (
            "_apply_auth_throttle must use HTTP 429 status on the HTTPException"
        )

    def test_retry_after_value_is_delay_seconds(self):
        fn = _parse_fn("_apply_auth_throttle")
        fn_src = ast.unparse(fn)
        assert "delay" in fn_src, (
            "_apply_auth_throttle must compute 'delay' from _throttle_delay_for_level "
            "and use it as the Retry-After value"
        )

    def test_apply_auth_throttle_is_account_gated(self):
        """
        LAURA-412-CRITICAL: the function must return early (no 429) when the
        account-level throttle level is zero — an implicated IP alone must
        never gate the request. Structural proxy: the acct/account level
        variable must be checked with a `<= 0` / `== 0` early-return BEFORE
        the HTTPException is constructed.
        """
        fn = _parse_fn("_apply_auth_throttle")
        fn_src = ast.unparse(fn)
        assert "acct_level" in fn_src, (
            "_apply_auth_throttle must read an account-level throttle value "
            "(acct_level) — the account dimension is the gate"
        )
        assert "return" in fn_src, (
            "_apply_auth_throttle must contain an early return for the "
            "clean-account (acct_level <= 0) case"
        )

    def test_no_global_bucket_in_apply_throttle(self):
        """
        LAURA-412-CRITICAL: the GLOBAL (any-IP) bucket must be fully removed
        from the throttle decision — it was the mechanism that let a single
        unauthenticated stranger lock out every account tenant-wide.
        """
        fn = _parse_fn("_apply_auth_throttle")
        fn_src = ast.unparse(fn)
        assert "global" not in fn_src.lower(), (
            "_apply_auth_throttle must not reference any 'global' bucket — "
            "removed per Laura's podman r4 CRITICAL finding"
        )

    def test_record_auth_failure_has_no_permanent_block_branch(self):
        """
        LAURA-412-CRITICAL: _record_auth_failure must never write
        auth:blocked:{ip} — the auto-permanent-block tail is removed.
        """
        fn = _parse_fn("_record_auth_failure")
        fn_src = ast.unparse(fn)
        assert "auth:blocked" not in fn_src, (
            "_record_auth_failure must NOT auto-populate auth:blocked:{ip} — "
            "the unbounded permanent-block escalation tail is removed "
            "(no unrecoverable state without an explicit admin action)"
        )

    def test_login_route_calls_throttle_with_username_and_response(self):
        """
        The login route must pass username AND the response object to
        _apply_auth_throttle.
        """
        fn = _parse_fn("login")
        fn_src = ast.unparse(fn)
        assert "_apply_auth_throttle(client_ip, body.username, response)" in fn_src, (
            "login() must call _apply_auth_throttle(client_ip, body.username, response)"
        )

    def test_login_route_not_awaiting_throttle(self):
        fn = _parse_fn("login")
        fn_src = ast.unparse(fn)
        assert "await _apply_auth_throttle" not in fn_src, (
            "login() must not 'await _apply_auth_throttle' — "
            "the function is now synchronous (raises 429 immediately)"
        )


# ---------------------------------------------------------------------------
# Behaviour checks — mock Redis, exercise throttle directly
# ---------------------------------------------------------------------------

class TestRetryAfterBehaviour:
    """
    Behaviour tests that exercise _apply_auth_throttle with a mocked Redis
    client and assert the HTTPException is raised with the right headers
    and body — and that the account dimension gates correctly.
    """

    def _import(self):
        try:
            return _import_module_symbols()
        except pytest.skip.Exception:
            pytest.skip("deps not available")

    def _make_mock_redis(self, ip_level: int = 0, acct_level: int = 0,
                          ip_fails: int = 0, acct_fails: int = 0) -> MagicMock:
        """Build a Redis mock whose pipeline().execute() returns the given state.

        Order matches _apply_auth_throttle's pipe.get() call order:
        ip_fail_key, ip_key, acct_fail_key, acct_key.
        """
        r = MagicMock()
        pipe = MagicMock()
        r.pipeline.return_value = pipe
        pipe.get.return_value = pipe
        pipe.execute.return_value = [
            str(ip_fails) if ip_fails else None,
            str(ip_level) if ip_level else None,
            str(acct_fails) if acct_fails else None,
            str(acct_level) if acct_level else None,
        ]
        return r

    def _make_mock_response(self) -> MagicMock:
        response = MagicMock()
        response.headers = {}
        return response

    def test_no_throttle_when_account_level_zero(self):
        """Account level 0 (clean account) — no exception, regardless of IP level."""
        mod = self._import()
        r = self._make_mock_redis(ip_level=5, acct_level=0)  # hot IP, clean account
        resp = self._make_mock_response()
        with patch.object(mod, "_get_throttle_redis", return_value=r):
            mod._apply_auth_throttle("1.2.3.4", "cedar", resp)  # must not raise

    def test_429_raised_at_account_level_1(self):
        """Account throttle level 1 → 429 raised with Retry-After: 30."""
        mod = self._import()
        from fastapi import HTTPException as FE

        r = self._make_mock_redis(ip_level=0, acct_level=1)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            with pytest.raises(FE) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", "cedar", resp)

        exc = exc_info.value
        assert exc.status_code == 429
        assert exc.headers["Retry-After"] == "30"

    def test_retry_after_escalates_by_level(self):
        """Retry-After value matches the bounded delay schedule at each level."""
        mod = self._import()
        from fastapi import HTTPException as FE

        expected = {1: 30, 2: 60, 3: 180, 4: 450, 5: 900}

        for level, delay in expected.items():
            r = self._make_mock_redis(ip_level=0, acct_level=level)
            resp = self._make_mock_response()

            with patch.object(mod, "_get_throttle_redis", return_value=r):
                with pytest.raises(FE) as exc_info:
                    mod._apply_auth_throttle("1.2.3.4", "cedar", resp)

            exc = exc_info.value
            assert exc.status_code == 429, f"Level {level}: expected 429"
            ra = exc.headers.get("Retry-After")
            assert ra == str(delay), (
                f"Level {level}: expected Retry-After={delay}, got {ra!r}"
            )

    def test_ip_level_alone_never_triggers_429(self):
        """
        LAURA-412-CRITICAL core invariant: an arbitrarily hot IP bucket with a
        CLEAN account (acct_level=0) must never produce a 429. This is the
        exact shape of Laura's proven exploit (shared/collapsed IP, unrelated
        account noise) and must hold at every IP level.
        """
        mod = self._import()
        for hot_ip_level in (1, 2, 3, 4, 5, 99):
            r = self._make_mock_redis(ip_level=hot_ip_level, acct_level=0)
            resp = self._make_mock_response()
            with patch.object(mod, "_get_throttle_redis", return_value=r):
                mod._apply_auth_throttle("10.89.1.2", "cedar", resp)  # must not raise

    def test_ip_level_escalates_severity_once_account_implicated(self):
        """
        When the account itself has failures (acct_level=2) AND its source IP
        is also hot (ip_level=4), the effective delay uses the higher of the
        two — the IP still contributes SEVERITY once the account is gated,
        it just can never gate alone.
        """
        mod = self._import()
        from fastapi import HTTPException as FE

        r = self._make_mock_redis(ip_level=4, acct_level=2)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            with pytest.raises(FE) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", "victim-account", resp)

        exc = exc_info.value
        assert exc.headers.get("Retry-After") == "450", (
            "Effective level = max(acct=2, ip=4) = 4 → delay 450s"
        )

    def test_banner_present_in_429_detail(self):
        mod = self._import()
        from fastapi import HTTPException as FE

        r = self._make_mock_redis(ip_level=0, acct_level=1)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            with pytest.raises(FE) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", "cedar", resp)

        detail = exc_info.value.detail
        assert isinstance(detail, dict), f"detail must be a dict, got {type(detail)}"
        assert "banner" in detail, f"detail must contain 'banner' key, got {list(detail.keys())}"

        banner = detail["banner"]
        assert isinstance(banner, str) and len(banner) > 10
        forbidden = ["agent", "redis", "postgres", "throttle_level", "LAURA", "AVA", "YCS"]
        for word in forbidden:
            assert word.lower() not in banner.lower(), (
                f"banner must not contain internal jargon '{word}': {banner!r}"
            )
        assert "30" in banner or "second" in banner.lower() or "wait" in banner.lower()

    def test_retry_after_seconds_field_matches_header(self):
        mod = self._import()
        from fastapi import HTTPException as FE

        r = self._make_mock_redis(ip_level=0, acct_level=3)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            with pytest.raises(FE) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", "cedar", resp)

        exc = exc_info.value
        ra_header = int(exc.headers["Retry-After"])
        ra_body = exc.detail.get("retry_after_seconds")
        assert ra_body == ra_header


# ---------------------------------------------------------------------------
# Throttle delay schedule (bounded) — unit tests for _throttle_delay_for_level
# ---------------------------------------------------------------------------

class TestThrottleDelaySchedule:
    """
    Verify the bounded escalation schedule (900s / 15-min cap, no permanent
    block) is correctly implemented.
    """

    def _get_delay_fn(self):
        mod = _import_module_symbols()
        return mod._throttle_delay_for_level

    def test_level_0_returns_0(self):
        fn = self._get_delay_fn()
        assert fn(0) == 0

    def test_level_1_returns_30(self):
        fn = self._get_delay_fn()
        assert fn(1) == 30

    def test_level_2_returns_60(self):
        fn = self._get_delay_fn()
        assert fn(2) == 60

    def test_level_3_returns_180(self):
        fn = self._get_delay_fn()
        assert fn(3) == 180

    def test_level_4_returns_450(self):
        fn = self._get_delay_fn()
        assert fn(4) == 450

    def test_level_5_returns_900(self):
        fn = self._get_delay_fn()
        assert fn(5) == 900

    def test_level_beyond_max_caps_at_900_not_permanent(self):
        """
        LAURA-412-CRITICAL: any level above the table caps at the bounded
        maximum (900s) — it must NEVER grow beyond that, and there is no
        separate "permanent" sentinel value or behaviour.
        """
        fn = self._get_delay_fn()
        for level in (6, 7, 50, 99, 10_000):
            assert fn(level) == 900, f"level={level} must cap at 900s, got {fn(level)}"
