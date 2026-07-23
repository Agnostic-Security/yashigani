"""
Tests for the login throttle's RFC 6585 Retry-After header + user-facing banner.

L-2 (v2.23.2 origin): throttled login responses must include:
  - HTTP 429 status code
  - Retry-After: <seconds> header (RFC 6585 §4)
  - JSON body with a customer-facing "banner" message
  - No internal jargon, no agent names, no internal IDs in banner text

LAURA-412-CRITICAL redesign (2026-07-19, fix/v412-auth-throttle-hardening,
round 1): the throttle is ACCOUNT-GATED (dual-bucket) — a login attempt is
only ever pre-auth-throttled if the SPECIFIC account being logged into
already has its own recorded attempts.  The per-IP bucket is a severity
MODIFIER only.  The GLOBAL (any-IP) bucket is REMOVED.  Escalation is
bounded at 900s (15 min).

LAURA-412-HIGH/MEDIUM fix (round 2, same date, Laura re-attack):
  - HIGH: the round-1 design read the current count/level, then incremented
    it SEPARATELY after authenticate() resolved — a TOCTOU race under
    concurrency.  Fixed by _throttle_admit(): a single Redis Lua script
    that atomically increments BOTH buckets and returns their PRIOR level
    in one round-trip, called BEFORE authenticate() ever runs.
    _record_auth_failure() no longer exists.
  - MEDIUM: the account bucket now keys on the account's stable account_id
    (via _account_bucket_key) rather than a casefolded username, closing a
    cross-account lockout for accounts differing only by case (this
    system's identity model is case-sensitive).

  Throttle schedule (bounded, index = level-1):
    Level 1:   30s  (after 3 consecutive per-account attempts)
    Level 2:   60s
    Level 3:  180s
    Level 4:  450s
    Level 5:  900s  (CEILING — further attempts refresh TTL, never escalate
                     further, never convert to a permanent block)

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
        _apply_auth_throttle must be a plain def (not async def) — the
        atomic Redis admit is a synchronous call; only the caller's account
        resolution is async.
        """
        fn = _parse_fn("_apply_auth_throttle")
        assert isinstance(fn, ast.FunctionDef), (
            "_apply_auth_throttle must be 'def' (sync), not 'async def'"
        )

    def test_apply_auth_throttle_accepts_all_required_params(self):
        """
        _apply_auth_throttle must accept 'username' (audit/banner text),
        'account_id' (LAURA-412-MEDIUM — the identity-stable bucket key),
        and 'response' (Retry-After header).
        """
        fn = _parse_fn("_apply_auth_throttle")
        param_names = [arg.arg for arg in fn.args.args]
        for required in ("client_ip", "username", "account_id", "response"):
            assert required in param_names, (
                f"_apply_auth_throttle must accept '{required}' (got: {param_names})"
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
        """
        AVA-412-DOS (2026-07-23) extracted the log/audit/raise-429 sequence
        (including the 'delay' computation) out of _apply_auth_throttle
        into a shared _reject_with_throttle helper — called from both the
        no-mutation fast-reject path and the post-admit path — so the
        'delay' computation now lives there rather than inline in
        _apply_auth_throttle itself. Check both functions' combined source.
        """
        apply_fn_src = ast.unparse(_parse_fn("_apply_auth_throttle"))
        reject_fn_src = ast.unparse(_parse_fn("_reject_with_throttle"))
        assert "delay" in apply_fn_src or "delay" in reject_fn_src, (
            "_apply_auth_throttle (or its _reject_with_throttle helper) must "
            "compute 'delay' from _throttle_delay_for_level and use it as "
            "the Retry-After value"
        )
        assert "_reject_with_throttle(" in apply_fn_src, (
            "_apply_auth_throttle must delegate the 429 raise to "
            "_reject_with_throttle so both the fast-reject and post-admit "
            "paths share identical Retry-After/banner/audit logic"
        )

    def test_apply_auth_throttle_is_account_gated(self):
        """
        LAURA-412-CRITICAL: the function must return early (no 429) when the
        account-level throttle level is zero.
        """
        fn = _parse_fn("_apply_auth_throttle")
        fn_src = ast.unparse(fn)
        assert "acct_level" in fn_src
        assert "return" in fn_src

    def test_no_global_bucket_in_apply_throttle(self):
        """LAURA-412-CRITICAL: the GLOBAL (any-IP) bucket must be fully removed."""
        fn = _parse_fn("_apply_auth_throttle")
        fn_src = ast.unparse(fn)
        assert "global" not in fn_src.lower()

    def test_apply_auth_throttle_uses_atomic_admit(self):
        """
        LAURA-412-HIGH (round 2): _apply_auth_throttle must call the atomic
        _throttle_admit helper — separate GET-then-later-INCR calls (the
        pre-fix race shape) must not reappear.
        """
        fn = _parse_fn("_apply_auth_throttle")
        fn_src = ast.unparse(fn)
        assert "_throttle_admit(" in fn_src, (
            "_apply_auth_throttle must call _throttle_admit() — the atomic "
            "Lua-based check-and-increment that closes the TOCTOU race"
        )
        assert ".pipeline()" not in fn_src, (
            "_apply_auth_throttle must not use a plain pipeline() (read-then-"
            "act) — that is exactly the race Laura proved with 25 concurrent "
            "requests"
        )

    def test_record_auth_failure_removed(self):
        """
        LAURA-412-HIGH (round 2): _record_auth_failure must no longer exist
        — counting now happens unconditionally inside the atomic admit,
        before authenticate() runs, not after it fails.
        """
        source = _get_source()
        tree = ast.parse(source)
        names = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        assert "_record_auth_failure" not in names, (
            "_record_auth_failure must be removed — see LAURA-412-HIGH fix"
        )

    def test_account_bucket_key_prefers_account_id(self):
        """
        LAURA-412-MEDIUM (round 2): _account_bucket_key must key on
        account_id (immune to any username normalisation) when the account
        exists, falling back to a hashed username only when it doesn't.
        """
        fn = _parse_fn("_account_bucket_key")
        fn_src = ast.unparse(fn)
        assert "account_id" in fn_src
        assert "id:" in fn_src, "must use an 'id:' prefixed key for real accounts"
        assert "unk:" in fn_src, "must use a distinct 'unk:' prefix for the fallback case"

    def test_login_route_resolves_account_id_before_throttle(self):
        """
        LAURA-412-MEDIUM: login() must resolve account_id BEFORE calling
        _apply_auth_throttle, so the bucket keys on the stable identity.
        """
        fn = _parse_fn("login")
        fn_src = ast.unparse(fn)
        resolve_idx = fn_src.find("_resolve_account_id_for_bucket(")
        throttle_idx = fn_src.find("_apply_auth_throttle(")
        assert resolve_idx != -1 and throttle_idx != -1
        assert resolve_idx < throttle_idx

    def test_login_route_not_awaiting_throttle(self):
        fn = _parse_fn("login")
        fn_src = ast.unparse(fn)
        assert "await _apply_auth_throttle" not in fn_src, (
            "login() must not 'await _apply_auth_throttle' — "
            "the function is synchronous (raises 429 immediately)"
        )


# ---------------------------------------------------------------------------
# Behaviour checks — mock Redis, exercise throttle directly
# ---------------------------------------------------------------------------

class TestRetryAfterBehaviour:
    """
    Behaviour tests that exercise _apply_auth_throttle with a mocked Redis
    ``eval`` return value and assert the HTTPException is raised with the
    right headers and body, and that the account dimension gates correctly.
    """

    def _import(self):
        try:
            return _import_module_symbols()
        except pytest.skip.Exception:
            pytest.skip("deps not available")

    def _make_mock_redis(self, ip_fails: int, ip_level_before: int,
                          acct_fails: int, acct_level_before: int) -> MagicMock:
        """Mock the atomic admit's eval() return value directly.

        AVA-412-DOS (2026-07-23): _apply_auth_throttle now does a read-only
        GET pre-check of the SAME throttle keys BEFORE deciding whether to
        call the mutating atomic admit (eval) at all. That GET must observe
        the identical "before this call" level these tests already encode
        via ip_level_before/acct_level_before for the eval mock — an
        unconfigured MagicMock().get() would otherwise return a truthy
        MagicMock whose int() coerces to 1, making every case look
        "already gated" regardless of the intended level. Wiring .get()
        to the same before-state keeps this mock an accurate stand-in for
        real Redis (where GET and the Lua's internal GET would of course
        agree, since they read the same key at the same instant).
        """
        r = MagicMock()
        r.eval.return_value = [ip_fails, ip_level_before, acct_fails, acct_level_before]

        def _fake_get(key):
            key_str = key.decode() if isinstance(key, bytes) else key
            if key_str.startswith("auth:throttle:ip:"):
                return str(ip_level_before).encode() if ip_level_before else None
            if key_str.startswith("auth:throttle:acct:"):
                return str(acct_level_before).encode() if acct_level_before else None
            return None

        r.get.side_effect = _fake_get
        return r

    def _make_mock_response(self) -> MagicMock:
        response = MagicMock()
        response.headers = {}
        return response

    def test_no_throttle_when_account_level_zero(self):
        """Account level 0 (clean account) — no exception, regardless of IP level."""
        mod = self._import()
        r = self._make_mock_redis(ip_fails=10, ip_level_before=5, acct_fails=1, acct_level_before=0)
        resp = self._make_mock_response()
        with patch.object(mod, "_get_throttle_redis", return_value=r):
            mod._apply_auth_throttle("1.2.3.4", "cedar", None, resp)  # must not raise

    def test_429_raised_at_account_level_1(self):
        """Account throttle level 1 (before this call) → 429 with Retry-After: 30."""
        mod = self._import()
        from fastapi import HTTPException as FE

        r = self._make_mock_redis(ip_fails=1, ip_level_before=0, acct_fails=4, acct_level_before=1)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            with pytest.raises(FE) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", "cedar", "acct-uuid-1", resp)

        exc = exc_info.value
        assert exc.status_code == 429
        assert exc.headers["Retry-After"] == "30"

    def test_retry_after_escalates_by_level(self):
        """Retry-After value matches the bounded delay schedule at each level."""
        mod = self._import()
        from fastapi import HTTPException as FE

        expected = {1: 30, 2: 60, 3: 180, 4: 450, 5: 900}

        for level, delay in expected.items():
            r = self._make_mock_redis(ip_fails=1, ip_level_before=0, acct_fails=99, acct_level_before=level)
            resp = self._make_mock_response()

            with patch.object(mod, "_get_throttle_redis", return_value=r):
                with pytest.raises(FE) as exc_info:
                    mod._apply_auth_throttle("1.2.3.4", "cedar", "acct-uuid-1", resp)

            exc = exc_info.value
            assert exc.status_code == 429, f"Level {level}: expected 429"
            ra = exc.headers.get("Retry-After")
            assert ra == str(delay), f"Level {level}: expected Retry-After={delay}, got {ra!r}"

    def test_ip_level_alone_never_triggers_429(self):
        """
        LAURA-412-CRITICAL core invariant: an arbitrarily hot IP bucket with a
        CLEAN account (acct_level_before=0) must never produce a 429.
        """
        mod = self._import()
        for hot_ip_level in (1, 2, 3, 4, 5, 99):
            r = self._make_mock_redis(ip_fails=10, ip_level_before=hot_ip_level, acct_fails=1, acct_level_before=0)
            resp = self._make_mock_response()
            with patch.object(mod, "_get_throttle_redis", return_value=r):
                mod._apply_auth_throttle("10.89.1.2", "cedar", "acct-uuid-1", resp)  # must not raise

    def test_ip_level_escalates_severity_once_account_implicated(self):
        """
        When the account itself has attempts (acct_level_before=2) AND its
        source IP is also hot (ip_level_before=4), the effective delay uses
        the higher of the two.
        """
        mod = self._import()
        from fastapi import HTTPException as FE

        r = self._make_mock_redis(ip_fails=10, ip_level_before=4, acct_fails=6, acct_level_before=2)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            with pytest.raises(FE) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", "victim-account", "acct-uuid-victim", resp)

        exc = exc_info.value
        assert exc.headers.get("Retry-After") == "450", (
            "Effective level = max(acct=2, ip=4) = 4 → delay 450s"
        )

    def test_banner_present_in_429_detail(self):
        mod = self._import()
        from fastapi import HTTPException as FE

        r = self._make_mock_redis(ip_fails=1, ip_level_before=0, acct_fails=4, acct_level_before=1)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            with pytest.raises(FE) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", "cedar", "acct-uuid-1", resp)

        detail = exc_info.value.detail
        assert isinstance(detail, dict), f"detail must be a dict, got {type(detail)}"
        assert "banner" in detail

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

        r = self._make_mock_redis(ip_fails=1, ip_level_before=0, acct_fails=99, acct_level_before=3)
        resp = self._make_mock_response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            with pytest.raises(FE) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", "cedar", "acct-uuid-1", resp)

        exc = exc_info.value
        ra_header = int(exc.headers["Retry-After"])
        ra_body = exc.detail.get("retry_after_seconds")
        assert ra_body == ra_header


# ---------------------------------------------------------------------------
# Account bucket key — LAURA-412-MEDIUM
# ---------------------------------------------------------------------------

class TestAccountBucketKey:

    def test_real_account_keys_on_account_id(self):
        mod = _import_module_symbols()
        key = mod._account_bucket_key("alice", "11111111-1111-1111-1111-111111111111")
        assert key == "id:11111111-1111-1111-1111-111111111111"

    def test_case_variants_of_a_real_account_share_no_bucket_when_ids_differ(self):
        """
        The whole point of the fix: two DIFFERENT account_ids (as would be
        the case for two distinct, case-variant accounts) must produce two
        DIFFERENT bucket keys, even though the underlying username strings
        only differ by case.
        """
        mod = _import_module_symbols()
        key_a = mod._account_bucket_key("collision-probe-a", "aaaaaaaa-0000-0000-0000-000000000001")
        key_b = mod._account_bucket_key("COLLISION-PROBE-A", "bbbbbbbb-0000-0000-0000-000000000002")
        assert key_a != key_b, "distinct account_ids must never collide, regardless of username casing"

    def test_nonexistent_username_falls_back_to_hash(self):
        mod = _import_module_symbols()
        key = mod._account_bucket_key("nonexistent_attacker_probe", None)
        assert key.startswith("unk:")

    def test_fallback_hash_still_casefolds_for_nonexistent_usernames(self):
        """
        Casefolding is safe (and even helpful) for the NONEXISTENT-username
        fallback only, since it can never collide with a real account_id
        bucket (different key namespace/prefix entirely).
        """
        mod = _import_module_symbols()
        key_a = mod._account_bucket_key("Nonexistent-Probe", None)
        key_b = mod._account_bucket_key("nonexistent-probe", None)
        assert key_a == key_b


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
        Any level above the table caps at the bounded maximum (900s) — it
        must NEVER grow beyond that, and there is no separate "permanent"
        sentinel value or behaviour.
        """
        fn = self._get_delay_fn()
        for level in (6, 7, 50, 99, 10_000):
            assert fn(level) == 900, f"level={level} must cap at 900s, got {fn(level)}"
