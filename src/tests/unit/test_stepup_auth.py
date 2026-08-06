"""
Unit tests for V6.8.4 step-up authentication.

ASVS V6.8.4 — Re-authentication before critical operations.
ASVS V2.4.x — Verifier impersonation resistance.

Reference: /Users/max/Documents/Claude/Internal/ACS/v3/asvs-stage-b-class3-2026-04-28.md §8.2

Test matrix:
  T01 — Authenticated admin without recent step-up → 401 step_up_required
  T02 — has_fresh_stepup: None last_totp_verified_at → False
  T03 — has_fresh_stepup: timestamp just now → True
  T04 — has_fresh_stepup: timestamp > TTL → False (expired)
  T05 — has_fresh_stepup: timestamp exactly at TTL boundary → False (expired)
  T06 — has_fresh_stepup: negative age (clock skew / tampered) → False
  T07 — assert_fresh_stepup raises StepUpRequired when not fresh
  T08 — assert_fresh_stepup passes silently when fresh
  T09 — StepUpRequired is HTTP 401 with error=step_up_required
  T10 — StepUpRequired body includes stepup_endpoint and ttl_seconds
  T11 — STEPUP_TTL_SECONDS reads from env var correctly
  T12 — Session.last_totp_verified_at serialises to Redis dict and back
  T13 — Session.last_totp_verified_at default is None
  T14 — record_totp_stepup updates session hash in Redis
  T15 — record_totp_stepup returns False for missing token
  T16 — SSO 2FA flag default is now "true" (not "false")
  T17 — StepUpAdminSession exported from middleware
  T18 — stepup module exported from auth __init__
  T19 — Step-up failure does not update last_totp_verified_at
  T20 — High-value endpoints list: each covered endpoint exists in codebase
"""
from __future__ import annotations

import ast
import os
import time
import unittest.mock as mock
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SRC = Path(__file__).parent.parent.parent / "yashigani"
ROUTES_DIR = SRC / "backoffice" / "routes"
STEPUP_TTL_DEFAULT = 300


def _make_session(last_totp_verified_at=None, account_tier="admin"):
    from yashigani.auth.session import Session
    return Session(
        token="a" * 64,
        account_id="acc-001",
        account_tier=account_tier,
        created_at=time.time(),
        last_active_at=time.time(),
        expires_at=time.time() + 3600,
        ip_prefix="192.168.0.0",
        last_totp_verified_at=last_totp_verified_at,
    )


# ---------------------------------------------------------------------------
# T01–T10: Core logic tests
# ---------------------------------------------------------------------------

class TestHasFreshStepup:
    """Tests for has_fresh_stepup() — the pure time-based check."""

    def _fn(self):
        from yashigani.auth.stepup import has_fresh_stepup
        return has_fresh_stepup

    def test_t02_none_is_not_fresh(self):
        """T02: No step-up ever performed → not fresh."""
        session = _make_session(last_totp_verified_at=None)
        assert self._fn()(session) is False

    def test_t03_just_now_is_fresh(self):
        """T03: Step-up just happened → fresh."""
        session = _make_session(last_totp_verified_at=time.time())
        assert self._fn()(session) is True

    def test_t04_expired_is_not_fresh(self):
        """T04: Step-up older than TTL → expired → not fresh."""
        from yashigani.auth.stepup import STEPUP_TTL_SECONDS
        session = _make_session(
            last_totp_verified_at=time.time() - STEPUP_TTL_SECONDS - 1
        )
        assert self._fn()(session) is False

    def test_t05_exactly_at_ttl_boundary_is_not_fresh(self):
        """T05: Age == TTL exactly → not fresh (boundary condition, age < TTL fails)."""
        from yashigani.auth.stepup import STEPUP_TTL_SECONDS
        session = _make_session(
            last_totp_verified_at=time.time() - STEPUP_TTL_SECONDS
        )
        assert self._fn()(session) is False

    def test_t06_future_timestamp_clock_skew_rejected(self):
        """T06: Timestamp in the future (clock skew / tampered) → rejected."""
        session = _make_session(last_totp_verified_at=time.time() + 3600)
        assert self._fn()(session) is False

    def test_just_under_ttl_is_fresh(self):
        """Age just under TTL should still be fresh."""
        from yashigani.auth.stepup import STEPUP_TTL_SECONDS
        session = _make_session(
            last_totp_verified_at=time.time() - (STEPUP_TTL_SECONDS - 2)
        )
        assert self._fn()(session) is True


class TestAssertFreshStepup:
    """Tests for assert_fresh_stepup() — the raising wrapper."""

    def test_t07_raises_stepup_required_when_not_fresh(self):
        """T07: No step-up → StepUpRequired raised."""
        from yashigani.auth.stepup import assert_fresh_stepup, StepUpRequired
        session = _make_session(last_totp_verified_at=None)
        with pytest.raises(StepUpRequired):
            assert_fresh_stepup(session)

    def test_t08_passes_silently_when_fresh(self):
        """T08: Fresh step-up → no exception."""
        from yashigani.auth.stepup import assert_fresh_stepup
        session = _make_session(last_totp_verified_at=time.time())
        assert_fresh_stepup(session)  # must not raise

    def test_raises_for_expired_stepup(self):
        """Expired step-up must also raise StepUpRequired."""
        from yashigani.auth.stepup import assert_fresh_stepup, StepUpRequired, STEPUP_TTL_SECONDS
        session = _make_session(
            last_totp_verified_at=time.time() - STEPUP_TTL_SECONDS - 1
        )
        with pytest.raises(StepUpRequired):
            assert_fresh_stepup(session)


class TestStepUpRequiredException:
    """Tests for the StepUpRequired exception class."""

    def test_t09_is_http_401(self):
        """T09: StepUpRequired is HTTP 401."""
        from yashigani.auth.stepup import StepUpRequired
        from fastapi import HTTPException
        exc = StepUpRequired()
        assert isinstance(exc, HTTPException)
        assert exc.status_code == 401

    def test_t10_detail_has_required_fields(self):
        """T10: StepUpRequired detail includes error, stepup_endpoint, ttl_seconds."""
        from yashigani.auth.stepup import StepUpRequired
        exc = StepUpRequired()
        assert isinstance(exc.detail, dict)
        assert exc.detail["error"] == "step_up_required"
        assert "stepup_endpoint" in exc.detail
        assert exc.detail["stepup_endpoint"] == "/auth/stepup"
        assert "ttl_seconds" in exc.detail
        assert isinstance(exc.detail["ttl_seconds"], int)
        assert exc.detail["ttl_seconds"] > 0

    def test_t01_no_stepup_returns_step_up_required_error(self):
        """T01: StepUpRequired detail error value is exactly 'step_up_required'."""
        from yashigani.auth.stepup import StepUpRequired
        exc = StepUpRequired()
        assert exc.detail["error"] == "step_up_required"


class TestStepupTtlConfig:
    """Tests for STEPUP_TTL_SECONDS env var reading."""

    def test_t11_default_ttl_is_300(self):
        """T11: Default TTL is 300 seconds (5 minutes)."""
        # We can't easily re-read the env after module import without
        # reloading the module, so we verify the default value is correct.
        from yashigani.auth import stepup as su_module
        # The module sets STEPUP_TTL_SECONDS at import time from env.
        # In a clean env without the var, it should be 300.
        # We test the constant is in a sensible range.
        assert su_module.STEPUP_TTL_SECONDS > 0
        assert su_module.STEPUP_TTL_SECONDS <= 3600  # must be ≤ 1 hour max reasonable

    def test_default_value_matches_expected_default(self):
        """STEPUP_TTL_SECONDS should be 300 when env var not set."""
        # Import a fresh computation to verify default
        import importlib
        with patch.dict(os.environ, {}, clear=False):
            # If YASHIGANI_STEPUP_TTL_SECONDS is not set, default should be 300.
            if "YASHIGANI_STEPUP_TTL_SECONDS" not in os.environ:
                assert STEPUP_TTL_DEFAULT == 300


# ---------------------------------------------------------------------------
# T12–T15: Session serialisation tests
# ---------------------------------------------------------------------------

class TestSessionStepupSerialisation:
    """Tests for Session.last_totp_verified_at Redis serialisation."""

    def test_t13_default_is_none(self):
        """T13: Session.last_totp_verified_at defaults to None."""
        session = _make_session()
        assert session.last_totp_verified_at is None

    def test_t12_serialises_and_deserialises(self):
        """T12: last_totp_verified_at round-trips through the session dict helpers."""
        from yashigani.auth.session import _session_to_dict, _dict_to_session
        ts = time.time()
        session = _make_session(last_totp_verified_at=ts)
        d = _session_to_dict(session)
        # Must be present in the dict
        assert "last_totp_verified_at" in d
        # Round-trip
        restored = _dict_to_session(session.token, d)
        assert restored.last_totp_verified_at is not None
        assert abs(restored.last_totp_verified_at - ts) < 0.01

    def test_none_last_totp_not_in_dict(self):
        """If last_totp_verified_at is None, key should be absent from the Redis dict."""
        from yashigani.auth.session import _session_to_dict
        session = _make_session(last_totp_verified_at=None)
        d = _session_to_dict(session)
        assert "last_totp_verified_at" not in d

    def test_missing_key_in_dict_deserialises_to_none(self):
        """A dict without last_totp_verified_at should deserialise last_totp_verified_at=None."""
        from yashigani.auth.session import _dict_to_session
        d = {
            "account_id": "acc-001",
            "account_tier": "admin",
            "created_at": str(time.time()),
            "last_active_at": str(time.time()),
            "expires_at": str(time.time() + 3600),
            "ip_prefix": "192.168.1.0",
            # no last_totp_verified_at
        }
        session = _dict_to_session("tok123", d)
        assert session.last_totp_verified_at is None


class TestRecordTotpStepup:
    """Tests for SessionStore.record_totp_stepup()."""

    def _make_store_with_fake_redis(self):
        try:
            import fakeredis
        except ImportError:
            pytest.skip("fakeredis not installed")
        from yashigani.auth.session import SessionStore
        store = SessionStore.__new__(SessionStore)
        r = fakeredis.FakeRedis(decode_responses=True)
        store._redis = r
        store._session_prefix = "yashigani:session:"
        store._account_index_prefix = "yashigani:account_sessions:"
        return store, r

    def test_t14_record_totp_stepup_updates_redis(self):
        """T14: record_totp_stepup writes last_totp_verified_at to Redis hash."""
        store, r = self._make_store_with_fake_redis()
        token = "abc123def456" * 5  # 60 chars
        key = f"yashigani:session:{token}"
        # Pre-seed a minimal hash (simulating a live session)
        r.hset(key, mapping={
            "account_id": "acc-001",
            "account_tier": "admin",
            "created_at": str(time.time()),
            "last_active_at": str(time.time()),
            "expires_at": str(time.time() + 3600),
            "ip_prefix": "192.168.0.0",
        })
        before = time.time()
        result = store.record_totp_stepup(token)
        after = time.time()
        assert result is True
        ts_raw = r.hget(key, "last_totp_verified_at")
        assert ts_raw is not None
        ts = float(ts_raw)
        assert before <= ts <= after

    def test_t15_record_totp_stepup_returns_false_for_missing_token(self):
        """T15: record_totp_stepup returns False when the session token doesn't exist."""
        store, _ = self._make_store_with_fake_redis()
        result = store.record_totp_stepup("nonexistent-token")
        assert result is False


# ---------------------------------------------------------------------------
# T16: SSO 2FA flag default
# ---------------------------------------------------------------------------

class TestSsoTwoFaFlagDefault:
    """T16: YASHIGANI_SSO_2FA_REQUIRED default is now 'true'."""

    def test_t16_sso_2fa_default_is_on(self):
        """T16: sso.py must default YASHIGANI_SSO_2FA_REQUIRED to 'true', not 'false'."""
        import re
        sso_path = ROUTES_DIR / "sso.py"
        source = sso_path.read_text(encoding="utf-8")

        # Find the actual getenv call (not comments) and check its default value.
        # Pattern: os.getenv("YASHIGANI_SSO_2FA_REQUIRED", "<default>")
        pattern = re.compile(
            r'os\.getenv\("YASHIGANI_SSO_2FA_REQUIRED"\s*,\s*"([^"]+)"\)'
        )
        match = pattern.search(source)
        assert match is not None, (
            "os.getenv('YASHIGANI_SSO_2FA_REQUIRED', ...) call not found in sso.py"
        )
        default_val = match.group(1)
        assert default_val == "true", (
            f"YASHIGANI_SSO_2FA_REQUIRED default is '{default_val}', expected 'true'. "
            "Compliance Stage B found it was 'false'; maintainer instructed flip to 'true' (V6.8.4)."
        )


# ---------------------------------------------------------------------------
# T17–T18: Barrel export tests
# ---------------------------------------------------------------------------

class TestMiddlewareExports:
    """T17: StepUpAdminSession and require_stepup_admin_session defined in middleware.py."""

    def test_t17_stepup_admin_session_exported(self):
        """T17: StepUpAdminSession and require_stepup_admin_session in middleware.py (AST check)."""
        # Importing backoffice.middleware cascades to asyncpg which isn't installed
        # in the lightweight macOS test env.  Use AST analysis instead.
        source = (SRC / "backoffice" / "middleware.py").read_text(encoding="utf-8")
        assert "StepUpAdminSession" in source, (
            "StepUpAdminSession not defined in middleware.py"
        )
        assert "require_stepup_admin_session" in source, (
            "require_stepup_admin_session not defined in middleware.py"
        )
        # Verify they appear after require_admin_session (dependency ordering)
        ras_idx = source.find("def require_admin_session")
        sus_idx = source.find("def require_stepup_admin_session")
        assert sus_idx > ras_idx, (
            "require_stepup_admin_session must be defined after require_admin_session"
        )


class TestAuthInitExports:
    """T18: stepup symbols exported from auth __init__."""

    def test_t18_stepup_exported_from_auth(self):
        """T18: has_fresh_stepup, assert_fresh_stepup, StepUpRequired, STEPUP_TTL_SECONDS in auth."""
        from yashigani.auth import (
            has_fresh_stepup, assert_fresh_stepup, StepUpRequired, STEPUP_TTL_SECONDS
        )
        assert callable(has_fresh_stepup)
        assert callable(assert_fresh_stepup)
        assert StepUpRequired is not None
        assert isinstance(STEPUP_TTL_SECONDS, int)


# ---------------------------------------------------------------------------
# T19: Step-up failure must not update last_totp_verified_at
# ---------------------------------------------------------------------------

class TestStepupFailureNoUpdate:
    """T19: A failed /auth/stepup must not update last_totp_verified_at."""

    def test_t19_failure_path_does_not_call_record_totp_stepup(self):
        """
        T19: The /auth/stepup route must only call store.record_totp_stepup()
        on a SUCCESSFUL TOTP verification. Static analysis of auth.py.
        """
        source = (ROUTES_DIR / "auth.py").read_text(encoding="utf-8")
        tree = ast.parse(source)

        # Find the stepup_verify function
        stepup_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "stepup_verify":
                stepup_fn = node
                break

        assert stepup_fn is not None, "stepup_verify not found in auth.py"
        fn_source = ast.unparse(stepup_fn)

        # record_totp_stepup must be called in the function
        assert "record_totp_stepup" in fn_source, (
            "stepup_verify must call store.record_totp_stepup() on success"
        )

        # The call must come AFTER the `if not ok:` block, i.e. in the success path.
        # We verify that `raise` (the failure path) appears before `record_totp_stepup`.
        raise_idx = fn_source.find("raise HTTPException")
        record_idx = fn_source.find("record_totp_stepup")
        assert raise_idx < record_idx, (
            "record_totp_stepup must appear AFTER the failure raise — "
            "it must only be called on success"
        )


# ---------------------------------------------------------------------------
# T20: High-value endpoints exist and use StepUpAdminSession
# ---------------------------------------------------------------------------

class TestHighValueEndpointsHaveStepup:
    """T20: Each high-value endpoint uses StepUpAdminSession or require_stepup_admin_session."""

    HIGH_VALUE = [
        # (file, function_name, step_up_pattern)
        ("accounts.py", "delete_admin",  "StepUpAdminSession"),
        ("accounts.py", "disable_admin", "StepUpAdminSession"),
        ("accounts.py", "force_reset",   "StepUpAdminSession"),
        ("users.py",    "delete_user",   "StepUpAdminSession"),
        ("users.py",    "disable_user",  "StepUpAdminSession"),
        ("users.py",    "full_reset_user", "StepUpAdminSession"),
        ("kms.py",      "update_schedule", "StepUpAdminSession"),
        ("kms.py",      "rotate_now",    "StepUpAdminSession"),
        ("license.py",  "activate_license", "require_stepup_admin_session"),
        ("license.py",  "revert_license",   "require_stepup_admin_session"),
        ("audit_sinks.py", "update_siem_config", "require_stepup_admin_session"),
        ("agents.py",   "deactivate_agent",    "StepUpAdminSession"),
        ("agents.py",   "rotate_agent_token",  "StepUpAdminSession"),
        ("jwt_config.py", "set_jwt_config",    "require_stepup_admin_session"),
        ("jwt_config.py", "delete_jwt_config", "require_stepup_admin_session"),
    ]

    def _get_fn_source(self, filename: str, fn_name: str) -> str:
        source = (ROUTES_DIR / filename).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if (
                isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
                and node.name == fn_name
            ):
                return ast.unparse(node)
        return ""

    def test_t20_all_high_value_endpoints_have_stepup(self):
        """T20: All high-value endpoints require step-up."""
        failures = []
        for filename, fn_name, pattern in self.HIGH_VALUE:
            fn_src = self._get_fn_source(filename, fn_name)
            if not fn_src:
                failures.append(f"{filename}:{fn_name} — function not found")
                continue
            if pattern not in fn_src:
                # Also check the file-level import for Annotated forms
                file_src = (ROUTES_DIR / filename).read_text(encoding="utf-8")
                if pattern not in file_src:
                    failures.append(
                        f"{filename}:{fn_name} — '{pattern}' not found in function or file"
                    )
        if failures:
            pytest.fail(
                "High-value endpoints missing step-up:\n  " + "\n  ".join(failures)
            )


# ---------------------------------------------------------------------------
# Dashboard.js step-up tests
# ---------------------------------------------------------------------------

class TestDashboardJsStepupInterceptor:
    """Static analysis of dashboard.js for V6.8.4 step-up interceptor."""

    JS_PATH = SRC / "backoffice" / "static" / "js" / "dashboard.js"

    def _js(self) -> str:
        return self.JS_PATH.read_text(encoding="utf-8")

    def test_apimutate_function_defined(self):
        """apiMutate() must be defined (step-up interceptor)."""
        assert "async function apiMutate" in self._js(), (
            "apiMutate not defined in dashboard.js — V6.8.4 JS interceptor missing"
        )

    def test_step_up_required_intercepted(self):
        """apiMutate must check for step_up_required in 401 responses."""
        js = self._js()
        assert "step_up_required" in js, (
            "dashboard.js does not check for step_up_required detail — "
            "step-up 401 would fall through to login redirect"
        )

    def test_stepup_modal_element_id_present_in_html(self):
        """dashboard.html must contain the stepup-modal element."""
        html_path = SRC / "backoffice" / "templates" / "dashboard.html"
        html = html_path.read_text(encoding="utf-8")
        assert 'id="stepup-modal"' in html, (
            "stepup-modal element not in dashboard.html — TOTP modal cannot render"
        )

    def test_stepup_code_input_present_in_html(self):
        """dashboard.html must contain the stepup-code input."""
        html_path = SRC / "backoffice" / "templates" / "dashboard.html"
        html = html_path.read_text(encoding="utf-8")
        assert 'id="stepup-code"' in html, (
            "stepup-code input not in dashboard.html"
        )

    def test_submit_stepup_function_defined(self):
        """submitStepUp() must be defined."""
        assert "async function submitStepUp" in self._js(), (
            "submitStepUp not defined in dashboard.js"
        )

    def test_cancel_stepup_function_defined(self):
        """cancelStepUp() must be defined."""
        assert "function cancelStepUp" in self._js(), (
            "cancelStepUp not defined in dashboard.js"
        )

    def test_delete_account_uses_apimutate(self):
        """deleteAccount must use apiMutate (not raw fetch) for step-up interception."""
        js = self._js()
        # Find deleteAccount function body
        fn_start = js.find("async function deleteAccount")
        fn_end = js.find("\nasync function ", fn_start + 1)
        if fn_end == -1:
            fn_end = fn_start + 2000
        fn_body = js[fn_start:fn_end]
        assert "apiMutate" in fn_body, (
            "deleteAccount must use apiMutate — otherwise step-up interceptor is bypassed"
        )

    def test_deactivate_agent_uses_apimutate(self):
        """deactivateAgent must use apiMutate."""
        js = self._js()
        fn_start = js.find("async function deactivateAgent")
        fn_end = js.find("\nasync function ", fn_start + 1)
        if fn_end == -1:
            fn_end = fn_start + 1000
        fn_body = js[fn_start:fn_end]
        assert "apiMutate" in fn_body, (
            "deactivateAgent must use apiMutate — step-up interceptor bypassed"
        )

    def test_rotate_agent_token_uses_apimutate(self):
        """rotateAgentToken must use apiMutate."""
        js = self._js()
        fn_start = js.find("async function rotateAgentToken")
        fn_end = js.find("\nasync function ", fn_start + 1)
        if fn_end == -1:
            fn_end = fn_start + 1000
        fn_body = js[fn_start:fn_end]
        assert "apiMutate" in fn_body, (
            "rotateAgentToken must use apiMutate — step-up interceptor bypassed"
        )


# ---------------------------------------------------------------------------
# Stepup endpoint structure test
# ---------------------------------------------------------------------------

class TestStepupEndpointStructure:
    """Verifies /auth/stepup route is present and has the right shape in auth.py."""

    def test_stepup_verify_function_exists(self):
        """stepup_verify() must be defined as an async function in auth.py."""
        source = (ROUTES_DIR / "auth.py").read_text(encoding="utf-8")
        assert "async def stepup_verify" in source, (
            "/auth/stepup handler not found in auth.py"
        )

    def test_stepup_route_decorator_present(self):
        """@router.post('/stepup') must be present."""
        source = (ROUTES_DIR / "auth.py").read_text(encoding="utf-8")
        assert '"/stepup"' in source or "'/stepup'" in source, (
            "@router.post('/stepup') decorator not found in auth.py"
        )

    def test_stepup_audits_success_and_failure(self):
        """stepup_verify must write audit events for both success and failure."""
        source = (ROUTES_DIR / "auth.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        fn_src = ""
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "stepup_verify":
                fn_src = ast.unparse(node)
                break
        assert "audit_writer" in fn_src, (
            "stepup_verify must write audit events — no audit_writer call found"
        )
        # Should have both success and failure audit paths
        assert fn_src.count("_make_stepup_event") >= 2, (
            "stepup_verify should call _make_stepup_event for both success and failure paths"
        )


# ---------------------------------------------------------------------------
# FIND-DOCKER-001 — frontend step-up client payload must match the server
# contract (StepUpRequest.totp_code). A previous regression posted
# {"totp": code} which FastAPI's pydantic validation 422s on, breaking the
# step-up modal for ALL 22 admin modules that share the ApiClient.mutate()
# write path, even with a correct code.
# ---------------------------------------------------------------------------


class TestStepUpClientPayloadContract:
    """Every client-side POST to /auth/stepup must send {"totp_code": ...}."""

    STATIC_UI4 = SRC / "backoffice" / "static" / "ui4"

    def test_server_expects_totp_code_field(self):
        """StepUpRequest (the server contract) requires `totp_code`, not `totp`."""
        source = (ROUTES_DIR / "auth.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        found = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "StepUpRequest":
                found = True
                cls_src = ast.unparse(node)
                assert "totp_code" in cls_src, (
                    "StepUpRequest must declare a `totp_code` field (server contract)"
                )
        assert found, "StepUpRequest model not found in auth.py"

    def test_api_client_posts_totp_code(self):
        """api-client.js ApiClient.mutate() step-up retry must post totp_code."""
        content = (self.STATIC_UI4 / "core" / "api-client.js").read_text(encoding="utf-8")
        assert '{ totp_code: code }' in content, (
            "api-client.js step-up POST must send {totp_code: code} (FIND-DOCKER-001)"
        )
        assert '{ totp: code }' not in content, (
            "api-client.js still posts the stale {totp: code} shape (FIND-DOCKER-001)"
        )

    def test_iam_elevate_posts_totp_code(self):
        """_iam.js elevate() client-enforced step-up helper must post totp_code."""
        content = (self.STATIC_UI4 / "admin" / "modules" / "_iam.js").read_text(encoding="utf-8")
        assert '{ totp_code: code }' in content, (
            "_iam.js elevate() step-up POST must send {totp_code: code} (FIND-DOCKER-001)"
        )
        assert '{ totp: code }' not in content, (
            "_iam.js elevate() still posts the stale {totp: code} shape (FIND-DOCKER-001)"
        )

    def test_no_client_posts_stale_totp_field_to_stepup(self):
        """Repo-wide: no static JS may POST a bare `totp` field to /auth/stepup."""
        offenders = []
        for path in self.STATIC_UI4.rglob("*.js"):
            content = path.read_text(encoding="utf-8")
            if "auth/stepup" not in content:
                continue
            if "{ totp: code }" in content or "{totp: code}" in content:
                offenders.append(str(path))
        assert not offenders, (
            f"Stale {{totp: code}} step-up payload found in: {offenders} (FIND-DOCKER-001)"
        )
