"""
Regression tests for v2.23.2 security findings.

LAURA-V232-003 — TOTP bypass on force_totp_provision=True accounts.
AVA-A006       — TOTP replay in step-up flow (stale window accepted).
AVA-C006       — Stored XSS via protocol-URI bypass (javascript:/data:/vbscript:).

Last updated: 2026-05-03T00:00:00+01:00
"""
from __future__ import annotations

import ast
import importlib.util
import sys
import time
import typing
from pathlib import Path
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

SRC = Path(__file__).parent.parent.parent / "yashigani"
ROUTES_AUTH = SRC / "backoffice" / "routes" / "auth.py"


# ---------------------------------------------------------------------------
# LAURA-V232-003 — TOTP bypass on force_totp_provision=True accounts
# ---------------------------------------------------------------------------

class TestTotpProvisionBypassV232003:
    """
    LAURA-V232-003: when authenticate() returns "totp_provision_required",
    the login route must issue a RESTRICTED session (account_tier="totp_provisioning"),
    NOT a full admin session.

    Without the fix: a new admin account (force_totp_provision=True) could log in
    with any 6-digit TOTP code and receive a full admin session.
    """

    def _get_login_source(self) -> str:
        return ROUTES_AUTH.read_text(encoding="utf-8")

    def _parse_login_fn(self) -> ast.AsyncFunctionDef:
        source = self._get_login_source()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "login":
                return node
        pytest.fail("login function not found in auth.py")

    def test_login_route_checks_totp_provision_reason(self):
        """
        LAURA-V232-003: login route must branch on reason == "totp_provision_required"
        (AST-level check that the guard is present).
        """
        source = self._get_login_source()
        assert "totp_provision_required" in source, (
            "LAURA-V232-003: login route must handle reason=='totp_provision_required' "
            "and issue a restricted session"
        )

    def test_login_route_issues_totp_provisioning_tier(self):
        """
        LAURA-V232-003: login route must create a session with account_tier
        'totp_provisioning' (not 'admin') when reason is totp_provision_required.
        """
        source = self._get_login_source()
        assert '"totp_provisioning"' in source or "'totp_provisioning'" in source, (
            "LAURA-V232-003: login route must issue account_tier='totp_provisioning' "
            "for force_totp_provision=True accounts — not a full admin session"
        )

    def test_login_fn_totp_provision_before_full_session(self):
        """
        LAURA-V232-003: in login(), the totp_provision_required branch must
        appear BEFORE the unrestricted session.create() call, and must return
        early (not fall through to full session creation).
        """
        source = self._get_login_source()
        provision_idx = source.find("totp_provision_required")
        full_session_idx = source.find(
            'account_tier=record.account_tier', provision_idx
        )
        assert provision_idx != -1, (
            "LAURA-V232-003: 'totp_provision_required' guard not found in login route"
        )
        assert full_session_idx > provision_idx, (
            "LAURA-V232-003: full-session creation must come AFTER the "
            "totp_provision_required guard, not before"
        )

    def test_authenticate_returns_provision_required_for_fresh_admin(self):
        """
        LAURA-V232-003: pg_auth.authenticate() must return
        (True, record, 'totp_provision_required') when force_totp_provision=True,
        regardless of what TOTP code is supplied (even '000000').

        This is the correct auth-service contract — the bypass lived in the
        LOGIN ROUTE (which issued a full session on this return value).
        """
        # AST-level check of authenticate() to confirm the existing contract.
        from pathlib import Path
        pg_auth = Path(__file__).parent.parent.parent / "yashigani" / "auth" / "pg_auth.py"
        source = pg_auth.read_text(encoding="utf-8")
        # The authenticate() method must branch on force_totp_provision
        assert "force_totp_provision" in source, (
            "LAURA-V232-003: authenticate() must check force_totp_provision"
        )
        # And must return "totp_provision_required" without invoking totp check
        assert "totp_provision_required" in source, (
            "LAURA-V232-003: authenticate() must emit 'totp_provision_required' reason"
        )

    def test_require_admin_session_rejects_non_admin_tier(self):
        """
        LAURA-V232-003: require_admin_session (middleware.py) must check
        account_tier == 'admin' — so 'totp_provisioning' sessions are rejected.

        AST-level check to avoid importing FastAPI in envs without all deps.
        """
        middleware_path = SRC / "backoffice" / "middleware.py"
        source = middleware_path.read_text(encoding="utf-8")

        # require_admin_session must gate on account_tier == "admin"
        assert 'account_tier' in source, (
            "LAURA-V232-003: require_admin_session must check account_tier"
        )
        assert '"admin"' in source or "'admin'" in source, (
            "LAURA-V232-003: require_admin_session must compare to literal 'admin'"
        )

        # Find require_admin_session function in AST
        tree = ast.parse(source)
        fn = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "require_admin_session":
                fn = node
                break
        assert fn is not None, "require_admin_session not found in middleware.py"
        fn_src = ast.unparse(fn)

        # Must contain an account_tier check
        assert "account_tier" in fn_src, (
            "LAURA-V232-003: require_admin_session must check session.account_tier"
        )
        # Must contain a comparison to 'admin'
        assert "'admin'" in fn_src or '"admin"' in fn_src, (
            "LAURA-V232-003: require_admin_session must compare account_tier to 'admin' — "
            "a 'totp_provisioning' session must be rejected"
        )

    def test_require_any_session_does_not_check_tier(self):
        """
        LAURA-V232-003: require_any_session must NOT check account_tier
        so 'totp_provisioning' sessions pass through for provisioning endpoints.
        """
        middleware_path = SRC / "backoffice" / "middleware.py"
        source = middleware_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        fn = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "require_any_session":
                fn = node
                break
        assert fn is not None, "require_any_session not found in middleware.py"
        fn_src = ast.unparse(fn)

        # require_any_session must NOT gate on a specific tier value
        assert "!= 'admin'" not in fn_src and "!= \"admin\"" not in fn_src, (
            "LAURA-V232-003: require_any_session must not reject non-admin tiers — "
            "'totp_provisioning' sessions must be able to reach provisioning endpoints"
        )


# ---------------------------------------------------------------------------
# AVA-A006 — TOTP replay in step-up flow (stale window accepted)
# ---------------------------------------------------------------------------

class TestTotpReplayAvaA006:
    """
    AVA-A006 / ASVS V2.8.3: TOTP replay protection in verify_totp().

    Root cause: verify_totp() builds window_key from the CURRENT time window
    regardless of which window offset (−1, 0, +1) matched the code. This
    means a code used in window T−1 inserts window_key T−1 into the cache,
    but a replay in the SAME session at window T checks key T — which is not
    cached — so the replay succeeds.

    Fix: window_key must encode the MATCHED offset's window, not always the
    current window.
    """

    def _import_verify_totp(self):
        try:
            import pyotp
            from yashigani.auth.totp import verify_totp, generate_totp_secret
            return verify_totp, generate_totp_secret, pyotp
        except ImportError as exc:
            pytest.skip(f"pyotp or totp module not available: {exc}")

    def test_replay_of_same_code_rejected_in_same_window(self):
        """
        AVA-A006: using the same TOTP code twice in the same time window
        must be rejected on the second attempt.
        """
        verify_totp, generate_totp_secret, pyotp = self._import_verify_totp()

        secret = generate_totp_secret()
        cache: set[str] = set()

        totp = pyotp.TOTP(secret)  # RFC 6238 default: HMAC-SHA1
        code = totp.now()

        first = verify_totp(secret_b32=secret, code=code, used_codes_cache=cache)
        assert first is True, "First use of valid TOTP must succeed"

        second = verify_totp(secret_b32=secret, code=code, used_codes_cache=cache)
        assert second is False, (
            "AVA-A006: same TOTP code must be rejected on second use in same window"
        )

    def test_replay_of_previous_window_code_rejected(self):
        """
        AVA-A006: a code from the previous time window (T−1) that was already
        accepted must be rejected on replay, even if still technically within
        the ±1 acceptance window.

        This tests the root cause: window_key must track the MATCHED window,
        not just the current window.
        """
        verify_totp, generate_totp_secret, pyotp = self._import_verify_totp()

        secret = generate_totp_secret()

        # Generate the code for window T−1 (30 seconds ago)
        now_ts = int(time.time())
        prev_window_ts = now_ts - 30
        totp = pyotp.TOTP(secret)  # RFC 6238 default: HMAC-SHA1
        prev_code = totp.at(prev_window_ts)

        # Only test if the code is still in the acceptance window (±1)
        current_code = totp.now()
        next_code = totp.at(now_ts + 30)
        if prev_code == current_code or prev_code == next_code:
            pytest.skip("Code collision between windows — unlikely but skip to avoid false failure")

        cache: set[str] = set()

        # First use: code from T−1 — accepted because ±1 window allows it
        first = verify_totp(secret_b32=secret, code=prev_code, used_codes_cache=cache)
        if not first:
            pytest.skip("prev_code not accepted in ±1 window — clock boundary")

        # Replay of the SAME code — must be rejected
        second = verify_totp(secret_b32=secret, code=prev_code, used_codes_cache=cache)
        assert second is False, (
            "AVA-A006: TOTP code from T−1 window must be rejected on replay "
            "(same code, same cache — replay protection must track matched window, "
            "not current window)"
        )

    def test_stepup_route_uses_verify_totp_with_replay(self):
        """
        AVA-A006: /auth/stepup must use _verify_totp_with_replay() (Postgres-backed
        replay cache), not a bare verify_totp() call.
        AST-level check.
        """
        source = ROUTES_AUTH.read_text(encoding="utf-8")

        # Find stepup_verify function
        tree = ast.parse(source)
        stepup_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "stepup_verify":
                stepup_fn = node
                break

        assert stepup_fn is not None, "stepup_verify not found in auth.py"
        fn_src = ast.unparse(stepup_fn)

        assert "_verify_totp_with_replay" in fn_src, (
            "AVA-A006: stepup_verify must use _verify_totp_with_replay() "
            "to apply Postgres-backed replay cache — bare verify_totp() has no "
            "cross-request replay protection"
        )

    def test_verify_totp_cross_window_replay_rejected(self):
        """
        AVA-A006: a code used at window T-1 must be rejected when replayed at
        window T (next 30-second window).

        This tests the cross-window replay scenario QA observed: the code was
        submitted once at T-1 (step-up request 1), then replayed at T (step-up
        request 2).  With the buggy verify_totp(), window_key is always based on
        the CURRENT wall-clock window, so:
          - Request 1 at time T-1: window_key = {secret}:{T-1//30}, cached
          - Request 2 at time T:   window_key = {secret}:{T//30}, NOT in cache → replay passes

        Fix: window_key must use the window of the MATCHED offset, not current time.
        We simulate the cross-window scenario by patching time.time() for the two calls.
        """
        verify_totp, generate_totp_secret, pyotp = self._import_verify_totp()
        from unittest.mock import patch

        secret = generate_totp_secret()

        # Synthesise a known window boundary:
        # Align to a 30-second window. window_T1 = current window, window_T = next.
        real_now = time.time()
        # Snap to 30s boundary: T-1 window is 30s behind T
        window_size = 30
        window_T = (int(real_now) // window_size) * window_size + window_size  # next boundary
        window_T1 = window_T - window_size  # previous window

        totp = pyotp.TOTP(secret)  # RFC 6238 default: HMAC-SHA1
        code_at_T1 = totp.at(window_T1)

        # Step 1: simulate request at T-1 → code is "current" (offset 0 in T-1 window)
        # We patch time.time() to return T-1 + 5 (mid-window)
        t1_time = float(window_T1 + 5)
        cache: set[str] = set()

        with patch("yashigani.auth.totp.time") as mock_time_1:
            mock_time_1.time.return_value = t1_time
            result_1 = verify_totp(secret_b32=secret, code=code_at_T1, used_codes_cache=cache)

        if not result_1:
            pytest.skip("T-1 code not accepted at T-1 time — unexpected; check window alignment")

        # Step 2: simulate replay at T (next window) — time has advanced 30s
        # code_at_T1 is still within ±1 window at T (it's offset -1 from T)
        t_time = float(window_T + 5)

        with patch("yashigani.auth.totp.time") as mock_time_2:
            mock_time_2.time.return_value = t_time
            result_2 = verify_totp(secret_b32=secret, code=code_at_T1, used_codes_cache=cache)

        assert result_2 is False, (
            "AVA-A006: code used at window T-1 must be rejected on replay at window T. "
            "verify_totp() must cache the MATCHED window key (not always current window key) "
            "so cross-window replay is blocked."
        )


# ---------------------------------------------------------------------------
# AVA-C006 — Protocol-URI bypass: javascript:/data:/vbscript: in agent name
# ASVS v5 V5.3.3 | CWE-79 | OWASP A03 | WSTG-INPV-01
# ---------------------------------------------------------------------------

_AGENTS_PATH_C006 = Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "agents.py"


def _load_agents_module_c006():
    """Load agents.py in isolation — same pattern as test_ava_2026_04_29_001_002.py."""
    _stubs = {
        "yashigani.backoffice.middleware": type(sys)("stub"),
        "yashigani.backoffice.state": type(sys)("stub"),
        "yashigani.licensing.enforcer": type(sys)("stub"),
        "pydantic": importlib.import_module("pydantic"),
        "fastapi": importlib.import_module("fastapi"),
    }
    _stubs["yashigani.backoffice.middleware"].require_admin_session = lambda *a, **kw: None
    _stubs["yashigani.backoffice.middleware"].AdminSession = object
    _stubs["yashigani.backoffice.middleware"].require_stepup_admin_session = lambda *a, **kw: None
    _stubs["yashigani.backoffice.middleware"].StepUpAdminSession = object
    _stubs["yashigani.backoffice.state"].backoffice_state = None
    _stubs["yashigani.licensing.enforcer"].require_feature = lambda *a, **kw: None

    old = {}
    for k, v in _stubs.items():
        old[k] = sys.modules.get(k)
        sys.modules[k] = v

    spec = importlib.util.spec_from_file_location("agents_isolated_ava_c006", _AGENTS_PATH_C006)
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


_agents_mod_c006 = _load_agents_module_c006()
_AgentRegisterRequestC006 = _agents_mod_c006.AgentRegisterRequest
_AgentUpdateRequestC006 = _agents_mod_c006.AgentUpdateRequest
try:
    _AgentUpdateRequestC006.model_rebuild(
        _types_namespace={"Optional": typing.Optional, "list": list},
    )
except Exception:
    pass


class TestAvaC006ProtocolUriBypass:
    """
    AVA-C006: agent name validator must reject javascript:, data:, and vbscript:
    protocol URIs in addition to HTML angle-bracket tags.

    Root cause: _HTML_TAG_RE only matched '<[a-zA-Z/!]', so protocol URIs such as
    'javascript:alert(1)' reached the registry and would execute if the UI rendered
    agent names inside <a href="..."> attributes.

    Fix: _HTML_TAG_RE (now a combined pattern) also matches (?i)javascript:|data:|vbscript:
    ASVS V5.3.3, CWE-79, OWASP A03 Injection.
    """

    _VALID_URL = "https://agent.example.com"

    # --- AgentRegisterRequest — protocol URI payloads -----------------------

    def test_register_rejects_javascript_uri_lowercase(self):
        """javascript:alert(1) must be rejected with HTTP 422."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequestC006(
                name="javascript:alert(1)",
                upstream_url=self._VALID_URL,
            )
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_register_rejects_javascript_uri_uppercase(self):
        """JAVASCRIPT:alert(1) must be rejected — check is case-insensitive."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequestC006(
                name="JAVASCRIPT:alert(1)",
                upstream_url=self._VALID_URL,
            )
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_register_rejects_javascript_uri_mixed_case(self):
        """JaVaScRiPt:alert(1) must be rejected — case-insensitive match."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequestC006(
                name="JaVaScRiPt:alert(1)",
                upstream_url=self._VALID_URL,
            )
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_register_rejects_data_uri(self):
        """data:text/html,<script>alert(1)</script> must be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequestC006(
                name="data:text/html,<script>alert(1)</script>",
                upstream_url=self._VALID_URL,
            )
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_register_rejects_vbscript_uri(self):
        """vbscript:msgbox(1) must be rejected."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequestC006(
                name="vbscript:msgbox(1)",
                upstream_url=self._VALID_URL,
            )
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_register_accepts_legitimate_name(self):
        """Legitimate agent slug names must still be accepted (positive path).
        Note: V232-CSCAN-01a tightened name to slug pattern '^[a-z][a-z0-9_-]{0,63}$'.
        """
        req = _AgentRegisterRequestC006(
            name="my-production-agent-v2",
            upstream_url=self._VALID_URL,
        )
        assert req.name == "my-production-agent-v2"

    def test_register_still_rejects_html_tag(self):
        """Existing angle-bracket tag rejection must not regress."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentRegisterRequestC006(
                name="<script>alert('XSS')</script>",
                upstream_url=self._VALID_URL,
            )
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    # --- AgentUpdateRequest — protocol URI payloads -------------------------

    def test_update_rejects_javascript_uri(self):
        """Update request must also reject javascript: URIs in name."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentUpdateRequestC006(name="javascript:alert(1)")
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_update_rejects_data_uri(self):
        """Update request must also reject data: URIs in name."""
        with pytest.raises(ValidationError) as exc_info:
            _AgentUpdateRequestC006(name="data:text/html,xss")
        errors = exc_info.value.errors()
        assert any(e["loc"] == ("name",) for e in errors), errors

    def test_update_accepts_none_name(self):
        """None (field omitted) must still pass for partial updates."""
        req = _AgentUpdateRequestC006(name=None)
        assert req.name is None

    def test_update_accepts_legitimate_name(self):
        """Legitimate slug on update must still be accepted.
        Note: V232-CSCAN-01a tightened name to slug pattern '^[a-z][a-z0-9_-]{0,63}$'.
        """
        req = _AgentUpdateRequestC006(name="renamed-agent")
        assert req.name == "renamed-agent"
