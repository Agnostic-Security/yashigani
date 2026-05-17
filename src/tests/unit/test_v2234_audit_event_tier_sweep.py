"""
Unit tests — v2.23.4 comprehensive account_tier hardcode sweep (wider class-of-bug).

Covers helpers fixed across routes and auth modules:

Batch 1 (fcc551a) — _make_*_event constructors in auth.py:
  - _make_login_event (auth.py)
  - _make_config_event (auth.py)

Batch 2 (this commit) — wider class of same bug:
  - _config_event in audit.py, users.py, accounts.py, ratelimit.py, inspection.py, kms.py
  - _masking_config_event in audit.py
  - _full_reset_event in users.py
  - _full_reset_totp_failure in users.py
  - _emit_lockout_event in pg_auth.py

ASVS V7.3.4 — Audit log accuracy: account_tier in every event reflects
the actual session/record tier, never a hardcoded literal.

Last updated: 2026-05-17T12:00:00+00:00

Test matrix — Batch 1 (T15-T25):
  T15  — _make_login_event user-tier → account_tier="user"
  T16  — _make_login_event admin-tier (regression) → account_tier="admin"
  T17  — _make_login_event default (pre-auth failure, record=None) → account_tier="admin"
  T18  — _make_config_event user-tier (defence-in-depth) → account_tier="user"
  T19  — _make_config_event admin-tier (regression) → account_tier="admin"
  T20  — _make_config_event default (admin-only route) → account_tier="admin"
  T21  — login success call site passes record.account_tier (structural/AST check)
  T22  — logout call site passes session.account_tier (structural/AST check)
  T23  — self_reset call site passes record.account_tier (structural/AST check)
  T24  — totp_provision_restricted call site passes record.account_tier (structural/AST check)
  T25  — defence-in-depth: non-admin session via _make_login_event records actual tier

Test matrix — Batch 2 (T26-T36):
  T26  — audit._config_event user-tier → account_tier="user"
  T27  — audit._masking_config_event user-tier → account_tier="user"
  T28  — users._config_event user-tier → account_tier="user"
  T29  — users._full_reset_event user-tier → account_tier="user"
  T30  — users._full_reset_totp_failure user-tier → account_tier="user"
  T31  — accounts._config_event user-tier → account_tier="user"
  T32  — ratelimit._config_event user-tier → account_tier="user"
  T33  — inspection._config_event user-tier → account_tier="user"
  T34  — kms._config_event user-tier → account_tier="user"
  T35  — pg_auth._emit_lockout_event user-tier → account_tier="user"
  T36  — structural: no bare account_tier="admin" in helper function bodies (sweep)
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Source text of auth.py — loaded once for structural tests
# ---------------------------------------------------------------------------

_AUTH_PY = (
    Path(__file__).resolve().parents[2]
    / "yashigani" / "backoffice" / "routes" / "auth.py"
).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# T15 — _make_login_event user-tier → account_tier="user"
# ---------------------------------------------------------------------------

class TestT15LoginEventUserTier:
    """T15: _make_login_event called with account_tier='user' produces user-tier event."""

    def test_user_tier_login_event(self):
        from yashigani.backoffice.routes.auth import _make_login_event

        event = _make_login_event("alice", "success", None, account_tier="user")
        assert event.account_tier == "user", (
            f"ASVS V7.3.4: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_user_tier_login_failure_event(self):
        from yashigani.backoffice.routes.auth import _make_login_event

        event = _make_login_event("alice", "failure", "invalid_credentials", account_tier="user")
        assert event.account_tier == "user"

    def test_user_tier_login_logout_event(self):
        from yashigani.backoffice.routes.auth import _make_login_event

        event = _make_login_event("alice", "logout", None, account_tier="user")
        assert event.account_tier == "user"


# ---------------------------------------------------------------------------
# T16 — _make_login_event admin-tier regression guard
# ---------------------------------------------------------------------------

class TestT16LoginEventAdminTierRegression:
    """T16: _make_login_event with admin tier still records 'admin' (regression guard)."""

    def test_admin_tier_login_event(self):
        from yashigani.backoffice.routes.auth import _make_login_event

        event = _make_login_event("superadmin", "success", None, account_tier="admin")
        assert event.account_tier == "admin"


# ---------------------------------------------------------------------------
# T17 — _make_login_event default → account_tier="admin" (pre-auth failure)
# ---------------------------------------------------------------------------

class TestT17LoginEventDefault:
    """T17: default account_tier="admin" preserved for pre-auth failure call site.

    In login(), authenticate() can return (False, None, reason) — record is None.
    The constructor must still produce a valid event with the safe default "admin"
    so the call site at login() line ~299 does not need to guard against None.
    """

    def test_default_is_admin_for_pre_auth_failure(self):
        from yashigani.backoffice.routes.auth import _make_login_event

        event = _make_login_event("nobody", "failure", "invalid_credentials")
        assert event.account_tier == "admin", (
            "Pre-auth failure call site must use 'admin' default when record is None"
        )

    def test_self_reset_outcome_default(self):
        from yashigani.backoffice.routes.auth import _make_login_event

        event = _make_login_event("nobody", "self_reset", None)
        assert event.account_tier == "admin"


# ---------------------------------------------------------------------------
# T18 — _make_config_event user-tier (defence-in-depth)
# ---------------------------------------------------------------------------

class TestT18ConfigEventUserTier:
    """T18: _make_config_event with user tier records 'user' (defence-in-depth).

    This helper is currently unused (callers build ConfigChangedEvent directly),
    but if RBAC gates break and a non-admin session reaches a config route,
    the audit record MUST reflect the actual tier, not mask it as 'admin'.
    """

    def test_user_tier_config_event_records_user(self):
        from yashigani.backoffice.routes.auth import _make_config_event

        event = _make_config_event(
            "alice", "rate_limit.global", "100", "200", account_tier="user"
        )
        assert event.account_tier == "user", (
            f"defence-in-depth: RBAC bypass must be visible in audit; got {event.account_tier!r}"
        )


# ---------------------------------------------------------------------------
# T19 — _make_config_event admin-tier regression guard
# ---------------------------------------------------------------------------

class TestT19ConfigEventAdminTierRegression:
    """T19: _make_config_event with admin tier still records 'admin' (regression)."""

    def test_admin_tier_config_event(self):
        from yashigani.backoffice.routes.auth import _make_config_event

        event = _make_config_event(
            "superadmin", "rate_limit.global", "100", "200", account_tier="admin"
        )
        assert event.account_tier == "admin"


# ---------------------------------------------------------------------------
# T20 — _make_config_event default → account_tier="admin"
# ---------------------------------------------------------------------------

class TestT20ConfigEventDefault:
    """T20: _make_config_event default is 'admin' (admin-only routes)."""

    def test_default_is_admin(self):
        from yashigani.backoffice.routes.auth import _make_config_event

        event = _make_config_event("superadmin", "some.setting", "old", "new")
        assert event.account_tier == "admin"


# ---------------------------------------------------------------------------
# T21 — login success call site passes record.account_tier (structural)
# ---------------------------------------------------------------------------

class TestT21LoginSuccessCallSiteStructural:
    """T21: Structural — login success call site passes account_tier=record.account_tier."""

    def test_login_success_passes_record_account_tier(self):
        """
        The source of auth.py must contain the call pattern
        _make_login_event(... "success" ... account_tier=record.account_tier)
        — not the hardcoded "admin".
        """
        assert 'account_tier=record.account_tier' in _AUTH_PY, (
            "login success call site must pass account_tier=record.account_tier"
        )
        # Confirm the literal no longer appears in the login-event constructor body
        # (the constructor itself now takes a parameter; the literal "admin" appears
        # only in the default= expression and the docstring, not in the body assignment)
        tree = ast.parse(_AUTH_PY)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.FunctionDef)
                and node.name == "_make_login_event"
            ):
                fn_src = ast.unparse(node)
                assert 'account_tier' in fn_src
                # The constructor must use the parameter, not a literal
                assert "account_tier=account_tier" in fn_src, (
                    "_make_login_event body must assign account_tier=account_tier (the parameter)"
                )


# ---------------------------------------------------------------------------
# T22 — logout call site passes session.account_tier (structural)
# ---------------------------------------------------------------------------

class TestT22LogoutCallSiteStructural:
    """T22: Structural — logout call site passes account_tier=session.account_tier."""

    def test_logout_passes_session_account_tier(self):
        assert 'account_tier=session.account_tier' in _AUTH_PY, (
            "logout call site must pass account_tier=session.account_tier"
        )


# ---------------------------------------------------------------------------
# T23 — self_reset call site passes record.account_tier (structural)
# ---------------------------------------------------------------------------

class TestT23SelfResetCallSiteStructural:
    """T23: Structural — self_reset outcome passes account_tier=record.account_tier."""

    def test_self_reset_passes_record_account_tier(self):
        # The self_reset call is _make_login_event(body.username, "self_reset", None,
        # account_tier=record.account_tier)
        # We check both "self_reset" AND "account_tier=record.account_tier" appear together
        # by checking the source contains the specific pattern
        assert '"self_reset"' in _AUTH_PY, "self_reset outcome must exist in auth.py"
        # Check both appear in the same call by confirming adjacent proximity in source
        idx_self_reset = _AUTH_PY.find('"self_reset", None')
        assert idx_self_reset != -1, '"self_reset", None call pattern not found'
        nearby = _AUTH_PY[idx_self_reset: idx_self_reset + 80]
        assert 'account_tier=record.account_tier' in nearby, (
            f"self_reset call must pass account_tier=record.account_tier; found: {nearby!r}"
        )


# ---------------------------------------------------------------------------
# T24 — totp_provision_restricted call site passes record.account_tier (structural)
# ---------------------------------------------------------------------------

class TestT24TotpProvisionRestrictedCallSiteStructural:
    """T24: Structural — totp_provision_restricted call passes account_tier=record.account_tier."""

    def test_totp_provision_restricted_passes_record_account_tier(self):
        idx = _AUTH_PY.find('"totp_provision_restricted"')
        assert idx != -1, 'totp_provision_restricted outcome not found in auth.py'
        nearby = _AUTH_PY[idx: idx + 100]
        assert 'account_tier=record.account_tier' in nearby, (
            f"totp_provision_restricted call must pass account_tier=record.account_tier; found: {nearby!r}"
        )


# ---------------------------------------------------------------------------
# T25 — defence-in-depth: non-admin session records actual tier not "admin"
# ---------------------------------------------------------------------------

class TestT25DefenceInDepthNonAdminSessionRecordsActualTier:
    """T25: If a non-admin session somehow bypassed RBAC, audit records actual tier.

    This tests the defence-in-depth property of _make_login_event: even if RBAC
    gates break and a 'user'-tier session reaches a route that calls _make_login_event,
    the audit record will carry 'user', not mask the bypass as 'admin'.
    """

    def test_rbac_bypass_visible_in_audit(self):
        from yashigani.backoffice.routes.auth import _make_login_event

        # Simulate a hypothetical RBAC bypass: user-tier session on admin route
        event = _make_login_event(
            "mallory",
            "success",
            None,
            account_tier="user",  # the actual bypassing tier
        )
        assert event.account_tier == "user", (
            "RBAC bypass must be visible in the audit record — "
            f"expected 'user', got {event.account_tier!r}"
        )
        # Confirm outcome is preserved correctly (event should still record login)
        assert event.outcome == "success"


# =============================================================================
# BATCH 2 — wider class-of-bug sweep (this commit)
# =============================================================================

# Source text helpers — loaded once per module for structural checks.
_AUDIT_ROUTES_PY = (
    Path(__file__).resolve().parents[2]
    / "yashigani" / "backoffice" / "routes" / "audit.py"
).read_text(encoding="utf-8")

_USERS_ROUTES_PY = (
    Path(__file__).resolve().parents[2]
    / "yashigani" / "backoffice" / "routes" / "users.py"
).read_text(encoding="utf-8")

_ACCOUNTS_ROUTES_PY = (
    Path(__file__).resolve().parents[2]
    / "yashigani" / "backoffice" / "routes" / "accounts.py"
).read_text(encoding="utf-8")

_RATELIMIT_ROUTES_PY = (
    Path(__file__).resolve().parents[2]
    / "yashigani" / "backoffice" / "routes" / "ratelimit.py"
).read_text(encoding="utf-8")

_INSPECTION_ROUTES_PY = (
    Path(__file__).resolve().parents[2]
    / "yashigani" / "backoffice" / "routes" / "inspection.py"
).read_text(encoding="utf-8")

_KMS_ROUTES_PY = (
    Path(__file__).resolve().parents[2]
    / "yashigani" / "backoffice" / "routes" / "kms.py"
).read_text(encoding="utf-8")

_PG_AUTH_PY = (
    Path(__file__).resolve().parents[2]
    / "yashigani" / "auth" / "pg_auth.py"
).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# T26 — audit._config_event user-tier
# ---------------------------------------------------------------------------

class TestT26AuditConfigEventUserTier:
    """T26: audit._config_event with user-tier records 'user' (defence-in-depth)."""

    def test_user_tier_config_event(self):
        from yashigani.backoffice.routes.audit import _config_event

        event = _config_event("alice", "siem_target_added", "", "splunk", account_tier="user")
        assert event.account_tier == "user", (
            f"ASVS V7.3.4: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_admin_tier_regression(self):
        from yashigani.backoffice.routes.audit import _config_event

        event = _config_event("admin1", "siem_target_added", "", "splunk", account_tier="admin")
        assert event.account_tier == "admin"

    def test_default_is_admin(self):
        from yashigani.backoffice.routes.audit import _config_event

        event = _config_event("admin1", "siem_target_added", "", "splunk")
        assert event.account_tier == "admin"


# ---------------------------------------------------------------------------
# T27 — audit._masking_config_event user-tier
# ---------------------------------------------------------------------------

class TestT27AuditMaskingConfigEventUserTier:
    """T27: audit._masking_config_event with user-tier records 'user'."""

    def test_user_tier_masking_config_event(self):
        from yashigani.backoffice.routes.audit import _masking_config_event

        event = _masking_config_event("alice", "masking.default", "False", "True", account_tier="user")
        assert event.account_tier == "user", (
            f"ASVS V7.3.4: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_admin_tier_regression(self):
        from yashigani.backoffice.routes.audit import _masking_config_event

        event = _masking_config_event("admin1", "masking.default", "False", "True", account_tier="admin")
        assert event.account_tier == "admin"

    def test_default_is_admin(self):
        from yashigani.backoffice.routes.audit import _masking_config_event

        event = _masking_config_event("admin1", "masking.default", "False", "True")
        assert event.account_tier == "admin"


# ---------------------------------------------------------------------------
# T28 — users._config_event user-tier
# ---------------------------------------------------------------------------

class TestT28UsersConfigEventUserTier:
    """T28: users._config_event with user-tier records 'user'."""

    def test_user_tier_config_event(self):
        from yashigani.backoffice.routes.users import _config_event

        event = _config_event("alice", "user_account_created", "", "bob", account_tier="user")
        assert event.account_tier == "user", (
            f"ASVS V7.3.4: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_admin_tier_regression(self):
        from yashigani.backoffice.routes.users import _config_event

        event = _config_event("admin1", "user_account_created", "", "bob", account_tier="admin")
        assert event.account_tier == "admin"

    def test_default_is_admin(self):
        from yashigani.backoffice.routes.users import _config_event

        event = _config_event("admin1", "user_account_created", "", "bob")
        assert event.account_tier == "admin"


# ---------------------------------------------------------------------------
# T29 — users._full_reset_event user-tier
# ---------------------------------------------------------------------------

class TestT29UsersFullResetEventUserTier:
    """T29: users._full_reset_event with user-tier records 'user'."""

    def test_user_tier_full_reset_event(self):
        from yashigani.backoffice.routes.users import _full_reset_event

        event = _full_reset_event("alice", "bob", account_tier="user")
        assert event.account_tier == "user", (
            f"ASVS V7.3.4: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_admin_tier_regression(self):
        from yashigani.backoffice.routes.users import _full_reset_event

        event = _full_reset_event("admin1", "bob", account_tier="admin")
        assert event.account_tier == "admin"

    def test_default_is_admin(self):
        from yashigani.backoffice.routes.users import _full_reset_event

        event = _full_reset_event("admin1", "bob")
        assert event.account_tier == "admin"


# ---------------------------------------------------------------------------
# T30 — users._full_reset_totp_failure user-tier
# ---------------------------------------------------------------------------

class TestT30UsersFullResetTotpFailureUserTier:
    """T30: users._full_reset_totp_failure with user-tier records 'user'."""

    def test_user_tier_full_reset_totp_failure(self):
        from yashigani.backoffice.routes.users import _full_reset_totp_failure

        event = _full_reset_totp_failure("alice", "bob", account_tier="user")
        assert event.account_tier == "user", (
            f"ASVS V7.3.4: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_admin_tier_regression(self):
        from yashigani.backoffice.routes.users import _full_reset_totp_failure

        event = _full_reset_totp_failure("admin1", "bob", account_tier="admin")
        assert event.account_tier == "admin"

    def test_default_is_admin(self):
        from yashigani.backoffice.routes.users import _full_reset_totp_failure

        event = _full_reset_totp_failure("admin1", "bob")
        assert event.account_tier == "admin"


# ---------------------------------------------------------------------------
# T31 — accounts._config_event user-tier
# ---------------------------------------------------------------------------

class TestT31AccountsConfigEventUserTier:
    """T31: accounts._config_event with user-tier records 'user'."""

    def test_user_tier_config_event(self):
        from yashigani.backoffice.routes.accounts import _config_event

        event = _config_event("alice", "admin_account_created", "", "newadmin", account_tier="user")
        assert event.account_tier == "user", (
            f"ASVS V7.3.4: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_admin_tier_regression(self):
        from yashigani.backoffice.routes.accounts import _config_event

        event = _config_event("admin1", "admin_account_created", "", "newadmin", account_tier="admin")
        assert event.account_tier == "admin"

    def test_default_is_admin(self):
        from yashigani.backoffice.routes.accounts import _config_event

        event = _config_event("admin1", "admin_account_created", "", "newadmin")
        assert event.account_tier == "admin"


# ---------------------------------------------------------------------------
# T32 — ratelimit._config_event user-tier
# ---------------------------------------------------------------------------

class TestT32RatelimitConfigEventUserTier:
    """T32: ratelimit._config_event with user-tier records 'user'."""

    def test_user_tier_config_event(self):
        from yashigani.backoffice.routes.ratelimit import _config_event

        event = _config_event("alice", "rate_limit_config", "100", "200", account_tier="user")
        assert event.account_tier == "user", (
            f"ASVS V7.3.4: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_admin_tier_regression(self):
        from yashigani.backoffice.routes.ratelimit import _config_event

        event = _config_event("admin1", "rate_limit_config", "100", "200", account_tier="admin")
        assert event.account_tier == "admin"

    def test_default_is_admin(self):
        from yashigani.backoffice.routes.ratelimit import _config_event

        event = _config_event("admin1", "rate_limit_config", "100", "200")
        assert event.account_tier == "admin"


# ---------------------------------------------------------------------------
# T33 — inspection._config_event user-tier
# ---------------------------------------------------------------------------

class TestT33InspectionConfigEventUserTier:
    """T33: inspection._config_event with user-tier records 'user'."""

    def test_user_tier_config_event(self):
        from yashigani.backoffice.routes.inspection import _config_event

        event = _config_event("alice", "inspection.mode", "strict", "permissive", account_tier="user")
        assert event.account_tier == "user", (
            f"ASVS V7.3.4: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_admin_tier_regression(self):
        from yashigani.backoffice.routes.inspection import _config_event

        event = _config_event("admin1", "inspection.mode", "strict", "permissive", account_tier="admin")
        assert event.account_tier == "admin"

    def test_default_is_admin(self):
        from yashigani.backoffice.routes.inspection import _config_event

        event = _config_event("admin1", "inspection.mode", "strict", "permissive")
        assert event.account_tier == "admin"


# ---------------------------------------------------------------------------
# T34 — kms._config_event user-tier
# ---------------------------------------------------------------------------

class TestT34KmsConfigEventUserTier:
    """T34: kms._config_event with user-tier records 'user'."""

    def test_user_tier_config_event(self):
        from yashigani.backoffice.routes.kms import _config_event

        event = _config_event("alice", "kms_manual_rotation", "", "triggered", account_tier="user")
        assert event.account_tier == "user", (
            f"ASVS V7.3.4: expected account_tier='user', got {event.account_tier!r}"
        )

    def test_admin_tier_regression(self):
        from yashigani.backoffice.routes.kms import _config_event

        event = _config_event("admin1", "kms_manual_rotation", "", "triggered", account_tier="admin")
        assert event.account_tier == "admin"

    def test_default_is_admin(self):
        from yashigani.backoffice.routes.kms import _config_event

        event = _config_event("admin1", "kms_manual_rotation", "", "triggered")
        assert event.account_tier == "admin"


# ---------------------------------------------------------------------------
# T35 — pg_auth._emit_lockout_event user-tier
# ---------------------------------------------------------------------------

class TestT35PgAuthEmitLockoutEventUserTier:
    """T35: pg_auth._emit_lockout_event with user-tier records 'user'.

    _emit_lockout_event now accepts account_tier from record.account_tier at
    both call sites (password lockout + TOTP lockout). This test confirms
    the parameter is wired through to the event.
    """

    def test_user_tier_lockout_event(self):
        from yashigani.auth.pg_auth import _emit_lockout_event

        captured = []

        class _FakeWriter:
            def write(self, evt):
                captured.append(evt)

        _emit_lockout_event(_FakeWriter(), "alice", "password", 5, account_tier="user")
        assert len(captured) == 1
        assert captured[0].account_tier == "user", (
            f"ASVS V7.3.4: expected account_tier='user', got {captured[0].account_tier!r}"
        )

    def test_admin_tier_regression(self):
        from yashigani.auth.pg_auth import _emit_lockout_event

        captured = []

        class _FakeWriter:
            def write(self, evt):
                captured.append(evt)

        _emit_lockout_event(_FakeWriter(), "admin1", "totp", 5, account_tier="admin")
        assert len(captured) == 1
        assert captured[0].account_tier == "admin"

    def test_default_is_admin(self):
        from yashigani.auth.pg_auth import _emit_lockout_event

        captured = []

        class _FakeWriter:
            def write(self, evt):
                captured.append(evt)

        _emit_lockout_event(_FakeWriter(), "admin1", "password", 5)
        assert len(captured) == 1
        assert captured[0].account_tier == "admin"

    def test_none_writer_no_error(self):
        """Confirm None audit_writer is still a no-op (regression guard)."""
        from yashigani.auth.pg_auth import _emit_lockout_event
        # Must not raise
        _emit_lockout_event(None, "admin1", "password", 5, account_tier="user")


# ---------------------------------------------------------------------------
# T36 — structural: no bare account_tier="admin" literal in helper bodies
# ---------------------------------------------------------------------------

class TestT36StructuralNoHardcodedAdminInHelperBodies:
    """T36: Structural sweep — helper function bodies must not contain account_tier="admin".

    Each source file is parsed with ast.parse(). We walk FunctionDef nodes
    whose names match the helper patterns and confirm their bodies do NOT
    contain a bare string constant "admin" assigned to account_tier.
    """

    _HELPERS = [
        ("audit.py", _AUDIT_ROUTES_PY, ["_config_event", "_masking_config_event"]),
        ("users.py", _USERS_ROUTES_PY, ["_config_event", "_full_reset_event", "_full_reset_totp_failure"]),
        ("accounts.py", _ACCOUNTS_ROUTES_PY, ["_config_event"]),
        ("ratelimit.py", _RATELIMIT_ROUTES_PY, ["_config_event"]),
        ("inspection.py", _INSPECTION_ROUTES_PY, ["_config_event"]),
        ("kms.py", _KMS_ROUTES_PY, ["_config_event"]),
        ("pg_auth.py", _PG_AUTH_PY, ["_emit_lockout_event"]),
    ]

    def _find_hardcoded_tier_in_fn(self, source: str, fn_name: str) -> list[str]:
        """Return list of violation descriptions found in fn_name's body."""
        violations = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return [f"SyntaxError parsing source"]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == fn_name:
                fn_src = ast.unparse(node)
                # Check that the body uses account_tier=account_tier (the parameter),
                # not account_tier="admin" or account_tier="user" as a literal assignment.
                # The parameter default "admin" is fine; it is in the function signature.
                # We look for keyword calls like ConfigChangedEvent(account_tier="admin")
                # inside the body (not in the default= expression).
                for child in ast.walk(node):
                    if isinstance(child, ast.keyword):
                        if (
                            child.arg == "account_tier"
                            and isinstance(child.value, ast.Constant)
                            and isinstance(child.value.value, str)
                        ):
                            violations.append(
                                f"{fn_name}: found account_tier={child.value.value!r} literal "
                                f"keyword argument (should be account_tier=account_tier)"
                            )
        return violations

    def test_no_hardcoded_admin_in_helper_bodies(self):
        all_violations = []
        for filename, source, fn_names in self._HELPERS:
            for fn_name in fn_names:
                viols = self._find_hardcoded_tier_in_fn(source, fn_name)
                for v in viols:
                    all_violations.append(f"{filename}/{v}")

        assert not all_violations, (
            "ASVS V7.3.4: hardcoded account_tier literals in helper bodies:\n"
            + "\n".join(f"  {v}" for v in all_violations)
        )
