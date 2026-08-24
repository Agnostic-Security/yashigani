"""
Regression test — SEC-001 / LAURA-2255-001: install_svc backdoor removed.

Verifies:
  1. _bootstrap_service_account does NOT exist in backoffice.app (function deleted).
  2. _bootstrap_admin_accounts does NOT call _bootstrap_service_account.
  3. fresh-boot: human admin seeding guard fires on count==0 only (install_svc
     can no longer occupy the first slot and block human admin creation).

These tests are unit-level (no DB / Redis required).

2026-08-16: test 3's ``_MockAuthService.set_totp_secret_direct`` signature was
stale against ``PostgresLocalAuthService.set_totp_secret_direct`` (real impl at
src/yashigani/auth/pg_auth.py:730), which gained an ``algorithm: str =
LEGACY_TOTP_ALGO`` parameter in 9d47affe ("feat(3.1 P13): role-tiered TOTP —
SHA-256/6 users, SHA-512/8 admins", 2026-06-28) — two weeks after this test was
authored (832e4d4a, 2026-06-14) and never re-run since src/tests/regression/
was wired into no YTF tier until today. `_bootstrap_admin_accounts` (app.py)
now calls ``set_totp_secret_direct(admin_username, totp_secret,
algorithm="SHA512")`` to match the admin-tier algorithm; the mock didn't accept
the kwarg and raised ``TypeError``. Unrelated to the SEC-001 property itself
(no install_svc): tests 1/2/4 (AST-based, checking for the deleted
_bootstrap_service_account function/call/literal) already passed unmodified —
the mock repair below only restores fidelity to the real auth-service
interface so test 3 can exercise the bootstrap path again. Also unrelated to
the concurrent FIND-0813-013 red-team review of the SEC-001 "no-admin-API
durable path" for agent registration (install.sh register_agent_bundles /
AgentDurableStore) — that is a different code surface
(src/yashigani/backoffice/app.py:_bootstrap_admin_accounts, human admin
bootstrap) from the one under review (install.sh, agent registration); this
fix does not depend on and does not pre-empt that review's conclusion.
"""
from __future__ import annotations

import ast
import inspect
import textwrap

import pytest


# ---------------------------------------------------------------------------
# Helper — parse app.py AST to find function defs
# ---------------------------------------------------------------------------

def _get_app_py_ast() -> ast.Module:
    import importlib.util
    import pathlib

    # Find app.py relative to the installed yashigani package
    spec = importlib.util.find_spec("yashigani.backoffice.app")
    if spec is None or spec.origin is None:
        pytest.skip("yashigani.backoffice.app not importable")
    src = pathlib.Path(spec.origin).read_text()
    return ast.parse(src), src


# ---------------------------------------------------------------------------
# Test 1: _bootstrap_service_account function must NOT exist in app.py
# ---------------------------------------------------------------------------

def test_no_bootstrap_service_account_function():
    """SEC-001: _bootstrap_service_account deleted from backoffice/app.py."""
    tree, src = _get_app_py_ast()
    fn_names = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    assert "_bootstrap_service_account" not in fn_names, (
        "SEC-001 REGRESSION: _bootstrap_service_account still defined in "
        "backoffice/app.py — the install_svc backdoor service account seeding "
        "function must be deleted."
    )


# ---------------------------------------------------------------------------
# Test 2: _bootstrap_admin_accounts must NOT call _bootstrap_service_account
# ---------------------------------------------------------------------------

def test_bootstrap_admin_accounts_no_svc_call():
    """SEC-001: _bootstrap_admin_accounts no longer calls _bootstrap_service_account."""
    tree, src = _get_app_py_ast()

    # Find the _bootstrap_admin_accounts function
    target_fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_bootstrap_admin_accounts":
            target_fn = node
            break

    assert target_fn is not None, "_bootstrap_admin_accounts not found in app.py"

    # Collect all call names inside _bootstrap_admin_accounts
    call_names = []
    for node in ast.walk(target_fn):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                call_names.append(node.func.attr)
            elif isinstance(node.func, ast.Name):
                call_names.append(node.func.id)

    assert "_bootstrap_service_account" not in call_names, (
        "SEC-001 REGRESSION: _bootstrap_admin_accounts still calls "
        "_bootstrap_service_account — the service-account seeding call must be removed."
    )


# ---------------------------------------------------------------------------
# Test 3: total_admin_count guard fires on count==0 (regression for LAURA-2255-001)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_human_admin_bootstrap_not_blocked_by_svc_account():
    """LAURA-2255-001: human admins ARE created on fresh DB (count==0 guard unblocked)."""
    import types

    # Build a minimal mock auth_service
    created: list[str] = []

    class _MockAuthService:
        async def total_admin_count(self):
            # Fresh DB: 0 admins exist (install_svc no longer pre-seeds)
            return len(created)

        async def create_admin(self, username, auto_generate, plaintext_password,
                               force_password_change=True, force_totp_provision=True):
            created.append(username)

        async def get_account(self, username):
            return None

        async def set_totp_secret_direct(self, username, secret, algorithm="SHA1"):
            # Phase 13 (9d47affe): real PostgresLocalAuthService.set_totp_secret_direct
            # takes an `algorithm` kwarg (admin bootstrap passes "SHA512"). Mirror the
            # real signature so this mock doesn't drift from the interface it stands in for.
            self.totp_algorithm = algorithm

    # Lu P2 (2026-08-16): _bootstrap_admin_accounts now writes an
    # AdminAccountBootstrappedEvent via state.audit_writer.write() BEFORE
    # create_admin() — see backoffice/app.py docstring. _MockState previously
    # had no audit_writer attribute at all, which would now raise
    # AttributeError on the `assert state.audit_writer is not None` guard.
    # Mirror the real AuditLogWriter surface just enough (a synchronous
    # .write(event) that records the event) to exercise the real code path.
    class _MockAuditWriter:
        def __init__(self):
            self.events: list = []

        def write(self, event):
            self.events.append(event)

    # Build a minimal mock state with _auth_bootstrap context
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write admin1 secret files
        for name, value in [
            ("admin1_username", "admin1"),
            ("admin1_password", "s3cr3t"),
            ("admin1_totp_secret", "JBSWY3DPEHPK3PXP"),
        ]:
            path = os.path.join(tmpdir, name)
            open(path, "w").write(value)

        class _MockState:
            _auth_bootstrap = {
                "admin_username": "admin1",
                "initial_admin_password": "s3cr3t",
                "secrets_dir": tmpdir,
            }
            audit_writer = _MockAuditWriter()

        from yashigani.backoffice.app import _bootstrap_admin_accounts

        auth_svc = _MockAuthService()
        mock_state = _MockState()
        await _bootstrap_admin_accounts(auth_svc, mock_state)

    # Lu P2: the bootstrap must have emitted the typed audit event for admin1
    # BEFORE create_admin(), not silently.
    from yashigani.audit.schema import AdminAccountBootstrappedEvent

    bootstrap_events = [
        e for e in mock_state.audit_writer.events
        if isinstance(e, AdminAccountBootstrappedEvent)
    ]
    assert len(bootstrap_events) == 1, (
        "Lu P2 REGRESSION: _bootstrap_admin_accounts must emit exactly one "
        "AdminAccountBootstrappedEvent for admin1 on fresh boot."
    )
    assert bootstrap_events[0].bootstrapped_username == "admin1"
    assert bootstrap_events[0].admin_slot == "primary"
    assert bootstrap_events[0].totp_provisioned is True

    # Admin-tier bootstrap must provision the admin-tier TOTP algorithm (Phase 13,
    # 9d47affe) — not just accept the kwarg without honouring it.
    assert getattr(auth_svc, "totp_algorithm", None) == "SHA512", (
        "_bootstrap_admin_accounts must call set_totp_secret_direct(..., "
        "algorithm='SHA512') for admin-tier accounts (Phase 13 role-tiered TOTP)."
    )

    # admin1 must have been created
    assert "admin1" in created, (
        "LAURA-2255-001 REGRESSION: admin1 not created on fresh boot. "
        "total_admin_count()==0 guard should have allowed seeding."
    )

    # install_svc (or any service account named install_svc) must NOT have been created
    assert "install_svc" not in created, (
        "SEC-001 REGRESSION: install_svc was seeded during _bootstrap_admin_accounts. "
        "The service account must not be created anywhere in this path."
    )


# ---------------------------------------------------------------------------
# Test 4: install_svc string must not appear in the bootstrap code path
# ---------------------------------------------------------------------------

def test_no_install_svc_literal_in_bootstrap():
    """SEC-001: 'install_svc' literal must not appear in the bootstrap function."""
    tree, src = _get_app_py_ast()

    # Extract the source of _bootstrap_admin_accounts only
    fn_src = ""
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.AsyncFunctionDef)
            and node.name == "_bootstrap_admin_accounts"
        ):
            # Get line range
            import pathlib, importlib.util
            spec = importlib.util.find_spec("yashigani.backoffice.app")
            lines = pathlib.Path(spec.origin).read_text().splitlines()
            fn_lines = lines[node.lineno - 1: node.end_lineno]
            fn_src = "\n".join(fn_lines)
            break

    assert "install_svc" not in fn_src, (
        "SEC-001 REGRESSION: 'install_svc' literal found inside "
        "_bootstrap_admin_accounts — remove all service-account references."
    )
