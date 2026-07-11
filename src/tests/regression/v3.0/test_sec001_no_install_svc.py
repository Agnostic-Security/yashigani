"""
Regression test — SEC-001 / LAURA-2255-001: install_svc backdoor removed.

Verifies:
  1. _bootstrap_service_account does NOT exist in backoffice.app (function deleted).
  2. _bootstrap_admin_accounts does NOT call _bootstrap_service_account.
  3. fresh-boot: human admin seeding guard fires on count==0 only (install_svc
     can no longer occupy the first slot and block human admin creation).

These tests are unit-level (no DB / Redis required).
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

        async def set_totp_secret_direct(self, username, secret):
            pass

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

        from yashigani.backoffice.app import _bootstrap_admin_accounts

        await _bootstrap_admin_accounts(_MockAuthService(), _MockState())

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
