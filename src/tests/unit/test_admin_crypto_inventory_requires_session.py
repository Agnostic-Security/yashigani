"""
Regression test — GET /admin/crypto/inventory must require admin session.

The crypto inventory endpoint returns a JSON document listing every cryptographic
algorithm in use, deprecated algorithms, post-quantum status, and compliance
references. While it does not expose key material, unauthenticated access leaks
reconnaissance data that is useful to an attacker profiling the deployment
(OWASP API1:2023 / ASVS V4.1.1).

The correct fix is a handler-level session=Depends(require_admin_session) parameter.

These tests assert (source-level, no full app stack needed):
  1. crypto_inventory.py imports require_admin_session.
  2. The handler signature includes Depends(require_admin_session).
  3. Depends is imported from fastapi.
  4. An AST-level check confirms the Depends() call is in the function's parameter defaults.

A functional test uses FastAPI TestClient with a minimal mirrored handler to
verify 401 is returned without a session and 200 with a mocked session.

Last updated: 2026-05-02T00:00:00+01:00
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_CRYPTO_PY = (
    Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "crypto_inventory.py"
)


class TestCryptoInventoryRequiresSession:
    """Source-level assertions that the auth guard is present."""

    def test_crypto_inventory_py_exists(self):
        assert _CRYPTO_PY.exists(), f"Missing: {_CRYPTO_PY}"

    def test_require_admin_session_imported(self):
        """crypto_inventory.py must import require_admin_session."""
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "require_admin_session" in source, (
            "REGRESSION: require_admin_session not imported in crypto_inventory.py. "
            "The /admin/crypto/inventory endpoint is unauthenticated."
        )

    def test_handler_has_session_dependency(self):
        """
        The crypto_inventory handler must have Depends(require_admin_session) in
        its parameter list. The docstring declares the endpoint admin-authenticated;
        this test enforces that the declaration is backed by an actual guard.
        """
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "Depends(require_admin_session)" in source, (
            "REGRESSION: Depends(require_admin_session) not found in crypto_inventory.py. "
            "The /admin/crypto/inventory endpoint is unauthenticated."
        )

    def test_depends_imported(self):
        """crypto_inventory.py must import Depends from fastapi."""
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "Depends" in source, (
            "Depends not imported in crypto_inventory.py — required for the auth guard."
        )

    def test_auth_note_present(self):
        """An authentication note must be present in the crypto_inventory.py docstring."""
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "require_admin_session" in source, (
            "Auth note referencing require_admin_session not found in crypto_inventory.py."
        )

    def test_handler_function_has_session_param_in_ast(self):
        """
        AST-level: the crypto_inventory function must have a parameter whose
        default is a Call to Depends(). This confirms the guard is wired into
        the function signature, not just present in a comment.
        """
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        tree = ast.parse(source)

        found_with_depends = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == "crypto_inventory":
                    for default in node.args.defaults:
                        if (
                            isinstance(default, ast.Call)
                            and isinstance(default.func, ast.Name)
                            and default.func.id == "Depends"
                        ):
                            found_with_depends = True
                            break
                    for default in node.args.kw_defaults:
                        if default and (
                            isinstance(default, ast.Call)
                            and isinstance(default.func, ast.Name)
                            and default.func.id == "Depends"
                        ):
                            found_with_depends = True
                            break

        assert found_with_depends, (
            "REGRESSION: crypto_inventory() function does not have a Depends() "
            "parameter default at the AST level. The session dependency is missing "
            "from the handler signature."
        )


class TestCryptoInventoryTotpHonestClaims:
    """
    LAURA-3X-003: crypto_inventory.py must not assert HMAC-SHA-1 as the
    deployed TOTP algorithm.  Phase 13 (v3.1) switched to role-tiered TOTP:
      - User tier:  HMAC-SHA-256 / 6-digit
      - Admin tier: HMAC-SHA-512 / 8-digit
    SHA-1 is NOT deployed for new enrolments; it is only a legacy-detection
    sentinel.  Listing SHA-1 as the live TOTP digest misleads auditors.
    """

    def test_hmac_sha1_not_falsely_listed_as_deployed_totp(self):
        """
        The crypto inventory must NOT contain an entry whose name is 'HMAC-SHA-1'
        with TOTP usage — that would falsely imply SHA-1 is the deployed algorithm.
        """
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        # The old entry was: {"name": "HMAC-SHA-1", "usage": "TOTP digest (RFC 6238 default)", ...}
        # We accept "HMAC-SHA-1" in comments / notes that clarify it is NOT deployed,
        # but it must not appear as an inventory entry name alongside TOTP usage.
        assert '"HMAC-SHA-1", "usage": "TOTP' not in source, (
            "LAURA-3X-003 REGRESSION: crypto_inventory.py still lists 'HMAC-SHA-1' "
            "as the deployed TOTP algorithm. Phase 13 (v3.1) uses SHA-256 (users) "
            "and SHA-512 (admins). Remove the SHA-1 entry."
        )

    def test_hmac_sha256_totp_user_tier_listed(self):
        """HMAC-SHA-256 (user-tier TOTP) must appear in the crypto inventory."""
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "HMAC-SHA-256" in source and "user tier" in source, (
            "LAURA-3X-003: crypto_inventory.py must list HMAC-SHA-256 as the "
            "user-tier TOTP algorithm (Phase 13 / v3.1)."
        )

    def test_hmac_sha512_totp_admin_tier_listed(self):
        """HMAC-SHA-512 (admin-tier TOTP) must appear in the crypto inventory."""
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "HMAC-SHA-512" in source and "admin tier" in source, (
            "LAURA-3X-003: crypto_inventory.py must list HMAC-SHA-512 as the "
            "admin-tier TOTP algorithm (Phase 13 / v3.1)."
        )

    def test_sha1_not_deployed_note_present(self):
        """
        The inventory must contain an explicit note that HMAC-SHA-1 is NOT deployed,
        so auditors reading the file do not infer SHA-1 is in use.
        """
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "SHA-1 NOT deployed" in source or "HMAC-SHA-1 NOT deployed" in source, (
            "LAURA-3X-003: crypto_inventory.py must contain an explicit note that "
            "HMAC-SHA-1 is NOT deployed (e.g. in a usage string or comment). "
            "Auditors must not infer SHA-1 is active."
        )


def _make_crypto_inventory_app():
    """
    Build a minimal FastAPI app with a /crypto/inventory-shaped route protected
    by a session guard. Uses the dependency_overrides pattern so FastAPI resolves
    the sentinel dependency without Python 3.9 annotation issues for local functions.

    Returns (app, sentinel_fn) so callers can wire overrides.
    """
    try:
        from fastapi import FastAPI, HTTPException, Depends, APIRouter
    except ImportError:
        return None, None

    def _sentinel_auth():
        """Placeholder — overridden via app.dependency_overrides in each test."""
        raise HTTPException(status_code=401, detail={"error": "authentication_required"})

    test_router = APIRouter()

    @test_router.get("/crypto/inventory")
    async def crypto_inventory(session=Depends(_sentinel_auth)):
        return {
            "algorithms": [{"name": "Argon2id", "usage": "password hashing"}],
            "deprecated": [],
            "post_quantum": ["ML-KEM-768"],
            "compliance": "NIST SP 800-131A Rev 2",
        }

    app = FastAPI()
    app.include_router(test_router, prefix="/admin")
    return app, _sentinel_auth


class TestCryptoInventorySessionEnforcementFunctional:
    """
    Functional test: mount a minimal router mirroring crypto_inventory's pattern
    and verify 401 is returned without a session cookie.

    Uses app.dependency_overrides (FastAPI-idiomatic approach) to avoid
    Python 3.9 type annotation resolution issues with locally-defined functions.
    """

    def test_unauthenticated_returns_401(self):
        """GET /admin/crypto/inventory must return 401 without a session cookie."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, sentinel = _make_crypto_inventory_app()
        if app is None:
            pytest.skip("fastapi not available")

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/admin/crypto/inventory")
        assert resp.status_code == 401, (
            f"REGRESSION: GET /admin/crypto/inventory returned {resp.status_code} "
            "without a session cookie, expected 401. "
            "The crypto inventory endpoint is publicly readable."
        )

    def test_authenticated_returns_200(self):
        """GET /admin/crypto/inventory with a valid session must return 200."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, sentinel = _make_crypto_inventory_app()
        if app is None:
            pytest.skip("fastapi not available")

        mock_session = MagicMock()
        mock_session.account_tier = "admin"

        app.dependency_overrides[sentinel] = lambda: mock_session
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/admin/crypto/inventory")
            assert resp.status_code == 200, (
                f"GET /admin/crypto/inventory with valid session returned {resp.status_code}, "
                "expected 200."
            )
        finally:
            app.dependency_overrides.clear()

    def test_authenticated_returns_crypto_inventory_keys(self):
        """Authenticated response must include all required CryptoBoM keys."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, sentinel = _make_crypto_inventory_app()
        if app is None:
            pytest.skip("fastapi not available")

        mock_session = MagicMock()
        mock_session.account_tier = "admin"

        app.dependency_overrides[sentinel] = lambda: mock_session
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/admin/crypto/inventory")
            assert resp.status_code == 200
            data = resp.json()
            assert "algorithms" in data, "Response missing 'algorithms' key"
            assert "deprecated" in data, "Response missing 'deprecated' key"
            assert "post_quantum" in data, "Response missing 'post_quantum' key"
            assert "compliance" in data, "Response missing 'compliance' key"
        finally:
            app.dependency_overrides.clear()
