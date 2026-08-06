"""
Regression test -- v4.1.2 YSG-RISK-141 (HIGH): OPA policy-save cross-namespace
injection.

Root cause: POST /admin/policies/save, PUT /admin/policies/custom/{name}/rego,
PUT /admin/policies/core/{policy_id:path}, and POST /admin/opa-assistant/
apply-rego all took a caller-chosen name/policy_name and PUT the submitted
Rego to OPA at a module id derived from that name (e.g. clients/<name>) --
but never verified that the `package` statement DECLARED INSIDE the Rego
actually matched that namespace. OPA keys the evaluated data document by the
package statement, not by the REST module id used in the PUT path, so a
caller could pass name="my_own_policy" (clean per the existing name-format
checks) while the Rego body declared `package clients.some_other_tenant`
(or a core namespace such as `yashigani`), silently shadowing/overriding
another tenant's decision document. opa_assistant.py's ApplyRegoRequest.
policy_name field description even claimed "must match the package
declaration" -- but nothing ever enforced it.

Fix: src/yashigani/opa_assistant/rego_package.py (extract_rego_package,
assert_client_package_scope, assert_core_package_scope) wired into
save_policy / edit_custom_policy_rego / edit_core_policy / duplicate_template
(policies.py) and apply_rego (opa_assistant.py) -- reject BEFORE any OPA PUT
is ever attempted.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

try:
    from fastapi.testclient import TestClient
    _HAVE_FASTAPI = True
except ImportError:
    _HAVE_FASTAPI = False

pytestmark = pytest.mark.skipif(not _HAVE_FASTAPI, reason="fastapi required")

_FAKE_SESSION = SimpleNamespace(account_id="test-admin", account_tier="admin")


# ---------------------------------------------------------------------------
# Unit tests -- rego_package.py (pure, no I/O)
# ---------------------------------------------------------------------------

class TestRegoPackageExtraction:
    def test_extract_simple_package(self):
        from yashigani.opa_assistant.rego_package import extract_rego_package
        assert extract_rego_package("package clients.foo\n\nimport rego.v1\n") == "clients.foo"

    def test_extract_missing_package_returns_none(self):
        from yashigani.opa_assistant.rego_package import extract_rego_package
        assert extract_rego_package("import rego.v1\ndeny contains 1\n") is None

    def test_extract_ignores_leading_comment_lines(self):
        from yashigani.opa_assistant.rego_package import extract_rego_package
        rego = "# a comment\n  package clients.bar\nimport rego.v1\n"
        assert extract_rego_package(rego) == "clients.bar"


class TestAssertClientPackageScope:
    def test_matching_package_passes(self):
        from yashigani.opa_assistant.rego_package import assert_client_package_scope
        # Must not raise.
        assert_client_package_scope("package clients.my_policy\nimport rego.v1\n", "my_policy")

    def test_cross_namespace_package_rejected(self):
        from fastapi import HTTPException

        from yashigani.opa_assistant.rego_package import assert_client_package_scope

        with pytest.raises(HTTPException) as exc_info:
            assert_client_package_scope(
                "package clients.some_other_tenant\nimport rego.v1\n", "my_own_policy",
            )
        assert exc_info.value.status_code == 400
        assert exc_info.value.detail["error"] == "package_namespace_mismatch"

    def test_core_namespace_escape_via_client_endpoint_rejected(self):
        """A client-scoped save declaring `package rbac` (core namespace) must
        be rejected -- not silently accepted just because the id-level
        reserved-name check only looks at the `name` field, not the Rego body."""
        from fastapi import HTTPException

        from yashigani.opa_assistant.rego_package import assert_client_package_scope

        with pytest.raises(HTTPException):
            assert_client_package_scope("package rbac\nimport rego.v1\n", "innocuous")

    def test_missing_package_rejected(self):
        from fastapi import HTTPException

        from yashigani.opa_assistant.rego_package import assert_client_package_scope

        with pytest.raises(HTTPException) as exc_info:
            assert_client_package_scope("import rego.v1\ndeny contains 1\n", "my_policy")
        assert exc_info.value.detail["error"] == "missing_package"


class TestAssertCorePackageScope:
    def test_core_root_package_passes(self):
        from yashigani.opa_assistant.rego_package import assert_core_package_scope
        assert_core_package_scope("package yashigani\nimport rego.v1\n")

    def test_core_subpackage_passes(self):
        from yashigani.opa_assistant.rego_package import assert_core_package_scope
        assert_core_package_scope("package yashigani.mcp\nimport rego.v1\n")

    def test_escape_to_clients_namespace_rejected(self):
        from fastapi import HTTPException

        from yashigani.opa_assistant.rego_package import assert_core_package_scope

        with pytest.raises(HTTPException) as exc_info:
            assert_core_package_scope("package clients.sneaky\nimport rego.v1\n")
        assert exc_info.value.detail["error"] == "package_namespace_mismatch"


# ---------------------------------------------------------------------------
# Route-level: reject BEFORE any OPA PUT is attempted
# ---------------------------------------------------------------------------

def _make_policies_app():
    import fastapi as _fastapi

    from yashigani.backoffice import middleware as mw
    from yashigani.backoffice.routes.policies import router

    app = _fastapi.FastAPI()
    app.dependency_overrides[mw.require_admin_session] = lambda: _FAKE_SESSION
    app.dependency_overrides[mw.require_stepup_admin_session] = lambda: _FAKE_SESSION
    app.include_router(router, prefix="/admin/policies")
    return app


def _make_opa_assistant_app():
    import fastapi as _fastapi

    from yashigani.backoffice import middleware as mw
    from yashigani.backoffice.routes.opa_assistant import router

    app = _fastapi.FastAPI()
    app.dependency_overrides[mw.require_admin_session] = lambda: _FAKE_SESSION
    app.dependency_overrides[mw.require_stepup_admin_session] = lambda: _FAKE_SESSION
    app.include_router(router, prefix="/admin/opa-assistant")
    return app


class TestSavePolicyRejectsCrossNamespace:
    def test_cross_namespace_package_never_reaches_opa(self):
        app = _make_policies_app()
        client = TestClient(app)

        never_called_client = AsyncMock()
        with patch(
            "yashigani.backoffice.routes.policies.internal_httpx_client",
            return_value=never_called_client,
        ):
            resp = client.post(
                "/admin/policies/save",
                json={
                    "name": "my_own_policy",
                    "rego": "package clients.some_other_tenant\nimport rego.v1\n"
                            "default decision := {\"allow\": true, \"deny\": set(), \"obligations\": set()}\n",
                },
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "package_namespace_mismatch"
        # The critical assertion: OPA was NEVER touched -- the reject happens
        # before any PUT is attempted, so the malicious module cannot land
        # even transiently.
        never_called_client.__aenter__.assert_not_called()


class TestEditCustomPolicyRejectsCrossNamespace:
    def test_cross_namespace_package_never_reaches_opa(self):
        app = _make_policies_app()
        client = TestClient(app)

        never_called_client = AsyncMock()
        with patch(
            "yashigani.backoffice.routes.policies.internal_httpx_client",
            return_value=never_called_client,
        ):
            resp = client.put(
                "/admin/policies/custom/my_own_policy/rego",
                json={"rego": "package clients.some_other_tenant\nimport rego.v1\n"},
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "package_namespace_mismatch"
        never_called_client.__aenter__.assert_not_called()


class TestEditCorePolicyRejectsClientNamespaceEscape:
    def test_client_namespace_package_never_reaches_opa(self):
        app = _make_policies_app()
        client = TestClient(app)

        never_called_client = AsyncMock()
        with patch(
            "yashigani.backoffice.routes.policies.internal_httpx_client",
            return_value=never_called_client,
        ):
            resp = client.put(
                "/admin/policies/core/rbac",
                json={
                    "rego": "package clients.sneaky\nimport rego.v1\n",
                    "confirm_danger": True,
                    "reason": "testing",
                },
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "package_namespace_mismatch"
        never_called_client.__aenter__.assert_not_called()


class TestApplyRegoRejectsCrossNamespace:
    def test_cross_namespace_package_never_validated_or_applied(self):
        app = _make_opa_assistant_app()
        client = TestClient(app)

        with patch(
            "yashigani.opa_assistant.rego_validator.validate_rego_module",
            new=AsyncMock(side_effect=AssertionError("must not be called")),
        ):
            resp = client.post(
                "/admin/opa-assistant/apply-rego",
                json={
                    "rego": "package clients.some_other_tenant\nimport rego.v1\n",
                    "policy_name": "my_own_slug",
                },
            )
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "package_namespace_mismatch"
