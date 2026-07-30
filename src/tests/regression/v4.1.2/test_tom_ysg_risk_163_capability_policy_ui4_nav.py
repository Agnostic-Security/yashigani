"""
Regression test -- v4.1.2 YSG-RISK-163: capability-policy admin view was
unreachable from the ui4 backoffice SPA.

Current state found: the capability-policy admin panel existed since 3.0
with a full working backend (routes/capability_policy.py, RBAC-scoped
browser Permissions-Policy: org/group/user tiers + baseline fallback) and
an OLD static/js/capability-policy.js frontend, but was never ported to the
ui4 admin shell rebuild (static/ui4/admin/). No module file, no
registerAdminModule() call, no admin-app.js import -- the view was
completely unreachable from the ui4 nav (the old static/js panel is dead
code, no longer linked from any ui4 page).

Fix: new static/ui4/admin/modules/capability-policy.js, mirroring the
sibling policies-opa.js module's registerAdminModule() pattern, wired into
admin-app.js's MODULES import block (Governance & Data group).

These are structural/static checks (grep + node --check syntax validation)
-- this repo has no JS test runner (no package.json / vitest / jest); E2E
click-through coverage is Ava's Playwright remit, tracked separately.
"""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_UI4_ADMIN = _REPO_ROOT / "yashigani" / "backoffice" / "static" / "ui4" / "admin"
_MODULE_FILE = _UI4_ADMIN / "modules" / "capability-policy.js"
_ADMIN_APP = _UI4_ADMIN / "admin-app.js"
_BACKEND_ROUTES = _REPO_ROOT / "yashigani" / "backoffice" / "routes" / "capability_policy.py"


class TestCapabilityPolicyModuleExists:
    def test_module_file_exists(self):
        assert _MODULE_FILE.is_file(), f"expected {_MODULE_FILE} to exist"

    def test_module_registers_with_expected_descriptor(self):
        src = _MODULE_FILE.read_text()
        assert "registerAdminModule(" in src
        assert re.search(r"id:\s*['\"]capability-policy['\"]", src)
        assert re.search(r"group:\s*['\"]governance['\"]", src)
        assert re.search(r"label:\s*['\"]Capability Policy['\"]", src)

    def test_module_uses_generic_render_contract(self):
        """render(ctx) must forward ctx.api / ctx.app per module-registry.js's
        PINNED contract -- confirms the module can actually mount, not just
        register a descriptor."""
        src = _MODULE_FILE.read_text()
        assert "render: (ctx) =>" in src
        assert ".api=${ctx.api}" in src
        assert ".app=${ctx.app}" in src


class TestAdminAppImportsTheModule:
    def test_admin_app_imports_capability_policy_module(self):
        src = _ADMIN_APP.read_text()
        assert "'./modules/capability-policy.js'" in src

    def test_import_sits_in_governance_module_group(self):
        """Confirms the import line is placed alongside the other Governance,
        Data & Workflows group modules (policies-opa.js is the sibling this
        was modelled on) -- not accidentally dropped into an unrelated group."""
        src = _ADMIN_APP.read_text()
        governance_marker = "// Governance, Data & Workflows module group"
        idx = src.index(governance_marker)
        next_group_marker = '// "Ops & Crypto" module group'
        governance_block = src[idx:src.index(next_group_marker)]
        assert "capability-policy.js" in governance_block
        assert "policies-opa.js" in governance_block


class TestModuleSyntaxValid:
    def test_module_is_valid_es_module_syntax(self):
        node = shutil.which("node")
        if not node:
            pytest.skip("node not installed -- syntax check skipped")
        result = subprocess.run(
            [node, "--input-type=module", "--check"],
            input=_MODULE_FILE.read_text(),
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, f"node --check failed:\n{result.stderr}"


class TestBackendRoutesWiredCorrectly:
    """Confirms the module's fetch URLs actually match live FastAPI routes --
    the backend has existed since 3.0 and was never broken; this just proves
    the ui4 port didn't invent a mismatched API surface."""

    def test_backend_routes_file_exists(self):
        assert _BACKEND_ROUTES.is_file()

    def test_module_org_scope_url_matches_backend_default_route(self):
        backend_src = _BACKEND_ROUTES.read_text()
        module_src = _MODULE_FILE.read_text()
        # Backend: @router.get("") / @router.put("") mounted at
        # /admin/api/capability-policy (see router prefix in backoffice/app.py).
        assert '@router.get(\n    "",' in backend_src or '@router.get("",' in backend_src
        assert "/admin/api/capability-policy" in module_src

    def test_module_effective_preview_url_matches_backend(self):
        backend_src = _BACKEND_ROUTES.read_text()
        module_src = _MODULE_FILE.read_text()
        assert '"/effective"' in backend_src
        assert "/admin/api/capability-policy/effective?user=" in module_src

    def test_backend_router_mounted_under_admin_api_prefix(self):
        from yashigani.backoffice.app import create_backoffice_app
        app = create_backoffice_app()
        paths = [r.path for r in app.routes if hasattr(r, "path")]
        assert "/admin/api/capability-policy" in paths
        assert "/admin/api/capability-policy/effective" in paths
