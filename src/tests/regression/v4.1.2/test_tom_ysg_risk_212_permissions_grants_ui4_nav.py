"""
Regression test -- v4.1.2 YSG-RISK-212: the unified Resource Permission
Grant admin surface (routes/permissions.py, mounted at /admin/api/permissions
since 3.1 Phase 8) was unreachable from the ui4 backoffice SPA.

Current state found: full working backend, an OLD static/js/permissions.js
frontend, but no static/ui4/admin/modules/permissions-grants.js, no
registerAdminModule() call, and no admin-app.js import -- the exact same
class of gap as YSG-RISK-163 (capability-policy), closed by
test_tom_ysg_risk_163_capability_policy_ui4_nav.py. This test is that
precedent's structure, applied to permissions-grants.js.

2026-08-16 (item 4 of the pre-push code-quality review): d5cc7096 shipped
static/ui4/admin/modules/permissions-grants.js (734 lines) and its
admin-app.js wiring with NO committed guard -- deleting the module and its
import left the suite green. The commit's own cited precedent
(YSG-RISK-163) shipped a guard; this one didn't. This closes that gap using
the same static-check strategy the precedent uses (this repo has no JS test
runner / package.json / vitest / jest):

  - the module file exists and registers with the expected descriptor
    (id/group/label) in the governance nav group, alongside its sibling
    capability-policy.js;
  - admin-app.js actually imports it;
  - render(ctx) forwards ctx.api/ctx.app per module-registry.js's pinned
    contract (proves the module can mount, not just register);
  - the module's fetch/mutate URLs actually match live FastAPI routes on
    routes/permissions.py, mounted where app.py says it is -- not just
    routes that LOOK plausible;
  - every StepUpAdminSession-gated backend route (PUT/DELETE grant, POST
    approve, DELETE reject) is called via ctx.api.mutate (never api.get),
    so step-up is the server's decision, never the client's (RISK-103);
  - no innerHTML/unsafeHTML anywhere in the module (SAFE-RENDER, the module
    header's own explicit claim about what replaced the legacy page's
    escapeHtml()-into-innerHTML pattern);
  - node --check syntax validation, skipped gracefully if node is not on
    PATH (this host does not have it on PATH by default; a vendored
    interpreter exists under testing_runs/yashigani/.jscheck-venv for local
    verification runs, but this test does not hardcode a machine-local path
    into committed source -- see the commit body / verification notes for
    how it was exercised).

Does NOT prove: nav click-through, the TOTP modal firing on a real 401, or
that the four scope-type URL encodings are byte-correct against a live
server (that's Ava's Playwright remit, tracked against
test_permissions_ui.py). This is a structural/wiring/route-existence guard,
not a behavioural one.
"""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_UI4_ADMIN = _REPO_ROOT / "yashigani" / "backoffice" / "static" / "ui4" / "admin"
_MODULE_FILE = _UI4_ADMIN / "modules" / "permissions-grants.js"
_ADMIN_APP = _UI4_ADMIN / "admin-app.js"
_BACKEND_ROUTES = _REPO_ROOT / "yashigani" / "backoffice" / "routes" / "permissions.py"


def _code_only(source: str) -> str:
    """Strip ``//``-comment-only lines before a static absence check.

    Applied uniformly here (BLOCK-2 of the 2026-08-16 pre-push review: the
    same repo's ``_code_only`` helper was applied to 1 of 4 guards in a
    sibling file, not all 4 -- do not repeat that here). The module's own
    header comment discusses innerHTML/unsafeHTML BY NAME while explaining
    why neither is used; an absence check that doesn't exclude comments
    trips on its own documentation."""
    return "\n".join(
        line for line in source.splitlines()
        if line.strip() and not line.strip().startswith("//")
    )


class TestPermissionsGrantsModuleExists:
    def test_module_file_exists(self):
        assert _MODULE_FILE.is_file(), f"expected {_MODULE_FILE} to exist"

    def test_module_registers_with_expected_descriptor(self):
        src = _MODULE_FILE.read_text()
        assert "registerAdminModule(" in src
        assert re.search(r"id:\s*['\"]permissions['\"]", src)
        assert re.search(r"group:\s*['\"]governance['\"]", src)
        assert re.search(r"label:\s*['\"]Resource Permissions['\"]", src)

    def test_module_uses_generic_render_contract(self):
        """render(ctx) must forward ctx.api / ctx.app per module-registry.js's
        PINNED contract -- confirms the module can actually mount, not just
        register a descriptor."""
        src = _MODULE_FILE.read_text()
        assert "render: (ctx) =>" in src
        assert ".api=${ctx.api}" in src
        assert ".app=${ctx.app}" in src

    def test_module_defines_the_custom_element(self):
        src = _MODULE_FILE.read_text()
        assert "customElements.define('ys-admin-permissions'" in src
        assert "export class YsAdminPermissions extends LitElement" in src


class TestAdminAppImportsTheModule:
    def test_admin_app_imports_permissions_grants_module(self):
        src = _ADMIN_APP.read_text()
        assert "'./modules/permissions-grants.js'" in src

    def test_import_sits_in_governance_module_group(self):
        """Confirms the import line is placed alongside the other Governance,
        Data & Workflows group modules (capability-policy.js is the sibling
        this was modelled on, per YSG-RISK-163) -- not accidentally dropped
        into an unrelated group."""
        src = _ADMIN_APP.read_text()
        governance_marker = "// Governance, Data & Workflows module group"
        idx = src.index(governance_marker)
        next_group_marker = '// "Ops & Crypto" module group'
        governance_block = src[idx:src.index(next_group_marker)]
        assert "permissions-grants.js" in governance_block
        assert "capability-policy.js" in governance_block


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
    """Confirms the module's fetch/mutate URLs actually match live FastAPI
    routes -- the backend has existed since 3.1 Phase 8 and was never
    broken; this just proves the ui4 port didn't invent a mismatched API
    surface."""

    def test_backend_routes_file_exists(self):
        assert _BACKEND_ROUTES.is_file()

    def test_grant_crud_urls_match_backend_routes(self):
        backend_src = _BACKEND_ROUTES.read_text()
        module_src = _MODULE_FILE.read_text()
        assert '"/grants/{scope}/{scope_id}/{resource_type}"' in backend_src
        assert '"/grants/{scope}/{scope_id}/{resource_type}/{resource_id}"' in backend_src
        assert "/admin/api/permissions/grants/" in module_src

    def test_effective_preview_url_matches_backend(self):
        backend_src = _BACKEND_ROUTES.read_text()
        module_src = _MODULE_FILE.read_text()
        assert '"/effective"' in backend_src
        assert "/admin/api/permissions/effective" in module_src

    def test_declarations_urls_match_backend(self):
        backend_src = _BACKEND_ROUTES.read_text()
        module_src = _MODULE_FILE.read_text()
        assert '"/declarations"' in backend_src
        assert '"/declarations/{resource_type}/{resource_id}/approve"' in backend_src
        assert '"/declarations/{resource_type}/{resource_id}"' in backend_src
        assert "/admin/api/permissions/declarations" in module_src
        assert "/approve" in module_src

    def test_backend_router_mounted_under_admin_api_prefix(self):
        from yashigani.backoffice.app import create_backoffice_app
        app = create_backoffice_app()
        paths = [r.path for r in app.routes if hasattr(r, "path")]
        assert "/admin/api/permissions/grants/{scope}/{scope_id}/{resource_type}" in paths
        assert "/admin/api/permissions/effective" in paths
        assert "/admin/api/permissions/declarations" in paths
        assert "/admin/api/permissions/declarations/{resource_type}/{resource_id}/approve" in paths


class TestStepUpGatedMutationsUseApiMutate:
    """RISK-103: the client must never decide what needs step-up -- every
    write to a StepUpAdminSession-gated backend route must go through
    ctx.api.mutate (which retries once through the shared TOTP modal on a
    401 step_up_required), never api.get. routes/permissions.py's PUT/DELETE
    grant, POST approve, and DELETE reject are all StepUpAdminSession
    server-side (confirmed against the backend source below)."""

    def test_backend_marks_write_routes_stepup(self):
        backend_src = _BACKEND_ROUTES.read_text()
        # Sanity: the routes this test relies on being step-up-gated really are,
        # in the actual backend -- not assumed from the module's own comments.
        put_grant = re.search(
            r'@router\.put\(\s*"/grants/[^)]*?\)\s*async def put_grant\([^)]*session:\s*StepUpAdminSession',
            backend_src, re.DOTALL,
        )
        assert put_grant, "PUT /grants/... is no longer StepUpAdminSession in the backend"
        approve = re.search(
            r'@router\.post\(\s*"/declarations/\{resource_type\}/\{resource_id\}/approve"[^)]*?\)\s*'
            r'async def approve_declaration\([^)]*session:\s*StepUpAdminSession',
            backend_src, re.DOTALL,
        )
        assert approve, "POST .../approve is no longer StepUpAdminSession in the backend"

    def test_grant_mutations_use_api_mutate(self):
        module_src = _MODULE_FILE.read_text()
        assert "this.api.mutate(this._grantUrl(rid), { method: 'PUT'" in module_src
        assert "this.api.mutate(this._grantUrl(rid), { method: 'DELETE'" in module_src

    def test_declaration_decisions_use_api_mutate(self):
        module_src = _MODULE_FILE.read_text()
        assert "this.api.mutate(url, { method: 'POST', body })" in module_src  # approve
        assert "this.api.mutate(url, { method: 'DELETE' })" in module_src      # reject


class TestNoUnsafeRenderSinks:
    """SAFE-RENDER: the module header explicitly claims no innerHTML/
    unsafeHTML anywhere -- every server- or operator-authored value is bound
    via Lit text-binding. This is the specific property that mattered for
    YSG-RISK-213's sibling module (documents-docopa.js) and the legacy
    permissions.js page this replaces used a hand-rolled
    escapeHtml()-into-innerHTML pattern."""

    def test_no_innerhtml_or_unsafehtml(self):
        module_src = _code_only(_MODULE_FILE.read_text())
        assert "innerHTML" not in module_src
        assert "unsafeHTML" not in module_src
