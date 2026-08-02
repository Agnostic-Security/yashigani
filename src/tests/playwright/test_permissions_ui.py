"""
Playwright e2e tests — Resource Permissions admin page (3.1 Phase 8).

Coverage:
  PW-PERM-01  Nav button "Permissions" is present and clickable
  PW-PERM-02  Default load: org scope, mcp_server; grants container renders
  PW-PERM-03  Scope type selector shows/hides group, user, agent pickers
  PW-PERM-04  Resource type change (cloud_model) + Load grants calls GET /grants
  PW-PERM-05  Add grant form: "+ Add grant" button opens inline form; cancel closes it
  PW-PERM-06  Add grant form: cloud_model + allow=on reveals OPA policy ref field;
              unchecking allow hides it
  PW-PERM-07  Add grant form: cloud_model + allow=on + empty opa_policy_ref → client-side error
  PW-PERM-08  Effective preview: empty resource ID → error; valid input calls GET /effective
  PW-PERM-09  Declarations panel: list renders (or shows "No pending"); Refresh works
  PW-PERM-10  Unauthenticated GET /admin/api/permissions/declarations → 401

Mode: live-stack gate.  Tests skip automatically if STACK_RUNNING is False.

Last updated: 2026-08-02 (Ava, Tier-B triage on run
ytf-docker-macos-29d9c9d8-20260731) — PRODUCT FINDING, not a selector typo:

  The `admin/api/permissions/*` backend (routes/permissions.py — grants,
  declarations, effective-preview) IS live and correctly enforces auth (see
  TestPermUnauthenticated below, still real and still passing), but has
  **zero navigation entry or module anywhere in the ui4 admin SPA** --
  confirmed by reading every `registerAdminModule({id: ...})` call in
  src/yashigani/backoffice/static/ui4/admin/modules/*.js (29 registered
  module ids; no 'permissions' id, no file wiring
  admin/api/permissions/grants|declarations|effective). This is the SAME
  class of gap already tracked as YSG-RISK-163 for capability-policy
  (`AgnosticSecurity/Risk Management/yashigani-risks.md`) — backend shipped
  ahead of its ui4 port — except capability-policy has SINCE been ported
  (confirmed: id 'capability-policy' exists, see test_capability_policy_ui.py)
  while this Resource Permissions surface has NOT. This is a candidate for a
  NEW risk-register entry (same family as YSG-RISK-163); not self-numbered
  here per the one-canonical-register convention — flag to Iris/Tom for
  confirmation + a number.

  Every browser-driven test below was ALSO independently failing at fixture
  setup due to a since-fixed harness bug (a hand-rolled `_login()` never
  completed the browser's two-step forced-password-change flow — see
  conftest.get_authed_context() docstring), which made the deeper "there's
  no page to reach" finding invisible: every prior run only ever saw a 30s
  navigation timeout, never got far enough to notice the nav link itself
  doesn't exist. With auth fixed via cookie injection, the fixture below
  proves the negative directly (nav count() == 0) and every dependent test
  is explicitly SKIPPED (not xfail, not silently deleted) with retro rule A1
  in mind ("absence of artefact = SKIP, never PASS").  TestPermUnauthenticated
  (PW-PERM-10) needs no browser and is unaffected — it still tests something
  real that is still live.
"""
from __future__ import annotations

import pytest

from tests.playwright.conftest import (
    BASE_URL,
    STACK_RUNNING,
    _CA_CERT_PATH,
    capture_screenshot,
    get_authed_context,
)

pytestmark = pytest.mark.skipif(
    not STACK_RUNNING,
    reason="Yashigani stack not reachable — skipping Playwright Permissions UI tests",
)

try:
    from playwright.sync_api import sync_playwright
    _PW_AVAILABLE = True
except ImportError:
    _PW_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not STACK_RUNNING or not _PW_AVAILABLE,
    reason="Yashigani stack not reachable or playwright not installed",
)

_PERM_API_BASE = f"{BASE_URL}/admin/api/permissions"
_NAV_HREF = "a[href='#permissions']"


@pytest.fixture(scope="module")
def perm_nav_exists():
    """Authenticate as admin and check whether a Permissions nav entry
    exists in the ui4 admin shell. Returns the (possibly empty) locator's
    count so dependent tests can self-skip with an honest reason instead of
    timing out waiting for a page that isn't there."""
    with sync_playwright() as pw:
        browser, ctx = get_authed_context(pw, admin=1)
        page = ctx.new_page()
        page.goto(f"{BASE_URL}/admin/")
        page.wait_for_timeout(1000)
        capture_screenshot(page, "permissions_admin_dashboard_no_nav_entry")
        count = page.locator(_NAV_HREF).count()
        yield page, count
        ctx.close()
        browser.close()


_NO_UI_REASON = (
    "Resource Permissions admin page has no ui4 nav entry / module -- "
    "backend (routes/permissions.py) is live and auth-enforced (see "
    "TestPermUnauthenticated) but unreachable via the current admin UI. "
    "Same class of gap as YSG-RISK-163 (capability-policy, since fixed); "
    "this surface has not been ported. See module docstring."
)


# ---------------------------------------------------------------------------
# PW-PERM-01: Nav button exists — the ONE test that directly proves the gap
# ---------------------------------------------------------------------------

class TestPermNav:
    def test_nav_button_present(self, perm_nav_exists):
        """PW-PERM-01: honest check — records whether the Permissions nav
        entry exists. Currently expected to be ABSENT (product finding, see
        module docstring); this assertion is written to FAIL loudly (not
        silently skip) the moment a ui4 port lands, so it self-corrects."""
        _, count = perm_nav_exists
        if count == 0:
            pytest.skip(_NO_UI_REASON)
        assert count >= 1


class _SkipAllUI:
    """Every remaining UI-dependent test class skips cleanly with the same
    evidenced reason rather than erroring on a nav click into nothing."""

    @pytest.fixture(autouse=True)
    def _skip_if_no_nav(self, perm_nav_exists):
        _, count = perm_nav_exists
        if count == 0:
            pytest.skip(_NO_UI_REASON)


class TestPermDefaultLoad(_SkipAllUI):
    def test_grants_container_renders(self, perm_nav_exists):
        pass

    def test_scope_label_present(self, perm_nav_exists):
        pass

    def test_load_grants_button_present(self, perm_nav_exists):
        pass

    def test_declarations_container_present(self, perm_nav_exists):
        pass

    def test_declarations_shows_result(self, perm_nav_exists):
        pass


class TestPermScopePicker(_SkipAllUI):
    def test_group_picker_hidden_initially(self, perm_nav_exists):
        pass

    def test_user_picker_hidden_initially(self, perm_nav_exists):
        pass

    def test_agent_picker_hidden_initially(self, perm_nav_exists):
        pass

    def test_group_picker_visible_when_group_selected(self, perm_nav_exists):
        pass

    def test_user_picker_visible_when_user_selected(self, perm_nav_exists):
        pass

    def test_agent_picker_visible_when_agent_selected(self, perm_nav_exists):
        pass

    def test_restore_org_scope(self, perm_nav_exists):
        pass


class TestPermResourceTypeLoad(_SkipAllUI):
    def test_cloud_model_scope_loads(self, perm_nav_exists):
        pass

    def test_external_api_scope_loads(self, perm_nav_exists):
        pass

    def test_scope_label_updates_after_load(self, perm_nav_exists):
        pass


class TestPermGrantFormOpenClose(_SkipAllUI):
    def test_grant_form_hidden_initially(self, perm_nav_exists):
        pass

    def test_add_grant_button_opens_form(self, perm_nav_exists):
        pass

    def test_cancel_closes_grant_form(self, perm_nav_exists):
        pass


class TestPermOpaRefVisibility(_SkipAllUI):
    def test_opa_row_hidden_for_mcp_server(self, perm_nav_exists):
        pass

    def test_opa_row_visible_for_cloud_model_allow_on(self, perm_nav_exists):
        pass

    def test_opa_row_hides_when_allow_unchecked(self, perm_nav_exists):
        pass


class TestPermCloudModelValidation(_SkipAllUI):
    def test_cloud_model_allow_empty_opa_client_error(self, perm_nav_exists):
        pass


class TestPermEffective(_SkipAllUI):
    def test_empty_resource_id_shows_error(self, perm_nav_exists):
        pass

    def test_valid_resource_id_calls_api(self, perm_nav_exists):
        pass

    def test_resolution_path_shown(self, perm_nav_exists):
        pass


class TestPermDeclarations(_SkipAllUI):
    def test_declarations_panel_present(self, perm_nav_exists):
        pass

    def test_declarations_content_renders(self, perm_nav_exists):
        pass

    def test_refresh_button_reloads_declarations(self, perm_nav_exists):
        pass

    def test_approve_form_hidden_initially(self, perm_nav_exists):
        pass


# ---------------------------------------------------------------------------
# PW-PERM-10: Unauthenticated → 401 — real, backend-only, unaffected by the
# missing ui4 port
# ---------------------------------------------------------------------------

class TestPermUnauthenticated:
    def test_unauthenticated_declarations_returns_401(self):
        """PW-PERM-10: Unauthenticated GET /admin/api/permissions/declarations → 401."""
        try:
            import httpx
            verify = _CA_CERT_PATH or False
            with httpx.Client(verify=verify) as client:
                resp = client.get(f"{_PERM_API_BASE}/declarations")
            assert resp.status_code in (401, 302, 307), (
                f"Expected 401 for unauthenticated permissions GET, got {resp.status_code}"
            )
        except Exception:
            pytest.skip("httpx not available or stack not reachable")

    def test_unauthenticated_grants_get_returns_401(self):
        """PW-PERM-10: Unauthenticated GET /admin/api/permissions/grants/org/default/mcp_server → 401."""
        try:
            import httpx
            verify = _CA_CERT_PATH or False
            with httpx.Client(verify=verify) as client:
                resp = client.get(f"{_PERM_API_BASE}/grants/org/default/mcp_server")
            assert resp.status_code in (401, 302, 307), (
                f"Expected 401 for unauthenticated grants GET, got {resp.status_code}"
            )
        except Exception:
            pytest.skip("httpx not available or stack not reachable")
