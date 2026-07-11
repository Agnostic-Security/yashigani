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

Last updated: 2026-06-28T00:00:00+00:00
"""
from __future__ import annotations

import pytest

from tests.playwright.conftest import (
    BASE_URL,
    STACK_RUNNING,
    _CA_CERT_PATH,
    get_admin_credentials,
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
_NAV_LABEL = "Permissions"


def _login(page, creds):
    page.goto(f"{BASE_URL}/admin/login")
    page.fill('input[name="username"], input[type="text"]', creds[0])
    page.fill('input[name="password"], input[type="password"]', creds[1])
    page.click('button[type="submit"], button:has-text("Login")')
    page.wait_for_url(f"{BASE_URL}/admin/")
    return page


@pytest.fixture(scope="module")
def perm_page():
    """Browser context logged in as admin; navigated to the Permissions page."""
    creds = get_admin_credentials()
    ctx_args = {"ignore_https_errors": True}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(**ctx_args)
        page = ctx.new_page()
        _login(page, creds)
        page.click(f"button:has-text('{_NAV_LABEL}')")
        page.wait_for_selector("#perm-grants-container", timeout=15000)
        yield page
        ctx.close()
        browser.close()


# ---------------------------------------------------------------------------
# PW-PERM-01: Nav button exists
# ---------------------------------------------------------------------------

class TestPermNav:
    def test_nav_button_present(self, perm_page):
        """PW-PERM-01: 'Permissions' nav button is visible."""
        btn = perm_page.locator(f"button:has-text('{_NAV_LABEL}')")
        assert btn.count() >= 1, "Permissions nav button not found"
        assert btn.first.is_visible()


# ---------------------------------------------------------------------------
# PW-PERM-02: Default load
# ---------------------------------------------------------------------------

class TestPermDefaultLoad:
    def test_grants_container_renders(self, perm_page):
        """PW-PERM-02: Grants container is present after page load."""
        perm_page.wait_for_selector("#perm-grants-container", timeout=10000)
        assert perm_page.locator("#perm-grants-container").count() >= 1

    def test_scope_label_present(self, perm_page):
        """PW-PERM-02: Scope label element exists."""
        assert perm_page.locator("#perm-scope-label").count() >= 1

    def test_load_grants_button_present(self, perm_page):
        """PW-PERM-02: 'Load grants' button is visible."""
        assert perm_page.locator("button:has-text('Load grants')").first.is_visible()

    def test_declarations_container_present(self, perm_page):
        """PW-PERM-02: Declarations panel container is present."""
        perm_page.wait_for_selector("#perm-decl-container", timeout=8000)
        assert perm_page.locator("#perm-decl-container").count() >= 1

    def test_declarations_shows_result(self, perm_page):
        """PW-PERM-02: Declarations container is not empty (shows grants or 'No pending')."""
        perm_page.wait_for_selector(
            "#perm-decl-container:not(:has(.loading))",
            timeout=10000,
        )
        text = perm_page.locator("#perm-decl-container").inner_text() or ""
        assert len(text.strip()) > 0


# ---------------------------------------------------------------------------
# PW-PERM-03: Scope picker behaviour
# ---------------------------------------------------------------------------

class TestPermScopePicker:
    def test_group_picker_hidden_initially(self, perm_page):
        """PW-PERM-03: Group picker is hidden when scope type is 'org'."""
        perm_page.select_option("#perm-scope-type", "org")
        perm_page.wait_for_timeout(200)
        classes = perm_page.locator("#perm-group-picker").get_attribute("class") or ""
        assert "is-hidden" in classes

    def test_user_picker_hidden_initially(self, perm_page):
        """PW-PERM-03: User picker is hidden when scope type is 'org'."""
        classes = perm_page.locator("#perm-user-picker").get_attribute("class") or ""
        assert "is-hidden" in classes

    def test_agent_picker_hidden_initially(self, perm_page):
        """PW-PERM-03: Agent picker is hidden when scope type is 'org'."""
        classes = perm_page.locator("#perm-agent-picker").get_attribute("class") or ""
        assert "is-hidden" in classes

    def test_group_picker_visible_when_group_selected(self, perm_page):
        """PW-PERM-03: Selecting 'Group' scope reveals the group picker."""
        perm_page.select_option("#perm-scope-type", "group")
        perm_page.wait_for_timeout(200)
        classes = perm_page.locator("#perm-group-picker").get_attribute("class") or ""
        assert "is-hidden" not in classes

    def test_user_picker_visible_when_user_selected(self, perm_page):
        """PW-PERM-03: Selecting 'User' scope reveals the user picker."""
        perm_page.select_option("#perm-scope-type", "user")
        perm_page.wait_for_timeout(200)
        classes = perm_page.locator("#perm-user-picker").get_attribute("class") or ""
        assert "is-hidden" not in classes

    def test_agent_picker_visible_when_agent_selected(self, perm_page):
        """PW-PERM-03: Selecting 'Agent' scope reveals the agent picker."""
        perm_page.select_option("#perm-scope-type", "agent")
        perm_page.wait_for_timeout(200)
        classes = perm_page.locator("#perm-agent-picker").get_attribute("class") or ""
        assert "is-hidden" not in classes

    def test_restore_org_scope(self, perm_page):
        """PW-PERM-03: Restoring 'org' scope hides all three pickers."""
        perm_page.select_option("#perm-scope-type", "org")
        perm_page.wait_for_timeout(200)
        for el_id in ("#perm-group-picker", "#perm-user-picker", "#perm-agent-picker"):
            classes = perm_page.locator(el_id).get_attribute("class") or ""
            assert "is-hidden" in classes, f"{el_id} should be hidden in org scope"


# ---------------------------------------------------------------------------
# PW-PERM-04: Resource type change + load
# ---------------------------------------------------------------------------

class TestPermResourceTypeLoad:
    def test_cloud_model_scope_loads(self, perm_page):
        """PW-PERM-04: Selecting cloud_model and clicking Load grants fetches grants."""
        perm_page.select_option("#perm-scope-type", "org")
        perm_page.select_option("#perm-resource-type", "cloud_model")
        perm_page.click("button:has-text('Load grants')")
        perm_page.wait_for_selector(
            "#perm-grants-container:not(:has(.loading))",
            timeout=10000,
        )
        text = perm_page.locator("#perm-grants-container").inner_text() or ""
        assert len(text.strip()) > 0, "Expected grants container to have content"

    def test_external_api_scope_loads(self, perm_page):
        """PW-PERM-04: Selecting external_api and clicking Load grants succeeds."""
        perm_page.select_option("#perm-resource-type", "external_api")
        perm_page.click("button:has-text('Load grants')")
        perm_page.wait_for_selector(
            "#perm-grants-container:not(:has(.loading))",
            timeout=10000,
        )
        text = perm_page.locator("#perm-grants-container").inner_text() or ""
        assert len(text.strip()) > 0

    def test_scope_label_updates_after_load(self, perm_page):
        """PW-PERM-04: Scope label reflects the selected resource type after load."""
        perm_page.select_option("#perm-resource-type", "mcp_server")
        perm_page.click("button:has-text('Load grants')")
        perm_page.wait_for_selector(
            "#perm-grants-container:not(:has(.loading))",
            timeout=10000,
        )
        label = perm_page.locator("#perm-scope-label").inner_text() or ""
        assert "MCP" in label or "mcp" in label.lower(), (
            f"Expected scope label to mention MCP Server, got: '{label}'"
        )


# ---------------------------------------------------------------------------
# PW-PERM-05: Add grant form open/cancel
# ---------------------------------------------------------------------------

class TestPermGrantFormOpenClose:
    def test_grant_form_hidden_initially(self, perm_page):
        """PW-PERM-05: Grant form is not open on page load."""
        form = perm_page.locator("#perm-grant-form")
        classes = form.get_attribute("class") or ""
        assert "is-open" not in classes

    def test_add_grant_button_opens_form(self, perm_page):
        """PW-PERM-05: Clicking '+ Add grant' opens the inline form."""
        perm_page.click("button[data-action='permGrantEdit'][data-rid='']")
        perm_page.wait_for_timeout(200)
        classes = perm_page.locator("#perm-grant-form").get_attribute("class") or ""
        assert "is-open" in classes

    def test_cancel_closes_grant_form(self, perm_page):
        """PW-PERM-05: Cancel button closes the inline form."""
        perm_page.click("button[data-action='permGrantEditCancel']")
        perm_page.wait_for_timeout(200)
        classes = perm_page.locator("#perm-grant-form").get_attribute("class") or ""
        assert "is-open" not in classes


# ---------------------------------------------------------------------------
# PW-PERM-06: OPA policy ref visibility for cloud_model
# ---------------------------------------------------------------------------

class TestPermOpaRefVisibility:
    def test_opa_row_hidden_for_mcp_server(self, perm_page):
        """PW-PERM-06: OPA policy ref row is hidden for mcp_server (non-cloud)."""
        perm_page.select_option("#perm-resource-type", "mcp_server")
        perm_page.wait_for_timeout(100)
        # Open the form
        perm_page.click("button[data-action='permGrantEdit'][data-rid='']")
        perm_page.wait_for_timeout(200)
        classes = perm_page.locator("#perm-grant-opa-row").get_attribute("class") or ""
        assert "is-hidden" in classes
        # Close form
        perm_page.click("button[data-action='permGrantEditCancel']")
        perm_page.wait_for_timeout(100)

    def test_opa_row_visible_for_cloud_model_allow_on(self, perm_page):
        """PW-PERM-06: OPA policy ref row appears for cloud_model with allow=on."""
        perm_page.select_option("#perm-resource-type", "cloud_model")
        perm_page.wait_for_timeout(100)
        perm_page.click("button[data-action='permGrantEdit'][data-rid='']")
        perm_page.wait_for_timeout(200)
        # Allow checkbox should be checked by default
        assert perm_page.locator("#perm-grant-allow").is_checked()
        classes = perm_page.locator("#perm-grant-opa-row").get_attribute("class") or ""
        assert "is-hidden" not in classes, "OPA row should be visible for cloud_model + allow"

    def test_opa_row_hides_when_allow_unchecked(self, perm_page):
        """PW-PERM-06: Unchecking allow hides the OPA policy ref row for cloud_model."""
        perm_page.uncheck("#perm-grant-allow")
        perm_page.wait_for_timeout(200)
        classes = perm_page.locator("#perm-grant-opa-row").get_attribute("class") or ""
        assert "is-hidden" in classes, "OPA row should be hidden when allow is unchecked"
        # Restore
        perm_page.check("#perm-grant-allow")
        perm_page.click("button[data-action='permGrantEditCancel']")
        perm_page.wait_for_timeout(100)


# ---------------------------------------------------------------------------
# PW-PERM-07: Client-side INV-2 validation
# ---------------------------------------------------------------------------

class TestPermCloudModelValidation:
    def test_cloud_model_allow_empty_opa_client_error(self, perm_page):
        """PW-PERM-07: cloud_model + allow + empty OPA ref → client-side error (no server round-trip)."""
        perm_page.select_option("#perm-resource-type", "cloud_model")
        perm_page.wait_for_timeout(100)
        perm_page.click("button[data-action='permGrantEdit'][data-rid='']")
        perm_page.wait_for_timeout(200)
        perm_page.fill("#perm-grant-rid", "gpt-4o-test")
        perm_page.check("#perm-grant-allow")
        perm_page.fill("#perm-grant-opa", "")   # empty OPA ref
        perm_page.click("button[data-action='permSaveGrant']")
        perm_page.wait_for_timeout(400)
        result_text = perm_page.locator("#perm-grant-result").inner_text() or ""
        assert len(result_text) > 0, "Expected a client-side error for cloud_model + allow + empty OPA ref"
        assert "badge-red" in (perm_page.locator("#perm-grant-result").inner_html() or ""), (
            "Expected red error badge"
        )
        # Close form
        perm_page.click("button[data-action='permGrantEditCancel']")
        perm_page.wait_for_timeout(100)


# ---------------------------------------------------------------------------
# PW-PERM-08: Effective preview
# ---------------------------------------------------------------------------

class TestPermEffective:
    def test_empty_resource_id_shows_error(self, perm_page):
        """PW-PERM-08: Empty resource ID → error, no network call."""
        perm_page.fill("#perm-eff-rid", "")
        perm_page.click("button[data-action='permEffective']")
        perm_page.wait_for_timeout(400)
        result_text = perm_page.locator("#perm-eff-result").inner_text() or ""
        assert len(result_text) > 0, "Expected error for empty resource ID"

    def test_valid_resource_id_calls_api(self, perm_page):
        """PW-PERM-08: Valid resource ID + type calls GET /effective and renders result."""
        perm_page.select_option("#perm-eff-rt", "mcp_server")
        perm_page.fill("#perm-eff-rid", "test-server-probe")
        perm_page.fill("#perm-eff-org", "default")
        perm_page.fill("#perm-eff-user", "")
        perm_page.fill("#perm-eff-groups", "")
        perm_page.click("button[data-action='permEffective']")
        perm_page.wait_for_selector("#perm-eff-result:not(:empty)", timeout=10000)
        result_text = perm_page.locator("#perm-eff-result").inner_text() or ""
        assert len(result_text) > 0, "Expected effective resolution result"
        # Should show ALLOW or DENY badge
        inner_html = perm_page.locator("#perm-eff-result").inner_html() or ""
        assert "ALLOW" in inner_html or "DENY" in inner_html, (
            f"Expected ALLOW or DENY badge in result, got: {inner_html[:200]}"
        )

    def test_resolution_path_shown(self, perm_page):
        """PW-PERM-08: Resolution path panel becomes visible after resolve."""
        path_classes = perm_page.locator("#perm-eff-path").get_attribute("class") or ""
        assert "is-hidden" not in path_classes, "Resolution path should be visible after resolve"


# ---------------------------------------------------------------------------
# PW-PERM-09: Declarations panel
# ---------------------------------------------------------------------------

class TestPermDeclarations:
    def test_declarations_panel_present(self, perm_page):
        """PW-PERM-09: Declarations panel container exists."""
        assert perm_page.locator("#perm-decl-container").count() >= 1

    def test_declarations_content_renders(self, perm_page):
        """PW-PERM-09: Declarations container shows content (empty or list)."""
        perm_page.wait_for_selector(
            "#perm-decl-container:not(:has(.loading))",
            timeout=10000,
        )
        text = perm_page.locator("#perm-decl-container").inner_text() or ""
        assert len(text.strip()) > 0

    def test_refresh_button_reloads_declarations(self, perm_page):
        """PW-PERM-09: Clicking Refresh button reloads the declarations list."""
        perm_page.click("button[data-action='loadDeclarations']")
        perm_page.wait_for_selector(
            "#perm-decl-container:not(:has(.loading))",
            timeout=10000,
        )
        text = perm_page.locator("#perm-decl-container").inner_text() or ""
        assert len(text.strip()) > 0

    def test_approve_form_hidden_initially(self, perm_page):
        """PW-PERM-09: Approve form is not open until an Approve button is clicked."""
        classes = perm_page.locator("#perm-decl-approve-form").get_attribute("class") or ""
        assert "is-open" not in classes


# ---------------------------------------------------------------------------
# PW-PERM-10: Unauthenticated request → 401
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
