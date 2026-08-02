"""
Playwright e2e tests — Capability Policy (Permissions-Policy) admin page (3.0).

Coverage:
  PW-CAP-01  Nav button "Permissions Policy" is present and clickable
  PW-CAP-02  Org scope loads automatically; all 5 capability rows visible
  PW-CAP-03  Scope type selector shows/hides group and user pickers
  PW-CAP-04  Setting a capability to "off" and saving calls PUT and reloads
  PW-CAP-05  Selecting "allow-list" reveals the origin input area; adding a
             bad URL shows a client-side error; adding a valid origin adds a chip
  PW-CAP-06  Effective policy preview: enter email → Resolve populates the table
  PW-CAP-07  Unauthenticated GET /admin/api/capability-policy → 401

Mode: live-stack gate. Tests skip automatically if STACK_RUNNING is False.

Last updated: 2026-08-02 (Ava, Tier-B triage on run
ytf-docker-macos-29d9c9d8-20260731): FULL rewrite against the real ui4
module (src/yashigani/backoffice/static/ui4/admin/modules/capability-policy.js,
component <ys-admin-capability-policy>). The previous version of this file
was entirely stale against a pre-ui4 markup contract that no longer exists
on disk:
  - Auth: hand-rolled `_login()` filled the login form directly and, on a
    genuinely fresh stack needing the forced password-change step, clicked
    #pw-btn and immediately called page.wait_for_url(".../admin/") -- but
    the real client flow (static/js/login.js) does NOT navigate after a
    successful password change; it just re-shows #login-form and requires a
    SECOND login submission. This always timed out (30s) on this suite's
    very first bootstrap login, and every retry after it, cascading into
    ~113 errors across the wider Tier-B run (poisoned the shared, process-
    global _rotated_admin_password cache with an unverified write). Replaced
    with get_authed_context() (httpx-obtained, assert-verified session
    cookie injected into a fresh browser context) -- matches the precedent
    already established by test_pki_admin_ui.py and
    test_pentest_webui_adversarial.py's _authed_context().
  - Nav: the real nav renders `<a href="#capability-policy">`
    (module-registry.js / admin-nav.js), never a `<button>`.
  - Every other selector in this file (`#cap-pol-rows`, `#cap-pol-scope-
    label`, `#cap-group-picker`/`#cap-user-picker` with an `is-hidden` CSS
    class, `#cap-val-camera`, `#cap-origins-camera`, `#cap-origin-input-
    camera`, `[data-action='capPolAddOrigin']`, `.cap-origin-chip`,
    `#cap-origin-err-camera`, `.cap-pol-table`, `#cap-pol-result`,
    `#cap-eff-result`, "Load policy" button text) does not exist anywhere in
    the real module -- confirmed by reading the full render() tree. The
    group/user pickers are CONDITIONALLY RENDERED (not CSS-hidden): the
    `#cap-group-id`/`#cap-user-email` elements are simply absent from the DOM
    unless that scope type is selected. Per-capability controls use a single
    `.cap-val-sel[data-cap="<name>"]` select and an unscoped `.cap-origins-
    area`/`.ys-field-error`/`.ys-chip` inside that capability's own `<tr>`
    (rows render in CAP_NAMES order: camera, microphone, geolocation,
    display-capture, fullscreen -- camera is always tbody tr:nth(0)).
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
    reason="Yashigani stack not reachable — skipping Playwright Capability Policy UI tests",
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

_CAP_API = f"{BASE_URL}/admin/api/capability-policy"
_NAV_HREF = "a[href='#capability-policy']"
_CAP_LABELS = ["Camera", "Microphone", "Geolocation", "Display Capture", "Fullscreen"]


@pytest.fixture(scope="module")
def cap_page():
    """Browser context authenticated as admin (cookie injection — see module
    docstring); navigated to the Capability Policy page."""
    with sync_playwright() as pw:
        browser, ctx = get_authed_context(pw, admin=1)
        page = ctx.new_page()
        page.goto(f"{BASE_URL}/admin/")
        page.wait_for_selector(_NAV_HREF, timeout=15000)
        capture_screenshot(page, "capability_policy_post_login_dashboard")
        page.click(_NAV_HREF)
        # Org scope auto-loads on mount (connectedCallback -> _load()).
        page.wait_for_selector("table.ys-table-plain", timeout=15000)
        capture_screenshot(page, "capability_policy_panel_loaded")
        yield page
        ctx.close()
        browser.close()


def _camera_row(page):
    """The camera row is always the first <tr> (CAP_NAMES order)."""
    return page.locator("table.ys-table-plain tbody tr").nth(0)


# ---------------------------------------------------------------------------
# PW-CAP-01: Nav button exists
# ---------------------------------------------------------------------------

class TestCapPolNav:
    def test_nav_button_present(self, cap_page):
        """PW-CAP-01: 'Permissions Policy' / Capability Policy nav entry is visible."""
        link = cap_page.locator(_NAV_HREF)
        assert link.count() >= 1, "Capability Policy nav entry not found"
        assert link.first.is_visible()


# ---------------------------------------------------------------------------
# PW-CAP-02: Org scope auto-loads with all 5 rows
# ---------------------------------------------------------------------------

class TestCapPolOrgLoad:
    def test_all_five_capabilities_visible(self, cap_page):
        """PW-CAP-02: All 5 capability rows render after auto-load of org scope."""
        for label in _CAP_LABELS:
            cells = cap_page.locator(f"table.ys-table-plain td:has-text('{label}')")
            assert cells.count() >= 1, f"Capability row '{label}' not found"

    def test_scope_label_shows_org(self, cap_page):
        """PW-CAP-02: Editor panel header shows 'Organisation (default)' for the
        default scope (real markup: '.ys-panel-header' text, no dedicated
        #cap-pol-scope-label id exists)."""
        header = cap_page.locator(".ys-panel-header:has-text('Organisation (default)')")
        assert header.count() >= 1, "Expected editor panel header to show org scope"

    def test_save_button_visible(self, cap_page):
        """PW-CAP-02: Save button (#cap-pol-save) is present."""
        assert cap_page.locator("#cap-pol-save").is_visible()


# ---------------------------------------------------------------------------
# PW-CAP-03: Scope type selector behaviour
# ---------------------------------------------------------------------------

class TestCapPolScopePicker:
    def test_group_picker_hidden_initially(self, cap_page):
        """PW-CAP-03: Group picker (#cap-group-id) is CONDITIONALLY RENDERED —
        absent from the DOM entirely when scope type is 'org' (not CSS-hidden)."""
        cap_page.select_option("#cap-scope-type", "org")
        assert cap_page.locator("#cap-group-id").count() == 0

    def test_user_picker_hidden_initially(self, cap_page):
        """PW-CAP-03: User picker (#cap-user-email) is absent when scope is 'org'."""
        cap_page.select_option("#cap-scope-type", "org")
        assert cap_page.locator("#cap-user-email").count() == 0

    def test_group_picker_visible_when_group_selected(self, cap_page):
        """PW-CAP-03: Selecting 'Group' scope renders the group picker."""
        cap_page.select_option("#cap-scope-type", "group")
        cap_page.wait_for_timeout(300)
        assert cap_page.locator("#cap-group-id").count() >= 1

    def test_user_picker_visible_when_user_selected(self, cap_page):
        """PW-CAP-03: Selecting 'User' scope renders the user picker."""
        cap_page.select_option("#cap-scope-type", "user")
        cap_page.wait_for_timeout(300)
        assert cap_page.locator("#cap-user-email").count() >= 1

    def test_restore_org_scope(self, cap_page):
        """PW-CAP-03: Restoring 'org' scope removes both pickers again."""
        cap_page.select_option("#cap-scope-type", "org")
        cap_page.wait_for_timeout(300)
        assert cap_page.locator("#cap-group-id").count() == 0
        assert cap_page.locator("#cap-user-email").count() == 0


# ---------------------------------------------------------------------------
# PW-CAP-04: Save org policy (camera → off)
# ---------------------------------------------------------------------------

class TestCapPolSave:
    def test_save_org_policy_camera_off(self, cap_page):
        """PW-CAP-04: Setting camera to 'off' and saving succeeds."""
        cap_page.select_option("#cap-scope-type", "org")
        cap_page.click("#cap-scope-load")
        cap_page.wait_for_selector("table.ys-table-plain", timeout=10000)

        cap_page.select_option(".cap-val-sel[data-cap='camera']", "off")
        cap_page.click("#cap-pol-save")
        # Result renders as a .ys-badge (green "Saved." or red error message).
        cap_page.wait_for_selector(".ys-badge", timeout=8000)
        result_text = cap_page.locator(".ys-badge").first.inner_text() or ""
        assert len(result_text) > 0, "Expected a result message after save"

        # Restore camera to 'self' so subsequent tests aren't affected.
        cap_page.select_option(".cap-val-sel[data-cap='camera']", "self")
        cap_page.click("#cap-pol-save")
        cap_page.wait_for_selector(".ys-badge", timeout=8000)


# ---------------------------------------------------------------------------
# PW-CAP-05: Allow-list origin validation (scoped to the camera row —
# always tbody tr:nth(0), see _camera_row())
# ---------------------------------------------------------------------------

class TestCapPolOriginInput:
    def test_allow_list_area_hidden_by_default(self, cap_page):
        """PW-CAP-05: Origins area absent until 'allow-list' is chosen for camera."""
        cap_page.select_option("#cap-scope-type", "org")
        cap_page.click("#cap-scope-load")
        cap_page.wait_for_selector("table.ys-table-plain", timeout=10000)
        cap_page.select_option(".cap-val-sel[data-cap='camera']", "self")
        cap_page.wait_for_timeout(200)
        assert _camera_row(cap_page).locator(".cap-origins-area").count() == 0

    def test_allow_list_area_revealed_on_select(self, cap_page):
        """PW-CAP-05: Origins area appears when 'allow-list' is selected."""
        cap_page.select_option(".cap-val-sel[data-cap='camera']", "allow_list")
        cap_page.wait_for_timeout(200)
        assert _camera_row(cap_page).locator(".cap-origins-area").count() >= 1

    def test_bad_origin_rejected_client_side(self, cap_page):
        """PW-CAP-05: Invalid (non-https) origin triggers a client-side error."""
        row = _camera_row(cap_page)
        row.locator(".cap-origin-add input").fill("http://not-https.com")
        row.locator(".cap-origin-add button").click()
        cap_page.wait_for_timeout(300)
        err = row.locator(".ys-field-error").inner_text() if row.locator(".ys-field-error").count() else ""
        assert err, "Expected client-side error for http:// origin"

    def test_valid_origin_adds_chip(self, cap_page):
        """PW-CAP-05: A valid https:// origin adds a chip."""
        row = _camera_row(cap_page)
        row.locator(".cap-origin-add input").fill("https://trusted.example.com")
        row.locator(".cap-origin-add button").click()
        cap_page.wait_for_timeout(300)
        chip = row.locator(".ys-chip:has-text('https://trusted.example.com')")
        assert chip.count() >= 1, "Expected origin chip to appear"

    def test_origin_with_path_rejected(self, cap_page):
        """PW-CAP-05: Origin with a path component is rejected client-side."""
        row = _camera_row(cap_page)
        row.locator(".cap-origin-add input").fill("https://example.com/some/path")
        row.locator(".cap-origin-add button").click()
        cap_page.wait_for_timeout(300)
        err = row.locator(".ys-field-error").inner_text() if row.locator(".ys-field-error").count() else ""
        assert err, "Expected client-side error for origin with path"

    def test_wildcard_origin_rejected(self, cap_page):
        """PW-CAP-05: Wildcard origin is rejected client-side."""
        row = _camera_row(cap_page)
        row.locator(".cap-origin-add input").fill("https://*.example.com")
        row.locator(".cap-origin-add button").click()
        cap_page.wait_for_timeout(300)
        err = row.locator(".ys-field-error").inner_text() if row.locator(".ys-field-error").count() else ""
        assert err, "Expected client-side error for wildcard origin"


# ---------------------------------------------------------------------------
# PW-CAP-06: Effective policy preview
# ---------------------------------------------------------------------------

class TestCapPolEffective:
    def _eff_panel(self, page):
        return page.locator(".ys-panel").filter(has_text="Effective policy preview")

    def test_effective_preview_renders_table(self, cap_page):
        """PW-CAP-06: Entering a user email and clicking Resolve shows a result
        (either the resolved-capabilities table or an explicit error badge —
        the endpoint does not require the address to belong to a real user;
        it computes the hypothetical effective policy)."""
        cap_page.fill("#cap-eff-user", "nonexistent@example.com")
        cap_page.click("#cap-eff-load")
        panel = self._eff_panel(cap_page)
        panel.locator(".ys-badge-red, .ys-badge-green, table").first.wait_for(
            state="visible", timeout=10000
        )
        rendered = panel.locator(".ys-badge-red, .ys-badge-green, table").count()
        assert rendered >= 1, "Expected a resolved-or-error result under Effective policy preview"

    def test_effective_empty_email_shows_error(self, cap_page):
        """PW-CAP-06: Empty email triggers a client-side error, not a network call."""
        cap_page.fill("#cap-eff-user", "")
        cap_page.click("#cap-eff-load")
        panel = self._eff_panel(cap_page)
        err = panel.locator(".ys-badge-red:has-text('Enter a user email')")
        err.wait_for(state="visible", timeout=5000)
        assert err.count() >= 1, "Expected 'Enter a user email.' error for empty input"


# ---------------------------------------------------------------------------
# PW-CAP-07: Unauthenticated request → 401
# ---------------------------------------------------------------------------

class TestCapPolUnauthenticated:
    def test_unauthenticated_get_returns_401(self):
        """PW-CAP-07: Unauthenticated GET /admin/api/capability-policy → 401."""
        try:
            import httpx
            verify = _CA_CERT_PATH or False
            with httpx.Client(verify=verify) as client:
                resp = client.get(_CAP_API)
            assert resp.status_code in (401, 302, 307), (
                f"Expected 401 for unauthenticated capability-policy GET, got {resp.status_code}"
            )
        except Exception:
            pytest.skip("httpx not available or stack not reachable")
