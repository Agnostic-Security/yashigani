"""
Unit tests — Runtime Settings UI Phase 2.

Verifies that the Phase 2 web UI artefacts are correctly wired:

  1. dashboard.html includes the nav button for Runtime Settings.
  2. dashboard.html includes the page div #page-runtime-settings.
  3. dashboard.html includes the settings table (#rs-tbody) and edit form.
  4. dashboard.html loads runtime-settings.js as a defer <script>.
  5. runtime-settings.js exposes loadRuntimeSettings, rsEditRow, rsResetRow.
  6. runtime-settings.js calls apiMutate for PUT and POST/reset (StepUp path).
  7. runtime-settings.js calls api (read-only) for GET.
  8. dashboard.js showPage() dispatches to loadRuntimeSettings for the page.
  9. dashboard.js event delegation handles rsEditRow and rsResetRow actions.
  10. dashboard.css contains runtime-settings CSS classes.

These are static-artefact tests — no server needed.

v2.24.3 / admin-surfaces-all-runtime-settings Phase 2.
Last updated: 2026-05-25T00:00:00+00:00
"""
from __future__ import annotations

import pathlib
import re

import pytest

# ── Paths ────────────────────────────────────────────────────────────────────

_REPO = pathlib.Path(__file__).parent.parent.parent.parent  # yashigani/
_STATIC = _REPO / "src" / "yashigani" / "backoffice" / "static"
_TEMPLATES = _REPO / "src" / "yashigani" / "backoffice" / "templates"

_DASHBOARD_HTML = _TEMPLATES / "dashboard.html"
_DASHBOARD_JS   = _STATIC / "js" / "dashboard.js"
_RS_JS          = _STATIC / "js" / "runtime-settings.js"
_DASHBOARD_CSS  = _STATIC / "css" / "dashboard.css"


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def dashboard_html() -> str:
    return _DASHBOARD_HTML.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def dashboard_js() -> str:
    return _DASHBOARD_JS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def rs_js() -> str:
    return _RS_JS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def dashboard_css() -> str:
    return _DASHBOARD_CSS.read_text(encoding="utf-8")


# ── HTML structure tests ──────────────────────────────────────────────────────

class TestDashboardHtml:
    def test_nav_button_present(self, dashboard_html):
        """Nav bar contains a Runtime Settings button."""
        assert 'data-param="runtime-settings"' in dashboard_html, (
            "Nav bar is missing the Runtime Settings button "
            "(data-param=\"runtime-settings\")"
        )

    def test_page_div_present(self, dashboard_html):
        """SPA page div #page-runtime-settings exists."""
        assert 'id="page-runtime-settings"' in dashboard_html

    def test_settings_tbody_present(self, dashboard_html):
        """Settings table body #rs-tbody is present."""
        assert 'id="rs-tbody"' in dashboard_html

    def test_edit_form_present(self, dashboard_html):
        """Inline edit form #rs-edit-form is present."""
        assert 'id="rs-edit-form"' in dashboard_html

    def test_edit_form_has_save_and_cancel(self, dashboard_html):
        """Edit form has Save and Cancel buttons."""
        assert 'id="rs-btn-save"' in dashboard_html
        assert 'id="rs-btn-cancel"' in dashboard_html

    def test_edit_form_has_value_input(self, dashboard_html):
        """Edit form has value input."""
        assert 'id="rs-edit-value"' in dashboard_html

    def test_totp_note_mentions_stepup(self, dashboard_html):
        """Panel body mentions TOTP step-up for writes (ASVS V6.8.4)."""
        assert "step-up" in dashboard_html.lower() or "TOTP" in dashboard_html, (
            "Runtime settings panel should mention TOTP step-up requirement"
        )

    def test_toast_div_present(self, dashboard_html):
        """Toast notification element present."""
        assert 'id="rs-toast"' in dashboard_html

    def test_rs_js_script_tag_present(self, dashboard_html):
        """runtime-settings.js is loaded as a defer <script>."""
        assert 'src="/static/js/runtime-settings.js"' in dashboard_html
        # Must be defer — no inline-js fallback (CSP script-src 'self')
        assert re.search(
            r'<script[^>]+runtime-settings\.js[^>]+defer',
            dashboard_html,
        ) or re.search(
            r'<script[^>]+defer[^>]+runtime-settings\.js',
            dashboard_html,
        ), "runtime-settings.js <script> tag must have defer attribute"

    def test_page_table_has_correct_columns(self, dashboard_html):
        """Settings table has expected column headers."""
        for col in ("Setting Key", "Current Value", "Source", "Last Changed By", "Last Changed At"):
            assert col in dashboard_html, f"Column header '{col}' missing from runtime-settings table"


# ── JS tests — runtime-settings.js ───────────────────────────────────────────

class TestRuntimeSettingsJs:
    def test_file_exists(self):
        assert _RS_JS.exists(), "runtime-settings.js does not exist"

    def test_exposes_load_function(self, rs_js):
        """loadRuntimeSettings is exposed on window for showPage() to call."""
        assert "window.loadRuntimeSettings = loadRuntimeSettings" in rs_js

    def test_exposes_edit_function(self, rs_js):
        """rsEditRow function is defined."""
        assert "function rsEditRow(" in rs_js

    def test_exposes_reset_function(self, rs_js):
        """rsResetRow function is defined."""
        assert "function rsResetRow(" in rs_js

    def test_get_uses_api_not_apiMutate(self, rs_js):
        """loadRuntimeSettings uses read-only api() for GET (no StepUp on reads)."""
        # api() is used in loadRuntimeSettings
        assert "await api('/admin/runtime-settings')" in rs_js

    def test_put_uses_apiMutate(self, rs_js):
        """rsSaveEdit uses apiMutate for PUT (triggers StepUp on 401)."""
        assert "apiMutate('/admin/runtime-settings/" in rs_js
        # PUT method
        assert "method: 'PUT'" in rs_js

    def test_reset_uses_apiMutate(self, rs_js):
        """rsResetRow uses apiMutate for POST /reset (triggers StepUp on 401)."""
        # POST /reset
        assert "/reset'" in rs_js
        assert "method: 'POST'" in rs_js

    def test_no_inline_event_handlers(self, rs_js):
        """No onclick= inline handlers — CSP script-src 'self' compliant."""
        assert "onclick=" not in rs_js, (
            "runtime-settings.js must not use inline onclick= (violates CSP script-src 'self')"
        )

    def test_uses_escapeHtml_for_user_data(self, rs_js):
        """All user-controlled values rendered via escapeHtml (CWE-79)."""
        assert "escapeHtml" in rs_js

    def test_data_action_rsEditRow(self, rs_js):
        """data-action=rsEditRow is wired in the rendered HTML string."""
        assert "data-action=\"rsEditRow\"" in rs_js or "data-action='rsEditRow'" in rs_js

    def test_data_action_rsResetRow(self, rs_js):
        """data-action=rsResetRow is wired in the rendered HTML string."""
        assert "data-action=\"rsResetRow\"" in rs_js or "data-action='rsResetRow'" in rs_js

    def test_depends_on_dashboard_js_globals(self, rs_js):
        """File declares dependency on dashboard.js via JSDoc comment."""
        assert "dashboard.js" in rs_js

    def test_toast_function_present(self, rs_js):
        """_rsToast helper present for user feedback."""
        assert "_rsToast" in rs_js

    def test_type_coercion_for_int(self, rs_js):
        """Client validates int type before sending."""
        assert "parseInt" in rs_js

    def test_type_coercion_for_float(self, rs_js):
        """Client validates float type before sending."""
        assert "parseFloat" in rs_js


# ── JS tests — dashboard.js wiring ───────────────────────────────────────────

class TestDashboardJsWiring:
    def test_showPage_dispatches_runtime_settings(self, dashboard_js):
        """showPage('runtime-settings') calls loadRuntimeSettings."""
        assert "loadRuntimeSettings" in dashboard_js

    def test_showPage_guards_with_typeof(self, dashboard_js):
        """showPage guards with typeof window.loadRuntimeSettings (defer-safe)."""
        assert "typeof window.loadRuntimeSettings" in dashboard_js

    def test_event_delegation_rsEditRow(self, dashboard_js):
        """Event delegation switch handles rsEditRow action."""
        assert "case 'rsEditRow':" in dashboard_js

    def test_event_delegation_rsResetRow(self, dashboard_js):
        """Event delegation switch handles rsResetRow action."""
        assert "case 'rsResetRow':" in dashboard_js

    def test_rsEditRow_reads_data_attrs(self, dashboard_js):
        """rsEditRow handler reads data-rs-key, data-rs-value, data-rs-type."""
        assert "data-rs-key" in dashboard_js
        assert "data-rs-value" in dashboard_js
        assert "data-rs-type" in dashboard_js

    def test_rsResetRow_reads_data_rs_key(self, dashboard_js):
        """rsResetRow handler reads data-rs-key."""
        # Verify the reset handler passes the key
        assert "'data-rs-key'" in dashboard_js or '"data-rs-key"' in dashboard_js


# ── CSS tests ─────────────────────────────────────────────────────────────────

class TestDashboardCss:
    def test_rs_edit_form_class(self, dashboard_css):
        assert ".rs-edit-form" in dashboard_css

    def test_rs_key_class(self, dashboard_css):
        assert ".rs-key" in dashboard_css

    def test_rs_val_class(self, dashboard_css):
        assert ".rs-val" in dashboard_css

    def test_rs_toast_class(self, dashboard_css):
        assert ".rs-toast" in dashboard_css

    def test_rs_toast_ok_class(self, dashboard_css):
        assert ".rs-toast-ok" in dashboard_css

    def test_rs_toast_err_class(self, dashboard_css):
        assert ".rs-toast-err" in dashboard_css
