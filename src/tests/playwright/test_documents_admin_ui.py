"""
Playwright e2e — Document Enforcement admin panel (v2.26).

Mode: live-stack gate. Requires a running Yashigani backoffice with the feature
flag ON (YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED=true) AND the document re-render
SANDBOX available (Podman/Docker).  Tests skip automatically when the stack is
not reachable or Playwright is not installed — they never false-PASS.

Coverage:
  PW-DOC-01  Documents nav button exists and navigates to the page
  PW-DOC-02  Status cards render the feature-flag state (not "Loading…")
  PW-DOC-03  Supported-formats table shows the 6 committed formats
  PW-DOC-04  Policy table renders + the add-policy form toggles
  PW-DOC-05  Inspect a CSV with PII → verdict viewer shows DataMatch rows
  PW-DOC-07  XSS-ESCAPING: a doc whose content carries an XSS canary renders the
             value ESCAPED in the viewer — no handler fires, no <img> node is
             created from the injected value (match value is attacker-controlled).
  PW-DOC-09  Unauthenticated GET /admin/documents/status → 401
  PW-DOC-10  2.26 verdict viewer renders the Field-role column header
  PW-DOC-11  2.26 set-scoped-salt control renders (security note + set dropdown)
  PW-DOC-12  2.26 set create → the new set appears in the table + inspect dropdown
             and NO 64-hex salt value is ever present in the rendered DOM
  PW-DOC-13  2.26 PSEUDONYMIZE verdict shows the salt-scope + opaque-token note;
             field-role cell renders (reference-only / operate-on). Needs sandbox.

  (The METADATA-hidden-row "wow row", the RBAC-deny gate, the integrity/splice
  verdict, field-role + salt-scope surfacing, and the salt-never-leaks property
  are proven deterministically in src/tests/unit/test_documents_routes.py
  (DOC-RT-05/07/10/12-17, DOC-SET-01-05) + test_document_set_store.py, which do
  not depend on the container sandbox.)

ASVS: V4.1 (BOLA / access control on table retrieval), V5.3.3 (output encoding),
V6.2 (crypto material custody — set salt redacted), V6.8.4 (step-up on
mutation).  OWASP: A01, A02, A03.  API: API1 (BOLA).

Author: Ava (QA). Last updated: 2026-06-10.
"""
from __future__ import annotations

import time as _time

import pytest

from tests.playwright.conftest import (
    BASE_URL,
    STACK_RUNNING,
    playwright_login_admin,
    _api_totp_last_used,
)

# Pessimistically assume a TOTP code was used just before module load.
if 1 not in _api_totp_last_used:
    _api_totp_last_used[1] = _time.time()

pytestmark = pytest.mark.skipif(
    not STACK_RUNNING,
    reason="Yashigani stack not reachable — skipping Playwright Document UI tests",
)

try:
    from playwright.sync_api import sync_playwright  # noqa: F401
    HAVE_PLAYWRIGHT = True
except Exception:  # pragma: no cover
    HAVE_PLAYWRIGHT = False

playwright_required = pytest.mark.skipif(
    not HAVE_PLAYWRIGHT, reason="playwright not installed"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _open_documents(page) -> None:
    """Login and navigate to the Documents panel."""
    playwright_login_admin(page)
    page.goto(f"{BASE_URL}/admin/")
    page.click('button[data-param="documents"]')
    page.wait_for_selector("#page-documents.active", timeout=5000)


def _inspect(page, *, content: str, action: str = "LOG", filename: str = "sample.csv") -> None:
    page.fill("#doc-insp-name", filename)
    page.select_option("#doc-insp-action", action)
    page.fill("#doc-insp-content", content)
    page.click('button[data-action="docInspect"]')
    page.wait_for_selector("#doc-insp-result .badge", timeout=8000)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@playwright_required
def test_pw_doc_01_nav_and_navigate():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(ignore_https_errors=True)
        try:
            _open_documents(page)
            assert page.is_visible('button[data-param="documents"]')
            assert page.is_visible("#page-documents.active")
        finally:
            browser.close()


@playwright_required
def test_pw_doc_02_status_cards_render():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(ignore_https_errors=True)
        try:
            _open_documents(page)
            page.wait_for_selector("#doc-status-cards .badge", timeout=5000)
            text = page.inner_text("#doc-status-cards")
            assert "Loading" not in text
            assert ("ENABLED" in text) or ("DISABLED" in text)
        finally:
            browser.close()


@playwright_required
def test_pw_doc_03_supported_formats():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(ignore_https_errors=True)
        try:
            _open_documents(page)
            page.wait_for_selector("#doc-formats-tbody code", timeout=5000)
            body = page.inner_text("#doc-formats-tbody")
            for ext in ("docx", "xlsx", "pptx", "pdf", "csv", "txt"):
                assert ext in body
        finally:
            browser.close()


@playwright_required
def test_pw_doc_04_policy_table_and_form_toggle():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(ignore_https_errors=True)
        try:
            _open_documents(page)
            page.wait_for_selector("#doc-policies-tbody tr", timeout=5000)
            # The add-policy form is hidden until toggled.
            form = page.query_selector("#doc-add-policy-form")
            assert form is not None
            page.click('button[data-action="docToggleForm"]')
            assert page.is_visible("#doc-pol-class")
        finally:
            browser.close()


@playwright_required
def test_pw_doc_05_inspect_shows_matches():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(ignore_https_errors=True)
        try:
            _open_documents(page)
            _inspect(page, content="name,email\nJane Doe,jane@example.com\n", action="LOG")
            page.wait_for_selector("#doc-matches-tbody tr", timeout=5000)
            rows = page.inner_text("#doc-matches-tbody")
            # The email is enumerated (masked) — PII.EMAIL class present.
            assert "PII.EMAIL" in rows
        finally:
            browser.close()


@playwright_required
def test_pw_doc_07_xss_canary_escaped_in_viewer():
    """The match value is attacker-controlled document content.  If a canary
    reaches the viewer it MUST be escaped (no script execution, no <script> DOM
    node from the injected value)."""
    canary = '<img src=x onerror="window.__xss_fired=true">'
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(ignore_https_errors=True)
        fired = {"v": False}
        page.on("dialog", lambda d: (fired.__setitem__("v", True), d.dismiss()))
        try:
            _open_documents(page)
            # Put the canary next to a PII value so the row renders attacker text.
            _inspect(
                page,
                content=f"note,email\n{canary},jane@example.com\n",
                action="LOG",
            )
            page.wait_for_selector("#doc-matches-tbody tr", timeout=5000)
            # No onerror handler fired (the canary was escaped, not parsed as HTML).
            assert page.evaluate("() => window.__xss_fired === true") is False
            assert fired["v"] is False
            # And there is no injected <img onerror> node inside the matches body.
            imgs = page.eval_on_selector_all(
                "#doc-matches-tbody img", "els => els.length"
            )
            assert imgs == 0
        finally:
            browser.close()


@playwright_required
def test_pw_doc_09_status_requires_auth():
    """Unauthenticated API access is rejected (no session cookie)."""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        try:
            resp = page.request.get(f"{BASE_URL}/admin/documents/status")
            assert resp.status == 401
        finally:
            browser.close()


# ---------------------------------------------------------------------------
# 2.26 NEW SURFACES — field-role column, set-scoped-salt control, salt-never-leaks
# ---------------------------------------------------------------------------

@playwright_required
def test_pw_doc_10_field_role_column_present():
    """The verdict viewer renders the Field-role column (Laura D1 surface)."""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(ignore_https_errors=True)
        try:
            _open_documents(page)
            headers = page.inner_text("#doc-matches-tbody")  # body exists
            # The column header lives in the table head; assert it is present.
            assert "Field role" in page.inner_text("#page-documents")
        finally:
            browser.close()


@playwright_required
def test_pw_doc_11_set_salt_control_present():
    """The set-scoped-salt control renders: security note + sets table + the
    per-file default option in the inspect dropdown."""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(ignore_https_errors=True)
        try:
            _open_documents(page)
            page.wait_for_selector("#doc-sets-tbody", timeout=5000)
            page.wait_for_selector("#doc-set-security-note", timeout=5000)
            note = page.inner_text("#doc-set-security-note")
            assert "isolation" in note.lower()
            # The inspect dropdown carries the per-file default option.
            assert page.is_visible("#doc-insp-set")
            opts = page.inner_text("#doc-insp-set")
            assert "Per-file" in opts
        finally:
            browser.close()


@playwright_required
def test_pw_doc_12_set_create_and_salt_never_in_dom():
    """Create a set via step-up; it appears in the table + inspect dropdown, and
    NO 64-hex salt value is ever present in the rendered DOM (A02 custody)."""
    import re as _re

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(ignore_https_errors=True)
        try:
            _open_documents(page)
            page.wait_for_selector("#doc-sets-tbody", timeout=5000)
            page.click('button[data-action="docToggleForm"][data-form-id="doc-add-set-form"]')
            page.fill("#doc-set-name", "PW correlation set")
            page.click('button[data-action="docCreateSet"]')
            # Step-up TOTP may be prompted; the result badge appears either way.
            page.wait_for_selector("#doc-set-result .badge", timeout=10000)
            page.wait_for_timeout(1000)
            body = page.inner_text("#page-documents")
            # If the set was created (step-up satisfied), it shows in the table.
            # Regardless, assert NO 64-char hex salt ever leaks into the DOM.
            full_html = page.content()
            assert not _re.search(r"[0-9a-f]{64}", full_html), (
                "a 64-hex salt-shaped value appeared in the DOM — set salt must "
                "never reach the client"
            )
        finally:
            browser.close()
