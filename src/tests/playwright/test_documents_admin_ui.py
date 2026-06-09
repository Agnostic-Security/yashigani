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

  (The METADATA-hidden-row "wow row" and the RBAC-deny gate are proven
  deterministically in src/tests/unit/test_documents_routes.py — DOC-RT-10,
  DOC-RT-05/07 — which do not depend on the container sandbox.)

ASVS: V4.1 (BOLA / access control on table retrieval), V5.3.3 (output encoding),
V6.8.4 (step-up on policy mutation).  OWASP: A01, A03.  API: API1 (BOLA).

Author: Ava (QA). Last updated: 2026-06-09.
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
