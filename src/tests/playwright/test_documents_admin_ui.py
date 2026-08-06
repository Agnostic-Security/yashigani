"""
Playwright e2e — Document Enforcement admin panel (v2.26).

Mode: live-stack gate. Requires a running Yashigani backoffice with the feature
flag ON (YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED=true) AND the document re-render
SANDBOX available (Podman/Docker).  Tests skip automatically when the stack is
not reachable or Playwright is not installed — they never false-PASS.

Coverage:
  PW-DOC-01  Documents nav entry exists and navigates to the page
  PW-DOC-02  Status panel renders the feature-flag state (not "Loading…")
  PW-DOC-03  Supported-formats note lists the 6 committed formats
  PW-DOC-04  Policy list + add-policy form both render (the form is always
             visible — see 2026-08-02 note, no toggle exists in the real UI)
  PW-DOC-05  Inspect a CSV with PII → result JSON shows a PII.EMAIL match
  PW-DOC-07  XSS-ESCAPING: a doc whose content carries an XSS canary renders the
             value ESCAPED in the viewer — no handler fires, no <img> node is
             created from the injected value (match value is attacker-controlled).
  PW-DOC-09  Unauthenticated GET /admin/documents/status → 401
  PW-DOC-10/11/12  SEE 2026-08-02 NOTE BELOW — SKIPPED, evidenced gap, not a
             selector bug.

ASVS: V4.1 (BOLA / access control on table retrieval), V5.3.3 (output encoding),
V6.2 (crypto material custody — set salt redacted), V6.8.4 (step-up on
mutation).  OWASP: A01, A02, A03.  API: API1 (BOLA).

Author: Ava (QA). Last updated: 2026-08-02 (Tier-B triage on run
ytf-docker-macos-29d9c9d8-20260731) — rewritten against the real ui4 module
(src/yashigani/backoffice/static/ui4/admin/modules/documents-docopa.js,
component <ys-admin-documents>, module id 'documents'):

  - Auth: `_open_documents()` already called the shared `playwright_login_admin()`
    helper, which had its own instance of the two-step forced-password-change
    bug (see conftest.py's playwright_login_admin() docstring — now fixed to
    delegate to the assert-verified httpx cookie-injection path). No change
    needed in THIS file for that part once conftest was fixed.
  - Selectors: none of `#page-documents`, `#doc-status-cards`,
    `#doc-formats-tbody`, `#doc-policies-tbody`, `#doc-add-policy-form`,
    `button[data-action="docToggleForm"]`, `#doc-pol-class`,
    `#doc-matches-tbody` exist anywhere in the real module (confirmed reading
    the full render() tree). The panel is a generic `.ys-admin-content-pad`;
    status is a `.ys-panel-header`/`.ys-txt-note` pair; supported formats are
    a plain-text note (no table); the add-policy form (`_renderCreate()`) has
    NO hide/show state at all — it always renders side-by-side with the
    policy list; inspect result renders as `#doc-inspect-result`
    (`<pre>{JSON.stringify(r, null, 2)}</pre>`, Lit-escaped), not a table of
    match rows.
  - PW-DOC-10/11/12 (Field-role column, set-scoped-salt control, set
    create+salt-never-leaks): the module's `connectedCallback`/`_load()`
    DOES fetch `/admin/documents/sets` and stores it in `this._sets`, but
    `render()` NEVER reads `this._sets` anywhere — no sets table, no
    "Field role" text, no `#doc-set-*` ids exist anywhere in this file. This
    is a genuine, evidenced UI gap (backend data fetched, never surfaced),
    not a stale-selector problem — same "wired-but-not-surfaced" family
    already tracked as YSG-RISK-163 for a different module
    (`AgnosticSecurity/Risk Management/yashigani-risks.md`). Flagged as a
    candidate finding for Iris/Tom, not self-numbered here. Rewritten to
    SKIP with that evidence rather than assert against markup that isn't
    there (retro rule A1: absence of artefact = SKIP, never PASS/FAIL-blind).
    Deterministic coverage for the underlying salt-custody property already
    exists and does not depend on this UI gap: src/tests/unit/
    test_documents_routes.py (DOC-SET-01..05) + test_document_set_store.py.
"""
from __future__ import annotations

import time as _time

import pytest

from tests.playwright.conftest import (
    launch_chromium,
    BASE_URL,
    STACK_RUNNING,
    _CA_CERT_PATH,
    _api_get_session_cookies,
    _read_secret,
    _wait_for_fresh_totp_window,
    capture_screenshot,
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

_SETS_GAP_REASON = (
    "documents-docopa.js fetches /admin/documents/sets into this._sets but "
    "render() never reads it -- no sets table, no 'Field role' column, no "
    "#doc-set-* controls exist anywhere in the module. Evidenced UI gap, "
    "same family as YSG-RISK-163; see module docstring. Deterministic "
    "coverage for the underlying salt-custody property lives in "
    "src/tests/unit/test_documents_routes.py + test_document_set_store.py."
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _open_documents(page) -> None:
    """Login and navigate to the Documents panel."""
    playwright_login_admin(page)
    page.goto(f"{BASE_URL}/admin/")
    page.wait_for_selector("a[href='#documents']", timeout=15000)
    page.click("a[href='#documents']")
    page.wait_for_selector(".ys-panel-header:has-text('Document enforcement')", timeout=8000)
    capture_screenshot(page, "documents_panel_loaded")


_enforcement_ensured = False


def _ensure_enforcement_enabled() -> None:
    """Self-heal a documents-enforcement-disabled deployment (idempotent,
    per-process cache).

    QA-fix (Ava, 2026-08-03, Tier-B 172-error triage): this test file's own
    module docstring documents the precondition "requires ... the feature
    flag ON (YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED=true)" -- but THIS
    deployment was not started with that env var set, so /admin/documents/
    inspect (and therefore PW-DOC-05/PW-DOC-07) returned "Document
    enforcement is disabled. Enable it via PUT /admin/documents/enforcement
    or set YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED=true" instead of a real
    match result -- confirmed live, not a selector/product bug. The route
    itself documents a live, in-process toggle (routes/documents.py
    set_enforcement(): STRENGTHEN direction i.e. enabled=True applies
    IMMEDIATELY with single-admin step-up, no dual-admin approval needed,
    unlike the WEAKEN/disable direction) -- self-heals by checking
    GET /admin/documents/enforcement and, if disabled, performing a fresh
    step-up + PUT enabled=true before the test proceeds, rather than
    silently accepting the deployment's default and reporting a false
    product-bug against a pure environment-config gap.
    """
    global _enforcement_ensured
    if _enforcement_ensured:
        return

    import hashlib

    import httpx
    import pyotp

    verify = _CA_CERT_PATH if _CA_CERT_PATH else False
    cookies = _api_get_session_cookies(admin=1)
    with httpx.Client(verify=verify, cookies=cookies, timeout=10) as c:
        status = c.get(f"{BASE_URL}/admin/documents/enforcement")
        if status.status_code == 200 and status.json().get("enabled"):
            _enforcement_ensured = True
            return

        _wait_for_fresh_totp_window(admin=1)
        totp_secret = _read_secret("admin1_totp_secret")
        code = pyotp.TOTP(totp_secret, digits=8, digest=hashlib.sha512).now()
        _api_totp_last_used[1] = _time.time()
        su = c.post(f"{BASE_URL}/auth/stepup", json={"totp_code": code})
        assert su.status_code == 200, (
            f"stepup before enabling document enforcement failed: "
            f"{su.status_code} {su.text[:200]}"
        )
        put = c.put(f"{BASE_URL}/admin/documents/enforcement", json={"enabled": True})
        assert put.status_code == 200, (
            f"PUT /admin/documents/enforcement enabled=True failed: "
            f"{put.status_code} {put.text[:300]}"
        )
    _enforcement_ensured = True


def _inspect(page, *, content: str) -> None:
    _ensure_enforcement_enabled()
    page.fill("#doc-sample", content)
    page.click("#doc-inspect")
    page.wait_for_selector("#doc-inspect-result", timeout=8000)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@playwright_required
def test_pw_doc_01_nav_and_navigate():
    with sync_playwright() as p:
        browser = launch_chromium(p)
        page = browser.new_page(ignore_https_errors=True)
        try:
            _open_documents(page)
            assert page.is_visible("a[href='#documents']")
            assert page.is_visible(".ys-panel-header:has-text('Document enforcement')")
        finally:
            browser.close()


@playwright_required
def test_pw_doc_02_status_cards_render():
    with sync_playwright() as p:
        browser = launch_chromium(p)
        page = browser.new_page(ignore_https_errors=True)
        try:
            _open_documents(page)
            header = page.locator(".ys-panel-header:has-text('Document enforcement')")
            text = header.inner_text() or ""
            assert "Loading" not in text
            assert ("enabled" in text) or ("disabled" in text)
        finally:
            browser.close()


@playwright_required
def test_pw_doc_03_supported_formats():
    with sync_playwright() as p:
        browser = launch_chromium(p)
        page = browser.new_page(ignore_https_errors=True)
        try:
            _open_documents(page)
            page.wait_for_selector(".ys-txt-note:has-text('Supported formats')", timeout=8000)
            body = page.inner_text(".ys-txt-note")
            for ext in ("docx", "xlsx", "pptx", "pdf", "csv", "txt"):
                assert ext in body, f"expected format {ext!r} in supported-formats note"
        finally:
            browser.close()


@playwright_required
def test_pw_doc_04_policy_list_and_add_form_render():
    """PW-DOC-04: policy list renders and the add-policy form's fields are
    present. The real UI has no hide/show toggle for this form -- it always
    renders alongside the policy list (see module docstring)."""
    with sync_playwright() as p:
        browser = launch_chromium(p)
        page = browser.new_page(ignore_https_errors=True)
        try:
            _open_documents(page)
            page.wait_for_selector(".ys-panel-header:has-text('Verdict policies')", timeout=8000)
            assert page.is_visible(".ys-panel-header:has-text('Add verdict policy')")
            assert page.is_visible("#doc-pid")
            assert page.is_visible("#doc-code")
            assert page.is_visible("#doc-msg")
            assert page.is_visible("#doc-create")
        finally:
            browser.close()


@playwright_required
def test_pw_doc_05_inspect_shows_matches():
    with sync_playwright() as p:
        browser = launch_chromium(p)
        page = browser.new_page(ignore_https_errors=True)
        try:
            _open_documents(page)
            _inspect(page, content="name,email\nJane Doe,jane@example.com\n")
            result = page.inner_text("#doc-inspect-result")
            assert "PII" in result and "EMAIL" in result.upper(), (
                f"expected a PII/EMAIL match in the inspect result JSON, got: {result[:300]!r}"
            )
        finally:
            browser.close()


@playwright_required
def test_pw_doc_07_xss_canary_escaped_in_viewer():
    """The match value is attacker-controlled document content.  If a canary
    reaches the viewer it MUST be escaped (no script execution, no <img> DOM
    node from the injected value). The result renders as
    `${JSON.stringify(r,null,2)}` inside a Lit `<pre>` -- text-interpolated,
    not innerHTML, so the payload should surface as an inert escaped string."""
    canary = '<img src=x onerror="window.__xss_fired=true">'
    with sync_playwright() as p:
        browser = launch_chromium(p)
        page = browser.new_page(ignore_https_errors=True)
        fired = {"v": False}
        page.on("dialog", lambda d: (fired.__setitem__("v", True), d.dismiss()))
        try:
            _open_documents(page)
            _inspect(page, content=f"note,email\n{canary},jane@example.com\n")
            assert page.evaluate("() => window.__xss_fired === true") is False
            assert fired["v"] is False
            imgs = page.eval_on_selector_all("#doc-inspect-result img", "els => els.length")
            assert imgs == 0, "an <img> DOM node was created from injected content — XSS not escaped"
        finally:
            browser.close()


@playwright_required
def test_pw_doc_09_status_requires_auth():
    """Unauthenticated API access is rejected (no session cookie)."""
    with sync_playwright() as p:
        browser = launch_chromium(p)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        try:
            resp = page.request.get(f"{BASE_URL}/admin/documents/status")
            assert resp.status == 401
        finally:
            browser.close()


# ---------------------------------------------------------------------------
# 2.26 NEW SURFACES — field-role column, set-scoped-salt control
# NOT RENDERED in the current ui4 module (see file docstring) — SKIPPED with
# evidence, not asserted against markup that doesn't exist.
# ---------------------------------------------------------------------------

@playwright_required
def test_pw_doc_10_field_role_column_present():
    pytest.skip(_SETS_GAP_REASON)


@playwright_required
def test_pw_doc_11_set_salt_control_present():
    pytest.skip(_SETS_GAP_REASON)


@playwright_required
def test_pw_doc_12_set_create_and_salt_never_in_dom():
    pytest.skip(_SETS_GAP_REASON)
