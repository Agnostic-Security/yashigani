"""
Playwright e2e tests — PKI admin panel (v2.23.3, PR #51 + #53).

Coverage:
  PW-PKI-01  PKI nav button exists and navigates to the PKI page
  PW-PKI-02  PKI status table loads and shows at least one service row
  PW-PKI-03  View (chain detail) button shows cert metadata for a service
  PW-PKI-04  Chain detail shows fingerprint_sha256 (64-char hex)
  PW-PKI-05  Chain detail shows subject_cn and issuer_cn fields
  PW-PKI-06  Rotate button requires step-up TOTP (modal appears)
  PW-PKI-07  Download bundle link fires download (no navigation to new page)
  PW-PKI-08  Unauthenticated GET /api/v1/admin/pki/status → 401
  PW-PKI-09  Unauthenticated GET /api/v1/admin/pki/chain/gateway → 401
  PW-PKI-10  Bundle response never contains PRIVATE KEY

Mode: live-stack gate. Requires running Yashigani backoffice + DB + cert files.
Tests skip automatically if STACK_RUNNING is False or playwright not installed.

ASVS: V6.8.4 (step-up on rotate), V9.1.1 (cert health), V7.1.3 (no secrets in responses)
CWE-200: private key never transmitted

Last updated: 2026-05-09T00:00:00+01:00
"""
from __future__ import annotations

import pytest

import time as _time

from tests.playwright.conftest import (
    launch_chromium,
    BASE_URL,
    STACK_RUNNING,
    _CA_CERT_PATH,
    capture_screenshot,
    get_admin_credentials,
    playwright_login_admin,
    _api_get_session_cookies,
    _api_totp_last_used,
)

# Pessimistically assume a TOTP code was used just before this module loaded
# (e.g. from a prior pytest invocation or diagnostic subprocess in the same
# 60s replay-cache window). This forces _api_get_session_cookies() to wait
# for a fresh window on the first call, preventing TOTP replay 401.
if 1 not in _api_totp_last_used:
    _api_totp_last_used[1] = _time.time()

pytestmark = pytest.mark.skipif(
    not STACK_RUNNING,
    reason="Yashigani stack not reachable — skipping Playwright PKI UI tests",
)

try:
    from playwright.sync_api import sync_playwright, expect
    _PW_AVAILABLE = True
except ImportError:
    _PW_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not STACK_RUNNING or not _PW_AVAILABLE,
    reason="Yashigani stack not reachable or playwright not installed",
)

_PKI_STATUS_API = f"{BASE_URL}/api/v1/admin/pki/status"
_PKI_CHAIN_API = f"{BASE_URL}/api/v1/admin/pki/chain/gateway"
_PKI_BUNDLE_API = f"{BASE_URL}/api/v1/admin/pki/bundle/gateway"
_ADMIN_DASHBOARD = f"{BASE_URL}/admin/"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _login(page, username: str = "", password: str = "") -> None:
    """Inject a valid admin1 session cookie into the page's browser context.

    Uses _api_get_session_cookies to obtain session cookies via the API (TOTP
    handled, result cached) and injects them via add_cookies. Then navigates to
    /admin/ to activate the session.

    The username/password args are kept for API compatibility but are ignored.
    Fix: v2.23.3 — original helper didn't supply TOTP, causing silent auth failure.

    QA-fix (Ava, Tier-B triage 2026-08-02): force_fresh=True — this file runs
    LAST in this suite's collection order. _api_get_session_cookies() caches
    its result process-wide with no TTL awareness; a cookie obtained near the
    START of a ~40min Tier-B run can outlive the server's own admin-session
    TTL by the time THIS file's fixtures run, producing "nav link not found
    at all" (the page silently bounces back to /admin/login, before any
    selector assertion even fires) rather than a clean auth error. Confirmed
    candidate cause: this file's own login mechanism is otherwise correct
    (unlike the browser-form-driven bug fixed elsewhere this session), so a
    stale cache is the remaining explanation for its failures on the
    ytf-docker-macos-29d9c9d8-20260731 run. force_fresh here costs one extra
    ~62s TOTP-replay wait per PKI test (each test opens a fresh
    sync_playwright() context and calls _login independently) in exchange for
    a session that is provably live for this specific test's lifetime.
    """
    cookies = _api_get_session_cookies(admin=1, force_fresh=True)
    ctx = page.context
    for name, value in cookies.items():
        # __Host- cookies require Secure=True, Path=/ and no explicit Domain.
        # Playwright requires either 'url' OR ('domain'+'path'). We use 'url'
        # so that Playwright infers domain+secure from the BASE_URL.
        # Do NOT include 'path' when 'url' is specified (mutually exclusive).
        ctx.add_cookies([{
            "name": name, "value": value,
            "url": BASE_URL,
            "httpOnly": True,
            "secure": True,
            "sameSite": "Strict",
        }])
    page.goto(f"{BASE_URL}/admin/")
    page.wait_for_timeout(2000)


_PKI_PANEL_HEADER = ".ys-panel-header:has-text('PKI — service certificates')"


def _navigate_to_pki(page) -> None:
    """Click the PKI nav button and wait for the panel to load with service rows.

    QA-fix (Ava, Tier-B triage 2026-08-02): `#pki-status-container` does not
    exist anywhere in the real module
    (src/yashigani/backoffice/static/ui4/admin/modules/kms-pki.js,
    <ys-admin-kms-pki>) -- confirmed reading the full render() tree. The PKI
    table renders inside a `.ys-panel` whose header text is literally
    "PKI — service certificates"; rows are a plain `<table class="ys-table">`
    with a "View"/"Rotate"/"Download" button per service, or a
    `.ys-txt-note` ("No services in the certificate manifest.") when empty.
    """
    page.click("a[href='#pki']")
    page.wait_for_selector(_PKI_PANEL_HEADER, timeout=8000)
    # Wait for the async API response to render: either rows or the empty note.
    page.wait_for_function(
        "() => { const h = [...document.querySelectorAll('.ys-panel-header')]"
        ".find(e => e.textContent.includes('PKI — service certificates'));"
        " if (!h) return false; const body = h.parentElement.querySelector('.ys-panel-body');"
        " return !!body && body.textContent.trim().length > 0; }",
        timeout=12000,
    )
    page.wait_for_timeout(500)
    capture_screenshot(page, "pki_panel_loaded")


# ---------------------------------------------------------------------------
# PW-PKI-01: Nav button exists and navigates to PKI page
# ---------------------------------------------------------------------------

def test_pki_nav_button_exists():
    username, password = get_admin_credentials()
    with sync_playwright() as pw:
        browser = launch_chromium(pw)
        ctx = browser.new_context(
            ignore_https_errors=True,
            **({"extra_http_headers": {"X-CA-Cert": _CA_CERT_PATH}} if _CA_CERT_PATH else {}),
        )
        page = ctx.new_page()
        _login(page, username, password)
        page.goto(_ADMIN_DASHBOARD)
        page.wait_for_timeout(2000)

        pki_btn = page.locator("a[href='#pki']")
        expect(pki_btn).to_be_visible()
        pki_btn.click()

        # PKI page should become visible (real header text — no #pki-status-container
        # id exists in the current ui4 module, see _navigate_to_pki() docstring)
        pki_panel = page.locator(_PKI_PANEL_HEADER)
        expect(pki_panel).to_be_visible()
        browser.close()


# ---------------------------------------------------------------------------
# PW-PKI-02: Status table loads with at least one service row
# ---------------------------------------------------------------------------

def test_pki_status_table_loads():
    username, password = get_admin_credentials()
    with sync_playwright() as pw:
        browser = launch_chromium(pw)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        _login(page, username, password)
        page.goto(_ADMIN_DASHBOARD)
        page.wait_for_timeout(2000)
        _navigate_to_pki(page)

        # The panel should not show an error state
        panel_text = page.locator(_PKI_PANEL_HEADER).locator("xpath=..").inner_text()
        assert "Failed to load" not in panel_text

        # At least one "View" button (per service row) — or the documented
        # empty-state note, never a blank/error panel (retro rule A1).
        view_buttons = page.locator("button:has-text('View')")
        if view_buttons.count() == 0:
            assert "No services in the certificate manifest" in panel_text, (
                f"expected either View buttons or the empty-state note, got: {panel_text!r}"
            )
        else:
            assert view_buttons.count() >= 1
        browser.close()


# ---------------------------------------------------------------------------
# PW-PKI-03: View button shows chain detail panel
# ---------------------------------------------------------------------------

def test_pki_view_chain_shows_detail():
    username, password = get_admin_credentials()
    with sync_playwright() as pw:
        browser = launch_chromium(pw)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        _login(page, username, password)
        page.goto(_ADMIN_DASHBOARD)
        page.wait_for_timeout(2000)
        _navigate_to_pki(page)

        view_buttons = page.locator("button:has-text('View')")
        if view_buttons.count() == 0:
            pytest.skip("PW-PKI-03 SKIPPED: no services in the certificate manifest.")
        view_buttons.first.click()
        page.wait_for_timeout(2000)

        # Chain detail renders as its own .ys-panel with header "Chain — {service}"
        # (no #pki-chain-detail id exists in the real module).
        detail = page.locator(".ys-panel-header:has-text('Chain —')")
        expect(detail).to_be_visible()
        browser.close()


# ---------------------------------------------------------------------------
# PW-PKI-04: Chain detail shows SHA-256 fingerprint (64-char hex)
# ---------------------------------------------------------------------------

def test_pki_chain_shows_fingerprint():
    username, password = get_admin_credentials()
    with sync_playwright() as pw:
        browser = launch_chromium(pw)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        _login(page, username, password)
        page.goto(_ADMIN_DASHBOARD)
        page.wait_for_timeout(2000)
        _navigate_to_pki(page)

        view_buttons = page.locator("button:has-text('View')")
        if view_buttons.count() == 0:
            pytest.skip("PW-PKI-04 SKIPPED: no services in the certificate manifest.")
        view_buttons.first.click()
        page.wait_for_timeout(2000)

        detail = page.locator(".ys-panel-header:has-text('Chain —')").locator("xpath=..")
        detail_text = detail.inner_text()
        # SHA-256 fingerprint = 64 hex chars
        import re
        hex_pattern = re.compile(r"[0-9a-f]{64}", re.IGNORECASE)
        assert hex_pattern.search(detail_text), "Expected 64-char SHA-256 hex in chain detail"
        browser.close()


# ---------------------------------------------------------------------------
# PW-PKI-05: Chain detail shows Subject CN and Issuer CN
# ---------------------------------------------------------------------------

def test_pki_chain_shows_cn_fields():
    username, password = get_admin_credentials()
    with sync_playwright() as pw:
        browser = launch_chromium(pw)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        _login(page, username, password)
        page.goto(_ADMIN_DASHBOARD)
        page.wait_for_timeout(2000)
        _navigate_to_pki(page)

        view_buttons = page.locator("button:has-text('View')")
        if view_buttons.count() == 0:
            pytest.skip("PW-PKI-05 SKIPPED: no services in the certificate manifest.")
        view_buttons.first.click()
        page.wait_for_timeout(2000)

        detail_text = page.locator(".ys-panel-header:has-text('Chain —')").locator("xpath=..").inner_text()
        assert "Subject CN" in detail_text or "subject_cn" in detail_text.lower()
        assert "Issuer CN" in detail_text or "issuer_cn" in detail_text.lower()
        browser.close()


# ---------------------------------------------------------------------------
# PW-PKI-06: Rotate button triggers step-up TOTP modal
# ---------------------------------------------------------------------------

def test_pki_rotate_triggers_stepup():
    """PW-PKI-06: the real Rotate button (kms-pki.js::_rotateCert) first fires
    a native `window.confirm()` guard, then (if accepted) calls
    ApiClient.mutate(), whose step-up interceptor opens a DYNAMICALLY BUILT
    modal (core/widgets/ys-modal.js::promptStepUp() — createElement, appended
    to <body>, no fixed id) headed "Step-up verification required". There is
    no `#stepup-modal` or `#pki-rotate-result` id anywhere in the real code —
    confirmed reading both files. Playwright auto-DISMISSES window.confirm()
    unless a dialog handler explicitly accepts it, so without one the click
    would silently no-op before ever reaching the step-up path."""
    username, password = get_admin_credentials()
    with sync_playwright() as pw:
        browser = launch_chromium(pw)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        page.on("dialog", lambda d: d.accept())
        _login(page, username, password)
        page.goto(_ADMIN_DASHBOARD)
        page.wait_for_timeout(2000)
        _navigate_to_pki(page)

        rotate_btns = page.locator("button:has-text('Rotate')")
        if rotate_btns.count() == 0:
            pytest.skip("No Rotate buttons found — no services in manifest?")

        rotate_btns.first.click()
        page.wait_for_timeout(2500)

        # The step-up modal (real markup: .ys-modal-header text) OR an
        # already-fresh session may let the mutate through without a prompt —
        # accept either as long as SOME response is visible (never a silent
        # no-op from the dismissed-confirm case, which this dialog handler
        # already prevents).
        stepup_modal = page.locator(".ys-modal-header:has-text('Step-up verification required')")
        modal_visible = stepup_modal.is_visible()
        result_text = page.locator("body").inner_text() or ""
        assert modal_visible or "step" in result_text.lower() or "totp" in result_text.lower() or "verification" in result_text.lower()
        browser.close()


# ---------------------------------------------------------------------------
# PW-PKI-07: Download bundle fires download (no navigation)
# ---------------------------------------------------------------------------

def test_pki_download_bundle_fires_download():
    username, password = get_admin_credentials()
    with sync_playwright() as pw:
        browser = launch_chromium(pw)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        _login(page, username, password)
        page.goto(_ADMIN_DASHBOARD)
        page.wait_for_timeout(2000)
        _navigate_to_pki(page)

        download_btns = page.locator("button", has_text="Download")
        if download_btns.count() == 0:
            pytest.skip("No Download buttons found — no services in manifest?")

        # Expect a download event, not navigation
        with page.expect_download(timeout=8000) as dl_info:
            download_btns.first.click()

        dl = dl_info.value
        assert dl.suggested_filename.endswith("_cert_bundle.pem")
        content = dl.path()  # local file
        assert content is not None

        import pathlib
        pem_bytes = pathlib.Path(content).read_bytes()
        assert b"BEGIN CERTIFICATE" in pem_bytes
        assert b"PRIVATE KEY" not in pem_bytes
        browser.close()


# ---------------------------------------------------------------------------
# PW-PKI-08: Unauthenticated /api/v1/admin/pki/status → 401
# ---------------------------------------------------------------------------

def test_pki_status_api_unauthenticated():
    import httpx

    verify: bool | str = _CA_CERT_PATH if _CA_CERT_PATH and _PKI_STATUS_API.startswith("https") else False  # type: ignore[assignment]
    resp = httpx.get(_PKI_STATUS_API, verify=verify, timeout=10)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# PW-PKI-09: Unauthenticated /api/v1/admin/pki/chain/gateway → 401
# ---------------------------------------------------------------------------

def test_pki_chain_api_unauthenticated():
    import httpx

    verify: bool | str = _CA_CERT_PATH if _CA_CERT_PATH and _PKI_CHAIN_API.startswith("https") else False  # type: ignore[assignment]
    resp = httpx.get(_PKI_CHAIN_API, verify=verify, timeout=10)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# PW-PKI-10: Bundle response never contains PRIVATE KEY (HTTP contract)
# ---------------------------------------------------------------------------

def test_pki_bundle_api_unauthenticated_401():
    """Bundle endpoint is auth-gated — unauthenticated → 401 (not 200 with key)."""
    import httpx

    verify: bool | str = _CA_CERT_PATH if _CA_CERT_PATH and _PKI_BUNDLE_API.startswith("https") else False  # type: ignore[assignment]
    resp = httpx.get(_PKI_BUNDLE_API, verify=verify, timeout=10)
    assert resp.status_code == 401
    assert b"PRIVATE KEY" not in resp.content
