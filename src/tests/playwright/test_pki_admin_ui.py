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
    BASE_URL,
    STACK_RUNNING,
    _CA_CERT_PATH,
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
    """
    cookies = _api_get_session_cookies(admin=1)
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


def _navigate_to_pki(page) -> None:
    """Click the PKI nav button and wait for panel to load with service rows.

    The PKI panel fires an async loadPkiStatus() which fetches /api/v1/admin/pki/status.
    We wait for either a View button (success) or an error paragraph to appear
    in the container, with a generous timeout to allow the API round-trip.
    """
    page.click("button[data-param='pki']")
    page.wait_for_selector("#pki-status-container", timeout=8000)
    # Wait for the async API response to render: either buttons or error text
    page.wait_for_selector(
        "#pki-status-container button, #pki-status-container p",
        timeout=12000,
    )
    page.wait_for_timeout(500)


# ---------------------------------------------------------------------------
# PW-PKI-01: Nav button exists and navigates to PKI page
# ---------------------------------------------------------------------------

def test_pki_nav_button_exists():
    username, password = get_admin_credentials()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(
            ignore_https_errors=True,
            **({"extra_http_headers": {"X-CA-Cert": _CA_CERT_PATH}} if _CA_CERT_PATH else {}),
        )
        page = ctx.new_page()
        _login(page, username, password)
        page.goto(_ADMIN_DASHBOARD)
        page.wait_for_timeout(2000)

        pki_btn = page.locator("button[data-param='pki']")
        expect(pki_btn).to_be_visible()
        pki_btn.click()

        # PKI page should become visible
        pki_container = page.locator("#pki-status-container")
        expect(pki_container).to_be_visible()
        browser.close()


# ---------------------------------------------------------------------------
# PW-PKI-02: Status table loads with at least one service row
# ---------------------------------------------------------------------------

def test_pki_status_table_loads():
    username, password = get_admin_credentials()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        _login(page, username, password)
        page.goto(_ADMIN_DASHBOARD)
        page.wait_for_timeout(2000)
        _navigate_to_pki(page)

        # The status container should not show an error
        container_text = page.locator("#pki-status-container").inner_text()
        assert "Failed to load" not in container_text

        # At least one "View" button (per service row)
        view_buttons = page.locator("#pki-status-container button")
        assert view_buttons.count() >= 1
        browser.close()


# ---------------------------------------------------------------------------
# PW-PKI-03: View button shows chain detail panel
# ---------------------------------------------------------------------------

def test_pki_view_chain_shows_detail():
    username, password = get_admin_credentials()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        _login(page, username, password)
        page.goto(_ADMIN_DASHBOARD)
        page.wait_for_timeout(2000)
        _navigate_to_pki(page)

        # Click the first "View" button
        first_view_btn = page.locator("#pki-status-container button").first
        first_view_btn.click()
        page.wait_for_timeout(2000)

        # Chain detail panel should appear
        detail = page.locator("#pki-chain-detail")
        expect(detail).to_be_visible()
        browser.close()


# ---------------------------------------------------------------------------
# PW-PKI-04: Chain detail shows SHA-256 fingerprint (64-char hex)
# ---------------------------------------------------------------------------

def test_pki_chain_shows_fingerprint():
    username, password = get_admin_credentials()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        _login(page, username, password)
        page.goto(_ADMIN_DASHBOARD)
        page.wait_for_timeout(2000)
        _navigate_to_pki(page)

        # Click the first View button
        page.locator("#pki-status-container button").first.click()
        page.wait_for_timeout(2000)

        detail_text = page.locator("#pki-chain-detail").inner_text()
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
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        _login(page, username, password)
        page.goto(_ADMIN_DASHBOARD)
        page.wait_for_timeout(2000)
        _navigate_to_pki(page)

        page.locator("#pki-status-container button").first.click()
        page.wait_for_timeout(2000)

        detail_text = page.locator("#pki-chain-detail").inner_text()
        assert "Subject CN" in detail_text or "subject_cn" in detail_text.lower()
        assert "Issuer CN" in detail_text or "issuer_cn" in detail_text.lower()
        browser.close()


# ---------------------------------------------------------------------------
# PW-PKI-06: Rotate button triggers step-up TOTP modal
# ---------------------------------------------------------------------------

def test_pki_rotate_triggers_stepup():
    username, password = get_admin_credentials()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        _login(page, username, password)
        page.goto(_ADMIN_DASHBOARD)
        page.wait_for_timeout(2000)
        _navigate_to_pki(page)

        # Find a Rotate button and click it
        # The button calls pkiRotate() which calls apiMutate() which handles step_up_required
        rotate_btns = page.locator("button", has_text="Rotate")
        if rotate_btns.count() == 0:
            pytest.skip("No Rotate buttons found — no services in manifest?")

        rotate_btns.first.click()
        page.wait_for_timeout(2500)

        # Either the step-up modal appears OR the result shows a step-up message
        stepup_modal = page.locator("#stepup-modal")
        result_el = page.locator("#pki-rotate-result")
        modal_visible = stepup_modal.is_visible()
        result_text = result_el.inner_text() if result_el.is_visible() else ""
        assert modal_visible or "step" in result_text.lower() or "totp" in result_text.lower() or "verification" in result_text.lower()
        browser.close()


# ---------------------------------------------------------------------------
# PW-PKI-07: Download bundle fires download (no navigation)
# ---------------------------------------------------------------------------

def test_pki_download_bundle_fires_download():
    username, password = get_admin_credentials()
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
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
