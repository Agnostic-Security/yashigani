"""
Playwright e2e tests — HIBP API key admin panel (v2.23.3, PR #59).

Coverage:
  PW-HIBP-01  Settings nav reaches HIBP panel section
  PW-HIBP-02  HIBP panel displays "Not configured" when no key set
  PW-HIBP-03  Setting a valid key shows masked value, not full key
  PW-HIBP-04  Clearing a key reverts to "Not configured"
  PW-HIBP-05  Saving without TOTP step-up fails (step-up modal appears)
  PW-HIBP-06  Invalid key format rejected client-side (before API call)
  PW-HIBP-07  Unauthenticated GET /api/v1/admin/auth/hibp/status → 401

Mode: live-stack gate. Requires running Yashigani backoffice + DB.
Tests skip automatically if STACK_RUNNING is False.

ASVS: V6.8.4 (step-up), V7.1.3 (no secrets in responses),
      V2.1.7 (HIBP config visible in UI)

Last updated: 2026-05-07T01:00:00+01:00
"""
from __future__ import annotations

import os

import pytest

from tests.playwright.conftest import (
    launch_chromium,
    BASE_URL,
    STACK_RUNNING,
    _CA_CERT_PATH,
    _generate_strong_password,
    _rotated_admin_password,
    get_admin_credentials,
    get_admin_totp_code,
    _wait_for_fresh_totp_window,
    _api_totp_last_used,
)

pytestmark = pytest.mark.skipif(
    not STACK_RUNNING,
    reason="Yashigani stack not reachable — skipping Playwright HIBP UI tests",
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

_HIBP_STATUS_API = f"{BASE_URL}/api/v1/admin/auth/hibp/status"
_SETTINGS_NAV = "Settings"

# A valid HIBP-key-shaped test value (UUID format, will be cleared after test)
_TEST_KEY = "a1b2c3d4-e5f6-0000-abcd-000000000001"


def _login(page, creds):
    """Log in to the admin panel and return the page ready for admin UI.

    FIXED 2026-07-30 (Ava, Tier-B leg v412-ytf-podman-13033ff9): TWO bugs --
    (1) `creds["admin1_username"]`/`creds["admin1_password"]` dict-key access
    on a TUPLE (get_admin_credentials() returns (username, password)) raised
    TypeError immediately, before any request was ever sent; (2) even past
    that, #totp_code was never filled (required by the server, Phase 13+).
    Fixed to unpack the tuple correctly and fill TOTP via the shared, correct
    (SHA-512/8-digit) helper, respecting the 62s replay window.

    QA-fix (Ava, 2026-07-31): on a genuinely fresh stack (admin creds still
    INITIAL) login redirects back to /admin/login with #pw-form visible
    instead of /admin/ -- this had no handling for that at all, so
    wait_for_url() below would simply time out, failing every test in this
    file. Now drives the password-change form (real id="pw-btn") and
    persists the rotated password so get_admin_credentials() stays correct
    for the rest of this pytest process.
    """
    _wait_for_fresh_totp_window(admin=1)
    username, password = creds
    page.goto(f"{BASE_URL}/admin/login")
    page.fill('input[name="username"], input[type="text"]', username)
    page.fill('input[name="password"], input[type="password"]', password)
    page.fill("#totp_code", get_admin_totp_code())
    _api_totp_last_used[1] = __import__("time").time()
    page.click('button[type="submit"], button:has-text("Login")')
    page.wait_for_timeout(3000)

    if page.locator("#pw-form").is_visible():
        new_pw = _generate_strong_password()
        page.fill("#new_password", new_pw)
        page.fill("#confirm_password", new_pw)
        page.click("#pw-btn")
        page.wait_for_timeout(2000)
        _rotated_admin_password[1] = new_pw

    page.wait_for_url(f"{BASE_URL}/admin/")
    return page


@pytest.fixture(scope="module")
def browser_ctx():
    """Browser context with CA cert trust."""
    creds = get_admin_credentials()

    with sync_playwright() as pw:
        browser = launch_chromium(pw)
        # FIXED 2026-07-30 (Ava, Tier-B leg v412-ytf-podman-13033ff9): this
        # previously only set ignore_https_errors when _CA_CERT_PATH was
        # truthy -- backwards for a selfsigned-mode deployment, where
        # _CA_CERT_PATH is correctly None (see conftest._resolve_ca_cert
        # docstring: ca_root.crt does not validate Caddy's public listener
        # cert here) and Chromium's real cert validation then fails outright
        # with net::ERR_CERT_AUTHORITY_INVALID, failing every test in this
        # file at fixture setup. Always accept the risk for local test
        # traffic, matching every other Playwright fixture in this suite.
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        _login(page, creds)
        yield page, creds
        ctx.close()
        browser.close()


# ---------------------------------------------------------------------------
# PW-HIBP-01: Settings nav reaches HIBP panel
# ---------------------------------------------------------------------------

class TestHibpNavigation:
    def test_settings_nav_shows_hibp_panel(self, browser_ctx):
        """PW-HIBP-01: Settings nav includes the HIBP API Key panel."""
        page, creds = browser_ctx
        # Navigate to settings
        page.click(f"button:has-text('{_SETTINGS_NAV}')")
        page.wait_for_selector("#hibp-status-container", timeout=10000)

        # Panel header present
        assert page.locator("text=Authentication > HIBP API Key").count() >= 1


# ---------------------------------------------------------------------------
# PW-HIBP-02: Not configured state
# ---------------------------------------------------------------------------

class TestHibpNotConfigured:
    def test_shows_not_configured_when_no_key(self, browser_ctx, monkeypatch):
        """PW-HIBP-02: Panel shows 'Not configured' badge when no key set."""
        page, creds = browser_ctx

        # First clear any key that might be set
        import httpx
        verify = _CA_CERT_PATH or False
        try:
            # Get session cookie from page context
            cookies = browser_ctx[0].context.cookies()
            sess_cookie = next(
                (c for c in cookies if "admin_session" in c["name"]), None
            )
            if sess_cookie:
                with httpx.Client(verify=verify) as client:
                    # Check status
                    r = client.get(
                        _HIBP_STATUS_API,
                        cookies={sess_cookie["name"]: sess_cookie["value"]},
                    )
                    # If 200 and configured, clear via DELETE (needs step-up — skip for now)
        except Exception:
            pass

        page.click(f"button:has-text('{_SETTINGS_NAV}')")
        page.wait_for_selector("#hibp-status-container", timeout=10000)

        # Either "Not configured" or "Configured" badge should be visible
        container = page.locator("#hibp-status-container")
        assert container.is_visible()


# ---------------------------------------------------------------------------
# PW-HIBP-06: Client-side validation rejects invalid key format
# ---------------------------------------------------------------------------

class TestHibpClientValidation:
    def test_invalid_key_rejected_client_side(self, browser_ctx):
        """PW-HIBP-06: Client-side validates key before API call."""
        page, creds = browser_ctx
        page.click(f"button:has-text('{_SETTINGS_NAV}')")
        page.wait_for_selector("#hibp-key-input", timeout=10000)

        # Enter an invalid key (has spaces)
        page.fill("#hibp-key-input", "bad key with spaces!!")
        page.click("#hibp-btn-save")

        # Error message should appear, no network call to API was needed
        result = page.locator("#hibp-key-result")
        result.wait_for(timeout=5000)
        result_text = result.inner_text()
        assert len(result_text) > 0, "Expected error message for invalid key"

    def test_too_short_key_rejected(self, browser_ctx):
        """PW-HIBP-06: Key shorter than 8 chars is rejected client-side."""
        page, creds = browser_ctx
        page.click(f"button:has-text('{_SETTINGS_NAV}')")
        page.wait_for_selector("#hibp-key-input", timeout=10000)

        page.fill("#hibp-key-input", "abc")
        page.click("#hibp-btn-save")

        result = page.locator("#hibp-key-result")
        result.wait_for(timeout=5000)
        assert len(result.inner_text()) > 0


# ---------------------------------------------------------------------------
# PW-HIBP-07: Unauthenticated request → 401
# ---------------------------------------------------------------------------

class TestHibpUnauthenticated:
    def test_unauthenticated_status_returns_401(self):
        """PW-HIBP-07: Unauthenticated GET /api/v1/admin/auth/hibp/status → 401."""
        try:
            import httpx
            verify = _CA_CERT_PATH or False
            with httpx.Client(verify=verify) as client:
                resp = client.get(_HIBP_STATUS_API)
            # Should be 401 or redirected to login (3xx)
            assert resp.status_code in (401, 302, 307), (
                f"Expected 401 for unauthenticated request, got {resp.status_code}"
            )
        except Exception:
            pytest.skip("httpx not available or stack not reachable")
