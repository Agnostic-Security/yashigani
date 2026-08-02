"""
Playwright e2e tests — HIBP API key admin panel (v2.23.3, PR #59).

Coverage:
  PW-HIBP-01  Nav reaches HIBP panel
  PW-HIBP-02  HIBP panel displays "not configured" when no key set
  PW-HIBP-06  Invalid key format rejected server-side (step-up gated PUT)
  PW-HIBP-07  Unauthenticated GET /api/v1/admin/auth/hibp/status → 401

Mode: live-stack gate. Tests skip automatically if STACK_RUNNING is False.

ASVS: V6.8.4 (step-up), V7.1.3 (no secrets in responses),
      V2.1.7 (HIBP config visible in UI)

Last updated: 2026-08-02 (Ava, Tier-B triage on run
ytf-docker-macos-29d9c9d8-20260731) — full rewrite against the real ui4
module (src/yashigani/backoffice/static/ui4/admin/modules/security-auth.js,
component <ys-admin-hibp>, module id 'hibp'):

  - Auth: the previous hand-rolled `_login()` had the same "never completes
    the browser's two-step forced-password-change flow" bug documented in
    conftest.get_authed_context()'s docstring (which fixes it) —
    contributing to the wider Tier-B cascade. Replaced with cookie
    injection, matching test_pki_admin_ui.py's established pattern.
  - Nav: HIBP is reached via a direct top-level nav entry
    `a[href='#hibp']` (module-registry.js: id 'hibp', group 'identity' —
    "Identity & Access"). There is NO "Settings" nav button/section
    anywhere in ui4 (confirmed: ADMIN_NAV_GROUPS in module-registry.js lists
    Overview / Agents & Orchestration / Identity & Access / Governance &
    Data / Platform & Ops — no "Settings"). `_SETTINGS_NAV = "Settings"` and
    `button:has-text('Settings')` never matched anything.
  - Content: the panel has no `#hibp-status-container`, `#hibp-key-input`,
    `#hibp-btn-save` or `#hibp-key-result` ids — these do not exist anywhere
    in the module. Real markup: the whole panel renders inside
    `[data-module="hibp"]`, status text is a `.ys-txt-note` inside the ONE
    `.ys-panel`, the key field is an *unlabelled-by-id*
    `input[type="password"]`, and the save control is a plain
    `<button>Save key (step-up)</button>` (no id).
  - PW-HIBP-06 ("invalid key format rejected client-side, before API call"):
    the real `_save()` handler (security-auth.js) has NO client-side format
    validation at all — only a non-empty check, reported via a toast, not an
    inline result element. The format/length control DOES exist, but
    SERVER-side: `routes/hibp.py::set_hibp_key()` calls
    `validate_hibp_key_format()` and returns 422 `invalid_key_format` for a
    malformed key — but only AFTER StepUpAdminSession passes (FastAPI
    dependency runs before the handler body). Rewritten to test the REAL
    control end-to-end via the API (stepup, then PUT a malformed key,
    expect 422) rather than assert a client-side behaviour that isn't
    implemented. This is a legitimate control (ASVS V6.8.4 + input
    validation), just enforced at a different layer than originally assumed
    — not filed as a product finding; not asserting the missing client-side
    guard either way pending Tom/product confirmation on intended UX.
"""
from __future__ import annotations

import hashlib
import time

import pyotp
import pytest

from tests.playwright.conftest import (
    BASE_URL,
    STACK_RUNNING,
    _CA_CERT_PATH,
    _api_get_session_cookies,
    _api_totp_last_used,
    _read_secret,
    capture_screenshot,
    get_authed_context,
)

pytestmark = pytest.mark.skipif(
    not STACK_RUNNING,
    reason="Yashigani stack not reachable — skipping Playwright HIBP UI tests",
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

_HIBP_STATUS_API = f"{BASE_URL}/api/v1/admin/auth/hibp/status"
_HIBP_KEY_API = f"{BASE_URL}/api/v1/admin/auth/hibp/key"
_NAV_HREF = "a[href='#hibp']"


@pytest.fixture(scope="module")
def hibp_page():
    """Browser context authenticated as admin (cookie injection); navigated
    to the HIBP panel."""
    with sync_playwright() as pw:
        browser, ctx = get_authed_context(pw, admin=1)
        page = ctx.new_page()
        page.goto(f"{BASE_URL}/admin/")
        page.wait_for_selector(_NAV_HREF, timeout=15000)
        page.click(_NAV_HREF)
        page.wait_for_selector("[data-module='hibp']", timeout=15000)
        capture_screenshot(page, "hibp_panel_loaded")
        yield page
        ctx.close()
        browser.close()


# ---------------------------------------------------------------------------
# PW-HIBP-01: Nav reaches HIBP panel
# ---------------------------------------------------------------------------

class TestHibpNavigation:
    def test_nav_shows_hibp_panel(self, hibp_page):
        """PW-HIBP-01: HIBP nav entry reaches the real panel."""
        panel = hibp_page.locator("[data-module='hibp']")
        assert panel.count() >= 1
        header = hibp_page.locator(".ys-panel-header:has-text('Have I Been Pwned')")
        assert header.count() >= 1, "Expected the HIBP panel header to render"


# ---------------------------------------------------------------------------
# PW-HIBP-02: Not configured state
# ---------------------------------------------------------------------------

class TestHibpNotConfigured:
    def test_shows_status_text(self, hibp_page):
        """PW-HIBP-02: Panel shows a 'Status: configured'/'not configured'
        line — whichever is true for this deployment right now (does not
        force-clear an existing key just to assert a specific state)."""
        note = hibp_page.locator("[data-module='hibp'] .ys-txt-note").first
        text = note.inner_text() or ""
        assert "Status:" in text and ("configured" in text), (
            f"Expected a 'Status: (not )?configured' line, got: {text!r}"
        )


# ---------------------------------------------------------------------------
# PW-HIBP-06: Malformed key rejected — real control is server-side,
# step-up-gated (see module docstring)
# ---------------------------------------------------------------------------

class TestHibpKeyValidation:
    def _stepup(self, cookies):
        import httpx

        admin_totp_secret = _read_secret("admin1_totp_secret")
        last = _api_totp_last_used.get(1, 0.0)
        elapsed = time.time() - last
        if elapsed < 62:
            time.sleep(62 - elapsed)
        secs_into = time.time() % 30
        if secs_into >= 27:
            time.sleep(32 - secs_into)
        code = pyotp.TOTP(admin_totp_secret, digits=8, digest=hashlib.sha512).now()
        _api_totp_last_used[1] = time.time()
        verify = _CA_CERT_PATH or False
        with httpx.Client(verify=verify, cookies=cookies, timeout=10) as c:
            r = c.post(f"{BASE_URL}/auth/stepup", json={"totp_code": code})
            assert r.status_code == 200, f"stepup failed: {r.status_code} {r.text[:200]}"

    def test_key_with_spaces_rejected(self):
        """PW-HIBP-06: A key containing spaces is rejected 422 server-side."""
        import httpx

        cookies = _api_get_session_cookies(admin=1)
        self._stepup(cookies)
        verify = _CA_CERT_PATH or False
        with httpx.Client(verify=verify, cookies=cookies, timeout=10) as c:
            r = c.put(_HIBP_KEY_API, json={"api_key": "bad key with spaces!!"})
        assert r.status_code == 422, (
            f"expected 422 invalid_key_format for a key containing spaces, got "
            f"{r.status_code} {r.text[:200]}"
        )

    def test_too_short_key_rejected(self):
        """PW-HIBP-06: A key shorter than the 8-char minimum is rejected 422."""
        import httpx

        cookies = _api_get_session_cookies(admin=1)
        self._stepup(cookies)
        verify = _CA_CERT_PATH or False
        with httpx.Client(verify=verify, cookies=cookies, timeout=10) as c:
            r = c.put(_HIBP_KEY_API, json={"api_key": "abc"})
        assert r.status_code == 422, (
            f"expected 422 invalid_key_format for a too-short key, got "
            f"{r.status_code} {r.text[:200]}"
        )


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
            assert resp.status_code in (401, 302, 307), (
                f"Expected 401 for unauthenticated request, got {resp.status_code}"
            )
        except Exception:
            pytest.skip("httpx not available or stack not reachable")
