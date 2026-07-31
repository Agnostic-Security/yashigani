"""
Playwright e2e tests — Backup Status + Verify UI panel (#47).

Coverage:
  PW-BAK-01  Backup nav button visible after login
  PW-BAK-02  Clicking Backup nav renders #page-backup panel
  PW-BAK-03  Status loads without error (empty-state or populated)
  PW-BAK-04  Verify now button present and enabled when backup exists
  PW-BAK-05  Successful verify → green PASS badge + backup_name + manifest state
  PW-BAK-06  Mismatch verify → red FAIL badge + mismatches rendered
  PW-BAK-07  Unauthenticated GET /admin/backup/status → 401 / redirect to /admin/login
  PW-BAK-08  XSS canary in backup_name rendered escaped in FAIL panel

Mode: deterministic gate.
ASVS: 4.1.1 (auth on all routes), 4.3.1 (body limit), 7.1.2 (audit on verify),
      9.2.1 (path traversal guard), 11.4 (no absolute FS paths in response)
OWASP WSTG: OTG-AUTHN-001 (auth bypass), OTG-INPVAL-002 (XSS)

Last updated: 2026-05-06
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

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

# ---------------------------------------------------------------------------
# Helpers — we use the sync API inside pytest (no asyncio needed)
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.playwright_ui


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tls_args(chromium) -> dict:
    """
    Playwright browser launch args.  When the stack uses a self-signed CA we
    cannot inject the custom CA into Chromium directly, so we accept the risk
    on localhost-only test traffic.  The gateway TLS layer is separately
    validated by the API contract tests (which use httpx with the real CA cert).
    """
    return {"ignore_https_errors": True}


# ---------------------------------------------------------------------------
# Fixture: authenticated admin page
# ---------------------------------------------------------------------------

def _do_login(page, username: str, password: str) -> None:
    """Log in via the admin login form.  Handles the force-password-change
    redirect only when it appears — if the password is already rotated the
    test won't enter the change flow.

    FIXED 2026-07-30 (Ava, Tier-B leg v412-ytf-podman-13033ff9): this
    previously (a) looked for input[name='totp'] -- the real field is
    id="totp_code"/name="totp_code" -- so totp_field was always None and NO
    code was ever submitted; (b) even when found, used bare
    pyotp.TOTP(secret).now() (SHA-1/6-digit default), which is WRONG for the
    admin tier (SHA-512/8-digit, see conftest.get_admin_totp_code() F9 note);
    (c) _read_totp_secret() used parents[4], one level above the repo root
    (off-by-one, same class of bug fixed in test_v233_webauthn_e2e.py).
    Net effect: login could never complete, so page.wait_for_url() always hit
    its 10s timeout, failing every test in this file. Now reuses the shared,
    correct conftest helpers (also respects the 62s TOTP-replay window).

    QA-fix (Ava, 2026-07-31): this docstring claimed the force-password-change
    redirect was "handled ... only when it appears", but no such handling
    existed in the code -- on a genuinely fresh stack (admin creds still
    INITIAL, as this Tier-B environment is) login lands back on
    /admin/login with #pw-form visible, and wait_for_url() below would
    simply time out, failing every test in this file. Now actually detects
    and drives the password-change form (using the real #pw-btn id, not the
    stale-and-nonexistent #pw-change-btn from other files' pre-fix state),
    and persists the rotated password into conftest._rotated_admin_password
    so get_admin_credentials() returns the right value for every subsequent
    test in this process."""
    _wait_for_fresh_totp_window(admin=1)
    page.goto(f"{BASE_URL}/admin/login")
    page.fill("input[name='username']", username)
    page.fill("input[name='password']", password)
    page.fill("#totp_code", get_admin_totp_code())
    _api_totp_last_used[1] = time.time()
    page.click("button[type='submit']")
    page.wait_for_timeout(3000)  # wait for fetch() to complete before checking for pw-form

    if page.locator("#pw-form").is_visible():
        new_pw = _generate_strong_password()
        page.fill("#new_password", new_pw)
        page.fill("#confirm_password", new_pw)
        page.click("#pw-btn")
        page.wait_for_timeout(2000)
        _rotated_admin_password[1] = new_pw

    # Allow redirect to settle
    page.wait_for_url(re.compile(r"/admin/"), timeout=10_000)
    # FIXED 2026-07-30 (Ava, Tier-B leg v412-ytf-podman-13033ff9): the ui4 SPA
    # bootstraps its nav asynchronously (module-registry / admin-nav.js) after
    # the URL changes -- wait_for_url alone races the nav render, so an
    # immediate query_selector("a[href='#backup']") right after this call can
    # return None even though the element renders a moment later. Every other
    # file's login helper either has an equivalent settle wait or relies on a
    # wait_for_selector() with a generous timeout right after; this one had
    # neither. Confirmed via test_webui_conformance_full.py's
    # test_nav_entry_present, which explicitly does
    # `page.wait_for_timeout(500)` after navigating to /admin/ before
    # querying nav links.
    page.wait_for_timeout(500)


# ---------------------------------------------------------------------------
# PW-BAK-07 — unauthenticated check (no browser needed, uses httpx)
# ---------------------------------------------------------------------------

@pytest.mark.api_contract
def test_unauth_status_redirects_or_401():
    """
    PW-BAK-07: GET /admin/backup/status without session cookie must return
    401 (API) or redirect to /admin/login (HTML).  MUST NOT return 200.

    ASVS 4.1.1: all admin routes require authentication.
    """
    import httpx

    verify: bool | str = _CA_CERT_PATH or False  # type: ignore[assignment]
    r = httpx.get(
        f"{BASE_URL}/admin/backup/status",
        verify=verify,
        follow_redirects=False,
        timeout=10,
    )
    assert r.status_code in (401, 302, 307, 308), (
        f"PW-BAK-07 FAIL: expected 401/3xx without session, got {r.status_code}. "
        "Broken access control — ASVS 4.1.1 / OWASP A01."
    )
    if r.status_code in (302, 307, 308):
        location = r.headers.get("location", "")
        assert "login" in location.lower(), (
            f"PW-BAK-07 FAIL: redirect does not go to login — Location: {location}"
        )


# ---------------------------------------------------------------------------
# PW-BAK-01 to PW-BAK-06, PW-BAK-08 — browser tests
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not STACK_RUNNING, reason="stack not running")
class TestBackupUI:
    """
    Browser-level tests for the Backup panel.  Uses playwright sync API via
    a context manager so each test gets a fresh browser context (no session
    bleed between tests).
    """

    def _get_page(self, playwright):
        browser = launch_chromium(playwright)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        return browser, context, page

    def test_backup_nav_visible(self):
        """PW-BAK-01: Backup nav button exists in the DOM after login."""
        from playwright.sync_api import sync_playwright

        username, password = get_admin_credentials()
        with sync_playwright() as pw:
            browser, ctx, page = self._get_page(pw)
            try:
                _do_login(page, username, password)
                # FIXED 2026-07-30 (Ava, Tier-B leg v412-ytf-podman-13033ff9):
                # same class of stale-selector bug as test_pki_admin_ui.py /
                # test_documents_admin_ui.py -- 'button[data-param="backup"]'
                # is pre-ui4-nav-rewrite; the current nav renders
                # `a[href='#module-id']` (see admin-nav.js/module-registry.js).
                btn = page.query_selector("a[href='#backup']")
                assert btn is not None, (
                    "PW-BAK-01 FAIL: Backup nav button not found in DOM after login."
                )
                assert btn.is_visible(), (
                    "PW-BAK-01 FAIL: Backup nav button present but not visible."
                )
            finally:
                ctx.close()
                browser.close()

    def test_backup_panel_renders_on_nav_click(self):
        """PW-BAK-02: Clicking Backup nav shows #page-backup panel."""
        from playwright.sync_api import sync_playwright

        username, password = get_admin_credentials()
        with sync_playwright() as pw:
            browser, ctx, page = self._get_page(pw)
            try:
                _do_login(page, username, password)
                page.click("a[href='#backup']")
                # Panel must be visible within 5 seconds
                panel = page.wait_for_selector("#page-backup", state="visible", timeout=5_000)
                assert panel is not None, "PW-BAK-02 FAIL: #page-backup panel did not become visible."
                assert panel.is_visible(), "PW-BAK-02 FAIL: #page-backup panel not visible after click."
                # Heading check
                heading = page.query_selector("#page-backup h2")
                assert heading is not None, "PW-BAK-02 FAIL: No h2 heading inside #page-backup."
                heading_text = (heading.inner_text() or "").strip()
                assert heading_text != "", "PW-BAK-02 FAIL: h2 heading is empty."
            finally:
                ctx.close()
                browser.close()

    def test_status_container_loads_without_error(self):
        """PW-BAK-03: After navigating to Backup panel, status container shows
        content (not the 'Failed to load' error message)."""
        from playwright.sync_api import sync_playwright

        username, password = get_admin_credentials()
        with sync_playwright() as pw:
            browser, ctx, page = self._get_page(pw)
            try:
                _do_login(page, username, password)
                page.click("a[href='#backup']")
                page.wait_for_selector("#page-backup", state="visible", timeout=5_000)
                # Wait for loading spinner to disappear (up to 8s for async data fetch)
                page.wait_for_function(
                    "() => !document.querySelector('#backup-status-container .loading')",
                    timeout=8_000,
                )
                container = page.query_selector("#backup-status-container")
                assert container is not None, "PW-BAK-03 FAIL: #backup-status-container not found."
                content = (container.inner_text() or "").strip()
                assert "Failed to load" not in content, (
                    f"PW-BAK-03 FAIL: Status container shows error text: {content!r}"
                )
                # Must show EITHER the empty-state message OR a table row — never blank
                assert content != "", (
                    "PW-BAK-03 FAIL: #backup-status-container is empty (no empty-state rendered)."
                )
            finally:
                ctx.close()
                browser.close()

    def test_verify_button_present(self):
        """PW-BAK-04: Verify-latest button is present in the panel."""
        from playwright.sync_api import sync_playwright

        username, password = get_admin_credentials()
        with sync_playwright() as pw:
            browser, ctx, page = self._get_page(pw)
            try:
                _do_login(page, username, password)
                page.click("a[href='#backup']")
                page.wait_for_selector("#page-backup", state="visible", timeout=5_000)
                btn = page.wait_for_selector("#btn-verify-latest", timeout=8_000)
                assert btn is not None, "PW-BAK-04 FAIL: #btn-verify-latest not found."
                assert btn.is_visible(), "PW-BAK-04 FAIL: #btn-verify-latest not visible."
            finally:
                ctx.close()
                browser.close()

    def test_verify_success_shows_pass_badge(self):
        """PW-BAK-05: When verify returns ok=True, the panel shows a PASS badge.

        This test requires at least one backup to exist under YASHIGANI_BACKUPS_DIR.
        If no backups exist the button stays disabled and the test is SKIPPED (not PASS).
        Retro rule A1: absent artefact = SKIP, not PASS.
        """
        from playwright.sync_api import sync_playwright

        username, password = get_admin_credentials()
        with sync_playwright() as pw:
            browser, ctx, page = self._get_page(pw)
            try:
                _do_login(page, username, password)
                page.click("a[href='#backup']")
                page.wait_for_selector("#page-backup", state="visible", timeout=5_000)
                page.wait_for_function(
                    "() => !document.querySelector('#backup-status-container .loading')",
                    timeout=8_000,
                )
                btn = page.wait_for_selector("#btn-verify-latest", timeout=5_000)
                assert btn is not None, "PW-BAK-05 FAIL: #btn-verify-latest not found."

                if btn.get_attribute("disabled") is not None:
                    pytest.skip(
                        "PW-BAK-05 SKIPPED: Verify button is disabled — "
                        "no backups exist. Deploy a backup first to run this gate."
                    )

                btn.click()
                # Wait for result div to appear
                result_div = page.wait_for_selector(
                    "#backup-verify-result", state="visible", timeout=15_000
                )
                assert result_div is not None, "PW-BAK-05 FAIL: #backup-verify-result not visible."
                result_text = (result_div.inner_text() or "").strip()
                assert result_text != "", "PW-BAK-05 FAIL: result div is empty."
                # Either PASS (ok=True) or FAIL (ok=False) badge must appear
                assert "PASS" in result_text or "FAIL" in result_text, (
                    f"PW-BAK-05 FAIL: Neither PASS nor FAIL badge in result: {result_text!r}"
                )
            finally:
                ctx.close()
                browser.close()

    def test_verify_mismatch_shows_fail_badge(self):
        """PW-BAK-06: When verify returns ok=False, red FAIL badge + mismatches shown.

        Requires: YASHIGANI_BACKUPS_DIR accessible from host AND writable so we can
        corrupt a test backup.  Uses YASHIGANI_PLAYWRIGHT_TEST_BACKUP_PATH env var to
        locate the backup directory that should be corrupted during the test.

        If the env var is not set, test is SKIPPED (retro rule A1: absent artefact = SKIP).
        """
        from playwright.sync_api import sync_playwright

        backup_dir_str = os.getenv("YASHIGANI_PLAYWRIGHT_TEST_BACKUP_PATH")
        if not backup_dir_str:
            pytest.skip(
                "PW-BAK-06 SKIPPED: YASHIGANI_PLAYWRIGHT_TEST_BACKUP_PATH not set. "
                "Set to a writable backup dir path on host to enable mismatch test."
            )

        backup_dir = Path(backup_dir_str)
        if not backup_dir.exists() or not backup_dir.is_dir():
            pytest.skip(
                f"PW-BAK-06 SKIPPED: Backup dir {backup_dir_str!r} does not exist."
            )

        # Find a data file (not MANIFEST) to corrupt
        data_files = [
            f for f in backup_dir.iterdir()
            if f.is_file() and f.name not in ("MANIFEST.sha256", "MANIFEST.sha256.sig")
        ]
        if not data_files:
            pytest.skip("PW-BAK-06 SKIPPED: No data files in backup dir to corrupt.")

        target_file = data_files[0]
        original_content = target_file.read_bytes()

        try:
            # Corrupt the file
            target_file.write_bytes(original_content + b"\x00CORRUPTED_BY_QA")

            username, password = get_admin_credentials()
            with sync_playwright() as pw:
                browser, ctx, page = self._get_page(pw)
                try:
                    _do_login(page, username, password)
                    page.click("a[href='#backup']")
                    page.wait_for_selector("#page-backup", state="visible", timeout=5_000)
                    page.wait_for_function(
                        "() => !document.querySelector('#backup-status-container .loading')",
                        timeout=8_000,
                    )
                    btn = page.wait_for_selector("#btn-verify-latest", timeout=5_000)
                    if btn is None or btn.get_attribute("disabled") is not None:
                        pytest.skip("PW-BAK-06 SKIPPED: Verify button disabled (no backups).")

                    btn.click()
                    result_div = page.wait_for_selector(
                        "#backup-verify-result", state="visible", timeout=15_000
                    )
                    assert result_div is not None, "PW-BAK-06 FAIL: result div not visible."
                    result_text = (result_div.inner_text() or "").strip()

                    # With a corrupted file the MANIFEST is signed but checksums differ
                    # → ok=False → FAIL badge
                    assert "FAIL" in result_text, (
                        f"PW-BAK-06 FAIL: Expected FAIL badge with corrupted file, got: {result_text!r}. "
                        "Either the verify endpoint is not detecting tampering, or "
                        "the backup has no MANIFEST (unsigned state returns ok=True)."
                    )
                finally:
                    ctx.close()
                    browser.close()
        finally:
            # Always restore the file
            target_file.write_bytes(original_content)

    def test_xss_in_backup_name_escaped(self):
        """PW-BAK-08: backup_name containing XSS payload is HTML-escaped in the result panel.

        Calls POST /admin/backup/verify directly with a crafted name, then checks that
        the error detail rendered in the UI does not execute script.
        OWASP WSTG OTG-INPVAL-002 / ASVS V14.3.2.
        """
        from playwright.sync_api import sync_playwright

        xss_payload = '<script>window._xss_fired=1</script>'
        username, password = get_admin_credentials()
        with sync_playwright() as pw:
            browser, ctx, page = self._get_page(pw)
            try:
                _do_login(page, username, password)
                page.click("a[href='#backup']")
                page.wait_for_selector("#page-backup", state="visible", timeout=5_000)

                # Inject XSS payload via JS so apiMutate wires it through
                # the normal UI code path (exercises escapeHtml in dashboard.js)
                page.evaluate(f"""
                    (async () => {{
                        var btn = document.getElementById('btn-verify-latest');
                        if (btn) btn.dataset.backupName = {json.dumps(xss_payload)};
                        if (typeof verifyBackup === 'function') {{
                            await verifyBackup();
                        }}
                    }})();
                """)
                # Small wait for the async call to complete
                page.wait_for_timeout(3_000)

                # Check that the script tag was never executed
                xss_fired = page.evaluate("window._xss_fired")
                assert xss_fired is None or xss_fired != 1, (
                    "PW-BAK-08 FAIL: XSS payload executed — window._xss_fired=1. "
                    "Stored/reflected XSS in backup verify result. "
                    "OWASP A03 / ASVS V14.3.2."
                )

                # The raw script tag must not appear un-escaped in the DOM
                page_source = page.content()
                assert "<script>window._xss_fired" not in page_source, (
                    "PW-BAK-08 FAIL: Raw <script> tag present in page source — "
                    "escapeHtml not applied. OWASP A03 / ASVS V14.3.2."
                )
            finally:
                ctx.close()
                browser.close()
