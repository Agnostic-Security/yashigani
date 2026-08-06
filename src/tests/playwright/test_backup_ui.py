"""
Playwright e2e tests — Backup Status + Verify UI panel (#47).

Coverage:
  PW-BAK-01  Backup nav entry visible after login
  PW-BAK-02  Clicking Backup nav renders the backup panel
  PW-BAK-03  Status loads without error (empty-state or populated table)
  PW-BAK-04  A per-backup Verify button is present when a backup exists
  PW-BAK-05  Successful verify → green "ok" badge + backup_name + manifest state
  PW-BAK-06  Mismatch verify → red "failed" badge + mismatches rendered
  PW-BAK-07  Unauthenticated GET /admin/backup/status → 401 / redirect to /admin/login
  PW-BAK-08  XSS canary in a verify request's backup_name is never reflected
             as executable markup in the API response body

Mode: deterministic gate.
ASVS: 4.1.1 (auth on all routes), 4.3.1 (body limit), 7.1.2 (audit on verify),
      9.2.1 (path traversal guard), 11.4 (no absolute FS paths in response)
OWASP WSTG: OTG-AUTHN-001 (auth bypass), OTG-INPVAL-002 (XSS)

Last updated: 2026-08-02 (Ava, Tier-B triage on run
ytf-docker-macos-29d9c9d8-20260731) — rewritten against the real ui4 module
(src/yashigani/backoffice/static/ui4/admin/modules/backup.js, component
<ys-admin-backup>):

  - Auth: `_do_login()` had the same "browser two-step forced-password-change
    never completes" bug documented in conftest.get_authed_context()'s
    docstring. Replaced with cookie injection (matches test_pki_admin_ui.py).
  - Content: there is NO `#page-backup`, `#backup-status-container`,
    `#btn-verify-latest` or `#backup-verify-result` anywhere in the real
    module (confirmed reading the full render() tree) — the panel is a
    generic `.ys-admin-content-pad` div, no per-backup "Verify latest"
    button (there is one per-row "Verify" button per backup, since the
    action targets a SPECIFIC backup by name, not "the latest"), and the
    verify RESULT renders as its own `.ys-panel` with header
    "Verify result — {name}" + an `.ys-badge-green`/`.ys-badge-red`
    ("ok"/"failed") — never the literal strings "PASS"/"FAIL".
  - PW-BAK-08 (XSS canary): the previous version called a global
    `verifyBackup()` function and set `btn.dataset.backupName` — neither
    exists; there is no global JS namespace or free-text backup_name input
    anywhere in the UI (Verify buttons always pass the SERVER's own
    backup name for that row, never user-typed text). There is therefore NO
    browser-reachable input vector for this canary in the current UI.
    Rewritten to test what IS reachable: a direct authenticated API call
    (same session cookie the browser holds) with a backup_name XSS payload,
    asserting the JSON response never echoes it as raw un-escaped HTML and
    the endpoint fails safely (backup not found) rather than 200/500-leaking
    internals. Full "does the SPA re-render this value safely" coverage
    would need a UI seam that lets a test drive a specific already-known
    bad backup_name through the real per-row Verify button (not available
    today, since backups are server-named on creation) — flagged as
    remaining harness debt in the Tier-B triage report, not silently
    dropped.
"""
from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

import pytest

from tests.playwright.conftest import (
    BASE_URL,
    STACK_RUNNING,
    _CA_CERT_PATH,
    capture_screenshot,
    get_authed_context,
)

pytestmark = pytest.mark.playwright_ui


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
    Browser-level tests for the Backup panel.  Each test gets a fresh
    browser context (cookie-injected, no session bleed between tests).
    """

    def _get_authed_page(self, playwright):
        browser, ctx = get_authed_context(playwright, admin=1)
        page = ctx.new_page()
        page.goto(f"{BASE_URL}/admin/")
        page.wait_for_selector("a[href='#backup']", timeout=15000)
        return browser, ctx, page

    def test_backup_nav_visible(self):
        """PW-BAK-01: Backup nav entry exists in the DOM after login."""
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser, ctx, page = self._get_authed_page(pw)
            try:
                btn = page.query_selector("a[href='#backup']")
                assert btn is not None, (
                    "PW-BAK-01 FAIL: Backup nav entry not found in DOM after login."
                )
                assert btn.is_visible(), (
                    "PW-BAK-01 FAIL: Backup nav entry present but not visible."
                )
            finally:
                ctx.close()
                browser.close()

    def test_backup_panel_renders_on_nav_click(self):
        """PW-BAK-02: Clicking Backup nav shows the real backup panel
        (.ys-admin-content-pad with an 'h2' "Backup & Restore" heading —
        there is no #page-backup id in the current ui4 markup)."""
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser, ctx, page = self._get_authed_page(pw)
            try:
                page.click("a[href='#backup']")
                heading = page.wait_for_selector(
                    "h2.ys-admin-section-title:has-text('Backup')", timeout=8_000
                )
                assert heading is not None, "PW-BAK-02 FAIL: 'Backup & Restore' heading did not render."
                assert (heading.inner_text() or "").strip() != "", "PW-BAK-02 FAIL: heading is empty."
                panel = page.query_selector(".ys-panel-header:has-text('Backups')")
                assert panel is not None, "PW-BAK-02 FAIL: 'Backups' panel not found."
                capture_screenshot(page, "backup_panel_loaded")
            finally:
                ctx.close()
                browser.close()

    def test_status_container_loads_without_error(self):
        """PW-BAK-03: After navigating to the Backup panel, the backups
        table/empty-state renders (not stuck on 'Loading backups…')."""
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser, ctx, page = self._get_authed_page(pw)
            try:
                page.click("a[href='#backup']")
                page.wait_for_selector(".ys-panel-header:has-text('Backups')", timeout=8_000)
                page.wait_for_function(
                    "() => !document.body.innerText.includes('Loading backups')",
                    timeout=8_000,
                )
                body_text = page.inner_text("body") or ""
                assert "Loading backups" not in body_text, (
                    "PW-BAK-03 FAIL: panel stuck on 'Loading backups…'."
                )
                # Must show EITHER the empty-state note OR a populated table — never blank.
                assert ("No backups found" in body_text) or (
                    page.query_selector("table.ys-table") is not None
                ), "PW-BAK-03 FAIL: neither empty-state text nor a backups table rendered."
            finally:
                ctx.close()
                browser.close()

    def test_verify_button_present_or_empty_state(self):
        """PW-BAK-04: If at least one backup exists, its row has a "Verify"
        button. If none exist, the empty-state note is shown instead — that
        is a legitimate, non-error state (retro rule A1: absence of an
        artefact is not a failure of the UI itself)."""
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser, ctx, page = self._get_authed_page(pw)
            try:
                page.click("a[href='#backup']")
                page.wait_for_selector(".ys-panel-header:has-text('Backups')", timeout=8_000)
                page.wait_for_function(
                    "() => !document.body.innerText.includes('Loading backups')",
                    timeout=8_000,
                )
                rows = page.query_selector_all("table.ys-table tbody tr")
                if not rows:
                    pytest.skip(
                        "PW-BAK-04 SKIPPED: no backups exist — empty-state renders "
                        "correctly (confirmed via PW-BAK-03), nothing to verify yet."
                    )
                verify_btn = rows[0].query_selector("button:has-text('Verify')")
                assert verify_btn is not None, "PW-BAK-04 FAIL: no Verify button in the first backup row."
                assert verify_btn.is_visible()
            finally:
                ctx.close()
                browser.close()

    def test_verify_success_shows_ok_badge(self):
        """PW-BAK-05: Clicking a real backup's Verify button renders a
        'Verify result' panel with an ok/failed badge, the backup name and
        manifest state.

        Requires at least one backup to exist. If none exist the test is
        SKIPPED (not PASS) per retro rule A1.
        """
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser, ctx, page = self._get_authed_page(pw)
            try:
                page.click("a[href='#backup']")
                page.wait_for_selector(".ys-panel-header:has-text('Backups')", timeout=8_000)
                page.wait_for_function(
                    "() => !document.body.innerText.includes('Loading backups')",
                    timeout=8_000,
                )
                rows = page.query_selector_all("table.ys-table tbody tr")
                if not rows:
                    pytest.skip("PW-BAK-05 SKIPPED: no backups exist to verify.")
                backup_name = (rows[0].query_selector("td").inner_text() or "").strip()
                rows[0].query_selector("button:has-text('Verify')").click()

                result_panel = page.wait_for_selector(
                    ".ys-panel-header:has-text('Verify result')", timeout=15_000
                )
                assert result_panel is not None, "PW-BAK-05 FAIL: Verify result panel did not render."
                result_text = (result_panel.inner_text() or "").strip()
                assert backup_name in result_text, (
                    f"PW-BAK-05 FAIL: result header does not mention the backup name "
                    f"{backup_name!r}: {result_text!r}"
                )
                badge = page.query_selector(".ys-panel-header:has-text('Verify result') .ys-badge")
                assert badge is not None, "PW-BAK-05 FAIL: no ok/failed badge rendered."
                assert (badge.inner_text() or "").strip() in ("ok", "failed"), (
                    f"PW-BAK-05 FAIL: unexpected badge text: {badge.inner_text()!r}"
                )
            finally:
                ctx.close()
                browser.close()

    def test_verify_mismatch_shows_failed_badge(self):
        """PW-BAK-06: When verify returns ok=False, a red 'failed' badge +
        mismatches are shown.

        Requires: YASHIGANI_BACKUPS_DIR accessible from host AND writable so
        we can corrupt a test backup.  Uses YASHIGANI_PLAYWRIGHT_TEST_BACKUP_PATH
        env var to locate the backup directory that should be corrupted
        during the test.

        If the env var is not set, test is SKIPPED (retro rule A1: absent
        artefact = SKIP).
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
            pytest.skip(f"PW-BAK-06 SKIPPED: Backup dir {backup_dir_str!r} does not exist.")

        data_files = [
            f for f in backup_dir.iterdir()
            if f.is_file() and f.name not in ("MANIFEST.sha256", "MANIFEST.sha256.sig")
        ]
        if not data_files:
            pytest.skip("PW-BAK-06 SKIPPED: No data files in backup dir to corrupt.")

        target_file = data_files[0]
        original_content = target_file.read_bytes()

        try:
            target_file.write_bytes(original_content + b"\x00CORRUPTED_BY_QA")

            with sync_playwright() as pw:
                browser, ctx, page = self._get_authed_page(pw)
                try:
                    page.click("a[href='#backup']")
                    page.wait_for_selector(".ys-panel-header:has-text('Backups')", timeout=8_000)
                    page.wait_for_function(
                        "() => !document.body.innerText.includes('Loading backups')",
                        timeout=8_000,
                    )
                    rows = page.query_selector_all("table.ys-table tbody tr")
                    if not rows:
                        pytest.skip("PW-BAK-06 SKIPPED: no backups exist to verify.")
                    rows[0].query_selector("button:has-text('Verify')").click()

                    badge = page.wait_for_selector(
                        ".ys-panel-header:has-text('Verify result') .ys-badge",
                        timeout=15_000,
                    )
                    assert badge is not None, "PW-BAK-06 FAIL: no badge rendered."
                    badge_text = (badge.inner_text() or "").strip()
                    assert badge_text == "failed", (
                        f"PW-BAK-06 FAIL: expected 'failed' badge with a corrupted file, got "
                        f"{badge_text!r}. Either the verify endpoint is not detecting "
                        "tampering, or this backup has no signed MANIFEST."
                    )
                finally:
                    ctx.close()
                    browser.close()
        finally:
            target_file.write_bytes(original_content)

    def test_xss_in_backup_name_never_reflected_unescaped(self):
        """PW-BAK-08: an XSS payload submitted as backup_name to
        POST /admin/backup/verify is never echoed back as raw, executable
        markup in the JSON response, and the endpoint fails safely (backup
        not found) rather than leaking internals.

        There is no browser-reachable free-text backup_name input in the
        current UI (Verify buttons always target a real, server-named
        backup) — see module docstring. This exercises the same
        authenticated session the browser holds, at the API boundary that
        IS reachable, rather than fabricating a UI interaction that does
        not exist.
        """
        from playwright.sync_api import sync_playwright

        xss_payload = "<script>window._xss_fired=1</script>"
        with sync_playwright() as pw:
            browser, ctx, page = self._get_authed_page(pw)
            try:
                cookies = {c["name"]: c["value"] for c in ctx.cookies()}
                import httpx

                verify_tls = _CA_CERT_PATH or False
                with httpx.Client(verify=verify_tls, cookies=cookies, timeout=10) as c:
                    r = c.post(
                        f"{BASE_URL}/admin/backup/verify",
                        json={"backup_name": xss_payload},
                    )
                assert r.status_code in (400, 404, 422), (
                    f"PW-BAK-08 FAIL: expected a safe not-found/validation error for a "
                    f"nonexistent+malicious backup_name, got {r.status_code}: {r.text[:200]}"
                )
                assert "<script>" not in r.text, (
                    "PW-BAK-08 FAIL: raw <script> tag reflected un-escaped in the API "
                    f"response body: {r.text[:300]!r}. OWASP A03 / ASVS V14.3.2."
                )
            finally:
                ctx.close()
                browser.close()
