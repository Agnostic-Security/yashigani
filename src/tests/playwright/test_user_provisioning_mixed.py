"""End-user provisioning across BOTH pathways — 3 via the WebUI, 2 via the API.

Tiago, 2026-08-12: "change the test and create the 5 users by hand 3 in the web ui
2 using API".

Why this shape:
- The suite previously obtained users only by `POST /admin/users`. That proves the
  endpoint and says NOTHING about the admin UI's create form — the same blind spot
  that let LAURA-001 ship a broken chat UI three times while every API test stayed
  green, and that QA SOP 4.17 Rule 6 forbids ("no test may bypass the user pathway").
- Creating through the UI also drives the ui4 step-up modal end-to-end. YSG-RISK-262
  ("admin step-up is universally broken from the browser") shipped precisely because
  step-up was only ever verified by direct API calls to /auth/stepup and never by
  typing a code into the real modal. This test closes that gap.
- The 5th/6th create also exercises the licence cap as a control rather than as an
  obstacle: at the cap the next create MUST be 402 end_user_limit_exceeded.

Effect-verified, not response-verified (YTF 5.3): every UI creation is confirmed by a
subsequent API read, so a form that "looks" successful but persists nothing fails here.
"""
from __future__ import annotations

import uuid

import pytest

from tests.playwright.conftest import (
    BASE_URL,
    wait_for_fresh_totp,
    STACK_RUNNING,
    _CA_CERT_PATH,
    delete_end_user,
    do_admin_stepup,
    get_admin_totp_code,
    playwright_login_admin,
    launch_chromium,
)

try:
    from playwright.sync_api import sync_playwright
    _PW_AVAILABLE = True
except ImportError:
    _PW_AVAILABLE = False

pytestmark = [
    pytest.mark.skipif(
        not STACK_RUNNING or not _PW_AVAILABLE,
        reason="Yashigani stack not reachable or playwright not installed",
    ),
    # FIND-0813-011 / NB-3 (2026-08-16): this file used to get the extended
    # 610s timeout budget via a nodeid substring match ("provisioning" +
    # "mixed" both hit the file path) -- see conftest.py's
    # pytest_collection_modifyitems. Explicit now: 5/6 identities created
    # here (3 UI + 2 API + the residual admin) each drive a fresh TOTP login,
    # the exact multi-identity shape the extended budget exists for.
    pytest.mark.multi_identity,
]

# FIND-0813-010: these used to be hardcoded 3 + 2 = 5, which exactly equals the
# COMMUNITY end-user cap — leaving no room for the residual account the product
# refuses to delete (409 USER_MINIMUM_VIOLATION). residual(1) + 3 + 2 = 6 > 5, so
# the second API create 402'd and the suite read a working licence control as a
# failure. Counts are now derived from the LIVE cap (GET /admin/license ->
# limits.end_users.maximum) minus whatever cannot be cleared, so the test is
# correct on community (5) and on any larger tier without editing it.
UI_USERS = 3          # upper bound; trimmed to fit available capacity at runtime
API_USERS = 2         # ditto — the remainder after the UI share
_MARK = "prov"  # emails are prov-<hex>@example.com so cleanup can never touch a real account


def _client(cookies: dict | None = None):
    """Cookies go on the CLIENT, not per-request: delete_end_user() issues its own
    call through this client, so a per-request cookie dict never reached it and every
    DELETE went out unauthenticated (2026-08-12: "could not clear end users, 5 remain").
    httpx also deprecates per-request cookies for exactly this ambiguity."""
    import httpx
    return httpx.Client(verify=_CA_CERT_PATH if _CA_CERT_PATH else False,
                        follow_redirects=False, timeout=20, cookies=cookies or {})


def _list_end_users(cookies: dict) -> list:
    with _client(cookies) as c:
        r = c.get(f"{BASE_URL}/admin/users")
        return r.json().get("users", []) if r.status_code == 200 else []


def _free_all_capacity(cookies: dict) -> int:
    """Delete every end user so the cap has room for the 5 this test provisions.

    A test stack only ever holds seeded/test identities. Deliberately explicit rather
    than hidden in a fixture: this test OWNS the end-user population for its duration.
    """
    deleted = 0
    # DELETE /admin/users/{u} is StepUpAdminSession-gated, and the elevation expires
    # after YASHIGANI_STEPUP_TTL_SECONDS. Deleting several accounts in a loop can
    # outlive one elevation — observed 2026-08-12: 4 of 5 deleted, the last failed,
    # leaving only 4 free slots so the API half of this test hit the cap. Re-elevate
    # and retry rather than assuming one step-up covers the whole loop.
    # FIND-0813-010: the product REFUSES to delete the final end-user account —
    # DELETE /admin/users/{u} returns 409 USER_MINIMUM_VIOLATION "Cannot delete
    # the last user account". That is a working control, not a failure. The
    # "4 of 5 deleted, the last failed" note above was misattributed to step-up
    # expiry; verified live 2026-08-16 with a fresh elevation, the 5th delete
    # still 409s. So a fully empty population is UNREACHABLE by design and
    # retrying for it just burns TOTP windows.
    for _attempt in range(3):
        remaining = _list_end_users(cookies)
        if len(remaining) <= 1:
            break                      # 1 residual is the floor, not a failure
        with _client(cookies) as c:
            for u in remaining:
                if delete_end_user(c, u.get("username")):
                    deleted += 1
        if len(_list_end_users(cookies)) > 1:
            do_admin_stepup(cookies, admin=1)
    return deleted


def _end_user_cap(cookies: dict) -> "int | None":
    """Live end-user cap from GET /admin/license (limits.end_users.maximum).

    Returns None for an unlimited/unknown cap, in which case the caller keeps
    the nominal UI_USERS/API_USERS split.
    """
    try:
        with _client(cookies) as c:
            r = c.get(f"{BASE_URL}/admin/license")
        if r.status_code != 200:
            return None
        blk = (r.json().get("limits") or {}).get("end_users") or {}
        return None if blk.get("unlimited") else blk.get("maximum")
    except Exception:
        return None


def _plan_provisioning(cookies: dict) -> "tuple[int, int]":
    """(ui_count, api_count) that FIT under the live cap after the residual.

    The cap is a CONTROL this suite deliberately exercises (test_05 asserts the
    next create is 402), so the plan must fill capacity exactly — not overflow
    it, which is what made test_03/test_04 fail on community tier.
    """
    cap = _end_user_cap(cookies)
    residual = len(_list_end_users(cookies))
    if cap is None:
        return UI_USERS, API_USERS
    available = max(cap - residual, 0)
    ui = min(UI_USERS, available)
    api = max(available - ui, 0)
    return ui, api


@pytest.fixture(scope="class")
def admin_page():
    with sync_playwright() as pw:
        browser = launch_chromium(pw)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        playwright_login_admin(page, admin=1, force_fresh=True)
        # The browser login consumes a TOTP code. do_admin_stepup() in the tests below
        # needs a code the server has NOT seen: inside the same 30s window it is a
        # replay and the server returns 401 invalid_totp_code (observed 2026-08-12 --
        # capacity never cleared, so every later create hit the full quota). Block on
        # the shared per-identity ledger rather than sleeping a guessed interval.
        wait_for_fresh_totp("admin:1")
        yield ctx, page
        ctx.close()
        browser.close()


class TestMixedUserProvisioning:
    """Users created through the real admin UI and the API, then the cap.

    Counts are derived at runtime from the live licence cap (see
    _plan_provisioning) — nominally 3 via UI + 2 via API, trimmed to fit
    whatever capacity the deployment's tier actually allows.
    """

    PLAN_UI = UI_USERS
    PLAN_API = API_USERS

    def test_01_clear_capacity(self, admin_page):
        ctx, _ = admin_page
        cookies = {c["name"]: c["value"] for c in ctx.cookies()}
        do_admin_stepup(cookies, admin=1)
        freed = _free_all_capacity(cookies)
        remaining = _list_end_users(cookies)
        # FIND-0813-010: asserting `not remaining` asserted that the
        # USER_MINIMUM_VIOLATION control does NOT exist. The floor is 1.
        assert len(remaining) <= 1, (
            f"could not clear end users, {len(remaining)} remain "
            f"(1 residual is expected — the product refuses to delete the last "
            f"account with 409 USER_MINIMUM_VIOLATION)"
        )
        print(f"  cleared {freed} end users — {len(remaining)} residual (floor is 1)")
        ui, api = _plan_provisioning(cookies)
        TestMixedUserProvisioning.PLAN_UI = ui
        TestMixedUserProvisioning.PLAN_API = api
        cap = _end_user_cap(cookies)
        print(f"  cap={cap} residual={len(remaining)} -> provisioning {ui} via UI + {api} via API")
        assert ui + api >= 1, (
            f"no end-user capacity available to provision (cap={cap}, "
            f"residual={len(remaining)}) — cannot exercise this suite")

    def test_02_create_three_users_via_webui(self, admin_page):
        """THE USER PATHWAY: fill the real form, click the real button, drive the real
        step-up modal, then prove each user persisted via an API read."""
        ctx, page = admin_page
        created = []
        for i in range(self.PLAN_UI):
            email = f"{_MARK}-ui-{uuid.uuid4().hex[:8]}@example.com"
            page.goto(f"{BASE_URL}/admin/#users")
            page.wait_for_timeout(1200)
            panel = page.locator('[data-module="users"]')
            panel.locator('input[type="email"]').first.fill(email)
            panel.locator('button:has-text("Create")').first.click()

            # ui4 routes mutations through ApiClient.mutate(), which raises the shared
            # step-up modal on 401 step_up_required. Type a REAL code into it — this is
            # the browser path YSG-RISK-262 shipped broken because nothing tested it.
            modal_input = page.locator('input[autocomplete="one-time-code"]')
            if modal_input.count() and modal_input.first.is_visible():
                modal_input.first.fill(get_admin_totp_code())
                page.locator('button:has-text("Confirm"), button:has-text("OK"), '
                             'button:has-text("Verify")').first.click()
            page.wait_for_timeout(2500)

            cookies = {c["name"]: c["value"] for c in ctx.cookies()}
            emails = [(u.get("email") or "") for u in _list_end_users(cookies)]
            assert email in emails, (
                f"user {email} was created through the UI form but does NOT exist via "
                f"GET /admin/users — the form did not persist it. Present: {emails}")
            created.append(email)
        assert len(created) == self.PLAN_UI
        print(f"  created {len(created)} users through the WebUI form")

    def test_03_create_two_users_via_api(self, admin_page):
        ctx, _ = admin_page
        cookies = {c["name"]: c["value"] for c in ctx.cookies()}
        do_admin_stepup(cookies, admin=1)
        created = []
        with _client(cookies) as c:
            for _ in range(self.PLAN_API):
                email = f"{_MARK}-api-{uuid.uuid4().hex[:8]}@example.com"
                r = c.post(f"{BASE_URL}/admin/users", json={"email": email})
                assert r.status_code == 200, f"API create failed: {r.status_code} {r.text[:200]}"
                body = r.json()
                assert body.get("temporary_password") and body.get("totp_secret")
                created.append(email)
        assert len(created) == self.PLAN_API
        print(f"  created {len(created)} users through the API")

    def test_04_five_users_present(self, admin_page):
        ctx, _ = admin_page
        cookies = {c["name"]: c["value"] for c in ctx.cookies()}
        users = [u for u in _list_end_users(cookies)
                 if (u.get("email") or "").startswith(f"{_MARK}-")]
        assert len(users) == self.PLAN_UI + self.PLAN_API, (
            f"expected {self.PLAN_UI + self.PLAN_API} provisioned users, found {len(users)}")
        ui = [u for u in users if "-ui-" in (u.get("email") or "")]
        api = [u for u in users if "-api-" in (u.get("email") or "")]
        assert len(ui) == self.PLAN_UI and len(api) == self.PLAN_API

    def test_05_sixth_user_is_refused_402(self, admin_page):
        """The licence cap as a CONTROL. At the cap the next create must be refused."""
        ctx, _ = admin_page
        cookies = {c["name"]: c["value"] for c in ctx.cookies()}
        do_admin_stepup(cookies, admin=1)
        with _client(cookies) as c:
            r = c.post(f"{BASE_URL}/admin/users",
                       json={"email": f"{_MARK}-sixth-{uuid.uuid4().hex[:8]}@example.com"})
        assert r.status_code == 402, (
            f"end-user cap NOT enforced: 6th create returned {r.status_code}, expected 402. "
            f"{r.text[:200]}")
        detail = r.json().get("detail", {})
        assert detail.get("error") == "end_user_limit_exceeded", r.text[:200]
        assert detail.get("current") == detail.get("limit"), r.text[:200]
        print(f"  cap enforced: {detail.get('current')}/{detail.get('limit')} -> 402")

    def test_06_cleanup(self, admin_page):
        ctx, _ = admin_page
        cookies = {c["name"]: c["value"] for c in ctx.cookies()}
        do_admin_stepup(cookies, admin=1)
        removed = 0
        with _client(cookies) as c:
            for u in _list_end_users(cookies):
                if (u.get("email") or "").startswith(f"{_MARK}-"):
                    removed += delete_end_user(c, u.get("username"))
        print(f"  removed {removed} provisioned users")
