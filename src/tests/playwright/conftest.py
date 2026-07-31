"""
Playwright test configuration for Yashigani admin UI.

Requires a running Yashigani stack. Tests skip if the stack is not reachable.
CA cert resolution follows the same pattern as src/tests/e2e/conftest.py.

Run with:
    YASHIGANI_ADMIN_URL=https://localhost:443 \\
    YASHIGANI_CA_CERT=docker/secrets/ca_root.crt \\
    pytest src/tests/playwright/ -v --timeout=60

Last updated: 2026-07-29 (YTF consolidation: kept at src/tests/playwright/ —
see YTF.md canonical-name-vs-physical-path note (root tests/ and src/tests/
are two same-named "tests" packages; moving playwright to root tests/
would break its absolute "from tests.playwright.conftest import ..." import
in test_webui_conformance_full.py). v2.23.3: fix parents[4]->[3] path bug;
add TOTP helpers; F9: admin TOTP corrected to HMAC-SHA-512/8-digit)
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Optional

import pytest


# ---------------------------------------------------------------------------
# Domain-routed target support (added 2026-07-30, Ava, Tier-B leg
# v412-ytf-podman-13033ff9): Caddy in this deployment routes by vhost
# (e.g. https://yashigani.local:8443), and a bare-IP/bare-"localhost" Host
# falls through to a default/catch-all 200 (see YTF status.md "Health gate"
# finding) -- a false-green trap. The correct fix is DNS-level: keep the
# Host header / TLS SNI as the real domain, only change *where* it resolves.
# On a locked-down runner without sudo (no /etc/hosts edit permitted --
# feedback_mac_max_no_sudo.md), this must happen in-process:
#   - httpx/urllib3 (used by conftest's own health probes + API-plane
#     assertions in the test files) resolve via socket.getaddrinfo --
#     patched below, scoped to the exact YASHIGANI_TEST_DOMAIN hostname only.
#   - Chromium is a separate process and does its own DNS resolution;
#     it is NOT affected by the getaddrinfo patch. It needs the equivalent
#     --host-resolver-rules launch flag, which is why every browser launch
#     in this suite should go through launch_chromium() below instead of
#     calling pw.chromium.launch() directly.
# Both mechanisms are additive/reversible test-harness config -- no system
# file is touched, no other hostname's resolution is altered.
# ---------------------------------------------------------------------------

YTF_TEST_DOMAIN = os.getenv("YASHIGANI_TEST_DOMAIN", "yashigani.local")
YTF_TEST_TARGET_IP = os.getenv("YASHIGANI_TEST_TARGET_IP", "127.0.0.1")

_real_getaddrinfo = socket.getaddrinfo


def _patched_getaddrinfo(host, *args, **kwargs):
    if host == YTF_TEST_DOMAIN:
        host = YTF_TEST_TARGET_IP
    return _real_getaddrinfo(host, *args, **kwargs)


socket.getaddrinfo = _patched_getaddrinfo  # process-scoped, single hostname only

# Chromium launch args: force DNS for YTF_TEST_DOMAIN to YTF_TEST_TARGET_IP
# while leaving the Host header / TLS SNI as the original domain, so Caddy's
# vhost routing sees the real hostname (this is what --resolve does for curl;
# --host-resolver-rules is the Chromium-native equivalent).
YTF_CHROMIUM_ARGS = [f"--host-resolver-rules=MAP {YTF_TEST_DOMAIN} {YTF_TEST_TARGET_IP}"]

# Headed/headless mode: run-test-framework.sh's --browser-mode flag maps here
# via YTF_HEADED=1 (see scripts/run-test-framework.sh Tier-B leg). Prior code
# hardcoded headless=True in every fixture across all 8 playwright test files
# -- "headed" mode never actually executed a headed browser regardless of any
# CLI flag. Fixed 2026-07-30 (Ava): every chromium.launch() call site now
# goes through launch_chromium() below.
YTF_HEADLESS = os.getenv("YTF_HEADED", "0") != "1"


def launch_chromium(pw_or_playwright):
    """Shared Chromium launcher for every Tier-B test file. Honors YTF_HEADED
    (headed/headless parity) and always injects --host-resolver-rules so
    tests can target a domain-routed Caddy vhost without a privileged
    /etc/hosts edit. Use this instead of calling `pw.chromium.launch()`
    directly."""
    return pw_or_playwright.chromium.launch(headless=YTF_HEADLESS, args=YTF_CHROMIUM_ARGS)


# ---------------------------------------------------------------------------
# CA cert resolution (mirrors e2e/conftest.py Pattern A)
# ---------------------------------------------------------------------------


def _resolve_ca_cert() -> Optional[str]:
    """Return a CA cert path to verify httpx TLS connections against, or None
    to mean "don't attempt cert-chain verification" (verify=False, mirroring
    the already-accepted-risk posture every Playwright/Chromium test in this
    suite takes via new_context(ignore_https_errors=True) for local test
    traffic -- see test_backup_ui.py._tls_args docstring).

    FIXED 2026-07-30 (Ava, Tier-B leg v412-ytf-podman-13033ff9): this
    previously auto-discovered docker/secrets/ca_root.crt unconditionally.
    For a `--tls-mode selfsigned` install (this deployment), Caddy's public
    HTTPS listener presents a cert chain issued by Caddy's OWN internal local
    CA ("Caddy Local Authority - ECC Intermediate"), NOT ca_root.crt (which is
    "Yashigani Internal Root CA" -- a distinct CA used elsewhere, e.g.
    mTLS/document-signing). Verified directly:
      openssl s_client -connect 127.0.0.1:8443 -servername yashigani.local \\
        -CAfile docker/secrets/ca_root.crt
      -> Verify return code: 20 (unable to get local issuer certificate)
    Auto-trusting ca_root.crt for the public listener therefore ALWAYS fails
    verification on a selfsigned-mode deployment (this caused ~322
    CERTIFICATE_VERIFY_FAILED / TLS-handshake failures across the httpx-based
    portion of this suite, unrelated to any product defect or DNS/host-resolver
    change). Only use an explicit CA when the caller KNOWS it matches (e.g. a
    `--tls-mode ca` deployment with a real issued cert) via YASHIGANI_CA_CERT.
    """
    explicit = os.getenv("YASHIGANI_CA_CERT")
    if explicit:
        return explicit
    return None


_CA_CERT_PATH: str | None = _resolve_ca_cert()


# ---------------------------------------------------------------------------
# Base URL resolution
# ---------------------------------------------------------------------------


def _resolve_base_url() -> str:
    override = os.getenv("YASHIGANI_ADMIN_URL")
    if override:
        return override.rstrip("/")
    # Prefer HTTPS; fall back to common installer ports
    candidates = [
        "https://localhost:8443",
        "https://localhost",
        "http://localhost:8080",
    ]
    try:
        import httpx

        for url in candidates:
            verify: bool | str = (_CA_CERT_PATH or False) if url.startswith("https://") else False  # type: ignore[assignment]
            try:
                r = httpx.get(f"{url}/healthz", verify=verify, timeout=3)
                if r.status_code == 200:
                    return url
            except Exception:
                continue
    except ImportError:
        pass
    return "https://localhost:8443"


BASE_URL: str = _resolve_base_url()
ADMIN_LOGIN_URL: str = f"{BASE_URL}/admin/login"


# ---------------------------------------------------------------------------
# Stack-running check
# ---------------------------------------------------------------------------


def _stack_running() -> bool:
    try:
        import httpx
    except ImportError:
        return False
    candidates = [
        BASE_URL + "/healthz",
        "https://localhost/healthz",
        "https://localhost:8443/healthz",
        "http://localhost:8080/healthz",
    ]
    for url in candidates:
        try:
            verify: bool | str = (_CA_CERT_PATH or False) if url.startswith("https://") else False  # type: ignore[assignment]
            r = httpx.get(url, verify=verify, timeout=3)
            if r.status_code == 200:
                return True
        except Exception:
            continue
    return False


STACK_RUNNING: bool = _stack_running()

_SKIP_NO_STACK = pytest.mark.skipif(
    not STACK_RUNNING,
    reason="Yashigani stack not running — start with docker/podman compose up",
)


# ---------------------------------------------------------------------------
# Admin credential helpers
# ---------------------------------------------------------------------------


def _read_secret(name: str) -> str:
    """Read a secret from docker/secrets/. Raises FileNotFoundError if absent."""
    # __file__ = .../yashigani/src/tests/playwright/conftest.py
    # parents[3] = .../yashigani (repo root)
    repo_root = Path(__file__).parents[3]
    p = repo_root / "docker" / "secrets" / name
    return p.read_text(encoding="utf-8").strip()


def get_admin_credentials() -> tuple[str, str]:
    """Return (username, current_password) for admin1.

    Prefers the in-process rotated password (_rotated_admin_password, set once
    this suite has actually completed the forced-password-change step this
    run) over the on-disk admin1_password secret, which stays stale for the
    lifetime of the run since nothing writes rotations back to disk. Falls
    back to admin_initial_password if admin1_password doesn't exist either
    (not yet rotated by anything, on-disk or in-process).
    """
    username = _read_secret("admin1_username")
    password = _current_admin_password(1)
    return username, password


def get_admin_totp_code() -> str:
    """Return a current HMAC-SHA-512/8-digit TOTP code for admin1.

    CORRECTED 2026-07-29 (v4.1.2 conformance suite, webui-findings.md F9):
    the server does NOT use pyotp's RFC 6238 default (HMAC-SHA1/6-digit).
    src/yashigani/auth/totp.py (Phase 13, role-tiered TOTP) implements its
    own RFC 4226/6238 logic and assigns admin accounts HMAC-SHA-512/8-digit
    (TOTP_ALGO_SHA512 / TOTP_DIGITS_ADMIN). The previous plain
    pyotp.TOTP(secret).now() call generated a SHA-1/6-digit code that would
    NOT match a freshly-bootstrapped 4.1.2 admin account (Phase 13 is the
    baseline, not an in-progress migration) — this was a live bug in the
    shared Playwright login helper, not a documentation typo.
    """
    import hashlib

    import pyotp

    secret = _read_secret("admin1_totp_secret")
    return pyotp.TOTP(secret, digits=8, digest=hashlib.sha512).now()


def get_admin2_totp_code() -> str:
    """Return a current HMAC-SHA-512/8-digit TOTP code for admin2. See
    get_admin_totp_code() docstring — same F9 correction applies."""
    import hashlib

    import pyotp

    secret = _read_secret("admin2_totp_secret")
    return pyotp.TOTP(secret, digits=8, digest=hashlib.sha512).now()


_session_cookie_cache: "dict[int, dict]" = {}  # admin_number → cookies
_api_totp_last_used: "dict[int, float]" = {}  # admin_number → time.time() of last API login

# QA-fix (Ava, 2026-07-31, Tier-B v412 fresh-bootstrap smoke): on a genuinely
# fresh stack (admin creds still INITIAL, force_password_change=True on first
# login) BOTH playwright_login_admin() and the (now-removed) local duplicates
# in test_v2233_login_redirect.py / test_backup_ui.py handled the forced
# password-change step by generating a random new password and submitting it
# -- but NEVER persisted that new password anywhere. get_admin_credentials()
# (and every helper's own admin2 resolution) kept reading the stale value
# from docker/secrets/, so the FIRST admin-dependent test to run would rotate
# the live password out from under every other test in the same pytest
# invocation, which would then fail with invalid_credentials. This process-
# lifetime cache is the single source of truth for "what is admin{N}'s
# CURRENT password right now" once this suite has rotated it; every login
# helper below reads/writes through it instead of re-reading the stale
# on-disk secret after first rotation.
_rotated_admin_password: "dict[int, str]" = {}


def _current_admin_password(admin: int = 1) -> str:
    """Return admin{N}'s current password: the in-process rotated value if
    this suite has already rotated it this run, else the on-disk secret."""
    if admin in _rotated_admin_password:
        return _rotated_admin_password[admin]
    if admin == 1:
        try:
            return _read_secret("admin1_password")
        except FileNotFoundError:
            return _read_secret("admin_initial_password")
    try:
        return _read_secret(f"admin{admin}_password")
    except FileNotFoundError:
        return _read_secret("admin_initial_password")


def _generate_strong_password() -> str:
    import secrets as _secrets
    import string as _string

    return "".join(
        _secrets.choice(_string.ascii_letters + _string.digits + "!*-._~,")
        for _ in range(42)
    )


def clear_auth_throttle() -> int:
    """Delete per-IP and global auth throttle/fail keys from Redis.

    Returns the number of keys deleted. No-ops gracefully if Redis is
    unreachable (tests can still run, throttle just won't be reset).

    Last updated: 2026-05-09 (v2.23.3: new helper)
    """
    import subprocess

    try:
        # Read Redis password from the backoffice container's secret
        pw_result = subprocess.run(
            ["docker", "exec", "docker-redis-1", "cat", "/run/secrets/redis_password"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if pw_result.returncode != 0:
            return 0
        redis_pw = pw_result.stdout.strip()

        del_result = subprocess.run(
            [
                "docker",
                "exec",
                "docker-redis-1",
                "redis-cli",
                "-p",
                "6380",
                "--tls",
                "--cert",
                "/run/secrets/redis_client.crt",
                "--key",
                "/run/secrets/redis_client.key",
                "--cacert",
                "/run/secrets/ca_root.crt",
                "--user",
                "default",
                "--pass",
                redis_pw,
                "-n",
                "1",
                "DEL",
                "auth:fail:global",
                "auth:fail:ip:172.23.0.2",
                "auth:throttle:global",
                "auth:throttle:ip:172.23.0.2",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (
            del_result.stdout.strip()
            .replace(
                "Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.", ""
            )
            .strip()
        )
        return int(output) if output.isdigit() else 0
    except Exception:
        return 0


def _api_get_session_cookies(*, admin: int = 1, force_fresh: bool = False) -> dict:
    """
    Obtain session cookies via the httpx API client (not the browser).

    Waits for a fresh TOTP time-step if the current code is within 2s of a
    window boundary to avoid replay collisions between tests.

    Returns a dict of {cookie_name: cookie_value} for injection into Playwright
    browser contexts.

    Caches the result per admin number to avoid multiple TOTP uses in the
    same test session. Use force_fresh=True to bypass the cache.

    Last updated: 2026-05-09 (v2.23.3: new helper for cookie injection; add cache)
    """
    global _session_cookie_cache
    if not force_fresh and admin in _session_cookie_cache:
        return _session_cookie_cache[admin]

    import hashlib
    import time

    import httpx
    import pyotp

    if admin == 1:
        username = _read_secret("admin1_username")
        totp_secret = _read_secret("admin1_totp_secret")
    else:
        username = _read_secret("admin2_username")
        totp_secret = _read_secret("admin2_totp_secret")
    password = _current_admin_password(admin)

    # F9 correction (2026-07-29): admin tier is HMAC-SHA-512/8-digit
    # (src/yashigani/auth/totp.py TOTP_ALGO_SHA512/TOTP_DIGITS_ADMIN), not
    # pyotp's RFC 6238 default (SHA-1/6-digit). See get_admin_totp_code().
    totp_obj = pyotp.TOTP(totp_secret, digits=8, digest=hashlib.sha512)

    def _wait_for_fresh_code() -> str:
        last = _api_totp_last_used.get(admin, 0.0)
        now = time.time()
        elapsed = now - last
        if elapsed < 62:
            wait_for_replay = 62 - elapsed
            secs_into = now % 30
            wait_for_window = (30 - secs_into + 2) if secs_into >= 27 else 0
            time.sleep(max(wait_for_replay, wait_for_window))
        else:
            secs_into = time.time() % 30
            if secs_into >= 27:
                time.sleep(32 - secs_into)
        code = totp_obj.now()
        _api_totp_last_used[admin] = time.time()
        return code

    # Wait at least 62s since the last TOTP use for this admin to avoid replay.
    # Also wait until we're in the first 27s of a 30s window.
    totp_code = _wait_for_fresh_code()
    verify: "bool | str" = _CA_CERT_PATH if _CA_CERT_PATH else False

    with httpx.Client(verify=verify, follow_redirects=False, timeout=10) as c:
        r = c.post(
            f"{BASE_URL}/auth/login",
            json={
                "username": username,
                "password": password,
                "totp_code": totp_code,
            },
        )
        assert r.status_code == 200, f"API login failed for admin{admin}: {r.status_code} {r.text[:200]}"
        data = r.json()

        # QA-fix (Ava, 2026-07-31): self-heal the forced-password-change step
        # instead of hard-asserting it already happened. On a genuinely fresh
        # stack (this Tier-B smoke: admin creds still INITIAL) this branch is
        # the FIRST and ONLY place the rotation actually happens; the result
        # is cached in _rotated_admin_password so every other helper
        # (get_admin_credentials, playwright_login_admin, this function
        # itself on a later call) sees the rotated password for the rest of
        # this pytest process.
        if data.get("force_password_change"):
            new_password = _generate_strong_password()
            change_r = c.post(
                f"{BASE_URL}/auth/password/change",
                json={"current_password": password, "new_password": new_password},
            )
            assert change_r.status_code == 200, (
                f"admin{admin} forced password-change failed: "
                f"{change_r.status_code} {change_r.text[:200]}"
            )
            _rotated_admin_password[admin] = new_password
            # Log out the restricted (password-change-required) session, then
            # re-login fresh with the rotated password to get a full session
            # and prove the rotation stuck (A2 step 4/5).
            c.post(f"{BASE_URL}/auth/logout")
            totp_code2 = _wait_for_fresh_code()
            r = c.post(
                f"{BASE_URL}/auth/login",
                json={
                    "username": username,
                    "password": new_password,
                    "totp_code": totp_code2,
                },
            )
            assert r.status_code == 200, (
                f"admin{admin} re-login after rotation failed: {r.status_code} {r.text[:200]}"
            )
            data = r.json()
            assert not data.get("force_password_change"), (
                f"admin{admin} still force_password_change=True after rotation — rotation did not stick"
            )

        result = dict(r.cookies)
    _session_cookie_cache[admin] = result
    return result


def playwright_login_admin(page, *, admin: int = 1) -> None:
    """
    Full Playwright login for admin1 (or admin2 if admin=2).

    Fills the login form with the admin's credentials and HMAC-SHA1 TOTP code.
    Waits for a fresh TOTP window if one was used recently (within 62s) to
    prevent TOTP replay rejection across multiple Playwright tests.

    After login, navigates to /admin/. BUG-LOGIN-REDIRECT-01 was fixed in
    v2.23.3: `(next && safeNext(next)) || '/admin/'` at the call site means
    login without a ?next= param now correctly lands on /admin/ directly.
    The direct navigate below is retained as a belt-and-braces guard in case
    of Playwright timing on the fetch() completion.

    Raises AssertionError if admin dashboard is not reached.

    Last updated: 2026-07-29 (F9: admin TOTP corrected to HMAC-SHA-512/8-digit;
    previously v2.23.3: BUG-LOGIN-REDIRECT-01 fixed)
    """
    import hashlib
    import time

    import pyotp

    if admin == 1:
        username = _read_secret("admin1_username")
        totp_secret = _read_secret("admin1_totp_secret")
    else:
        username = _read_secret("admin2_username")
        totp_secret = _read_secret("admin2_totp_secret")
    password = _current_admin_password(admin)

    # F9 correction (2026-07-29): admin tier is HMAC-SHA-512/8-digit, not
    # pyotp's RFC 6238 default. See get_admin_totp_code() docstring.
    totp_obj = pyotp.TOTP(totp_secret, digits=8, digest=hashlib.sha512)

    # Wait for a fresh TOTP window if we used a code for this admin recently.
    # Server TTL for used codes is 60s. We wait until at least 62s have passed
    # since the last login for this admin to guarantee a fresh code.
    # Shares _api_totp_last_used with _api_get_session_cookies.
    last = _api_totp_last_used.get(admin, 0.0)
    now = time.time()
    elapsed = now - last
    if elapsed < 62:
        wait = 62 - elapsed
        secs_into = now % 30
        window_wait = (30 - secs_into + 2) if secs_into >= 25 else 0
        wait = max(wait, window_wait)
        time.sleep(wait)
    else:
        secs_into = time.time() % 30
        if secs_into >= 27:
            time.sleep(32 - secs_into)

    totp_code = totp_obj.now()
    _api_totp_last_used[admin] = time.time()

    page.goto(f"{BASE_URL}/admin/login")
    page.fill("#username", username)
    page.fill("#password", password)
    page.fill("#totp_code", totp_code)
    page.click("button[type='submit'], #login-btn")
    page.wait_for_timeout(3000)  # wait for fetch() to complete

    # Handle forced password change if still needed
    if page.locator("#pw-form").is_visible():
        new_pw = _generate_strong_password()
        page.fill("#new_password", new_pw)
        page.fill("#confirm_password", new_pw)
        # QA-fix (Ava, 2026-07-31): the real submit button is id="pw-btn"
        # (src/yashigani/backoffice/templates/login.html:47). The old
        # selector "#pw-change-btn, button[type='submit']" referenced a
        # nonexistent ID and silently fell back to the ambiguous group
        # selector, which also matches the original (now-hidden but still
        # in the DOM) #login-btn — Playwright resolves to that hidden match
        # first and times out. Also: the randomly-generated new_pw was
        # NEVER persisted anywhere, so every OTHER helper/test reading
        # admin{N}'s password from docker/secrets/ would immediately start
        # failing with invalid_credentials once this branch fired. Now
        # cached in _rotated_admin_password so get_admin_credentials() /
        # _api_get_session_cookies() / this function's own next call all
        # see the current password for the rest of this pytest process.
        page.click("#pw-btn")
        page.wait_for_timeout(2000)
        _rotated_admin_password[admin] = new_pw

    # Belt-and-braces: if login didn't redirect to /admin/ (e.g. timing), navigate directly.
    if "/admin/" not in page.url or "login" in page.url:
        page.goto(f"{BASE_URL}/admin/")
        page.wait_for_timeout(3000)

    # Confirm admin dashboard elements are present.
    # FIXED 2026-07-30 (Ava, Tier-B leg v412-ytf-podman-13033ff9): the previous
    # selector ("#page-dashboard, #nav-links, #health-cards") targeted the
    # LEGACY 3.0-era dashboard.html template (backoffice/templates/dashboard.html).
    # The currently-served /admin/ app is ui4 (backoffice/static/ui4/admin/admin.html
    # -- root custom element <ys-admin-app>, module nav rendered as
    # `a[href='#module-id']` per module-registry.js / admin-nav.js), which never
    # renders those legacy IDs. This caused EVERY test depending on this shared
    # login helper to fail immediately after an otherwise-successful login
    # (confirmed: the server-side session was valid -- see the module's own
    # test_nav_entry_present using `a[href='#{module_id}']`, and the direct
    # curl-based 5-step bootstrap evidence in tier-b-ava/step5_relogin_final.json
    # -- this was a stale test-helper assertion, not a product defect).
    assert "/admin/login" not in page.url, (
        f"Still on login page after admin{admin} login — URL: {page.url}\n"
        "Possible: TOTP replay, wrong credentials, throttle."
    )
    assert page.locator("ys-admin-app, a[href^='#']").count() > 0, (
        f"Admin app shell not found — URL: {page.url}"
    )


# ---------------------------------------------------------------------------
# User-tier session helpers (v4.1.2 conformance suite — webui-inventory.md)
#
# Unlike admin1/admin2, no user-tier account is seeded at install time.
# `bootstrap_user_session()` provisions a throwaway user via the admin API
# (POST /admin/users, StepUpAdminSession-gated), then drives the full
# 5-step first-login flow: initial password → forced password change →
# TOTP provision start/confirm → logout → re-login with rotated creds.
# Mirrors the admin bootstrap discipline (retro v2.23.1 §6.C / A2) but for
# the user plane, which has no pre-provisioned secrets file to read.
#
# User-tier TOTP is SHA-256/6-digit (routes/users.py: TOTP_ALGO_SHA256,
# TOTP_DIGITS_USER) — distinct from admin's SHA-512/8-digit. pyotp needs an
# explicit digest= kwarg for this; admin helpers above rely on pyotp's
# HMAC-SHA1 default, which is WRONG for both tiers in production but is a
# separate, already-tracked pin (project_totp_uses_sha256_not_sha1.md) —
# not re-litigated here. This helper uses SHA-256/6-digit unconditionally
# for user accounts, matching the server-side constant.
# ---------------------------------------------------------------------------

import hashlib as _hashlib
import time as _time
import uuid as _uuid

_user_session_cache: "dict[str, dict]" = {}  # cache key -> cookies dict


def _admin_headers(admin: int = 1) -> dict:
    return {"X-Yashigani-Plane": "admin"}


def bootstrap_user_session(*, cache_key: str = "default", force_fresh: bool = False) -> dict:
    """
    Provision a throwaway user-tier account and complete the full 5-step
    first-login bootstrap. Returns a dict:
      {
        "username": str, "email": str,
        "password": str,          # ROTATED password (post force-change)
        "totp_secret": str,       # base32 secret, SHA-256/6-digit
        "cookies": dict,          # __Host-yashigani_session cookies, post-rotation login
      }

    Requires an admin1 session (uses _api_get_session_cookies(admin=1) plus a
    fresh /auth/stepup call — POST /admin/users is StepUpAdminSession-gated).

    Cached per cache_key for the pytest session so multiple test modules can
    share one throwaway user without re-provisioning (and without exhausting
    the 62s TOTP replay window on every test file). Use force_fresh=True for
    tests that need an ISOLATED user (e.g. BOLA cross-user probes need TWO
    distinct users — call with two different cache_key values).
    """
    global _user_session_cache
    if not force_fresh and cache_key in _user_session_cache:
        return _user_session_cache[cache_key]

    import httpx
    import pyotp

    verify: "bool | str" = _CA_CERT_PATH if _CA_CERT_PATH else False
    admin_cookies = _api_get_session_cookies(admin=1)

    # Fresh TOTP window for the /auth/stepup call required by StepUpAdminSession.
    _wait_for_fresh_totp_window(admin=1)
    admin_totp_secret = _read_secret("admin1_totp_secret")
    stepup_code = pyotp.TOTP(admin_totp_secret, digits=8, digest=_hashlib.sha512).now()
    _api_totp_last_used[1] = _time.time()

    unique = _uuid.uuid4().hex[:10]
    # FIXED 2026-07-30 (Ava, Tier-B leg v412-ytf-podman-13033ff9): the server's
    # email validator (email-validator, syntax-only / check_deliverability=False)
    # rejects the ".invalid" TLD outright as an RFC 2606 special-use reserved
    # name ("value is not a valid email address ... special-use or reserved
    # name") -- confirmed directly:
    #   python3 -c "from email_validator import validate_email;
    #     validate_email('a@example.invalid', check_deliverability=False)"
    #   -> EmailNotValidError. The SAME check accepts 'example.com' (also
    # RFC 2606-reserved, but not on email-validator's syntax-reject list) --
    # matches the domain already used by other test suites (test_user_
    # documents_gaps_3_4_5.py, test_per_user_ratelimit.py, etc). This was
    # blocking every bootstrap_user_session() caller (BOLA probes, documents/
    # sensitivity/chat user-plane tests) with a 422, not a product defect.
    email = f"ava-conf-{unique}@example.com"

    with httpx.Client(verify=verify, cookies=admin_cookies, follow_redirects=False, timeout=10) as c:
        stepup_resp = c.post(f"{BASE_URL}/auth/stepup", json={"totp_code": stepup_code})
        assert stepup_resp.status_code == 200, (
            f"stepup failed: {stepup_resp.status_code} {stepup_resp.text[:200]}"
        )

        create_resp = c.post(f"{BASE_URL}/admin/users", json={"email": email})
        assert create_resp.status_code == 200, (
            f"POST /admin/users failed: {create_resp.status_code} {create_resp.text[:300]}"
        )
        created = create_resp.json()

    username = created["username"]
    temp_password = created["temporary_password"]
    totp_secret = created["totp_secret"]
    totp = pyotp.TOTP(totp_secret, digits=6, digest=_hashlib.sha256)

    # Wait for a fresh 30s window before the first user-tier TOTP use.
    secs_into = _time.time() % 30
    if secs_into >= 27:
        _time.sleep(32 - secs_into)

    new_password = "".join(
        __import__("secrets").choice(__import__("string").ascii_letters + __import__("string").digits + "!*-._~,")
        for _ in range(40)
    )

    first_totp_code = totp.now()
    _first_totp_used_at = _time.time()
    with httpx.Client(verify=verify, follow_redirects=False, timeout=10) as c:
        # Step 1: initial login with temp password -> force_password_change:true
        login_resp = c.post(
            f"{BASE_URL}/auth/login",
            json={"username": username, "password": temp_password, "totp_code": first_totp_code},
        )
        assert login_resp.status_code == 200, (
            f"initial user login failed: {login_resp.status_code} {login_resp.text[:300]}"
        )
        login_data = login_resp.json()
        first_login_cookies = dict(login_resp.cookies)
        assert login_data.get("force_password_change") is True, (
            "expected force_password_change=True on first user login "
            f"(got {login_data})"
        )

        # Step 2: forced password change.
        c.cookies.update(first_login_cookies)
        pw_resp = c.post(
            f"{BASE_URL}/auth/password/change",
            json={"current_password": temp_password, "new_password": new_password},
        )
        assert pw_resp.status_code == 200, (
            f"user password change failed: {pw_resp.status_code} {pw_resp.text[:300]}"
        )

    # FIXED 2026-07-30 (Ava, Tier-B leg v412-ytf-podman-13033ff9): this
    # previously only aligned to a 30s window BOUNDARY (secs_into >= 25/27 ->
    # sleep to the next window), which does NOT guarantee the user-tier 60s
    # TOTP replay cache has expired since first_totp_code was used above --
    # if step 2 (password change) completes quickly, totp.now() below can
    # return the IDENTICAL code value as step 1, and the server correctly
    # rejects it as a replay (surfaced as generic "invalid_credentials" for
    # anti-enumeration, not an obviously-TOTP-shaped error). Confirmed live:
    # this crashed "user re-login after password rotation failed: 401
    # invalid_credentials" while testing the chat/PII byte-proof. Now
    # explicitly waits until >=62s have elapsed since first_totp_code was
    # used (mirrors _wait_for_fresh_totp_window's admin-tier logic), THEN
    # additionally avoids the last few seconds of whatever window that lands
    # in, guaranteeing a genuinely fresh, never-before-submitted code.
    _elapsed = _time.time() - _first_totp_used_at
    if _elapsed < 62:
        _time.sleep(62 - _elapsed)
    secs_into = _time.time() % 30
    if secs_into >= 25:
        _time.sleep(32 - secs_into)

    with httpx.Client(verify=verify, follow_redirects=False, timeout=10) as c:
        # Step 3/4: re-login with rotated password, proves rotation stuck (A2 step 5
        # -- here folded in since TOTP was already provisioned server-side at
        # POST /admin/users time; there is no separate provision/start+confirm
        # round-trip for admin-created user accounts, unlike self-service TOTP
        # provisioning. The re-login IS the "prove rotation stuck" step.)
        relogin_resp = c.post(
            f"{BASE_URL}/auth/login",
            json={"username": username, "password": new_password, "totp_code": totp.now()},
        )
        assert relogin_resp.status_code == 200, (
            f"user re-login after password rotation failed: "
            f"{relogin_resp.status_code} {relogin_resp.text[:300]}"
        )
        relogin_data = relogin_resp.json()
        assert not relogin_data.get("force_password_change"), (
            "user still force_password_change=True after completing the change flow"
        )
        final_cookies = dict(relogin_resp.cookies)

    result = {
        "username": username,
        "email": email,
        "password": new_password,
        "totp_secret": totp_secret,
        "cookies": final_cookies,
    }
    _user_session_cache[cache_key] = result
    return result


def _wait_for_fresh_totp_window(*, admin: int = 1) -> None:
    """Block until at least 62s have passed since the last TOTP use for this
    admin AND we're in the first ~27s of a 30s window. Shared replay-avoidance
    logic factored out of _api_get_session_cookies/playwright_login_admin."""
    last = _api_totp_last_used.get(admin, 0.0)
    now = _time.time()
    elapsed = now - last
    if elapsed < 62:
        wait_for_replay = 62 - elapsed
        secs_into = now % 30
        wait_for_window = (30 - secs_into + 2) if secs_into >= 27 else 0
        _time.sleep(max(wait_for_replay, wait_for_window))
    else:
        secs_into = _time.time() % 30
        if secs_into >= 27:
            _time.sleep(32 - secs_into)


def playwright_login_user(page, *, cache_key: str = "default", force_fresh: bool = False) -> dict:
    """
    Full Playwright login for a throwaway user-tier account, provisioned via
    bootstrap_user_session(). Injects the rotated-session cookie into the
    Playwright browser context (faster + avoids a second TOTP round-trip vs.
    driving the login form again) then navigates to /chat to confirm.

    Returns the same dict as bootstrap_user_session().
    """
    creds = bootstrap_user_session(cache_key=cache_key, force_fresh=force_fresh)
    page.context.add_cookies([
        {
            "name": name,
            "value": value,
            "domain": BASE_URL.split("://", 1)[-1].split(":")[0],
            "path": "/",
            "secure": BASE_URL.startswith("https://"),
        }
        for name, value in creds["cookies"].items()
    ])
    page.goto(f"{BASE_URL}/chat")
    page.wait_for_timeout(1500)
    assert "/login" not in page.url, (
        f"user session cookie injection did not authenticate — URL: {page.url}"
    )
    return creds


# ---------------------------------------------------------------------------
# pytest_configure — register markers
# ---------------------------------------------------------------------------


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "playwright_ui: marks Playwright browser-based tests",
    )
    config.addinivalue_line(
        "markers",
        "api_contract: marks HTTP-level API contract tests (no browser)",
    )
    config.addinivalue_line(
        "markers",
        "security_probe: marks adversarial / purple-team security tests",
    )


# ---------------------------------------------------------------------------
# pytest_collection_modifyitems — auto-skip when stack not running
# ---------------------------------------------------------------------------


def pytest_collection_modifyitems(config, items):
    if not STACK_RUNNING:
        skip = pytest.mark.skip(reason="Yashigani stack not running — start with docker/podman compose up")
        for item in items:
            if "playwright" in str(item.fspath):
                item.add_marker(skip)
