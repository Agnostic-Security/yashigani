"""
Playwright test configuration for Yashigani admin UI.

Requires a running Yashigani stack. Tests skip if the stack is not reachable.
CA cert resolution follows the same pattern as src/tests/e2e/conftest.py.

Run with:
    YASHIGANI_ADMIN_URL=https://localhost:443 \\
    YASHIGANI_CA_CERT=docker/secrets/ca_root.crt \\
    pytest src/tests/playwright/ -v --timeout=60

Last updated: 2026-05-09 (v2.23.3: fix parents[4]→[3] path bug; add TOTP helpers)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import pytest


# ---------------------------------------------------------------------------
# CA cert resolution (mirrors e2e/conftest.py Pattern A)
# ---------------------------------------------------------------------------


def _resolve_ca_cert() -> Optional[str]:
    explicit = os.getenv("YASHIGANI_CA_CERT")
    if explicit:
        return explicit
    candidates = [
        Path(__file__).parents[3] / "docker" / "secrets" / "ca_root.crt",
        Path("/run/secrets/ca_root.crt"),
    ]
    for p in candidates:
        if p.exists():
            return str(p)
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
            verify: bool | str = _CA_CERT_PATH if url.startswith("https://") else False  # type: ignore[assignment]
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
            verify: bool | str = _CA_CERT_PATH if url.startswith("https://") else False  # type: ignore[assignment]
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

    Prefers admin1_password (post-bootstrap rotated), falls back to
    admin_initial_password if admin1_password matches initial (not yet rotated).
    """
    username = _read_secret("admin1_username")
    # After the mandatory first-login password change, admin1_password holds the
    # rotated credential. admin_initial_password is the bootstrap value and may
    # still match admin1_password on a fresh install before rotation.
    try:
        password = _read_secret("admin1_password")
    except FileNotFoundError:
        password = _read_secret("admin_initial_password")
    return username, password


def get_admin_totp_code() -> str:
    """Return a current SHA-256 TOTP code for admin1.

    The server uses pyotp.TOTP(secret, digest=hashlib.sha256) — standard SHA-1
    TOTP will produce wrong codes. Uses ±1 window tolerance.
    """
    import hashlib
    import pyotp

    secret = _read_secret("admin1_totp_secret")
    return pyotp.TOTP(secret, digest=hashlib.sha256).now()


def get_admin2_totp_code() -> str:
    """Return a current SHA-256 TOTP code for admin2 (orchid)."""
    import hashlib
    import pyotp

    secret = _read_secret("admin2_totp_secret")
    return pyotp.TOTP(secret, digest=hashlib.sha256).now()


_session_cookie_cache: "dict[int, dict]" = {}  # admin_number → cookies
_api_totp_last_used: "dict[int, float]" = {}  # admin_number → time.time() of last API login


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
        username, password = get_admin_credentials()
        totp_secret = _read_secret("admin1_totp_secret")
    else:
        username = _read_secret("admin2_username")
        try:
            password = _read_secret("admin2_password")
        except FileNotFoundError:
            password = _read_secret("admin_initial_password")
        totp_secret = _read_secret("admin2_totp_secret")

    totp_obj = pyotp.TOTP(totp_secret, digest=hashlib.sha256)

    # Wait at least 62s since the last TOTP use for this admin to avoid replay.
    # Also wait until we're in the first 27s of a 30s window.
    last = _api_totp_last_used.get(admin, 0.0)
    now = time.time()
    elapsed = now - last
    if elapsed < 62:
        wait_for_replay = 62 - elapsed
        # Additionally align to a fresh window
        secs_into = now % 30
        wait_for_window = (30 - secs_into + 2) if secs_into >= 27 else 0
        wait = max(wait_for_replay, wait_for_window)
        time.sleep(wait)
    else:
        # Just make sure we're not at the window boundary
        secs_into = time.time() % 30
        if secs_into >= 27:
            time.sleep(32 - secs_into)

    totp_code = totp_obj.now()
    _api_totp_last_used[admin] = time.time()
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
    assert not data.get("force_password_change"), f"admin{admin}: force_password_change=True — complete bootstrap first"
    result = dict(r.cookies)
    _session_cookie_cache[admin] = result
    return result


def playwright_login_admin(page, *, admin: int = 1) -> None:
    """
    Full Playwright login for admin1 (or admin2 if admin=2).

    Fills the login form with the admin's credentials and SHA-256 TOTP code.
    Waits for a fresh TOTP window if one was used recently (within 62s) to
    prevent TOTP replay rejection across multiple Playwright tests.

    After login, navigates to /admin/. BUG-LOGIN-REDIRECT-01 was fixed in
    v2.23.3: `(next && safeNext(next)) || '/admin/'` at the call site means
    login without a ?next= param now correctly lands on /admin/ directly.
    The direct navigate below is retained as a belt-and-braces guard in case
    of Playwright timing on the fetch() completion.

    Raises AssertionError if admin dashboard is not reached.

    Last updated: 2026-05-09 (v2.23.3: BUG-LOGIN-REDIRECT-01 fixed)
    """
    import hashlib
    import time

    import pyotp

    if admin == 1:
        username, password = get_admin_credentials()
        totp_secret = _read_secret("admin1_totp_secret")
    else:
        username = _read_secret("admin2_username")
        try:
            password = _read_secret("admin2_password")
        except FileNotFoundError:
            password = _read_secret("admin_initial_password")
        totp_secret = _read_secret("admin2_totp_secret")

    totp_obj = pyotp.TOTP(totp_secret, digest=hashlib.sha256)

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
        import secrets as _secrets
        import string as _string

        new_pw = "".join(_secrets.choice(_string.ascii_letters + _string.digits + "!*-._~,") for _ in range(42))
        page.fill("#new_password", new_pw)
        page.fill("#confirm_password", new_pw)
        page.click("#pw-change-btn, button[type='submit']")
        page.wait_for_timeout(2000)

    # Belt-and-braces: if login didn't redirect to /admin/ (e.g. timing), navigate directly.
    if "/admin/" not in page.url or "login" in page.url:
        page.goto(f"{BASE_URL}/admin/")
        page.wait_for_timeout(3000)

    # Confirm admin dashboard elements are present
    assert "/admin/login" not in page.url, (
        f"Still on login page after admin{admin} login — URL: {page.url}\n"
        "Possible: TOTP replay, wrong credentials, throttle."
    )
    assert page.locator("#page-dashboard, #nav-links, #health-cards").count() > 0, (
        f"Admin dashboard elements not found — URL: {page.url}"
    )


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
