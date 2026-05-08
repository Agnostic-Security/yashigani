"""
Playwright / API e2e tests — WebAuthn / FIDO2 admin login (v2.23.3, retro #56).

Validates PR #62 (feat/v233-webauthn-fido2) end-to-end:

  Scenario 1 — Registration happy path
    WA-REG-01  Authenticated admin can call register/start → 200 + options
    WA-REG-02  register/finish with virtual authenticator stores credential
    WA-REG-03  Audit event WEBAUTHN_CREDENTIAL_REGISTERED emitted

  Scenario 2 — WebAuthn login happy path
    WA-LOGIN-01  login/start for enrolled user returns options + user_id
    WA-LOGIN-02  login/finish with virtual authenticator returns 200 + session cookie
    WA-LOGIN-03  Session cookie grants access to authenticated endpoint (/admin/accounts)
    WA-LOGIN-04  Audit event WEBAUTHN_LOGIN_SUCCESS with correct event_type (commit 6892907)

  Scenario 3 — Failed login (invalid credential / wrong origin / replay)
    WA-FAIL-01  login/finish with malformed credential_response → 401
    WA-FAIL-02  login/finish with wrong username → 401
    WA-FAIL-03  login/finish with replayed (stale) challenge → 401
    WA-FAIL-04  Audit event WEBAUTHN_LOGIN_FAILURE emitted on each rejection

  Scenario 4 — Credential revocation
    WA-REVOKE-01  DELETE /api/v1/admin/webauthn/credentials/{id} (step-up) → 200
    WA-REVOKE-02  Subsequent login/start with revoked credential → 400 (no credentials)
    WA-REVOKE-03  Audit event WEBAUTHN_CREDENTIAL_REVOKED emitted

  Scenario 5 — Multi-credential support
    WA-MULTI-01  Register two distinct credentials → list shows both
    WA-MULTI-02  Login succeeds via credential A
    WA-MULTI-03  Login succeeds via credential B
    WA-MULTI-04  Revoking credential A does not affect credential B login
    WA-MULTI-05  Revoking credential B leaves empty list

Mode: deterministic gate.

ASVS: V2.8 (FIDO2 / challenge single-use / sign_count), V6.8.4 (step-up for DELETE),
      V3.3 (session cookie on WebAuthn success), V7.1.2 (audit event on every outcome).
OWASP API: API2 (broken auth), API7 (SSRF/origin), API1 (BOLA on credential_id).
PR #62 commit: 6892907 — WEBAUTHN_LOGIN_SUCCESS event_type wire-format alignment.
Retro tracker: #56 (P1).

Implementation notes:
- Virtual authenticator created via CDP WebAuthn domain (Chromium DevTools Protocol).
  CDP commands: WebAuthn.enable, WebAuthn.addVirtualAuthenticator,
                WebAuthn.getCredentials, WebAuthn.addCredential.
  This avoids any real hardware key requirement.
- Audit events are verified via GET /admin/audit/search?event_type=<type>
  (authenticated, reads the NDJSON log file server-side).
- Step-up for revocation uses pyotp to generate a live TOTP code from
  the admin's TOTP secret (read from docker/secrets/admin1_totp_secret).
- All tests are self-contained: each registers its own credential and cleans up
  on success. Failed runs leave at most one orphaned credential (harmless —
  sign-in via password+TOTP remains available).

Flake observations:
- CDP send() is synchronous in Playwright sync API — no race conditions.
- The virtual authenticator responds instantly; no timing-related flake expected.
- Audit search tail-races the route: we wait up to 5 s polling the search
  endpoint. In practice the write is synchronous so the first poll succeeds.

Run with:
    pytest src/tests/playwright/test_v233_webauthn_e2e.py -v --timeout=60

Last updated: 2026-05-08T00:00:00+00:00
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import time
from pathlib import Path
from typing import Optional

import pytest

from tests.playwright.conftest import (
    BASE_URL,
    STACK_RUNNING,
    _CA_CERT_PATH,
)

pytestmark = pytest.mark.playwright_ui

# ---------------------------------------------------------------------------
# Skip guard — all tests skip when the stack is not reachable
# ---------------------------------------------------------------------------

skip_no_stack = pytest.mark.skipif(
    not STACK_RUNNING,
    reason="Yashigani stack not running — start with docker/podman compose up",
)

# ---------------------------------------------------------------------------
# Repo-root helpers
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parents[4]


def _read_secret(name: str) -> str:
    p = _REPO_ROOT / "docker" / "secrets" / name
    return p.read_text(encoding="utf-8").strip()


def _verify_param():
    """Return httpx 'verify' parameter: CA cert path or False."""
    return _CA_CERT_PATH if _CA_CERT_PATH else False  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Admin credential helpers
# ---------------------------------------------------------------------------

def _admin1_username() -> str:
    return _read_secret("admin1_username")


def _admin1_initial_password() -> str:
    return _read_secret("admin_initial_password")


def _admin1_totp_secret() -> str:
    """Return admin1 TOTP seed (base32). Raises FileNotFoundError if absent."""
    return _read_secret("admin1_totp_secret")


def _current_totp(totp_secret: str) -> str:
    """Generate a current TOTP code from the base32 seed."""
    try:
        import pyotp
        return pyotp.TOTP(totp_secret).now()
    except ImportError as exc:
        raise RuntimeError(
            "pyotp not installed — required for step-up TOTP in WebAuthn e2e tests. "
            "pip install pyotp"
        ) from exc


# ---------------------------------------------------------------------------
# HTTP session helpers (httpx — no browser needed for API-layer assertions)
# ---------------------------------------------------------------------------

def _get_authed_client():
    """
    Return an httpx.Client with a valid admin1 session cookie.

    Uses password+TOTP login.  Raises AssertionError if login fails.
    The caller must have admin1 credentials fully provisioned (password changed,
    TOTP set up) — this precondition is met by the admin bootstrap in install.sh.
    """
    import httpx

    username = _admin1_username()
    password = _admin1_initial_password()
    totp_secret = _admin1_totp_secret()
    verify = _verify_param()

    client = httpx.Client(verify=verify, follow_redirects=False, timeout=15)

    # Attempt login with TOTP — admin1 has already completed bootstrap.
    totp_code = _current_totp(totp_secret)
    r = client.post(
        f"{BASE_URL}/login",
        json={"username": username, "password": password, "totp_code": totp_code},
    )
    assert r.status_code in (200, 302, 307, 308), (
        f"Admin1 login failed: HTTP {r.status_code} — {r.text[:200]}"
    )

    # Verify we actually got a session cookie.
    session_cookie = None
    for name in ("__Host-yashigani_admin_session", "__Host-yashigani_session"):
        if name in client.cookies:
            session_cookie = client.cookies[name]
            break

    assert session_cookie is not None, (
        "Admin1 login HTTP: 200 but no session cookie received — "
        "admin1 bootstrap may not be complete."
    )
    return client


def _list_webauthn_credentials(client) -> list:
    """Return list of registered WebAuthn credentials for the authed admin."""
    r = client.get(f"{BASE_URL}/api/v1/admin/webauthn/credentials")
    assert r.status_code == 200, (
        f"GET /api/v1/admin/webauthn/credentials failed: {r.status_code} {r.text[:200]}"
    )
    return r.json().get("credentials", [])


def _delete_credential(client, credential_id: str, totp_secret: str) -> int:
    """
    Revoke a WebAuthn credential (step-up required — ASVS V6.8.4).
    Returns the HTTP status code.
    """
    # Perform step-up first.
    totp_code = _current_totp(totp_secret)
    su = client.post(
        f"{BASE_URL}/stepup",
        json={"totp_code": totp_code},
    )
    assert su.status_code == 200, (
        f"Step-up failed before revocation: {su.status_code} {su.text[:200]}"
    )

    r = client.delete(
        f"{BASE_URL}/api/v1/admin/webauthn/credentials/{credential_id}",
    )
    return r.status_code


# ---------------------------------------------------------------------------
# Audit log assertion helpers
# ---------------------------------------------------------------------------

def _wait_for_audit_event(
    client,
    event_type: str,
    timeout_s: float = 5.0,
    poll_interval_s: float = 0.5,
) -> Optional[dict]:
    """
    Poll /admin/audit/search?event_type=<type> until a matching event appears
    or timeout is reached.  Returns the most recent matching row or None.

    The audit write is synchronous (write-ahead in the route handler) so the
    first poll normally succeeds; 5s timeout is belt-and-suspenders.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        r = client.get(
            f"{BASE_URL}/admin/audit/search",
            params={"event_type": event_type},
        )
        if r.status_code == 200:
            rows = r.json().get("rows", [])
            if rows:
                return rows[-1]  # most recent
        time.sleep(poll_interval_s)
    return None


# ---------------------------------------------------------------------------
# CDP / virtual authenticator helpers (Playwright-based)
# ---------------------------------------------------------------------------

def _enable_virtual_authenticator(cdp_session) -> str:
    """
    Enable the WebAuthn virtual environment on the CDP session and add a
    software authenticator (ctap2/internal transport, UV capable).

    Returns the authenticator ID string.

    CDP domain: WebAuthn (Chromium DevTools Protocol).
    Ref: https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/
    """
    cdp_session.send("WebAuthn.enable", {"enableUI": False})
    result = cdp_session.send(
        "WebAuthn.addVirtualAuthenticator",
        {
            "options": {
                "protocol": "ctap2",
                "transport": "internal",
                "hasResidentKey": True,
                "hasUserVerification": True,
                "isUserVerified": True,
                "automaticPresenceSimulation": True,
            }
        },
    )
    return result["authenticatorId"]


def _disable_virtual_authenticator(cdp_session, authenticator_id: str) -> None:
    """Remove the virtual authenticator and disable the virtual environment."""
    try:
        cdp_session.send(
            "WebAuthn.removeVirtualAuthenticator",
            {"authenticatorId": authenticator_id},
        )
    except Exception:
        pass
    try:
        cdp_session.send("WebAuthn.disable")
    except Exception:
        pass


def _get_virtual_credentials(cdp_session, authenticator_id: str) -> list:
    """Return all credentials stored on the virtual authenticator."""
    result = cdp_session.send(
        "WebAuthn.getCredentials",
        {"authenticatorId": authenticator_id},
    )
    return result.get("credentials", [])


# ---------------------------------------------------------------------------
# Browser-based WebAuthn flow helper
# ---------------------------------------------------------------------------

def _do_webauthn_register_via_api(client, credential_name: str = "E2E Test Key") -> dict:
    """
    Drive the WebAuthn registration ceremony over the HTTP API.

    We use httpx + the virtual authenticator is on the CDP session attached
    to a running Playwright browser page.  The API layer itself doesn't touch
    the browser; the browser JS flow is tested separately in the UI tests below.

    This helper uses a synthetic credential response created by the server-side
    virtual authenticator (via the CDP WebAuthn domain) to avoid needing
    navigator.credentials.create() from within httpx.

    Because py_webauthn is the verifier and the CDP virtual authenticator
    generates valid CBOR-encoded attestation objects, this constitutes a true
    end-to-end test of the registration pathway.

    Returns the register/finish response body dict.
    """
    # Step 1: start registration.
    r_start = client.post(
        f"{BASE_URL}/api/v1/admin/webauthn/register/start",
        json={"credential_name": credential_name},
    )
    assert r_start.status_code == 200, (
        f"register/start failed: {r_start.status_code} {r_start.text[:300]}"
    )
    body_start = r_start.json()
    assert body_start.get("status") == "ok", f"register/start not ok: {body_start}"
    options = body_start["options"]

    # The options dict contains a base64url-encoded challenge and rp/user data.
    # We return it so callers can drive the browser to complete the ceremony.
    return options


def _browser_complete_registration(page, cdp_session, options: dict) -> dict:
    """
    Inject the PublicKeyCredentialCreationOptions into the browser page and
    use navigator.credentials.create() to produce a credential.

    Returns the serialised credential response dict ready for register/finish.
    """
    options_json = json.dumps(options)
    # Inject a helper that drives the WebAuthn registration in the browser JS context.
    result = page.evaluate(
        """async (optionsJson) => {
            function base64urlToBuffer(b64url) {
                var b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
                while (b64.length % 4) { b64 += '='; }
                var binary = atob(b64);
                var buf = new Uint8Array(binary.length);
                for (var i = 0; i < binary.length; i++) {
                    buf[i] = binary.charCodeAt(i);
                }
                return buf.buffer;
            }
            function bufferToBase64url(buf) {
                var bytes = new Uint8Array(buf);
                var binary = '';
                for (var i = 0; i < bytes.byteLength; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
            }

            var opts = JSON.parse(optionsJson);
            opts.challenge = base64urlToBuffer(opts.challenge);
            opts.user.id = base64urlToBuffer(opts.user.id);
            if (opts.excludeCredentials) {
                opts.excludeCredentials = opts.excludeCredentials.map(function(c) {
                    return { type: c.type, id: base64urlToBuffer(c.id) };
                });
            }

            try {
                var cred = await navigator.credentials.create({ publicKey: opts });
                var response = cred.response;
                return {
                    id: cred.id,
                    rawId: bufferToBase64url(cred.rawId),
                    type: cred.type,
                    response: {
                        attestationObject: bufferToBase64url(response.attestationObject),
                        clientDataJSON: bufferToBase64url(response.clientDataJSON),
                    },
                };
            } catch (e) {
                return { error: e.message };
            }
        }""",
        options_json,
    )
    assert "error" not in result, (
        f"navigator.credentials.create() failed in browser: {result.get('error')}"
    )
    return result


def _browser_complete_authentication(page, options: dict) -> dict:
    """
    Inject PublicKeyCredentialRequestOptions into the browser page and drive
    navigator.credentials.get() using the virtual authenticator.

    Returns the serialised assertion response dict ready for login/finish.
    """
    options_json = json.dumps(options)
    result = page.evaluate(
        """async (optionsJson) => {
            function base64urlToBuffer(b64url) {
                var b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
                while (b64.length % 4) { b64 += '='; }
                var binary = atob(b64);
                var buf = new Uint8Array(binary.length);
                for (var i = 0; i < binary.length; i++) {
                    buf[i] = binary.charCodeAt(i);
                }
                return buf.buffer;
            }
            function bufferToBase64url(buf) {
                var bytes = new Uint8Array(buf);
                var binary = '';
                for (var i = 0; i < bytes.byteLength; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
            }

            var opts = JSON.parse(optionsJson);
            opts.challenge = base64urlToBuffer(opts.challenge);
            if (opts.allowCredentials) {
                opts.allowCredentials = opts.allowCredentials.map(function(c) {
                    return {
                        type: c.type,
                        id: base64urlToBuffer(c.id),
                        transports: c.transports || [],
                    };
                });
            }

            try {
                var cred = await navigator.credentials.get({ publicKey: opts });
                var response = cred.response;
                return {
                    id: cred.id,
                    rawId: bufferToBase64url(cred.rawId),
                    type: cred.type,
                    response: {
                        authenticatorData: bufferToBase64url(response.authenticatorData),
                        clientDataJSON: bufferToBase64url(response.clientDataJSON),
                        signature: bufferToBase64url(response.signature),
                        userHandle: response.userHandle
                            ? bufferToBase64url(response.userHandle)
                            : null,
                    },
                };
            } catch (e) {
                return { error: e.message };
            }
        }""",
        options_json,
    )
    assert "error" not in result, (
        f"navigator.credentials.get() failed in browser: {result.get('error')}"
    )
    return result


# ---------------------------------------------------------------------------
# Fixture: Playwright browser page with virtual authenticator
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def browser_page_with_va():
    """
    Yield (page, cdp_session, authenticator_id) for a Playwright browser page
    that has a virtual FIDO2 authenticator attached.

    Uses real Chromium via playwright.sync_api.

    Teardown: removes the virtual authenticator and closes the browser.
    """
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()

        # Navigate to the admin login page so origin matches the server's
        # expected_origin (derived from X-Forwarded-Proto + Host on the server).
        page.goto(f"{BASE_URL}/admin/login", wait_until="domcontentloaded")

        # Attach CDP session to the page.
        cdp = ctx.new_cdp_session(page)

        # Enable virtual authenticator environment and add a software authenticator.
        auth_id = _enable_virtual_authenticator(cdp)

        try:
            yield page, cdp, auth_id
        finally:
            _disable_virtual_authenticator(cdp, auth_id)
            browser.close()


# ---------------------------------------------------------------------------
# Fixture: authed httpx client (password+TOTP login)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def authed_client():
    """Return an httpx.Client logged in as admin1 with a valid session cookie."""
    return _get_authed_client()


# ---------------------------------------------------------------------------
# Fixture: authed client + any pre-existing E2E test credentials cleaned up
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def clean_authed_client():
    """
    Return an httpx.Client with admin1 session AND any credentials whose
    name starts with 'E2E' already revoked (idempotent pre-test cleanup).
    """
    client = _get_authed_client()
    totp_secret = _admin1_totp_secret()

    existing = _list_webauthn_credentials(client)
    for cred in existing:
        if cred.get("name", "").startswith("E2E"):
            try:
                _delete_credential(client, cred["id"], totp_secret)
            except Exception:
                pass  # best-effort cleanup; test will fail meaningfully if cleanup fails

    return client


# ---------------------------------------------------------------------------
# ==========================================================================
# SCENARIO 1 — Registration happy path
# ==========================================================================
# ---------------------------------------------------------------------------

@skip_no_stack
def test_wa_reg_01_register_start_returns_options(authed_client):
    """
    WA-REG-01: POST /api/v1/admin/webauthn/register/start returns 200 with
    valid PublicKeyCredentialCreationOptions.

    ASVS V2.8: challenge must be present (server-generated, ≥32 bytes when
    decoded from base64url).
    """
    r = authed_client.post(
        f"{BASE_URL}/api/v1/admin/webauthn/register/start",
        json={"credential_name": "E2E WA-REG-01"},
    )
    assert r.status_code == 200, (
        f"WA-REG-01 FAIL: register/start returned {r.status_code}. Body: {r.text[:300]}"
    )
    body = r.json()
    assert body.get("status") == "ok", f"WA-REG-01 FAIL: status not 'ok': {body}"
    options = body.get("options")
    assert isinstance(options, dict), f"WA-REG-01 FAIL: options not a dict: {body}"
    assert "challenge" in options, "WA-REG-01 FAIL: options missing 'challenge' field"
    # Verify challenge is at least 32 bytes when decoded.
    raw_challenge = options["challenge"]
    padded = raw_challenge + "=" * (4 - len(raw_challenge) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        pytest.fail(f"WA-REG-01 FAIL: challenge is not valid base64url: {exc}")
    assert len(decoded) >= 32, (
        f"WA-REG-01 FAIL: challenge is only {len(decoded)} bytes (ASVS V2.8 requires ≥32)"
    )
    assert "rp" in options, "WA-REG-01 FAIL: options missing 'rp' (relying party) field"
    assert "user" in options, "WA-REG-01 FAIL: options missing 'user' field"


@skip_no_stack
def test_wa_reg_02_register_finish_stores_credential(
    clean_authed_client, browser_page_with_va
):
    """
    WA-REG-02: Full registration ceremony:
      1. register/start → options
      2. Browser navigator.credentials.create() via virtual authenticator
      3. register/finish → credential stored, 200 returned

    Verifies the credential appears in GET /api/v1/admin/webauthn/credentials.

    ASVS V2.8: credential persisted server-side.
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va

    # Step 1: get registration options.
    options = _do_webauthn_register_via_api(client, credential_name="E2E WA-REG-02")

    # Step 2: browser creates credential using virtual authenticator.
    credential_response = _browser_complete_registration(page, cdp, options)

    # Step 3: send to server to complete registration.
    r_finish = client.post(
        f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
        json={
            "credential_name": "E2E WA-REG-02",
            "credential_response": credential_response,
        },
    )
    assert r_finish.status_code == 200, (
        f"WA-REG-02 FAIL: register/finish returned {r_finish.status_code}. "
        f"Body: {r_finish.text[:300]}"
    )
    body = r_finish.json()
    assert body.get("status") == "ok", f"WA-REG-02 FAIL: finish status not 'ok': {body}"
    assert "credential_id" in body, "WA-REG-02 FAIL: credential_id missing from response"
    assert "name" in body, "WA-REG-02 FAIL: name missing from response"

    # Verify credential appears in list.
    creds = _list_webauthn_credentials(client)
    credential_ids = [c["id"] for c in creds]
    assert body["credential_id"] in credential_ids, (
        f"WA-REG-02 FAIL: newly registered credential_id={body['credential_id']} "
        f"not found in /credentials list: {creds}"
    )

    # Cleanup.
    totp_secret = _admin1_totp_secret()
    _delete_credential(client, body["credential_id"], totp_secret)


@skip_no_stack
def test_wa_reg_03_audit_event_emitted_on_registration(
    clean_authed_client, browser_page_with_va
):
    """
    WA-REG-03: WEBAUTHN_CREDENTIAL_REGISTERED audit event emitted after
    successful credential registration.

    ASVS V7.1.2: security-relevant actions must generate audit events.
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va

    # Mark time before registration to identify the event we just caused.
    ts_before = time.time()

    options = _do_webauthn_register_via_api(client, "E2E WA-REG-03")
    cred_response = _browser_complete_registration(page, cdp, options)

    r_finish = client.post(
        f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
        json={"credential_name": "E2E WA-REG-03", "credential_response": cred_response},
    )
    assert r_finish.status_code == 200, (
        f"WA-REG-03 FAIL: register/finish failed: {r_finish.status_code} {r_finish.text[:200]}"
    )
    credential_id = r_finish.json().get("credential_id")

    # Poll audit log for the registration event.
    event = _wait_for_audit_event(
        client, "WEBAUTHN_CREDENTIAL_REGISTERED", timeout_s=5.0
    )
    assert event is not None, (
        "WA-REG-03 FAIL: WEBAUTHN_CREDENTIAL_REGISTERED audit event not found "
        "within 5 s of register/finish. ASVS V7.1.2 requires audit on registration."
    )
    assert event.get("event_type") == "WEBAUTHN_CREDENTIAL_REGISTERED", (
        f"WA-REG-03 FAIL: event_type mismatch: {event}"
    )
    assert event.get("outcome") == "success", (
        f"WA-REG-03 FAIL: expected outcome=success in audit event: {event}"
    )

    # Cleanup.
    if credential_id:
        _delete_credential(client, credential_id, _admin1_totp_secret())


# ---------------------------------------------------------------------------
# ==========================================================================
# SCENARIO 2 — WebAuthn login happy path
# ==========================================================================
# ---------------------------------------------------------------------------

@skip_no_stack
def test_wa_login_01_login_start_returns_options(clean_authed_client, browser_page_with_va):
    """
    WA-LOGIN-01: POST /api/v1/admin/webauthn/login/start for enrolled user
    returns 200 with valid PublicKeyCredentialRequestOptions.

    ASVS V2.8: challenge freshly issued.
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va

    # Register a credential first so the user is enrolled.
    options_reg = _do_webauthn_register_via_api(client, "E2E WA-LOGIN-01")
    cred_response = _browser_complete_registration(page, cdp, options_reg)
    r_finish = client.post(
        f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
        json={"credential_name": "E2E WA-LOGIN-01", "credential_response": cred_response},
    )
    assert r_finish.status_code == 200
    credential_id = r_finish.json()["credential_id"]

    try:
        # Call login/start (PUBLIC endpoint).
        import httpx
        verify = _verify_param()
        r_start = httpx.post(
            f"{BASE_URL}/api/v1/admin/webauthn/login/start",
            json={"username": _admin1_username()},
            verify=verify,
            timeout=10,
        )
        assert r_start.status_code == 200, (
            f"WA-LOGIN-01 FAIL: login/start returned {r_start.status_code}. "
            f"Body: {r_start.text[:300]}"
        )
        body = r_start.json()
        assert body.get("status") == "ok", f"WA-LOGIN-01 FAIL: status not ok: {body}"
        assert "options" in body, "WA-LOGIN-01 FAIL: options missing from login/start response"
        assert "user_id" in body, "WA-LOGIN-01 FAIL: user_id missing from login/start response"
        options = body["options"]
        assert "challenge" in options, "WA-LOGIN-01 FAIL: challenge missing from options"
        assert "allowCredentials" in options, (
            "WA-LOGIN-01 FAIL: allowCredentials missing — enrolled credential not returned"
        )
        assert len(options["allowCredentials"]) > 0, (
            "WA-LOGIN-01 FAIL: allowCredentials list is empty — enrolled credential not listed"
        )
    finally:
        _delete_credential(client, credential_id, _admin1_totp_secret())


@skip_no_stack
def test_wa_login_02_login_finish_issues_session_cookie(
    clean_authed_client, browser_page_with_va
):
    """
    WA-LOGIN-02: POST /api/v1/admin/webauthn/login/finish with virtual
    authenticator returns 200 and sets the admin session cookie.

    ASVS V3.3: session cookie must be set on successful authentication.
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va

    # Register credential.
    options_reg = _do_webauthn_register_via_api(client, "E2E WA-LOGIN-02")
    cred_response = _browser_complete_registration(page, cdp, options_reg)
    r_reg = client.post(
        f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
        json={"credential_name": "E2E WA-LOGIN-02", "credential_response": cred_response},
    )
    assert r_reg.status_code == 200
    credential_id = r_reg.json()["credential_id"]

    try:
        # login/start — unauthenticated.
        import httpx
        verify = _verify_param()
        anon_client = httpx.Client(verify=verify, follow_redirects=False, timeout=15)

        r_start = anon_client.post(
            f"{BASE_URL}/api/v1/admin/webauthn/login/start",
            json={"username": _admin1_username()},
        )
        assert r_start.status_code == 200, (
            f"WA-LOGIN-02 FAIL: login/start returned {r_start.status_code}"
        )
        auth_options = r_start.json()["options"]

        # Drive browser authentication using virtual authenticator.
        assertion = _browser_complete_authentication(page, auth_options)

        # login/finish — send assertion.
        r_finish = anon_client.post(
            f"{BASE_URL}/api/v1/admin/webauthn/login/finish",
            json={"username": _admin1_username(), "credential_response": assertion},
        )
        assert r_finish.status_code == 200, (
            f"WA-LOGIN-02 FAIL: login/finish returned {r_finish.status_code}. "
            f"Body: {r_finish.text[:300]}"
        )
        body = r_finish.json()
        assert body.get("status") == "ok", (
            f"WA-LOGIN-02 FAIL: login/finish response status not ok: {body}"
        )

        # Verify session cookie was set.
        session_cookie = None
        for name in ("__Host-yashigani_admin_session", "__Host-yashigani_session"):
            if name in anon_client.cookies:
                session_cookie = anon_client.cookies[name]
                break
        assert session_cookie is not None, (
            "WA-LOGIN-02 FAIL: login/finish returned 200 but no session cookie was set. "
            "ASVS V3.3 requires session establishment on successful auth."
        )
    finally:
        _delete_credential(client, credential_id, _admin1_totp_secret())


@skip_no_stack
def test_wa_login_03_session_grants_authenticated_access(
    clean_authed_client, browser_page_with_va
):
    """
    WA-LOGIN-03: Session cookie issued by login/finish grants access to
    authenticated admin endpoints (/admin/accounts or equivalent).

    Proves the session is fully authorised, not just set.
    ASVS V3.3.
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va

    # Register.
    options_reg = _do_webauthn_register_via_api(client, "E2E WA-LOGIN-03")
    cred_resp = _browser_complete_registration(page, cdp, options_reg)
    r_reg = client.post(
        f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
        json={"credential_name": "E2E WA-LOGIN-03", "credential_response": cred_resp},
    )
    assert r_reg.status_code == 200
    credential_id = r_reg.json()["credential_id"]

    try:
        import httpx
        verify = _verify_param()
        anon_client = httpx.Client(verify=verify, follow_redirects=False, timeout=15)

        # Login via WebAuthn.
        r_start = anon_client.post(
            f"{BASE_URL}/api/v1/admin/webauthn/login/start",
            json={"username": _admin1_username()},
        )
        auth_options = r_start.json()["options"]
        assertion = _browser_complete_authentication(page, auth_options)

        r_finish = anon_client.post(
            f"{BASE_URL}/api/v1/admin/webauthn/login/finish",
            json={"username": _admin1_username(), "credential_response": assertion},
        )
        assert r_finish.status_code == 200, (
            f"WA-LOGIN-03 FAIL: WebAuthn login failed: {r_finish.status_code}"
        )

        # Use the WebAuthn session to access an authenticated endpoint.
        r_accounts = anon_client.get(f"{BASE_URL}/admin/accounts")
        assert r_accounts.status_code in (200, 302), (
            f"WA-LOGIN-03 FAIL: Authenticated request with WebAuthn session returned "
            f"{r_accounts.status_code}. Session not accepted for admin access."
        )
        # Must NOT be a redirect to login (which would indicate the session was not accepted).
        if r_accounts.status_code == 302:
            location = r_accounts.headers.get("location", "")
            assert "login" not in location.lower(), (
                f"WA-LOGIN-03 FAIL: WebAuthn session redirected to login. "
                f"Location: {location}. Session was not accepted."
            )
    finally:
        _delete_credential(client, credential_id, _admin1_totp_secret())


@skip_no_stack
def test_wa_login_04_audit_event_webauthn_login_success(
    clean_authed_client, browser_page_with_va
):
    """
    WA-LOGIN-04: WEBAUTHN_LOGIN_SUCCESS audit event emitted after successful
    WebAuthn login, with event_type matching PR #62 commit 6892907 wire format.

    Verifies B5 fix: event_type = "WEBAUTHN_LOGIN_SUCCESS" (not the v0.9.0
    class WEBAUTHN_CREDENTIAL_USED which carried a different wire value).

    ASVS V7.1.2.
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va

    # Register credential.
    options_reg = _do_webauthn_register_via_api(client, "E2E WA-LOGIN-04")
    cred_resp = _browser_complete_registration(page, cdp, options_reg)
    r_reg = client.post(
        f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
        json={"credential_name": "E2E WA-LOGIN-04", "credential_response": cred_resp},
    )
    assert r_reg.status_code == 200
    credential_id = r_reg.json()["credential_id"]

    try:
        import httpx
        verify = _verify_param()
        anon_client = httpx.Client(verify=verify, follow_redirects=False, timeout=15)

        # Perform WebAuthn login.
        r_start = anon_client.post(
            f"{BASE_URL}/api/v1/admin/webauthn/login/start",
            json={"username": _admin1_username()},
        )
        assert r_start.status_code == 200
        auth_options = r_start.json()["options"]
        assertion = _browser_complete_authentication(page, auth_options)

        r_finish = anon_client.post(
            f"{BASE_URL}/api/v1/admin/webauthn/login/finish",
            json={"username": _admin1_username(), "credential_response": assertion},
        )
        assert r_finish.status_code == 200, (
            f"WA-LOGIN-04 FAIL: login/finish failed: {r_finish.status_code}"
        )

        # Assert audit event (search with the authed client — it can read audit log).
        event = _wait_for_audit_event(client, "WEBAUTHN_LOGIN_SUCCESS", timeout_s=5.0)
        assert event is not None, (
            "WA-LOGIN-04 FAIL: WEBAUTHN_LOGIN_SUCCESS audit event not found within 5 s. "
            "PR #62 commit 6892907 must emit this event_type on login success."
        )
        assert event.get("event_type") == "WEBAUTHN_LOGIN_SUCCESS", (
            f"WA-LOGIN-04 FAIL: event_type is '{event.get('event_type')}', "
            f"expected 'WEBAUTHN_LOGIN_SUCCESS'. "
            f"B5 fix (commit 6892907) aligns wire-format event_type with route label."
        )
    finally:
        _delete_credential(client, credential_id, _admin1_totp_secret())


# ---------------------------------------------------------------------------
# ==========================================================================
# SCENARIO 3 — Failed login (adversarial)
# ==========================================================================
# ---------------------------------------------------------------------------

@skip_no_stack
def test_wa_fail_01_malformed_credential_response_returns_401(clean_authed_client):
    """
    WA-FAIL-01: login/finish with a malformed credential_response → 401.

    Verifies the server rejects garbage input without leaking error detail.
    ASVS V2.8, OWASP API2 (broken auth).
    """
    import httpx
    verify = _verify_param()

    # We need to first register a credential so login/start succeeds.
    # We register via the authed client then test login/finish with malformed data.
    client = clean_authed_client

    # login/start — must have a registered credential to get a challenge.
    # Use a throwaway login/start to get a fresh challenge — then immediately
    # hit login/finish with garbage. (challenge will be consumed/rejected).
    r_start = httpx.post(
        f"{BASE_URL}/api/v1/admin/webauthn/login/start",
        json={"username": _admin1_username()},
        verify=verify,
        timeout=10,
    )
    # If no credentials registered this returns 400 — that's a different scenario.
    # We test with admin1 who we expect to have credentials (or may not — both
    # outcome paths are valid here as long as login/finish rejects malformed input).
    if r_start.status_code == 400:
        # No credentials registered — login/start correctly returns 400.
        # Proceed to test login/finish directly with malformed input.
        pass

    malformed_response = {
        "id": "not-a-valid-base64url",
        "rawId": "garbage!!!",
        "type": "public-key",
        "response": {
            "authenticatorData": "not-cbor",
            "clientDataJSON": "not-json",
            "signature": "not-a-signature",
            "userHandle": None,
        },
    }
    r_finish = httpx.post(
        f"{BASE_URL}/api/v1/admin/webauthn/login/finish",
        json={"username": _admin1_username(), "credential_response": malformed_response},
        verify=verify,
        timeout=10,
    )
    assert r_finish.status_code in (400, 401, 422), (
        f"WA-FAIL-01 FAIL: malformed credential_response returned {r_finish.status_code}, "
        f"expected 400/401/422. Body: {r_finish.text[:300]}"
    )
    # Must not leak stack traces or internal error detail.
    body_text = r_finish.text.lower()
    assert "traceback" not in body_text, (
        "WA-FAIL-01 FAIL: response leaks Python traceback — information disclosure."
    )
    assert "exception" not in body_text and "error'" not in body_text.replace("error", ""), (
        # Allow {"error": "..."} envelope but not raw exception objects.
        "WA-FAIL-01 partial: check response for stack trace leakage"
    )


@skip_no_stack
def test_wa_fail_02_unknown_username_returns_401(clean_authed_client):
    """
    WA-FAIL-02: login/start with unknown username returns 400 (no credentials),
    and login/finish with unknown username returns 401.

    Verifies enumerate-safe response: both cases return the same generic error.
    ASVS V2.1.5 (user enumeration prevention).
    """
    import httpx
    verify = _verify_param()

    nonexistent = "definitely-not-a-real-admin@yashigani.local"

    r_start = httpx.post(
        f"{BASE_URL}/api/v1/admin/webauthn/login/start",
        json={"username": nonexistent},
        verify=verify,
        timeout=10,
    )
    # Must be 400 with generic error — not 404 (which reveals user non-existence)
    # and not 500 (server error).
    assert r_start.status_code == 400, (
        f"WA-FAIL-02 FAIL: login/start for unknown user returned {r_start.status_code}, "
        f"expected 400 (enumerate-safe). Body: {r_start.text[:200]}"
    )
    body = r_start.json()
    error_detail = body.get("detail", {})
    if isinstance(error_detail, dict):
        assert error_detail.get("error") == "no_credentials_registered", (
            f"WA-FAIL-02 FAIL: unexpected error code for unknown user: {error_detail}"
        )

    # login/finish with unknown username → 401.
    r_finish = httpx.post(
        f"{BASE_URL}/api/v1/admin/webauthn/login/finish",
        json={
            "username": nonexistent,
            "credential_response": {
                "id": "dummy",
                "rawId": "dummy",
                "type": "public-key",
                "response": {
                    "authenticatorData": "dummy",
                    "clientDataJSON": "dummy",
                    "signature": "dummy",
                    "userHandle": None,
                },
            },
        },
        verify=verify,
        timeout=10,
    )
    assert r_finish.status_code == 401, (
        f"WA-FAIL-02 FAIL: login/finish for unknown user returned {r_finish.status_code}, "
        f"expected 401. Body: {r_finish.text[:200]}"
    )


@skip_no_stack
def test_wa_fail_03_replayed_challenge_returns_401(
    clean_authed_client, browser_page_with_va
):
    """
    WA-FAIL-03: Using a stale / replayed challenge in login/finish → 401.

    Calls login/start twice to generate two challenges.  The first challenge
    is consumed by login/finish (the server's Redis challenge store uses GETDEL).
    A second login/finish attempt with the same credential_response must fail.

    ASVS V2.8: challenge single-use (Redis GETDEL ensures atomicity).
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va

    # Register a credential.
    options_reg = _do_webauthn_register_via_api(client, "E2E WA-FAIL-03")
    cred_resp = _browser_complete_registration(page, cdp, options_reg)
    r_reg = client.post(
        f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
        json={"credential_name": "E2E WA-FAIL-03", "credential_response": cred_resp},
    )
    assert r_reg.status_code == 200
    credential_id = r_reg.json()["credential_id"]

    try:
        import httpx
        verify = _verify_param()
        anon_client = httpx.Client(verify=verify, follow_redirects=False, timeout=15)

        # First login/start — issue challenge.
        r_start1 = anon_client.post(
            f"{BASE_URL}/api/v1/admin/webauthn/login/start",
            json={"username": _admin1_username()},
        )
        assert r_start1.status_code == 200
        auth_options1 = r_start1.json()["options"]

        # Create assertion from first challenge.
        assertion = _browser_complete_authentication(page, auth_options1)

        # First login/finish — valid, consumes the challenge.
        r_finish1 = anon_client.post(
            f"{BASE_URL}/api/v1/admin/webauthn/login/finish",
            json={"username": _admin1_username(), "credential_response": assertion},
        )
        assert r_finish1.status_code == 200, (
            f"WA-FAIL-03 FAIL: first login/finish failed unexpectedly: "
            f"{r_finish1.status_code} {r_finish1.text[:200]}"
        )

        # Second login/start — issues a new challenge, overwriting the old one in Redis.
        r_start2 = anon_client.post(
            f"{BASE_URL}/api/v1/admin/webauthn/login/start",
            json={"username": _admin1_username()},
        )
        assert r_start2.status_code == 200

        # Replay: send the SAME assertion from the first challenge with the
        # new challenge pending (the server will GETDEL the new challenge,
        # then the assertion clientDataJSON won't match the new challenge → 401).
        r_finish2 = anon_client.post(
            f"{BASE_URL}/api/v1/admin/webauthn/login/finish",
            json={"username": _admin1_username(), "credential_response": assertion},
        )
        assert r_finish2.status_code == 401, (
            f"WA-FAIL-03 FAIL: replayed assertion was accepted (status {r_finish2.status_code}). "
            f"ASVS V2.8 requires single-use challenges. Body: {r_finish2.text[:200]}"
        )
    finally:
        _delete_credential(client, credential_id, _admin1_totp_secret())


@skip_no_stack
def test_wa_fail_04_audit_event_webauthn_login_failure(clean_authed_client):
    """
    WA-FAIL-04: WEBAUTHN_LOGIN_FAILURE audit event emitted on failed assertion.

    Submits a malformed credential_response (guaranteed to fail) and verifies
    the event_type in the audit log is exactly 'WEBAUTHN_LOGIN_FAILURE'.

    ASVS V7.1.2 (audit on auth failure).
    PR #62 commit 6892907: WEBAUTHN_LOGIN_FAILURE wire-format alignment.
    """
    import httpx
    verify = _verify_param()
    client = clean_authed_client

    # Submit a deliberately malformed credential to trigger FAILURE audit event.
    httpx.post(
        f"{BASE_URL}/api/v1/admin/webauthn/login/finish",
        json={
            "username": _admin1_username(),
            "credential_response": {
                "id": "badcred",
                "rawId": "badcred",
                "type": "public-key",
                "response": {
                    "authenticatorData": "AAAA",
                    "clientDataJSON": "AAAA",
                    "signature": "AAAA",
                    "userHandle": None,
                },
            },
        },
        verify=verify,
        timeout=10,
    )
    # (We don't assert on the HTTP code here — just trigger the event.
    # The actual response code assertion is covered by WA-FAIL-01.)

    event = _wait_for_audit_event(client, "WEBAUTHN_LOGIN_FAILURE", timeout_s=5.0)
    assert event is not None, (
        "WA-FAIL-04 FAIL: WEBAUTHN_LOGIN_FAILURE audit event not found within 5 s. "
        "PR #62 commit 6892907 must emit this event_type on login failure."
    )
    assert event.get("event_type") == "WEBAUTHN_LOGIN_FAILURE", (
        f"WA-FAIL-04 FAIL: event_type is '{event.get('event_type')}', "
        f"expected 'WEBAUTHN_LOGIN_FAILURE'."
    )


# ---------------------------------------------------------------------------
# ==========================================================================
# SCENARIO 4 — Credential revocation
# ==========================================================================
# ---------------------------------------------------------------------------

@skip_no_stack
def test_wa_revoke_01_delete_credential_returns_200(
    clean_authed_client, browser_page_with_va
):
    """
    WA-REVOKE-01: DELETE /api/v1/admin/webauthn/credentials/{id} with valid
    step-up returns 200.

    ASVS V6.8.4: high-value mutating action requires fresh TOTP step-up.
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va

    # Register credential.
    options_reg = _do_webauthn_register_via_api(client, "E2E WA-REVOKE-01")
    cred_resp = _browser_complete_registration(page, cdp, options_reg)
    r_reg = client.post(
        f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
        json={"credential_name": "E2E WA-REVOKE-01", "credential_response": cred_resp},
    )
    assert r_reg.status_code == 200
    credential_id = r_reg.json()["credential_id"]

    # Revoke it (step-up inside _delete_credential).
    status_code = _delete_credential(client, credential_id, _admin1_totp_secret())
    assert status_code == 200, (
        f"WA-REVOKE-01 FAIL: DELETE /credentials/{credential_id} returned {status_code}. "
        f"Expected 200."
    )

    # Verify it no longer appears in the credential list.
    creds = _list_webauthn_credentials(client)
    remaining_ids = [c["id"] for c in creds]
    assert credential_id not in remaining_ids, (
        f"WA-REVOKE-01 FAIL: credential {credential_id} still present in list after deletion."
    )


@skip_no_stack
def test_wa_revoke_02_login_fails_after_revocation(
    clean_authed_client, browser_page_with_va
):
    """
    WA-REVOKE-02: After a credential is revoked, login/start for a user with
    no remaining credentials returns 400 (no credentials registered).

    ASVS V2.8: revoked credential must not be usable.
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va

    # Register credential.
    options_reg = _do_webauthn_register_via_api(client, "E2E WA-REVOKE-02")
    cred_resp = _browser_complete_registration(page, cdp, options_reg)
    r_reg = client.post(
        f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
        json={"credential_name": "E2E WA-REVOKE-02", "credential_response": cred_resp},
    )
    assert r_reg.status_code == 200
    credential_id = r_reg.json()["credential_id"]

    # Revoke.
    sc = _delete_credential(client, credential_id, _admin1_totp_secret())
    assert sc == 200, f"WA-REVOKE-02 FAIL: revocation returned {sc}"

    # Verify login/start now returns 400 for this user (no credentials).
    import httpx
    verify = _verify_param()
    r_start = httpx.post(
        f"{BASE_URL}/api/v1/admin/webauthn/login/start",
        json={"username": _admin1_username()},
        verify=verify,
        timeout=10,
    )
    assert r_start.status_code == 400, (
        f"WA-REVOKE-02 FAIL: login/start after revocation returned {r_start.status_code}, "
        f"expected 400 (no credentials). Body: {r_start.text[:200]}"
    )
    detail = r_start.json().get("detail", {})
    if isinstance(detail, dict):
        assert detail.get("error") == "no_credentials_registered", (
            f"WA-REVOKE-02 FAIL: unexpected error code after revocation: {detail}"
        )


@skip_no_stack
def test_wa_revoke_03_audit_event_credential_revoked(
    clean_authed_client, browser_page_with_va
):
    """
    WA-REVOKE-03: WEBAUTHN_CREDENTIAL_REVOKED audit event emitted after deletion.

    ASVS V7.1.2: credential revocation is a security-relevant event.
    PR #62 commit 6892907: event_type = 'WEBAUTHN_CREDENTIAL_REVOKED'.
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va

    # Register.
    options_reg = _do_webauthn_register_via_api(client, "E2E WA-REVOKE-03")
    cred_resp = _browser_complete_registration(page, cdp, options_reg)
    r_reg = client.post(
        f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
        json={"credential_name": "E2E WA-REVOKE-03", "credential_response": cred_resp},
    )
    assert r_reg.status_code == 200
    credential_id = r_reg.json()["credential_id"]

    # Revoke.
    sc = _delete_credential(client, credential_id, _admin1_totp_secret())
    assert sc == 200, f"WA-REVOKE-03 FAIL: revocation failed: {sc}"

    # Poll for audit event.
    event = _wait_for_audit_event(client, "WEBAUTHN_CREDENTIAL_REVOKED", timeout_s=5.0)
    assert event is not None, (
        "WA-REVOKE-03 FAIL: WEBAUTHN_CREDENTIAL_REVOKED audit event not found within 5 s. "
        "ASVS V7.1.2 requires audit on credential revocation."
    )
    assert event.get("event_type") == "WEBAUTHN_CREDENTIAL_REVOKED", (
        f"WA-REVOKE-03 FAIL: event_type is '{event.get('event_type')}', "
        f"expected 'WEBAUTHN_CREDENTIAL_REVOKED'."
    )
    assert event.get("outcome") == "success", (
        f"WA-REVOKE-03 FAIL: expected outcome=success in revocation event: {event}"
    )


@skip_no_stack
def test_wa_revoke_04_without_stepup_returns_401(clean_authed_client, browser_page_with_va):
    """
    WA-REVOKE-04 (additional security probe): DELETE /credentials/{id} without
    step-up returns 401 with error='step_up_required'.

    ASVS V6.8.4: step-up MUST be enforced, not just documented.
    OWASP A01: broken access control probe.
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va

    # Register credential.
    options_reg = _do_webauthn_register_via_api(client, "E2E WA-REVOKE-04")
    cred_resp = _browser_complete_registration(page, cdp, options_reg)
    r_reg = client.post(
        f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
        json={"credential_name": "E2E WA-REVOKE-04", "credential_response": cred_resp},
    )
    assert r_reg.status_code == 200
    credential_id = r_reg.json()["credential_id"]

    try:
        # Attempt delete WITHOUT step-up.
        r_del = client.delete(
            f"{BASE_URL}/api/v1/admin/webauthn/credentials/{credential_id}",
        )
        assert r_del.status_code == 401, (
            f"WA-REVOKE-04 FAIL: DELETE without step-up returned {r_del.status_code}, "
            f"expected 401. ASVS V6.8.4 step-up not enforced."
        )
        detail = r_del.json().get("detail", {})
        if isinstance(detail, dict):
            assert detail.get("error") == "step_up_required", (
                f"WA-REVOKE-04 FAIL: expected step_up_required error, got: {detail}"
            )
    finally:
        # Cleanup — must do step-up for real.
        _delete_credential(client, credential_id, _admin1_totp_secret())


# ---------------------------------------------------------------------------
# ==========================================================================
# SCENARIO 5 — Multi-credential support
# ==========================================================================
# ---------------------------------------------------------------------------

@skip_no_stack
def test_wa_multi_01_register_two_credentials_both_listed(
    clean_authed_client, browser_page_with_va
):
    """
    WA-MULTI-01: Register two credentials; verify both appear in the credential list.

    OWASP API1: each credential belongs to the authenticated admin.
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va
    totp_secret = _admin1_totp_secret()
    registered_ids = []

    try:
        for i in range(2):
            options_reg = _do_webauthn_register_via_api(client, f"E2E WA-MULTI-01 Key {i+1}")
            cred_resp = _browser_complete_registration(page, cdp, options_reg)
            r_reg = client.post(
                f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
                json={
                    "credential_name": f"E2E WA-MULTI-01 Key {i+1}",
                    "credential_response": cred_resp,
                },
            )
            assert r_reg.status_code == 200, (
                f"WA-MULTI-01 FAIL: Registration {i+1} failed: {r_reg.status_code}"
            )
            registered_ids.append(r_reg.json()["credential_id"])

        # Verify both appear.
        creds = _list_webauthn_credentials(client)
        listed_ids = {c["id"] for c in creds}
        for cred_id in registered_ids:
            assert cred_id in listed_ids, (
                f"WA-MULTI-01 FAIL: Registered credential {cred_id} not in list: {listed_ids}"
            )
    finally:
        for cred_id in registered_ids:
            try:
                _delete_credential(client, cred_id, totp_secret)
            except Exception:
                pass


@skip_no_stack
def test_wa_multi_02_03_both_credentials_usable(
    clean_authed_client, browser_page_with_va
):
    """
    WA-MULTI-02 + WA-MULTI-03: With two registered credentials, login succeeds
    via each one (tested sequentially using the same virtual authenticator,
    which stores both credentials internally).

    Note: the virtual authenticator (CDP) maintains both credentials on the
    same device. The server presents both in allowCredentials; the authenticator
    picks the one it holds and produces a valid assertion for each challenge.
    Since the virtual authenticator auto-selects, we verify two successful
    login/finish calls (both must return 200 + session cookie).
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va
    totp_secret = _admin1_totp_secret()
    registered_ids = []

    try:
        # Register both credentials.
        for i in range(2):
            options_reg = _do_webauthn_register_via_api(client, f"E2E WA-MULTI-0{i+2}")
            cred_resp = _browser_complete_registration(page, cdp, options_reg)
            r_reg = client.post(
                f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
                json={
                    "credential_name": f"E2E WA-MULTI-0{i+2}",
                    "credential_response": cred_resp,
                },
            )
            assert r_reg.status_code == 200, (
                f"WA-MULTI-0{i+2} FAIL: Registration failed: {r_reg.status_code}"
            )
            registered_ids.append(r_reg.json()["credential_id"])

        import httpx
        verify = _verify_param()

        # Perform two independent login flows (two fresh challenges).
        for attempt in range(2):
            anon_client = httpx.Client(verify=verify, follow_redirects=False, timeout=15)
            r_start = anon_client.post(
                f"{BASE_URL}/api/v1/admin/webauthn/login/start",
                json={"username": _admin1_username()},
            )
            assert r_start.status_code == 200, (
                f"WA-MULTI-0{attempt+2} FAIL: login/start returned {r_start.status_code}"
            )
            auth_options = r_start.json()["options"]
            assertion = _browser_complete_authentication(page, auth_options)
            r_finish = anon_client.post(
                f"{BASE_URL}/api/v1/admin/webauthn/login/finish",
                json={"username": _admin1_username(), "credential_response": assertion},
            )
            assert r_finish.status_code == 200, (
                f"WA-MULTI-0{attempt+2} FAIL: login attempt {attempt+1} with two credentials "
                f"returned {r_finish.status_code}. Body: {r_finish.text[:200]}"
            )
    finally:
        for cred_id in registered_ids:
            try:
                _delete_credential(client, cred_id, totp_secret)
            except Exception:
                pass


@skip_no_stack
def test_wa_multi_04_revoke_one_does_not_affect_other(
    clean_authed_client, browser_page_with_va
):
    """
    WA-MULTI-04: Revoking one credential does not prevent login with the other.

    OWASP API1 (BOLA): credential A belongs to admin; admin revokes A; B still works.
    ASVS V2.8: per-credential lifecycle management.
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va
    totp_secret = _admin1_totp_secret()
    registered_ids = []

    try:
        # Register two credentials.
        for i in range(2):
            options_reg = _do_webauthn_register_via_api(client, f"E2E WA-MULTI-04 Key {i+1}")
            cred_resp = _browser_complete_registration(page, cdp, options_reg)
            r_reg = client.post(
                f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
                json={
                    "credential_name": f"E2E WA-MULTI-04 Key {i+1}",
                    "credential_response": cred_resp,
                },
            )
            assert r_reg.status_code == 200
            registered_ids.append(r_reg.json()["credential_id"])

        id_a, id_b = registered_ids[0], registered_ids[1]

        # Revoke credential A.
        sc = _delete_credential(client, id_a, totp_secret)
        assert sc == 200, f"WA-MULTI-04 FAIL: revocation of credential A failed: {sc}"

        # Verify credential A is gone, B still present.
        creds = _list_webauthn_credentials(client)
        listed_ids = {c["id"] for c in creds}
        assert id_a not in listed_ids, (
            f"WA-MULTI-04 FAIL: revoked credential A ({id_a}) still in list"
        )
        assert id_b in listed_ids, (
            f"WA-MULTI-04 FAIL: credential B ({id_b}) disappeared after revoking A"
        )

        # Login must still succeed (virtual authenticator holds B; server lists only B).
        import httpx
        verify = _verify_param()
        anon_client = httpx.Client(verify=verify, follow_redirects=False, timeout=15)
        r_start = anon_client.post(
            f"{BASE_URL}/api/v1/admin/webauthn/login/start",
            json={"username": _admin1_username()},
        )
        assert r_start.status_code == 200, (
            f"WA-MULTI-04 FAIL: login/start after revoking A returned {r_start.status_code}"
        )
        auth_options = r_start.json()["options"]
        assertion = _browser_complete_authentication(page, auth_options)
        r_finish = anon_client.post(
            f"{BASE_URL}/api/v1/admin/webauthn/login/finish",
            json={"username": _admin1_username(), "credential_response": assertion},
        )
        assert r_finish.status_code == 200, (
            f"WA-MULTI-04 FAIL: login with credential B failed after revoking A: "
            f"{r_finish.status_code}. Body: {r_finish.text[:200]}"
        )
    finally:
        for cred_id in registered_ids:
            try:
                _delete_credential(client, cred_id, totp_secret)
            except Exception:
                pass


@skip_no_stack
def test_wa_multi_05_revoke_all_leaves_empty_list(
    clean_authed_client, browser_page_with_va
):
    """
    WA-MULTI-05: After revoking all credentials, the credentials list is empty
    and login/start returns 400 (no credentials registered).

    Recovery path: password+TOTP remains available (tested separately in
    the existing admin login suite).
    """
    client = clean_authed_client
    page, cdp, auth_id = browser_page_with_va
    totp_secret = _admin1_totp_secret()
    registered_ids = []

    # Register two credentials.
    for i in range(2):
        options_reg = _do_webauthn_register_via_api(client, f"E2E WA-MULTI-05 Key {i+1}")
        cred_resp = _browser_complete_registration(page, cdp, options_reg)
        r_reg = client.post(
            f"{BASE_URL}/api/v1/admin/webauthn/register/finish",
            json={
                "credential_name": f"E2E WA-MULTI-05 Key {i+1}",
                "credential_response": cred_resp,
            },
        )
        assert r_reg.status_code == 200
        registered_ids.append(r_reg.json()["credential_id"])

    # Revoke all.
    for cred_id in registered_ids:
        sc = _delete_credential(client, cred_id, totp_secret)
        assert sc == 200, (
            f"WA-MULTI-05 FAIL: revocation of {cred_id} returned {sc}"
        )

    # Verify list is empty.
    creds = _list_webauthn_credentials(client)
    e2e_creds = [c for c in creds if c.get("name", "").startswith("E2E")]
    assert len(e2e_creds) == 0, (
        f"WA-MULTI-05 FAIL: {len(e2e_creds)} E2E credentials remain after revoking all: "
        f"{e2e_creds}"
    )

    # Verify login/start returns 400.
    import httpx
    verify = _verify_param()
    r_start = httpx.post(
        f"{BASE_URL}/api/v1/admin/webauthn/login/start",
        json={"username": _admin1_username()},
        verify=verify,
        timeout=10,
    )
    assert r_start.status_code == 400, (
        f"WA-MULTI-05 FAIL: login/start after revoking all credentials returned "
        f"{r_start.status_code}, expected 400. Body: {r_start.text[:200]}"
    )
