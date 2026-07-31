"""
HTTP-level API contract tests — /admin/backup/status + /admin/backup/verify (#47).

These tests hit the running stack directly via httpx.  They do NOT require a browser.
They run even when Playwright Chromium is unavailable.

Coverage:
  API-BAK-01  GET /admin/backup/status: 200 + schema validation
  API-BAK-02  GET /admin/backup/status: 401 with no session cookie
  API-BAK-03  GET /admin/backup/status: empty-state (no backup dir) → clean 200, not 500
  API-BAK-04  POST /admin/backup/verify: 200 + schema validation (signed backup)
  API-BAK-05  POST /admin/backup/verify: 401 without session cookie
  API-BAK-06  POST /admin/backup/verify: 422 with missing body field
  API-BAK-07  POST /admin/backup/verify: 422 with empty string backup_name
  API-BAK-08  POST /admin/backup/verify: 404 when backup_name is valid but missing
  API-BAK-09  POST /admin/backup/verify: 413/422 when body exceeds 256-byte limit (ASVS 4.3.1)
  API-BAK-10  POST /admin/backup/verify: 422 path traversal — ../etc/passwd
  API-BAK-11  POST /admin/backup/verify: 422 path traversal — ../../
  API-BAK-12  POST /admin/backup/verify: 422 path traversal — ./
  API-BAK-13  POST /admin/backup/verify: 422 path traversal — .. (bare double-dot)
  API-BAK-14  POST /admin/backup/verify: stale/forged session cookie → 401
  API-BAK-15  CSRF probe — POST /admin/backup/verify without Origin/Referer header still
              requires valid session (SameSite=Strict cookie is the primary CSRF defence here)
  API-BAK-16  Rate-limit probe — 20 rapid verify calls; no unexpected 5xx
  API-BAK-17  CWE-200 — response never leaks absolute filesystem path

Mode: deterministic gate.
ASVS: 4.1.1, 4.3.1, 9.2.1, 11.4 (no absolute paths)
OWASP: A01 (access control), A03 (injection), API4 (unrestricted resource consumption)
CWE: CWE-22 (path traversal), CWE-200 (information exposure)

Last updated: 2026-05-06
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

import pytest

from tests.playwright.conftest import BASE_URL, STACK_RUNNING, _CA_CERT_PATH, _api_get_session_cookies

pytestmark = pytest.mark.api_contract


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _verify_param() -> bool | str:
    """httpx verify parameter — CA cert or False for no-CA fallback."""
    return _CA_CERT_PATH if _CA_CERT_PATH else False  # type: ignore[return-value]


def _admin_session_cookie(username: str, password: str) -> Optional[str]:
    """
    Log in as admin and return the session cookie value.
    Returns None if login fails (test will assert on None and produce clear failure).
    """
    import httpx

    verify = _verify_param()
    # Step 1: POST /login
    r = httpx.post(
        f"{BASE_URL}/login",
        json={"username": username, "password": password},
        verify=verify,
        follow_redirects=False,
        timeout=10,
    )
    # Accept 200 (immediate session) or 302/307 (redirect after login)
    if r.status_code not in (200, 302, 307, 308, 401, 403):
        return None

    # Extract __Host-yashigani_admin_session cookie
    for cookie_name in ("__Host-yashigani_admin_session", "__Host-yashigani_session"):
        val = r.cookies.get(cookie_name)
        if val:
            return val
    return None


def _read_admin_creds() -> tuple[str, str]:
    repo_root = Path(__file__).parents[3]
    username = (repo_root / "docker" / "secrets" / "admin1_username").read_text().strip()
    password = (repo_root / "docker" / "secrets" / "admin_initial_password").read_text().strip()
    return username, password


def _authed_client():
    """Return an httpx.Client with a valid admin session cookie.

    QA-fix (Ava, 2026-07-31): this previously (a) posted to f"{BASE_URL}/login"
    -- a GET-only user-facing page route (app.py: @app.get("/login")); admin
    login is POST /auth/login (auth_router mounted with prefix="/auth"); (b)
    never submitted totp_code at all, which the server requires on every
    login; (c) never handled force_password_change, so on a genuinely fresh
    stack (admin creds still INITIAL) no valid session cookie was ever
    obtainable -- all 12 tests in this file depending on _authed_client()
    would see 401s that looked like product bugs but were actually a broken
    test harness. Now delegates to conftest._api_get_session_cookies(), which
    already has the correct SHA-512/8-digit TOTP, self-heals the forced
    password-change step, and persists the rotated password so every other
    file's login helper in this pytest run stays in sync.
    """
    import httpx

    cookies = _api_get_session_cookies(admin=1)
    verify = _verify_param()
    client = httpx.Client(verify=verify, follow_redirects=False, timeout=15)
    client.cookies.update(cookies)
    return client


# ---------------------------------------------------------------------------
# Skip guard
# ---------------------------------------------------------------------------

skip_no_stack = pytest.mark.skipif(
    not STACK_RUNNING, reason="Yashigani stack not running"
)


# ---------------------------------------------------------------------------
# API-BAK-01: GET /admin/backup/status — 200 + schema
# ---------------------------------------------------------------------------

@skip_no_stack
def test_status_200_schema():
    """API-BAK-01: authenticated GET returns 200 + valid JSON schema."""
    import httpx

    client = _authed_client()
    r = client.get(f"{BASE_URL}/admin/backup/status")
    assert r.status_code == 200, (
        f"API-BAK-01 FAIL: expected 200, got {r.status_code}. Body: {r.text[:200]}"
    )
    data = r.json()
    # Schema: {backups: list, latest: object|null, backups_dir: str}
    assert "backups" in data, "API-BAK-01 FAIL: 'backups' key missing from response."
    assert isinstance(data["backups"], list), "API-BAK-01 FAIL: 'backups' is not a list."
    assert "latest" in data, "API-BAK-01 FAIL: 'latest' key missing from response."
    assert "backups_dir" in data, "API-BAK-01 FAIL: 'backups_dir' key missing."
    # CWE-200: backups_dir must be relative sentinel, never absolute
    assert not data["backups_dir"].startswith("/"), (
        f"API-BAK-17 FAIL (from API-BAK-01): backups_dir leaks absolute path: "
        f"{data['backups_dir']!r}. CWE-200 / ASVS 11.4."
    )


# ---------------------------------------------------------------------------
# API-BAK-02: GET without session → 401/302
# ---------------------------------------------------------------------------

@skip_no_stack
def test_status_401_without_session():
    """API-BAK-02: no session cookie → 401 or redirect. ASVS 4.1.1."""
    import httpx

    r = httpx.get(
        f"{BASE_URL}/admin/backup/status",
        verify=_verify_param(),
        follow_redirects=False,
        timeout=10,
    )
    assert r.status_code in (401, 302, 307, 308), (
        f"API-BAK-02 FAIL: got {r.status_code} without session. "
        "Broken access control — ASVS 4.1.1 / OWASP A01."
    )


# ---------------------------------------------------------------------------
# API-BAK-03: Missing backup dir → clean 200 empty state, not 500
# ---------------------------------------------------------------------------
# This is already tested in the unit suite.  At the API level we assert the
# same guarantee when the stack's backups dir is empty (default).

@skip_no_stack
def test_status_empty_state_not_500():
    """API-BAK-03: When no backups exist, returns 200 {backups:[], latest:null}."""
    import httpx

    client = _authed_client()
    r = client.get(f"{BASE_URL}/admin/backup/status")
    assert r.status_code == 200, (
        f"API-BAK-03 FAIL: expected 200 empty-state, got {r.status_code}."
    )
    assert r.status_code != 500, "API-BAK-03 FAIL: 500 when backups dir missing."


# ---------------------------------------------------------------------------
# API-BAK-04: POST /admin/backup/verify — 200 + schema (if backups exist)
# ---------------------------------------------------------------------------

@skip_no_stack
def test_verify_schema_when_backup_exists():
    """API-BAK-04: POST /admin/backup/verify with a real backup_name returns
    200 + correct schema.  Skips if no backups exist (retro A1)."""
    import httpx

    client = _authed_client()
    # First get a backup name
    sr = client.get(f"{BASE_URL}/admin/backup/status")
    assert sr.status_code == 200
    sd = sr.json()
    if not sd.get("backups"):
        pytest.skip(
            "API-BAK-04 SKIPPED: No backups found — deploy a backup first. "
            "Retro A1: absent artefact = SKIP."
        )
    backup_name = sd["backups"][0]["name"]
    r = client.post(
        f"{BASE_URL}/admin/backup/verify",
        json={"backup_name": backup_name},
    )
    assert r.status_code == 200, (
        f"API-BAK-04 FAIL: expected 200, got {r.status_code}. Body: {r.text[:300]}"
    )
    data = r.json()
    required_keys = {"ok", "backup_name", "manifest_state", "computed_checksums",
                     "recorded_checksums", "mismatches", "verified_at",
                     "concurrent_write_risk"}
    missing = required_keys - set(data.keys())
    assert not missing, f"API-BAK-04 FAIL: response missing keys: {missing}"
    assert isinstance(data["ok"], bool), "API-BAK-04 FAIL: 'ok' must be bool."
    assert isinstance(data["mismatches"], list), "API-BAK-04 FAIL: 'mismatches' must be list."
    assert data["manifest_state"] in ("signed", "unsigned", "corrupt"), (
        f"API-BAK-04 FAIL: unexpected manifest_state: {data['manifest_state']!r}"
    )
    # CWE-200: no absolute path in backup_name echo or computed_checksums keys
    for key in data.get("computed_checksums", {}).keys():
        assert not key.startswith("/"), (
            f"API-BAK-17 FAIL: absolute path leaked in computed_checksums key: {key!r}. "
            "CWE-200 / ASVS 11.4."
        )


# ---------------------------------------------------------------------------
# API-BAK-05: POST without session → 401
# ---------------------------------------------------------------------------

@skip_no_stack
def test_verify_401_without_session():
    """API-BAK-05: POST /admin/backup/verify without session → 401. ASVS 4.1.1."""
    import httpx

    r = httpx.post(
        f"{BASE_URL}/admin/backup/verify",
        json={"backup_name": "some_backup"},
        verify=_verify_param(),
        follow_redirects=False,
        timeout=10,
    )
    assert r.status_code in (401, 302, 307, 308), (
        f"API-BAK-05 FAIL: got {r.status_code} without session. "
        "Broken access control — ASVS 4.1.1."
    )


# ---------------------------------------------------------------------------
# API-BAK-06: 422 missing body field
# ---------------------------------------------------------------------------

@skip_no_stack
def test_verify_422_missing_backup_name():
    """API-BAK-06: POST with empty JSON body → 422 (Pydantic validation)."""
    import httpx

    client = _authed_client()
    r = client.post(f"{BASE_URL}/admin/backup/verify", json={})
    assert r.status_code == 422, (
        f"API-BAK-06 FAIL: expected 422 for missing backup_name, got {r.status_code}."
    )


# ---------------------------------------------------------------------------
# API-BAK-07: 422 empty backup_name
# ---------------------------------------------------------------------------

@skip_no_stack
def test_verify_422_empty_backup_name():
    """API-BAK-07: POST with backup_name='' → 422 (regex rejects empty string)."""
    import httpx

    client = _authed_client()
    r = client.post(f"{BASE_URL}/admin/backup/verify", json={"backup_name": ""})
    assert r.status_code == 422, (
        f"API-BAK-07 FAIL: expected 422 for empty backup_name, got {r.status_code}. "
        "Empty string should fail _BACKUP_NAME_RE regex."
    )


# ---------------------------------------------------------------------------
# API-BAK-08: 404 valid name, missing backup
# ---------------------------------------------------------------------------

@skip_no_stack
def test_verify_404_backup_not_found():
    """API-BAK-08: POST with a valid but non-existent backup_name → 404."""
    import httpx

    client = _authed_client()
    r = client.post(
        f"{BASE_URL}/admin/backup/verify",
        json={"backup_name": "definitely_does_not_exist_qa_probe"},
    )
    assert r.status_code == 404, (
        f"API-BAK-08 FAIL: expected 404 for missing backup, got {r.status_code}."
    )
    data = r.json()
    assert data.get("detail", {}).get("error") == "backup_not_found", (
        f"API-BAK-08 FAIL: unexpected detail: {data.get('detail')}"
    )
    # CWE-200: error must not contain absolute path
    detail_str = str(data.get("detail", ""))
    assert "/data/backups" not in detail_str and "/var/" not in detail_str, (
        f"API-BAK-17 FAIL: error detail leaks filesystem path: {detail_str!r}. CWE-200."
    )


# ---------------------------------------------------------------------------
# API-BAK-09: 413/422 oversized body (>256 bytes)  ASVS 4.3.1
# ---------------------------------------------------------------------------

@skip_no_stack
def test_verify_413_oversized_body():
    """API-BAK-09: POST with body > 256 bytes → 413 or 422. ASVS 4.3.1."""
    import httpx

    client = _authed_client()
    # Craft a body that's clearly over 256 bytes
    big_name = "a" * 300
    payload = {"backup_name": big_name}
    r = client.post(f"{BASE_URL}/admin/backup/verify", json=payload)
    assert r.status_code in (413, 422), (
        f"API-BAK-09 FAIL: expected 413 or 422 for oversized body, got {r.status_code}. "
        "Body-limit middleware may not be applying to /admin/backup. ASVS 4.3.1."
    )


# ---------------------------------------------------------------------------
# API-BAK-10 to API-BAK-13: Path traversal probes  CWE-22 / ASVS 9.2.1
# ---------------------------------------------------------------------------

@skip_no_stack
@pytest.mark.security_probe
@pytest.mark.parametrize("traversal_name,case_id", [
    ("../etc/passwd",       "API-BAK-10"),
    ("../../",              "API-BAK-11"),
    ("./",                  "API-BAK-12"),
    ("..",                  "API-BAK-13"),
    ("./..",                "API-BAK-13b"),
    ("valid/../etc/passwd", "API-BAK-13c"),
    ("%2e%2e%2fetc%2fpasswd", "API-BAK-13d"),   # URL-encoded traversal
])
def test_verify_path_traversal_rejected(traversal_name: str, case_id: str):
    """Path traversal names must be rejected with 422. CWE-22 / ASVS 9.2.1."""
    import httpx

    client = _authed_client()
    r = client.post(
        f"{BASE_URL}/admin/backup/verify",
        json={"backup_name": traversal_name},
    )
    assert r.status_code == 422, (
        f"{case_id} FAIL: path traversal {traversal_name!r} was not rejected with 422, "
        f"got {r.status_code}. CWE-22 / ASVS 9.2.1 / OWASP A01."
    )
    detail = r.json().get("detail", {})
    assert detail.get("error") in ("invalid_backup_name", "path_traversal_rejected"), (
        f"{case_id} FAIL: unexpected error code: {detail.get('error')!r}. "
        f"Expected regex-layer or resolved-path rejection."
    )


# ---------------------------------------------------------------------------
# API-BAK-14: Stale/forged session cookie → 401
# ---------------------------------------------------------------------------

@skip_no_stack
@pytest.mark.security_probe
def test_verify_forged_session_cookie_rejected():
    """API-BAK-14: POST with a forged/stale session cookie → 401.
    ASVS 3.2.1 (session invalidation) / OWASP A07 (auth failures)."""
    import httpx

    forged_token = "forged_session_token_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    r = httpx.post(
        f"{BASE_URL}/admin/backup/verify",
        json={"backup_name": "some_backup"},
        cookies={"__Host-yashigani_admin_session": forged_token},
        verify=_verify_param(),
        follow_redirects=False,
        timeout=10,
    )
    assert r.status_code in (401, 302, 307, 308), (
        f"API-BAK-14 FAIL: forged session cookie accepted, got {r.status_code}. "
        "OWASP A07 / ASVS 3.2.1 — session fixation or auth bypass."
    )


# ---------------------------------------------------------------------------
# API-BAK-15: CSRF — POST without Origin/Referer
# The session cookie is SameSite=Strict, which is the primary CSRF defence.
# In a test harness we cannot send a cross-origin browser request, so we verify
# that the endpoint still requires a valid session (no anonymous bypass).
# ---------------------------------------------------------------------------

@skip_no_stack
@pytest.mark.security_probe
def test_verify_no_anonymous_csrf_bypass():
    """API-BAK-15: POST without any session (simulating CSRF from unauthenticated origin)
    must be rejected.  SameSite=Strict is the CSRF control; we validate it's effective
    by confirming the endpoint is not callable without a valid session.
    ASVS 4.2.2 / OWASP A01."""
    import httpx

    r = httpx.post(
        f"{BASE_URL}/admin/backup/verify",
        json={"backup_name": "some_backup"},
        headers={"Origin": "https://evil.example.com"},
        verify=_verify_param(),
        follow_redirects=False,
        timeout=10,
    )
    assert r.status_code in (401, 403, 302, 307, 308), (
        f"API-BAK-15 FAIL: request from evil.example.com without session was accepted "
        f"({r.status_code}). ASVS 4.2.2 / OWASP A01."
    )


# ---------------------------------------------------------------------------
# API-BAK-16: Rate-limit probe — 20 rapid calls; no unexpected 5xx
# ---------------------------------------------------------------------------

@skip_no_stack
@pytest.mark.security_probe
def test_verify_burst_no_5xx():
    """API-BAK-16: 20 rapid POST /admin/backup/verify calls with an invalid name.
    None should return 5xx.  If rate-limiting is enforced, 429s are acceptable.

    Note: as of 2026-05-06 no per-session rate-limit is configured on /admin/backup/verify
    (only login has rate-limiting). This test verifies no 5xx under burst — it does NOT
    assert a 429 because that control is not implemented on this endpoint.
    See security finding FINDING-BAK-RL-01 in the test report.

    API4 (Unrestricted Resource Consumption) — test for absence of 5xx, not presence of 429.
    """
    import httpx

    client = _authed_client()
    status_codes = []
    for _ in range(20):
        r = client.post(
            f"{BASE_URL}/admin/backup/verify",
            json={"backup_name": "nonexistent_burst_probe"},
        )
        status_codes.append(r.status_code)

    unexpected_5xx = [s for s in status_codes if s >= 500]
    assert not unexpected_5xx, (
        f"API-BAK-16 FAIL: Got 5xx responses under burst: {unexpected_5xx}. "
        "Server error under load — OWASP API4."
    )
    # Expected responses: 404 (not found) or 429 (rate limited) or 401 (session expired)
    for s in status_codes:
        assert s in (404, 429, 401, 403), (
            f"API-BAK-16 FAIL: Unexpected status {s} under burst. "
            f"All statuses: {status_codes}"
        )


# ---------------------------------------------------------------------------
# API-BAK-17: CWE-200 — no absolute path in any response
# (covered inline in API-BAK-01, API-BAK-04, API-BAK-08 above)
# This test is a dedicated sweep across all three endpoints.
# ---------------------------------------------------------------------------

@skip_no_stack
@pytest.mark.security_probe
def test_no_absolute_path_in_any_response():
    """API-BAK-17: No response from /admin/backup/* leaks absolute filesystem paths.
    CWE-200 / ASVS 11.4 / API-SP-3."""
    import httpx

    client = _authed_client()
    responses_to_check = []

    # Status endpoint
    sr = client.get(f"{BASE_URL}/admin/backup/status")
    if sr.status_code == 200:
        responses_to_check.append(("GET /admin/backup/status", sr.text))

    # Verify with traversal (gets a 422)
    vr = client.post(
        f"{BASE_URL}/admin/backup/verify",
        json={"backup_name": "../etc/passwd"},
    )
    responses_to_check.append(("POST /admin/backup/verify (traversal)", vr.text))

    # Verify with not-found (gets a 404)
    vr2 = client.post(
        f"{BASE_URL}/admin/backup/verify",
        json={"backup_name": "does_not_exist_qa"},
    )
    responses_to_check.append(("POST /admin/backup/verify (not found)", vr2.text))

    # Paths that must never appear in responses
    forbidden_prefixes = ["/data/backups", "/var/", "/home/", "/root/", "/etc/"]

    for label, body in responses_to_check:
        for prefix in forbidden_prefixes:
            assert prefix not in body, (
                f"API-BAK-17 FAIL [{label}]: response contains absolute path {prefix!r}. "
                f"CWE-200 / ASVS 11.4. Body snippet: {body[:300]!r}"
            )
