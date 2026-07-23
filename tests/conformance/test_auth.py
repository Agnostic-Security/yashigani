"""
Conformance group: AUTH.

Closes G1 (Lu audit YCS-20260723-v4.1.2-CONFORMANCE) for:
  routes/auth.py         (25 endpoints) — /auth/*
  routes/sso.py           (6 endpoints) — /auth/sso/*
  routes/webauthn.py      (6 endpoints) — /auth/webauthn/* + /admin/settings/webauthn/credentials*
  routes/webauthn_v1.py   (6 endpoints) — /api/v1/admin/webauthn/*
Total: 43 endpoints.

Convention: see tests/conformance/conftest.py module docstring.

MOCKED dependencies (all documented at point of use below):
  - auth_service: production is `PostgresLocalAuthService` (asyncpg-backed).
    No fakeredis/fake-Postgres equivalent exists, so this module wraps the
    REAL, in-memory, synchronous `yashigani.auth.local_auth.LocalAuthService`
    (genuine argon2 password hashing, genuine TOTP generation/verification/
    replay, genuine lockout counters) with a thin async facade
    (`_FakeAsyncAuthService`) so it satisfies the `await state.auth_service.X()`
    contract auth.py's routes use. Only the sync->async boundary and two
    methods LocalAuthService doesn't implement (`get_account_by_id`,
    `force_totp_reprovision` — added to PostgresLocalAuthService after
    LocalAuthService was written) are bridged here.
  - `_pg_tenant_transaction()` (auth.py's password-history/self-reset DB
    calls): Postgres-only, no fakeredis equivalent. Replaced with a minimal
    in-memory async context manager (`_FakeConn`) implementing only
    `fetch`/`fetchrow`/`execute` — the exact surface those two routes touch.
  - `backoffice_state.pg_webauthn_service` (webauthn_v1.py): Postgres+Redis
    backed (asyncpg pool + RedisWebAuthnChallengeStore). No live Postgres
    offline. `_FakePgWebAuthnFacade` wraps the REAL legacy in-memory
    `yashigani.auth.webauthn.WebAuthnService` (sync) with an async shim so
    begin_registration/begin_authentication/list_credentials/
    delete_credential are genuinely exercised (real py-webauthn options
    generation, real in-memory credential store). complete_registration/
    complete_authentication are NOT wired to a real verifier — a signed FIDO2
    assertion cannot be constructed without a hardware/software authenticator
    (checked: `python3 -c "import webauthn; print(dir(webauthn))"` — py-webauthn
    ships no virtual/test authenticator helper). Those two paths are exercised
    against the REAL `yashigani.auth.webauthn.WebAuthnService` directly in the
    webauthn.py (legacy) section instead, where calling complete_* without a
    prior begin_* call deterministically raises the same ValueError a bad/
    replayed assertion would (genuine code path, not a stub).
  - SSO IdP handshakes (sso.py): OIDC token exchange and SAML assertion
    parsing require a live external IdP. NOT covered — documented per-test
    below with the exact reason.

FINDING (webauthn.py wiring gap — flagged in final report, not silently
"fixed"): `_get_service()` at webauthn.py:280 reads
`backoffice_state.webauthn_service` (the deprecated v0.9.0 in-memory
service). The real app lifespan (`backoffice/app.py:454-466`) only ever
populates `backoffice_state.pg_webauthn_service` (the v2.23.3 Postgres-backed
service used by webauthn_v1.py). `webauthn_service` is NEVER set at startup —
so all six `/auth/webauthn/*` + `/admin/settings/webauthn/credentials*`
routes permanently 503 `webauthn_not_configured` in production. This is
asserted below as the REAL baseline behaviour; a second set of tests wires
the (real, but production-dead) legacy service directly to prove the route
logic itself is sound — the divergence is a wiring gap in app.py, not a bug
in webauthn.py.

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

import contextlib
import time

import pytest

pytestmark = pytest.mark.conformance

_GROUP_PREFIXES = ("/auth", "/admin/settings/webauthn", "/api/v1/admin/webauthn")


# ---------------------------------------------------------------------------
# Route-completeness check (this IS the coverage gate for this group)
# ---------------------------------------------------------------------------


def test_group_covers_all_declared_routes(route_prefix_filter):
    declared = route_prefix_filter(*_GROUP_PREFIXES)
    declared_set = {(m, p) for (m, p, _r) in declared}
    assert len(declared_set) == 43, (
        f"Expected 43 declared routes under {_GROUP_PREFIXES}, found "
        f"{len(declared_set)}: {sorted(declared_set)}"
    )


# ---------------------------------------------------------------------------
# Shared helpers (not fixtures — plain functions used by fixtures/tests)
# ---------------------------------------------------------------------------


def _current_totp_code(secret: str, algorithm: str, digits: int) -> str:
    """Compute a currently-valid TOTP code for `secret` (real RFC 6238 math)."""
    from yashigani.auth.totp import _totp_at

    return _totp_at(secret, int(time.time()), algorithm, digits)


def _seed_provisioned_account(
    fake_auth_service,
    *,
    account_id: str,
    username: str,
    tier: str = "admin",
):
    """Insert a fully-provisioned (password + TOTP enrolled) AccountRecord
    directly into the fake auth service's in-memory store, keyed to a
    caller-chosen `account_id` so it lines up with a conftest session
    fixture's fixed account_id (conftest's admin_client/user_client/
    stepup_admin_client sessions carry hardcoded account_ids that
    LocalAuthService.create_admin()/create_user() cannot produce — they
    always mint a fresh uuid4). Returns (record, plaintext_password,
    totp_secret)."""
    from yashigani.auth.local_auth import AccountRecord
    from yashigani.auth.password import generate_password, hash_password
    from yashigani.auth.totp import (
        ROLE_TOTP_ALGO,
        ROLE_TOTP_DIGITS,
        generate_provisioning,
        generate_recovery_code_set,
    )

    password = generate_password(36)
    algo = ROLE_TOTP_ALGO.get(tier, "SHA256")
    digits = ROLE_TOTP_DIGITS.get(tier, 6)
    prov = generate_provisioning(account_name=username, algorithm=algo, digits=digits)
    codes = generate_recovery_code_set(prov.recovery_codes)
    record = AccountRecord(
        account_id=account_id,
        username=username,
        password_hash=hash_password(password, check_breach=False),
        totp_secret=prov.secret_b32,
        recovery_codes=codes,
        account_tier=tier,
        email=username,
        force_password_change=False,
        force_totp_provision=False,
        totp_algorithm=algo,
    )
    fake_auth_service._svc._accounts[username] = record
    return record, password, prov.secret_b32


# ---------------------------------------------------------------------------
# auth_service — MOCKED (see module docstring)
# ---------------------------------------------------------------------------


class _FakeAsyncAuthService:
    """MOCKED: async facade over the REAL in-memory LocalAuthService — see
    module docstring for the full rationale. Implements only the methods
    auth.py's routes actually call (verified via
    `grep -n "await .*auth_service\\." auth.py`): authenticate, get_account,
    get_account_by_id, provision_totp_start, provision_totp_confirm,
    force_totp_reprovision, _verify_totp_with_replay."""

    def __init__(self) -> None:
        from yashigani.auth.local_auth import LocalAuthService

        self._svc = LocalAuthService()

    async def authenticate(self, username, password, totp_code, *, audit_writer=None):
        return self._svc.authenticate(username, password, totp_code)

    async def get_account(self, username):
        return self._svc._accounts.get(username)

    async def get_account_by_id(self, account_id):
        for rec in self._svc._accounts.values():
            if rec.account_id == account_id:
                return rec
        return None

    async def provision_totp_start(self, username):
        return self._svc.provision_totp_start(username)

    async def provision_totp_confirm(self, username, totp_code):
        return self._svc.provision_totp_confirm(username, totp_code)

    async def force_totp_reprovision(self, username):
        record = self._svc._accounts.get(username)
        if record is None:
            return False
        record.totp_secret = ""
        record.recovery_codes = None
        record.force_totp_provision = True
        record.totp_algorithm = "SHA1"
        return True

    async def _verify_totp_with_replay(self, conn, secret_b32, totp_code, algorithm="SHA1", digits=6):
        from yashigani.auth.totp import verify_totp

        return verify_totp(secret_b32, totp_code, self._svc._used_totp_codes, algorithm=algorithm, digits=digits)


@pytest.fixture
def fake_auth_service(session_store, mock_audit_writer, monkeypatch):
    """Wires `_FakeAsyncAuthService` into `backoffice_state.auth_service`.
    Depends on `session_store` because auth.py's throttle helpers
    (`_get_throttle_redis`) read `backoffice_state.session_store._redis`.
    Depends on `mock_audit_writer` because every auth.py route that touches
    `auth_service` also unconditionally asserts `state.audit_writer is not
    None` (`assert state.audit_writer is not None # set unconditionally at
    startup`) before doing any work — the two are wired together at real
    startup and this fixture mirrors that pairing."""
    from yashigani.backoffice.state import backoffice_state

    svc = _FakeAsyncAuthService()
    monkeypatch.setattr(backoffice_state, "auth_service", svc, raising=False)
    return svc


class _FakeConn:
    """MOCKED: stands in for an asyncpg Connection acquired via
    `yashigani.db.postgres.tenant_transaction` inside auth.py's
    `_pg_tenant_transaction()` wrapper — no live Postgres offline.
    Implements only fetch/fetchrow/execute, the exact surface
    change_password()/self_service_password_reset() touch."""

    def __init__(self, history_rows: list[dict] | None = None) -> None:
        self._history_rows = history_rows or []
        self.executed: list[tuple] = []

    async def fetch(self, query, *args):
        return self._history_rows

    async def fetchrow(self, query, *args):
        return None

    async def execute(self, query, *args):
        self.executed.append((query, args))
        return "OK"


@pytest.fixture
def pg_stub_factory(monkeypatch):
    """Factory fixture: `pg_stub_factory(history_rows=[...])` replaces
    auth.py's `_pg_tenant_transaction()` with a fake async context manager
    yielding a `_FakeConn`, and returns that `_FakeConn` for assertion."""
    from yashigani.backoffice.routes import auth as auth_routes

    def _make(history_rows=None):
        conn = _FakeConn(history_rows)

        @contextlib.asynccontextmanager
        async def _cm():
            yield conn

        monkeypatch.setattr(auth_routes, "_pg_tenant_transaction", lambda: _cm())
        return conn

    return _make


@pytest.fixture
def pg_tenant_transaction_stub(pg_stub_factory):
    """Default (empty password-history) fake Postgres transaction."""
    return pg_stub_factory()


@pytest.fixture
def caddy_hmac_secret_file(monkeypatch):
    """MOCKED: issue_operator_token()/verify_operator_token() hardcode
    `open('/run/secrets/caddy_internal_hmac')` with no env-var override
    (unlike stepup.py's `_load_signing_key`, which honours
    YASHIGANI_STEPUP_SIGNING_KEY). Intercepts ONLY that exact path so the
    mint+verify round-trip is genuinely testable offline; every other path
    falls through to the real builtins.open."""
    import builtins
    import io

    real_open = builtins.open
    secret_value = "test-operator-token-hmac-secret-0123456789abcdef"

    def _fake_open(file, *args, **kwargs):
        if file == "/run/secrets/caddy_internal_hmac":
            return io.StringIO(secret_value)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _fake_open)
    return secret_value


@pytest.fixture
def stepup_signing_key_env(monkeypatch):
    """mint_stepup_proof()'s `_load_signing_key()` honours
    YASHIGANI_STEPUP_SIGNING_KEY directly — no file interception needed."""
    monkeypatch.setenv("YASHIGANI_STEPUP_SIGNING_KEY", "test-stepup-proof-signing-key")
    return "test-stepup-proof-signing-key"


# ---------------------------------------------------------------------------
# auth.py — /auth/login
# ---------------------------------------------------------------------------


class TestAuthLogin:
    # GAP-CLOSED: POST /auth/login
    def test_malformed_body_422(self, unauth_client):
        r = unauth_client.post("/auth/login", json={"username": "x"})
        assert r.status_code == 422

    def test_unknown_username_401(self, unauth_client, fake_auth_service):
        r = unauth_client.post(
            "/auth/login",
            json={"username": "nobody@example.com", "password": "wrongwrongwrong", "totp_code": "123456"},
            headers={"X-Real-Ip": "10.10.10.1"},
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "invalid_credentials"

    def test_wrong_password_401(self, unauth_client, fake_auth_service):
        from yashigani.auth.password import generate_password

        fake_auth_service._svc.create_admin(
            "wrongpw-admin@example.com", auto_generate=False, plaintext_password=generate_password(36)
        )
        r = unauth_client.post(
            "/auth/login",
            json={"username": "wrongpw-admin@example.com", "password": "definitely-not-it-1234567890", "totp_code": "123456"},
            headers={"X-Real-Ip": "10.10.10.2"},
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "invalid_credentials"

    def test_fresh_account_requires_totp_provisioning(self, unauth_client, fake_auth_service):
        password = "a-genuinely-random-password-value-1"
        from yashigani.auth.password import generate_password

        password = generate_password(36)
        fake_auth_service._svc.create_admin(
            "fresh-admin@example.com", auto_generate=False, plaintext_password=password
        )
        r = unauth_client.post(
            "/auth/login",
            json={"username": "fresh-admin@example.com", "password": password, "totp_code": "123456"},
            headers={"X-Real-Ip": "10.10.10.3"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "totp_provision_required"
        assert body["force_totp_provision"] is True
        assert "__Host-yashigani_session" in r.cookies

    def test_full_login_success(self, unauth_client, fake_auth_service):
        from yashigani.auth.totp import ROLE_TOTP_ALGO, ROLE_TOTP_DIGITS

        password = _create_and_provision_admin(fake_auth_service, "success-admin@example.com")
        secret = fake_auth_service._svc._accounts["success-admin@example.com"].totp_secret
        code = _current_totp_code(secret, ROLE_TOTP_ALGO["admin"], ROLE_TOTP_DIGITS["admin"])
        r = unauth_client.post(
            "/auth/login",
            json={"username": "success-admin@example.com", "password": password, "totp_code": code},
            headers={"X-Real-Ip": "10.10.10.4"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["redirect_to"] == "/admin/"
        assert "__Host-yashigani_admin_session" in r.cookies

    def test_ip_blocklist_403(self, unauth_client, fake_auth_service, fake_redis_client):
        fake_redis_client.set("auth:blocked:10.10.10.9", "manual-block")
        r = unauth_client.post(
            "/auth/login",
            json={"username": "x@example.com", "password": "whatever-not-real-12345678", "totp_code": "123456"},
            headers={"X-Real-Ip": "10.10.10.9"},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "ip_blocked"

    def test_ip_not_in_allowlist_403(self, unauth_client, fake_auth_service, fake_redis_client):
        fake_redis_client.sadd("auth:allowlist", "192.168.99.0/24")
        r = unauth_client.post(
            "/auth/login",
            json={"username": "x@example.com", "password": "whatever-not-real-12345678", "totp_code": "123456"},
            headers={"X-Real-Ip": "10.10.10.10"},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "ip_not_allowed"

    def test_brute_force_throttle_429_on_4th_attempt(self, unauth_client, fake_auth_service):
        """SPEC-CONFORMANCE / regression guard (LAURA-412-CRITICAL/HIGH):
        the account-gated atomic-admit throttle allows exactly 3 genuine
        attempts through to real auth before gating the 4th — see auth.py
        module docstring `_apply_auth_throttle`/`_throttle_admit`. Same
        client IP across all 4 attempts so the IP-severity bucket does not
        confound the account-gate assertion."""
        from yashigani.auth.password import generate_password

        password = generate_password(36)
        fake_auth_service._svc.create_admin(
            "throttle-admin@example.com", auto_generate=False, plaintext_password=password
        )
        headers = {"X-Real-Ip": "10.10.10.20"}
        body = {"username": "throttle-admin@example.com", "password": "wrong-wrong-wrong-1234567890", "totp_code": "123456"}
        codes = []
        for _ in range(3):
            r = unauth_client.post("/auth/login", json=body, headers=headers)
            codes.append(r.status_code)
        assert codes == [401, 401, 401], "first 3 attempts must still reach real auth (401), not be pre-gated"
        r4 = unauth_client.post("/auth/login", json=body, headers=headers)
        assert r4.status_code == 429
        assert r4.json()["detail"]["error"] == "too_many_requests"
        assert "Retry-After" in r4.headers


def _create_and_provision_admin(fake_auth_service, username: str) -> str:
    """Create an admin account and mark TOTP enrolment complete, returning
    the plaintext password. Uses the REAL LocalAuthService for account
    creation + REAL totp module for the seed. Deliberately does NOT drive
    this through `provision_totp_confirm()` (that flow — including its own
    TOTP verification — is exercised directly in
    TestAuthTotpProvisionSplit/TestAuthTotpProvisionAtomic): consuming a
    code here would claim that 30s window's replay-cache slot on the
    account's `_used_totp_codes` set, making a caller-computed code for the
    SAME window at login (milliseconds later) a genuine replay rejection —
    RFC 6238 replay protection working correctly, not a bug, but it would
    make this login-focused fixture flaky/wrong for what it's testing."""
    from yashigani.auth.password import generate_password

    password = generate_password(36)
    svc = fake_auth_service._svc
    svc.create_admin(username, auto_generate=False, plaintext_password=password)
    _prov, _codes = svc.provision_totp_start(username)
    record = svc._accounts[username]
    record.force_totp_provision = False
    # create_admin() always sets force_password_change=True (local_auth.py) —
    # clear it too so the login test exercises the "ok" success path rather
    # than the (separately-relevant) admin_password_change_required branch.
    record.force_password_change = False
    return password


# ---------------------------------------------------------------------------
# auth.py — /auth/logout, /auth/logout-redirect, /auth/status
# ---------------------------------------------------------------------------


class TestAuthLogout:
    # GAP-CLOSED: POST /auth/logout
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/auth/logout")
        assert r.status_code == 401

    def test_admin_logout_clears_session(self, admin_client, session_store):
        r = admin_client.post("/auth/logout")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}
        assert session_store.get(admin_client.conformance_session.token) is None

    def test_user_tier_logout_allowed(self, user_client, session_store):
        """Phase 1 regression guard: user-tier sessions must NOT 403 here
        (the historic 'no end-user logout' bug — AnySession, not AdminSession)."""
        r = user_client.post("/auth/logout")
        assert r.status_code == 200


class TestAuthLogoutRedirect:
    # GAP-CLOSED: GET /auth/logout-redirect
    def test_no_session_redirects_to_login(self, unauth_client):
        r = unauth_client.get("/auth/logout-redirect", follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/login"

    def test_with_admin_session_invalidates_and_redirects(self, admin_client, session_store):
        r = admin_client.get("/auth/logout-redirect", follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/login"
        assert session_store.get(admin_client.conformance_session.token) is None


class TestAuthStatus:
    # GAP-CLOSED: GET /auth/status
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/auth/status").status_code == 401

    def test_user_tier_403(self, user_client):
        r = user_client.get("/auth/status")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "insufficient_tier"

    def test_admin_200(self, admin_client):
        r = admin_client.get("/auth/status")
        assert r.status_code == 200
        body = r.json()
        assert body["account_id"] == "conformance-admin1"
        assert body["account_tier"] == "admin"


# ---------------------------------------------------------------------------
# auth.py — /auth/password/self-reset
# ---------------------------------------------------------------------------


class TestAuthPasswordSelfReset:
    # GAP-CLOSED: POST /auth/password/self-reset
    def test_unknown_username_401(self, unauth_client, fake_auth_service, pg_tenant_transaction_stub):
        r = unauth_client.post(
            "/auth/password/self-reset", json={"username": "no-such-user@example.com", "totp_code": "123456"}
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "invalid_credentials"

    def test_valid_totp_issues_temp_password(self, unauth_client, fake_auth_service, pg_tenant_transaction_stub, session_store):
        from yashigani.auth.totp import ROLE_TOTP_ALGO, ROLE_TOTP_DIGITS

        _create_and_provision_admin(fake_auth_service, "selfreset-admin@example.com")
        secret = fake_auth_service._svc._accounts["selfreset-admin@example.com"].totp_secret
        code = _current_totp_code(secret, ROLE_TOTP_ALGO["admin"], ROLE_TOTP_DIGITS["admin"])
        r = unauth_client.post(
            "/auth/password/self-reset",
            json={"username": "selfreset-admin@example.com", "totp_code": code},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert len(body["temporary_password"]) >= 36
        assert body["force_password_change"] is True

    def test_wrong_totp_401(self, unauth_client, fake_auth_service, pg_tenant_transaction_stub):
        _create_and_provision_admin(fake_auth_service, "selfreset-badotp@example.com")
        r = unauth_client.post(
            "/auth/password/self-reset",
            json={"username": "selfreset-badotp@example.com", "totp_code": "000000"},
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "invalid_credentials"


# ---------------------------------------------------------------------------
# auth.py — /auth/verify, /auth/verify-admin, /auth/verify-user
# ---------------------------------------------------------------------------


class TestAuthVerify:
    # GAP-CLOSED: GET /auth/verify
    def test_no_cookie_401(self, unauth_client, fake_auth_service):
        assert unauth_client.get("/auth/verify").status_code == 401

    def test_admin_session_rejected_403(self, admin_client, fake_auth_service):
        """SoD-003: admin sessions must never traverse the data plane."""
        _seed_provisioned_account(fake_auth_service, account_id="conformance-admin1", username="verify-admin@example.com")
        r = admin_client.get("/auth/verify")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "admin_session_not_allowed_data_plane"

    def test_user_session_200(self, user_client, fake_auth_service):
        _seed_provisioned_account(fake_auth_service, account_id="conformance-userA", username="verify-user@example.com", tier="user")
        r = user_client.get("/auth/verify")
        assert r.status_code == 200
        assert r.headers["X-Forwarded-User"] == "verify-user@example.com"


class TestAuthVerifyAdmin:
    # GAP-CLOSED: GET /auth/verify-admin
    def test_no_cookie_401(self, unauth_client, fake_auth_service):
        assert unauth_client.get("/auth/verify-admin").status_code == 401

    def test_user_session_401_no_admin_cookie_presented(self, user_client, fake_auth_service):
        """SPEC-CONFORMANCE: verify_admin_session() reads ONLY the admin
        cookie name (`_SESSION_COOKIE`) — never falls back to the user
        cookie. `user_client` (per conftest.py) sets ONLY the user cookie,
        so no admin-cookie token is presented at all: this is a 401
        (`no token`), not a 403 (`wrong tier`) — the tier-mismatch branch is
        only reached when an admin-cookie-shaped token IS presented but
        resolves to a non-admin session, which cannot happen via the
        cookie-name split itself."""
        r = user_client.get("/auth/verify-admin")
        assert r.status_code == 401

    def test_admin_session_200(self, admin_client, fake_auth_service):
        _seed_provisioned_account(fake_auth_service, account_id="conformance-admin1", username="verifyadmin-ok@example.com")
        r = admin_client.get("/auth/verify-admin")
        assert r.status_code == 200
        assert r.headers["X-Forwarded-User"] == "verifyadmin-ok@example.com"


class TestAuthVerifyUser:
    # GAP-CLOSED: GET /auth/verify-user
    def test_no_cookie_401(self, unauth_client, fake_auth_service):
        assert unauth_client.get("/auth/verify-user").status_code == 401

    def test_admin_session_403(self, admin_client, fake_auth_service):
        r = admin_client.get("/auth/verify-user")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "admin_session_not_allowed_user_path"

    def test_user_session_no_rbac_owui_gate_200(self, user_client, fake_auth_service):
        """rbac_store is unwired (None) by default in this group's fixtures —
        the OWUI membership gate must skip-allow, never lock everyone out."""
        _seed_provisioned_account(fake_auth_service, account_id="conformance-userA", username="verifyuser-ok@example.com", tier="user")
        r = user_client.get("/auth/verify-user")
        assert r.status_code == 200
        assert r.headers["X-Forwarded-User"] == "verifyuser-ok@example.com"


# ---------------------------------------------------------------------------
# auth.py — /auth/verify-mcp
# ---------------------------------------------------------------------------


class TestAuthVerifyMcp:
    # GAP-CLOSED: GET /auth/verify-mcp
    def test_invalid_target_slug_403(self, unauth_client):
        r = unauth_client.get("/auth/verify-mcp", params={"tenant": "not a slug!", "server": "x"})
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "invalid_target"

    def test_no_spiffe_id_401(self, unauth_client):
        r = unauth_client.get("/auth/verify-mcp", params={"tenant": "default", "server": "langflow"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "no_spiffe_id"

    def test_gateway_subject_envelope_store_unavailable_503(self, unauth_client):
        """No live Postgres offline — CapabilityEnvelopeService construction
        via get_pool() raises RuntimeError, caught and converted to a 503
        deny (fail-closed), never a silent allow."""
        r = unauth_client.get(
            "/auth/verify-mcp",
            params={"tenant": "default", "server": "langflow"},
            headers={"x-spiffe-id": "spiffe://yashigani.internal/gateway"},
        )
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "envelope_store_unavailable"

    def test_backoffice_subject_wrong_server_403(self, unauth_client):
        r = unauth_client.get(
            "/auth/verify-mcp",
            params={"tenant": "default", "server": "not-langflow"},
            headers={"x-spiffe-id": "spiffe://yashigani.internal/backoffice"},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "transport_subject_not_allowed"

    def test_foreign_identity_403(self, unauth_client):
        r = unauth_client.get(
            "/auth/verify-mcp",
            params={"tenant": "default", "server": "langflow"},
            headers={"x-spiffe-id": "spiffe://evil.example/agents/default/x/1"},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "foreign_identity"


# ---------------------------------------------------------------------------
# auth.py — /auth/verify-webhook
# ---------------------------------------------------------------------------


class TestAuthVerifyWebhook:
    # GAP-CLOSED: GET /auth/verify-webhook
    def test_wrong_forwarded_method_401(self, unauth_client):
        r = unauth_client.get(
            "/auth/verify-webhook", params={"provider": "slack"}, headers={"x-forwarded-method": "GET"}
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "method_not_post"

    def test_unknown_provider_401(self, unauth_client):
        r = unauth_client.get(
            "/auth/verify-webhook", params={"provider": "discord"}, headers={"x-forwarded-method": "POST"}
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "unknown_provider"

    def test_slack_missing_timestamp_401(self, unauth_client):
        r = unauth_client.get(
            "/auth/verify-webhook", params={"provider": "slack"}, headers={"x-forwarded-method": "POST"}
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "slack_timestamp_missing"

    def test_slack_stale_timestamp_401(self, unauth_client):
        r = unauth_client.get(
            "/auth/verify-webhook",
            params={"provider": "slack"},
            headers={"x-forwarded-method": "POST", "x-slack-request-timestamp": "1"},
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "slack_timestamp_stale"

    def test_slack_malformed_signature_401(self, unauth_client):
        r = unauth_client.get(
            "/auth/verify-webhook",
            params={"provider": "slack"},
            headers={
                "x-forwarded-method": "POST",
                "x-slack-request-timestamp": str(int(time.time())),
                "x-slack-signature": "not-a-real-sig",
            },
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "slack_signature_malformed"

    def test_slack_replay_dedup_second_call_401(self, unauth_client):
        headers = {
            "x-forwarded-method": "POST",
            "x-slack-request-timestamp": str(int(time.time())),
            "x-slack-signature": "v0=" + "a" * 64,
        }
        r1 = unauth_client.get("/auth/verify-webhook", params={"provider": "slack"}, headers=headers)
        assert r1.status_code == 200
        r2 = unauth_client.get("/auth/verify-webhook", params={"provider": "slack"}, headers=headers)
        assert r2.status_code == 401
        assert r2.json()["detail"]["error"] == "slack_replay_detected"

    def test_telegram_missing_token_401(self, unauth_client):
        r = unauth_client.get(
            "/auth/verify-webhook", params={"provider": "telegram"}, headers={"x-forwarded-method": "POST"}
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "telegram_token_missing"

    def test_telegram_secret_file_unavailable_503(self, unauth_client):
        """Real fail-closed behaviour offline: /run/secrets/openclaw_telegram_webhook_secret
        is not mounted in this test environment."""
        r = unauth_client.get(
            "/auth/verify-webhook",
            params={"provider": "telegram"},
            headers={"x-forwarded-method": "POST", "x-telegram-bot-api-secret-token": "whatever"},
        )
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "telegram_secret_unavailable"


# ---------------------------------------------------------------------------
# auth.py — /auth/password/change
# ---------------------------------------------------------------------------


class TestAuthPasswordChange:
    # GAP-CLOSED: POST /auth/password/change
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/auth/password/change", json={"current_password": "x", "new_password": "y" * 40})
        assert r.status_code == 401

    def test_new_password_too_short_422(self, user_client):
        r = user_client.post("/auth/password/change", json={"current_password": "x", "new_password": "short"})
        assert r.status_code == 422

    def test_wrong_current_password_401(self, user_client, fake_auth_service, pg_tenant_transaction_stub):
        _seed_provisioned_account(fake_auth_service, account_id="conformance-userA", username="pwchange-user@example.com", tier="user")
        from yashigani.auth.password import generate_password

        r = user_client.post(
            "/auth/password/change",
            json={"current_password": "definitely-wrong-value-here", "new_password": generate_password(36)},
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "invalid_current_password"

    def test_success_invalidates_sessions(self, user_client, fake_auth_service, pg_tenant_transaction_stub, session_store):
        from yashigani.auth.password import generate_password

        _record, current_password, _secret = _seed_provisioned_account(
            fake_auth_service, account_id="conformance-userA", username="pwchange-ok@example.com", tier="user"
        )
        r = user_client.post(
            "/auth/password/change",
            json={"current_password": current_password, "new_password": generate_password(36)},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["sessions_invalidated"] is True
        assert session_store.get(user_client.conformance_session.token) is None

    def test_password_reuse_rejected_422(self, user_client, fake_auth_service, pg_stub_factory):
        from yashigani.auth.password import generate_password, hash_password

        _record, current_password, _secret = _seed_provisioned_account(
            fake_auth_service, account_id="conformance-userA", username="pwchange-reuse@example.com", tier="user"
        )
        reused_password = generate_password(36)
        pg_stub_factory(history_rows=[{"password_hash": hash_password(reused_password, check_breach=False)}])
        r = user_client.post(
            "/auth/password/change",
            json={"current_password": current_password, "new_password": reused_password},
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "password_reuse"


# ---------------------------------------------------------------------------
# auth.py — /auth/totp/provision/start, /confirm, and atomic /provision
# ---------------------------------------------------------------------------


class TestAuthTotpProvisionSplit:
    # GAP-CLOSED: POST /auth/totp/provision/start
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/auth/totp/provision/start").status_code == 401

    def test_start_returns_seed(self, user_client, fake_auth_service):
        from yashigani.auth.local_auth import AccountRecord
        from yashigani.auth.password import generate_password, hash_password

        record = AccountRecord(
            account_id="conformance-userA",
            username="totpstart-user@example.com",
            password_hash=hash_password(generate_password(36), check_breach=False),
            totp_secret="",
            recovery_codes=None,
            account_tier="user",
            force_totp_provision=True,
        )
        fake_auth_service._svc._accounts["totpstart-user@example.com"] = record
        r = user_client.post("/auth/totp/provision/start")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "pending_confirmation"
        assert body["totp_algorithm"] == "SHA256"
        assert body["totp_digits"] == 6

    # GAP-CLOSED: POST /auth/totp/provision/confirm
    def test_confirm_unauth_401(self, unauth_client):
        assert unauth_client.post("/auth/totp/provision/confirm", json={"totp_code": "123456"}).status_code == 401

    def test_confirm_wrong_code_400(self, user_client, fake_auth_service):
        from yashigani.auth.local_auth import AccountRecord
        from yashigani.auth.password import generate_password, hash_password

        fake_auth_service._svc._accounts["totpconfirm-user@example.com"] = AccountRecord(
            account_id="conformance-userA",
            username="totpconfirm-user@example.com",
            password_hash=hash_password(generate_password(36), check_breach=False),
            totp_secret="",
            recovery_codes=None,
            account_tier="user",
            force_totp_provision=True,
        )
        fake_auth_service._svc.provision_totp_start("totpconfirm-user@example.com")
        r = user_client.post("/auth/totp/provision/confirm", json={"totp_code": "000000"})
        assert r.status_code == 400

    def test_confirm_success(self, user_client, fake_auth_service):
        from yashigani.auth.local_auth import AccountRecord
        from yashigani.auth.password import generate_password, hash_password
        from yashigani.auth.totp import ROLE_TOTP_ALGO, ROLE_TOTP_DIGITS

        fake_auth_service._svc._accounts["totpconfirm-ok@example.com"] = AccountRecord(
            account_id="conformance-userA",
            username="totpconfirm-ok@example.com",
            password_hash=hash_password(generate_password(36), check_breach=False),
            totp_secret="",
            recovery_codes=None,
            account_tier="user",
            force_totp_provision=True,
        )
        prov, _codes = fake_auth_service._svc.provision_totp_start("totpconfirm-ok@example.com")
        code = _current_totp_code(prov.secret_b32, ROLE_TOTP_ALGO["user"], ROLE_TOTP_DIGITS["user"])
        r = user_client.post("/auth/totp/provision/confirm", json={"totp_code": code})
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestAuthTotpProvisionAtomic:
    # GAP-CLOSED: POST /auth/totp/provision (back-compat atomic)
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/auth/totp/provision", json={"totp_code": "123456"}).status_code == 401

    def test_wrong_code_rolls_back_400(self, user_client, fake_auth_service):
        from yashigani.auth.local_auth import AccountRecord
        from yashigani.auth.password import generate_password, hash_password

        fake_auth_service._svc._accounts["totpatomic-user@example.com"] = AccountRecord(
            account_id="conformance-userA",
            username="totpatomic-user@example.com",
            password_hash=hash_password(generate_password(36), check_breach=False),
            totp_secret="",
            recovery_codes=None,
            account_tier="user",
            force_totp_provision=True,
        )
        r = user_client.post("/auth/totp/provision", json={"totp_code": "000000"})
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_totp_code"


# ---------------------------------------------------------------------------
# auth.py — /auth/stepup
# ---------------------------------------------------------------------------


class TestAuthStepup:
    # GAP-CLOSED: POST /auth/stepup
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/auth/stepup", json={"totp_code": "123456"}).status_code == 401

    def test_no_matching_account_403(self, admin_client, fake_auth_service):
        r = admin_client.post("/auth/stepup", json={"totp_code": "123456"})
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "totp_not_configured"

    def test_wrong_code_401(self, admin_client, fake_auth_service, pg_tenant_transaction_stub):
        _seed_provisioned_account(fake_auth_service, account_id="conformance-admin1", username="stepup-wrong@example.com")
        r = admin_client.post("/auth/stepup", json={"totp_code": "000000"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "invalid_totp_code"

    def test_correct_code_200(self, admin_client, fake_auth_service, pg_tenant_transaction_stub):
        from yashigani.auth.totp import ROLE_TOTP_ALGO, ROLE_TOTP_DIGITS

        _record, _pw, secret = _seed_provisioned_account(
            fake_auth_service, account_id="conformance-admin1", username="stepup-ok@example.com"
        )
        code = _current_totp_code(secret, ROLE_TOTP_ALGO["admin"], ROLE_TOTP_DIGITS["admin"])
        r = admin_client.post("/auth/stepup", json={"totp_code": code})
        assert r.status_code == 200
        assert r.json()["stepup_verified"] is True


# ---------------------------------------------------------------------------
# auth.py — /auth/operator-token, /auth/operator-token/verify
# ---------------------------------------------------------------------------


class TestAuthOperatorToken:
    # GAP-CLOSED: POST /auth/operator-token
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/auth/operator-token", json={}).status_code == 401

    def test_without_stepup_401(self, admin_client):
        r = admin_client.post("/auth/operator-token", json={})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_signing_key_unavailable_500(self, stepup_admin_client, fake_auth_service):
        """Baseline offline behaviour: /run/secrets/caddy_internal_hmac is not
        mounted — fail-closed 500, never a silently-unsigned token."""
        _seed_provisioned_account(fake_auth_service, account_id="conformance-admin-stepup", username="optoken-nosecret@example.com")
        r = stepup_admin_client.post("/auth/operator-token", json={})
        assert r.status_code == 500
        assert r.json()["detail"]["error"] == "signing_key_unavailable"

    def test_mint_and_verify_roundtrip(self, stepup_admin_client, fake_auth_service, caddy_hmac_secret_file):
        _seed_provisioned_account(fake_auth_service, account_id="conformance-admin-stepup", username="optoken-ok@example.com")
        r = stepup_admin_client.post("/auth/operator-token", json={"issued_for": "test-agent"})
        assert r.status_code == 200
        body = r.json()
        assert body["token_type"] == "Bearer"
        token = body["token"]

        # GAP-CLOSED: GET /auth/operator-token/verify
        r2 = unauth_client_placeholder_call(stepup_admin_client, token)
        assert r2.status_code == 200
        assert r2.json()["sub"] == "optoken-ok@example.com"

    def test_verify_missing_bearer_400(self, unauth_client):
        r = unauth_client.get("/auth/operator-token/verify")
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "missing_bearer_token"

    def test_verify_invalid_token_401(self, unauth_client, caddy_hmac_secret_file):
        r = unauth_client.get("/auth/operator-token/verify", headers={"Authorization": "Bearer not-a-real-jwt"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "invalid_token"


def unauth_client_placeholder_call(client, token: str):
    """GET /auth/operator-token/verify does not require a session — reuse any
    client's underlying TestClient transport (no cookies matter here)."""
    return client.get("/auth/operator-token/verify", headers={"Authorization": f"Bearer {token}"})


# ---------------------------------------------------------------------------
# auth.py — /auth/stepup-proof
# ---------------------------------------------------------------------------


class TestAuthStepupProof:
    # GAP-CLOSED: POST /auth/stepup-proof
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/auth/stepup-proof", json={"op": "add-component"}).status_code == 401

    def test_without_stepup_401(self, admin_client):
        r = admin_client.post("/auth/stepup-proof", json={"op": "add-component"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_invalid_op_pattern_422(self, stepup_admin_client):
        r = stepup_admin_client.post("/auth/stepup-proof", json={"op": "Add Component!"})
        assert r.status_code == 422

    def test_mint_success(self, stepup_admin_client, fake_auth_service, stepup_signing_key_env):
        _seed_provisioned_account(fake_auth_service, account_id="conformance-admin-stepup", username="stepupproof-ok@example.com")
        r = stepup_admin_client.post("/auth/stepup-proof", json={"op": "add-component"})
        assert r.status_code == 200
        body = r.json()
        assert body["op"] == "add-component"
        assert body["purpose"] == "privileged-mutation"


# ---------------------------------------------------------------------------
# auth.py — /auth/onboard-event
# ---------------------------------------------------------------------------


class TestAuthOnboardEvent:
    # GAP-CLOSED: POST /auth/onboard-event
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post(
            "/auth/onboard-event",
            json={"identity_quality": "weak", "agent_name": "a", "agent_url": "http://x"},
        ).status_code == 401

    def test_invalid_identity_quality_422(self, admin_client):
        r = admin_client.post(
            "/auth/onboard-event",
            json={"identity_quality": "bogus", "agent_name": "a", "agent_url": "http://x"},
        )
        assert r.status_code == 422

    def test_admin_success(self, admin_client, mock_audit_writer):
        r = admin_client.post(
            "/auth/onboard-event",
            json={"identity_quality": "attested", "agent_name": "my-agent", "agent_url": "http://agent.local"},
        )
        assert r.status_code == 200
        assert r.json()["identity_quality"] == "attested"
        mock_audit_writer.write.assert_called_once()


# ---------------------------------------------------------------------------
# auth.py — /auth/blocked-ips, /auth/blocked-ips/{ip}
# ---------------------------------------------------------------------------


class TestAuthBlockedIps:
    # GAP-CLOSED: GET /auth/blocked-ips
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/auth/blocked-ips").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/auth/blocked-ips").status_code == 403

    def test_admin_lists_blocked_and_throttled(self, admin_client, fake_redis_client):
        fake_redis_client.set("auth:blocked:1.2.3.4", '{"reason": "manual"}')
        fake_redis_client.set("auth:throttle:ip:5.6.7.8", "2")
        r = admin_client.get("/auth/blocked-ips")
        assert r.status_code == 200
        body = r.json()
        assert "1.2.3.4" in body["blocked_ips"]
        assert "5.6.7.8" in body["throttled_ips"]
        assert body["throttled_ips"]["5.6.7.8"]["level"] == 2

    # GAP-CLOSED: DELETE /auth/blocked-ips/{ip}
    def test_unblock_unauth_401(self, unauth_client):
        assert unauth_client.delete("/auth/blocked-ips/1.2.3.4").status_code == 401

    def test_unblock_not_found_404(self, admin_client):
        r = admin_client.delete("/auth/blocked-ips/9.9.9.9")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "ip_not_found"

    def test_unblock_success(self, admin_client, fake_redis_client):
        fake_redis_client.set("auth:blocked:1.2.3.5", "x")
        r = admin_client.delete("/auth/blocked-ips/1.2.3.5")
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "unblocked": "1.2.3.5"}


# ---------------------------------------------------------------------------
# auth.py — /auth/allowed-ips
# ---------------------------------------------------------------------------


class TestAuthAllowedIps:
    # GAP-CLOSED: GET /auth/allowed-ips
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/auth/allowed-ips").status_code == 401

    def test_admin_empty_open_mode(self, admin_client):
        r = admin_client.get("/auth/allowed-ips")
        assert r.status_code == 200
        assert r.json()["mode"] == "open (all IPs permitted)"

    # GAP-CLOSED: POST /auth/allowed-ips
    def test_add_unauth_401(self, unauth_client):
        assert unauth_client.post("/auth/allowed-ips", json={"ip": "1.2.3.4"}).status_code == 401

    def test_add_invalid_ip_400(self, admin_client):
        r = admin_client.post("/auth/allowed-ips", json={"ip": "not-an-ip"})
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_ip"

    def test_add_valid_ip_then_list(self, admin_client):
        r = admin_client.post("/auth/allowed-ips", json={"ip": "203.0.113.5"})
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "added": "203.0.113.5"}
        r2 = admin_client.get("/auth/allowed-ips")
        assert "203.0.113.5" in r2.json()["allowed_ips"]
        assert r2.json()["mode"] == "restrict"

    # GAP-CLOSED: DELETE /auth/allowed-ips/{ip_or_cidr}
    def test_remove_unauth_401(self, unauth_client):
        assert unauth_client.delete("/auth/allowed-ips/1.2.3.4").status_code == 401

    def test_remove_not_found_404(self, admin_client):
        r = admin_client.delete("/auth/allowed-ips/198.51.100.9")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "entry_not_found"

    def test_remove_success(self, admin_client):
        admin_client.post("/auth/allowed-ips", json={"ip": "198.51.100.10"})
        r = admin_client.delete("/auth/allowed-ips/198.51.100.10")
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "removed": "198.51.100.10"}


# ---------------------------------------------------------------------------
# auth.py — /auth/post-login-redirect
# ---------------------------------------------------------------------------


class TestAuthPostLoginRedirect:
    # GAP-CLOSED: GET /auth/post-login-redirect
    def test_no_session_required_valid_next_redirects(self, unauth_client):
        r = unauth_client.get("/auth/post-login-redirect", params={"next": "/chat"}, follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/chat"

    def test_absolute_url_rejected_redirects_to_root(self, unauth_client, mock_audit_writer):
        r = unauth_client.get(
            "/auth/post-login-redirect", params={"next": "https://evil.example/steal"}, follow_redirects=False
        )
        assert r.status_code == 302
        assert r.headers["location"] == "/"

    def test_protocol_relative_rejected(self, unauth_client):
        r = unauth_client.get("/auth/post-login-redirect", params={"next": "//evil.example"}, follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/"

    def test_empty_next_rejected(self, unauth_client):
        r = unauth_client.get("/auth/post-login-redirect", follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/"


# ---------------------------------------------------------------------------
# sso.py — /auth/sso/select
# ---------------------------------------------------------------------------


@pytest.fixture
def community_licensed(monkeypatch):
    """Explicitly force COMMUNITY (no oidc/saml feature) regardless of
    ambient module-level license state any other conformance group's tests
    may have mutated via `set_license()` in this same pytest session."""
    from yashigani.licensing import enforcer
    from yashigani.licensing.model import COMMUNITY_LICENSE

    monkeypatch.setattr(enforcer, "_license", COMMUNITY_LICENSE)
    return COMMUNITY_LICENSE


@pytest.fixture
def oidc_saml_licensed(monkeypatch):
    """Explicitly force a license with oidc+saml features enabled."""
    import dataclasses

    from yashigani.licensing import enforcer
    from yashigani.licensing.model import COMMUNITY_LICENSE, LicenseFeature

    lic = dataclasses.replace(
        COMMUNITY_LICENSE,
        tier=COMMUNITY_LICENSE.tier,
        features=frozenset({LicenseFeature.OIDC, LicenseFeature.SAML}),
    )
    monkeypatch.setattr(enforcer, "_license", lic)
    return lic


def _make_rsa_sp_private_key_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@pytest.fixture
def sso_broker(monkeypatch):
    """Wires a REAL IdentityBroker with one enabled OIDC IdP (metadata_url
    uses an unsafe http:// scheme so OIDC discovery fails FAST via
    `_assert_safe_discovery_url` — no real network I/O, no slow timeout —
    see sso.py test class docstrings) and one enabled SAML IdP (real RSA SP
    key, generated on the fly; genuinely exercises SAMLProvider.__init__'s
    YSG-RISK-044 RSA-key enforcement)."""
    from yashigani.auth.broker import IdentityBroker, IdPConfig
    from yashigani.backoffice.state import backoffice_state

    broker = IdentityBroker(tier="enterprise")
    broker.add_idp(
        IdPConfig(
            id="test-oidc",
            name="Test OIDC IdP",
            protocol="oidc",
            metadata_url="http://sso.example.com/.well-known/openid-configuration",
            client_id="test-client-id",
            client_secret="test-client-secret",
            enabled=True,
        ),
        redirect_uri="https://yashigani.local/auth/sso/oidc/test-oidc/callback",
    )
    broker.add_idp(
        IdPConfig(
            id="test-saml",
            name="Test SAML IdP",
            protocol="saml",
            entity_id="https://yashigani.local/saml/sp",
            saml_idp_sso_url="https://idp.example.com/sso",
            saml_sp_private_key=_make_rsa_sp_private_key_pem(),
            enabled=True,
        ),
        redirect_uri="https://yashigani.local/auth/sso/saml/test-saml/acs",
    )
    monkeypatch.setattr(backoffice_state, "identity_broker", broker, raising=False)
    return broker


class TestSsoSelect:
    # GAP-CLOSED: GET /auth/sso/select
    def test_no_broker_empty_list(self, unauth_client):
        r = unauth_client.get("/auth/sso/select")
        assert r.status_code == 200
        assert r.json() == {"idps": []}

    def test_with_broker_lists_idps_bopla_stripped(self, unauth_client, sso_broker):
        r = unauth_client.get("/auth/sso/select")
        assert r.status_code == 200
        idps = r.json()["idps"]
        ids = {i["id"] for i in idps}
        assert ids == {"test-oidc", "test-saml"}
        for idp in idps:
            # BOPLA #90 — client_secret/private_key must never be exposed.
            assert "client_secret" not in idp
            assert "sp_private_key" not in idp
            assert "saml_sp_private_key" not in idp


class TestSsoOidcInitiate:
    # GAP-CLOSED: GET /auth/sso/oidc/{idp_id}
    def test_feature_gated_402(self, unauth_client, sso_broker, community_licensed):
        r = unauth_client.get("/auth/sso/oidc/test-oidc", follow_redirects=False)
        assert r.status_code == 402

    def test_idp_not_found_404(self, unauth_client, sso_broker, oidc_saml_licensed):
        r = unauth_client.get("/auth/sso/oidc/nonexistent", follow_redirects=False)
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "idp_not_found"

    def test_wrong_protocol_400(self, unauth_client, sso_broker, oidc_saml_licensed):
        r = unauth_client.get("/auth/sso/oidc/test-saml", follow_redirects=False)
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "idp_not_oidc"

    def test_broker_unavailable_503(self, unauth_client, oidc_saml_licensed):
        r = unauth_client.get("/auth/sso/oidc/anything", follow_redirects=False)
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "identity_broker_unavailable"

    def test_discovery_unsafe_scheme_502(self, unauth_client, sso_broker, oidc_saml_licensed):
        """NOT COVERED beyond this gate: a real OIDC authorization-URL
        redirect requires a genuine HTTPS discovery document from a live
        IdP — no test double is cheap/safe to build without either a real
        network call or reimplementing authlib's OAuth2Session. This test
        instead pins the REAL, fast, offline-safe fail-closed path: an
        http:// (non-https) discovery_url is rejected by
        `OIDCProvider._assert_safe_discovery_url` before any network I/O."""
        r = unauth_client.get("/auth/sso/oidc/test-oidc", follow_redirects=False)
        assert r.status_code == 502
        assert r.json()["detail"]["error"] == "oidc_discovery_failed"


class TestSsoOidcCallback:
    # GAP-CLOSED: GET /auth/sso/oidc/{idp_id}/callback
    def test_idp_error_redirects_to_login(self, unauth_client):
        r = unauth_client.get(
            "/auth/sso/oidc/test-oidc/callback",
            params={"error": "access_denied", "error_description": "user cancelled"},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert "error=sso_failed" in r.headers["location"]

    def test_missing_code_or_state_400(self, unauth_client, sso_broker, oidc_saml_licensed):
        r = unauth_client.get("/auth/sso/oidc/test-oidc/callback", follow_redirects=False)
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "missing_code_or_state"

    def test_feature_gated_402(self, unauth_client, community_licensed):
        r = unauth_client.get(
            "/auth/sso/oidc/test-oidc/callback", params={"code": "abc", "state": "xyz"}, follow_redirects=False
        )
        assert r.status_code == 402

    def test_invalid_or_expired_state_400(self, unauth_client, sso_broker, oidc_saml_licensed):
        """Real CSRF-state check (ASVS V3.5.3): state was never issued via
        the initiate leg, so Redis has no matching sso:state: key.
        NOT COVERED beyond this: the full code-exchange + ID-token-validate
        success path requires a live IdP token endpoint — external
        dependency, no offline test double attempted (would just
        reimplement authlib)."""
        r = unauth_client.get(
            "/auth/sso/oidc/test-oidc/callback",
            params={"code": "abc", "state": "never-issued-state-token"},
            follow_redirects=False,
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_or_expired_state"


class TestSso2fa:
    # GAP-CLOSED: GET /auth/sso/2fa
    def test_no_pending_cookie_redirects_to_login(self, unauth_client):
        r = unauth_client.get("/auth/sso/2fa", follow_redirects=False)
        assert r.status_code == 302
        assert "error=no_pending_sso" in r.headers["location"]

    def test_expired_pending_cookie_redirects(self, unauth_client):
        r = unauth_client.get(
            "/auth/sso/2fa", cookies={"yashigani_sso_pending": "not-a-real-pending-token"}, follow_redirects=False
        )
        assert r.status_code == 302
        assert "error=sso_2fa_expired" in r.headers["location"]


class TestSso2faVerify:
    # GAP-CLOSED: POST /auth/sso/2fa/verify
    def test_no_pending_cookie_401(self, unauth_client):
        r = unauth_client.post("/auth/sso/2fa/verify", json={"totp_code": "123456"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "no_pending_sso_session"

    def test_expired_pending_token_401(self, unauth_client):
        r = unauth_client.post(
            "/auth/sso/2fa/verify",
            json={"totp_code": "123456"},
            cookies={"yashigani_sso_pending": "not-a-real-pending-token"},
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "sso_2fa_expired_or_invalid"

    def test_malformed_totp_code_400(self, unauth_client, fake_redis_client):
        fake_redis_client.set("sso:pending_2fa:realtoken", '{"identity_id": "x"}', ex=300)
        r = unauth_client.post(
            "/auth/sso/2fa/verify",
            json={"totp_code": "abc"},
            cookies={"yashigani_sso_pending": "realtoken"},
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_totp_code_format"

    def test_identity_registry_unavailable_503(self, unauth_client, fake_redis_client):
        fake_redis_client.set("sso:pending_2fa:realtoken2", '{"identity_id": "x"}', ex=300)
        r = unauth_client.post(
            "/auth/sso/2fa/verify",
            json={"totp_code": "123456"},
            cookies={"yashigani_sso_pending": "realtoken2"},
        )
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "identity_registry_unavailable"


class TestSsoSamlAcs:
    # GAP-CLOSED: POST /auth/sso/saml/{idp_id}/acs
    def test_feature_gated_402(self, unauth_client, sso_broker, community_licensed):
        r = unauth_client.post("/auth/sso/saml/test-saml/acs", data={}, follow_redirects=False)
        assert r.status_code == 402

    def test_broker_unavailable_503(self, unauth_client, oidc_saml_licensed):
        r = unauth_client.post("/auth/sso/saml/anything/acs", data={}, follow_redirects=False)
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "identity_broker_unavailable"

    def test_idp_not_found_404(self, unauth_client, sso_broker, oidc_saml_licensed):
        r = unauth_client.post("/auth/sso/saml/nonexistent/acs", data={}, follow_redirects=False)
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "idp_not_found"

    def test_missing_saml_response_400(self, unauth_client, sso_broker, oidc_saml_licensed):
        """NOT COVERED beyond this gate: a genuine signed SAMLResponse
        assertion requires a real IdP (or reimplementing python3-saml's XML
        signing) — external dependency, no test double attempted."""
        r = unauth_client.post("/auth/sso/saml/test-saml/acs", data={"RelayState": "x"}, follow_redirects=False)
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "missing_saml_response"


# ---------------------------------------------------------------------------
# webauthn.py — legacy /auth/webauthn/* + /admin/settings/webauthn/credentials*
#
# FINDING: see module docstring. `backoffice_state.webauthn_service` is NEVER
# populated by the real app lifespan — these 6 routes permanently 503 in
# production. Baseline tests below assert that REAL default (no fixture)
# behaviour first; a second set of tests wires the REAL legacy
# `yashigani.auth.webauthn.WebAuthnService` (sync, in-memory) directly to
# prove the route logic itself is sound.
# ---------------------------------------------------------------------------


@pytest.fixture
def legacy_webauthn_service(monkeypatch):
    from yashigani.auth.webauthn import WebAuthnConfig, WebAuthnService
    from yashigani.backoffice.state import backoffice_state

    svc = WebAuthnService(WebAuthnConfig())
    monkeypatch.setattr(backoffice_state, "webauthn_service", svc, raising=False)
    return svc


class TestWebauthnRegisterBegin:
    # GAP-CLOSED: POST /auth/webauthn/register/begin
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post(
            "/auth/webauthn/register/begin", json={"user_name": "alice"}
        ).status_code == 401

    def test_default_503_wiring_gap(self, admin_client):
        """FINDING (webauthn.py:280 vs app.py:454-466) — see module
        docstring. This is the REAL production behaviour today."""
        r = admin_client.post("/auth/webauthn/register/begin", json={"user_name": "alice"})
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "webauthn_not_configured"

    def test_with_legacy_service_wired_500_dependency_break(self, admin_client, legacy_webauthn_service):
        """FINDING (dependency version break, NOT this test's fault):
        `pyproject.toml` pins `webauthn>=2.1` with no upper bound. The
        installed `webauthn==3.0.0` moved `AuthenticatorSelectionCriteria` /
        `UserVerificationRequirement` / `AttestationConveyancePreference`
        from the top-level `webauthn` module to `webauthn.helpers.structs`.
        `src/yashigani/auth/webauthn.py` `_map_uv()`/`_map_attestation()`/
        `begin_registration()` (lines 185-189, 362-377) still reference the
        old top-level path, so even with the service correctly wired this
        call genuinely 500s today. Asserted here as the REAL current
        behaviour (regression guard), not papered over — see this file's
        module docstring and the final report for the full citation. The
        SAME bug is shared by `pg_webauthn.py` (the PRODUCTION v1 API path,
        see TestWebauthnV1RegisterStart) since it imports these same two
        helpers."""
        r = admin_client.post("/auth/webauthn/register/begin", json={"user_name": "alice"})
        assert r.status_code == 500
        assert r.json()["detail"]["error"] == "webauthn_register_begin_failed"


class TestWebauthnRegisterComplete:
    # GAP-CLOSED: POST /auth/webauthn/register/complete
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post(
            "/auth/webauthn/register/complete", json={"credential_response": {}}
        ).status_code == 401

    def test_default_503(self, admin_client):
        r = admin_client.post("/auth/webauthn/register/complete", json={"credential_response": {}})
        assert r.status_code == 503

    def test_no_pending_challenge_400(self, admin_client, legacy_webauthn_service, mock_audit_writer):
        """Real ValueError path: complete_registration() with no prior
        begin_registration() call for this user_id raises "No pending
        registration challenge" — genuine code, not a stub."""
        r = admin_client.post("/auth/webauthn/register/complete", json={"credential_response": {"id": "x"}})
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "webauthn registration failed"


class TestWebauthnAuthenticateBegin:
    # GAP-CLOSED: POST /auth/webauthn/authenticate/begin
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/auth/webauthn/authenticate/begin").status_code == 401

    def test_default_503(self, admin_client):
        assert admin_client.post("/auth/webauthn/authenticate/begin").status_code == 503

    def test_with_legacy_service_wired_500_dependency_break(self, admin_client, legacy_webauthn_service):
        """FINDING — same webauthn==3.0.0 top-level-attribute break as
        TestWebauthnRegisterBegin (webauthn.py:270, `_map_uv`). Asserts the
        REAL current 500, not the intended 200."""
        r = admin_client.post("/auth/webauthn/authenticate/begin")
        assert r.status_code == 500
        assert r.json()["detail"]["error"] == "webauthn_authenticate_begin_failed"


class TestWebauthnAuthenticateComplete:
    # GAP-CLOSED: POST /auth/webauthn/authenticate/complete
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post(
            "/auth/webauthn/authenticate/complete", json={"credential_response": {}}
        ).status_code == 401

    def test_default_503(self, admin_client):
        r = admin_client.post("/auth/webauthn/authenticate/complete", json={"credential_response": {}})
        assert r.status_code == 503

    def test_no_pending_challenge_401(self, admin_client, legacy_webauthn_service, mock_audit_writer):
        r = admin_client.post("/auth/webauthn/authenticate/complete", json={"credential_response": {"id": "x"}})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "webauthn authentication failed"


class TestWebauthnCredentialsList:
    # GAP-CLOSED: GET /admin/settings/webauthn/credentials
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/settings/webauthn/credentials").status_code == 401

    def test_default_503(self, admin_client):
        assert admin_client.get("/admin/settings/webauthn/credentials").status_code == 503

    def test_with_legacy_service_empty_list(self, admin_client, legacy_webauthn_service):
        r = admin_client.get("/admin/settings/webauthn/credentials")
        assert r.status_code == 200
        assert r.json() == {"credentials": [], "total": 0}


class TestWebauthnCredentialsDelete:
    # GAP-CLOSED: DELETE /admin/settings/webauthn/credentials/{credential_id}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/settings/webauthn/credentials/abc").status_code == 401

    def test_default_503(self, admin_client):
        assert admin_client.delete("/admin/settings/webauthn/credentials/abc").status_code == 503

    def test_with_legacy_service_not_found_404(self, admin_client, legacy_webauthn_service):
        r = admin_client.delete("/admin/settings/webauthn/credentials/does-not-exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "credential_not_found"


# ---------------------------------------------------------------------------
# webauthn_v1.py — /api/v1/admin/webauthn/*
# ---------------------------------------------------------------------------


class _FakePgWebAuthnFacade:
    """MOCKED: async shim over the REAL legacy in-memory WebAuthnService —
    see module docstring. PgWebAuthnService (production) is Postgres+Redis
    backed; no fakeredis/fake-Postgres equivalent for credential storage
    exists offline. complete_registration/complete_authentication
    deliberately raise (no real attestation/assertion can be constructed
    offline — see module docstring)."""

    def __init__(self) -> None:
        from yashigani.auth.webauthn import WebAuthnConfig, WebAuthnService

        self._svc = WebAuthnService(WebAuthnConfig())

    async def begin_registration(self, user_id, user_name):
        return self._svc.begin_registration(user_id=user_id, user_name=user_name)

    async def complete_registration(self, **kwargs):
        raise ValueError("MOCKED facade: no real attestation verifier offline")

    async def begin_authentication(self, user_id):
        return self._svc.begin_authentication(user_id=user_id)

    async def complete_authentication(self, **kwargs):
        raise ValueError("MOCKED facade: no real assertion verifier offline")

    async def list_credentials(self, user_id):
        return self._svc.list_credentials(user_id=user_id)

    async def delete_credential(self, user_id, credential_uuid):
        return self._svc.delete_credential(user_id=user_id, credential_uuid=credential_uuid)


@pytest.fixture
def pg_webauthn_service_fake(monkeypatch):
    from yashigani.backoffice.state import backoffice_state

    svc = _FakePgWebAuthnFacade()
    monkeypatch.setattr(backoffice_state, "pg_webauthn_service", svc, raising=False)
    return svc


class TestWebauthnV1RegisterStart:
    # GAP-CLOSED: POST /api/v1/admin/webauthn/register/start
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post(
            "/api/v1/admin/webauthn/register/start", json={"credential_name": "YubiKey"}
        ).status_code == 401

    def test_default_503(self, admin_client):
        r = admin_client.post("/api/v1/admin/webauthn/register/start", json={"credential_name": "YubiKey"})
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "webauthn_not_configured"

    def test_with_service_wired_500_dependency_break(self, admin_client, pg_webauthn_service_fake):
        """FINDING (production-affecting, see module docstring): the REAL
        `pg_webauthn.py` (production PgWebAuthnService) imports the SAME
        `_map_uv`/`_map_attestation` helpers from `auth/webauthn.py`
        (pg_webauthn.py:39-40) that break under the installed
        `webauthn==3.0.0` (top-level `AuthenticatorSelectionCriteria` /
        `UserVerificationRequirement` moved to `webauthn.helpers.structs`;
        `pyproject.toml` pins `webauthn>=2.1` with no upper bound). This
        means `POST /api/v1/admin/webauthn/register/start` — the PRODUCTION
        FIDO2 registration entrypoint, not dead code — genuinely 500s today
        even when pg_webauthn_service is fully wired with live Postgres.
        Asserted here as the REAL current behaviour, not the intended 200."""
        r = admin_client.post("/api/v1/admin/webauthn/register/start", json={"credential_name": "YubiKey"})
        assert r.status_code == 500
        assert r.json()["detail"]["error"] == "webauthn_register_start_failed"


class TestWebauthnV1RegisterFinish:
    # GAP-CLOSED: POST /api/v1/admin/webauthn/register/finish
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post(
            "/api/v1/admin/webauthn/register/finish", json={"credential_response": {}}
        ).status_code == 401

    def test_default_503(self, admin_client):
        r = admin_client.post("/api/v1/admin/webauthn/register/finish", json={"credential_response": {}})
        assert r.status_code == 503

    def test_verification_failure_400(self, admin_client, pg_webauthn_service_fake, mock_audit_writer):
        r = admin_client.post("/api/v1/admin/webauthn/register/finish", json={"credential_response": {}})
        assert r.status_code == 400


class TestWebauthnV1LoginStart:
    # GAP-CLOSED: POST /api/v1/admin/webauthn/login/start (PUBLIC)
    def test_unknown_username_400(self, unauth_client):
        """NOT COVERED beyond this: `_resolve_admin_id` always fails open to
        None offline (no live Postgres), so the real-credential-exists
        success branch (calling svc.begin_authentication) is unreachable in
        this suite regardless of whether pg_webauthn_service is wired —
        genuine offline limitation, not a stub."""
        r = unauth_client.post("/api/v1/admin/webauthn/login/start", json={"username": "nobody@example.com"})
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "no_credentials_registered"

    def test_ip_blocklist_403(self, unauth_client, fake_redis_client):
        fake_redis_client.set("auth:blocked:10.10.10.30", "x")
        r = unauth_client.post(
            "/api/v1/admin/webauthn/login/start",
            json={"username": "nobody@example.com"},
            headers={"X-Forwarded-For": "10.10.10.30"},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "ip_blocked"


class TestWebauthnV1LoginFinish:
    # GAP-CLOSED: POST /api/v1/admin/webauthn/login/finish (PUBLIC)
    def test_unknown_username_401(self, unauth_client):
        r = unauth_client.post(
            "/api/v1/admin/webauthn/login/finish",
            json={"username": "nobody@example.com", "credential_response": {}},
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "webauthn_login_failed"


class TestWebauthnV1CredentialsList:
    # GAP-CLOSED: GET /api/v1/admin/webauthn/credentials
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/api/v1/admin/webauthn/credentials").status_code == 401

    def test_default_503(self, admin_client):
        assert admin_client.get("/api/v1/admin/webauthn/credentials").status_code == 503

    def test_with_service_wired_empty_list(self, admin_client, pg_webauthn_service_fake):
        r = admin_client.get("/api/v1/admin/webauthn/credentials")
        assert r.status_code == 200
        assert r.json()["credentials"] == []
        assert r.json()["total"] == 0


class TestWebauthnV1RevokeCredential:
    # GAP-CLOSED: DELETE /api/v1/admin/webauthn/credentials/{credential_id}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.delete("/api/v1/admin/webauthn/credentials/abc").status_code == 401

    def test_without_stepup_401(self, admin_client):
        r = admin_client.delete("/api/v1/admin/webauthn/credentials/abc")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_stepup_default_503(self, stepup_admin_client):
        r = stepup_admin_client.delete("/api/v1/admin/webauthn/credentials/abc")
        assert r.status_code == 503

    def test_stepup_with_service_not_found_404(self, stepup_admin_client, pg_webauthn_service_fake):
        r = stepup_admin_client.delete("/api/v1/admin/webauthn/credentials/does-not-exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "credential_not_found"
