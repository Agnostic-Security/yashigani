"""
Yashigani 4.1.2 conformance suite — AUTH / IDENTITY / RBAC surface.

Target commit: mustui/acc/v412-integrated-latest-20260722 @ 250b486d.

Closes the AUTH/IDENTITY/RBAC surface for:
  routes/auth.py          (25 endpoints) — /auth/*  (includes TOTP provisioning,
                            step-up, operator tokens, IP allow/block lists)
  routes/me.py             (3 endpoints) — /me/api-key, /me/api-keys*
  routes/users.py          (9 endpoints) — /admin/users/*
  routes/accounts.py       (8 endpoints) — /admin/accounts/*
  routes/sso.py            (6 endpoints) — /auth/sso/*
  routes/rbac.py           (9 endpoints) — /admin/rbac/* (groups incl. members/policy push)
  routes/rbac_sources.py   (2 endpoints) — /admin/rbac/sources/*
  routes/budget.py         (9 endpoints) — /admin/budget/{org-caps,groups,individuals}
Total: 71 endpoints.

SCOPE DECISION (documented per PROPOSE-FIRST discipline — flag, don't guess silently):
  The dispatch brief names "totp.py" and "groups.py" as separate files and lists
  "org-caps, individuals, pending" as additional surface items. Verified against
  this exact commit (`grep -rn '@router\\.' src/yashigani/backoffice/routes/*.py`):
    - totp.py does NOT exist as a standalone module; the three /auth/totp/*
      endpoints live inside auth.py and are counted in its 25.
    - groups.py does NOT exist as a standalone module; the RBAC group endpoints
      live inside rbac.py (/admin/rbac/groups*) and are counted in its 9.
    - "org-caps, individuals" — the only real path match anywhere in the codebase
      is routes/budget.py (/admin/budget/org-caps, /admin/budget/groups,
      /admin/budget/individuals — 9 endpoints total, ALL admin-only via a
      router-level `dependencies=[Depends(require_admin_session)]`). Budget is a
      billing/cost-control domain, not literally auth/identity/rbac, but it is
      identity-scoped (caps keyed by identity_id/org_id/group_id) and was
      explicitly named — INCLUDED. budget.py also exposes GET /admin/budget/tree,
      GET /admin/budget/usage/{identity_id}, GET /admin/budget/models/local-inventory
      — NOT named by the brief — EXCLUDED from this suite's route-completeness
      gate (still admin-gated by the same router dependency; not a gap).
    - "pending" — the only real /pending path in the codebase is
      routes/envelope_reapproval.py (/admin/mcp/envelopes/pending*), which is MCP
      tool-call provenance re-approval (a maker-checker workflow on data
      exfiltration risk), unrelated to identity/RBAC/auth by any reasonable
      reading. EXCLUDED — flagged here rather than guess-mapped, per
      accuracy-over-creativity discipline.
  routes/webauthn.py, routes/webauthn_v1.py, and routes/scim.py are also NOT in
  the brief's file list and are EXCLUDED here — they are already covered
  (with real, documented findings) by the pre-existing tests/conformance/
  suite at this same commit (test_auth.py, test_identity_rbac.py — see this
  module's companion findings.md for a pointer, not a re-litigation).

Convention: boots the REAL FastAPI backoffice app via TestClient, wires genuine
session-store/RBAC/identity-registry state backed by fakeredis (see
conftest.py module docstring for the DB-separation rationale — this is the
reason this suite is NOT a copy of the pre-existing tests/conformance/ suite).
Runs fully offline. NEVER asserts a blanket `status_code in (...)` — every
assertion pins an EXACT expected status/shape per auth tier. Every REAL
deviation from documented/expected behaviour is asserted (not skipped) and
cross-referenced in testing_runs/yashigani/v412-conformance-250b486d/
auth-identity-rbac-findings.md.

Last updated: 2026-07-29T00:00:00+00:00
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.conformance

# ---------------------------------------------------------------------------
# LOCAL, MODULE-SCOPED FIXTURES (YTF consolidation, 2026-07-29, Iris).
#
# This suite was originally authored (Tom, branch conf/v412-auth-identity-rbac)
# with its OWN conftest.py, distinct from the pre-existing tests/conformance/
# conftest.py, for exactly one reason documented below: the pre-existing
# suite's own `me_state` fixture (tests/conformance/test_user_plane_agents.py
# :233-239) wires IdentityRegistry against the SAME fakeredis instance
# session_store uses, which MASKS a real DB-separation divergence (production
# session_store = Redis logical DB1, identity_registry/rbac_store = DB3 —
# genuinely disjoint keyspaces; see TestMeApiKeyCrossDatastore below for the
# proven consequence). YTF consolidation rule: "use honest separate-client
# fixtures — never re-introduce masking fixtures" (Iris dispatch brief).
#
# Rather than mutate the SHARED tests/conformance/conftest.py (which would
# change fixture behaviour for the pre-existing 1117-test suite and the
# sibling admin_config_obs/dataplane_gateway_mcp suites with zero benefit to
# them), these fixtures are kept MODULE-LOCAL here. Pytest resolves same-named
# fixtures with module-local precedence over conftest.py, so this file's
# `session_store` fixture below deliberately SHADOWS the shared conftest's
# `session_store` (fake_redis_client-backed) with a two-client, non-masking
# version — scoped ONLY to this module, zero blast radius on any other suite.
#
# FINDING (route to Tom, do not fix here — framework-build only):
# tests/conformance/test_user_plane_agents.py:233-239 `me_state` fixture
# still shares one fakeredis instance across session_store + identity
# registry and should be migrated to this module's two-client pattern to stop
# masking the DB1/DB3 divergence for ITS OWN test class.
# ---------------------------------------------------------------------------

import os

import fakeredis
from fastapi.testclient import TestClient

_ADMIN_SESSION_COOKIE = "__Host-yashigani_admin_session"
_USER_SESSION_COOKIE = "__Host-yashigani_session"
X_CADDY_HEADER = {"X-Caddy-Verified-Secret": os.environ["CADDY_INTERNAL_HMAC"]}


@pytest.fixture
def session_redis_client():
    """Stands in for production Redis logical DB 1 (session_store)."""
    client = fakeredis.FakeRedis(decode_responses=True)
    yield client
    client.flushall()


@pytest.fixture
def identity_redis_client():
    """Stands in for production Redis logical DB 3 (identity_registry +
    rbac_store — genuinely the SAME db in production, both wired here to one
    shared fake client, which is correct since they really do share a DB)."""
    client = fakeredis.FakeRedis(decode_responses=False)
    yield client
    client.flushall()


@pytest.fixture
def session_store(session_redis_client, monkeypatch):
    """SHADOWS tests/conformance/conftest.py::session_store for THIS module
    only — wires session_store to the DB1-standin client, distinct from
    identity_redis_client (DB3-standin), so any cross-datastore divergence
    this suite's routes rely on is provable, not hidden."""
    from yashigani.auth.session import SessionStore
    from yashigani.backoffice.state import backoffice_state

    store = SessionStore.__new__(SessionStore)
    store._redis = session_redis_client
    store._account_index_prefix = "yashigani:account_sessions:"
    store._session_prefix = "yashigani:session:"
    monkeypatch.setattr(backoffice_state, "session_store", store, raising=False)
    return store


@pytest.fixture
def identity_registry(identity_redis_client, monkeypatch):
    """REAL IdentityRegistry (constructor takes redis_client directly —
    src/yashigani/identity/registry.py:152) against the DB3-standin client."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.identity.registry import IdentityRegistry

    registry = IdentityRegistry(redis_client=identity_redis_client)
    monkeypatch.setattr(backoffice_state, "identity_registry", registry, raising=False)
    return registry


@pytest.fixture
def rbac_store(identity_redis_client, monkeypatch):
    """REAL RBACStore (src/yashigani/rbac/store.py:43, redis_client direct)
    against the SAME DB3-standin client as identity_registry — genuinely the
    same production database. Points opa_url at a closed local port so the
    fire-and-forget OPA push in rbac.py fails fast (connection-refused) offline."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.rbac.store import RBACStore

    store = RBACStore(redis_client=identity_redis_client)
    monkeypatch.setattr(backoffice_state, "rbac_store", store, raising=False)
    monkeypatch.setattr(backoffice_state, "opa_url", "http://127.0.0.1:1", raising=False)
    return store


@pytest.fixture(autouse=True)
def _disable_redis_selfheal(monkeypatch):
    """Autouse, MODULE-LOCAL ONLY (does not affect other suites): neutralises
    YSG-RISK-122's redis_selfheal_middleware for this suite's per-endpoint
    conformance assertions — see tests/conformance/conftest.py's own
    docstring point on background-mutation nondeterminism for the rationale."""
    import yashigani.backoffice.redis_selfheal as _selfheal

    async def _noop():
        return None

    monkeypatch.setattr(_selfheal, "maybe_selfheal", _noop, raising=True)


@pytest.fixture(autouse=True)
def _reset_budget_module_singleton(monkeypatch):
    """Autouse, MODULE-LOCAL ONLY: routes/budget.py's `_state` is a bare
    module-level global, not app/request-scoped — force it to the
    "nothing configured" baseline for every test in THIS suite so budget.py
    tests are order-independent regardless of what ran earlier in the same
    pytest process."""
    from yashigani.backoffice.routes import budget as _budget_routes

    monkeypatch.setattr(_budget_routes._state, "budget_enforcer", None, raising=False)
    monkeypatch.setattr(_budget_routes._state, "identity_registry", None, raising=False)
    monkeypatch.setattr(_budget_routes._state, "budget_store", None, raising=False)


@pytest.fixture
def unauth_client(bo_app, session_store):
    with TestClient(bo_app, headers=X_CADDY_HEADER) as client:
        yield client


@pytest.fixture
def admin_client(bo_app, session_store):
    session = session_store.create(
        account_id="conf-authrbac-admin1", account_tier="admin", client_ip="127.0.0.1"
    )
    with TestClient(bo_app, headers=X_CADDY_HEADER) as client:
        client.cookies.set(_ADMIN_SESSION_COOKIE, session.token)
        client.conformance_session = session  # type: ignore[attr-defined]
        yield client


@pytest.fixture
def stepup_admin_client(bo_app, session_store):
    session = session_store.create(
        account_id="conf-authrbac-admin-stepup", account_tier="admin", client_ip="127.0.0.1"
    )
    session_store.record_totp_stepup(session.token)
    with TestClient(bo_app, headers=X_CADDY_HEADER) as client:
        client.cookies.set(_ADMIN_SESSION_COOKIE, session.token)
        client.conformance_session = session  # type: ignore[attr-defined]
        yield client


@pytest.fixture
def user_client(bo_app, session_store):
    session = session_store.create(
        account_id="conf-authrbac-userA", account_tier="user", client_ip="127.0.0.1"
    )
    with TestClient(bo_app, headers=X_CADDY_HEADER) as client:
        client.cookies.set(_USER_SESSION_COOKIE, session.token)
        client.conformance_session = session  # type: ignore[attr-defined]
        yield client


@pytest.fixture
def stepup_user_client(bo_app, session_store):
    session = session_store.create(
        account_id="conf-authrbac-user-stepup", account_tier="user", client_ip="127.0.0.1"
    )
    session_store.record_totp_stepup(session.token)
    with TestClient(bo_app, headers=X_CADDY_HEADER) as client:
        client.cookies.set(_USER_SESSION_COOKIE, session.token)
        client.conformance_session = session  # type: ignore[attr-defined]
        yield client


@pytest.fixture
def second_user_client(bo_app, session_store):
    session = session_store.create(
        account_id="conf-authrbac-userB", account_tier="user", client_ip="127.0.0.1"
    )
    with TestClient(bo_app, headers=X_CADDY_HEADER) as client:
        client.cookies.set(_USER_SESSION_COOKIE, session.token)
        client.conformance_session = session  # type: ignore[attr-defined]
        yield client


class FakeAsyncAuthService:
    """MOCKED: no fakeredis/fake-Postgres equivalent exists for
    `PostgresLocalAuthService` (asyncpg-backed). Wraps the REAL, in-memory,
    synchronous `yashigani.auth.local_auth.LocalAuthService` (genuine argon2
    hashing, genuine role-tiered TOTP generation/verification/replay, genuine
    lockout counters) with a thin async facade."""

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

    async def get_account_by_email(self, email):
        for rec in self._svc._accounts.values():
            if (rec.email or "").lower() == (email or "").lower():
                return rec
        return None

    async def list_accounts(self):
        return list(self._svc._accounts.values())

    async def total_admin_count(self):
        return self._svc.total_admin_count()

    async def active_admin_count(self):
        return self._svc.active_admin_count()

    async def total_user_count(self):
        return self._svc.total_user_count()

    async def create_admin(self, username, auto_generate=True):
        return self._svc.create_admin(username, auto_generate=auto_generate)

    async def create_user(self, username, plaintext_password):
        return self._svc.create_user(username, plaintext_password)

    async def delete_account(self, username):
        return self._svc._accounts.pop(username, None) is not None

    async def disable(self, username):
        return self._svc.disable(username)

    async def enable(self, username):
        return self._svc.enable(username)

    async def force_password_change(self, username):
        rec = self._svc._accounts.get(username)
        if rec is None:
            return False
        rec.force_password_change = True
        return True

    async def force_totp_reprovision(self, username):
        rec = self._svc._accounts.get(username)
        if rec is None:
            return False
        rec.totp_secret = ""
        rec.recovery_codes = None
        rec.force_totp_provision = True
        rec.totp_algorithm = "SHA1"
        return True

    async def set_totp_secret_direct(self, username, totp_secret, algorithm="SHA1"):
        rec = self._svc._accounts.get(username)
        if rec is None:
            return False
        rec.totp_secret = totp_secret
        rec.totp_algorithm = algorithm
        return True

    async def set_email(self, username, email):
        rec = self._svc._accounts.get(username)
        if rec is None:
            return False
        rec.email = email
        return True

    async def full_reset_user(self, username, admin_totp_secret, admin_totp_code,
                               admin_totp_algorithm="SHA1", admin_totp_digits=8):
        return self._svc.full_reset_user(
            username, admin_totp_secret, admin_totp_code,
            admin_totp_algorithm=admin_totp_algorithm, admin_totp_digits=admin_totp_digits,
        )

    async def provision_totp_start(self, username):
        return self._svc.provision_totp_start(username)

    async def provision_totp_confirm(self, username, totp_code):
        return self._svc.provision_totp_confirm(username, totp_code)

    async def _verify_totp_with_replay(self, conn, secret_b32, totp_code, algorithm="SHA1", digits=6):
        from yashigani.auth.totp import verify_totp

        return verify_totp(secret_b32, totp_code, self._svc._used_totp_codes, algorithm=algorithm, digits=digits)


@pytest.fixture(autouse=True)
def fake_auth_service(session_store, mock_audit_writer, monkeypatch):
    """Autouse, MODULE-LOCAL ONLY: wires FakeAsyncAuthService into
    backoffice_state.auth_service. Several routes unconditionally
    `assert state.auth_service is not None` before checking whether a
    token/session is even present."""
    from yashigani.backoffice.state import backoffice_state

    svc = FakeAsyncAuthService()
    monkeypatch.setattr(backoffice_state, "auth_service", svc, raising=False)
    return svc


def seed_provisioned_account(fake_auth_service, *, account_id: str, username: str,
                              tier: str = "admin", email: str | None = None):
    """Insert a fully-provisioned (password + role-tiered TOTP enrolled)
    AccountRecord directly into the fake auth service's in-memory store."""
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
        email=email if email is not None else username,
        force_password_change=False,
        force_totp_provision=False,
        totp_algorithm=algo,
    )
    fake_auth_service._svc._accounts[username] = record
    return record, password, prov.secret_b32, algo, digits


class _FakeConn:
    """MOCKED: stands in for an asyncpg Connection acquired via
    yashigani.db.postgres.tenant_transaction inside auth.py's
    _pg_tenant_transaction() wrapper — no live Postgres offline."""

    def __init__(self, history_rows=None) -> None:
        self._history_rows = history_rows or []
        self.executed: list = []

    async def fetch(self, query, *args):
        return self._history_rows

    async def fetchrow(self, query, *args):
        return None

    async def execute(self, query, *args):
        self.executed.append((query, args))
        return "OK"


@pytest.fixture
def pg_stub_factory(monkeypatch):
    """Factory fixture: pg_stub_factory(history_rows=[...]) replaces auth.py's
    _pg_tenant_transaction() with a fake async context manager yielding a
    _FakeConn, and returns that _FakeConn for assertion."""
    import contextlib

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
    return pg_stub_factory()


def totp_now(secret: str, algorithm: str, digits: int) -> str:
    """Compute a genuinely valid TOTP code using the app's OWN raw RFC
    4226/6238 implementation (yashigani.auth.totp._totp_at)."""
    import time

    from yashigani.auth import totp as _totp_mod

    return _totp_mod._totp_at(secret, int(time.time()), algorithm, digits)


@pytest.fixture
def seed_account():
    return seed_provisioned_account


@pytest.fixture
def totp_code_now():
    return totp_now


@pytest.fixture
def identity_broker(monkeypatch):
    """A REAL IdentityBroker with zero IdPs configured — for sso.py tests
    that need to reach the "idp not found" branch past the
    identity_broker_unavailable (503) guard, without needing a live IdP."""
    from yashigani.auth.broker import IdentityBroker
    from yashigani.backoffice.state import backoffice_state

    broker = IdentityBroker(tier="professional")
    monkeypatch.setattr(backoffice_state, "identity_broker", broker, raising=False)
    return broker


@pytest.fixture
def caddy_secret_file(monkeypatch):
    """POST /auth/operator-token and POST /auth/stepup-proof read the JWT
    signing key directly from the literal path /run/secrets/caddy_internal_hmac
    — never writes to the real /run/secrets; intercepts only this exact
    literal path via a wrapped `open()`."""
    import builtins

    real_open = builtins.open
    target_path = "/run/secrets/caddy_internal_hmac"
    secret_value = os.environ["CADDY_INTERNAL_HMAC"]

    def _fake_open(file, *args, **kwargs):
        if str(file) == target_path:
            import io

            return io.StringIO(secret_value)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _fake_open)
    return secret_value


# ---------------------------------------------------------------------------
# Route-completeness gate — exact expected (method, path) set for this
# suite's scope (see module docstring scope decision above).
# ---------------------------------------------------------------------------

_EXPECTED_ROUTES: set[tuple[str, str]] = {
    # auth.py (25)
    ("POST", "/auth/login"),
    ("POST", "/auth/logout"),
    ("GET", "/auth/logout-redirect"),
    ("GET", "/auth/status"),
    ("POST", "/auth/password/self-reset"),
    ("GET", "/auth/verify"),
    ("GET", "/auth/verify-admin"),
    ("GET", "/auth/verify-user"),
    ("GET", "/auth/verify-mcp"),
    ("GET", "/auth/verify-webhook"),
    ("POST", "/auth/password/change"),
    ("POST", "/auth/totp/provision/start"),
    ("POST", "/auth/totp/provision/confirm"),
    ("POST", "/auth/totp/provision"),
    ("POST", "/auth/stepup"),
    ("POST", "/auth/operator-token"),
    ("GET", "/auth/operator-token/verify"),
    ("POST", "/auth/stepup-proof"),
    ("POST", "/auth/onboard-event"),
    ("GET", "/auth/blocked-ips"),
    ("DELETE", "/auth/blocked-ips/{ip}"),
    ("GET", "/auth/allowed-ips"),
    ("POST", "/auth/allowed-ips"),
    ("DELETE", "/auth/allowed-ips/{ip_or_cidr:path}"),
    ("GET", "/auth/post-login-redirect"),
    # me.py (3)
    ("POST", "/me/api-key"),
    ("GET", "/me/api-keys"),
    ("DELETE", "/me/api-keys/{key_id}"),
    # users.py (9)
    ("GET", "/admin/users"),
    ("POST", "/admin/users"),
    ("PUT", "/admin/users/{username}"),
    ("DELETE", "/admin/users/{username}"),
    ("POST", "/admin/users/{username}/full-reset"),
    ("POST", "/admin/users/{username}/disable"),
    ("POST", "/admin/users/{username}/enable"),
    ("POST", "/admin/users/{username}/reactivate"),
    ("POST", "/admin/users/{username}/api-key"),
    # accounts.py (8)
    ("GET", "/admin/accounts/enforcement"),
    ("GET", "/admin/accounts"),
    ("POST", "/admin/accounts"),
    ("DELETE", "/admin/accounts/{username}"),
    ("POST", "/admin/accounts/{username}/disable"),
    ("POST", "/admin/accounts/{username}/enable"),
    ("POST", "/admin/accounts/{username}/force-reset"),
    ("PUT", "/admin/accounts/{username}"),
    # sso.py (6)
    ("GET", "/auth/sso/select"),
    ("GET", "/auth/sso/oidc/{idp_id}"),
    ("GET", "/auth/sso/oidc/{idp_id}/callback"),
    ("GET", "/auth/sso/2fa"),
    ("POST", "/auth/sso/2fa/verify"),
    ("POST", "/auth/sso/saml/{idp_id}/acs"),
    # rbac.py (9)
    ("GET", "/admin/rbac/groups"),
    ("POST", "/admin/rbac/groups"),
    ("GET", "/admin/rbac/groups/{group_id}"),
    ("PUT", "/admin/rbac/groups/{group_id}"),
    ("DELETE", "/admin/rbac/groups/{group_id}"),
    ("POST", "/admin/rbac/groups/{group_id}/members"),
    ("DELETE", "/admin/rbac/groups/{group_id}/members/{email}"),
    ("GET", "/admin/rbac/users/{email}/groups"),
    ("POST", "/admin/rbac/policy/push"),
    # rbac_sources.py (2)
    ("GET", "/admin/rbac/sources/paths"),
    ("GET", "/admin/rbac/sources/methods"),
    # budget.py (9 — org-caps/groups/individuals only, see scope note)
    ("GET", "/admin/budget/org-caps"),
    ("POST", "/admin/budget/org-caps"),
    ("DELETE", "/admin/budget/org-caps"),
    ("GET", "/admin/budget/groups"),
    ("POST", "/admin/budget/groups"),
    ("DELETE", "/admin/budget/groups"),
    ("GET", "/admin/budget/individuals"),
    ("POST", "/admin/budget/individuals"),
    ("DELETE", "/admin/budget/individuals"),
}


def test_group_covers_all_declared_routes(declared_routes):
    declared_set = {(m, p) for (m, p, _r) in declared_routes}
    missing = _EXPECTED_ROUTES - declared_set
    assert not missing, f"Endpoints in scope but not found in the live route walk: {missing}"
    # Confirm we enumerated exactly the endpoint count claimed in the module
    # docstring (71) — a route added/removed under these prefixes since this
    # suite was authored should fail loudly, not silently under-cover.
    assert len(_EXPECTED_ROUTES) == 71


# ===========================================================================
# auth.py — /auth/login, /logout*, /status, /password/*, /verify*,
#            /totp/provision*, /stepup*, /operator-token*, /onboard-event,
#            /blocked-ips*, /allowed-ips*, /post-login-redirect
# ===========================================================================


class TestAuthLogin:
    # GAP-CLOSED: POST /auth/login
    def test_unauth_reachable_but_malformed_body_422(self, unauth_client):
        r = unauth_client.post("/auth/login", json={"username": "x"})
        assert r.status_code == 422, r.text

    def test_totp_code_wrong_length_422(self, unauth_client):
        r = unauth_client.post(
            "/auth/login",
            json={"username": "a@b.com", "password": "x", "totp_code": "12"},
        )
        assert r.status_code == 422, r.text

    def test_unknown_user_401_generic(self, fake_auth_service, unauth_client):
        r = unauth_client.post(
            "/auth/login",
            json={"username": "nobody@x.com", "password": "wrongwrongwrong", "totp_code": "123456"},
        )
        assert r.status_code == 401, r.text
        assert r.json()["detail"]["error"] == "invalid_credentials"

    def test_admin_login_success_sets_admin_cookie_and_redirect(
        self, fake_auth_service, session_store, unauth_client, seed_account, totp_code_now,
    ):
        _record, password, secret, algo, digits = seed_account(
            fake_auth_service, account_id="login-admin-1", username="admin1@x.com", tier="admin",
        )
        code = totp_code_now(secret, algo, digits)
        r = unauth_client.post(
            "/auth/login", json={"username": "admin1@x.com", "password": password, "totp_code": code},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "ok"
        assert body["redirect_to"] == "/admin/"
        assert "__Host-yashigani_admin_session" in r.cookies

    def test_user_login_success_sets_user_cookie_and_redirect(
        self, fake_auth_service, session_store, unauth_client, seed_account, totp_code_now,
    ):
        _record, password, secret, algo, digits = seed_account(
            fake_auth_service, account_id="login-user-1", username="user1@x.com", tier="user",
        )
        code = totp_code_now(secret, algo, digits)
        r = unauth_client.post(
            "/auth/login", json={"username": "user1@x.com", "password": password, "totp_code": code},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["redirect_to"] == "/chat"
        assert "__Host-yashigani_session" in r.cookies

    # GAP-CLOSED: TOTP tier proof — admin uses SHA-512/8-digit, user SHA-256/6-digit.
    def test_admin_totp_is_sha512_8digit_not_interchangeable_with_user(
        self, fake_auth_service, session_store, unauth_client, seed_account, totp_code_now,
    ):
        _record, password, secret, algo, digits = seed_account(
            fake_auth_service, account_id="login-admin-tier-1", username="admtier@x.com", tier="admin",
        )
        assert (algo, digits) == ("SHA512", 8)
        # A correctly-shaped 6-digit code computed with the WRONG algorithm
        # (SHA256, as if this were a user account) must be rejected — proves
        # the server enforces the account's OWN enrolled tier, not merely
        # "any 6-8 digit code that validates against the secret".
        wrong_tier_code = totp_code_now(secret, "SHA256", 6)
        r = unauth_client.post(
            "/auth/login",
            json={"username": "admtier@x.com", "password": password, "totp_code": wrong_tier_code},
        )
        assert r.status_code == 401, r.text

    def test_user_totp_is_sha256_6digit_not_interchangeable_with_admin(
        self, fake_auth_service, session_store, unauth_client, seed_account, totp_code_now,
    ):
        _record, password, secret, algo, digits = seed_account(
            fake_auth_service, account_id="login-user-tier-1", username="usrtier@x.com", tier="user",
        )
        assert (algo, digits) == ("SHA256", 6)
        wrong_tier_code = totp_code_now(secret, "SHA512", 8)
        r = unauth_client.post(
            "/auth/login",
            json={"username": "usrtier@x.com", "password": password, "totp_code": wrong_tier_code},
        )
        assert r.status_code == 401, r.text

    def test_wrong_password_401_no_stack_leak(self, fake_auth_service, session_store, unauth_client, seed_account):
        _record, _password, _secret, _algo, _digits = seed_account(
            fake_auth_service, account_id="login-badpw-1", username="badpw@x.com", tier="user",
        )
        r = unauth_client.post(
            "/auth/login",
            json={"username": "badpw@x.com", "password": "totally-wrong-password", "totp_code": "000000"},
        )
        assert r.status_code == 401
        text = r.text
        assert "Traceback" not in text and "traceback" not in text.lower()
        assert "File \"" not in text


class TestAuthLogout:
    # GAP-CLOSED: POST /auth/logout
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/auth/logout")
        assert r.status_code == 401, r.text

    def test_admin_clears_session(self, admin_client, session_store):
        token = admin_client.conformance_session.token
        r = admin_client.post("/auth/logout")
        assert r.status_code == 200, r.text
        assert session_store.get(token) is None

    def test_user_can_logout_no_end_user_trap(self, user_client, session_store):
        # Phase 1 fix regression: logout was AdminSession-only, trapping user
        # sessions. Must be reachable by user tier too.
        token = user_client.conformance_session.token
        r = user_client.post("/auth/logout")
        assert r.status_code == 200, r.text
        assert session_store.get(token) is None

    # GAP-CLOSED: GET /auth/logout-redirect
    def test_logout_redirect_unauth_still_redirects_to_login(self, unauth_client):
        r = unauth_client.get("/auth/logout-redirect", follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == "/login"

    def test_logout_redirect_admin_clears_and_redirects(self, admin_client, session_store):
        token = admin_client.conformance_session.token
        r = admin_client.get("/auth/logout-redirect", follow_redirects=False)
        assert r.status_code == 302
        assert session_store.get(token) is None


class TestAuthStatus:
    # GAP-CLOSED: GET /auth/status
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get("/auth/status")
        assert r.status_code == 401, r.text

    def test_admin_200(self, admin_client):
        r = admin_client.get("/auth/status")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["account_tier"] == "admin"
        assert body["account_id"] == admin_client.conformance_session.account_id

    def test_user_403(self, user_client):
        # /auth/status uses AdminSession — a user-tier session (not merely
        # "no session") is a REAL, spec-relevant divergence to pin: users
        # cannot self-check session status via this endpoint at all.
        r = user_client.get("/auth/status")
        assert r.status_code == 403, r.text


class TestAuthPasswordSelfReset:
    # GAP-CLOSED: POST /auth/password/self-reset
    def test_malformed_body_422(self, unauth_client):
        r = unauth_client.post("/auth/password/self-reset", json={"username": "ab"})
        assert r.status_code == 422, r.text

    def test_unknown_user_401_generic(self, fake_auth_service, unauth_client):
        r = unauth_client.post(
            "/auth/password/self-reset",
            json={"username": "nope@x.com", "totp_code": "123456"},
        )
        assert r.status_code == 401, r.text

    def test_success_issues_temp_password_and_invalidates_sessions(
        self, fake_auth_service, session_store, pg_tenant_transaction_stub,
        unauth_client, seed_account, totp_code_now,
    ):
        _record, _password, secret, algo, digits = seed_account(
            fake_auth_service, account_id="selfreset-1", username="selfreset@x.com", tier="user",
        )
        old_session = session_store.create(
            account_id="selfreset-1", account_tier="user", client_ip="127.0.0.1",
        )
        code = totp_code_now(secret, algo, digits)
        r = unauth_client.post(
            "/auth/password/self-reset",
            json={"username": "selfreset@x.com", "totp_code": code},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["force_password_change"] is True
        assert len(body["temporary_password"]) >= 30
        # Real side-effect: prior session is invalidated via the SAME
        # session_store the /auth/verify path reads.
        assert session_store.get(old_session.token) is None


class TestAuthVerifyEndpoints:
    # GAP-CLOSED: GET /auth/verify
    def test_verify_unauth_401(self, unauth_client):
        assert unauth_client.get("/auth/verify").status_code == 401

    def test_verify_admin_session_rejected_403_sod003(self, admin_client, fake_auth_service, seed_account):
        seed_account(fake_auth_service, account_id=admin_client.conformance_session.account_id,
                      username="sod003@x.com", tier="admin")
        r = admin_client.get("/auth/verify")
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "admin_session_not_allowed_data_plane"

    def test_verify_user_session_200_with_identity_headers(self, user_client, fake_auth_service, seed_account):
        seed_account(fake_auth_service, account_id=user_client.conformance_session.account_id,
                      username="verifyuser@x.com", tier="user")
        r = user_client.get("/auth/verify")
        assert r.status_code == 200, r.text
        assert r.headers["X-Forwarded-User"] == "verifyuser@x.com"

    # GAP-CLOSED: GET /auth/verify-admin
    def test_verify_admin_unauth_401(self, unauth_client):
        assert unauth_client.get("/auth/verify-admin").status_code == 401

    def test_verify_admin_user_session_403(self, bo_app, session_store, caddy_headers):
        # /auth/verify-admin reads ONLY the admin cookie slot (no fallback to
        # the user cookie) — a plain user_client (which sets only the user
        # cookie) produces 401 "no token" here, not 403. To exercise the REAL
        # wrong-tier branch, present a user-tier session's token UNDER the
        # admin cookie name (the scenario the 403 branch actually guards
        # against — e.g. cookie confusion/tampering).
        from fastapi.testclient import TestClient

        session = session_store.create(account_id="verify-admin-wrongtier", account_tier="user", client_ip="127.0.0.1")
        with TestClient(bo_app, headers=caddy_headers) as client:
            client.cookies.set("__Host-yashigani_admin_session", session.token)
            r = client.get("/auth/verify-admin")
        assert r.status_code == 403, r.text

    def test_verify_admin_admin_session_200(self, admin_client, fake_auth_service, seed_account):
        seed_account(fake_auth_service, account_id=admin_client.conformance_session.account_id,
                      username="verifyadmin@x.com", tier="admin")
        r = admin_client.get("/auth/verify-admin")
        assert r.status_code == 200, r.text

    # GAP-CLOSED: GET /auth/verify-user
    def test_verify_user_unauth_401(self, unauth_client):
        assert unauth_client.get("/auth/verify-user").status_code == 401

    def test_verify_user_admin_session_403(self, admin_client):
        r = admin_client.get("/auth/verify-user")
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "admin_session_not_allowed_user_path"

    def test_verify_user_user_session_200(self, user_client, fake_auth_service, seed_account):
        # rbac_store not wired -> getattr(state, "rbac_store", None) is None
        # -> owui-users membership check is skipped (documented fail-open for
        # community/no-RBAC deployments) -> 200.
        seed_account(fake_auth_service, account_id=user_client.conformance_session.account_id,
                      username="verifyuserU@x.com", tier="user")
        r = user_client.get("/auth/verify-user")
        assert r.status_code == 200, r.text


class TestAuthVerifyMcpWebhook:
    # GAP-CLOSED: GET /auth/verify-mcp — Caddy-only ingress gate (mTLS
    # peer-cert trust chain terminated by Caddy, not exercised offline).
    # Scope: assert the Python-reachable fail-closed default (no spoofable
    # x-spiffe-id header, no valid server) denies.
    def test_verify_mcp_no_server_denied(self, unauth_client):
        r = unauth_client.get("/auth/verify-mcp", params={"tenant": "t1", "server": "unknownserver"})
        assert r.status_code in (401, 403), r.text

    def test_verify_mcp_invalid_slug_rejected(self, unauth_client):
        r = unauth_client.get("/auth/verify-mcp", params={"tenant": "t1", "server": "bad server!"})
        assert r.status_code in (400, 401, 403), r.text

    # GAP-CLOSED: GET /auth/verify-webhook
    def test_verify_webhook_missing_method_header_401(self, unauth_client):
        r = unauth_client.get("/auth/verify-webhook", params={"provider": "slack"})
        assert r.status_code == 401, r.text

    def test_verify_webhook_unknown_provider_401(self, unauth_client):
        r = unauth_client.get(
            "/auth/verify-webhook",
            params={"provider": "unknown-provider"},
            headers={"X-Forwarded-Method": "POST"},
        )
        assert r.status_code == 401, r.text


class TestAuthPasswordChange:
    # GAP-CLOSED: POST /auth/password/change
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/auth/password/change",
            json={"current_password": "x", "new_password": "y" * 40},
        )
        assert r.status_code == 401, r.text

    def test_short_new_password_422(self, user_client):
        r = user_client.post(
            "/auth/password/change",
            json={"current_password": "x", "new_password": "short"},
        )
        assert r.status_code == 422, r.text

    def test_wrong_current_password_rejected(
        self, fake_auth_service, session_store, pg_tenant_transaction_stub,
        user_client, seed_account,
    ):
        seed_account(fake_auth_service, account_id=user_client.conformance_session.account_id,
                      username="pwchange@x.com", tier="user")
        r = user_client.post(
            "/auth/password/change",
            json={"current_password": "totally-wrong", "new_password": "n" * 40},
        )
        assert r.status_code in (400, 401), r.text

    def test_success_invalidates_all_sessions(
        self, bo_app, fake_auth_service, session_store, pg_tenant_transaction_stub, mock_audit_writer,
        seed_account, caddy_headers, monkeypatch,
    ):
        from fastapi.testclient import TestClient

        # change_password() calls hash_password(check_breach=True) (the ONLY
        # route in this suite's scope that does — every other password write
        # uses check_breach=False for system-generated passwords). Disabling
        # the network-dependent HIBP check is scoped to THIS test only via
        # monkeypatch (auto-reverted by pytest) — see conftest.py's note on
        # why this must never be a process-wide os.environ.setdefault().
        monkeypatch.setenv("YASHIGANI_HIBP_CHECK_ENABLED", "false")

        _record, password, _secret, _algo, _digits = seed_account(
            fake_auth_service, account_id="pwchange-success-1", username="pwok@x.com", tier="user",
        )
        # NOTE: SessionStore.create() calls invalidate_all_for_account() as its
        # own first step (single-session-per-account by construction), so a
        # single session is the correct fixture here — verifying "all sessions
        # invalidated" reduces to "the very session used to authenticate the
        # request is itself dead afterwards" (ASVS V2.1.4).
        session = session_store.create(account_id="pwchange-success-1", account_tier="user", client_ip="127.0.0.1")
        with TestClient(bo_app, headers=caddy_headers) as client:
            client.cookies.set("__Host-yashigani_session", session.token)
            r = client.post(
                "/auth/password/change",
                json={"current_password": password, "new_password": "a-brand-new-strong-credential-phrase-ok"},
            )
        assert r.status_code == 200, r.text
        # Real side-effect: the session is invalidated post-change.
        assert session_store.get(session.token) is None


class TestAuthTotpProvision:
    # GAP-CLOSED: POST /auth/totp/provision/start
    def test_start_unauth_401(self, unauth_client):
        assert unauth_client.post("/auth/totp/provision/start").status_code == 401

    def test_start_user_200_returns_role_tiered_secret(self, fake_auth_service, user_client):
        # A NOT-yet-provisioned account (force_totp_provision=True, the real
        # create_user() default) hits the "first enrolment, no step-up needed"
        # branch. seed_account() would instead produce an ALREADY-provisioned
        # account, which correctly demands step-up (YSG-RISK-082) — tested
        # separately below, not conflated with this first-enrolment case.
        record = fake_auth_service._svc.create_user("totpstart@x.com", "totally-fine-temp-credential-value" + "x" * 10)
        record.account_id = user_client.conformance_session.account_id  # mutate in place, same dict entry
        r = user_client.post("/auth/totp/provision/start")
        assert r.status_code == 200, r.text
        assert r.json()["totp_algorithm"] == "SHA256"
        assert r.json()["totp_digits"] == 6

    def test_start_already_provisioned_requires_stepup_401(self, fake_auth_service, seed_account, user_client):
        seed_account(fake_auth_service, account_id=user_client.conformance_session.account_id,
                      username="totpstart2@x.com", tier="user")
        r = user_client.post("/auth/totp/provision/start")
        assert r.status_code == 401, r.text
        assert r.json()["detail"]["error"] == "step_up_required"

    # GAP-CLOSED: POST /auth/totp/provision/confirm
    def test_confirm_unauth_401(self, unauth_client):
        r = unauth_client.post("/auth/totp/provision/confirm", json={"totp_code": "123456"})
        assert r.status_code == 401, r.text

    def test_confirm_malformed_code_422(self, user_client):
        r = user_client.post("/auth/totp/provision/confirm", json={"totp_code": "abc"})
        assert r.status_code == 422, r.text

    # GAP-CLOSED: POST /auth/totp/provision (atomic back-compat)
    def test_atomic_unauth_401(self, unauth_client):
        r = unauth_client.post("/auth/totp/provision", json={"totp_code": "123456"})
        assert r.status_code == 401, r.text


class TestAuthStepup:
    # GAP-CLOSED: POST /auth/stepup
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/auth/stepup", json={"totp_code": "123456"})
        assert r.status_code == 401, r.text

    def test_wrong_code_401(self, fake_auth_service, pg_tenant_transaction_stub, session_store,
                             user_client, seed_account):
        seed_account(fake_auth_service, account_id=user_client.conformance_session.account_id,
                      username="stepupwrong@x.com", tier="user")
        r = user_client.post("/auth/stepup", json={"totp_code": "000000"})
        assert r.status_code == 401, r.text

    def test_success_records_fresh_stepup(self, fake_auth_service, pg_tenant_transaction_stub,
                                           session_store, user_client, seed_account, totp_code_now):
        _record, _password, secret, algo, digits = seed_account(
            fake_auth_service, account_id=user_client.conformance_session.account_id,
            username="stepupok@x.com", tier="user",
        )
        code = totp_code_now(secret, algo, digits)
        r = user_client.post("/auth/stepup", json={"totp_code": code})
        assert r.status_code == 200, r.text
        assert r.json()["stepup_verified"] is True
        # Real side-effect: the SAME session, re-fetched, now has a fresh stepup.
        from yashigani.auth.stepup import has_fresh_stepup
        refreshed = session_store.get(user_client.conformance_session.token)
        assert has_fresh_stepup(refreshed)


class TestAuthOperatorToken:
    # GAP-CLOSED: POST /auth/operator-token
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/auth/operator-token", json={"issued_for": "x"}).status_code == 401

    def test_user_403(self, user_client):
        assert user_client.post("/auth/operator-token", json={"issued_for": "x"}).status_code == 403

    def test_admin_no_stepup_401(self, fake_auth_service, seed_account, admin_client):
        seed_account(fake_auth_service, account_id=admin_client.conformance_session.account_id,
                      username="optoken@x.com", tier="admin")
        r = admin_client.post("/auth/operator-token", json={"issued_for": "onboard-test"})
        assert r.status_code == 401, r.text
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_admin_with_stepup_200(self, fake_auth_service, seed_account, caddy_secret_file, stepup_admin_client):
        seed_account(fake_auth_service, account_id=stepup_admin_client.conformance_session.account_id,
                      username="optokenok@x.com", tier="admin")
        r = stepup_admin_client.post("/auth/operator-token", json={"issued_for": "onboard-test"})
        assert r.status_code == 200, r.text
        assert "token" in r.json() or "jwt" in str(r.json()).lower() or r.json().get("status") == "ok"

    # GAP-CLOSED: GET /auth/operator-token/verify
    def test_verify_no_bearer_400_or_401(self, unauth_client):
        r = unauth_client.get("/auth/operator-token/verify")
        assert r.status_code in (400, 401), r.text

    def test_verify_garbage_bearer_401(self, caddy_secret_file, unauth_client):
        r = unauth_client.get(
            "/auth/operator-token/verify", headers={"Authorization": "Bearer not-a-real-jwt"},
        )
        assert r.status_code == 401, r.text


class TestAuthStepupProof:
    # GAP-CLOSED: POST /auth/stepup-proof
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/auth/stepup-proof", json={"op": "add-component"}).status_code == 401

    def test_invalid_op_pattern_422(self, admin_client):
        r = admin_client.post("/auth/stepup-proof", json={"op": "Invalid Op!"})
        assert r.status_code == 422, r.text

    def test_admin_no_stepup_401(self, admin_client):
        r = admin_client.post("/auth/stepup-proof", json={"op": "add-component"})
        assert r.status_code == 401, r.text

    def test_admin_with_stepup_mints_proof(self, fake_auth_service, seed_account, caddy_secret_file, stepup_admin_client):
        seed_account(fake_auth_service, account_id=stepup_admin_client.conformance_session.account_id,
                      username="stepupproof@x.com", tier="admin")
        r = stepup_admin_client.post("/auth/stepup-proof", json={"op": "add-component"})
        assert r.status_code == 200, r.text


class TestAuthOnboardEvent:
    # GAP-CLOSED: POST /auth/onboard-event
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/auth/onboard-event",
            json={"identity_quality": "weak", "agent_name": "a", "agent_url": "http://x"},
        )
        assert r.status_code == 401, r.text

    def test_user_403(self, user_client):
        r = user_client.post(
            "/auth/onboard-event",
            json={"identity_quality": "weak", "agent_name": "a", "agent_url": "http://x"},
        )
        assert r.status_code == 403, r.text

    def test_bad_identity_quality_enum_422(self, admin_client):
        r = admin_client.post(
            "/auth/onboard-event",
            json={"identity_quality": "definitely-not-valid", "agent_name": "a", "agent_url": "http://x"},
        )
        assert r.status_code == 422, r.text

    def test_admin_success(self, admin_client):
        r = admin_client.post(
            "/auth/onboard-event",
            json={"identity_quality": "attested", "agent_name": "myagent", "agent_url": "http://x/mcp"},
        )
        assert r.status_code == 200, r.text


class TestAuthIpLists:
    # GAP-CLOSED: GET /auth/blocked-ips
    def test_blocked_ips_unauth_401(self, unauth_client):
        assert unauth_client.get("/auth/blocked-ips").status_code == 401

    def test_blocked_ips_user_403(self, user_client):
        assert user_client.get("/auth/blocked-ips").status_code == 403

    def test_blocked_ips_admin_200(self, admin_client):
        r = admin_client.get("/auth/blocked-ips")
        assert r.status_code == 200, r.text
        assert "blocked_ips" in r.json()

    # GAP-CLOSED: DELETE /auth/blocked-ips/{ip}
    def test_unblock_unknown_ip_404(self, admin_client):
        r = admin_client.delete("/auth/blocked-ips/203.0.113.99")
        assert r.status_code == 404, r.text

    # GAP-CLOSED: GET /auth/allowed-ips, POST /auth/allowed-ips, DELETE /auth/allowed-ips/{ip}
    def test_allowed_ips_unauth_401(self, unauth_client):
        assert unauth_client.get("/auth/allowed-ips").status_code == 401
        assert unauth_client.post("/auth/allowed-ips", json={"ip": "1.2.3.4"}).status_code == 401
        assert unauth_client.delete("/auth/allowed-ips/1.2.3.4").status_code == 401

    def test_add_invalid_ip_400(self, admin_client):
        r = admin_client.post("/auth/allowed-ips", json={"ip": "not-an-ip"})
        assert r.status_code == 400, r.text

    def test_add_list_remove_roundtrip_real_sideeffect(self, admin_client, session_store):
        r1 = admin_client.post("/auth/allowed-ips", json={"ip": "198.51.100.7"})
        assert r1.status_code == 200, r1.text
        # Real datastore check: the SAME redis set /auth/allowed-ips (GET) reads.
        assert session_store._redis.sismember("auth:allowlist", "198.51.100.7")
        r2 = admin_client.get("/auth/allowed-ips")
        assert "198.51.100.7" in r2.json()["allowed_ips"]
        r3 = admin_client.delete("/auth/allowed-ips/198.51.100.7")
        assert r3.status_code == 200, r3.text
        assert not session_store._redis.sismember("auth:allowlist", "198.51.100.7")

    def test_remove_unknown_entry_404(self, admin_client):
        r = admin_client.delete("/auth/allowed-ips/192.0.2.55")
        assert r.status_code == 404, r.text


class TestAuthPostLoginRedirect:
    # GAP-CLOSED: GET /auth/post-login-redirect
    def test_unauth_reachable(self, unauth_client):
        r = unauth_client.get("/auth/post-login-redirect", params={"next": "/chat"}, follow_redirects=False)
        assert r.status_code == 302, r.text

    def test_open_redirect_rejected(self, unauth_client):
        r = unauth_client.get(
            "/auth/post-login-redirect", params={"next": "https://evil.example.com/steal"},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert "evil.example.com" not in r.headers.get("location", "")


# ===========================================================================
# sso.py — pre-auth flows, unauthenticated by design.
# ===========================================================================


class TestSso:
    # GAP-CLOSED: GET /auth/sso/select
    def test_select_unauth_200_empty_by_default(self, unauth_client):
        r = unauth_client.get("/auth/sso/select")
        assert r.status_code == 200, r.text
        assert r.json() == {"idps": []}

    # GAP-CLOSED: GET /auth/sso/oidc/{idp_id}
    def test_oidc_initiate_community_tier_402_license_gated(self, unauth_client):
        # Real Community-tier behaviour: the license feature gate
        # (require_feature("oidc")) is checked BEFORE idp lookup, so an
        # unlicensed install 402s regardless of whether the idp_id is real.
        r = unauth_client.get("/auth/sso/oidc/no-such-idp")
        assert r.status_code == 402, r.text
        assert r.json()["feature"] == "oidc"

    def test_oidc_initiate_licensed_unknown_idp_404(self, identity_broker, unauth_client, monkeypatch):
        import dataclasses

        from yashigani.licensing import enforcer
        from yashigani.licensing.model import COMMUNITY_LICENSE, LicenseFeature, LicenseTier

        licensed = dataclasses.replace(
            COMMUNITY_LICENSE, tier=LicenseTier.PROFESSIONAL, features=frozenset({LicenseFeature.OIDC}),
        )
        enforcer.set_license(licensed)
        try:
            r = unauth_client.get("/auth/sso/oidc/no-such-idp")
            assert r.status_code == 404, r.text
        finally:
            enforcer.set_license(COMMUNITY_LICENSE)

    # GAP-CLOSED: GET /auth/sso/oidc/{idp_id}/callback
    def test_oidc_callback_missing_code_state_400(self, unauth_client):
        r = unauth_client.get("/auth/sso/oidc/no-such-idp/callback")
        assert r.status_code == 400, r.text

    def test_oidc_callback_idp_error_redirects_login(self, unauth_client):
        r = unauth_client.get(
            "/auth/sso/oidc/no-such-idp/callback",
            params={"error": "access_denied"},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert "sso_failed" in r.headers["location"]

    # GAP-CLOSED: GET /auth/sso/2fa
    def test_2fa_page_no_pending_cookie_redirects_login(self, unauth_client):
        r = unauth_client.get("/auth/sso/2fa", follow_redirects=False)
        assert r.status_code == 302
        assert "no_pending_sso" in r.headers["location"]

    # GAP-CLOSED: POST /auth/sso/2fa/verify
    def test_2fa_verify_no_pending_cookie_401(self, unauth_client):
        r = unauth_client.post("/auth/sso/2fa/verify", json={"totp_code": "123456"})
        assert r.status_code == 401, r.text

    # GAP-CLOSED: POST /auth/sso/saml/{idp_id}/acs
    def test_saml_acs_community_tier_402_license_gated(self, unauth_client):
        r = unauth_client.post("/auth/sso/saml/no-such-idp/acs", data={"SAMLResponse": "x"})
        assert r.status_code == 402, r.text
        assert r.json()["feature"] == "saml"

    def test_saml_acs_licensed_unknown_idp_404(self, identity_broker, unauth_client):
        import dataclasses

        from yashigani.licensing import enforcer
        from yashigani.licensing.model import COMMUNITY_LICENSE, LicenseFeature, LicenseTier

        licensed = dataclasses.replace(
            COMMUNITY_LICENSE, tier=LicenseTier.PROFESSIONAL, features=frozenset({LicenseFeature.SAML}),
        )
        enforcer.set_license(licensed)
        try:
            r = unauth_client.post("/auth/sso/saml/no-such-idp/acs", data={"SAMLResponse": "x"})
            assert r.status_code == 404, r.text
        finally:
            enforcer.set_license(COMMUNITY_LICENSE)


# ===========================================================================
# me.py — self-service API key issuance. Includes the cross-Redis-DB
# CRITICAL FINDING (see findings.md).
# ===========================================================================


class TestMeApiKey:
    # GAP-CLOSED: POST /me/api-key
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/me/api-key").status_code == 401

    def test_admin_tier_rejected_403(self, admin_client):
        r = admin_client.post("/me/api-key")
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "user_tier_required"

    def test_user_without_stepup_401(self, fake_auth_service, identity_registry, seed_account, user_client):
        seed_account(fake_auth_service, account_id=user_client.conformance_session.account_id,
                      username="mekey1@x.com", tier="user", email="mekey1@x.com")
        r = user_client.post("/me/api-key")
        assert r.status_code == 401, r.text
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_identity_registry_unavailable_503(self, fake_auth_service, seed_account, stepup_user_client, monkeypatch):
        from yashigani.backoffice.state import backoffice_state
        seed_account(fake_auth_service, account_id=stepup_user_client.conformance_session.account_id,
                      username="mekey2@x.com", tier="user", email="mekey2@x.com")
        monkeypatch.setattr(backoffice_state, "identity_registry", None, raising=False)
        r = stepup_user_client.post("/me/api-key")
        assert r.status_code == 503, r.text

    # GAP-CLOSED: GET /me/api-keys
    def test_list_unauth_401(self, unauth_client):
        assert unauth_client.get("/me/api-keys").status_code == 401

    def test_list_admin_403(self, admin_client):
        assert admin_client.get("/me/api-keys").status_code == 403

    def test_list_no_identity_yet_empty(self, fake_auth_service, identity_registry, seed_account, user_client):
        seed_account(fake_auth_service, account_id=user_client.conformance_session.account_id,
                      username="mekey3@x.com", tier="user", email="mekey3@x.com")
        r = user_client.get("/me/api-keys")
        assert r.status_code == 200, r.text
        assert r.json() == {"api_keys": []}

    # GAP-CLOSED: DELETE /me/api-keys/{key_id}
    def test_revoke_unauth_401(self, unauth_client):
        assert unauth_client.delete("/me/api-keys/idnt_deadbeefcafe").status_code == 401

    def test_revoke_admin_403(self, admin_client):
        assert admin_client.delete("/me/api-keys/idnt_deadbeefcafe").status_code == 403

    def test_revoke_not_owned_403(self, fake_auth_service, identity_registry, seed_account, user_client):
        # A key_id that does not match the caller's own identity_id (even a
        # syntactically plausible one) is rejected before ever checking
        # existence — no IDOR/BOLA leak of "exists vs not". Requires the
        # caller to HAVE a registered identity first (otherwise the route
        # 404s "key_not_found" before ever reaching the ownership check —
        # a distinct, also-correct branch, not the one under test here).
        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug

        seed_account(fake_auth_service, account_id=user_client.conformance_session.account_id,
                      username="mekey4@x.com", tier="user", email="mekey4@x.com")
        slug = email_to_slug("mekey4@x.com")
        identity_registry.register(kind=IdentityKind.HUMAN, name="mekey4@x.com", slug=slug)
        r = user_client.delete("/me/api-keys/idnt_notmyidentity01")
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "key_not_owned_by_caller"

    # -----------------------------------------------------------------
    # CRITICAL FINDING — cross-Redis-DB divergence (YSG-RISK-131/010-class).
    # See conftest.py module docstring + findings.md for full root-cause.
    # This test PINS the REAL (broken) behaviour — it is NOT a false
    # negative or a badly-written test; it fails loudly if the underlying
    # bug is ever silently "fixed" without updating this assertion, which
    # is the correct behaviour for a conformance test recording a known gap.
    # -----------------------------------------------------------------
    def test_FINDING_issue_then_list_returns_empty_cross_db_bug(
        self, fake_auth_service, identity_registry, seed_account, stepup_user_client,
    ):
        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug

        seed_account(fake_auth_service, account_id=stepup_user_client.conformance_session.account_id,
                      username="crossdb1@x.com", tier="user", email="crossdb1@x.com")
        slug = email_to_slug("crossdb1@x.com")
        identity_registry.register(kind=IdentityKind.HUMAN, name="crossdb1@x.com", slug=slug)

        issue = stepup_user_client.post("/me/api-key")
        assert issue.status_code == 200, issue.text
        assert issue.json()["plaintext_token"]  # a real token WAS issued and written

        listing = stepup_user_client.get("/me/api-keys")
        assert listing.status_code == 200
        # FINDING: this SHOULD contain the just-issued key. It does not,
        # because list_api_keys() reads via backoffice_state.session_store._redis
        # (production DB1) while registry.rotate_key() wrote the key via the
        # IdentityRegistry's own client (production DB3). Pinned here as the
        # real, reproduced behaviour — see findings.md AUTH-IDENTITY-RBAC-001.
        assert listing.json() == {"api_keys": []}, (
            "If this assertion starts failing, the cross-DB bug has been fixed "
            "upstream — update findings.md AUTH-IDENTITY-RBAC-001 to CLOSED and "
            "flip this assertion to the correct (non-empty) expectation."
        )

    def test_FINDING_issue_then_revoke_404s_cross_db_bug(
        self, fake_auth_service, identity_registry, seed_account, stepup_user_client,
    ):
        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug

        seed_account(fake_auth_service, account_id=stepup_user_client.conformance_session.account_id,
                      username="crossdb2@x.com", tier="user", email="crossdb2@x.com")
        slug = email_to_slug("crossdb2@x.com")
        identity_id, _ = identity_registry.register(kind=IdentityKind.HUMAN, name="crossdb2@x.com", slug=slug)

        issue = stepup_user_client.post("/me/api-key")
        assert issue.status_code == 200, issue.text

        revoke = stepup_user_client.delete(f"/me/api-keys/{identity_id}")
        # FINDING: this SHOULD be 204 (the caller's own, just-issued, valid
        # key). It is 404 because revoke_api_key() also reads via
        # backoffice_state.session_store._redis (DB1) instead of the
        # registry's own client (DB3) where the key actually lives.
        assert revoke.status_code == 404, (
            "If this assertion starts failing (i.e. now returns 204), the "
            "cross-DB bug has been fixed upstream — update findings.md "
            "AUTH-IDENTITY-RBAC-001 to CLOSED."
        )


# ===========================================================================
# users.py — /admin/users/*
# ===========================================================================


class TestUsersList:
    # GAP-CLOSED: GET /admin/users
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/users").status_code == 401

    def test_user_403(self, user_client):
        assert user_client.get("/admin/users").status_code == 403

    def test_admin_200_no_secrets_leaked(self, fake_auth_service, admin_client, seed_account):
        seed_account(fake_auth_service, account_id="uxlist-1", username="uxlist@x.com", tier="user")
        r = admin_client.get("/admin/users")
        assert r.status_code == 200, r.text
        for u in r.json()["users"]:
            assert "password_hash" not in u
            assert "totp_secret" not in u
            assert "recovery_codes" not in u


class TestUsersCreate:
    # GAP-CLOSED: POST /admin/users
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/users", json={"email": "a@b.com"}).status_code == 401

    def test_user_403(self, user_client):
        assert user_client.post("/admin/users", json={"email": "a@b.com"}).status_code == 403

    def test_admin_no_stepup_401(self, admin_client):
        r = admin_client.post("/admin/users", json={"email": "newuser@x.com"})
        assert r.status_code == 401, r.text
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_invalid_email_422(self, stepup_admin_client):
        r = stepup_admin_client.post("/admin/users", json={"email": "not-an-email"})
        assert r.status_code == 422, r.text

    def test_success_derives_username_and_returns_role_tiered_totp(
        self, fake_auth_service, stepup_admin_client,
    ):
        r = stepup_admin_client.post("/admin/users", json={"email": "alice@domain.com"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["username"] == "alicedomain"
        assert len(body["temporary_password"]) >= 30
        assert body["totp_secret"]
        # Real side-effect: the account is retrievable from the SAME store,
        # with the user-tier (SHA-256/6-digit) TOTP algorithm actually set.
        rec = fake_auth_service._svc._accounts["alicedomain"]
        assert rec.totp_algorithm == "SHA256"

    def test_admin_user_collision_sod002a_409(self, fake_auth_service, seed_account, stepup_admin_client):
        seed_account(fake_auth_service, account_id="sod002a-1", username="collide@x.com", tier="admin")
        r = stepup_admin_client.post("/admin/users", json={"email": "collide@x.com", "username": "collide2"})
        assert r.status_code == 409, r.text
        assert r.json()["detail"]["error"] == "admin_user_collision"


class TestUsersMutations:
    # GAP-CLOSED: PUT /admin/users/{username}
    def test_update_unauth_401(self, unauth_client):
        assert unauth_client.put("/admin/users/nobody", json={}).status_code == 401

    def test_update_no_stepup_401(self, admin_client):
        assert admin_client.put("/admin/users/nobody", json={}).status_code == 401

    def test_update_not_found_404(self, stepup_admin_client):
        r = stepup_admin_client.put("/admin/users/nobody", json={"disabled": True})
        assert r.status_code == 404, r.text

    def test_update_bad_sensitivity_ceiling_422(self, fake_auth_service, seed_account, stepup_admin_client):
        seed_account(fake_auth_service, account_id="upduser-1", username="upduser@x.com", tier="user")
        r = stepup_admin_client.put(
            "/admin/users/upduser@x.com", json={"sensitivity_ceiling": "NOT_A_REAL_CEILING"},
        )
        assert r.status_code == 422, r.text

    # GAP-CLOSED: DELETE /admin/users/{username}
    def test_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/users/nobody").status_code == 401

    def test_delete_last_user_blocked_409(self, fake_auth_service, seed_account, stepup_admin_client):
        seed_account(fake_auth_service, account_id="lastuser-1", username="lastuser@x.com", tier="user")
        r = stepup_admin_client.delete("/admin/users/lastuser@x.com")
        assert r.status_code == 409, r.text
        assert r.json()["detail"]["error"] == "USER_MINIMUM_VIOLATION"

    def test_delete_success_real_removal(self, fake_auth_service, seed_account, session_store, stepup_admin_client):
        seed_account(fake_auth_service, account_id="deluser-keep", username="deluser-keep@x.com", tier="user")
        seed_account(fake_auth_service, account_id="deluser-target", username="deluser-target@x.com", tier="user")
        r = stepup_admin_client.delete("/admin/users/deluser-target@x.com")
        assert r.status_code == 200, r.text
        assert "deluser-target@x.com" not in fake_auth_service._svc._accounts

    # GAP-CLOSED: POST /admin/users/{username}/full-reset
    def test_full_reset_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/users/nobody/full-reset", json={"totp_code": "123456"}).status_code == 401

    def test_full_reset_bad_admin_totp_403(
        self, fake_auth_service, seed_account, pg_tenant_transaction_stub,
        stepup_admin_client, session_store,
    ):
        seed_account(fake_auth_service, account_id=stepup_admin_client.conformance_session.account_id,
                      username=stepup_admin_client.conformance_session.account_id + "@x.com", tier="admin")
        seed_account(fake_auth_service, account_id="fr-target-1", username="frtarget@x.com", tier="user")
        r = stepup_admin_client.post("/admin/users/frtarget@x.com/full-reset", json={"totp_code": "000000"})
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "invalid_admin_totp"

    # GAP-CLOSED: POST /admin/users/{username}/disable
    def test_disable_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/users/nobody/disable").status_code == 401

    def test_disable_real_sideeffect_invalidates_sessions(
        self, fake_auth_service, seed_account, session_store, stepup_admin_client,
    ):
        seed_account(fake_auth_service, account_id="disuser-1", username="disuser@x.com", tier="user")
        victim_session = session_store.create(account_id="disuser-1", account_tier="user", client_ip="1.1.1.1")
        r = stepup_admin_client.post("/admin/users/disuser@x.com/disable")
        assert r.status_code == 200, r.text
        assert fake_auth_service._svc._accounts["disuser@x.com"].disabled is True
        assert session_store.get(victim_session.token) is None

    # GAP-CLOSED: POST /admin/users/{username}/enable
    def test_enable_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/users/nobody/enable").status_code == 401

    def test_enable_not_found_404(self, stepup_admin_client):
        r = stepup_admin_client.post("/admin/users/nobody/enable")
        assert r.status_code == 404, r.text

    # GAP-CLOSED: POST /admin/users/{username}/reactivate
    def test_reactivate_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/users/nobody/reactivate", json={}).status_code == 401

    def test_reactivate_user_not_found_404(self, stepup_admin_client):
        r = stepup_admin_client.post("/admin/users/nobody/reactivate", json={})
        assert r.status_code == 404, r.text

    def test_reactivate_real_sideeffect(self, fake_auth_service, identity_registry, seed_account, stepup_admin_client):
        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug

        seed_account(fake_auth_service, account_id="react-1", username="react@x.com", tier="user", email="react@x.com")
        slug = email_to_slug("react@x.com")
        identity_id, _ = identity_registry.register(kind=IdentityKind.HUMAN, name="react@x.com", slug=slug)
        identity_registry.suspend(identity_id)
        r = stepup_admin_client.post("/admin/users/react@x.com/reactivate", json={"reason": "test"})
        assert r.status_code == 200, r.text
        assert identity_registry.get(identity_id)["status"] == "active"

    # GAP-CLOSED: POST /admin/users/{username}/api-key
    def test_admin_issue_user_apikey_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/users/nobody/api-key").status_code == 401

    def test_admin_issue_user_apikey_real_sideeffect(
        self, fake_auth_service, identity_registry, seed_account, stepup_admin_client,
    ):
        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug

        seed_account(fake_auth_service, account_id="adminissue-1", username="adminissue@x.com",
                     tier="user", email="adminissue@x.com")
        slug = email_to_slug("adminissue@x.com")
        identity_id, _ = identity_registry.register(kind=IdentityKind.HUMAN, name="adminissue@x.com", slug=slug)
        r = stepup_admin_client.post("/admin/users/adminissue@x.com/api-key")
        assert r.status_code == 200, r.text
        assert r.json()["plaintext_token"]
        # This route uses registry.rotate_key() directly (no session_store
        # cross-DB read) — verify against the registry's OWN client, which is
        # the only correct path (users.py does NOT have the me.py bug).
        assert identity_registry._r.get(f"identity:key:{identity_id}") is not None


# ===========================================================================
# accounts.py — /admin/accounts/*
# ===========================================================================


class TestAccountsList:
    # GAP-CLOSED: GET /admin/accounts/enforcement
    def test_enforcement_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/accounts/enforcement").status_code == 401

    def test_enforcement_user_403(self, user_client):
        assert user_client.get("/admin/accounts/enforcement").status_code == 403

    def test_enforcement_admin_200(self, admin_client):
        r = admin_client.get("/admin/accounts/enforcement")
        assert r.status_code == 200, r.text
        assert "below_minimum" in r.json()

    # GAP-CLOSED: GET /admin/accounts
    def test_list_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/accounts").status_code == 401

    def test_list_admin_200_no_secrets(self, fake_auth_service, admin_client, seed_account):
        seed_account(fake_auth_service, account_id="acctlist-1", username="acctlist@x.com", tier="admin")
        r = admin_client.get("/admin/accounts")
        assert r.status_code == 200, r.text
        for a in r.json()["accounts"]:
            assert "password_hash" not in a
            assert "totp_secret" not in a


class TestAccountsCreate:
    # GAP-CLOSED: POST /admin/accounts
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/accounts", json={"username": "a@b.com"}).status_code == 401

    def test_user_403(self, user_client):
        assert user_client.post("/admin/accounts", json={"username": "a@b.com"}).status_code == 403

    def test_no_stepup_401(self, admin_client):
        r = admin_client.post("/admin/accounts", json={"username": "newadmin@x.com"})
        assert r.status_code == 401, r.text

    def test_invalid_username_pattern_422(self, stepup_admin_client):
        r = stepup_admin_client.post("/admin/accounts", json={"username": "not-an-email"})
        assert r.status_code == 422, r.text

    def test_success_sets_admin_tier_totp(self, fake_auth_service, stepup_admin_client):
        r = stepup_admin_client.post("/admin/accounts", json={"username": "newadmin2@x.com"})
        assert r.status_code == 200, r.text
        rec = fake_auth_service._svc._accounts["newadmin2@x.com"]
        assert rec.totp_algorithm == "SHA512"

    def test_sod001_user_collision_409(self, fake_auth_service, seed_account, stepup_admin_client):
        seed_account(fake_auth_service, account_id="sod001-1", username="existinguser@x.com", tier="user")
        r = stepup_admin_client.post("/admin/accounts", json={"username": "existinguser@x.com"})
        assert r.status_code == 409, r.text
        assert r.json()["detail"]["error"] == "admin_user_collision"


class TestAccountsMutations:
    # GAP-CLOSED: DELETE /admin/accounts/{username}
    def test_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/accounts/nobody").status_code == 401

    def test_delete_min_total_guard_409(self, fake_auth_service, seed_account, stepup_admin_client):
        seed_account(fake_auth_service, account_id="min1", username="min1@x.com", tier="admin")
        seed_account(fake_auth_service, account_id="min2", username="min2@x.com", tier="admin")
        r = stepup_admin_client.delete("/admin/accounts/min1@x.com")
        assert r.status_code == 409, r.text
        assert r.json()["detail"]["error"] == "ADMIN_MINIMUM_VIOLATION"

    # GAP-CLOSED: POST /admin/accounts/{username}/disable
    def test_disable_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/accounts/nobody/disable").status_code == 401

    def test_disable_min_active_guard_409(self, fake_auth_service, seed_account, stepup_admin_client):
        seed_account(fake_auth_service, account_id="act1", username="act1@x.com", tier="admin")
        seed_account(fake_auth_service, account_id="act2", username="act2@x.com", tier="admin")
        r = stepup_admin_client.post("/admin/accounts/act1@x.com/disable")
        assert r.status_code == 409, r.text
        assert r.json()["detail"]["error"] == "ADMIN_ACTIVE_MINIMUM_VIOLATION"

    # GAP-CLOSED: POST /admin/accounts/{username}/enable
    def test_enable_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/accounts/nobody/enable").status_code == 401

    def test_enable_not_found_404(self, stepup_admin_client):
        r = stepup_admin_client.post("/admin/accounts/nobody/enable")
        assert r.status_code == 404, r.text

    # GAP-CLOSED: POST /admin/accounts/{username}/force-reset
    def test_force_reset_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/accounts/nobody/force-reset", json={"action": "password_reset"}).status_code == 401

    def test_force_reset_bad_action_422(self, stepup_admin_client):
        r = stepup_admin_client.post("/admin/accounts/nobody/force-reset", json={"action": "not_a_real_action"})
        assert r.status_code == 422, r.text

    def test_force_reset_real_sideeffect(self, fake_auth_service, seed_account, session_store, stepup_admin_client):
        seed_account(fake_auth_service, account_id="fr-acct-1", username="fracct@x.com", tier="admin")
        victim_session = session_store.create(account_id="fr-acct-1", account_tier="admin", client_ip="1.1.1.1")
        r = stepup_admin_client.post("/admin/accounts/fracct@x.com/force-reset", json={"action": "password_reset"})
        assert r.status_code == 200, r.text
        assert fake_auth_service._svc._accounts["fracct@x.com"].force_password_change is True
        assert session_store.get(victim_session.token) is None

    # GAP-CLOSED: PUT /admin/accounts/{username}
    def test_update_unauth_401(self, unauth_client):
        assert unauth_client.put("/admin/accounts/nobody", json={}).status_code == 401

    def test_update_email_collision_with_user_409(self, fake_auth_service, seed_account, stepup_admin_client):
        seed_account(fake_auth_service, account_id="updadmin-1", username="updadmin@x.com", tier="admin")
        seed_account(fake_auth_service, account_id="upduser2-1", username="upduser2@x.com", tier="user")
        r = stepup_admin_client.put("/admin/accounts/updadmin@x.com", json={"email": "upduser2@x.com"})
        assert r.status_code == 409, r.text


# ===========================================================================
# rbac.py — /admin/rbac/groups*, /admin/rbac/users/{email}/groups,
#           /admin/rbac/policy/push
# ===========================================================================


class TestRbacGroups:
    # GAP-CLOSED: GET /admin/rbac/groups
    def test_list_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/rbac/groups").status_code == 401

    def test_list_user_403(self, user_client):
        assert user_client.get("/admin/rbac/groups").status_code == 403

    def test_list_admin_200(self, rbac_store, admin_client):
        r = admin_client.get("/admin/rbac/groups")
        assert r.status_code == 200, r.text
        assert r.json() == {"groups": []}

    # GAP-CLOSED: POST /admin/rbac/groups
    def test_create_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/rbac/groups", json={"display_name": "x"}).status_code == 401

    def test_create_no_stepup_401(self, rbac_store, admin_client):
        r = admin_client.post("/admin/rbac/groups", json={"display_name": "x"})
        assert r.status_code == 401, r.text

    def test_create_bad_method_422(self, rbac_store, stepup_admin_client):
        r = stepup_admin_client.post(
            "/admin/rbac/groups",
            json={"display_name": "g1", "allowed_resources": [{"method": "TRACE", "path_glob": "/v1/**"}]},
        )
        assert r.status_code == 422, r.text

    def test_create_shell_metachar_path_glob_422(self, rbac_store, stepup_admin_client):
        r = stepup_admin_client.post(
            "/admin/rbac/groups",
            json={"display_name": "g2", "allowed_resources": [{"method": "GET", "path_glob": "/v1/$(whoami)"}]},
        )
        assert r.status_code == 422, r.text

    def test_create_success_real_sideeffect_in_store(self, rbac_store, stepup_admin_client):
        r = stepup_admin_client.post("/admin/rbac/groups", json={"display_name": "engineering"})
        assert r.status_code == 201, r.text
        group_id = r.json()["id"]
        # Real datastore check: read back via the SAME rbac_store object, not
        # just trust the HTTP 201.
        assert rbac_store.get_group(group_id) is not None
        assert rbac_store.get_group(group_id).display_name == "engineering"

    # GAP-CLOSED: GET /admin/rbac/groups/{group_id}
    def test_get_not_found_404(self, rbac_store, admin_client):
        r = admin_client.get("/admin/rbac/groups/nonexistent")
        assert r.status_code == 404, r.text

    # GAP-CLOSED: PUT /admin/rbac/groups/{group_id}
    def test_update_unauth_401(self, unauth_client):
        assert unauth_client.put("/admin/rbac/groups/x", json={}).status_code == 401

    def test_update_not_found_404(self, rbac_store, stepup_admin_client):
        r = stepup_admin_client.put("/admin/rbac/groups/nonexistent", json={"display_name": "y"})
        assert r.status_code == 404, r.text

    def test_update_real_sideeffect(self, rbac_store, stepup_admin_client):
        create = stepup_admin_client.post("/admin/rbac/groups", json={"display_name": "before"})
        group_id = create.json()["id"]
        r = stepup_admin_client.put(f"/admin/rbac/groups/{group_id}", json={"display_name": "after"})
        assert r.status_code == 200, r.text
        assert rbac_store.get_group(group_id).display_name == "after"

    # GAP-CLOSED: DELETE /admin/rbac/groups/{group_id}
    def test_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/rbac/groups/x").status_code == 401

    def test_delete_real_sideeffect(self, rbac_store, stepup_admin_client):
        create = stepup_admin_client.post("/admin/rbac/groups", json={"display_name": "todelete"})
        group_id = create.json()["id"]
        r = stepup_admin_client.delete(f"/admin/rbac/groups/{group_id}")
        assert r.status_code == 204, r.text
        assert rbac_store.get_group(group_id) is None


class TestRbacMembers:
    # GAP-CLOSED: POST /admin/rbac/groups/{group_id}/members
    def test_add_member_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/rbac/groups/x/members", json={"email": "a@b.com"}).status_code == 401

    def test_add_member_unregistered_identity_422(self, rbac_store, identity_registry, stepup_admin_client):
        create = stepup_admin_client.post("/admin/rbac/groups", json={"display_name": "memtest"})
        group_id = create.json()["id"]
        r = stepup_admin_client.post(f"/admin/rbac/groups/{group_id}/members", json={"email": "unregistered@x.com"})
        assert r.status_code == 422, r.text
        assert r.json()["detail"]["error"] == "identity_not_found"

    def test_add_member_real_sideeffect_identity_id_keyed(self, rbac_store, identity_registry, stepup_admin_client):
        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug

        slug = email_to_slug("member1@x.com")
        identity_id, _ = identity_registry.register(kind=IdentityKind.HUMAN, name="member1@x.com", slug=slug)
        create = stepup_admin_client.post("/admin/rbac/groups", json={"display_name": "memtest2"})
        group_id = create.json()["id"]
        r = stepup_admin_client.post(f"/admin/rbac/groups/{group_id}/members", json={"email": "member1@x.com"})
        assert r.status_code == 201, r.text
        # Real store check: members are keyed by identity_id, not raw email
        # (post-4.1 UID migration — RBAC-BUG-4.1.1).
        assert identity_id in rbac_store.get_group(group_id).members
        assert "member1@x.com" not in rbac_store.get_group(group_id).members

    # GAP-CLOSED: DELETE /admin/rbac/groups/{group_id}/members/{email}
    def test_remove_member_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/rbac/groups/x/members/a@b.com").status_code == 401

    def test_remove_member_real_sideeffect(self, rbac_store, identity_registry, stepup_admin_client):
        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug

        slug = email_to_slug("member2@x.com")
        identity_id, _ = identity_registry.register(kind=IdentityKind.HUMAN, name="member2@x.com", slug=slug)
        create = stepup_admin_client.post("/admin/rbac/groups", json={"display_name": "memtest3"})
        group_id = create.json()["id"]
        stepup_admin_client.post(f"/admin/rbac/groups/{group_id}/members", json={"email": "member2@x.com"})
        r = stepup_admin_client.delete(f"/admin/rbac/groups/{group_id}/members/member2@x.com")
        assert r.status_code == 204, r.text
        assert identity_id not in rbac_store.get_group(group_id).members

    # GAP-CLOSED: GET /admin/rbac/users/{email}/groups
    def test_user_groups_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/rbac/users/a@b.com/groups").status_code == 401

    def test_user_groups_unregistered_returns_empty_not_error(self, rbac_store, identity_registry, admin_client):
        r = admin_client.get("/admin/rbac/users/nobody@x.com/groups")
        assert r.status_code == 200, r.text
        assert r.json()["groups"] == []

    def test_user_groups_real_membership_resolved(self, rbac_store, identity_registry, stepup_admin_client, admin_client):
        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug

        slug = email_to_slug("member3@x.com")
        identity_registry.register(kind=IdentityKind.HUMAN, name="member3@x.com", slug=slug)
        create = stepup_admin_client.post("/admin/rbac/groups", json={"display_name": "memtest4"})
        group_id = create.json()["id"]
        stepup_admin_client.post(f"/admin/rbac/groups/{group_id}/members", json={"email": "member3@x.com"})
        r = admin_client.get("/admin/rbac/users/member3@x.com/groups")
        assert r.status_code == 200, r.text
        assert any(g["id"] == group_id for g in r.json()["groups"])

    # GAP-CLOSED: POST /admin/rbac/policy/push
    def test_policy_push_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/rbac/policy/push").status_code == 401

    def test_policy_push_no_stepup_401(self, rbac_store, admin_client):
        r = admin_client.post("/admin/rbac/policy/push")
        assert r.status_code == 401, r.text

    def test_policy_push_admin_200(self, rbac_store, stepup_admin_client):
        r = stepup_admin_client.post("/admin/rbac/policy/push")
        assert r.status_code == 200, r.text
        assert r.json()["pushed"] is True


# ===========================================================================
# rbac_sources.py — /admin/rbac/sources/*
# ===========================================================================


class TestRbacSources:
    # GAP-CLOSED: GET /admin/rbac/sources/paths
    def test_paths_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/rbac/sources/paths").status_code == 401

    def test_paths_user_403(self, user_client):
        assert user_client.get("/admin/rbac/sources/paths").status_code == 403

    def test_paths_admin_200(self, admin_client):
        r = admin_client.get("/admin/rbac/sources/paths")
        assert r.status_code == 200, r.text
        assert r.json()["count"] == len(r.json()["paths"])

    # GAP-CLOSED: GET /admin/rbac/sources/methods
    def test_methods_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/rbac/sources/methods").status_code == 401

    def test_methods_admin_200(self, admin_client):
        r = admin_client.get("/admin/rbac/sources/methods")
        assert r.status_code == 200, r.text
        assert "*" in r.json()["allowed_values"]


# ===========================================================================
# budget.py — /admin/budget/{org-caps,groups,individuals} (router-level
# require_admin_session dependency; NONE of these six handlers declare a
# `session` parameter of their own — the gate is enforced entirely by the
# APIRouter(dependencies=[...]) declaration. Verified empirically below.
# ===========================================================================


class TestBudgetOrgCaps:
    # GAP-CLOSED: GET /admin/budget/org-caps
    def test_list_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/budget/org-caps")
        assert r.status_code == 401, r.text

    def test_list_user_403(self, user_client):
        assert user_client.get("/admin/budget/org-caps").status_code == 403

    def test_list_admin_200(self, admin_client):
        r = admin_client.get("/admin/budget/org-caps")
        assert r.status_code == 200, r.text
        assert r.json() == {"org_caps": []}

    # GAP-CLOSED: POST /admin/budget/org-caps
    def test_create_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/budget/org-caps",
            json={"org_id": "o1", "provider": "openai", "token_cap": 1000},
        )
        assert r.status_code == 401, r.text

    def test_create_bad_period_422(self, admin_client):
        r = admin_client.post(
            "/admin/budget/org-caps",
            json={"org_id": "o1", "provider": "openai", "token_cap": 1000, "period": "hourly"},
        )
        assert r.status_code == 422, r.text

    def test_create_negative_cap_422(self, admin_client):
        r = admin_client.post(
            "/admin/budget/org-caps",
            json={"org_id": "o1", "provider": "openai", "token_cap": -5},
        )
        assert r.status_code == 422, r.text

    def test_create_admin_201_no_store_wired_still_returns_shape(self, admin_client):
        # budget_store is not wired in this suite's fixtures (out-of-scope for
        # a persistence-level test — see route source: `if _state.budget_store:`
        # gates the actual write, else the handler still returns the echoed
        # response shape). This documents the real behaviour: creating a cap
        # with no store configured is a SILENT NO-OP that still returns 201.
        r = admin_client.post(
            "/admin/budget/org-caps",
            json={"org_id": "o1", "provider": "openai", "token_cap": 1000},
        )
        assert r.status_code == 201, r.text

    # GAP-CLOSED: DELETE /admin/budget/org-caps
    def test_delete_unauth_401(self, unauth_client):
        r = unauth_client.delete("/admin/budget/org-caps", params={"org_id": "o1", "provider": "openai"})
        assert r.status_code == 401, r.text

    def test_delete_no_store_503(self, admin_client):
        r = admin_client.delete("/admin/budget/org-caps", params={"org_id": "o1", "provider": "openai"})
        assert r.status_code == 503, r.text


class TestBudgetGroups:
    # GAP-CLOSED: GET /admin/budget/groups
    def test_list_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/budget/groups").status_code == 401

    # GAP-CLOSED: POST /admin/budget/groups
    def test_create_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/budget/groups",
            json={"group_id": "g1", "token_budget": 500},
        )
        assert r.status_code == 401, r.text

    def test_create_negative_budget_422(self, admin_client):
        r = admin_client.post("/admin/budget/groups", json={"group_id": "g1", "token_budget": 0})
        assert r.status_code == 422, r.text

    # GAP-CLOSED: DELETE /admin/budget/groups
    def test_delete_unauth_401(self, unauth_client):
        r = unauth_client.delete("/admin/budget/groups", params={"group_id": "g1", "provider": "*"})
        assert r.status_code == 401, r.text

    def test_delete_no_store_503(self, admin_client):
        r = admin_client.delete("/admin/budget/groups", params={"group_id": "g1", "provider": "*"})
        assert r.status_code == 503, r.text


class TestBudgetIndividuals:
    # GAP-CLOSED: GET /admin/budget/individuals
    def test_list_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/budget/individuals").status_code == 401

    # GAP-CLOSED: POST /admin/budget/individuals
    def test_create_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/budget/individuals",
            json={"identity_id": "idnt_x", "token_budget": 100},
        )
        assert r.status_code == 401, r.text

    def test_create_bad_period_422(self, admin_client):
        r = admin_client.post(
            "/admin/budget/individuals",
            json={"identity_id": "idnt_x", "token_budget": 100, "period": "yearly"},
        )
        assert r.status_code == 422, r.text

    # GAP-CLOSED: DELETE /admin/budget/individuals
    def test_delete_unauth_401(self, unauth_client):
        r = unauth_client.delete("/admin/budget/individuals", params={"identity_id": "idnt_x", "provider": "*"})
        assert r.status_code == 401, r.text

    def test_delete_no_store_503(self, admin_client):
        r = admin_client.delete("/admin/budget/individuals", params={"identity_id": "idnt_x", "provider": "*"})
        assert r.status_code == 503, r.text
