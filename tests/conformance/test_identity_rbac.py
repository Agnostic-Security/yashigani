"""
Conformance group: IDENTITY-RBAC.

Closes G1 (Lu audit YCS-20260723-v4.1.2-CONFORMANCE) for:
  routes/accounts.py      (8 endpoints) — /admin/accounts/*
  routes/users.py         (9 endpoints) — /admin/users/*
  routes/scim.py          (7 endpoints) — /scim/v2/*
  routes/rbac.py          (9 endpoints) — /admin/rbac/*
  routes/rbac_sources.py  (2 endpoints) — /admin/rbac/sources/*
Total: 35 endpoints (Lu matrix rows 13-20, 339-347, 265-271, 250-258, 259-260;
verified against the live route walk in test_group_covers_all_declared_routes
below, which is authoritative).

Convention: see tests/conformance/conftest.py module docstring.

MOCKED: backoffice_state.auth_service is PostgresLocalAuthService — async,
Postgres-only, no fakeredis equivalent. FakeAuthService below implements
exactly the methods accounts.py/users.py call on it (grepped 2026-07-23),
storing rows as the REAL AccountRecord dataclass (yashigani.auth.local_auth)
so field access on the route side is genuine, not duck-typed.

REAL (not mocked): backoffice_state.identity_registry uses the REAL
IdentityRegistry class (constructor accepts redis_client directly —
src/yashigani/identity/registry.py:152) against fakeredis. backoffice_state.
rbac_store uses the REAL RBACStore (src/yashigani/rbac/store.py:43,
redis_client direct). This gives genuine persistence assertions for RBAC
group CRUD, member add/remove, and identity reactivate/suspend/rotate-key.

SPEC-DIVERGENCE FINDING (flagged per convention, not silently worked around):
scim.py's Group member endpoints (POST/PATCH /scim/v2/Groups) write and read
RBACGroup.members using the RAW EMAIL string directly (scim.py:394-401,
scim.py:459-497, scim.py:216-232 treats group.members entries as emails).
RBACStore's own docstring (rbac/store.py:9-12) and rbac.py's admin-plane
group-member endpoints (rbac.py:352-355, `_email_to_identity_id`) require
group members to be the opaque identity_id (idnt_{12hex}) after the 4.1 UID
migration (RBAC-BUG-4.1.1). Consequence: a member added via SCIM is
email-keyed in `rbac:user:{member}`/`RBACGroup.members`, while a member
added via /admin/rbac/groups/{id}/members is identity_id-keyed — the two
provisioning paths write to DISJOINT keyspaces for the same underlying user
and a policy decision keyed on identity_id will never see an SCIM-provisioned
membership (or vice-versa). Verified by test_scim_group_members_use_raw_email_
not_identity_id below, which pins the REAL (divergent) behaviour rather than
papering over it. Reported to Maxine/Iris for a design-review ticket.

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

import dataclasses
import time
import uuid

import pytest

pytestmark = pytest.mark.conformance

_GROUP_PREFIXES = ("/admin/accounts", "/admin/users", "/scim/v2", "/admin/rbac")


# ---------------------------------------------------------------------------
# Group-specific state wiring
# ---------------------------------------------------------------------------


class FakeAuthService:
    """
    MOCKED: see module docstring. Implements ONLY the async methods
    accounts.py / users.py actually call on `backoffice_state.auth_service`
    (grepped `state.auth_service\\.` 2026-07-23): total_admin_count,
    active_admin_count, total_user_count, list_accounts, get_account,
    get_account_by_id, get_account_by_email, create_admin, create_user,
    delete_account, disable, enable, force_password_change,
    force_totp_reprovision, set_totp_secret_direct, set_email,
    full_reset_user.

    full_reset_user() verifies the admin TOTP code with the REAL
    yashigani.auth.totp.verify_totp() function — not a stub that always
    returns True — so the 403 invalid_admin_totp / 200 success split in the
    tests below is a genuine assertion of the real HMAC-based verification.
    """

    def __init__(self) -> None:
        self._by_username: dict = {}

    def _seed(self, record) -> None:
        self._by_username[record.username] = record

    async def total_admin_count(self) -> int:
        return sum(1 for r in self._by_username.values() if r.account_tier == "admin")

    async def active_admin_count(self) -> int:
        return sum(
            1
            for r in self._by_username.values()
            if r.account_tier == "admin" and not r.disabled
        )

    async def total_user_count(self) -> int:
        return sum(1 for r in self._by_username.values() if r.account_tier == "user")

    async def list_accounts(self):
        return list(self._by_username.values())

    async def get_account(self, username: str):
        return self._by_username.get(username)

    async def get_account_by_id(self, account_id: str):
        for r in self._by_username.values():
            if r.account_id == account_id:
                return r
        return None

    async def get_account_by_email(self, email: str):
        for r in self._by_username.values():
            if (r.email or "").lower() == email.lower():
                return r
        return None

    async def create_admin(
        self,
        username: str,
        auto_generate: bool = True,
        plaintext_password=None,
        *,
        force_password_change: bool = True,
        force_totp_provision: bool = True,
    ):
        from yashigani.auth.local_auth import AccountRecord

        plaintext = plaintext_password or f"temp-pw-{username}"
        record = AccountRecord(
            account_id=str(uuid.uuid4()),
            username=username,
            password_hash="fake-hash",
            totp_secret="",
            recovery_codes=None,
            account_tier="admin",
            email=username,
            force_password_change=force_password_change,
            force_totp_provision=force_totp_provision,
        )
        self._seed(record)
        return record, (plaintext if auto_generate else None)

    async def create_user(self, username: str, plaintext_password: str):
        from yashigani.auth.local_auth import AccountRecord

        record = AccountRecord(
            account_id=str(uuid.uuid4()),
            username=username,
            password_hash="fake-hash",
            totp_secret="",
            recovery_codes=None,
            account_tier="user",
            force_password_change=True,
            force_totp_provision=True,
        )
        self._seed(record)
        return record

    async def delete_account(self, username: str) -> bool:
        return self._by_username.pop(username, None) is not None

    async def disable(self, username: str) -> bool:
        r = self._by_username.get(username)
        if r is None:
            return False
        r.disabled = True
        return True

    async def enable(self, username: str) -> bool:
        r = self._by_username.get(username)
        if r is None:
            return False
        r.disabled = False
        return True

    async def force_password_change(self, username: str) -> bool:
        r = self._by_username.get(username)
        if r is None:
            return False
        r.force_password_change = True
        return True

    async def force_totp_reprovision(self, username: str) -> bool:
        r = self._by_username.get(username)
        if r is None:
            return False
        r.totp_secret = ""
        r.force_totp_provision = True
        return True

    async def set_totp_secret_direct(self, username: str, totp_secret: str, algorithm: str = "SHA1") -> bool:
        r = self._by_username.get(username)
        if r is None:
            return False
        r.totp_secret = totp_secret
        r.totp_algorithm = algorithm
        return True

    async def set_email(self, username: str, email: str) -> bool:
        r = self._by_username.get(username)
        if r is None:
            return False
        r.email = email
        return True

    async def full_reset_user(
        self,
        username: str,
        admin_totp_secret: str,
        admin_totp_code: str,
        admin_totp_algorithm: str = "SHA1",
        admin_totp_digits: int = 8,
    ):
        from yashigani.auth.totp import verify_totp

        if not verify_totp(
            admin_totp_secret,
            admin_totp_code,
            set(),
            algorithm=admin_totp_algorithm,
            digits=admin_totp_digits,
        ):
            return False, "invalid_admin_totp"
        r = self._by_username.get(username)
        if r is None:
            return False, "user_not_found"
        r.totp_secret = ""
        r.totp_algorithm = "SHA1"
        r.force_password_change = True
        r.force_totp_provision = True
        return True, "ok"


def _totp_now(secret: str, algorithm: str, digits: int) -> str:
    """Compute a genuinely valid TOTP code for `secret` at the current
    time-slot using the app's OWN raw RFC 4226/6238 implementation
    (yashigani.auth.totp._totp_at — the same function verify_totp() calls
    internally). Whitebox re-use of the real primitive, not a
    re-implementation that could silently diverge from it."""
    from yashigani.auth import totp as _totp_mod

    return _totp_mod._totp_at(secret, int(time.time()), algorithm, digits)


@pytest.fixture
def auth_state(fake_redis_client, mock_audit_writer, monkeypatch):
    """Wires FakeAuthService (see class docstring) + a REAL IdentityRegistry
    (redis_client-constructed — src/yashigani/identity/registry.py:152)
    against fakeredis into backoffice_state."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.identity.registry import IdentityRegistry

    fake_auth = FakeAuthService()
    registry = IdentityRegistry(redis_client=fake_redis_client)
    monkeypatch.setattr(backoffice_state, "auth_service", fake_auth, raising=False)
    monkeypatch.setattr(backoffice_state, "identity_registry", registry, raising=False)
    return fake_auth, registry


@pytest.fixture
def rbac_state(fake_redis_client, monkeypatch):
    """Wires the REAL RBACStore against fakeredis (constructor takes
    redis_client directly — src/yashigani/rbac/store.py:43). Also points
    opa_url at a closed local port so the fire-and-forget OPA push
    (rbac.py `_push`) fails FAST via connection-refused instead of depending
    on DNS resolution of the default 'policy' hostname (unavailable offline,
    and DNS lookup latency for an unresolvable host is not guaranteed
    bounded the way a refused TCP connect to 127.0.0.1 is)."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.rbac.store import RBACStore

    store = RBACStore(redis_client=fake_redis_client)
    monkeypatch.setattr(backoffice_state, "rbac_store", store, raising=False)
    monkeypatch.setattr(backoffice_state, "opa_url", "http://127.0.0.1:1", raising=False)
    return store


@pytest.fixture
def scim_licensed():
    """Temporarily upgrades the active license to a tier carrying the 'scim'
    feature. The Community default (COMMUNITY_LICENSE, features=frozenset())
    fail-closes every SCIM MUTATION route with 402 LICENSE_FEATURE_GATED —
    verified as real, deliberate behaviour (scim.py require_feature("scim")
    calls), not a bug. `enforcer._license` is a process-global singleton, so
    this fixture restores COMMUNITY_LICENSE on teardown to avoid leaking
    state into other groups' tests sharing this pytest session."""
    from yashigani.licensing import enforcer
    from yashigani.licensing.model import COMMUNITY_LICENSE, LicenseFeature, LicenseTier

    licensed = dataclasses.replace(
        COMMUNITY_LICENSE,
        tier=LicenseTier.PROFESSIONAL,
        features=frozenset({LicenseFeature.SCIM}),
    )
    enforcer.set_license(licensed)
    yield licensed
    enforcer.set_license(COMMUNITY_LICENSE)


def _register_human(registry, email: str, suspended: bool = False) -> str:
    """Register a HUMAN identity for `email` via the REAL IdentityRegistry
    and return its identity_id. Optionally suspends it immediately (for
    reactivate_user tests)."""
    from yashigani.identity.registry import IdentityKind
    from yashigani.identity.slug import email_to_slug

    slug = email_to_slug(email)
    identity_id, _plaintext_key = registry.register(kind=IdentityKind.HUMAN, name=email, slug=slug)
    if suspended:
        registry.suspend(identity_id)
    return identity_id


# ---------------------------------------------------------------------------
# Route-completeness check (this IS the coverage gate for this group)
# ---------------------------------------------------------------------------


def test_group_covers_all_declared_routes(route_prefix_filter):
    declared = route_prefix_filter(*_GROUP_PREFIXES)
    declared_set = {(m, p) for (m, p, _r) in declared}
    assert len(declared_set) == 35, (
        f"Expected 35 declared routes under {_GROUP_PREFIXES}, found "
        f"{len(declared_set)}: {sorted(declared_set)}"
    )


# ---------------------------------------------------------------------------
# accounts.py — 8 endpoints
# ---------------------------------------------------------------------------


class TestAccountsEnforcement:
    # GAP-CLOSED: GET /admin/accounts/enforcement
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/accounts/enforcement").status_code == 401

    def test_user_tier_403(self, user_client):
        r = user_client.get("/admin/accounts/enforcement")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "insufficient_tier"

    def test_admin_below_minimum(self, admin_client, auth_state):
        r = admin_client.get("/admin/accounts/enforcement")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 0 and body["below_minimum"] is True
        assert body["action_required"] is True
        assert body["min_total"] == 2 and body["min_active"] == 2


class TestAccountsList:
    # GAP-CLOSED: GET /admin/accounts
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/accounts").status_code == 401

    def test_admin_empty_list(self, admin_client, auth_state):
        r = admin_client.get("/admin/accounts")
        assert r.status_code == 200
        assert r.json() == {
            "accounts": [], "total": 0, "active": 0,
            "min_total": 2, "min_active": 2, "soft_target": 3, "below_soft_target": True,
        }

    def test_admin_list_excludes_secrets_bopla(self, admin_client, auth_state):
        """BOPLA (#90): AdminAccountPublic strips password_hash/totp_secret/
        recovery_codes from the list response."""
        fake_auth, _registry = auth_state
        import asyncio

        asyncio.new_event_loop().run_until_complete(fake_auth.create_admin("seed@example.com"))
        r = admin_client.get("/admin/accounts")
        assert r.status_code == 200
        acct = r.json()["accounts"][0]
        assert "password_hash" not in acct and "totp_secret" not in acct


class TestAccountsCreate:
    # GAP-CLOSED: POST /admin/accounts
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/accounts", json={"username": "new@example.com"})
        assert r.status_code == 401

    def test_admin_without_stepup_401(self, admin_client, auth_state):
        r = admin_client.post("/admin/accounts", json={"username": "new@example.com"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_stepup_create_success(self, stepup_admin_client, auth_state, mock_audit_writer):
        r = stepup_admin_client.post("/admin/accounts", json={"username": "newadmin@example.com"})
        assert r.status_code == 200
        body = r.json()
        assert body["username"] == "newadmin@example.com"
        assert body["totp_secret"] and body["temporary_password"]
        mock_audit_writer.write.assert_called_once()

    def test_sod001_user_email_collision_409(self, stepup_admin_client, auth_state):
        """SoD-001: an existing user-tier account with the same
        username/email must block admin creation (admin/user identity
        stores must stay disjoint)."""
        fake_auth, _registry = auth_state
        import asyncio

        asyncio.new_event_loop().run_until_complete(fake_auth.create_user("collide@example.com", "x"))
        r = stepup_admin_client.post("/admin/accounts", json={"username": "collide@example.com"})
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "admin_user_collision"


class TestAccountsDelete:
    # GAP-CLOSED: DELETE /admin/accounts/{username}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/accounts/nope@example.com").status_code == 401

    def test_stepup_not_found_404(self, stepup_admin_client, auth_state):
        r = stepup_admin_client.delete("/admin/accounts/nope@example.com")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "account_not_found"

    def test_min_total_guard_then_success(self, stepup_admin_client, auth_state, mock_audit_writer):
        """Guard: total admin accounts must never drop below admin_min_total
        (2). Seed 3 admins so the first delete succeeds (3->2); the second
        delete must be blocked (2<=2)."""
        fake_auth, _registry = auth_state
        import asyncio

        loop = asyncio.new_event_loop()
        for i in range(3):
            loop.run_until_complete(fake_auth.create_admin(f"admin{i}@example.com"))

        r1 = stepup_admin_client.delete("/admin/accounts/admin0@example.com")
        assert r1.status_code == 200
        mock_audit_writer.write.assert_called()

        r2 = stepup_admin_client.delete("/admin/accounts/admin1@example.com")
        assert r2.status_code == 409
        assert r2.json()["detail"]["error"] == "ADMIN_MINIMUM_VIOLATION"


class TestAccountsDisable:
    # GAP-CLOSED: POST /admin/accounts/{username}/disable
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/accounts/x@example.com/disable").status_code == 401

    def test_min_active_guard_then_success(self, stepup_admin_client, auth_state, mock_audit_writer):
        """Guard: active admin count must never drop below admin_min_active
        (2). Seed 3 active admins so the first disable succeeds (3->2); the
        second is blocked (2<=2)."""
        fake_auth, _registry = auth_state
        import asyncio

        loop = asyncio.new_event_loop()
        for i in range(3):
            loop.run_until_complete(fake_auth.create_admin(f"admin{i}@example.com"))

        r1 = stepup_admin_client.post("/admin/accounts/admin0@example.com/disable")
        assert r1.status_code == 200

        r2 = stepup_admin_client.post("/admin/accounts/admin1@example.com/disable")
        assert r2.status_code == 409
        assert r2.json()["detail"]["error"] == "ADMIN_ACTIVE_MINIMUM_VIOLATION"

    def test_already_disabled_idempotent(self, stepup_admin_client, auth_state):
        fake_auth, _registry = auth_state
        import asyncio

        loop = asyncio.new_event_loop()
        for i in range(3):
            loop.run_until_complete(fake_auth.create_admin(f"admin{i}@example.com"))
        loop.run_until_complete(fake_auth.disable("admin0@example.com"))
        r = stepup_admin_client.post("/admin/accounts/admin0@example.com/disable")
        assert r.status_code == 200
        assert r.json()["message"] == "already_disabled"


class TestAccountsEnable:
    # GAP-CLOSED: POST /admin/accounts/{username}/enable
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/accounts/x@example.com/enable").status_code == 401

    def test_seat_limit_blocks_reenable(self, stepup_admin_client, auth_state):
        """Community license max_admin_seats=2: with 2 total admins already
        on record (one disabled), re-enabling hits the seat ceiling — a real,
        documented consequence of counting TOTAL (not active) admins against
        the seat limit."""
        fake_auth, _registry = auth_state
        import asyncio

        loop = asyncio.new_event_loop()
        loop.run_until_complete(fake_auth.create_admin("admin0@example.com"))
        loop.run_until_complete(fake_auth.create_admin("admin1@example.com"))
        loop.run_until_complete(fake_auth.disable("admin1@example.com"))

        r = stepup_admin_client.post("/admin/accounts/admin1@example.com/enable")
        assert r.status_code == 402
        # SPEC-DIVERGENCE (minor): enable_admin's 402 body uses
        # license_limit_exceeded_response() -> error="LICENSE_LIMIT_EXCEEDED",
        # while create_admin's 402 body uses a hand-built dict with
        # error="admin_seat_limit_exceeded" (accounts.py:163-166 vs
        # accounts.py:349-352) for the SAME underlying LicenseLimitExceeded.
        # Not security-relevant (both fail closed with 402), but an API
        # consistency gap a client-side error handler must account for.
        assert r.json()["detail"]["error"] == "LICENSE_LIMIT_EXCEEDED"
        assert r.json()["detail"]["limit"] == "max_admin_seats"

    def test_enable_success_under_seat_limit(self, stepup_admin_client, auth_state, mock_audit_writer):
        fake_auth, _registry = auth_state
        import asyncio

        loop = asyncio.new_event_loop()
        loop.run_until_complete(fake_auth.create_admin("admin0@example.com"))
        loop.run_until_complete(fake_auth.disable("admin0@example.com"))

        r = stepup_admin_client.post("/admin/accounts/admin0@example.com/enable")
        assert r.status_code == 200
        mock_audit_writer.write.assert_called_once()

    def test_not_found_404(self, stepup_admin_client, auth_state):
        r = stepup_admin_client.post("/admin/accounts/nope@example.com/enable")
        assert r.status_code == 404


class TestAccountsForceReset:
    # GAP-CLOSED: POST /admin/accounts/{username}/force-reset
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/accounts/x@example.com/force-reset", json={"action": "password_reset"}
        )
        assert r.status_code == 401

    def test_not_found_404(self, stepup_admin_client, auth_state):
        r = stepup_admin_client.post(
            "/admin/accounts/nope@example.com/force-reset", json={"action": "password_reset"}
        )
        assert r.status_code == 404

    def test_invalid_action_422(self, stepup_admin_client, auth_state):
        fake_auth, _registry = auth_state
        import asyncio

        asyncio.new_event_loop().run_until_complete(fake_auth.create_admin("admin0@example.com"))
        r = stepup_admin_client.post(
            "/admin/accounts/admin0@example.com/force-reset", json={"action": "bogus"}
        )
        assert r.status_code == 422  # Pydantic pattern validation

    def test_password_reset_success(self, stepup_admin_client, auth_state, mock_audit_writer):
        fake_auth, _registry = auth_state
        import asyncio

        asyncio.new_event_loop().run_until_complete(fake_auth.create_admin("admin0@example.com"))
        r = stepup_admin_client.post(
            "/admin/accounts/admin0@example.com/force-reset", json={"action": "password_reset"}
        )
        assert r.status_code == 200
        mock_audit_writer.write.assert_called_once()


class TestAccountsUpdate:
    # GAP-CLOSED: PUT /admin/accounts/{username}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.put("/admin/accounts/x@example.com", json={}).status_code == 401

    def test_not_found_404(self, stepup_admin_client, auth_state):
        r = stepup_admin_client.put("/admin/accounts/nope@example.com", json={"email": "a@b.com"})
        assert r.status_code == 404

    def test_sod001_email_collision_409(self, stepup_admin_client, auth_state):
        fake_auth, _registry = auth_state
        import asyncio

        loop = asyncio.new_event_loop()
        loop.run_until_complete(fake_auth.create_admin("admin0@example.com"))
        loop.run_until_complete(fake_auth.create_user("someuser@example.com", "x"))
        loop.run_until_complete(fake_auth.set_email("someuser@example.com", "collide@example.com"))

        r = stepup_admin_client.put(
            "/admin/accounts/admin0@example.com", json={"email": "collide@example.com"}
        )
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "admin_user_collision"

    def test_email_update_success(self, stepup_admin_client, auth_state, mock_audit_writer):
        fake_auth, _registry = auth_state
        import asyncio

        asyncio.new_event_loop().run_until_complete(fake_auth.create_admin("admin0@example.com"))
        r = stepup_admin_client.put(
            "/admin/accounts/admin0@example.com", json={"email": "new-email@example.com"}
        )
        assert r.status_code == 200
        assert r.json()["changed"] == ["email"]


# ---------------------------------------------------------------------------
# users.py — 9 endpoints
# ---------------------------------------------------------------------------


class TestUsersList:
    # GAP-CLOSED: GET /admin/users
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/users").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/users").status_code == 403

    def test_admin_empty_list(self, admin_client, auth_state):
        r = admin_client.get("/admin/users")
        assert r.status_code == 200
        assert r.json() == {"users": [], "total": 0, "min_total": 1}


class TestUsersCreate:
    # GAP-CLOSED: POST /admin/users
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/users", json={"email": "new@example.com"})
        assert r.status_code == 401

    def test_admin_without_stepup_401(self, admin_client, auth_state):
        r = admin_client.post("/admin/users", json={"email": "new@example.com"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_stepup_create_derives_username(self, stepup_admin_client, auth_state, mock_audit_writer):
        """Q1/v2.23.4 username derivation: alice@domain.com -> alicedomain."""
        r = stepup_admin_client.post("/admin/users", json={"email": "alice@domain.com"})
        assert r.status_code == 200
        body = r.json()
        assert body["username"] == "alicedomain"
        assert body["totp_secret"] and body["temporary_password"]

    def test_sod002a_admin_collision_409(self, stepup_admin_client, auth_state):
        fake_auth, _registry = auth_state
        import asyncio

        asyncio.new_event_loop().run_until_complete(fake_auth.create_admin("collide@example.com"))
        r = stepup_admin_client.post("/admin/users", json={"email": "collide@example.com"})
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "admin_user_collision"


class TestUsersUpdate:
    # GAP-CLOSED: PUT /admin/users/{username}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.put("/admin/users/nope", json={}).status_code == 401

    def test_not_found_404(self, stepup_admin_client, auth_state):
        r = stepup_admin_client.put("/admin/users/nope", json={"email": "a@b.com"})
        assert r.status_code == 404

    def test_invalid_sensitivity_ceiling_422(self, stepup_admin_client, auth_state):
        fake_auth, _registry = auth_state
        import asyncio

        asyncio.new_event_loop().run_until_complete(fake_auth.create_user("bob", "x"))
        r = stepup_admin_client.put(
            "/admin/users/bob", json={"sensitivity_ceiling": "not-a-real-level"}
        )
        assert r.status_code == 422

    def test_email_and_disabled_update_success(self, stepup_admin_client, auth_state, mock_audit_writer):
        fake_auth, _registry = auth_state
        import asyncio

        loop = asyncio.new_event_loop()
        loop.run_until_complete(fake_auth.create_user("bob", "x"))
        loop.run_until_complete(fake_auth.create_user("carol", "x"))  # 2nd user so disable doesn't hit USER_MINIMUM_VIOLATION

        r = stepup_admin_client.put(
            "/admin/users/bob", json={"email": "bob@example.com", "disabled": True}
        )
        assert r.status_code == 200
        assert set(r.json()["changed"]) == {"email", "disabled"}

    def test_user_minimum_violation_on_disable(self, stepup_admin_client, auth_state):
        fake_auth, _registry = auth_state
        import asyncio

        asyncio.new_event_loop().run_until_complete(fake_auth.create_user("onlyuser", "x"))
        r = stepup_admin_client.put("/admin/users/onlyuser", json={"disabled": True})
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "USER_MINIMUM_VIOLATION"


class TestUsersDelete:
    # GAP-CLOSED: DELETE /admin/users/{username}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/users/nope").status_code == 401

    def test_min_total_guard_then_success(self, stepup_admin_client, auth_state, mock_audit_writer):
        fake_auth, _registry = auth_state
        import asyncio

        loop = asyncio.new_event_loop()
        loop.run_until_complete(fake_auth.create_user("bob", "x"))
        loop.run_until_complete(fake_auth.create_user("carol", "x"))

        r1 = stepup_admin_client.delete("/admin/users/bob")
        assert r1.status_code == 200

        r2 = stepup_admin_client.delete("/admin/users/carol")
        assert r2.status_code == 409
        assert r2.json()["detail"]["error"] == "USER_MINIMUM_VIOLATION"


class TestUsersFullReset:
    # GAP-CLOSED: POST /admin/users/{username}/full-reset
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/users/bob/full-reset", json={"totp_code": "123456"})
        assert r.status_code == 401

    def test_admin_totp_not_configured_403(self, stepup_admin_client, auth_state):
        """stepup_admin_client's own AccountRecord doesn't exist in
        FakeAuthService (no get_account_by_id match) — get_account_by_id
        returns None, so the route must 403 admin_totp_not_configured."""
        fake_auth, _registry = auth_state
        import asyncio

        asyncio.new_event_loop().run_until_complete(fake_auth.create_user("bob", "x"))
        r = stepup_admin_client.post("/admin/users/bob/full-reset", json={"totp_code": "12345678"})
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "admin_totp_not_configured"

    def test_invalid_admin_totp_403(self, stepup_admin_client, auth_state):
        """Real HMAC verification: a syntactically valid but wrong code must
        be rejected — proves verify_totp() is genuinely exercised, not
        stubbed to always succeed."""
        fake_auth, _registry = auth_state
        import asyncio

        from yashigani.auth.totp import TOTP_ALGO_SHA512, generate_totp_secret

        loop = asyncio.new_event_loop()
        # Seed the ACTING admin (account_id must match stepup_admin_client's session)
        admin_secret = generate_totp_secret()
        record, _ = loop.run_until_complete(fake_auth.create_admin("acting-admin@example.com"))
        record.account_id = "conformance-admin-stepup"  # match stepup_admin_client's session.account_id
        record.totp_secret = admin_secret
        record.totp_algorithm = TOTP_ALGO_SHA512
        loop.run_until_complete(fake_auth.create_user("bob", "x"))

        r = stepup_admin_client.post("/admin/users/bob/full-reset", json={"totp_code": "00000000"})
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "invalid_admin_totp"

    def test_valid_admin_totp_success(self, stepup_admin_client, auth_state, mock_audit_writer):
        fake_auth, _registry = auth_state
        import asyncio

        from yashigani.auth.totp import TOTP_ALGO_SHA512, generate_totp_secret

        loop = asyncio.new_event_loop()
        admin_secret = generate_totp_secret()
        record, _ = loop.run_until_complete(fake_auth.create_admin("acting-admin@example.com"))
        record.account_id = "conformance-admin-stepup"
        record.totp_secret = admin_secret
        record.totp_algorithm = TOTP_ALGO_SHA512
        loop.run_until_complete(fake_auth.create_user("bob", "x"))

        code = _totp_now(admin_secret, TOTP_ALGO_SHA512, 8)
        r = stepup_admin_client.post("/admin/users/bob/full-reset", json={"totp_code": code})
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


class TestUsersDisable:
    # GAP-CLOSED: POST /admin/users/{username}/disable
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/users/bob/disable").status_code == 401

    def test_success(self, stepup_admin_client, auth_state, mock_audit_writer):
        fake_auth, _registry = auth_state
        import asyncio

        asyncio.new_event_loop().run_until_complete(fake_auth.create_user("bob", "x"))
        r = stepup_admin_client.post("/admin/users/bob/disable")
        assert r.status_code == 200

    def test_not_found_404(self, stepup_admin_client, auth_state):
        r = stepup_admin_client.post("/admin/users/nope/disable")
        assert r.status_code == 404


class TestUsersEnable:
    # GAP-CLOSED: POST /admin/users/{username}/enable
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/users/bob/enable").status_code == 401

    def test_success_under_seat_limit(self, stepup_admin_client, auth_state, mock_audit_writer):
        fake_auth, _registry = auth_state
        import asyncio

        loop = asyncio.new_event_loop()
        loop.run_until_complete(fake_auth.create_user("bob", "x"))
        loop.run_until_complete(fake_auth.disable("bob"))
        r = stepup_admin_client.post("/admin/users/bob/enable")
        assert r.status_code == 200

    def test_not_found_404(self, stepup_admin_client, auth_state):
        r = stepup_admin_client.post("/admin/users/nope/enable")
        assert r.status_code == 404


class TestUsersReactivate:
    # GAP-CLOSED: POST /admin/users/{username}/reactivate
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/users/bob/reactivate", json={}).status_code == 401

    def test_no_identity_registered_404(self, stepup_admin_client, auth_state):
        fake_auth, _registry = auth_state
        import asyncio

        asyncio.new_event_loop().run_until_complete(fake_auth.create_user("bob", "x"))
        r = stepup_admin_client.post("/admin/users/bob/reactivate", json={"reason": "test"})
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "identity_not_found"

    def test_reactivate_suspended_identity_success(self, stepup_admin_client, auth_state, mock_audit_writer):
        fake_auth, registry = auth_state
        import asyncio

        loop = asyncio.new_event_loop()
        record = loop.run_until_complete(fake_auth.create_user("bob", "x"))
        record.email = "bob@yashigani.local"
        _register_human(registry, "bob@yashigani.local", suspended=True)

        r = stepup_admin_client.post("/admin/users/bob/reactivate", json={"reason": "back from leave"})
        assert r.status_code == 200
        assert r.json()["identity_status"] == "active"

    def test_reactivate_already_active_idempotent(self, stepup_admin_client, auth_state):
        fake_auth, registry = auth_state
        import asyncio

        loop = asyncio.new_event_loop()
        record = loop.run_until_complete(fake_auth.create_user("bob", "x"))
        record.email = "bob@yashigani.local"
        _register_human(registry, "bob@yashigani.local", suspended=False)

        r = stepup_admin_client.post("/admin/users/bob/reactivate", json={})
        assert r.status_code == 200
        assert "already active" in r.json()["message"]


class TestUsersApiKey:
    # GAP-CLOSED: POST /admin/users/{username}/api-key
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/users/bob/api-key").status_code == 401

    def test_registry_unavailable_503(self, stepup_admin_client, auth_state, monkeypatch):
        fake_auth, _registry = auth_state
        import asyncio

        from yashigani.backoffice.state import backoffice_state

        asyncio.new_event_loop().run_until_complete(fake_auth.create_user("bob", "x"))
        monkeypatch.setattr(backoffice_state, "identity_registry", None, raising=False)
        r = stepup_admin_client.post("/admin/users/bob/api-key")
        assert r.status_code == 503

    def test_no_identity_404(self, stepup_admin_client, auth_state):
        fake_auth, _registry = auth_state
        import asyncio

        asyncio.new_event_loop().run_until_complete(fake_auth.create_user("bob", "x"))
        r = stepup_admin_client.post("/admin/users/bob/api-key")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "identity_not_found"

    def test_issue_key_success(self, stepup_admin_client, auth_state, mock_audit_writer):
        fake_auth, registry = auth_state
        import asyncio

        loop = asyncio.new_event_loop()
        record = loop.run_until_complete(fake_auth.create_user("bob", "x"))
        record.email = "bob@yashigani.local"
        _register_human(registry, "bob@yashigani.local")

        r = stepup_admin_client.post("/admin/users/bob/api-key")
        assert r.status_code == 200
        body = r.json()
        assert body["shown_once"] is True and body["plaintext_token"]


# ---------------------------------------------------------------------------
# scim.py — 7 endpoints. All require AdminSession; mutations require
# require_feature("scim") — 402 on Community by default (no scim_licensed).
# ---------------------------------------------------------------------------


class TestScimUsers:
    # GAP-CLOSED: GET /scim/v2/Users
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/scim/v2/Users").status_code == 401

    def test_store_unconfigured_503(self, admin_client):
        r = admin_client.get("/scim/v2/Users")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "rbac_store_not_configured"

    def test_list_empty_with_store(self, admin_client, rbac_state):
        r = admin_client.get("/scim/v2/Users")
        assert r.status_code == 200
        assert r.json()["totalResults"] == 0

    # GAP-CLOSED: POST /scim/v2/Users
    def test_provision_unauth_401(self, unauth_client):
        r = unauth_client.post("/scim/v2/Users", json={"userName": "x@example.com"})
        assert r.status_code == 401

    def test_provision_without_license_402(self, admin_client, rbac_state):
        r = admin_client.post("/scim/v2/Users", json={"userName": "x@example.com"})
        assert r.status_code == 402
        assert r.json()["error"] == "LICENSE_FEATURE_GATED"

    def test_provision_with_license_success(self, admin_client, rbac_state, scim_licensed):
        r = admin_client.post("/scim/v2/Users", json={"userName": "newscim@example.com"})
        assert r.status_code == 201
        assert r.json()["userName"] == "newscim@example.com"

    # GAP-CLOSED: DELETE /scim/v2/Users/{user_id}
    def test_deprovision_unauth_401(self, unauth_client):
        assert unauth_client.delete("/scim/v2/Users/x@example.com").status_code == 401

    def test_deprovision_without_license_402(self, admin_client, rbac_state):
        r = admin_client.delete("/scim/v2/Users/x@example.com")
        assert r.status_code == 402

    def test_deprovision_with_license_success(self, admin_client, rbac_state, scim_licensed, mock_audit_writer):
        r = admin_client.delete("/scim/v2/Users/nomember@example.com")
        assert r.status_code == 204  # idempotent — user has no group memberships


class TestScimGroups:
    # GAP-CLOSED: GET /scim/v2/Groups
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/scim/v2/Groups").status_code == 401

    def test_list_empty(self, admin_client, rbac_state):
        r = admin_client.get("/scim/v2/Groups")
        assert r.status_code == 200
        assert r.json()["Resources"] == []

    # GAP-CLOSED: POST /scim/v2/Groups
    def test_create_unauth_401(self, unauth_client):
        r = unauth_client.post("/scim/v2/Groups", json={"displayName": "eng"})
        assert r.status_code == 401

    def test_create_without_license_402(self, admin_client, rbac_state):
        r = admin_client.post("/scim/v2/Groups", json={"displayName": "eng"})
        assert r.status_code == 402

    def test_create_with_license_success(self, admin_client, rbac_state, scim_licensed, mock_audit_writer):
        r = admin_client.post("/scim/v2/Groups", json={"displayName": "engineering"})
        assert r.status_code == 201
        assert r.json()["displayName"] == "engineering"
        # Two writes: the RBACGroupEvent (create) + the fire-and-forget
        # RBACPolicyPushEvent from _push() (rbac.py) — OPA is unreachable
        # offline so the push outcome is "failure", but the mutation itself
        # already succeeded and both audit events are genuinely emitted.
        assert mock_audit_writer.write.call_count == 2

    # GAP-CLOSED: PATCH /scim/v2/Groups/{group_id}
    def test_patch_unauth_401(self, unauth_client):
        r = unauth_client.patch(
            "/scim/v2/Groups/x", json={"Operations": [{"op": "add", "path": "members", "value": []}]}
        )
        assert r.status_code == 401

    def test_patch_without_license_402(self, admin_client, rbac_state):
        r = admin_client.patch(
            "/scim/v2/Groups/x", json={"Operations": [{"op": "add", "path": "members", "value": []}]}
        )
        assert r.status_code == 402

    def test_patch_not_found_404(self, admin_client, rbac_state, scim_licensed):
        r = admin_client.patch(
            "/scim/v2/Groups/does-not-exist",
            json={"Operations": [{"op": "add", "path": "members", "value": []}]},
        )
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "group_not_found"

    def test_scim_group_members_use_raw_email_not_identity_id(
        self, admin_client, rbac_state, scim_licensed, mock_audit_writer
    ):
        """SPEC-DIVERGENCE (see module docstring): SCIM group PATCH add
        stores the RAW EMAIL as the member key, bypassing the
        email->identity_id resolution rbac.py's /admin/rbac/groups/{id}/members
        endpoint enforces (RBAC-BUG-4.1.1). This pins the REAL, current
        behaviour rather than assuming (incorrectly) that SCIM and the admin
        RBAC UI are keyspace-compatible."""
        create = admin_client.post("/scim/v2/Groups", json={"displayName": "eng"}).json()
        group_id = create["id"]

        r = admin_client.patch(
            f"/scim/v2/Groups/{group_id}",
            json={
                "Operations": [
                    {"op": "add", "path": "members", "value": [{"value": "alice@example.com"}]}
                ]
            },
        )
        assert r.status_code == 200
        members = [m["value"] for m in r.json()["members"]]
        assert members == ["alice@example.com"], (
            "scim.py:462 stores the raw email as the RBACGroup member key — "
            "NOT an identity_id — diverging from rbac.py's identity_id-keyed "
            "contract (rbac/store.py:9-12, rbac.py:352-355)"
        )

    # GAP-CLOSED: DELETE /scim/v2/Groups/{group_id}
    def test_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/scim/v2/Groups/x").status_code == 401

    def test_delete_without_license_402(self, admin_client, rbac_state):
        r = admin_client.delete("/scim/v2/Groups/x")
        assert r.status_code == 402

    def test_delete_not_found_404(self, admin_client, rbac_state, scim_licensed):
        r = admin_client.delete("/scim/v2/Groups/does-not-exist")
        assert r.status_code == 404

    def test_delete_success(self, admin_client, rbac_state, scim_licensed, mock_audit_writer):
        create = admin_client.post("/scim/v2/Groups", json={"displayName": "temp"}).json()
        group_id = create["id"]
        r = admin_client.delete(f"/scim/v2/Groups/{group_id}")
        assert r.status_code == 204
        assert admin_client.get("/scim/v2/Groups").json()["Resources"] == []


# ---------------------------------------------------------------------------
# rbac.py — 9 endpoints
# ---------------------------------------------------------------------------


class TestRbacGroupsList:
    # GAP-CLOSED: GET /admin/rbac/groups
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/rbac/groups").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/rbac/groups").status_code == 403

    def test_store_unconfigured_503(self, admin_client):
        r = admin_client.get("/admin/rbac/groups")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "rbac_store_not_configured"

    def test_list_empty(self, admin_client, rbac_state):
        r = admin_client.get("/admin/rbac/groups")
        assert r.status_code == 200
        assert r.json() == {"groups": []}


class TestRbacGroupsCreate:
    # GAP-CLOSED: POST /admin/rbac/groups
    def test_admin_without_stepup_401(self, admin_client, rbac_state):
        r = admin_client.post("/admin/rbac/groups", json={"display_name": "eng"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_stepup_create_success_persists(self, stepup_admin_client, rbac_state, mock_audit_writer):
        r = stepup_admin_client.post(
            "/admin/rbac/groups",
            json={
                "display_name": "engineering",
                "allowed_resources": [{"method": "GET", "path_glob": "/tools/**"}],
            },
        )
        assert r.status_code == 201
        body = r.json()
        assert body["display_name"] == "engineering"
        group_id = body["id"]
        r2 = stepup_admin_client.get(f"/admin/rbac/groups/{group_id}")
        assert r2.status_code == 200
        # Two writes: RBACGroupEvent (create) + RBACPolicyPushEvent (_push,
        # OPA push fails offline but is fire-and-forget — see module docstring).
        assert mock_audit_writer.write.call_count == 2

    def test_invalid_path_glob_rejected_422(self, stepup_admin_client, rbac_state):
        """Ava input-validation finding: path_glob charset is restricted —
        shell/regex metacharacters must be rejected (rbac.py:43)."""
        r = stepup_admin_client.post(
            "/admin/rbac/groups",
            json={
                "display_name": "bad",
                "allowed_resources": [{"method": "GET", "path_glob": "/tools/$(whoami)"}],
            },
        )
        assert r.status_code == 422


class TestRbacGroupGet:
    # GAP-CLOSED: GET /admin/rbac/groups/{group_id}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/rbac/groups/x").status_code == 401

    def test_not_found_404(self, admin_client, rbac_state):
        r = admin_client.get("/admin/rbac/groups/does-not-exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "group_not_found"


class TestRbacGroupUpdate:
    # GAP-CLOSED: PUT /admin/rbac/groups/{group_id}
    def test_admin_without_stepup_401(self, admin_client, rbac_state):
        r = admin_client.put("/admin/rbac/groups/x", json={"display_name": "y"})
        assert r.status_code == 401

    def test_not_found_404(self, stepup_admin_client, rbac_state):
        r = stepup_admin_client.put("/admin/rbac/groups/does-not-exist", json={"display_name": "y"})
        assert r.status_code == 404

    def test_update_success_persists(self, stepup_admin_client, rbac_state, mock_audit_writer):
        create = stepup_admin_client.post(
            "/admin/rbac/groups", json={"display_name": "old-name"}
        ).json()
        group_id = create["id"]

        r = stepup_admin_client.put(
            f"/admin/rbac/groups/{group_id}", json={"display_name": "new-name"}
        )
        assert r.status_code == 200
        assert r.json()["display_name"] == "new-name"


class TestRbacGroupDelete:
    # GAP-CLOSED: DELETE /admin/rbac/groups/{group_id}
    def test_admin_without_stepup_401(self, admin_client, rbac_state):
        assert admin_client.delete("/admin/rbac/groups/x").status_code == 401

    def test_not_found_404(self, stepup_admin_client, rbac_state):
        r = stepup_admin_client.delete("/admin/rbac/groups/does-not-exist")
        assert r.status_code == 404

    def test_delete_success(self, stepup_admin_client, rbac_state, mock_audit_writer):
        create = stepup_admin_client.post("/admin/rbac/groups", json={"display_name": "temp"}).json()
        group_id = create["id"]
        r = stepup_admin_client.delete(f"/admin/rbac/groups/{group_id}")
        assert r.status_code == 204
        assert stepup_admin_client.get(f"/admin/rbac/groups/{group_id}").status_code == 404


class TestRbacMembers:
    # GAP-CLOSED: POST /admin/rbac/groups/{group_id}/members
    def test_admin_without_stepup_401(self, admin_client, rbac_state):
        r = admin_client.post(
            "/admin/rbac/groups/x/members", json={"email": "alice@example.com"}
        )
        assert r.status_code == 401

    def test_registry_unavailable_503(self, stepup_admin_client, rbac_state, mock_audit_writer):
        """rbac_state does not wire identity_registry — matches the fixture
        boundary (auth_state owns identity_registry). Genuine fail-closed 503
        when the registry dependency is absent (rbac.py:194-198)."""
        create = stepup_admin_client.post("/admin/rbac/groups", json={"display_name": "eng"}).json()
        r = stepup_admin_client.post(
            f"/admin/rbac/groups/{create['id']}/members", json={"email": "alice@example.com"}
        )
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "identity_registry_not_available"

    def test_unregistered_identity_422(self, stepup_admin_client, rbac_state, auth_state, mock_audit_writer):
        _fake_auth, _registry = auth_state
        create = stepup_admin_client.post("/admin/rbac/groups", json={"display_name": "eng"}).json()
        r = stepup_admin_client.post(
            f"/admin/rbac/groups/{create['id']}/members", json={"email": "nobody@example.com"}
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "identity_not_found"

    def test_add_member_success_resolves_to_identity_id(
        self, stepup_admin_client, rbac_state, auth_state, mock_audit_writer
    ):
        """Contrast with the SCIM divergence test above: the ADMIN-plane
        add_member endpoint resolves email -> identity_id BEFORE writing to
        RBACStore (rbac.py:355), so `members` in the response is the opaque
        identity_id, never the raw email."""
        _fake_auth, registry = auth_state
        identity_id = _register_human(registry, "alice@example.com")
        create = stepup_admin_client.post("/admin/rbac/groups", json={"display_name": "eng"}).json()
        group_id = create["id"]

        r = stepup_admin_client.post(
            f"/admin/rbac/groups/{group_id}/members", json={"email": "alice@example.com"}
        )
        assert r.status_code == 201
        assert r.json() == {"group_id": group_id, "email": "alice@example.com", "action": "added"}

        r2 = stepup_admin_client.get(f"/admin/rbac/groups/{group_id}")
        assert r2.json()["members"] == [identity_id]

    def test_group_not_found_404(self, stepup_admin_client, rbac_state, auth_state):
        _fake_auth, registry = auth_state
        _register_human(registry, "alice@example.com")
        r = stepup_admin_client.post(
            "/admin/rbac/groups/does-not-exist/members", json={"email": "alice@example.com"}
        )
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "group_not_found"

    # GAP-CLOSED: DELETE /admin/rbac/groups/{group_id}/members/{email}
    def test_remove_member_unauth_401(self, unauth_client):
        r = unauth_client.delete("/admin/rbac/groups/x/members/alice@example.com")
        assert r.status_code == 401

    def test_remove_member_success(self, stepup_admin_client, rbac_state, auth_state, mock_audit_writer):
        _fake_auth, registry = auth_state
        identity_id = _register_human(registry, "alice@example.com")
        create = stepup_admin_client.post("/admin/rbac/groups", json={"display_name": "eng"}).json()
        group_id = create["id"]
        stepup_admin_client.post(f"/admin/rbac/groups/{group_id}/members", json={"email": "alice@example.com"})

        r = stepup_admin_client.delete(f"/admin/rbac/groups/{group_id}/members/alice@example.com")
        assert r.status_code == 204

        r2 = stepup_admin_client.get(f"/admin/rbac/groups/{group_id}")
        assert identity_id not in r2.json()["members"]


class TestRbacUserGroups:
    # GAP-CLOSED: GET /admin/rbac/users/{email}/groups
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/rbac/users/alice@example.com/groups").status_code == 401

    def test_unresolvable_email_returns_empty(self, admin_client, rbac_state):
        r = admin_client.get("/admin/rbac/users/nobody@example.com/groups")
        assert r.status_code == 200
        assert r.json()["groups"] == []

    def test_resolved_identity_shows_membership(self, stepup_admin_client, rbac_state, auth_state, mock_audit_writer):
        _fake_auth, registry = auth_state
        _register_human(registry, "alice@example.com")
        create = stepup_admin_client.post("/admin/rbac/groups", json={"display_name": "eng"}).json()
        group_id = create["id"]
        stepup_admin_client.post(f"/admin/rbac/groups/{group_id}/members", json={"email": "alice@example.com"})

        r = stepup_admin_client.get("/admin/rbac/users/alice@example.com/groups")
        assert r.status_code == 200
        assert [g["id"] for g in r.json()["groups"]] == [group_id]


class TestRbacPolicyPush:
    # GAP-CLOSED: POST /admin/rbac/policy/push
    def test_admin_without_stepup_401(self, admin_client, rbac_state):
        assert admin_client.post("/admin/rbac/policy/push").status_code == 401

    def test_stepup_push_success(self, stepup_admin_client, rbac_state, mock_audit_writer):
        r = stepup_admin_client.post("/admin/rbac/policy/push")
        assert r.status_code == 200
        assert r.json()["pushed"] is True
        assert "groups_count" in r.json() and "users_count" in r.json()


# ---------------------------------------------------------------------------
# rbac_sources.py — 2 endpoints, static introspection catalogues (R13),
# no store dependency.
# ---------------------------------------------------------------------------


class TestRbacSources:
    # GAP-CLOSED: GET /admin/rbac/sources/paths
    def test_paths_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/rbac/sources/paths").status_code == 401

    def test_paths_user_tier_403(self, user_client):
        assert user_client.get("/admin/rbac/sources/paths").status_code == 403

    def test_paths_admin_200(self, admin_client):
        r = admin_client.get("/admin/rbac/sources/paths")
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == len(body["paths"]) > 0
        assert any(p["glob"] == "**" for p in body["paths"])

    # GAP-CLOSED: GET /admin/rbac/sources/methods
    def test_methods_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/rbac/sources/methods").status_code == 401

    def test_methods_admin_200(self, admin_client):
        r = admin_client.get("/admin/rbac/sources/methods")
        assert r.status_code == 200
        body = r.json()
        assert set(body["allowed_values"]) >= {"GET", "POST", "PUT", "PATCH", "DELETE", "*"}
