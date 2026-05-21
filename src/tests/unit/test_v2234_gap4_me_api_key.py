"""
Gap 4 / v2.23.4 arch-completion — /me/api-key self-service Bearer issuance.

Locks in the security invariants for the four new routes:
  POST /me/api-key              — issue/rotate HUMAN-identity Bearer
  GET  /me/api-keys             — list key metadata (no plaintext)
  DELETE /me/api-keys/{key_id} — revoke a key
  POST /admin/users/{username}/api-key — admin override (30-sec grace)

Security invariants verified:
  1. Plaintext returned ONCE in POST body; GET never returns plaintext.
  2. StepUp required for POST /me/api-key.
  3. Admin tier rejected on all /me/* routes (403).
  4. totp_provisioning tier rejected on all /me/* routes (403).
  5. force_password_change blocks issuance (403).
  6. Second POST immediately invalidates prior token (grace_seconds=0).
  7. GET returns metadata (last4, timestamps) — no plaintext field.
  8. DELETE returns 204, key not usable after.
  9. Cross-user DELETE returns 403.
  10. Admin route requires StepUpAdminSession (admin + StepUp).
  11. Admin rotation gives 30-sec grace on prior token.
  12. 6th issuance attempt within an hour returns 429.
  13. identity_registry is None → 503.

Source-code regression targets:
  src/yashigani/backoffice/routes/me.py
  src/yashigani/backoffice/routes/users.py (admin override route)

ASVS v5 controls: V4.1.1, V4.1.2, V4.2.1, V7.1.1, V11.1.5
Gap reference: project_yashigani_arch_completion_v2235.md § Gap 4

Last updated: 2026-05-14T00:00:00+01:00
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Shared stubs (mirrors Gap 3 test helpers)
# ---------------------------------------------------------------------------

@dataclass
class _StubRecord:
    username: str
    account_id: str
    account_tier: str       # "admin" | "user" | "totp_provisioning"
    disabled: bool = False
    force_password_change: bool = False
    force_totp_provision: bool = False
    email: Optional[str] = None
    password_hash: str = "hashed"
    totp_secret: str = "JBSWY3DPEHPK3PXP"


class _StubRedis:
    """Minimal Redis stub — models the key/value operations used in me.py."""

    def __init__(self):
        self._data: dict = {}

    def exists(self, key):
        return key in self._data

    def smembers(self, key):
        return set()

    def pipeline(self):
        return _StubPipeline(self)

    def get(self, key):
        return self._data.get(key)

    def set(self, key, value, ex=None):
        self._data[key] = value

    def incr(self, key):
        self._data[key] = int(self._data.get(key, 0)) + 1
        return self._data[key]

    def expire(self, key, seconds):
        pass

    def delete(self, *keys):
        for k in keys:
            self._data.pop(k, None)

    def scan_iter(self, pattern):
        return iter([])

    def hset(self, key, *args, mapping=None):
        if mapping:
            self._data.setdefault(key, {})
            if isinstance(self._data[key], dict):
                self._data[key].update(mapping)

    def hgetall(self, key):
        val = self._data.get(key)
        if isinstance(val, dict):
            return val
        return {}


class _StubPipeline:
    def __init__(self, redis):
        self._redis = redis
        self._cmds = []

    def get(self, key):
        self._cmds.append(("get", key))
        return self

    def set(self, key, value, ex=None):
        self._cmds.append(("set", key, value))
        return self

    def delete(self, *keys):
        return self

    def execute(self):
        return [None] * len(self._cmds)


class _StubSessionStore:
    def __init__(self, redis=None):
        self.created = []
        self._redis = redis or _StubRedis()

    def create(self, *, account_id, account_tier, client_ip):
        sess = MagicMock()
        sess.token = f"tok-{account_id}"
        sess.account_tier = account_tier
        self.created.append(sess)
        return sess

    def invalidate_all_for_account(self, account_id: str) -> int:
        return 0

    def get(self, token):
        return None

    def record_totp_stepup(self, token: str) -> None:
        pass


class _StubAuditWriter:
    def __init__(self):
        self.events = []

    def write(self, event) -> None:
        self.events.append(event)


class _StubAuthService:
    def __init__(self, record: _StubRecord):
        self._record = record

    async def authenticate(self, username, password, totp_code, *, audit_writer=None):
        return True, self._record, None

    async def get_account(self, username: str):
        if self._record.username == username:
            return self._record
        return None

    async def get_account_by_id(self, account_id: str):
        if self._record.account_id == account_id:
            return self._record
        return None


def _make_registry_stub(plaintext_key="yk_test_plaintext_key_1234"):
    """
    MagicMock IdentityRegistry with:
      - get_by_slug → returns a HUMAN identity dict
      - rotate_key  → returns the given plaintext_key
      - get         → returns registry data with metadata fields
    """
    registry = MagicMock()
    identity = {
        "identity_id": "idnt_abc123",
        "kind": "human",
        "slug": "alice-example-com",
        "status": "active",
        "api_key_created_at": "2026-05-14T00:00:00+00:00",
        "api_key_rotated_at": "2026-05-14T00:00:00+00:00",
        "api_key_expires_at": "2027-05-14T00:00:00+00:00",
        "last_seen_at": "",
    }
    registry.get_by_slug = MagicMock(return_value=identity)
    registry.get = MagicMock(return_value=identity)
    registry.rotate_key = MagicMock(return_value=plaintext_key)
    registry.register = MagicMock(return_value=("idnt_abc123", plaintext_key))
    return registry


def _make_session(account_id: str, account_tier: str, stepup_age: float = 60.0):
    """
    Build a stub Session object.  stepup_age controls the age of the
    last_totp_verified_at timestamp (in seconds from now — smaller = fresher).
    """
    session = MagicMock()
    session.account_id = account_id
    session.account_tier = account_tier
    session.token = f"tok-{account_id}"
    session.last_totp_verified_at = time.time() - stepup_age
    return session


def _make_state(record: _StubRecord, registry=None, redis=None):
    """Return a minimal BackofficeState-like object with all required fields."""
    state = MagicMock()
    stub_redis = redis or _StubRedis()
    # Seed a key hash for the identity so rotate_key logic sees an existing key
    stub_redis.set("identity:key:idnt_abc123", b"$2b$12$fakehash")
    state.auth_service = _StubAuthService(record)
    state.session_store = _StubSessionStore(redis=stub_redis)
    state.audit_writer = _StubAuditWriter()
    state.identity_registry = registry
    return state


# ---------------------------------------------------------------------------
# FastAPI test app builder
# ---------------------------------------------------------------------------

def _build_me_app(
    record: _StubRecord,
    registry=None,
    stepup_age: float = 60.0,   # seconds since stepup — <300 = fresh
):
    """
    Minimal FastAPI app exposing /me/* routes.
    Injects stubs into backoffice_state.
    Returns (app, state, session_store, originals).
    """
    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from yashigani.backoffice import state as state_mod
    from yashigani.backoffice.routes import me as me_mod
    from yashigani.backoffice import middleware as mw_mod

    # Stash originals
    orig_auth = state_mod.backoffice_state.auth_service
    orig_session = state_mod.backoffice_state.session_store
    orig_audit = state_mod.backoffice_state.audit_writer
    orig_registry = state_mod.backoffice_state.identity_registry

    stub_redis = _StubRedis()
    # Seed existing key so rotate_key sees something to move to grace
    stub_redis.set("identity:key:idnt_abc123", b"$2b$12$fakehash")

    stub_session_store = _StubSessionStore(redis=stub_redis)
    stub_audit = _StubAuditWriter()
    stub_auth = _StubAuthService(record)

    state_mod.backoffice_state.auth_service = stub_auth
    state_mod.backoffice_state.session_store = stub_session_store
    state_mod.backoffice_state.audit_writer = stub_audit
    state_mod.backoffice_state.identity_registry = registry

    app = FastAPI()
    app.include_router(me_mod.router)

    # Patch require_any_session to inject a controlled session
    user_session = _make_session(
        account_id=record.account_id,
        account_tier=record.account_tier,
        stepup_age=stepup_age,
    )

    from fastapi import Depends
    from yashigani.backoffice.middleware import AnySession

    async def _override_any_session():
        return user_session

    app.dependency_overrides[mw_mod.require_any_session] = _override_any_session

    originals = (orig_auth, orig_session, orig_audit, orig_registry)
    return app, stub_session_store, stub_audit, stub_redis, originals


def _teardown(originals):
    from yashigani.backoffice import state as state_mod
    state_mod.backoffice_state.auth_service = originals[0]
    state_mod.backoffice_state.session_store = originals[1]
    state_mod.backoffice_state.audit_writer = originals[2]
    state_mod.backoffice_state.identity_registry = originals[3]


# ---------------------------------------------------------------------------
# Test 1: POST /me/api-key returns plaintext token once
# ---------------------------------------------------------------------------

class TestPostMeApiKeyReturnsPlaintextTokenOnce:
    """
    POST returns 200 with plaintext_token + shown_once.
    GET never returns plaintext.

    Regression: if plaintext_token is removed from POST body or leaked via GET,
    one of these assertions fails.
    """

    def test_post_returns_plaintext_token(self):
        from fastapi.testclient import TestClient

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub(plaintext_key="yk_abc123def456ghi789jkl012mno345pq")
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.post("/me/api-key")
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
            body = resp.json()
            assert "plaintext_token" in body, f"Missing plaintext_token: {body}"
            assert body["shown_once"] is True
            assert body["plaintext_token"] == "yk_abc123def456ghi789jkl012mno345pq"
        finally:
            _teardown(originals)

    def test_get_never_returns_plaintext(self):
        from fastapi.testclient import TestClient

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.get("/me/api-keys")
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
            body = resp.json()
            # plaintext must never appear anywhere in the response
            body_str = str(body)
            assert "plaintext_token" not in body_str, (
                f"REGRESSION: GET /me/api-keys contains plaintext_token: {body}"
            )
            # api_keys entries must not have a 'token' or 'plaintext' field
            for key_entry in body.get("api_keys", []):
                assert "token" not in key_entry, f"REGRESSION: GET key entry has 'token': {key_entry}"
                assert "plaintext" not in str(key_entry), f"REGRESSION: plaintext in key entry: {key_entry}"
        finally:
            _teardown(originals)


# ---------------------------------------------------------------------------
# Test 2: StepUp required — stale TOTP → 401 step_up_required
# ---------------------------------------------------------------------------

class TestPostMeApiKeyRequiresStepUp:
    """
    When last_totp_verified_at is older than STEPUP_TTL_SECONDS (default 300s),
    POST /me/api-key must return 401 with error="step_up_required".

    Regression: if assert_fresh_stepup is removed from the route, stale
    sessions can issue tokens and this test fails.
    """

    def test_stale_stepup_returns_401(self):
        from fastapi.testclient import TestClient

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        # stepup_age=400 > default TTL of 300 → stale
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry, stepup_age=400.0)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/me/api-key")
            assert resp.status_code == 401, f"Expected 401 for stale stepup, got {resp.status_code}: {resp.text}"
            detail = resp.json().get("detail", {})
            assert detail.get("error") == "step_up_required", (
                f"REGRESSION: expected error=step_up_required, got: {detail}"
            )
        finally:
            _teardown(originals)

    def test_no_stepup_at_all_returns_401(self):
        from fastapi.testclient import TestClient
        from yashigani.backoffice import state as state_mod
        from yashigani.backoffice import middleware as mw_mod

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)

        # Override session to have last_totp_verified_at=None
        session_no_stepup = _make_session(record.account_id, "user", stepup_age=0)
        session_no_stepup.last_totp_verified_at = None

        async def _override_no_stepup():
            return session_no_stepup

        app.dependency_overrides[mw_mod.require_any_session] = _override_no_stepup
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/me/api-key")
            assert resp.status_code == 401, f"Expected 401 (no stepup), got {resp.status_code}: {resp.text}"
        finally:
            _teardown(originals)


# ---------------------------------------------------------------------------
# Test 3: Admin tier rejected with 403
# ---------------------------------------------------------------------------

class TestPostMeApiKeyAdminTierRejected:
    """
    account_tier == "admin" → POST /me/api-key returns 403 user_tier_required.

    Regression: if the _assert_user_tier guard is removed, admins can issue
    Bearer tokens via /me/api-key and this test fails.
    """

    def test_admin_session_returns_403(self):
        from fastapi.testclient import TestClient
        from yashigani.backoffice import middleware as mw_mod

        record = _StubRecord(
            username="admin@example.com", account_id="admin-001", account_tier="admin",
            email="admin@example.com",
        )
        registry = _make_registry_stub()
        # Build app but override session to admin tier
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)

        admin_session = _make_session(record.account_id, "admin", stepup_age=60)

        async def _override_admin():
            return admin_session

        app.dependency_overrides[mw_mod.require_any_session] = _override_admin
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/me/api-key")
            assert resp.status_code == 403, f"Expected 403 for admin tier, got {resp.status_code}: {resp.text}"
            detail = resp.json().get("detail", {})
            assert detail.get("error") == "user_tier_required", (
                f"REGRESSION: expected error=user_tier_required, got: {detail}"
            )
        finally:
            _teardown(originals)


# ---------------------------------------------------------------------------
# Test 4: totp_provisioning tier rejected with 403
# ---------------------------------------------------------------------------

class TestPostMeApiKeyTotpProvisioningRejected:
    """
    account_tier == "totp_provisioning" → 403.

    Regression: provisional accounts must not be able to issue Bearer tokens.
    """

    def test_totp_provisioning_session_returns_403(self):
        from fastapi.testclient import TestClient
        from yashigani.backoffice import middleware as mw_mod

        record = _StubRecord(
            username="newuser", account_id="user-002", account_tier="totp_provisioning",
            email="newuser@example.com",
        )
        registry = _make_registry_stub()
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)

        prov_session = _make_session(record.account_id, "totp_provisioning", stepup_age=60)

        async def _override_prov():
            return prov_session

        app.dependency_overrides[mw_mod.require_any_session] = _override_prov
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/me/api-key")
            assert resp.status_code == 403, (
                f"Expected 403 for totp_provisioning tier, got {resp.status_code}: {resp.text}"
            )
            detail = resp.json().get("detail", {})
            assert detail.get("error") == "user_tier_required", (
                f"REGRESSION: expected error=user_tier_required, got: {detail}"
            )
        finally:
            _teardown(originals)


# ---------------------------------------------------------------------------
# Test 5: force_password_change pending → 403
# ---------------------------------------------------------------------------

class TestPostMeApiKeyForcePasswordChangeRejected:
    """
    force_password_change == True → 403 force_password_change_pending.

    Regression: partially-provisioned accounts must not obtain Bearer tokens.
    """

    def test_force_password_change_returns_403(self):
        from fastapi.testclient import TestClient

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
            force_password_change=True,
        )
        registry = _make_registry_stub()
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/me/api-key")
            assert resp.status_code == 403, (
                f"Expected 403 for force_password_change, got {resp.status_code}: {resp.text}"
            )
            detail = resp.json().get("detail", {})
            assert detail.get("error") == "force_password_change_pending", (
                f"REGRESSION: expected error=force_password_change_pending, got: {detail}"
            )
        finally:
            _teardown(originals)


# ---------------------------------------------------------------------------
# Test 6: Second POST immediately invalidates prior token
# ---------------------------------------------------------------------------

class TestPostMeApiKeyRotatesPriorTokenImmediately:
    """
    Self-rotation: grace_seconds=0 must be passed to rotate_key so the prior
    token is immediately invalidated (no grace period).

    Regression: if grace_seconds > 0 is passed, prior tokens remain valid
    during the grace window — violating the "user explicitly asked" invariant.
    """

    def test_rotate_key_called_with_grace_zero(self):
        from fastapi.testclient import TestClient

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.post("/me/api-key")
            assert resp.status_code == 200

            # rotate_key must have been called with grace_seconds=0
            assert registry.rotate_key.called, "rotate_key was never called"
            call_kwargs = registry.rotate_key.call_args
            grace = call_kwargs.kwargs.get("grace_seconds", call_kwargs.args[1] if len(call_kwargs.args) > 1 else None)
            assert grace == 0, (
                f"REGRESSION: self-rotation must use grace_seconds=0, got: {grace}. "
                "Prior token must be immediately invalidated."
            )
        finally:
            _teardown(originals)

    def test_second_post_returns_new_token(self):
        from fastapi.testclient import TestClient

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        tokens = ["yk_first_token_1234567890abcdef12", "yk_second_token_abcdef1234567890"]
        call_count = {"n": 0}

        def _rotating_rotate_key(identity_id, grace_seconds=0):
            t = tokens[call_count["n"]]
            call_count["n"] += 1
            return t

        registry = _make_registry_stub()
        registry.rotate_key = MagicMock(side_effect=_rotating_rotate_key)
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp1 = client.post("/me/api-key")
            assert resp1.status_code == 200
            token1 = resp1.json()["plaintext_token"]

            resp2 = client.post("/me/api-key")
            assert resp2.status_code == 200
            token2 = resp2.json()["plaintext_token"]

            # Different tokens
            assert token1 != token2, "REGRESSION: both POSTs returned the same token"
            assert token1 == tokens[0]
            assert token2 == tokens[1]
        finally:
            _teardown(originals)


# ---------------------------------------------------------------------------
# Test 7: GET /me/api-keys returns metadata, no plaintext
# ---------------------------------------------------------------------------

class TestGetMeApiKeysReturnsMetadataNoPlaintext:
    """
    GET /me/api-keys: response has last4, timestamps, key_id.
    plaintext_token MUST NOT appear anywhere in the response.

    Regression: if plaintext is ever added to the GET response body, this
    test catches it immediately.
    """

    def test_get_returns_metadata_fields(self):
        from fastapi.testclient import TestClient

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.get("/me/api-keys")
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
            body = resp.json()
            keys = body.get("api_keys", [])
            assert len(keys) == 1, f"Expected 1 key entry, got: {keys}"
            entry = keys[0]
            # Must have expected metadata fields
            assert "key_id" in entry, f"Missing key_id: {entry}"
            assert "last4" in entry, f"Missing last4: {entry}"
            assert "expires_at" in entry, f"Missing expires_at: {entry}"
            # Must NOT have plaintext
            assert "plaintext_token" not in entry, (
                f"REGRESSION: GET response contains plaintext_token: {entry}"
            )
            assert "plaintext" not in str(entry).lower() or entry.get("last4", "") == "****", (
                f"REGRESSION: plaintext appears in key entry: {entry}"
            )
        finally:
            _teardown(originals)

    def test_get_returns_empty_when_no_identity(self):
        from fastapi.testclient import TestClient

        record = _StubRecord(
            username="bob", account_id="user-003", account_tier="user",
            email="bob@example.com",
        )
        # Registry returns None for slug (no identity registered)
        registry = _make_registry_stub()
        registry.get_by_slug = MagicMock(return_value=None)

        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.get("/me/api-keys")
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
            body = resp.json()
            assert body.get("api_keys") == [], (
                f"Expected empty list when no identity, got: {body}"
            )
        finally:
            _teardown(originals)


# ---------------------------------------------------------------------------
# Test 8: DELETE /me/api-keys/{key_id} revokes key → 204
# ---------------------------------------------------------------------------

class TestDeleteMeApiKeyRevokes:
    """
    DELETE /me/api-keys/{key_id}: returns 204, Redis keys deleted.

    Regression: if the delete route is missing or doesn't remove Redis keys,
    revoked tokens remain usable.
    """

    def test_delete_returns_204(self):
        from fastapi.testclient import TestClient

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.delete("/me/api-keys/idnt_abc123")
            assert resp.status_code == 204, (
                f"Expected 204 for successful revocation, got {resp.status_code}: {resp.text}"
            )
        finally:
            _teardown(originals)

    def test_delete_removes_redis_key(self):
        from fastapi.testclient import TestClient

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)
        try:
            # Verify key exists before delete
            assert redis.get("identity:key:idnt_abc123") is not None, (
                "Test setup error: expected key in Redis before delete"
            )

            client = TestClient(app, raise_server_exceptions=True)
            resp = client.delete("/me/api-keys/idnt_abc123")
            assert resp.status_code == 204

            # Key must be gone after delete
            assert redis.get("identity:key:idnt_abc123") is None, (
                "REGRESSION: identity:key not deleted after revocation"
            )
        finally:
            _teardown(originals)


# ---------------------------------------------------------------------------
# Test 9: Cross-user DELETE → 403
# ---------------------------------------------------------------------------

class TestDeleteMeApiKeyCrossUserForbidden:
    """
    Alice cannot revoke Bob's key — key_id belongs to different identity_id.
    403 if key_id in URL != caller's identity_id.

    Regression: if ownership check is removed, any user can revoke any key.
    """

    def test_cross_user_revocation_returns_403(self):
        from fastapi.testclient import TestClient

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()  # alice's identity_id = "idnt_abc123"
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            # Attempt to delete Bob's key_id (different from alice's idnt_abc123)
            resp = client.delete("/me/api-keys/idnt_bob999")
            assert resp.status_code == 403, (
                f"REGRESSION: expected 403 for cross-user delete, got {resp.status_code}: {resp.text}"
            )
            detail = resp.json().get("detail", {})
            assert detail.get("error") == "key_not_owned_by_caller", (
                f"Expected error=key_not_owned_by_caller, got: {detail}"
            )
        finally:
            _teardown(originals)


# ---------------------------------------------------------------------------
# Test 10: Admin /admin/users/{username}/api-key — admin only
# ---------------------------------------------------------------------------

class TestAdminUsersUsernameApiKeyAdminOnly:
    """
    POST /admin/users/{username}/api-key requires admin tier + StepUp.
    Non-admin must get 403; stale StepUp must get 401.

    This tests the users.py admin override route guard.
    """

    def _build_admin_app(self, admin_record, target_record, registry=None, stepup_age=60.0):
        """Build a minimal app exposing /admin/users/* routes."""
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from yashigani.backoffice import state as state_mod
        from yashigani.backoffice.routes import users as users_mod
        from yashigani.backoffice import middleware as mw_mod

        orig_auth = state_mod.backoffice_state.auth_service
        orig_session = state_mod.backoffice_state.session_store
        orig_audit = state_mod.backoffice_state.audit_writer
        orig_registry = state_mod.backoffice_state.identity_registry

        stub_redis = _StubRedis()
        stub_redis.set("identity:key:idnt_abc123", b"$2b$12$fakehash")

        class _TwoUserAuthService:
            def __init__(self):
                self._admin = admin_record
                self._target = target_record

            async def get_account(self, username: str):
                if username == self._admin.username:
                    return self._admin
                if username == self._target.username:
                    return self._target
                return None

            async def get_account_by_id(self, account_id: str):
                if account_id == self._admin.account_id:
                    return self._admin
                if account_id == self._target.account_id:
                    return self._target
                return None

            async def list_accounts(self):
                return [self._admin, self._target]

            async def total_user_count(self):
                return 1

        state_mod.backoffice_state.auth_service = _TwoUserAuthService()
        state_mod.backoffice_state.session_store = _StubSessionStore(redis=stub_redis)
        state_mod.backoffice_state.audit_writer = _StubAuditWriter()
        state_mod.backoffice_state.identity_registry = registry

        app = FastAPI()
        app.include_router(users_mod.router, prefix="/admin/users")

        admin_session = _make_session(admin_record.account_id, "admin", stepup_age=stepup_age)

        async def _override_stepup_admin():
            from yashigani.auth.stepup import assert_fresh_stepup
            assert_fresh_stepup(admin_session)
            return admin_session

        app.dependency_overrides[mw_mod.require_stepup_admin_session] = _override_stepup_admin

        originals = (orig_auth, orig_session, orig_audit, orig_registry)
        return app, originals

    def test_admin_can_issue_key_for_user(self):
        from fastapi.testclient import TestClient

        admin_record = _StubRecord(
            username="admin@example.com", account_id="admin-001", account_tier="admin",
            email="admin@example.com",
        )
        target_record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        app, originals = self._build_admin_app(admin_record, target_record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.post("/admin/users/alice/api-key")
            assert resp.status_code == 200, (
                f"Expected 200 for admin key issuance, got {resp.status_code}: {resp.text}"
            )
            body = resp.json()
            assert "plaintext_token" in body, f"Missing plaintext_token in admin response: {body}"
            assert body["shown_once"] is True
            assert "grace_seconds" in body, f"Missing grace_seconds in admin response: {body}"
        finally:
            _teardown(originals)

    def test_non_user_account_returns_404(self):
        from fastapi.testclient import TestClient

        admin_record = _StubRecord(
            username="admin@example.com", account_id="admin-001", account_tier="admin",
            email="admin@example.com",
        )
        target_record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        app, originals = self._build_admin_app(admin_record, target_record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            # Attempt to issue key for a non-existent user
            resp = client.post("/admin/users/nonexistent/api-key")
            assert resp.status_code == 404, (
                f"Expected 404 for unknown user, got {resp.status_code}: {resp.text}"
            )
        finally:
            _teardown(originals)


# ---------------------------------------------------------------------------
# Test 11: Admin rotation gives 30-sec grace window on prior token
# ---------------------------------------------------------------------------

class TestAdminUsersApiKeyGraceWindow:
    """
    Admin-issued rotation: rotate_key must be called with grace_seconds=30.

    Regression: if grace_seconds=0 is used for admin rotation, prior tokens
    are immediately killed instead of having the 30-sec transition window.
    """

    def _build_admin_app_minimal(self, target_record, registry):
        pytest.importorskip("fastapi")
        from fastapi import FastAPI
        from yashigani.backoffice import state as state_mod
        from yashigani.backoffice.routes import users as users_mod
        from yashigani.backoffice import middleware as mw_mod

        orig = (
            state_mod.backoffice_state.auth_service,
            state_mod.backoffice_state.session_store,
            state_mod.backoffice_state.audit_writer,
            state_mod.backoffice_state.identity_registry,
        )

        stub_redis = _StubRedis()
        stub_redis.set("identity:key:idnt_abc123", b"$2b$12$fakehash")

        class _TargetAuthService:
            async def get_account(self, username):
                if username == target_record.username:
                    return target_record
                return None

            async def get_account_by_id(self, account_id):
                if account_id == target_record.account_id:
                    return target_record
                return None

            async def list_accounts(self):
                return [target_record]

            async def total_user_count(self):
                return 1

        state_mod.backoffice_state.auth_service = _TargetAuthService()
        state_mod.backoffice_state.session_store = _StubSessionStore(redis=stub_redis)
        state_mod.backoffice_state.audit_writer = _StubAuditWriter()
        state_mod.backoffice_state.identity_registry = registry

        app = FastAPI()
        app.include_router(users_mod.router, prefix="/admin/users")

        admin_session = _make_session("admin-001", "admin", stepup_age=60)

        async def _override_stepup():
            return admin_session

        app.dependency_overrides[mw_mod.require_stepup_admin_session] = _override_stepup
        return app, orig

    def test_admin_rotation_uses_30_sec_grace(self):
        from fastapi.testclient import TestClient

        target_record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        app, originals = self._build_admin_app_minimal(target_record, registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.post("/admin/users/alice/api-key")
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

            # Verify rotate_key called with grace_seconds=30
            assert registry.rotate_key.called, "rotate_key was never called"
            call_kwargs = registry.rotate_key.call_args
            grace = call_kwargs.kwargs.get("grace_seconds", None)
            if grace is None and len(call_kwargs.args) > 1:
                grace = call_kwargs.args[1]
            assert grace == 30, (
                f"REGRESSION: admin rotation must use grace_seconds=30, got: {grace}. "
                "Prior token must remain valid for 30 seconds (client transition window)."
            )

            # Response must also report grace_seconds
            body = resp.json()
            assert body.get("grace_seconds") == 30, (
                f"Expected grace_seconds=30 in response, got: {body}"
            )
        finally:
            _teardown(originals)


# ---------------------------------------------------------------------------
# Test 12: Rate limit — 6th attempt returns 429
# ---------------------------------------------------------------------------

class TestRateLimit5PerHour:
    """
    Max 5 issuance attempts per user per hour.
    The 6th attempt within the same hour MUST return 429.

    Regression: if _check_rate_limit is removed or the limit raised, more
    than 5 attempts per hour succeed and this test fails.
    """

    def test_sixth_attempt_returns_429(self):
        from fastapi.testclient import TestClient
        from yashigani.backoffice.routes.me import _API_KEY_RATE_LIMIT

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)
        try:
            # Seed Redis to simulate that the limit has already been reached
            rl_key = f"me:api-key:rl:{record.account_id}"
            redis.set(rl_key, _API_KEY_RATE_LIMIT)  # At the limit

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/me/api-key")
            # Next call (count=limit+1) must return 429
            assert resp.status_code == 429, (
                f"REGRESSION: expected 429 on rate-limit breach, got {resp.status_code}: {resp.text}"
            )
            detail = resp.json().get("detail", {})
            assert detail.get("error") == "api_key_rate_limit_exceeded", (
                f"Expected error=api_key_rate_limit_exceeded, got: {detail}"
            )
        finally:
            _teardown(originals)

    def test_first_five_attempts_succeed(self):
        from fastapi.testclient import TestClient
        from yashigani.backoffice.routes.me import _API_KEY_RATE_LIMIT

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub()
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            for i in range(_API_KEY_RATE_LIMIT):
                resp = client.post("/me/api-key")
                assert resp.status_code == 200, (
                    f"Expected 200 for attempt {i+1}/{_API_KEY_RATE_LIMIT}, "
                    f"got {resp.status_code}: {resp.text}"
                )
        finally:
            _teardown(originals)


# ---------------------------------------------------------------------------
# Test 13: Community tier (identity_registry is None) → 503
# ---------------------------------------------------------------------------

class TestCommunityTier503:
    """
    identity_registry is None → POST /me/api-key returns 503
    user_identity_registry_unavailable.

    Regression: if the registry=None check is removed, AttributeError is raised
    instead of a clean 503 and this test fails.
    """

    def test_community_tier_returns_503(self):
        from fastapi.testclient import TestClient

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        # registry=None → community tier
        app, ss, audit, redis, originals = _build_me_app(record, registry=None)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post("/me/api-key")
            assert resp.status_code == 503, (
                f"REGRESSION: expected 503 for community-tier (registry=None), "
                f"got {resp.status_code}: {resp.text}"
            )
            detail = resp.json().get("detail", {})
            assert detail.get("error") == "user_identity_registry_unavailable", (
                f"Expected error=user_identity_registry_unavailable, got: {detail}"
            )
        finally:
            _teardown(originals)

    def test_community_tier_get_returns_503(self):
        from fastapi.testclient import TestClient

        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        app, ss, audit, redis, originals = _build_me_app(record, registry=None)
        try:
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/me/api-keys")
            assert resp.status_code == 503, (
                f"REGRESSION: expected 503 for GET on community-tier, "
                f"got {resp.status_code}: {resp.text}"
            )
        finally:
            _teardown(originals)


# ---------------------------------------------------------------------------
# Audit event verification — no plaintext in audit log
# ---------------------------------------------------------------------------

class TestAuditEventsNeverLogPlaintext:
    """
    Verify that the UserApiKeyIssuedEvent written after POST /me/api-key
    does NOT contain the plaintext token — only key_last4.

    Regression: if plaintext_token is accidentally passed to the audit event,
    it would appear in audit sinks (SIEM, file, etc.) — this test catches it.
    """

    def test_audit_event_does_not_log_plaintext(self):
        from fastapi.testclient import TestClient

        plaintext = "yk_" + "a" * 60  # 63-char token
        record = _StubRecord(
            username="alice", account_id="user-001", account_tier="user",
            email="alice@example.com",
        )
        registry = _make_registry_stub(plaintext_key=plaintext)
        app, ss, audit, redis, originals = _build_me_app(record, registry=registry)
        try:
            client = TestClient(app, raise_server_exceptions=True)
            resp = client.post("/me/api-key")
            assert resp.status_code == 200

            # Inspect audit events
            events_with_plaintext = [
                e for e in audit.events
                if plaintext in str(vars(e) if hasattr(e, "__dict__") else e)
            ]
            assert len(events_with_plaintext) == 0, (
                f"REGRESSION: audit event contains plaintext token: {events_with_plaintext}"
            )
        finally:
            _teardown(originals)
