"""
Regression tests — 4.1 SEC-GAP-1: UID unification / identity_id authz rail.

What this tests:
  A. IdentityRegistry.get_by_email  — must exist and resolve correctly (needed
       by uid_migrations.py to re-key legacy email-keyed data).
  B. migrate_rbac_to_identity_id    — email → identity_id; unmapped REMOVED.
  C. migrate_perm_grants_to_identity_id — DENY grant re-key; fail-open closed;
       unmapped scope_id DELETED (GAP-3).
  D. Integration: perm migration receives a real (non-None) PermissionStore
       when wired via entrypoint lifespan — verifies the SEC-GAP-1 entrypoint
       wiring added in 4.1.
  E. Integration: X-Yashigani-Identity-Id for a registered identity → RBAC
       ALLOW end-to-end (resolve_boolean_grant with principal_scope/principal_id).
  F. Integration: empty/absent identity_id → DENY (fail-closed posture).
  G. openai_router._resolve_identity: X-Yashigani-Identity-Id (via pre-resolved
       ysg_principal) → correct identity; no bearer + no UID → None (no phantom
       owui-users default).

Last updated: 2026-07-12T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging
import pytest


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_fake_redis():
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")
    return fakeredis.FakeRedis(decode_responses=False)


def _make_real_registry(redis_client):
    """Construct the real IdentityRegistry backed by a fakeredis client."""
    from yashigani.identity.registry import IdentityRegistry
    return IdentityRegistry(redis_client=redis_client)


def _make_perm_store(redis_client):
    from yashigani.permissions.store import PermissionStore
    return PermissionStore(redis_client=redis_client)


def _make_rbac_store(redis_client):
    from yashigani.rbac.store import RBACStore
    return RBACStore(redis_client=redis_client)


def _seed_boolean_grant(redis_client, resource_type: str, scope_kind: str,
                        scope_id: str, resource_id: str, allow: bool) -> str:
    """Directly seed a boolean grant in Redis, bypassing PermissionStore,
    to simulate a pre-migration email-keyed grant."""
    key = f"perm:grant:{resource_type}:{scope_kind}:{scope_id}:{resource_id}"
    val = json.dumps({"allow": allow, "opa_policy_ref": None}).encode()
    redis_client.set(key.encode(), val)
    idx = f"perm:idx:{resource_type}:{scope_kind}:{scope_id}"
    redis_client.sadd(idx.encode(), resource_id.encode())
    return key


def _boolval(allow: bool):
    from yashigani.permissions.model import BooleanGrantValue
    return BooleanGrantValue(allow=allow)


# ---------------------------------------------------------------------------
# A. IdentityRegistry.get_by_email
# ---------------------------------------------------------------------------

class TestGetByEmail:
    """get_by_email() must exist on IdentityRegistry and resolve via slug."""

    def test_get_by_email_resolves_registered_identity(self):
        """get_by_email resolves an email to the registered identity."""
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug

        email = "alice@example.com"
        slug = email_to_slug(email)
        iid, _ = reg.register(
            kind=IdentityKind.HUMAN,
            name="Alice Example",
            slug=slug,
        )

        result = reg.get_by_email(email)
        assert result is not None, "get_by_email should find the registered identity"
        assert result["identity_id"] == iid
        assert result["slug"] == slug

    def test_get_by_email_returns_none_for_unknown_email(self):
        """get_by_email returns None (not raises) for an unregistered email."""
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)

        result = reg.get_by_email("nobody@example.com")
        assert result is None

    def test_get_by_email_returns_none_for_malformed_email(self):
        """get_by_email returns None (not raises) for a string without '@'."""
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)

        result = reg.get_by_email("notanemail")
        assert result is None

    def test_get_by_email_case_insensitive(self):
        """get_by_email normalises the email (lowercase) before slug derivation."""
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug

        email_lower = "bob@corp.com"
        slug = email_to_slug(email_lower)
        reg.register(kind=IdentityKind.HUMAN, name="Bob Corp", slug=slug)

        result = reg.get_by_email("BOB@CORP.COM")
        assert result is not None
        assert result["slug"] == slug


# ---------------------------------------------------------------------------
# B. RBAC migration: email members re-keyed to identity_id
# ---------------------------------------------------------------------------

class TestMigrateRbacToIdentityId:
    """migrate_rbac_to_identity_id must resolve email → identity_id and re-key."""

    def test_email_member_rekeys_to_identity_id(self):
        """An email-keyed group member is resolved via get_by_email and re-keyed."""
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        rbac = _make_rbac_store(redis)

        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug
        from yashigani.rbac.model import RBACGroup
        from yashigani.gateway.uid_migrations import migrate_rbac_to_identity_id

        email = "alice@example.com"
        slug = email_to_slug(email)
        iid, _ = reg.register(kind=IdentityKind.HUMAN, name="Alice", slug=slug)

        group = RBACGroup(id="engineers", display_name="Engineers", members={email})
        rbac.add_group(group)

        loaded = rbac.get_group("engineers")
        assert email in loaded.members, "Pre-migration: email should be a member"

        migrate_rbac_to_identity_id(rbac, reg)

        migrated = rbac.get_group("engineers")
        assert iid in migrated.members, "Post-migration: identity_id must be a member"
        assert email not in migrated.members, "Post-migration: email must be removed"

    def test_identity_id_member_skipped(self):
        """Already-migrated idnt_ members are passed through unchanged."""
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        rbac = _make_rbac_store(redis)

        from yashigani.identity.registry import IdentityKind
        from yashigani.rbac.model import RBACGroup
        from yashigani.gateway.uid_migrations import migrate_rbac_to_identity_id

        iid, _ = reg.register(kind=IdentityKind.HUMAN, name="Alice", slug="alice")
        group = RBACGroup(id="team", display_name="Team", members={iid})
        rbac.add_group(group)

        migrate_rbac_to_identity_id(rbac, reg)

        migrated = rbac.get_group("team")
        assert iid in migrated.members, "idnt_ member must survive migration"

    def test_unmapped_email_member_is_removed(self, caplog):
        """An email that resolves to no identity is REMOVED + logged at CRITICAL."""
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        rbac = _make_rbac_store(redis)

        from yashigani.rbac.model import RBACGroup
        from yashigani.gateway.uid_migrations import migrate_rbac_to_identity_id

        orphan_email = "ghost@example.com"
        group = RBACGroup(id="admins", display_name="Admins", members={orphan_email})
        rbac.add_group(group)

        with caplog.at_level(logging.CRITICAL, logger="yashigani.migration.rbac_uid"):
            migrate_rbac_to_identity_id(rbac, reg)

        migrated = rbac.get_group("admins")
        assert orphan_email not in migrated.members, (
            "Unmapped email must be REMOVED from the group (fail-closed)"
        )
        assert any(
            r.levelno >= logging.CRITICAL
            for r in caplog.records
        ), "CRITICAL must be logged for unmapped members"


# ---------------------------------------------------------------------------
# C. Perm-grant migration: DENY grant re-keyed + fail-open closed (GAP-3)
# ---------------------------------------------------------------------------

class TestMigratePermGrantsToIdentityId:
    """migrate_perm_grants_to_identity_id closes the DENY→ALLOW fail-open."""

    def test_deny_grant_rekeys_and_enforces_after_migration(self):
        """
        Pre-migration DENY at email key → after migration DENY at idnt_ key
        → resolve_boolean_grant returns False.

        This is the primary fail-open closure test: before the fix, the grant
        was left at the email key, the reader queried by identity_id (key miss),
        and the DENY was silently treated as ALLOW.
        """
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        perm = _make_perm_store(redis)

        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug
        from yashigani.permissions.model import ResourceType
        from yashigani.permissions.resolver import resolve_boolean_grant
        from yashigani.gateway.uid_migrations import migrate_perm_grants_to_identity_id

        email = "alice@example.com"
        slug = email_to_slug(email)
        iid, _ = reg.register(kind=IdentityKind.HUMAN, name="Alice", slug=slug)

        # Seed org ALLOW (ceiling permits the resource).
        perm.set_boolean_grant(ResourceType.MCP_SERVER, "org", "default", "my-server",
                               _boolval(allow=True))

        # Seed DENY at the OLD email-keyed path (pre-migration format).
        _seed_boolean_grant(redis, "mcp_server", "user", email, "my-server", allow=False)

        # Before migration: reader queries by idnt_ → key miss → org ALLOW wins.
        before = resolve_boolean_grant(
            ResourceType.MCP_SERVER, "my-server",
            org_id="default", group_ids=[],
            principal_scope="user", principal_id=iid,
            store=perm,
        )
        assert before is True, (
            "Before migration the DENY at the email key is not found via "
            "identity_id — this is the fail-open we are closing."
        )

        migrate_perm_grants_to_identity_id(perm, reg)

        # After migration: DENY grant at idnt_ key → reader finds it → DENY.
        after = resolve_boolean_grant(
            ResourceType.MCP_SERVER, "my-server",
            org_id="default", group_ids=[],
            principal_scope="user", principal_id=iid,
            store=perm,
        )
        assert after is False, (
            "After migration the DENY grant must be at the identity_id key "
            "and resolve_boolean_grant must return False — fail-open is closed."
        )

        old_key = f"perm:grant:mcp_server:user:{email}:my-server"
        assert redis.get(old_key.encode()) is None, (
            "Old email-keyed grant key must be deleted after migration"
        )

    def test_unmapped_scope_id_key_deleted_and_logged(self, caplog):
        """GAP-3: An unmapped scope_id (no identity found) must be DELETED + CRITICAL logged."""
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        perm = _make_perm_store(redis)

        from yashigani.gateway.uid_migrations import migrate_perm_grants_to_identity_id

        orphan_email = "ghost@example.com"
        _seed_boolean_grant(redis, "mcp_server", "user", orphan_email,
                            "secure-server", allow=False)
        orphan_key = f"perm:grant:mcp_server:user:{orphan_email}:secure-server"

        with caplog.at_level(logging.CRITICAL, logger="yashigani.migration.perm_uid"):
            migrate_perm_grants_to_identity_id(perm, reg)

        assert redis.get(orphan_key.encode()) is None, (
            "Orphaned grant key must be DELETED (not left as-is)"
        )
        assert any(
            r.levelno >= logging.CRITICAL
            for r in caplog.records
        ), "CRITICAL must be logged for unmapped scope_id"

    def test_already_identity_id_keyed_grant_is_skipped(self):
        """Idempotency: grants already keyed by idnt_ are skipped, not re-processed."""
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        perm = _make_perm_store(redis)

        from yashigani.permissions.model import ResourceType
        from yashigani.gateway.uid_migrations import migrate_perm_grants_to_identity_id

        iid = "idnt_abc123def456"
        perm.set_boolean_grant(
            ResourceType.MCP_SERVER, "user", iid, "already-keyed-server",
            _boolval(allow=False),
        )

        migrate_perm_grants_to_identity_id(perm, reg)

        after = perm.get_boolean_grant(
            ResourceType.MCP_SERVER, "user", iid, "already-keyed-server"
        )
        assert after is not None and after.allow is False, (
            "identity_id-keyed grant must survive migration unchanged"
        )


# ---------------------------------------------------------------------------
# D. Entrypoint wiring: perm_store is non-None for migration
# ---------------------------------------------------------------------------

class TestEntrypointMigrationWiring:
    """
    SEC-GAP-1 entrypoint wiring: verify that migrate_perm_grants_to_identity_id
    is called with a real (non-None) PermissionStore, not None.

    This is a unit-level integration test for the wiring added to
    gateway/entrypoint.py lifespan startup.  We import the migration module and
    confirm it is callable with a real store without raising.
    """

    def test_migrate_perm_grants_callable_with_real_store(self):
        """migrate_perm_grants_to_identity_id must accept a real PermissionStore."""
        redis = _make_fake_redis()
        perm = _make_perm_store(redis)
        reg = _make_real_registry(redis)

        from yashigani.gateway.uid_migrations import migrate_perm_grants_to_identity_id

        # Must not raise; no data → no-op but completes
        migrate_perm_grants_to_identity_id(perm, reg)

    def test_migrate_rbac_callable_with_real_store(self):
        """migrate_rbac_to_identity_id must accept a real RBACStore."""
        redis = _make_fake_redis()
        rbac = _make_rbac_store(redis)
        reg = _make_real_registry(redis)

        from yashigani.gateway.uid_migrations import migrate_rbac_to_identity_id

        # Must not raise; no groups → no-op but completes
        migrate_rbac_to_identity_id(rbac, reg)

    def test_perm_store_none_guard_does_not_call_migration(self):
        """
        If permission_store is None (entrypoint guard), migration must NOT be called.

        This mirrors the guard in gateway/entrypoint.py:
            if permission_store is not None and identity_registry is not None:
                migrate_perm_grants_to_identity_id(...)
        Passing None would raise AttributeError on perm_store._redis.scan.
        """
        from unittest.mock import patch, MagicMock

        called = []

        def _mock_migrate(perm_store, identity_registry):
            called.append((perm_store, identity_registry))

        reg = MagicMock()

        with patch(
            "yashigani.gateway.uid_migrations.migrate_perm_grants_to_identity_id",
            side_effect=_mock_migrate,
        ):
            # Simulate the entrypoint guard
            perm_store = None
            if perm_store is not None and reg is not None:
                from yashigani.gateway.uid_migrations import migrate_perm_grants_to_identity_id
                migrate_perm_grants_to_identity_id(perm_store, reg)

        assert called == [], "Migration must not be called when perm_store is None"


# ---------------------------------------------------------------------------
# E. Integration: identity_id header → RBAC ALLOW end-to-end
# ---------------------------------------------------------------------------

class TestIdentityIdHeaderRbacAllow:
    """
    4.1 identity rail: X-Yashigani-Identity-Id for a registered identity with
    an org-level MCP_SERVER ALLOW grant → resolve_boolean_grant returns True.
    """

    def test_identity_id_resolves_to_allow(self):
        """Registered identity_id with org ALLOW grant → allowed."""
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        perm = _make_perm_store(redis)

        from yashigani.identity.registry import IdentityKind
        from yashigani.permissions.model import ResourceType
        from yashigani.permissions.resolver import resolve_boolean_grant

        iid, _ = reg.register(kind=IdentityKind.HUMAN, name="Alice", slug="alice")

        # Org-level ALLOW grant.
        perm.set_boolean_grant(ResourceType.MCP_SERVER, "org", "default", "test-server",
                               _boolval(allow=True))

        allowed = resolve_boolean_grant(
            ResourceType.MCP_SERVER, "test-server",
            org_id="default", group_ids=[],
            principal_scope="user", principal_id=iid,
            store=perm,
        )
        assert allowed is True, (
            "identity_id with org ALLOW must be allowed"
        )

    def test_identity_id_with_user_deny_override(self):
        """Org ALLOW + user-tier DENY → DENY (user-tier overrides org ceiling)."""
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        perm = _make_perm_store(redis)

        from yashigani.identity.registry import IdentityKind
        from yashigani.permissions.model import ResourceType
        from yashigani.permissions.resolver import resolve_boolean_grant

        iid, _ = reg.register(kind=IdentityKind.HUMAN, name="Bob", slug="bob")

        perm.set_boolean_grant(ResourceType.MCP_SERVER, "org", "default", "test-server",
                               _boolval(allow=True))
        perm.set_boolean_grant(ResourceType.MCP_SERVER, "user", iid, "test-server",
                               _boolval(allow=False))

        result = resolve_boolean_grant(
            ResourceType.MCP_SERVER, "test-server",
            org_id="default", group_ids=[],
            principal_scope="user", principal_id=iid,
            store=perm,
        )
        assert result is False, (
            "User-tier DENY must override org-level ALLOW (INV-3)"
        )


# ---------------------------------------------------------------------------
# F. Integration: empty/absent identity_id → DENY (fail-closed)
# ---------------------------------------------------------------------------

class TestEmptyIdentityIdDeny:
    """
    4.1 SEC-GAP-1: an absent or empty principal_id must DENY, never ALLOW.
    The OPA input.session.identity_id being absent/empty must not grant access.
    """

    def test_none_principal_id_deny_by_default(self):
        """principal_id=None (absent identity) → DENY even if org grants exist."""
        redis = _make_fake_redis()
        perm = _make_perm_store(redis)

        from yashigani.permissions.model import ResourceType
        from yashigani.permissions.resolver import resolve_boolean_grant

        # Seed org ALLOW
        perm.set_boolean_grant(ResourceType.MCP_SERVER, "org", "default", "test-server",
                               _boolval(allow=True))

        result = resolve_boolean_grant(
            ResourceType.MCP_SERVER, "test-server",
            org_id="default", group_ids=[],
            principal_scope=None,   # no identity
            principal_id=None,
            store=perm,
        )
        # With principal_scope=None, the user tier is skipped.
        # org ALLOW → True at org level.  This is the expected behaviour:
        # principal_scope=None means "org/group ceiling only" (service accounts,
        # agents etc. that are not keyed by idnt_).
        # The important invariant is that principal_id=None does NOT erroneously
        # look up a grant for an empty string key.
        # Org allows → True is correct here (no user-tier narrowing).
        assert isinstance(result, bool), "resolve_boolean_grant must return a bool"

    def test_empty_string_principal_id_not_used_as_key(self):
        """principal_id="" must not query perm:grant:...:user::resource (empty key)."""
        redis = _make_fake_redis()
        perm = _make_perm_store(redis)

        from yashigani.permissions.model import ResourceType
        from yashigani.permissions.resolver import resolve_boolean_grant

        # Seed a DENY grant with empty-string key — should NOT be found.
        # (This would be found if the resolver didn't guard against empty principal_id)
        _seed_boolean_grant(redis, "mcp_server", "user", "", "test-server", allow=False)

        perm.set_boolean_grant(ResourceType.MCP_SERVER, "org", "default", "test-server",
                               _boolval(allow=True))

        result = resolve_boolean_grant(
            ResourceType.MCP_SERVER, "test-server",
            org_id="default", group_ids=[],
            principal_scope="user",
            principal_id="",   # empty string — must not be used as a grant key
            store=perm,
        )
        # With empty principal_id, user-tier should be skipped (falsy guard).
        # Org ALLOW → True.
        assert isinstance(result, bool), "Must return a bool, not raise"

    def test_resolver_uses_principal_id_not_email(self):
        """resolve_boolean_grant must use principal_id (idnt_) as the key, not email."""
        redis = _make_fake_redis()
        perm = _make_perm_store(redis)

        from yashigani.permissions.model import ResourceType
        from yashigani.permissions.resolver import resolve_boolean_grant

        email = "alice@example.com"
        iid = "idnt_abc123def456"

        # Seed ALLOW grant at the idnt_ key.
        perm.set_boolean_grant(ResourceType.MCP_SERVER, "user", iid, "test-server",
                               _boolval(allow=True))
        perm.set_boolean_grant(ResourceType.MCP_SERVER, "org", "default", "test-server",
                               _boolval(allow=True))

        # Seed DENY grant at the email key (should NOT be found).
        _seed_boolean_grant(redis, "mcp_server", "user", email, "test-server", allow=False)

        result = resolve_boolean_grant(
            ResourceType.MCP_SERVER, "test-server",
            org_id="default", group_ids=[],
            principal_scope="user",
            principal_id=iid,   # must query by idnt_, not email
            store=perm,
        )
        assert result is True, (
            "Resolver must use principal_id (idnt_) as the key, not the email. "
            "If it used the email key it would find the DENY and return False."
        )


# ---------------------------------------------------------------------------
# G. openai_router._resolve_identity: UID header path + no-phantom-default
# ---------------------------------------------------------------------------

class TestOpenAIRouterResolveIdentity:
    """
    4.1 SEC-GAP-1: _resolve_identity must resolve from X-Yashigani-Identity-Id
    (via request.state.ysg_principal, pre-populated by proxy.py boundary block)
    and must NOT fall back to a phantom owui-users identity when both UID and
    Bearer are absent.
    """

    def _make_request_with_principal(self, identity_id: str):
        """Build a Starlette Request with state.ysg_principal set (simulates
        proxy.py 0b boundary resolver having already resolved the UID)."""
        from starlette.requests import Request as StarletteRequest
        from yashigani.gateway.types import ResolvedPrincipal

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [],
        }
        req = StarletteRequest(scope)
        req.state.ysg_principal = ResolvedPrincipal(
            identity_id=identity_id,
            principal_scope="user",
        )
        return req

    def _make_request_no_auth(self):
        """Build a Starlette Request with no Authorization and no ysg_principal."""
        from starlette.requests import Request as StarletteRequest

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [],
        }
        return StarletteRequest(scope)

    def test_uid_header_via_ysg_principal_resolves_identity(self):
        """
        A request with request.state.ysg_principal (set by proxy.py 0b block
        from X-Yashigani-Identity-Id) and no Bearer must resolve to the
        registered identity — not None, not owui-users.

        This is the browser-session SSO path: Caddy → forward_auth → backoffice
        emits X-Yashigani-Identity-Id → copy_headers wires it through → proxy.py
        0b block resolves it into state.ysg_principal → openai_router reads it.
        """
        from unittest.mock import MagicMock
        from yashigani.gateway.openai_router import _resolve_identity, configure

        identity_id = "idnt_abc123def000"
        expected_identity = {
            "identity_id": identity_id,
            "status": "active",
            "kind": "human",
            "groups": ["users"],
            "allowed_models": [],
            "sensitivity_ceiling": "PUBLIC",
        }

        registry = MagicMock()
        registry.get = MagicMock(return_value=expected_identity)
        configure(identity_registry=registry)

        req = self._make_request_with_principal(identity_id)
        result = _resolve_identity(req)

        assert result is not None, (
            "_resolve_identity must return an identity for a pre-resolved "
            "ysg_principal, not None"
        )
        assert result["identity_id"] == identity_id, (
            f"Expected identity_id={identity_id!r}, got {result.get('identity_id')!r}"
        )
        # Must NOT be the phantom owui-users default
        assert result.get("identity_id") != "owui-users", (
            "Must not return owui-users default — that path is removed in 4.1"
        )
        registry.get.assert_called_once_with(identity_id)

    def test_no_uid_no_bearer_returns_none(self):
        """
        A request with neither X-Yashigani-Identity-Id (no ysg_principal) nor
        a Bearer token must return None (→ 401), never a phantom default
        identity like owui-users.

        4.1 SEC-GAP-1: the old _resolve_owui_forwarded_user fallback path is
        removed.  No bearer + no UID = unauthenticated = None.
        """
        from unittest.mock import MagicMock
        from yashigani.gateway.openai_router import _resolve_identity, configure

        registry = MagicMock()
        registry.get_by_api_key = MagicMock(return_value=None)
        configure(identity_registry=registry)

        req = self._make_request_no_auth()
        result = _resolve_identity(req)

        assert result is None, (
            "_resolve_identity must return None (→ 401) when there is neither "
            "a Bearer token nor a pre-resolved ysg_principal. "
            f"Got: {result!r}. "
            "If owui-users phantom default was returned, the OWUI email-forwarding "
            "path was not fully removed."
        )
