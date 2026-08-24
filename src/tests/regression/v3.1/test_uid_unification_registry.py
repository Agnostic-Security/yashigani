"""
Regression tests — 3.1 UID unification: registry method correctness + migration
fail-closed posture.

These tests were added to catch the BLOCK defects found by Lu + Laura's static
review of the uncommitted uid-unification refactor:

  BLOCK-1 (HIGH): IdentityRegistry had no get_by_email() method.  Calls in
      uid_migrations.py:65,206 and backoffice/routes/rbac.py:150 / scim.py:146
      raised AttributeError, masked by the bare except or MagicMock in tests.
      Fix: add get_by_email(email) → email_to_slug() → get_by_slug().

  BLOCK-2 (MEDIUM): permissions.py:387 called get_by_identity_id() (nonexistent)
      inside except Exception: pass — admin grant existence guard was dead code.
      Fix: use get(scope_id) + fail-closed on registry error.

  GAP-3: migrate_perm_grants_to_identity_id left unmapped DENY grants as-is
      (orphaned at the old email key).  Reader now queries by identity_id →
      key miss → DENY silently becomes ALLOW (fail-open).
      Fix: CRITICAL log + DELETE the orphaned key, consistent with the RBAC
      migration which REMOVES unmapped members.

Why MagicMock was not enough:
  MagicMock auto-creates any attribute access, so mock.get_by_identity_id()
  returns a new MagicMock instead of raising AttributeError.  The bugs were
  completely invisible to the original test suite.  These tests use the REAL
  IdentityRegistry (fakeredis-backed) or the _FaithfulStub from
  test_permissions_api.py, so a call to a nonexistent method fails immediately.

Last updated: 2026-07-03T00:00:00+00:00
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
                        scope_id: str, resource_id: str, allow: bool) -> bytes:
    """Directly seed a boolean grant in Redis, bypassing the PermissionStore,
    to simulate a pre-migration email-keyed grant."""
    key = f"perm:grant:{resource_type}:{scope_kind}:{scope_id}:{resource_id}"
    val = json.dumps({"allow": allow, "opa_policy_ref": None}).encode()
    redis_client.set(key, val)
    idx = f"perm:idx:{resource_type}:{scope_kind}:{scope_id}"
    redis_client.sadd(idx, resource_id.encode())
    return key.encode()


# ---------------------------------------------------------------------------
# A. IdentityRegistry.get_by_email
# ---------------------------------------------------------------------------

class TestGetByEmail:
    """get_by_email() must use email_to_slug() → get_by_slug() correctly."""

    def test_get_by_email_resolves_registered_identity(self):
        """get_by_email resolves an email to the registered identity."""
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug

        email = "alice@example.com"
        slug = email_to_slug(email)
        _iid, _ = reg.register(
            kind=IdentityKind.HUMAN,
            name="Alice Example",
            slug=slug,
        )

        result = reg.get_by_email(email)
        assert result is not None, "get_by_email should find the registered identity"
        assert result["identity_id"] == _iid
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

        # Lookup with mixed case — should still resolve
        result = reg.get_by_email("BOB@CORP.COM")
        assert result is not None
        assert result["slug"] == slug


# ---------------------------------------------------------------------------
# B. RBAC migration: email members re-keyed to identity_id
# ---------------------------------------------------------------------------

class TestMigrateRbacToIdentityId:
    """migrate_rbac_to_identity_id must resolve email → identity_id and re-key."""

    def test_email_member_rekeys_to_identity_id(self):
        """
        An email-keyed group member is resolved via get_by_email and the group
        is rewritten with the identity_id.

        This test verifies BLOCK-1 is actually closed: the migration calls
        get_by_email() on the real registry (not MagicMock), so if the method
        were still absent it would raise AttributeError and fail here.
        """
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

        # Pre-migration: group has the email address as the member (old format).
        group = RBACGroup(id="engineers", display_name="Engineers", members={email})
        rbac.add_group(group)

        # Confirm the email is in the group before migration
        loaded = rbac.get_group("engineers")
        assert email in loaded.members, "Pre-migration: email should be a member"

        migrate_rbac_to_identity_id(rbac, reg)

        # Post-migration: the group should have the identity_id, NOT the email.
        migrated = rbac.get_group("engineers")
        assert iid in migrated.members, "Post-migration: identity_id must be a member"
        assert email not in migrated.members, "Post-migration: email must be removed"

    def test_unmapped_email_member_is_removed(self, caplog):
        """
        An email that resolves to no identity is REMOVED from the group and
        logged at CRITICAL (GAP-3 consistency: both migrations must be fail-closed).
        """
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        rbac = _make_rbac_store(redis)

        from yashigani.rbac.model import RBACGroup
        from yashigani.gateway.uid_migrations import migrate_rbac_to_identity_id

        orphan_email = "ghost@example.com"
        # No identity registered for ghost@example.com.
        group = RBACGroup(id="admins", display_name="Admins", members={orphan_email})
        rbac.add_group(group)

        with caplog.at_level(logging.CRITICAL, logger="yashigani.migration.rbac_uid"):
            migrate_rbac_to_identity_id(rbac, reg)

        # The orphan must have been removed from the group.
        migrated = rbac.get_group("admins")
        assert orphan_email not in migrated.members, (
            "Unmapped email must be REMOVED from the group (fail-closed)"
        )
        # CRITICAL must have been logged.
        assert any("INCOMPLETE" in r.message or "REMOVED" in r.message
                   for r in caplog.records
                   if r.levelno >= logging.CRITICAL), (
            "CRITICAL log must be emitted for unmapped members"
        )


# ---------------------------------------------------------------------------
# C. Perm-grant migration: DENY grant re-keyed + fail-open closed
# ---------------------------------------------------------------------------

class TestMigratePermGrantsToIdentityId:
    """
    migrate_perm_grants_to_identity_id must re-key email-keyed grants to
    identity_id — specifically DENY grants, which silently become ALLOW when
    left at the old email key (fail-open / the original Iris finding).
    """

    def test_deny_grant_rekeys_and_enforces_after_migration(self):
        """
        A pre-migration DENY grant at perm:grant:*:user:{email}:* is re-keyed
        to perm:grant:*:user:{identity_id}:* and resolve_boolean_grant returns
        False (DENIED) for the identity after migration.

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

        # Seed the org ALLOW grant (so the org ceiling permits the resource).
        perm.set_boolean_grant(ResourceType.MCP_SERVER, "org", "default", "my-server",
                               _boolval(allow=True))

        # Seed the DENY grant at the OLD email-keyed path (pre-migration format).
        _seed_boolean_grant(redis, "mcp_server", "user", email, "my-server", allow=False)

        # Before migration: resolver queries by identity_id → key miss → returns
        # True (org allows, no user-tier DENY found at the identity_id key).
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

        # Run the migration.
        migrate_perm_grants_to_identity_id(perm, reg)

        # After migration: DENY grant is at the identity_id key → resolver
        # finds it and returns False (DENIED).
        after = resolve_boolean_grant(
            ResourceType.MCP_SERVER, "my-server",
            org_id="default", group_ids=[],
            principal_scope="user", principal_id=iid,
            store=perm,
        )
        assert after is False, (
            "After migration the DENY grant must be at the identity_id key "
            "and resolve_boolean_grant must return False (DENIED) — "
            "fail-open is closed."
        )

        # Also verify the old email-keyed key is gone.
        old_key = f"perm:grant:mcp_server:user:{email}:my-server"
        assert redis.get(old_key.encode()) is None, (
            "The old email-keyed grant key must have been deleted after migration"
        )

    def test_unmapped_scope_id_key_deleted_and_logged(self, caplog):
        """
        GAP-3: An unmapped scope_id (no identity found) must have its key
        DELETED (not left as-is) and CRITICAL must be logged.

        Before the fix: warning + left as-is → a DENY grant silently becomes
        ALLOW because the reader never queries by email key again.
        """
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        perm = _make_perm_store(redis)

        from yashigani.gateway.uid_migrations import migrate_perm_grants_to_identity_id

        orphan_email = "ghost@example.com"
        # Seed a DENY grant at an orphaned email key. No identity registered.
        _seed_boolean_grant(redis, "mcp_server", "user", orphan_email,
                            "secure-server", allow=False)
        orphan_key = f"perm:grant:mcp_server:user:{orphan_email}:secure-server"

        with caplog.at_level(logging.CRITICAL, logger="yashigani.migration.perm_uid"):
            migrate_perm_grants_to_identity_id(perm, reg)

        # Key must be deleted (not left silently as-is).
        assert redis.get(orphan_key.encode()) is None, (
            "Orphaned grant key must be DELETED (not left as 'orphaned, inert')"
        )
        # CRITICAL must be logged.
        assert any("REMOVED" in r.message
                   for r in caplog.records
                   if r.levelno >= logging.CRITICAL), (
            "CRITICAL log must be emitted for unmapped scope_id"
        )

    def test_already_identity_id_keyed_grant_is_skipped(self):
        """
        Idempotency: grants already keyed by identity_id (idnt_*) are skipped,
        not re-processed.
        """
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)
        perm = _make_perm_store(redis)

        from yashigani.gateway.uid_migrations import migrate_perm_grants_to_identity_id

        identity_id = "idnt_abc123def456"
        perm.set_boolean_grant(
            __import__("yashigani.permissions.model", fromlist=["ResourceType"]).ResourceType.MCP_SERVER,
            "user", identity_id, "already-keyed-server",
            _boolval(allow=False),
        )

        # Migration should not remove/modify identity_id-keyed entries.
        migrate_perm_grants_to_identity_id(perm, reg)

        from yashigani.permissions.model import ResourceType
        after = perm.get_boolean_grant(
            ResourceType.MCP_SERVER, "user", identity_id, "already-keyed-server"
        )
        assert after is not None and after.allow is False, (
            "Identity_id-keyed grant must survive the migration unchanged"
        )


# ---------------------------------------------------------------------------
# D. RBAC route: email → identity_id resolution uses get_by_email
# ---------------------------------------------------------------------------

class TestRbacRouteEmailResolution:
    """
    _resolve_identity_id_from_email in backoffice/routes/rbac.py must resolve
    an email to identity_id via get_by_email (which now exists on the registry).
    Before the fix, get_by_email raised AttributeError → caught → HTTP 503.
    """

    def test_resolve_identity_id_from_email_succeeds_with_real_registry(self):
        """
        rbac._resolve_identity_id_from_email resolves a registered email to
        its identity_id using the real IdentityRegistry (fakeredis-backed).
        """
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)

        from yashigani.identity.registry import IdentityKind
        from yashigani.identity.slug import email_to_slug
        from yashigani.backoffice.routes import rbac as rbac_mod
        from yashigani.backoffice.state import BackofficeState

        email = "carol@test.example"
        slug = email_to_slug(email)
        iid, _ = reg.register(kind=IdentityKind.HUMAN, name="Carol", slug=slug)

        state = BackofficeState()
        state.identity_registry = reg

        original = rbac_mod.backoffice_state
        rbac_mod.backoffice_state = state
        try:
            resolved = rbac_mod._resolve_identity_id_from_email(email)
            assert resolved == iid, (
                "_resolve_identity_id_from_email must return the identity_id "
                "for a registered email"
            )
        finally:
            rbac_mod.backoffice_state = original

    def test_resolve_identity_id_from_email_raises_503_when_get_by_email_missing(self):
        """
        If the registry stub lacks get_by_email (AttributeError), the route
        catches it and returns HTTP 503 — never silently passes through.

        This test verifies the pre-fix failure mode: a stub without get_by_email
        caused 503 for all real callers, meaning RBAC membership management was
        completely broken. After the fix, the real registry has get_by_email and
        this test documents what 503 looks like when the registry is broken.
        """
        from fastapi import HTTPException

        class _NoEmailMethodRegistry:
            """Stub that has NO get_by_email — simulates the pre-fix state."""
            def get(self, identity_id):
                return None
            def get_by_slug(self, slug):
                return None
            # Deliberately NO get_by_email.

        from yashigani.backoffice.routes import rbac as rbac_mod
        from yashigani.backoffice.state import BackofficeState

        state = BackofficeState()
        state.identity_registry = _NoEmailMethodRegistry()

        original = rbac_mod.backoffice_state
        rbac_mod.backoffice_state = state
        try:
            with pytest.raises(HTTPException) as exc_info:
                rbac_mod._resolve_identity_id_from_email("user@example.com")
            assert exc_info.value.status_code == 503, (
                "AttributeError from a registry with no get_by_email must "
                "produce HTTP 503 — never a silent 200"
            )
        finally:
            rbac_mod.backoffice_state = original

    def test_resolve_identity_id_from_email_raises_404_for_unregistered_email(self):
        """
        rbac._resolve_identity_id_from_email returns HTTP 404 when the email
        is valid but not registered in the identity registry.
        """
        redis = _make_fake_redis()
        reg = _make_real_registry(redis)

        from fastapi import HTTPException
        from yashigani.backoffice.routes import rbac as rbac_mod
        from yashigani.backoffice.state import BackofficeState

        state = BackofficeState()
        state.identity_registry = reg  # real registry, no identities registered

        original = rbac_mod.backoffice_state
        rbac_mod.backoffice_state = state
        try:
            with pytest.raises(HTTPException) as exc_info:
                rbac_mod._resolve_identity_id_from_email("nobody@example.com")
            assert exc_info.value.status_code == 404
            assert exc_info.value.detail["error"] == "identity_not_found"
        finally:
            rbac_mod.backoffice_state = original


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _boolval(allow: bool):
    from yashigani.permissions.model import BooleanGrantValue
    return BooleanGrantValue(allow=allow)
