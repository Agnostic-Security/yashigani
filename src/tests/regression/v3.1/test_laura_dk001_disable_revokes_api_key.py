"""
Regression test — LAURA-DK-001 (Medium): disabling a user account must revoke
their HUMAN identity so the API key returns 401/403 on /v1/*.

Root cause (confirmed 2026-07-04):
  _register_human_identity_on_login() in auth.py called registry.register()
  without org_id — it defaulted to "".  The Lua script skips the
  ``identity:index:org:{org_id}`` SADD when org_id="", so the org index is
  never populated.  suspend_owned_by(account_id) then finds an empty set and
  suspends zero identities.  The LF-DISABLE-PARTIAL code was wired correctly
  but silently a no-op for every HUMAN identity.

Fixes shipped:
  (a) auth.py: pass org_id=record.account_id at HUMAN identity registration —
      populates the org index for all new logins.
  (b) users.py / accounts.py: slug-based fallback in
      _suspend_identity_registry_for_account — when suspend_owned_by returns 0
      and we have username/email, derive the canonical slug and suspend the
      identity directly.  Covers ALL existing identities with no Redis
      backfill required.

Tests:
  DK001-1  Human identity is registered with org_id=account_id (fix a)
  DK001-2  disable via suspend_owned_by path (post-fix-a identities)
  DK001-3  disable via slug fallback path (pre-fix-a identities with org_id="")
  DK001-4  account A disable does NOT touch account B identity
  DK001-5  reactivate restores the identity to active (round-trip)
  DK001-6  empty org_id guard — suspend_owned_by("") is a no-op, no broad blast
  DK001-7  slug fallback is not called when suspend_owned_by already found entries

ASVS v5: V4.1.1 (access revocation), V9.1.2 (deprovisioning).
Last updated: 2026-07-04T00:00:00+00:00
"""
from __future__ import annotations

import pytest
from dataclasses import dataclass
from typing import Optional
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------

def _make_fake_redis():
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")
    return fakeredis.FakeRedis(decode_responses=False)


def _make_real_registry(redis_client, durable_store=None):
    from yashigani.identity.registry import IdentityRegistry
    return IdentityRegistry(redis_client=redis_client, durable_store=durable_store)


@dataclass
class _AccountRecord:
    username: str
    account_id: str
    account_tier: str = "user"
    email: Optional[str] = None
    disabled: bool = False
    force_password_change: bool = False
    force_totp_provision: bool = False


def _register_human(registry, username: str, account_id: str, email: Optional[str] = None):
    """Register a HUMAN identity as auth.py does AFTER fix (a): with org_id=account_id."""
    from yashigani.identity.registry import IdentityKind
    from yashigani.identity.slug import email_to_slug
    slug_email = email or f"{username}@yashigani.local"
    slug = email_to_slug(slug_email)
    identity_id, plaintext_key = registry.register(
        kind=IdentityKind.HUMAN,
        name=username,
        slug=slug,
        description=f"local-auth user; account_id={account_id}",
        org_id=account_id,  # fix (a)
    )
    return identity_id, plaintext_key, slug


def _register_human_legacy(registry, username: str, account_id: str, email: Optional[str] = None):
    """Register a HUMAN identity as auth.py did BEFORE fix (a): without org_id."""
    from yashigani.identity.registry import IdentityKind
    from yashigani.identity.slug import email_to_slug
    slug_email = email or f"{username}@yashigani.local"
    slug = email_to_slug(slug_email)
    identity_id, plaintext_key = registry.register(
        kind=IdentityKind.HUMAN,
        name=username,
        slug=slug,
        description=f"local-auth user; account_id={account_id}",
        # org_id intentionally omitted — reproduces the pre-fix bug
    )
    return identity_id, plaintext_key, slug


# ---------------------------------------------------------------------------
# DK001-1: HUMAN identity is registered with org_id=account_id after fix (a)
# ---------------------------------------------------------------------------

class TestFix_A_OrgIdAtRegistration:
    """fix (a): auth.py now passes org_id=account_id when registering HUMAN identities."""

    def test_human_identity_registered_with_org_id(self):
        """The identity:index:org:{account_id} Redis set is populated at registration."""
        r = _make_fake_redis()
        registry = _make_real_registry(r)
        account_id = "usr_aaa111"

        identity_id, _, _ = _register_human(registry, "alice", account_id, email="alice@example.com")

        # Org index must have this identity_id
        members = {
            m.decode() if isinstance(m, bytes) else m
            for m in r.smembers(f"identity:index:org:{account_id}")
        }
        assert identity_id in members, (
            f"LAURA-DK-001 fix (a) MISSING: identity:index:org:{account_id} not populated. "
            "auth.py must pass org_id=record.account_id to registry.register()."
        )

    def test_suspend_owned_by_finds_human_identity_after_fix_a(self):
        """After fix (a), suspend_owned_by(account_id) finds and suspends the HUMAN identity."""
        r = _make_fake_redis()
        registry = _make_real_registry(r)
        account_id = "usr_bbb222"

        identity_id, _, _ = _register_human(registry, "bob", account_id, email="bob@example.com")
        assert registry.get(identity_id)["status"] == "active"

        count = registry.suspend_owned_by(account_id)

        assert count == 1, "suspend_owned_by must return 1 for a HUMAN registered with org_id"
        assert registry.get(identity_id)["status"] == "suspended"


# ---------------------------------------------------------------------------
# DK001-2 / DK001-3: _suspend_identity_registry_for_account behaviour
# ---------------------------------------------------------------------------

class TestSuspendHelperBothPaths:
    """
    Tests for _suspend_identity_registry_for_account in users.py.
    Uses a real IdentityRegistry backed by fakeredis so we catch real missing
    org-index bugs (MagicMock would hide them).
    """

    def _make_backoffice_state(self, registry):
        state = MagicMock()
        state.identity_registry = registry
        return state

    def test_dk001_2_suspend_via_org_index_path(self):
        """DK001-2: post-fix-a identity (org_id=account_id) is suspended via org index."""
        r = _make_fake_redis()
        registry = _make_real_registry(r)
        account_id = "usr_post_fix"

        identity_id, _, _ = _register_human(
            registry, "carol", account_id, email="carol@example.com"
        )

        state = self._make_backoffice_state(registry)
        with patch(
            "yashigani.backoffice.routes.users.backoffice_state", state
        ):
            from yashigani.backoffice.routes.users import _suspend_identity_registry_for_account
            _suspend_identity_registry_for_account(
                account_id, username="carol", email="carol@example.com"
            )

        assert registry.get(identity_id)["status"] == "suspended", (
            "LAURA-DK-001: identity must be suspended after account disable (org-index path)"
        )

    def test_dk001_3_suspend_via_slug_fallback_legacy_identity(self):
        """DK001-3: pre-fix-a identity (org_id="") is suspended via slug fallback."""
        r = _make_fake_redis()
        registry = _make_real_registry(r)
        account_id = "usr_pre_fix"

        # Register WITHOUT org_id — reproduces the pre-fix bug
        identity_id, _, _ = _register_human_legacy(
            registry, "dave", account_id, email="dave@example.com"
        )

        # Confirm the org index is empty (the pre-fix bug state)
        members = {
            m.decode() if isinstance(m, bytes) else m
            for m in r.smembers(f"identity:index:org:{account_id}")
        }
        assert identity_id not in members, "Precondition: legacy identity has no org index entry"

        state = self._make_backoffice_state(registry)
        with patch(
            "yashigani.backoffice.routes.users.backoffice_state", state
        ):
            from yashigani.backoffice.routes.users import _suspend_identity_registry_for_account
            _suspend_identity_registry_for_account(
                account_id, username="dave", email="dave@example.com"
            )

        assert registry.get(identity_id)["status"] == "suspended", (
            "LAURA-DK-001: legacy identity (org_id='') must be suspended via slug fallback. "
            "Disabling a user must revoke their API key even for pre-fix registrations."
        )

    def test_dk001_3_slug_fallback_uses_synthetic_email_when_no_email(self):
        """DK001-3 variant: slug fallback works when email is None (synthetic @yashigani.local)."""
        r = _make_fake_redis()
        registry = _make_real_registry(r)
        account_id = "usr_no_email"

        # Legacy registration, no email — uses synthetic slug
        identity_id, _, _ = _register_human_legacy(
            registry, "eve", account_id, email=None
        )

        state = self._make_backoffice_state(registry)
        with patch(
            "yashigani.backoffice.routes.users.backoffice_state", state
        ):
            from yashigani.backoffice.routes.users import _suspend_identity_registry_for_account
            _suspend_identity_registry_for_account(
                account_id,
                username="eve",
                email=None,  # no email — fallback uses {username}@yashigani.local
            )

        assert registry.get(identity_id)["status"] == "suspended", (
            "LAURA-DK-001: slug fallback must work when email is None (synthetic slug path)"
        )


# ---------------------------------------------------------------------------
# DK001-4: account A disable does NOT touch account B identity
# ---------------------------------------------------------------------------

class TestScopeIsolation:
    """Disabling account A must not affect account B's identities."""

    def test_dk001_4_account_a_disable_does_not_touch_account_b(self):
        """DK001-4: suspend is scoped to the target account only."""
        r = _make_fake_redis()
        registry = _make_real_registry(r)

        account_a = "usr_aaa"
        account_b = "usr_bbb"

        # Register both accounts — post-fix (org_id set correctly)
        id_a, _, _ = _register_human(registry, "frank", account_a, email="frank@example.com")
        id_b, _, _ = _register_human(registry, "grace", account_b, email="grace@example.com")

        # Disable account A via the helper
        state = MagicMock()
        state.identity_registry = registry
        with patch("yashigani.backoffice.routes.users.backoffice_state", state):
            from yashigani.backoffice.routes.users import _suspend_identity_registry_for_account
            _suspend_identity_registry_for_account(
                account_a, username="frank", email="frank@example.com"
            )

        assert registry.get(id_a)["status"] == "suspended", "Account A identity must be suspended"
        assert registry.get(id_b)["status"] == "active", (
            "LAURA-DK-001 scope violation: account B identity must NOT be affected "
            "by account A disable"
        )

    def test_dk001_4_legacy_slug_fallback_does_not_touch_other_account(self):
        """DK001-4 legacy path: slug fallback is scoped to the target account slug only."""
        r = _make_fake_redis()
        registry = _make_real_registry(r)

        account_a = "usr_legacy_a"
        account_b = "usr_legacy_b"

        # Register both WITHOUT org_id (legacy)
        id_a, _, _ = _register_human_legacy(registry, "henry", account_a, email="henry@example.com")
        id_b, _, _ = _register_human_legacy(registry, "iris", account_b, email="iris@example.com")

        state = MagicMock()
        state.identity_registry = registry
        with patch("yashigani.backoffice.routes.users.backoffice_state", state):
            from yashigani.backoffice.routes.users import _suspend_identity_registry_for_account
            _suspend_identity_registry_for_account(
                account_a, username="henry", email="henry@example.com"
            )

        assert registry.get(id_a)["status"] == "suspended"
        assert registry.get(id_b)["status"] == "active", (
            "LAURA-DK-001 slug fallback scope: account B must not be touched"
        )


# ---------------------------------------------------------------------------
# DK001-5: reactivate restores the identity (round-trip)
# ---------------------------------------------------------------------------

class TestReactivateRoundTrip:
    """disable → identity suspended → reactivate_user → identity active."""

    def test_dk001_5_reactivate_restores_identity(self):
        """DK001-5: reactivate restores a suspended HUMAN identity to active."""
        r = _make_fake_redis()
        registry = _make_real_registry(r)
        account_id = "usr_roundtrip"

        identity_id, _, _ = _register_human(
            registry, "jake", account_id, email="jake@example.com"
        )

        # Step 1: suspend (as disable_user would)
        registry.suspend(identity_id)
        assert registry.get(identity_id)["status"] == "suspended"

        # Step 2: reactivate (as reactivate_user endpoint does)
        registry.reactivate(identity_id)
        assert registry.get(identity_id)["status"] == "active", (
            "LAURA-DK-001 round-trip: reactivate must restore identity to active"
        )

    def test_dk001_5_verify_key_rejected_while_suspended_accepted_after_reactivate(self):
        """
        DK001-5 end-to-end: after suspend, key verification must fail; after
        reactivate and status restored, the calling code can re-accept the key.

        Note: the gateway auth path checks identity status via get_by_api_key
        which iterates identity:index:active — suspended identities are removed
        from that set by registry.suspend().
        """
        r = _make_fake_redis()
        registry = _make_real_registry(r)
        account_id = "usr_keycheck"

        identity_id, plaintext_key, _ = _register_human(
            registry, "kim", account_id, email="kim@example.com"
        )

        # Verify key before suspend
        found_before = registry.get_by_api_key(plaintext_key)
        assert found_before is not None, "Key must be valid before suspend"
        assert found_before["status"] == "active"

        # Suspend
        registry.suspend(identity_id)

        # After suspend, identity is removed from identity:index:active.
        # get_by_api_key iterates that set — so it should NOT find the key.
        found_after_suspend = registry.get_by_api_key(plaintext_key)
        assert found_after_suspend is None, (
            "LAURA-DK-001: after account disable (identity suspended), "
            "get_by_api_key must return None — the gateway must reject the key."
        )

        # Reactivate
        registry.reactivate(identity_id)

        # Key must work again
        found_after_reactivate = registry.get_by_api_key(plaintext_key)
        assert found_after_reactivate is not None, (
            "LAURA-DK-001 round-trip: after reactivate, key must be accepted again"
        )
        assert found_after_reactivate["status"] == "active"


# ---------------------------------------------------------------------------
# DK001-6: empty org_id guard — no broad blast
# ---------------------------------------------------------------------------

class TestEmptyOrgIdGuard:
    """suspend_owned_by("") must be a no-op — must not suspend all identities."""

    def test_dk001_6_empty_string_org_id_is_noop(self):
        """DK001-6: suspend_owned_by("") returns 0, no identity touched."""
        r = _make_fake_redis()
        registry = _make_real_registry(r)

        # Register two identities with org_id="" (legacy style)
        id1, _, _ = _register_human_legacy(registry, "user1", "acct-1", email="u1@example.com")
        id2, _, _ = _register_human_legacy(registry, "user2", "acct-2", email="u2@example.com")

        count = registry.suspend_owned_by("")
        assert count == 0, "suspend_owned_by('') must be a no-op"
        assert registry.get(id1)["status"] == "active"
        assert registry.get(id2)["status"] == "active"


# ---------------------------------------------------------------------------
# DK001-7: slug fallback is NOT called when org-index path already found entries
# ---------------------------------------------------------------------------

class TestSlugFallbackNotCalledWhenOrgIndexWorks:
    """DK001-7: slug fallback fires only when suspend_owned_by returns 0."""

    def test_dk001_7_no_slug_lookup_when_org_index_succeeds(self):
        """When org-index path suspends >=1 identities, slug fallback must not be called."""
        r = _make_fake_redis()
        registry = _make_real_registry(r)
        account_id = "usr_orgidx"

        identity_id, _, _ = _register_human(
            registry, "lee", account_id, email="lee@example.com"
        )

        state = MagicMock()
        state.identity_registry = registry

        with patch("yashigani.backoffice.routes.users.backoffice_state", state):
            # Spy on get_by_slug to confirm it is NOT called
            with patch.object(registry, "get_by_slug", wraps=registry.get_by_slug) as mock_slug:
                from yashigani.backoffice.routes.users import _suspend_identity_registry_for_account
                _suspend_identity_registry_for_account(
                    account_id, username="lee", email="lee@example.com"
                )
                # org-index path (suspend_owned_by) returns 1 → slug path skipped
                mock_slug.assert_not_called()

        assert registry.get(identity_id)["status"] == "suspended"
