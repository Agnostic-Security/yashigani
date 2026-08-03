"""Tests for the unified identity registry."""
from __future__ import annotations

import time

import fakeredis
import pytest

from yashigani.identity import (
    IdentityRegistry,
    IdentityKind,
    generate_api_key,
    hash_api_key,
    verify_api_key,
)
from yashigani.identity.api_key import (
    is_expired,
    needs_rotation,
    expiry_from_now,
    DEFAULT_ROTATION_DAYS,
)


@pytest.fixture
def redis():
    return fakeredis.FakeRedis()


@pytest.fixture
def registry(redis):
    return IdentityRegistry(redis)


# ── API Key Tests ────────────────────────────────────────────────────────


class TestApiKey:
    def test_generate_key_length(self):
        key = generate_api_key()
        assert len(key) == 64  # 256-bit hex

    def test_generate_key_uniqueness(self):
        keys = {generate_api_key() for _ in range(100)}
        assert len(keys) == 100

    def test_hash_and_verify(self):
        key = generate_api_key()
        hashed = hash_api_key(key)
        assert verify_api_key(key, hashed)

    def test_wrong_key_rejected(self):
        key = generate_api_key()
        hashed = hash_api_key(key)
        assert not verify_api_key("wrong" * 16, hashed)

    def test_is_expired_none(self):
        assert not is_expired(None)

    def test_is_expired_future(self):
        assert not is_expired(expiry_from_now(30))

    def test_needs_rotation_none(self):
        assert needs_rotation(None)

    def test_needs_rotation_recent(self):
        import datetime
        recent = datetime.datetime.now(tz=datetime.timezone.utc)
        assert not needs_rotation(recent, DEFAULT_ROTATION_DAYS)


# ── Registry Tests ───────────────────────────────────────────────────────


class TestIdentityRegistry:
    def test_register_human(self, registry):
        identity_id, key = registry.register(
            kind=IdentityKind.HUMAN,
            name="Alice",
            slug="alice",
            description="Test user",
        )
        assert identity_id.startswith("idnt_")
        assert len(key) == 64

    def test_register_service(self, registry):
        identity_id, key = registry.register(
            kind=IdentityKind.SERVICE,
            name="Langflow",
            slug="langflow",
            description="Visual multi-agent workflow builder",
            upstream_url="http://langflow:7860",
            container_image="docker.io/langflowai/langflow:1.9.0",
            capabilities=["code_execution"],
        )
        identity = registry.get(identity_id)
        assert identity["kind"] == "service"
        assert identity["upstream_url"] == "http://langflow:7860"
        assert "code_execution" in identity["capabilities"]

    def test_slug_uniqueness(self, registry):
        registry.register(kind=IdentityKind.HUMAN, name="A", slug="alice")
        with pytest.raises(ValueError, match="already taken"):
            registry.register(kind=IdentityKind.HUMAN, name="B", slug="alice")

    def test_get_by_slug(self, registry):
        identity_id, _ = registry.register(
            kind=IdentityKind.HUMAN, name="Bob", slug="bob",
        )
        result = registry.get_by_slug("bob")
        assert result is not None
        assert result["identity_id"] == identity_id

    def test_get_by_slug_not_found(self, registry):
        assert registry.get_by_slug("nonexistent") is None

    def test_verify_key(self, registry):
        identity_id, key = registry.register(
            kind=IdentityKind.HUMAN, name="C", slug="charlie",
        )
        assert registry.verify_key(identity_id, key)
        assert not registry.verify_key(identity_id, "wrong" * 16)

    def test_get_by_api_key(self, registry):
        identity_id, key = registry.register(
            kind=IdentityKind.HUMAN, name="D", slug="delta",
        )
        result = registry.get_by_api_key(key)
        assert result is not None
        assert result["identity_id"] == identity_id

    def test_list_all(self, registry):
        registry.register(kind=IdentityKind.HUMAN, name="H1", slug="h1")
        registry.register(kind=IdentityKind.SERVICE, name="S1", slug="s1")
        all_ids = registry.list_all()
        assert len(all_ids) == 2

    def test_list_by_kind(self, registry):
        registry.register(kind=IdentityKind.HUMAN, name="H1", slug="h1")
        registry.register(kind=IdentityKind.HUMAN, name="H2", slug="h2")
        registry.register(kind=IdentityKind.SERVICE, name="S1", slug="s1")
        humans = registry.list_all(kind=IdentityKind.HUMAN)
        services = registry.list_all(kind=IdentityKind.SERVICE)
        assert len(humans) == 2
        assert len(services) == 1

    def test_count(self, registry):
        registry.register(kind=IdentityKind.HUMAN, name="H1", slug="h1")
        registry.register(kind=IdentityKind.SERVICE, name="S1", slug="s1")
        assert registry.count() == 2
        assert registry.count(kind=IdentityKind.HUMAN) == 1
        assert registry.count(kind=IdentityKind.SERVICE) == 1

    def test_update(self, registry):
        identity_id, _ = registry.register(
            kind=IdentityKind.HUMAN, name="Old", slug="upd",
        )
        registry.update(identity_id, name="New", description="Updated")
        result = registry.get(identity_id)
        assert result["name"] == "New"
        assert result["description"] == "Updated"

    def test_suspend_and_reactivate(self, registry):
        identity_id, _ = registry.register(
            kind=IdentityKind.HUMAN, name="S", slug="susp",
        )
        registry.suspend(identity_id)
        assert registry.count(status="active") == 0
        registry.reactivate(identity_id)
        assert registry.count(status="active") == 1

    def test_deactivate(self, registry):
        identity_id, key = registry.register(
            kind=IdentityKind.HUMAN, name="D", slug="deact",
        )
        registry.deactivate(identity_id)
        result = registry.get(identity_id)
        assert result["status"] == "deactivated"
        # Key should be deleted
        assert not registry.verify_key(identity_id, key)
        # Slug should be freed
        assert registry.get_by_slug("deact") is None

    def test_rotate_key(self, registry):
        identity_id, old_key = registry.register(
            kind=IdentityKind.HUMAN, name="R", slug="rot",
        )
        new_key = registry.rotate_key(identity_id, grace_seconds=60)
        assert new_key != old_key
        # New key works
        assert registry.verify_key(identity_id, new_key)
        # Old key works during grace period
        assert registry.verify_key(identity_id, old_key)

    def test_rotate_key_grace_seconds_zero_does_not_raise(self, registry):
        """
        SF-010 regression: rotate_key(grace_seconds=0) must NOT raise.

        Before the fix, registry.py:509 executed:
            pipe.set(f"identity:key:grace:{identity_id}", current, ex=0)
        Real Redis rejects EX 0 with:
            redis.exceptions.ResponseError: invalid expire time in 'set' command

        After the fix the grace-key SET is skipped entirely when grace_seconds=0,
        so no EX 0 is sent to Redis and rotate_key completes normally.

        This is the exact call path triggered by POST /me/api-key → me.py:239:
            registry.rotate_key(identity_id, grace_seconds=0)
        """
        identity_id, old_key = registry.register(
            kind=IdentityKind.HUMAN, name="G0", slug="grace-zero",
        )
        # Must not raise — pre-fix this would raise ResponseError via fakeredis
        new_key = registry.rotate_key(identity_id, grace_seconds=0)
        assert new_key != old_key
        # New key is valid
        assert registry.verify_key(identity_id, new_key)
        # Old key must NOT be valid — grace_seconds=0 means immediate invalidation
        assert not registry.verify_key(identity_id, old_key)
        # Grace key must not exist in Redis
        grace_key = f"identity:key:grace:{identity_id}"
        assert registry._r.get(grace_key) is None

    def test_last_seen_updated_on_verify(self, registry):
        identity_id, key = registry.register(
            kind=IdentityKind.HUMAN, name="LS", slug="lastseen",
        )
        result_before = registry.get(identity_id)
        assert result_before["last_seen_at"] == ""
        registry.verify_key(identity_id, key)
        result_after = registry.get(identity_id)
        assert result_after["last_seen_at"] != ""

    def test_sensitivity_ceiling(self, registry):
        identity_id, _ = registry.register(
            kind=IdentityKind.SERVICE,
            name="Sec",
            slug="sec",
            sensitivity_ceiling="CONFIDENTIAL",
        )
        result = registry.get(identity_id)
        assert result["sensitivity_ceiling"] == "CONFIDENTIAL"

    def test_allowed_models(self, registry):
        identity_id, _ = registry.register(
            kind=IdentityKind.HUMAN,
            name="Models",
            slug="models",
            allowed_models=["qwen2.5:3b", "claude-opus-4-6"],
        )
        result = registry.get(identity_id)
        assert "qwen2.5:3b" in result["allowed_models"]
        assert "claude-opus-4-6" in result["allowed_models"]


# ─────────────────────────────────────────────────────────────────────────────
# FIND-SEAT-LEAK (HIGH) regression — end-user seat is never reclaimed
#
# Root cause: the HUMAN registration Lua script (_REGISTER_HUMAN_LUA) enforces
# max_end_users by SCARD-ing identity:index:kind:human, and SADDs every new
# HUMAN identity_id to that set. No lifecycle op (suspend/reactivate/
# deactivate) ever SREM'd from identity:index:kind:*, so a deactivated
# identity permanently held its seat — Community (max_end_users=5) would
# permanently exhaust all 5 seats after 5 cumulative registrations regardless
# of how many were still active. Fixed by deactivate() SREM-ing the identity
# from identity:index:kind:{kind}; suspend() intentionally does NOT (a
# suspended user still holds their seat until admin reactivate or deactivate).
# ─────────────────────────────────────────────────────────────────────────────

class TestSeatLeakRegression:
    @pytest.fixture(autouse=True)
    def _license_seats(self):
        """Cap max_end_users at 2 for these tests; restore original after."""
        from yashigani.licensing.enforcer import get_license, set_license
        from yashigani.licensing.model import LicenseState, LicenseTier
        import datetime as _dt
        import uuid as _uuid

        original = get_license()
        capped = LicenseState(
            tier=LicenseTier.PROFESSIONAL,
            org_domain="example.com",
            max_agents=500,
            max_end_users=2,
            max_admin_seats=50,
            max_orgs=1,
            features=frozenset(),
            issued_at=_dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc),
            expires_at=_dt.datetime(2027, 1, 1, tzinfo=_dt.timezone.utc),
            license_id=str(_uuid.uuid4()),
            valid=True,
            error=None,
        )
        set_license(capped)
        yield
        set_license(original)

    def test_seat_limit_enforced_at_registration(self, registry):
        """Fills the 2-seat license; the 3rd HUMAN registration must raise."""
        from yashigani.licensing.enforcer import LicenseLimitExceeded

        registry.register(kind=IdentityKind.HUMAN, name="U1", slug="seat-u1")
        registry.register(kind=IdentityKind.HUMAN, name="U2", slug="seat-u2")
        with pytest.raises(LicenseLimitExceeded) as exc_info:
            registry.register(kind=IdentityKind.HUMAN, name="U3", slug="seat-u3")
        assert exc_info.value.limit_name == "max_end_users"
        assert exc_info.value.current == 2
        assert exc_info.value.max_val == 2

    def test_deactivate_frees_seat_for_new_registration(self, registry, redis):
        """FIND-SEAT-LEAK: deactivating one identity must free its seat so a
        fresh HUMAN registration succeeds without raising, and the kind-set
        SCARD must drop by exactly one."""
        id1, _ = registry.register(kind=IdentityKind.HUMAN, name="U1", slug="seat-u1")
        id2, _ = registry.register(kind=IdentityKind.HUMAN, name="U2", slug="seat-u2")
        assert redis.scard("identity:index:kind:human") == 2

        registry.deactivate(id1)
        assert redis.scard("identity:index:kind:human") == 1

        # Pre-fix, this raised LicenseLimitExceeded even though only 1 of 2
        # seats was actually occupied — the deactivated identity never left
        # the kind set.
        id3, _ = registry.register(kind=IdentityKind.HUMAN, name="U3", slug="seat-u3")
        assert redis.scard("identity:index:kind:human") == 2
        assert registry.get(id3) is not None
        # The deactivated identity is gone from the kind set, not just "active".
        assert not redis.sismember("identity:index:kind:human", id1)
        assert redis.sismember("identity:index:kind:human", id2)
        assert redis.sismember("identity:index:kind:human", id3)

    def test_suspend_does_not_free_seat(self, registry, redis):
        """suspend() is a HOLD: a suspended identity must still count against
        the seat limit — only deactivate() releases it."""
        from yashigani.licensing.enforcer import LicenseLimitExceeded

        id1, _ = registry.register(kind=IdentityKind.HUMAN, name="U1", slug="seat-u1")
        registry.register(kind=IdentityKind.HUMAN, name="U2", slug="seat-u2")
        assert redis.scard("identity:index:kind:human") == 2

        registry.suspend(id1)
        # Still 2 members of the kind set — suspend does not release the seat.
        assert redis.scard("identity:index:kind:human") == 2
        assert redis.sismember("identity:index:kind:human", id1)

        # A 3rd registration must still be rejected while suspended.
        with pytest.raises(LicenseLimitExceeded):
            registry.register(kind=IdentityKind.HUMAN, name="U3", slug="seat-u3")

        # Reactivating keeps the seat consistent: still 2 members, id1 active again.
        registry.reactivate(id1)
        assert redis.scard("identity:index:kind:human") == 2
        assert registry.count(status="active") == 2
