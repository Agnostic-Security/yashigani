"""Tests for the Pool Manager."""
from __future__ import annotations

import time

import pytest

from yashigani.pool.manager import (
    PoolManager,
    ContainerInfo,
    TierLimits,
    PoolLimitExceeded,
)


@pytest.fixture
def pool():
    """Pool with no Docker client (stub mode)."""
    return PoolManager(docker_client=None, tier="community", idle_timeout_seconds=60)


@pytest.fixture
def enterprise_pool():
    return PoolManager(docker_client=None, tier="enterprise", idle_timeout_seconds=60)


class TestTierLimits:
    def test_community_limits(self):
        limits = TierLimits.from_tier("community")
        assert limits.per_service_per_identity == 1
        assert limits.total_concurrent == 3

    def test_professional_plus_limits(self):
        limits = TierLimits.from_tier("professional_plus")
        assert limits.per_service_per_identity == 5
        assert limits.total_concurrent == 50

    def test_enterprise_limits(self):
        limits = TierLimits.from_tier("enterprise")
        assert limits.total_concurrent == 9999

    def test_academic_nonprofit_is_unlimited_not_community(self):
        """TB-07 (Lu, 4.1.2): this test previously called
        TierLimits.from_tier("academic") and asserted COMMUNITY-equivalent
        limits -- that was itself an instance of the stale-key defect it
        should have caught. LicenseTier.ACADEMIC_NONPROFIT.value is
        "academic_nonprofit"; "academic" is not a real tier string. Pre-fix,
        this passed because _TIER_LIMITS carried a literal "academic" key
        mapping to community limits (coincidence, not coverage). Post-fix,
        "academic" is an unrecognised key hitting the fail-closed default
        (which also equals community) -- the assertion kept passing for a
        reason unrelated to its name, while asserting a product claim the
        TB-07 fix made false: academic_nonprofit is Unlimited (999/9999
        sentinel, matching enterprise) per README.md Sec.8, not
        community-equivalent (1/3). Re-aimed at the real tier string and
        the real (unlimited) entitlement -- see
        test_tom_tb07_license_tier_key_enum_divergence.py for the full
        root-cause writeup and
        TestPoolManagerTierLimitsTB07.test_from_tier_resolves_academic_nonprofit_correctly
        for the equivalent assertion in the new regression suite."""
        academic_nonprofit = TierLimits.from_tier("academic_nonprofit")
        enterprise = TierLimits.from_tier("enterprise")
        community = TierLimits.from_tier("community")
        assert academic_nonprofit.per_service_per_identity == enterprise.per_service_per_identity
        assert academic_nonprofit.total_concurrent == enterprise.total_concurrent
        assert academic_nonprofit.per_service_per_identity != community.per_service_per_identity
        assert academic_nonprofit.total_concurrent != community.total_concurrent

    def test_unknown_tier_defaults(self):
        limits = TierLimits.from_tier("nonexistent")
        assert limits.per_service_per_identity == 1


class TestPoolManager:
    def test_create_container(self, pool):
        info = pool.get_or_create("user1", "goose", "ghcr.io/block/goose:latest")
        assert info.identity_id == "user1"
        assert info.service_slug == "goose"
        assert info.status == "starting"
        assert "goose" in info.container_name

    def test_get_existing_returns_same(self, pool):
        info1 = pool.get_or_create("user1", "goose", "image")
        info2 = pool.get_or_create("user1", "goose", "image")
        assert info1.container_id == info2.container_id

    def test_different_identities_get_different_containers(self, pool):
        info1 = pool.get_or_create("user1", "goose", "image")
        info2 = pool.get_or_create("user2", "goose", "image")
        assert info1.container_id != info2.container_id

    def test_different_services_get_different_containers(self, pool):
        info1 = pool.get_or_create("user1", "goose", "image1")
        info2 = pool.get_or_create("user1", "langgraph", "image2")
        assert info1.container_id != info2.container_id

    def test_community_tier_limit(self, pool):
        pool.get_or_create("user1", "goose", "img")
        pool.get_or_create("user1", "langgraph", "img")
        pool.get_or_create("user1", "openclaw", "img")
        with pytest.raises(PoolLimitExceeded):
            pool.get_or_create("user1", "custom-agent", "img")

    def test_enterprise_no_limit(self, enterprise_pool):
        for i in range(20):
            enterprise_pool.get_or_create("user1", f"agent-{i}", "img")
        assert enterprise_pool.count("user1") == 20

    def test_get_returns_none_when_not_running(self, pool):
        assert pool.get("user1", "goose") is None

    def test_list_for_identity(self, pool):
        pool.get_or_create("user1", "goose", "img")
        pool.get_or_create("user1", "langgraph", "img")
        pool.get_or_create("user2", "goose", "img")
        assert len(pool.list_for_identity("user1")) == 2
        assert len(pool.list_for_identity("user2")) == 1

    def test_list_all(self, pool):
        pool.get_or_create("user1", "goose", "img")
        pool.get_or_create("user2", "goose", "img")
        assert len(pool.list_all()) == 2

    def test_mark_healthy(self, pool):
        pool.get_or_create("user1", "goose", "img")
        pool.mark_healthy("user1", "goose")
        info = pool.get("user1", "goose")
        assert info.status == "healthy"

    def test_mark_unhealthy_threshold(self, pool):
        pool.get_or_create("user1", "goose", "img")
        pool.mark_unhealthy("user1", "goose")
        pool.mark_unhealthy("user1", "goose")
        assert pool.get("user1", "goose").status == "starting"  # Not yet unhealthy
        pool.mark_unhealthy("user1", "goose")  # 3rd failure
        assert pool.get("user1", "goose").status == "unhealthy"

    def test_teardown(self, pool):
        pool.get_or_create("user1", "goose", "img")
        assert pool.count() == 1
        pool.teardown("user1", "goose", "test")
        assert pool.count() == 0

    def test_teardown_all_for_identity(self, pool):
        pool.get_or_create("user1", "goose", "img")
        pool.get_or_create("user1", "langgraph", "img")
        pool.get_or_create("user2", "goose", "img")
        count = pool.teardown_all_for_identity("user1", "deactivated")
        assert count == 2
        assert pool.count() == 1  # user2's container remains

    def test_cleanup_idle(self, pool):
        info = pool.get_or_create("user1", "goose", "img")
        # Fake the last_active to be old
        info.last_active = time.time() - 120  # 2 minutes ago, timeout is 60s
        cleaned = pool.cleanup_idle()
        assert cleaned == 1
        assert pool.count() == 0

    def test_cleanup_idle_spares_active(self, pool):
        pool.get_or_create("user1", "goose", "img")
        # Last active is now, so should not be cleaned
        cleaned = pool.cleanup_idle()
        assert cleaned == 0

    def test_count(self, pool):
        assert pool.count() == 0
        pool.get_or_create("u1", "goose", "img")
        assert pool.count() == 1
        assert pool.count("u1") == 1
        assert pool.count("u2") == 0

    def test_last_active_updated_on_get(self, pool):
        info = pool.get_or_create("user1", "goose", "img")
        first_active = info.last_active
        time.sleep(0.01)
        info2 = pool.get_or_create("user1", "goose", "img")
        assert info2.last_active >= first_active

    def test_replace_in_stub_mode(self, pool):
        pool.get_or_create("user1", "goose", "img")
        old_id = pool.get("user1", "goose").container_id
        new_info = pool.replace("user1", "goose", "unhealthy")
        assert new_info is not None
        assert new_info.container_id != old_id
