"""
Regression tests — 3.1 Phase 2: Unified Permission Store + Resolver.

Covers all required semantics (Tiago-decided, firm):

  A. Model — ResourceType, SubjectKind, BooleanGrantValue, INV-2 validation

  B. Store round-trips — get/set/delete for boolean grants (all blast-radius
     resource_types) and browser_capability grants (via adapter and directly)

  C. Resolver — org-ceiling semantics for boolean resource_types:
       C1. DENY BY DEFAULT — no org grant → denied
       C2. Org-deny caps everyone — org allow=False → denied regardless of group/user
       C3. Group can only narrow — group deny with org allow → denied
       C4. User can only narrow — user deny with org allow → denied
       C5. Lower-level allow with no org grant has NO effect
       C6. Unauthenticated skips group/user tiers
       C7. cloud_model allow=True requires opa_policy_ref (INV-2)

  D. Resolver — org-ceiling for browser_capability (tri-state most-restrictive-wins):
       D1. Org caps user widen attempt (user "allow_list" ≤ org "self" → "self")
       D2. Org caps group widen attempt
       D3. User can narrow below org
       D4. Group can narrow below org
       D5. Most-restrictive of all three levels wins
       D6. Unauthenticated gets org policy (no group/user tiers)
       D7. Baseline fallback when no org key exists

  E. Audit schema — PermissionGrantChangedEvent round-trip

  F. Adapter — CapabilityPolicyStore delegates to PermissionStore correctly

Last updated: 2026-06-28T00:00:00+00:00
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _perm_store(default_org_id="default"):
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")
    from yashigani.permissions.store import PermissionStore
    redis = fakeredis.FakeRedis(decode_responses=False)
    return PermissionStore(redis, default_org_id=default_org_id)


def _cap_store(default_org_id="default"):
    """CapabilityPolicyStore (adapter over PermissionStore)."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")
    from yashigani.capability_policy.store import CapabilityPolicyStore
    redis = fakeredis.FakeRedis(decode_responses=False)
    return CapabilityPolicyStore(redis, default_org_id=default_org_id)


def _rbac(user_groups: dict):
    """Build a minimal mock RBACStore."""
    rbac = MagicMock()

    class _FakeGroup:
        def __init__(self, gid):
            self.id = gid

    rbac.get_user_groups = MagicMock(
        side_effect=lambda email: [_FakeGroup(gid) for gid in user_groups.get(email, [])]
    )
    return rbac


# ============================================================================
# A. Model
# ============================================================================

class TestModel:

    def test_resource_type_values(self):
        from yashigani.permissions.model import ResourceType, BLAST_RADIUS_TYPES
        assert ResourceType.MCP_SERVER in BLAST_RADIUS_TYPES
        assert ResourceType.EXTERNAL_API in BLAST_RADIUS_TYPES
        assert ResourceType.CLOUD_MODEL in BLAST_RADIUS_TYPES
        assert ResourceType.AGENT in BLAST_RADIUS_TYPES
        assert ResourceType.BROWSER_CAPABILITY not in BLAST_RADIUS_TYPES

    def test_subject_parse_org(self):
        from yashigani.permissions.model import Subject, SubjectKind
        s = Subject.parse("org:my-org")
        assert s.kind == SubjectKind.ORG
        assert s.id == "my-org"
        assert str(s) == "org:my-org"

    def test_subject_parse_user(self):
        from yashigani.permissions.model import Subject, SubjectKind
        s = Subject.parse("user:alice@example.com")
        assert s.kind == SubjectKind.USER
        assert s.id == "alice@example.com"

    def test_subject_parse_gateway_orchestrator(self):
        from yashigani.permissions.model import Subject, SubjectKind
        s = Subject.parse("gateway:orchestrator")
        assert s.kind == SubjectKind.GATEWAY
        assert s.id == "orchestrator"

    def test_subject_parse_invalid_kind(self):
        from yashigani.permissions.model import Subject
        with pytest.raises(ValueError, match="Unknown subject kind"):
            Subject.parse("superadmin:x")

    def test_subject_parse_missing_colon(self):
        from yashigani.permissions.model import Subject
        with pytest.raises(ValueError, match="Invalid subject"):
            Subject.parse("justplaintext")

    def test_subject_factory_methods(self):
        from yashigani.permissions.model import Subject, SubjectKind
        assert Subject.org("acme").kind == SubjectKind.ORG
        assert Subject.group("g1").kind == SubjectKind.GROUP
        assert Subject.user("u@example.com").kind == SubjectKind.USER
        assert Subject.agent("a1").kind == SubjectKind.AGENT
        assert Subject.gateway_orchestrator().kind == SubjectKind.GATEWAY

    def test_boolean_grant_value_serialise(self):
        from yashigani.permissions.model import BooleanGrantValue
        v = BooleanGrantValue(allow=True, opa_policy_ref="yashigani/cloud/gpt4o")
        d = v.to_dict()
        assert d == {"allow": True, "opa_policy_ref": "yashigani/cloud/gpt4o"}
        v2 = BooleanGrantValue.from_dict(d)
        assert v2.allow is True
        assert v2.opa_policy_ref == "yashigani/cloud/gpt4o"

    def test_inv2_cloud_model_allow_requires_opa_policy_ref(self):
        """INV-2: cloud_model allow=True MUST carry opa_policy_ref."""
        from yashigani.permissions.model import (
            ResourceType, BooleanGrantValue, validate_boolean_grant, GrantValidationError
        )
        value = BooleanGrantValue(allow=True, opa_policy_ref=None)
        with pytest.raises(GrantValidationError, match="INV-2"):
            validate_boolean_grant(ResourceType.CLOUD_MODEL, value)

    def test_inv2_cloud_model_allow_empty_string_rejected(self):
        """INV-2: empty string opa_policy_ref is also rejected."""
        from yashigani.permissions.model import (
            ResourceType, BooleanGrantValue, validate_boolean_grant, GrantValidationError
        )
        value = BooleanGrantValue(allow=True, opa_policy_ref="   ")
        with pytest.raises(GrantValidationError, match="INV-2"):
            validate_boolean_grant(ResourceType.CLOUD_MODEL, value)

    def test_inv2_cloud_model_deny_no_ref_ok(self):
        """INV-2: cloud_model allow=False does NOT require opa_policy_ref."""
        from yashigani.permissions.model import (
            ResourceType, BooleanGrantValue, validate_boolean_grant
        )
        # Should not raise
        validate_boolean_grant(ResourceType.CLOUD_MODEL, BooleanGrantValue(allow=False))

    def test_inv2_other_blast_radius_no_ref_ok(self):
        """Non-cloud_model blast-radius types do NOT require opa_policy_ref."""
        from yashigani.permissions.model import (
            ResourceType, BooleanGrantValue, validate_boolean_grant
        )
        for rt in (ResourceType.MCP_SERVER, ResourceType.EXTERNAL_API, ResourceType.AGENT):
            validate_boolean_grant(rt, BooleanGrantValue(allow=True))  # must not raise

    def test_validate_boolean_grant_rejects_browser_capability(self):
        """validate_boolean_grant rejects non-blast-radius resource types."""
        from yashigani.permissions.model import (
            ResourceType, BooleanGrantValue, validate_boolean_grant, GrantValidationError
        )
        with pytest.raises(GrantValidationError, match="does not use boolean grants"):
            validate_boolean_grant(
                ResourceType.BROWSER_CAPABILITY, BooleanGrantValue(allow=True)
            )


# ============================================================================
# B. Store round-trips
# ============================================================================

class TestStoreRoundTrips:

    def test_boolean_grant_set_get(self):
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        store.set_boolean_grant(
            ResourceType.MCP_SERVER, "org", "acme", "github-mcp",
            BooleanGrantValue(allow=True),
        )
        result = store.get_boolean_grant(ResourceType.MCP_SERVER, "org", "acme", "github-mcp")
        assert result is not None
        assert result.allow is True

    def test_boolean_grant_absent_returns_none(self):
        from yashigani.permissions.model import ResourceType
        store = _perm_store()
        result = store.get_boolean_grant(ResourceType.MCP_SERVER, "org", "acme", "no-such-mcp")
        assert result is None

    def test_boolean_grant_delete(self):
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        store.set_boolean_grant(
            ResourceType.EXTERNAL_API, "org", "acme", "stripe",
            BooleanGrantValue(allow=True),
        )
        deleted = store.delete_boolean_grant(ResourceType.EXTERNAL_API, "org", "acme", "stripe")
        assert deleted is True
        assert store.get_boolean_grant(ResourceType.EXTERNAL_API, "org", "acme", "stripe") is None

    def test_boolean_grant_delete_nonexistent_returns_false(self):
        from yashigani.permissions.model import ResourceType
        store = _perm_store()
        assert store.delete_boolean_grant(
            ResourceType.AGENT, "org", "acme", "no-agent"
        ) is False

    def test_inv2_enforced_at_store_write_time(self):
        """Store.set_boolean_grant raises GrantValidationError for INV-2 violation."""
        from yashigani.permissions.model import ResourceType, BooleanGrantValue, GrantValidationError
        store = _perm_store()
        with pytest.raises(GrantValidationError, match="INV-2"):
            store.set_boolean_grant(
                ResourceType.CLOUD_MODEL, "org", "acme", "gpt-4o",
                BooleanGrantValue(allow=True, opa_policy_ref=None),
            )

    def test_cloud_model_grant_with_ref_stored(self):
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        store.set_boolean_grant(
            ResourceType.CLOUD_MODEL, "org", "acme", "gpt-4o",
            BooleanGrantValue(allow=True, opa_policy_ref="yashigani/cloud/gpt4o"),
        )
        result = store.get_boolean_grant(ResourceType.CLOUD_MODEL, "org", "acme", "gpt-4o")
        assert result is not None
        assert result.allow is True
        assert result.opa_policy_ref == "yashigani/cloud/gpt4o"

    def test_list_boolean_grants(self):
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        store.set_boolean_grant(ResourceType.MCP_SERVER, "org", "acme", "s1", BooleanGrantValue(allow=True))
        store.set_boolean_grant(ResourceType.MCP_SERVER, "org", "acme", "s2", BooleanGrantValue(allow=False))
        grants = store.list_boolean_grants(ResourceType.MCP_SERVER, "org", "acme")
        ids = {rid for rid, _ in grants}
        assert "s1" in ids
        assert "s2" in ids
        allows = {rid: v.allow for rid, v in grants}
        assert allows["s1"] is True
        assert allows["s2"] is False

    def test_browser_cap_seeded_on_init(self):
        from yashigani.capability_policy.model import CAPABILITY_NAMES
        store = _cap_store()
        policy = store.get_org("default")
        assert set(policy.keys()) == CAPABILITY_NAMES
        assert all(s.value == "self" for s in policy.values())

    def test_browser_cap_org_set_get(self):
        from yashigani.capability_policy.model import CapabilitySetting, default_policy
        store = _cap_store()
        p = default_policy()
        p["camera"] = CapabilitySetting("off")
        store.set_org("default", p)
        result = store.get_org("default")
        assert result["camera"].value == "off"
        assert result["microphone"].value == "self"

    def test_browser_cap_group_set_get_delete(self):
        from yashigani.capability_policy.model import CapabilitySetting
        store = _cap_store()
        store.set_group("grp-a", {"microphone": CapabilitySetting("off")})
        result = store.get_group("grp-a")
        assert result["microphone"].value == "off"
        assert "camera" not in result
        assert store.delete_group("grp-a") is True
        assert store.get_group("grp-a") == {}

    def test_browser_cap_user_set_get_delete(self):
        from yashigani.capability_policy.model import CapabilitySetting
        store = _cap_store()
        store.set_user("alice@example.com", {"geolocation": CapabilitySetting("off")})
        result = store.get_user("alice@example.com")
        assert result["geolocation"].value == "off"
        assert store.delete_user("alice@example.com") is True
        assert store.get_user("alice@example.com") == {}


# ============================================================================
# C. Resolver — boolean (blast-radius) org-ceiling semantics
# ============================================================================

class TestBooleanResolver:

    def _resolve(self, resource_type, resource_id, *, org_id, group_ids, user_email, store):
        from yashigani.permissions.resolver import resolve_boolean_grant
        return resolve_boolean_grant(
            resource_type, resource_id,
            org_id=org_id, group_ids=group_ids,
            principal_scope="user" if user_email else None,
            principal_id=user_email if user_email else None,
            store=store,
        )

    # C1 — DENY BY DEFAULT

    def test_no_org_grant_denied(self):
        """C1: No org grant → DENIED regardless of resource_type."""
        from yashigani.permissions.model import ResourceType
        store = _perm_store()
        for rt in (ResourceType.MCP_SERVER, ResourceType.EXTERNAL_API,
                   ResourceType.CLOUD_MODEL, ResourceType.AGENT):
            result = self._resolve(
                rt, "some-resource",
                org_id="acme", group_ids=[], user_email="user@example.com",
                store=store,
            )
            assert result is False, f"Expected DENIED for {rt} with no org grant"

    def test_org_allow_no_group_user_grants_allowed(self):
        """C1: Org allows, no group/user grants → ALLOWED."""
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        store.set_boolean_grant(
            ResourceType.MCP_SERVER, "org", "acme", "github-mcp",
            BooleanGrantValue(allow=True),
        )
        result = self._resolve(
            ResourceType.MCP_SERVER, "github-mcp",
            org_id="acme", group_ids=[], user_email="user@example.com",
            store=store,
        )
        assert result is True

    # C2 — Org-deny caps everyone

    def test_org_deny_caps_group_allow(self):
        """C2: Org denies → DENIED even if group has no deny (org is ceiling)."""
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        # Org: no grant (deny by default)
        # Group: allow=True (but this has NO effect without org grant)
        store.set_boolean_grant(
            ResourceType.MCP_SERVER, "group", "admins", "github-mcp",
            BooleanGrantValue(allow=True),
        )
        result = self._resolve(
            ResourceType.MCP_SERVER, "github-mcp",
            org_id="acme", group_ids=["admins"], user_email="user@example.com",
            store=store,
        )
        assert result is False  # No org grant → group allow has NO effect

    def test_org_explicit_deny_caps_user(self):
        """C2: Org allow=False → DENIED even if user has no deny."""
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        store.set_boolean_grant(
            ResourceType.EXTERNAL_API, "org", "acme", "stripe",
            BooleanGrantValue(allow=False),
        )
        store.set_boolean_grant(
            ResourceType.EXTERNAL_API, "user", "alice@example.com", "stripe",
            BooleanGrantValue(allow=True),  # user "allow" cannot override org "deny"
        )
        result = self._resolve(
            ResourceType.EXTERNAL_API, "stripe",
            org_id="acme", group_ids=[], user_email="alice@example.com",
            store=store,
        )
        assert result is False  # Org deny is the ceiling

    # C3 — Group can only narrow

    def test_group_deny_narrows_below_org_allow(self):
        """C3: Org allows but group denies → DENIED (group narrows within org ceiling)."""
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        store.set_boolean_grant(
            ResourceType.AGENT, "org", "acme", "letta-agent",
            BooleanGrantValue(allow=True),
        )
        store.set_boolean_grant(
            ResourceType.AGENT, "group", "restricted", "letta-agent",
            BooleanGrantValue(allow=False),
        )
        result = self._resolve(
            ResourceType.AGENT, "letta-agent",
            org_id="acme", group_ids=["restricted"], user_email="u@example.com",
            store=store,
        )
        assert result is False  # Group deny narrows

    def test_group_allow_with_org_allow_allowed(self):
        """C3: Org allows and group also allows (no narrowing) → ALLOWED."""
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        store.set_boolean_grant(
            ResourceType.AGENT, "org", "acme", "letta-agent",
            BooleanGrantValue(allow=True),
        )
        store.set_boolean_grant(
            ResourceType.AGENT, "group", "g1", "letta-agent",
            BooleanGrantValue(allow=True),
        )
        result = self._resolve(
            ResourceType.AGENT, "letta-agent",
            org_id="acme", group_ids=["g1"], user_email="u@example.com",
            store=store,
        )
        assert result is True

    def test_any_group_deny_blocks_even_if_other_group_allows(self):
        """C3: Multiple groups; one deny is enough to block."""
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        store.set_boolean_grant(
            ResourceType.MCP_SERVER, "org", "acme", "s1",
            BooleanGrantValue(allow=True),
        )
        store.set_boolean_grant(
            ResourceType.MCP_SERVER, "group", "liberal", "s1",
            BooleanGrantValue(allow=True),
        )
        store.set_boolean_grant(
            ResourceType.MCP_SERVER, "group", "strict", "s1",
            BooleanGrantValue(allow=False),
        )
        result = self._resolve(
            ResourceType.MCP_SERVER, "s1",
            org_id="acme", group_ids=["liberal", "strict"], user_email="u@example.com",
            store=store,
        )
        assert result is False  # "strict" group deny blocks

    # C4 — User can only narrow

    def test_user_deny_narrows_below_org_allow(self):
        """C4: Org allows, no group deny, but user denies → DENIED."""
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        store.set_boolean_grant(
            ResourceType.EXTERNAL_API, "org", "acme", "openai",
            BooleanGrantValue(allow=True),
        )
        store.set_boolean_grant(
            ResourceType.EXTERNAL_API, "user", "alice@example.com", "openai",
            BooleanGrantValue(allow=False),
        )
        result = self._resolve(
            ResourceType.EXTERNAL_API, "openai",
            org_id="acme", group_ids=[], user_email="alice@example.com",
            store=store,
        )
        assert result is False  # User deny narrows

    # C5 — Lower-level allow with no org grant has NO effect

    def test_user_allow_with_no_org_grant_denied(self):
        """C5: User allow=True is irrelevant when no org grant exists."""
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        store.set_boolean_grant(
            ResourceType.MCP_SERVER, "user", "alice@example.com", "github-mcp",
            BooleanGrantValue(allow=True),
        )
        result = self._resolve(
            ResourceType.MCP_SERVER, "github-mcp",
            org_id="acme", group_ids=[], user_email="alice@example.com",
            store=store,
        )
        assert result is False  # Lower-level allow has NO effect without org grant

    # C6 — Unauthenticated skips group/user tiers

    def test_unauthenticated_gets_org_decision(self):
        """C6: email=None → org-only decision (groups/user skipped)."""
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        store.set_boolean_grant(
            ResourceType.MCP_SERVER, "org", "acme", "github-mcp",
            BooleanGrantValue(allow=True),
        )
        result = self._resolve(
            ResourceType.MCP_SERVER, "github-mcp",
            org_id="acme", group_ids=["restricted"], user_email=None,
            store=store,
        )
        assert result is True  # Org allows; no user/group tiers checked for unauthed

    def test_unauthenticated_no_org_grant_denied(self):
        """C6: Unauthenticated and no org grant → DENIED."""
        from yashigani.permissions.model import ResourceType
        store = _perm_store()
        result = self._resolve(
            ResourceType.EXTERNAL_API, "stripe",
            org_id="acme", group_ids=[], user_email="",
            store=store,
        )
        assert result is False

    # C7 — cloud_model INV-2 enforced at store write time (see TestModel + TestStoreRoundTrips)

    def test_cloud_model_with_policy_ref_resolves(self):
        """C7: cloud_model grant with opa_policy_ref resolves correctly."""
        from yashigani.permissions.model import ResourceType, BooleanGrantValue
        store = _perm_store()
        store.set_boolean_grant(
            ResourceType.CLOUD_MODEL, "org", "acme", "gpt-4o",
            BooleanGrantValue(allow=True, opa_policy_ref="yashigani/cloud/gpt4o"),
        )
        result = self._resolve(
            ResourceType.CLOUD_MODEL, "gpt-4o",
            org_id="acme", group_ids=[], user_email="user@example.com",
            store=store,
        )
        assert result is True


# ============================================================================
# D. Resolver — browser_capability org-ceiling (most-restrictive-wins)
# ============================================================================

class TestBrowserCapabilityResolver:

    def _resolve_set(self, *, org_id, group_ids, user_email, store):
        from yashigani.permissions.resolver import resolve_browser_capability_set
        perm_store = getattr(store, "perm_store", store)
        return resolve_browser_capability_set(
            org_id=org_id,
            group_ids=group_ids,
            principal_scope="user" if user_email else None,
            principal_id=user_email if user_email else None,
            store=perm_store,
        )

    # D1 — Org caps user widen attempt

    def test_d1_org_caps_user_widen_attempt(self):
        """
        D1: Org="self" is the ceiling; user "allow_list" is capped to "self".
        This is the KEY invariant change from Phase 1 to Phase 2.
        """
        from yashigani.capability_policy.model import CapabilitySetting
        store = _cap_store()
        # Org has baseline "self" for camera (no override needed — seeded as self)
        store.set_user("alice@example.com", {"camera": CapabilitySetting("allow_list", ["https://cam.example.com"])})
        result = self._resolve_set(
            org_id="default", group_ids=[], user_email="alice@example.com", store=store
        )
        # Org "self" (1) < allow_list (2) → most-restrictive = "self"
        assert result["camera"].value == "self", (
            "Org ceiling: user 'allow_list' must be capped at org 'self'"
        )

    def test_d1_org_off_caps_user_self(self):
        """D1: Org="off" caps user "self"."""
        from yashigani.capability_policy.model import CapabilitySetting, default_policy
        store = _cap_store()
        p = default_policy()
        p["camera"] = CapabilitySetting("off")
        store.set_org("default", p)
        store.set_user("alice@example.com", {"camera": CapabilitySetting("self")})
        result = self._resolve_set(
            org_id="default", group_ids=[], user_email="alice@example.com", store=store
        )
        assert result["camera"].value == "off"  # Org "off" caps user "self"

    # D2 — Org caps group widen attempt

    def test_d2_org_caps_group_widen_attempt(self):
        """D2: Group "allow_list" cannot exceed org "self"."""
        from yashigani.capability_policy.model import CapabilitySetting
        store = _cap_store()
        # Org: camera=self (seeded baseline)
        store.set_group("g1", {"camera": CapabilitySetting("allow_list", ["https://g.example.com"])})
        result = self._resolve_set(
            org_id="default", group_ids=["g1"], user_email="user@example.com", store=store
        )
        assert result["camera"].value == "self"  # Org "self" caps group "allow_list"

    # D3 — User can narrow below org

    def test_d3_user_narrows_below_org(self):
        """D3: User "off" narrows below org "self" — narrowing IS allowed."""
        from yashigani.capability_policy.model import CapabilitySetting
        store = _cap_store()
        # Org: camera=self (baseline)
        store.set_user("alice@example.com", {"camera": CapabilitySetting("off")})
        result = self._resolve_set(
            org_id="default", group_ids=[], user_email="alice@example.com", store=store
        )
        assert result["camera"].value == "off"  # User narrows: "off" < org "self"

    def test_d3_user_self_with_org_allow_list(self):
        """D3: Org="allow_list", user="self" → user narrows to "self"."""
        from yashigani.capability_policy.model import CapabilitySetting, default_policy
        store = _cap_store()
        p = default_policy()
        p["camera"] = CapabilitySetting("allow_list", ["https://cam.example.com"])
        store.set_org("default", p)
        store.set_user("alice@example.com", {"camera": CapabilitySetting("self")})
        result = self._resolve_set(
            org_id="default", group_ids=[], user_email="alice@example.com", store=store
        )
        assert result["camera"].value == "self"  # User self is MORE restrictive than org allow_list

    # D4 — Group can narrow below org

    def test_d4_group_narrows_below_org(self):
        """D4: Group "off" narrows below org "self"."""
        from yashigani.capability_policy.model import CapabilitySetting
        store = _cap_store()
        store.set_group("strict", {"microphone": CapabilitySetting("off")})
        result = self._resolve_set(
            org_id="default", group_ids=["strict"], user_email="u@example.com", store=store
        )
        assert result["microphone"].value == "off"  # Group narrows

    # D5 — Most-restrictive of all three levels wins

    def test_d5_most_restrictive_wins_three_levels(self):
        """
        D5: Most-restrictive of {org, group, user} wins.
        org="self", group="off", user="allow_list" → "off" (group is most restrictive).
        """
        from yashigani.capability_policy.model import CapabilitySetting
        store = _cap_store()
        # Org: camera=self (baseline)
        store.set_group("g1", {"camera": CapabilitySetting("off")})
        store.set_user("u@example.com", {"camera": CapabilitySetting("allow_list", ["https://u.example.com"])})
        result = self._resolve_set(
            org_id="default", group_ids=["g1"], user_email="u@example.com", store=store
        )
        # min(self=1, off=0, allow_list=2) = off
        assert result["camera"].value == "off"

    def test_d5_multiple_groups_most_restrictive_wins(self):
        """D5: Multiple groups; most restrictive group setting wins."""
        from yashigani.capability_policy.model import CapabilitySetting
        store = _cap_store()
        store.set_group("liberal", {"microphone": CapabilitySetting("allow_list", ["https://x.example.com"])})
        store.set_group("strict", {"microphone": CapabilitySetting("off")})
        store.set_group("middle", {"microphone": CapabilitySetting("self")})
        result = self._resolve_set(
            org_id="default",
            group_ids=["liberal", "strict", "middle"],
            user_email="u@example.com",
            store=store,
        )
        # org=self, liberal=allow_list, strict=off, middle=self → min = off
        assert result["microphone"].value == "off"

    def test_d5_all_five_capabilities_always_present(self):
        """D5: Resolver always returns all 5 capabilities."""
        from yashigani.capability_policy.model import CAPABILITY_NAMES
        store = _cap_store()
        result = self._resolve_set(
            org_id="default", group_ids=[], user_email="u@example.com", store=store
        )
        assert set(result.keys()) == CAPABILITY_NAMES

    # D6 — Unauthenticated gets org policy

    def test_d6_unauthenticated_gets_org_policy(self):
        """D6: email=None → org policy returned (group/user tiers skipped)."""
        from yashigani.capability_policy.model import CapabilitySetting, default_policy
        store = _cap_store()
        p = default_policy()
        p["camera"] = CapabilitySetting("off")
        store.set_org("default", p)
        store.set_user("alice@example.com", {"camera": CapabilitySetting("allow_list")})
        result = self._resolve_set(
            org_id="default", group_ids=[], user_email=None, store=store
        )
        assert result["camera"].value == "off"  # Org policy, user tier skipped

    def test_d6_empty_email_treated_as_unauthenticated(self):
        """D6: email="" is equivalent to None (unauthenticated)."""
        from yashigani.capability_policy.model import CapabilitySetting
        store = _cap_store()
        store.set_user("", {"camera": CapabilitySetting("allow_list")})
        result = self._resolve_set(
            org_id="default", group_ids=[], user_email="", store=store
        )
        # Should get org policy, not the user override for ""
        assert result["camera"].value == "self"  # Org baseline

    # D7 — Baseline fallback

    def test_d7_baseline_fallback_when_no_org_key(self):
        """D7: When org key doesn't exist, resolver falls back to immutable baseline self×5."""
        from yashigani.capability_policy.model import CAPABILITY_NAMES
        store = _cap_store()
        # Delete the default org key
        store.delete_org("default")
        result = self._resolve_set(
            org_id="default", group_ids=[], user_email="u@example.com", store=store
        )
        assert set(result.keys()) == CAPABILITY_NAMES
        assert all(s.value == "self" for s in result.values()), (
            "After org key deletion, baseline self×5 must be the fallback"
        )

    def test_d7_unknown_org_returns_baseline(self):
        """D7: Unknown org_id returns baseline (no crash)."""
        store = _cap_store()
        result = self._resolve_set(
            org_id="no-such-org", group_ids=[], user_email="u@example.com", store=store
        )
        assert all(s.value == "self" for s in result.values())


# ============================================================================
# E. Audit schema — PermissionGrantChangedEvent
# ============================================================================

class TestAuditSchema:

    def test_permission_grant_changed_event_type_exists(self):
        from yashigani.audit.schema import EventType
        assert hasattr(EventType, "PERMISSION_GRANT_CHANGED")
        assert EventType.PERMISSION_GRANT_CHANGED == "PERMISSION_GRANT_CHANGED"

    def test_permission_grant_changed_event_fields(self):
        from yashigani.audit.schema import PermissionGrantChangedEvent, EventType, AccountTier
        evt = PermissionGrantChangedEvent(
            admin_account="admin@example.com",
            resource_type="mcp_server",
            resource_id="github-mcp",
            scope="org",
            scope_id="acme",
            change_type="set",
            grant_value={"allow": True},
        )
        assert evt.event_type == EventType.PERMISSION_GRANT_CHANGED
        assert evt.account_tier == AccountTier.ADMIN
        assert evt.masking_applied is True
        assert evt.resource_type == "mcp_server"
        assert evt.resource_id == "github-mcp"
        assert evt.scope == "org"
        assert evt.scope_id == "acme"
        assert evt.change_type == "set"
        assert evt.grant_value == {"allow": True}

    def test_permission_grant_changed_event_serialises(self):
        """PermissionGrantChangedEvent must survive to_dict() (used by audit chain)."""
        from yashigani.audit.schema import PermissionGrantChangedEvent
        evt = PermissionGrantChangedEvent(
            admin_account="admin@example.com",
            resource_type="cloud_model",
            resource_id="gpt-4o",
            scope="org",
            scope_id="acme",
            change_type="set",
            grant_value={"allow": True, "opa_policy_ref": "yashigani/cloud/gpt4o"},
        )
        d = evt.to_dict()
        assert d["event_type"] == "PERMISSION_GRANT_CHANGED"
        assert d["grant_value"]["opa_policy_ref"] == "yashigani/cloud/gpt4o"
        assert "audit_event_id" in d
        assert "timestamp" in d

    def test_capability_policy_changed_still_exists(self):
        """Backward compat: CAPABILITY_POLICY_CHANGED event type and class still present."""
        from yashigani.audit.schema import EventType, CapabilityPolicyChangedEvent
        assert EventType.CAPABILITY_POLICY_CHANGED == "CAPABILITY_POLICY_CHANGED"
        # The CapabilityPolicyChangedEvent still works
        evt = CapabilityPolicyChangedEvent(
            admin_account="admin@example.com",
            scope="org",
            scope_id="default",
            change_type="set",
            capabilities_changed=["camera"],
        )
        assert evt.event_type == "CAPABILITY_POLICY_CHANGED"


# ============================================================================
# F. Adapter — CapabilityPolicyStore delegates to PermissionStore
# ============================================================================

class TestCapabilityPolicyAdapter:

    def test_adapter_exposes_perm_store(self):
        """CapabilityPolicyStore.perm_store is a PermissionStore instance."""
        from yashigani.capability_policy.store import CapabilityPolicyStore
        from yashigani.permissions.store import PermissionStore
        store = _cap_store()
        assert isinstance(store.perm_store, PermissionStore)

    def test_adapter_set_org_readable_from_perm_store(self):
        """CapabilityPolicyStore.set_org writes through to PermissionStore."""
        from yashigani.capability_policy.model import CapabilitySetting, default_policy
        store = _cap_store()
        p = default_policy()
        p["camera"] = CapabilitySetting("off")
        store.set_org("default", p)
        # Read back via CapabilityPolicyStore
        result = store.get_org("default")
        assert result["camera"].value == "off"
        # Read back directly from PermissionStore
        perm_result = store.perm_store.get_browser_cap_org_policy("default")
        assert perm_result["camera"].value == "off"

    def test_resolve_policy_uses_org_ceiling_via_adapter(self):
        """resolve_policy (cap_policy adapter) enforces org-ceiling semantics."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting, default_policy
        store = _cap_store()
        # Org: camera=self (baseline, no explicit org override needed)
        # User tries to widen to allow_list
        store.set_user("alice@example.com", {"camera": CapabilitySetting("allow_list", ["https://cam.example.com"])})
        rbac = _rbac({})
        result = resolve_policy("alice@example.com", rbac, store)
        # Org "self" caps user "allow_list" → effective "self"
        assert result["camera"].value == "self"

    def test_resolve_policy_user_narrowing_still_works(self):
        """resolve_policy: user CAN narrow (off < org self) — only widening is blocked."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting
        store = _cap_store()
        store.set_user("alice@example.com", {"camera": CapabilitySetting("off")})
        rbac = _rbac({})
        result = resolve_policy("alice@example.com", rbac, store)
        assert result["camera"].value == "off"  # User narrowing is still effective

    def test_resolve_policy_group_via_rbac(self):
        """resolve_policy reads group membership from rbac_store."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting
        store = _cap_store()
        store.set_group("strict", {"microphone": CapabilitySetting("off")})
        rbac = _rbac({"bob@example.com": ["strict"]})
        result = resolve_policy("bob@example.com", rbac, store)
        assert result["microphone"].value == "off"

    def test_resolve_policy_no_rbac_skips_groups(self):
        """resolve_policy with rbac_store=None skips group tier."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting
        store = _cap_store()
        store.set_group("strict", {"camera": CapabilitySetting("off")})
        # No rbac_store → group lookup skipped → camera falls through to org "self"
        result = resolve_policy("alice@example.com", None, store)
        assert result["camera"].value == "self"

    def test_resolve_policy_unauthenticated(self):
        """resolve_policy with email=None returns org policy."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting, default_policy
        store = _cap_store()
        p = default_policy()
        p["camera"] = CapabilitySetting("off")
        store.set_org("default", p)
        result = resolve_policy(None, None, store)
        assert result["camera"].value == "off"
