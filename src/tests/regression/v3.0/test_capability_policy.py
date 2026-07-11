"""
Regression tests for the 3.0 browser Permissions-Policy feature
(admin-configurable, Redis-backed, 4-tier RBAC-scoped).

Scope precedence (highest → lowest):
    user override  >  most-restrictive group override  >  org policy  >  BASELINE (self×5)

Coverage:
  A. Resolver precedence — per-capability user > group (most-restrictive) > org > baseline
  B. Header rendering — off / self / allow_list forms
  C. Validation — unknown capabilities, bad origins, allow-list length cap
  D. Store — read/write/delete round-trips via fakeredis (incl. org tier)
  E. API routes — auth + audit emission (unit-level, mocked state)
     Includes new /orgs/{org_id} endpoints and updated audit scope="org"

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import time
import pytest
from unittest.mock import MagicMock


# ============================================================================
# A. Resolver precedence
# ============================================================================


def _make_store(
    org_overrides=None,
    group_overrides=None,
    user_overrides=None,
    default_org_id="default",
):
    """Build a CapabilityPolicyStore populated with test data using fakeredis."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from yashigani.capability_policy.store import CapabilityPolicyStore
    from yashigani.capability_policy.model import CapabilitySetting, default_policy

    redis = fakeredis.FakeRedis(decode_responses=False)
    store = CapabilityPolicyStore(redis_client=redis, default_org_id=default_org_id)

    if org_overrides:
        # Merge overrides into the baseline and write to the default org
        org = default_policy()
        org.update(org_overrides)
        store.set_org(default_org_id, org)

    if group_overrides:
        for gid, policy in group_overrides.items():
            store.set_group(gid, policy)

    if user_overrides:
        for email, policy in user_overrides.items():
            store.set_user(email, policy)

    return store


def _make_rbac_store(user_groups: dict):
    """Build a minimal mock RBACStore that returns fixed group memberships."""
    rbac = MagicMock()

    class _FakeGroup:
        def __init__(self, gid):
            self.id = gid

    def _get_user_groups(email):
        return [_FakeGroup(gid) for gid in user_groups.get(email, [])]

    rbac.get_user_groups = MagicMock(side_effect=_get_user_groups)
    return rbac


class TestResolverPrecedence:

    def test_unauthenticated_returns_org_policy(self):
        """email=None → org policy (not hardcoded baseline)."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting
        store = _make_store(org_overrides={"camera": CapabilitySetting("off")})
        result = resolve_policy(None, None, store)
        # org sets camera=off — unauthenticated should get org policy, not baseline
        assert result["camera"].value == "off"
        assert set(result.keys()) == {"camera", "microphone", "geolocation", "display-capture", "fullscreen"}

    def test_empty_email_returns_org_policy(self):
        """email="" → org policy."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting
        store = _make_store(org_overrides={"microphone": CapabilitySetting("off")})
        result = resolve_policy("", None, store)
        assert result["microphone"].value == "off"

    def test_unauthenticated_org_baseline_fallback(self):
        """email=None with default org → gets baseline self×5 when org not overridden."""
        from yashigani.capability_policy.resolver import resolve_policy
        store = _make_store()
        result = resolve_policy(None, None, store)
        assert all(s.value == "self" for s in result.values())

    def test_user_with_no_overrides_inherits_org(self):
        """User with no overrides anywhere → org policy for all capabilities."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting
        store = _make_store(
            org_overrides={"camera": CapabilitySetting("off")}
        )
        rbac = _make_rbac_store({})
        result = resolve_policy("alice@example.com", rbac, store)
        assert result["camera"].value == "off"  # org override
        assert result["microphone"].value == "self"  # baseline via org

    def test_org_ceiling_caps_user_widen_attempt(self):
        """
        Phase 2 (org-ceiling): user cannot widen above org.
        Org sets camera="off"; user tries to widen to "self".
        Effective = most-restrictive of {org="off", user="self"} = "off".

        Changed from Phase 1 test_user_override_wins_over_org which asserted
        result["camera"].value == "self" (user won).  Under the new org-ceiling
        semantics, org="off" caps the user's "self" attempt — the user can only
        NARROW, never widen.
        """
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting
        store = _make_store(
            org_overrides={"camera": CapabilitySetting("off")},
            user_overrides={"alice@example.com": {"camera": CapabilitySetting("self")}},
        )
        rbac = _make_rbac_store({})
        result = resolve_policy("alice@example.com", rbac, store)
        assert result["camera"].value == "off"  # org ceiling: "off" caps user "self"

    def test_group_deny_caps_user_widen_attempt(self):
        """
        Phase 2 (org-ceiling): user cannot widen above group.
        Group sets microphone="off"; user tries to widen to "self".
        Effective = most-restrictive of {org="self"(baseline), group="off", user="self"} = "off".

        Changed from Phase 1 test_user_override_wins_over_group which asserted
        result["microphone"].value == "self" (user won over group "off").
        Under the new most-restrictive-wins semantics, the more restrictive
        group setting "off" takes precedence — user can only narrow, not widen.
        """
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting
        store = _make_store(
            group_overrides={"group-1": {"microphone": CapabilitySetting("off")}},
            user_overrides={"bob@example.com": {"microphone": CapabilitySetting("self")}},
        )
        rbac = _make_rbac_store({"bob@example.com": ["group-1"]})
        result = resolve_policy("bob@example.com", rbac, store)
        assert result["microphone"].value == "off"  # group "off" is more restrictive than user "self"

    def test_group_override_wins_over_org(self):
        """Group override takes precedence over the org policy."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting
        store = _make_store(
            org_overrides={"camera": CapabilitySetting("self")},
            group_overrides={"group-strict": {"camera": CapabilitySetting("off")}},
        )
        rbac = _make_rbac_store({"dave@example.com": ["group-strict"]})
        result = resolve_policy("dave@example.com", rbac, store)
        assert result["camera"].value == "off"  # group "off" beats org "self"

    def test_group_override_used_when_no_user_override(self):
        """Group override applies per capability when user has no override."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting
        store = _make_store(
            group_overrides={"group-a": {"geolocation": CapabilitySetting("off")}},
        )
        rbac = _make_rbac_store({"carol@example.com": ["group-a"]})
        result = resolve_policy("carol@example.com", rbac, store)
        assert result["geolocation"].value == "off"  # from group
        assert result["camera"].value == "self"       # from org (baseline)

    def test_most_restrictive_group_wins_on_conflict(self):
        """When user is in multiple groups with conflicting overrides, most restrictive wins."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting

        store = _make_store(
            group_overrides={
                "grp-liberal": {"camera": CapabilitySetting("allow_list", ["https://example.com"])},
                "grp-strict": {"camera": CapabilitySetting("off")},
                "grp-middle": {"camera": CapabilitySetting("self")},
            },
        )
        rbac = _make_rbac_store({"dave@example.com": ["grp-liberal", "grp-strict", "grp-middle"]})
        result = resolve_policy("dave@example.com", rbac, store)
        assert result["camera"].value == "off"  # most restrictive = off (restrictiveness 0)

    def test_per_capability_inheritance_three_levels(self):
        """
        Phase 2 (org-ceiling): per-capability most-restrictive wins.

        Setup:
          org: fullscreen="off"  (org overrides only fullscreen)
          group grp-x: microphone="off"
          user eve: camera="allow_list"  (tries to widen above org baseline "self")

        Expected (org-ceiling, most-restrictive-wins):
          camera:        org="self" (baseline), user="allow_list" →
                         most-restrictive=min(self=1, allow_list=2)="self"
                         User "allow_list" is capped at org's "self". [CHANGED from Phase 1]
          microphone:    org="self", group="off" → min(self=1, off=0)="off"
          fullscreen:    org="off" → "off"
          geolocation:   org="self" (baseline), no overrides → "self"
          display-capture: org="self" (baseline), no overrides → "self"

        Phase 1 asserted camera="allow_list" (user won).  Phase 2 corrects this:
        the user's attempt to widen above the org baseline "self" is blocked.
        """
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting

        store = _make_store(
            org_overrides={"fullscreen": CapabilitySetting("off")},
            group_overrides={"grp-x": {"microphone": CapabilitySetting("off")}},
            user_overrides={"eve@example.com": {"camera": CapabilitySetting("allow_list", ["https://cam.example.com"])}},
        )
        rbac = _make_rbac_store({"eve@example.com": ["grp-x"]})
        result = resolve_policy("eve@example.com", rbac, store)

        # camera: org="self" caps user "allow_list" — org ceiling enforced [CHANGED]
        assert result["camera"].value == "self"
        assert result["camera"].allow_list == []
        assert result["microphone"].value == "off"           # group override (most-restrictive)
        assert result["fullscreen"].value == "off"           # org override
        assert result["geolocation"].value == "self"         # baseline (via org)
        assert result["display-capture"].value == "self"     # baseline (via org)

    def test_full_precedence_chain_all_four_tiers(self):
        """
        Phase 2 (org-ceiling): full most-restrictive-wins chain across all tiers.

        Setup (demonstrates narrowing at each tier, not widening):
            camera:          user sets "off" (user narrowing below org baseline "self")
            microphone:      group sets "off" (group narrowing below org baseline "self")
            geolocation:     org sets "off" (org ceiling)
            fullscreen:      no override → baseline "self" (via org)
            display-capture: no override → baseline "self" (via org)

        Phase 1 used camera="allow_list" to show "user wins".  Phase 2 corrects
        this: the test now shows user NARROWING (user="off") rather than widening.
        Under org-ceiling semantics only narrowing is meaningful at the user tier.
        """
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting

        store = _make_store(
            org_overrides={"geolocation": CapabilitySetting("off")},
            group_overrides={"grp-a": {"microphone": CapabilitySetting("off")}},
            user_overrides={"test@example.com": {
                "camera": CapabilitySetting("off")  # user narrows (off < org-baseline self)
            }},
        )
        rbac = _make_rbac_store({"test@example.com": ["grp-a"]})
        result = resolve_policy("test@example.com", rbac, store)

        # User tier — user set "off" which narrows below org baseline "self"
        assert result["camera"].value == "off"
        # Group tier — group "off" narrows below org baseline "self"
        assert result["microphone"].value == "off"
        # Org tier — org ceiling at "off"
        assert result["geolocation"].value == "off"
        # Baseline via org — no override, org baseline = "self"
        assert result["fullscreen"].value == "self"
        assert result["display-capture"].value == "self"

    def test_explicit_org_id_parameter(self):
        """resolve_policy with explicit org_id uses that org's policy, not the default."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting

        try:
            import fakeredis
        except ImportError:
            pytest.skip("fakeredis not installed")

        from yashigani.capability_policy.store import CapabilityPolicyStore
        from yashigani.capability_policy.model import default_policy

        redis = fakeredis.FakeRedis(decode_responses=False)
        store = CapabilityPolicyStore(redis_client=redis, default_org_id="default")

        # Seed a SECOND org with camera=off
        custom_org_policy = default_policy()
        custom_org_policy["camera"] = CapabilitySetting("off")
        store.set_org("acme-corp", custom_org_policy)

        # Default org has camera=self; acme-corp has camera=off
        result_default = resolve_policy("user@example.com", None, store, org_id="default")
        result_acme = resolve_policy("user@example.com", None, store, org_id="acme-corp")

        assert result_default["camera"].value == "self"
        assert result_acme["camera"].value == "off"

    def test_org_fallback_to_baseline_when_org_deleted(self):
        """After delete_org, resolver returns baseline values (self×5) for that org."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting

        try:
            import fakeredis
        except ImportError:
            pytest.skip("fakeredis not installed")

        from yashigani.capability_policy.store import CapabilityPolicyStore
        from yashigani.capability_policy.model import default_policy

        redis = fakeredis.FakeRedis(decode_responses=False)
        store = CapabilityPolicyStore(redis_client=redis, default_org_id="default")

        # Set org with camera=off
        p = default_policy()
        p["camera"] = CapabilitySetting("off")
        store.set_org("default", p)

        result_before = resolve_policy("user@example.com", None, store)
        assert result_before["camera"].value == "off"

        store.delete_org("default")
        # After deletion, get_org merges {} over baseline → baseline self×5
        result_after = resolve_policy("user@example.com", None, store)
        assert result_after["camera"].value == "self"

    def test_allow_list_origins_preserved_in_resolution(self):
        """
        allow_list entries are preserved through the resolver.

        Phase 2 note: Under org-ceiling semantics a user cannot widen above org.
        To test allow_list origin round-trip, the org-level policy must itself
        carry allow_list origins (org is the ceiling).  The user tier can then
        either inherit or narrow further.

        Here the ORG sets display-capture=allow_list with specific origins and
        the user has no override → the org allow_list origins must come through
        unchanged.
        """
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting, default_policy

        origins = ["https://app1.example.com", "https://app2.example.com"]
        store = _make_store(
            org_overrides={
                "display-capture": CapabilitySetting("allow_list", origins)
            },
        )
        rbac = _make_rbac_store({})
        # frank has no user/group override → inherits org allow_list
        result = resolve_policy("frank@example.com", rbac, store)
        assert result["display-capture"].value == "allow_list"
        assert result["display-capture"].allow_list == origins

    def test_no_rbac_store_falls_back_to_org(self):
        """rbac_store=None → group lookup is skipped; org and user still apply."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CapabilitySetting
        store = _make_store(
            org_overrides={"camera": CapabilitySetting("off")},
        )
        result = resolve_policy("grace@example.com", None, store)
        assert result["camera"].value == "off"  # org (no groups, no user override)

    def test_all_five_capabilities_always_present(self):
        """Resolved policy always contains exactly the 5 required capabilities."""
        from yashigani.capability_policy.resolver import resolve_policy
        from yashigani.capability_policy.model import CAPABILITY_NAMES
        store = _make_store()
        result = resolve_policy("hank@example.com", None, store)
        assert set(result.keys()) == CAPABILITY_NAMES


# ============================================================================
# B. Header rendering
# ============================================================================

class TestHeaderRendering:

    def _render(self, overrides: dict) -> str:
        from yashigani.capability_policy.header import render_permissions_policy
        from yashigani.capability_policy.model import default_policy, CapabilitySetting
        policy = default_policy()
        policy.update(overrides)
        return render_permissions_policy(policy)

    def test_all_self_renders_correctly(self):
        """Default policy: all 5 capabilities = (self)."""
        header = self._render({})
        assert "camera=(self)" in header
        assert "microphone=(self)" in header
        assert "geolocation=(self)" in header
        assert "display-capture=(self)" in header
        assert "fullscreen=(self)" in header

    def test_off_renders_empty_parens(self):
        """off → camera=()"""
        from yashigani.capability_policy.model import CapabilitySetting
        header = self._render({"camera": CapabilitySetting("off")})
        assert "camera=()" in header
        # Other capabilities still self
        assert "microphone=(self)" in header

    def test_allow_list_renders_origins(self):
        """allow_list → camera=(self "https://a.com" "https://b.com")"""
        from yashigani.capability_policy.model import CapabilitySetting
        header = self._render({
            "camera": CapabilitySetting("allow_list", ["https://a.com", "https://b.com"])
        })
        assert 'camera=(self "https://a.com" "https://b.com")' in header

    def test_empty_allow_list_renders_as_self(self):
        """allow_list with no entries falls back to (self) in the header."""
        from yashigani.capability_policy.model import CapabilitySetting
        header = self._render({"camera": CapabilitySetting("allow_list", [])})
        assert "camera=(self)" in header

    def test_header_is_comma_separated(self):
        """Header values are separated by ', '."""
        header = self._render({})
        parts = [p.strip() for p in header.split(",")]
        assert len(parts) == 5  # exactly 5 capabilities

    def test_header_deterministic_order(self):
        """Capabilities are always emitted in alphabetical order."""
        header = self._render({})
        # camera < display-capture < fullscreen < geolocation < microphone
        positions = {
            cap: header.index(cap)
            for cap in ["camera", "display-capture", "fullscreen", "geolocation", "microphone"]
        }
        caps_ordered = sorted(positions, key=lambda c: positions[c])
        assert caps_ordered == ["camera", "display-capture", "fullscreen", "geolocation", "microphone"]

    def test_multiple_origins_in_allow_list(self):
        """Multiple origins are separated by spaces inside the parens."""
        from yashigani.capability_policy.model import CapabilitySetting
        from yashigani.capability_policy.header import render_permissions_policy
        from yashigani.capability_policy.model import default_policy
        policy = default_policy()
        policy["microphone"] = CapabilitySetting(
            "allow_list",
            ["https://voice1.example.com", "https://voice2.example.com"]
        )
        header = render_permissions_policy(policy)
        assert 'microphone=(self "https://voice1.example.com" "https://voice2.example.com")' in header


# ============================================================================
# C. Validation
# ============================================================================

class TestValidation:

    def test_unknown_capability_name_rejected(self):
        """Unknown capability name raises ValidationError."""
        from yashigani.capability_policy.model import (
            validate_capability_name, ValidationError
        )
        with pytest.raises(ValidationError, match="Unknown capability"):
            validate_capability_name("speakers")

    def test_known_capability_names_accepted(self):
        """All 5 valid names pass validation."""
        from yashigani.capability_policy.model import validate_capability_name, CAPABILITY_NAMES
        for name in CAPABILITY_NAMES:
            validate_capability_name(name)  # must not raise

    def test_invalid_value_rejected(self):
        """Value not in {off, self, allow_list} raises ValidationError."""
        from yashigani.capability_policy.model import (
            CapabilitySetting, validate_capability_setting, ValidationError
        )
        with pytest.raises(ValidationError, match="value must be one of"):
            validate_capability_setting("camera", CapabilitySetting("enabled"))

    def test_allow_list_length_cap(self):
        """allow_list with more than 10 entries raises ValidationError."""
        from yashigani.capability_policy.model import (
            CapabilitySetting, validate_capability_setting, ValidationError,
            MAX_ALLOW_LIST_ENTRIES
        )
        too_many = [f"https://origin{i}.example.com" for i in range(MAX_ALLOW_LIST_ENTRIES + 1)]
        with pytest.raises(ValidationError, match="at most"):
            validate_capability_setting("camera", CapabilitySetting("allow_list", too_many))

    def test_allow_list_valid_origins_accepted(self):
        """Valid https:// origins pass validation."""
        from yashigani.capability_policy.model import CapabilitySetting, validate_capability_setting
        valid_origins = [
            "https://example.com",
            "https://sub.domain.example.com",
            "https://example.com:8443",
            "https://localhost:3000",
        ]
        for origin in valid_origins:
            setting = CapabilitySetting("allow_list", [origin])
            validate_capability_setting("camera", setting)  # must not raise

    def test_allow_list_http_origin_rejected(self):
        """http:// origin is not a valid https:// origin."""
        from yashigani.capability_policy.model import (
            CapabilitySetting, validate_capability_setting, ValidationError
        )
        with pytest.raises(ValidationError, match="invalid origin"):
            validate_capability_setting(
                "camera",
                CapabilitySetting("allow_list", ["http://example.com"])
            )

    def test_allow_list_path_in_origin_rejected(self):
        """Origins with a path component are rejected."""
        from yashigani.capability_policy.model import (
            CapabilitySetting, validate_capability_setting, ValidationError
        )
        with pytest.raises(ValidationError, match="invalid origin"):
            validate_capability_setting(
                "camera",
                CapabilitySetting("allow_list", ["https://example.com/path"])
            )

    def test_allow_list_wildcard_host_rejected(self):
        """Wildcard hostnames like *.example.com are not valid origins."""
        from yashigani.capability_policy.model import (
            CapabilitySetting, validate_capability_setting, ValidationError
        )
        with pytest.raises(ValidationError, match="invalid origin"):
            validate_capability_setting(
                "microphone",
                CapabilitySetting("allow_list", ["https://*.example.com"])
            )

    def test_validate_policy_set_requires_all_for_org(self):
        """validate_policy_set(require_all=True) raises if any capability is missing."""
        from yashigani.capability_policy.model import (
            CapabilitySetting, validate_policy_set, ValidationError
        )
        partial = {
            "camera": CapabilitySetting("self"),
            # missing the other 4
        }
        with pytest.raises(ValidationError, match="Missing"):
            validate_policy_set(partial, require_all=True)

    def test_validate_policy_set_partial_allowed(self):
        """validate_policy_set(require_all=False) allows partial dicts."""
        from yashigani.capability_policy.model import CapabilitySetting, validate_policy_set
        partial = {"camera": CapabilitySetting("off")}
        validate_policy_set(partial, require_all=False)  # must not raise


# ============================================================================
# D. Store — read/write/delete round-trips (incl. org tier)
# ============================================================================

class TestStore:

    @pytest.fixture
    def store(self):
        try:
            import fakeredis
        except ImportError:
            pytest.skip("fakeredis not installed")
        from yashigani.capability_policy.store import CapabilityPolicyStore
        redis = fakeredis.FakeRedis(decode_responses=False)
        return CapabilityPolicyStore(redis_client=redis, default_org_id="default")

    def test_org_defaults_seeded_on_init(self, store):
        """Org defaults are written to Redis on first init."""
        from yashigani.capability_policy.model import CAPABILITY_NAMES
        policy = store.get_org("default")
        assert set(policy.keys()) == CAPABILITY_NAMES
        assert all(s.value == "self" for s in policy.values())

    def test_set_and_get_org(self, store):
        """Round-trip for org policy."""
        from yashigani.capability_policy.model import CapabilitySetting, default_policy
        new_policy = default_policy()
        new_policy["camera"] = CapabilitySetting("off")
        store.set_org("default", new_policy)
        result = store.get_org("default")
        assert result["camera"].value == "off"
        assert result["microphone"].value == "self"

    def test_delete_org(self, store):
        """delete_org removes the org policy; get_org then returns baseline."""
        from yashigani.capability_policy.model import CapabilitySetting, default_policy
        p = default_policy()
        p["camera"] = CapabilitySetting("off")
        store.set_org("default", p)
        assert store.get_org("default")["camera"].value == "off"
        deleted = store.delete_org("default")
        assert deleted is True
        # After deletion, get_org merges {} over baseline → self
        assert store.get_org("default")["camera"].value == "self"

    def test_delete_org_nonexistent_returns_false(self, store):
        """delete_org on missing key returns False (not an error)."""
        result = store.delete_org("no-such-org")
        assert result is False

    def test_custom_org_id_seeded(self):
        """Store seeded with a custom org_id writes to the correct key."""
        try:
            import fakeredis
        except ImportError:
            pytest.skip("fakeredis not installed")
        from yashigani.capability_policy.store import CapabilityPolicyStore
        from yashigani.capability_policy.model import CAPABILITY_NAMES
        redis = fakeredis.FakeRedis(decode_responses=False)
        store = CapabilityPolicyStore(redis_client=redis, default_org_id="acme")
        policy = store.get_org("acme")
        assert set(policy.keys()) == CAPABILITY_NAMES
        assert all(s.value == "self" for s in policy.values())
        # default org key should NOT be seeded
        assert store.get_org("default")["camera"].value == "self"  # falls back to baseline

    def test_multiple_orgs_independent(self):
        """Two org policies are stored independently."""
        try:
            import fakeredis
        except ImportError:
            pytest.skip("fakeredis not installed")
        from yashigani.capability_policy.store import CapabilityPolicyStore
        from yashigani.capability_policy.model import CapabilitySetting, default_policy
        redis = fakeredis.FakeRedis(decode_responses=False)
        store = CapabilityPolicyStore(redis_client=redis, default_org_id="default")

        p1 = default_policy()
        p1["camera"] = CapabilitySetting("off")
        store.set_org("org-a", p1)

        p2 = default_policy()
        p2["microphone"] = CapabilitySetting("off")
        store.set_org("org-b", p2)

        assert store.get_org("org-a")["camera"].value == "off"
        assert store.get_org("org-a")["microphone"].value == "self"

        assert store.get_org("org-b")["camera"].value == "self"
        assert store.get_org("org-b")["microphone"].value == "off"

    def test_get_group_empty_when_no_override(self, store):
        """get_group returns {} if no override is stored."""
        result = store.get_group("nonexistent-group")
        assert result == {}

    def test_set_and_get_group(self, store):
        """Round-trip for group override."""
        from yashigani.capability_policy.model import CapabilitySetting
        store.set_group("grp-abc", {"microphone": CapabilitySetting("off")})
        result = store.get_group("grp-abc")
        assert result["microphone"].value == "off"
        assert "camera" not in result  # partial — only microphone stored

    def test_delete_group(self, store):
        """delete_group removes the override."""
        from yashigani.capability_policy.model import CapabilitySetting
        store.set_group("grp-del", {"camera": CapabilitySetting("off")})
        assert store.get_group("grp-del") != {}
        deleted = store.delete_group("grp-del")
        assert deleted is True
        assert store.get_group("grp-del") == {}

    def test_delete_group_nonexistent_returns_false(self, store):
        """delete_group on missing key returns False (not an error)."""
        result = store.delete_group("does-not-exist")
        assert result is False

    def test_set_and_get_user(self, store):
        """Round-trip for user override."""
        from yashigani.capability_policy.model import CapabilitySetting
        store.set_user("alice@example.com", {"geolocation": CapabilitySetting("off")})
        result = store.get_user("alice@example.com")
        assert result["geolocation"].value == "off"

    def test_delete_user(self, store):
        """delete_user removes the override."""
        from yashigani.capability_policy.model import CapabilitySetting
        store.set_user("bob@example.com", {"camera": CapabilitySetting("off")})
        deleted = store.delete_user("bob@example.com")
        assert deleted is True
        assert store.get_user("bob@example.com") == {}

    def test_allow_list_round_trip(self, store):
        """allow_list origins survive a store round-trip."""
        from yashigani.capability_policy.model import CapabilitySetting
        origins = ["https://a.example.com", "https://b.example.com"]
        store.set_user("carol@example.com", {
            "display-capture": CapabilitySetting("allow_list", origins)
        })
        result = store.get_user("carol@example.com")
        assert result["display-capture"].value == "allow_list"
        assert result["display-capture"].allow_list == origins


# ============================================================================
# E. API routes — auth + audit emission
# ============================================================================

def _make_admin_session(email="admin@example.com"):
    from yashigani.auth.session import Session
    now = time.time()
    return Session(
        token="test-token",
        account_id=email,
        account_tier="admin",
        created_at=now,
        last_active_at=now,
        expires_at=now + 3600,
        ip_prefix="127.0.0",
        last_totp_verified_at=now,
    )


@pytest.mark.asyncio
async def test_get_org_returns_all_capabilities():
    """GET root returns all 5 capabilities for the default org."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from yashigani.capability_policy.store import CapabilityPolicyStore
    from yashigani.backoffice.routes import capability_policy as cp_mod
    from yashigani.backoffice.state import BackofficeState

    state = BackofficeState()
    redis = fakeredis.FakeRedis(decode_responses=False)
    state.capability_policy_store = CapabilityPolicyStore(redis_client=redis)
    state.audit_writer = MagicMock()

    original = cp_mod.backoffice_state
    cp_mod.backoffice_state = state
    try:
        result = await cp_mod.get_org_policy(_make_admin_session())
    finally:
        cp_mod.backoffice_state = original

    assert "org" in result
    assert "org_id" in result
    assert set(result["org"].keys()) == {
        "camera", "microphone", "geolocation", "display-capture", "fullscreen"
    }
    for cap in result["org"].values():
        assert cap["value"] == "self"
        assert cap["allow_list"] == []


@pytest.mark.asyncio
async def test_put_org_validates_all_five_required():
    """PUT org with missing capability raises 422."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from fastapi import HTTPException
    from yashigani.capability_policy.store import CapabilityPolicyStore
    from yashigani.backoffice.routes import capability_policy as cp_mod
    from yashigani.backoffice.routes.capability_policy import CapabilityPolicyBody
    from yashigani.backoffice.state import BackofficeState

    state = BackofficeState()
    redis = fakeredis.FakeRedis(decode_responses=False)
    state.capability_policy_store = CapabilityPolicyStore(redis_client=redis)
    state.audit_writer = MagicMock()
    state.audit_writer.write = MagicMock()

    original = cp_mod.backoffice_state
    cp_mod.backoffice_state = state
    try:
        # Only camera provided — other 4 missing → should raise
        from yashigani.backoffice.routes.capability_policy import CapabilitySettingIn
        body = CapabilityPolicyBody(camera=CapabilitySettingIn(value="off"))
        with pytest.raises(HTTPException) as exc_info:
            await cp_mod.set_org_policy(body, _make_admin_session())
        assert exc_info.value.status_code == 422
    finally:
        cp_mod.backoffice_state = original


@pytest.mark.asyncio
async def test_put_org_emits_audit_event():
    """PUT org emits CAPABILITY_POLICY_CHANGED audit event with scope='org'."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from yashigani.capability_policy.store import CapabilityPolicyStore
    from yashigani.backoffice.routes import capability_policy as cp_mod
    from yashigani.backoffice.routes.capability_policy import (
        CapabilityPolicyBody, CapabilitySettingIn
    )
    from yashigani.backoffice.state import BackofficeState
    from yashigani.audit.schema import EventType

    state = BackofficeState()
    redis = fakeredis.FakeRedis(decode_responses=False)
    state.capability_policy_store = CapabilityPolicyStore(redis_client=redis)

    audit_events: list = []
    mock_audit = MagicMock()
    mock_audit.write = lambda ev: audit_events.append(ev)
    state.audit_writer = mock_audit

    original = cp_mod.backoffice_state
    cp_mod.backoffice_state = state
    try:
        body = CapabilityPolicyBody(
            camera=CapabilitySettingIn(value="off"),
            microphone=CapabilitySettingIn(value="self"),
            geolocation=CapabilitySettingIn(value="self"),
            fullscreen=CapabilitySettingIn(value="self"),
            display_capture=CapabilitySettingIn(value="self"),  # populate_by_name=True
        )
        result = await cp_mod.set_org_policy(body, _make_admin_session("boss@example.com"))
    finally:
        cp_mod.backoffice_state = original

    assert len(audit_events) == 1
    evt = audit_events[0]
    assert evt.event_type == EventType.CAPABILITY_POLICY_CHANGED
    assert evt.scope == "org"
    assert evt.scope_id == "default"   # DEFAULT_ORG_ID
    assert evt.change_type == "set"
    assert evt.admin_account == "boss@example.com"
    assert "camera" in evt.capabilities_changed

    # Verify the stored value
    assert result["org"]["camera"]["value"] == "off"
    assert result["org_id"] == "default"


@pytest.mark.asyncio
async def test_put_org_by_id_emits_audit_event():
    """PUT /orgs/{org_id} emits CAPABILITY_POLICY_CHANGED with scope='org' and correct scope_id."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from yashigani.capability_policy.store import CapabilityPolicyStore
    from yashigani.backoffice.routes import capability_policy as cp_mod
    from yashigani.backoffice.routes.capability_policy import (
        CapabilityPolicyBody, CapabilitySettingIn
    )
    from yashigani.backoffice.state import BackofficeState
    from yashigani.audit.schema import EventType

    state = BackofficeState()
    redis = fakeredis.FakeRedis(decode_responses=False)
    state.capability_policy_store = CapabilityPolicyStore(redis_client=redis)

    audit_events: list = []
    mock_audit = MagicMock()
    mock_audit.write = lambda ev: audit_events.append(ev)
    state.audit_writer = mock_audit

    original = cp_mod.backoffice_state
    cp_mod.backoffice_state = state
    try:
        body = CapabilityPolicyBody(
            camera=CapabilitySettingIn(value="off"),
            microphone=CapabilitySettingIn(value="self"),
            geolocation=CapabilitySettingIn(value="self"),
            fullscreen=CapabilitySettingIn(value="self"),
            display_capture=CapabilitySettingIn(value="self"),
        )
        result = await cp_mod.set_org_by_id("acme-corp", body, _make_admin_session())
    finally:
        cp_mod.backoffice_state = original

    assert len(audit_events) == 1
    evt = audit_events[0]
    assert evt.scope == "org"
    assert evt.scope_id == "acme-corp"
    assert result["org_id"] == "acme-corp"
    assert result["org"]["camera"]["value"] == "off"


@pytest.mark.asyncio
async def test_get_org_by_id():
    """GET /orgs/{org_id} returns the correct org policy."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from yashigani.capability_policy.store import CapabilityPolicyStore
    from yashigani.capability_policy.model import CapabilitySetting, default_policy
    from yashigani.backoffice.routes import capability_policy as cp_mod
    from yashigani.backoffice.state import BackofficeState

    state = BackofficeState()
    redis = fakeredis.FakeRedis(decode_responses=False)
    store = CapabilityPolicyStore(redis_client=redis)
    # Manually set a non-default org
    p = default_policy()
    p["geolocation"] = CapabilitySetting("off")
    store.set_org("example-corp", p)
    state.capability_policy_store = store
    state.audit_writer = MagicMock()

    original = cp_mod.backoffice_state
    cp_mod.backoffice_state = state
    try:
        result = await cp_mod.get_org_by_id("example-corp", _make_admin_session())
    finally:
        cp_mod.backoffice_state = original

    assert result["org_id"] == "example-corp"
    assert result["org"]["geolocation"]["value"] == "off"
    assert result["org"]["camera"]["value"] == "self"


@pytest.mark.asyncio
async def test_delete_org_by_id_emits_audit():
    """DELETE /orgs/{org_id} emits audit with change_type=deleted."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from yashigani.capability_policy.store import CapabilityPolicyStore
    from yashigani.backoffice.routes import capability_policy as cp_mod
    from yashigani.backoffice.state import BackofficeState
    from yashigani.audit.schema import EventType

    state = BackofficeState()
    redis = fakeredis.FakeRedis(decode_responses=False)
    state.capability_policy_store = CapabilityPolicyStore(redis_client=redis)

    audit_events: list = []
    mock_audit = MagicMock()
    mock_audit.write = lambda ev: audit_events.append(ev)
    state.audit_writer = mock_audit

    original = cp_mod.backoffice_state
    cp_mod.backoffice_state = state
    try:
        await cp_mod.delete_org_by_id("test-org", _make_admin_session())
    finally:
        cp_mod.backoffice_state = original

    assert len(audit_events) == 1
    evt = audit_events[0]
    assert evt.event_type == EventType.CAPABILITY_POLICY_CHANGED
    assert evt.scope == "org"
    assert evt.scope_id == "test-org"
    assert evt.change_type == "deleted"


@pytest.mark.asyncio
async def test_put_group_emits_audit_event():
    """PUT group emits CAPABILITY_POLICY_CHANGED audit event with scope=group."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from yashigani.capability_policy.store import CapabilityPolicyStore
    from yashigani.backoffice.routes import capability_policy as cp_mod
    from yashigani.backoffice.routes.capability_policy import (
        CapabilityPolicyBody, CapabilitySettingIn
    )
    from yashigani.backoffice.state import BackofficeState
    from yashigani.audit.schema import EventType

    state = BackofficeState()
    redis = fakeredis.FakeRedis(decode_responses=False)
    state.capability_policy_store = CapabilityPolicyStore(redis_client=redis)

    audit_events: list = []
    mock_audit = MagicMock()
    mock_audit.write = lambda ev: audit_events.append(ev)
    state.audit_writer = mock_audit

    original = cp_mod.backoffice_state
    cp_mod.backoffice_state = state
    try:
        body = CapabilityPolicyBody(microphone=CapabilitySettingIn(value="off"))
        result = await cp_mod.set_group("grp-xyz", body, _make_admin_session())
    finally:
        cp_mod.backoffice_state = original

    assert len(audit_events) == 1
    evt = audit_events[0]
    assert evt.event_type == EventType.CAPABILITY_POLICY_CHANGED
    assert evt.scope == "group"
    assert evt.scope_id == "grp-xyz"
    assert evt.change_type == "set"
    assert "microphone" in evt.capabilities_changed


@pytest.mark.asyncio
async def test_delete_user_emits_audit_event():
    """DELETE user emits CAPABILITY_POLICY_CHANGED audit event with change_type=deleted."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from yashigani.capability_policy.store import CapabilityPolicyStore
    from yashigani.backoffice.routes import capability_policy as cp_mod
    from yashigani.backoffice.state import BackofficeState
    from yashigani.audit.schema import EventType

    state = BackofficeState()
    redis = fakeredis.FakeRedis(decode_responses=False)
    state.capability_policy_store = CapabilityPolicyStore(redis_client=redis)

    audit_events: list = []
    mock_audit = MagicMock()
    mock_audit.write = lambda ev: audit_events.append(ev)
    state.audit_writer = mock_audit

    original = cp_mod.backoffice_state
    cp_mod.backoffice_state = state
    try:
        await cp_mod.delete_user("alice@example.com", _make_admin_session())
    finally:
        cp_mod.backoffice_state = original

    assert len(audit_events) == 1
    evt = audit_events[0]
    assert evt.event_type == EventType.CAPABILITY_POLICY_CHANGED
    assert evt.scope == "user"
    assert evt.scope_id == "alice@example.com"
    assert evt.change_type == "deleted"


@pytest.mark.asyncio
async def test_get_effective_reflects_org_level():
    """GET /effective returns the resolver output including org-level override."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")

    from yashigani.capability_policy.store import CapabilityPolicyStore
    from yashigani.capability_policy.model import CapabilitySetting, default_policy
    from yashigani.backoffice.routes import capability_policy as cp_mod
    from yashigani.backoffice.state import BackofficeState

    state = BackofficeState()
    redis = fakeredis.FakeRedis(decode_responses=False)
    store = CapabilityPolicyStore(redis_client=redis)
    # Set org-level camera=off and a user override on geolocation
    p = default_policy()
    p["camera"] = CapabilitySetting("off")
    store.set_org("default", p)
    store.set_user("frank@example.com", {"geolocation": CapabilitySetting("off")})
    state.capability_policy_store = store
    state.rbac_store = None
    state.audit_writer = MagicMock()

    original = cp_mod.backoffice_state
    cp_mod.backoffice_state = state
    try:
        result = await cp_mod.get_effective(_make_admin_session(), user="frank@example.com")
    finally:
        cp_mod.backoffice_state = original

    assert result["user"] == "frank@example.com"
    assert result["org_id"] == "default"
    assert result["effective"]["camera"]["value"] == "off"       # from org
    assert result["effective"]["geolocation"]["value"] == "off"  # from user override
    assert result["effective"]["microphone"]["value"] == "self"  # baseline via org


@pytest.mark.asyncio
async def test_store_not_configured_returns_503():
    """Routes return 503 when capability_policy_store is None."""
    from fastapi import HTTPException
    from yashigani.backoffice.routes import capability_policy as cp_mod
    from yashigani.backoffice.state import BackofficeState

    state = BackofficeState()
    state.capability_policy_store = None

    original = cp_mod.backoffice_state
    cp_mod.backoffice_state = state
    try:
        with pytest.raises(HTTPException) as exc_info:
            await cp_mod.get_org_policy(_make_admin_session())
        assert exc_info.value.status_code == 503
    finally:
        cp_mod.backoffice_state = original
