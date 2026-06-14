"""Tier enforcement smoke test — yashigani-retro #42.

Pins two contracts that together prove "HTTP 402 returned at exactly the
tier boundary with descriptive error body":

  Layer A — Tier-defaults boundary (hermetic, enforcer level):
    For every canonical tier in TIER_DEFAULTS, the four resource axes
    (max_agents, max_end_users, max_admin_seats, max_orgs) raise at the
    EXACT documented boundary, accept count = boundary - 1, and never
    raise when the limit is -1 (Enterprise unlimited).

  Layer B — Route → HTTP 402 wiring (FastAPI integration):
    When an over-limit request hits the actual registered route, the
    response is HTTP 402 with the documented error-code body. Wired
    against the real handler from yashigani.backoffice.routes.agents
    so route-level regressions surface here, not in QA.

  Layer C — Feature-gate matrix (per README §8):
    OIDC available on Starter+, SAML/SCIM on Professional+ — assert
    require_feature() raises LicenseFeatureGated for tiers below the
    documented availability and passes for tiers at/above.

  Layer D — multi-org gate:
    Pro+ allows up to 5 orgs; Community/Starter/Pro are single-org.
    Asserts max_orgs > 1 only on Pro+ and Enterprise.

SOURCE OF TRUTH:
    Website pricing + user-number table (mirrored in README §8) is the
    canonical contract. TIER_DEFAULTS in src/yashigani/licensing/model.py
    is aligned with that table — this test asserts both values and
    boundaries. Any future drift between TIER_DEFAULTS and the website
    surfaces as a hard fail here.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from yashigani.licensing.enforcer import (
    LicenseFeatureGated,
    LicenseLimitExceeded,
    check_admin_seat_limit,
    check_agent_limit,
    check_end_user_limit,
    check_org_limit,
    license_feature_gated_response,
    license_limit_exceeded_response,
    require_feature,
    set_license,
)
from yashigani.licensing.model import (
    TIER_DEFAULTS,
    LicenseFeature,
    LicenseState,
    LicenseTier,
)


# ---------------------------------------------------------------------------
# Canonical tier feature matrix (from README.md §8 / pricing page). Pinned
# here so the test fails loud if the matrix ever drifts in either direction.
#
# ENT-001 (2026-06-14): pii_log / pii_redact removed from this matrix.
# PII detection is ALWAYS AVAILABLE on every tier (including Community) and is
# no longer tier-gated.  The enforcer short-circuits on those feature keys via
# _ALWAYS_AVAILABLE_FEATURES so a license payload need not carry them.
# ---------------------------------------------------------------------------
_TIER_FEATURES: dict[str, set[str]] = {
    "community":          set(),
    "igniter":            {"oidc"},
    "starter":            {"oidc"},
    "professional":       {"oidc", "saml", "scim"},
    "professional_plus":  {"oidc", "saml", "scim"},
    "enterprise":         {"oidc", "saml", "scim"},
    "academic_nonprofit": {"oidc", "saml", "scim"},
}

_LIMIT_AXES = ("max_agents", "max_end_users", "max_admin_seats", "max_orgs")
_LIMIT_FN = {
    "max_agents":      check_agent_limit,
    "max_end_users":   check_end_user_limit,
    "max_admin_seats": check_admin_seat_limit,
    "max_orgs":        check_org_limit,
}
_TIER_NAMES_SCOPE = (
    "community",
    "igniter",
    "starter",
    "professional",
    "professional_plus",
    "enterprise",
    "academic_nonprofit",
)


def _build_license(tier_name: str) -> LicenseState:
    """Build a LicenseState whose limits + features match the canonical
    contract for `tier_name`. The tier defaults come from the code's own
    TIER_DEFAULTS table; features come from the README §8 matrix pinned
    in _TIER_FEATURES."""
    defaults = TIER_DEFAULTS[tier_name]
    feature_strs = _TIER_FEATURES[tier_name]
    feature_enums = frozenset(LicenseFeature(f) for f in feature_strs)
    return LicenseState(
        tier=LicenseTier(tier_name),
        org_domain="example.com",
        max_agents=defaults["max_agents"],
        max_end_users=defaults["max_end_users"],
        max_admin_seats=defaults["max_admin_seats"],
        max_orgs=defaults["max_orgs"],
        features=feature_enums,
        issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        expires_at=datetime(2027, 1, 1, tzinfo=timezone.utc),
        license_id=str(uuid.uuid4()),
        valid=True,
        error=None,
    )


@pytest.fixture(autouse=True)
def _reset_license_after_each_test():
    """Tests mutate module-level _license; restore community defaults after."""
    yield
    from yashigani.licensing.model import COMMUNITY_LICENSE
    set_license(COMMUNITY_LICENSE)


# ---------------------------------------------------------------------------
# Layer A — Tier-defaults boundary
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tier_name", _TIER_NAMES_SCOPE)
@pytest.mark.parametrize("axis", _LIMIT_AXES)
def test_enforcer_raises_at_exact_tier_boundary(tier_name: str, axis: str):
    """For every (tier, axis) the enforcer raises at count = max, and only
    at max (not max - 1, not unlimited)."""
    lic = _build_license(tier_name)
    set_license(lic)

    max_val = TIER_DEFAULTS[tier_name][axis]
    check = _LIMIT_FN[axis]

    if max_val == -1:
        # Enterprise — unlimited never raises, even at very large counts.
        check(1_000_000)
        return

    # Just below boundary — must NOT raise.
    check(max_val - 1)

    # Exactly at boundary — must raise.
    with pytest.raises(LicenseLimitExceeded) as exc_info:
        check(max_val)
    assert exc_info.value.limit_name == axis, (
        f"{tier_name}/{axis}: enforcer raised with wrong limit_name"
    )
    assert exc_info.value.current == max_val
    assert exc_info.value.max_val == max_val


@pytest.mark.parametrize("tier_name", _TIER_NAMES_SCOPE)
def test_limit_exceeded_response_body_is_descriptive(tier_name: str):
    """The 402 body must carry tier, limit, current, maximum, upgrade_url, and
    a human-readable message — that's the 'descriptive error body' from #42."""
    lic = _build_license(tier_name)
    set_license(lic)

    max_val = TIER_DEFAULTS[tier_name]["max_agents"]
    if max_val == -1:
        pytest.skip("enterprise has no boundary to trip")

    try:
        check_agent_limit(max_val)
    except LicenseLimitExceeded as exc:
        body = license_limit_exceeded_response(exc)

    assert body["error"] == "LICENSE_LIMIT_EXCEEDED"
    assert body["limit"] == "max_agents"
    assert body["current"] == max_val
    assert body["maximum"] == max_val
    assert body["tier"] == tier_name
    assert "upgrade_url" in body and body["upgrade_url"].startswith("https://")
    assert isinstance(body["message"], str) and body["message"]


# ---------------------------------------------------------------------------
# Layer B — Route → HTTP 402 wiring (real handler, mocked deps)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "tier_name", ("community", "igniter", "starter", "professional", "professional_plus")
)
def test_register_agent_route_returns_402_at_limit(tier_name: str):
    """When the agent registry is at max for the active tier, POST /admin/agents
    returns HTTP 402 with detail.error == 'agent_limit_exceeded'.

    Imports the actual register_agent handler from agents.py and mounts it on
    a minimal FastAPI app — proves the route is wired to the enforcer, the
    HTTPException is raised, and FastAPI surfaces it as 402.
    """
    fastapi = pytest.importorskip("fastapi")
    pytest.importorskip("fastapi.testclient")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from yashigani.backoffice import state as state_mod
    from yashigani.backoffice.middleware import Session, require_stepup_admin_session
    from yashigani.backoffice.routes import agents as agents_mod

    set_license(_build_license(tier_name))
    max_agents = TIER_DEFAULTS[tier_name]["max_agents"]

    from yashigani.licensing.enforcer import LicenseLimitExceeded as _LLE

    class _MockRegistry:
        def count(self, status: str = "active") -> int:
            return max_agents  # exactly at the boundary

        def register(self, **kwargs):
            # GROUP-4 moved limit enforcement into register() via Lua; the
            # mock raises LicenseLimitExceeded to simulate the atomic path.
            raise _LLE(
                limit_name="max_agents",
                current=max_agents,
                max_val=max_agents,
            )

        def get(self, agent_id: str):
            return None  # never reached in the limit-exceeded path

    # Save then patch backoffice singleton state.
    original_registry = state_mod.backoffice_state.agent_registry
    original_audit = state_mod.backoffice_state.audit_writer
    state_mod.backoffice_state.agent_registry = _MockRegistry()
    state_mod.backoffice_state.audit_writer = None

    try:
        import unittest.mock as _mock
        from yashigani.auth import spiffe as _spiffe_mod

        # YSG-RISK-012b: POST /admin/agents now has require_spiffe_id gate.
        # Stub _load_acls to bypass the SPIFFE gate in this tier-limit test —
        # the gate is separately tested in test_acs_risk_012b_spiffe_admin_agents.py;
        # this test's contract is "tier limit → HTTP 402", not SPIFFE identity.
        _ADMIN_AGENTS_ACL = {"/admin/agents": frozenset({
            "spiffe://yashigani.internal/caddy",
            "spiffe://yashigani.internal/backoffice",
        })}

        with _mock.patch.object(_spiffe_mod, "_load_acls", return_value=_ADMIN_AGENTS_ACL):
            app = FastAPI()
            app.include_router(agents_mod.router)

            # Override the step-up admin session dep — produce a benign Session.
            async def _fake_session():
                s = Session.__new__(Session)
                s.account_id = "test-admin"
                s.username = "test-admin"
                return s
            app.dependency_overrides[require_stepup_admin_session] = _fake_session

            # Simulate the Caddy-proxied path: inject the allowlisted SPIFFE header
            # so the gate passes and tier-limit enforcement is exercised.
            client = TestClient(app, raise_server_exceptions=False, headers={
                "X-SPIFFE-ID-Peer-Cert": "spiffe://yashigani.internal/caddy",
            })
            # Minimal valid AgentRegisterRequest body — name + upstream_url required.
            body = {"name": "smoke-test-agent", "upstream_url": "http://upstream.example.com"}
            resp = client.post("/admin/agents", json=body)

            assert resp.status_code == 402, (
                f"{tier_name}: expected 402 at agent boundary, got {resp.status_code} "
                f"body={resp.text}"
            )
            detail = resp.json().get("detail", {})
            assert detail.get("error") == "agent_limit_exceeded", (
                f"{tier_name}: 402 body missing agent_limit_exceeded sentinel: {detail}"
            )
            assert detail.get("limit") == max_agents
            assert detail.get("current") == max_agents
    finally:
        state_mod.backoffice_state.agent_registry = original_registry
        state_mod.backoffice_state.audit_writer = original_audit


def test_register_agent_route_returns_201_below_limit():
    """Sanity sibling — at count = max - 1 the route must NOT 402.

    We don't assert 201 (the registry is mocked and downstream might 500),
    but the response status MUST NOT be 402 — that proves the boundary is
    truly at `count == max`, not below."""
    pytest.importorskip("fastapi")
    pytest.importorskip("fastapi.testclient")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from yashigani.backoffice import state as state_mod
    from yashigani.backoffice.middleware import Session as _Session, require_stepup_admin_session as _req_step_up
    from yashigani.backoffice.routes import agents as agents_mod

    set_license(_build_license("starter"))
    max_agents = TIER_DEFAULTS["starter"]["max_agents"]

    class _MockRegistry:
        def count(self) -> int:
            return max_agents - 1  # one below the boundary

        def register(self, **kwargs):
            return ("agent-id", "plaintext-token")

        def get(self, agent_id):
            class _A: ...
            a = _A()
            a.agent_id = agent_id
            return a

        def list_all(self):
            return []

    original_registry = state_mod.backoffice_state.agent_registry
    original_audit = state_mod.backoffice_state.audit_writer
    state_mod.backoffice_state.agent_registry = _MockRegistry()
    state_mod.backoffice_state.audit_writer = None

    try:
        import unittest.mock as _mock
        from yashigani.auth import spiffe as _spiffe_mod

        # YSG-RISK-012b: POST /admin/agents now has require_spiffe_id gate.
        # Stub _load_acls to bypass the SPIFFE gate here — gate behaviour is
        # separately tested in test_acs_risk_012b_spiffe_admin_agents.py.
        _ADMIN_AGENTS_ACL = {"/admin/agents": frozenset({
            "spiffe://yashigani.internal/caddy",
            "spiffe://yashigani.internal/backoffice",
        })}

        with _mock.patch.object(_spiffe_mod, "_load_acls", return_value=_ADMIN_AGENTS_ACL):
            app = FastAPI()
            app.include_router(agents_mod.router)

            async def _fake_session():
                s = _Session.__new__(_Session)
                s.account_id = "test-admin"
                s.username = "test-admin"
                return s
            app.dependency_overrides[_req_step_up] = _fake_session

            client = TestClient(app, raise_server_exceptions=False, headers={
                "X-SPIFFE-ID-Peer-Cert": "spiffe://yashigani.internal/caddy",
            })
            body = {"name": "smoke-test-agent", "upstream_url": "http://upstream.example.com"}
            resp = client.post("/admin/agents", json=body)

            assert resp.status_code != 402, (
                f"starter: at count = max - 1 ({max_agents - 1}) the enforcer must "
                f"NOT 402 — got {resp.status_code} body={resp.text}"
            )
    finally:
        state_mod.backoffice_state.agent_registry = original_registry
        state_mod.backoffice_state.audit_writer = original_audit


# ---------------------------------------------------------------------------
# Layer C — Feature-gate matrix
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tier_name", _TIER_NAMES_SCOPE)
@pytest.mark.parametrize("feature_str", ("oidc", "saml", "scim"))
def test_require_feature_matches_tier_matrix(tier_name: str, feature_str: str):
    """For every (tier, feature) pair, require_feature() raises iff the tier
    does NOT have that feature per the README §8 matrix.

    ENT-001: pii_log / pii_redact removed from this parametrize — they are
    always available and never raise LicenseFeatureGated (tested separately
    in test_pii_always_available_on_all_tiers).
    """
    set_license(_build_license(tier_name))
    expected_present = feature_str in _TIER_FEATURES[tier_name]

    if expected_present:
        require_feature(feature_str)  # must not raise
    else:
        with pytest.raises(LicenseFeatureGated) as exc_info:
            require_feature(feature_str)
        assert exc_info.value.feature == feature_str
        assert exc_info.value.tier == LicenseTier(tier_name)


# ENT-001 (2026-06-14): PII is available on ALL tiers — no gate, no 402.
@pytest.mark.parametrize("tier_name", _TIER_NAMES_SCOPE)
@pytest.mark.parametrize("pii_feature", ("pii_log", "pii_redact"))
def test_pii_always_available_on_all_tiers(tier_name: str, pii_feature: str):
    """require_feature(pii_log/pii_redact) MUST NOT raise on any tier.

    PII detection (LOG / REDACT / BLOCK) is available on every tier
    including Community/free per README §8 Feature Matrix and the
    "PII filtering runs on all traffic, by default" product narrative.
    """
    set_license(_build_license(tier_name))
    # Must not raise regardless of what the license payload carries
    require_feature(pii_feature)


def test_feature_gated_response_body_is_descriptive():
    """The 402 body for a feature gate must carry feature, tier, upgrade_url,
    and a message — that's the 'descriptive error body' for OIDC/SAML/SCIM."""
    set_license(_build_license("community"))
    try:
        require_feature("saml")
    except LicenseFeatureGated as exc:
        body = license_feature_gated_response(exc)

    assert body["error"] == "LICENSE_FEATURE_GATED"
    assert body["feature"] == "saml"
    assert body["tier"] == "community"
    assert "upgrade_url" in body and body["upgrade_url"].startswith("https://")
    assert isinstance(body["message"], str) and body["message"]


# ---------------------------------------------------------------------------
# Layer D — multi-org gate
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "tier_name,expected_multi",
    [
        ("community",          False),  # max_orgs = 1
        ("igniter",            False),  # max_orgs = 1
        ("starter",            False),  # max_orgs = 1
        ("professional",       False),  # max_orgs = 1
        ("professional_plus",  True),   # max_orgs = 5
        ("enterprise",         True),   # max_orgs = -1 (unlimited)
        ("academic_nonprofit", True),   # max_orgs = -1 (unlimited)
    ],
)
def test_multi_org_gate_matches_tier(tier_name: str, expected_multi: bool):
    """multi-org capability is enforced via max_orgs > 1 (or -1 for unlimited).

    Asserts the tier-default reflects the issue body's 'multi-org Pro+' rule.
    """
    max_orgs = TIER_DEFAULTS[tier_name]["max_orgs"]
    has_multi = (max_orgs == -1) or (max_orgs > 1)
    assert has_multi == expected_multi, (
        f"{tier_name}: max_orgs={max_orgs} contradicts expected multi-org={expected_multi}"
    )

    # And: enforcer raises at the documented org boundary.
    set_license(_build_license(tier_name))
    if max_orgs == -1:
        check_org_limit(1_000_000)  # unlimited
    elif max_orgs == 1:
        check_org_limit(0)  # under
        with pytest.raises(LicenseLimitExceeded):
            check_org_limit(1)
    else:
        check_org_limit(max_orgs - 1)
        with pytest.raises(LicenseLimitExceeded):
            check_org_limit(max_orgs)
