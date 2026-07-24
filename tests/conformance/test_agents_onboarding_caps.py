"""
Conformance group: AGENTS-ONBOARDING-CAPS.

Closes G1 (Lu audit YCS-20260723-v4.1.2-CONFORMANCE) for:
  routes/agents.py           (10 endpoints) — /admin/agents/*, /admin/identities, /admin/nhi/*
  routes/agent_bundles.py     (2 endpoints) — /admin/agent-bundles/*
  routes/agent_policies.py    (5 endpoints) — /admin/agent-policies/*
  routes/permissions.py       (8 endpoints) — /admin/api/permissions/*
  routes/capability_policy.py (12 endpoints) — /admin/api/capability-policy/*
Total: 37 endpoints (Lu matrix rows 32-41, 25-26, 27-31, 210-217, 108-119 —
verified against the live route walk in test_group_covers_all_declared_routes,
which is authoritative over the matrix per the dispatch brief).

Convention: see tests/conformance/conftest.py module docstring.

Store wiring
------------
  agent_registry_state       — REAL AgentRegistry(redis_client=...) (fakeredis-
                                injectable, src/yashigani/agents/registry.py:98).
  identity_registry_state    — REAL IdentityRegistry(redis_client=...) (fakeredis-
                                injectable, src/yashigani/identity/registry.py:152).
  capability_policy_state    — REAL CapabilityPolicyStore(redis_client=...)
                                (src/yashigani/capability_policy/store.py:55).
                                This ALSO backs permissions.py — _get_perm_store()
                                resolves backoffice_state.capability_policy_store
                                .perm_store (a thin adapter property exposing the
                                same PermissionStore instance), so one fixture
                                wires both router files' real stores.
  mcp_registry_store_state   — REAL DurableMcpRegistryStore(redis_client) for
                                agent_policies.py (src/yashigani/mcp/_durable_registry.py:92).
                                backoffice_state.mcp_registry_store is NOT a
                                declared dataclass field (dynamic getattr(...,
                                None) read site) so raising=False is required.
  spiffe_acl                 — monkeypatches yashigani.auth.spiffe._load_acls
                                directly. This is an explicitly documented test
                                hook (see that module's docstring: "the bare
                                frozenset shape is retained for back-compat
                                (tests and any caller that monkeypatches
                                _load_acls with {path: frozenset(ids)})") — NOT
                                a bypass of the real control. Without this
                                fixture, require_spiffe_id-gated routes are
                                fail-closed 403 no_acl_for_path because no
                                service_identities.yaml manifest exists on the
                                test host — see TestAgentsRegister.test_no_acl_
                                403_without_wired_acl_is_fail_closed_by_default
                                for an explicit assertion of that real,
                                undoctored default behaviour.

MOCKED: PKI/CA material (mint_agent_leaf, live intermediate CA) is NOT
fakeredis-backed and has no offline equivalent — every route that would mint a
real cert (POST /admin/nhi/{id}/approve, POST /admin/agents/{id}/cert/rotate)
is asserted against its documented FAIL-CLOSED contract (502 svid_issuance_
failed / 403 identity_not_provisioned) rather than mocked to a fake success,
per the module's own "BUG-A" fail-closed design (mint before approve; svid_
issued is never set without a real cert on disk).

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

import fakeredis
import pytest

pytestmark = pytest.mark.conformance

_GROUP_PREFIXES = (
    "/admin/agents",
    "/admin/agent-bundles",
    "/admin/agent-policies",
    "/admin/api/permissions",
    "/admin/api/capability-policy",
    "/admin/identities",
    "/admin/nhi",
)

# ---------------------------------------------------------------------------
# SPIFFE test identities (see spiffe_acl fixture docstring below)
# ---------------------------------------------------------------------------

_SPIFFE_BACKOFFICE = "spiffe://yashigani.internal/backoffice"
_SPIFFE_AGENT_PREFIX = "spiffe://yashigani.internal/agents/"
_SPIFFE_OPENCLAW_AGENT = "spiffe://yashigani.internal/agents/default/openclaw"
_SPIFFE_HDR = {"X-Spiffe-Id": _SPIFFE_BACKOFFICE}


_TEST_UPSTREAM_HOST = "agent-test.internal"


@pytest.fixture(autouse=True)
def _agent_upstream_allowlist(monkeypatch):
    """agents.py's upstream_url SSRF guard (_ssrf.py) does a REAL DNS
    resolution and rejects unresolvable hosts (CWE-918 / LAURA-300-001) —
    correct fail-closed behaviour, but this suite runs OFFLINE (conftest.py
    module docstring) and cannot rely on real DNS resolving a test hostname.
    Using the guard's own documented operator opt-in
    (YASHIGANI_AGENT_UPSTREAM_HOSTNAMES) — the SAME mechanism a real operator
    uses for internal Docker-mesh agents — bypasses only the IP-category
    check for this one test hostname, exactly as designed."""
    monkeypatch.setenv("YASHIGANI_AGENT_UPSTREAM_HOSTNAMES", _TEST_UPSTREAM_HOST)


def test_group_covers_all_declared_routes(route_prefix_filter):
    declared = route_prefix_filter(*_GROUP_PREFIXES)
    declared_set = {(m, p) for (m, p, _r) in declared}
    assert len(declared_set) == 37, (
        f"Expected 37 declared routes under {_GROUP_PREFIXES}, found "
        f"{len(declared_set)}: {sorted(declared_set)}"
    )


# ---------------------------------------------------------------------------
# Group-specific state wiring
# ---------------------------------------------------------------------------


@pytest.fixture
def spiffe_acl(monkeypatch):
    """Wire a fixed SPIFFE ACL table for require_spiffe_id-gated routes in
    this group: /admin/agents (register/update/deactivate/token-rotate),
    /admin/agent-policies (apply/adjust/revoke), and the cert/rotate
    per-instance ACL path.

    Grants _SPIFFE_BACKOFFICE exact access to the two admin-plane paths, and
    an agent-namespace prefix grant (verify_spiffe_matches_agent_id=True) for
    cert/rotate — mirroring the real service_identities.yaml shape
    (src/yashigani/pki/identity.py EndpointAcl).
    """
    from yashigani.auth import spiffe as spiffe_mod
    from yashigani.pki.identity import EndpointAcl

    acls = {
        "/admin/agents": frozenset({_SPIFFE_BACKOFFICE}),
        "/admin/agent-policies": frozenset({_SPIFFE_BACKOFFICE}),
        "/admin/agents/*/cert/rotate": EndpointAcl(
            allowed_spiffe_ids=frozenset({_SPIFFE_BACKOFFICE}),
            allowed_spiffe_prefix=_SPIFFE_AGENT_PREFIX,
            verify_spiffe_matches_agent_id=True,
        ),
    }
    monkeypatch.setattr(spiffe_mod, "_load_acls", lambda: acls)
    return acls


@pytest.fixture
def raw_redis_client():
    """A fresh fakeredis client with decode_responses=False.

    Every production construction site for AgentRegistry, IdentityRegistry,
    CapabilityPolicyStore, and DurableMcpRegistryStore uses
    ``redis.from_url(..., decode_responses=False)`` on a SHARED db/3 instance
    (verified: src/yashigani/backoffice/entrypoint.py:212,704;
    src/yashigani/gateway/entrypoint.py:200,211-215,951). AgentRegistry/
    IdentityRegistry's ``_decode_agent``/``_decode`` helpers hardcode BYTES
    keys (``raw.get(b"name", b"")``) — verified empirically 2026-07-23:
    constructing AgentRegistry against the shared ``fake_redis_client``
    fixture (decode_responses=True, used elsewhere in this suite for
    SessionStore) silently returns EMPTY defaults for every field
    (name='', status='', kind='' instead of 'nhi') because ``hgetall()``
    returns str keys that never match the ``b"..."`` lookups. This is a
    fixture-wiring hazard, not a product bug — this suite's clients must
    match the real decode_responses=False wiring exactly."""
    client = fakeredis.FakeRedis(decode_responses=False)
    yield client
    client.flushall()


@pytest.fixture
def agent_registry_state(raw_redis_client, monkeypatch):
    """Wires the REAL AgentRegistry against fakeredis (constructor takes
    redis_client directly — src/yashigani/agents/registry.py:98)."""
    from yashigani.agents.registry import AgentRegistry
    from yashigani.backoffice.state import backoffice_state

    registry = AgentRegistry(redis_client=raw_redis_client)
    monkeypatch.setattr(backoffice_state, "agent_registry", registry, raising=False)
    return registry


@pytest.fixture
def identity_registry_state(raw_redis_client, monkeypatch):
    """Wires the REAL IdentityRegistry against fakeredis (constructor takes
    redis_client directly — src/yashigani/identity/registry.py:152)."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.identity.registry import IdentityRegistry

    registry = IdentityRegistry(redis_client=raw_redis_client)
    monkeypatch.setattr(backoffice_state, "identity_registry", registry, raising=False)
    return registry


@pytest.fixture
def capability_policy_state(raw_redis_client, monkeypatch):
    """Wires the REAL CapabilityPolicyStore against fakeredis (constructor
    takes redis_client directly — src/yashigani/capability_policy/store.py:55).

    This backs BOTH capability_policy.py AND permissions.py routes:
    permissions.py's _get_perm_store() reads backoffice_state
    .capability_policy_store.perm_store, a property exposing the SAME
    PermissionStore instance the adapter wraps internally.
    """
    from yashigani.backoffice.state import backoffice_state
    from yashigani.capability_policy.store import CapabilityPolicyStore

    store = CapabilityPolicyStore(redis_client=raw_redis_client)
    monkeypatch.setattr(backoffice_state, "capability_policy_store", store, raising=False)
    return store


@pytest.fixture
def mcp_registry_store_state(raw_redis_client, monkeypatch):
    """Wires the REAL DurableMcpRegistryStore against fakeredis (constructor
    takes a bare redis_client — src/yashigani/mcp/_durable_registry.py:92) for
    agent_policies.py. backoffice_state.mcp_registry_store is a dynamically-
    read attribute (getattr(..., None) at the call site, not a declared
    dataclass field), so raising=False is required (mirrors the
    endpoint_rate_limiter pattern in test_budget_models_inspection.py)."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.mcp._durable_registry import DurableMcpRegistryStore

    store = DurableMcpRegistryStore(raw_redis_client)
    monkeypatch.setattr(backoffice_state, "mcp_registry_store", store, raising=False)
    return store


# ---------------------------------------------------------------------------
# agents.py — GET/POST /admin/agents
# ---------------------------------------------------------------------------


class TestAgentsList:
    # GAP-CLOSED: GET /admin/agents
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/agents")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "authentication_required"

    def test_user_tier_403(self, user_client):
        r = user_client.get("/admin/agents")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "insufficient_tier"

    def test_admin_503_without_registry(self, admin_client):
        r = admin_client.get("/admin/agents")
        assert r.status_code == 503

    def test_admin_empty_list_with_registry(self, admin_client, agent_registry_state):
        r = admin_client.get("/admin/agents")
        assert r.status_code == 200
        assert r.json() == []


class TestAgentsRegister:
    # GAP-CLOSED: POST /admin/agents
    def test_unauth_401(self, unauth_client, spiffe_acl):
        r = unauth_client.post(
            "/admin/agents",
            json={"name": "svc1", "upstream_url": "https://agent-test.internal/svc1"},
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 401

    def test_admin_without_stepup_401(self, admin_client, spiffe_acl, agent_registry_state):
        r = admin_client.post(
            "/admin/agents",
            json={"name": "svc1", "upstream_url": "https://agent-test.internal/svc1"},
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_no_acl_403_without_wired_acl_is_fail_closed_by_default(
        self, stepup_admin_client, agent_registry_state,
    ):
        """SPEC-CONFORMANCE (real, undoctored default): no service_identities
        .yaml manifest exists on the test host, so yashigani.auth.spiffe's
        module-level ACL cache fails closed to {} on first load (agents.py:
        974, spiffe.py _load_acls). Even with a fresh step-up admin session
        AND a syntactically-valid X-Spiffe-Id header, register_agent 403s —
        proving the ACL gate is genuinely fail-closed-by-default, not merely
        fail-closed when a hostile header is presented."""
        r = stepup_admin_client.post(
            "/admin/agents",
            json={"name": "svc1", "upstream_url": "https://agent-test.internal/svc1"},
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 403
        assert r.json()["detail"] == "no_acl_for_path"

    def test_stepup_admin_register_201(
        self, stepup_admin_client, spiffe_acl, agent_registry_state, mock_audit_writer,
    ):
        r = stepup_admin_client.post(
            "/admin/agents",
            json={"name": "svc1", "upstream_url": "https://agent-test.internal/svc1"},
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 201
        body = r.json()
        assert body["name"] == "svc1"
        assert body["token"], "plaintext PSK must be returned once on register"
        mock_audit_writer.write.assert_called_once()
        # Genuine persistence assertion (real AgentRegistry + fakeredis).
        r2 = stepup_admin_client.get(f"/admin/agents/{body['agent_id']}")
        assert r2.status_code == 200

    def test_register_rejects_stored_xss_in_name_422(
        self, stepup_admin_client, spiffe_acl, agent_registry_state,
    ):
        """SPEC-CONFORMANCE (AVA-2026-04-29-001 / CWE-79): the name pattern
        constraint alone would already reject '<script>' (lowercase-slug
        pattern), but this pins the dedicated HTML-tag/protocol-URI
        field_validator's error path too — both fire 422."""
        r = stepup_admin_client.post(
            "/admin/agents",
            json={"name": "javascript:alert(1)", "upstream_url": "https://x.example.com"},
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 422

    def test_register_requires_upstream_url_or_pool_image_422(
        self, stepup_admin_client, spiffe_acl, agent_registry_state,
    ):
        r = stepup_admin_client.post(
            "/admin/agents", json={"name": "svc2"}, headers=_SPIFFE_HDR,
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "upstream_url_required"


class TestAgentGet:
    # GAP-CLOSED: GET /admin/agents/{agent_id}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/agents/agnt_x").status_code == 401

    def test_admin_404_unknown(self, admin_client, agent_registry_state):
        r = admin_client.get("/admin/agents/agnt_doesnotexist")
        assert r.status_code == 404

    def test_admin_200_after_register(self, admin_client, agent_registry_state):
        agent_id, _token = agent_registry_state.register(
            name="svc3", upstream_url="https://agent-test.internal/svc3",
            groups=[], allowed_caller_groups=[], allowed_paths=[],
        )
        r = admin_client.get(f"/admin/agents/{agent_id}")
        assert r.status_code == 200
        assert r.json()["agent_id"] == agent_id


class TestAgentUpdate:
    # GAP-CLOSED: PUT /admin/agents/{agent_id}
    def test_unauth_401(self, unauth_client, spiffe_acl):
        r = unauth_client.put(
            "/admin/agents/agnt_x", json={"name": "renamed"}, headers=_SPIFFE_HDR,
        )
        assert r.status_code == 401

    def test_admin_without_stepup_401(self, admin_client, spiffe_acl, agent_registry_state):
        r = admin_client.put(
            "/admin/agents/agnt_x", json={"name": "renamed"}, headers=_SPIFFE_HDR,
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_update_unknown_404(self, stepup_admin_client, spiffe_acl, agent_registry_state):
        r = stepup_admin_client.put(
            "/admin/agents/agnt_doesnotexist", json={"name": "renamed"}, headers=_SPIFFE_HDR,
        )
        assert r.status_code == 404

    def test_update_success_persists(
        self, stepup_admin_client, spiffe_acl, agent_registry_state, mock_audit_writer,
    ):
        agent_id, _token = agent_registry_state.register(
            name="svc4", upstream_url="https://agent-test.internal/svc4",
            groups=[], allowed_caller_groups=[], allowed_paths=[],
        )
        r = stepup_admin_client.put(
            f"/admin/agents/{agent_id}",
            json={"name": "svc4renamed"},
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 200
        assert r.json()["name"] == "svc4renamed"
        mock_audit_writer.write.assert_called_once()


class TestAgentDeactivate:
    # GAP-CLOSED: DELETE /admin/agents/{agent_id}
    def test_unauth_401(self, unauth_client, spiffe_acl):
        r = unauth_client.delete("/admin/agents/agnt_x", headers=_SPIFFE_HDR)
        assert r.status_code == 401

    def test_deactivate_unknown_404(self, stepup_admin_client, spiffe_acl, agent_registry_state):
        r = stepup_admin_client.delete("/admin/agents/agnt_doesnotexist", headers=_SPIFFE_HDR)
        assert r.status_code == 404

    def test_deactivate_success_then_409_on_repeat(
        self, stepup_admin_client, spiffe_acl, agent_registry_state, mock_audit_writer,
    ):
        agent_id, _token = agent_registry_state.register(
            name="svc5", upstream_url="https://agent-test.internal/svc5",
            groups=[], allowed_caller_groups=[], allowed_paths=[],
        )
        r = stepup_admin_client.delete(f"/admin/agents/{agent_id}", headers=_SPIFFE_HDR)
        assert r.status_code == 204
        mock_audit_writer.write.assert_called_once()

        r2 = stepup_admin_client.delete(f"/admin/agents/{agent_id}", headers=_SPIFFE_HDR)
        assert r2.status_code == 409


class TestAgentTokenRotate:
    # GAP-CLOSED: POST /admin/agents/{agent_id}/token/rotate
    def test_unauth_401(self, unauth_client, spiffe_acl):
        r = unauth_client.post("/admin/agents/agnt_x/token/rotate", headers=_SPIFFE_HDR)
        assert r.status_code == 401

    def test_rotate_unknown_404(self, stepup_admin_client, spiffe_acl, agent_registry_state):
        r = stepup_admin_client.post(
            "/admin/agents/agnt_doesnotexist/token/rotate", headers=_SPIFFE_HDR,
        )
        assert r.status_code == 404

    def test_rotate_success_returns_new_token(
        self, stepup_admin_client, spiffe_acl, agent_registry_state, mock_audit_writer,
    ):
        agent_id, original_token = agent_registry_state.register(
            name="svc6", upstream_url="https://agent-test.internal/svc6",
            groups=[], allowed_caller_groups=[], allowed_paths=[],
        )
        r = stepup_admin_client.post(
            f"/admin/agents/{agent_id}/token/rotate", headers=_SPIFFE_HDR,
        )
        assert r.status_code == 200
        new_token = r.json()["token"]
        assert new_token and new_token != original_token
        mock_audit_writer.write.assert_called_once()


class TestAgentCertRotate:
    """POST /admin/agents/{agent_id}/cert/rotate — no admin session; identity
    is the presented client cert's SPIFFE URI (Nico Q1). MOCKED: no live PKI/
    CA on disk in this offline suite, so every path beyond the ACL gate itself
    resolves to the documented fail-closed 403 (identity_not_provisioned) —
    asserted explicitly rather than mocking mint_agent_leaf to a fake success.
    """

    # GAP-CLOSED: POST /admin/agents/{agent_id}/cert/rotate
    def test_no_spiffe_header_401(self, unauth_client, spiffe_acl):
        r = unauth_client.post("/admin/agents/openclaw/cert/rotate")
        assert r.status_code == 401
        assert r.json()["detail"] == "no_spiffe_id"

    def test_non_agent_caller_403_requires_agent_identity(self, unauth_client, spiffe_acl):
        """Caller matches the ACL's EXACT allowlist (_SPIFFE_BACKOFFICE) but is
        not under the agents/ namespace — the route's own business logic
        (parse_agent_spiffe_uri returns None) rejects it: only an agent's own
        svid-sidecar identity may rotate its cert (agents.py:1073-1083)."""
        r = unauth_client.post(
            "/admin/agents/openclaw/cert/rotate", headers=_SPIFFE_HDR,
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "cert_rotate_requires_agent_identity"

    def test_cross_agent_rotation_denied_at_acl_gate(self, unauth_client, spiffe_acl):
        """BOLA-class assertion: an agent presenting its OWN valid SPIFFE
        (agent_name='openclaw') must NOT be able to rotate a DIFFERENT
        agent's cert by putting a different {agent_id} in the path — the ACL
        gate itself (verify_spiffe_matches_agent_id=True) rejects the
        mismatch BEFORE the route body runs (spiffe.py:356-370)."""
        r = unauth_client.post(
            "/admin/agents/some-other-agent/cert/rotate",
            headers={"X-Spiffe-Id": _SPIFFE_OPENCLAW_AGENT},
        )
        assert r.status_code == 403
        # NOTE: spiffe.py raises this HTTPException with a bare string detail
        # (detail="spiffe_id_agent_mismatch"), NOT a {"error": ...} dict shape
        # like every other 40x in this gate — verified spiffe.py:367-370.
        assert r.json()["detail"] == "spiffe_id_agent_mismatch"

    def test_own_agent_identity_clears_acl_but_fails_closed_no_manifest(
        self, unauth_client, spiffe_acl,
    ):
        """Caller's own agent SPIFFE + matching path {agent_id} clears the ACL
        gate (prefix + agent-id match). Beyond the gate, no runtime identity
        manifest exists on the test host (no PKI provisioning offline) —
        _runtime_manifest_agent_entry returns None and the route fails closed
        403 identity_not_provisioned (agents.py:1091-1099), rather than
        silently minting/accepting an unprovisioned identity."""
        r = unauth_client.post(
            "/admin/agents/openclaw/cert/rotate",
            headers={"X-Spiffe-Id": _SPIFFE_OPENCLAW_AGENT},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "identity_not_provisioned"


class TestAgentQuickstart:
    # GAP-CLOSED: GET /admin/agents/{agent_id}/quickstart
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/agents/agnt_x/quickstart").status_code == 401

    def test_admin_404_unknown(self, admin_client, agent_registry_state):
        r = admin_client.get("/admin/agents/agnt_doesnotexist/quickstart")
        assert r.status_code == 404

    def test_admin_200_after_register(self, admin_client, agent_registry_state):
        agent_id, _token = agent_registry_state.register(
            name="svc7", upstream_url="https://agent-test.internal/svc7",
            groups=[], allowed_caller_groups=[], allowed_paths=[],
        )
        r = admin_client.get(f"/admin/agents/{agent_id}/quickstart")
        assert r.status_code == 200
        assert r.json()["agent_id"] == agent_id
        assert "<your-token>" in r.json()["quick_start"]["curl"]


class TestIdentities:
    # GAP-CLOSED: GET /admin/identities
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/identities").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/identities").status_code == 403

    def test_admin_503_without_identity_registry(self, admin_client):
        r = admin_client.get("/admin/identities")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "identity_registry_unavailable"

    def test_admin_200_lists_human_identity(self, admin_client, identity_registry_state):
        from yashigani.identity.registry import IdentityKind

        identity_registry_state.register(
            kind=IdentityKind.HUMAN, name="Alice", slug="alice",
        )
        r = admin_client.get("/admin/identities")
        assert r.status_code == 200
        names = {i["name"] for i in r.json()}
        assert "Alice" in names

    def test_invalid_kind_filter_422(self, admin_client, identity_registry_state):
        r = admin_client.get("/admin/identities", params={"kind": "bogus"})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_kind"


class TestNhiApprove:
    """POST /admin/nhi/{nhi_id}/approve — MOCKED: no live PKI/CA on disk, so
    the genuine offline contract is the BUG-A fail-closed 502 path (mint
    BEFORE approve; svid_issued never set without a real cert on disk).
    """

    # GAP-CLOSED: POST /admin/nhi/{nhi_id}/approve
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/nhi/nhi_x/approve").status_code == 401

    def test_unknown_nhi_404(self, stepup_admin_client, agent_registry_state):
        r = stepup_admin_client.post("/admin/nhi/nhi_doesnotexist/approve")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "nhi_not_found"

    def test_non_nhi_kind_404(self, stepup_admin_client, agent_registry_state):
        agent_id, _token = agent_registry_state.register(
            name="svc8", upstream_url="https://agent-test.internal/svc8",
            groups=[], allowed_caller_groups=[], allowed_paths=[],
        )
        r = stepup_admin_client.post(f"/admin/nhi/{agent_id}/approve")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "not_an_nhi"

    def test_real_nhi_502_svid_issuance_failed_offline(
        self, stepup_admin_client, agent_registry_state, mock_audit_writer,
    ):
        """SPEC-CONFORMANCE (BUG-A fail-closed, v4.1 Phase 0): mint_agent_leaf
        requires a live internal CA (secrets_dir/ca_intermediate.*) that does
        not exist in this offline suite. The route's documented contract is
        to ABORT the approval (502 svid_issuance_failed) and leave svid_issued
        unset — never claim an issued SVID with no cert on disk. This is the
        real, exercised fail path, not a stub."""
        nhi_id, _token = agent_registry_state.register_nhi(
            name="nhi1", owner_identity_id="tenant1", template_id="tmpl-1",
            allowed_tools=[], allowed_paths=[], allowed_models=[],
            sensitivity_ceiling="PUBLIC", budget_cap={},
        )
        r = stepup_admin_client.post(f"/admin/nhi/{nhi_id}/approve")
        assert r.status_code == 502
        assert r.json()["detail"]["error"] == "svid_issuance_failed"
        mock_audit_writer.write.assert_called_once()


# ---------------------------------------------------------------------------
# agent_bundles.py — 2 endpoints (static catalogue, AdminSession only)
# ---------------------------------------------------------------------------


class TestAgentBundles:
    # GAP-CLOSED: GET /admin/agent-bundles/
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/agent-bundles/").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/agent-bundles/").status_code == 403

    def test_admin_200_lists_bundles(self, admin_client):
        r = admin_client.get("/admin/agent-bundles/")
        assert r.status_code == 200
        body = r.json()
        ids = {b["id"] for b in body["bundles"]}
        assert {"langflow", "letta", "openclaw"} <= ids
        assert body["disclaimer"]

    # GAP-CLOSED: GET /admin/agent-bundles/disclaimer
    def test_disclaimer_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/agent-bundles/disclaimer").status_code == 401

    def test_disclaimer_admin_200(self, admin_client):
        r = admin_client.get("/admin/agent-bundles/disclaimer")
        assert r.status_code == 200
        assert "AS IS" in r.json()["disclaimer"]


# ---------------------------------------------------------------------------
# agent_policies.py — 5 endpoints
# ---------------------------------------------------------------------------


class TestAgentPoliciesTemplates:
    # GAP-CLOSED: GET /admin/agent-policies/templates
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/agent-policies/templates").status_code == 401

    def test_admin_200_lists_shipped_templates(self, admin_client):
        r = admin_client.get("/admin/agent-policies/templates")
        assert r.status_code == 200
        tmpl_ids = {t["template_id"] for t in r.json()}
        assert "tmpl-openclaw-default" in tmpl_ids

    # GAP-CLOSED: GET /admin/agent-policies/status
    def test_status_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/agent-policies/status").status_code == 401

    def test_status_admin_200_with_store(self, admin_client, mcp_registry_store_state):
        r = admin_client.get("/admin/agent-policies/status")
        assert r.status_code == 200
        systems = {row["system_id"] for row in r.json()}
        assert {"openclaw", "langflow", "letta"} <= systems


class TestAgentPoliciesApply:
    # GAP-CLOSED: POST /admin/agent-policies/{tenant}/{system}/apply
    def test_unauth_401(self, unauth_client, spiffe_acl):
        r = unauth_client.post(
            "/admin/agent-policies/default/openclaw/apply",
            json={"template_id": "tmpl-openclaw-default"},
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 401

    def test_admin_without_stepup_401(
        self, admin_client, spiffe_acl, mcp_registry_store_state,
    ):
        r = admin_client.post(
            "/admin/agent-policies/default/openclaw/apply",
            json={"template_id": "tmpl-openclaw-default"},
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_wrong_tenant_403_tenant_scope_violation(
        self, stepup_admin_client, spiffe_acl, mcp_registry_store_state,
    ):
        """Laura F8 tenant-scope authz: path {tenant} must equal the
        configured installation tenant ("default" when YASHIGANI_TENANT_ID is
        unset). This IS the applicable cross-scope (BOLA-class) gate for this
        route set — verified it holds, not merely assumed."""
        r = stepup_admin_client.post(
            "/admin/agent-policies/some-other-tenant/openclaw/apply",
            json={"template_id": "tmpl-openclaw-default"},
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "tenant_scope_violation"

    def test_apply_shipped_template_200_grants_mode_a_prefixes_only(
        self, stepup_admin_client, spiffe_acl, mcp_registry_store_state, mock_audit_writer,
    ):
        """Genuine positive path against the REAL DurableMcpRegistryStore +
        the REAL shipped tmpl-openclaw-default.yaml (bundles/policy-templates/).
        Asserts Mode-B (slack, connect) is excluded from granted_prefixes even
        though it is present in the template — it is enabled:false + Track-2-
        only in Track 1 (agent_policies.py _run_apply step 3)."""
        r = stepup_admin_client.post(
            "/admin/agent-policies/default/openclaw/apply",
            json={"template_id": "tmpl-openclaw-default"},
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "applied"
        assert body["granted_prefixes"] == ["llm", "telegram"]
        assert mock_audit_writer.write.call_count == 2  # grant-written + template-applied

    def test_apply_unknown_template_404(
        self, stepup_admin_client, spiffe_acl, mcp_registry_store_state,
    ):
        r = stepup_admin_client.post(
            "/admin/agent-policies/default/openclaw/apply",
            json={"template_id": "tmpl-does-not-exist"},
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "template_not_found"

    def test_apply_rejects_free_form_connect_hosts_override_422(
        self, stepup_admin_client, spiffe_acl, mcp_registry_store_state,
    ):
        """Laura F2: connect_hosts is perimeter-owned immutable data — Pydantic
        validator rejects it in overrides before the route body even runs."""
        r = stepup_admin_client.post(
            "/admin/agent-policies/default/openclaw/apply",
            json={
                "template_id": "tmpl-openclaw-default",
                "overrides": {"connect_hosts": ["evil.example.com:443"]},
            },
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 422


class TestAgentPoliciesAdjust:
    # GAP-CLOSED: POST /admin/agent-policies/{tenant}/{system}/adjust
    def test_unauth_401(self, unauth_client, spiffe_acl):
        r = unauth_client.post(
            "/admin/agent-policies/default/openclaw/adjust",
            json={"template_id": "tmpl-openclaw-default"},
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 401

    def test_adjust_reapplies_200(
        self, stepup_admin_client, spiffe_acl, mcp_registry_store_state, mock_audit_writer,
    ):
        r = stepup_admin_client.post(
            "/admin/agent-policies/default/openclaw/adjust",
            json={"template_id": "tmpl-openclaw-default"},
            headers=_SPIFFE_HDR,
        )
        assert r.status_code == 200
        assert r.json()["status"] == "applied"


class TestAgentPoliciesRevoke:
    # GAP-CLOSED: DELETE /admin/agent-policies/{tenant}/{system}/grant
    def test_unauth_401(self, unauth_client, spiffe_acl):
        r = unauth_client.delete(
            "/admin/agent-policies/default/openclaw/grant", headers=_SPIFFE_HDR,
        )
        assert r.status_code == 401

    def test_wrong_tenant_403(self, stepup_admin_client, spiffe_acl, mcp_registry_store_state):
        r = stepup_admin_client.delete(
            "/admin/agent-policies/some-other-tenant/openclaw/grant", headers=_SPIFFE_HDR,
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "tenant_scope_violation"

    def test_revoke_fails_closed_503_no_live_opa(
        self, stepup_admin_client, spiffe_acl, mcp_registry_store_state,
    ):
        """SPEC-CONFORMANCE (Lu R1 HARD GATE): revoke_grant uses
        push_and_verify_egress_grants with must_be_absent — a real readback-
        verified push. No live OPA exists in this offline suite, so the
        genuine, documented fail-closed contract is 503 revoke_push_failed
        (agent_policies.py:962-980), NOT a silent 200. This is the exact
        fail-closed behaviour Lu's R1 gate exists to guarantee — plain
        push_egress_grants (no verify) would be the regression this proves
        is NOT present."""
        r = stepup_admin_client.delete(
            "/admin/agent-policies/default/openclaw/grant", headers=_SPIFFE_HDR,
        )
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "revoke_push_failed"


# ---------------------------------------------------------------------------
# permissions.py — 8 endpoints (Unified Permission Grant admin API)
# ---------------------------------------------------------------------------


class TestPermissionsGrantsList:
    # GAP-CLOSED: GET /admin/api/permissions/grants/{scope}/{scope_id}/{resource_type}
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/api/permissions/grants/org/default/mcp_server")
        assert r.status_code == 401

    def test_user_tier_403(self, user_client):
        r = user_client.get("/admin/api/permissions/grants/org/default/mcp_server")
        assert r.status_code == 403

    def test_admin_503_without_store(self, admin_client):
        r = admin_client.get("/admin/api/permissions/grants/org/default/mcp_server")
        assert r.status_code == 503

    def test_invalid_scope_422(self, admin_client, capability_policy_state):
        r = admin_client.get("/admin/api/permissions/grants/bogus-scope/default/mcp_server")
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_scope"

    def test_invalid_resource_type_422(self, admin_client, capability_policy_state):
        r = admin_client.get("/admin/api/permissions/grants/org/default/bogus_type")
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_resource_type"

    def test_admin_empty_list_with_store(self, admin_client, capability_policy_state):
        r = admin_client.get("/admin/api/permissions/grants/org/default/mcp_server")
        assert r.status_code == 200
        assert r.json()["grants"] == []


class TestPermissionsGrantsPutDelete:
    # GAP-CLOSED: PUT /admin/api/permissions/grants/{scope}/{scope_id}/{resource_type}/{resource_id}
    def test_put_unauth_401(self, unauth_client):
        r = unauth_client.put(
            "/admin/api/permissions/grants/org/default/mcp_server/srv1",
            json={"allow": True},
        )
        assert r.status_code == 401

    def test_put_admin_without_stepup_401(self, admin_client, capability_policy_state):
        r = admin_client.put(
            "/admin/api/permissions/grants/org/default/mcp_server/srv1",
            json={"allow": True},
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_put_cloud_model_allow_without_opa_ref_422_inv2(
        self, stepup_admin_client, capability_policy_state,
    ):
        """INV-2: cloud_model allow=True MUST carry opa_policy_ref."""
        r = stepup_admin_client.put(
            "/admin/api/permissions/grants/org/default/cloud_model/gpt4o",
            json={"allow": True},
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "inv2_opa_policy_ref_required"

    def test_put_browser_capability_rejected_here(
        self, stepup_admin_client, capability_policy_state,
    ):
        r = stepup_admin_client.put(
            "/admin/api/permissions/grants/org/default/browser_capability/camera",
            json={"allow": True},
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "browser_capability_not_supported_here"

    def test_put_lifecycle_then_delete(
        self, stepup_admin_client, capability_policy_state, mock_audit_writer,
    ):
        r = stepup_admin_client.put(
            "/admin/api/permissions/grants/org/default/mcp_server/srv1",
            json={"allow": True},
        )
        assert r.status_code == 200
        assert r.json()["allow"] is True
        mock_audit_writer.write.assert_called_once()

        # Genuine persistence via the real PermissionStore + fakeredis.
        r2 = stepup_admin_client.get("/admin/api/permissions/grants/org/default/mcp_server")
        assert r2.json()["grants"] == [{"resource_id": "srv1", "allow": True, "opa_policy_ref": None}]

        # GAP-CLOSED: DELETE /admin/api/permissions/grants/{scope}/{scope_id}/{resource_type}/{resource_id}
        r3 = stepup_admin_client.delete(
            "/admin/api/permissions/grants/org/default/mcp_server/srv1",
        )
        assert r3.status_code == 204

    def test_delete_unauth_401(self, unauth_client):
        r = unauth_client.delete("/admin/api/permissions/grants/org/default/mcp_server/srv1")
        assert r.status_code == 401


class TestPermissionsEffective:
    # GAP-CLOSED: GET /admin/api/permissions/effective
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get(
            "/admin/api/permissions/effective",
            params={"resource_type": "mcp_server", "resource_id": "srv1"},
        )
        assert r.status_code == 401

    def test_deny_by_default_no_org_grant(self, admin_client, capability_policy_state):
        """INV-1: no org grant -> effective_allow False, even though this is
        an admin-tier caller (deny-by-default is a data invariant, not an
        authz check)."""
        r = admin_client.get(
            "/admin/api/permissions/effective",
            params={"resource_type": "mcp_server", "resource_id": "srv1", "org_id": "default"},
        )
        assert r.status_code == 200
        assert r.json()["effective_allow"] is False

    def test_org_ceiling_group_narrows(self, admin_client, capability_policy_state):
        """INV-3 (org is the ceiling; group can only narrow): org allows,
        group explicitly denies -> effective False."""
        store = capability_policy_state.perm_store
        from yashigani.permissions.model import BooleanGrantValue, ResourceType

        store.set_boolean_grant(
            ResourceType.MCP_SERVER, "org", "default", "srv1", BooleanGrantValue(allow=True),
        )
        store.set_boolean_grant(
            ResourceType.MCP_SERVER, "group", "eng", "srv1", BooleanGrantValue(allow=False),
        )
        r = admin_client.get(
            "/admin/api/permissions/effective",
            params={
                "resource_type": "mcp_server", "resource_id": "srv1",
                "org_id": "default", "group_ids": "eng",
            },
        )
        assert r.status_code == 200
        assert r.json()["effective_allow"] is False


class TestPermissionsDeclarations:
    # GAP-CLOSED: GET /admin/api/permissions/declarations
    def test_list_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/api/permissions/declarations").status_code == 401

    def test_list_admin_empty(self, admin_client, capability_policy_state):
        r = admin_client.get("/admin/api/permissions/declarations")
        assert r.status_code == 200
        assert r.json() == {"pending": [], "count": 0}

    # GAP-CLOSED: POST /admin/api/permissions/declarations
    def test_create_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/api/permissions/declarations",
            json={
                "resource_type": "mcp_server", "resource_id": "srv2",
                "declared_by": "agent:svc1",
            },
        )
        assert r.status_code == 401

    def test_create_declaration_201_no_stepup_required(
        self, admin_client, capability_policy_state,
    ):
        """create_declaration only requires AdminSession (not step-up) — the
        weaken-class control is the APPROVE step, not the declare step."""
        r = admin_client.post(
            "/admin/api/permissions/declarations",
            json={
                "resource_type": "mcp_server", "resource_id": "srv2",
                "declared_by": "agent:svc1", "justification": "needed for X",
            },
        )
        assert r.status_code == 201
        assert r.json()["status"] == "pending"

        r2 = admin_client.get("/admin/api/permissions/declarations")
        assert r2.json()["count"] == 1

    def test_create_declaration_invalid_resource_type_422(
        self, admin_client, capability_policy_state,
    ):
        r = admin_client.post(
            "/admin/api/permissions/declarations",
            json={
                "resource_type": "bogus_type", "resource_id": "srv2",
                "declared_by": "agent:svc1",
            },
        )
        assert r.status_code == 422

    # GAP-CLOSED: POST /admin/api/permissions/declarations/{resource_type}/{resource_id}/approve
    # GAP-CLOSED: DELETE /admin/api/permissions/declarations/{resource_type}/{resource_id}
    def test_approve_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/api/permissions/declarations/mcp_server/srv2/approve", json={},
        )
        assert r.status_code == 401

    def test_reject_unauth_401(self, unauth_client):
        r = unauth_client.delete("/admin/api/permissions/declarations/mcp_server/srv2")
        assert r.status_code == 401

    def test_MAKER_CHECKER_FINDING_same_admin_session_declares_and_approves(
        self, admin_client, stepup_admin_client, capability_policy_state, mock_audit_writer,
    ):
        """FINDING (maker-checker gap, permissions.py:39,627-744): approve_
        declaration is StepUpAdminSession-gated (a fresh TOTP re-verification)
        but there is NO distinct-approver check anywhere in create_declaration
        or approve_declaration — declared_by is a free-form string with no
        binding to any session/account_id, and approve_declaration never
        compares session.account_id against the declaration's declared_by nor
        requires a DIFFERENT admin account than the one that declared it.

        This test proves the SAME admin account (conformance-admin-stepup,
        via the stepup_admin_client fixture) can submit a declaration on its
        own behalf ('declared_by': its own account id) and then, in the very
        next call with the same session, approve it — a true one-person
        declare-then-approve round trip with no maker-checker separation.
        Contrast with the dp_weaken-style two-person control referenced in
        the dispatch brief: no equivalent distinct-approver enforcement
        exists here. This is DIFFERENT from the tenant-scope check in
        agent_policies.py (which IS enforced) — reported here as a genuine,
        unmitigated gap, not softened to a passing assertion."""
        own_account = "conformance-admin-stepup"
        r_declare = stepup_admin_client.post(
            "/admin/api/permissions/declarations",
            json={
                "resource_type": "external_api", "resource_id": "api.example.com",
                "declared_by": own_account, "justification": "self-declared by the approver",
            },
        )
        assert r_declare.status_code == 201

        # Same session approves its own declaration — no distinct-approver
        # check anywhere in the code path rejects this.
        r_approve = stepup_admin_client.post(
            "/admin/api/permissions/declarations/external_api/api.example.com/approve",
            json={"allow": True},
        )
        assert r_approve.status_code == 200, (
            "MAKER-CHECKER GAP CONFIRMED: the same admin session that declared "
            "the resource was able to approve its own declaration — approve_"
            "declaration only requires StepUpAdminSession (fresh TOTP), never "
            "a distinct approver identity. If this assertion ever starts "
            "failing because a distinct-approver check was added, update this "
            "test to assert the (now fixed) 403 instead."
        )
        assert r_approve.json()["approved"] is True
        assert r_approve.json()["actor"] == own_account


# ---------------------------------------------------------------------------
# capability_policy.py — 12 endpoints
# ---------------------------------------------------------------------------

_FULL_CAP_BODY = {
    "camera": {"value": "off", "allow_list": []},
    "microphone": {"value": "off", "allow_list": []},
    "geolocation": {"value": "self", "allow_list": []},
    "display-capture": {"value": "off", "allow_list": []},
    "fullscreen": {"value": "self", "allow_list": []},
}


class TestCapabilityPolicyOrgDefault:
    # GAP-CLOSED: GET /admin/api/capability-policy
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/api/capability-policy").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/api/capability-policy").status_code == 403

    def test_admin_503_without_store(self, admin_client):
        r = admin_client.get("/admin/api/capability-policy")
        assert r.status_code == 503

    def test_admin_200_baseline_default(self, admin_client, capability_policy_state):
        r = admin_client.get("/admin/api/capability-policy")
        assert r.status_code == 200
        assert set(r.json()["org"].keys()) == {
            "camera", "microphone", "geolocation", "display-capture", "fullscreen",
        }

    # GAP-CLOSED: PUT /admin/api/capability-policy
    def test_put_unauth_401(self, unauth_client):
        r = unauth_client.put("/admin/api/capability-policy", json=_FULL_CAP_BODY)
        assert r.status_code == 401

    def test_put_requires_all_five_422(self, admin_client, capability_policy_state):
        r = admin_client.put(
            "/admin/api/capability-policy", json={"camera": {"value": "off", "allow_list": []}},
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_capability_policy"

    def test_put_full_policy_200_persists(
        self, admin_client, capability_policy_state, mock_audit_writer,
    ):
        r = admin_client.put("/admin/api/capability-policy", json=_FULL_CAP_BODY)
        assert r.status_code == 200
        assert r.json()["org"]["camera"]["value"] == "off"
        mock_audit_writer.write.assert_called_once()

        r2 = admin_client.get("/admin/api/capability-policy")
        assert r2.json()["org"]["camera"]["value"] == "off"


class TestCapabilityPolicyOrgById:
    # GAP-CLOSED: GET/PUT/DELETE /admin/api/capability-policy/orgs/{org_id}
    def test_get_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/api/capability-policy/orgs/acme").status_code == 401

    def test_get_admin_200_baseline(self, admin_client, capability_policy_state):
        r = admin_client.get("/admin/api/capability-policy/orgs/acme")
        assert r.status_code == 200
        assert r.json()["org_id"] == "acme"

    def test_put_unauth_401(self, unauth_client):
        r = unauth_client.put("/admin/api/capability-policy/orgs/acme", json=_FULL_CAP_BODY)
        assert r.status_code == 401

    def test_put_then_delete_falls_back_to_baseline(
        self, admin_client, capability_policy_state, mock_audit_writer,
    ):
        r = admin_client.put("/admin/api/capability-policy/orgs/acme", json=_FULL_CAP_BODY)
        assert r.status_code == 200

        r2 = admin_client.delete("/admin/api/capability-policy/orgs/acme")
        assert r2.status_code == 204

        r3 = admin_client.get("/admin/api/capability-policy/orgs/acme")
        assert r3.json()["org"]["fullscreen"]["value"] == "self"  # baseline default

    def test_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/api/capability-policy/orgs/acme").status_code == 401


class TestCapabilityPolicyGroupOverride:
    # GAP-CLOSED: GET/PUT/DELETE /admin/api/capability-policy/groups/{group_id}
    def test_get_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/api/capability-policy/groups/eng").status_code == 401

    def test_get_empty_override(self, admin_client, capability_policy_state):
        r = admin_client.get("/admin/api/capability-policy/groups/eng")
        assert r.status_code == 200
        assert r.json()["overrides"] == {}

    def test_put_unauth_401(self, unauth_client):
        r = unauth_client.put(
            "/admin/api/capability-policy/groups/eng",
            json={"camera": {"value": "off", "allow_list": []}},
        )
        assert r.status_code == 401

    def test_put_empty_body_422(self, admin_client, capability_policy_state):
        r = admin_client.put("/admin/api/capability-policy/groups/eng", json={})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "empty_policy"

    def test_put_partial_then_delete(
        self, admin_client, capability_policy_state, mock_audit_writer,
    ):
        r = admin_client.put(
            "/admin/api/capability-policy/groups/eng",
            json={"camera": {"value": "off", "allow_list": []}},
        )
        assert r.status_code == 200
        assert r.json()["overrides"] == {"camera": {"value": "off", "allow_list": []}}

        r2 = admin_client.delete("/admin/api/capability-policy/groups/eng")
        assert r2.status_code == 204

        r3 = admin_client.get("/admin/api/capability-policy/groups/eng")
        assert r3.json()["overrides"] == {}

    def test_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/api/capability-policy/groups/eng").status_code == 401


class TestCapabilityPolicyUserOverride:
    """GET/PUT/DELETE /admin/api/capability-policy/users/{user} — this is the
    ADMIN configuration surface (any admin may set ANY user's browser-
    capability override by design; it is not a self-service /me endpoint), so
    there is no cross-user BOLA boundary to prove here — the applicable
    cross-scope control in this group is agent_policies.py's tenant-scope
    check (see TestAgentPoliciesApply.test_wrong_tenant_403_tenant_scope_
    violation), which IS enforced."""

    # GAP-CLOSED: GET/PUT/DELETE /admin/api/capability-policy/users/{user}
    def test_get_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/api/capability-policy/users/alice@acme.com")
        assert r.status_code == 401

    def test_put_unauth_401(self, unauth_client):
        r = unauth_client.put(
            "/admin/api/capability-policy/users/alice@acme.com",
            json={"camera": {"value": "off", "allow_list": []}},
        )
        assert r.status_code == 401

    def test_admin_can_set_any_users_override_by_design(
        self, admin_client, capability_policy_state, mock_audit_writer,
    ):
        r = admin_client.put(
            "/admin/api/capability-policy/users/alice@acme.com",
            json={"microphone": {"value": "off", "allow_list": []}},
        )
        assert r.status_code == 200

        r2 = admin_client.get("/admin/api/capability-policy/users/alice@acme.com")
        assert r2.json()["overrides"] == {"microphone": {"value": "off", "allow_list": []}}

        r3 = admin_client.delete("/admin/api/capability-policy/users/alice@acme.com")
        assert r3.status_code == 204

    def test_delete_unauth_401(self, unauth_client):
        r = unauth_client.delete("/admin/api/capability-policy/users/alice@acme.com")
        assert r.status_code == 401


class TestCapabilityPolicyEffective:
    # GAP-CLOSED: GET /admin/api/capability-policy/effective
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get(
            "/admin/api/capability-policy/effective", params={"user": "alice@acme.com"},
        )
        assert r.status_code == 401

    def test_user_narrowing_cannot_widen_org_ceiling(
        self, admin_client, capability_policy_state,
    ):
        """ORG IS THE CEILING (resolve_browser_capability_set): org sets
        camera=self; user override attempts camera=allow_list (WIDER) — the
        effective value must stay the more-restrictive org setting."""
        admin_client.put(
            "/admin/api/capability-policy",
            json={
                **_FULL_CAP_BODY,
                "camera": {"value": "self", "allow_list": []},
            },
        )
        admin_client.put(
            "/admin/api/capability-policy/users/alice@acme.com",
            json={"camera": {"value": "allow_list", "allow_list": ["https://x.example.com"]}},
        )
        r = admin_client.get(
            "/admin/api/capability-policy/effective", params={"user": "alice@acme.com"},
        )
        assert r.status_code == 200
        assert r.json()["effective"]["camera"]["value"] == "self"
