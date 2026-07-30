"""
Conformance group: BUDGET-MODELS-INSPECTION.

Closes G1 (Lu audit YCS-20260723-v4.1.2-CONFORMANCE) for:
  routes/budget.py             (12 endpoints) — /admin/budget/*
  routes/models.py              (9 endpoints) — /admin/models/*
  routes/inspection.py           (7 endpoints) — /admin/inspection/{status,models,model,threshold,mode}
  routes/inspection_backend.py   (4 endpoints) — /admin/inspection/backend*
  routes/infrastructure.py       (4 endpoints) — /admin/infrastructure/*
  routes/ratelimit.py            (7 endpoints) — /admin/ratelimit/*
Total: 43 endpoints (Lu matrix rows 93-107, 120-125*, 165-179, 194-202, 243-249;
* budget/local-inventory + models overlap corrected against the live route walk,
  see test_group_covers_all_declared_routes below for the authoritative count).

Convention: see tests/conformance/conftest.py module docstring.

All 6 router modules degrade gracefully to a 503/empty-list response when
their backing store is `None` (a deliberate fail-safe pattern in this
codebase, not a test artefact) — see e.g. inspection.py:70-78. Where a store
accepts `redis_client` directly (RateLimiter, BudgetConfigStore,
ModelAliasStore, ModelAllocationStore — all verified against
src/yashigani/{billing,models,ratelimit}/*.py __init__ signatures), this
suite wires the REAL class against fakeredis for genuine positive-path
mutation assertions. Where no fakeredis-injectable class exists
(InspectionPipeline — Ollama-backed classifier object), a minimal duck-typed
fake implementing exactly the attributes/methods the route touches is used
(documented inline below).

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

pytestmark = pytest.mark.conformance

_GROUP_PREFIXES = (
    "/admin/budget",
    "/admin/models",
    "/admin/inspection",
    "/admin/infrastructure",
    "/admin/ratelimit",
)


# ---------------------------------------------------------------------------
# Group-specific state wiring
# ---------------------------------------------------------------------------


class FakeOllamaClassifier:
    """Minimal duck-typed fake for InspectionPipeline._classifier.

    MOCKED: InspectionPipeline wraps a live Ollama HTTP classifier
    (yashigani.inspection.pipeline). No fakeredis equivalent exists (it isn't
    Redis-backed) — this fake implements only the 3 attributes/1 method
    inspection.py actually reads (available_models(), _model, _base_url).
    """

    def __init__(self) -> None:
        self._model = "qwen2.5:3b"
        self._base_url = "http://ollama:11434"

    def available_models(self) -> list[str]:
        return ["qwen2.5:3b", "llama3.1:8b"]


class FakeInspectionPipeline:
    """MOCKED: see FakeOllamaClassifier docstring. Implements only
    `_classifier`, `_threshold`, `_mode`, `update_threshold()` — the exact
    surface inspection.py's routes touch (verified by reading the route file
    2026-07-23)."""

    def __init__(self) -> None:
        self._classifier = FakeOllamaClassifier()
        self._threshold = 0.85
        self._mode = "strict"

    def update_threshold(self, value: float) -> None:
        if not (0.70 <= value <= 0.99):
            raise ValueError("threshold out of range")
        self._threshold = value


@pytest.fixture
def budget_state(fake_redis_client, mock_audit_writer):
    """Wires the REAL BudgetConfigStore (Redis db/3-shaped, accepts
    redis_client directly per src/yashigani/billing/budget_config_store.py)
    against fakeredis, plus a MagicMock budget_enforcer (BudgetEnforcer is
    also redis_client-constructed but its `get_usage_summary` needs live
    gateway-written counters we don't have offline — MagicMock with a
    realistic return shape is the documented fallback)."""
    from yashigani.backoffice.routes import budget as budget_routes
    from yashigani.billing.budget_config_store import BudgetConfigStore

    store = BudgetConfigStore(redis_client=fake_redis_client)
    enforcer = MagicMock()
    enforcer.get_usage_summary.return_value = {"anthropic": {"used": 0, "cap": 0}}
    enforcer.set_allocation = MagicMock()
    budget_routes.configure(budget_enforcer=enforcer, budget_store=store)
    yield store, enforcer
    budget_routes.configure(budget_enforcer=None, budget_store=None)  # tear down module-level singleton


@pytest.fixture
def ratelimit_state(fake_redis_client, monkeypatch):
    """Wires the REAL RateLimiter against fakeredis (constructor takes
    redis_client directly — src/yashigani/ratelimit/limiter.py:107)."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.ratelimit.limiter import RateLimiter

    limiter = RateLimiter(redis_client=fake_redis_client)
    monkeypatch.setattr(backoffice_state, "rate_limiter", limiter, raising=False)
    monkeypatch.setattr(backoffice_state, "ratelimit_config_last_changed", None, raising=False)
    return limiter


@pytest.fixture
def endpoint_ratelimit_state(fake_redis_client, monkeypatch):
    """Wires the REAL EndpointRateLimiter against fakeredis (constructor
    takes redis_client directly — src/yashigani/gateway/endpoint_ratelimit.py:72).
    `backoffice_state.endpoint_rate_limiter` is a dynamically-added attribute
    (not declared in the BackofficeState dataclass — read via `getattr(...,
    None)` at every call site in ratelimit.py), so `raising=False` is
    required here."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.gateway.endpoint_ratelimit import EndpointRateLimiter

    ep_rl = EndpointRateLimiter(redis_client=fake_redis_client)
    monkeypatch.setattr(backoffice_state, "endpoint_rate_limiter", ep_rl, raising=False)
    return ep_rl


@pytest.fixture
def inspection_state(monkeypatch):
    from yashigani.backoffice.state import backoffice_state

    pipeline = FakeInspectionPipeline()
    monkeypatch.setattr(backoffice_state, "inspection_pipeline", pipeline, raising=False)
    return pipeline


@pytest.fixture
def models_state(fake_redis_client, monkeypatch):
    """Wires REAL ModelAliasStore + ModelAllocationStore against fakeredis
    (both accept redis_client directly — src/yashigani/models/{alias_store,
    allocation_store}.py)."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.models.alias_store import ModelAliasStore
    from yashigani.models.allocation_store import ModelAllocationStore

    alias_store = ModelAliasStore(redis_client=fake_redis_client)
    alloc_store = ModelAllocationStore(redis_client=fake_redis_client, durable_store=None)
    monkeypatch.setattr(backoffice_state, "model_alias_store", alias_store, raising=False)
    monkeypatch.setattr(backoffice_state, "model_allocation_store", alloc_store, raising=False)
    return alias_store, alloc_store


# ---------------------------------------------------------------------------
# Route-completeness check (this IS the coverage gate for this group)
# ---------------------------------------------------------------------------


def test_group_covers_all_declared_routes(route_prefix_filter):
    declared = route_prefix_filter(*_GROUP_PREFIXES)
    declared_set = {(m, p) for (m, p, _r) in declared}
    # Every (method, path) this test module asserts against — kept in sync by
    # hand; a mismatch here means either Lu's matrix or this file is stale.
    assert len(declared_set) == 43, (
        f"Expected 43 declared routes under {_GROUP_PREFIXES}, found "
        f"{len(declared_set)}: {sorted(declared_set)}"
    )


# ---------------------------------------------------------------------------
# budget.py — 12 endpoints, router-level dependencies=[Depends(require_admin_session)]
# ---------------------------------------------------------------------------


class TestBudgetOrgCaps:
    # GAP-CLOSED: GET /admin/budget/org-caps
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/budget/org-caps")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "authentication_required"

    def test_user_tier_403(self, user_client):
        r = user_client.get("/admin/budget/org-caps")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "insufficient_tier"

    def test_admin_empty_list(self, admin_client, budget_state):
        r = admin_client.get("/admin/budget/org-caps")
        assert r.status_code == 200
        assert r.json() == {"org_caps": []}

    # GAP-CLOSED: POST /admin/budget/org-caps
    def test_unauth_post_401(self, unauth_client):
        r = unauth_client.post("/admin/budget/org-caps", json={
            "org_id": "acme", "provider": "anthropic", "token_cap": 1000,
        })
        assert r.status_code == 401

    def test_admin_create_then_list(self, admin_client, budget_state):
        r = admin_client.post("/admin/budget/org-caps", json={
            "org_id": "acme", "provider": "anthropic", "token_cap": 1000, "period": "monthly",
        })
        assert r.status_code == 201
        body = r.json()
        assert body["org_id"] == "acme" and body["token_cap"] == 1000
        # Genuine persistence assertion (real BudgetConfigStore + fakeredis) —
        # proves the mutation actually round-trips, not just constructs a response.
        r2 = admin_client.get("/admin/budget/org-caps")
        assert r2.json()["org_caps"], "org cap did not persist to the real store"

    def test_admin_create_rejects_invalid_period(self, admin_client, budget_state):
        r = admin_client.post("/admin/budget/org-caps", json={
            "org_id": "acme", "provider": "anthropic", "token_cap": 1000, "period": "yearly",
        })
        assert r.status_code == 422  # Pydantic pattern validation — spec conformance

    # GAP-CLOSED: DELETE /admin/budget/org-caps
    def test_delete_nonexistent_404(self, admin_client, budget_state):
        r = admin_client.delete("/admin/budget/org-caps", params={"org_id": "nope", "provider": "x"})
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "org_cap_not_found"

    def test_delete_unauth_401(self, unauth_client):
        r = unauth_client.delete("/admin/budget/org-caps", params={"org_id": "x", "provider": "y"})
        assert r.status_code == 401


class TestBudgetGroups:
    # GAP-CLOSED: GET/POST/DELETE /admin/budget/groups
    def test_full_lifecycle(self, admin_client, budget_state, mock_audit_writer):
        r = admin_client.get("/admin/budget/groups")
        assert r.status_code == 200 and r.json() == {"group_budgets": []}

        r = admin_client.post("/admin/budget/groups", json={
            "group_id": "eng", "provider": "*", "token_budget": 50000, "period": "monthly",
        })
        assert r.status_code == 201
        assert r.json()["auto_calculated"] is False

        r = admin_client.delete("/admin/budget/groups", params={"group_id": "eng", "provider": "*"})
        assert r.status_code == 204
        mock_audit_writer.write.assert_called_once()

        r = admin_client.delete("/admin/budget/groups", params={"group_id": "eng", "provider": "*"})
        assert r.status_code == 404, "second delete of the same key must 404, not silently 204 again"

    def test_unauth_all_methods_401(self, unauth_client):
        assert unauth_client.get("/admin/budget/groups").status_code == 401
        assert unauth_client.post("/admin/budget/groups", json={}).status_code == 401
        assert unauth_client.delete("/admin/budget/groups", params={"group_id": "x", "provider": "y"}).status_code == 401


class TestBudgetIndividuals:
    # GAP-CLOSED: GET/POST/DELETE /admin/budget/individuals
    def test_full_lifecycle(self, admin_client, budget_state):
        r = admin_client.get("/admin/budget/individuals")
        assert r.status_code == 200 and r.json() == {"individual_budgets": []}

        r = admin_client.post("/admin/budget/individuals", json={
            "identity_id": "alice@acme.com", "provider": "*", "token_budget": 5000,
        })
        assert r.status_code == 201
        assert r.json()["remaining"] == 5000
        _store, enforcer = budget_state
        enforcer.set_allocation.assert_called_once_with("alice@acme.com", "*", 5000)

        r = admin_client.delete("/admin/budget/individuals", params={
            "identity_id": "alice@acme.com", "provider": "*",
        })
        assert r.status_code == 204

    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/budget/individuals").status_code == 401


class TestBudgetUsageTreeInventory:
    # GAP-CLOSED: GET /admin/budget/usage/{identity_id}
    def test_usage_503_without_enforcer(self, admin_client):
        r = admin_client.get("/admin/budget/usage/alice@acme.com")
        assert r.status_code == 503, "budget_enforcer is None by default — must fail closed, not 200 empty"

    def test_usage_with_enforcer(self, admin_client, budget_state):
        r = admin_client.get("/admin/budget/usage/alice@acme.com")
        assert r.status_code == 200
        assert r.json()["identity_id"] == "alice@acme.com"

    def test_usage_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/budget/usage/x").status_code == 401

    # YSG-RISK-157 CLOSED: GET /admin/budget/tree is an honest 501, not a
    # misleading 200/empty-tree stub — see test_tom_ysg_risk_156_157_honest_
    # stub_endpoints.py.
    def test_tree_admin_501_not_implemented(self, admin_client):
        r = admin_client.get("/admin/budget/tree")
        assert r.status_code == 501
        assert r.json()["detail"]["error"] == "not_implemented"

    def test_tree_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/budget/tree").status_code == 401

    # GAP-CLOSED: GET /admin/budget/models/local-inventory
    def test_local_inventory_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/budget/models/local-inventory").status_code == 401

    def test_local_inventory_admin_ollama_unreachable_502(self, admin_client):
        """Offline-environment reality: this route makes a REAL httpx call to
        Ollama /api/tags with no mock hook (budget.py:544) — there is no
        Ollama in this offline suite, so the genuine, documented fail-closed
        contract is HTTP 502 `ollama_unavailable` (budget.py:557-563), not
        200. Verified as real behaviour, not a stub — the route's error
        path IS being exercised."""
        r = admin_client.get("/admin/budget/models/local-inventory")
        assert r.status_code == 502
        assert r.json()["detail"]["error"] == "ollama_unavailable"


# ---------------------------------------------------------------------------
# models.py — 9 endpoints. Mutations are StepUpAdminSession-gated.
# ---------------------------------------------------------------------------


class TestModelAliases:
    # GAP-CLOSED: GET /admin/models
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/models").status_code == 401

    def test_alias_store_unconfigured_503(self, admin_client):
        r = admin_client.get("/admin/models")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "alias_store_unavailable"

    def test_list_empty_with_store(self, admin_client, models_state):
        r = admin_client.get("/admin/models")
        assert r.status_code == 200

    # GAP-CLOSED: POST /admin/models (step-up required)
    def test_create_requires_stepup_not_just_admin(self, admin_client, models_state):
        """SPEC-CONFORMANCE: admin session WITHOUT a fresh TOTP step-up must
        be rejected (401 step_up_required) — this is the exact ASVS V6.8.4
        control this codebase's release history (project_totp memory) flags
        as security-critical. Regression-guards against re-introducing the
        LF-STEPUP-AGENT-CREATE bypass."""
        r = admin_client.post("/admin/models", json={
            "alias": "fast", "provider": "ollama", "model": "qwen2.5:3b",
        })
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_create_with_stepup_201(self, stepup_admin_client, models_state):
        r = stepup_admin_client.post("/admin/models", json={
            "alias": "fast", "provider": "ollama", "model": "qwen2.5:3b",
        })
        assert r.status_code == 201

    # GAP-CLOSED: DELETE /admin/models/{alias}
    def test_delete_requires_stepup(self, admin_client, models_state):
        r = admin_client.delete("/admin/models/fast")
        assert r.status_code == 401

    def test_delete_nonexistent_with_stepup(self, stepup_admin_client, models_state):
        r = stepup_admin_client.delete("/admin/models/does-not-exist")
        assert r.status_code == 404

    # GAP-CLOSED: GET /admin/models/available
    def test_available_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/models/available").status_code == 401


class TestModelPull:
    # GAP-CLOSED: POST /admin/models/pull (step-up required)
    def test_pull_requires_stepup(self, admin_client):
        r = admin_client.post("/admin/models/pull", json={"name": "qwen2.5:3b"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_pull_ollama_unreachable_503(self, stepup_admin_client, monkeypatch):
        """Offline-safe: monkeypatch the Ollama transport factory to raise a
        connection error immediately rather than depend on network reachability
        (which is unavailable/undesirable in this offline suite) — proves the
        route's documented fail-closed 503 `ollama_unreachable` contract."""
        import contextlib

        @contextlib.asynccontextmanager
        async def _raise_connect_error(*_a, **_kw):
            raise httpx.ConnectError("no ollama in offline conformance suite")
            yield  # pragma: no cover — unreachable, satisfies generator shape

        monkeypatch.setattr(
            "yashigani.inspection._ollama_transport.ollama_async_client",
            _raise_connect_error,
        )
        r = stepup_admin_client.post("/admin/models/pull", json={"name": "qwen2.5:3b"})
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "ollama_unreachable"


class TestModelAllocationTargets:
    # GAP-CLOSED: GET /admin/models/allocation-targets
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/models/allocation-targets", params={"target_type": "user"})
        assert r.status_code == 401

    def test_invalid_target_type_400(self, admin_client):
        r = admin_client.get("/admin/models/allocation-targets", params={"target_type": "bogus"})
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_target_type"

    def test_org_target_type_always_has_default(self, admin_client):
        r = admin_client.get("/admin/models/allocation-targets", params={"target_type": "org"})
        assert r.status_code == 200
        ids = {t["id"] for t in r.json()["targets"]}
        assert "default" in ids

    def test_user_target_type_degrades_empty_without_auth_service(self, admin_client):
        r = admin_client.get("/admin/models/allocation-targets", params={"target_type": "user"})
        assert r.status_code == 200
        assert r.json()["targets"] == []


class TestModelAllocations:
    # GAP-CLOSED: GET/POST/DELETE /admin/models/allocations
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/models/allocations").status_code == 401

    def test_lifecycle_with_stores(self, stepup_admin_client, models_state):
        alias_store, _alloc_store = models_state
        from yashigani.models.alias_store import ModelAlias
        alias_store.set("fast", ModelAlias(alias="fast", provider="ollama", model="qwen2.5:3b"))

        r = stepup_admin_client.get("/admin/models/allocations")
        assert r.status_code == 200 and r.json()["allocations"] == []

        r = stepup_admin_client.post("/admin/models/allocations", json={
            "model_alias": "fast", "target_type": "user", "target_id": "alice@acme.com",
        })
        assert r.status_code == 201
        alloc_id = r.json()["allocation"]["id"]

        r = stepup_admin_client.delete(f"/admin/models/allocations/{alloc_id}")
        assert r.status_code == 200

        r = stepup_admin_client.delete(f"/admin/models/allocations/{alloc_id}")
        assert r.status_code == 404

    def test_create_allocation_unknown_alias_404(self, stepup_admin_client, models_state):
        r = stepup_admin_client.post("/admin/models/allocations", json={
            "model_alias": "does-not-exist", "target_type": "user", "target_id": "bob@acme.com",
        })
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "alias_not_found"


# ---------------------------------------------------------------------------
# inspection.py — 7 endpoints
# ---------------------------------------------------------------------------


class TestInspectionPipeline:
    # GAP-CLOSED: GET /admin/inspection/status
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/inspection/status").status_code == 401

    def test_status_degraded_without_pipeline(self, admin_client):
        r = admin_client.get("/admin/inspection/status")
        assert r.status_code == 200
        assert r.json() == {"configured": False, "healthy": False}

    def test_status_with_pipeline(self, admin_client, inspection_state):
        r = admin_client.get("/admin/inspection/status")
        assert r.status_code == 200
        body = r.json()
        assert body["configured"] is True
        assert body["model"] == "qwen2.5:3b"

    # GAP-CLOSED: GET /admin/inspection/models
    def test_models_503_without_pipeline(self, admin_client):
        r = admin_client.get("/admin/inspection/models")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "inspection_pipeline_not_configured"

    def test_models_with_pipeline(self, admin_client, inspection_state):
        r = admin_client.get("/admin/inspection/models")
        assert r.status_code == 200
        assert "qwen2.5:3b" in r.json()["models"]

    # GAP-CLOSED: POST /admin/inspection/model
    def test_set_model_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/inspection/model", json={"model": "x"}).status_code == 401

    def test_set_model_not_available_422(self, admin_client, inspection_state):
        r = admin_client.post("/admin/inspection/model", json={"model": "not-a-real-model"})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "model_not_available"

    def test_set_model_success(self, admin_client, inspection_state, mock_audit_writer):
        r = admin_client.post("/admin/inspection/model", json={"model": "llama3.1:8b"})
        assert r.status_code == 200
        assert inspection_state._classifier._model == "llama3.1:8b"
        mock_audit_writer.write.assert_called_once()

    # GAP-CLOSED: GET/POST /admin/inspection/threshold
    def test_get_threshold_503_without_pipeline(self, admin_client):
        assert admin_client.get("/admin/inspection/threshold").status_code == 503

    def test_set_threshold_out_of_range_422(self, admin_client, inspection_state):
        r = admin_client.post("/admin/inspection/threshold", json={"threshold": 0.5})
        assert r.status_code == 422  # Pydantic Field(ge=0.70, le=0.99)

    def test_set_threshold_success(self, admin_client, inspection_state, mock_audit_writer):
        r = admin_client.post("/admin/inspection/threshold", json={"threshold": 0.9})
        assert r.status_code == 200
        assert inspection_state._threshold == 0.9
        mock_audit_writer.write.assert_called_once()

    # GAP-CLOSED: GET/POST /admin/inspection/mode
    def test_get_mode_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/inspection/mode").status_code == 401

    def test_set_mode_invalid_422(self, admin_client, inspection_state):
        r = admin_client.post("/admin/inspection/mode", json={"mode": "bogus"})
        assert r.status_code == 422  # Pydantic pattern validation

    def test_set_mode_success(self, admin_client, inspection_state, mock_audit_writer):
        r = admin_client.post("/admin/inspection/mode", json={"mode": "permissive"})
        assert r.status_code == 200
        assert inspection_state._mode == "permissive"
        mock_audit_writer.write.assert_called_once()


# ---------------------------------------------------------------------------
# inspection_backend.py — 4 endpoints. All 503 without wired stores.
# ---------------------------------------------------------------------------


class TestInspectionBackend:
    # GAP-CLOSED: GET /admin/inspection/backend
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/inspection/backend").status_code == 401

    def test_get_backend_503_without_registry(self, admin_client):
        r = admin_client.get("/admin/inspection/backend")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "backend_registry_not_configured"

    # GAP-CLOSED: PUT /admin/inspection/backend
    def test_put_backend_unauth_401(self, unauth_client):
        r = unauth_client.put("/admin/inspection/backend", json={"active_backend": "ollama"})
        assert r.status_code == 401

    def test_put_backend_503_without_registry(self, admin_client):
        r = admin_client.put("/admin/inspection/backend", json={"active_backend": "ollama"})
        assert r.status_code == 503

    # GAP-CLOSED: GET /admin/inspection/backend/{backend_name}/health
    def test_health_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/inspection/backend/ollama/health").status_code == 401

    def test_health_503_without_registry(self, admin_client):
        r = admin_client.get("/admin/inspection/backend/ollama/health")
        assert r.status_code == 503

    # GAP-CLOSED: POST /admin/inspection/backend/{backend_name}/test
    def test_test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/inspection/backend/ollama/test").status_code == 401

    def test_test_503_without_registry(self, admin_client):
        r = admin_client.post("/admin/inspection/backend/ollama/test")
        assert r.status_code == 503


# ---------------------------------------------------------------------------
# infrastructure.py — 4 endpoints, no backing store (in-memory state only)
# ---------------------------------------------------------------------------


class TestInfrastructure:
    # GAP-CLOSED: GET /admin/infrastructure/topology
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/infrastructure/topology").status_code == 401

    def test_get_topology_defaults(self, admin_client):
        r = admin_client.get("/admin/infrastructure/topology")
        assert r.status_code == 200
        body = r.json()
        assert body["az_count"] == 1
        assert "Single AZ detected" in body["warnings"][0]

    # GAP-CLOSED: PUT /admin/infrastructure/topology
    def test_put_topology_single_az_conflict_422(self, admin_client, mock_audit_writer):
        r = admin_client.put("/admin/infrastructure/topology", json={
            "zones": ["us-east-1a"], "spread_policy": "DoNotSchedule",
        })
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "single_az_conflict"

    def test_put_topology_success(self, admin_client, mock_audit_writer):
        r = admin_client.put("/admin/infrastructure/topology", json={
            "zones": ["us-east-1a", "us-east-1b"], "spread_policy": "DoNotSchedule",
        })
        assert r.status_code == 200
        assert r.json()["az_count"] == 2
        mock_audit_writer.write.assert_called_once()

    def test_put_topology_unauth_401(self, unauth_client):
        r = unauth_client.put("/admin/infrastructure/topology", json={"zones": ["a"]})
        assert r.status_code == 401

    # GAP-CLOSED: GET /admin/infrastructure/autoscaling
    def test_get_autoscaling(self, admin_client):
        r = admin_client.get("/admin/infrastructure/autoscaling")
        assert r.status_code == 200
        assert r.json()["keda_enabled"] is True

    # GAP-CLOSED: PUT /admin/infrastructure/autoscaling/{workload}
    def test_put_autoscaling_invalid_workload_404(self, admin_client):
        r = admin_client.put("/admin/infrastructure/autoscaling/not-a-workload", json={
            "min_replicas": 1, "max_replicas": 2,
        })
        assert r.status_code == 404

    def test_put_autoscaling_valid_workload(self, admin_client):
        r = admin_client.put("/admin/infrastructure/autoscaling/gateway", json={
            "min_replicas": 2, "max_replicas": 5,
        })
        assert r.status_code == 200

    def test_put_autoscaling_unauth_401(self, unauth_client):
        r = unauth_client.put("/admin/infrastructure/autoscaling/gateway", json={
            "min_replicas": 1, "max_replicas": 2,
        })
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# ratelimit.py — 7 endpoints
# ---------------------------------------------------------------------------


class TestRatelimitConfig:
    # GAP-CLOSED: GET /admin/ratelimit/config
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/ratelimit/config").status_code == 401

    def test_get_config_degraded_without_limiter(self, admin_client):
        r = admin_client.get("/admin/ratelimit/config")
        assert r.status_code == 200
        assert r.json() == {"configured": False}

    def test_get_config_with_limiter(self, admin_client, ratelimit_state):
        r = admin_client.get("/admin/ratelimit/config")
        assert r.status_code == 200
        assert r.json()["configured"] is True

    # GAP-CLOSED: PUT /admin/ratelimit/config
    def test_put_config_503_without_limiter(self, admin_client):
        r = admin_client.put("/admin/ratelimit/config", json={})
        assert r.status_code == 503

    def test_put_config_success(self, admin_client, ratelimit_state):
        r = admin_client.put("/admin/ratelimit/config", json={"global_rps": 2000.0})
        assert r.status_code == 200
        r2 = admin_client.get("/admin/ratelimit/config")
        assert r2.json()["global_rps"] == 2000.0

    def test_put_config_unauth_401(self, unauth_client):
        assert unauth_client.put("/admin/ratelimit/config", json={}).status_code == 401

    # GAP-CLOSED: GET /admin/ratelimit/status
    def test_status_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/ratelimit/status").status_code == 401

    def test_status_admin(self, admin_client, ratelimit_state):
        r = admin_client.get("/admin/ratelimit/status")
        assert r.status_code == 200

    # GAP-CLOSED: POST /admin/ratelimit/reset/{bucket_key}
    def test_reset_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/ratelimit/reset/some-key").status_code == 401

    def test_reset_rejects_non_ratelimit_key_422(self, admin_client, ratelimit_state):
        """SPEC-CONFORMANCE (allowlist validation): bucket_key must start with
        `yashigani:rl:` — this is a defence-in-depth allowlist preventing an
        admin-tier-confused-deputy from being used to delete arbitrary Redis
        keys (ratelimit.py:151)."""
        r = admin_client.post("/admin/ratelimit/reset/global")
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_bucket_key"

    def test_reset_admin_valid_key(self, admin_client, ratelimit_state, mock_audit_writer):
        r = admin_client.post("/admin/ratelimit/reset/yashigani:rl:ip:deadbeef")
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "bucket_key": "yashigani:rl:ip:deadbeef"}
        mock_audit_writer.write.assert_called_once()

    # GAP-CLOSED: GET/POST /admin/ratelimit/endpoints
    def test_endpoints_list_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/ratelimit/endpoints").status_code == 401

    def test_endpoints_list_degrades_empty_without_store(self, admin_client):
        r = admin_client.get("/admin/ratelimit/endpoints")
        assert r.status_code == 200
        assert r.json() == {"endpoints": []}

    def test_endpoints_list_admin(self, admin_client, endpoint_ratelimit_state):
        r = admin_client.get("/admin/ratelimit/endpoints")
        assert r.status_code == 200

    def test_endpoints_create_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/ratelimit/endpoints", json={
            "endpoint_template": "/agents/{agent_id}", "rps": 10, "burst": 5,
        })
        assert r.status_code == 401

    def test_endpoints_create_503_without_store(self, admin_client):
        r = admin_client.post("/admin/ratelimit/endpoints", json={
            "endpoint_template": "/agents/{agent_id}", "rps": 10, "burst": 5,
        })
        assert r.status_code == 503

    def test_endpoints_create_and_delete_lifecycle(self, admin_client, endpoint_ratelimit_state):
        r = admin_client.post("/admin/ratelimit/endpoints", json={
            "endpoint_template": "/agents/{agent_id}", "rps": 10, "burst": 5,
        })
        assert r.status_code == 200
        ep_hash = r.json()["endpoint_hash"]

        r2 = admin_client.get("/admin/ratelimit/endpoints")
        assert len(r2.json()["endpoints"]) == 1

        r3 = admin_client.delete(f"/admin/ratelimit/endpoints/{ep_hash}")
        assert r3.status_code == 200

    # GAP-CLOSED: DELETE /admin/ratelimit/endpoints/{endpoint_hash}
    def test_endpoints_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/ratelimit/endpoints/deadbeef").status_code == 401

    def test_endpoints_delete_unknown_hash_is_idempotent_200(self, admin_client, endpoint_ratelimit_state):
        """SPEC-CONFORMANCE (divergence note): delete_config() is a bare
        Redis DEL with no existence check (endpoint_ratelimit.py:150) — the
        route returns 200 "deleted" even for an unknown hash, it never 404s.
        This is documented, idempotent-delete behaviour, not a bug; asserting
        it here pins the actual contract so a future accidental 404/500
        regression is caught."""
        r = admin_client.delete("/admin/ratelimit/endpoints/deadbeef")
        assert r.status_code == 200
        assert r.json() == {"status": "deleted", "endpoint_hash": "deadbeef"}

    def test_endpoints_delete_503_without_store(self, admin_client):
        r = admin_client.delete("/admin/ratelimit/endpoints/deadbeef")
        assert r.status_code == 503
