"""
Conformance group: OPA-POLICY.

Closes G1 (Lu audit YCS-20260723-v4.1.2-CONFORMANCE) for:
  routes/policies.py             (16 endpoints) — /admin/policies/*
  routes/opa_assistant.py         (7 endpoints) — /admin/opa-assistant/*
  routes/envelope_reapproval.py   (4 endpoints) — /admin/mcp/envelopes/pending*
Total: 27 endpoints (Lu matrix rows 227-242 policies, 203-209 opa_assistant,
157-160 envelope_reapproval).

Also closes G3 (Lu audit): PUT /admin/policies/core/{policy_id} previously had
only the pre-commit 401 (StepUp-missing) proven by Laura — the actual
conforming mutation (stepped-up admin edits core policy, change lands) was
never exercised. See TestCorePolicyEditStepUp below — the isolated positive
test proves the mutation reaches the (fake) OPA backend AND that a plain
admin session (no step-up) is rejected before ever reaching the handler body.

Convention: see tests/conformance/conftest.py module docstring.

OPA wiring notes:
  policies.py imports `internal_httpx_client` at MODULE TOP (bound once at
  import time), so mocking it requires patching
  `yashigani.backoffice.routes.policies.internal_httpx_client` directly.
  opa_assistant.py / opa_assistant/sanity.py / opa_assistant/rego_validator.py
  all re-import `internal_httpx_client` LAZILY (`from yashigani.pki.client
  import internal_httpx_client` inside the function body) on every call, so
  patching `yashigani.pki.client.internal_httpx_client` (the source module)
  is sufficient for those call sites. The `fake_opa` fixture below patches
  BOTH locations with the SAME in-memory backend so a PUT that lands via one
  path (e.g. a sanity-check sandbox PUT) and a PUT that lands via the other
  (e.g. policies.py's own direct core-policy PUT) share one consistent view
  of "what's loaded in OPA" — this is what makes the G3 mutation-landed
  assertion meaningful rather than trivially true.

  Real httpx.Response objects are returned (not MagicMocks) so `.json()`,
  `.status_code`, `.raise_for_status()` all behave exactly as the real
  httpx client would — verified against httpx installed in this venv.

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

from typing import Self
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

pytestmark = pytest.mark.conformance

_GROUP_PREFIXES = (
    "/admin/policies",
    "/admin/opa-assistant",
    "/admin/mcp/envelopes",
)


# ---------------------------------------------------------------------------
# Fake in-memory OPA REST backend (PUT/GET/DELETE /v1/policies/*,
# POST /v1/data/*) — shared by policies.py's module-top-bound client AND the
# lazy-imported clients in sanity.py / rego_validator.py / opa_assistant.py.
# ---------------------------------------------------------------------------


def _resp(status_code: int, json_body: object = None) -> httpx.Response:
    """Build an httpx.Response with a `.request` attached so
    `.raise_for_status()` works exactly as it would on a real response (a
    bare `httpx.Response(...)` has no request set and raises RuntimeError —
    not the intended HTTPStatusError — the moment route code calls
    `.raise_for_status()`, verified empirically 2026-07-23 in this suite)."""
    return httpx.Response(
        status_code,
        json=json_body if json_body is not None else {},
        request=httpx.Request("GET", "https://policy:8181/fake"),
    )


class _FakeOpaAsyncClient:
    """Matches the `async with internal_httpx_client(...) as client:` surface
    (get/put/post/delete) that every OPA call site in this group uses."""

    def __init__(self, backend: _FakeOpaBackend) -> None:
        self._backend = backend

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def get(self, url: str, **_kw: object) -> httpx.Response:
        return self._backend.handle_get(url)

    async def put(self, url: str, content: object = b"", **_kw: object) -> httpx.Response:
        return self._backend.handle_put(url, content)

    async def post(self, url: str, json: object = None, **_kw: object) -> httpx.Response:
        return self._backend.handle_post(url, json)

    async def delete(self, url: str, **_kw: object) -> httpx.Response:
        return self._backend.handle_delete(url)


class _FakeOpaBackend:
    """In-memory OPA REST surface: PUT/GET/DELETE `/v1/policies/{id}` (raw
    Rego text) and POST `/v1/data/{path}` (decision evaluation). Real state,
    not a stub — a PUT genuinely persists, a subsequent GET genuinely reflects
    it, and DELETE genuinely removes it.

    `decisions` lets a test force a specific decision result at a given data
    path (e.g. for the R12 simulate deny/allow/undefined tests); anything not
    forced defaults to `{"allow": True, "deny": [], "obligations": []}` — this
    default is deliberate: it makes the sanity-check sandbox evaluation (3
    benign samples, all default to allow=True) NOT trip the deny_all/
    never_allow HIGH-severity warnings, so save/edit/duplicate positive paths
    are exercisable without per-test decision plumbing.
    """

    def __init__(self) -> None:
        self.policies: dict[str, str] = {}
        self.decisions: dict[str, dict] = {}

    def factory(self, *_a: object, **_kw: object) -> _FakeOpaAsyncClient:
        return _FakeOpaAsyncClient(self)

    @staticmethod
    def _pid(url: str) -> str:
        return url.split("/v1/policies/", 1)[1]

    def handle_get(self, url: str) -> httpx.Response:
        if url.rstrip("/").endswith("/v1/policies"):
            result = [{"id": pid, "ast": {"package": {"path": []}}} for pid in self.policies]
            return _resp(200, {"result": result})
        pid = self._pid(url)
        if pid not in self.policies:
            return _resp(404, {"error": "not_found"})
        return _resp(200, {"result": {"id": pid, "raw": self.policies[pid], "ast": {}}})

    def handle_put(self, url: str, content: object) -> httpx.Response:
        pid = self._pid(url)
        rego = content.decode("utf-8") if isinstance(content, (bytes, bytearray)) else str(content)
        if "package" not in rego:
            return _resp(400, {"errors": [{"message": "rego_parse_error: package expected"}]})
        self.policies[pid] = rego
        return _resp(200, {})

    def handle_delete(self, url: str) -> httpx.Response:
        self.policies.pop(self._pid(url), None)
        return _resp(204)

    def handle_post(self, url: str, body: object) -> httpx.Response:
        if "/v1/data/" not in url:
            return _resp(404, {"error": "not_found"})
        path = url.split("/v1/data/", 1)[1]
        forced = self.decisions.get(path)
        if forced is not None:
            return _resp(200, {"result": forced})
        return _resp(200, {"result": {"allow": True, "deny": [], "obligations": []}})


@pytest.fixture
def fake_opa(monkeypatch):
    backend = _FakeOpaBackend()
    monkeypatch.setattr(
        "yashigani.backoffice.routes.policies.internal_httpx_client", backend.factory
    )
    monkeypatch.setattr("yashigani.pki.client.internal_httpx_client", backend.factory)
    return backend


@pytest.fixture
def noop_push_bindings(monkeypatch):
    """policies.py's `_push_bindings()` fans out to a REAL sync-httpx PUT to
    OPA (`policy_bindings/opa_push.py`, off the event loop via
    `asyncio.to_thread`) — deliberately NOT covered by `fake_opa` (that's an
    async-client backend; this is a sync one). Bind/unbind tests care about
    the binding CRUD + scope_id validation logic, not the OPA push transport,
    so this fixture no-ops it (mirrors how the reference group treats
    fire-and-forget OPA syncs as out of scope for a route-conformance
    assertion)."""
    import yashigani.backoffice.routes.policies as policies_mod

    monkeypatch.setattr(policies_mod, "_push_bindings", AsyncMock(return_value=None))


@pytest.fixture
def binding_state(fake_redis_client, monkeypatch):
    """Wires the REAL BindingStore against fakeredis (constructor takes
    redis_client directly — src/yashigani/policy_bindings/store.py:70)."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.policy_bindings.store import BindingStore

    store = BindingStore(redis_client=fake_redis_client)
    monkeypatch.setattr(backoffice_state, "binding_store", store, raising=False)
    return store


@pytest.fixture
def envelope_pending_state(fake_redis_client, monkeypatch):
    """Wires the REAL EnvelopePendingStore against fakeredis (constructor
    takes redis_client directly — src/yashigani/mcp/envelope_pending_store.py:87)."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.mcp.envelope_pending_store import EnvelopePendingStore

    store = EnvelopePendingStore(redis_client=fake_redis_client)
    monkeypatch.setattr(backoffice_state, "envelope_pending_store", store, raising=False)
    return store


def _seed_pending(store, provenance_id: str = "prov-1", tenant_id: str = "default"):
    from yashigani.mcp._envelope import ServerEnvelope

    candidate = ServerEnvelope(
        provenance_id=provenance_id, tenant_id=tenant_id, tools={}, egress_posture="NONE"
    )
    return store.record_block(
        provenance_id=provenance_id,
        tenant_id=tenant_id,
        server_id="srv-acme",
        candidate=candidate,
        triage_class="expanding",
        new_surface_hash="deadbeef",
    )


# ---------------------------------------------------------------------------
# Route-completeness check
# ---------------------------------------------------------------------------


def test_group_covers_all_declared_routes(route_prefix_filter):
    declared = route_prefix_filter(*_GROUP_PREFIXES)
    declared_set = {(m, p) for (m, p, _r) in declared}
    assert len(declared_set) == 27, (
        f"Expected 27 declared routes under {_GROUP_PREFIXES}, found "
        f"{len(declared_set)}: {sorted(declared_set)}"
    )


# ---------------------------------------------------------------------------
# policies.py — list / bindings / lifecycle (7 endpoints)
# ---------------------------------------------------------------------------


class TestListPolicies:
    # GAP-CLOSED: GET /admin/policies
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/policies")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "authentication_required"

    def test_user_tier_403(self, user_client):
        r = user_client.get("/admin/policies")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "insufficient_tier"

    def test_admin_opa_unreachable_503(self, admin_client, monkeypatch):
        """SPEC-CONFORMANCE: a genuine network failure talking to OPA (not a
        stub) must fail closed with 503 opa_unreachable, per policies.py:
        188-193 (`except httpx.HTTPError`). Simulated with an
        httpx.ConnectError raised from the client's own `.get()` rather than
        the fully-unmocked real client — the real internal_httpx_client()
        raises `yashigani.pki.identity.ManifestError` at CONSTRUCTION time in
        this harness (YASHIGANI_SERVICE_NAME unset), which is a DIFFERENT,
        unhandled exception the route's `except httpx.HTTPError` does NOT
        catch (a real divergence worth flagging to Lu for production
        containers that somehow lose their service-identity env var — but
        not the network-unreachable path this test targets)."""
        import yashigani.backoffice.routes.policies as policies_mod

        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        client.get = AsyncMock(side_effect=httpx.ConnectError("opa unreachable"))
        monkeypatch.setattr(policies_mod, "internal_httpx_client", lambda **_kw: client)
        r = admin_client.get("/admin/policies")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "opa_unreachable"

    def test_admin_lists_and_categorizes(self, admin_client, fake_opa):
        fake_opa.policies["examples/gdpr"] = "package examples.gdpr\nimport rego.v1\n"
        fake_opa.policies["clients/mypol"] = "package clients.mypol\nimport rego.v1\n"
        r = admin_client.get("/admin/policies")
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 2
        by_id = {p["id"]: p for p in body["policies"]}
        assert by_id["examples/gdpr"]["category"] == "example"
        assert by_id["clients/mypol"]["category"] == "client"
        assert by_id["clients/mypol"]["lifecycle_status"] == "draft"


class TestListBindings:
    # GAP-CLOSED: GET /admin/policies/bindings
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/policies/bindings").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/policies/bindings").status_code == 403

    def test_admin_unconfigured_503(self, admin_client):
        r = admin_client.get("/admin/policies/bindings")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "binding_store_unavailable"

    def test_admin_empty_with_store(self, admin_client, binding_state):
        r = admin_client.get("/admin/policies/bindings")
        assert r.status_code == 200
        assert r.json() == {"bindings": [], "total": 0}


class TestLifecycleList:
    # GAP-CLOSED: GET /admin/policies/lifecycle
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/policies/lifecycle").status_code == 401

    def test_admin_lists_all(self, admin_client):
        from yashigani.backoffice.routes.policies import _lifecycle_store

        with _lifecycle_store._lock:
            _lifecycle_store._data.clear()
        _lifecycle_store.init_if_absent("polx", status="staging")
        r = admin_client.get("/admin/policies/lifecycle")
        assert r.status_code == 200
        names = {e["name"] for e in r.json()["lifecycle"]}
        assert "polx" in names


class TestLifecycleGet:
    # GAP-CLOSED: GET /admin/policies/lifecycle/{name}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/policies/lifecycle/mypol").status_code == 401

    def test_invalid_name_400(self, admin_client):
        r = admin_client.get("/admin/policies/lifecycle/NOT-VALID")
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_name"

    def test_missing_name_defaults_draft(self, admin_client):
        from yashigani.backoffice.routes.policies import _lifecycle_store

        with _lifecycle_store._lock:
            _lifecycle_store._data.pop("neverseen", None)
        r = admin_client.get("/admin/policies/lifecycle/neverseen")
        assert r.status_code == 200
        assert r.json()["status"] == "draft"


class TestLifecyclePromote:
    # GAP-CLOSED: POST /admin/policies/lifecycle/{name}/promote
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/policies/lifecycle/mypol/promote")
        assert r.status_code == 401

    def test_admin_no_stepup_401(self, admin_client):
        """SPEC-CONFORMANCE: promote is StepUpAdminSession-gated — a plain
        admin session (no fresh TOTP) must be rejected BEFORE the handler
        body runs, regardless of policy state."""
        r = admin_client.post("/admin/policies/lifecycle/mypol/promote")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_invalid_name_400(self, stepup_admin_client):
        # NOTE: the route lowercases the name BEFORE validating _NAME_RE, so
        # an uppercase name like "NOPE" normalizes to a VALID "nope" and does
        # NOT trip this check (verified against policies.py:272-274) — use a
        # name that fails the regex even after lowercasing (leading digit).
        r = stepup_admin_client.post("/admin/policies/lifecycle/1nope/promote")
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_name"

    def test_not_loaded_404(self, stepup_admin_client, fake_opa):
        from yashigani.backoffice.routes.policies import _lifecycle_store

        with _lifecycle_store._lock:
            _lifecycle_store._data.pop("neverloaded", None)
        r = stepup_admin_client.post("/admin/policies/lifecycle/neverloaded/promote")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "policy_not_loaded"

    def test_draft_to_staging_to_production_then_conflict(
        self, stepup_admin_client, fake_opa, mock_audit_writer
    ):
        from yashigani.backoffice.routes.policies import _lifecycle_store

        fake_opa.policies["clients/promo1"] = "package clients.promo1\nimport rego.v1\n"
        with _lifecycle_store._lock:
            _lifecycle_store._data.pop("promo1", None)

        r = stepup_admin_client.post("/admin/policies/lifecycle/promo1/promote")
        assert r.status_code == 200
        assert r.json()["lifecycle_status"] == "staging"
        mock_audit_writer.write.assert_called_once()

        r = stepup_admin_client.post("/admin/policies/lifecycle/promo1/promote")
        assert r.status_code == 200
        assert r.json()["lifecycle_status"] == "production"

        r = stepup_admin_client.post("/admin/policies/lifecycle/promo1/promote")
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "invalid_transition"


class TestLifecycleArchive:
    # GAP-CLOSED: POST /admin/policies/lifecycle/{name}/archive
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/policies/lifecycle/mypol/archive").status_code == 401

    def test_admin_no_stepup_401(self, admin_client):
        assert admin_client.post("/admin/policies/lifecycle/mypol/archive").status_code == 401

    def test_stepup_archives(self, stepup_admin_client, mock_audit_writer):
        from yashigani.backoffice.routes.policies import _lifecycle_store

        _lifecycle_store.init_if_absent("archme", status="production")
        r = stepup_admin_client.post("/admin/policies/lifecycle/archme/archive")
        assert r.status_code == 200
        assert r.json()["lifecycle_status"] == "archived"
        mock_audit_writer.write.assert_called_once()


# ---------------------------------------------------------------------------
# R12 — simulate (1 endpoint)
# ---------------------------------------------------------------------------


class TestSimulatePolicy:
    # GAP-CLOSED: POST /admin/policies/simulate
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/policies/simulate",
            json={"policy_id": "clients/x", "input_scenario": {}, "ai_explain": False},
        )
        assert r.status_code == 401

    def test_user_tier_403(self, user_client):
        r = user_client.post(
            "/admin/policies/simulate",
            json={"policy_id": "clients/x", "input_scenario": {}, "ai_explain": False},
        )
        assert r.status_code == 403

    def test_allow_verdict(self, admin_client, fake_opa):
        fake_opa.decisions["clients/mypol/decision"] = {
            "allow": True, "deny": [], "obligations": ["audit"],
        }
        r = admin_client.post(
            "/admin/policies/simulate",
            json={"policy_id": "clients/mypol", "input_scenario": {"identity": {}}, "ai_explain": False},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["verdict"] == "allow"
        assert body["ai_explanation"] is None

    def test_deny_verdict(self, admin_client, fake_opa):
        fake_opa.decisions["clients/mypol/decision"] = {
            "allow": False, "deny": ["gdpr_violation"], "obligations": [],
        }
        r = admin_client.post(
            "/admin/policies/simulate",
            json={"policy_id": "clients/mypol", "input_scenario": {}, "ai_explain": False},
        )
        assert r.status_code == 200
        assert r.json()["verdict"] == "deny"
        assert "gdpr_violation" in r.json()["deny"]

    def test_undefined_decision(self, admin_client, fake_opa):
        # No forced decision AND no data path override -> emulate undefined by
        # forcing a null result explicitly.
        real_post = fake_opa.handle_post

        def _null_post(url, body):
            if "/v1/data/" in url:
                return httpx.Response(200, json={"result": None})
            return real_post(url, body)

        fake_opa.handle_post = _null_post  # type: ignore[assignment]
        r = admin_client.post(
            "/admin/policies/simulate",
            json={"policy_id": "clients/undefinedpol", "input_scenario": {}, "ai_explain": False},
        )
        assert r.status_code == 200
        assert r.json()["verdict"] == "undefined"

    def test_policy_not_found_404(self, admin_client, monkeypatch):
        def _404_post(url, body):
            return httpx.Response(404, json={})

        import yashigani.backoffice.routes.policies as policies_mod
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        client.post = AsyncMock(return_value=httpx.Response(404, json={}))
        monkeypatch.setattr(policies_mod, "internal_httpx_client", lambda **_kw: client)
        r = admin_client.post(
            "/admin/policies/simulate",
            json={"policy_id": "clients/missing", "input_scenario": {}, "ai_explain": False},
        )
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "policy_not_found"

    def test_ai_explain_degrades_gracefully_offline(self, admin_client, fake_opa, monkeypatch):
        """ai_explain=True with no reachable Ollama in this offline suite must
        NOT fail the request — `_resolve_default_model` raising is caught by
        the route's broad `except Exception` around the AI-explain block
        (policies.py:433-435), so ai_explanation degrades to None while the
        OPA verdict itself is still returned. Patches httpx.AsyncClient so the
        assertion runs fast (no real DNS/connect timeout)."""
        import yashigani.backoffice.routes.policies as policies_mod

        monkeypatch.setattr(
            policies_mod,
            "_resolve_default_model",
            AsyncMock(side_effect=httpx.ConnectError("no ollama offline")),
        )
        fake_opa.decisions["clients/mypol/decision"] = {"allow": True, "deny": [], "obligations": []}
        r = admin_client.post(
            "/admin/policies/simulate",
            json={"policy_id": "clients/mypol", "input_scenario": {}, "ai_explain": True},
        )
        assert r.status_code == 200
        assert r.json()["verdict"] == "allow"
        assert r.json()["ai_explanation"] is None


# ---------------------------------------------------------------------------
# R8 — templates/duplicate + custom/{name}/rego (2 endpoints)
# ---------------------------------------------------------------------------


class TestTemplateDuplicate:
    # GAP-CLOSED: POST /admin/policies/templates/duplicate
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/policies/templates/duplicate",
            json={"template_id": "examples/gdpr", "new_name": "copy1"},
        )
        assert r.status_code == 401

    def test_admin_no_stepup_401(self, admin_client):
        r = admin_client.post(
            "/admin/policies/templates/duplicate",
            json={"template_id": "examples/gdpr", "new_name": "copy1"},
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_reserved_name_rejected(self, stepup_admin_client):
        r = stepup_admin_client.post(
            "/admin/policies/templates/duplicate",
            json={"template_id": "examples/gdpr", "new_name": "rbac"},
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_name"

    def test_template_not_found_404(self, stepup_admin_client, fake_opa):
        r = stepup_admin_client.post(
            "/admin/policies/templates/duplicate",
            json={"template_id": "examples/does_not_exist", "new_name": "copy2"},
        )
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "template_not_found"

    def test_duplicate_succeeds_and_lands_in_fake_opa(self, stepup_admin_client, fake_opa, mock_audit_writer):
        fake_opa.policies["examples/gdpr"] = "package examples.gdpr\nimport rego.v1\ndefault allow := false\n"
        r = stepup_admin_client.post(
            "/admin/policies/templates/duplicate",
            json={"template_id": "examples/gdpr", "new_name": "my_gdpr_copy"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["id"] == "clients/my_gdpr_copy"
        assert body["lifecycle_status"] == "draft"
        # Genuine persistence: the new module actually landed in the fake OPA.
        assert "clients/my_gdpr_copy" in fake_opa.policies
        assert "package clients.my_gdpr_copy" in fake_opa.policies["clients/my_gdpr_copy"]
        mock_audit_writer.write.assert_called_once()


class TestEditCustomPolicyRego:
    # GAP-CLOSED: PUT /admin/policies/custom/{name}/rego
    def test_unauth_401(self, unauth_client):
        r = unauth_client.put(
            "/admin/policies/custom/mypol/rego", json={"rego": "package clients.mypol\n"}
        )
        assert r.status_code == 401

    def test_admin_no_stepup_401(self, admin_client):
        r = admin_client.put(
            "/admin/policies/custom/mypol/rego", json={"rego": "package clients.mypol\n"}
        )
        assert r.status_code == 401

    def test_reserved_name_rejected(self, stepup_admin_client):
        r = stepup_admin_client.put(
            "/admin/policies/custom/rbac/rego", json={"rego": "package clients.rbac\n"}
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_name"

    def test_missing_package_400(self, stepup_admin_client):
        r = stepup_admin_client.put(
            "/admin/policies/custom/mypol/rego", json={"rego": "import rego.v1\n"}
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "missing_package"

    def test_edit_saves_and_demotes_to_draft(self, stepup_admin_client, fake_opa, mock_audit_writer):
        rego = "package clients.mypol\nimport rego.v1\ndefault allow := true\n"
        r = stepup_admin_client.put("/admin/policies/custom/mypol/rego", json={"rego": rego})
        assert r.status_code == 200, r.text
        assert r.json()["lifecycle_status"] == "draft"
        assert fake_opa.policies["clients/mypol"] == rego
        mock_audit_writer.write.assert_called_once()

    def test_check_only_reports_high_warnings_without_saving(self, stepup_admin_client, fake_opa):
        """SPEC-CONFORMANCE: force a deny-all sandbox decision so the static
        sanity check reports a HIGH warning, and prove check_only=True neither
        saves the module nor requires confirm_warnings."""
        rego = "package clients.denyall\nimport rego.v1\ndefault allow := false\n"
        default_handle_post = fake_opa.handle_post

        def _deny_all_post(url, body):
            if "_sanity_denyall" in url and "/v1/data/" in url:
                return httpx.Response(200, json={"result": {"allow": False, "deny": ["blocked"]}})
            return default_handle_post(url, body)

        fake_opa.handle_post = _deny_all_post  # type: ignore[assignment]
        r = stepup_admin_client.put(
            "/admin/policies/custom/denyall/rego", json={"rego": rego, "check_only": True}
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "checked"
        assert body["ok"] is False
        assert "clients/denyall" not in fake_opa.policies


# ---------------------------------------------------------------------------
# R9 — core policy edit with confirm_danger guard (G3 ISOLATED POSITIVE TEST)
# ---------------------------------------------------------------------------


class TestCorePolicyEditStepUp:
    """G3 (Lu audit): the pre-commit 401 (StepUp missing) was already proven
    by Laura. This class closes the gap — an ISOLATED positive-path test
    proving a STEPPED-UP admin CAN edit core policy and the mutation takes
    effect, contrasted directly against the same request on a plain admin
    session (no step-up) to prove StepUp is what unlocks it, not admin tier
    alone."""

    # GAP-CLOSED: PUT /admin/policies/core/{policy_id}
    def test_unauth_401(self, unauth_client):
        r = unauth_client.put(
            "/admin/policies/core/yashigani",
            json={"rego": "package yashigani\n", "confirm_danger": True, "reason": "x"},
        )
        assert r.status_code == 401

    def test_admin_without_stepup_rejected_401_before_handler_runs(self, admin_client, fake_opa):
        """CONTRAST CASE: admin tier alone (no fresh TOTP step-up) is REJECTED
        by the `StepUpAdminSession` dependency BEFORE the handler body ever
        executes — even with confirm_danger=true and a valid reason supplied,
        and even though the policy would otherwise be editable. Proves the
        401 is a StepUp gate, not a body-level validation failure."""
        r = admin_client.put(
            "/admin/policies/core/yashigani",
            json={
                "rego": "package yashigani\nimport rego.v1\ndefault allow := true\n",
                "confirm_danger": True,
                "reason": "attempting edit without step-up",
            },
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"
        # The mutation must NOT have landed anywhere.
        assert "yashigani" not in fake_opa.policies

    def test_stepup_admin_edit_lands_in_opa(self, stepup_admin_client, fake_opa, mock_audit_writer):
        """POSITIVE PATH (the gap G3 asks for): a stepped-up admin submits a
        valid core-policy rego edit with confirm_danger=true + a reason. The
        route returns 200 AND the actual rego text is now what `fake_opa`
        holds for the `yashigani` module id — proving the conforming mutation
        landed, not just that the endpoint returned success."""
        new_rego = (
            "package yashigani\nimport rego.v1\n"
            "default allow := true\n"
            "# G3 conformance marker — proves this exact text reached OPA\n"
        )
        r = stepup_admin_client.put(
            "/admin/policies/core/yashigani",
            json={
                "rego": new_rego,
                "confirm_danger": True,
                "reason": "G3 conformance isolated positive-path test",
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "ok"
        assert body["id"] == "yashigani"
        assert body["category"] == "core"
        # The genuine persistence assertion — this IS the mutation landing.
        assert fake_opa.policies.get("yashigani") == new_rego
        mock_audit_writer.write.assert_called_once()

    def test_missing_confirm_danger_409_even_with_stepup(self, stepup_admin_client):
        r = stepup_admin_client.put(
            "/admin/policies/core/yashigani",
            json={"rego": "package yashigani\n", "confirm_danger": False, "reason": "x"},
        )
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "confirm_danger_required"

    def test_missing_reason_400_even_with_stepup(self, stepup_admin_client):
        r = stepup_admin_client.put(
            "/admin/policies/core/yashigani",
            json={"rego": "package yashigani\n", "confirm_danger": True, "reason": ""},
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "reason_required"

    def test_non_core_policy_id_rejected(self, stepup_admin_client):
        r = stepup_admin_client.put(
            "/admin/policies/core/clients/notcore",
            json={
                "rego": "package clients.notcore\n",
                "confirm_danger": True,
                "reason": "x",
            },
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "not_a_core_policy"


# ---------------------------------------------------------------------------
# Existing read + mutation endpoints (5 endpoints)
# ---------------------------------------------------------------------------


class TestGetPolicy:
    # GAP-CLOSED: GET /admin/policies/{policy_id:path}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/policies/yashigani").status_code == 401

    def test_not_found_404(self, admin_client, fake_opa):
        r = admin_client.get("/admin/policies/does/not/exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "policy_not_found"

    def test_found_returns_raw(self, admin_client, fake_opa):
        fake_opa.policies["yashigani"] = "package yashigani\nimport rego.v1\n"
        r = admin_client.get("/admin/policies/yashigani")
        assert r.status_code == 200
        body = r.json()
        assert body["raw"] == "package yashigani\nimport rego.v1\n"
        assert body["category"] == "core"
        assert body["lifecycle_status"] == "production"


class TestSavePolicy:
    # GAP-CLOSED: POST /admin/policies/save
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/policies/save", json={"name": "mypol", "rego": "package clients.mypol\n"}
        )
        assert r.status_code == 401

    def test_admin_no_stepup_401(self, admin_client):
        r = admin_client.post(
            "/admin/policies/save", json={"name": "mypol", "rego": "package clients.mypol\n"}
        )
        assert r.status_code == 401

    def test_invalid_name_400(self, stepup_admin_client):
        r = stepup_admin_client.post(
            "/admin/policies/save", json={"name": "yashigani", "rego": "package clients.yashigani\n"}
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "invalid_name"

    def test_save_succeeds(self, stepup_admin_client, fake_opa, mock_audit_writer):
        rego = "package clients.newpol\nimport rego.v1\ndefault allow := true\n"
        r = stepup_admin_client.post(
            "/admin/policies/save", json={"name": "newpol", "rego": rego}
        )
        assert r.status_code == 200, r.text
        assert r.json()["lifecycle_status"] == "draft"
        assert fake_opa.policies["clients/newpol"] == rego
        mock_audit_writer.write.assert_called_once()


class TestGeneratePolicy:
    # GAP-CLOSED: POST /admin/policies/generate
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/policies/generate", json={"prompt": "block PII access"})
        assert r.status_code == 401

    def test_llm_unavailable_503(self, admin_client, monkeypatch):
        """Real offline behaviour: the /api/generate call fails (no Ollama in
        this suite) -> the route's documented fail-closed 503 llm_unavailable
        contract (policies.py:1042-1043)."""
        import yashigani.backoffice.routes.policies as policies_mod

        monkeypatch.setattr(
            policies_mod, "_resolve_default_model", AsyncMock(return_value=("qwen2.5:3b", ["qwen2.5:3b"]))
        )
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("no ollama offline"))
        monkeypatch.setattr("httpx.AsyncClient", lambda **_kw: mock_client)
        r = admin_client.post("/admin/policies/generate", json={"prompt": "block PII access from agents"})
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "llm_unavailable"

    def test_generate_success(self, admin_client, fake_opa, monkeypatch):
        import yashigani.backoffice.routes.policies as policies_mod

        monkeypatch.setattr(
            policies_mod, "_resolve_default_model", AsyncMock(return_value=("qwen2.5:3b", ["qwen2.5:3b"]))
        )
        gen_rego = "package clients.generated\nimport rego.v1\ndefault allow := false\n"
        mock_resp = _resp(200, {"response": gen_rego})
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=mock_resp)
        monkeypatch.setattr("httpx.AsyncClient", lambda **_kw: mock_client)
        r = admin_client.post(
            "/admin/policies/generate", json={"prompt": "block PII access from agents", "name": "generated"}
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "ok"
        assert body["compile_ok"] is True
        assert "package clients.generated" in body["rego"]


class TestActivatePolicy:
    # GAP-CLOSED: POST /admin/policies/activate
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/policies/activate", json={"name": "mypol"}).status_code == 401

    def test_admin_no_stepup_401(self, admin_client):
        assert admin_client.post("/admin/policies/activate", json={"name": "mypol"}).status_code == 401

    def test_not_loaded_404(self, stepup_admin_client, fake_opa):
        r = stepup_admin_client.post("/admin/policies/activate", json={"name": "neveractivated"})
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "policy_not_loaded"

    def test_activate_idempotent_200(self, stepup_admin_client, fake_opa, mock_audit_writer):
        fake_opa.policies["clients/actme"] = "package clients.actme\nimport rego.v1\n"
        r = stepup_admin_client.post("/admin/policies/activate", json={"name": "actme"})
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "name": "actme", "loaded": True}
        r2 = stepup_admin_client.post("/admin/policies/activate", json={"name": "actme"})
        assert r2.status_code == 200


# ---------------------------------------------------------------------------
# Bind / Unbind (2 endpoints)
# ---------------------------------------------------------------------------


class TestBindPolicy:
    # GAP-CLOSED: POST /admin/policies/bind
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/policies/bind",
            json={"policy_name": "mypol", "scope_kind": "service", "scope_id": "svc1", "direction": "both"},
        )
        assert r.status_code == 401

    def test_admin_no_stepup_401(self, admin_client, binding_state):
        r = admin_client.post(
            "/admin/policies/bind",
            json={"policy_name": "mypol", "scope_kind": "service", "scope_id": "svc1", "direction": "both"},
        )
        assert r.status_code == 401

    def test_binding_store_unavailable_503(self, stepup_admin_client):
        r = stepup_admin_client.post(
            "/admin/policies/bind",
            json={"policy_name": "mypol", "scope_kind": "service", "scope_id": "svc1", "direction": "both"},
        )
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "binding_store_unavailable"

    def test_policy_not_loaded_404(self, stepup_admin_client, binding_state, fake_opa, noop_push_bindings):
        r = stepup_admin_client.post(
            "/admin/policies/bind",
            json={"policy_name": "unloadedpol", "scope_kind": "service", "scope_id": "svc1", "direction": "both"},
        )
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "policy_not_loaded"

    def test_bind_succeeds_and_persists(
        self, stepup_admin_client, binding_state, fake_opa, noop_push_bindings, mock_audit_writer
    ):
        fake_opa.policies["clients/boundpol"] = "package clients.boundpol\nimport rego.v1\n"
        r = stepup_admin_client.post(
            "/admin/policies/bind",
            json={
                "policy_name": "boundpol", "scope_kind": "service", "scope_id": "svc1", "direction": "ingress",
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["binding"]["id"]
        assert len(binding_state.list()) == 1
        mock_audit_writer.write.assert_called_once()


class TestUnbindPolicy:
    # GAP-CLOSED: DELETE /admin/policies/bind/{binding_id}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/policies/bind/deadbeef").status_code == 401

    def test_admin_no_stepup_401(self, admin_client, binding_state):
        assert admin_client.delete("/admin/policies/bind/deadbeef").status_code == 401

    def test_store_unavailable_503(self, stepup_admin_client):
        r = stepup_admin_client.delete("/admin/policies/bind/deadbeef")
        assert r.status_code == 503

    def test_unknown_binding_404(self, stepup_admin_client, binding_state, noop_push_bindings):
        r = stepup_admin_client.delete("/admin/policies/bind/deadbeef")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "binding_not_found"

    def test_unbind_succeeds(self, stepup_admin_client, binding_state, fake_opa, noop_push_bindings, mock_audit_writer):
        from yashigani.policy_bindings.store import PolicyBinding

        b = binding_state.add(PolicyBinding(policy_name="x", scope_kind="service", scope_id="s1", direction="both"))
        r = stepup_admin_client.delete(f"/admin/policies/bind/{b.id}")
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "removed": b.id}
        assert binding_state.get(b.id) is None


# ---------------------------------------------------------------------------
# opa_assistant.py — Mode A (RBAC JSON) — 4 endpoints
# ---------------------------------------------------------------------------

_VALID_RBAC_DOC = {
    "groups": {
        "eng": {"id": "eng", "display_name": "Engineering",
                "allowed_resources": [{"method": "*", "path_glob": "/tools/**"}]},
    },
    "user_groups": {"alice@example.com": ["eng"]},
}


class TestOpaAssistantSuggest:
    # GAP-CLOSED: POST /admin/opa-assistant/suggest
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/opa-assistant/suggest", json={"description": "engineering full access"}
        )
        assert r.status_code == 401

    def test_user_tier_403(self, user_client):
        r = user_client.post(
            "/admin/opa-assistant/suggest", json={"description": "engineering full access"}
        )
        assert r.status_code == 403

    def test_suggest_success(self, admin_client, monkeypatch, mock_audit_writer):
        """MOCKED: OPAAssistantGenerator wraps a live Ollama chat call — no
        Ollama in this offline suite. `.generate()` is patched at the class
        level (documented pattern this file establishes) to prove the route's
        schema-validation + audit-write logic independent of the LLM."""
        from yashigani.opa_assistant.generator import OPAAssistantGenerator

        monkeypatch.setattr(
            OPAAssistantGenerator, "generate",
            AsyncMock(return_value={"suggestion": _VALID_RBAC_DOC, "valid": True, "error": None}),
        )
        r = admin_client.post(
            "/admin/opa-assistant/suggest",
            json={"description": "engineering team full tool access", "include_current": False},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["valid"] is True
        assert body["suggestion"] == _VALID_RBAC_DOC
        mock_audit_writer.write.assert_called_once()

    def test_suggest_generator_reports_invalid(self, admin_client, monkeypatch):
        from yashigani.opa_assistant.generator import OPAAssistantGenerator

        monkeypatch.setattr(
            OPAAssistantGenerator, "generate",
            AsyncMock(return_value={"suggestion": None, "valid": False, "error": "llm_unreachable"}),
        )
        r = admin_client.post(
            "/admin/opa-assistant/suggest",
            json={"description": "engineering team full tool access", "include_current": False},
        )
        assert r.status_code == 200
        assert r.json()["valid"] is False
        assert r.json()["error"] == "llm_unreachable"


class TestOpaAssistantApply:
    # GAP-CLOSED: POST /admin/opa-assistant/apply
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/opa-assistant/apply", json={"suggestion": _VALID_RBAC_DOC}
        )
        assert r.status_code == 401

    def test_admin_no_stepup_401(self, admin_client):
        r = admin_client.post("/admin/opa-assistant/apply", json={"suggestion": _VALID_RBAC_DOC})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_invalid_suggestion_422(self, stepup_admin_client):
        r = stepup_admin_client.post(
            "/admin/opa-assistant/apply", json={"suggestion": {"groups": {}}}
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_suggestion"

    def test_apply_pushes_to_opa_and_audits(self, stepup_admin_client, monkeypatch, mock_audit_writer):
        """apply_suggestion calls push_rbac_data() -> a SYNC internal-mTLS PUT
        (rbac/opa_push.py, `internal_httpx_sync_client`, module-top-bound) —
        distinct from the async `fake_opa` backend used elsewhere in this
        file. Patched here at the source module so the genuine push call is
        exercised (not skipped) without a real network dial."""
        import yashigani.rbac.opa_push as opa_push_mod

        pushed: dict = {}

        class _FakeSyncResp:
            status_code = 200

            def raise_for_status(self) -> None:
                return None

        class _FakeSyncClient:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None

            def put(self, url, json=None, **_kw):
                pushed["url"] = url
                pushed["doc"] = json
                return _FakeSyncResp()

        monkeypatch.setattr(opa_push_mod, "internal_httpx_sync_client", lambda **_kw: _FakeSyncClient())
        r = stepup_admin_client.post(
            "/admin/opa-assistant/apply", json={"suggestion": _VALID_RBAC_DOC, "description": "eng grant"}
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "applied"
        assert body["groups_applied"] == 1
        assert body["users_applied"] == 1
        # push_rbac_data wraps the raw suggestion into the combined
        # {"rbac": ..., "agents": ...} document (rbac/opa_push.py) — the
        # pushed rbac sub-document is what must match the applied suggestion.
        assert pushed["doc"]["rbac"] == _VALID_RBAC_DOC
        mock_audit_writer.write.assert_called_once()


class TestOpaAssistantReject:
    # GAP-CLOSED: POST /admin/opa-assistant/reject
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/opa-assistant/reject", json={"reason": "no"}).status_code == 401

    def test_admin_rejects_no_stepup_required(self, admin_client, mock_audit_writer):
        """SPEC-CONFORMANCE: reject is audit-log-only (no mutation) and is
        AdminSession-gated, NOT StepUpAdminSession — a plain admin session
        suffices (contrast with /apply above)."""
        r = admin_client.post("/admin/opa-assistant/reject", json={"reason": "rejected by admin"})
        assert r.status_code == 200
        assert r.json() == {"status": "rejected"}
        mock_audit_writer.write.assert_called_once()


class TestOpaAssistantSchema:
    # GAP-CLOSED: GET /admin/opa-assistant/schema
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/opa-assistant/schema").status_code == 401

    def test_admin_returns_schema(self, admin_client):
        r = admin_client.get("/admin/opa-assistant/schema")
        assert r.status_code == 200
        assert "groups" in r.json()["schema"]["properties"]


# ---------------------------------------------------------------------------
# opa_assistant.py — Mode B (Rego authoring) — 3 endpoints
# ---------------------------------------------------------------------------


class TestOpaAssistantSuggestRego:
    # GAP-CLOSED: POST /admin/opa-assistant/suggest-rego
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/opa-assistant/suggest-rego",
            json={"description": "block PII tool access", "policy_name": "blockpii"},
        )
        assert r.status_code == 401

    def test_invalid_policy_name_422(self, admin_client):
        r = admin_client.post(
            "/admin/opa-assistant/suggest-rego",
            json={"description": "block PII tool access", "policy_name": "yashigani"},
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "reserved_policy_name"

    def test_suggest_rego_success(self, admin_client, fake_opa, monkeypatch, mock_audit_writer):
        """MOCKED: RegoGenerator wraps a live Ollama call — patched at the
        class level. The server-side OPA compile validation (validate_rego_module,
        lazy-imported from pki.client) is REAL against `fake_opa`."""
        from yashigani.opa_assistant.rego_generator import RegoGenerator

        good_rego = "package clients.blockpii\nimport rego.v1\ndefault allow := false\n"
        monkeypatch.setattr(
            RegoGenerator, "generate",
            AsyncMock(return_value={"rego": good_rego, "error": None}),
        )
        r = admin_client.post(
            "/admin/opa-assistant/suggest-rego",
            json={"description": "block PII tool access", "policy_name": "blockpii"},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["valid"] is True
        assert body["rego"] == good_rego
        assert body["attempts"] == 1
        mock_audit_writer.write.assert_called_once()

    def test_suggest_rego_all_attempts_fail(self, admin_client, fake_opa, monkeypatch):
        from yashigani.opa_assistant.rego_generator import RegoGenerator

        broken_rego = "not even rego\n"  # missing "package" -> fake_opa PUT 400s
        monkeypatch.setattr(
            RegoGenerator, "generate",
            AsyncMock(return_value={"rego": broken_rego, "error": None}),
        )
        r = admin_client.post(
            "/admin/opa-assistant/suggest-rego",
            json={"description": "block PII tool access", "policy_name": "brokenpol"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["valid"] is False
        assert body["rego"] is None
        assert "after_3_attempts" in body["validation_error"] or "after_1_attempt" in body["validation_error"]


class TestOpaAssistantApplyRego:
    # GAP-CLOSED: POST /admin/opa-assistant/apply-rego
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/opa-assistant/apply-rego",
            json={"rego": "package clients.x\n", "policy_name": "x"},
        )
        assert r.status_code == 401

    def test_admin_no_stepup_401(self, admin_client):
        r = admin_client.post(
            "/admin/opa-assistant/apply-rego",
            json={"rego": "package clients.x\n", "policy_name": "x"},
        )
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_compile_error_422(self, stepup_admin_client, fake_opa):
        r = stepup_admin_client.post(
            "/admin/opa-assistant/apply-rego",
            json={"rego": "this has no valid module declaration at all, ten chars+", "policy_name": "badpol"},
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "rego_compile_error"

    def test_apply_rego_succeeds(self, stepup_admin_client, fake_opa, mock_audit_writer):
        good_rego = "package clients.goodpol\nimport rego.v1\ndefault allow := false\n"
        r = stepup_admin_client.post(
            "/admin/opa-assistant/apply-rego",
            json={"rego": good_rego, "policy_name": "goodpol", "description": "test apply"},
        )
        assert r.status_code == 200, r.text
        assert r.json() == {"status": "applied", "policy_name": "goodpol"}
        assert fake_opa.policies["clients/goodpol"] == good_rego
        mock_audit_writer.write.assert_called_once()


class TestOpaAssistantRejectRego:
    # GAP-CLOSED: POST /admin/opa-assistant/reject-rego
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/opa-assistant/reject-rego", json={"policy_name": "x"})
        assert r.status_code == 401

    def test_admin_rejects_no_stepup_required(self, admin_client, mock_audit_writer):
        r = admin_client.post(
            "/admin/opa-assistant/reject-rego", json={"policy_name": "x", "reason": "no thanks"}
        )
        assert r.status_code == 200
        assert r.json() == {"status": "rejected"}
        mock_audit_writer.write.assert_called_once()


# ---------------------------------------------------------------------------
# envelope_reapproval.py — 4 endpoints (YSG-RISK-060)
# ---------------------------------------------------------------------------


class TestEnvelopePendingList:
    # GAP-CLOSED: GET /admin/mcp/envelopes/pending
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/mcp/envelopes/pending").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/mcp/envelopes/pending").status_code == 403

    def test_store_unavailable_503(self, admin_client):
        r = admin_client.get("/admin/mcp/envelopes/pending")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "envelope_pending_store_unavailable"

    def test_empty_queue_200(self, admin_client, envelope_pending_state):
        r = admin_client.get("/admin/mcp/envelopes/pending")
        assert r.status_code == 200
        assert r.json() == {"pending": []}

    def test_lists_seeded_entry(self, admin_client, envelope_pending_state):
        _seed_pending(envelope_pending_state, provenance_id="prov-list")
        r = admin_client.get("/admin/mcp/envelopes/pending")
        assert r.status_code == 200
        rows = r.json()["pending"]
        assert len(rows) == 1
        assert rows[0]["provenance_id"] == "prov-list"


class TestEnvelopePendingDiff:
    # GAP-CLOSED: GET /admin/mcp/envelopes/pending/{provenance_id}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/mcp/envelopes/pending/prov-x").status_code == 401

    def test_no_pending_404(self, admin_client, envelope_pending_state):
        r = admin_client.get("/admin/mcp/envelopes/pending/no-such-prov")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "no_pending_reapproval"

    def test_pending_without_db_pool_503(self, admin_client, envelope_pending_state):
        """SPEC-CONFORMANCE (real offline behaviour): the diff view needs the
        durable envelope service (asyncpg pool) to fetch the ORIGINAL
        baseline — unavailable in this offline suite -> genuine, documented
        fail-closed 503 envelope_service_unavailable (envelope_reapproval.py:
        100-108), NOT a 200 with empty/fabricated data."""
        _seed_pending(envelope_pending_state, provenance_id="prov-diff")
        r = admin_client.get("/admin/mcp/envelopes/pending/prov-diff")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "envelope_service_unavailable"


class TestEnvelopePendingApprove:
    # GAP-CLOSED: POST /admin/mcp/envelopes/pending/{provenance_id}/approve
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/mcp/envelopes/pending/prov-x/approve").status_code == 401

    def test_no_pending_404(self, admin_client, envelope_pending_state):
        r = admin_client.post("/admin/mcp/envelopes/pending/no-such-prov/approve")
        assert r.status_code == 404

    def test_approve_without_db_pool_503(self, admin_client, envelope_pending_state):
        """DIVERGENCE NOTE (real finding, not a test artefact): `approve_pending`
        constructs the envelope service (`_envelope_service()`,
        envelope_reapproval.py:273) BEFORE the step-up gate inside
        `reapprove_envelope` ever runs. In this offline suite (no asyncpg
        pool) EVERY approve call — admin or stepped-up-admin alike — 503s at
        the service-construction step, so the step-up-vs-not distinction that
        IS exercisable for /reject (see TestEnvelopePendingReject below) is
        NOT independently exercisable for /approve without a live DB. Still
        fail-closed (503, no mutation), but flagged here as a genuine
        check-ordering divergence for Lu (envelope_reapproval.py:263-281 —
        service construction precedes the audited step-up gate)."""
        _seed_pending(envelope_pending_state, provenance_id="prov-appr")
        r = admin_client.post("/admin/mcp/envelopes/pending/prov-appr/approve")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "envelope_service_unavailable"


class TestEnvelopePendingReject:
    # GAP-CLOSED: POST /admin/mcp/envelopes/pending/{provenance_id}/reject
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/mcp/envelopes/pending/prov-x/reject").status_code == 401

    def test_no_pending_404(self, admin_client, envelope_pending_state):
        r = admin_client.post("/admin/mcp/envelopes/pending/no-such-prov/reject")
        assert r.status_code == 404

    def test_admin_without_stepup_rejected_401(self, admin_client, envelope_pending_state):
        """CONTRAST CASE (mirrors the G3 discipline applied to core-policy
        edit): reject_pending does NOT depend on a DB pool (no
        `_envelope_service()` call), so the step-up gate IS independently
        exercisable here — a plain admin (no fresh TOTP) is rejected before
        the queue entry is touched."""
        _seed_pending(envelope_pending_state, provenance_id="prov-rej-1")
        r = admin_client.post("/admin/mcp/envelopes/pending/prov-rej-1/reject")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"
        # Entry must still be there — no mutation occurred.
        assert envelope_pending_state.get("prov-rej-1", "default") is not None

    def test_stepup_admin_reject_consumes_entry(self, stepup_admin_client, envelope_pending_state):
        """POSITIVE PATH: a stepped-up admin CAN reject/keep-blocked, and the
        pending entry is consumed (no mutation of the underlying block — it
        stays latched — but the queue entry itself is resolved)."""
        _seed_pending(envelope_pending_state, provenance_id="prov-rej-2")
        r = stepup_admin_client.post("/admin/mcp/envelopes/pending/prov-rej-2/reject")
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "ok"
        assert envelope_pending_state.get("prov-rej-2", "default") is None
