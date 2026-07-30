"""
Exhaustive per-endpoint API conformance suite — Yashigani 4.1.2 @ 250b486d.

Scope (per dispatch brief):
  DATA-PLANE (backoffice): documents.py, user_ui.py, user_conversations.py,
    sensitivity.py (folds in "masking"/"patterns"/"taxonomy" — see note below),
    dp_weaken.py, rbac_sources.py, mcp_servers.py (backoffice MCP admin CRUD).
  GATEWAY: gateway/proxy.py, gateway/openai_router.py (/v1/*),
    gateway/_client_enforce.py, gateway/agent_router.py + agent_auth.py.
  MCP: gateway/mcp_router_runtime.py (/mcp/{agent_name}), auth/spiffe.py
    (trust-chain gate reused by every mesh-internal endpoint incl. /mcp/*
    and /agents/*), backoffice/mcp_onboard.py + routes/mcp_servers.py.

FILE-NAME MAPPING NOTE (structural finding #0, not a defect):
  The brief lists standalone files `masking.py`, `patterns.py`, `taxonomy.py`,
  `sets.py` under the backoffice data-plane.  At 250b486d these do NOT exist
  as separate route modules.  Route enumeration (`grep -rn '@router\\.' src/`)
  confirms the actual code organisation:
    - "patterns"  -> sensitivity.py  GET/POST /patterns, DELETE /patterns/{id}
    - "taxonomy"  -> sensitivity.py  GET /taxonomy(/defaults), POST/DELETE /taxonomy/{level}
    - "sets"      -> documents.py    GET/POST /sets, POST /sets/{id}/members, DELETE /sets/{id}
    - "masking"   -> audit/masking.py is a MASKING UTILITY (no @router routes at
                      all — it's a masking function library used by audit event
                      serialisation, not an HTTP surface). There is no masking
                      API endpoint in this codebase at 250b486d.
  This suite tests the REAL routes as they exist, cross-referenced against
  every `@router.<method>` decorator in the listed files (see the inventory
  comment block below each section).

Mode: FastAPI TestClient, in-process, real dependency chain (real
SessionStore backed by fakeredis + real require_admin_session /
require_user_session / require_stepup_admin_session — NOT dependency-
override shortcuts) so the auth conformance assertions exercise the ACTUAL
production auth gate, not a test double standing in for it.

Deviations discovered while building this suite are recorded in
testing_runs/yashigani/v412-conformance-250b486d/dataplane-gateway-mcp-findings.md
(NOT fixed here — build+find only, per dispatch brief).

Author: Tom. Last updated: 2026-07-29.
"""
from __future__ import annotations

import base64
import os
import time
from typing import Optional
from unittest.mock import AsyncMock, MagicMock

os.environ.setdefault("YASHIGANI_ENV", "dev")
os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-internal-bearer-token-for-conformance-suite")
os.environ.setdefault("YASHIGANI_OPA_OPTIONAL", "true")

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from yashigani.auth.session import Session, SessionStore
from yashigani.backoffice.middleware import get_session_store
from yashigani.backoffice.state import backoffice_state


# ===========================================================================
# Shared fixtures — REAL SessionStore (fakeredis-backed), REAL auth gate.
# ===========================================================================

def _fake_session_store() -> SessionStore:
    """A SessionStore whose Redis client is fakeredis — bypasses __init__'s
    real `redis.Redis.from_url()` call (no live Redis needed) while every
    other method (create/get/invalidate/record_totp_stepup) is the REAL
    implementation. This is deliberately NOT a mock of SessionStore itself —
    only the transport is faked, so require_admin_session / require_user_session
    exercise their genuine tier/step-up/expiry logic against it."""
    import fakeredis
    store = SessionStore.__new__(SessionStore)
    store._redis = fakeredis.FakeRedis(decode_responses=True)
    store._account_index_prefix = "yashigani:account_sessions:"
    store._session_prefix = "yashigani:session:"
    return store


@pytest.fixture()
def session_store():
    return _fake_session_store()


def _mint(store: SessionStore, tier: str, *, stepup: bool = False) -> str:
    """Create a real session of the given tier and return its token."""
    sess = store.create(account_id=f"conf-{tier}-{id(store)}", account_tier=tier, client_ip="127.0.0.1")
    if stepup:
        store.record_totp_stepup(sess.token)
    return sess.token


def _admin_cookie(store: SessionStore, *, stepup: bool = False) -> dict:
    return {"__Host-yashigani_admin_session": _mint(store, "admin", stepup=stepup)}


def _user_cookie(store: SessionStore) -> dict:
    return {"__Host-yashigani_session": _mint(store, "user")}


def _mount(app: FastAPI, store: SessionStore) -> None:
    """Wire the REAL session-store dependency (not require_* itself) so the
    genuine require_admin_session/require_user_session/require_stepup_admin_session
    functions execute against a working (fake-transport) backend."""
    app.dependency_overrides[get_session_store] = lambda: store


# ===========================================================================
# SECTION 1 — backoffice/routes/documents.py
#
# Route inventory (grep -n '@router\.(get|post|put|patch|delete)'
#   src/yashigani/backoffice/routes/documents.py  — 250b486d):
#   GET    /status                        AdminSession
#   GET    /enforcement                   AdminSession
#   PUT    /enforcement                   StepUpAdminSession
#   GET    /policies                      AdminSession
#   POST   /policies                      StepUpAdminSession   (201)
#   DELETE /policies/{policy_id}          StepUpAdminSession
#   POST   /inspect                       AdminSession
#   GET    /results                       AdminSession
#   GET    /results/{request_id}          AdminSession
#   GET    /results/{request_id}/table              StepUpAdminSession
#   GET    /results/{request_id}/table.csv          StepUpAdminSession
#   GET    /results/{request_id}/integrity          AdminSession
#   GET    /sets                          AdminSession
#   POST   /sets                          StepUpAdminSession   (201)
#   POST   /sets/{set_id}/members         StepUpAdminSession
#   DELETE /sets/{set_id}                 StepUpAdminSession
#
# Deep functional/RBAC/BOLA coverage for this router already exists in
# src/tests/unit/test_documents_routes.py (DOC-RT-*, DOC-SET-*, IRIS-META-*)
# — this section adds the ROLE-MATRIX (admin/user/unauth) + validation-422
# conformance layer that file does not enumerate exhaustively.
# ===========================================================================

@pytest.fixture()
def documents_app(session_store, monkeypatch):
    import fakeredis
    from yashigani.backoffice.routes import documents as docroutes
    from yashigani.documents.policy_store import DocumentPolicyStore
    from yashigani.documents.set_store import DocumentSetStore
    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    app = FastAPI()
    app.include_router(docroutes.router, prefix="/admin/documents")
    _mount(app, session_store)
    backoffice_state.rbac_store = None
    backoffice_state.audit_writer = None
    # Real fakeredis-backed stores — the role-matrix "2xx for admin" assertions
    # must exercise the REAL persistence-layer route, not an artificially
    # unwired one (that's covered separately by the 503 fail-closed tests).
    backoffice_state.document_policy_store = DocumentPolicyStore(fakeredis.FakeStrictRedis())
    backoffice_state.document_policy_store.seed_defaults()
    backoffice_state.document_set_store = DocumentSetStore(fakeredis.FakeStrictRedis())
    monkeypatch.setattr(
        "yashigani.documents.opa_push.push_document_data", lambda s, url: None,
    )
    docroutes._results.clear()
    yield TestClient(app), docroutes
    docroutes._results.clear()
    backoffice_state.document_policy_store = None
    backoffice_state.document_set_store = None


# (method, path, admin_body, expected_success_status_family)
_DOC_ADMIN_ROUTES = [
    ("GET", "/admin/documents/status", None),
    ("GET", "/admin/documents/enforcement", None),
    ("GET", "/admin/documents/policies", None),
    ("GET", "/admin/documents/results", None),
    ("GET", "/admin/documents/sets", None),
]
_DOC_STEPUP_ROUTES = [
    ("PUT", "/admin/documents/enforcement", {"enabled": True}),
    ("POST", "/admin/documents/sets", {"name": "conformance-set"}),
]


@pytest.mark.parametrize("method,path,body", _DOC_ADMIN_ROUTES)
def test_documents_admin_route_unauth_401(documents_app, method, path, body):
    tc, _ = documents_app
    r = tc.request(method, path, json=body)
    assert r.status_code == 401, f"{method} {path}: expected 401 unauth, got {r.status_code}: {r.text}"


@pytest.mark.parametrize("method,path,body", _DOC_ADMIN_ROUTES)
def test_documents_admin_route_user_session_403(documents_app, session_store, method, path, body):
    """A genuine USER-tier session presented at an AdminSession route must be
    rejected 403 insufficient_tier — never silently promoted."""
    tc, _ = documents_app
    r = tc.request(method, path, json=body, cookies=_user_cookie(session_store))
    assert r.status_code == 403, f"{method} {path}: expected 403 for user-tier, got {r.status_code}: {r.text}"
    assert r.json()["detail"]["error"] == "insufficient_tier"


@pytest.mark.parametrize("method,path,body", _DOC_ADMIN_ROUTES)
def test_documents_admin_route_admin_session_2xx(documents_app, session_store, method, path, body):
    tc, _ = documents_app
    r = tc.request(method, path, json=body, cookies=_admin_cookie(session_store))
    assert r.status_code < 400, f"{method} {path}: expected 2xx for admin, got {r.status_code}: {r.text}"


@pytest.mark.parametrize("method,path,body", _DOC_STEPUP_ROUTES)
def test_documents_stepup_route_unauth_401(documents_app, method, path, body):
    tc, _ = documents_app
    r = tc.request(method, path, json=body)
    assert r.status_code == 401


@pytest.mark.parametrize("method,path,body", _DOC_STEPUP_ROUTES)
def test_documents_stepup_route_admin_without_stepup_401(documents_app, session_store, method, path, body):
    """Admin session WITHOUT a fresh TOTP step-up must be rejected 401
    step_up_required — a plain admin cookie must never satisfy a StepUpAdminSession
    route (ASVS V6.8.4)."""
    tc, _ = documents_app
    r = tc.request(method, path, json=body, cookies=_admin_cookie(session_store, stepup=False))
    assert r.status_code == 401, f"{method} {path}: expected 401 step_up_required, got {r.status_code}"
    assert r.json()["detail"]["error"] == "step_up_required"


@pytest.mark.parametrize("method,path,body", _DOC_STEPUP_ROUTES)
def test_documents_stepup_route_user_session_403(documents_app, session_store, method, path, body):
    tc, _ = documents_app
    r = tc.request(method, path, json=body, cookies=_user_cookie(session_store))
    assert r.status_code == 403


@pytest.mark.parametrize("method,path,body", _DOC_STEPUP_ROUTES)
def test_documents_stepup_route_admin_with_stepup_2xx(documents_app, session_store, method, path, body):
    tc, _ = documents_app
    r = tc.request(method, path, json=body, cookies=_admin_cookie(session_store, stepup=True))
    assert r.status_code < 400, f"{method} {path}: {r.status_code}: {r.text}"


def test_documents_policies_post_validation_422(documents_app, session_store):
    """POST /policies with a body missing required contract fields -> 422,
    never 500 (validation-before-handler)."""
    tc, _ = documents_app
    r = tc.post(
        "/admin/documents/policies",
        json={"data_class": "PII", "format": "any", "route": "any", "action": "LOG"},
        cookies=_admin_cookie(session_store, stepup=True),
    )
    assert r.status_code == 422


def test_documents_inspect_validation_422_empty_content(documents_app, session_store):
    tc, _ = documents_app
    r = tc.post(
        "/admin/documents/inspect",
        json={"content": "", "filename": "x.txt"},
        cookies=_admin_cookie(session_store),
    )
    assert r.status_code == 422


def test_documents_result_not_found_404_not_500(documents_app, session_store):
    tc, _ = documents_app
    r = tc.get("/admin/documents/results/does-not-exist", cookies=_admin_cookie(session_store))
    assert r.status_code == 404


def test_documents_policies_get_503_when_store_unwired(documents_app, session_store):
    tc, _ = documents_app
    backoffice_state.document_policy_store = None
    r = tc.get("/admin/documents/policies", cookies=_admin_cookie(session_store))
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "policy_store_unavailable"


def test_documents_sets_post_503_when_store_unwired(documents_app, session_store):
    tc, _ = documents_app
    backoffice_state.document_set_store = None
    r = tc.post(
        "/admin/documents/sets", json={"name": "x"},
        cookies=_admin_cookie(session_store, stepup=True),
    )
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "set_store_unavailable"


# ===========================================================================
# SECTION 2 — backoffice/routes/sensitivity.py
#
# Route inventory:
#   GET    /patterns                   AdminSession
#   POST   /patterns                   StepUpAdminSession (201)
#   DELETE /patterns/{pattern_id}      StepUpAdminSession
#   GET    /status                     AdminSession
#   POST   /test                       AdminSession
#   GET    /taxonomy/defaults          AdminSession
#   GET    /taxonomy                   AdminSession
#   POST   /taxonomy/{level}           StepUpAdminSession (200)
#   DELETE /taxonomy/{level}           StepUpAdminSession
#   POST   /generate-pattern           AdminSession
# ===========================================================================

@pytest.fixture()
def sensitivity_app(session_store):
    from yashigani.backoffice.routes import sensitivity as sensroutes
    app = FastAPI()
    app.include_router(sensroutes.router, prefix="/admin/sensitivity")
    _mount(app, session_store)
    backoffice_state.inspection_pipeline = None
    yield TestClient(app), sensroutes


_SENS_ADMIN_ROUTES = [
    ("GET", "/admin/sensitivity/patterns", None),
    ("GET", "/admin/sensitivity/status", None),
    ("GET", "/admin/sensitivity/taxonomy/defaults", None),
    ("GET", "/admin/sensitivity/taxonomy", None),
]
_SENS_STEPUP_ROUTES = [
    ("POST", "/admin/sensitivity/patterns",
     {"classification": "3", "type": "regex", "pattern": r"\d{3}-\d{2}-\d{4}", "description": "ssn"}),
    ("POST", "/admin/sensitivity/taxonomy/3",
     {"label": "Confidential", "colour_class": "sens-level-3"}),
]


@pytest.mark.parametrize("method,path,body", _SENS_ADMIN_ROUTES)
def test_sensitivity_admin_route_unauth_401(sensitivity_app, method, path, body):
    tc, _ = sensitivity_app
    r = tc.request(method, path, json=body)
    assert r.status_code == 401


@pytest.mark.parametrize("method,path,body", _SENS_ADMIN_ROUTES)
def test_sensitivity_admin_route_user_403(sensitivity_app, session_store, method, path, body):
    tc, _ = sensitivity_app
    r = tc.request(method, path, json=body, cookies=_user_cookie(session_store))
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "insufficient_tier"


@pytest.mark.parametrize("method,path,body", _SENS_ADMIN_ROUTES)
def test_sensitivity_admin_route_admin_2xx(sensitivity_app, session_store, method, path, body):
    tc, _ = sensitivity_app
    r = tc.request(method, path, json=body, cookies=_admin_cookie(session_store))
    assert r.status_code < 400, f"{method} {path}: {r.status_code}: {r.text}"


@pytest.mark.parametrize("method,path,body", _SENS_STEPUP_ROUTES)
def test_sensitivity_stepup_route_unauth_401(sensitivity_app, method, path, body):
    tc, _ = sensitivity_app
    r = tc.request(method, path, json=body)
    assert r.status_code == 401


@pytest.mark.parametrize("method,path,body", _SENS_STEPUP_ROUTES)
def test_sensitivity_stepup_route_no_stepup_401(sensitivity_app, session_store, method, path, body):
    tc, _ = sensitivity_app
    r = tc.request(method, path, json=body, cookies=_admin_cookie(session_store, stepup=False))
    assert r.status_code == 401
    assert r.json()["detail"]["error"] == "step_up_required"


@pytest.mark.parametrize("method,path,body", _SENS_STEPUP_ROUTES)
def test_sensitivity_stepup_route_with_stepup_2xx(sensitivity_app, session_store, method, path, body):
    tc, _ = sensitivity_app
    r = tc.request(method, path, json=body, cookies=_admin_cookie(session_store, stepup=True))
    assert r.status_code < 400, f"{method} {path}: {r.status_code}: {r.text}"


def test_sensitivity_pattern_create_validation_422_unsafe_regex(sensitivity_app, session_store):
    """LAURA-2255-005: catastrophic-backtracking regex rejected at the create
    boundary — must 422/400, never accepted then DoS the classifier at match time."""
    tc, _ = sensitivity_app
    r = tc.post(
        "/admin/sensitivity/patterns",
        json={"classification": "3", "type": "regex", "pattern": "(a+)+$", "description": "evil"},
        cookies=_admin_cookie(session_store, stepup=True),
    )
    assert r.status_code in (400, 422), f"expected reject for ReDoS pattern, got {r.status_code}: {r.text}"


def test_sensitivity_taxonomy_delete_level1_rejected(sensitivity_app, session_store):
    """Deleting the lowest taxonomy level must be rejected (structural floor),
    never silently succeed and corrupt the 5-level scale."""
    tc, _ = sensitivity_app
    r = tc.delete("/admin/sensitivity/taxonomy/1", cookies=_admin_cookie(session_store, stepup=True))
    assert r.status_code == 422, f"expected 422 for level-1 delete, got {r.status_code}: {r.text}"


# ===========================================================================
# SECTION 3 — backoffice/routes/dp_weaken.py
#
# Route inventory:
#   GET  /status                                AdminSession
#   GET  /weaken-requests                       AdminSession
#   POST /weaken-requests                       StepUpAdminSession (202)
#   POST /weaken-requests/{id}/approve          StepUpAdminSession
#   POST /weaken-requests/{id}/reject           StepUpAdminSession
# ===========================================================================

class _FakeAuthServiceTwoAdmins:
    """Satisfies _require_at_least_two_active_admins() so the weaken-request
    submit route reaches its OWN store check (dual-admin gate is tested
    separately, in isolation, below)."""
    async def active_admin_count(self) -> int:
        return 2


@pytest.fixture()
def dp_weaken_app(session_store):
    import fakeredis
    from yashigani.backoffice.routes import dp_weaken as dproutes
    from yashigani.protection.weaken_pending_store import DpWeakenPendingStore
    app = FastAPI()
    app.include_router(dproutes.router, prefix="/admin/data-protection")
    _mount(app, session_store)
    backoffice_state.dp_weaken_store = DpWeakenPendingStore(fakeredis.FakeStrictRedis())
    backoffice_state.auth_service = _FakeAuthServiceTwoAdmins()
    backoffice_state.audit_writer = None
    yield TestClient(app), dproutes
    backoffice_state.dp_weaken_store = None
    backoffice_state.auth_service = None


_DPW_ADMIN_ROUTES = [
    ("GET", "/admin/data-protection/status", None),
    ("GET", "/admin/data-protection/weaken-requests", None),
]
_DPW_STEPUP_ROUTES = [
    ("POST", "/admin/data-protection/weaken-requests",
     {"control": "doc_enforcement", "to_state": {"enabled": False}}),
    ("POST", "/admin/data-protection/weaken-requests/does-not-exist/approve", None),
    ("POST", "/admin/data-protection/weaken-requests/does-not-exist/reject", None),
]


@pytest.mark.parametrize("method,path,body", _DPW_ADMIN_ROUTES)
def test_dp_weaken_admin_route_unauth_401(dp_weaken_app, method, path, body):
    tc, _ = dp_weaken_app
    r = tc.request(method, path, json=body)
    assert r.status_code == 401


@pytest.mark.parametrize("method,path,body", _DPW_ADMIN_ROUTES)
def test_dp_weaken_admin_route_user_403(dp_weaken_app, session_store, method, path, body):
    tc, _ = dp_weaken_app
    r = tc.request(method, path, json=body, cookies=_user_cookie(session_store))
    assert r.status_code == 403


@pytest.mark.parametrize("method,path,body", _DPW_ADMIN_ROUTES)
def test_dp_weaken_admin_route_admin_2xx(dp_weaken_app, session_store, method, path, body):
    tc, _ = dp_weaken_app
    r = tc.request(method, path, json=body, cookies=_admin_cookie(session_store))
    assert r.status_code < 400, f"{method} {path}: {r.status_code}: {r.text}"


@pytest.mark.parametrize("method,path,body", _DPW_STEPUP_ROUTES)
def test_dp_weaken_stepup_route_unauth_401(dp_weaken_app, method, path, body):
    tc, _ = dp_weaken_app
    r = tc.request(method, path, json=body)
    assert r.status_code == 401


@pytest.mark.parametrize("method,path,body", _DPW_STEPUP_ROUTES)
def test_dp_weaken_stepup_route_no_stepup_401(dp_weaken_app, session_store, method, path, body):
    tc, _ = dp_weaken_app
    r = tc.request(method, path, json=body, cookies=_admin_cookie(session_store, stepup=False))
    assert r.status_code == 401
    assert r.json()["detail"]["error"] == "step_up_required"


def test_dp_weaken_submit_fail_closed_when_store_unwired(dp_weaken_app, session_store):
    """Store unwired (but dual-admin gate satisfied) -> 503 fail-closed, never
    a phantom-accepted weaken request."""
    tc, _ = dp_weaken_app
    backoffice_state.dp_weaken_store = None
    r = tc.post(
        "/admin/data-protection/weaken-requests",
        json={"control": "doc_enforcement", "to_state": {"enabled": False}},
        cookies=_admin_cookie(session_store, stepup=True),
    )
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "dp_weaken_store_unavailable"


def test_dp_weaken_submit_fail_closed_when_auth_service_unwired(dp_weaken_app, session_store):
    """auth_service unwired -> 503 fail-closed BEFORE the store is even
    consulted (dual-admin-count gate is the FIRST check in submit_weaken_request —
    confirmed by source read). Never silently allows a solo-admin weaken."""
    tc, _ = dp_weaken_app
    backoffice_state.auth_service = None
    r = tc.post(
        "/admin/data-protection/weaken-requests",
        json={"control": "doc_enforcement", "to_state": {"enabled": False}},
        cookies=_admin_cookie(session_store, stepup=True),
    )
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "auth_service_unavailable"


def test_dp_weaken_submit_409_when_fewer_than_two_active_admins(dp_weaken_app, session_store):
    """Fail-closed dual-admin floor: <2 active admins -> 409, request refused
    (there would be no distinct second admin able to approve it)."""
    tc, _ = dp_weaken_app

    class _OneAdmin:
        async def active_admin_count(self) -> int:
            return 1

    backoffice_state.auth_service = _OneAdmin()
    r = tc.post(
        "/admin/data-protection/weaken-requests",
        json={"control": "doc_enforcement", "to_state": {"enabled": False}},
        cookies=_admin_cookie(session_store, stepup=True),
    )
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "insufficient_active_admins"


def test_dp_weaken_control_validation_422(dp_weaken_app, session_store):
    tc, _ = dp_weaken_app
    r = tc.post(
        "/admin/data-protection/weaken-requests",
        json={"control": "not_a_real_control", "to_state": {}},
        cookies=_admin_cookie(session_store, stepup=True),
    )
    assert r.status_code == 422


# ===========================================================================
# SECTION 4 — backoffice/routes/rbac_sources.py
#
# Route inventory:
#   GET /sources/paths     AdminSession
#   GET /sources/methods   AdminSession
# ===========================================================================

@pytest.fixture()
def rbac_sources_app(session_store):
    from yashigani.backoffice.routes import rbac_sources as rbacroutes
    app = FastAPI()
    app.include_router(rbacroutes.router, prefix="/admin/rbac")
    _mount(app, session_store)
    yield TestClient(app)


_RBAC_SRC_ROUTES = ["/admin/rbac/sources/paths", "/admin/rbac/sources/methods"]


@pytest.mark.parametrize("path", _RBAC_SRC_ROUTES)
def test_rbac_sources_unauth_401(rbac_sources_app, path):
    r = rbac_sources_app.get(path)
    assert r.status_code == 401


@pytest.mark.parametrize("path", _RBAC_SRC_ROUTES)
def test_rbac_sources_user_403(rbac_sources_app, session_store, path):
    r = rbac_sources_app.get(path, cookies=_user_cookie(session_store))
    assert r.status_code == 403


@pytest.mark.parametrize("path", _RBAC_SRC_ROUTES)
def test_rbac_sources_admin_200(rbac_sources_app, session_store, path):
    r = rbac_sources_app.get(path, cookies=_admin_cookie(session_store))
    assert r.status_code == 200
    assert isinstance(r.json(), (dict, list))


# ===========================================================================
# SECTION 5 — backoffice/routes/mcp_servers.py (admin CRUD onboarding surface)
#
# Route inventory:
#   GET    /                AdminSession
#   POST   /import           StepUpAdminSession
#   DELETE /{server_id}      StepUpAdminSession
# ===========================================================================

@pytest.fixture()
def mcp_admin_app(session_store):
    from yashigani.backoffice.routes import mcp_servers as mcproutes
    app = FastAPI()
    app.include_router(mcproutes.router, prefix="/admin/mcp/servers")
    _mount(app, session_store)
    yield TestClient(app), mcproutes


def test_mcp_admin_list_unauth_401(mcp_admin_app):
    tc, _ = mcp_admin_app
    r = tc.get("/admin/mcp/servers/")
    assert r.status_code == 401


def test_mcp_admin_list_user_403(mcp_admin_app, session_store):
    tc, _ = mcp_admin_app
    r = tc.get("/admin/mcp/servers/", cookies=_user_cookie(session_store))
    assert r.status_code == 403


def test_mcp_admin_list_admin_2xx_or_clean_5xx(mcp_admin_app, session_store, monkeypatch):
    """Envelope service needs a live Postgres pool; in-process unit test has
    none. Mock _envelope_service so the AUTH gate (what this suite proves) is
    isolated from the DB-availability concern."""
    tc, mod = mcp_admin_app
    fake_svc = MagicMock()
    fake_svc.list_active = AsyncMock(return_value=[])
    monkeypatch.setattr(mod, "_envelope_service", lambda: fake_svc)
    r = tc.get("/admin/mcp/servers/", cookies=_admin_cookie(session_store))
    assert r.status_code == 200
    assert r.json()["servers"] == []


def test_mcp_admin_import_unauth_401(mcp_admin_app):
    tc, _ = mcp_admin_app
    r = tc.post("/admin/mcp/servers/import", json={"server_id": "x", "upstream_url": "http://x:8000"})
    assert r.status_code == 401


def test_mcp_admin_import_no_stepup_401(mcp_admin_app, session_store):
    tc, _ = mcp_admin_app
    r = tc.post(
        "/admin/mcp/servers/import",
        json={"server_id": "x", "upstream_url": "http://x:8000"},
        cookies=_admin_cookie(session_store, stepup=False),
    )
    assert r.status_code == 401
    assert r.json()["detail"]["error"] == "step_up_required"


def test_mcp_admin_import_user_403(mcp_admin_app, session_store):
    tc, _ = mcp_admin_app
    r = tc.post(
        "/admin/mcp/servers/import",
        json={"server_id": "x", "upstream_url": "http://x:8000"},
        cookies=_user_cookie(session_store),
    )
    assert r.status_code == 403


def test_mcp_admin_import_invalid_egress_posture_422(mcp_admin_app, session_store):
    tc, _ = mcp_admin_app
    r = tc.post(
        "/admin/mcp/servers/import",
        json={"server_id": "x", "upstream_url": "http://x:8000", "egress_posture": "WIDE_OPEN"},
        cookies=_admin_cookie(session_store, stepup=True),
    )
    assert r.status_code == 422


def test_mcp_admin_delete_unauth_401(mcp_admin_app):
    tc, _ = mcp_admin_app
    r = tc.delete("/admin/mcp/servers/some-server")
    assert r.status_code == 401


def test_mcp_admin_delete_user_403(mcp_admin_app, session_store):
    tc, _ = mcp_admin_app
    r = tc.delete("/admin/mcp/servers/some-server", cookies=_user_cookie(session_store))
    assert r.status_code == 403


# ===========================================================================
# SECTION 6 — backoffice/routes/user_ui.py (USER-plane data surface)
#
# Route inventory (API routes only — the four SPA-shell routes /chat,
# /agents, /builder, /workflows serve static HTML behind a cookie-presence
# pre-flight, not UserSession, and are out of scope for a JSON-API
# conformance matrix; RISK-100's SPA-page redirect behaviour is already
# covered in test_user_plane_contract.py CT-100-10):
#   GET  /user/agents               UserSession
#   GET  /user/budget                UserSession
#   GET  /user/models                UserSession
#   GET  /user/memory                UserSession
#   POST /user/documents             UserSession   <-- YSG-RISK-128
#   POST /user/chat/completions      UserSession   (trusted-forwarder proxy)
# ===========================================================================

@pytest.fixture()
def user_ui_app(session_store):
    from yashigani.backoffice.routes import user_ui as uiroutes
    app = FastAPI()
    app.include_router(uiroutes.router, tags=["user-ui"])
    _mount(app, session_store)
    backoffice_state.agent_registry = None
    backoffice_state.identity_registry = None
    backoffice_state.model_alias_store = None
    backoffice_state.model_allocation_store = None
    yield TestClient(app), uiroutes


_USER_GET_ROUTES = [
    "/user/agents",
    "/user/budget",
    "/user/models",
    "/user/memory",
]


@pytest.mark.parametrize("path", _USER_GET_ROUTES)
def test_user_ui_get_route_unauth_401(user_ui_app, path):
    tc, _ = user_ui_app
    r = tc.get(path)
    assert r.status_code == 401
    assert r.json()["detail"]["error"] == "authentication_required"


@pytest.mark.parametrize("path", _USER_GET_ROUTES)
def test_user_ui_get_route_admin_session_403_wrong_plane(user_ui_app, session_store, path):
    """A genuine ADMIN-tier session (browsing with the ADMIN cookie) hitting a
    UserSession route must be rejected — RISK-100 plane discipline. The admin
    cookie is intentionally distinct from the user cookie
    (__Host-yashigani_admin_session vs __Host-yashigani_session); this test
    presents the user-cookie NAME carrying an admin-tier token, which is the
    exact cross-tier scenario require_user_session's wrong_plane branch guards
    (an admin who also holds/reuses a user-plane cookie slot)."""
    tc, _ = user_ui_app
    admin_token = _mint(session_store, "admin")
    r = tc.get(path, cookies={"__Host-yashigani_session": admin_token})
    assert r.status_code == 403, f"{path}: expected 403 wrong_plane, got {r.status_code}: {r.text}"
    assert r.json()["detail"]["error"] == "wrong_plane"


@pytest.mark.parametrize("path", _USER_GET_ROUTES)
def test_user_ui_get_route_user_session_2xx(user_ui_app, session_store, path):
    tc, _ = user_ui_app
    r = tc.get(path, cookies=_user_cookie(session_store))
    if path == "/user/memory":
        # YSG-RISK-156 CLOSED: /user/memory is a DECLARED stub (Phase 3 /
        # RISK-107, needs the NHI/SVID mesh + per-user Letta container) —
        # rewritten from a misleading 200 {"configured": false, "entries":
        # []} to an honest 501 not_implemented. See
        # test_tom_ysg_risk_156_157_honest_stub_endpoints.py and
        # test_user_ui_memory_is_a_declared_stub below. Auth still gates
        # BEFORE this 501 (proven by the unauth_401/wrong_plane_403 tests
        # above using the same _USER_GET_ROUTES list), so it stays in this
        # shared parametrization rather than a separate route list.
        assert r.status_code == 501, f"{path}: {r.status_code}: {r.text}"
        assert r.json()["detail"]["error"] == "not_implemented"
    else:
        assert r.status_code == 200, f"{path}: {r.status_code}: {r.text}"


def test_user_ui_memory_is_a_declared_stub():
    """STRUCTURAL FINDING (self-documented, not hidden): /user/memory is
    unconditionally NOT IMPLEMENTED — the route body contains no branching
    logic, it always raises 501. The docstring calls this out as a
    'Phase 3' item (NHI/SVID mesh + per-user Letta container, RISK-107).
    Recorded as a conformance fact, not a defect (the code is honest about
    it), per findings-doc discipline.

    YSG-RISK-156 (merged v4.1.2 integrated fixbatch 2026-07-30) rewrote this
    route from a misleading 200 {"configured": false, "entries": []} to an
    honest 501 — updated this test's marker from the old return-value literal
    to the new one accordingly (test-inventory drift at the integration seam,
    same class as the route-count fixes elsewhere in this file)."""
    import inspect as _inspect
    from yashigani.backoffice.routes import user_ui as uiroutes
    src = _inspect.getsource(uiroutes.user_memory)
    assert '"error": "not_implemented"' in src
    assert "HTTP_501_NOT_IMPLEMENTED" in src
    assert "Phase 3 stub" in _inspect.getsource(uiroutes) or "Phase 3" in src


# ---------------------------------------------------------------------------
# YSG-RISK-128 — POST /user/documents disposition-ladder ACTUAL BEHAVIOUR.
#
# Brief: "assert the REAL upload path's enforcement matches the authoritative
# source + the disposition ladder (OFF->passthrough / LOG->detect+audit /
# PSEUDONYMIZE / REDACT / BLOCK). Enforcement default is env-gated OFF today
# (128 fix pending) -- assert ACTUAL current behavior + flag the divergence."
#
# ACTUAL BEHAVIOUR CONFIRMED BY SOURCE (documents/config.py):
#   YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED default = "false" (env-gated OFF).
# ACTUAL BEHAVIOUR CONFIRMED BY ROUTE (user_ui.py L655-662):
#   is_document_enforcement_enabled() is FALSE -> HTTPException 409
#   {"error": "document_enforcement_disabled"}. The upload is REJECTED
#   OUTRIGHT — the file NEVER reaches the caller's destination.
#
# THIS IS A DIVERGENCE from "OFF -> passthrough" as literally read: the OFF
# state is NOT a silent pass-through of the file (which would itself be the
# unsafe direction) — it is a hard 409 refusal of the upload API entirely.
# Recorded as finding DP128-F1 in the findings doc (favourable direction —
# fails closed, not open — but does not match the "passthrough" semantics
# named in the brief, so it is flagged rather than silently assumed).
# ---------------------------------------------------------------------------

@pytest.fixture()
def user_docs_app(session_store, monkeypatch):
    from yashigani.backoffice.routes import user_ui as uiroutes
    app = FastAPI()
    app.include_router(uiroutes.router, tags=["user-ui"])
    _mount(app, session_store)
    backoffice_state.identity_registry = None
    backoffice_state.audit_writer = None
    backoffice_state.opa_url = "https://policy:8181"
    yield TestClient(app), uiroutes, monkeypatch


def _upload_body() -> dict:
    content = b"Name: Jordan\nEmail: jordan.whitfield@example.com\n"
    return {
        "filename": "salary.txt",
        "content_type": "text/plain",
        "content_base64": base64.b64encode(content).decode("ascii"),
        "route": "ingress-upload",
        "pseudonymize_mode": "A",
    }


def test_risk128_disposition_off_is_hard_409_not_silent_passthrough(user_docs_app, session_store, monkeypatch):
    """DP128-F1: with enforcement OFF (the shipped default), the upload is
    REJECTED with 409 document_enforcement_disabled -- it is NOT silently
    forwarded/passed-through. Confirms the ACTUAL current behaviour differs
    from a literal 'OFF -> passthrough' reading of the disposition ladder."""
    tc, _, mp = user_docs_app
    mp.delenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", raising=False)  # unset -> code default
    from yashigani.documents.config import is_document_enforcement_enabled
    assert is_document_enforcement_enabled() is False, (
        "YSG-RISK-128 precondition changed: enforcement now defaults ON. "
        "Re-verify this finding against the new default."
    )
    r = tc.post("/user/documents", json=_upload_body(), cookies=_user_cookie(session_store))
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "document_enforcement_disabled"


def test_risk128_disposition_off_explicit_false_same_409(user_docs_app, session_store, monkeypatch):
    tc, _, mp = user_docs_app
    mp.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "false")
    r = tc.post("/user/documents", json=_upload_body(), cookies=_user_cookie(session_store))
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "document_enforcement_disabled"


class _WorkerSubprocessBackend:
    """Runs the REAL extractor worker as a subprocess — mirrors the technique
    in test_user_documents_gaps_3_4_5.py so this suite exercises the REAL
    DocumentInspectionPipeline, not a mock disposition function."""

    def run_extractor_job(self, *, stdin, timeout_s, command, **kwargs):
        import subprocess
        from pathlib import Path
        # YSG-RISK-161 bisection (Iris, 4.1.2 integrated fixbatch, 2026-07-30):
        # this file lives at tests/conformance/<file>.py — only 2 levels below
        # repo root (parents[0]=conformance, parents[1]=tests, parents[2]=repo
        # root). The parents[3] constant was copy-pasted from
        # src/tests/unit/test_user_documents_gaps_3_4_5.py, which sits 3 levels
        # below repo root (src/tests/unit/<file>.py) — correct THERE, wrong HERE.
        # parents[3] resolved one directory ABOVE the actual repo root, so the
        # subprocess command pointed at a worker.py that does not exist:
        # "can't open file '.../worker.py': [Errno 2] No such file or directory",
        # exit code 2. The pipeline's fail-closed-on-subprocess-failure guard
        # then (correctly) forced BLOCK for the REDACT/PSEUDONYMIZE rungs,
        # masquerading as a disposition-ladder product regression. Confirmed
        # test-harness artifact, not a product bug — LOG/BLOCK rungs never
        # exercise this subprocess path (LOG needs no re-render; BLOCK's
        # expected outcome coincides with the same fail-closed result the
        # broken path already produced), which is why only REDACT/PSEUDONYMIZE
        # surfaced the defect.
        repo_root = Path(__file__).resolve().parents[2]
        worker_path = repo_root / "docker" / "extractor" / "worker.py"
        env = dict(os.environ)
        env["PYTHONPATH"] = str(repo_root / "src")
        proc = subprocess.run(
            ["python3", str(worker_path), *command],
            input=stdin, capture_output=True, timeout=timeout_s, env=env,
        )
        return (proc.stdout, proc.returncode, False)


def _real_pipeline(audit_context=None):
    from yashigani.documents.audit_bridge import make_document_audit_callback
    from yashigani.documents.extractor import ExtractorRegistry
    from yashigani.documents.pipeline import DocumentInspectionPipeline
    from yashigani.documents.sandbox import SandboxedExtractorRunner
    runner = SandboxedExtractorRunner(backend=_WorkerSubprocessBackend())
    registry = ExtractorRegistry(sandbox_runner=runner)
    audit_cb = make_document_audit_callback(
        backoffice_state.audit_writer, surface="user-upload", context=audit_context,
    )
    return DocumentInspectionPipeline(registry=registry, on_audit=audit_cb, small_set_escalation=False)


def _fake_opa_decision(action: str):
    async def _fake(opa_url, document_input, *, route="any", pseudonymize_mode="A", identity_id="", timeout_s=5.0):
        return {
            "action": action,
            "policy_id": "DOC-CONF-TEST",
            "code": f"DOCUMENT_{action}",
            "user_message": f"file was {action.lower()}",
            "deny": [] if action != "BLOCK" else ["unpoliced_sensitive_class"],
            "obligations": ["audit_document_decision"] + (
                ["apply_pseudonymize_tokens"] if action == "PSEUDONYMIZE" else []
            ),
        }
    return _fake


@pytest.mark.parametrize("opa_action,expected_disposition", [
    ("LOG", "LOG"),
    ("REDACT", "REDACT"),
    ("PSEUDONYMIZE", "PSEUDONYMIZE"),
    ("BLOCK", "BLOCK"),
])
def test_risk128_disposition_ladder_when_enabled(
    user_docs_app, session_store, opa_action, expected_disposition,
):
    """With enforcement ENABLED, the disposition ladder rungs LOG / REDACT /
    PSEUDONYMIZE / BLOCK each drive the OPA-decided action through the REAL
    pipeline end to end (not a stub)."""
    tc, uiroutes, mp = user_docs_app
    mp.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    mp.setattr(uiroutes, "_build_pipeline", _real_pipeline)
    mp.setattr(
        "yashigani.documents.opa_decision.evaluate_document_decision",
        _fake_opa_decision(opa_action),
    )
    r = tc.post("/user/documents", json=_upload_body(), cookies=_user_cookie(session_store))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["disposition"] == expected_disposition
    assert body["action"] == opa_action
    assert body["blocked"] == (opa_action == "BLOCK")
    if opa_action == "BLOCK":
        assert body["processed_content"] is None
        assert body["user_alert"] is not None
    if opa_action == "LOG":
        assert body["processed_content"] is None
    if opa_action in ("REDACT", "PSEUDONYMIZE"):
        assert body["processed_content"] is not None


def test_risk128_upload_validation_bad_route_422(user_docs_app, session_store, monkeypatch):
    tc, _, mp = user_docs_app
    mp.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    body = _upload_body()
    body["route"] = "not-a-real-route"
    r = tc.post("/user/documents", json=body, cookies=_user_cookie(session_store))
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "invalid_route"


def test_risk128_upload_validation_bad_base64_422(user_docs_app, session_store, monkeypatch):
    tc, _, mp = user_docs_app
    mp.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    body = _upload_body()
    body["content_base64"] = "not valid base64!!"
    r = tc.post("/user/documents", json=body, cookies=_user_cookie(session_store))
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "invalid_base64"


def test_risk128_upload_unauth_401(user_docs_app):
    tc, _, mp = user_docs_app
    mp.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    r = tc.post("/user/documents", json=_upload_body())
    assert r.status_code == 401


def test_risk128_upload_admin_session_403_wrong_plane(user_docs_app, session_store):
    tc, _, mp = user_docs_app
    mp.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    admin_token = _mint(session_store, "admin")
    r = tc.post(
        "/user/documents", json=_upload_body(),
        cookies={"__Host-yashigani_session": admin_token},
    )
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "wrong_plane"


# ===========================================================================
# SECTION 7 — backoffice/routes/user_conversations.py
#
# Route inventory:
#   GET    /user/conversations                          UserSession
#   POST   /user/conversations                           UserSession (201)
#   GET    /user/conversations/{conv_id}                 UserSession
#   PATCH  /user/conversations/{conv_id}                 UserSession
#   DELETE /user/conversations/{conv_id}                 UserSession (204)
#   POST   /user/conversations/{conv_id}/messages         UserSession (201)
#
# All routes call yashigani.db.postgres.get_pool() with no DB configured in
# this in-process unit run -- so the AUTH-GATE layer (what this section
# proves) is isolated cleanly: the 401/403 assertions below prove auth runs
# and rejects BEFORE any DB access is attempted; the pool-unavailable path
# proves fail-closed (503, never 500) once auth passes. Full CRUD + BOLA
# functional coverage (owned-row scoping) requires a live Postgres and is out
# of scope for this in-process suite -- see findings doc for the explicit
# coverage note.
# ===========================================================================

@pytest.fixture()
def user_conv_app(session_store):
    from yashigani.backoffice.routes import user_conversations as convroutes
    app = FastAPI()
    app.include_router(convroutes.router, tags=["user-conversations"])
    _mount(app, session_store)
    yield TestClient(app), convroutes


_CONV_ROUTES = [
    ("GET", "/user/conversations", None),
    ("POST", "/user/conversations", {"title": "conf"}),
    ("GET", "/user/conversations/abc-123", None),
    ("PATCH", "/user/conversations/abc-123", {"title": "renamed"}),
    ("DELETE", "/user/conversations/abc-123", None),
    ("POST", "/user/conversations/abc-123/messages", {"messages": [{"role": "user", "content": "hi"}]}),
]


@pytest.mark.parametrize("method,path,body", _CONV_ROUTES)
def test_user_conversations_unauth_401(user_conv_app, method, path, body):
    tc, _ = user_conv_app
    r = tc.request(method, path, json=body)
    assert r.status_code == 401, f"{method} {path}: expected 401, got {r.status_code}"


@pytest.mark.parametrize("method,path,body", _CONV_ROUTES)
def test_user_conversations_admin_session_403_wrong_plane(user_conv_app, session_store, method, path, body):
    tc, _ = user_conv_app
    admin_token = _mint(session_store, "admin")
    r = tc.request(method, path, json=body, cookies={"__Host-yashigani_session": admin_token})
    assert r.status_code == 403, f"{method} {path}: expected 403, got {r.status_code}: {r.text}"
    assert r.json()["detail"]["error"] == "wrong_plane"


@pytest.mark.parametrize("method,path,body", _CONV_ROUTES)
def test_user_conversations_user_session_fails_closed_not_500(user_conv_app, session_store, method, path, body):
    """Auth passes (real user session); no live Postgres in-process -> the
    route must fail CLOSED (503/404-family) and must NEVER surface a raw 500
    (unhandled exception) to the caller."""
    tc, _ = user_conv_app
    r = tc.request(method, path, json=body, cookies=_user_cookie(session_store))
    assert r.status_code != 500, f"{method} {path}: got unhandled 500 -- {r.text}"


def test_user_conversations_create_validation_422_empty_title(user_conv_app, session_store):
    tc, _ = user_conv_app
    r = tc.post(
        "/user/conversations", json={"title": ""},
        cookies=_user_cookie(session_store),
    )
    assert r.status_code == 422


def test_user_conversations_append_validation_422_bad_role(user_conv_app, session_store):
    tc, _ = user_conv_app
    r = tc.post(
        "/user/conversations/abc/messages",
        json={"messages": [{"role": "not-a-real-role", "content": "hi"}]},
        cookies=_user_cookie(session_store),
    )
    assert r.status_code == 422


# ===========================================================================
# SECTION 8 — gateway/proxy.py (public + SPIFFE-gated + MCP-owned endpoints)
#
# Route inventory (from create_gateway_app, cross-checked against the
# module source — not mounted via a router, defined inline on `app`):
#   GET /healthz                              public (no auth)
#   GET /internal/metrics                     Depends(require_spiffe_id(...))
#   GET /openapi.json, /docs, /redoc          Depends(_require_gateway_identity)
#   GET /.well-known/yashigani-mcp-jwks.json  public; 404 mcp_not_configured guard
#   GET /mcp/health                           public; 503 mcp_not_configured guard
#   *   /{path:path}                          catch-all -> _handle_request()
# ===========================================================================

@pytest.fixture()
def gateway_app():
    from yashigani.gateway.proxy import create_gateway_app, GatewayConfig
    cfg = GatewayConfig(upstream_base_url="http://mcp:8080", opa_url="https://policy:8181")
    app = create_gateway_app(
        config=cfg,
        inspection_pipeline=None,
        chs=MagicMock(),
        audit_writer=MagicMock(),
        rate_limiter=None,
        rbac_store=None,
        agent_registry=None,
    )
    yield TestClient(app, raise_server_exceptions=False)


def test_gateway_healthz_is_public_no_auth(gateway_app):
    r = gateway_app.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_gateway_metrics_unauth_401_no_spiffe_header(gateway_app, monkeypatch):
    from yashigani.auth import spiffe as _spiffe
    monkeypatch.setattr(
        _spiffe, "_load_acls",
        lambda: {"/internal/metrics": frozenset({"spiffe://yashigani.internal/prometheus"})},
    )
    r = gateway_app.get("/internal/metrics")
    assert r.status_code == 401


def test_gateway_metrics_default_deny_403_when_no_acl(gateway_app, monkeypatch):
    """No ACL rule at all for the path -> 403 no_acl_for_path -- default-deny,
    never an implicit-allow when the manifest omits an endpoint."""
    from yashigani.auth import spiffe as _spiffe
    monkeypatch.setattr(_spiffe, "_load_acls", lambda: {})
    r = gateway_app.get(
        "/internal/metrics",
        headers={"X-SPIFFE-ID": "spiffe://yashigani.internal/prometheus"},
    )
    assert r.status_code == 403


def test_gateway_metrics_wrong_spiffe_403(gateway_app, monkeypatch):
    from yashigani.auth import spiffe as _spiffe
    monkeypatch.setattr(
        _spiffe, "_load_acls",
        lambda: {"/internal/metrics": frozenset({"spiffe://yashigani.internal/prometheus"})},
    )
    r = gateway_app.get(
        "/internal/metrics",
        headers={"X-SPIFFE-ID": "spiffe://yashigani.internal/some-other-workload"},
    )
    assert r.status_code == 403


def test_gateway_metrics_trusted_spiffe_200(gateway_app, monkeypatch):
    from yashigani.auth import spiffe as _spiffe
    monkeypatch.setattr(
        _spiffe, "_load_acls",
        lambda: {"/internal/metrics": frozenset({"spiffe://yashigani.internal/prometheus"})},
    )
    r = gateway_app.get(
        "/internal/metrics",
        headers={"X-SPIFFE-ID": "spiffe://yashigani.internal/prometheus"},
    )
    assert r.status_code == 200


def test_gateway_jwks_guard_404_when_mcp_not_configured(gateway_app):
    """No MCP servers configured on this install -> the JWKS guard 404s rather
    than forwarding to the (nonexistent) upstream -- FIND-3.1-004."""
    r = gateway_app.get("/.well-known/yashigani-mcp-jwks.json")
    assert r.status_code == 404
    assert r.json()["error"] == "mcp_not_configured"


def test_gateway_mcp_health_guard_503_when_mcp_not_configured(gateway_app):
    r = gateway_app.get("/mcp/health")
    assert r.status_code == 503
    assert r.json()["detail"] == "mcp_not_configured"


def test_gateway_openapi_unauth_401(gateway_app):
    r = gateway_app.get("/openapi.json")
    assert r.status_code == 401


def test_gateway_docs_unauth_401(gateway_app):
    r = gateway_app.get("/docs")
    assert r.status_code == 401


# ===========================================================================
# SECTION 9 — gateway/openai_router.py (/v1/*)
#
# Route inventory:
#   POST /v1/chat/completions   (identity-gated inline, no router-level Depends)
#   POST /v1/embeddings
#   GET  /v1/models
#
# Model-RBAC choke point: models/effective.py model_denied_for_caller() /
# resolve_effective_allowed_models() -- the SINGLE authority every /v1/*
# path consults (per source docstring, Track B1). Tested directly (unit
# level) for determinism, plus TestClient-level unauth/validation checks.
# ===========================================================================

def test_v1_chat_completions_unauth_401():
    from fastapi import FastAPI as _FA
    from yashigani.gateway.openai_router import router as _oa_router, configure as _oa_configure
    _oa_configure(opa_url="")  # dev opt-in path (YASHIGANI_OPA_OPTIONAL=true from module setup)
    app = _FA()
    app.include_router(_oa_router)
    tc = TestClient(app, raise_server_exceptions=False)
    r = tc.post("/v1/chat/completions", json={"model": "smart", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 401


def test_v1_models_unauth_401():
    from fastapi import FastAPI as _FA
    from yashigani.gateway.openai_router import router as _oa_router, configure as _oa_configure
    _oa_configure(opa_url="")
    app = _FA()
    app.include_router(_oa_router)
    tc = TestClient(app, raise_server_exceptions=False)
    r = tc.get("/v1/models")
    assert r.status_code == 401


@pytest.mark.parametrize("bad_model", [
    "",
    "http://evil.example.com/model",
    "../../etc/passwd",
    "null",
    "none",
    "undefined",
    "model\x00.bin",
    "model|rm -rf",
    "openai://gpt-4o",
    "​gpt-4o",  # zero-width space
])
def test_v1_model_string_validation_rejects_bad_input(bad_model):
    """LAURA-412-002: the positive-allowlist model-string validator rejects
    every known bypass class. A caller sending any of these must get 422 at
    the API boundary (validated at the TestClient level below), never reach
    RBAC or the local-default fallback."""
    from yashigani.gateway.openai_router import _validate_model_string
    assert _validate_model_string(bad_model) is not None, f"{bad_model!r} should be rejected"


def test_v1_model_string_validation_accepts_good_input():
    from yashigani.gateway.openai_router import _validate_model_string
    for good in ("gpt-4o", "openai:gpt-4o", "openai/gpt-4o", "qwen2.5:3b"):
        assert _validate_model_string(good) is None, f"{good!r} should be accepted"


def test_v1_model_string_agent_prefix_is_validator_accepted_not_call_site_exempted():
    """YSG-RISK-158 CLOSED: @-prefixed agent-call model strings used to be
    EXEMPTED from _validate_model_string entirely at the chat_completions
    call site (`if body.model and not is_agent_call and not
    brain_reasoning_leg:`) -- so a malicious "@"-prefixed payload (URL
    scheme, path traversal, null bytes) reached agent-routing code with
    ZERO of the validator's defenses. Fix: the "@" exemption now lives
    INSIDE _validate_model_string itself (_AGENT_CALL_VALID_RE) -- the call
    site validates ALL body.model values, agent calls included; a
    legitimate "@handle" is accepted by the validator, a malicious one is
    rejected by it. Only the SEPARATE normalization/known-model-allowlist
    gate below the validation call remains agent-call-exempt (an @-handle
    is an agent identifier resolved via agent_registry, not an LLM model
    name) -- confirmed by the second assertion below. See
    test_ysg_risk_158_agent_call_validator_exemption.py."""
    from yashigani.gateway.openai_router import _validate_model_string

    # A legitimate agent-call handle is now accepted BY THE VALIDATOR
    # (not merely skipped by the call site).
    assert _validate_model_string("@my-agent") is None
    # A malicious agent-call payload is REJECTED by the validator itself.
    assert _validate_model_string("@http://evil.example.com") is not None
    assert _validate_model_string("@../../etc/passwd") is not None

    # The normalization + known-model-allowlist gate (a DIFFERENT code path
    # to validation, not applicable to agent identifiers) remains
    # agent-call-exempt.
    import inspect as _inspect
    from yashigani.gateway import openai_router as _oa
    src = _inspect.getsource(_oa.chat_completions)
    assert "not is_agent_call and not brain_reasoning_leg" in src
    # ...but the validation call itself is NO LONGER agent-call-exempt.
    assert "if body.model and not brain_reasoning_leg:" in src


def test_v1_model_rbac_granted_cloud_model_not_denied():
    """A caller explicitly allocated a cloud model is NOT denied that model."""
    from yashigani.models.effective import model_denied_for_caller
    identity = {"identity_id": "alice", "allowed_models": ["openai:gpt-4o"], "groups": []}
    denied, effective = model_denied_for_caller(identity, "openai:gpt-4o", alloc_store=None, alias_store=None)
    assert denied is False
    assert effective.has_restriction is True


def test_v1_model_rbac_ungranted_cloud_model_denied_no_silent_local_fallback():
    """THE key assertion: a caller restricted to a LOCAL model is DENIED an
    ungranted CLOUD model -- there is no silent local-fallback substitution
    at the RBAC layer (is_model_denied returns True; the caller/route decides
    what happens next, but the choke point itself never says 'allowed')."""
    from yashigani.models.effective import model_denied_for_caller
    identity = {"identity_id": "bob", "allowed_models": ["qwen2.5:3b"], "groups": []}
    denied, effective = model_denied_for_caller(identity, "anthropic:claude-sonnet-4-6", alloc_store=None, alias_store=None)
    assert denied is True
    assert effective.has_restriction is True


def test_v1_model_rbac_brain_leg_exemption_is_server_minted_only():
    """The brain_leg=True exemption bypasses the deny -- confirms the
    exemption exists and is a NAMED KEYWORD ARG (never derived from any
    client-controllable field), per the function's own docstring contract."""
    from yashigani.models.effective import model_denied_for_caller
    identity = {"identity_id": "internal", "allowed_models": [], "groups": []}
    denied, _ = model_denied_for_caller(identity, "gated-brain-model", alloc_store=None, alias_store=None, brain_leg=True)
    assert denied is False
    import inspect as _inspect
    sig = _inspect.signature(model_denied_for_caller)
    assert sig.parameters["brain_leg"].kind == _inspect.Parameter.KEYWORD_ONLY


@pytest.mark.asyncio
async def test_v1_opa_v1_check_fail_closed_when_opa_not_configured_production():
    """OPA default-deny: opa_url empty + production env (no dev opt-in) ->
    deny, never a silent allow."""
    from yashigani.gateway import openai_router as _oa
    orig_url = _oa._state.opa_url
    _oa._state.opa_url = ""
    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("YASHIGANI_ENV", "production")
            mp.setenv("YASHIGANI_OPA_OPTIONAL", "false")
            result = await _oa._opa_v1_check(
                identity={"identity_id": "x", "groups": []},
                selected_model="gpt-4o",
                selected_provider="openai",
                sensitivity_level="PUBLIC",
                route_reason="test",
                request_path="/v1/chat/completions",
            )
        assert result["allow"] is False
        assert result["reason"] == "opa_not_configured"
    finally:
        _oa._state.opa_url = orig_url


# ===========================================================================
# SECTION 10 — gateway/_client_enforce.py
#
# In scope per brief. Pure-function fail-closed contract: any of
# not-configured / OPA-unreachable / undefined-result -> {"allow": False, ...}.
# ===========================================================================

@pytest.mark.asyncio
async def test_client_enforce_fail_closed_not_configured():
    from yashigani.gateway._client_enforce import evaluate_client_policies
    cfg = MagicMock(opa_url="")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("YASHIGANI_OPA_OPTIONAL", "false")
        mp.setenv("YASHIGANI_ENV", "production")
        result = await evaluate_client_policies(cfg, "human", "alice", "request", {})
    assert result["allow"] is False
    assert result["deny"] == ["client_enforce_not_configured"]


@pytest.mark.asyncio
async def test_client_enforce_fail_closed_opa_unreachable():
    from yashigani.gateway._client_enforce import evaluate_client_policies
    cfg = MagicMock(opa_url="https://policy-that-does-not-resolve.invalid:8181")
    result = await evaluate_client_policies(cfg, "agent", "agent-1", "response", {"foo": "bar"})
    assert result["allow"] is False
    assert result["deny"] == ["client_enforce_unavailable"]


@pytest.mark.asyncio
async def test_client_enforce_dev_opt_in_allows_when_not_configured():
    """Explicit dev opt-in (non-production + YASHIGANI_OPA_OPTIONAL=true) is
    the ONLY path that allows without OPA -- mirrors _opa_v1_check's
    documented dev-opt-in contract."""
    from yashigani.gateway._client_enforce import evaluate_client_policies
    cfg = MagicMock(opa_url="")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("YASHIGANI_OPA_OPTIONAL", "true")
        mp.setenv("YASHIGANI_ENV", "dev")
        result = await evaluate_client_policies(cfg, "human", "alice", "request", {})
    assert result["allow"] is True


def test_client_enforce_scope_kind_mapping_unknown_defaults_to_most_restrictive():
    from yashigani.gateway._client_enforce import scope_kind_for
    assert scope_kind_for("agent") == "agent"
    assert scope_kind_for("mcp_server") == "mcp_server"
    assert scope_kind_for(None) == "human"
    assert scope_kind_for("something-unrecognised") == "human"


# ===========================================================================
# SECTION 11 — gateway/agent_router.py + agent_auth.py (/agents/*)
# ===========================================================================

def test_agents_unauth_no_bearer_401():
    from yashigani.gateway.agent_auth import AgentAuthMiddleware
    app = FastAPI()

    @app.get("/agents/target/tools/list")
    async def _h():
        return {"ok": True}

    app.add_middleware(AgentAuthMiddleware, agent_registry=MagicMock(), audit_writer=MagicMock())
    tc = TestClient(app, raise_server_exceptions=False)
    r = tc.get("/agents/target/tools/list")
    assert r.status_code == 401
    assert r.json()["error"] == "AGENT_AUTH_FAILED"
    assert r.json()["reason"] == "missing_or_malformed_bearer"


def test_agents_unauth_missing_caller_id_header_401():
    from yashigani.gateway.agent_auth import AgentAuthMiddleware
    app = FastAPI()

    @app.get("/agents/target/tools/list")
    async def _h():
        return {"ok": True}

    app.add_middleware(AgentAuthMiddleware, agent_registry=MagicMock(), audit_writer=MagicMock())
    tc = TestClient(app, raise_server_exceptions=False)
    r = tc.get("/agents/target/tools/list", headers={"Authorization": "Bearer " + "a" * 64})
    assert r.status_code == 401
    assert r.json()["reason"] == "missing_caller_agent_id_header"


def test_agents_invalid_token_401():
    from yashigani.gateway.agent_auth import AgentAuthMiddleware
    app = FastAPI()

    @app.get("/agents/target/tools/list")
    async def _h():
        return {"ok": True}

    registry = MagicMock()
    registry.verify_token.return_value = False
    app.add_middleware(AgentAuthMiddleware, agent_registry=registry, audit_writer=MagicMock())
    tc = TestClient(app, raise_server_exceptions=False)
    r = tc.get(
        "/agents/target/tools/list",
        headers={"Authorization": "Bearer " + "a" * 64, "X-Yashigani-Caller-Agent-Id": "caller"},
    )
    assert r.status_code == 401
    assert r.json()["reason"] == "invalid_token"


def test_agents_registry_unavailable_fail_closed_503():
    """No agent_registry wired -> 503, never a silent allow."""
    from yashigani.gateway.agent_auth import AgentAuthMiddleware
    app = FastAPI()

    @app.get("/agents/target/tools/list")
    async def _h():
        return {"ok": True}

    app.add_middleware(AgentAuthMiddleware, agent_registry=None, audit_writer=MagicMock())
    tc = TestClient(app, raise_server_exceptions=False)
    r = tc.get(
        "/agents/target/tools/list",
        headers={"Authorization": "Bearer " + "a" * 64, "X-Yashigani-Caller-Agent-Id": "caller"},
    )
    assert r.status_code == 503


def test_agents_valid_token_passes_middleware():
    # NOTE: `Request` must be imported at MODULE level (see top-of-file
    # import) — not locally here — so FastAPI's get_type_hints() can resolve
    # the annotation via `_h.__globals__` under `from __future__ import
    # annotations` (see test_user_plane_contract.py for the documented
    # pitfall this avoids: a local-only import makes the type unresolvable
    # and FastAPI silently treats `request` as a required body param -> 422).
    from yashigani.gateway.agent_auth import AgentAuthMiddleware
    app = FastAPI()
    seen = {}

    @app.get("/agents/target/tools/list")
    async def _h(request: Request):
        seen["caller_type"] = getattr(request.state, "caller_type", None)
        return {"ok": True}

    registry = MagicMock()
    registry.verify_token.return_value = True
    registry.get.return_value = None
    app.add_middleware(AgentAuthMiddleware, agent_registry=registry, audit_writer=MagicMock())
    tc = TestClient(app, raise_server_exceptions=False)
    r = tc.get(
        "/agents/target/tools/list",
        headers={"Authorization": "Bearer " + "a" * 64, "X-Yashigani-Caller-Agent-Id": "caller"},
    )
    assert r.status_code == 200
    assert seen["caller_type"] == "agent"


@pytest.mark.asyncio
async def test_agents_opa_check_fail_closed_on_unreachable_opa():
    """route_agent_call's OPA gate (_opa_agent_check): unreachable OPA ->
    (False, "opa_unreachable") -- default-deny, never a silent allow when the
    policy engine cannot be consulted."""
    from yashigani.gateway.agent_router import _opa_agent_check
    allowed, reason = await _opa_agent_check(
        "https://policy-that-does-not-resolve.invalid:8181",
        {"principal": {"agent_id": "caller"}, "target_agent": {"agent_id": "target"}},
    )
    assert allowed is False
    assert reason == "opa_unreachable"


# ===========================================================================
# SECTION 12 — MCP: gateway/mcp_router_runtime.py (/mcp/{agent_name}) trust
# chain + auth/spiffe.py (the SAME require_spiffe_id gate mechanism reused
# across every mesh-internal endpoint, tested exhaustively in Section 8).
#
# Deep OPA-decision-shape / fail-closed coverage for the MCP tools/call path
# already exists in src/tests/unit/test_v250_p3p9_mcp_opa_policy.py,
# test_p3_mcp_broker_wiring.py, test_mcp_router_document_enforcement_gap1.py,
# and the egress-grant suite (test_v41_egress_grants.py) referenced above --
# this section adds the ROUTING + TRUST-CHAIN layer those files don't
# enumerate as a role-matrix.
# ===========================================================================

@pytest.mark.asyncio
async def test_mcp_dispatch_unknown_agent_name_404_not_500():
    """dispatch_mcp_call with an agent_name absent from the registry ->
    clean 404 MCP_SERVER_NOT_FOUND, never an unhandled exception."""
    from yashigani.gateway.mcp_router_runtime import dispatch_mcp_call
    from starlette.requests import Request as _Request

    registry = MagicMock()
    registry.get.return_value = None
    scope = {
        "type": "http", "method": "POST", "path": "/mcp/does-not-exist",
        "query_string": b"", "headers": [(b"content-type", b"application/json")],
    }
    request = _Request(scope)

    async def _receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}
    request._receive = _receive

    resp = await dispatch_mcp_call("does-not-exist", request, registry)
    assert resp.status_code == 404


def test_mcp_mesh_caller_is_internal_requires_valid_bearer_not_header_alone():
    """YSG-RISK-108 T-3/T-4 trust gate: presenting an identity-forwarding
    header WITHOUT the per-install internal bearer must NOT be treated as an
    internal mesh caller -- proves the trust chain is bearer-anchored, not
    header-trusting."""
    from yashigani.gateway.mcp_router_runtime import _mesh_caller_is_internal
    from starlette.requests import Request as _Request

    # No Authorization header at all -- spoofed identity header alone.
    scope_no_auth = {
        "type": "http", "method": "POST", "path": "/mcp/x", "query_string": b"",
        "headers": [(b"x-yashigani-identity-id", b"idnt_forged")],
    }
    assert _mesh_caller_is_internal(_Request(scope_no_auth)) is False

    # Wrong bearer value -- forged token, not the real per-install secret.
    scope_wrong_bearer = {
        "type": "http", "method": "POST", "path": "/mcp/x", "query_string": b"",
        "headers": [(b"authorization", b"Bearer wrong-token-value")],
    }
    assert _mesh_caller_is_internal(_Request(scope_wrong_bearer)) is False

    # Correct per-install bearer (matches YASHIGANI_INTERNAL_BEARER from
    # conftest/module bootstrap) -- proven internal.
    bearer = os.environ["YASHIGANI_INTERNAL_BEARER"]
    scope_valid = {
        "type": "http", "method": "POST", "path": "/mcp/x", "query_string": b"",
        "headers": [(b"authorization", f"Bearer {bearer}".encode())],
    }
    assert _mesh_caller_is_internal(_Request(scope_valid)) is True


@pytest.mark.parametrize("path,acl,header,expected_status,expected_error", [
    # Default-deny: no ACL rule at all for the path.
    ("/admin/agents", {}, "spiffe://yashigani.internal/x", 403, "no_acl_for_path"),
    # Trust-chain required: ACL exists but caller presents no SPIFFE identity.
    ("/admin/agents", {"/admin/agents": frozenset({"spiffe://yashigani.internal/x"})}, None, 401, "no_spiffe_id"),
    # Trust-chain proven but identity not on the allowlist.
    ("/admin/agents", {"/admin/agents": frozenset({"spiffe://yashigani.internal/x"})}, "spiffe://yashigani.internal/y", 403, "spiffe_id_not_allowed"),
])
def test_spiffe_trust_chain_gate_matrix(monkeypatch, path, acl, header, expected_status, expected_error):
    """require_spiffe_id is the SAME trust-chain-required + default-deny gate
    mechanism this codebase applies at every mesh-internal boundary (proven
    live at /internal/metrics in Section 8; also wired to
    /admin/agents,/admin/agent-policies). This matrix proves its three
    fail-closed branches independent of which route mounts it."""
    from fastapi import Depends as _Depends
    from yashigani.auth import spiffe as _spiffe
    monkeypatch.setattr(_spiffe, "_load_acls", lambda: acl)
    app = FastAPI()

    @app.get("/probe")
    async def _probe(caller: str = _Depends(_spiffe.require_spiffe_id(path))):
        return {"caller": caller}

    tc = TestClient(app, raise_server_exceptions=False)
    headers = {"X-SPIFFE-ID": header} if header else {}
    r = tc.get("/probe", headers=headers)
    assert r.status_code == expected_status
    assert r.json()["detail"] == expected_error


def test_spiffe_trust_chain_gate_allows_matching_identity(monkeypatch):
    from yashigani.auth import spiffe as _spiffe
    monkeypatch.setattr(
        _spiffe, "_load_acls",
        lambda: {"/admin/agents": frozenset({"spiffe://yashigani.internal/x"})},
    )
    from fastapi import Depends as _Depends
    app = FastAPI()

    @app.get("/probe")
    async def _probe(caller: str = _Depends(_spiffe.require_spiffe_id("/admin/agents"))):
        return {"caller": caller}

    tc = TestClient(app, raise_server_exceptions=False)
    r = tc.get("/probe", headers={"X-SPIFFE-ID": "spiffe://yashigani.internal/x"})
    assert r.status_code == 200
    assert r.json()["caller"] == "spiffe://yashigani.internal/x"
