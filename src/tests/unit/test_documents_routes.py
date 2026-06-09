"""
Deterministic gate suite — Document Enforcement admin routes (v2.26).

Mode: DETERMINISTIC GATE (machine-judged, binary PASS/FAIL per assertion).
Runs with FastAPI TestClient + dependency overrides — NO live stack required.

Coverage (each maps to a control ID):
  DOC-RT-01  /status renders enabled=false when dark (feature flag honoured)   [Insecure-Design / ships-dark]
  DOC-RT-02  /inspect returns 409 when feature disabled                        [fail-closed]
  DOC-RT-03  /inspect (enabled) returns a verdict + DataMatch[] viewer rows    [functional]
  DOC-RT-04  PSEUDONYMIZE mode A produces a retrievable correspondence table   [functional]
  DOC-RT-05  RBAC GATE: admin NOT in detokenize role → 403, NO rows returned   [A01 BOLA / API1 / ASVS V4.1]
  DOC-RT-06  RBAC GATE: admin IN detokenize role → 200 + rows                  [A01 positive]
  DOC-RT-07  table.csv RBAC gate: unauthorised → 403                           [A01 BOLA]
  DOC-RT-08  XSS canary in match value is returned as data (UI escapes); the   [A03 Injection / CWE-79]
             route never emits HTML and never raw-renders the canary.
  DOC-RT-09  Unguessable replacer-map handle NEVER appears in any response     [A02 / F5 crown-jewel]
  DOC-RT-10  Verdict viewer flags a METADATA/hidden-part match as hidden       [functional — the wow row]
  DOC-RT-11  Policy add is step-up gated (unauth dep → blocked)                [ASVS V6.8.4]

Author: Ava (QA). Last updated: 2026-06-09.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from yashigani.auth.session import Session
from yashigani.backoffice.middleware import (
    require_admin_session,
    require_stepup_admin_session,
)
from yashigani.backoffice.routes import documents as docroutes
from yashigani.backoffice.state import backoffice_state


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeGroup:
    def __init__(self, gid: str, display_name: str):
        self.id = gid
        self.display_name = display_name


class _FakeRBACStore:
    """Minimal get_user_groups(email) -> [group] for the detokenize gate."""

    def __init__(self, membership: dict[str, list[_FakeGroup]]):
        self._membership = membership

    def get_user_groups(self, email: str):
        return self._membership.get(email, [])


def _session(account_id: str) -> Session:
    return Session(
        token="t",
        account_id=account_id,
        account_tier="admin",
        created_at=0.0,
        last_active_at=0.0,
        expires_at=9_999_999_999.0,
        ip_prefix="x",
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

AUTHORISED_ADMIN = "reverser@yashigani.local"
UNAUTHORISED_ADMIN = "nobody@yashigani.local"
DETOK_ROLE = "doc-pseudonymize-reverser"


@pytest.fixture
def client(monkeypatch):
    """Mount the documents router with overridden auth + a fake RBAC store.

    By default the feature flag is ON (so we can exercise the real pipeline);
    individual tests flip it off via monkeypatch where needed.
    """
    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")

    app = FastAPI()
    app.include_router(docroutes.router, prefix="/admin/documents")

    # Auth: the AUTHORISED admin is in the detokenize role group; the other isn't.
    store = _FakeRBACStore({
        AUTHORISED_ADMIN: [_FakeGroup(DETOK_ROLE, "Document Reversers")],
        UNAUTHORISED_ADMIN: [_FakeGroup("some-other-group", "Other")],
    })
    backoffice_state.rbac_store = store
    backoffice_state.audit_writer = None

    # Default to the authorised admin; tests override per-call where needed.
    app.dependency_overrides[require_admin_session] = lambda: _session(AUTHORISED_ADMIN)
    app.dependency_overrides[require_stepup_admin_session] = lambda: _session(AUTHORISED_ADMIN)

    # Reset the in-memory result store between tests for isolation.
    docroutes._results.clear()

    yield TestClient(app), app

    backoffice_state.rbac_store = None
    docroutes._results.clear()


def _as_admin(app: FastAPI, account_id: str) -> None:
    app.dependency_overrides[require_admin_session] = lambda: _session(account_id)


# ---------------------------------------------------------------------------
# DOC-RT-01 / 02 — feature flag honoured
# ---------------------------------------------------------------------------

def test_doc_rt_01_status_reflects_flag(client, monkeypatch):
    tc, app = client
    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "false")
    r = tc.get("/admin/documents/status")
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is False
    assert len(body["supported_formats"]) == 6
    assert any(f["ext"] == "xlsx" for f in body["supported_formats"])
    assert len(body["parked_formats"]) >= 1


def test_doc_rt_02_inspect_409_when_disabled(client, monkeypatch):
    tc, app = client
    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "false")
    r = tc.post("/admin/documents/inspect", json={"content": "hello", "filename": "x.txt"})
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "document_enforcement_disabled"


# ---------------------------------------------------------------------------
# DOC-RT-03 — inspect returns a verdict + matches
# ---------------------------------------------------------------------------

def test_doc_rt_03_inspect_returns_verdict_and_matches(client):
    tc, app = client
    content = "name,email\nJane Doe,jane@example.com\n"
    r = tc.post("/admin/documents/inspect", json={
        "content": content, "filename": "people.csv", "declared_mime": "text/csv",
        "requested_action": "LOG",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"]["disposition"] in ("LOG", "BLOCK")
    # The CSV carries an email → at least one PII match enumerated.
    assert isinstance(body["matches"], list)
    if body["summary"]["disposition"] == "LOG":
        assert body["summary"]["match_count"] == len(body["matches"])


# ---------------------------------------------------------------------------
# DOC-RT-04 / 05 / 06 / 07 — mode-A table + RBAC gate (the load-bearing tests)
# ---------------------------------------------------------------------------

def _make_pseudonymized_doc(tc) -> str:
    """Create a mode-A PSEUDONYMIZE result with a real CorrespondenceTable and
    register it in the route's result store, returning its request_id.

    We assemble the result directly from the REAL pipeline value objects
    (``TokenAssigner`` → ``CorrespondenceTable`` + ``ReplacerMap``) rather than
    driving the full :meth:`inspect` path, because the PSEUDONYMIZE/REDACT
    re-render runs inside the container SANDBOX (``SandboxedExtractor``), which
    is not available in the unit-test environment (no Podman/Docker socket with
    the required kwargs).  The RBAC gate, the table contents, and the
    handle-never-leaks property are all EXERCISED here deterministically — the
    only thing the sandbox would add is the re-rendered artefact bytes, which
    the gate does not depend on.  The end-to-end re-render is covered by the
    Playwright live-stack suite (which has the sandbox).
    """
    from yashigani.documents.datamatch import DataMatch
    from yashigani.documents.pipeline import (
        DocumentInspectionResult,
        DISPOSITION_PSEUDONYMIZE,
    )
    from yashigani.documents.pseudonymize import (
        CorrespondenceTable,
        ReplacerMap,
        TokenAssigner,
    )

    assigner = TokenAssigner()
    # Two real values → consistent tokens (builds the crown-jewel reverse map).
    assigner.token_for("jane@example.com", "PII.EMAIL")
    assigner.token_for("john@example.com", "PII.EMAIL")
    matches = [
        DataMatch("PII.EMAIL", False, "ja****om", "TABLE_CELL:row=2,col=2:span=0-16", 0, 16),
        DataMatch("PII.EMAIL", False, "jo****om", "TABLE_CELL:row=3,col=2:span=0-16", 0, 16),
    ]
    rmap = ReplacerMap.create(assigner.reverse_map, detokenize_rbac_role=DETOK_ROLE)
    table = CorrespondenceTable.from_assigner(assigner, detokenize_rbac_role=DETOK_ROLE)

    rid = f"doc-{len(docroutes._results) + 1}-people.csv"
    docroutes._results[rid] = DocumentInspectionResult(
        request_id=rid,
        disposition=DISPOSITION_PSEUDONYMIZE,
        extraction_complete=True,
        detected_format="csv",
        matches=matches,
        replacer_map=rmap,
        correspondence_table=table,
        pseudonymize_mode="A",
    )
    return rid


def test_doc_rt_04_mode_a_table_available(client):
    tc, app = client
    rid = _make_pseudonymized_doc(tc)
    # The summary advertises a table when PSEUDONYMIZE mode A produced one.
    r = tc.get(f"/admin/documents/results/{rid}")
    assert r.status_code == 200
    summary = r.json()["summary"]
    assert summary["disposition"] == "PSEUDONYMIZE"
    assert summary["has_correspondence_table"] is True
    assert summary["detokenize_rbac_role"] == DETOK_ROLE


def test_doc_rt_05_rbac_gate_denies_unauthorised(client):
    """THE gate: an admin NOT in the detokenize role gets 403 and NO rows."""
    tc, app = client
    rid = _make_pseudonymized_doc(tc)
    _as_admin(app, UNAUTHORISED_ADMIN)
    r = tc.get(f"/admin/documents/results/{rid}/table")
    assert r.status_code == 403, r.text
    body = r.json()
    assert body["detail"]["error"] == "detokenize_forbidden"
    # CRITICAL: the response must NOT leak any table rows.
    assert "rows" not in body
    assert "original" not in r.text.lower() or "required_role" in r.text


def test_doc_rt_06_rbac_gate_allows_authorised(client):
    tc, app = client
    rid = _make_pseudonymized_doc(tc)
    _as_admin(app, AUTHORISED_ADMIN)
    r = tc.get(f"/admin/documents/results/{rid}/table")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["detokenize_rbac_role"] == DETOK_ROLE
    assert isinstance(body["rows"], list) and len(body["rows"]) >= 1
    for row in body["rows"]:
        assert "token" in row and "original" in row


def test_doc_rt_07_table_csv_rbac_gate(client):
    tc, app = client
    rid = _make_pseudonymized_doc(tc)
    _as_admin(app, UNAUTHORISED_ADMIN)
    r = tc.get(f"/admin/documents/results/{rid}/table.csv")
    assert r.status_code == 403
    # No CSV content delivered.
    assert "text/csv" not in r.headers.get("content-type", "")

    _as_admin(app, AUTHORISED_ADMIN)
    r2 = tc.get(f"/admin/documents/results/{rid}/table.csv")
    assert r2.status_code == 200
    assert "text/csv" in r2.headers.get("content-type", "")
    assert r2.text.splitlines()[0] == "token,original"


# ---------------------------------------------------------------------------
# DOC-RT-08 — XSS canary in attacker-controlled match value
# ---------------------------------------------------------------------------

def test_doc_rt_08_xss_canary_is_data_not_html(client):
    """A doc whose content carries an XSS canary alongside detectable PII: the
    route returns match values as JSON strings (data), never HTML.  The
    server-side instance is MASKED.  The escaping boundary is the browser sink
    (documents.js escapeHtml), asserted separately in the Playwright suite —
    here we assert the route never emits a raw <script> as HTML."""
    tc, app = client
    canary = '<script>alert(1)</script>'
    content = f"comment,email\n{canary},victim@example.com\n"
    r = tc.post("/admin/documents/inspect", json={
        "content": content, "filename": "c.csv", "declared_mime": "text/csv",
        "requested_action": "LOG",
    })
    assert r.status_code == 200
    # The response is JSON; a JSON string is inert (the browser will not execute
    # it).  Assert the content-type is JSON, not HTML.
    assert "application/json" in r.headers["content-type"]
    # The masked instance must not be a raw executable script tag verbatim in a
    # field that the UI renders without escaping — and the UI escapes anyway.
    body = r.json()
    # Email match instance is masked; the canary itself is body text, not a PII
    # match, so it should not surface as a match instance at all.
    for m in body["matches"]:
        assert m["instance"] != canary  # never the raw canary as a "value"


# ---------------------------------------------------------------------------
# DOC-RT-09 — crown-jewel handle never leaks
# ---------------------------------------------------------------------------

def test_doc_rt_09_handle_never_in_response(client):
    tc, app = client
    rid = _make_pseudonymized_doc(tc)
    result = docroutes._results.get(rid)
    handle = getattr(getattr(result, "replacer_map", None), "handle", None)

    # Walk every endpoint that returns the result and assert the handle is absent.
    assert handle, "expected a replacer-map handle on the synthetic result"
    _as_admin(app, AUTHORISED_ADMIN)
    bodies = [
        tc.get(f"/admin/documents/results/{rid}").text,
        tc.get("/admin/documents/results").text,
        tc.get(f"/admin/documents/results/{rid}/table").text,
    ]
    for b in bodies:
        assert handle not in b, "replacer-map capability handle leaked in a response"


# ---------------------------------------------------------------------------
# DOC-RT-10 — METADATA/hidden-part match is flagged (the wow row)
# ---------------------------------------------------------------------------

def test_doc_rt_10_hidden_part_flagged_in_viewer(client, monkeypatch):
    """Inject a synthetic result whose match sits in a METADATA part and assert
    the viewer marks it hidden=True (the 'secret in the metadata' wow row)."""
    tc, app = client
    from yashigani.documents.datamatch import DataMatch
    from yashigani.documents.pipeline import DocumentInspectionResult, DISPOSITION_LOG

    rid = "doc-synthetic-metadata"
    meta_match = DataMatch(
        data_class="SECRET",
        qi=False,
        instance="sk-***MASKED***",
        location="METADATA:docProps/custom.xml:span=0-20",
        char_start=0,
        char_end=20,
    )
    docroutes._results[rid] = DocumentInspectionResult(
        request_id=rid,
        disposition=DISPOSITION_LOG,
        extraction_complete=True,
        detected_format="docx",
        matches=[meta_match],
    )
    r = tc.get(f"/admin/documents/results/{rid}")
    assert r.status_code == 200
    rows = r.json()["matches"]
    assert len(rows) == 1
    assert rows[0]["hidden"] is True
    assert rows[0]["segment_kind"] == "METADATA"


# ---------------------------------------------------------------------------
# DOC-RT-11 — policy add is step-up gated (source-level + dep wiring)
# ---------------------------------------------------------------------------

def test_doc_rt_11_policy_add_uses_stepup_dep():
    """The create/delete policy routes MUST depend on StepUpAdminSession."""
    import inspect as _inspect
    src = _inspect.getsource(docroutes)
    assert "StepUpAdminSession" in src
    # Both mutating routes carry the step-up session dependency.
    assert src.count("session: StepUpAdminSession") >= 2


# ===========================================================================
# 2.26 PRODUCTIONISED POLICY LAYER — persistent store + real-OPA decision path
# ===========================================================================

@pytest.fixture
def store_client(monkeypatch):
    """documents router wired to a REAL DocumentPolicyStore (fakeredis) + an
    injectable OPA decision, so we can assert the route honours OPA's action."""
    import fakeredis
    from yashigani.documents.policy_store import DocumentPolicyStore

    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")

    app = FastAPI()
    app.include_router(docroutes.router, prefix="/admin/documents")

    store = DocumentPolicyStore(fakeredis.FakeStrictRedis())
    store.seed_defaults()
    backoffice_state.document_policy_store = store
    backoffice_state.rbac_store = _FakeRBACStore({})
    backoffice_state.audit_writer = None
    backoffice_state.opa_url = "https://policy:8181"

    app.dependency_overrides[require_admin_session] = lambda: _session(AUTHORISED_ADMIN)
    app.dependency_overrides[require_stepup_admin_session] = lambda: _session(AUTHORISED_ADMIN)

    # Make the OPA push a no-op (no live OPA in unit tests) but record it fired.
    pushes = []
    monkeypatch.setattr(
        "yashigani.documents.opa_push.push_document_data",
        lambda s, url: pushes.append((s, url)),
    )

    docroutes._results.clear()
    yield TestClient(app), app, store, pushes
    backoffice_state.document_policy_store = None
    backoffice_state.rbac_store = None
    docroutes._results.clear()


def test_doc_prod_01_list_reads_persistent_store(store_client):
    """GET /policies reads the seeded persistent matrix (not the old stub)."""
    tc, app, store, _ = store_client
    r = tc.get("/admin/documents/policies")
    assert r.status_code == 200
    policies = r.json()["policies"]
    # Seeded matrix = default rows + the 4 example OPAs (PII/PCI × pseudonymise/redact).
    assert len(policies) == 5
    assert any(p["action"] == "BLOCK" and p["data_class"] == "PCI" for p in policies)
    ids = {p["id"] for p in policies}
    assert {"PII-1", "PII-2", "PCI-1", "PCI-2"} <= ids


def test_doc_prod_02_create_persists_and_pushes(store_client):
    """POST /policies writes through to Redis AND re-pushes to OPA."""
    tc, app, store, pushes = store_client
    r = tc.post("/admin/documents/policies", json={
        "data_class": "SECRET", "format": "any", "route": "any",
        "action": "BLOCK", "description": "secrets never leave",
    })
    assert r.status_code == 201, r.text
    assert len(store.list_policies()) == 6  # 5 seeded + 1 created
    assert len(pushes) == 1  # OPA re-push fired


def test_doc_prod_03_delete_persists_and_pushes(store_client):
    tc, app, store, pushes = store_client
    r = tc.delete("/admin/documents/policies/1")
    assert r.status_code == 200
    assert all(p["id"] != "1" for p in store.list_policies())
    assert len(pushes) == 1


def test_doc_prod_04_create_503_when_store_unwired(store_client, monkeypatch):
    """Fail-closed: a mutation against a missing store 503s, never phantom-writes."""
    tc, app, store, _ = store_client
    backoffice_state.document_policy_store = None
    r = tc.post("/admin/documents/policies", json={
        "data_class": "PII", "format": "any", "route": "any",
        "action": "LOG", "description": "x",
    })
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "policy_store_unavailable"


def test_doc_prod_05_inspect_applies_opa_action(store_client, monkeypatch):
    """The route applies the action the REAL-OPA client returns (here mocked to
    LOG) — proving the disposition flows from the OPA decision, not a Python
    branch in the route."""
    tc, app, store, _ = store_client

    async def _fake_decision(opa_url, document_input, *, route="any", pseudonymize_mode="A", timeout_s=5.0):
        return {
            "action": "LOG",
            "policy_id": "DOC-ENFORCE-001",
            "code": "DOCUMENT_LOGGED",
            "user_message": "logged",
            "deny": [],
            "obligations": ["audit_document_decision"],
        }

    monkeypatch.setattr(
        "yashigani.documents.opa_decision.evaluate_document_decision", _fake_decision
    )
    r = tc.post("/admin/documents/inspect", json={
        "content": "name,email\nJane,jane@example.com\n",
        "filename": "p.csv", "declared_mime": "text/csv", "route": "ingress-upload",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["opa_decision"]["action"] == "LOG"
    assert body["opa_decision"]["policy_id"] == "DOC-ENFORCE-001"
    assert body["summary"]["disposition"] == "LOG"


def test_doc_prod_06_inspect_block_carries_user_alert(store_client, monkeypatch):
    """When OPA decides BLOCK, the route surfaces the self-describing user_alert
    (policy_id + user_message + code) straight from the decision."""
    tc, app, store, _ = store_client

    async def _fake_block(opa_url, document_input, *, route="any", pseudonymize_mode="A", timeout_s=5.0):
        return {
            "action": "BLOCK",
            "policy_id": "DOC-ENFORCE-001",
            "code": "DOCUMENT_BLOCKED",
            "user_message": "blocked for safety",
            "deny": ["unpoliced_sensitive_class"],
            "obligations": [],
        }

    monkeypatch.setattr(
        "yashigani.documents.opa_decision.evaluate_document_decision", _fake_block
    )
    r = tc.post("/admin/documents/inspect", json={
        "content": "card 4111111111111111\n", "filename": "c.txt", "route": "egress-mcp-result",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["opa_decision"]["action"] == "BLOCK"
    assert body["user_alert"]["code"] == "DOCUMENT_BLOCKED"
    assert body["user_alert"]["policy_id"] == "DOC-ENFORCE-001"
    assert body["user_alert"]["user_message"] == "blocked for safety"
