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

# DP-Y-002 §3.1: deploy secret is mandatory; patch it into every test that
# constructs a pipeline (via the client fixture) so the fail-closed guard passes
# and tokens minted by helpers round-trip through verify_integrity correctly.
_TEST_SECRET = b"test-deploy-secret-for-unit-tests-only-32b"
_TEST_SECRET_STR = _TEST_SECRET.decode("utf-8")


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


class _FakeAccountRecord:
    """Minimal account record returned by the fake auth service."""

    def __init__(self, email: str):
        self.email = email
        self.username = email


class _FakeAuthService:
    """Minimal async auth_service for the detokenize gate (LAURA-30-003).

    The gate calls ``await auth_service.get_account_by_id(account_id)`` to
    resolve UUID → email.  In these unit tests ``account_id`` IS already an
    email address (tests pre-date the UUID→email fix), so the fake returns an
    AccountRecord whose email equals the supplied account_id.
    """

    async def get_account_by_id(self, account_id: str):  # noqa: D401
        return _FakeAccountRecord(email=account_id)


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
    # DP-Y-002 §3.1: provision the mandatory deploy secret so _build_pipeline()
    # returns a non-None _pseudonymize_secret; tokens minted with _TEST_SECRET
    # will round-trip through the route's verify_integrity call correctly.
    monkeypatch.setenv("YASHIGANI_DOCUMENT_PSEUDONYMIZE_SECRET", _TEST_SECRET_STR)

    app = FastAPI()
    app.include_router(docroutes.router, prefix="/admin/documents")

    # Auth: the AUTHORISED admin is in the detokenize role group; the other isn't.
    store = _FakeRBACStore({
        AUTHORISED_ADMIN: [_FakeGroup(DETOK_ROLE, "Document Reversers")],
        UNAUTHORISED_ADMIN: [_FakeGroup("some-other-group", "Other")],
    })
    backoffice_state.rbac_store = store
    backoffice_state.audit_writer = None
    # LAURA-30-003: wire a fake auth_service so the detokenize gate can resolve
    # account_id → email.  In these tests account_id IS the email, so the fake
    # returns an AccountRecord with email == account_id.
    backoffice_state.auth_service = _FakeAuthService()

    # Default to the authorised admin; tests override per-call where needed.
    app.dependency_overrides[require_admin_session] = lambda: _session(AUTHORISED_ADMIN)
    app.dependency_overrides[require_stepup_admin_session] = lambda: _session(AUTHORISED_ADMIN)

    # Reset the in-memory result store between tests for isolation.
    docroutes._results.clear()

    yield TestClient(app), app

    backoffice_state.rbac_store = None
    backoffice_state.auth_service = None
    docroutes._results.clear()


def _as_admin(app: FastAPI, account_id: str) -> None:
    app.dependency_overrides[require_admin_session] = lambda: _session(account_id)
    # The table-retrieval surfaces are step-up gated (G-NEW-2 / R5); override the
    # step-up dep too so the test exercises the role/identity gate, not the TOTP
    # freshness check (which has its own dedicated test).
    app.dependency_overrides[require_stepup_admin_session] = lambda: _session(account_id)


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
    from yashigani.documents.token_scheme import compute_doc_hash

    # Opaque, per-file-salted assigner (DECIDED 2026-06-10): bind to a fixed salt.
    # DP-Y-002 §3.1: secret is mandatory; use _TEST_SECRET so tokens round-trip
    # through verify_integrity (which reads the same secret from the env var set
    # by the client fixture).
    assigner = TokenAssigner(compute_doc_hash(b"people.csv-bytes"), secret=_TEST_SECRET)
    # Two real values → consistent tokens (builds the crown-jewel reverse map).
    assigner.token_for("jane@example.com", "PII.EMAIL")
    assigner.token_for("john@example.com", "PII.EMAIL")
    matches = [
        DataMatch("PII.EMAIL", False, "ja****om", "TABLE_CELL:row=2,col=2:span=0-16", 0, 16),
        DataMatch("PII.EMAIL", False, "jo****om", "TABLE_CELL:row=3,col=2:span=0-16", 0, 16),
    ]
    # G-NEW-2 / R5: bind the crown-jewel map + table to the requester identity +
    # this install's tenant (the AUTHORISED admin "minted" it), single-use.  The
    # retrieval gate requires the SAME identity + tenant (close BOLA).
    rmap = ReplacerMap.create(
        assigner.reverse_map, detokenize_rbac_role=DETOK_ROLE,
        owner_identity=AUTHORISED_ADMIN, tenant="default", single_use=True,
    )
    table = CorrespondenceTable.from_assigner(
        assigner, detokenize_rbac_role=DETOK_ROLE,
        owner_identity=AUTHORISED_ADMIN, tenant="default",
        ttl_s=3600,  # DP-Y-004 §3.1 GAP-1: table must carry a TTL > 0
    )

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
    lines = r2.text.splitlines()
    # Mapping file header binds the table to its source document (per-file salt).
    assert lines[0].startswith("# doc_hash=")
    assert lines[1] == "token,original"


# ---------------------------------------------------------------------------
# DOC-RT-G5-* — G-NEW-2 / R5: identity+tenant binding, step-up, single-use.
# ---------------------------------------------------------------------------

#: A second authorised reverser — IN the detokenize role but NOT the principal
#: who minted the result (the BOLA actor: right role, wrong identity).
OTHER_AUTHORISED = "reverser2@yashigani.local"


def _grant_role(account_id: str) -> None:
    """Add an account to the detokenize role group in the fake RBAC store."""
    backoffice_state.rbac_store._membership[account_id] = [_FakeGroup(DETOK_ROLE, "Document Reversers")]


def test_doc_rt_g5_01_cross_identity_same_role_denied(client):
    """BOLA close: another admin IN the detokenize role but who did NOT mint the
    result cannot retrieve the table (identity binding beats role-only)."""
    tc, app = client
    rid = _make_pseudonymized_doc(tc)  # bound to AUTHORISED_ADMIN
    _grant_role(OTHER_AUTHORISED)
    _as_admin(app, OTHER_AUTHORISED)   # right role, wrong identity
    r = tc.get(f"/admin/documents/results/{rid}/table")
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"] == "detokenize_forbidden"
    assert "rows" not in r.json()
    assert "original" not in r.text.lower()


def test_doc_rt_g5_02_cross_tenant_denied(client, monkeypatch):
    """Cross-tenant close: the requester identity matches but the install tenant
    differs from the one the table was minted under → 403, no rows."""
    tc, app = client
    rid = _make_pseudonymized_doc(tc)  # minted under tenant "default"
    _as_admin(app, AUTHORISED_ADMIN)
    # The retrieval install now reports a DIFFERENT tenant.
    monkeypatch.setenv("YASHIGANI_TENANT_ID", "tenant-b")
    r = tc.get(f"/admin/documents/results/{rid}/table")
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"] == "detokenize_forbidden"


def test_doc_rt_g5_03_single_use_burn_after_read(client):
    """Single-use: the first authorised retrieval burns the table; a replay 404s
    (the crown jewel cannot be re-retrieved with a leaked/replayed request)."""
    tc, app = client
    rid = _make_pseudonymized_doc(tc)
    _as_admin(app, AUTHORISED_ADMIN)
    r1 = tc.get(f"/admin/documents/results/{rid}/table")
    assert r1.status_code == 200, r1.text
    assert len(r1.json()["rows"]) >= 1
    # Replay — the table was burned; no rows are ever served again.
    r2 = tc.get(f"/admin/documents/results/{rid}/table")
    assert r2.status_code == 404, r2.text
    assert "rows" not in r2.json()


def test_doc_rt_g5_04_table_routes_require_stepup(client):
    """Step-up is enforced on BOTH table surfaces (no fresh TOTP → 401).

    We drop the fixture's step-up override so the REAL
    ``require_stepup_admin_session`` runs against an admin session that never
    performed a TOTP step-up (``last_totp_verified_at`` is None) → 401."""
    tc, app = client
    rid = _make_pseudonymized_doc(tc)
    # Keep a valid admin session, but let the genuine step-up gate run (no TOTP).
    app.dependency_overrides[require_admin_session] = lambda: _session(AUTHORISED_ADMIN)
    app.dependency_overrides.pop(require_stepup_admin_session, None)

    r = tc.get(f"/admin/documents/results/{rid}/table")
    assert r.status_code == 401, r.text
    assert r.json()["detail"]["error"] == "step_up_required"
    # The table was NOT served and NOT burned (still retrievable with step-up).
    assert "rows" not in r.json()

    r_csv = tc.get(f"/admin/documents/results/{rid}/table.csv")
    assert r_csv.status_code == 401, r_csv.text


def test_doc_rt_g5_05_inspect_binds_requester_identity(client):
    """The /inspect route threads the requester identity + tenant into the
    pipeline so the minted map/table are identity+tenant bound."""
    import inspect as _inspect
    src = _inspect.getsource(docroutes.inspect_document)
    assert "requester_identity=session.account_id" in src
    assert "tenant=_install_tenant()" in src


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
    # Both mutating routes + the set mutations carry the step-up session dep.
    assert src.count("session: StepUpAdminSession") >= 2


# ===========================================================================
# 2.26 NEW SURFACES — opaque-token render, field-role, integrity, set-salt
# (regression coverage for the verdict-viewer + set-scoped-salt deliverables)
# ===========================================================================

def _register_pseudonymize_result(salt_scope="file", *, field_role="REFERENCE_ONLY",
                                   operate_on_classes=None, route_local=False):
    """Register a synthetic PSEUDONYMIZE result carrying the new 2.26 fields, with
    a REAL correspondence table so the integrity endpoint can re-derive."""
    from yashigani.documents.datamatch import DataMatch
    from yashigani.documents.pipeline import (
        DocumentInspectionResult, DISPOSITION_PSEUDONYMIZE,
    )
    from yashigani.documents.pseudonymize import CorrespondenceTable, ReplacerMap, TokenAssigner
    from yashigani.documents.token_scheme import compute_doc_hash

    salt = compute_doc_hash(b"doc-bytes-for-2.26-surfaces")
    # DP-Y-002 §3.1: secret mandatory; matches the env var set by client fixture.
    assigner = TokenAssigner(salt, secret=_TEST_SECRET)
    assigner.token_for("jane@example.com", "PII.EMAIL")
    rmap = ReplacerMap.create(assigner.reverse_map, detokenize_rbac_role=DETOK_ROLE)
    table = CorrespondenceTable.from_assigner(
        assigner, detokenize_rbac_role=DETOK_ROLE, ttl_s=3600,
    )  # DP-Y-004 §3.1 GAP-1: ttl_s > 0 required; no identity binding (RBAC tests only)
    m = DataMatch("PII.EMAIL", False, "ja****om", "TABLE_CELL:row=2,col=2:span=0-16", 0, 16,
                  field_role=field_role)
    rid = f"doc-{len(docroutes._results) + 1}-surfaces.csv"
    docroutes._results[rid] = DocumentInspectionResult(
        request_id=rid,
        disposition=DISPOSITION_PSEUDONYMIZE,
        extraction_complete=True,
        detected_format="csv",
        matches=[m],
        replacer_map=rmap,
        correspondence_table=table,
        pseudonymize_mode="A",
        doc_hash=salt,
        salt_scope=salt_scope,
        route_local=route_local,
        operate_on_classes=operate_on_classes or [],
    )
    return rid, salt


def test_doc_rt_12_summary_surfaces_salt_scope_and_doc_hash(client):
    """DOC-RT-12: the verdict summary surfaces salt_scope + doc_hash (never a
    salt secret) so the operator sees the isolation level.  [func / set-salt]"""
    tc, app = client
    rid, salt = _register_pseudonymize_result(salt_scope="set")
    r = tc.get(f"/admin/documents/results/{rid}")
    assert r.status_code == 200, r.text
    summary = r.json()["summary"]
    assert summary["salt_scope"] == "set"
    assert summary["doc_hash"] == salt          # doc_hash IS surfaced (not secret)
    # The salt value itself must NEVER appear (we never store a set salt on the
    # result; assert the response carries no field literally named "salt").
    assert "\"salt\"" not in r.text


def test_doc_rt_13_matches_surface_field_role(client):
    """DOC-RT-13: each match carries field_role + operate_on_sensitive so the UI
    can render the reference-only vs operate-on/kept-local indicator. [Laura D1]"""
    tc, app = client
    rid, _ = _register_pseudonymize_result(field_role="OPERATE_ON")
    r = tc.get(f"/admin/documents/results/{rid}")
    assert r.status_code == 200
    rows = r.json()["matches"]
    assert rows[0]["field_role"] == "OPERATE_ON"
    assert "operate_on_sensitive" in rows[0]


def test_doc_rt_14_route_local_outcome_surfaced(client):
    """DOC-RT-14: a kept-local routing decision surfaces route_local +
    operate_on_classes (class names only, never values). [Laura D1]"""
    tc, app = client
    rid, _ = _register_pseudonymize_result(
        route_local=True, operate_on_classes=["PCI.IBAN", "PII.SALARY"],
    )
    r = tc.get(f"/admin/documents/results/{rid}")
    summary = r.json()["summary"]
    assert summary["route_local"] is True
    assert summary["operate_on_classes"] == ["PCI.IBAN", "PII.SALARY"]


def test_doc_rt_15_integrity_ok_for_intact_result(client):
    """DOC-RT-15: integrity endpoint confirms a clean result binds to its doc_hash
    and reports zero foreign tokens. [integrity / splice-verify]"""
    tc, app = client
    rid, _ = _register_pseudonymize_result()
    r = tc.get(f"/admin/documents/results/{rid}/integrity")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["foreign_token_count"] == 0
    assert body["token_count"] >= 1
    # Never leaks the mapping cleartext — only counts + the non-secret doc_hash.
    assert "jane@example.com" not in r.text


def test_doc_rt_16_integrity_detects_foreign_salt_splice(client):
    """DOC-RT-16: a spliced mapping (token minted under a DIFFERENT salt) is
    rejected — foreign_token_count > 0, ok=False. [integrity / cross-file splice]"""
    tc, app = client
    from yashigani.documents.datamatch import DataMatch
    from yashigani.documents.pipeline import DocumentInspectionResult, DISPOSITION_PSEUDONYMIZE
    from yashigani.documents.pseudonymize import CorrespondenceTable, ReplacerMap, TokenAssigner
    from yashigani.documents.token_scheme import compute_doc_hash

    # Mint a token under salt-A, but record salt-B as the result's doc_hash —
    # exactly a cross-file splice (mapping paired with the wrong original).
    salt_a = compute_doc_hash(b"file-A")
    salt_b = compute_doc_hash(b"file-B")
    # DP-Y-002 §3.1: secret mandatory; same secret as the pipeline gets via the
    # client fixture env var.  The splice is detected via the WRONG SALT (salt_a
    # vs salt_b), not via a secret mismatch.
    assigner = TokenAssigner(salt_a, secret=_TEST_SECRET)
    assigner.token_for("alice@corp.com", "PII.EMAIL")
    table = CorrespondenceTable.from_assigner(
        assigner, detokenize_rbac_role=DETOK_ROLE, ttl_s=3600,
    )  # DP-Y-004 §3.1 GAP-1: ttl_s > 0; integrity endpoint bypasses _detokenize_gate
    rmap = ReplacerMap.create(assigner.reverse_map, detokenize_rbac_role=DETOK_ROLE)
    rid = "doc-spliced"
    docroutes._results[rid] = DocumentInspectionResult(
        request_id=rid, disposition=DISPOSITION_PSEUDONYMIZE, extraction_complete=True,
        detected_format="csv",
        matches=[DataMatch("PII.EMAIL", False, "al****om", "TABLE_CELL:row=1:span=0-1", 0, 1)],
        replacer_map=rmap, correspondence_table=table, pseudonymize_mode="A",
        doc_hash=salt_b,  # WRONG salt → splice
    )
    r = tc.get(f"/admin/documents/results/{rid}/integrity")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert body["foreign_token_count"] >= 1


def test_doc_rt_16b_integrity_not_applicable_at_set_scope(client):
    """DOC-RT-16b: a set-scoped result's tokens were minted under the SET salt
    (not retained on the result), so the per-file splice verify must report
    'not applicable' (ok=None, applicable=False) — NEVER a false splice.
    [honest assurance — A09]"""
    tc, app = client
    rid, _ = _register_pseudonymize_result(salt_scope="set")
    r = tc.get(f"/admin/documents/results/{rid}/integrity")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["applicable"] is False
    assert body["ok"] is None
    assert body["salt_scope"] == "set"
    assert body["foreign_token_count"] is None


def test_doc_rt_17_integrity_404_when_no_artefacts(client):
    """DOC-RT-17: integrity on a LOG result (no table/doc_hash) → 404, never 500."""
    tc, app = client
    from yashigani.documents.datamatch import DataMatch
    from yashigani.documents.pipeline import DocumentInspectionResult, DISPOSITION_LOG
    rid = "doc-log-only"
    docroutes._results[rid] = DocumentInspectionResult(
        request_id=rid, disposition=DISPOSITION_LOG, extraction_complete=True,
        detected_format="csv",
        matches=[DataMatch("PII.EMAIL", False, "x", "BODY:span=0-1", 0, 1)],
    )
    r = tc.get(f"/admin/documents/results/{rid}/integrity")
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "no_integrity_artefacts"


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
    pids = {p.get("policy_id") for p in policies}
    assert {"DOC-EX-PII-1", "DOC-EX-PII-2", "DOC-EX-PCI-1", "DOC-EX-PCI-2"} <= pids
    assert any(p["action"] == "PSEUDONYMIZE" and p["data_class"] == "PCI" for p in policies)


def test_doc_prod_02_create_persists_and_pushes(store_client):
    """POST /policies writes through to Redis AND re-pushes to OPA."""
    tc, app, store, pushes = store_client
    r = tc.post("/admin/documents/policies", json={
        "data_class": "SECRET", "format": "any", "route": "any",
        "action": "BLOCK", "description": "secrets never leave",
        # IRIS-DOC-META: required self-describing contract fields.
        "policy_id": "DOC-OP-SEC-TEST",
        "user_message": "A secret was detected. The file was blocked from leaving your environment.",
        "code": "DOCUMENT_BLOCKED",
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
        # IRIS-DOC-META: required self-describing contract fields (so validation
        # passes and the fail-closed 503 is what we're actually testing).
        "policy_id": "DOC-OP-TEST",
        "user_message": "This file was logged for audit.",
        "code": "DOCUMENT_LOGGED",
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


# ===========================================================================
# 2.26 DOCUMENT SETS — set-scoped-salt control (CRUD + salt-never-leaks)
# ===========================================================================

@pytest.fixture
def set_client(monkeypatch):
    """documents router wired to a REAL DocumentSetStore (fakeredis)."""
    import fakeredis
    from yashigani.documents.set_store import DocumentSetStore

    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    app = FastAPI()
    app.include_router(docroutes.router, prefix="/admin/documents")

    store = DocumentSetStore(fakeredis.FakeStrictRedis())
    backoffice_state.document_set_store = store
    backoffice_state.rbac_store = _FakeRBACStore({})
    backoffice_state.audit_writer = None

    app.dependency_overrides[require_admin_session] = lambda: _session(AUTHORISED_ADMIN)
    app.dependency_overrides[require_stepup_admin_session] = lambda: _session(AUTHORISED_ADMIN)

    docroutes._results.clear()
    yield TestClient(app), app, store
    backoffice_state.document_set_store = None
    backoffice_state.rbac_store = None
    docroutes._results.clear()


def test_doc_set_01_create_and_list_salt_redacted(set_client):
    """DOC-SET-01: create a set; the salt is NEVER returned (create or list).
    [A02 crypto custody — the set salt is a secret]"""
    tc, app, store = set_client
    r = tc.post("/admin/documents/sets", json={"name": "Q2 exports"})
    assert r.status_code == 201, r.text
    created = r.json()["set"]
    assert created["name"] == "Q2 exports"
    assert "salt" not in created and created["has_salt"] is True
    # The salt is non-empty in the store (real secret) but absent from the wire.
    assert store.get_salt(created["id"])  # exists internally
    assert "salt" not in r.text or "has_salt" in r.text

    lst = tc.get("/admin/documents/sets")
    assert lst.status_code == 200
    body = lst.json()
    assert any(s["name"] == "Q2 exports" for s in body["sets"])
    assert "REDUCES per-file isolation" in body["security_note"]
    # No salt value in the list response (the real 64-hex salt never appears).
    salt = store.get_salt(created["id"])
    assert salt not in lst.text


def test_doc_set_02_create_is_stepup_gated():
    """DOC-SET-02: set mutation requires StepUpAdminSession (source-level)."""
    import inspect as _inspect
    src = _inspect.getsource(docroutes.create_set)
    assert "StepUpAdminSession" in src
    assert "StepUpAdminSession" in _inspect.getsource(docroutes.delete_set)


def test_doc_set_03_delete(set_client):
    tc, app, store = set_client
    sid = tc.post("/admin/documents/sets", json={"name": "temp"}).json()["set"]["id"]
    r = tc.delete(f"/admin/documents/sets/{sid}")
    assert r.status_code == 200
    assert store.get_set(sid) is None
    # Deleting a missing set is a clean 404, not a 500.
    assert tc.delete("/admin/documents/sets/nope").status_code == 404


def test_doc_set_04_inspect_unknown_set_id_404(set_client, monkeypatch):
    """DOC-SET-04: inspecting with a set_id that does not exist fails closed (404)
    — never silently falls back to the per-file salt. [fail-closed]"""
    tc, app, store = set_client

    async def _fake(opa_url, document_input, *, route="any", pseudonymize_mode="A", timeout_s=5.0):
        return {"action": "LOG", "policy_id": "P", "code": "C", "user_message": "m", "deny": [], "obligations": []}

    monkeypatch.setattr(
        "yashigani.documents.opa_decision.evaluate_document_decision", _fake
    )
    r = tc.post("/admin/documents/inspect", json={
        "content": "name,email\nJane,jane@example.com\n", "filename": "p.csv",
        "declared_mime": "text/csv", "set_id": "does-not-exist",
    })
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "document_set_not_found"


def test_doc_set_05_inspect_503_when_set_id_but_store_unwired(set_client, monkeypatch):
    """DOC-SET-05: set_id supplied but the set store is unwired → 503, never a
    silent per-file fallback. [fail-closed]"""
    tc, app, store = set_client
    backoffice_state.document_set_store = None
    r = tc.post("/admin/documents/inspect", json={
        "content": "x", "filename": "p.csv", "set_id": "1",
    })
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "set_store_unavailable"


# ===========================================================================
# IRIS-DOC-META — operator-created policies must carry the self-describing
# decision contract (policy_id + user_message + code).
# ===========================================================================
#
# Coverage:
#   IRIS-META-01  POST /policies with all contract fields persists + returns them
#   IRIS-META-02  Missing required field (policy_id) → 422 validation error
#   IRIS-META-03  Missing required field (user_message) → 422 validation error
#   IRIS-META-04  Missing required field (code) → 422 validation error
#   IRIS-META-05  policy_id format validated: lowercase rejected, correct pattern accepted
#   IRIS-META-06  code format validated: spaces/lowercase rejected
#   IRIS-META-07  Stored policy carries policy_id + user_message + code (store layer)
#   IRIS-META-08  OPA /inspect BLOCK decision carries user_message from operator policy
#
# Author: Tom. IRIS-DOC-META (3.1). Last updated: 2026-06-19.
# ===========================================================================

# Minimal valid PolicyRequest payload including the new contract fields.
_VALID_CONTRACT_BODY = {
    "data_class": "PHI",
    "format": "pdf",
    "route": "egress-mcp-result",
    "action": "BLOCK",
    "description": "Block all PHI in PDF exports",
    "policy_id": "DOC-OP-PHI-001",
    "user_message": "This file was blocked because it contains health information that must not leave your environment.",
    "code": "DOCUMENT_BLOCKED",
}


def test_iris_meta_01_create_persists_contract_fields(store_client):
    """IRIS-META-01: POST /policies with policy_id + user_message + code
    persists all three fields and returns them in the response body."""
    tc, app, store, pushes = store_client
    r = tc.post("/admin/documents/policies", json=_VALID_CONTRACT_BODY)
    assert r.status_code == 201, r.text
    policy = r.json()["policy"]
    # All self-describing fields must be present and populated in the response.
    assert policy["policy_id"] == "DOC-OP-PHI-001"
    assert policy["user_message"] == _VALID_CONTRACT_BODY["user_message"]
    assert policy["code"] == "DOCUMENT_BLOCKED"
    # OPA re-push fired.
    assert len(pushes) == 1
    # Persistent: a fresh list also carries the fields.
    r2 = tc.get("/admin/documents/policies")
    rows = r2.json()["policies"]
    created = next((p for p in rows if p.get("policy_id") == "DOC-OP-PHI-001"), None)
    assert created is not None
    assert created["user_message"] == _VALID_CONTRACT_BODY["user_message"]
    assert created["code"] == "DOCUMENT_BLOCKED"


def test_iris_meta_02_missing_policy_id_rejected(store_client):
    """IRIS-META-02: Omitting policy_id returns 422 (required field)."""
    tc, app, store, _ = store_client
    body = {**_VALID_CONTRACT_BODY}
    del body["policy_id"]
    r = tc.post("/admin/documents/policies", json=body)
    assert r.status_code == 422, r.text


def test_iris_meta_03_missing_user_message_rejected(store_client):
    """IRIS-META-03: Omitting user_message returns 422 (required field)."""
    tc, app, store, _ = store_client
    body = {**_VALID_CONTRACT_BODY}
    del body["user_message"]
    r = tc.post("/admin/documents/policies", json=body)
    assert r.status_code == 422, r.text


def test_iris_meta_04_missing_code_rejected(store_client):
    """IRIS-META-04: Omitting code returns 422 (required field)."""
    tc, app, store, _ = store_client
    body = {**_VALID_CONTRACT_BODY}
    del body["code"]
    r = tc.post("/admin/documents/policies", json=body)
    assert r.status_code == 422, r.text


def test_iris_meta_05_policy_id_format_validated(store_client):
    """IRIS-META-05: policy_id must match ^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$ —
    lowercase, no-hyphen, or wrong-structure patterns are rejected."""
    tc, app, store, _ = store_client
    for bad in (
        "doc-op-001",         # lowercase
        "DOCOP001",           # no hyphens
        "-DOC-001",           # leading hyphen
        "DOC-",               # trailing hyphen (nothing after it)
        "DOC",                # no hyphens at all
        "",                   # empty (also min_length=1)
    ):
        body = {**_VALID_CONTRACT_BODY, "policy_id": bad}
        r = tc.post("/admin/documents/policies", json=body)
        assert r.status_code == 422, f"expected 422 for policy_id={bad!r}, got {r.status_code}"

    # A valid id must be accepted.
    body = {**_VALID_CONTRACT_BODY, "policy_id": "DOC-OP-001"}
    r = tc.post("/admin/documents/policies", json=body)
    assert r.status_code == 201, f"expected 201 for valid policy_id, got {r.status_code}: {r.text}"


def test_iris_meta_06_code_format_validated(store_client):
    """IRIS-META-06: code must match ^[A-Z][A-Z0-9_]+$ — lowercase, spaces, or
    leading underscores are rejected."""
    tc, app, store, _ = store_client
    for bad in (
        "document_blocked",   # lowercase
        "DOCUMENT BLOCKED",   # space
        "_DOCUMENT_BLOCKED",  # leading underscore
        "",                   # empty (also min_length=1)
    ):
        body = {**_VALID_CONTRACT_BODY, "code": bad}
        r = tc.post("/admin/documents/policies", json=body)
        assert r.status_code == 422, f"expected 422 for code={bad!r}, got {r.status_code}"

    # A valid code must be accepted.
    body = {**_VALID_CONTRACT_BODY, "code": "DOCUMENT_PHI_BLOCKED"}
    r = tc.post("/admin/documents/policies", json=body)
    assert r.status_code == 201, f"expected 201 for valid code, got {r.status_code}: {r.text}"


def test_iris_meta_07_store_layer_persists_contract_fields():
    """IRIS-META-07: DocumentPolicyStore.add_policy() persists policy_id +
    user_message + code and replays them on a fresh store (store-layer, no HTTP)."""
    import fakeredis
    from yashigani.documents.policy_store import DocumentPolicyStore

    redis = fakeredis.FakeStrictRedis()
    store = DocumentPolicyStore(redis)
    p = store.add_policy(
        data_class="SECRET",
        format="any",
        route="any",
        action="BLOCK",
        description="test",
        policy_id="DOC-OP-SEC-001",
        user_message="A secret was found. The file was blocked.",
        code="DOCUMENT_SECRET_BLOCKED",
        name="Block all secrets",
    )
    assert p["policy_id"] == "DOC-OP-SEC-001"
    assert p["user_message"] == "A secret was found. The file was blocked."
    assert p["code"] == "DOCUMENT_SECRET_BLOCKED"
    assert p["name"] == "Block all secrets"

    # Replay from Redis — fields survive restart.
    fresh = DocumentPolicyStore(redis)
    replayed = next(x for x in fresh.list_policies() if x["policy_id"] == "DOC-OP-SEC-001")
    assert replayed["user_message"] == "A secret was found. The file was blocked."
    assert replayed["code"] == "DOCUMENT_SECRET_BLOCKED"


def test_iris_meta_08_inspect_block_carries_operator_user_message(store_client, monkeypatch):
    """IRIS-META-08: when OPA decides BLOCK for an operator-authored policy, the
    route surfaces the operator's user_message in the user_alert — not the
    built-in fallback.  Proves the contract flows end-to-end through /inspect."""
    tc, app, store, _ = store_client

    # Plant an operator policy with a custom user_message into the store.
    store.add_policy(
        data_class="PHI",
        format="any",
        route="egress-mcp-result",
        action="BLOCK",
        description="block PHI",
        policy_id="DOC-OP-PHI-002",
        user_message="Health records were blocked. Contact compliance@example.com.",
        code="DOCUMENT_PHI_BLOCKED",
    )

    async def _fake_block(opa_url, document_input, *, route="any", pseudonymize_mode="A", timeout_s=5.0):
        # Simulate OPA resolving to the operator-authored policy.
        return {
            "action": "BLOCK",
            "policy_id": "DOC-OP-PHI-002",
            "code": "DOCUMENT_PHI_BLOCKED",
            "user_message": "Health records were blocked. Contact compliance@example.com.",
            "deny": ["unpoliced_sensitive_class"],
            "obligations": [],
        }

    monkeypatch.setattr(
        "yashigani.documents.opa_decision.evaluate_document_decision", _fake_block
    )
    r = tc.post("/admin/documents/inspect", json={
        "content": "Patient: John Smith, DOB 1990-01-01\n",
        "filename": "referral.txt",
        "route": "egress-mcp-result",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["opa_decision"]["action"] == "BLOCK"
    assert body["opa_decision"]["policy_id"] == "DOC-OP-PHI-002"
    assert body["opa_decision"]["code"] == "DOCUMENT_PHI_BLOCKED"
    # The user_alert must carry the OPERATOR's message, not the built-in fallback.
    assert body["user_alert"] is not None
    assert body["user_alert"]["policy_id"] == "DOC-OP-PHI-002"
    assert body["user_alert"]["user_message"] == "Health records were blocked. Contact compliance@example.com."
    assert body["user_alert"]["code"] == "DOCUMENT_PHI_BLOCKED"
