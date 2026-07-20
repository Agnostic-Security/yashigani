"""
Deterministic gate suite — POST /user/documents RESTART-013 gaps #3/#4/#5.

Mode: DETERMINISTIC GATE (FastAPI TestClient + dependency overrides + a REAL
DocumentInspectionPipeline wired to the real worker subprocess backend, same
technique as test_documents_end_to_end_log.py's ``_WorkerSubprocessBackend`` —
no live extractor-svc container needed, no mocked redaction/pseudonymization).

Coverage:
  GAP3-01  REDACT: processed_content is populated (base64) with the ACTUAL
           redacted bytes — no longer hardcoded None.
  GAP3-02  BLOCK: processed_content stays None (nothing to forward).
  GAP3-03  LOG: processed_content stays None (no transform occurred).
  GAP4-01  The caller's resolved identity_id is threaded into
           evaluate_document_decision() as identity_id=... (per-user policy
           dimension actually reaches the OPA call, not just the schema).
  GAP4-02  An unresolvable identity (no identity_registry) degrades to "" —
           the upload still succeeds (global-policy fallback), never 500s.
  GAP5-01  A REAL DocumentEnforcementDecisionEvent is written to the audit
           chain for the disposition (executes the rego's ever-present
           "audit_document_decision" obligation) — carrying identity_id +
           obligations, not a bare logger.info.

Author: Tom. Last updated: 2026-07-20.
"""
from __future__ import annotations

import base64
import os
import subprocess
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from yashigani.auth.session import Session
from yashigani.backoffice.middleware import require_user_session
from yashigani.backoffice.routes import user_ui
from yashigani.backoffice.state import backoffice_state
from yashigani.documents.extractor import ExtractorRegistry
from yashigani.documents.pipeline import DocumentInspectionPipeline
from yashigani.documents.sandbox import SandboxedExtractorRunner

_REPO_ROOT = Path(__file__).resolve().parents[3]
_WORKER_PATH = _REPO_ROOT / "docker" / "extractor" / "worker.py"


class _WorkerSubprocessBackend:
    """Runs the REAL worker as a subprocess via the stdin->stdout->exit
    contract the hardened container uses — no live extractor-svc needed.
    Mirrors test_documents_end_to_end_log.py's helper of the same name."""

    def run_extractor_job(self, *, stdin, timeout_s, command, **kwargs):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(_REPO_ROOT / "src")
        proc = subprocess.run(
            ["python3", str(_WORKER_PATH), *command],
            input=stdin, capture_output=True, timeout=timeout_s, env=env,
        )
        return (proc.stdout, proc.returncode, False)


class _FakeAuditWriter:
    def __init__(self) -> None:
        self.events: list = []

    def write(self, event, agent_id=None, user_handle=None, component=None) -> None:
        self.events.append(event)


class _FakeIdentityRegistry:
    def __init__(self, mapping: dict) -> None:
        self._mapping = mapping

    def get_by_account_id(self, account_id: str):
        return self._mapping.get(account_id)


def _session(account_id: str) -> Session:
    return Session(
        token="tok", account_id=account_id, account_tier="user",
        created_at=0.0, last_active_at=0.0, expires_at=9_999_999_999.0,
        ip_prefix="127.0.0",
    )


def _test_build_pipeline(audit_context=None):
    """Test double for user_ui._build_pipeline: same audit wiring (REAL,
    exercises audit_bridge.make_document_audit_callback), but the registry
    is backed by the real worker subprocess instead of DocumentEnforcementConfig
    .from_env().build_registry() (which needs a live extractor-svc)."""
    from yashigani.documents.audit_bridge import make_document_audit_callback

    runner = SandboxedExtractorRunner(backend=_WorkerSubprocessBackend())
    registry = ExtractorRegistry(sandbox_runner=runner)
    _audit = make_document_audit_callback(
        backoffice_state.audit_writer, surface="user-upload", context=audit_context,
    )
    return DocumentInspectionPipeline(
        registry=registry, on_audit=_audit, small_set_escalation=False,
    )


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setattr(user_ui, "_build_pipeline", _test_build_pipeline)

    app = FastAPI()
    app.include_router(user_ui.router, tags=["user-ui"])
    app.dependency_overrides[require_user_session] = lambda: _session("acct-redact-001")

    audit_writer = _FakeAuditWriter()
    backoffice_state.audit_writer = audit_writer
    backoffice_state.identity_registry = _FakeIdentityRegistry(
        {"acct-redact-001": {"identity_id": "idnt_userredact01"}}
    )
    backoffice_state.opa_url = "https://policy:8181"

    yield TestClient(app), audit_writer

    backoffice_state.audit_writer = None
    backoffice_state.identity_registry = None


_PII_EMAIL = "jordan.whitfield@example.com"


def _upload_body(action_hint: str = "redact") -> dict:
    content = f"Name: Jordan\nEmail: {_PII_EMAIL}\n".encode()
    return {
        "filename": "salary.txt",
        "content_type": "text/plain",
        "content_base64": base64.b64encode(content).decode("ascii"),
        "route": "ingress-upload",
        "pseudonymize_mode": "A",
    }


def _fake_decision(action: str, identity_id_capture: list):
    async def _fake(opa_url, document_input, *, route="any", pseudonymize_mode="A", identity_id="", timeout_s=5.0):
        identity_id_capture.append(identity_id)
        return {
            "action": action,
            "policy_id": "DOC-EX-TEST",
            "code": f"DOCUMENT_{action}",
            "user_message": f"file was {action.lower()}ed",
            "deny": [] if action != "BLOCK" else ["unpoliced_sensitive_class"],
            "obligations": ["audit_document_decision"] + (
                ["apply_pseudonymize_tokens", "deliver_correspondence_table_rbac"]
                if action == "PSEUDONYMIZE" else []
            ),
        }
    return _fake


# ---------------------------------------------------------------------------
# GAP #3 — deliver transformed bytes
# ---------------------------------------------------------------------------

def test_gap3_01_redact_delivers_real_transformed_bytes(client, monkeypatch):
    tc, _audit_writer = client
    captured: list = []
    monkeypatch.setattr(
        "yashigani.documents.opa_decision.evaluate_document_decision",
        _fake_decision("REDACT", captured),
    )
    r = tc.post("/user/documents", json=_upload_body())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["disposition"] == "REDACT"
    assert body["processed_content"] is not None
    transformed = base64.b64decode(body["processed_content"])
    # The real redacted artefact must NOT contain the original email anymore.
    assert _PII_EMAIL.encode() not in transformed
    assert b"Jordan" in transformed  # unredacted context survives


def test_gap3_02_block_processed_content_is_none(client, monkeypatch):
    tc, _audit_writer = client
    captured: list = []
    monkeypatch.setattr(
        "yashigani.documents.opa_decision.evaluate_document_decision",
        _fake_decision("BLOCK", captured),
    )
    r = tc.post("/user/documents", json=_upload_body())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["disposition"] == "BLOCK"
    assert body["processed_content"] is None


def test_gap3_03_log_processed_content_is_none(client, monkeypatch):
    tc, _audit_writer = client
    captured: list = []
    monkeypatch.setattr(
        "yashigani.documents.opa_decision.evaluate_document_decision",
        _fake_decision("LOG", captured),
    )
    r = tc.post("/user/documents", json=_upload_body())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["disposition"] == "LOG"
    assert body["processed_content"] is None


# ---------------------------------------------------------------------------
# GAP #4 — per-user identity dimension threaded through
# ---------------------------------------------------------------------------

def test_gap4_01_resolved_identity_id_threaded_to_opa(client, monkeypatch):
    tc, _audit_writer = client
    captured: list = []
    monkeypatch.setattr(
        "yashigani.documents.opa_decision.evaluate_document_decision",
        _fake_decision("REDACT", captured),
    )
    r = tc.post("/user/documents", json=_upload_body())
    assert r.status_code == 200, r.text
    assert captured == ["idnt_userredact01"]


def test_gap4_02_unresolved_identity_degrades_to_empty_not_500(client, monkeypatch):
    tc, _audit_writer = client
    backoffice_state.identity_registry = None  # registry unavailable
    captured: list = []
    monkeypatch.setattr(
        "yashigani.documents.opa_decision.evaluate_document_decision",
        _fake_decision("LOG", captured),
    )
    r = tc.post("/user/documents", json=_upload_body())
    assert r.status_code == 200, r.text
    assert captured == [""]


# ---------------------------------------------------------------------------
# GAP #5 — obligation execution: real audit event written
# ---------------------------------------------------------------------------

def test_gap5_01_redact_writes_real_audit_event(client, monkeypatch):
    tc, audit_writer = client
    captured: list = []
    monkeypatch.setattr(
        "yashigani.documents.opa_decision.evaluate_document_decision",
        _fake_decision("REDACT", captured),
    )
    r = tc.post("/user/documents", json=_upload_body())
    assert r.status_code == 200, r.text

    from yashigani.audit.schema import DocumentEnforcementDecisionEvent
    doc_events = [e for e in audit_writer.events if isinstance(e, DocumentEnforcementDecisionEvent)]
    assert doc_events, "expected at least one DocumentEnforcementDecisionEvent on the audit chain"
    ev = doc_events[-1]
    assert ev.surface == "user-upload"
    assert ev.disposition == "REDACT"
    assert ev.identity_id == "idnt_userredact01"
    assert "audit_document_decision" in ev.obligations
    assert "apply_pseudonymize_tokens" not in ev.obligations  # REDACT, not PSEUDONYMIZE obligations
    # Raw PII value must never appear in the audit event (masking floor).
    assert _PII_EMAIL not in repr(ev.to_dict())


def test_gap5_02_pseudonymize_audit_event_carries_pseudonymize_obligations(client, monkeypatch):
    tc, audit_writer = client
    captured: list = []
    monkeypatch.setattr(
        "yashigani.documents.opa_decision.evaluate_document_decision",
        _fake_decision("PSEUDONYMIZE", captured),
    )
    r = tc.post("/user/documents", json=_upload_body())
    assert r.status_code == 200, r.text

    from yashigani.audit.schema import DocumentEnforcementDecisionEvent
    doc_events = [e for e in audit_writer.events if isinstance(e, DocumentEnforcementDecisionEvent)]
    ev = doc_events[-1]
    assert ev.disposition == "PSEUDONYMIZE"
    assert "apply_pseudonymize_tokens" in ev.obligations
    assert "deliver_correspondence_table_rbac" in ev.obligations


def test_gap5_03_no_audit_writer_does_not_break_upload(client, monkeypatch):
    """Audit is a side channel — a missing/absent audit_writer must never
    break the actual document decision (fail-safe, not fail-closed, for the
    AUDIT WRITE specifically; the pipeline's own BLOCK decision is untouched)."""
    tc, _audit_writer = client
    backoffice_state.audit_writer = None
    captured: list = []
    monkeypatch.setattr(
        "yashigani.documents.opa_decision.evaluate_document_decision",
        _fake_decision("REDACT", captured),
    )
    r = tc.post("/user/documents", json=_upload_body())
    assert r.status_code == 200, r.text
    assert r.json()["disposition"] == "REDACT"
