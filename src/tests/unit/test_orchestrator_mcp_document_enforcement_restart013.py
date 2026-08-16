"""
FINDING-V412-RESTART-013 — chat->MCP tool-call path document enforcement.

Before this fix: ``gateway/orchestrator.py:_execute_mcp_tool`` — the primary
chat->MCP dispatch path (called from ``_call_tool_hop`` at line ~944, one hop
per tool the orchestrator brain decides to invoke) — had ZERO references to
``DocumentInspectionPipeline`` / ``mcp_document_bridge``. A document embedded
in a tool call's ``args`` was forwarded to the upstream MCP server completely
unredacted / un-pseudonymized / unblocked, even though the user-upload channel
(``backoffice/routes/user_ui.py``) and the ``/mcp/<agent_name>`` HTTP
entrypoint (``gateway/mcp_router_runtime.py``) both already enforced document
policy correctly.

Mode: REAL DocumentInspectionPipeline + REAL PiiDetector + REAL redact/
pseudonymize re-render (through the sandboxed worker subprocess, faithful to
production per ``test_documents_end_to_end_actions.py``'s established
pattern) — only ``evaluate_document_decision`` (the OPA HTTP call) is mocked
deterministically per test, so this proves ACTUAL byte transformation
reaching the outbound JSON-RPC POST, not a mocked bridge. The fixture is the
exact reproduction from the finding (SSN + EMAIL + "Name: Alice Zhang").

Coverage:
  R013-01  REDACT identity: SSN + EMAIL + PERSON_NAME are all stripped from
           the bytes actually POSTed to the upstream MCP server.
  R013-02  PSEUDONYMIZE identity: SSN + EMAIL + PERSON_NAME are all replaced
           with tokens in the bytes actually POSTed upstream.
  R013-03  BLOCK: a document-level BLOCK decision holds the WHOLE call —
           the upstream MCP server is never even called.
  R013-04  document_pipeline=None (default/dark) — zero behaviour change;
           the bridge is never invoked, args forwarded byte-identical.
  R013-05  DOCUMENT_ENFORCEMENT_DECISION audit event fires with
           surface="mcp-tool-call" and the correct disposition, for both
           REDACT and PSEUDONYMIZE.

Author: Tom. Last updated: 2026-07-21.
"""
from __future__ import annotations

import base64
import os
import pathlib
import subprocess

import pytest

from yashigani.documents import proxy_modeb  # noqa: E402
from yashigani.documents.audit_bridge import make_shared_document_audit_callback  # noqa: E402
from yashigani.documents.extractor import ExtractorRegistry  # noqa: E402
from yashigani.documents.pipeline import DocumentInspectionPipeline  # noqa: E402
from yashigani.documents.sandbox import SandboxedExtractorRunner  # noqa: E402
from yashigani.gateway import orchestrator  # noqa: E402
from yashigani.gateway.openai_router import _state as oa_state  # noqa: E402


# ---------------------------------------------------------------------------
# The finding's exact reproduction fixture.
# ---------------------------------------------------------------------------

EMPLOYEE_RECORD = (
    b"Employee record.\n"
    b"SSN: 123-45-6789\n"
    b"Email: alice@acme.com\n"
    b"Name: Alice Zhang\n"
    b"End of record.\n"
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_WORKER_PATH = _REPO_ROOT / "docker" / "extractor" / "worker.py"


class _WorkerSubprocessBackend:
    """A ContainerBackend stand-in that runs the REAL worker as a subprocess
    via the exact stdin->stdout->exit contract the hardened container uses —
    faithful to the parser code, just without the container isolation (proven
    separately). Local copy of the fixture already established by
    test_documents_end_to_end_log.py / test_documents_end_to_end_actions.py
    (not imported from there — that module's importorskip("openpyxl"/"pypdf"/
    "lxml") guards for its OTHER format parametrizations would skip THIS
    module's collection too, even though this suite only exercises TXT, which
    needs none of those optional deps)."""

    def run_extractor_job(self, *, stdin, timeout_s, command, **kwargs):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(_REPO_ROOT / "src")
        proc = subprocess.run(
            ["python3", str(_WORKER_PATH), *command],
            input=stdin, capture_output=True, timeout=timeout_s, env=env,
        )
        return (proc.stdout, proc.returncode, False)


def _pipeline(audit_writer) -> DocumentInspectionPipeline:
    """A real pipeline (real PII detector, real redact/pseudonymize re-render
    via the worker-subprocess sandbox backend) wired to a capturing audit
    writer through the SAME shared/singleton audit callback
    entrypoint.py wires the gateway's real document_pipeline with.

    small_set_escalation=False isolates the transform mechanics under test
    from the F2 small-set re-identification gate (our tiny fixture — 1
    "record" — would otherwise escalate to BLOCK on the small-set rule,
    which has its own dedicated test coverage elsewhere)."""
    runner = SandboxedExtractorRunner(backend=_WorkerSubprocessBackend())
    registry = ExtractorRegistry(sandbox_runner=runner)
    return DocumentInspectionPipeline(
        registry=registry,
        on_audit=make_shared_document_audit_callback(audit_writer, surface="proxy-egress"),
        small_set_escalation=False,
    )


class _FakeAuditWriter:
    def __init__(self) -> None:
        self.events: list = []

    def write(self, event, agent_id=None, user_handle=None, component=None) -> None:
        self.events.append(event)


def _make_fake_client_factory(captured: list):
    """httpx.AsyncClient stand-in: captures the JSON-RPC body actually POSTed
    to the (fake) upstream MCP server, and returns a benign tool result."""

    class _Resp:
        def json(self):
            return {
                "jsonrpc": "2.0", "id": "t1",
                "result": {"content": [{"type": "text", "text": "ok"}]},
            }

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            captured.append(json)
            return _Resp()

    return lambda *a, **k: _Client()


async def _fake_ingress_allow(identity, server, tool):
    return {"allow": True, "reason": "ok"}


async def _fake_egress_allow(identity, server, tool, verdict, response_sensitivity=None):
    return {"allow": True, "reason": "ok"}


# YSG-RISK-257: orchestrator._inspect_result is now async (offloads the
# blocking classifier call via asyncio.to_thread).
async def _fake_inspect_clean(text, identity, rid):
    return "CLEAN", 1.0, None


def _fake_decision_factory(action: str):
    async def _fake(opa_url, document_input, *, route="any", pseudonymize_mode="A",
                    identity_id="", timeout_s=5.0):
        return {
            "action": action,
            "policy_id": f"DOC-EX-TEST-{action}",
            "code": f"DOCUMENT_{action}",
            "user_message": "m",
            "deny": [] if action != "BLOCK" else ["unpoliced_sensitive_class"],
            "obligations": ["audit_document_decision"],
        }
    return _fake


def _wire_common(monkeypatch, pipeline, audit_writer, captured_posts):
    monkeypatch.setattr(orchestrator, "_opa_ingress_for_mcp", _fake_ingress_allow)
    monkeypatch.setattr(orchestrator, "_opa_egress_for_mcp_result", _fake_egress_allow)
    monkeypatch.setattr(orchestrator, "_inspect_result", _fake_inspect_clean)

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _make_fake_client_factory(captured_posts))

    monkeypatch.setattr(oa_state, "document_pipeline", pipeline)
    monkeypatch.setattr(oa_state, "opa_url", "https://policy:8181")
    monkeypatch.setattr(oa_state, "audit_writer", audit_writer)


# ---------------------------------------------------------------------------
# R013-01 / R013-05a — REDACT
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_r013_01_redact_identity_transforms_outbound_bytes(monkeypatch):
    audit_writer = _FakeAuditWriter()
    pipeline = _pipeline(audit_writer)
    monkeypatch.setattr(proxy_modeb, "evaluate_document_decision",
                        _fake_decision_factory("REDACT"))

    captured_posts: list = []
    _wire_common(monkeypatch, pipeline, audit_writer, captured_posts)

    b64_doc = base64.b64encode(EMPLOYEE_RECORD).decode("ascii")
    args = {"content_b64": b64_doc}

    res = await orchestrator._execute_mcp_tool(
        server="demo-mcp", upstream_url="http://demo-mcp:8000", tool="upload",
        args=args, identity={"identity_id": "idnt_redactuser01"},
        depth=1, root_rid="r-redact", request_id="rq-redact",
    )

    assert res.blocked is False
    assert captured_posts, "the upstream MCP server was never called"
    forwarded_rpc = captured_posts[0]
    assert forwarded_rpc["method"] == "tools/call"
    forwarded_b64 = forwarded_rpc["params"]["arguments"]["content_b64"]
    forwarded_bytes = base64.b64decode(forwarded_b64)

    # THE PROOF: transformed bytes are what actually reached the JSON-RPC POST.
    assert forwarded_bytes != EMPLOYEE_RECORD
    assert b"123-45-6789" not in forwarded_bytes       # SSN gone
    assert b"alice@acme.com" not in forwarded_bytes     # EMAIL gone
    assert b"Alice Zhang" not in forwarded_bytes         # PERSON_NAME gone (gap #2)
    # The document pipeline's REDACT plan destroys the matched span in place
    # (unlike the plain-text PiiDetector.REDACT mode's "[REDACTED:TYPE]"
    # literal) — assert the labels survive (REDACT strips values, not
    # structure) while the values themselves are gone (already asserted
    # above).
    assert b"SSN:" in forwarded_bytes
    assert b"Email:" in forwarded_bytes
    assert b"Name:" in forwarded_bytes

    # `args` (the SAME dict the caller holds) was mutated in place — the
    # "forwarded args" the brief asks to prove transformed.
    assert base64.b64decode(args["content_b64"]) == forwarded_bytes

    # Audit: DOCUMENT_ENFORCEMENT_DECISION, surface=mcp-tool-call, REDACT.
    doc_events = [e for e in audit_writer.events
                 if getattr(e, "surface", "") == "mcp-tool-call"]
    assert doc_events, "no audit event carried surface=mcp-tool-call"
    assert any(e.disposition == "REDACT" for e in doc_events)
    assert any(e.identity_id == "idnt_redactuser01" for e in doc_events)


# ---------------------------------------------------------------------------
# R013-02 / R013-05b — PSEUDONYMIZE
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_r013_02_pseudonymize_identity_transforms_outbound_bytes(monkeypatch):
    audit_writer = _FakeAuditWriter()
    pipeline = _pipeline(audit_writer)
    monkeypatch.setattr(proxy_modeb, "evaluate_document_decision",
                        _fake_decision_factory("PSEUDONYMIZE"))

    captured_posts: list = []
    _wire_common(monkeypatch, pipeline, audit_writer, captured_posts)

    b64_doc = base64.b64encode(EMPLOYEE_RECORD).decode("ascii")
    args = {"content_b64": b64_doc}

    res = await orchestrator._execute_mcp_tool(
        server="demo-mcp", upstream_url="http://demo-mcp:8000", tool="upload",
        args=args, identity={"identity_id": "idnt_pseudouser01"},
        depth=1, root_rid="r-pseudo", request_id="rq-pseudo",
    )

    assert res.blocked is False
    assert captured_posts, "the upstream MCP server was never called"
    forwarded_b64 = captured_posts[0]["params"]["arguments"]["content_b64"]
    forwarded_bytes = base64.b64decode(forwarded_b64)

    assert forwarded_bytes != EMPLOYEE_RECORD
    assert b"123-45-6789" not in forwarded_bytes
    assert b"alice@acme.com" not in forwarded_bytes
    assert b"Alice Zhang" not in forwarded_bytes
    # PSEUDONYMIZE mode A tokenizes (opaque per-file-salted token), not the
    # bracketed [REDACTED:...] literal placeholder.
    assert b"[REDACTED:" not in forwarded_bytes

    doc_events = [e for e in audit_writer.events
                 if getattr(e, "surface", "") == "mcp-tool-call"]
    assert doc_events
    assert any(e.disposition == "PSEUDONYMIZE" for e in doc_events)
    assert any(e.identity_id == "idnt_pseudouser01" for e in doc_events)


# ---------------------------------------------------------------------------
# R013-03 — BLOCK holds the whole call, upstream never reached
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_r013_03_block_never_reaches_upstream(monkeypatch):
    audit_writer = _FakeAuditWriter()
    pipeline = _pipeline(audit_writer)
    monkeypatch.setattr(proxy_modeb, "evaluate_document_decision",
                        _fake_decision_factory("BLOCK"))

    captured_posts: list = []
    _wire_common(monkeypatch, pipeline, audit_writer, captured_posts)

    b64_doc = base64.b64encode(EMPLOYEE_RECORD).decode("ascii")
    args = {"content_b64": b64_doc}

    res = await orchestrator._execute_mcp_tool(
        server="demo-mcp", upstream_url="http://demo-mcp:8000", tool="upload",
        args=args, identity={"identity_id": "idnt_blockuser01"},
        depth=1, root_rid="r-block", request_id="rq-block",
    )

    assert res.blocked is True
    assert res.block_source == "document_enforcement"
    assert res.http_status == 403
    assert not captured_posts, "upstream MUST NOT be called on a document BLOCK"
    assert "DOCUMENT ENFORCEMENT" in res.text


# ---------------------------------------------------------------------------
# R013-04 — dark (document_pipeline=None) is a pure no-op
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_r013_04_dark_when_pipeline_none_zero_behaviour_change(monkeypatch):
    captured_posts: list = []
    monkeypatch.setattr(orchestrator, "_opa_ingress_for_mcp", _fake_ingress_allow)
    monkeypatch.setattr(orchestrator, "_opa_egress_for_mcp_result", _fake_egress_allow)
    monkeypatch.setattr(orchestrator, "_inspect_result", _fake_inspect_clean)
    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _make_fake_client_factory(captured_posts))
    monkeypatch.setattr(oa_state, "document_pipeline", None)

    b64_doc = base64.b64encode(EMPLOYEE_RECORD).decode("ascii")
    args = {"content_b64": b64_doc}

    res = await orchestrator._execute_mcp_tool(
        server="demo-mcp", upstream_url="http://demo-mcp:8000", tool="upload",
        args=args, identity={"identity_id": "idnt_darkuser01"},
        depth=1, root_rid="r-dark", request_id="rq-dark",
    )

    assert res.blocked is False
    forwarded_b64 = captured_posts[0]["params"]["arguments"]["content_b64"]
    # Byte-identical — the pre-fix behaviour is unchanged when the feature
    # is not opted in (mode-B-proxy flag off / document_pipeline is None).
    assert forwarded_b64 == b64_doc
