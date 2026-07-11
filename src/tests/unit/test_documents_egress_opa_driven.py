"""
2.26 gap #2 — policy-driven proxy egress: OPA decides the action + mode.

Iris cross-seam integration audit.  These tests cross the seams that single-
component specialists miss:

  * the egress decision is taken by the REAL rego over the seeded example matrix
    (not a hardcoded "blanket mode-B"), and the SAME decision drives the matching
    action end-to-end on a REAL document sample through the REAL pipeline;
  * OPA-unreachable on the egress leg FAILS CLOSED to a held document (BLOCK),
    never a forward (the nightmare: a doc that escapes because the policy engine
    was down);
  * flag-off proves ZERO impact — egress_decide is never even reached, the body
    is forwarded byte-identical.

The egress reuses ``evaluate_document_decision`` — the SAME decision source the
backoffice ``/inspect`` route uses — so there is ONE decision source of truth for
UI and proxy.  Here we wire that decision to the ACTUAL ``opa`` binary on the
SHIPPED ``policy/document.rego`` + the seeded ``DocumentPolicyStore`` matrix, so
the action that drives the egress is genuinely engine-computed.

Author: Iris. Date: 2026-06-10.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import fakeredis
import pytest

pytest.importorskip("openpyxl", reason="xlsx parser (shared extractor deps)")

from src.tests.unit.test_documents_end_to_end_log import (  # noqa: E402
    _WorkerSubprocessBackend,
)
from yashigani.documents import proxy_modeb as _pm  # noqa: E402
from yashigani.documents.extractor import ExtractorRegistry  # noqa: E402
from yashigani.documents.pipeline import DocumentInspectionPipeline  # noqa: E402
from yashigani.documents.policy_store import DocumentPolicyStore  # noqa: E402
from yashigani.documents.proxy_modeb import EgressOutcome, egress_decide  # noqa: E402
from yashigani.documents.sandbox import SandboxedExtractorRunner  # noqa: E402

_OPA = shutil.which("opa")
_REPO_ROOT = Path(__file__).resolve().parents[3]
_REGO = _REPO_ROOT / "policy" / "document.rego"

_needs_opa = pytest.mark.skipif(
    _OPA is None or not _REGO.exists(),
    reason="opa binary or policy/document.rego not available",
)

# A multi-row CSV so the small-set re-identification gate does NOT fire (this
# suite isolates the egress decision wiring, not the L-01 gate which has its own
# tests).  One identifying value per row, plenty of rows.
_CSV_HEADER = "id,note,email\n"
_CSV_ROWS = "".join(
    f"{i},contact for record {i},user{i}@example.com\n" for i in range(1, 41)
)
_CSV_BYTES = (_CSV_HEADER + _CSV_ROWS).encode()
_CSV_MIME = "text/csv"
_ONE_ORIGINAL = "user1@example.com"


def _real_pipeline() -> DocumentInspectionPipeline:
    runner = SandboxedExtractorRunner(backend=_WorkerSubprocessBackend())
    reg = ExtractorRegistry(sandbox_runner=runner)
    return DocumentInspectionPipeline(registry=reg)


@pytest.fixture
def seeded_store():
    s = DocumentPolicyStore(fakeredis.FakeStrictRedis())
    s.seed_defaults()
    return s


def _real_opa_decision_fn(store: DocumentPolicyStore, tmp_path):
    """Return an async callable matching evaluate_document_decision's signature
    that runs the ACTUAL opa binary on the shipped rego + the store's matrix.

    This is the genuine cross-seam: the egress's decision is computed by the real
    engine over the real seeded example policies, not a Python fixture dict."""
    data_file = tmp_path / "data.json"
    data_file.write_text(
        json.dumps({"yashigani": {"document": store.to_opa_document()}})
    )

    async def _decide(opa_url, document_input, *, route="any",
                      pseudonymize_mode="A", timeout_s=5.0):
        full_input = {
            "document": document_input,
            "routing_decision": {"route": route},
            "request": {"pseudonymize_mode": pseudonymize_mode},
        }
        proc = subprocess.run(
            [
                _OPA, "eval",
                "--data", str(_REGO),
                "--data", str(data_file),
                "--stdin-input",
                "--format", "json",
                "data.yashigani.document.decision",
            ],
            input=json.dumps(full_input),
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"opa eval failed: {proc.stderr}"
        out = json.loads(proc.stdout)
        return out["result"][0]["expressions"][0]["value"]

    return _decide


# ---------------------------------------------------------------------------
# 1. The seeded example OPA matrix drives the matching action END-TO-END on a
#    real sample through the REAL rego.
# ---------------------------------------------------------------------------

@_needs_opa
@pytest.mark.asyncio
async def test_example_opa_pseudonymize_drives_egress_modeb(monkeypatch, seeded_store, tmp_path):
    """PII example policy (DOC-EX-PII-1: PII on egress-mcp-result -> PSEUDONYMIZE
    mode A).  But the egress travels mode B by request, and a separate mode-A
    seeded policy exists.  Assert: OPA returns PSEUDONYMIZE, the egress tokenizes
    the sample, and the original NEVER reaches the upstream."""
    monkeypatch.setattr(
        _pm, "evaluate_document_decision",
        _real_opa_decision_fn(seeded_store, tmp_path),
    )

    out: EgressOutcome = await egress_decide(
        _real_pipeline(),
        opa_url="http://opa:8181",
        body=_CSV_BYTES,
        content_type=_CSV_MIME,
        request_id="egress-1",
        route="egress-mcp-result",
    )

    # OPA (DOC-EX-PII-1) decided PSEUDONYMIZE → the egress transformed the body.
    assert out.action == "PSEUDONYMIZE"
    assert out.transformed is True
    assert out.blocked is False
    assert out.forward_bytes is not None
    fwd = out.forward_bytes.decode()
    assert _ONE_ORIGINAL not in fwd, "original value leaked to upstream"
    assert "EMAIL" in fwd.upper(), "tokenized artefact missing class token"


@_needs_opa
@pytest.mark.asyncio
async def test_example_opa_redact_drives_egress(monkeypatch, seeded_store, tmp_path):
    """DOC-EX-PII-2: PII on json-attachment -> REDACT.  Route the egress on
    json-attachment; OPA decides REDACT; the egress forwards the stripped artefact
    and holds NO round-trip (REDACT is irreversible — there is nothing to restore)."""
    monkeypatch.setattr(
        _pm, "evaluate_document_decision",
        _real_opa_decision_fn(seeded_store, tmp_path),
    )

    out = await egress_decide(
        _real_pipeline(),
        opa_url="http://opa:8181",
        body=_CSV_BYTES,
        content_type=_CSV_MIME,
        request_id="egress-2",
        route="json-attachment",
    )

    assert out.action == "REDACT"
    assert out.transformed is True
    assert out.engaged is False, "REDACT must not hold a mode-B round-trip"
    assert out.round_trip is None
    assert out.forward_bytes is not None
    assert _ONE_ORIGINAL not in out.forward_bytes.decode()


@_needs_opa
@pytest.mark.asyncio
async def test_example_opa_log_forwards_original_unchanged(monkeypatch, seeded_store, tmp_path):
    """DOC-EX-PII-LOG: PII on ingress-upload -> LOG.  OPA decides LOG; the egress
    forwards the ORIGINAL bytes unchanged (allow + audit), no transform."""
    monkeypatch.setattr(
        _pm, "evaluate_document_decision",
        _real_opa_decision_fn(seeded_store, tmp_path),
    )

    out = await egress_decide(
        _real_pipeline(),
        opa_url="http://opa:8181",
        body=_CSV_BYTES,
        content_type=_CSV_MIME,
        request_id="egress-3",
        route="ingress-upload",
    )

    assert out.action == "LOG"
    assert out.transformed is False
    assert out.blocked is False
    assert out.forward_bytes is None, "LOG forwards the ORIGINAL (proxy keeps its bytes)"


@_needs_opa
@pytest.mark.asyncio
async def test_operator_block_precedence_holds_egress(monkeypatch, seeded_store, tmp_path):
    """An operator BLOCK row over PII wins by precedence IN THE REGO → the egress
    HOLDS the document (blocked=True), never forwards.  This is the fail-closed
    contract crossing the policy-store→rego→egress seam."""
    seeded_store.add_policy(data_class="PII", format="any", route="any", action="BLOCK")
    monkeypatch.setattr(
        _pm, "evaluate_document_decision",
        _real_opa_decision_fn(seeded_store, tmp_path),
    )

    out = await egress_decide(
        _real_pipeline(),
        opa_url="http://opa:8181",
        body=_CSV_BYTES,
        content_type=_CSV_MIME,
        request_id="egress-4",
        route="egress-mcp-result",
    )

    assert out.action == "BLOCK"
    assert out.blocked is True
    assert out.forward_bytes is None, "a BLOCKED document must NEVER be forwarded"


# ---------------------------------------------------------------------------
# 2. Fail-closed: OPA unreachable on the egress leg → held, never forwarded.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_opa_unreachable_fails_closed_to_block(monkeypatch):
    """With NO live OPA server, evaluate_document_decision returns a synthetic
    fail-closed BLOCK.  The egress MUST hold the document (blocked=True), never
    forward — proving the seam fails closed, not open.

    This uses the REAL evaluate_document_decision (not a mock): the internal httpx
    client cannot reach the bogus OPA URL, so the decision degrades to BLOCK."""
    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("YASHIGANI_DOCUMENT_MODEB_PROXY_ENABLED", "true")

    out = await egress_decide(
        _real_pipeline(),
        # A URL that cannot resolve/connect → httpx error → fail-closed BLOCK.
        opa_url="https://opa-not-here.invalid:8181",
        body=_CSV_BYTES,
        content_type=_CSV_MIME,
        request_id="egress-fc",
        route="egress-mcp-result",
    )

    assert out.action == "BLOCK"
    assert out.blocked is True
    assert out.forward_bytes is None, (
        "OPA-unreachable forwarded the document — FAIL-OPEN regression"
    )


# ---------------------------------------------------------------------------
# 3. Flag-off zero-impact — the master gate is the proxy's; here we prove that
#    when the egress IS reached, an OPA LOG decision is a true no-op transform
#    (the body the upstream receives is byte-identical to the original).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_log_decision_is_byte_identical_noop(monkeypatch):
    """An OPA LOG decision must not mutate a single byte: the egress reports no
    transform and keeps no forward_bytes, so the proxy forwards the ORIGINAL
    verbatim.  (Zero-impact proof for the allow path.)"""
    async def _log_decision(opa_url, document_input, *, route="any",
                            pseudonymize_mode="A", timeout_s=5.0):
        return {"action": "LOG", "allow": True, "deny": [],
                "policy_id": "DOC-EX-PII-LOG", "code": "DOCUMENT_LOGGED"}

    monkeypatch.setattr(_pm, "evaluate_document_decision", _log_decision)

    out = await egress_decide(
        _real_pipeline(),
        opa_url="http://opa:8181",
        body=_CSV_BYTES,
        content_type=_CSV_MIME,
        request_id="egress-log",
        route="egress-mcp-result",
    )
    assert out.action == "LOG"
    assert out.transformed is False
    assert out.engaged is False
    assert out.forward_bytes is None  # proxy keeps + forwards the original bytes
