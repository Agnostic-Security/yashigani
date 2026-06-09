"""
End-to-end proof: document decision runs through the REAL OPA engine (2.26).

Mode: DETERMINISTIC GATE. Invokes the actual ``opa`` binary on the SHIPPED
production rego (policy/document.rego) with:
  - data  = DocumentPolicyStore.to_opa_document()   (the operator's matrix)
  - input = DocumentDecisionInput.to_opa_input()     (the gateway's extraction)

This proves the action is computed by OPA over the live matrix — NOT by a Python
stub — and that strongest-action precedence (BLOCK > REDACT > PSEUDONYMIZE > LOG)
is enforced IN THE REGO.  Skips cleanly if the ``opa`` binary is absent.

The Python-side evaluate_document_decision() (the async httpx→OPA client) is the
same query against a live OPA server; here we exercise the rego itself through
the engine via ``opa eval`` so the test needs no running policy container.

Author: Tom. Last updated: 2026-06-09.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import fakeredis
import pytest

from yashigani.documents.datamatch import DataMatch, DocumentDecisionInput
from yashigani.documents.policy_store import DocumentPolicyStore

_OPA = shutil.which("opa")
_REPO_ROOT = Path(__file__).resolve().parents[3]
_REGO = _REPO_ROOT / "policy" / "document.rego"

pytestmark = pytest.mark.skipif(
    _OPA is None or not _REGO.exists(),
    reason="opa binary or policy/document.rego not available",
)


def _decide(store: DocumentPolicyStore, opa_input: dict, *, route: str, mode: str = "A", tmp_path) -> dict:
    """Run the REAL opa engine over the shipped rego + the store's matrix data."""
    data_file = tmp_path / "data.json"
    data_file.write_text(json.dumps({"yashigani": {"document": store.to_opa_document()}}))
    full_input = {
        "document": opa_input,
        "routing_decision": {"route": route},
        "request": {"pseudonymize_mode": mode},
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


@pytest.fixture
def store():
    s = DocumentPolicyStore(fakeredis.FakeStrictRedis())
    s.seed_defaults()
    return s


def _doc(matches, *, fmt="xlsx", complete=True, supported=True, record_count=100):
    di = DocumentDecisionInput(
        format=fmt,
        extraction_complete=complete,
        segment_kinds=["BODY"],
        matches=matches,
        record_count=record_count,
        redaction_supported=supported,
        pseudonymize_supported=supported,
        reid_handle="cap-abc",
    )
    return di.to_opa_input()


def _email():
    return DataMatch("PII.EMAIL", False, "j***@e.com", "BODY:p1:span=0-9", 0, 9)


def _card():
    return DataMatch("PCI.CARD", False, "****-1234", "BODY:p1:span=0-9", 0, 9)


def test_e2e_pci_pseudonymize_through_real_opa(store, tmp_path):
    """Seeded example matrix: PCI on egress -> PSEUDONYMIZE (PCI-1). Engine-decided."""
    d = _decide(store, _doc([_card()]), route="egress-mcp-result", tmp_path=tmp_path)
    assert d["action"] == "PSEUDONYMIZE"
    assert d["policy_id"] == "DOC-ENFORCE-001"
    assert d["allow"] is True


def test_e2e_pci_redact_through_real_opa(store, tmp_path):
    """Seeded example matrix: PCI on json-attachment -> REDACT (PCI-2). Engine-decided."""
    d = _decide(store, _doc([_card()]), route="json-attachment", tmp_path=tmp_path)
    assert d["action"] == "REDACT"
    assert d["allow"] is True


def test_e2e_pci_block_via_operator_precedence(store, tmp_path):
    """An operator BLOCK row added over the PCI example wins by precedence
    (BLOCK > REDACT > PSEUDONYMIZE) — decided in the rego."""
    store.add_policy(data_class="PCI", format="any", route="any", action="BLOCK")
    d = _decide(store, _doc([_card()]), route="egress-mcp-result", tmp_path=tmp_path)
    assert d["action"] == "BLOCK"
    assert d["allow"] is False
    assert d["code"] == "DOCUMENT_BLOCKED"


def test_e2e_pseudonymize_through_real_opa(store, tmp_path):
    """Seeded matrix: PII on xlsx egress -> PSEUDONYMIZE. Engine-decided."""
    d = _decide(store, _doc([_email()]), route="egress-mcp-result", tmp_path=tmp_path)
    assert d["action"] == "PSEUDONYMIZE"
    assert d["allow"] is True
    assert any(o == "apply_pseudonymize_tokens" for o in d["obligations"])
    assert len(d["per_match_actions"]) == 1


def test_e2e_log_internal_pii_through_real_opa(store, tmp_path):
    """Seeded matrix: PII any/any -> LOG when route doesn't hit the egress rule."""
    d = _decide(store, _doc([_email()], fmt="txt"), route="ingress-upload", tmp_path=tmp_path)
    assert d["action"] == "LOG"
    assert d["allow"] is True


def test_e2e_precedence_block_wins_through_real_opa(store, tmp_path):
    """A BLOCK policy + a PSEUDONYMIZE policy both match -> BLOCK wins IN REGO."""
    # Add a PII BLOCK so PII has both PSEUDONYMIZE (seeded #2 on xlsx egress) and BLOCK.
    store.add_policy(data_class="PII", format="any", route="any", action="BLOCK")
    d = _decide(store, _doc([_email()]), route="egress-mcp-result", tmp_path=tmp_path)
    assert d["action"] == "BLOCK"


def test_e2e_fail_closed_incomplete_extraction(store, tmp_path):
    """extraction_complete=False -> BLOCK regardless of matches (fail-closed)."""
    d = _decide(store, _doc([], complete=False), route="ingress-upload", tmp_path=tmp_path)
    assert d["action"] == "BLOCK"


def test_e2e_fail_closed_unpoliced_class(store, tmp_path):
    """A SECRET match with no SECRET policy -> BLOCK (no clearance)."""
    secret = DataMatch("SECRET.API_KEY", False, "sk-****", "BODY:p1:span=0-7", 0, 7)
    d = _decide(store, _doc([secret]), route="ingress-upload", tmp_path=tmp_path)
    assert d["action"] == "BLOCK"
