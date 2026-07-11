"""
2.26 PART 2 (Laura D1) — field-role ROUTE_LOCAL is POLICY-decided in OPA.

The pipeline already carries the Python field-role seam (an operate-on sensitive
field on a cloud-bound mode-B PSEUDONYMIZE routes the whole document to the LOCAL
model instead of blobbing a value the cloud would hallucinate over).  These tests
prove the SAME decision is now taken by the REAL rego over the operator's matrix —
``policy/document.rego`` emits a ROUTE_LOCAL action — and that the egress wiring
honours it, with the Python seam staying as the FAIL-CLOSED backstop when OPA is
unreachable (route-local / BLOCK, never fail-open to the cloud).

Cross-seam coverage (mirrors test_documents_egress_opa_driven.py):
  * OPERATE_ON sensitive + cloud (mode B) + PSEUDONYMIZE  → REAL rego ROUTE_LOCAL,
    egress forwards the ORIGINAL bytes flagged route_local (never the transformed
    blob, never the cloud);
  * REFERENCE_ONLY only                                   → normal PSEUDONYMIZE
    (the seam does NOT fire);
  * OPA unreachable                                       → the egress + the Python
    seam fail CLOSED (held / route-local), never a cloud forward of the value.

Author: Tom. Date: 2026-06-10.
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
from yashigani.documents.pipeline import (  # noqa: E402
    DISPOSITION_BLOCK,
    DISPOSITION_PSEUDONYMIZE,
    DISPOSITION_ROUTE_LOCAL,
    DocumentInspectionPipeline,
)
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

# A salary column = an OPERATE_ON sensitive class (the model sums/compares it).
# >20 rows so the F2 small-set re-identification gate does NOT fire — we isolate
# the field-role ROUTE_LOCAL decision, not the small-set gate (which has its own
# tests).  One salary per row, plenty of rows.
_CSV_HEADER = "name,email,salary\n"
_CSV_ROWS = "".join(
    f"Person{i},user{i}@example.com,{40000 + i * 137}\n" for i in range(1, 41)
)
_SALARY_CSV = (_CSV_HEADER + _CSV_ROWS).encode()
# A reference-only-only CSV (names + emails, no operate-on field).
_REF_ONLY_CSV = (
    "name,email\n"
    + "".join(f"Person{i},user{i}@example.com\n" for i in range(1, 41))
).encode()
_CSV_MIME = "text/csv"
_ONE_SALARY = "40137"  # 40000 + 1*137


def _real_pipeline() -> DocumentInspectionPipeline:
    runner = SandboxedExtractorRunner(backend=_WorkerSubprocessBackend())
    reg = ExtractorRegistry(sandbox_runner=runner)
    return DocumentInspectionPipeline(registry=reg)


@pytest.fixture
def pseudo_modeb_store():
    """A matrix with a PII -> PSEUDONYMIZE policy on the cloud egress route.  The
    request travels mode B, so an operate-on sensitive field escalates the rego to
    ROUTE_LOCAL."""
    s = DocumentPolicyStore(fakeredis.FakeStrictRedis())
    s.add_policy(
        data_class="PII", format="any", route="any",
        action="PSEUDONYMIZE", pseudonymize_mode="B",
    )
    return s


def _real_opa_decision_fn(store: DocumentPolicyStore, tmp_path):
    """Async callable matching evaluate_document_decision's signature that runs the
    ACTUAL opa binary on the shipped rego + the store's matrix — the genuine
    cross-seam (the decision is engine-computed, not a Python fixture)."""
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
# 1. OPERATE_ON sensitive + cloud (mode B) → REAL rego ROUTE_LOCAL → egress
#    forwards the ORIGINAL bytes flagged route_local, never the cloud blob.
# ---------------------------------------------------------------------------

@_needs_opa
@pytest.mark.asyncio
async def test_operate_on_sensitive_modeb_real_opa_routes_local(
    monkeypatch, pseudo_modeb_store, tmp_path
):
    """The REAL rego, over a PSEUDONYMIZE-mode-B matrix, escalates a salary column
    to ROUTE_LOCAL.  The egress forwards the ORIGINAL bytes flagged route_local —
    the values stay in-estate, never tokenised to the cloud upstream."""
    monkeypatch.setattr(
        _pm, "evaluate_document_decision",
        _real_opa_decision_fn(pseudo_modeb_store, tmp_path),
    )

    out: EgressOutcome = await egress_decide(
        _real_pipeline(),
        opa_url="http://opa:8181",
        body=_SALARY_CSV,
        content_type=_CSV_MIME,
        request_id="rl-1",
        route="egress-mcp-result",
    )

    assert out.action == DISPOSITION_ROUTE_LOCAL
    assert out.route_local is True
    assert out.blocked is False
    assert out.transformed is False
    assert out.engaged is False, "ROUTE_LOCAL holds no cloud round-trip"
    assert out.round_trip is None
    # The LOCAL route receives the ORIGINAL bytes (values never tokenised to cloud).
    assert out.forward_bytes == _SALARY_CSV
    assert any("SALARY" in c for c in out.operate_on_classes)


@_needs_opa
@pytest.mark.asyncio
async def test_reference_only_modeb_real_opa_stays_pseudonymize(
    monkeypatch, pseudo_modeb_store, tmp_path
):
    """A reference-only set (names + emails, no operate-on field) on the SAME
    mode-B matrix is safe to opaque-tokenise: the rego decides PSEUDONYMIZE, the
    egress transforms the body and holds the mode-B round-trip — ROUTE_LOCAL does
    NOT fire."""
    monkeypatch.setattr(
        _pm, "evaluate_document_decision",
        _real_opa_decision_fn(pseudo_modeb_store, tmp_path),
    )

    out = await egress_decide(
        _real_pipeline(),
        opa_url="http://opa:8181",
        body=_REF_ONLY_CSV,
        content_type=_CSV_MIME,
        request_id="rl-2",
        route="egress-mcp-result",
    )

    assert out.action == DISPOSITION_PSEUDONYMIZE
    assert out.route_local is False
    assert out.transformed is True
    assert out.engaged is True, "mode-B PSEUDONYMIZE holds the round-trip"
    assert out.forward_bytes is not None
    assert "user1@example.com" not in out.forward_bytes.decode()


# ---------------------------------------------------------------------------
# 2. Fail-closed backstop: OPA unreachable → never a cloud forward of the value.
#    The egress degrades to a held document (BLOCK) — the synthetic fail-closed
#    decision — and the PIPELINE'S OWN field-role seam (the Python backstop) still
#    routes an operate-on sensitive mode-B document LOCAL / BLOCK, never fail-open.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_opa_unreachable_egress_fails_closed_not_to_cloud(monkeypatch):
    """With NO live OPA, evaluate_document_decision returns a synthetic fail-closed
    BLOCK; the egress HOLDS the salary document — it is NEVER forwarded to the
    cloud upstream (the nightmare regression: an operate-on sensitive value escapes
    because the policy engine was down)."""
    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("YASHIGANI_DOCUMENT_MODEB_PROXY_ENABLED", "true")

    out = await egress_decide(
        _real_pipeline(),
        opa_url="https://opa-not-here.invalid:8181",
        body=_SALARY_CSV,
        content_type=_CSV_MIME,
        request_id="rl-fc",
        route="egress-mcp-result",
    )

    assert out.action == DISPOSITION_BLOCK
    assert out.blocked is True
    assert out.forward_bytes is None, (
        "OPA-unreachable forwarded the salary document — FAIL-OPEN regression"
    )


def test_python_field_role_backstop_routes_local_when_opa_absent():
    """The pipeline's OWN field-role seam is the fail-closed backstop: even with no
    OPA in the loop at all, asking the pipeline to PSEUDONYMIZE a salary column
    mode-B routes the whole document LOCAL (default routing) — the values stay
    in-estate, NOT blobbed to the cloud.  This is the seam OPA now also decides;
    the Python path remains the backstop."""
    pipe = _real_pipeline()
    r = pipe.inspect(
        _SALARY_CSV, _CSV_MIME, request_id="rl-bk",
        requested_action="PSEUDONYMIZE", pseudonymize_mode="B",
    )
    assert r.disposition == DISPOSITION_ROUTE_LOCAL, r.block_reason
    assert r.route_local is True
    assert r.forward_bytes == _SALARY_CSV  # original to local, not a cloud blob
    assert r.mode_b_roundtrip is None      # no cloud round-trip held
    assert any("SALARY" in c for c in r.operate_on_classes)


def test_python_backstop_block_routing_fails_closed_no_local():
    """When the operator's routing is BLOCK (no local route available), the Python
    backstop fails CLOSED to BLOCK rather than blobbing the operate-on sensitive
    value to the cloud — proving the backstop never fails open."""
    from yashigani.documents.pipeline import OPERATE_ON_BLOCK

    pipe = _real_pipeline()
    r = pipe.inspect(
        _SALARY_CSV, _CSV_MIME, request_id="rl-bkb",
        requested_action="PSEUDONYMIZE", pseudonymize_mode="B",
        operate_on_routing=OPERATE_ON_BLOCK,
    )
    assert r.disposition == DISPOSITION_BLOCK
    assert "operate-on sensitive" in (r.block_reason or "")


# ---------------------------------------------------------------------------
# 3. inspect() dispatches an OPA-decided ROUTE_LOCAL action directly (the action
#    decision source-of-truth path: OPA decides ROUTE_LOCAL, the pipeline applies
#    _route_local — forward the ORIGINAL bytes to the local model).
# ---------------------------------------------------------------------------

def test_inspect_dispatches_route_local_action():
    """When the (OPA-decided) requested_action IS ROUTE_LOCAL, inspect() drives the
    _route_local handler — forward the ORIGINAL bytes, flag route_local, record the
    operate_on_classes breadcrumb — rather than fail-closing to BLOCK on an
    'unknown action'."""
    pipe = _real_pipeline()
    r = pipe.inspect(
        _SALARY_CSV, _CSV_MIME, request_id="rl-disp",
        requested_action=DISPOSITION_ROUTE_LOCAL,
    )
    assert r.disposition == DISPOSITION_ROUTE_LOCAL
    assert r.route_local is True
    assert r.forward_bytes == _SALARY_CSV
    assert any("SALARY" in c for c in r.operate_on_classes)
