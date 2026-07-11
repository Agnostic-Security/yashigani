"""
2.26 gap #1 — PSEUDONYMIZE mode-B over the REAL gateway proxy egress path.

Exercises the runtime request→upstream→response seam in ``gateway/proxy.py``
(``_proxy_request_body``) with a STUB upstream (monkeypatched ``_forward``), the
flags ON, and a REAL :class:`DocumentInspectionPipeline` (subprocess extractor
backend) doing genuine tokenization + restoration.  The four invariants the brief
requires:

  1. tokenized OUTBOUND  — the upstream receives the ``[CLASS_N]`` artefact, never
     the original value;
  2. restored INBOUND    — a genuine transformed upstream answer that preserves the
     token's egress neighbourhood is restored to cleartext on the way back;
  3. verbatim-echo blocked — an upstream that bounces the egress frame back (the
     harvest attack, L-02) restores NOTHING and is marked tainted;
  4. flag-off bypassed   — with the mode-B-proxy flag off, the body is forwarded
     verbatim, untouched, and no mode-B header is set.

Plus: a non-document request is untouched even with the flags on, and an
unexpected pipeline fault degrades to forwarding the original (traffic-safe).
"""
from __future__ import annotations

import time as _time
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

pytest.importorskip("openpyxl", reason="xlsx parser (shared extractor deps)")

from src.tests.unit.test_documents_end_to_end_log import (  # noqa: E402
    _WorkerSubprocessBackend,
)
from yashigani.documents.extractor import ExtractorRegistry  # noqa: E402
from yashigani.documents.pipeline import DocumentInspectionPipeline  # noqa: E402
from yashigani.documents.sandbox import SandboxedExtractorRunner  # noqa: E402

# A document whose ONE PII value sits inside >=24 chars of stable filler on both
# sides, so the token's egress context window is reproducible in a genuine
# upstream answer (the L-02 position binding is a ±24-char neighbourhood).
_LEFT = "the verified billing contact is "
_RIGHT = " for all future correspondence here"
_ORIGINAL = "alice@example.com"
_DOC_BYTES = (_LEFT + _ORIGINAL + _RIGHT).encode()
_DOC_MIME = "text/plain"


def _real_pipeline() -> DocumentInspectionPipeline:
    runner = SandboxedExtractorRunner(backend=_WorkerSubprocessBackend())
    reg = ExtractorRegistry(sandbox_runner=runner)
    # Small-set escalation off: a one-row flat doc is a re-identifiable small set;
    # this test isolates the mode-B egress mechanic, not the L-01 gate (which has
    # its own dedicated tests).
    return DocumentInspectionPipeline(registry=reg, small_set_escalation=False)


def _state(document_pipeline=None):
    from yashigani.gateway.proxy import GatewayConfig

    return {
        "config": GatewayConfig(
            upstream_base_url="http://mcp:8080", opa_url="http://opa:8181"
        ),
        "inspection_pipeline": None,
        "response_inspection_pipeline": None,
        "auth_service": None,
        "chs": None,
        "audit_writer": MagicMock(),
        "rate_limiter": None,
        "rbac_store": None,
        "agent_registry": None,
        "jwt_inspector": None,
        "endpoint_rate_limiter": None,
        "response_cache": None,
        "fasttext_backend": None,
        "inference_logger": None,
        "anomaly_detector": None,
        "ddos_protector": None,
        "pii_detector": None,
        "document_pipeline": document_pipeline,
        "http_client": AsyncMock(),
    }


def _request(body: bytes, content_type: str = _DOC_MIME):
    req = MagicMock()
    req.method = "POST"
    req.headers = MagicMock()

    def _get(k, d=""):
        kl = k.lower()
        if kl == "content-type":
            return content_type
        return d

    req.headers.get = _get
    req.headers.items = lambda: [("content-type", content_type)]
    req.cookies = {}
    req.url = MagicMock()
    req.url.query = ""
    req.body = AsyncMock(return_value=body)
    return req


def _pseudonymize_modeb_decision() -> dict:
    """The OPA decision a policy-driven egress yields for a PII document on the
    egress-mcp-result route with a PSEUDONYMIZE mode-B policy.  This is what the
    REAL rego returns; the egress applies it.  (The egress decision now reuses
    evaluate_document_decision — the SAME source the backoffice /inspect uses — so
    these tests pin the OPA decision rather than letting it fail-closed without a
    live OPA server.)"""
    return {
        "allow": True,
        "deny": [],
        "action": "PSEUDONYMIZE",
        "pseudonymize_mode": "B",
        "policy_id": "DOC-EX-PII-1",
        "code": "DOCUMENT_PII_PSEUDONYMIZED",
        "obligations": ["apply_pseudonymize_tokens", "vault_replacer_map_round_trip"],
        "detokenize_rbac_role": "doc-pseudonymize-reverser",
    }


def _patch_common(monkeypatch, captured: dict, upstream: httpx.Response,
                  *, egress_decision: dict | None = None):
    """Patch the proxy's request/identity/OPA seams + capture the forwarded body.

    ``egress_decision`` pins the OPA document decision the policy-driven egress
    consumes (default: PSEUDONYMIZE mode B).  Pass an alternate dict to drive the
    egress through a different OPA action (LOG/REDACT/BLOCK)."""
    from yashigani.gateway import proxy as _proxy
    from yashigani.documents import proxy_modeb as _pm

    monkeypatch.setattr(_proxy, "_opa_check", AsyncMock(return_value=True))
    monkeypatch.setattr(
        _proxy, "_opa_proxy_response_check",
        AsyncMock(return_value={"allow": True, "reason": "ok"}),
    )
    monkeypatch.setattr(_proxy, "_proxy_response_sensitivity", lambda *a, **kw: "PUBLIC")
    monkeypatch.setattr(_proxy, "_extract_identity", lambda r: ("sess-1", "", "alice"))
    monkeypatch.setattr(_proxy, "_get_client_ip", lambda r: "127.0.0.1")

    # Pin the policy-driven egress decision (real OPA call seam).  egress_decide
    # imports evaluate_document_decision into proxy_modeb's namespace, so patch it
    # there.
    _decision = egress_decision if egress_decision is not None else _pseudonymize_modeb_decision()
    monkeypatch.setattr(
        _pm, "evaluate_document_decision", AsyncMock(return_value=_decision)
    )

    async def _fake_forward(client, request, path, forwarded_body, request_id):
        captured["forwarded_body"] = forwarded_body
        return upstream

    monkeypatch.setattr(_proxy, "_forward", _fake_forward)


async def _run(state, req):
    from yashigani.gateway import proxy as _proxy

    return await _proxy._proxy_request_body(
        request=req,
        path="/mcp/upload",
        state=state,
        _tracer=None,
        _root_span=MagicMock(set_attribute=MagicMock()),
        request_id="req-modeb",
        cfg=state["config"],
        audit_writer=state["audit_writer"],
        start=_time.monotonic(),
    )


# ---------------------------------------------------------------------------
# 1 + 2 — tokenized outbound, restored inbound (the happy round-trip).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_modeb_proxy_tokenizes_outbound_and_restores_inbound(monkeypatch):
    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("YASHIGANI_DOCUMENT_MODEB_PROXY_ENABLED", "true")

    # Opaque token (DECIDED 2026-06-10): the token is a deterministic function of
    # (doc_hash, value, secret), so a probe pipeline tokenizing the SAME bytes
    # yields the SAME token the proxy will emit.  Learn it, then build a genuine
    # transformed upstream answer that reproduces the token's egress neighbourhood
    # (so position binding restores it) but is NOT an echo.
    probe = _real_pipeline().inspect(
        data=_DOC_BYTES, declared_mime=_DOC_MIME, request_id="probe",
        requested_action="PSEUDONYMIZE", pseudonymize_mode="B",
    )
    email_tok = next(
        tok for tok, occ in probe.mode_b_roundtrip.binder._egress.items()
        if occ.original == _ORIGINAL
    )
    upstream_answer = ("Answer: " + _LEFT + email_tok + _RIGHT + " — end.").encode()
    upstream = httpx.Response(200, content=upstream_answer)

    captured: dict = {}
    _patch_common(monkeypatch, captured, upstream)

    state = _state(document_pipeline=_real_pipeline())
    resp = await _run(state, _request(_DOC_BYTES))

    # OUTBOUND: the upstream received the tokenized artefact, never the original.
    fwd = captured["forwarded_body"].decode()
    assert email_tok in fwd, "outbound body was not tokenized"
    assert _ORIGINAL not in fwd, "original value leaked to upstream (mode-B failed)"

    # INBOUND: the response delivered downstream carries the restored cleartext.
    assert resp.status_code == 200
    assert _ORIGINAL.encode() in resp.body, "value was not restored on the response leg"
    assert resp.headers.get("X-Yashigani-Document-ModeB") == "restored"


# ---------------------------------------------------------------------------
# 3 — verbatim-echo blocked (the harvest attack, L-02).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_modeb_proxy_blocks_verbatim_echo(monkeypatch):
    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("YASHIGANI_DOCUMENT_MODEB_PROXY_ENABLED", "true")

    pipeline = _real_pipeline()

    # First, learn the exact egress frame the proxy will produce by tokenizing the
    # same doc through the same pipeline — the attacker bounces THAT frame back.
    pre = pipeline.inspect(
        data=_DOC_BYTES, declared_mime=_DOC_MIME, request_id="probe",
        requested_action="PSEUDONYMIZE", pseudonymize_mode="B",
    )
    egress_frame = pre.forward_bytes.decode()

    upstream = httpx.Response(200, content=egress_frame.encode())
    captured: dict = {}
    _patch_common(monkeypatch, captured, upstream)

    state = _state(document_pipeline=pipeline)
    resp = await _run(state, _request(_DOC_BYTES))

    # The echo restores NOTHING: the value must not appear, the token stays, and
    # the round-trip is flagged tainted.
    assert resp.status_code == 200
    assert _ORIGINAL.encode() not in resp.body, "echo harvest recovered cleartext (L-02 breach)"
    # The opaque token survives in the (rejected) echo response, unrestored.
    email_tok = next(
        tok for tok, occ in pre.mode_b_roundtrip.binder._egress.items()
        if occ.original == _ORIGINAL
    )
    assert email_tok.encode() in resp.body, "tokenized echo response not preserved"
    assert resp.headers.get("X-Yashigani-Document-ModeB") == "tainted"


# ---------------------------------------------------------------------------
# 4 — flag-off bypassed (the hot path is untouched).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_modeb_proxy_flag_off_bypasses(monkeypatch):
    # Document enforcement on but mode-B-proxy OFF → no tokenization at all.
    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("YASHIGANI_DOCUMENT_MODEB_PROXY_ENABLED", "false")

    upstream = httpx.Response(200, content=b"upstream said hello")
    captured: dict = {}
    _patch_common(monkeypatch, captured, upstream)

    state = _state(document_pipeline=_real_pipeline())
    resp = await _run(state, _request(_DOC_BYTES))

    # Outbound body forwarded verbatim (the original value, NOT a token).
    assert captured["forwarded_body"] == _DOC_BYTES
    assert resp.status_code == 200
    assert resp.headers.get("X-Yashigani-Document-ModeB") is None


# ---------------------------------------------------------------------------
# Guard — a non-document request is untouched even with both flags on.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_modeb_proxy_non_document_untouched(monkeypatch):
    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("YASHIGANI_DOCUMENT_MODEB_PROXY_ENABLED", "true")

    json_body = b'{"method":"tools/list"}'
    upstream = httpx.Response(200, content=b'{"result": "ok"}')
    captured: dict = {}
    _patch_common(monkeypatch, captured, upstream)

    state = _state(document_pipeline=_real_pipeline())
    resp = await _run(state, _request(json_body, content_type="application/json"))

    # A JSON/MCP body is not a document egress → forwarded verbatim, no header.
    assert captured["forwarded_body"] == json_body
    assert resp.status_code == 200
    assert resp.headers.get("X-Yashigani-Document-ModeB") is None


# ---------------------------------------------------------------------------
# Traffic-safety — an unexpected pipeline fault degrades to forwarding original.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_modeb_proxy_pipeline_fault_forwards_original(monkeypatch):
    monkeypatch.setenv("YASHIGANI_DOCUMENT_ENFORCEMENT_ENABLED", "true")
    monkeypatch.setenv("YASHIGANI_DOCUMENT_MODEB_PROXY_ENABLED", "true")

    # A pipeline whose inspect() raises unexpectedly (NOT a disposition).
    broken = MagicMock(spec=DocumentInspectionPipeline)
    broken.inspect.side_effect = RuntimeError("synthetic fault")

    upstream = httpx.Response(200, content=b"upstream ok")
    captured: dict = {}
    _patch_common(monkeypatch, captured, upstream)

    state = _state(document_pipeline=broken)
    resp = await _run(state, _request(_DOC_BYTES))

    # The fault must NOT break traffic: the ORIGINAL bytes are forwarded and the
    # request completes normally (mode-B simply disengaged).
    assert captured["forwarded_body"] == _DOC_BYTES
    assert resp.status_code == 200
    assert resp.headers.get("X-Yashigani-Document-ModeB") is None
