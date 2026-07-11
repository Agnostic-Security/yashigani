"""
DP-Y-003 §3.4 — Semantic-intent classifier wired at import time.

Defensive publication §3.4: "descriptions and schemas are passed through a
SEMANTIC-INTENT CLASSIFIER at import/approval time … the gateway's EXISTING
semantic-intent classifier applied at a new point — the import path."

Honesty invariant: "if the sidecar is unreachable, the verdict records
``classifier_status='unavailable'`` and ``sidecar_used=False`` — it does NOT
claim ``sidecar_used=True`` while only running the heuristic."

EU AI Act Art.14: classifier flags to the operator but NEVER auto-rejects;
operator approval remains mandatory regardless of verdict.

Tests (binary PASS/FAIL):

  S1  sidecar=None  → verdict records sidecar_used=False + classifier_status="not_configured"
  S2  sidecar=mock + flag ON → verdict records sidecar_used=True + classifier_status="ran"
  S3  sidecar wired → build_catalogue receives the sidecar object (not None)
  S4  sidecar unavailable → filter_version="v2_heuristic" (honest record)
  S5  sidecar available  → filter_version="v2_semantic"
  S6  operator approval is ALWAYS required, regardless of sidecar verdict
       (step-up gate fires BEFORE mint, even if sidecar passes every tool)

Last updated: 2026-07-02
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from yashigani.auth.session import Session
from yashigani.backoffice.middleware import require_admin_session
from yashigani.backoffice.routes.envelope_import import router as import_router
from yashigani.backoffice.state import backoffice_state
from yashigani.mcp._envelope import compute_provenance_id, project_surface
from yashigani.mcp.envelope_service import EnvelopeRecord

# ── Constants ──────────────────────────────────────────────────────────────────

TENANT = "default"
SERVER = "sidecar-test-mcp"
UPSTREAM_URL = "http://sidecar-test-mcp:8000"

MCP_SERVERS_ENV = json.dumps([
    {"agent_name": SERVER, "upstream_url": UPSTREAM_URL, "tenant_id": TENANT}
])

RAW_TOOLS = [
    {"name": "echo", "description": "Echo the input text back.",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}},
    {"name": "summarise", "description": "Summarise a document.",
     "inputSchema": {"type": "object", "properties": {"doc": {"type": "string"}}}},
]

TOOLS_LIST_RESPONSE = {
    "jsonrpc": "2.0",
    "id": "import-ceremony",
    "result": {"tools": RAW_TOOLS},
}


# ── Stub envelope service ──────────────────────────────────────────────────────

class _StubEnvelopeService:
    def __init__(self, *, existing_baseline=None):
        self._baseline = existing_baseline
        self.minted: list[dict] = []

    async def get_baseline_envelope(self, provenance_id: str):
        return self._baseline

    async def mint_envelope(self, env, *, server_id, operator_identity,
                            topology="ring_fenced", sidecar_scan_verdict=None) -> int:
        self.minted.append({
            "server_id": server_id,
            "sidecar_scan_verdict": sidecar_scan_verdict,
        })
        return 99


# ── Mock sidecar ───────────────────────────────────────────────────────────────

def _mock_sidecar():
    """Stub SemanticIntentSidecar — returns a benign verdict for any input.

    ``evaluate`` is a SYNCHRONOUS method on SemanticIntentSidecar; it returns
    a SemanticIntentVerdict-like object (not a coroutine).  The mock therefore
    uses a plain MagicMock (not AsyncMock) and returns an object with the
    attributes that ``filter_description_v2`` reads: ``skipped`` and
    ``is_injection``.
    """
    sidecar = MagicMock()
    _benign_verdict = MagicMock()
    _benign_verdict.skipped = False        # sidecar ran
    _benign_verdict.is_injection = False   # content is clean
    sidecar.evaluate = MagicMock(return_value=_benign_verdict)
    return sidecar


# ── Session helpers ────────────────────────────────────────────────────────────

def _admin_session(*, stepup: bool, tier: str = "admin") -> Session:
    now = time.time()
    return Session(
        token="t", account_id="admin1", account_tier=tier,
        created_at=now, last_active_at=now, expires_at=now + 3600,
        ip_prefix="10.0.0.x",
        last_totp_verified_at=(now if stepup else None),
    )


# ── Fixture builder ────────────────────────────────────────────────────────────

@dataclass
class _Ctx:
    client: TestClient
    svc: _StubEnvelopeService
    session_box: dict


def _build_app(svc: _StubEnvelopeService, *, mcp_servers: str = MCP_SERVERS_ENV):
    app = FastAPI()
    app.include_router(import_router, prefix="/admin/mcp/envelopes")
    session_box: dict = {"session": _admin_session(stepup=True)}
    app.dependency_overrides[require_admin_session] = lambda: session_box["session"]

    import yashigani.backoffice.routes.envelope_import as mod
    mod_patch = patch.object(mod, "_envelope_service", return_value=svc)
    env_patch = patch.dict(
        "os.environ",
        {"YASHIGANI_MCP_SERVERS": mcp_servers, "YASHIGANI_TENANT_ID": TENANT},
    )
    mod_patch.start()
    env_patch.start()
    return app, session_box, (mod_patch, env_patch)


def _http_mock():
    """Return a mock httpx.AsyncClient that returns TOOLS_LIST_RESPONSE."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = TOOLS_LIST_RESPONSE
    mock_client = MagicMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)
    return mock_client


# ── S1 — sidecar=None → sidecar_used=False + unavailable ─────────────────────


def test_s1_sidecar_none_honest_verdict():
    """S1: When backoffice_state.semantic_intent_sidecar is None, verdict records
    sidecar_used=False and classifier_status='not_configured'.

    CT-1 fix: status is derived from whether the classifier actually evaluated,
    not from object existence.  No sidecar object → 'not_configured' (was the
    old wrong 'unavailable' label which conflated "no object" with "object
    present but errored").
    """
    svc = _StubEnvelopeService()
    app, session_box, patches = _build_app(svc)
    http_patch = patch(
        "yashigani.backoffice.routes.envelope_import.httpx.AsyncClient",
        return_value=_http_mock(),
    )
    http_patch.start()
    backoffice_state.semantic_intent_sidecar = None
    backoffice_state.audit_writer = None

    try:
        client = TestClient(app)
        r = client.post(f"/admin/mcp/envelopes/import/{SERVER}", json={
            "egress_posture": "NONE", "topology": "ring_fenced",
        })
        assert r.status_code == 200, r.text
        body = r.json()
        verdict = body["sidecar_scan_verdict"]
        # Honesty invariant: must NOT claim the classifier ran
        assert verdict["sidecar_used"] is False, "sidecar_used must be False when sidecar is None"
        # CT-1: "not_configured" when no sidecar object — distinct from object-present-but-errored
        assert verdict["classifier_status"] == "not_configured", (
            f"CT-1: expected 'not_configured', got {verdict['classifier_status']!r}"
        )
        assert "tool_count" in verdict
        assert verdict["tool_count"] == len(RAW_TOOLS)
    finally:
        for p in patches:
            p.stop()
        http_patch.stop()
        backoffice_state.semantic_intent_sidecar = None


# ── S2 — sidecar wired → sidecar_used=True + available ───────────────────────


def test_s2_sidecar_wired_verdict():
    """S2: When backoffice_state.semantic_intent_sidecar is set AND the feature
    flag is ON, verdict records sidecar_used=True and classifier_status='ran'.

    CT-1 fix: 'ran' (was wrong 'available') — status reflects actual evaluation.
    Flag must be ON; without it the verdict honestly reports 'disabled_by_flag'.
    The sidecar mock's evaluate() returns skipped=False so filter_description_v2
    annotates semantic_intent_score on each FilterResult, proving evaluation ran.
    """
    svc = _StubEnvelopeService()
    app, session_box, patches = _build_app(svc)
    http_patch = patch(
        "yashigani.backoffice.routes.envelope_import.httpx.AsyncClient",
        return_value=_http_mock(),
    )
    http_patch.start()
    # CT-1: flag must be ON for the status to reflect actual evaluation
    flag_patch = patch.dict("os.environ", {"YASHIGANI_SEMANTIC_INTENT_SIDECAR": "1"})
    flag_patch.start()
    backoffice_state.semantic_intent_sidecar = _mock_sidecar()
    backoffice_state.audit_writer = None

    try:
        client = TestClient(app)
        r = client.post(f"/admin/mcp/envelopes/import/{SERVER}", json={
            "egress_posture": "NONE", "topology": "ring_fenced",
        })
        assert r.status_code == 200, r.text
        body = r.json()
        verdict = body["sidecar_scan_verdict"]
        assert verdict["sidecar_used"] is True, "sidecar_used must be True when sidecar ran"
        # CT-1: 'ran' not 'available' — derived from actual evaluation markers
        assert verdict["classifier_status"] == "ran", (
            f"CT-1: expected 'ran', got {verdict['classifier_status']!r}"
        )
        assert verdict["tool_count"] == len(RAW_TOOLS)
    finally:
        for p in patches:
            p.stop()
        http_patch.stop()
        flag_patch.stop()
        backoffice_state.semantic_intent_sidecar = None


# ── S3 — build_catalogue receives the sidecar object ─────────────────────────


def test_s3_build_catalogue_receives_sidecar():
    """S3: _screen_tools passes backoffice_state.semantic_intent_sidecar (not None)
    to build_catalogue as the sidecar keyword argument (DP-Y-003 §3.4 wiring)."""
    sidecar = _mock_sidecar()
    catalogue_calls: list[dict] = []

    from yashigani.mcp._content_filter import TenantCatalogue, ToolDescriptor, FilterResult

    def _fake_build_catalogue(**kwargs):
        catalogue_calls.append(kwargs)
        # Return a minimal catalogue with the two tools all-passing
        tools = [
            ToolDescriptor(
                tool_name=t["name"],
                safe_description=t["description"],
                filter_result=FilterResult(
                    rejected=False, reject_reason="", safe_text=t["description"],
                    normalised_length=len(t["description"]),
                    original_length=len(t["description"]),
                ),
            )
            for t in RAW_TOOLS
        ]
        return TenantCatalogue(tenant_id=TENANT, server_id=SERVER, tools=tools)

    # build_catalogue is imported inside _screen_tools with a local import
    # ``from yashigani.mcp._content_filter import build_catalogue`` — patch at
    # the source module so the local import picks up the stub.
    import yashigani.mcp._content_filter as filter_mod
    with patch.object(filter_mod, "build_catalogue", side_effect=_fake_build_catalogue):
        backoffice_state.semantic_intent_sidecar = sidecar
        try:
            from yashigani.backoffice.routes.envelope_import import _screen_tools
            _raw_tools, verdict = _screen_tools(SERVER, RAW_TOOLS)
        finally:
            backoffice_state.semantic_intent_sidecar = None

    assert len(catalogue_calls) == 1
    call_kwargs = catalogue_calls[0]
    # The sidecar must be passed through — not None, and the exact mock object
    assert call_kwargs.get("sidecar") is sidecar, (
        f"build_catalogue must receive sidecar=<mock>, got sidecar={call_kwargs.get('sidecar')!r}"
    )


# ── S4 — sidecar unavailable → filter_version="v2_heuristic" ─────────────────


def test_s4_filter_version_heuristic_when_no_sidecar():
    """S4: With no sidecar, filter_version is 'v2_heuristic' (honest record)."""
    svc = _StubEnvelopeService()
    app, session_box, patches = _build_app(svc)
    http_patch = patch(
        "yashigani.backoffice.routes.envelope_import.httpx.AsyncClient",
        return_value=_http_mock(),
    )
    http_patch.start()
    backoffice_state.semantic_intent_sidecar = None
    backoffice_state.audit_writer = None

    try:
        client = TestClient(app)
        r = client.post(f"/admin/mcp/envelopes/import/{SERVER}", json={})
        assert r.status_code == 200, r.text
        verdict = r.json()["sidecar_scan_verdict"]
        assert verdict["filter_version"] == "v2_heuristic"
    finally:
        for p in patches:
            p.stop()
        http_patch.stop()
        backoffice_state.semantic_intent_sidecar = None


# ── S5 — sidecar available → filter_version="v2_semantic" ────────────────────


def test_s5_filter_version_semantic_when_sidecar_present():
    """S5: With sidecar wired AND flag ON, filter_version is 'v2_semantic'.

    CT-1 fix: filter_version='v2_semantic' is only set when the classifier
    actually evaluated (flag ON + object present + evaluate() succeeded).
    Without the flag, filter_version is 'v2_heuristic' (disabled_by_flag).
    """
    svc = _StubEnvelopeService()
    app, session_box, patches = _build_app(svc)
    http_patch = patch(
        "yashigani.backoffice.routes.envelope_import.httpx.AsyncClient",
        return_value=_http_mock(),
    )
    http_patch.start()
    # CT-1: flag must be ON for filter_version to be 'v2_semantic'
    flag_patch = patch.dict("os.environ", {"YASHIGANI_SEMANTIC_INTENT_SIDECAR": "1"})
    flag_patch.start()
    backoffice_state.semantic_intent_sidecar = _mock_sidecar()
    backoffice_state.audit_writer = None

    try:
        client = TestClient(app)
        r = client.post(f"/admin/mcp/envelopes/import/{SERVER}", json={})
        assert r.status_code == 200, r.text
        verdict = r.json()["sidecar_scan_verdict"]
        assert verdict["filter_version"] == "v2_semantic", (
            f"CT-1: expected 'v2_semantic', got {verdict['filter_version']!r}"
        )
    finally:
        for p in patches:
            p.stop()
        http_patch.stop()
        flag_patch.stop()
        backoffice_state.semantic_intent_sidecar = None


# ── S6 — Operator approval mandatory, regardless of sidecar verdict ───────────


def test_s6_no_stepup_blocks_import_even_if_sidecar_passes():
    """S6 (EU AI Act Art.14): step-up is required even when the sidecar passes all
    tools — the classifier verdict does NOT auto-approve.  Operator must review."""
    svc = _StubEnvelopeService()
    app, session_box, patches = _build_app(svc)
    http_patch = patch(
        "yashigani.backoffice.routes.envelope_import.httpx.AsyncClient",
        return_value=_http_mock(),
    )
    http_patch.start()
    # Set sidecar — classifier would report all tools clean
    backoffice_state.semantic_intent_sidecar = _mock_sidecar()
    backoffice_state.audit_writer = None

    try:
        # Remove step-up from session — simulates operator without fresh TOTP
        session_box["session"] = _admin_session(stepup=False)
        client = TestClient(app)
        r = client.post(f"/admin/mcp/envelopes/import/{SERVER}", json={})
        # MUST block — step-up required regardless of classifier verdict
        assert r.status_code == 401, (
            f"Expected 401 step_up_required even with clean sidecar verdict, got {r.status_code}: {r.text}"
        )
        assert r.json()["detail"]["error"] == "step_up_required"
        # Absolutely no envelope should have been minted
        assert svc.minted == [], "mint must never happen without step-up"
    finally:
        for p in patches:
            p.stop()
        http_patch.stop()
        backoffice_state.semantic_intent_sidecar = None


def test_s6b_non_admin_blocked_even_if_sidecar_passes():
    """S6b: user-tier session is forbidden even with clean sidecar verdict."""
    svc = _StubEnvelopeService()
    app, session_box, patches = _build_app(svc)
    http_patch = patch(
        "yashigani.backoffice.routes.envelope_import.httpx.AsyncClient",
        return_value=_http_mock(),
    )
    http_patch.start()
    backoffice_state.semantic_intent_sidecar = _mock_sidecar()
    backoffice_state.audit_writer = None

    try:
        session_box["session"] = _admin_session(stepup=True, tier="user")
        client = TestClient(app)
        r = client.post(f"/admin/mcp/envelopes/import/{SERVER}", json={})
        assert r.status_code == 403, r.text
        assert svc.minted == []
    finally:
        for p in patches:
            p.stop()
        http_patch.stop()
        backoffice_state.semantic_intent_sidecar = None
