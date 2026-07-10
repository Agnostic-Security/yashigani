"""
3.0 DETERMINISTIC GATE — capability-envelope re-approval admin route.

Machine-judged, binary PASS/FAIL per assertion (Ava A3).  Each test maps to an
ASVS / OWASP-API / OWASP-Web control and proves a security property of the
re-approval SPA's backend seam (backoffice/routes/envelope_reapproval.py +
mcp/envelope_pending_store.py).  The route wires the REAL services:

  * EnvelopePendingStore over a fakeredis client (the real store code path).
  * A stub CapabilityEnvelopeService returning a REAL ServerEnvelope baseline
    (so the diff is computed by the REAL compute_field_level_diff /
    diff_envelope authority — not mocked).
  * The REAL step-up gate (assert_privileged_mutation) via an injected Session
    whose tier + last_totp_verified_at we control.

Gate assertions:
  G1  list pending — admin only; tenant-scoped queue                  (API1/BOLA, ASVS V8)
  G2  diff vs ORIGINAL baseline is computed + returned                (anti-rug-pull, design)
  G3  XSS — hostile tool name returned as JSON string, never HTML     (ASVS V5.3.3 / A03)
  G4  approve WITHOUT fresh step-up → 401 step_up_required            (ASVS V6.8.4 / API2)
  G5  approve by NON-admin → 403 (RBAC), no mint                      (API5 / ASVS V8)
  G6  approve WITH step-up → mints new baseline + clears pending      (design happy-path)
  G7  reject WITHOUT step-up → 401; with step-up → keeps block        (API2 / design)
  G8  IDOR/BOLA — cross-tenant provenance → 404, never the candidate  (API1 / A01)
  G9  no secret / handle in any response body                        (ASVS V8.3 / A02)

Run:
  PYTHONPATH=src pytest src/tests/unit/test_v30_envelope_reapproval_route.py -q

Last updated: 2026-06-10
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import fakeredis
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from yashigani.auth.session import Session
from yashigani.backoffice.middleware import require_admin_session
from yashigani.backoffice.routes.envelope_reapproval import router as env_router
from yashigani.backoffice.state import backoffice_state
from yashigani.mcp._envelope import (
    compute_provenance_id,
    project_surface,
)
from yashigani.mcp.envelope_pending_store import EnvelopePendingStore
from yashigani.mcp.envelope_service import EnvelopeRecord

TENANT = "default"
OTHER_TENANT = "tenant-evil"
PROV = compute_provenance_id("github-mcp", "sha256:deadbeef")
SERVER = "github-mcp"

# A hostile tool name an upstream MCP could advertise — the XSS canary.
XSS_NAME = '<img src=x onerror=alert(1)>'


# ── Surfaces ────────────────────────────────────────────────────────────────

def _tool(name, *, effect="READ", props=None):
    schema = {"type": "object", "properties": props or {}, "additionalProperties": False}
    raw = {"name": name, "description": f"{name} tool", "inputSchema": schema}
    if effect in ("WRITE", "EXEC"):
        # destructiveHint raises the structural floor to WRITE (a real expansion).
        raw["annotations"] = {"destructiveHint": True}
    return raw


# ORIGINAL approved baseline: a single read-only tool, no egress.
BASELINE_TOOLS = [_tool("read_file", props={"path": {"type": "string"}})]

# CANDIDATE (refreshed) surface: adds a destructive tool with a HOSTILE name +
# flips egress to OUTBOUND — the "read-only → file-delete + outbound network"
# expansion story.  This is what the operator is asked to approve.
CANDIDATE_TOOLS = BASELINE_TOOLS + [
    _tool(XSS_NAME, effect="WRITE", props={"target": {"type": "string"}}),
]


def _baseline_env():
    return project_surface(PROV, TENANT, BASELINE_TOOLS, egress_posture="NONE")


def _candidate_env():
    return project_surface(PROV, TENANT, CANDIDATE_TOOLS, egress_posture="OUTBOUND")


# ── A stub CapabilityEnvelopeService backed by the REAL diff ─────────────────

class _StubEnvelopeService:
    """Returns a REAL baseline ServerEnvelope; records mint() calls.

    The route's diff is computed by the REAL compute_field_level_diff over this
    baseline + the candidate from the store — so the diff assertions exercise
    the authoritative structural diff, not a mock."""

    def __init__(self):
        self.minted = []

    def _record(self, env, version):
        return EnvelopeRecord(
            id=1, provenance_id=PROV, tenant_id=TENANT, server_id=SERVER,
            envelope_version=version, previous_envelope_id=None, status="active",
            egress_posture=env.egress_posture, surface_set_hash="h", current_surface_hash="h",
            topology="ring_fenced", approved_by_operator_identity="admin1",
            approved_at=time.time(), envelope=env,
        )

    async def get_baseline_envelope(self, provenance_id):
        return self._record(_baseline_env(), 1)

    async def get_active_envelope(self, provenance_id):
        return self._record(_baseline_env(), 1)

    async def mint_envelope(self, candidate, *, server_id, operator_identity,
                            topology="ring_fenced", sidecar_scan_verdict=None):
        self.minted.append((candidate.provenance_id, operator_identity))
        return 99


# ── Fixtures ─────────────────────────────────────────────────────────────────

@dataclass
class _Ctx:
    client: TestClient
    store: EnvelopePendingStore
    svc: _StubEnvelopeService
    session_box: dict


@pytest.fixture
def ctx(monkeypatch):
    # Real store over fakeredis.
    fake = fakeredis.FakeStrictRedis()
    store = EnvelopePendingStore(redis_client=fake)
    svc = _StubEnvelopeService()

    backoffice_state.envelope_pending_store = store
    backoffice_state.audit_writer = None

    # The route constructs the envelope service via _envelope_service(); stub it.
    import yashigani.backoffice.routes.envelope_reapproval as mod
    monkeypatch.setattr(mod, "_envelope_service", lambda: svc)

    # Session injection — a mutable box the override reads, so each test sets the
    # tier + step-up freshness it wants.
    session_box = {"session": _admin_session(stepup=False)}

    app = FastAPI()
    app.include_router(env_router, prefix="/admin/mcp/envelopes")
    app.dependency_overrides[require_admin_session] = lambda: session_box["session"]

    return _Ctx(client=TestClient(app), store=store, svc=svc, session_box=session_box)


def _admin_session(*, stepup: bool, tier: str = "admin") -> Session:
    now = time.time()
    return Session(
        token="t", account_id="admin1", account_tier=tier,
        created_at=now, last_active_at=now, expires_at=now + 3600,
        ip_prefix="10.0.0.x",
        last_totp_verified_at=(now if stepup else None),
    )


def _seed_pending(store, *, tenant=TENANT):
    store.record_block(
        provenance_id=PROV, tenant_id=tenant, server_id=SERVER,
        candidate=project_surface(PROV, tenant, CANDIDATE_TOOLS, egress_posture="OUTBOUND"),
        triage_class="expanding", new_surface_hash="abc123",
        findings=[{"dimension": "tool_set", "tool_key": f"{PROV}::{XSS_NAME}",
                   "detail": "new tool added"}],
    )


# ── G1 — list pending (admin, tenant-scoped) ─────────────────────────────────

def test_g1_list_pending_admin_tenant_scoped(ctx):
    _seed_pending(ctx.store)
    r = ctx.client.get("/admin/mcp/envelopes/pending")
    assert r.status_code == 200
    body = r.json()
    assert len(body["pending"]) == 1
    row = body["pending"][0]
    assert row["provenance_id"] == PROV
    assert row["triage_class"] == "expanding"
    assert row["candidate_tool_count"] == 2
    assert row["candidate_egress_posture"] == "OUTBOUND"


# ── G2 — diff vs ORIGINAL baseline is computed ───────────────────────────────

def test_g2_diff_vs_original_baseline(ctx):
    _seed_pending(ctx.store)
    r = ctx.client.get(f"/admin/mcp/envelopes/pending/{PROV}")
    assert r.status_code == 200
    body = r.json()
    # The REAL structural diff must flag the new tool + the egress jump vs ORIGINAL.
    dims = {f["dimension"] for f in body["vs_original"]}
    assert "tool_set" in dims, body["vs_original"]
    assert "egress" in dims, body["vs_original"]
    assert body["egress_change"] is True
    assert body["egress_from"] == "NONE" and body["egress_to"] == "OUTBOUND"
    # Anti-rug-pull: vs_original is present AND non-empty.
    assert body["vs_original"], "vs_original diff must be populated"


# ── G3 — XSS: hostile tool name returned as JSON string, never executable HTML ─

def test_g3_xss_tool_name_returned_as_inert_json(ctx):
    _seed_pending(ctx.store)
    r = ctx.client.get(f"/admin/mcp/envelopes/pending/{PROV}")
    assert r.status_code == 200
    # The raw response TEXT must NOT contain an unescaped <img ...onerror> HTML
    # element that a browser could execute — the payload travels as a JSON string
    # (JSON-encoded), and the SPA escapeHtml()s it at the DOM sink.  Assert the
    # content-type is JSON (not text/html) and the payload is carried as data.
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    blob = r.text
    # The hostile name appears in the candidate tool_key as DATA (good)...
    found = any(XSS_NAME in t["tool_key"] for t in body["candidate"]["tools"])
    assert found, "hostile tool name should be carried as candidate data"
    # ...but it must never be emitted as a live HTML element in an HTML response.
    assert "text/html" not in r.headers["content-type"]
    # The JSON serialiser keeps it a string value — there is no HTML document
    # wrapper, so no browser HTML-parses this response.
    assert "<html" not in blob.lower() and "<!doctype" not in blob.lower()


# ── G4 — approve without fresh step-up → 401 step_up_required, NO mint ────────

def test_g4_approve_without_stepup_blocked(ctx):
    _seed_pending(ctx.store)
    ctx.session_box["session"] = _admin_session(stepup=False)
    r = ctx.client.post(f"/admin/mcp/envelopes/pending/{PROV}/approve")
    assert r.status_code == 401
    assert r.json()["detail"]["error"] == "step_up_required"
    assert ctx.svc.minted == [], "no envelope may be minted without step-up"
    assert ctx.store.get(PROV, TENANT) is not None, "pending entry must survive a blocked approve"


# ── G5 — approve by non-admin → 403, NO mint ─────────────────────────────────

def test_g5_approve_non_admin_forbidden(ctx):
    _seed_pending(ctx.store)
    # Even WITH a fresh step-up, a non-operator tier must be rejected by RBAC.
    ctx.session_box["session"] = _admin_session(stepup=True, tier="user")
    r = ctx.client.post(f"/admin/mcp/envelopes/pending/{PROV}/approve")
    assert r.status_code == 403
    assert ctx.svc.minted == [], "non-admin must never mint"


# ── G6 — approve WITH fresh step-up → mints new baseline + clears pending ─────

def test_g6_approve_with_stepup_mints_and_clears(ctx):
    _seed_pending(ctx.store)
    ctx.session_box["session"] = _admin_session(stepup=True)
    r = ctx.client.post(f"/admin/mcp/envelopes/pending/{PROV}/approve")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["new_envelope_id"] == 99
    # POSITIVE artefact: the mint actually happened (Ava A1 — no absence==pass).
    assert ctx.svc.minted == [(PROV, "admin1")], "candidate must be minted as new baseline"
    # And the pending queue entry is consumed.
    assert ctx.store.get(PROV, TENANT) is None, "pending entry must be cleared after approve"


# ── G7 — reject: without step-up → 401; with step-up → block kept, no mint ────

def test_g7_reject_requires_stepup_then_keeps_block(ctx):
    _seed_pending(ctx.store)
    ctx.session_box["session"] = _admin_session(stepup=False)
    r1 = ctx.client.post(f"/admin/mcp/envelopes/pending/{PROV}/reject")
    assert r1.status_code == 401
    assert r1.json()["detail"]["error"] == "step_up_required"
    assert ctx.store.get(PROV, TENANT) is not None

    ctx.session_box["session"] = _admin_session(stepup=True)
    r2 = ctx.client.post(f"/admin/mcp/envelopes/pending/{PROV}/reject")
    assert r2.status_code == 200
    # Reject NEVER mints a new baseline (the block stays latched in the DB).
    assert ctx.svc.minted == [], "reject must not mint"
    # The pending queue entry is consumed (no longer nags the operator).
    assert ctx.store.get(PROV, TENANT) is None


# ── G8 — IDOR / BOLA: cross-tenant provenance → 404, never the candidate ─────

def test_g8_cross_tenant_bola_404(ctx):
    # Seed a pending entry under ANOTHER tenant.
    _seed_pending(ctx.store, tenant=OTHER_TENANT)
    # This install resolves tenant "default" — the other tenant's entry is invisible.
    r_list = ctx.client.get("/admin/mcp/envelopes/pending")
    assert r_list.status_code == 200
    assert r_list.json()["pending"] == [], "cross-tenant entries must not appear"

    r_diff = ctx.client.get(f"/admin/mcp/envelopes/pending/{PROV}")
    assert r_diff.status_code == 404, "cross-tenant diff must 404, never leak the candidate"

    ctx.session_box["session"] = _admin_session(stepup=True)
    r_appr = ctx.client.post(f"/admin/mcp/envelopes/pending/{PROV}/approve")
    assert r_appr.status_code == 404
    assert ctx.svc.minted == [], "cross-tenant approve must never mint"


# ── G9 — no secret / handle in any response body ─────────────────────────────

def test_g9_no_secret_or_handle_in_responses(ctx):
    _seed_pending(ctx.store)
    bodies = [
        ctx.client.get("/admin/mcp/envelopes/pending").text,
        ctx.client.get(f"/admin/mcp/envelopes/pending/{PROV}").text,
    ]
    banned = ["salt", "secret", "map_handle", "replacer", "private_key",
              "pin_material", "totp_secret", "password"]
    for blob in bodies:
        low = blob.lower()
        for term in banned:
            assert term not in low, f"response leaked '{term}': {blob[:200]}"


# ── G10 — broker block path HANDS the candidate to the pending sink ──────────
#
# The end-to-end wiring proof (Ava A1 — positive artefact): when the broker
# LATCHES a block on an EXPANDING refresh, it must invoke pending_block_sink
# with the REAL candidate surface, so the re-approval queue is actually
# populated (otherwise the SPA would show an empty queue while the DB is
# blocked).  Maps to the design contract closing the gap in the backend.

@pytest.mark.asyncio
async def test_g10_broker_block_populates_pending_sink():
    from unittest.mock import AsyncMock, MagicMock
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig
    from yashigani.mcp import UpstreamPinConfig
    from yashigani.mcp.envelope_service import EnvelopeRecord

    # Real store over fakeredis as the sink target.
    store = EnvelopePendingStore(redis_client=fakeredis.FakeStrictRedis())

    pin = UpstreamPinConfig(
        server_id=SERVER, host="gh", port=443,
        cert_fingerprint_sha256="sha256:deadbeef",
    )

    def _rec(env, version):
        return EnvelopeRecord(
            id=1, provenance_id=PROV, tenant_id=TENANT, server_id=SERVER,
            envelope_version=version, previous_envelope_id=None, status="active",
            egress_posture=env.egress_posture, surface_set_hash=env.surface_set_hash,
            current_surface_hash=env.surface_set_hash, topology="ring_fenced",
            approved_by_operator_identity="admin1", approved_at=time.time(), envelope=env,
        )

    base = _baseline_env()
    svc = MagicMock()
    svc.get_baseline_envelope = AsyncMock(return_value=_rec(base, 1))
    svc.get_active_envelope = AsyncMock(return_value=_rec(base, 1))
    svc.latch_block = AsyncMock(return_value=True)
    svc.record_benign_repin = AsyncMock(return_value=True)

    captured = {}

    def _sink(**kwargs):
        captured.update(kwargs)
        store.record_block(**kwargs)

    cfg = McpBrokerConfig(
        opa_url="http://opa:8181", tenant_id=TENANT,
        upstream_pin_configs=[pin], envelope_service=svc,
        enforce_capability_envelope=True, pending_block_sink=_sink,
        audit_writer=None,
    )
    broker = McpBroker(cfg)

    # Refresh with the EXPANDING candidate (new destructive tool + OUTBOUND egress).
    outcome = await broker.refresh_and_triage_tools(SERVER, CANDIDATE_TOOLS, [])

    # The block latched AND the sink received the REAL candidate.
    assert outcome is not None and outcome.should_block
    svc.latch_block.assert_awaited_once()
    assert captured.get("provenance_id") == PROV
    assert captured.get("triage_class") == "expanding"
    # The candidate carries the new (destructive) tool — the structural
    # expansion that triggered the block.  NOTE (design): the broker projects
    # egress from the per-SERVER posture floor (pinned to baseline at this hook),
    # NOT from raw tools/list — so the candidate's egress equals baseline here;
    # an egress-posture change is detected on the server-header path, not this
    # tool-refresh hook.  The route-level egress story (G2) exercises a candidate
    # whose egress already differs.
    cand = captured["candidate"]
    assert len(cand.tools) == 2, "candidate must include the new tool"
    assert any(XSS_NAME in tk for tk in cand.tools), "new (hostile) tool present in candidate"
    # The store now lists the pending re-approval (the SPA would see it).
    pending = store.list_for_tenant(TENANT)
    assert len(pending) == 1 and pending[0]["provenance_id"] == PROV
    assert pending[0]["candidate_tool_count"] == 2
