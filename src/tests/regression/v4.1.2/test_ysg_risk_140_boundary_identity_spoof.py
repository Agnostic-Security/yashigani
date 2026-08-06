"""
Regression tests — YSG-RISK-140 (CRITICAL): MCP identity-header spoof via the
gateway boundary resolver.

ROOT CAUSE (gateway/proxy.py _proxy_request_body, "0b-pre boundary resolution",
~line 654 pre-fix):

    if not hasattr(request.state, "ysg_principal") or request.state.ysg_principal is None:
        _id_reg = state.get("identity_registry")
        _iid_raw = request.headers.get("x-yashigani-identity-id", "").strip()
        if _iid_raw and _id_reg is not None:
            ...
            request.state.ysg_principal = _RP(identity_id=_iid_raw, ...)

This block is the ONLY place in the gateway that ever assigns
``request.state.ysg_principal`` (verified: no other assignment site exists in
openai_router.py, mcp_router_runtime.py, or agent_router.py — those modules
only *read* it). Pre-fix, it trusted the raw client-controllable
``X-Yashigani-Identity-Id`` header as long as the value existed in the
identity registry — with NO check that the caller proved a trusted transport
(``X-Caddy-Verified-Secret`` — Layer B HMAC, or the per-install internal mesh
bearer, or a verified mTLS/SPIFFE peer per T-3).

This silently bypassed the dedicated T-3/T-4 mesh-port trust gate that
``mcp_router_runtime._handle_mcp_call_inner`` implements (YSG-RISK-108,
``_caller_is_trusted = _mesh_caller_is_internal(request) or _caller_is_caddy``)
because that gate only fires when ``request.state.ysg_principal is None``
(see mcp_router_runtime.py line 447: ``_rp_mcp = getattr(request.state,
"ysg_principal", None)``). Once proxy.py's ungated boundary resolver had
already populated ``ysg_principal`` from the raw header, mcp_router_runtime's
own gate became dead code for that request.

Reachability: ``CaddyVerifiedMiddleware`` (Layer B) guards gateway:8080 (the
public/Caddy-fronted listener) end-to-end, so on that port the header would
already have survived a valid Caddy secret check. BUT gateway:8081
(mesh_mode=True) explicitly SKIPS CaddyVerifiedMiddleware and
SpiffePeerCertMiddleware — "Port 8081 is protected by network isolation only"
(entrypoint.py ~line 1253). Any caller able to reach :8081 (compromised
container on the data network, misconfigured NetworkPolicy, adjacent
workload) could set X-Yashigani-Identity-Id to ANY identity present in the
registry and have it adjudicated as that identity for MCP tools/call —
including OPA sensitivity-ceiling lookups, per-user rate-limit bucketing, and
tool-call routing — a full authentication-bypass-by-spoofing (CWE-290 /
ASVS V1.4.5 / OWASP A07:2021).

Fix: gate the boundary resolver's acceptance of X-Yashigani-Identity-Id on
the SAME trusted-transport proof mcp_router_runtime already requires
(X-Caddy-Verified-Secret validated OR the per-install internal mesh bearer).
Untrusted callers presenting the header are treated as anonymous (fail
closed — ysg_principal stays None) and a MeshIdentityHeaderRejectedEvent is
written to the tamper-evident audit chain (same event YSG-RISK-108 uses).

This test drives the REAL ``_proxy_request_body`` end to end (not a re-derived
mock of the logic) through to the point where it would dispatch the MCP call,
proving the identity actually used for adjudication.

Cross-ref: YSG-RISK-108, YSG-RISK-113, YSG-RISK-114 (same MCP-identity family).
"""
from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from yashigani.gateway.proxy import GatewayConfig, _proxy_request_body


_VICTIM_IID = "idnt_victim0001"


class _Headers:
    """Case-insensitive header lookup matching Starlette's Request.headers.get()."""

    def __init__(self, headers: dict[str, str]):
        self._h = {k.lower(): v for k, v in headers.items()}

    def get(self, key: str, default: str = "") -> str:
        return self._h.get(key.lower(), default)


class _FakeRequest:
    def __init__(
        self,
        headers: dict[str, str],
        path: str = "/mcp/victim-server",
        method: str = "POST",
        body: bytes = b'{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{}}',
    ):
        self.headers = _Headers(headers)
        self.url = SimpleNamespace(path=path)
        self.method = method
        self.client = SimpleNamespace(host="10.0.0.99")  # attacker on the data network
        self.cookies: dict[str, str] = {}
        self.state = SimpleNamespace()  # real attribute semantics — NOT MagicMock
        self._body = body

    async def body(self) -> bytes:
        return self._body


class _RecordingAuditWriter:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def write(self, event: Any) -> None:
        self.events.append(event)


def _identity_registry_with(iid: str, kind: str = "human") -> MagicMock:
    reg = MagicMock()
    reg.get.side_effect = lambda k: (
        {"kind": kind, "groups": []} if k == iid else None
    )
    return reg


def _permissive_rate_limiter() -> MagicMock:
    rl = MagicMock()
    rl.check.return_value = SimpleNamespace(allowed=True, remaining=999, retry_after_ms=0)
    return rl


def _base_state(identity_registry, audit_writer) -> dict:
    """Minimal state dict — every optional subsystem disabled so execution
    reaches the MCP dispatch call (step 4c) without a working OPA/Redis/etc.
    """
    return {
        "ddos_protector": None,
        "identity_registry": identity_registry,
        "rate_limiter": _permissive_rate_limiter(),
        "rbac_store": None,
        "audit_writer": audit_writer,
        "endpoint_rate_limiter": None,
        "jwt_inspector": None,
        "inspection_pipeline": None,
        "pii_detector": None,
        "response_cache": None,
        "mcp_broker_registry": MagicMock(),  # non-None -> step 4c dispatch path taken
        "response_inspection_pipeline": None,
        "agent_registry": None,
        "document_pipeline": None,
    }


@pytest.fixture(autouse=True)
def _stub_downstream(monkeypatch):
    """Stub OPA (always-allow) and capture what dispatch_mcp_call receives —
    the ONLY thing under test is what identity reaches MCP adjudication.
    """
    monkeypatch.setattr(
        "yashigani.gateway.proxy._opa_check", AsyncMock(return_value=True)
    )

    captured: dict[str, Any] = {}

    async def _fake_dispatch_mcp_call(agent_name, request, **kwargs):
        captured["ysg_principal"] = getattr(request.state, "ysg_principal", None)
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=200, content={"ok": True})

    monkeypatch.setattr(
        "yashigani.gateway.mcp_router_runtime.dispatch_mcp_call",
        _fake_dispatch_mcp_call,
    )
    yield captured


def _cfg() -> GatewayConfig:
    return GatewayConfig(upstream_base_url="https://upstream.internal", opa_url="https://policy:8181")


async def _drive(request: _FakeRequest, state: dict):
    return await _proxy_request_body(
        request=request,
        path=request.url.path,
        state=state,
        _tracer=None,
        _root_span=MagicMock(),
        request_id="req-140-test",
        cfg=_cfg(),
        audit_writer=state["audit_writer"],
        start=time.time(),
    )


# ---------------------------------------------------------------------------
# T-3 (YSG-RISK-140): untrusted caller spoofs X-Yashigani-Identity-Id
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ysg_risk_140_untrusted_header_spoof_is_rejected(_stub_downstream):
    """
    Exploit shape: a caller with NO X-Caddy-Verified-Secret and NO internal
    mesh bearer (e.g. reaching gateway:8081 directly on the data network)
    presents X-Yashigani-Identity-Id: idnt_victim0001 — an identity that DOES
    exist in the registry.

    FIX behaviour: the header MUST NOT be trusted absent proof of a trusted
    transport. request.state.ysg_principal must stay None (anonymous) by the
    time MCP dispatch runs, and a MeshIdentityHeaderRejectedEvent must be
    written to the audit chain.

    Pre-fix, this assertion FAILS: ysg_principal.identity_id == the spoofed
    victim id — i.e. the exploit reproduces (adjudication uses the spoofed
    header with zero transport binding).
    """
    audit_writer = _RecordingAuditWriter()
    identity_registry = _identity_registry_with(_VICTIM_IID)
    state = _base_state(identity_registry, audit_writer)

    request = _FakeRequest(
        headers={"X-Yashigani-Identity-Id": _VICTIM_IID},
        path="/mcp/victim-server",
    )

    resp = await _drive(request, state)

    assert resp.status_code == 200, f"dispatch should still succeed (anonymous): {resp}"

    captured_principal = _stub_downstream["ysg_principal"]
    assert captured_principal is None, (
        "YSG-RISK-140 REGRESSION: untrusted caller's spoofed "
        f"X-Yashigani-Identity-Id was trusted -> ysg_principal={captured_principal!r} "
        "instead of remaining anonymous (None)."
    )

    event_types = [type(e).__name__ for e in audit_writer.events]
    assert "MeshIdentityHeaderRejectedEvent" in event_types, (
        f"Expected MeshIdentityHeaderRejectedEvent audit event; got: {event_types}"
    )


@pytest.mark.asyncio
async def test_ysg_risk_140_no_header_no_audit_event(_stub_downstream):
    """Negative control: no identity header at all -> no rejection event, no principal."""
    audit_writer = _RecordingAuditWriter()
    identity_registry = _identity_registry_with(_VICTIM_IID)
    state = _base_state(identity_registry, audit_writer)

    request = _FakeRequest(headers={}, path="/mcp/victim-server")
    resp = await _drive(request, state)

    assert resp.status_code == 200
    assert _stub_downstream["ysg_principal"] is None
    event_types = [type(e).__name__ for e in audit_writer.events]
    assert "MeshIdentityHeaderRejectedEvent" not in event_types


# ---------------------------------------------------------------------------
# Positive paths — the fix must not break legitimate callers
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ysg_risk_140_caddy_verified_header_is_trusted(monkeypatch, _stub_downstream):
    """Legitimate public-edge path: caller presents a VALID X-Caddy-Verified-Secret
    (as Caddy always sets on every upstream reverse_proxy call) alongside the
    identity header -> the identity MUST resolve normally (no regression).
    """
    import yashigani.auth.caddy_verified as caddy_verified

    monkeypatch.setattr(caddy_verified, "_caddy_secret", "test-per-install-secret")

    audit_writer = _RecordingAuditWriter()
    identity_registry = _identity_registry_with(_VICTIM_IID)
    state = _base_state(identity_registry, audit_writer)

    request = _FakeRequest(
        headers={
            "X-Yashigani-Identity-Id": _VICTIM_IID,
            "X-Caddy-Verified-Secret": "test-per-install-secret",
        },
        path="/mcp/victim-server",
    )

    resp = await _drive(request, state)

    assert resp.status_code == 200
    captured_principal = _stub_downstream["ysg_principal"]
    assert captured_principal is not None
    assert captured_principal.identity_id == _VICTIM_IID
    event_types = [type(e).__name__ for e in audit_writer.events]
    assert "MeshIdentityHeaderRejectedEvent" not in event_types


@pytest.mark.asyncio
async def test_ysg_risk_140_internal_bearer_header_is_trusted(monkeypatch, _stub_downstream):
    """Legitimate mesh self-call path: caller presents the per-install internal
    mesh bearer alongside the identity header -> identity resolves normally.
    """
    from yashigani.gateway import proxy as proxy_mod

    monkeypatch.setattr(proxy_mod, "_INTERNAL_BEARER", "test-internal-bearer-32-chars!!")

    audit_writer = _RecordingAuditWriter()
    identity_registry = _identity_registry_with(_VICTIM_IID)
    state = _base_state(identity_registry, audit_writer)

    request = _FakeRequest(
        headers={
            "X-Yashigani-Identity-Id": _VICTIM_IID,
            "Authorization": "Bearer test-internal-bearer-32-chars!!",
        },
        path="/mcp/victim-server",
    )

    resp = await _drive(request, state)

    assert resp.status_code == 200
    captured_principal = _stub_downstream["ysg_principal"]
    assert captured_principal is not None
    assert captured_principal.identity_id == _VICTIM_IID
    event_types = [type(e).__name__ for e in audit_writer.events]
    assert "MeshIdentityHeaderRejectedEvent" not in event_types
