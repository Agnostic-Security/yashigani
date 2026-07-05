# Last updated: 2026-07-06T00:00:00+00:00
"""
Unit tests — /auth/verify-mcp forward-auth gate (v4.1 Phase 1c, Task A).

The per-MCP Caddy-front wrap (codegen `_gen_caddy_snippet_mcp`) forward_auths
every mesh request to this endpoint.  Contract under test:

  * ALLOW: gateway mesh transport identity (spiffe://<td>/gateway).
  * ALLOW: registered per-instance agent identity (Nico's contract
    spiffe://<td>/agents/<tenant>/<name>/<nhi_id>) with svid_issued and an
    exact registry SPIFFE match, targeting an onboarded server.
  * DENY (fail-closed): missing subject header, foreign trust domain, legacy
    2-segment URI, cross-tenant subject, unknown NHI, svid not issued,
    registry SPIFFE mismatch, un-onboarded server, registry/envelope store
    unavailable, malformed route params.
  * Every DENY writes MCP_INGRESS_DENIED to the audit chain.

Spoofing note: x-spiffe-id reaching the route is Caddy-set by construction
(CaddyVerifiedMiddleware + SpiffePeerCertMiddleware Option C) — middleware
behaviour is covered by the existing EX-231-10 suites; these tests exercise
the route-level authorisation on the already-laundered header.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request

from yashigani.audit.schema import EventType

_TD = "yashigani.internal"  # legacy default trust domain (env unset in tests)
_TENANT = "default"
_SERVER = "cloud9-demo"
_NHI = "nhi_0123456789ab"
_AGENT_SPIFFE = f"spiffe://{_TD}/agents/{_TENANT}/letta/{_NHI}"
_GATEWAY_SPIFFE = f"spiffe://{_TD}/gateway"


def _mock_request(spiffe: str | None) -> MagicMock:
    req = MagicMock(spec=Request)
    headers = {}
    if spiffe is not None:
        headers["x-spiffe-id"] = spiffe
    req.headers = headers
    return req


def _mock_state(nhi: dict | None = None, registry_none: bool = False) -> MagicMock:
    state = MagicMock()
    state.audit_writer = MagicMock()
    if registry_none:
        state.agent_registry = None
    else:
        state.agent_registry = MagicMock()
        state.agent_registry.get = MagicMock(return_value=nhi)
    return state


def _nhi_record(spiffe: str = _AGENT_SPIFFE, svid_issued: bool = True) -> dict:
    return {
        "kind": "nhi",
        "svid_issued": svid_issued,
        "spiffe_id": spiffe,
        "status": "active",
    }


def _envelope_svc(rec: object | None = ..., raises: bool = False) -> MagicMock:
    svc = MagicMock()
    if raises:
        svc.get_active_envelope = AsyncMock(side_effect=RuntimeError("db down"))
    else:
        if rec is ...:
            rec = MagicMock()
            rec.tenant_id = _TENANT
            rec.id = 42
        svc.get_active_envelope = AsyncMock(return_value=rec)
    return svc


async def _call(spiffe, state, svc, tenant=_TENANT, server=_SERVER):
    from yashigani.backoffice.routes import auth as _auth_mod

    with patch.object(_auth_mod, "backoffice_state", state), \
         patch.object(_auth_mod, "_verify_mcp_envelope_service", return_value=svc):
        return await _auth_mod.verify_mcp_ingress(
            _mock_request(spiffe), tenant=tenant, server=server,
        )


def _assert_denied(exc_info, status_code: int, reason: str, state) -> None:
    assert exc_info.value.status_code == status_code
    assert exc_info.value.detail == {"error": reason}
    # MCP_INGRESS_DENIED must be on the audit chain.
    events = [c.args[0] for c in state.audit_writer.write.call_args_list]
    assert any(
        e.event_type == EventType.MCP_INGRESS_DENIED and e.reason == reason
        for e in events
    ), f"no MCP_INGRESS_DENIED({reason}) audit event written"


# ---------------------------------------------------------------------------
# ALLOW paths
# ---------------------------------------------------------------------------

class TestVerifyMcpAllows:
    @pytest.mark.asyncio
    async def test_gateway_transport_identity_allowed(self):
        state = _mock_state()
        resp = await _call(_GATEWAY_SPIFFE, state, _envelope_svc())
        assert resp.status_code == 200
        assert resp.headers["X-Yashigani-Mcp-Caller"] == _GATEWAY_SPIFFE

    @pytest.mark.asyncio
    async def test_registered_per_instance_agent_allowed(self):
        state = _mock_state(nhi=_nhi_record())
        resp = await _call(_AGENT_SPIFFE, state, _envelope_svc())
        assert resp.status_code == 200
        assert resp.headers["X-Yashigani-Mcp-Caller"] == _AGENT_SPIFFE
        assert resp.headers["X-Yashigani-Mcp-Envelope"] == "42"
        state.agent_registry.get.assert_called_once_with(_NHI)


# ---------------------------------------------------------------------------
# DENY paths (fail-closed + audited)
# ---------------------------------------------------------------------------

class TestVerifyMcpDenies:
    @pytest.mark.asyncio
    async def test_missing_subject_header_401(self):
        state = _mock_state()
        with pytest.raises(HTTPException) as exc_info:
            await _call(None, state, _envelope_svc())
        _assert_denied(exc_info, 401, "no_spiffe_id", state)

    @pytest.mark.asyncio
    async def test_empty_subject_header_401(self):
        state = _mock_state()
        with pytest.raises(HTTPException) as exc_info:
            await _call("   ", state, _envelope_svc())
        _assert_denied(exc_info, 401, "no_spiffe_id", state)

    @pytest.mark.asyncio
    async def test_foreign_trust_domain_403(self):
        state = _mock_state(nhi=_nhi_record())
        with pytest.raises(HTTPException) as exc_info:
            await _call(
                f"spiffe://evil.example/agents/{_TENANT}/letta/{_NHI}",
                state, _envelope_svc(),
            )
        _assert_denied(exc_info, 403, "foreign_identity", state)

    @pytest.mark.asyncio
    async def test_non_agent_namespace_403(self):
        state = _mock_state()
        with pytest.raises(HTTPException) as exc_info:
            await _call(f"spiffe://{_TD}/prometheus", state, _envelope_svc())
        _assert_denied(exc_info, 403, "foreign_identity", state)

    @pytest.mark.asyncio
    async def test_legacy_two_segment_uri_403(self):
        """Per-instance identity is REQUIRED at the wrap (GAP-1)."""
        state = _mock_state(nhi=_nhi_record())
        with pytest.raises(HTTPException) as exc_info:
            await _call(
                f"spiffe://{_TD}/agents/{_TENANT}/letta", state, _envelope_svc(),
            )
        _assert_denied(exc_info, 403, "legacy_identity", state)

    @pytest.mark.asyncio
    async def test_cross_tenant_subject_403(self):
        state = _mock_state(nhi=_nhi_record())
        with pytest.raises(HTTPException) as exc_info:
            await _call(
                f"spiffe://{_TD}/agents/other-tenant/letta/{_NHI}",
                state, _envelope_svc(),
            )
        _assert_denied(exc_info, 403, "cross_tenant", state)

    @pytest.mark.asyncio
    async def test_unknown_nhi_403(self):
        state = _mock_state(nhi=None)
        with pytest.raises(HTTPException) as exc_info:
            await _call(_AGENT_SPIFFE, state, _envelope_svc())
        _assert_denied(exc_info, 403, "nhi_not_found", state)

    @pytest.mark.asyncio
    async def test_svid_not_issued_403(self):
        """Pending-approval NHIs must not reach the MCP (fail-closed)."""
        state = _mock_state(nhi=_nhi_record(svid_issued=False))
        with pytest.raises(HTTPException) as exc_info:
            await _call(_AGENT_SPIFFE, state, _envelope_svc())
        _assert_denied(exc_info, 403, "nhi_not_approved", state)

    @pytest.mark.asyncio
    async def test_registry_spiffe_mismatch_403(self):
        """A valid mesh cert for a DIFFERENT instance must not authorise."""
        other = f"spiffe://{_TD}/agents/{_TENANT}/letta/nhi_ffffffffffff"
        state = _mock_state(nhi=_nhi_record(spiffe=other))
        with pytest.raises(HTTPException) as exc_info:
            await _call(_AGENT_SPIFFE, state, _envelope_svc())
        _assert_denied(exc_info, 403, "spiffe_mismatch", state)

    @pytest.mark.asyncio
    async def test_registry_unavailable_503(self):
        state = _mock_state(registry_none=True)
        with pytest.raises(HTTPException) as exc_info:
            await _call(_AGENT_SPIFFE, state, _envelope_svc())
        _assert_denied(exc_info, 503, "registry_unavailable", state)

    @pytest.mark.asyncio
    async def test_server_not_onboarded_403(self):
        state = _mock_state()
        with pytest.raises(HTTPException) as exc_info:
            await _call(_GATEWAY_SPIFFE, state, _envelope_svc(rec=None))
        _assert_denied(exc_info, 403, "server_not_onboarded", state)

    @pytest.mark.asyncio
    async def test_envelope_tenant_mismatch_403(self):
        """An active envelope under a DIFFERENT tenant must not authorise."""
        rec = MagicMock()
        rec.tenant_id = "other-tenant"
        rec.id = 7
        state = _mock_state()
        with pytest.raises(HTTPException) as exc_info:
            await _call(_GATEWAY_SPIFFE, state, _envelope_svc(rec=rec))
        _assert_denied(exc_info, 403, "server_not_onboarded", state)

    @pytest.mark.asyncio
    async def test_envelope_store_down_503(self):
        state = _mock_state()
        with pytest.raises(HTTPException) as exc_info:
            await _call(_GATEWAY_SPIFFE, state, _envelope_svc(raises=True))
        _assert_denied(exc_info, 503, "envelope_store_unavailable", state)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tenant,server", [
        ("", _SERVER), (_TENANT, ""), ("../etc", _SERVER),
        (_TENANT, "a b"), ("t" * 64, _SERVER),
    ])
    async def test_malformed_route_params_403(self, tenant, server):
        state = _mock_state()
        with pytest.raises(HTTPException) as exc_info:
            await _call(_GATEWAY_SPIFFE, state, _envelope_svc(),
                        tenant=tenant, server=server)
        _assert_denied(exc_info, 403, "invalid_target", state)

    @pytest.mark.asyncio
    async def test_spoofed_header_for_unregistered_instance_denied(self):
        """The forge shape: attacker-controlled x-spiffe-id naming a
        plausible but unregistered instance is denied (registry is the
        corroboration anchor, not the header)."""
        state = _mock_state(nhi=None)
        with pytest.raises(HTTPException) as exc_info:
            await _call(
                f"spiffe://{_TD}/agents/{_TENANT}/ghost/nhi_deadbeef0000",
                state, _envelope_svc(),
            )
        _assert_denied(exc_info, 403, "nhi_not_found", state)
