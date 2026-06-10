"""
#47 / G-NEW-5 / R3 — agent-router orchestration-principal signing (integration).

Exercises the full ``agent_router.route_agent_call`` path with the signed
orchestration-principal machinery wired into the gateway state:

  * FIRST hop (no inbound principal claim) → the immediate caller is the
    principal, OPA sees principal.verified == False, and the gateway SIGNS a
    fresh claim onto the forwarded request (bound to the TARGET SPIFFE);
  * RELAY hop (valid inbound claim bound to the presenting caller) → the
    verified upstream principal feeds OPA as principal.verified == True;
  * FORGED inbound claim (bound to a DIFFERENT SPIFFE) → 403, fail-closed,
    AGENT_CALL_DENIED reason principal_claim_unverifiable, NOT forwarded;
  * REPLAYED inbound claim (jti reused) → 403, fail-closed.

No live OPA / upstream — httpx is mocked.  Marked integration because it drives
the end-to-end router function.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from yashigani.gateway.agent_router import route_agent_call, _PRINCIPAL_HEADER
from yashigani.gateway.principal_token import (
    OrchestrationPrincipalSigner,
    OrchestrationPrincipalVerifier,
    caller_spiffe_uri,
)
from yashigani.mcp._nonce import InMemoryNonceStore


_TENANT = "default"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_registry(caller_agent_id: str) -> MagicMock:
    """Registry with the target 'agent-b' (has upstream) + the caller + the
    original orchestration principal 'agent-orig'."""
    registry = MagicMock()
    agents = {
        "agent-b": {
            "agent_id": "agent-b",
            "status": "active",
            "upstream_url": "http://fake-upstream:9999",
            "allowed_caller_groups": ["grp1"],
            "allowed_paths": ["**"],
            "groups": ["grp1"],
        },
        caller_agent_id: {
            "agent_id": caller_agent_id,
            "status": "active",
            "groups": ["grp1"],
        },
        "agent-orig": {
            "agent_id": "agent-orig",
            "status": "active",
            "groups": ["grp1"],
        },
    }
    registry.get = lambda agent_id: agents.get(agent_id)
    return registry


def _make_request(caller_agent_id: str, headers: dict | None = None) -> MagicMock:
    req = MagicMock()
    req.method = "POST"
    req.state = MagicMock()
    req.state.agent_id = caller_agent_id
    req.state.request_id = "req-g5-001"
    req.headers = headers or {}
    req.body = AsyncMock(return_value=b'{"hello":"world"}')
    return req


def _make_config() -> MagicMock:
    config = MagicMock()
    config.opa_url = "https://policy:8181"
    return config


def _opa_allow_cm():
    """OPA mock: agent_call_allowed → True; response_decision → allow."""
    async def _post(url, json=None, headers=None, **kwargs):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        if "agent_call_allowed" in url:
            resp.json = MagicMock(return_value={"result": True})
        else:
            resp.json = MagicMock(return_value={"result": {"allow": True, "reason": "ok"}})
        # Stash the principal input for assertions on the FIRST OPA call.
        if "agent_call_allowed" in url and json is not None:
            _opa_allow_cm.captured_principal = json.get("input", {}).get("principal")
        return resp

    client = AsyncMock()
    client.post = _post
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _upstream_cm():
    """httpx upstream mock; records the forwarded headers."""
    resp = MagicMock()
    resp.status_code = 200
    resp.content = b'{"ok":true}'
    resp.text = '{"ok":true}'
    _hdr = {"content-type": "application/json"}
    hm = MagicMock()
    hm.get = lambda k, d=None: _hdr.get(k, d)
    hm.items = lambda: _hdr.items()
    resp.headers = hm

    client = AsyncMock()

    async def _request(method, url, content=None, headers=None, **kw):
        _upstream_cm.captured_headers = headers or {}
        return resp

    client.request = _request

    class _CM:
        async def __aenter__(self):
            return client
        async def __aexit__(self, *a):
            return False

    return _CM()


def _state(registry, *, signer, verifier):
    return {
        "agent_registry": registry,
        "audit_writer": MagicMock(write=MagicMock()),
        "config": _make_config(),
        "principal_signer": signer,
        "principal_verifier": verifier,
        "principal_tenant_id": _TENANT,
    }


async def _allow_client_policies(cfg, scope_kind, scope_id, direction, base_input):
    """Pass-through for the orthogonal #16 client-policy gate (not under test).

    The client-policy aggregate gate needs a service manifest / identity that is
    not present in the unit-test environment; it is exercised by its own suite.
    Here we let it allow so the test isolates the principal-signing surface."""
    return {"allow": True, "deny": [], "obligations": []}


async def _run(req, state):
    with patch(
        "yashigani.gateway.agent_router.internal_httpx_client",
        return_value=_opa_allow_cm(),
    ):
        with patch(
            "yashigani.gateway.agent_router.evaluate_client_policies",
            new=_allow_client_policies,
        ):
            with patch("httpx.AsyncClient", return_value=_upstream_cm()):
                return await route_agent_call(req, "/agents/agent-b/do", state)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_first_hop_signs_principal_and_opa_sees_unverified():
    """No inbound claim → caller is principal (verified False), and a fresh
    signed claim is minted onto the forwarded request (bound to TARGET SPIFFE)."""
    s = OrchestrationPrincipalSigner(tenant_id=_TENANT)
    v = OrchestrationPrincipalVerifier.from_signer(s, nonce_store=InMemoryNonceStore())
    reg = _make_registry("agent-a")
    req = _make_request("agent-a")  # no principal header
    resp = await _run(req, _state(reg, signer=s, verifier=v))
    assert resp.status_code == 200, getattr(resp, "body", resp)
    # OPA saw the immediate caller as principal, unverified.
    principal = _opa_allow_cm.captured_principal
    assert principal["agent_id"] == "agent-a"
    assert principal["verified"] is False
    # A signed principal claim was forwarded, bound to the TARGET (agent-b) SPIFFE.
    fwd = _upstream_cm.captured_headers
    assert _PRINCIPAL_HEADER in fwd
    claim = v.verify(fwd[_PRINCIPAL_HEADER], presenting_spiffe=caller_spiffe_uri(_TENANT, "agent-b"))
    assert claim["principal_agent_id"] == "agent-a"


@pytest.mark.asyncio
async def test_relay_hop_verified_principal_feeds_opa():
    """A valid inbound claim (bound to the presenting caller agent-b) → the
    verified UPSTREAM principal (agent-orig) feeds OPA as verified True."""
    s = OrchestrationPrincipalSigner(tenant_id=_TENANT)
    v = OrchestrationPrincipalVerifier.from_signer(s, nonce_store=InMemoryNonceStore())
    reg = _make_registry("agent-relay")
    # Inbound claim: principal=agent-orig, bound to the PRESENTING caller agent-b.
    inbound = s.sign(
        principal_agent_id="agent-orig",
        caller_spiffe=caller_spiffe_uri(_TENANT, "agent-relay"),
        caller_groups=["grp1"],
    )
    req = _make_request("agent-relay", headers={_PRINCIPAL_HEADER.lower(): inbound})
    resp = await _run(req, _state(reg, signer=s, verifier=v))
    assert resp.status_code == 200, getattr(resp, "body", resp)
    principal = _opa_allow_cm.captured_principal
    assert principal["agent_id"] == "agent-orig"
    assert principal["verified"] is True


@pytest.mark.asyncio
async def test_forged_principal_bound_to_other_spiffe_rejected():
    """An inbound claim bound to a DIFFERENT SPIFFE than the presenting caller is
    a forge → 403 fail-closed, NOT forwarded."""
    s = OrchestrationPrincipalSigner(tenant_id=_TENANT)
    v = OrchestrationPrincipalVerifier.from_signer(s, nonce_store=InMemoryNonceStore())
    reg = _make_registry("agent-relay")
    # Claim bound to agent-z, but presented by agent-b (the authenticated caller).
    forged = s.sign(
        principal_agent_id="agent-admin",
        caller_spiffe=caller_spiffe_uri(_TENANT, "agent-z"),
    )
    req = _make_request("agent-relay", headers={_PRINCIPAL_HEADER.lower(): forged})
    _upstream_cm.captured_headers = {"sentinel": "not-forwarded"}
    resp = await _run(req, _state(reg, signer=s, verifier=v))
    assert resp.status_code == 403, getattr(resp, "body", resp)
    import json as _json
    body = _json.loads(bytes(resp.body))
    assert body["reason"] == "principal_claim_unverifiable"
    # The upstream was never called (no forward of a forged principal).
    assert _upstream_cm.captured_headers == {"sentinel": "not-forwarded"}


@pytest.mark.asyncio
async def test_replayed_principal_rejected():
    """Re-presenting the same signed claim (same jti) is a replay → 403."""
    s = OrchestrationPrincipalSigner(tenant_id=_TENANT)
    nonce = InMemoryNonceStore()
    v = OrchestrationPrincipalVerifier.from_signer(s, nonce_store=nonce)
    reg = _make_registry("agent-relay")
    inbound = s.sign(
        principal_agent_id="agent-orig",
        caller_spiffe=caller_spiffe_uri(_TENANT, "agent-relay"),
        caller_groups=["grp1"],
    )
    req1 = _make_request("agent-relay", headers={_PRINCIPAL_HEADER.lower(): inbound})
    r1 = await _run(req1, _state(reg, signer=s, verifier=v))
    assert r1.status_code == 200
    # Replay the SAME claim.
    req2 = _make_request("agent-relay", headers={_PRINCIPAL_HEADER.lower(): inbound})
    r2 = await _run(req2, _state(reg, signer=s, verifier=v))
    assert r2.status_code == 403, getattr(r2, "body", r2)
    import json as _json
    body = _json.loads(bytes(r2.body))
    assert body["reason"] == "principal_claim_unverifiable"
