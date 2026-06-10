"""
#47 / G-NEW-5 / R3 — signed orchestration-principal claim (unit tests).

The orchestration principal is no longer a TRUSTED header — it is an ES384-signed
claim bound to the caller's SPIFFE identity and replay-deduped by jti.  These
tests prove the security properties of the signer/verifier in isolation:

  * sign+verify round-trip yields the principal as a VERIFIED fact;
  * a claim bound to SPIFFE A is REJECTED when presented by SPIFFE B (forge);
  * a tampered signature is rejected;
  * a replayed jti is rejected (nonce dedup);
  * an expired claim is rejected;
  * a wrong-audience token (e.g. an MCP relay JWT) is rejected (audience pinning);
  * every failure mode fails CLOSED (raises PrincipalClaimError).
"""
from __future__ import annotations

import time

import pytest

from yashigani.gateway.principal_token import (
    OrchestrationPrincipalSigner,
    OrchestrationPrincipalVerifier,
    PrincipalClaimError,
    caller_spiffe_uri,
)
from yashigani.mcp._nonce import InMemoryNonceStore


_TENANT = "default"


def _signer() -> OrchestrationPrincipalSigner:
    return OrchestrationPrincipalSigner(tenant_id=_TENANT)


def _verifier(signer, *, nonce=None) -> OrchestrationPrincipalVerifier:
    return OrchestrationPrincipalVerifier.from_signer(signer, nonce_store=nonce)


def test_sign_verify_roundtrip_binds_principal_and_spiffe():
    s = _signer()
    v = _verifier(s)
    spiffe = caller_spiffe_uri(_TENANT, "agent-b")
    tok = s.sign(principal_agent_id="agent-a", caller_spiffe=spiffe, caller_groups=["g1"])
    claim = v.verify(tok, presenting_spiffe=spiffe)
    assert claim["principal_agent_id"] == "agent-a"
    assert claim["bound_spiffe"] == spiffe
    assert claim["groups"] == ["g1"]


def test_forge_rejected_when_presenting_spiffe_differs():
    """A claim issued FOR SPIFFE B cannot be presented BY SPIFFE C (forge close)."""
    s = _signer()
    v = _verifier(s)
    spiffe_b = caller_spiffe_uri(_TENANT, "agent-b")
    tok = s.sign(principal_agent_id="agent-a", caller_spiffe=spiffe_b)
    with pytest.raises(PrincipalClaimError):
        v.verify(tok, presenting_spiffe=caller_spiffe_uri(_TENANT, "agent-c"))


def test_tampered_signature_rejected():
    s = _signer()
    v = _verifier(s)
    spiffe = caller_spiffe_uri(_TENANT, "agent-b")
    tok = s.sign(principal_agent_id="agent-a", caller_spiffe=spiffe)
    # Flip a character in the signature segment.
    head, payload, sig = tok.split(".")
    bad = head + "." + payload + "." + ("A" if sig[0] != "A" else "B") + sig[1:]
    with pytest.raises(PrincipalClaimError):
        v.verify(bad, presenting_spiffe=spiffe)


def test_replay_rejected_by_nonce_store():
    s = _signer()
    nonce = InMemoryNonceStore()
    v = _verifier(s, nonce=nonce)
    spiffe = caller_spiffe_uri(_TENANT, "agent-b")
    tok = s.sign(principal_agent_id="agent-a", caller_spiffe=spiffe)
    # First use is accepted.
    v.verify(tok, presenting_spiffe=spiffe)
    # Replay of the SAME jti is rejected.
    with pytest.raises(PrincipalClaimError):
        v.verify(tok, presenting_spiffe=spiffe)


def test_expired_claim_rejected():
    """A claim whose exp is in the past (beyond the skew window) is rejected."""
    import jwt as _pyjwt

    s = _signer()
    v = _verifier(s)
    spiffe = caller_spiffe_uri(_TENANT, "agent-b")
    # Mint a token directly with the signer's key but an exp far in the PAST
    # (deterministic — no sleep).  Same claim shape as sign() produces.
    now = int(time.time())
    payload = {
        "iss": "https://gateway.yashigani.internal/default",
        "aud": "yashigani-orchestration-principal",
        "iat": now - 1000,
        "exp": now - 100,  # well past exp + 5s skew
        "jti": "expired-jti",
        "tenant": _TENANT,
        "principal_agent_id": "agent-a",
        "bound_spiffe": spiffe,
        "groups": [],
    }
    tok = _pyjwt.encode(
        payload, s._issuer._key, algorithm="ES384",
        headers={"kid": s.kid, "alg": "ES384"},
    )
    with pytest.raises(PrincipalClaimError):
        v.verify(tok, presenting_spiffe=spiffe)


def test_wrong_audience_token_rejected():
    """Audience pinning: a JWT signed with the SAME gateway key but a DIFFERENT
    audience (e.g. an MCP relay JWT, aud "yashigani-mcp-upstream") is NOT a valid
    orchestration-principal claim — claim-confusion is closed."""
    import jwt as _pyjwt

    s = _signer()
    v = _verifier(s)
    spiffe = caller_spiffe_uri(_TENANT, "agent-b")
    now = int(time.time())
    payload = {
        "iss": "https://gateway.yashigani.internal/default",
        "aud": "yashigani-mcp-upstream",  # wrong audience
        "iat": now,
        "exp": now + 30,
        "jti": "x",
        "tenant": _TENANT,
        "principal_agent_id": "agent-a",
        "bound_spiffe": spiffe,
        "groups": [],
    }
    tok = _pyjwt.encode(
        payload, s._issuer._key, algorithm="ES384",
        headers={"kid": s.kid, "alg": "ES384"},
    )
    with pytest.raises(PrincipalClaimError):
        v.verify(tok, presenting_spiffe=spiffe)


def test_empty_token_and_missing_presenting_spiffe_fail_closed():
    s = _signer()
    v = _verifier(s)
    spiffe = caller_spiffe_uri(_TENANT, "agent-b")
    tok = s.sign(principal_agent_id="agent-a", caller_spiffe=spiffe)
    with pytest.raises(PrincipalClaimError):
        v.verify("", presenting_spiffe=spiffe)
    with pytest.raises(PrincipalClaimError):
        v.verify(tok, presenting_spiffe="")


def test_sign_refuses_empty_principal_or_spiffe():
    s = _signer()
    with pytest.raises(PrincipalClaimError):
        s.sign(principal_agent_id="", caller_spiffe=caller_spiffe_uri(_TENANT, "b"))
    with pytest.raises(PrincipalClaimError):
        s.sign(principal_agent_id="a", caller_spiffe="")
