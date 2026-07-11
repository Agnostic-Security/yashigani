"""
I6 — Signed orchestration principal: verified claim only; forge/replay rejected.

INVARIANT (must ALWAYS hold): an orchestration-principal claim is trusted ONLY
when it is (a) signed by the gateway's ES384 key, (b) audience-pinned to the
orchestration-principal audience, (c) SPIFFE-bound to the presenting workload, and
(d) not replayed (jti dedup). A forged / wrong-audience / wrong-signer /
cross-bound / replayed / expired claim is REJECTED fail-closed — the verifier
NEVER returns an unverified principal.

Why an invariant: this closes the confused-deputy header-forgery seam (a relay
forging an upstream principal, or replaying a captured one). It is the trust
anchor for every orchestration hop. If any rejection path weakens, an attacker can
assert a principal they are not.

Asserted here: sign→verify round-trip succeeds; each tamper class raises
PrincipalClaimError. Uses an explicit in-process ES384 key + in-memory nonce store
(no live stack).

LIVE-PROOF (#44): a live forged/replayed claim presented over the wire to an
orchestration hop is the VM probe; here we prove the verifier contract.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from yashigani.gateway.principal_token import (
    OrchestrationPrincipalSigner,
    OrchestrationPrincipalVerifier,
    PrincipalClaimError,
)
from yashigani.mcp._jwt import McpJwtIssuer
from yashigani.mcp._nonce import InMemoryNonceStore

TENANT = "tenant-a"
SPIFFE = "spiffe://yashigani.internal/agents/tenant-a/orchestrator"
PRINCIPAL = "orchestrator"


def _machinery():
    """Co-located signer+verifier sharing one ES384 key + an in-memory nonce store
    (the production wiring, minus the KMS/file key source)."""
    key = ec.generate_private_key(ec.SECP384R1())
    issuer = McpJwtIssuer(tenant_id=TENANT, private_key=key)
    signer = OrchestrationPrincipalSigner(tenant_id=TENANT, issuer=issuer)
    nonce = InMemoryNonceStore()
    verifier = OrchestrationPrincipalVerifier.from_signer(signer, nonce_store=nonce)
    return signer, verifier


def test_valid_claim_round_trips() -> None:
    signer, verifier = _machinery()
    token = signer.sign(principal_agent_id=PRINCIPAL, caller_spiffe=SPIFFE)
    payload = verifier.verify(token, presenting_spiffe=SPIFFE)
    assert payload["principal_agent_id"] == PRINCIPAL
    assert payload["bound_spiffe"] == SPIFFE


def test_replayed_claim_rejected() -> None:
    """The same jti presented twice ⇒ rejected fail-closed (replay defence)."""
    signer, verifier = _machinery()
    token = signer.sign(principal_agent_id=PRINCIPAL, caller_spiffe=SPIFFE)
    verifier.verify(token, presenting_spiffe=SPIFFE)
    with pytest.raises(PrincipalClaimError):
        verifier.verify(token, presenting_spiffe=SPIFFE)


def test_spiffe_cross_binding_rejected() -> None:
    """A claim bound to SPIFFE A presented by workload B ⇒ rejected (no forge)."""
    signer, verifier = _machinery()
    token = signer.sign(principal_agent_id=PRINCIPAL, caller_spiffe=SPIFFE)
    other = "spiffe://yashigani.internal/agents/tenant-a/attacker"
    with pytest.raises(PrincipalClaimError):
        verifier.verify(token, presenting_spiffe=other)


def test_foreign_signer_rejected() -> None:
    """A claim signed by a DIFFERENT key (forged signer) ⇒ rejected fail-closed."""
    signer_a, _ = _machinery()
    token = signer_a.sign(principal_agent_id=PRINCIPAL, caller_spiffe=SPIFFE)
    # An independent verifier that does NOT know signer_a's key.
    _, verifier_b = _machinery()
    with pytest.raises(PrincipalClaimError):
        verifier_b.verify(token, presenting_spiffe=SPIFFE)


def test_missing_token_rejected() -> None:
    _, verifier = _machinery()
    with pytest.raises(PrincipalClaimError):
        verifier.verify("", presenting_spiffe=SPIFFE)


def test_missing_presenting_spiffe_rejected() -> None:
    """No presenting SPIFFE ⇒ cannot bind ⇒ cannot trust ⇒ reject."""
    signer, verifier = _machinery()
    token = signer.sign(principal_agent_id=PRINCIPAL, caller_spiffe=SPIFFE)
    with pytest.raises(PrincipalClaimError):
        verifier.verify(token, presenting_spiffe="")


def test_tampered_token_rejected() -> None:
    """A bit-flipped token body ⇒ signature fails ⇒ rejected fail-closed."""
    signer, verifier = _machinery()
    token = signer.sign(principal_agent_id=PRINCIPAL, caller_spiffe=SPIFFE)
    h, p, s = token.split(".")
    # mutate one char of the payload segment
    tampered = ".".join([h, p[:-2] + ("A" if p[-2] != "A" else "B") + p[-1], s])
    with pytest.raises(PrincipalClaimError):
        verifier.verify(tampered, presenting_spiffe=SPIFFE)


def test_signer_refuses_empty_binding() -> None:
    """The signer will not mint a claim with no SPIFFE binding (no unbound
    principal can ever be created)."""
    signer, _ = _machinery()
    with pytest.raises(PrincipalClaimError):
        signer.sign(principal_agent_id=PRINCIPAL, caller_spiffe="")
    with pytest.raises(PrincipalClaimError):
        signer.sign(principal_agent_id="", caller_spiffe=SPIFFE)
