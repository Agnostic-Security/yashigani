"""
Yashigani Gateway — signed orchestration-principal claim (G-NEW-5 / R3).

#47 MCP-surface hardening, item #1.

THE PROBLEM (confused-deputy surface)
-------------------------------------
On the internal agent-to-agent path the orchestration principal (the asserting
caller identity that feeds OPA) was propagated as a **trusted header**
(``X-Yashigani-Caller-Agent-Id``, forwarded plaintext by the gateway in
``agent_router.route_agent_call``).  A downstream entity that can reach an
upstream agent directly — or replay a captured request — could FORGE or REPLAY
another principal: the header was asserted, not proven.  OPA then adjudicated on
an *asserted* fact.

THE FIX (signed, SPIFFE-bound, replay-proof claim)
--------------------------------------------------
The GATEWAY is the asserting authority.  It SIGNS the principal claim
(ES384 / ECDSA P-384, the SAME crypto + SAME signing key the MCP broker uses —
``/run/secrets/mcp_identity_signing_key`` / ``YASHIGANI_MCP_SIGNING_KEY_PEM`` —
we do NOT invent a new key path) and BINDS it to the SPIFFE identity of the real
caller workload.  Every downstream hop:

  1. verifies the signature against the gateway JWKS (kid-selected), and
  2. binds the claim to the SPIFFE identity of the PRESENTING workload — a hop
     cannot present a principal claim that was issued for a different SPIFFE
     identity (no forge / no cross-binding), and
  3. rejects a replay via the shared jti nonce store (the SAME store the MCP
     broker uses for relay-JWT dedup).

Fail-closed: a missing / malformed / expired / wrong-audience / bad-signature /
SPIFFE-mismatch / replayed principal is REJECTED (no silent trust), an audit
event is emitted, and the principal feeds OPA as a *verified* fact — never as an
asserted one.

WHY A DEDICATED CLAIM (not the MCP relay JWT)
---------------------------------------------
The MCP relay JWT (``mcp/_jwt.py``) carries an MCP-specific claim shape
(posture, tool action, identity.chain, audience ``yashigani-mcp-upstream``).
The orchestration principal is a smaller, agent-path concept (the asserting
principal_agent_id bound to a caller SPIFFE).  This module reuses the MCP
broker's loaded ES384 KEY (via ``McpJwtIssuer`` — composition, no MCP-broker
change) and the shared ``NonceStore``, but signs its own audience
(``yashigani-orchestration-principal``) and claim shape so the two artefact
types can never be confused for one another (audience pinning).

References
----------
- G-NEW-5 / R3 (#47 MCP-surface hardening).
- Reuses: mcp/_jwt.py (ES384 key load + FIPS guard), mcp/_nonce.py (jti dedup).
- Every-hop OPA adjudication: gateway/agent_router.py (principal -> input).
"""
from __future__ import annotations

import logging
import time
import uuid
from typing import Optional

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from yashigani.identity.trust_domain import agent_spiffe_uri, gateway_issuer_prefix
from yashigani.mcp._jwt import McpJwtIssuer
from yashigani.mcp._nonce import NonceStore

logger = logging.getLogger(__name__)

# Locked constants — mirror the MCP relay JWT crypto (Nico spec §1/§3) so the
# same FIPS-validated primitives are in force on this path too.
_ALGORITHM = "ES384"
#: Distinct audience so an orchestration-principal claim can NEVER be replayed as
#: an MCP relay JWT (or vice versa) — audience pinning closes claim confusion.
_AUDIENCE = "yashigani-orchestration-principal"
#: Short TTL — the principal claim is single-hop and re-minted at the gateway on
#: every forward, so it does not need to live long.  jti dedup closes replay
#: WITHIN this window; the short window bounds the residual.
_TTL_SECONDS = 30
_CLOCK_SKEW_SECONDS = 5
#: Gateway issuer prefix — derived from the instance trust domain (MI-6 /
#: YSG-RISK-061) via ``gateway_issuer_prefix()`` at each call site below, so a
#: non-legacy instance mints AND accepts only its own
#: ``https://gateway.<project>.yashigani.internal/`` issuer and rejects a foreign
#: (incl. legacy) issuer.  Resolved per-call, never frozen at import time.


class PrincipalClaimError(Exception):
    """The presented orchestration-principal claim is missing, malformed,
    expired, wrong-audience, badly-signed, SPIFFE-mismatched, or replayed.

    The caller MUST treat this as a hard deny (fail-closed) — never trust an
    unverifiable principal."""


def caller_spiffe_uri(tenant_id: str, agent_id: str) -> str:
    """Deterministic SPIFFE URI for an agent caller.

    Mirrors the canonical agent identity format used across the codebase
    (``pool/manager.py``, ``manifest/codegen.py``):
    ``spiffe://<trust_domain>/agents/{tenant_id}/{agent_name}``.  This is the
    'real caller's SPIFFE identity' the principal claim is bound to.  The trust
    domain is per-instance (MI-6 / YSG-RISK-061), so on a non-legacy instance the
    binding uses ``<project>.yashigani.internal`` and matches that instance's own
    cert SAN."""
    return agent_spiffe_uri(tenant_id, agent_id)


class OrchestrationPrincipalSigner:
    """Signs orchestration-principal claims (gateway = asserting authority).

    Reuses the MCP broker's loaded ES384 signing key + kid (composition over
    ``McpJwtIssuer`` — NO change to the MCP broker; the SAME key file / env var /
    FIPS guard / prod-fail-closed behaviour applies verbatim).
    """

    def __init__(
        self,
        tenant_id: str,
        *,
        issuer: Optional[McpJwtIssuer] = None,
        ttl_seconds: int = _TTL_SECONDS,
    ) -> None:
        # Build (or reuse) an McpJwtIssuer purely to obtain the SAME loaded key +
        # kid the broker uses.  Its startup self-test also runs — a key/FIPS
        # misconfiguration fails CLOSED here, at construction, not at request time.
        self._issuer = issuer or McpJwtIssuer(tenant_id=tenant_id)
        self._tenant_id = tenant_id
        self._ttl = ttl_seconds

    @property
    def kid(self) -> str:
        return self._issuer.kid

    @property
    def public_key(self) -> EllipticCurvePublicKey:
        return self._issuer._public_key

    def public_key_jwk(self) -> dict:
        """JWK for JWKS publication (delegates to the shared issuer)."""
        return self._issuer.public_key_jwk()

    def sign(
        self,
        *,
        principal_agent_id: str,
        caller_spiffe: str,
        caller_groups: Optional[list[str]] = None,
    ) -> str:
        """Sign an orchestration-principal claim bound to ``caller_spiffe``.

        Parameters
        ----------
        principal_agent_id:
            The orchestration principal's agent id (the asserting caller).
        caller_spiffe:
            The SPIFFE URI of the real caller workload the claim is BOUND to.
            A downstream hop must present this exact SPIFFE identity to use the
            claim (no forge / no cross-binding).
        caller_groups:
            RBAC group ids carried as a convenience for OPA (the verified fact);
            authority still derives from the registry at adjudication time.
        """
        if not principal_agent_id:
            raise PrincipalClaimError("cannot sign an empty principal_agent_id")
        if not caller_spiffe:
            raise PrincipalClaimError("cannot sign a principal with no caller SPIFFE binding")
        iat = int(time.time())
        payload = {
            "iss": f"{gateway_issuer_prefix()}{self._tenant_id}",
            "aud": _AUDIENCE,
            "iat": iat,
            "exp": iat + self._ttl,
            "jti": str(uuid.uuid4()),
            "tenant": self._tenant_id,
            # The asserting orchestration principal.
            "principal_agent_id": principal_agent_id,
            # The SPIFFE identity the claim is BOUND to (verified at each hop).
            "bound_spiffe": caller_spiffe,
            "groups": list(caller_groups or []),
        }
        token = pyjwt.encode(
            payload,
            self._issuer._key,
            algorithm=_ALGORITHM,
            headers={"kid": self.kid, "alg": _ALGORITHM},
        )
        logger.debug(
            "orchestration-principal: signed claim jti=%s principal=%s bound_spiffe=%s",
            payload["jti"], principal_agent_id, caller_spiffe,
        )
        return token


class OrchestrationPrincipalVerifier:
    """Verifies orchestration-principal claims and binds them to the presenting
    workload's SPIFFE identity (G-NEW-5 / R3).

    Fail-closed on EVERY failure mode (raises :class:`PrincipalClaimError`):
    missing / malformed / wrong-alg / wrong-audience / bad-signature / expired /
    wrong-issuer / SPIFFE-mismatch / replayed.  Never returns an unverified
    principal.
    """

    def __init__(
        self,
        kid_to_key: dict[str, EllipticCurvePublicKey],
        *,
        nonce_store: Optional[NonceStore] = None,
        tenant_id: str = "default",
        skew_tolerance: float = _CLOCK_SKEW_SECONDS,
    ) -> None:
        self._kid_map = dict(kid_to_key)
        self._nonce = nonce_store
        self._tenant_id = tenant_id
        self._skew = skew_tolerance

    @classmethod
    def from_signer(
        cls,
        signer: OrchestrationPrincipalSigner,
        *,
        nonce_store: Optional[NonceStore] = None,
    ) -> "OrchestrationPrincipalVerifier":
        """Co-located verifier (same-process gateway): trust the signer's key."""
        return cls(
            {signer.kid: signer.public_key},
            nonce_store=nonce_store,
            tenant_id=signer._tenant_id,
        )

    def verify(self, token: str, *, presenting_spiffe: str) -> dict:
        """Verify a signed principal claim AND bind it to ``presenting_spiffe``.

        ``presenting_spiffe`` is the SPIFFE identity of the workload presenting
        the claim on THIS hop (the authenticated caller).  The claim's
        ``bound_spiffe`` MUST equal it — a hop cannot present a principal claim
        issued for a DIFFERENT SPIFFE identity.

        Returns the verified claim payload on success.  Raises
        :class:`PrincipalClaimError` (fail-closed) on ANY failure.
        """
        if not token:
            raise PrincipalClaimError("no orchestration-principal claim presented")
        if not presenting_spiffe:
            # We cannot bind the claim to a workload identity → cannot trust it.
            raise PrincipalClaimError(
                "no presenting SPIFFE identity to bind the principal claim to"
            )

        try:
            header = pyjwt.get_unverified_header(token)
        except pyjwt.PyJWTError as exc:
            raise PrincipalClaimError(f"malformed principal claim header: {exc}") from exc

        if header.get("alg") != _ALGORITHM:
            raise PrincipalClaimError(
                f"principal claim alg must be {_ALGORITHM}; got {header.get('alg')!r}"
            )

        kid = header.get("kid")
        keys_to_try: list[EllipticCurvePublicKey]
        if kid and kid in self._kid_map:
            keys_to_try = [self._kid_map[kid]]
        else:
            # Rotation overlap: try all known keys.
            keys_to_try = list(self._kid_map.values())
        if not keys_to_try:
            raise PrincipalClaimError("no verification key available for principal claim")

        last_exc: Exception = PrincipalClaimError("signature verification failed")
        payload: Optional[dict] = None
        for pubkey in keys_to_try:
            try:
                payload = pyjwt.decode(
                    token,
                    pubkey,
                    algorithms=[_ALGORITHM],
                    audience=_AUDIENCE,
                    leeway=self._skew,
                )
                break
            except pyjwt.PyJWTError as exc:
                last_exc = exc
                continue
        if payload is None:
            raise PrincipalClaimError(f"principal claim verification failed: {last_exc}")

        # Issuer prefix check (belt-and-suspenders — decode already validated aud).
        # Per-instance trust domain (MI-6): a foreign-issuer claim (incl. legacy
        # ``yashigani.internal`` on a non-legacy instance) is rejected here.
        iss = payload.get("iss", "")
        if not iss.startswith(gateway_issuer_prefix()):
            raise PrincipalClaimError(f"principal claim iss={iss!r} not a gateway issuer")

        # SPIFFE binding: the claim must have been issued FOR the presenting
        # workload (no forge / no cross-binding).
        bound = payload.get("bound_spiffe", "")
        if not bound or bound != presenting_spiffe:
            raise PrincipalClaimError(
                "principal claim bound_spiffe does not match the presenting "
                "workload — forge/cross-binding rejected (fail-closed)"
            )

        principal_agent_id = payload.get("principal_agent_id", "")
        if not principal_agent_id:
            raise PrincipalClaimError("principal claim carries no principal_agent_id")

        # Replay dedup (jti nonce store — the SAME store the MCP broker uses).
        jti = payload.get("jti", "")
        if not jti:
            raise PrincipalClaimError("principal claim carries no jti — cannot dedup")
        if self._nonce is not None:
            exp = float(payload.get("exp", time.time()))
            try:
                is_new = self._nonce.check_and_record(jti, exp, self._tenant_id)
            except Exception as exc:  # NonceStoreError -> fail-closed (SOP 1)
                raise PrincipalClaimError(
                    f"principal-claim nonce store failure — fail-closed: {exc}"
                ) from exc
            if not is_new:
                raise PrincipalClaimError(
                    "principal claim jti replayed — rejected (fail-closed)"
                )

        logger.debug(
            "orchestration-principal: verified claim jti=%s principal=%s bound_spiffe=%s",
            jti, principal_agent_id, bound,
        )
        return payload


def build_principal_machinery(
    tenant_id: str = "default",
) -> tuple[OrchestrationPrincipalSigner, OrchestrationPrincipalVerifier]:
    """Build a co-located signer + verifier sharing the gateway's ES384 key and
    the shared jti nonce store (G-NEW-5 / R3).

    Reuses the SAME key path the MCP broker uses (via ``McpJwtIssuer``) and the
    SAME ``NonceStore`` wiring (RedisNonceStore when ``REDIS_URL`` is set, else
    InMemoryNonceStore for dev) — we do NOT invent a new key path or a new nonce
    store.  Fail-closed: a key/FIPS misconfiguration (or a missing persistent key
    in production/staging) raises here at startup, not at request time.
    """
    import os

    signer = OrchestrationPrincipalSigner(tenant_id=tenant_id)

    nonce_store: Optional[NonceStore] = None
    redis_url = os.environ.get("REDIS_URL", "").strip()
    if redis_url:
        try:
            import redis  # type: ignore[import-untyped]
            from yashigani.mcp._nonce import RedisNonceStore
            nonce_store = RedisNonceStore(
                redis.from_url(redis_url, decode_responses=False)
            )
            logger.info(
                "orchestration-principal: RedisNonceStore wired for replay "
                "prevention (multi-replica safe)"
            )
        except ImportError as exc:
            raise RuntimeError(
                "REDIS_URL is set but the 'redis' package is not installed — "
                "cannot wire the orchestration-principal replay store."
            ) from exc
        except Exception as exc:
            raise RuntimeError(
                f"Failed to construct the orchestration-principal nonce store: {exc}"
            ) from exc
    else:
        from yashigani.mcp._nonce import InMemoryNonceStore
        nonce_store = InMemoryNonceStore()

    verifier = OrchestrationPrincipalVerifier.from_signer(
        signer, nonce_store=nonce_store
    )
    return signer, verifier


__all__ = [
    "PrincipalClaimError",
    "OrchestrationPrincipalSigner",
    "OrchestrationPrincipalVerifier",
    "build_principal_machinery",
    "caller_spiffe_uri",
]
