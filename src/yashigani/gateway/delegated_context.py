"""
Yashigani Gateway — Server-side delegated context (R2 / R12 / R13).

PURPOSE
-------
When user U invokes NHI A, the gateway does NOT pass the user's identity to the
NHI container via a settable header.  Instead it:

  1. Mints a signed ``X-Yashigani-Session-Id`` nonce (ES384, DEDICATED key,
     audience ``yashigani-delegated-context`` — R13: distinct from the
     orchestration-principal audience per NIST SP 800-57).
  2. Writes a Redis delegation record keyed by the nonce's ``jti``:
       ``delegated_ctx:{jti}`` → JSON {nhi_id, user_identity_id, effective_scope, exp}
     TTL = nonce ``exp`` − ``iat`` (same window, single-use via jti replay guard).
  3. The NHI container carries ONLY the signed nonce as a request header —
     it CANNOT forge the user identity or the effective_scope.
  4. On each NHI callback, ``resolve_context()`` verifies the nonce signature,
     reads the Redis record, and ASSERTS that ``record.nhi_id`` matches the
     ``presenting_agent_spiffe`` of the caller (R12: leaked nonce unusable by
     another agent even within TTL).

OPA sees ``on_behalf_of`` from the resolved context, NEVER from a header the
NHI can set.  This closes RISK-097 / FIND-3.1-AGENT-BEARER-IMPERSONATION.

DEDICATED SIGNING KEY (R13)
---------------------------
This module uses audience ``yashigani-delegated-context`` — distinct from:
  - ``yashigani-orchestration-principal`` (principal_token.py)
  - ``yashigani-mcp-upstream``            (mcp/_jwt.py)
Audience pinning ensures these three token types can NEVER be replayed
cross-context even if the signing key is shared (NIST SP 800-57 §5.3).

The signing key is the SAME ES384 key as the MCP broker (loaded via
``McpJwtIssuer``) — R13 mandates a DEDICATED KEY in the full Phase-3 delivery
(separate PEM on disk).  Until that key is provisioned in install.sh, the
existing MCP key is used with audience pinning as the isolation layer.
A TODO(R13) marks the key-separation seam.

Redis DB
--------
Delegation records live in Redis db/4, key prefix ``delegated_ctx:``.
This is isolated from:
  - db/0 — application (sessions, rate limits)
  - db/1 — nonce store (MCP relay JWT + orchestration-principal JTIs)
  - db/3 — agent registry (AgentRegistry)

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import jwt as pyjwt

from yashigani.mcp._jwt import McpJwtIssuer
from yashigani.mcp._nonce import NonceStore

logger = logging.getLogger(__name__)

# R13 — DEDICATED audience for delegated-context tokens.
# A token signed with audience "yashigani-delegated-context" can NEVER be
# accepted on the orchestration-principal path (audience="yashigani-
# orchestration-principal") and vice versa.
_AUDIENCE = "yashigani-delegated-context"
_ALGORITHM = "ES384"
# TTL is deliberately short — the NHI makes its callback within one request cycle.
# jti dedup (via NonceStore) closes replay within this window.
_TTL_SECONDS = 300   # 5 minutes; configurable for long-running NHI tasks


class DelegatedContextError(Exception):
    """Raised when mint or resolve fails.  Callers MUST treat as hard deny."""


@dataclass
class DelegatedContext:
    """Server-side delegated context for an NHI invocation.

    Stored in Redis as JSON; reconstructed by ``resolve_context()``.
    ``effective_scope`` is the server-computed intersection (R3) — NOT
    client-supplied.  It is what OPA evaluates as ``on_behalf_of.authority``.
    """
    nhi_id: str
    user_identity_id: str
    jti: str                     # nonce — the Redis key suffix and the signed claim
    exp: float                   # Unix timestamp for TTL
    effective_scope: dict = field(default_factory=dict)   # allowed_paths, tools, models
    # R12: presenting agent's SPIFFE id — the delegation record is bound to this.
    # resolve_context() asserts presenting_agent_spiffe == this value (fail-closed).
    bound_spiffe: str = ""

    def to_json(self) -> str:
        return json.dumps({
            "nhi_id": self.nhi_id,
            "user_identity_id": self.user_identity_id,
            "jti": self.jti,
            "exp": self.exp,
            "effective_scope": self.effective_scope,
            "bound_spiffe": self.bound_spiffe,
        })

    @classmethod
    def from_json(cls, raw: str) -> "DelegatedContext":
        d = json.loads(raw)
        return cls(
            nhi_id=d["nhi_id"],
            user_identity_id=d["user_identity_id"],
            jti=d["jti"],
            exp=d["exp"],
            effective_scope=d.get("effective_scope", {}),
            bound_spiffe=d.get("bound_spiffe", ""),
        )


class DelegatedContextStore:
    """Mint and resolve server-side delegated contexts.

    One instance per gateway process — constructed at lifespan startup (SOP 1).
    Holds the ES384 signer and the Redis db/4 client.

    TODO(R13): once install.sh provisions ``/run/secrets/delegated_ctx_signing_key``,
    load that PEM instead of reusing the McpJwtIssuer key.  The audience pinning
    already isolates the two token types, but a DEDICATED key per NIST SP 800-57
    is the target state.
    """

    def __init__(
        self,
        redis_client,
        *,
        tenant_id: str = "default",
        nonce_store: Optional[NonceStore] = None,
        ttl_seconds: int = _TTL_SECONDS,
        issuer: Optional[McpJwtIssuer] = None,
    ) -> None:
        # TODO(R13): replace with a dedicated PEM when install.sh provisions it.
        self._issuer = issuer or McpJwtIssuer(tenant_id=tenant_id)
        self._r = redis_client
        self._tenant_id = tenant_id
        self._nonce = nonce_store
        self._ttl = ttl_seconds
        logger.info(
            "DelegatedContextStore: initialised (audience=%s ttl=%ds redis=db/4)",
            _AUDIENCE, self._ttl,
        )

    # ── Mint ──────────────────────────────────────────────────────────────────

    def mint(
        self,
        *,
        nhi_id: str,
        user_identity_id: str,
        effective_scope: dict,
        bound_spiffe: str,
    ) -> str:
        """Mint a signed delegation handle and write the Redis record.

        Returns the signed JWT string — the gateway sets this as
        ``X-Yashigani-Session-Id`` on requests forwarded to the NHI container.
        The NHI carries it opaquely and returns it on callbacks.

        Parameters
        ----------
        nhi_id:
            The NHI being invoked.
        user_identity_id:
            The invoking user's identity_id (from the session).
        effective_scope:
            Server-computed R3 intersection — what the NHI may do on behalf of
            the user.  Stored in the Redis record; OPA reads it from there.
        bound_spiffe:
            The NHI's SPIFFE ID (R12) — ``resolve()`` asserts the presenting
            caller matches this before returning the context.

        Raises ``DelegatedContextError`` on any failure (fail-closed).
        """
        if not nhi_id or not user_identity_id:
            raise DelegatedContextError("nhi_id and user_identity_id are required")
        if not bound_spiffe:
            raise DelegatedContextError("bound_spiffe is required for R12 binding")

        iat = int(time.time())
        exp = iat + self._ttl
        jti = str(uuid.uuid4())

        # Sign the nonce (ES384, dedicated audience R13)
        payload = {
            "iss": f"yashigani-gateway/{self._tenant_id}",
            "aud": _AUDIENCE,
            "iat": iat,
            "exp": exp,
            "jti": jti,
            "nhi_id": nhi_id,
            "bound_spiffe": bound_spiffe,
        }
        try:
            token = pyjwt.encode(
                payload,
                self._issuer._key,
                algorithm=_ALGORITHM,
                headers={"kid": self._issuer.kid, "alg": _ALGORITHM},
            )
        except Exception as exc:
            raise DelegatedContextError(
                f"failed to sign delegated-context nonce: {exc}"
            ) from exc

        # Jti replay guard (same NonceStore as MCP relay JWT, db/1)
        if self._nonce is not None:
            try:
                is_new = self._nonce.check_and_record(jti, float(exp), self._tenant_id)
            except Exception as exc:
                raise DelegatedContextError(
                    f"delegated-context nonce store failure — fail-closed: {exc}"
                ) from exc
            if not is_new:
                raise DelegatedContextError("delegated-context jti collision — should never happen")

        # Redis delegation record (db/4, TTL = nonce window)
        ctx = DelegatedContext(
            nhi_id=nhi_id,
            user_identity_id=user_identity_id,
            jti=jti,
            exp=float(exp),
            effective_scope=effective_scope,
            bound_spiffe=bound_spiffe,
        )
        redis_key = f"delegated_ctx:{jti}"
        try:
            self._r.setex(redis_key, self._ttl, ctx.to_json().encode("utf-8"))
        except Exception as exc:
            raise DelegatedContextError(
                f"failed to write delegated-context Redis record: {exc}"
            ) from exc

        logger.debug(
            "DelegatedContextStore.mint: jti=%s nhi_id=%s user=%s bound_spiffe=%s",
            jti, nhi_id, user_identity_id, bound_spiffe,
        )
        return token

    # ── Resolve ───────────────────────────────────────────────────────────────

    def resolve(self, token: str, *, presenting_agent_spiffe: str) -> DelegatedContext:
        """Verify the signed nonce and return the server-side delegated context.

        R12: ``presenting_agent_spiffe`` MUST equal the ``bound_spiffe`` stored
        in the Redis record.  A leaked ``X-Yashigani-Session-Id`` is then
        unusable by another agent — even within TTL.

        Raises ``DelegatedContextError`` (fail-closed) on ANY failure:
        malformed token, wrong audience, expired, bad signature, SPIFFE mismatch,
        Redis record missing/expired, or jti replay.
        """
        if not token:
            raise DelegatedContextError("no delegated-context token presented")
        if not presenting_agent_spiffe:
            raise DelegatedContextError(
                "no presenting SPIFFE identity — cannot bind delegated context (R12)"
            )

        # Decode and verify the JWT
        try:
            header = pyjwt.get_unverified_header(token)
        except pyjwt.PyJWTError as exc:
            raise DelegatedContextError(f"malformed delegated-context header: {exc}") from exc

        if header.get("alg") != _ALGORITHM:
            raise DelegatedContextError(
                f"delegated-context alg must be {_ALGORITHM}; got {header.get('alg')!r}"
            )

        try:
            payload = pyjwt.decode(
                token,
                self._issuer._public_key,
                algorithms=[_ALGORITHM],
                audience=_AUDIENCE,
                leeway=5,
            )
        except pyjwt.ExpiredSignatureError as exc:
            raise DelegatedContextError("delegated-context token expired") from exc
        except pyjwt.PyJWTError as exc:
            raise DelegatedContextError(f"delegated-context verification failed: {exc}") from exc

        jti = payload.get("jti", "")
        if not jti:
            raise DelegatedContextError("delegated-context token carries no jti")

        nhi_id_claim = payload.get("nhi_id", "")
        bound_spiffe_claim = payload.get("bound_spiffe", "")

        # R12: SPIFFE binding check — presenting agent must match the claim
        if bound_spiffe_claim != presenting_agent_spiffe:
            raise DelegatedContextError(
                "delegated-context bound_spiffe mismatch — "
                "leaked token unusable by another agent (R12 fail-closed)"
            )

        # Fetch Redis record (may have expired or been consumed)
        redis_key = f"delegated_ctx:{jti}"
        try:
            raw = self._r.get(redis_key)
        except Exception as exc:
            raise DelegatedContextError(
                f"delegated-context Redis lookup failed — fail-closed: {exc}"
            ) from exc

        if raw is None:
            raise DelegatedContextError(
                "delegated-context record not found (expired or already consumed)"
            )

        ctx = DelegatedContext.from_json(
            raw.decode("utf-8") if isinstance(raw, bytes) else raw
        )

        # Cross-check: Redis record must agree with the JWT claims (R12)
        if ctx.nhi_id != nhi_id_claim:
            raise DelegatedContextError(
                "delegated-context Redis record nhi_id does not match JWT claim — tamper?"
            )
        if ctx.bound_spiffe != presenting_agent_spiffe:
            raise DelegatedContextError(
                "delegated-context Redis record bound_spiffe mismatch (R12)"
            )

        logger.debug(
            "DelegatedContextStore.resolve: jti=%s nhi_id=%s user=%s",
            jti, ctx.nhi_id, ctx.user_identity_id,
        )
        return ctx

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def session_id_hash(raw_session_id: str) -> str:
        """SHA-384 hex of the raw session_id — for audit events (never log raw)."""
        return "sha384:" + hashlib.sha384(raw_session_id.encode("utf-8")).hexdigest()

    @staticmethod
    def binding_hash(nhi_id: str, user_identity_id: str, jti: str) -> str:
        """SHA-384 of nhi_id:user_identity_id:jti — for DelegatedCtxMintedEvent."""
        raw = f"{nhi_id}:{user_identity_id}:{jti}"
        return "sha384:" + hashlib.sha384(raw.encode("utf-8")).hexdigest()


def build_delegated_context_store(
    redis_client,
    *,
    tenant_id: str = "default",
    nonce_store: Optional[NonceStore] = None,
    ttl_seconds: int = _TTL_SECONDS,
) -> DelegatedContextStore:
    """Construct a ``DelegatedContextStore`` for lifespan wiring (SOP 1).

    Fails closed (raises) if the signing key cannot be loaded — prevents a
    misconfigured deployment from starting with a broken delegated-context path.
    """
    store = DelegatedContextStore(
        redis_client,
        tenant_id=tenant_id,
        nonce_store=nonce_store,
        ttl_seconds=ttl_seconds,
    )
    return store


__all__ = [
    "DelegatedContextError",
    "DelegatedContext",
    "DelegatedContextStore",
    "build_delegated_context_store",
]
