"""
Yashigani Document Enforcement — PSEUDONYMIZE engine (host-side, plan §5.3).

PSEUDONYMIZE replaces each matched value with a **consistent, reversible token**
and keeps the token->original **replacer map** so the value is recoverable.  This
module owns the HOST-side machinery — the parts that must NEVER enter the jail:

  - :class:`TokenAssigner` — value-keyed, type-tagged, consistent token
    assignment (same source value -> same token within the request; distinct
    values -> distinct tokens — coherence, §5.3a).  Covers the FULL set of
    identifying / quasi-identifying classes the policy asked to pseudonymize
    (red-team F2: all QIs, not just direct identifiers).

  - :class:`ReplacerMap` — the crown-jewel correspondence map (red-team F5/§5.3b).
    Held request-scoped, **encrypted at rest** (AES-256-GCM via the vetted
    ``cryptography`` library), **TTL'd** (fail-closed default expiry), and
    addressed by an **unguessable, single-use, high-entropy capability handle**
    (``secrets.token_urlsafe``) that is **NOT** ``request.id`` and is **never**
    written to logs / audit / traces / errors.

  - :class:`CorrespondenceTable` — mode-A artefact (Tiago's default): the
    token->original table delivered to the user over an RBAC'd channel, plus the
    LOCAL re-merge primitive (:func:`local_remerge`) that restores real values
    from the user's table, keyed on the identifier — the §5.3.1 capability.

  - :class:`PositionBinder` — mode-B (F3 / L-02): binds each token to its egress
    provenance (the textual CONTEXT it was emitted in) AND occurrence count, and
    only restores at positions consistent with where it was issued — rejecting
    replays of in-map tokens in attacker-chosen positions (the namespace-dump
    attack), not merely when a count budget is exceeded.

The replacer map is the GDPR Art. 4(5) "additional information kept separately"
(§5.6) — it is exactly the data we just protected, keyed by token.  Everything in
this module treats it as a high-value secret: encrypted, TTL'd, RBAC'd, audited,
and never serialised into the jail plan or any log line.
"""
from __future__ import annotations

import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from yashigani.documents.datamatch import DataMatch
from yashigani.documents.token_scheme import (
    TOKEN_CHARS,
    derive_token,
)
from yashigani.documents.transform import RenderPlan, RenderSpan, SpanAction


# ---------------------------------------------------------------------------
# Token assignment — opaque, per-file-salted, value-keyed (DECIDED 2026-06-10).
# ---------------------------------------------------------------------------

#: Canonical opaque-token shape — a short lowercase base32 alphanumeric string of
#: exactly :data:`TOKEN_CHARS` characters, minted by
#: :meth:`OpaqueTokenAssigner.token_for` as the truncated HMAC of
#: ``doc_hash || value`` (see ``token_scheme``).  It carries NO class tag and NO
#: counter — the deliberate opacity that closes Laura's class/count-leak finding
#: on the old ``[CLASS_N]`` scheme.  SINGLE source of truth for the shape so the
#: residual re-detect (``qi_context._value_plausible``) recognises and never
#: re-flags our OWN emitted tokens (an opaque token under a still-present ``name``
#: header would otherwise be re-classified and BLOCK a clean artefact).  Anchored
#: so it matches a whole cell value, not a fragment embedded in prose.
_TOKEN_SHAPE = re.compile(rf"^\s*[a-z2-7]{{{TOKEN_CHARS}}}\s*$")


def is_pseudonymization_token(value: str) -> bool:
    """Whether ``value`` has the shape of one of OUR emitted opaque tokens.

    Used by the residual re-detect (``qi_context._value_plausible``) to avoid
    re-flagging our own opaque substitutions as surviving PII when the re-render
    output is re-classified.  The opaque token has no value structure, so a real
    input cell is extremely unlikely to collide with the shape; excluding it from
    the input-side classifier is correct, not merely convenient.

    NOTE this is a *shape* test (12 lowercase base32 chars), not a validity test —
    it does not prove the token was minted for THIS document.  Cross-file splice
    / foreign-salt detection is the job of ``token_scheme.token_matches_doc`` and
    :meth:`verify_token_integrity`, which recompute the keyed HMAC.
    """
    return bool(_TOKEN_SHAPE.match(value))


class OpaqueTokenAssigner:
    """Assigns consistent, **opaque, per-file-salted** tokens to matched values.

    DECIDED 2026-06-10 (supersedes the type-tagged sequential ``[CLASS_N]``
    assigner, which leaked class + count — Laura).  Each token is
    ``base32(HMAC-SHA256(deployment_secret, doc_hash || value))[:N]`` (see
    ``token_scheme``):

      * **Value-keyed coherence (§5.3a)** — the SAME original value derives the
        SAME token everywhere it appears in THIS document (the salt is constant
        within the file), so joins / repeats / cross-references survive.
      * **Per-file uniqueness** — the salt is ``doc_hash`` (SHA-256 of the
        original bytes), so the same value in a DIFFERENT document derives a
        DIFFERENT token — defeating cross-file correlation + binding the token to
        its source document for integrity / splice detection.
      * **Opaque** — no class tag, no counter, no value structure.

    Bijection guarantee: distinct values derive distinct tokens with overwhelming
    probability (≈4·10⁻⁷ even at 10⁶ values, N=12), AND any actual within-document
    collision is **detected and resolved** deterministically by re-deriving with a
    bounded domain-separation counter — so two distinct values never share a token
    (which would corrupt the data on restore).

    The assigner builds the token→original map (the crown jewel) which the caller
    hands to :class:`ReplacerMap` for encrypted, TTL'd custody.
    """

    #: Bound on the collision-resolution counter.  A run of this many derivations
    #: all colliding for distinct values is astronomically improbable at 60 bits;
    #: exceeding it is a hard error (we never silently ship a non-bijective map).
    _MAX_COLLISION_RESOLVE = 8

    def __init__(
        self,
        doc_hash: str,
        *,
        secret: Optional[bytes],
        chars: int = TOKEN_CHARS,
    ) -> None:
        if not doc_hash:
            raise ValueError("OpaqueTokenAssigner requires a non-empty doc_hash salt")
        self._doc_hash = doc_hash
        self._secret = secret
        self._chars = chars
        # original value -> token (the forward, value-keyed coherence map)
        self._value_to_token: dict[str, str] = {}
        # token -> original value (the reverse map; the crown jewel)
        self._token_to_value: dict[str, str] = {}

    @property
    def doc_hash(self) -> str:
        """The per-file salt this assigner is bound to (mapping-file header)."""
        return self._doc_hash

    def token_for(self, original: str, data_class: str = "") -> str:
        """Return the stable opaque token for ``original`` (minting on first sight).

        ``data_class`` is accepted for call-site compatibility but is deliberately
        NOT used in the derivation — the token must leak nothing about the class.
        """
        existing = self._value_to_token.get(original)
        if existing is not None:
            return existing
        # Derive; resolve the (rare) collision against a DISTINCT value
        # deterministically with a domain-separation counter.
        for counter in range(0, self._MAX_COLLISION_RESOLVE + 1):
            token = derive_token(
                self._doc_hash, original,
                secret=self._secret, chars=self._chars, counter=counter,
            )
            holder = self._token_to_value.get(token)
            if holder is None:
                break  # free token
            if holder == original:  # pragma: no cover - guarded by _value_to_token
                break  # same value (shouldn't reach here)
            # Collision with a DISTINCT value → try the next counter.
        else:
            raise RuntimeError(
                "opaque token collision could not be resolved within bound — "
                "refusing to ship a non-bijective map (fail-closed)"
            )
        self._value_to_token[original] = token
        self._token_to_value[token] = original
        return token

    @property
    def reverse_map(self) -> dict[str, str]:
        """token -> original (a COPY — the crown jewel; never log this)."""
        return dict(self._token_to_value)

    @property
    def token_count(self) -> int:
        return len(self._token_to_value)


#: Back-compat alias.  The old name ``TokenAssigner`` referred to the type-tagged
#: sequential assigner; it now resolves to the opaque assigner so existing call
#: sites keep working — but the constructor signature CHANGED (it now requires a
#: ``doc_hash`` salt + ``secret``), which is the whole point of the new scheme.
TokenAssigner = OpaqueTokenAssigner


# ---------------------------------------------------------------------------
# Replacer map — crown-jewel custody (plan §5.3b, red-team F5).
# ---------------------------------------------------------------------------

#: Fail-closed default TTL (seconds) for a request-scoped replacer map while in
#: gateway custody.  Never "unbounded".
DEFAULT_MAP_TTL_S = 300


class ReplacerMapExpiredError(Exception):
    """The replacer map TTL fired (or it was destroyed) — fail-closed.

    Mode-B restoration of an expired map MUST NOT return partially-restored data
    (§5.4 fail-closed corner)."""


class ReplacerMapIdentityError(ReplacerMapExpiredError):
    """The presenting caller's identity / tenant does not match the identity +
    tenant the map was bound to at mint time (G-NEW-2 / R5 — BOLA/IDOR close).

    Subclasses :class:`ReplacerMapExpiredError` so existing fail-closed call
    sites that catch the base error also fail closed on an identity/tenant
    mismatch — but the distinct type lets the retrieval surface emit a precise
    audit + 403 reason without leaking whether the map exists.  The reveal path
    NEVER returns partial data on a mismatch (fail-closed corner)."""


class ReplacerMapConsumedError(ReplacerMapExpiredError):
    """The map's capability handle was already consumed by a prior successful
    reveal (DP-Y-004 single-use gate).

    Distinct from :class:`ReplacerMapExpiredError` (TTL) so the audit surface
    and API can tell apart a replay (consumed) from a stale reference (expired)
    and emit the correct signal without leaking which state it is in to the
    unauthenticated surface (the HTTP status code is distinct; the error key is
    ``handle_already_consumed``).

    The :class:`CorrespondenceTable` ``consumed`` flag is the canonical marker.
    ``_detokenize_gate`` raises ``HTTPException(409)`` directly (for a uniform
    HTTP contract); this exception type is available for testing and for future
    call sites where a higher-level handler maps it to 409.  Nothing in the
    current gate flow raises it — that is intentional, not an oversight."""


#: Sentinel binding used when a map is minted WITHOUT an identity/tenant owner
#: (back-compat for the internal mode-B round-trip, which is gateway-scoped and
#: never reached through the identity-gated admin retrieval surface).  An
#: unbound map cannot be revealed through the identity-checked ``reveal`` path —
#: it must use ``reveal_unbound`` explicitly (mode-B internal restore only).
_UNBOUND = ""


@dataclass
class ReplacerMap:
    """A request-scoped, encrypted, TTL'd token->original map addressed by an
    unguessable capability handle (red-team F5), bound to the requester's
    IDENTITY + TENANT and (optionally) single-use (G-NEW-2 / R5).

    The map is encrypted at rest with AES-256-GCM (vetted ``cryptography`` lib).
    The plaintext map exists only transiently inside :meth:`reveal` while the
    caller holds it; at rest only the ciphertext + nonce are retained.  The
    ``handle`` is a 256-bit URL-safe random token — NOT ``request.id`` — and is
    NOT sufficient on its own to retrieve the map:

      * **Identity + tenant binding (G-NEW-2 / R5)** — ``owner_identity`` and
        ``tenant`` are folded into the AEAD **additional authenticated data**
        alongside the handle, AND checked explicitly (constant-time) in
        :meth:`reveal`.  A leaked handle presented by a DIFFERENT principal, or
        a role-downgraded principal whose identity no longer matches, fails the
        AAD auth AND the explicit check → :class:`ReplacerMapIdentityError`
        (fail-closed, no partial restore).  This closes the BOLA/IDOR seam where
        any member of ``detokenize_rbac_role`` could reverse ANY document's map.
      * **Single-use / burn-after-read** — when ``single_use`` is set the map is
        :meth:`destroy`ed on the FIRST successful reveal, so a leaked handle (or
        a replay) cannot re-retrieve it within the TTL window.
      * **TTL** — fail-closed default expiry; an expired/destroyed map reveals
        nothing.

    ``detokenize_rbac_role`` is retained as the COARSE role gate (checked at the
    route layer); identity+tenant is the FINE BOLA-closing gate enforced here.
    """

    handle: str
    detokenize_rbac_role: str
    ttl_s: int
    _nonce: bytes
    _ciphertext: bytes
    _key: bytes
    _created_at: float
    #: The identity (account_id) the map is bound to.  Empty == unbound
    #: (internal mode-B round-trip only; never reachable via reveal()).
    owner_identity: str = _UNBOUND
    #: The tenant the map is bound to.  Empty == unbound.
    tenant: str = _UNBOUND
    #: Burn-after-read: destroy on first successful reveal (default True for the
    #: identity-bound admin retrieval; mode-B internal maps mint single_use=False
    #: because the gateway may restore many response tokens across the round-trip).
    single_use: bool = True
    _destroyed: bool = False

    @staticmethod
    def _aad(handle: str, owner_identity: str, tenant: str) -> bytes:
        """Additional authenticated data binding ciphertext to handle+identity+tenant.

        Folding identity + tenant into the AAD means the AEAD decrypt itself
        fails if a different (identity, tenant) is presented — the crypto, not
        just an application check, enforces the binding (defence in depth)."""
        return f"{handle}\x00{owner_identity}\x00{tenant}".encode("utf-8")

    @classmethod
    def create(
        cls,
        reverse_map: dict[str, str],
        *,
        detokenize_rbac_role: str,
        owner_identity: str = _UNBOUND,
        tenant: str = _UNBOUND,
        single_use: bool = True,
        ttl_s: int = DEFAULT_MAP_TTL_S,
        now: Optional[float] = None,
    ) -> "ReplacerMap":
        """Mint a fresh map: unguessable handle + AES-256-GCM encryption, bound to
        ``owner_identity`` + ``tenant`` in the AEAD AAD (G-NEW-2 / R5).

        The handle and the encryption key are independent high-entropy secrets;
        possession of the handle alone does not decrypt the map (the key lives in
        the object held by the gateway, not in the handle), AND the presenting
        caller's identity+tenant must match what the map was minted for."""
        # F5: 256-bit unguessable, single-use capability handle. NOT request.id.
        handle = secrets.token_urlsafe(32)
        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        # Serialise the reverse map deterministically (token\x00value\x01...).
        # Raw originals are encrypted immediately and never held in plaintext at
        # rest on this object.
        blob = "\x01".join(f"{t}\x00{v}" for t, v in reverse_map.items()).encode("utf-8")
        aad = cls._aad(handle, owner_identity, tenant)
        ciphertext = AESGCM(key).encrypt(nonce, blob, aad)
        ttl = ttl_s if ttl_s and ttl_s > 0 else DEFAULT_MAP_TTL_S
        return cls(
            handle=handle,
            detokenize_rbac_role=detokenize_rbac_role,
            ttl_s=ttl,
            _nonce=nonce,
            _ciphertext=ciphertext,
            _key=key,
            _created_at=now if now is not None else time.monotonic(),
            owner_identity=owner_identity,
            tenant=tenant,
            single_use=single_use,
        )

    def _expired(self, now: Optional[float] = None) -> bool:
        t = now if now is not None else time.monotonic()
        return self._destroyed or (t - self._created_at) >= self.ttl_s

    def reveal(
        self,
        handle: str,
        *,
        identity: str,
        tenant: str,
        now: Optional[float] = None,
    ) -> dict[str, str]:
        """Decrypt + return the token->original map for an authorised caller.

        The caller MUST present (a) the exact capability handle (F5), AND (b) the
        IDENTITY + TENANT the map was bound to at mint time (G-NEW-2 / R5).  Any
        mismatch fails closed:

          * expired / destroyed map → :class:`ReplacerMapExpiredError`;
          * wrong handle           → :class:`ReplacerMapExpiredError` (uniform);
          * wrong identity/tenant  → :class:`ReplacerMapIdentityError`
            (the AEAD AAD check ALSO fails, but we reject early + uniformly).

        On a successful reveal of a ``single_use`` map the map is destroyed
        (burn-after-read) so the handle cannot be replayed within the TTL.
        """
        if self._expired(now):
            raise ReplacerMapExpiredError(
                "replacer map expired/destroyed — fail-closed (no partial restore)"
            )
        if not secrets.compare_digest(handle, self.handle):
            # Wrong handle — do not reveal. (Constant-time compare; the AEAD AAD
            # check below would also fail, but reject early + uniformly.)
            raise ReplacerMapExpiredError("replacer map handle mismatch — fail-closed")
        # G-NEW-2 / R5: identity + tenant must match the binding (BOLA/IDOR close).
        # Constant-time compare each component; an unbound map (empty owner) is
        # NOT retrievable through this identity-checked path.
        identity_ok = (
            bool(self.owner_identity)
            and secrets.compare_digest(identity, self.owner_identity)
        )
        tenant_ok = (
            bool(self.tenant)
            and secrets.compare_digest(tenant, self.tenant)
        )
        if not (identity_ok and tenant_ok):
            raise ReplacerMapIdentityError(
                "replacer map identity/tenant mismatch — fail-closed "
                "(another principal's handle, a role-downgrade, or an unbound map)"
            )
        out = self._decrypt(handle, identity, tenant)
        if self.single_use:
            # Burn-after-read: a leaked handle cannot be replayed within the TTL.
            self.destroy()
        return out

    def reveal_unbound(self, handle: str, *, now: Optional[float] = None) -> dict[str, str]:
        """Internal mode-B restore path: reveal an UNBOUND (gateway-scoped) map.

        Used ONLY by the gateway's own mode-B round-trip restore (no external
        principal is involved — the gateway holds the handle in request scope and
        never exposes it).  Refuses to reveal a map that WAS bound to an identity
        (that map must go through the identity-checked :meth:`reveal`)."""
        if self._expired(now):
            raise ReplacerMapExpiredError(
                "replacer map expired/destroyed — fail-closed (no partial restore)"
            )
        if not secrets.compare_digest(handle, self.handle):
            raise ReplacerMapExpiredError("replacer map handle mismatch — fail-closed")
        if self.owner_identity or self.tenant:
            raise ReplacerMapIdentityError(
                "identity-bound map must be revealed through the identity-checked "
                "path — refusing unbound reveal (fail-closed)"
            )
        return self._decrypt(handle, self.owner_identity, self.tenant)

    def _decrypt(self, handle: str, identity: str, tenant: str) -> dict[str, str]:
        aad = self._aad(handle, identity, tenant)
        blob = AESGCM(self._key).decrypt(self._nonce, self._ciphertext, aad)
        out: dict[str, str] = {}
        text = blob.decode("utf-8")
        if text:
            for pair in text.split("\x01"):
                tok, _, val = pair.partition("\x00")
                out[tok] = val
        return out

    def destroy(self) -> None:
        """Destroy the map (request end / TTL).  Idempotent.  After this, reveal
        fails closed.  We zero the key + ciphertext references."""
        self._destroyed = True
        self._key = b""
        self._ciphertext = b""
        self._nonce = b""


# ---------------------------------------------------------------------------
# Mode A — correspondence table + LOCAL re-merge (plan §5.3.1, Tiago's default).
# ---------------------------------------------------------------------------

@dataclass
class CorrespondenceTable:
    """Mode-A artefact: the token->original table delivered to the USER as a
    first-class output over an RBAC'd channel (custody transfers to the user).

    This table IS the re-identification key (GDPR Art. 4(5)) — it is delivered
    only over an authenticated/RBAC'd channel and the delivery is audited
    (handled by the pipeline).  The table itself is the user's join key for the
    §5.3.1 local re-merge.
    """

    rows: dict[str, str]  # token -> original
    detokenize_rbac_role: str
    #: The per-file salt (doc_hash) the tokens were derived under — the
    #: mapping-file HEADER (DECIDED 2026-06-10).  Lets the holder confirm the
    #: table belongs to a given document (integrity) and lets the local re-merge
    #: reject a table paired with the wrong file.  Not a secret (hash of bytes
    #: the holder already has).
    doc_hash: str = ""
    #: The identity (account_id) + tenant the correspondence table is bound to
    #: (G-NEW-2 / R5).  Only this principal, in this tenant, may retrieve it — the
    #: BOLA/IDOR close: role membership is NOT sufficient on its own.  Empty when
    #: minted without a requester context (legacy / non-gated call shapes).
    owner_identity: str = ""
    tenant: str = ""
    #: DP-Y-004 §3.1 — plaintext TTL.  The monotonic timestamp at which this
    #: table was minted and the TTL in seconds, matching the companion
    #: ``ReplacerMap`` so the plaintext and the encrypted vault expire together.
    #: Default ``0.0`` / ``0`` means "no TTL metadata" — ``_expired()`` treats
    #: this as expired (fail-closed) so old tables without metadata cannot be
    #: retrieved indefinitely.
    created_at: float = field(default=0.0, repr=False, compare=False)
    ttl_s: int = field(default=0, repr=False, compare=False)
    #: DP-Y-004 — single-use consumption flag.
    #: Set to True by the reveal surface (``_detokenize_gate``) after the first
    #: successful authorised retrieval.  Subsequent attempts find this True and are
    #: rejected with a distinct 409 ``handle_already_consumed`` error that is also
    #: audited.  Thread-safe in asyncio: the gate sets this to True in a
    #: synchronous block (no ``await`` between the check and the set), so two
    #: concurrent coroutines cannot both observe it as False — the first wins and
    #: the second is rejected.  ``init=False`` keeps it out of ``__init__`` so
    #: every call to :meth:`from_assigner` starts unconsumed by construction.
    consumed: bool = field(default=False, repr=False, compare=False, init=False)

    def _expired(self, now: Optional[float] = None) -> bool:
        """True when this plaintext table is past its TTL — fail-closed.

        Fail-closed: if ``created_at`` is zero/missing OR ``ttl_s`` is
        zero/non-positive, treat the table as expired rather than as fresh.
        A table minted without TTL metadata (e.g. created by old code or
        constructed without the ``ttl_s`` / ``created_at`` parameters) must
        not be retrievable indefinitely — it fails closed immediately."""
        if not self.created_at or self.ttl_s <= 0:
            # Missing or invalid TTL metadata → fail-closed: expired.
            return True
        t = now if now is not None else time.monotonic()
        return (t - self.created_at) >= self.ttl_s

    @classmethod
    def from_assigner(
        cls,
        assigner: "OpaqueTokenAssigner",
        *,
        detokenize_rbac_role: str,
        owner_identity: str = "",
        tenant: str = "",
        ttl_s: int = 0,
        now: Optional[float] = None,
    ) -> "CorrespondenceTable":
        """Mint a CorrespondenceTable from a token assigner.

        Pass ``ttl_s`` from the companion :class:`ReplacerMap` so the
        plaintext and the encrypted vault expire at the same wall-clock time
        (DP-Y-004 §3.1 — the plaintext TTL matches the operator-facing vault
        TTL)."""
        return cls(
            rows=assigner.reverse_map,
            detokenize_rbac_role=detokenize_rbac_role,
            doc_hash=assigner.doc_hash,
            owner_identity=owner_identity,
            tenant=tenant,
            created_at=now if now is not None else time.monotonic(),
            ttl_s=ttl_s,
        )

    def to_csv(self) -> str:
        """Render the table as a CSV the user can keep (token,original).

        The mapping-file HEADER carries the per-file salt (``# doc_hash=…``) so
        the table is bound to its source document (integrity / splice rejection).
        This is the user's key — the pipeline delivers it over the RBAC'd channel
        and never writes it to an audit/log line."""
        import csv
        import io
        buf = io.StringIO()
        if self.doc_hash:
            # Comment header binds the table to the document it re-identifies.
            buf.write(f"# doc_hash={self.doc_hash}\n")
        w = csv.writer(buf)
        w.writerow(["token", "original"])
        for tok, val in self.rows.items():
            w.writerow([tok, val])
        return buf.getvalue()


def local_remerge(tokenized_text: str, table: dict[str, str]) -> str:
    """Mode-A user-driven restore (§5.3.1): join the tokenized content back to
    real values using the user's correspondence table, keyed on the token.

    Runs LOCALLY (the gateway's local-AI/local capability) — real values touch
    neither the cloud egress nor a remote restore service.  Deterministic,
    table-driven re-substitution: every ``[PERSON_1]`` becomes the one original
    value it stood for.  Longest tokens first so ``[PERSON_10]`` is not partially
    matched by ``[PERSON_1]``.
    """
    out = tokenized_text
    for tok in sorted(table, key=len, reverse=True):
        out = out.replace(tok, table[tok])
    return out


# ---------------------------------------------------------------------------
# Mode B — position/count binding on the response path (plan §5.4, red-team F3).
# ---------------------------------------------------------------------------

def _context_key(text: str, start: int, end: int, *, radius: int = 24) -> str:
    """Provenance fingerprint of the context a token was emitted in.

    The key is the normalised surrounding window (``radius`` chars either side of
    the token span, the token itself elided, whitespace collapsed, casefolded).
    Two emissions of the same token in the same egress neighbourhood produce the
    same key; the same token replayed in a different (attacker-framed) sentence
    produces a different key.  This is the position/provenance the response path
    binds restoration to — not a raw character offset (which the cloud reflows),
    but the *textual context* the token legitimately stood in on egress.
    """
    import re as _re

    left = text[max(0, start - radius):start]
    right = text[end:end + radius]
    ctx = f"{left}\x00{right}"
    return _re.sub(r"\s+", " ", ctx).strip().casefold()


@dataclass
class _EgressOccurrence:
    """One egress emission of a token: the value it stood for, and the set of
    context fingerprints it was legitimately emitted in."""

    original: str
    egress_count: int = 0
    #: context-key -> remaining restore budget for THAT context.  Restoration is
    #: only permitted at a context consistent with where the token was issued.
    contexts: dict[str, int] = field(default_factory=dict)


def _token_alternation(tokens: "list[str]") -> "re.Pattern[str]":
    """Compile a regex matching EXACTLY the known egress tokens.

    Opaque tokens (DECIDED 2026-06-10) are bare 12-char base32 strings with no
    bracketed shape, so the response path can no longer scan for a generic
    ``[TAG_n]`` shape — it must look for the EXACT tokens it issued.  Longest
    first so a token is never partially matched by a shorter one (defensive; all
    opaque tokens are the same length, but a mixed-length namespace stays safe).
    Word-boundaried so a token is matched as a whole alphanumeric run, not as a
    substring of a longer word.
    """
    import re as _re

    if not tokens:
        # Match nothing.
        return _re.compile(r"(?!x)x")
    alt = "|".join(_re.escape(t) for t in sorted(tokens, key=len, reverse=True))
    return _re.compile(rf"(?<![A-Za-z0-9])(?:{alt})(?![A-Za-z0-9])")


class EchoEgressError(Exception):
    """The cloud response is structurally an ECHO of the egress frame (L-02
    verbatim-echo) — fail-closed: restore NOTHING, flag, alert.

    The egress frame (the tokenized payload we sent to the untrusted cloud) is
    KNOWN to the adversary by construction.  Pure position/context binding cannot
    distinguish a legitimate answer (a *transformation* of the input) from a
    crafted verbatim/near-verbatim echo of the egress frame (whose every token
    lands in exactly the context it was issued in, so every context check
    passes).  A response that reproduces the egress frame's token layout/
    structure is therefore treated as anomalous and the whole round-trip fails
    closed — the namespace is NOT restored into attacker-shaped output."""


@dataclass
class PositionBinder:
    """Mode-B re-substitution guard (red-team F3 / L-02).

    The cloud response is UNTRUSTED.  An attacker who learned the token namespace
    (we sent ``[PERSON_1..N]``) can replay each in-map token **once**, within the
    per-token count budget, in an attacker-chosen sentence — a "namespace dump" —
    and a count-only cap restores the entire real-value set into exfil-shaped
    output with zero over-restore flags (Laura, PROVEN).  The count-cap is the
    WRONG invariant: it stops amplification, not namespace exfiltration.

    This binder restores a token only when BOTH hold:

      - **count budget** — the token is restored at most the number of times it
        was SENT (surplus instances are left as tokens + flagged over-restore);
      - **position / provenance binding (L-02)** — the token is restored only at
        a response position whose surrounding context is CONSISTENT with an
        egress context the token was issued in (:func:`_context_key`).  A token
        that reappears in a new / attacker-chosen position is NOT restored — it
        is left as the token and reported in ``rejected_positions`` so the
        pipeline fails the round-trip closed.

    An unknown token (never in the egress set) is left as-is (never guessed,
    §5.4 fail-closed corner).  The namespace-dump attack — replay every token
    once in a "Full staff directory: …" sentence — therefore restores NOTHING:
    every replay lands in an attacker context the token was never issued in.

    **Verbatim-egress-echo close (L-02 residual).** Context binding alone cannot
    distinguish a legitimate answer from an echo of the egress frame, because the
    frame is known to the adversary and every token in the echo lands in exactly
    the context it was issued in.  Two complementary structural controls close
    this, evaluated in :meth:`restore` BEFORE any per-token restoration:

      1. **Echo-shaped-response rejection** — when the egress frame text is
         recorded (:meth:`record_egress_frame`), a response whose token layout /
         structure is suspiciously similar to the egress frame (Jaccard overlap
         of the inter-token "skeleton" ≥ ``echo_similarity_threshold``, or the
         response reproduces the egress token *sequence* near-verbatim) is
         rejected as an echo → :class:`EchoEgressError`, restore nothing.  A
         genuine answer is a *transformation* (a summary, an extracted field, a
         decision) — not a reproduction of the frame's structure.

      2. **Bounded restoration** — even below the echo threshold, no single
         response may restore more than ``max_restore_fraction`` of the distinct
         egress namespace.  A response trying to restore most/all of the
         namespace (the harvest goal) is anomalous and fails closed; a genuine
         answer references a small handful of tokens.

    **Documented residual + blast-radius (for Lu / Petra / threat model).**
    The echo guard + bounded restoration close Laura's *verbatim*-echo (the whole
    frame bounced back) and bound any single response to ``max_restore_fraction``
    of the namespace.  A *partial*-slice echo that stays both below the echo
    threshold AND under the per-response cap can still restore up to that fraction
    of the namespace into an attacker-shaped response.  The blast radius is
    bounded three ways: (a) at most ~``max_restore_fraction`` of ONE request's
    namespace per response; (b) every request mints a FRESH, independent token
    namespace + a fresh, TTL'd :class:`ReplacerMap` (the assigner + map are
    request-scoped in the pipeline), so an attacker cannot accumulate restorations
    across requests against a stable namespace; (c) position binding still
    requires each restored token to land in its issued ±24-char context, so the
    slice must reproduce genuine egress context (not arbitrary attacker framing).
    A full namespace harvest from a single tokenized payload is therefore NOT
    achievable; the residual is a partial, single-request, context-faithful slice
    — materially weaker than the original whole-namespace dump.  Operators handling
    extreme-sensitivity sets should keep mode B for non-token-list documents (a
    degenerate pure-token-list frame fails closed — see below) and may lower
    ``max_restore_fraction`` to tighten the per-response cap further.

    (Per-request namespace salting + injection-classify-before-restore remain
    pipeline/Ogen concerns; this object owns the count + position + echo/anomaly
    mechanics — the ``bind_restore_to_egress_positions`` obligation the rego
    surfaces.)
    """

    _egress: dict[str, _EgressOccurrence] = field(default_factory=dict)
    #: The recorded egress-frame text (the tokenized payload sent to the cloud)
    #: used for echo-shaped-response detection.  Set via
    #: :meth:`record_egress_frame`; when unset, echo detection degrades to the
    #: token-sequence check over the egress map only.
    _egress_frame: str = ""
    #: Reject a response whose inter-token structural skeleton overlaps the
    #: egress frame at or above this Jaccard ratio (verbatim/near-verbatim echo).
    echo_similarity_threshold: float = 0.6
    #: A single response may restore at most this fraction of the DISTINCT egress
    #: namespace.  Above this, the response is treated as a namespace harvest and
    #: fails closed.  (1.0 only when there is a single token — see _restore_cap.)
    max_restore_fraction: float = 0.5

    def record_egress(
        self,
        token: str,
        original: str,
        count: int = 1,
        *,
        egress_text: Optional[str] = None,
        span: Optional[tuple[int, int]] = None,
    ) -> None:
        """Register that ``token`` (standing for ``original``) was sent.

        Called as the tokenized payload leaves the gateway.  When the egress
        ``egress_text`` and the token's ``span`` are supplied, the binder records
        the **context fingerprint** the token was emitted in (L-02 position
        binding) so the response path can reject replays in foreign positions.

        If no context is supplied the binder degrades to count-only binding for
        that emission (back-compat); callers wanting the L-02 guarantee MUST
        supply the egress text + span — which the pipeline does for every span it
        emits.  When the same egress text is supplied without an explicit span,
        every occurrence of the token in that text is recorded as a valid
        context (the common "I tokenized this whole payload" call shape)."""
        occ = self._egress.get(token)
        if occ is None:
            occ = _EgressOccurrence(original=original)
            self._egress[token] = occ
        occ.egress_count += count

        if egress_text is None:
            return
        if span is not None:
            key = _context_key(egress_text, span[0], span[1])
            occ.contexts[key] = occ.contexts.get(key, 0) + 1
            return
        # No explicit span: record EVERY occurrence of the token in egress_text
        # as a legitimate context.
        idx = egress_text.find(token)
        while idx != -1:
            key = _context_key(egress_text, idx, idx + len(token))
            occ.contexts[key] = occ.contexts.get(key, 0) + 1
            idx = egress_text.find(token, idx + len(token))

    def record_egress_frame(self, egress_text: str) -> None:
        """Record the full egress-frame text (the tokenized payload sent to the
        untrusted cloud) for verbatim-echo detection (L-02).

        Called once per request as the tokenized artefact leaves the gateway.
        The response path compares the cloud response against this frame; a
        response that structurally reproduces it is rejected as an echo."""
        self._egress_frame = egress_text or ""

    def _token_re(self) -> "re.Pattern[str]":
        """Regex matching exactly THIS binder's known egress tokens (opaque)."""
        return _token_alternation(list(self._egress.keys()))

    def _structural_skeleton(self, text: str) -> list[str]:
        """The inter-token structural skeleton of ``text``: the ordered list of
        normalised non-token fragments BETWEEN the placeholder tokens, plus a
        generic ``TOKEN`` marker at each token position in order.

        Two texts with the same skeleton say the same thing around tokens in the
        same order — i.e. one is an echo of the other's frame.  A genuine answer
        rearranges / drops / summarises the frame and so has a very different
        skeleton.  Token IDENTITY is elided to a generic ``TOKEN`` marker (opaque
        tokens carry no type tag) so that simply permuting which value lands where
        does not evade the check — the structure (prose around N tokens) is what
        the echo-guard compares."""
        import re as _re

        token_re = self._token_re()
        parts: list[str] = []
        last = 0
        for m in token_re.finditer(text):
            between = text[last:m.start()]
            norm = _re.sub(r"\s+", " ", between).strip().casefold()
            if norm:
                parts.append(norm)
            parts.append("\x00TOKEN")
            last = m.end()
        tail = _re.sub(r"\s+", " ", text[last:]).strip().casefold()
        if tail:
            parts.append(tail)
        return parts

    def _is_echo_shaped(self, response_text: str) -> bool:
        """True iff ``response_text`` is a verbatim/near-verbatim echo of the
        recorded egress frame (L-02 verbatim-echo).

        Two structural signals, EITHER of which trips the guard:

          * **skeleton Jaccard** — the inter-token skeletons of the response and
            the egress frame overlap at or above ``echo_similarity_threshold``;
          * **token-sequence reproduction** — the ordered sequence of token
            *tags* in the response reproduces the egress frame's token-tag
            sequence as a contiguous run (the attacker simply pasted the frame
            back, possibly wrapped in a little prose).
        """
        frame = self._egress_frame
        if not frame:
            return False
        resp_skel = self._structural_skeleton(response_text)
        frame_skel = self._structural_skeleton(frame)
        if not frame_skel:
            return False

        # Signal 1 — skeleton Jaccard overlap.
        rs, fs = set(resp_skel), set(frame_skel)
        if fs:
            jaccard = len(rs & fs) / len(rs | fs)
            if jaccard >= self.echo_similarity_threshold:
                return True

        # Signal 2 — the egress token sequence (by token IDENTITY) appears
        # verbatim in the response (the frame pasted back, optionally wrapped).
        # Opaque tokens carry no tag, so identity IS the sequence — an attacker
        # echoing the frame reproduces the exact token order.
        token_re = self._token_re()

        def _seq(t: str) -> list[str]:
            return [m.group(0) for m in token_re.finditer(t)]

        frame_seq = _seq(frame)
        resp_seq = _seq(response_text)
        if frame_seq and len(frame_seq) >= 2 and len(resp_seq) >= len(frame_seq):
            n = len(frame_seq)
            for i in range(0, len(resp_seq) - n + 1):
                if resp_seq[i:i + n] == frame_seq:
                    return True
        return False

    def _restore_cap(self) -> int:
        """Max distinct tokens a single response may restore (bounded restoration).

        ``ceil(max_restore_fraction * namespace_size)`` with a floor of 1 so a
        single-token namespace still round-trips, and so a small answer that
        references one or two tokens is never penalised."""
        import math

        size = len(self._egress)
        if size <= 1:
            return size
        return max(1, math.ceil(self.max_restore_fraction * size))

    def restore(self, response_text: str) -> tuple[str, list[str]]:
        """Restore tokens in an untrusted cloud response — count- AND position-bound,
        with verbatim-echo rejection + bounded restoration (L-02 close).

        Returns ``(restored_text, flags)`` where ``flags`` lists tokens that were
        partially or wholly REFUSED restoration (over-restore beyond count budget,
        OR replay in a position inconsistent with egress provenance — L-02).  A
        non-empty ``flags`` list fails the round-trip closed in the pipeline.

        Before any per-token restoration:

          * if the response is structurally an ECHO of the egress frame
            (:meth:`_is_echo_shaped`) the whole round-trip fails closed with
            :class:`EchoEgressError` — restore NOTHING (the verbatim-echo close);
          * restoration is BOUNDED to :meth:`_restore_cap` distinct tokens; a
            response trying to harvest more of the namespace than that is treated
            as anomalous and every further distinct token is left as a token +
            flagged.

        Each token instance in the response is then examined IN PLACE: it is
        restored only if (a) the token's count budget is not yet exhausted AND
        (b) a position-binding context for this occurrence is still available
        (when the token was egress-bound to contexts).  Replays in attacker-
        chosen positions consume no budget and are LEFT AS THE TOKEN — so the
        namespace-dump attack restores nothing.
        """
        # --- Verbatim-echo close (L-02): reject an echo of the egress frame ----
        if self._is_echo_shaped(response_text):
            raise EchoEgressError(
                "cloud response is structurally an echo of the egress frame — "
                "refusing to restore the namespace (verbatim-echo, fail-closed)"
            )

        flags: list[str] = []
        # Bounded restoration: distinct tokens already restored this response.
        cap = self._restore_cap()
        restored_distinct: set[str] = set()
        # Remaining count budget + per-context budget for each token.
        count_left = {tok: occ.egress_count for tok, occ in self._egress.items()}
        ctx_left = {
            tok: dict(occ.contexts) for tok, occ in self._egress.items()
        }

        token_re = self._token_re()

        def _replace(m: "re.Match[str]") -> str:
            tok = m.group(0)
            occ = self._egress.get(tok)
            if occ is None:  # pragma: no cover - token_re only matches known tokens
                # Unknown token — never guessed (§5.4 fail-closed).
                return tok
            # Count budget exhausted → over-restore; leave as token.
            if count_left.get(tok, 0) <= 0:
                if tok not in flags:
                    flags.append(tok)
                return tok
            # Bounded restoration: a single response may restore at most ``cap``
            # DISTINCT tokens.  A new distinct token beyond the cap is a namespace
            # harvest → leave as token + flag.  (Already-restored tokens within
            # budget are unaffected — this bounds breadth, not depth.)
            if tok not in restored_distinct and len(restored_distinct) >= cap:
                if tok not in flags:
                    flags.append(tok)
                return tok
            # Position binding (L-02): if the token was egress-bound to specific
            # contexts, the replay's context MUST match one with budget left.
            ctxs = ctx_left.get(tok)
            if ctxs:  # token has recorded egress provenance
                key = _context_key(response_text, m.start(), m.end())
                if ctxs.get(key, 0) <= 0:
                    # Replay in a position the token was NOT issued in — refuse.
                    if tok not in flags:
                        flags.append(tok)
                    return tok
                ctxs[key] -= 1
            # Authorised: consume count budget, restore.
            count_left[tok] -= 1
            restored_distinct.add(tok)
            return occ.original

        result = token_re.sub(_replace, response_text)
        return result, flags


# ---------------------------------------------------------------------------
# Mode B — request-scoped round-trip holder (pipeline seam, F3 / L-02).
# ---------------------------------------------------------------------------

@dataclass
class ModeBRoundTrip:
    """The request-scoped state the gateway holds for a PSEUDONYMIZE mode-B
    round-trip: the encrypted/TTL'd :class:`ReplacerMap` (crown jewel) + the
    :class:`PositionBinder` primed with the egress provenance + egress frame.

    The gateway tokenizes the document on egress (the cloud sees only the
    placeholders), holds THIS object request-scoped keyed by the map's unguessable
    handle, and on the response path calls :meth:`restore` — which restores ONLY
    tokens that satisfy count + position binding, rejects a verbatim echo of the
    egress frame, and bounds how much of the namespace any one response may
    restore.  The :class:`ReplacerMap` itself is never surfaced to the cloud, the
    plan, or any log line; only ``restore`` ever touches the real values, and only
    on the trusted host after the binder has cleared the response."""

    binder: "PositionBinder"
    replacer_map: "ReplacerMap"
    #: The token->original map, decrypted ONCE from the ReplacerMap at restore
    #: time via the handle.  Held on the binder's _egress already (originals), so
    #: this field is not stored; restoration uses the binder's recorded originals.

    @property
    def handle(self) -> str:
        """The unguessable capability handle of the replacer map (NEVER logged)."""
        return self.replacer_map.handle

    def restore(self, response_text: str) -> tuple[str, list[str]]:
        """Restore an untrusted cloud response on the trusted host.

        Fail-closed: a verbatim-echo of the egress frame raises
        :class:`EchoEgressError` (restore nothing); any token left un-restored
        (foreign position, over-restore, or namespace-harvest beyond the cap) is
        returned in ``flags`` so the pipeline can fail the round-trip closed and
        alert.  The replacer map is never surfaced — only restored cleartext for
        the cleared tokens appears in the returned text."""
        return self.binder.restore(response_text)

    def destroy(self) -> None:
        """End-of-request teardown: destroy the replacer map (fail-closed)."""
        self.replacer_map.destroy()


def build_modeb_roundtrip(
    assigner: "TokenAssigner",
    replacer_map: "ReplacerMap",
    egress_frame: str,
) -> "ModeBRoundTrip":
    """Prime a :class:`PositionBinder` from the tokenized egress frame and wrap it
    with the replacer map as a request-scoped :class:`ModeBRoundTrip`.

    ``egress_frame`` is the text of the tokenized artefact AS THE CLOUD WILL SEE
    IT (the re-extracted output segments joined) — the binder records, for every
    token, the egress context(s) it was emitted in within that frame, and records
    the frame itself for verbatim-echo detection.
    """
    binder = PositionBinder()
    # Bind each distinct token to the contexts it occupies in the egress frame.
    for token, original in assigner.reverse_map.items():
        # count = number of times this token appears in the egress frame.
        n = egress_frame.count(token)
        if n <= 0:
            # Token was assigned but did not survive into the rendered frame
            # (e.g. only present in a stripped hidden part) — record count 0 so a
            # response referencing it cannot restore (no budget).
            binder.record_egress(token, original, count=0)
            continue
        binder.record_egress(token, original, count=n, egress_text=egress_frame)
    binder.record_egress_frame(egress_frame)
    return ModeBRoundTrip(binder=binder, replacer_map=replacer_map)


# ---------------------------------------------------------------------------
# Plan builders — turn the host DataMatch[] + token assignment into a RenderPlan.
# ---------------------------------------------------------------------------

def _segment_location_of(match: DataMatch) -> str:
    """Recover the WORKER-side segment location from a DataMatch.location.

    DataMatch.location is ``"<kind>:<segment.location>:span=A-B"`` (see
    ``datamatch.location_for``).  The worker keys segments by ``<segment.location>``
    so we strip the leading ``<kind>:`` and the trailing ``:span=...``.
    """
    loc = match.location
    # Strip trailing ":span=A-B" if present.
    if ":span=" in loc:
        loc = loc.rsplit(":span=", 1)[0]
    # Strip leading "<KIND>:" (the SegmentKind enum value) if present.
    if ":" in loc:
        head, _, rest = loc.partition(":")
        if head.isupper() and rest:
            loc = rest
    return loc


def build_redact_plan(matches: list[DataMatch], originals: dict[str, str]) -> RenderPlan:
    """Build a REDACT plan: destroy every matched span + strip hidden/metadata.

    ``originals`` maps ``match.location -> raw matched substring`` (the gateway
    has it from enumeration over the cleartext segment; it never leaves the
    host except into the jail plan, which re-renders from the same bytes)."""
    spans: list[RenderSpan] = []
    for m in matches:
        original = originals.get(m.location)
        if not original:
            continue
        spans.append(
            RenderSpan(
                segment_location=_segment_location_of(m),
                original=original,
                action=SpanAction.REDACT,
                data_class=m.data_class,
            )
        )
    return RenderPlan(spans=spans, strip_hidden_and_metadata=True)


def build_pseudonymize_plan(
    matches: list[DataMatch],
    originals: dict[str, str],
    assigner: TokenAssigner,
) -> RenderPlan:
    """Build a PSEUDONYMIZE plan: token-substitute every matched span (consistent
    value-keyed tokens) + strip hidden/metadata.  Mutates ``assigner`` to record
    the token->original map (the caller then vaults it as a :class:`ReplacerMap`).
    """
    spans: list[RenderSpan] = []
    for m in matches:
        original = originals.get(m.location)
        if not original:
            continue
        token = assigner.token_for(original, m.data_class)
        spans.append(
            RenderSpan(
                segment_location=_segment_location_of(m),
                original=original,
                action=SpanAction.PSEUDONYMIZE,
                token=token,
                data_class=m.data_class,
            )
        )
    return RenderPlan(spans=spans, strip_hidden_and_metadata=True)
