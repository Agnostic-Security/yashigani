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
import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from yashigani.documents.datamatch import DataMatch
from yashigani.documents.transform import RenderPlan, RenderSpan, SpanAction


# ---------------------------------------------------------------------------
# Token assignment — consistent, type-tagged, value-keyed (plan §5.3a, F2).
# ---------------------------------------------------------------------------

def _type_tag(data_class: str) -> str:
    """Map a (possibly namespaced) data_class to a token type tag.

    ``PII.EMAIL`` -> ``EMAIL``; ``PII.CREDIT_CARD`` -> ``CARD``; an unknown class
    falls back to the bare class so a token is always type-tagged (the downstream
    model still knows it reasons over *a* class — §5.3a)."""
    bare = data_class.rsplit(".", 1)[-1].upper()
    # Normalise a couple of long names to the short tags used in the plan/docs.
    return {
        "CREDIT_CARD": "CARD",
        "DATE_OF_BIRTH": "DOB",
        "NATIONAL_ID": "ID",
        "DRIVERS_LICENCE": "DL",
        "NHS_NUMBER": "NHS",
        "IP_ADDRESS": "IP",
    }.get(bare, bare or "VALUE")


class TokenAssigner:
    """Assigns consistent, type-tagged tokens to matched values within a request.

    Value-keyed: the SAME original value gets the SAME token everywhere it
    appears (across cells/paragraphs/slides) so the tokenized artefact stays
    internally coherent (joins, repeats and cross-references survive — §5.3a).
    Distinct values get distinct tokens.  Counters are per type tag so tokens
    read ``[PERSON_1]``, ``[PERSON_2]``, ``[IBAN_1]`` …

    The assigner builds the token->original map (the crown jewel) which the
    caller hands to :class:`ReplacerMap` for encrypted, TTL'd custody.
    """

    def __init__(self) -> None:
        # original value -> token (the forward, value-keyed coherence map)
        self._value_to_token: dict[str, str] = {}
        # token -> original value (the reverse map; the crown jewel)
        self._token_to_value: dict[str, str] = {}
        # per-type-tag running counter
        self._counters: dict[str, int] = {}

    def token_for(self, original: str, data_class: str) -> str:
        """Return the stable token for ``original`` (minting one on first sight)."""
        if original in self._value_to_token:
            return self._value_to_token[original]
        tag = _type_tag(data_class)
        self._counters[tag] = self._counters.get(tag, 0) + 1
        token = f"[{tag}_{self._counters[tag]}]"
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


@dataclass
class ReplacerMap:
    """A request-scoped, encrypted, TTL'd token->original map addressed by an
    unguessable capability handle (red-team F5).

    The map is encrypted at rest with AES-256-GCM (vetted ``cryptography`` lib).
    The plaintext map exists only transiently inside :meth:`reveal` while the
    caller holds it; at rest only the ciphertext + nonce are retained.  The
    ``handle`` is a 256-bit URL-safe random token — NOT ``request.id`` — and is
    the only key that retrieves the map; it is bound to ``detokenize_rbac_role``
    and is NEVER logged.
    """

    handle: str
    detokenize_rbac_role: str
    ttl_s: int
    _nonce: bytes
    _ciphertext: bytes
    _key: bytes
    _created_at: float
    _destroyed: bool = False

    @classmethod
    def create(
        cls,
        reverse_map: dict[str, str],
        *,
        detokenize_rbac_role: str,
        ttl_s: int = DEFAULT_MAP_TTL_S,
        now: Optional[float] = None,
    ) -> "ReplacerMap":
        """Mint a fresh map: unguessable handle + AES-256-GCM encryption.

        The handle and the encryption key are independent high-entropy secrets;
        possession of the handle alone does not decrypt the map (the key lives in
        the object held by the gateway, not in the handle)."""
        # F5: 256-bit unguessable, single-use capability handle. NOT request.id.
        handle = secrets.token_urlsafe(32)
        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        # Serialise the reverse map deterministically (token\x00value\x01...).
        # Raw originals are encrypted immediately and never held in plaintext at
        # rest on this object.
        blob = "\x01".join(f"{t}\x00{v}" for t, v in reverse_map.items()).encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, blob, handle.encode("ascii"))
        ttl = ttl_s if ttl_s and ttl_s > 0 else DEFAULT_MAP_TTL_S
        return cls(
            handle=handle,
            detokenize_rbac_role=detokenize_rbac_role,
            ttl_s=ttl,
            _nonce=nonce,
            _ciphertext=ciphertext,
            _key=key,
            _created_at=now if now is not None else time.monotonic(),
        )

    def _expired(self, now: Optional[float] = None) -> bool:
        t = now if now is not None else time.monotonic()
        return self._destroyed or (t - self._created_at) >= self.ttl_s

    def reveal(self, handle: str, *, now: Optional[float] = None) -> dict[str, str]:
        """Decrypt + return the token->original map for an authorised caller.

        The caller MUST present the exact capability handle (F5) — a mismatched
        handle fails the AEAD auth (the handle is the AAD).  An expired/destroyed
        map fails closed (:class:`ReplacerMapExpiredError`), never partial.
        """
        if self._expired(now):
            raise ReplacerMapExpiredError(
                "replacer map expired/destroyed — fail-closed (no partial restore)"
            )
        if not secrets.compare_digest(handle, self.handle):
            # Wrong handle — do not reveal. (Constant-time compare; the AEAD AAD
            # check below would also fail, but reject early + uniformly.)
            raise ReplacerMapExpiredError("replacer map handle mismatch — fail-closed")
        blob = AESGCM(self._key).decrypt(self._nonce, self._ciphertext, handle.encode("ascii"))
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

    @classmethod
    def from_assigner(cls, assigner: TokenAssigner, *, detokenize_rbac_role: str) -> "CorrespondenceTable":
        return cls(rows=assigner.reverse_map, detokenize_rbac_role=detokenize_rbac_role)

    def to_csv(self) -> str:
        """Render the table as a CSV the user can keep (token,original).

        This is the user's key — the pipeline delivers it over the RBAC'd channel
        and never writes it to an audit/log line."""
        import csv
        import io
        buf = io.StringIO()
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


# Token-shaped fragments the response path scans for: ``[TAG_n]``.
_TOKEN_RE_SRC = r"\[[A-Z0-9]+_\d+\]"


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

    (Per-request namespace salting + injection-classify-before-restore remain
    pipeline/Ogen concerns; this object owns the count + position mechanics — the
    ``bind_restore_to_egress_positions`` obligation the rego surfaces.)
    """

    _egress: dict[str, _EgressOccurrence] = field(default_factory=dict)

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

    def restore(self, response_text: str) -> tuple[str, list[str]]:
        """Restore tokens in an untrusted cloud response — count- AND position-bound.

        Returns ``(restored_text, flags)`` where ``flags`` lists tokens that were
        partially or wholly REFUSED restoration (over-restore beyond count budget,
        OR replay in a position inconsistent with egress provenance — L-02).  A
        non-empty ``flags`` list fails the round-trip closed in the pipeline.

        Each token instance in the response is examined IN PLACE: it is restored
        only if (a) the token's count budget is not yet exhausted AND (b) a
        position-binding context for this occurrence is still available (when the
        token was egress-bound to contexts).  Replays in attacker-chosen
        positions consume no budget and are LEFT AS THE TOKEN — so the
        namespace-dump attack restores nothing.
        """
        import re

        flags: list[str] = []
        # Remaining count budget + per-context budget for each token.
        count_left = {tok: occ.egress_count for tok, occ in self._egress.items()}
        ctx_left = {
            tok: dict(occ.contexts) for tok, occ in self._egress.items()
        }

        token_re = re.compile(_TOKEN_RE_SRC)

        def _replace(m: "re.Match[str]") -> str:
            tok = m.group(0)
            occ = self._egress.get(tok)
            if occ is None:
                # Unknown token — never guessed (§5.4 fail-closed).
                return tok
            # Count budget exhausted → over-restore; leave as token.
            if count_left.get(tok, 0) <= 0:
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
            return occ.original

        result = token_re.sub(_replace, response_text)
        return result, flags


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
