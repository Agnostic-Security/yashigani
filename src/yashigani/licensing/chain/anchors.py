"""
Yashigani licence-hardening v2 — trust-anchor SET.

Ref: design doc "MASTER-ROTATION READINESS" (LOCKED DECISIONS) +
"Key-management & KMS-migration abstraction" §3.

    "master trust is an anchor SET, not a single key. The build embeds a
    list of master anchors, each {pubkey, alg, status: active|retiring|
    retired, added}. The verifier validates a leaf_cert against ANY active
    anchor in the set. Must support N>=2 concurrently (old+new during
    rotation; ECDSA + PQC)."

Status semantics (judgement call — see docstring on AnchorSet.trusted_anchors
and the Phase A delivery report):
    active   — trusted for verification AND the anchor new issuance should
               use / new builds should embed as their primary.
    retiring — STILL TRUSTED for verification (a leaf_cert signed under a
               retiring anchor must keep validating) but no longer used for
               NEW issuance. This is what makes the rotation lifecycle
               non-breaking: "mark M1 retiring -> once all migrated,
               retired" only becomes a hard failure at the retired step.
               Confirmed against the design's own test matrix: "M1-license
               on build after M1 retired=FAIL->re-issue" names RETIRED, not
               RETIRING, as the failure trigger.
    retired  — NOT trusted. Dropped from new builds. A leaf_cert chaining
               only to a retired anchor fails to validate.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

from yashigani.licensing.chain.algorithms import Alg, verify_signature
from yashigani.licensing.chain.leaf_cert import LeafCert


class AnchorStatus(str, Enum):
    ACTIVE = "active"
    RETIRING = "retiring"
    RETIRED = "retired"


@dataclass(frozen=True)
class TrustAnchor:
    """One master public key in the embedded trust-anchor set.

    anchor_id is a stable identifier (e.g. a fingerprint or serial) used by
    the kill-list's "master-anchor entries" (LOCKED DECISIONS: "the
    kill-list carries master-anchor entries (alongside leaf + licence
    serials)") — Phase B/Su territory; defined here so the field exists in
    the shared schema.
    """

    anchor_id: str
    pubkey_pem: str
    alg: Alg
    status: AnchorStatus
    added: datetime

    def __post_init__(self) -> None:
        if self.added.tzinfo is None:
            raise ValueError("added must be timezone-aware (UTC)")


class AnchorSet:
    """An embedded, ordered collection of TrustAnchor entries.

    Supports N>=2 concurrently (design requirement) and mixed algorithms
    (ECDSA today, PQC once ml-dsa-87 lands — "PQC-master add=purely
    additive" per the design's test matrix).
    """

    def __init__(self, anchors: list[TrustAnchor]) -> None:
        ids = [a.anchor_id for a in anchors]
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate anchor_id in anchor set: {ids}")
        self._anchors = list(anchors)

    def __len__(self) -> int:
        return len(self._anchors)

    def all_anchors(self) -> list[TrustAnchor]:
        return list(self._anchors)

    def active_anchors(self) -> list[TrustAnchor]:
        """Strictly status==ACTIVE. This is the set NEW builds should embed
        as their primary trust set and the set new issuance should sign
        under (design: 'issue new/renewing clients under M2')."""
        return [a for a in self._anchors if a.status == AnchorStatus.ACTIVE]

    def trusted_anchors(self) -> list[TrustAnchor]:
        """ACTIVE + RETIRING — the verification-time trust set. A leaf_cert
        signed under a RETIRING anchor must still validate (rotation grace
        period); only RETIRED anchors are excluded. See module docstring for
        the semantics judgement call and its citation in the design's own
        rotation test matrix."""
        return [a for a in self._anchors if a.status in (AnchorStatus.ACTIVE, AnchorStatus.RETIRING)]

    def get(self, anchor_id: str) -> Optional[TrustAnchor]:
        for a in self._anchors:
            if a.anchor_id == anchor_id:
                return a
        return None

    def validate_leaf_cert(self, leaf_cert: LeafCert, leaf_cert_sig: bytes) -> Optional[TrustAnchor]:
        """Try leaf_cert_sig against every trusted (active+retiring) anchor.

        Returns the matching TrustAnchor on success, or None if no trusted
        anchor's signature validates (including the case where the ONLY
        matching key material belongs to a RETIRED anchor — retired anchors
        are never tried).

        Does NOT check leaf_cert.not_before/not_after — those are
        SIGNING-SIDE ONLY per the design ("Windows are SIGNING-SIDE ONLY —
        never checked at verify-time"). A leaf_cert with an expired window
        that carries a valid signature from a trusted anchor MUST still
        validate here; expiry-style verify-time gating belongs on the
        LICENCE's own term (Phase B), never on the leaf window.

        Algorithm-agile: dispatches per-anchor by anchor.alg, so a mixed
        ECDSA+PQC anchor set (the PQC-root-add scenario) is tried
        transparently — an AlgorithmUnavailableError from one anchor (e.g.
        an ml-dsa-87 anchor before that backend lands) does not stop other
        anchors from being tried; it propagates only if NO anchor could
        even attempt verification productively... actually: we let it
        propagate per-anchor-attempt exceptions other than InvalidSignature
        bubble up naturally via verify_signature()'s contract, EXCEPT we
        explicitly skip (not fail) anchors whose algorithm has no live
        backend yet, since "PQC-master add=purely additive" must not break
        verification against the OTHER (e.g. still-ECDSA) anchors.
        """
        from yashigani.licensing.chain.algorithms import AlgorithmUnavailableError
        from yashigani.licensing.chain.canonical import leaf_cert_signing_digest

        digest = leaf_cert_signing_digest(leaf_cert.to_canonical_dict())
        for anchor in self.trusted_anchors():
            try:
                if verify_signature(anchor.alg, anchor.pubkey_pem, digest, leaf_cert_sig):
                    return anchor
            except AlgorithmUnavailableError:
                # PQC-master add=purely additive: an anchor whose alg has no
                # live backend yet must not break validation against other
                # (e.g. still-ECDSA) anchors in the same set.
                continue
        return None
