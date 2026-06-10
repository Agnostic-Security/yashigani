"""
Yashigani Document Enforcement — the DataMatch model + OPA decision input.

A :class:`DataMatch` is the single object the four document actions
(LOG / REDACT / PSEUDONYMIZE / BLOCK) consume (plan §3.1.1).  It carries the
data class, a MASKED instance (raw sensitive values never leave the detector),
and full provenance (segment kind + location + char span).

This slice produces the ``DataMatch[]`` enumeration from the EXISTING PII
detector (plan §3.1.1: "reuses existing classifier + PII module; no new
detection engine") and assembles the ``DocumentDecisionInput`` that the OPA
decision point consumes (plan §4.2).  Only the data-protection classes are in
scope; document-borne INJECTION is PARKED (rev 7, §A) and is NOT produced here.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from yashigani.documents.segment import Segment


@dataclass(frozen=True)
class DataMatch:
    """One sensitive/identifying match inside an extracted segment.

    Mirrors the plan §3.1.1 ``DataMatch`` contract.  ``data_class`` is a
    namespaced string (e.g. ``"PII.EMAIL"``) so the OPA policy can match
    per-class.  ``instance`` is ALWAYS the masked value — raw PII never appears
    here (audit-safe, ASVS V7/V8).  ``qi`` flags quasi-identifiers (red-team
    F2); in this slice it defaults False (the QI tagger is a next-slice,
    net-new detector — TODO below) so the field/contract is stable now.
    """

    data_class: str        # e.g. "PII.EMAIL", "PII.CREDIT_CARD"
    qi: bool                # F2: quasi-identifier (re-identifies in combination)
    instance: str           # MASKED value — never raw
    location: str           # provenance: "<kind>:<segment.location>:<span>"
    char_start: int
    char_end: int
    # PART 2 (Laura D1): how the downstream model must USE this value —
    # REFERENCE_ONLY (safe to opaque-tokenise) vs OPERATE_ON (the model computes
    # on / validates it, so an opaque blob makes it hallucinate).  Defaults to
    # the empty string for back-compat; the pipeline sets it during enumeration.
    field_role: str = ""

    def as_opa_match(self) -> dict:
        """Shape consumed by the OPA ``document.matches[]`` input (plan §4.2)."""
        return {
            "data_class": self.data_class,
            "qi": self.qi,
            "instance": self.instance,
            "location": self.location,
            # PART 2: carried so a policy can route operate-on fields (local /
            # keep / generalise) instead of blobbing them to the cloud.
            "field_role": self.field_role,
        }


@dataclass
class DocumentDecisionInput:
    """The ``input.document`` object the OPA decision point consumes (plan §4.2).

    The gateway POPULATES this from extraction + enumeration (the correct trust
    boundary — the attacker does not write rego input directly, red-team F9).
    ``extraction_complete`` + ``matches`` together carry the fail-closed
    guarantee: ``matches=[]`` is trustworthy ONLY when ``extraction_complete``
    is True (plan §6.1).
    """

    format: str
    extraction_complete: bool
    segment_kinds: list[str]
    matches: list[DataMatch] = field(default_factory=list)
    # record_count drives the F2 small-set re-identification gate; for a
    # flat/tabular doc it is the row count.  0 until a richer extractor sets it.
    record_count: int = 0
    # Capability-token slot for the replacer map (F5).  Minted by the gateway,
    # never request.id, never logged.  Populated by the PSEUDONYMIZE slice.
    reid_handle: str = ""
    # Formats where REDACT / PSEUDONYMIZE re-render a coherent artefact THIS
    # version (plan §5.2 / §5.5).  False for txt/csv in THIS slice because the
    # re-render machinery (B4) is a later slice — so a REDACT/PSEUDONYMIZE
    # decision fails closed to BLOCK until then.
    redaction_supported: bool = False
    pseudonymize_supported: bool = False

    def to_opa_input(self) -> dict:
        """Render the OPA ``input.document`` object (plan §4.2)."""
        return {
            "format": self.format,
            "extraction_complete": self.extraction_complete,
            "segment_kinds": self.segment_kinds,
            "matches": [m.as_opa_match() for m in self.matches],
            "record_count": self.record_count,
            "reid_handle": self.reid_handle,
            "redaction_supported": self.redaction_supported,
            "pseudonymize_supported": self.pseudonymize_supported,
            # max_sensitivity is fail-closed: an incomplete extraction is
            # treated as the highest sensitivity by the policy (plan §6.1).
            "max_sensitivity": "RESTRICTED" if not self.extraction_complete else "INTERNAL",
        }


def location_for(segment: Segment, char_start: int, char_end: int) -> str:
    """Build a precise provenance string for a match within a segment."""
    return f"{segment.kind.value}:{segment.location}:span={char_start}-{char_end}"
