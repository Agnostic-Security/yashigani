"""
Yashigani Document Enforcement — the document inspection pipeline (front-end
into the EXISTING inspection engines).

Flow (plan §4.2 — reuse, don't duplicate):

    document bytes
       │  size/cap guard + magic-byte sniff (detection.py, fail-closed F8)
       ▼
    [ EXTRACTOR ]  → segments + provenance (extractor.py; fail-closed §6.1)
       │
       ▼
    [ EXISTING PII detector, per-segment ]  → DataMatch[] enumeration (§3.1.1)
       │
       ▼
    [ OPA-ready DocumentDecisionInput ]  (datamatch.py — handed to the policy)
       │
       ▼
    [ ACTION ]  LOG (end-to-end here) / BLOCK (wired) /
                REDACT, PSEUDONYMIZE (stubbed fail-closed → BLOCK)

This module DOES NOT re-implement detection — it calls the existing
``yashigani.pii.PiiDetector`` per segment (plan §3.1.1).  Document-borne
INJECTION is PARKED (rev 7) and is NOT classified here.

Fail-closed (plan §6.1, NON-NEGOTIABLE): ANY extraction error, over-cap,
polyglot, or unavailable-format → ``DISPOSITION_BLOCK`` with a precise reason.
``extraction_complete=False`` likewise forces a fail-closed disposition even
if no matches were found ("matches=[] is trustworthy only when extraction is
complete", F9).
"""
from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional


def secrets_compare(a: str, b: str) -> bool:
    """Constant-time string compare (doc_hash binding check)."""
    return hmac.compare_digest(a, b)

from yashigani.documents.datamatch import (
    DataMatch,
    DocumentDecisionInput,
    location_for,
)
from yashigani.documents.extractor import (
    DocumentExtractionError,
    DocumentTooLargeError,
    ExtractorNotAvailableError,
    ExtractorRegistry,
    UnsupportedFormatError,
)
from yashigani.documents.field_role import (
    classify_field_role,
    is_operate_on_sensitive,
)
from yashigani.documents.pseudonymize import (
    DEFAULT_MAP_TTL_S,
    CorrespondenceTable,
    EchoEgressError,
    ModeBRoundTrip,
    ReplacerMap,
    TokenAssigner,
    build_modeb_roundtrip,
    build_pseudonymize_plan,
    build_redact_plan,
)
from yashigani.documents.qi_context import header_driven_matches
from yashigani.documents.residual_proof import residual_substring_hit
from yashigani.documents.segment import ExtractionResult, Segment, SegmentKind
from yashigani.documents.token_scheme import (
    compute_doc_hash,
    load_deployment_secret,
    token_matches_doc,
)
from yashigani.pii.detector import PiiDetector, PiiMode, _mask

logger = logging.getLogger(__name__)


# Document-level dispositions (mirror the OPA action vocabulary, plan §5.0).
DISPOSITION_LOG = "LOG"
DISPOSITION_REDACT = "REDACT"
DISPOSITION_PSEUDONYMIZE = "PSEUDONYMIZE"
DISPOSITION_BLOCK = "BLOCK"
#: PART 2 (Laura D1): the document carries an operate-on sensitive field that an
#: opaque blob would make the cloud hallucinate, so it must NOT go to the cloud —
#: route the whole document + its agent call to a LOCAL model instead (reuse the
#: existing sensitivity→local-model routing).  A document-level disposition, not
#: a per-span transform.
DISPOSITION_ROUTE_LOCAL = "ROUTE_LOCAL"

#: PART 2 routing policy for operate-on sensitive fields on a CLOUD-bound
#: (mode-B) PSEUDONYMIZE.  Conservative default = ROUTE_LOCAL (never silent-blob).
OPERATE_ON_ROUTE_LOCAL = "route_local"   # send the whole doc to the local model
OPERATE_ON_BLOCK = "block"               # fail-closed if no local route
OPERATE_ON_ALLOW_BLOB = "allow_blob"     # explicit opt-in: tokenise anyway (unsafe)

#: Formats with proven regenerate-from-cleaned-content re-render this version
#: (plan §5.2 / §5.5).  A REDACT/PSEUDONYMIZE decision on any OTHER format fails
#: closed to BLOCK (redaction_supported / pseudonymize_supported = False).
_RENDER_SUPPORTED_FORMATS = frozenset({"txt", "csv", "docx", "xlsx", "pptx", "pdf"})

#: Default RBAC role permitted to de-tokenize / receive the mode-A table (the
#: demo rego default; operator-overridable).  Mirrors the rego ``_detok_role``.
DEFAULT_DETOKENIZE_ROLE = "doc-pseudonymize-reverser"


@dataclass
class DocumentInspectionResult:
    """Outcome of inspecting one document."""

    request_id: str
    disposition: str                       # LOG | REDACT | PSEUDONYMIZE | BLOCK
    extraction_complete: bool
    detected_format: str
    matches: list[DataMatch] = field(default_factory=list)
    # The OPA-ready input the gateway would hand to the policy (plan §4.2).
    opa_input: Optional[dict] = None
    # Precise reason for a BLOCK (audit + layman alert).
    block_reason: Optional[str] = None
    audit_fields: dict = field(default_factory=dict)
    # The bytes to forward.  For LOG this is the original document (allow +
    # audit); for REDACT/PSEUDONYMIZE the freshly re-rendered artefact; None for
    # BLOCK.
    forward_bytes: Optional[bytes] = None
    # --- PSEUDONYMIZE outputs (None for other dispositions) ---------------
    #: The replacer map (crown jewel — F5).  Held request-scoped, encrypted,
    #: TTL'd.  ``handle`` is the unguessable capability; the map itself is never
    #: logged.  Present for both modes; in mode B the gateway drives the round-
    #: trip from it, in mode A it backs the correspondence table.
    replacer_map: Optional["ReplacerMap"] = None
    #: Mode-A artefact: the token->original correspondence table delivered to the
    #: user over the RBAC'd channel (the user's re-identification key, §5.3.1).
    correspondence_table: Optional["CorrespondenceTable"] = None
    #: The PSEUDONYMIZE delivery mode actually applied ("A" | "B").
    pseudonymize_mode: Optional[str] = None
    #: The per-file salt (SHA-256 of the ORIGINAL document bytes) the opaque
    #: tokens were derived under.  Stored in the mapping-file header and used by
    #: :meth:`DocumentInspectionPipeline.verify_integrity` to confirm a tokenised
    #: output + its mapping belong to the original (and to reject a cross-file
    #: splice).  Not a secret (it is a hash of bytes the holder already has), so
    #: it MAY be carried in the audit event as a correlation/integrity field.
    doc_hash: Optional[str] = None
    #: Which salt scope the opaque tokens were derived under: ``"file"`` (default,
    #: per-file isolation — the same value tokenises differently across files) or
    #: ``"set"`` (a shared set salt — the same value tokenises consistently across
    #: the operator-defined set, REDUCING per-file isolation).  Surfaced so the
    #: operator can SEE the isolation level in the verdict viewer.  Never carries
    #: the salt value itself (only the scope name) — the salt stays opaque.
    salt_scope: str = "file"
    # --- PART 2 (Laura D1) field-role routing -----------------------------
    #: True when the document carries an operate-on SENSITIVE field that an opaque
    #: blob would make the cloud hallucinate, so it was NOT tokenised to the
    #: cloud — the document must be routed to the LOCAL model instead.  Drives the
    #: ``DISPOSITION_ROUTE_LOCAL`` disposition.
    route_local: bool = False
    #: The operate-on sensitive data classes that forced the routing decision
    #: (audit / layman-alert breadcrumb; class names only, never values).
    operate_on_classes: list[str] = field(default_factory=list)
    #: Mode-B artefact (F3 / L-02): the request-scoped round-trip holder — the
    #: PositionBinder primed with the egress frame + provenance, wrapping the
    #: encrypted/TTL'd ReplacerMap.  The gateway holds it keyed by the map handle
    #: and calls :meth:`DocumentInspectionPipeline.restore_modeb_response` on the
    #: response path.  None for mode A / non-PSEUDONYMIZE.  The map is never
    #: surfaced; only the binder's cleared restorations ever yield cleartext.
    mode_b_roundtrip: Optional["ModeBRoundTrip"] = None


@dataclass
class ModeBRestoreResult:
    """Outcome of restoring an untrusted mode-B cloud/upstream response (F3 / L-02).

    ``restored`` is True only on a clean restore (no flags, no echo).  When
    ``echo_rejected`` is True the response was a verbatim echo of the egress frame
    and NOTHING was restored (``restored_text`` is the unchanged tokenized
    response).  When ``flags`` is non-empty the binder refused some tokens
    (foreign position / over-restore / namespace-harvest) — the caller treats the
    round-trip as tainted and alerts."""

    request_id: str
    restored_text: str
    restored: bool
    echo_rejected: bool
    flags: list[str] = field(default_factory=list)
    audit_fields: dict = field(default_factory=dict)


@dataclass
class IntegrityVerifyResult:
    """Outcome of :meth:`DocumentInspectionPipeline.verify_integrity`.

    ``ok`` is True only when the mapping's recorded salt matches the recomputed
    SHA-256 of the original bytes AND every token re-derives under that salt + the
    deployment secret (no foreign-salt / cross-file-splice tokens)."""

    ok: bool
    salt_match: bool
    actual_doc_hash: str
    foreign_tokens: list[str] = field(default_factory=list)
    audit_fields: dict = field(default_factory=dict)


class DocumentInspectionPipeline:
    """Channel-agnostic document front-end into the existing PII enumeration.

    Parameters
    ----------
    registry:
        The :class:`ExtractorRegistry` (caps live here).
    pii_detector:
        The EXISTING PII detector.  Defaults to a LOG-mode detector over all
        types — the document path uses it purely for enumeration (the action
        is decided by disposition, not by the detector's mode).
    on_audit:
        Audit sink ``(event_name, fields) -> None`` — reuses the gateway's
        existing audit callback shape (see InspectionPipeline.on_audit).
    """

    def __init__(
        self,
        registry: Optional[ExtractorRegistry] = None,
        pii_detector: Optional[PiiDetector] = None,
        on_audit: Optional[Callable[[str, dict], None]] = None,
        small_set_threshold: int = 20,
        small_set_escalation: bool = True,
    ) -> None:
        self._registry = registry or ExtractorRegistry()
        # LOG mode: enumerate only; never mutate text in the detector — the
        # document path owns the action decision (LOG/REDACT/PSEUDONYMIZE/BLOCK).
        self._pii = pii_detector or PiiDetector(mode=PiiMode.LOG)
        # Opaque-token deployment secret, sourced ONCE from the existing gateway
        # secret mechanism (/run/secrets / KMS).  None → salt-only keying
        # fallback (still per-file-unique + opaque; keyed form preferred).  Read
        # at construction so a per-request hot path never touches the filesystem;
        # never logged.
        self._pseudonymize_secret = load_deployment_secret()
        if self._pseudonymize_secret is None:
            # DP-Y-002 §3.1 — secret is MANDATORY on the PSEUDONYMIZE path.
            # The published token-security property requires a keyed HMAC whose
            # key is NOT derivable from the source document alone.  Without a
            # deployment secret the key would fall back to the per-file salt
            # (doc_hash = SHA-256 of the original bytes), which is computable by
            # ANY holder of the source document — voiding the claimed property.
            # Warn loudly at startup so operators see this in logs; the
            # _pseudonymize() path enforces it fail-closed at request time.
            logger.warning(
                "PSEUDONYMIZE deployment secret NOT provisioned "
                "(%s / %s). Any PSEUDONYMIZE operation will be REFUSED "
                "fail-closed (DP-Y-002 §3.1). Run install.sh to provision "
                "the secret.",
                "YASHIGANI_DOCUMENT_PSEUDONYMIZE_SECRET",
                "/run/secrets/document_pseudonymize_secret",
            )
        self._on_audit = on_audit or (lambda name, data: None)
        # F2 small-set re-identification threshold (mirrors the rego default).
        self._small_set_threshold = small_set_threshold
        # F2 small-set escalation toggle (mirrors a policy's small_set_escalation
        # flag; default ON — fail-closed for re-identifiable small sets, L-01).
        self._small_set_escalation_enabled = small_set_escalation

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect(
        self,
        data: bytes,
        declared_mime: str,
        request_id: str,
        *,
        requested_action: str = DISPOSITION_LOG,
        pseudonymize_mode: str = "A",
        detokenize_rbac_role: str = DEFAULT_DETOKENIZE_ROLE,
        map_ttl_s: int = DEFAULT_MAP_TTL_S,
        operate_on_routing: str = OPERATE_ON_ROUTE_LOCAL,
        set_salt: Optional[str] = None,
        requester_identity: str = "",
        tenant: str = "",
    ) -> DocumentInspectionResult:
        """Inspect a document end-to-end.

        ``requested_action`` is the action a policy/operator asked for.  All four
        actions are wired: LOG (allow + audit), BLOCK (fail-safe), REDACT
        (irreversible re-render), PSEUDONYMIZE (reversible token re-render).  The
        re-render runs in the SAME jail as extraction (red-team F6) — never in the
        gateway process.

        ``pseudonymize_mode`` selects mode A (deliver the user the correspondence
        table — default) or B (internal vault round-trip; position-binding wired).

        ``set_salt`` is the **set-scoped-salt** hook (salt-parameterised assigner).
        When ``None`` (the default) the PSEUDONYMIZE path derives tokens under the
        per-FILE salt ``doc_hash = SHA-256(original bytes)`` — maximum isolation,
        the same value tokenises DIFFERENTLY across files.  When an operator has
        defined a "document set" that should share a salt (so the same value
        tokenises CONSISTENTLY across that defined set for legitimate cross-file
        correlation), the gateway passes that set's salt here; it replaces the
        per-file salt as the HMAC salt.  This REDUCES per-file isolation (a value's
        token is now recognisable across every file in the set) and is opt-in only;
        the engine never widens the salt scope on its own.  The set salt is an
        opaque high-entropy string minted + custodied by the operator's set store,
        never the set name (so the token still leaks nothing about the set).
        """
        # --- Extract (fail-closed on every error) -------------------------
        try:
            extraction = self._registry.extract(data, declared_mime)
        except DocumentTooLargeError as exc:
            return self._block(request_id, f"document over cap: {exc}", detected="oversize")
        except ExtractorNotAvailableError as exc:
            return self._block(
                request_id, f"format not yet supported (fail-closed): {exc}",
                detected="unavailable_format",
            )
        except UnsupportedFormatError as exc:
            return self._block(
                request_id, f"unsupported/ambiguous format: {exc}",
                detected="unsupported",
            )
        except DocumentExtractionError as exc:
            return self._block(request_id, f"extraction failed: {exc}", detected="error")
        except Exception as exc:  # pragma: no cover - defensive
            # Unexpected extractor failure is STILL fail-closed — we never pass
            # a document we could not fully process (plan §6.1).
            logger.exception("document extraction raised unexpectedly")
            return self._block(request_id, f"unexpected extraction error: {exc!r}", detected="error")

        # --- Enumerate DataMatch[] over EVERY segment (existing PII engine) -
        matches, originals = self._enumerate(extraction)

        fmt = extraction.detected_format
        supported = fmt in _RENDER_SUPPORTED_FORMATS
        decision_input = DocumentDecisionInput(
            format=fmt,
            extraction_complete=extraction.extraction_complete,
            segment_kinds=extraction.segment_kinds,
            matches=matches,
            record_count=self._record_count(extraction),
            redaction_supported=supported,
            pseudonymize_supported=supported,
        )
        opa_input = decision_input.to_opa_input()

        # --- Fail-closed: incomplete extraction never passes (F9/§6.1) -----
        if not extraction.extraction_complete:
            return self._block(
                request_id,
                "extraction incomplete — uninspectable parts present, failing closed",
                detected=extraction.detected_format,
                matches=matches,
                opa_input=opa_input,
            )

        # --- Dispatch the action ------------------------------------------
        action = (requested_action or DISPOSITION_LOG).upper()
        if action == DISPOSITION_LOG:
            return self._log(request_id, data, extraction, matches, opa_input)
        if action == DISPOSITION_BLOCK:
            return self._block(
                request_id, "policy requested BLOCK",
                detected=extraction.detected_format, matches=matches, opa_input=opa_input,
            )
        if action == DISPOSITION_ROUTE_LOCAL:
            # PART 2 (Laura D1): OPA decided the field-role escalation — route the
            # whole document to the LOCAL model (forward the ORIGINAL bytes; the
            # values stay in-estate, no opaque blob bound for the cloud).  OPA is
            # the decision source of truth; the in-_pseudonymize seam below stays
            # as the fail-closed backstop for when OPA is unreachable.
            operate_on = sorted({
                m.data_class for m in matches
                if is_operate_on_sensitive(m.data_class)
            })
            return self._route_local(
                request_id, data, extraction, matches, opa_input, operate_on,
            )
        if action == DISPOSITION_REDACT:
            return self._redact(
                request_id, data, extraction, matches, originals, opa_input,
            )
        if action == DISPOSITION_PSEUDONYMIZE:
            return self._pseudonymize(
                request_id, data, extraction, matches, originals, opa_input,
                mode=pseudonymize_mode,
                detokenize_rbac_role=detokenize_rbac_role,
                map_ttl_s=map_ttl_s,
                operate_on_routing=operate_on_routing,
                set_salt=set_salt,
                requester_identity=requester_identity,
                tenant=tenant,
            )
        # Unknown action → fail-closed.
        return self._block(
            request_id, f"unknown action '{action}' — failing closed",
            detected=extraction.detected_format, matches=matches, opa_input=opa_input,
        )

    # ------------------------------------------------------------------
    # Enumeration (reuse existing PII detector — plan §3.1.1)
    # ------------------------------------------------------------------

    #: PII types that are quasi-identifiers (re-identify in combination — F2).
    #: A QI match on a small record set escalates the disposition (§5.3c).
    #: Broadened (L-01): DOB, phone, IP, National Insurance and postal address
    #: all re-identify a small structured set when they co-occur per row.
    _QI_TYPES = frozenset({
        "DATE_OF_BIRTH", "PHONE", "IP_ADDRESS",
        "NATIONAL_INSURANCE", "POSTAL_ADDRESS",
    })

    def _enumerate(
        self, extraction: ExtractionResult
    ) -> tuple[list[DataMatch], dict[str, str]]:
        """Run the EXISTING PII detector per segment incl. hidden/metadata, then
        augment with header-driven column-semantic identifying classes (L-01/F2).

        Returns ``(matches, originals)`` where ``originals`` maps
        ``match.location -> raw matched substring``.  The raw substring is needed
        ONLY to drive the re-render (find-and-transform in the jail) and never
        appears in an audit/log line — the :class:`DataMatch` carries only the
        masked instance (F12).  ``qi`` is set for quasi-identifier classes (F2).

        Two passes, de-duplicated by ``(location, char-span)``:

          1. **value-only** — the existing regex PII detector, per segment
             (email/phone/PAN/IBAN/NHS/NI/postcode etc.);
          2. **header-driven** — column-semantic classes whose value has no
             distinctive lone-cell form (DOB column, CVV, expiry,
             cardholder/full-name) recovered from the spreadsheet header
             (:mod:`yashigani.documents.qi_context`).  This is the QI breadth
             that makes PSEUDONYMIZE tokenize EVERY identifying column, not just
             name+email, and that feeds the small-set re-identification gate.
        """
        matches: list[DataMatch] = []
        originals: dict[str, str] = {}

        # --- Pass 2 FIRST: header-driven column-semantic detection --------
        # These cover the WHOLE cell (span 0..len) for columns whose value has
        # no distinctive lone-cell form (DOB column, CVV, expiry, cardholder/
        # full-name) — and supersede any value-only sub-match inside the same
        # cell (e.g. the inner postcode inside a classified address cell).
        header_matches = header_driven_matches(extraction.segments)
        covered_cells: set[str] = set()
        for cm in header_matches:
            seg = cm.segment
            covered_cells.add(seg.location)
            loc = location_for(seg, cm.char_start, cm.char_end)
            matches.append(
                DataMatch(
                    data_class=cm.data_class,
                    qi=cm.qi,
                    instance=_mask(seg.text[cm.char_start:cm.char_end]),
                    location=loc,
                    char_start=cm.char_start,
                    char_end=cm.char_end,
                    field_role=classify_field_role(cm.data_class).value,
                )
            )
            originals[loc] = seg.text[cm.char_start:cm.char_end]

        # --- Pass 1: value-only regex detection (per segment) -------------
        # Skip cells fully covered by a header-driven whole-cell match so we do
        # not double-count (a header-classified address cell is one match, not
        # an address match plus an inner-postcode match).
        for seg in extraction.segments:
            if seg.location in covered_cells:
                continue
            result = self._pii.detect(seg.text)
            for f in result.findings:
                loc = location_for(seg, f.start, f.end)
                is_qi = f.pii_type.value in self._QI_TYPES
                data_class = f"PII.{f.pii_type.value}"
                matches.append(
                    DataMatch(
                        data_class=data_class,
                        qi=is_qi,
                        instance=f.masked_value,
                        location=loc,
                        char_start=f.start,
                        char_end=f.end,
                        field_role=classify_field_role(data_class).value,
                    )
                )
                # The raw substring (host-side only) for the re-render transform.
                originals[loc] = seg.text[f.start:f.end]
        return matches, originals

    @staticmethod
    def _record_count(extraction: ExtractionResult) -> int:
        """Population size of the record set (F2 small-set gate).

        The record count is the number of distinct DATA rows in the table
        (header row excluded), across BOTH provenance schemes:

          * CSV  → ``row=R,col=C``      → distinct ``R``;
          * xlsx → ``sheet=Title!B12``  → distinct ``(sheet, row-number)``.

        (L-06: counting only ``row=`` provenance left ``record_count == 0`` for
        the canonical xlsx spreadsheet, so the small-set gate was blind to the
        exact format the demo uses.  Both schemes are now counted.)  For flat
        text the count is 0 (not a record set).  Parsed from segment provenance
        without re-reading the document; the lowest row per sheet is treated as
        the header and excluded so a 30-data-row sheet counts as 30, not 31.
        """
        import re as _re

        csv_rows: set[str] = set()
        xlsx_rows: set[tuple[str, int]] = set()
        xlsx_min: dict[str, int] = {}
        cell_re = _re.compile(r"sheet=(?P<sheet>[^!]+)!(?P<col>[A-Z]+)(?P<row>\d+)")
        for seg in extraction.segments:
            if seg.location.startswith("row="):
                csv_rows.add(seg.location.split(",", 1)[0])
                continue
            m = cell_re.search(seg.location)
            if m:
                sheet = m.group("sheet")
                row = int(m.group("row"))
                xlsx_rows.add((sheet, row))
                if sheet not in xlsx_min or row < xlsx_min[sheet]:
                    xlsx_min[sheet] = row

        # CSV: rows are "row=1".."row=N"; drop the header row ("row=1") if present.
        csv_count = len(csv_rows)
        if "row=1" in csv_rows:
            csv_count -= 1
        # xlsx: drop the header (lowest) row of each sheet.
        xlsx_count = sum(
            1 for (sheet, row) in xlsx_rows if row != xlsx_min.get(sheet)
        )
        return csv_count + xlsx_count

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def _log(
        self,
        request_id: str,
        data: bytes,
        extraction: ExtractionResult,
        matches: list[DataMatch],
        opa_input: dict,
    ) -> DocumentInspectionResult:
        """LOG: allow the document through, but record EVERY match (with
        provenance) to the audit event (plan §5.0)."""
        audit = {
            "event_type": "DOCUMENT_INSPECTED",
            "request_id": request_id,
            "disposition": DISPOSITION_LOG,
            "detected_format": extraction.detected_format,
            "extraction_complete": extraction.extraction_complete,
            "segment_count": len(extraction.segments),
            "segment_kinds": extraction.segment_kinds,
            "match_count": len(matches),
            # Full per-match record (masked instances only — never raw, F12).
            "matches": [m.as_opa_match() for m in matches],
        }
        self._on_audit("DOCUMENT_INSPECTED", audit)
        return DocumentInspectionResult(
            request_id=request_id,
            disposition=DISPOSITION_LOG,
            extraction_complete=extraction.extraction_complete,
            detected_format=extraction.detected_format,
            matches=matches,
            opa_input=opa_input,
            audit_fields=audit,
            forward_bytes=data,  # LOG forwards the original document unchanged.
        )

    def _route_local(
        self,
        request_id: str,
        data: bytes,
        extraction: ExtractionResult,
        matches: list[DataMatch],
        opa_input: Optional[dict],
        operate_on_classes: list[str],
    ) -> DocumentInspectionResult:
        """PART 2 (Laura D1): route the whole document + its agent call to the
        LOCAL model instead of blobbing an operate-on sensitive field to the
        cloud.  This reuses the existing sensitivity→local-model routing seam (the
        document rides the rerouted call — plan §5.0 reroute-to-local); the
        gateway forwards the ORIGINAL bytes to the LOCAL route (the values never
        leave the estate, so they need no tokenisation), and the disposition tells
        the proxy to pin the local model.  We never silently feed the cloud a
        hallucination-prone blob."""
        audit = {
            "event_type": "DOCUMENT_ROUTED_LOCAL",
            "request_id": request_id,
            "disposition": DISPOSITION_ROUTE_LOCAL,
            "detected_format": extraction.detected_format,
            "match_count": len(matches),
            "matches": [m.as_opa_match() for m in matches],
            # Class names only — never values.
            "operate_on_classes": operate_on_classes,
            "reason": (
                "operate-on sensitive field present; opaque blob would make the "
                "cloud hallucinate — routed to the local model (PART 2)"
            ),
        }
        self._on_audit("DOCUMENT_ROUTED_LOCAL", audit)
        return DocumentInspectionResult(
            request_id=request_id,
            disposition=DISPOSITION_ROUTE_LOCAL,
            extraction_complete=extraction.extraction_complete,
            detected_format=extraction.detected_format,
            matches=matches,
            opa_input=opa_input,
            audit_fields=audit,
            # The LOCAL route receives the ORIGINAL bytes (values stay in-estate,
            # no broken blob).  The proxy pins the local model off route_local.
            forward_bytes=data,
            route_local=True,
            operate_on_classes=operate_on_classes,
        )

    # ------------------------------------------------------------------
    # REDACT / PSEUDONYMIZE — re-render in the jail (F6), assert no-residual.
    # ------------------------------------------------------------------

    def _assert_no_residual(
        self,
        output_segments: list[dict],
        originals: dict[str, str],
        *,
        request_id: str,
        fmt: str,
        opa_input: Optional[dict],
        matches: list[DataMatch],
    ) -> Optional[DocumentInspectionResult]:
        """Re-extract-the-output proof (Laura's gate): assert NO original matched
        value survives anywhere in the re-rendered artefact — body, hidden part,
        or metadata.  Returns a BLOCK result if ANY original leaked, else None.

        Two complementary checks; a hit on EITHER fails the document closed
        (L-03).  The original implementation used a raw byte-exact substring scan
        which Laura proved has false negatives under the normalisation the
        re-render + re-extract round-trip introduces (PDF newline-collapse /
        90-char wrap, homoglyph / Unicode normal form).  Both checks below are
        normalisation-resistant:

          1. **Normalised substring scan** — fold both the re-extracted output
             and each raw original to a canonical form (NFKC + homoglyph
             skeleton + whitespace/wrap collapse + casefold) before comparing, so
             a reformatted survivor of a KNOWN original is still found
             (:func:`residual_proof.residual_substring_hit`).

          2. **Detector re-pass over the OUTPUT** — re-run the same PII / QI
             detector over the output segments (not merely substring-match the
             known originals) and BLOCK if any data class we redacted/pseudonymised
             reappears.  This catches a value that survives in a form the literal
             scan can never reach — a different but still-recognised rendering of
             the same class.

        We never ship an artefact we could not prove clean."""
        output_text = "\n".join(str(s.get("text", "")) for s in output_segments)

        # --- Check 1: normalisation-resistant substring scan of known originals.
        for loc, original in originals.items():
            if original and residual_substring_hit(output_text, original):
                return self._block(
                    request_id,
                    f"re-render residual check FAILED: a matched value survived in "
                    f"the output artefact ({loc}, normalised) — refusing to ship, "
                    f"fail-closed",
                    detected=fmt, matches=matches, opa_input=opa_input,
                )

        # --- Check 2: re-run the detector over the OUTPUT and reject any data
        # class we acted on that reappears (surviving-but-reformatted value).
        # The classes we redacted/pseudonymised are exactly those in ``matches``;
        # a re-detected match of one of those classes in the output is a residual.
        acted_classes = {m.data_class for m in matches}
        if acted_classes:
            residual_loc = self._detect_residual_classes(
                output_segments, acted_classes
            )
            if residual_loc is not None:
                data_class, where = residual_loc
                return self._block(
                    request_id,
                    f"re-render residual check FAILED: a {data_class} value was "
                    f"re-detected in the output artefact ({where}) — the value "
                    f"survived in a reformatted form; refusing to ship, fail-closed",
                    detected=fmt, matches=matches, opa_input=opa_input,
                )
        return None

    def _detect_residual_classes(
        self, output_segments: list[dict], acted_classes: set[str]
    ) -> Optional[tuple[str, str]]:
        """Re-run the PII + QI detector over output segments; return the first
        ``(data_class, location)`` of an acted-on class that reappears, else None.

        L-03 detector-pass: a residual is not only a literal survivor of a known
        original — it is ANY value the detector still recognises as one of the
        classes we were supposed to strip.  We rebuild lightweight Segments from
        the worker's output dicts and run both detection passes (regex PII +
        header-driven column-semantic QI) the same way :meth:`_enumerate` does,
        so a QI class (DOB column, cardholder name) surviving by reflow is caught
        even though the lone-cell regex would not flag it."""
        out_segments: list[Segment] = []
        for s in output_segments:
            text = str(s.get("text", ""))
            if not text:
                continue
            kind_raw = str(s.get("kind", SegmentKind.BODY.value))
            try:
                kind = SegmentKind(kind_raw)
            except ValueError:
                kind = SegmentKind.BODY
            loc = str(s.get("location") or "output")
            out_segments.append(Segment(text=text, kind=kind, location=loc))

        # Pass A: header-driven column-semantic classes (QI breadth).
        for cm in header_driven_matches(out_segments):
            if cm.data_class in acted_classes:
                return cm.data_class, cm.segment.location

        # Pass B: regex PII detector per segment.
        for seg in out_segments:
            for f in self._pii.detect(seg.text).findings:
                data_class = f"PII.{f.pii_type.value}"
                if data_class in acted_classes:
                    return data_class, seg.location
        return None

    def _redact(
        self,
        request_id: str,
        data: bytes,
        extraction: ExtractionResult,
        matches: list[DataMatch],
        originals: dict[str, str],
        opa_input: dict,
    ) -> DocumentInspectionResult:
        """REDACT: irreversibly destroy every matched span + strip ALL hidden
        parts and metadata, re-render a fresh clean artefact in the jail (F6),
        then PROVE no residual by re-extracting the output."""
        fmt = extraction.detected_format
        if not matches:
            # Nothing to redact → still re-render to strip hidden/metadata? No —
            # a clean doc with no matches passes as LOG (forward original). REDACT
            # with zero matches is a no-op disposition → forward unchanged + audit.
            return self._log(request_id, data, extraction, matches, opa_input)

        plan = build_redact_plan(matches, originals)
        try:
            result = self._registry.render(
                data, fmt, job="redact", plan_b64=plan.to_b64(),
            )
        except Exception as exc:
            return self._block(
                request_id, f"REDACT re-render failed: {exc} — fail-closed",
                detected=fmt, matches=matches, opa_input=opa_input,
            )

        residual = self._assert_no_residual(
            result.output_segments, originals,
            request_id=request_id, fmt=fmt, opa_input=opa_input, matches=matches,
        )
        if residual is not None:
            return residual

        audit = {
            "event_type": "DOCUMENT_REDACTED",
            "request_id": request_id,
            "disposition": DISPOSITION_REDACT,
            "detected_format": fmt,
            "match_count": len(matches),
            "matches": [m.as_opa_match() for m in matches],
            "hidden_and_metadata_stripped": True,
            "no_residual_verified": True,
        }
        self._on_audit("DOCUMENT_REDACTED", audit)
        return DocumentInspectionResult(
            request_id=request_id,
            disposition=DISPOSITION_REDACT,
            extraction_complete=extraction.extraction_complete,
            detected_format=fmt,
            matches=matches,
            opa_input=opa_input,
            audit_fields=audit,
            forward_bytes=result.rendered_bytes,
        )

    def _small_set_escalation(self, matches: list[DataMatch], record_count: int) -> bool:
        """F2 small-set re-identification gate: escalate (→ BLOCK) when the record
        set is small AND quasi-identifiers are present.

        L-01 fix.  The previous gate only fired when a QI class was left
        **un-tokenized** — but the wired PSEUDONYMIZE path tokenizes EVERY
        detected class, so that residual set was always empty and the gate was
        structurally dead code (Laura, PROVEN).  The honest invariant, matching
        the production rego (``policy/document.rego`` ``_reid_escalation``: small
        set + a QI match present + escalation enabled), is that **consistent
        tokenization of a small structured record set is still re-identifiable by
        row co-occurrence** — tokenizing the name column while every row still
        carries DOB + postcode + NI re-identifies the subject by inference.  So
        the gate fires on a small set that carries quasi-identifiers at all, and
        the disposition escalates to BLOCK rather than ship false-assurance
        "pseudonymized" rows the cloud can trivially re-identify.

        Disabled when ``small_set_escalation`` is off (parity with a policy that
        opted out, mirroring the rego ``small_set_escalation == false`` path).
        """
        if not self._small_set_escalation_enabled:
            return False
        if record_count <= 0 or record_count > self._small_set_threshold:
            return False
        has_qi = any(m.qi for m in matches)
        return bool(matches) and has_qi

    def _pseudonymize(
        self,
        request_id: str,
        data: bytes,
        extraction: ExtractionResult,
        matches: list[DataMatch],
        originals: dict[str, str],
        opa_input: dict,
        *,
        mode: str,
        detokenize_rbac_role: str,
        map_ttl_s: int,
        operate_on_routing: str = OPERATE_ON_ROUTE_LOCAL,
        set_salt: Optional[str] = None,
        requester_identity: str = "",
        tenant: str = "",
    ) -> DocumentInspectionResult:
        """PSEUDONYMIZE: replace each matched value with a consistent reversible
        token (all QIs — F2), re-render in the jail (F6), vault the replacer map
        (F5), and emit the mode-A table / wire the mode-B binder.

        Fail-closed: an empty plan, a re-render failure, a residual leak, OR a
        small-set re-identification escalation (F2) → BLOCK.

        PART 2 (Laura D1) — field-role routing: when the document carries an
        operate-on SENSITIVE field (a currency amount, DOB, IBAN/PAN the model
        would compute on / validate), an opaque blob would make the cloud
        HALLUCINATE a plausible value and reason over the invention.  We therefore
        do NOT silently blob such a field to the cloud in ANY mode — per
        ``operate_on_routing`` we route the whole document to the LOCAL model
        (default), or fail-closed to BLOCK, or (only on explicit opt-in) tokenise
        anyway.  Mode B is the definite cloud round-trip; mode A forwards
        tokenised bytes that the caller may then submit to the cloud.  Both modes
        must honour the operate-on routing gate (DP-Y-002 §3.2)."""
        fmt = extraction.detected_format

        # DP-Y-002 §3.1 — deployment secret is MANDATORY on the PSEUDONYMIZE path.
        # The published property "an adversary with the tokenised output AND the
        # source document still cannot regenerate/confirm tokens without the secret"
        # is void when the key falls back to doc_hash (computable by any holder of
        # the source document).  Fail-closed: if no secret is provisioned, block
        # rather than mint doc_hash-keyed tokens that lack the claimed security
        # property.  The operator must provision the secret via install.sh or
        # YASHIGANI_DOCUMENT_PSEUDONYMIZE_SECRET / the default secret-file path.
        if self._pseudonymize_secret is None:
            return self._block(
                request_id,
                "PSEUDONYMIZE refused: deployment secret not provisioned "
                "(YASHIGANI_DOCUMENT_PSEUDONYMIZE_SECRET / "
                "/run/secrets/document_pseudonymize_secret). "
                "The keyed-HMAC token property requires a secret not derivable "
                "from the source document alone — fail-closed (DP-Y-002 §3.1). "
                "Run install.sh to provision the secret.",
                detected=fmt, matches=matches, opa_input=opa_input,
            )

        if not matches:
            return self._log(request_id, data, extraction, matches, opa_input)

        # PART 2 routing seam (Laura D1 / DP-Y-002 §3.2): an operate-on sensitive
        # field must not be silently blobbed to the cloud in ANY mode.  Mode B is
        # the definite cloud round-trip; mode A forwards tokenised bytes the caller
        # may then submit to the cloud.  Both modes honour this gate — an OPA policy
        # returning pseudonymize_mode:"A" for cloud egress cannot bypass the
        # operate-on protection.  Explicit OPERATE_ON_ALLOW_BLOB opt-in is required
        # to bypass; without it the document is routed local or blocked.
        operate_on = sorted({
            m.data_class for m in matches
            if is_operate_on_sensitive(m.data_class)
        })
        if operate_on and operate_on_routing != OPERATE_ON_ALLOW_BLOB:
            if operate_on_routing == OPERATE_ON_ROUTE_LOCAL:
                return self._route_local(
                    request_id, data, extraction, matches, opa_input, operate_on,
                )
            # Fail-closed: no local route available → BLOCK rather than blob.
            return self._block(
                request_id,
                "operate-on sensitive field present (an opaque blob would make "
                f"the cloud hallucinate): {', '.join(operate_on)} — fail-closed "
                "(no local route), not blobbed to cloud (PART 2 / Laura D1)",
                detected=fmt, matches=matches, opa_input=opa_input,
            )

        # F2 small-set gate (L-01): consistent tokenization of a SMALL structured
        # record set is still re-identifiable by row co-occurrence — tokenizing
        # the name column while every row still carries DOB/postcode/NI
        # re-identifies the subject by inference.  So a small set carrying
        # quasi-identifiers escalates to BLOCK rather than ship false-assurance
        # "pseudonymized" rows.  (Was dead code: the old gate required an
        # un-tokenized QI, which the wired path never produces.)
        record_count = self._record_count(extraction)
        if self._small_set_escalation(matches, record_count):
            return self._block(
                request_id,
                "re-identifiable small record set with quasi-identifiers — "
                "escalated to BLOCK (F2), fail-closed",
                detected=fmt, matches=matches, opa_input=opa_input,
            )

        # Opaque, per-file-salted token assigner (DECIDED 2026-06-10):
        # token = base32(HMAC-SHA256(deployment_secret, doc_hash || value))[:N].
        # doc_hash = SHA-256(ORIGINAL document bytes) = the per-file salt, so the
        # same value in two documents derives different tokens (cross-file
        # correlation defeated) and every token binds to THIS document for
        # integrity/splice detection.  The deployment secret comes from the
        # existing gateway secret mechanism (/run/secrets / KMS); salt-only
        # keying is the fallback when unset.  Never logged.
        doc_hash = compute_doc_hash(data)
        # Set-scoped-salt hook (salt-parameterised assigner): default is the
        # per-FILE salt (doc_hash) for maximum isolation; when the operator has
        # bound this document to a defined "set" the gateway passes that set's
        # opaque salt, so the SAME value tokenises consistently across the set
        # (legitimate cross-file correlation) at the cost of per-file isolation.
        # doc_hash is ALWAYS retained as the integrity/splice salt recorded in the
        # mapping header (the token salt and the integrity salt are decoupled).
        token_salt = set_salt if set_salt else doc_hash
        salt_scope = "set" if set_salt else "file"
        assigner = TokenAssigner(token_salt, secret=self._pseudonymize_secret)
        plan = build_pseudonymize_plan(matches, originals, assigner)
        try:
            result = self._registry.render(
                data, fmt, job="pseudonymize", plan_b64=plan.to_b64(),
            )
        except Exception as exc:
            return self._block(
                request_id, f"PSEUDONYMIZE re-render failed: {exc} — fail-closed",
                detected=fmt, matches=matches, opa_input=opa_input,
            )

        # No-residual proof: assert NO original value survives in the output
        # (tokenization that leaks the original is worse than useless, §5.5).
        residual = self._assert_no_residual(
            result.output_segments, originals,
            request_id=request_id, fmt=fmt, opa_input=opa_input, matches=matches,
        )
        if residual is not None:
            return residual

        # Vault the replacer map (F5): unguessable handle, AES-256-GCM, TTL'd.
        # The map is the crown jewel — never logged.
        #
        # G-NEW-2 / R5: a MODE-A map is the admin-retrievable re-identification
        # key, so it is bound to the requester's IDENTITY + TENANT (close BOLA:
        # only the requester, in this tenant, may reverse it — role membership is
        # NOT sufficient) AND is single-use (burn-after-read so a leaked handle
        # cannot be replayed within the TTL).  A MODE-B map is the gateway's own
        # internal round-trip vault (never reached through the admin surface), so
        # it stays UNBOUND + non-single-use (the gateway restores many response
        # tokens across one round-trip via the binder, not via reveal()).
        if mode == "A":
            replacer_map = ReplacerMap.create(
                assigner.reverse_map,
                detokenize_rbac_role=detokenize_rbac_role,
                owner_identity=requester_identity,
                tenant=tenant,
                single_use=True,
                ttl_s=map_ttl_s,
            )
            table = CorrespondenceTable.from_assigner(
                assigner,
                detokenize_rbac_role=detokenize_rbac_role,
                owner_identity=requester_identity,
                tenant=tenant,
                ttl_s=map_ttl_s,  # DP-Y-004 §3.1: plaintext TTL matches the
                                   # encrypted ReplacerMap TTL so they expire
                                   # together (GAP-1 fix).
            )
        else:
            replacer_map = ReplacerMap.create(
                assigner.reverse_map,
                detokenize_rbac_role=detokenize_rbac_role,
                single_use=False,
                ttl_s=map_ttl_s,
            )
            table = None

        # Mode B (F3 / L-02): prime the round-trip holder from the EGRESS FRAME —
        # the text of the tokenized artefact exactly as the untrusted cloud will
        # see it (the re-extracted output segments).  The binder records each
        # token's egress provenance + the frame itself, so the response path can
        # restore only count/position-consistent tokens, reject a verbatim echo of
        # the frame, and bound how much of the namespace any one response restores.
        # The replacer map is wrapped in the holder and NEVER surfaced to the
        # cloud, the plan, or any log line.
        mode_b: Optional[ModeBRoundTrip] = None
        if mode == "B":
            egress_frame = "\n".join(
                str(s.get("text", "")) for s in result.output_segments
            )
            mode_b = build_modeb_roundtrip(assigner, replacer_map, egress_frame)

        audit = {
            "event_type": "DOCUMENT_PSEUDONYMIZED",
            "request_id": request_id,
            "disposition": DISPOSITION_PSEUDONYMIZE,
            "detected_format": fmt,
            "pseudonymize_mode": mode,
            "match_count": len(matches),
            "token_count": assigner.token_count,
            # Masked instances + classes only — NEVER the original or the map (F12).
            "matches": [m.as_opa_match() for m in matches],
            "detokenize_rbac_role": detokenize_rbac_role,
            "replacer_map_ttl_s": replacer_map.ttl_s,
            "no_residual_verified": True,
            # The per-file salt the opaque tokens were derived under (not a
            # secret — a hash of bytes the holder already has).  Binds the audit
            # record to the document for integrity/splice correlation.
            "doc_hash": doc_hash,
            # Token salt SCOPE only (never the salt value): "file" = per-file
            # isolation (default), "set" = shared set salt (reduced isolation,
            # cross-file correlation within the operator-defined set).
            "salt_scope": salt_scope,
            # The unguessable handle is a CORRELATION-safe field ONLY if it is
            # never the retrieval capability in a log; we deliberately DO NOT put
            # the handle in the audit event (F5) — it is the capability token.
        }
        self._on_audit("DOCUMENT_PSEUDONYMIZED", audit)
        return DocumentInspectionResult(
            request_id=request_id,
            disposition=DISPOSITION_PSEUDONYMIZE,
            extraction_complete=extraction.extraction_complete,
            detected_format=fmt,
            matches=matches,
            opa_input=opa_input,
            audit_fields=audit,
            forward_bytes=result.rendered_bytes,
            replacer_map=replacer_map,
            correspondence_table=table,
            pseudonymize_mode=mode,
            mode_b_roundtrip=mode_b,
            doc_hash=doc_hash,
            salt_scope=salt_scope,
        )

    # ------------------------------------------------------------------
    # Mode-B response path — restore the untrusted cloud response (F3 / L-02).
    # ------------------------------------------------------------------

    def restore_modeb_response(
        self,
        request_id: str,
        response_text: str,
        round_trip: ModeBRoundTrip,
    ) -> "ModeBRestoreResult":
        """Restore tokens in an untrusted mode-B cloud/upstream response.

        This is the RESPONSE-PATH seam of the mode-B round-trip (the egress→
        response path the gateway already runs for request→upstream→response
        inspection — see ``proxy.py``).  Called once on the way back, AFTER the
        tokenized payload was sent out and the cloud answered.

        The restore is fail-closed on the cloud-egress security boundary:

          * **verbatim-echo (L-02)** — if the response is structurally an echo of
            the egress frame (the harvest attack: bounce the frame back to
            recover cleartext), restoration is REFUSED wholesale, an alert audit
            event is written, and the ORIGINAL (still-tokenized) response is
            returned.  No real value is restored.
          * **anomalous restore** — any token left un-restored by the binder
            (foreign position, over-restore, namespace-harvest beyond the cap) is
            reported in ``flags``; the caller treats a flagged round-trip as
            tainted (forward the partially-/non-restored text + alert), never as a
            clean success.

        The :class:`ReplacerMap` is NEVER surfaced — only the binder's cleared
        restorations yield cleartext, and only here on the trusted host.
        """
        try:
            restored, flags = round_trip.restore(response_text)
        except EchoEgressError as exc:
            audit: dict = {
                "event_type": "DOCUMENT_MODEB_ECHO_REJECTED",
                "request_id": request_id,
                "disposition": "RESTORE_REFUSED",
                "reason": str(exc),
                # The handle is the capability — NEVER audited (F5).
            }
            self._on_audit("DOCUMENT_MODEB_ECHO_REJECTED", audit)
            return ModeBRestoreResult(
                request_id=request_id,
                restored_text=response_text,  # unchanged — nothing restored
                restored=False,
                echo_rejected=True,
                flags=[],
                audit_fields=audit,
            )

        ok = not flags
        event_name = "DOCUMENT_MODEB_RESTORED" if ok else "DOCUMENT_MODEB_RESTORE_FLAGGED"
        audit = {
            "event_type": event_name,
            "request_id": request_id,
            "disposition": "RESTORED" if ok else "RESTORE_FLAGGED",
            # Flags are token IDs only (e.g. "[PERSON_3]") — never the originals.
            "flagged_tokens": list(flags),
        }
        self._on_audit(event_name, audit)
        return ModeBRestoreResult(
            request_id=request_id,
            restored_text=restored,
            restored=ok,
            echo_rejected=False,
            flags=list(flags),
            audit_fields=audit,
        )

    # ------------------------------------------------------------------
    # Integrity verify — tokenised output + mapping belong to the original;
    # cross-file splice (foreign-salt tokens) rejected (DECIDED 2026-06-10).
    # ------------------------------------------------------------------

    def verify_integrity(
        self,
        original_bytes: bytes,
        mapping: "dict[str, str]",
        claimed_doc_hash: str,
    ) -> "IntegrityVerifyResult":
        """Confirm a tokenised output + its mapping file belong to ``original_bytes``.

        Two independent checks; a failure on either fails closed:

          1. **Salt binding** — recompute ``doc_hash = SHA-256(original_bytes)``
             and compare it to the ``claimed_doc_hash`` recorded in the mapping
             file header.  A mismatch means the mapping was paired with the WRONG
             original (splice / wrong-file) → reject.

          2. **Foreign-salt token rejection** — every token in the mapping must
             validly re-derive from its value under THIS document's salt + the
             deployment secret (``token_scheme.token_matches_doc``).  A token
             minted under a different document's salt (cross-file splice) will not
             re-derive and is reported as ``foreign_tokens`` → reject.

        Returns an :class:`IntegrityVerifyResult`; ``ok`` is True only when the
        salt binds AND no foreign tokens are present.  The deployment secret is
        read from the same source the assigner used; the mapping cleartext is
        never logged (only token strings appear in the result's foreign list)."""
        actual = compute_doc_hash(original_bytes)
        salt_ok = secrets_compare(actual, claimed_doc_hash)

        foreign: list[str] = []
        for token, value in mapping.items():
            if not token_matches_doc(
                token, value, actual, secret=self._pseudonymize_secret
            ):
                foreign.append(token)

        ok = salt_ok and not foreign
        audit = {
            "event_type": "DOCUMENT_INTEGRITY_VERIFIED" if ok
            else "DOCUMENT_INTEGRITY_FAILED",
            "disposition": "INTEGRITY_OK" if ok else "INTEGRITY_REJECTED",
            "salt_match": salt_ok,
            "doc_hash": actual,
            # token IDs only — never the mapping cleartext.
            "foreign_token_count": len(foreign),
        }
        self._on_audit(str(audit["event_type"]), audit)
        return IntegrityVerifyResult(
            ok=ok,
            salt_match=salt_ok,
            actual_doc_hash=actual,
            foreign_tokens=foreign,
            audit_fields=audit,
        )

    def _block(
        self,
        request_id: str,
        reason: str,
        *,
        detected: str = "unknown",
        matches: Optional[list[DataMatch]] = None,
        opa_input: Optional[dict] = None,
    ) -> DocumentInspectionResult:
        """BLOCK: stop the document; never forward.  Also the fail-safe
        fallback for every error/over-cap/unavailable path (plan §5.0 / §6.1)."""
        matches = matches or []
        audit = {
            "event_type": "DOCUMENT_BLOCKED",
            "request_id": request_id,
            "disposition": DISPOSITION_BLOCK,
            "detected_format": detected,
            "block_reason": reason,
            "match_count": len(matches),
            "matches": [m.as_opa_match() for m in matches],
        }
        self._on_audit("DOCUMENT_BLOCKED", audit)
        return DocumentInspectionResult(
            request_id=request_id,
            disposition=DISPOSITION_BLOCK,
            extraction_complete=False,
            detected_format=detected,
            matches=matches,
            opa_input=opa_input,
            block_reason=reason,
            audit_fields=audit,
            forward_bytes=None,  # BLOCK never forwards.
        )
