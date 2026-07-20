"""
Yashigani Document Enforcement — MCP tool-call bridge (RESTART-013 gap #1).

Before this module existed, document REDACT/PSEUDONYMIZE enforcement was
completely unreachable from MCP traffic: ``gateway/proxy.py`` dispatches
``/mcp/<agent_name>`` at step 4c and RETURNS before step 4d (the only place
``state["document_pipeline"]`` was ever invoked); ``gateway/mcp_router_runtime.py``
(the actual MCP call handler) had ZERO references to
``DocumentInspectionPipeline`` anywhere in it. A file inside an MCP tool-call
argument, or a file an MCP tool returned in its result, was never extracted,
matched, redacted, or tokenized — proven live (mirror-mcp round-trip probe,
FINDING-V412-RESTART-013 gap #2/#1).

This module scans an MCP JSON-RPC ``tools/call`` payload (the caller's
``params.arguments`` dict on the OUTBOUND leg, or the upstream's ``result`` on
the INBOUND leg) for embedded base64 document blobs and runs EACH one found
through the SAME OPA-decided document-enforcement decision the generic proxy
egress uses (:func:`yashigani.documents.proxy_modeb.egress_decide`) — ONE
decision source of truth for the UI, the generic proxy egress, and MCP traffic.

Design (payload-schema-agnostic, deliberately scoped):
  - MCP tool schemas are arbitrary (unlike the generic proxy egress, which has
    a Content-Type header naming the WHOLE body a document). There is no
    single field name to key on (the mirror-mcp test tool uses
    ``content_b64``; a real-world tool might use ``file``, ``data``,
    ``attachment``, ...). Instead of hardcoding field names, this module walks
    every string LEAF in the JSON structure and treats each one as a candidate
    document blob if it (a) decodes as base64 and (b) the decoded bytes sniff
    to a KNOWN document format (``documents/detection.py``) — the same
    magic-byte sniff the pipeline itself uses, so a plain API token / UUID /
    short string is never mistaken for a document (cheap pre-filter BEFORE
    the expensive pipeline call, mirroring ``proxy_modeb.looks_like_document_
    egress``'s role for the generic egress path).
  - Mode A only (give-the-user/agent-the-table if PSEUDONYMIZE — no mode-B
    round-trip). Mode B's response-leg restore
    (``proxy_modeb.ingress_restore``) is designed around ONE document per
    request/response pair; an MCP payload can carry >1 candidate blob with no
    natural 1:1 pairing across the call. Scoped out for THIS gap — a future
    slice can extend mode-B round-trip pairing per matched-blob path if a real
    need arises. REDACT and PSEUDONYMIZE mode A already close the "raw PII
    document leaves the ring-fence via an MCP tool call" gap this ticket
    targets.
  - Fail-closed-but-non-fatal, mirroring ``proxy_modeb``'s established
    discipline for this exact class of hot-path code: a real OPA/pipeline
    BLOCK decision on ANY candidate blocks the WHOLE call (never partial-
    forward some blobs and hold others); an *unexpected* exception in the
    bridge's OWN code (JSON walking / base64 handling) degrades to leaving
    that candidate's bytes UNCHANGED rather than crashing the call — the
    G-ORCH-OPA-1 response-inspection PII/injection classifier remains the
    backstop on the response leg; there is no equivalent backstop on the
    request leg today, matching the pre-existing MCP dispatch pipeline's own
    posture (this module CLOSES that specific enforcement gap; it does not
    invent a new one).
"""
from __future__ import annotations

import base64
import binascii
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from yashigani.documents.detection import DetectedType, detect_format
from yashigani.documents.pipeline import DocumentInspectionPipeline
from yashigani.documents.proxy_modeb import PROXY_EGRESS_ROUTE, egress_decide

logger = logging.getLogger(__name__)

#: Below this length, a string is far more likely to be a token/id/short value
#: than an encoded document — skip the (relatively) expensive base64-decode +
#: magic-byte sniff for anything shorter. Chosen so even a tiny real document
#: (a one-line txt/csv fixture) still clears it once base64-inflated (~4/3).
_MIN_CANDIDATE_LEN = 64

#: Defence-in-depth cap on how many string leaves are inspected per call — an
#: adversarial payload with thousands of tiny strings must not turn one MCP
#: call into thousands of pipeline invocations.
_MAX_CANDIDATES_PER_CALL = 16

_B64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)


@dataclass
class McpDocumentOutcome:
    """Result of scanning + enforcing one MCP JSON-RPC payload."""

    #: True when ANY candidate blob was OPA-decided BLOCK (or the bridge's own
    #: code hit an unexpected fault while a real block was already in flight —
    #: see module docstring). The caller MUST deny the whole MCP call/response.
    blocked: bool = False
    block_reason: str = ""
    #: True when at least one candidate blob was rewritten in place (REDACT or
    #: PSEUDONYMIZE mode A applied) — the caller should re-serialise ``payload``.
    transformed: bool = False
    #: The (possibly mutated in place) payload — same object identity as the
    #: ``payload`` argument; returned for call-site convenience/clarity.
    payload: Any = None
    #: Per-candidate OPA action, in scan order — audit/debug breadcrumb only.
    dispositions: list = field(default_factory=list)
    #: How many candidate blobs were found + inspected (0 = payload carried no
    #: document-shaped content — the common case for ordinary tool calls).
    candidate_count: int = 0


def _iter_string_leaves(obj: Any, path: tuple = ()):
    """Yield (path, value) for every string leaf in a JSON-shaped structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _iter_string_leaves(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _iter_string_leaves(v, path + (i,))
    elif isinstance(obj, str):
        yield path, obj


def _set_at_path(obj: Any, path: tuple, value: str) -> None:
    """Mutate ``obj`` in place, replacing the leaf at ``path`` with ``value``."""
    cur = obj
    for key in path[:-1]:
        cur = cur[key]
    cur[path[-1]] = value


def _looks_like_base64(s: str) -> bool:
    if len(s) < _MIN_CANDIDATE_LEN:
        return False
    # Cheap alphabet check on a bounded prefix — avoid an O(n) scan of a
    # multi-megabyte string just to reject it (the size cap upstream —
    # MCP_BODY_SIZE_LIMIT_BYTES — already bounds the worst case, but this
    # keeps the pre-filter itself cheap regardless).
    return all(c in _B64_ALPHABET for c in s[:512])


def candidate_document_bytes(s: str) -> Optional[bytes]:
    """Return the decoded bytes if ``s`` looks like a base64-encoded document
    (decodes cleanly AND sniffs to a known committed format), else ``None``.

    This is the cheap pre-filter that keeps ordinary tool-call traffic (ids,
    tokens, short strings, prose) from ever reaching the pipeline/OPA — the
    SAME magic-byte sniff the pipeline itself uses (``documents/detection.py``),
    run here first so a non-document string never costs an OPA round-trip.
    """
    if not _looks_like_base64(s):
        return None
    try:
        decoded = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not decoded:
        return None
    detection = detect_format(decoded, "")
    if detection.detected_type == DetectedType.UNKNOWN:
        return None
    return decoded


async def enforce_mcp_document_payload(
    pipeline: DocumentInspectionPipeline,
    *,
    opa_url: str,
    payload: Any,
    request_id: str,
    identity_id: str = "",
    tenant: str = "",
    surface: str = "mcp-tool-call",
) -> McpDocumentOutcome:
    """Scan + enforce document content embedded in an MCP JSON-RPC payload.

    ``payload`` is typically ``params["arguments"]`` (outbound, agent → tool)
    or the parsed ``result`` object (inbound, tool → agent) — any JSON-shaped
    structure. Mutated IN PLACE for any candidate that OPA decided to
    transform (REDACT/PSEUDONYMIZE mode A); the caller re-serialises it.

    Returns a fail-closed outcome: ``blocked=True`` means the caller MUST deny
    the whole MCP call/response — never forward some candidates' transformed
    bytes while silently dropping a BLOCKed one (partial-allow is exactly the
    "hollow green" this ticket closes).
    """
    outcome = McpDocumentOutcome(payload=payload)
    try:
        candidates = list(_iter_string_leaves(payload))[:_MAX_CANDIDATES_PER_CALL]
    except Exception:
        # Fail-closed-but-non-fatal (bridge's OWN code, not a policy decision):
        # cannot even walk the payload — treat as "no document content found"
        # rather than crash the MCP call. The pipeline's own controls on
        # anything that DOES land elsewhere (e.g. response PII inspection)
        # remain the backstop.
        logger.exception(
            "mcp document bridge: payload walk raised (request_id=%s) — "
            "treating as no document content found", request_id,
        )
        return outcome

    for path, s in candidates:
        try:
            data = candidate_document_bytes(s)
        except Exception:
            logger.exception(
                "mcp document bridge: candidate sniff raised (request_id=%s) "
                "— skipping this candidate, leaving it unchanged", request_id,
            )
            continue
        if data is None:
            continue

        outcome.candidate_count += 1
        try:
            egress = await egress_decide(
                pipeline,
                opa_url=opa_url,
                body=data,
                content_type="",
                request_id=request_id,
                route=PROXY_EGRESS_ROUTE,
                egress_mode="A",
                identity_id=identity_id,
                tenant=tenant,
                surface=surface,
            )
        except Exception:
            logger.exception(
                "mcp document bridge: egress_decide raised unexpectedly "
                "(request_id=%s) — fail-closed BLOCK (a policy decision could "
                "not be reached; never forward an uninspected document)",
                request_id,
            )
            outcome.blocked = True
            outcome.block_reason = "mcp_document_enforcement_error"
            return outcome

        outcome.dispositions.append(egress.action)

        if egress.blocked:
            outcome.blocked = True
            outcome.block_reason = egress.block_reason or "document_blocked"
            return outcome

        if egress.route_local:
            # No local-model leg exists on the MCP tool-call path (scoped out
            # above — mode A never actually triggers ROUTE_LOCAL since the
            # rego's escalation requires the cloud-bound mode-B leg; this is
            # a fail-closed backstop in case that invariant ever changes).
            outcome.blocked = True
            outcome.block_reason = "document_route_local_not_supported_on_mcp_path"
            return outcome

        if egress.transformed and egress.forward_bytes is not None:
            new_b64 = base64.b64encode(egress.forward_bytes).decode("ascii")
            _set_at_path(payload, path, new_b64)
            outcome.transformed = True
        # LOG / non-engaged: leave this candidate's bytes unchanged.

    return outcome
