"""
Yashigani Document Enforcement — the re-render PLAN contract (REDACT / PSEUDONYMIZE).

This is the language-agnostic, process-level contract that travels from the
gateway (host) to the in-jail re-render worker (``docker/extractor/worker.py``,
red-team F6 — re-render runs in the SAME sandbox as extraction).  It mirrors the
``DataMatch`` enumeration the read path produces, narrowed to exactly what the
worker needs to *act* on each matched span and emit a freshly re-rendered
artefact (never an overlay — F4).

The trust boundary (F5, NON-NEGOTIABLE):
  - The plan carries, per span, the **original matched substring** (so the worker
    can find-and-transform it inside the part it re-renders) + the **action** +
    (for PSEUDONYMIZE) the assigned **token**.
  - The plan does **NOT** carry the replacer map handle, the request id, or any
    correlation key.  The replacer MAP (token -> original) is the crown jewel; it
    is held HOST-side only (``pseudonymize.ReplacerMap``) and never enters the
    jail.  The jail receives only "replace value V with token T" / "destroy value
    V" instructions and the document bytes it already has — it learns nothing it
    could not already read from the document.
  - The original substrings in the plan ARE the sensitive values, but they are
    values the jail is ALREADY parsing out of the same document bytes on its own
    re-extract pass; the plan does not concentrate anything new in the jail, and
    the plan is never logged/audited host-side (only the masked instance is).

Plan transport: the plan is serialised to compact JSON, base64'd, and passed as
the worker ``--plan`` argv argument (the document bytes stay on stdin — the
single read-only input).  The plan is small (one entry per match) and contains no
map, so argv is an acceptable channel; the document never travels in argv.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from enum import Enum


class SpanAction(str, Enum):
    """The per-span transform the worker applies during re-render."""

    REDACT = "REDACT"            # destroy the matched span (irreversible, §5.1)
    PSEUDONYMIZE = "PSEUDONYMIZE"  # replace with a consistent token (§5.3)


@dataclass(frozen=True)
class RenderSpan:
    """One per-span transform instruction for the re-render worker.

    Parameters
    ----------
    segment_location:
        The WORKER-side segment provenance (e.g. ``word/document.xml#p=1``,
        ``sheet=Visible!C1``, ``page=1``).  The worker re-extracts the document,
        keys segments by this location, and transforms inside the matching
        segment(s) only.  An empty location is rejected (the worker cannot place
        an unanchored transform — fail-closed).
    original:
        The EXACT matched substring to find-and-transform within the located
        segment.  Value-keyed (not offset-keyed) so a small re-extract drift in
        offsets cannot mis-place the transform, and so the SAME value collapses to
        the SAME token everywhere it appears (coherence, §5.3a).
    action:
        REDACT (destroy) or PSEUDONYMIZE (token-substitute).
    token:
        For PSEUDONYMIZE only — the consistent, OPAQUE placeholder (a short
        lowercase base32 string derived host-side as a per-file-salted HMAC of
        the value; DECIDED 2026-06-10).  The worker treats it as an inert string
        to substitute in place of ``original`` — it never parses or derives the
        token, so the opaque scheme is entirely host-side.  Empty for REDACT.
    data_class:
        The data class (audit/labelling only; the worker does not branch on it).
    """

    segment_location: str
    original: str
    action: SpanAction
    token: str = ""
    data_class: str = ""

    def __post_init__(self) -> None:
        if not self.segment_location:
            raise ValueError("RenderSpan.segment_location must not be empty")
        if self.original == "":
            raise ValueError("RenderSpan.original must not be empty")
        if self.action == SpanAction.PSEUDONYMIZE and not self.token:
            raise ValueError("PSEUDONYMIZE span requires a token")

    def to_dict(self) -> dict:
        return {
            "segment_location": self.segment_location,
            "original": self.original,
            "action": self.action.value,
            "token": self.token,
            "data_class": self.data_class,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RenderSpan":
        return cls(
            segment_location=str(d["segment_location"]),
            original=str(d["original"]),
            action=SpanAction(str(d["action"])),
            token=str(d.get("token", "")),
            data_class=str(d.get("data_class", "")),
        )


@dataclass
class RenderPlan:
    """The full set of per-span transforms for one re-render job.

    ``strip_hidden_and_metadata`` is ALWAYS true for REDACT (you cannot certify
    "no residual" while leaving hidden parts + metadata intact — §5.1 point 3 /
    red-team F4); the worker strips ALL hidden parts + metadata wholesale during
    a REDACT/PSEUDONYMIZE re-render regardless of where matches were found.
    """

    spans: list[RenderSpan] = field(default_factory=list)
    strip_hidden_and_metadata: bool = True

    def to_json(self) -> str:
        return json.dumps(
            {
                "spans": [s.to_dict() for s in self.spans],
                "strip_hidden_and_metadata": self.strip_hidden_and_metadata,
            },
            separators=(",", ":"),
        )

    def to_b64(self) -> str:
        """Serialise for the worker ``--plan`` argv channel."""
        return base64.b64encode(self.to_json().encode("utf-8")).decode("ascii")

    @classmethod
    def from_json(cls, raw: str) -> "RenderPlan":
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError("render plan must be a JSON object")
        spans = [RenderSpan.from_dict(s) for s in obj.get("spans", [])]
        return cls(
            spans=spans,
            strip_hidden_and_metadata=bool(obj.get("strip_hidden_and_metadata", True)),
        )

    @classmethod
    def from_b64(cls, raw: str) -> "RenderPlan":
        return cls.from_json(base64.b64decode(raw.encode("ascii")).decode("utf-8"))

    def by_segment(self) -> dict[str, list[RenderSpan]]:
        """Group spans by their worker-side segment location."""
        out: dict[str, list[RenderSpan]] = {}
        for s in self.spans:
            out.setdefault(s.segment_location, []).append(s)
        return out
