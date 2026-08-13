"""
Yashigani Backoffice — Sensitivity pattern management + taxonomy routes.

# Last updated: 2026-06-13T00:00:00+00:00

CRUD for detection patterns used by the sensitivity classifier pipeline,
plus taxonomy config for R14/R15 (v2.25.5) and AI-assisted pattern generation
for R16 (v2.25.5).

  GET     /admin/sensitivity/patterns            — List all patterns
  POST    /admin/sensitivity/patterns            — Create a pattern (step-up required)
  DELETE  /admin/sensitivity/patterns/{id}       — Delete a pattern (step-up required)
  GET     /admin/sensitivity/status              — Pipeline status (layers active/inactive)
  POST    /admin/sensitivity/test                — Test classify a text sample

  GET     /admin/sensitivity/taxonomy            — List current taxonomy
  POST    /admin/sensitivity/taxonomy/{level}    — Upsert a level (step-up required)
  DELETE  /admin/sensitivity/taxonomy/{level}    — Delete a level (step-up required)
  GET     /admin/sensitivity/taxonomy/defaults   — Return canonical defaults

  POST    /admin/sensitivity/generate-pattern    — R16: AI-generate a detection pattern
                                                    from plain-English description,
                                                    using the install-default model.

LF-STEPUP-AGENT-CREATE (2026-04-27): POST and DELETE /patterns added step-up
gate — DLP rule mutation is a policy-sensitive operation; a hijacked admin
session must not bypass TOTP to neutralise detection patterns.

R14/R15 (v2.25.5): taxonomy endpoints added with step-up gate for write
operations; PatternRequest.classification now accepts numeric strings (1–5)
in addition to the legacy string names.

R16 (v2.25.5): AI-generate detection pattern endpoint added. Admin describes
a data type in plain English; the install-default LLM returns a regex + suggested
sensitivity level. Uses the same model-resolution path as the OPA policy generator
(YASHIGANI_OPA_ASSISTANT_MODEL / OLLAMA_MODEL / first available model).
"""
from __future__ import annotations

import hashlib as _hashlib
import json as _json
import logging
import os
import re as _re

import httpx as _httpx
from fastapi import HTTPException as _HTTPException

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope
from yashigani.optimization.taxonomy_store import TaxonomyStore, DEFAULT_TAXONOMY
from yashigani.audit.schema import (
    SensitivityPatternCreatedEvent,
    SensitivityPatternDeletedEvent,
    SensitivityPatternAIGeneratedEvent,
    TaxonomyLevelChangedEvent,
)

# ---------------------------------------------------------------------------
# LAURA-2255-005: ReDoS protection helpers (AUDIT-GAP-001: also used below
# in create_pattern and generate_pattern to validate AI-generated regexes).
#
# Strategy: structural heuristic (no re2/recheck dependency).  Patterns that
# would require re2 for full linear-time guarantees are already rejected here
# because the heuristic flags all catastrophic-backtracking structures
# (nested quantifiers on variable-length groups) and trivially-overbroad
# patterns (bare .*) that the ReDoS finding specifically calls out.
# ---------------------------------------------------------------------------

# Heuristic patterns that flag potential catastrophic backtracking.
# Covers the canonical evil forms: (a+)+, (a*)+, (a+)*, (a|a)+, etc.
_REDOS_NESTED_RE = _re.compile(
    r"""
    # nested quantifiers: (...+)+ / (...*)+ / (...+)* etc.
    \(          # opening group paren
    [^)]*       # any group content (lazy — we care about the structure)
    [+*]        # inner quantifier on whatever is inside the group
    [^)]*       # possibly more content after inner quantifier
    \)          # closing paren
    [+*]        # outer quantifier on the group itself
    """,
    _re.VERBOSE,
)

# Trivially-overbroad single-element patterns: bare .* or .+ (no anchors,
# no surrounding context) — useless for DLP and cause performance issues.
_OVERBROAD_RE = _re.compile(r"^\.\*$|^\.\+$|^\(\.\*\)$|^\(\.\+\)$")

# F3 (HIGH — Laura, FINDING-V412-DOCKER-CLEANROUND-BATCH): _REDOS_NESTED_RE
# above only fires when the nested quantifier is inside a `(...)` GROUP —
# e.g. "(a+)+".  It does NOT fire on an UNPARENTHESIZED chain of adjacent
# broad-wildcard quantifiers with no grouping at all, e.g.:
#     .*.*.*.*.*.*x
# Laura's PoC: this pattern PASSED _validate_regex_safety unchanged (no
# parens anywhere in the string) and then hung the regex engine for
# minutes against a short adversarial input with no trailing "x" — classic
# catastrophic backtracking (measured live: n=100 chars already ~24s,
# n=120 ~74s on stdlib re; the exact hang time scales with input length
# and interpreter, but the underlying vulnerability class is identical to
# the parenthesized nested-quantifier case _REDOS_NESTED_RE already
# blocks).  A string that is entirely all-numeric TLD-shaped never occurs
# in real hostnames, but here the analogous invariant is: two or more
# quantified "broad" atoms (., \w, \W, \s, \S, \d, \D, or any bracket
# expression) placed DIRECTLY adjacent to each other (no literal/anchor
# separating them) is inherently ambiguous for the backtracking engine —
# there is no reason a legitimate DLP pattern needs this shape, and it is
# the textbook catastrophic-backtracking construction.
#
# _REDOS_ADJACENT_WILDCARD_RE requires >= 2 such atom+quantifier units in
# an unbroken row.  Verified NOT to false-positive on any of the 5 seeded
# built-in patterns (credit card / API key / SSN / phone / email) — each
# either uses a bounded {n} / {n,} quantifier (not bare * or +) or has a
# literal/anchor between quantified atoms, so none of them chain adjacent
# unbounded wildcards.
_REDOS_WILDCARD_ATOM = r"(?:(?<!\\)\.|\\[wWsSdD]|\[\^?[^\]]*\])"
_REDOS_ADJACENT_WILDCARD_RE = _re.compile(
    r"(?:%s[*+]){2,}" % _REDOS_WILDCARD_ATOM
)


_MAX_REGEX_PATTERN_LEN = 512


def _validate_regex_safety(pattern: str) -> None:
    """Validate a pattern string for ReDoS risk and compilability.

    Raises HTTPException 422 on:
      - Patterns longer than _MAX_REGEX_PATTERN_LEN (#1900: hard cap enforced
        HERE, first, so every caller is covered regardless of whether the
        pattern came through a length-constrained Pydantic field (create_pattern,
        PatternRequest.pattern max_length=512) or an unbounded source (the
        LLM-generated `generated_regex` in generate_pattern, which has no field
        constraint of its own) — the ReDoS heuristic below must never see input
        longer than this cap.
      - Patterns that fail to compile (invalid regex).
      - Patterns with nested quantifiers on variable-length groups
        (catastrophic backtracking risk).
      - Trivially-overbroad patterns (bare .* / .+) with no context.
    """
    # 0. Hard length cap — FIRST check, before any regex engine touches the
    #    string. This is caller-independent: it covers both the length-capped
    #    PatternRequest.pattern field AND the unbounded LLM-generated regex
    #    fed in by generate_pattern() before this function is ever reached.
    if len(pattern) > _MAX_REGEX_PATTERN_LEN:
        raise _HTTPException(
            status_code=422,
            detail={
                "error": "pattern_too_long",
                "message": (
                    f"Pattern exceeds the maximum allowed length of "
                    f"{_MAX_REGEX_PATTERN_LEN} characters."
                ),
            },
        )

    # 1. Compilability guard — reject syntactically invalid regexes.
    try:
        _re.compile(pattern)
    except _re.error as exc:
        raise _HTTPException(
            status_code=422,
            detail={
                "error": "invalid_regex",
                "message": f"Pattern is not a valid regular expression: {exc}",
            },
        )

    # 2. Trivially-overbroad check.
    if _OVERBROAD_RE.match(pattern):
        raise _HTTPException(
            status_code=422,
            detail={
                "error": "overbroad_pattern",
                "message": (
                    "Pattern '.*' or '.*' alone matches everything — it provides no "
                    "discrimination and would flag every message.  Provide a more "
                    "specific pattern."
                ),
            },
        )

    # 3. Nested-quantifier heuristic (catastrophic backtracking).
    if _REDOS_NESTED_RE.search(pattern):
        raise _HTTPException(
            status_code=422,
            detail={
                "error": "redos_risk",
                "message": (
                    "Pattern contains nested quantifiers on a variable-length group "
                    "(e.g. (a+)+) which can cause catastrophic backtracking.  "
                    "Rewrite without nesting quantifiers, e.g. use 'a+' instead of '(a+)+'."
                ),
            },
        )

    # 4. F3 (HIGH — Laura): unparenthesized adjacent-quantifier heuristic.
    #    Catches ".*.*.*.*.*.*x" and similar chains of directly-adjacent
    #    broad-wildcard quantifiers that _REDOS_NESTED_RE (parens-only)
    #    does not see at all.
    if _REDOS_ADJACENT_WILDCARD_RE.search(pattern):
        raise _HTTPException(
            status_code=422,
            detail={
                "error": "redos_risk_adjacent_wildcard",
                "message": (
                    "Pattern contains two or more adjacent quantified broad-wildcard "
                    "tokens (e.g. '.*.*', '\\w+\\w+', '[^,]*[^,]*') with no literal or "
                    "anchor between them.  This is ambiguous for the backtracking regex "
                    "engine and can cause catastrophic (exponential-time) backtracking "
                    "even without any parentheses (F3 / CWE-1333).  Rewrite the pattern "
                    "so at most one broad wildcard is quantified in any unbroken run, "
                    "e.g. add a literal separator or anchor between the wildcard groups."
                ),
            },
        )

logger = logging.getLogger(__name__)

router = APIRouter()


def _sha256_hex(text: str) -> str:
    """SHA-256 hex digest of a UTF-8 string (for audit records — raw value not stored)."""
    return _hashlib.sha256(text.encode("utf-8")).hexdigest()

# Shared taxonomy store instance (no DB connection in constructor)
_taxonomy_store = TaxonomyStore()


# ── In-memory pattern store ──────────────────────────────────────────────

_patterns: list[dict] = [
    {"id": "1", "classification": "4", "type": "regex", "pattern": r"\b(?:\d[ -]*?){13,19}\b", "description": "Credit/debit card"},
    {"id": "2", "classification": "4", "type": "regex", "pattern": r"\b(?:sk-|sk-ant-)[A-Za-z0-9_-]{20,}\b", "description": "API key"},
    {"id": "3", "classification": "4", "type": "regex", "pattern": r"\b\d{3}-\d{2}-\d{4}\b", "description": "US SSN"},
    {"id": "4", "classification": "3", "type": "regex", "pattern": r"\b\d{3}[- ]?\d{3}[- ]?\d{4}\b", "description": "US/CA phone"},
    {"id": "5", "classification": "2", "type": "regex", "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "description": "Email address"},
]
_pattern_counter = 5


# ── Helper: normalise classification string to canonical level int ────────

def _normalise_classification(classification: str) -> str:
    """Map legacy string or numeric string to canonical numeric string.

    Accepts: "RESTRICTED", "CONFIDENTIAL", "INTERNAL", "PUBLIC", "SENSITIVE",
             "1", "2", "3", "4", "5".
    Returns: the canonical numeric string ("1"–"5").
    """
    from yashigani.optimization.sensitivity_classifier import _STRING_TO_LEVEL
    lvl = _STRING_TO_LEVEL.get(classification.upper())
    if lvl is not None:
        return str(lvl)
    return classification  # pass through (should be rejected by validator)


# ── Helper: build the SAME unified sensitivity classifier the runtime uses ──
#
# FIND-LAURA-412-CRIT-001 sweep (2026-08-08): POST /admin/sensitivity/test
# previously ran ONLY `backoffice_state.inspection_pipeline.process()` — the
# prompt-injection / credential-exfil classifier (yashigani.inspection.pipeline
# .InspectionPipeline) — never the sensitivity/PII/PCI classifier
# (yashigani.optimization.sensitivity_classifier.SensitivityClassifier) that
# gateway ingress/egress actually enforce PAN/PII detection with. An admin
# pasting a Luhn-valid PAN into the "test" box got back an injection verdict
# only, with NO signal about whether the SAME text would trip POL-009
# pci_data_present / the PCI egress ceiling in production — admin test results
# did not match enforcement, exactly the failure mode this sweep closes.
#
# Backoffice and gateway are separate processes/containers — the literal
# SensitivityClassifier object cannot be shared across them. "Unify" here
# means: construct an instance of the SAME class, using the SAME
# `_DEFAULT_PATTERNS` + the SAME `_scan_regex()` method (which normalizes
# every non-card pattern via `normalize_for_pattern_matching` and delegates
# card detection to the Luhn-validated `contains_pci_pan`) — so the
# deterministic regex floor (the ONLY layer guaranteed identical between the
# two processes; sklearn/ollama depend on per-process backend availability)
# agrees byte-for-byte with what gateway enforcement would flag. Rebuilt on
# every call (cheap: a handful of `re.compile`s) so a just-created/-deleted
# admin pattern is reflected immediately, with no cache-invalidation surface.
def _regex_only_test_patterns() -> list:
    """Default patterns + any admin-created custom regex patterns, as the
    ``(pattern, SensitivityLevel, description)`` tuples ``SensitivityClassifier``
    expects."""
    from yashigani.optimization.sensitivity_classifier import (
        SensitivityLevel,
        _DEFAULT_PATTERNS,
    )

    merged = list(_DEFAULT_PATTERNS)
    for p in _patterns:
        if p.get("type") != "regex":
            continue
        try:
            level = SensitivityLevel(int(p["classification"]))
        except (KeyError, ValueError, TypeError):
            continue
        merged.append((p["pattern"], level, p.get("description") or p["pattern"]))
    return merged


def _build_test_sensitivity_classifier():
    """Regex-only ``SensitivityClassifier`` (Layer 1 only — no sklearn/ollama
    backend, which are process-local and would not reflect gateway state
    anyway) over the merged default + custom pattern set."""
    from yashigani.optimization.sensitivity_classifier import SensitivityClassifier

    return SensitivityClassifier(
        patterns=_regex_only_test_patterns(),
        enable_sklearn=False,
        enable_ollama=False,
    )


# ── Request / Response models ─────────────────────────────────────────────

class PatternRequest(BaseModel):
    # R14/R15 (v2.25.5): accept numeric strings (1–5) AND legacy string names.
    classification: str = Field(
        pattern=r"^([1-5]|RESTRICTED|CONFIDENTIAL|INTERNAL|PUBLIC|SENSITIVE)$"
    )
    type: str = Field(default="regex", pattern=r"^(regex|keyword|classifier|fasttext|ollama)$")
    pattern: str = Field(min_length=1, max_length=512)
    description: str = Field(min_length=1, max_length=256)


class TestClassifyRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10000)


class TaxonomyLevelRequest(BaseModel):
    """Request body for POST /admin/sensitivity/taxonomy/{level}."""
    label: str = Field(min_length=1, max_length=64)
    colour_class: str = Field(pattern=r"^sens-level-[1-5]$")


# ── Endpoints: Patterns ───────────────────────────────────────────────────

@router.get("/patterns")
async def list_patterns(session: AdminSession):
    """List all detection patterns with resolved taxonomy labels."""
    # Best-effort taxonomy enrichment: fetch labels for each pattern's level.
    try:
        taxonomy = await _taxonomy_store.get_taxonomy("default")
    except Exception:
        taxonomy = dict(DEFAULT_TAXONOMY)

    enriched = []
    for p in _patterns:
        entry = dict(p)
        raw_cls = p.get("classification", "")
        # Try to resolve numeric classification to a label
        try:
            lvl_int = int(raw_cls)
            tax_entry = taxonomy.get(lvl_int)
            entry["classification_label"] = tax_entry["label"] if tax_entry else raw_cls
        except (ValueError, TypeError):
            entry["classification_label"] = raw_cls
        enriched.append(entry)

    return {"patterns": enriched}


@router.post("/patterns", status_code=201)
async def create_pattern(body: PatternRequest, session: StepUpAdminSession):
    global _pattern_counter
    # LAURA-2255-005: reject unsafe regex patterns at the create boundary.
    if body.type == "regex":
        _validate_regex_safety(body.pattern)
    _pattern_counter += 1
    # Normalise legacy string names to numeric
    classification = _normalise_classification(body.classification)
    pattern = {
        "id": str(_pattern_counter),
        "classification": classification,
        "type": body.type,
        "pattern": body.pattern,
        "description": body.description,
    }
    _patterns.append(pattern)

    # AUDIT-GAP-001: emit to the SHA-384 hash-chain ledger.
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(
                SensitivityPatternCreatedEvent(
                    admin_account=session.account_id,
                    pattern_id=str(_pattern_counter),
                    classification=classification,
                    pattern_type=body.type,
                    pattern_hash=_sha256_hex(body.pattern),
                    description=body.description,
                )
            )
        except Exception as _exc:
            logger.error("Failed to write SensitivityPatternCreatedEvent: %s", _exc)

    return {"status": "ok", "pattern": pattern}


@router.delete("/patterns/{pattern_id}")
async def delete_pattern(pattern_id: str, session: StepUpAdminSession):
    global _patterns
    before = len(_patterns)
    _patterns = [p for p in _patterns if p["id"] != pattern_id]
    if len(_patterns) == before:
        raise HTTPException(status_code=404, detail={"error": "pattern_not_found"})

    # AUDIT-GAP-001: emit to the SHA-384 hash-chain ledger.
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(
                SensitivityPatternDeletedEvent(
                    admin_account=session.account_id,
                    pattern_id=pattern_id,
                )
            )
        except Exception as _exc:
            logger.error("Failed to write SensitivityPatternDeletedEvent: %s", _exc)

    return {"status": "ok"}


@router.get("/status")
async def pipeline_status(session: AdminSession):
    """Return which layers of the sensitivity pipeline are active."""
    sklearn_available = False
    ollama_available = False

    pipeline = backoffice_state.inspection_pipeline
    if pipeline:
        # Check if backend_registry has backends
        br = getattr(pipeline, '_backend_registry', None)
        if br:
            ollama_available = True
        else:
            ollama_available = getattr(pipeline, '_classifier', None) is not None

    # sklearn availability (v2.23.3 — replaces fasttext-wheel)
    try:
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend  # noqa: F401
        sklearn_available = True
    except Exception:
        pass

    return {
        "regex": True,  # always active
        "sklearn_available": sklearn_available,
        "classifier_available": sklearn_available,
        # Legacy key — DEPRECATED in v2.25.3, removed in v2.26.0.
        "fasttext_available": sklearn_available,
        "ollama_available": ollama_available,
        "pattern_count": len(_patterns),
    }


@router.post("/test")
async def test_classify(body: TestClassifyRequest, session: AdminSession):
    """Test the sensitivity classifier against a text sample.

    Returns TWO independent verdicts over the same sample:
      - is_injection/confidence/action/classification: the prompt-injection /
        credential-exfil pipeline (yashigani.inspection.pipeline.InspectionPipeline).
      - sensitivity_level/sensitivity_label/sensitivity_triggers: the
        PAN/PII/PCI sensitivity regex floor (yashigani.optimization
        .sensitivity_classifier.SensitivityClassifier) — the SAME unified,
        NFKC+Cf-normalized, Luhn-validated detection path gateway ingress/
        egress enforce POL-009 pci_data_present with (FIND-LAURA-412-CRIT-001
        sweep, 2026-08-08). Previously this endpoint ran ONLY the injection
        pipeline, so admin test results for a pasted card/SSN/PII sample did
        not reflect what production enforcement would actually do with it.
    """
    from yashigani.optimization.sensitivity_classifier import _LEVEL_TO_LEGACY_STRING

    pipeline = backoffice_state.inspection_pipeline
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Inspection pipeline not available")

    # Regex-floor sensitivity/PAN/PII classification — deterministic, no
    # external backend dependency, never allowed to break this endpoint.
    sensitivity_level: int | None = None
    sensitivity_label: str | None = None
    sensitivity_triggers: list[str] = []
    try:
        sens_result = _build_test_sensitivity_classifier().classify_decoded(body.text)
        sensitivity_level = sens_result.level
        sensitivity_label = _LEVEL_TO_LEGACY_STRING.get(sens_result.level)
        sensitivity_triggers = sens_result.triggers
    except Exception as exc:
        logger.warning("sensitivity regex-floor test failed: %s", exc)

    try:
        result = pipeline.process(
            raw_query=body.text,
            session_id="test",
            agent_id="backoffice-test",
            user_id="admin",
        )
        is_injection = result.action in ("SANITIZED", "DISCARDED")
        return {
            "is_injection": is_injection,
            "confidence": result.confidence,
            "action": result.action,
            "classification": result.classification,
            "sensitivity_level": sensitivity_level,
            "sensitivity_label": sensitivity_label,
            "sensitivity_triggers": sensitivity_triggers,
        }
    except Exception as exc:
        # V232-CSCAN-01e: log full exception server-side; safe envelope to client.
        envelope, _ = safe_error_envelope(exc, public_message="sensitivity classifier unavailable")
        return {
            "is_injection": False,
            "confidence": 0.0,
            "action": "error",
            "error": envelope["error"],
            "request_id": envelope["request_id"],
            "sensitivity_level": sensitivity_level,
            "sensitivity_label": sensitivity_label,
            "sensitivity_triggers": sensitivity_triggers,
        }


# ── Endpoints: Taxonomy ───────────────────────────────────────────────────

@router.get("/taxonomy/defaults")
async def get_taxonomy_defaults(session: AdminSession):
    """Return the canonical 5-level defaults (not tenant-specific)."""
    entries = [
        {"level": lvl, "label": entry["label"], "colour_class": entry["colour_class"]}
        for lvl, entry in sorted(DEFAULT_TAXONOMY.items())
    ]
    return {"taxonomy": entries}


@router.get("/taxonomy")
async def get_taxonomy(session: AdminSession):
    """Return the current taxonomy for the default tenant."""
    try:
        taxonomy = await _taxonomy_store.get_taxonomy("default")
        entries = [
            {"level": lvl, "label": entry["label"], "colour_class": entry["colour_class"]}
            for lvl, entry in sorted(taxonomy.items())
        ]
        return {"taxonomy": entries}
    except Exception as exc:
        logger.warning("get_taxonomy failed: %s", exc)
        # Return defaults on error
        entries = [
            {"level": lvl, "label": entry["label"], "colour_class": entry["colour_class"]}
            for lvl, entry in sorted(DEFAULT_TAXONOMY.items())
        ]
        return {"taxonomy": entries}


@router.post("/taxonomy/{level}", status_code=200)
async def upsert_taxonomy_level(
    level: int,
    body: TaxonomyLevelRequest,
    session: StepUpAdminSession,
):
    """Upsert a taxonomy level for the default tenant."""
    if level < 1 or level > 10:
        raise HTTPException(
            status_code=422,
            detail={"error": "level_out_of_range", "message": "Level must be 1–10."},
        )
    try:
        await _taxonomy_store.set_level(
            tenant_id="default",
            level_number=level,
            label=body.label,
            colour_class=body.colour_class,
        )
        # AUDIT-GAP-001: emit to the SHA-384 hash-chain ledger.
        if backoffice_state.audit_writer is not None:
            try:
                backoffice_state.audit_writer.write(
                    TaxonomyLevelChangedEvent(
                        admin_account=session.account_id,
                        level=level,
                        change_type="upsert",
                        label=body.label,
                        colour_class=body.colour_class,
                    )
                )
            except Exception as _exc:
                logger.error("Failed to write TaxonomyLevelChangedEvent (upsert): %s", _exc)
        return {"status": "ok", "level": level, "label": body.label, "colour_class": body.colour_class}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": "invalid_colour_class", "message": str(exc)}) from exc
    except Exception as exc:
        logger.warning("upsert_taxonomy_level failed level=%d: %s", level, exc)
        raise HTTPException(status_code=500, detail={"error": "taxonomy_update_failed"}) from exc


@router.delete("/taxonomy/{level}")
async def delete_taxonomy_level(level: int, session: StepUpAdminSession):
    """Delete a taxonomy level for the default tenant.

    FIND-3.0-004b: check existence before delete.  The underlying SQL DELETE
    is a no-op for a non-existent level (zero rows affected, no exception) so
    without this guard the route would return 200 for a phantom level.
    """
    try:
        # Existence check — must precede business-rule guards (ValueError for
        # level 1 / current-max) so the two failure modes are kept distinct.
        taxonomy = await _taxonomy_store.get_taxonomy("default")
        if level not in taxonomy:
            raise HTTPException(
                status_code=404,
                detail={"error": "taxonomy_level_not_found", "level": level},
            )
        await _taxonomy_store.delete_level(tenant_id="default", level_number=level)
        # AUDIT-GAP-001: emit to the SHA-384 hash-chain ledger.
        if backoffice_state.audit_writer is not None:
            try:
                backoffice_state.audit_writer.write(
                    TaxonomyLevelChangedEvent(
                        admin_account=session.account_id,
                        level=level,
                        change_type="delete",
                    )
                )
            except Exception as _exc:
                logger.error("Failed to write TaxonomyLevelChangedEvent (delete): %s", _exc)
        return {"status": "ok", "level": level}
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": "delete_not_allowed", "message": str(exc)}) from exc
    except Exception as exc:
        logger.warning("delete_taxonomy_level failed level=%d: %s", level, exc)
        raise HTTPException(status_code=500, detail={"error": "taxonomy_delete_failed"}) from exc


# ── R16: AI-generate detection pattern ───────────────────────────────────────

# LAURA-2255-003 / 30-008: use chat API with separate system + user roles.
# The description is passed as a USER message only — never concatenated into
# the system prompt. format:json ensures structured output. The system prompt
# is fixed operator-controlled text; the user-supplied description cannot
# override instructions in a different role.
_PATTERN_GEN_SYSTEM_MSG = (
    "You are a detection-pattern engineer for an AI security gateway's DLP pipeline. "
    "Given a plain-English description of a sensitive data type, produce:\n"
    "1. A single Python-compatible regular expression that detects it.\n"
    "2. A suggested sensitivity level from 1 (least sensitive) to 5 (most sensitive).\n"
    "3. A short description (max 80 chars).\n\n"
    "Output ONLY a JSON object with exactly these keys: "
    '"regex" (string), "level" (integer 1-5), "description" (string). '
    "No prose, no markdown fences, no explanation.\n\n"
    'Example: {"regex": "\\\\bOFFICIAL[\\\\s-]SENSITIVE\\\\b", "level": 4, '
    '"description": "UK OFFICIAL-SENSITIVE classification marking"}'
)


class GeneratePatternRequest(BaseModel):
    description: str = Field(
        min_length=5, max_length=500,
        description="Plain-English description of the sensitive data type to detect, "
                    "e.g. 'credit-card numbers' or 'OFFICIAL-SENSITIVE marking'."
    )


@router.post("/generate-pattern")
async def generate_pattern(body: GeneratePatternRequest, session: AdminSession):  # noqa: ARG001
    """R16 — AI-generate a detection pattern from a plain-English description.

    POST a description of a sensitive data type → returns a generated regex,
    suggested sensitivity level (1–5), and short description. Uses the
    install-default model (resolved via YASHIGANI_OPA_ASSISTANT_MODEL env var;
    defaults to qwen2.5:3b — the structured-output capable model always pulled
    by the installer). FIND-003: never uses OLLAMA_MODEL (may be a VRAM-tier
    model that returns empty JSON for structured-output tasks).

    The returned pattern is a DRAFT — the admin reviews and creates it via
    POST /admin/sensitivity/patterns. Nothing is auto-applied.

    Worked example: "UK government OFFICIAL-SENSITIVE document markings"
    → regex matching OFFICIAL-SENSITIVE → level 4.

    LAURA-2255-003 hardening: uses chat API (system+user roles), format:json,
    and does NOT return the raw LLM response to the client.
    FIND-003 hardening: retries once with stricter prompt on empty response;
    returns actionable error instead of silent empty pattern.
    """
    # YSG-RISK-193: getattr(backoffice_state, "ollama_url", ...) was always
    # truthy (dataclass default "http://ollama:11434" — the attribute is
    # never actually assigned anywhere in the backoffice codebase), so the
    # YASHIGANI_OLLAMA_URL/OLLAMA_BASE_URL env-var fallback below it was dead
    # code and this route was permanently pinned to the hardcoded literal,
    # bypassing the Caddy mesh front. Mirrors routes/models.py's
    # _ollama_base() precedence: YASHIGANI_OLLAMA_URL -> OLLAMA_BASE_URL ->
    # hardcoded dev default.
    ollama_url = (
        os.getenv("YASHIGANI_OLLAMA_URL") or os.getenv("OLLAMA_BASE_URL") or "http://ollama:11434"
    ).rstrip("/")

    # FIND-003 (fix/medlow-findings): resolve model for structured-output tasks.
    # YASHIGANI_OPA_ASSISTANT_MODEL is the operator override (highest priority).
    # Default: qwen2.5:3b — the small instruct model always pulled by the installer
    # and capable of format:json structured output.
    # We do NOT fall through to OLLAMA_MODEL: it may be a VRAM-tier model
    # (llama3.1:8b etc.) that returns empty JSON for generate-pattern tasks.
    pref = os.getenv("YASHIGANI_OPA_ASSISTANT_MODEL")
    _STRUCTURED_OUTPUT_DEFAULT = "qwen2.5:3b"
    ollama_reachable = False
    from yashigani.inspection._ollama_transport import ollama_async_client
    try:
        async with ollama_async_client(ollama_url, timeout=10.0) as c:
            tags_resp = await c.get(ollama_url + "/api/tags")
            tags_resp.raise_for_status()
            avail = [m.get("name") for m in tags_resp.json().get("models", []) if m.get("name")]
            ollama_reachable = True
    except Exception as _exc:
        logger.warning("generate_pattern: Ollama unreachable at %s: %s", ollama_url, _exc)
        avail = []
    if not avail and not pref:
        raise _HTTPException(
            status_code=503,
            detail={
                "error": "no_model_available",
                "message": (
                    f"No LLM models available. Ollama at {ollama_url} "
                    + ("returned 0 models — pull one first (e.g. `ollama pull qwen2.5:3b`)"
                       if ollama_reachable else "is unreachable — ensure the Ollama service is running")
                    + ". Set YASHIGANI_OPA_ASSISTANT_MODEL to override the model choice."
                ),
            },
        )
    model = pref if pref else _STRUCTURED_OUTPUT_DEFAULT
    if pref and avail and pref not in avail:
        logger.warning(
            "generate_pattern: preferred model %r not in pulled models %s — will attempt anyway",
            pref, avail,
        )

    # LAURA-2255-003: chat API with separate system + user roles.
    # description is the user message — not concatenated into the system prompt.
    # FIND-003: helper to call the chat API once; used for initial attempt + retry.
    async def _call_llm(system_msg: str) -> str:
        async with ollama_async_client(ollama_url, timeout=60.0) as client:
            r = await client.post(
                ollama_url + "/api/chat",
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_msg},
                        {"role": "user", "content": body.description},
                    ],
                    "format": "json",
                    "stream": False,
                },
            )
            r.raise_for_status()
            return (r.json().get("message", {}).get("content") or "").strip()

    try:
        raw = await _call_llm(_PATTERN_GEN_SYSTEM_MSG)
    except _httpx.HTTPError as exc:
        logger.warning("generate_pattern: LLM error: %s", exc)
        # P1.4: include the model name so admins can diagnose
        # "model not found" (404) vs "Ollama down" vs other issues.
        raise _HTTPException(
            status_code=503,
            detail={"error": "llm_unavailable",
                    "message": f"LLM request failed (model={model!r}, ollama={ollama_url}): {exc}"},
        )

    # FIND-003: retry once with a stricter prompt if the response is empty or
    # clearly not a JSON object. Some VRAM-tier models ignore format:json on the
    # first attempt. qwen2.5:3b reliably handles this on retry.
    _STRICT_SUFFIX = (
        "\n\nIMPORTANT: You MUST respond with ONLY a JSON object, no other text. "
        'Example: {"regex": "\\\\bpattern\\\\b", "level": 3, "description": "short desc"}'
    )
    _needs_retry = not raw or not _re.search(r"\{", raw)
    if _needs_retry:
        logger.warning(
            "generate_pattern: empty/non-JSON response from model=%r (len=%d) — retrying with stricter prompt",
            model, len(raw),
        )
        try:
            raw = await _call_llm(_PATTERN_GEN_SYSTEM_MSG + _STRICT_SUFFIX)
        except _httpx.HTTPError as exc:
            logger.warning("generate_pattern: retry LLM error: %s", exc)
            raise _HTTPException(
                status_code=503,
                detail={"error": "llm_unavailable",
                        "message": f"LLM retry failed (model={model!r}, ollama={ollama_url}): {exc}"},
            )

    # Parse JSON — best-effort; log failures server-side only (never expose raw to client)
    generated_regex: str = ""
    suggested_level: int = 3
    generated_description: str = body.description[:80]
    parse_ok: bool = False

    try:
        m = _re.search(r"\{[^{}]+\}", raw, _re.DOTALL)
        payload = _json.loads(m.group(0) if m else raw)
        generated_regex = str(payload.get("regex", "")).strip()
        raw_level = payload.get("level", 3)
        try:
            suggested_level = max(1, min(5, int(raw_level)))
        except (TypeError, ValueError):
            suggested_level = 3
        generated_description = str(payload.get("description", body.description))[:80]
        parse_ok = True
    except Exception as exc:
        # Log server-side only — never expose raw LLM output to client
        logger.warning("generate_pattern: parse error (logged server-side only): %s | raw=%r", exc, raw[:300])

    # FIND-003: empty regex after a successful parse is still a failure.
    # Surface a clear error rather than silently returning an empty pattern.
    if parse_ok and not generated_regex:
        logger.warning(
            "generate_pattern: model=%r returned parseable JSON but empty regex field — "
            "returning empty_regex error (raw logged server-side only)",
            model,
        )
        parse_ok = False

    # Validate the AI-generated regex for safety before returning it
    if generated_regex:
        try:
            _validate_regex_safety(generated_regex)
        except _HTTPException:
            # Generated regex is unsafe; clear it and report as a draft problem
            logger.warning(
                "generate_pattern: AI-generated regex failed safety validation "
                "(unsafe pattern suppressed): %r", generated_regex,
            )
            generated_regex = ""
            parse_ok = False

    # AUDIT-GAP-001: emit AI-generation event to the hash-chain ledger.
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(
                SensitivityPatternAIGeneratedEvent(
                    admin_account=session.account_id,
                    description_length=len(body.description),
                    model=model,
                    generated_regex_hash=_sha256_hex(generated_regex) if generated_regex else "",
                    suggested_level=suggested_level,
                    parse_ok=parse_ok,
                )
            )
        except Exception as _exc:
            logger.error("Failed to write SensitivityPatternAIGeneratedEvent: %s", _exc)

    # LAURA-2255-003: raw_llm_response is NEVER returned to the client.
    # Log it server-side above; the client gets only the structured fields.
    # FIND-003: "ok" requires a non-empty regex. "parse_error" = unparseable JSON.
    # "empty_regex" = parseable JSON but the regex field was empty (actionable signal
    # to the admin: try a more specific description or set YASHIGANI_OPA_ASSISTANT_MODEL).
    if parse_ok:
        status_str = "ok"
    elif not raw or not _re.search(r"\{", raw):
        status_str = "empty_response"
    else:
        status_str = "parse_error"

    note_ok = (
        "AI-generated draft — review the regex before applying. "
        "To create the pattern: POST /admin/sensitivity/patterns with "
        "{'classification': '<level>', 'type': 'regex', "
        "'pattern': '<regex>', 'description': '<desc>'}."
    )
    note_fail = (
        "The model returned an empty or unparseable response. "
        "Try a more specific description (e.g. 'UK National Insurance numbers in the format AB123456C'). "
        "You can also set YASHIGANI_OPA_ASSISTANT_MODEL=qwen2.5:3b in docker/.env to force the "
        "structured-output model."
    )
    return {
        "status": status_str,
        "description": body.description,
        "model": model,
        "generated_regex": generated_regex,
        "suggested_level": suggested_level,
        "generated_description": generated_description,
        "note": note_ok if parse_ok else note_fail,
    }
