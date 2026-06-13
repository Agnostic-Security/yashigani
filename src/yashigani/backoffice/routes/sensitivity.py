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

logger = logging.getLogger(__name__)

router = APIRouter()

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
    return {"status": "ok", "pattern": pattern}


@router.delete("/patterns/{pattern_id}")
async def delete_pattern(pattern_id: str, session: StepUpAdminSession):
    global _patterns
    before = len(_patterns)
    _patterns = [p for p in _patterns if p["id"] != pattern_id]
    if len(_patterns) == before:
        raise HTTPException(status_code=404, detail={"error": "pattern_not_found"})
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
    """Test the sensitivity classifier against a text sample."""
    pipeline = backoffice_state.inspection_pipeline
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Inspection pipeline not available")

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
        return {"status": "ok", "level": level, "label": body.label, "colour_class": body.colour_class}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": "invalid_colour_class", "message": str(exc)}) from exc
    except Exception as exc:
        logger.warning("upsert_taxonomy_level failed level=%d: %s", level, exc)
        raise HTTPException(status_code=500, detail={"error": "taxonomy_update_failed"}) from exc


@router.delete("/taxonomy/{level}")
async def delete_taxonomy_level(level: int, session: StepUpAdminSession):
    """Delete a taxonomy level for the default tenant."""
    try:
        await _taxonomy_store.delete_level(tenant_id="default", level_number=level)
        return {"status": "ok", "level": level}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": "delete_not_allowed", "message": str(exc)}) from exc
    except Exception as exc:
        logger.warning("delete_taxonomy_level failed level=%d: %s", level, exc)
        raise HTTPException(status_code=500, detail={"error": "taxonomy_delete_failed"}) from exc


# ── R16: AI-generate detection pattern ───────────────────────────────────────

# Few-shot examples that calibrate the LLM to the expected output format.
# The OFFICIAL-SENSITIVE example is the documented worked example from the brief.
_PATTERN_GEN_SYSTEM = """You are a detection-pattern engineer for an AI security gateway's DLP pipeline.
Given a plain-English description of a sensitive data type, produce:
1. A single Python-compatible regular expression that detects it.
2. A suggested sensitivity level from 1 (least sensitive) to 5 (most sensitive).
3. A short description (max 80 chars).

Output ONLY a JSON object with these keys: "regex", "level" (integer 1-5), "description".
No prose, no markdown fences, no explanation.

Example input: "UK government OFFICIAL-SENSITIVE document markings"
Example output: {"regex": "\\\\bOFFICIAL[\\\\s-]SENSITIVE\\\\b", "level": 4, "description": "UK OFFICIAL-SENSITIVE classification marking"}

Example input: "credit card numbers (Visa, Mastercard, Amex)"
Example output: {"regex": "\\\\b(?:\\\\d[ -]*?){13,19}\\\\b", "level": 4, "description": "Credit/debit card number"}

Example input: "US Social Security Numbers"
Example output: {"regex": "\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b", "level": 4, "description": "US SSN"}

Now produce the JSON for:"""


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
    install-default model (resolved via YASHIGANI_OPA_ASSISTANT_MODEL /
    OLLAMA_MODEL / first available Ollama model).

    The returned pattern is a DRAFT — the admin reviews and creates it via
    POST /admin/sensitivity/patterns. Nothing is auto-applied.

    Worked example: "UK government OFFICIAL-SENSITIVE document markings"
    → regex matching OFFICIAL-SENSITIVE → level 4.
    """
    from yashigani.backoffice.state import backoffice_state as _state

    ollama_url = str(
        getattr(_state, "ollama_url", None)
        or os.getenv("YASHIGANI_OLLAMA_URL", "http://ollama:11434")
    ).rstrip("/")

    # Resolve install-default model
    pref = os.getenv("YASHIGANI_OPA_ASSISTANT_MODEL") or os.getenv("OLLAMA_MODEL")
    try:
        async with _httpx.AsyncClient(timeout=10.0) as c:
            tags_resp = await c.get(ollama_url + "/api/tags")
            avail = [m.get("name") for m in tags_resp.json().get("models", []) if m.get("name")]
    except Exception:
        avail = []
    model = pref if (pref and pref in avail) else (avail[0] if avail else (pref or "qwen2.5:3b"))

    prompt = f"{_PATTERN_GEN_SYSTEM} {body.description}\nJSON output:"

    try:
        async with _httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                ollama_url + "/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
            )
            resp.raise_for_status()
            raw = (resp.json().get("response") or "").strip()
    except _httpx.HTTPError as exc:
        logger.warning("generate_pattern: LLM error: %s", exc)
        raise _HTTPException(
            status_code=503,
            detail={"error": "llm_unavailable",
                    "message": "Could not reach the pattern-generation LLM. "
                               "Ensure the Ollama service is running."},
        )

    # Strip markdown fences if any
    if raw.startswith("```"):
        lines = raw.split("\n")
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        raw = "\n".join(lines[1:]).strip()

    # Parse JSON — best-effort; return raw on parse failure
    generated_regex: str = ""
    suggested_level: int = 3
    generated_description: str = body.description[:80]
    parse_error: str | None = None

    try:
        # Find the first {...} block in case the LLM added preamble
        m = _re.search(r"\{[^{}]+\}", raw, _re.DOTALL)
        payload = _json.loads(m.group(0) if m else raw)
        generated_regex = str(payload.get("regex", "")).strip()
        raw_level = payload.get("level", 3)
        try:
            suggested_level = max(1, min(5, int(raw_level)))
        except (TypeError, ValueError):
            suggested_level = 3
        generated_description = str(payload.get("description", body.description))[:80]
    except Exception as exc:
        parse_error = f"LLM response could not be parsed as JSON: {exc}. Raw: {raw[:300]}"
        logger.warning("generate_pattern: parse error: %s", parse_error)

    return {
        "status": "ok" if not parse_error else "parse_error",
        "description": body.description,
        "model": model,
        "generated_regex": generated_regex,
        "suggested_level": suggested_level,
        "generated_description": generated_description,
        "parse_error": parse_error,
        "raw_llm_response": raw if parse_error else None,
        "note": (
            "AI-generated draft — review the regex before applying. "
            "To create the pattern: POST /admin/sensitivity/patterns with "
            "{'classification': '<level>', 'type': 'regex', "
            "'pattern': '<regex>', 'description': '<desc>'}."
        ),
    }
