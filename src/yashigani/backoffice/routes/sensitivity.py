"""
Yashigani Backoffice — Sensitivity pattern management routes.

# Last updated: 2026-05-03T00:00:00+01:00

CRUD for detection patterns used by the sensitivity classifier pipeline.
  GET     /admin/sensitivity/patterns    — List all patterns
  POST    /admin/sensitivity/patterns    — Create a pattern (step-up required)
  DELETE  /admin/sensitivity/patterns/{id} — Delete a pattern (step-up required)
  GET     /admin/sensitivity/status      — Pipeline status (layers active/inactive)
  POST    /admin/sensitivity/test        — Test classify a text sample

LF-STEPUP-AGENT-CREATE (2026-04-27): POST and DELETE /patterns added step-up
gate — DLP rule mutation is a policy-sensitive operation; a hijacked admin
session must not bypass TOTP to neutralise detection patterns.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope

logger = logging.getLogger(__name__)

router = APIRouter()


# ── In-memory pattern store ──────────────────────────────────────────────

_patterns: list[dict] = [
    {"id": "1", "classification": "RESTRICTED", "type": "regex", "pattern": r"\b(?:\d[ -]*?){13,19}\b", "description": "Credit/debit card"},
    {"id": "2", "classification": "RESTRICTED", "type": "regex", "pattern": r"\b(?:sk-|sk-ant-)[A-Za-z0-9_-]{20,}\b", "description": "API key"},
    {"id": "3", "classification": "CONFIDENTIAL", "type": "regex", "pattern": r"\b\d{3}-\d{2}-\d{4}\b", "description": "US SSN"},
    {"id": "4", "classification": "CONFIDENTIAL", "type": "regex", "pattern": r"\b\d{3}[- ]?\d{3}[- ]?\d{4}\b", "description": "US/CA phone"},
    {"id": "5", "classification": "INTERNAL", "type": "regex", "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "description": "Email address"},
]
_pattern_counter = 5


# ── Request / Response models ─────────────────────────────────────────────

class PatternRequest(BaseModel):
    classification: str = Field(pattern=r"^(RESTRICTED|CONFIDENTIAL|INTERNAL|PUBLIC)$")
    type: str = Field(default="regex", pattern=r"^(regex|keyword|fasttext|ollama)$")
    pattern: str = Field(min_length=1, max_length=512)
    description: str = Field(min_length=1, max_length=256)


class TestClassifyRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10000)


# ── Endpoints ─────────────────────────────────────────────────────────────

@router.get("/patterns")
async def list_patterns(session: AdminSession):
    return {"patterns": _patterns}


@router.post("/patterns", status_code=201)
async def create_pattern(body: PatternRequest, session: StepUpAdminSession):
    global _pattern_counter
    _pattern_counter += 1
    pattern = {
        "id": str(_pattern_counter),
        "classification": body.classification,
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
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend
        sklearn_available = True
    except Exception:
        pass

    return {
        "regex": True,  # always active
        "sklearn_available": sklearn_available,
        # Legacy key retained for dashboard.js backward-compat; remove in v2.24.0.
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
