"""
Yashigani Backoffice — Inspection pipeline management routes.
GET  /inspection/status        — pipeline health, current model, threshold, mode
GET  /inspection/models        — list available Ollama models
POST /inspection/model         — set active classifier model
GET  /inspection/threshold     — get sanitization confidence threshold
POST /inspection/threshold     — set sanitization confidence threshold (0.70–0.99)
GET  /inspection/mode          — get pipeline mode (strict | permissive)
POST /inspection/mode          — set pipeline mode

Last updated: 2026-05-03
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.common.error_envelope import safe_error_envelope

router = APIRouter()

_VALID_MODES = {"strict", "permissive"}


class ModelSelectRequest(BaseModel):
    model: str = Field(min_length=1, max_length=128)


class ThresholdRequest(BaseModel):
    threshold: float = Field(ge=0.70, le=0.99)


class ModeRequest(BaseModel):
    mode: str = Field(pattern=r"^(strict|permissive)$")


@router.get("/status")
async def inspection_status(session: AdminSession):
    """Return current pipeline configuration and health."""
    state = backoffice_state
    pipeline = state.inspection_pipeline

    if pipeline is None:
        return {
            "configured": False,
            "healthy": False,
        }

    classifier = pipeline._classifier
    models = classifier.available_models()
    ollama_reachable = len(models) > 0

    return {
        "configured": True,
        "healthy": ollama_reachable,
        "model": classifier._model,
        "ollama_base_url": classifier._base_url,
        "threshold": pipeline._threshold,
        "mode": getattr(pipeline, "_mode", "strict"),
        "ollama_models_available": models,
    }


@router.get("/models")
async def list_models(session: AdminSession):
    """Return all model tags currently available in the local Ollama instance."""
    state = backoffice_state
    pipeline = state.inspection_pipeline

    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "inspection_pipeline_not_configured"},
        )

    models = pipeline._classifier.available_models()
    return {"models": models, "total": len(models)}


@router.post("/model")
async def set_model(body: ModelSelectRequest, session: AdminSession):
    """Switch the active classifier model. Model must be available in Ollama."""
    state = backoffice_state
    pipeline = state.inspection_pipeline

    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "inspection_pipeline_not_configured"},
        )

    available = pipeline._classifier.available_models()
    if available and body.model not in available:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "model_not_available",
                "message": f"Model '{body.model}' not found in Ollama. "
                           "Pull it first with: ollama pull " + body.model,
                "available_models": available,
            },
        )

    prev_model = pipeline._classifier._model
    pipeline._classifier._model = body.model

    assert state.audit_writer is not None  # set unconditionally at startup
    state.audit_writer.write(_config_event(
        session.account_id, "inspection.model", prev_model, body.model,
        account_tier=session.account_tier,
    ))
    return {"status": "ok", "model": body.model}


@router.get("/threshold")
async def get_threshold(session: AdminSession):
    state = backoffice_state
    pipeline = state.inspection_pipeline

    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "inspection_pipeline_not_configured"},
        )

    return {
        "threshold": pipeline._threshold,
        "description": "Minimum confidence required to attempt sanitization on CREDENTIAL_EXFIL detections.",
    }


@router.post("/threshold")
async def set_threshold(body: ThresholdRequest, session: AdminSession):
    """Update the sanitization confidence threshold (0.70–0.99)."""
    state = backoffice_state
    pipeline = state.inspection_pipeline

    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "inspection_pipeline_not_configured"},
        )

    prev = pipeline._threshold
    try:
        pipeline.update_threshold(body.threshold)
    except ValueError as exc:
        payload, _ = safe_error_envelope(exc, public_message="inspection backend unavailable", status=422)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=payload,
        )

    assert state.audit_writer is not None  # set unconditionally at startup
    state.audit_writer.write(_config_event(
        session.account_id,
        "inspection.threshold",
        str(prev),
        str(body.threshold),
        account_tier=session.account_tier,
    ))
    return {"status": "ok", "threshold": body.threshold}


@router.get("/mode")
async def get_mode(session: AdminSession):
    """
    Return the current pipeline mode.

    strict     — any detection at or above threshold triggers sanitization/discard.
    permissive — detections below threshold are logged but allowed through with an alert.
    """
    state = backoffice_state
    pipeline = state.inspection_pipeline

    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "inspection_pipeline_not_configured"},
        )

    return {"mode": getattr(pipeline, "_mode", "strict")}


@router.post("/mode")
async def set_mode(body: ModeRequest, session: AdminSession):
    state = backoffice_state
    pipeline = state.inspection_pipeline

    if pipeline is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "inspection_pipeline_not_configured"},
        )

    prev = getattr(pipeline, "_mode", "strict")
    pipeline._mode = body.mode  # type: ignore[attr-defined]

    assert state.audit_writer is not None  # set unconditionally at startup
    state.audit_writer.write(_config_event(
        session.account_id, "inspection.mode", prev, body.mode,
        account_tier=session.account_tier,
    ))
    return {"status": "ok", "mode": body.mode}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _config_event(admin_id: str, setting: str, prev: str, new: str, account_tier: str = "admin"):
    # account_tier derived from session at call site — defence-in-depth: RBAC bypass visible in audit.
    from yashigani.audit.schema import ConfigChangedEvent
    return ConfigChangedEvent(
        account_tier=account_tier,
        admin_account=admin_id,
        setting=setting,
        previous_value=prev,
        new_value=new,
    )
