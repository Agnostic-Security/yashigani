"""
Yashigani Backoffice — 5.0 model-security admin routes (T5).

Operator surface for the new dual-control security controls. All mutating
endpoints require a stepped-up admin session; the store enforces B≠A (the
approver must differ from the proposer) and the confirming-digest byte-compare.

Routes:
  A5 model-integrity pin:
    POST /admin/model-security/pin/bootstrap
    POST /admin/model-security/pin/propose
    POST /admin/model-security/pin/approve
  Rug-pull manifest re-approval:
    POST /admin/model-security/manifest/approve
  T1 rule promotion (LLM→mechanical learning loop):
    GET  /admin/model-security/promotions            (list pending)
    POST /admin/model-security/promotions/approve
    POST /admin/model-security/promotions/reject
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import StepUpAdminSession
from yashigani.backoffice.state import backoffice_state

router = APIRouter()
logger = logging.getLogger("yashigani.model_security")


def _pin_dc():
    dc = backoffice_state.model_pin_dual_control
    if dc is None:
        raise HTTPException(status_code=503, detail={"error": "model_pin_unavailable"})
    return dc


def _manifest_gate():
    g = backoffice_state.manifest_reapproval_gate
    if g is None:
        raise HTTPException(status_code=503, detail={"error": "manifest_gate_unavailable"})
    return g


def _promo_store():
    s = backoffice_state.rule_promotion_store
    if s is None:
        raise HTTPException(status_code=503, detail={"error": "rule_promotion_unavailable"})
    return s


# ── A5 model-integrity pin ───────────────────────────────────────────────────

class PinBootstrapRequest(BaseModel):
    model: str = Field(min_length=1, max_length=128)
    weights_sha256: str = Field(default="", max_length=128)
    manifest_digest: str = Field(default="", max_length=256)


class PinProposeRequest(BaseModel):
    model: str = Field(min_length=1, max_length=128)
    new_weights_sha256: str = Field(default="", max_length=128)
    new_manifest_digest: str = Field(default="", max_length=256)
    justification: str = Field(min_length=4, max_length=2000)


class PinApproveRequest(BaseModel):
    model: str = Field(min_length=1, max_length=128)
    confirming_weights_sha256: str = Field(default="", max_length=128)
    confirming_manifest_digest: str = Field(default="", max_length=256)


@router.post("/pin/bootstrap")
async def pin_bootstrap(body: PinBootstrapRequest, session: StepUpAdminSession):
    from yashigani.inspection.model_integrity import ModelIntegrityError
    try:
        pin = _pin_dc().bootstrap(
            body.model, body.weights_sha256, body.manifest_digest,
            actor_id=session.account_id,
        )
    except ModelIntegrityError as exc:
        raise HTTPException(status_code=400, detail={"error": "bootstrap_failed", "message": str(exc)})
    return {"status": "bootstrapped", "model": pin.model}


@router.post("/pin/propose")
async def pin_propose(body: PinProposeRequest, session: StepUpAdminSession):
    from yashigani.inspection.model_integrity import DualControlError
    try:
        pid = _pin_dc().propose(
            body.model, body.new_weights_sha256, body.new_manifest_digest,
            justification=body.justification, initiator_id=session.account_id,
        )
    except DualControlError as exc:
        raise HTTPException(status_code=400, detail={"error": "propose_failed", "message": str(exc)})
    return {"status": "pending_approval", "model": body.model, "proposal_id": pid}


@router.post("/pin/approve")
async def pin_approve(body: PinApproveRequest, session: StepUpAdminSession):
    from yashigani.inspection.model_integrity import DualControlError
    try:
        pin = _pin_dc().approve(
            body.model, approver_id=session.account_id,
            confirming_weights_sha256=body.confirming_weights_sha256,
            confirming_manifest_digest=body.confirming_manifest_digest,
        )
    except DualControlError as exc:
        raise HTTPException(status_code=400, detail={"error": "approve_failed", "message": str(exc)})
    return {"status": "approved", "model": pin.model}


# ── rug-pull manifest re-approval ────────────────────────────────────────────

class ManifestApproveRequest(BaseModel):
    agent_id: str = Field(min_length=1, max_length=128)
    confirming_sha: str = Field(min_length=1, max_length=128)


@router.post("/manifest/approve")
async def manifest_approve(body: ManifestApproveRequest, session: StepUpAdminSession):
    from yashigani.mcp.manifest_reapproval import ManifestReapprovalError
    try:
        sha = _manifest_gate().approve(
            body.agent_id, approver_id=session.account_id, confirming_sha=body.confirming_sha)
    except ManifestReapprovalError as exc:
        raise HTTPException(status_code=400, detail={"error": "manifest_approve_failed", "message": str(exc)})
    return {"status": "approved", "agent_id": body.agent_id, "active_sha": sha}


# ── T1 rule promotion ────────────────────────────────────────────────────────

class PromotionApproveRequest(BaseModel):
    candidate_id: str = Field(min_length=1, max_length=64)
    confirming_pattern: str = Field(min_length=1, max_length=512)


class PromotionRejectRequest(BaseModel):
    candidate_id: str = Field(min_length=1, max_length=64)


@router.get("/promotions")
async def list_promotions(session: StepUpAdminSession):  # noqa: ARG001 — auth gate
    store = _promo_store()
    pending = []
    try:
        for key in store._r.scan_iter("yashigani:rulepromo:pending:*"):
            raw = store._r.get(key)
            if raw:
                rec = json.loads(raw if isinstance(raw, str) else raw.decode())
                pending.append({"candidate_id": rec["candidate_id"],
                                "pattern": rec["pattern"], "source": rec["source"]})
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail={"error": "store_unavailable", "message": str(exc)})
    return {"pending": pending}


@router.post("/promotions/approve")
async def approve_promotion(body: PromotionApproveRequest, session: StepUpAdminSession):
    from yashigani.inspection.rule_promotion import RulePromotionError
    try:
        pat = _promo_store().approve(
            body.candidate_id, approver_id=session.account_id,
            confirming_pattern=body.confirming_pattern)
    except RulePromotionError as exc:
        raise HTTPException(status_code=400, detail={"error": "promotion_approve_failed", "message": str(exc)})
    return {"status": "approved", "candidate_id": body.candidate_id, "pattern": pat}


@router.post("/promotions/reject")
async def reject_promotion(body: PromotionRejectRequest, session: StepUpAdminSession):
    _promo_store().reject(body.candidate_id, approver_id=session.account_id)
    return {"status": "rejected", "candidate_id": body.candidate_id}
