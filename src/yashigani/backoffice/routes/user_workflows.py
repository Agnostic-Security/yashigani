"""
Yashigani Backoffice — 4.0 Workflow run-history routes.

All endpoints enforce ``require_user_session`` (RISK-100): user-tier session
required; admin sessions are rejected with 403 wrong_plane.

BOLA / OWASP API3: every query that touches a specific workflow includes an
owner_identity_id check scoped to ``session.account_id``.  A mismatch returns
404 — never 403 — so a workflow's existence cannot be inferred.

Architecture note: the WorkflowScheduler runs in the GATEWAY process.  These
backoffice routes read run history directly from Redis DB 6 (same data the
scheduler writes) — no IPC required.  The spec key provides BOLA enforcement.

Routes
------
  GET /user/workflows/{workflow_id}/runs
      List run records for a workflow (newest first, max 50).
      Returns 404 if the session's account_id != workflow owner or spec missing.

  GET /user/workflows/{workflow_id}/runs/{run_id}
      Fetch one run record (per-step detail).

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter, HTTPException, status

from yashigani.backoffice.middleware import UserSession

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Redis DB 6 client (workflow scheduler namespace)
# ---------------------------------------------------------------------------

def _get_wf_redis():
    """Return a Redis client for DB 6 (workflow scheduler namespace) or raise 503."""
    try:
        import redis as _redis
        from yashigani.gateway._redis_url import build_redis_url

        secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
        redis_use_tls = os.getenv("REDIS_USE_TLS", "true").lower() == "true"
        url = build_redis_url(
            6,
            use_tls=redis_use_tls,
            secrets_dir=secrets_dir,
            client_cert_name="gateway_client",
        )
        r = _redis.from_url(url, decode_responses=False)
        r.ping()
        return r
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "scheduler_unavailable",
                    "message": "Workflow run store not available."},
        ) from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _authorise_workflow(r, workflow_id: str, session) -> None:
    """BOLA guard: verify the session owner matches the workflow owner.

    Raises HTTP 404 on mismatch or missing spec (existence must not be revealed).
    """
    from yashigani.gateway.workflow_scheduler import _redis_get_spec
    spec = _redis_get_spec(r, workflow_id)
    if spec is None:
        raise HTTPException(status_code=404,
                            detail={"error": "not_found"})
    if spec.owner_identity_id != session.account_id:
        # Return 404 — not 403 — to avoid leaking existence (OWASP API3)
        raise HTTPException(status_code=404,
                            detail={"error": "not_found"})


def _run_to_dict(run) -> dict:
    """Serialise a WorkflowRun to a JSON-safe dict (output redacted on denied steps)."""
    return {
        "run_id": run.run_id,
        "workflow_id": run.workflow_id,
        "status": run.status,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "trigger_kind": run.trigger_kind,
        "steps": [
            {
                "step_index": s.step_index,
                "actor": s.actor,
                "action": s.action,
                "status": s.status,
                "block_source": s.block_source,
                "ingress_opa": s.ingress_opa,
                "egress_opa": s.egress_opa,
                "inspection_verdict": s.inspection_verdict,
                "started_at": s.started_at,
                "finished_at": s.finished_at,
                # Output is included for completed steps only.
                # Denied steps never store output (blocked payload never persisted).
                "output": s.output if s.status == "completed" else None,
            }
            for s in run.steps
        ],
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/user/workflows/{workflow_id}/runs")
async def list_workflow_runs(
    workflow_id: str,
    session: UserSession,
    limit: int = 50,
):
    """List run history for a workflow (newest first).

    Returns at most ``limit`` records (max 100).  BOLA-enforced: session
    account_id must match the workflow owner_identity_id.
    """
    if limit < 1 or limit > 100:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_limit", "message": "limit must be 1–100"},
        )
    r = _get_wf_redis()
    _authorise_workflow(r, workflow_id, session)
    from yashigani.gateway.workflow_scheduler import _redis_list_runs
    runs = _redis_list_runs(r, workflow_id, limit=limit)
    return {
        "workflow_id": workflow_id,
        "runs": [_run_to_dict(run) for run in runs],
    }


@router.get("/user/workflows/{workflow_id}/runs/{run_id}")
async def get_workflow_run(
    workflow_id: str,
    run_id: str,
    session: UserSession,
):
    """Fetch a single run record with per-step detail."""
    r = _get_wf_redis()
    _authorise_workflow(r, workflow_id, session)
    from yashigani.gateway.workflow_scheduler import _redis_get_run
    run = _redis_get_run(r, workflow_id, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return _run_to_dict(run)
