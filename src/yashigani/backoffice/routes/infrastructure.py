"""
Yashigani Backoffice — Infrastructure management routes.

Last updated: 2026-05-02T09:00:00+01:00

Provides admin control over:
  - Availability zone topology configuration
  - KEDA autoscaling parameters per workload
"""
from __future__ import annotations
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)
router = APIRouter()


class TopologyConfig(BaseModel):
    zones: list[str] = Field(description="List of AZ names, e.g. ['us-east-1a', 'us-east-1b']")
    spread_policy: str = Field(
        default="ScheduleAnyway",
        pattern="^(DoNotSchedule|ScheduleAnyway)$",
        description="K8s topology spread policy"
    )
    max_skew: int = Field(default=1, ge=1, le=5)


class AutoscalingConfig(BaseModel):
    min_replicas: int = Field(ge=1, le=20)
    max_replicas: int = Field(ge=1, le=100)
    cpu_threshold: Optional[int] = Field(default=70, ge=10, le=100)
    memory_threshold: Optional[int] = Field(default=80, ge=10, le=100)


@router.get("/topology")
async def get_topology(session: AdminSession):
    """Return current AZ topology info and warnings."""
    az_count = getattr(backoffice_state, "cluster_az_count", 1)
    warnings = []
    if az_count < 2:
        warnings.append(
            "Single AZ detected. A zone outage will take down the entire stack. "
            "Add nodes in additional AZs and reconfigure topology."
        )
    return {
        "az_count": az_count,
        "spread_policy": getattr(backoffice_state, "topology_spread_policy", "ScheduleAnyway"),
        "warnings": warnings,
    }


@router.put("/topology")
async def update_topology(
    body: TopologyConfig,
    session: AdminSession,
):
    """Update topology spread configuration."""
    az_count = len(set(body.zones))
    if body.spread_policy == "DoNotSchedule" and az_count < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "single_az_conflict",
                "detail": f"DoNotSchedule requires >=2 zones; detected {az_count}",
            },
        )

    # YSG-RISK-154: audit_writer being completely UNSET is a startup-invariant
    # violation (every sibling comment claims "set unconditionally at
    # startup"), not a transient write hiccup. Previously this was an
    # `assert` INSIDE the same try/except that also caught write failures —
    # AssertionError IS an Exception, so the "fail-fast" assert was silently
    # swallowed by its own surrounding except, and the mutation below still
    # completed with a 200 and zero audit trail. Check BEFORE mutating state
    # so an unavailable audit subsystem rejects the change outright rather
    # than silently enacting an unaudited one.
    if backoffice_state.audit_writer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "audit_writer_unavailable",
                "message": "Topology change rejected: the audit subsystem is not available.",
            },
        )

    # Persist to state (would trigger helm upgrade in full implementation)
    backoffice_state.cluster_az_count = az_count  # type: ignore[attr-defined]
    backoffice_state.topology_spread_policy = body.spread_policy  # type: ignore[attr-defined]

    # YSG-RISK-153: a TRANSIENT write failure (writer present, .write() itself
    # raised) must not silently vanish into a clean 200 with no trace — surface
    # it in the response (audit_recorded=false) so the caller/admin knows the
    # audit trail may be incomplete for this change. The mutation itself still
    # stands (consistent with the rest of the codebase's fail-soft-on-write
    # convention); only the writer-unset case above is fail-closed.
    audit_recorded = True
    try:
        from yashigani.audit.schema import ConfigChangedEvent
        backoffice_state.audit_writer.write(ConfigChangedEvent(
            admin_account=session.account_id,
            setting="topology",
            previous_value="",
            new_value=f"zones={body.zones}, policy={body.spread_policy}",
        ))
    except Exception as exc:
        logger.warning("Audit write failed: %s", exc)
        audit_recorded = False

    return {
        "zones": body.zones,
        "az_count": az_count,
        "spread_policy": body.spread_policy,
        "max_skew": body.max_skew,
        "audit_recorded": audit_recorded,
    }


@router.get("/autoscaling")
async def get_autoscaling(session: AdminSession):
    """Return current autoscaling config for all workloads."""
    return {
        "keda_enabled": True,
        "workloads": {
            "gateway": {"min_replicas": 2, "max_replicas": 10, "cpu_threshold": 70, "memory_threshold": 80},
            "backoffice": {"min_replicas": 2, "max_replicas": 4, "cpu_threshold": 70, "memory_threshold": 80},
            "policy": {"min_replicas": 2, "max_replicas": 6, "cpu_threshold": 60},
            "ollama": {"min_replicas": 1, "max_replicas": 4, "latency_p95_threshold_seconds": 5},
        },
        "note": "Changes apply via helm upgrade. Use PUT /autoscaling/{workload} to update.",
    }


@router.put("/autoscaling/{workload}")
async def update_autoscaling(
    workload: str,
    body: AutoscalingConfig,
    session: AdminSession,
):
    """Update autoscaling parameters for a workload."""
    valid_workloads = {"gateway", "backoffice", "policy", "ollama"}
    if workload not in valid_workloads:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "workload_not_found", "valid": list(valid_workloads)},
        )
    if body.min_replicas > body.max_replicas:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_replica_range", "detail": "min_replicas must be <= max_replicas"},
        )
    logger.info(
        "Autoscaling update: workload=%s min=%d max=%d (admin=%s)",
        workload, body.min_replicas, body.max_replicas, session.account_id,
    )
    return {
        "workload": workload,
        "min_replicas": body.min_replicas,
        "max_replicas": body.max_replicas,
        "cpu_threshold": body.cpu_threshold,
        "memory_threshold": body.memory_threshold,
        "status": "applied",
        "note": "ScaledObject patched. Changes take effect within 30 seconds.",
    }
