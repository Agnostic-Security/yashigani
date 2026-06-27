"""
Yashigani 4.0 — Workflow Scheduler + Governed Executor.

Every step of every workflow run is dispatched through the OPA-every-hop
orchestrator path (gateway/orchestrator._execute_tool_call).  Execution runs on
the workflow owner's NHI/delegated context — NOT a raw user token.  A denied hop
stops the run immediately (fail-closed) and audits a WORKFLOW_STEP_DENIED event.

Redis DB 6 — key schema (isolated namespace, separate from db/0-5):
  wf:spec:{workflow_id}           → JSON: full workflow spec (set by Tom's backend)
  wf:sched:index                  → Set: workflow_ids with enabled schedules
  wf:sched:next:{workflow_id}     → str: next fire Unix timestamp (float)
  wf:run:{workflow_id}:{run_id}   → JSON: run record (TTL 7 days)
  wf:run:idx:{workflow_id}        → ZSET: run_ids scored by started_at timestamp
  wf:lock:exec:{workflow_id}      → NX EX 900: prevents double-fire across replicas

Scheduler design
----------------
- In-process asyncio background task; check loop every 5 s.
- Single-owner per run via Redis NX lock: if another replica holds the lock for a
  given workflow_id this replica skips it silently.  No double-fire.
- Survives restart: next-fire times persisted in Redis; on startup the scheduler
  loads all enabled workflows and recomputes next-fire from the persisted state.
- K8s multi-replica: NX lock gives single-owner per run.  For strict leader-election
  wire K8s Lease objects (follow-up, documented below as F-UP-1).

Governed execution
------------------
Steps execute sequentially.  Each step's actor is a @-handle (agent slug or MCP
server).  The orchestrator._execute_tool_call path handles OPA ingress + egress +
ResponseInspection for every hop — identical to interactive orchestration.

Step output is piped to the next step's input (task argument).

Audited events
--------------
  WORKFLOW_RUN_STARTED      — one per run, on trigger
  WORKFLOW_STEP_COMPLETED   — one per clean step
  WORKFLOW_STEP_DENIED      — on OPA/inspection block (run halts)
  WORKFLOW_RUN_COMPLETED    — run finished all steps cleanly
  WORKFLOW_RUN_FAILED       — run aborted (exception or all-steps-denied)

Follow-up items
---------------
  F-UP-1  K8s Lease-based leader election for strict single-replica scheduling.
  F-UP-2  Cron DST-safe firing (currently uses UTC timestamps throughout).
  F-UP-3  Per-workflow retry policy (currently: fail immediately on denied hop).

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RUN_TTL_S = 7 * 24 * 3600   # 7 days for run records
_LOCK_TTL_S = 900             # 15-minute lock per run (generous for long steps)
_LOOP_INTERVAL_S = 5.0        # scheduler check frequency
_STEP_DEPTH = 0               # workflow-triggered hops start at depth 0
_MAX_STEPS = 50               # hard cap on steps per workflow (defence-in-depth)

# Redis key helpers
_KEY_SPEC = "wf:spec:{}"
_KEY_SCHED_INDEX = "wf:sched:index"
_KEY_SCHED_NEXT = "wf:sched:next:{}"
_KEY_RUN = "wf:run:{}:{}"
_KEY_RUN_IDX = "wf:run:idx:{}"
_KEY_LOCK = "wf:lock:exec:{}"


# ---------------------------------------------------------------------------
# Data models (mirrors Tom's pinned contract)
# ---------------------------------------------------------------------------

@dataclass
class WorkflowStep:
    """One step in a workflow.

    actor:     @-handle for the agent/persona to invoke (e.g. "@Mimi")
    action:    Free-text instruction to the actor
    uses:      List of @-handles the actor may call (MCPs / agents); scope hint
    output_to: @-handle of the entity / next step that receives this step's output
    """
    actor: str = ""
    action: str = ""
    uses: list[str] = field(default_factory=list)
    output_to: str = ""


@dataclass
class WorkflowSchedule:
    """Schedule descriptor.

    kind:    "interval" (fire every N seconds) or "cron" (UTC cron expression)
    seconds: Interval in seconds (interval kind)
    cron:    Cron expression (cron kind), e.g. "*/10 * * * *"
    """
    kind: str = "interval"
    seconds: int = 600
    cron: str = ""


@dataclass
class WorkflowSpec:
    """Full workflow specification — mirrors GET /user/workflows/{id} response."""
    workflow_id: str = ""
    owner_identity_id: str = ""
    enabled: bool = True
    steps: list[WorkflowStep] = field(default_factory=list)
    schedule: WorkflowSchedule = field(default_factory=WorkflowSchedule)

    @classmethod
    def from_dict(cls, d: dict) -> "WorkflowSpec":
        sched_d = d.get("schedule") or {}
        schedule = WorkflowSchedule(
            kind=sched_d.get("kind", "interval"),
            seconds=int(sched_d.get("seconds", 600)),
            cron=sched_d.get("cron", ""),
        )
        steps = [
            WorkflowStep(
                actor=s.get("actor", ""),
                action=s.get("action", ""),
                uses=list(s.get("uses") or []),
                output_to=s.get("output_to", ""),
            )
            for s in (d.get("steps") or [])
        ]
        return cls(
            workflow_id=d.get("workflow_id", ""),
            owner_identity_id=d.get("owner_identity_id", ""),
            enabled=bool(d.get("enabled", True)),
            steps=steps,
            schedule=schedule,
        )

    def to_dict(self) -> dict:
        return {
            "workflow_id": self.workflow_id,
            "owner_identity_id": self.owner_identity_id,
            "enabled": self.enabled,
            "steps": [asdict(s) for s in self.steps],
            "schedule": asdict(self.schedule),
        }


@dataclass
class WorkflowStepRecord:
    """Per-step execution result stored in the run record."""
    step_index: int = 0
    actor: str = ""
    action: str = ""
    status: str = "pending"   # pending | completed | denied | error
    output: str = ""
    block_source: str = ""
    ingress_opa: str = ""
    egress_opa: str = ""
    inspection_verdict: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0


@dataclass
class WorkflowRun:
    """Per-run record persisted in Redis."""
    run_id: str = ""
    workflow_id: str = ""
    owner_identity_id: str = ""
    status: str = "running"   # running | completed | blocked | failed
    steps: list[WorkflowStepRecord] = field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0
    trigger_kind: str = "scheduler"   # scheduler | manual

    def to_json(self) -> str:
        d = {
            "run_id": self.run_id,
            "workflow_id": self.workflow_id,
            "owner_identity_id": self.owner_identity_id,
            "status": self.status,
            "steps": [asdict(s) for s in self.steps],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "trigger_kind": self.trigger_kind,
        }
        return json.dumps(d)

    @classmethod
    def from_json(cls, raw: str | bytes) -> "WorkflowRun":
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        d = json.loads(raw)
        steps = [WorkflowStepRecord(**s) for s in (d.get("steps") or [])]
        return cls(
            run_id=d.get("run_id", ""),
            workflow_id=d.get("workflow_id", ""),
            owner_identity_id=d.get("owner_identity_id", ""),
            status=d.get("status", "unknown"),
            steps=steps,
            started_at=d.get("started_at", 0.0),
            finished_at=d.get("finished_at", 0.0),
            trigger_kind=d.get("trigger_kind", "scheduler"),
        )


# ---------------------------------------------------------------------------
# Cron parser (minimal UTC — handles standard 5-field cron)
# ---------------------------------------------------------------------------

def _cron_matches(expr: str, t: float) -> bool:
    """Return True if time ``t`` (Unix UTC) matches the 5-field cron expression.

    Supports: * (wildcard), N (exact), */N (every N), N-M (range), N,M (list).
    Always evaluated in UTC.
    """
    import datetime
    dt = datetime.datetime.fromtimestamp(t, tz=datetime.timezone.utc)
    try:
        fields = expr.strip().split()
        if len(fields) != 5:
            return False
        minute_f, hour_f, dom_f, month_f, dow_f = fields
        return (
            _cron_field_match(minute_f, dt.minute, 0, 59)
            and _cron_field_match(hour_f, dt.hour, 0, 23)
            and _cron_field_match(dom_f, dt.day, 1, 31)
            and _cron_field_match(month_f, dt.month, 1, 12)
            and _cron_field_match(dow_f, dt.weekday(), 0, 6)
        )
    except Exception as exc:
        logger.warning("workflow cron parse error %r: %s", expr, exc)
        return False


def _cron_field_match(field: str, value: int, lo: int, hi: int) -> bool:
    if field == "*":
        return True
    if field.startswith("*/"):
        try:
            step = int(field[2:])
            return (value - lo) % step == 0
        except ValueError:
            return False
    for part in field.split(","):
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                if int(a) <= value <= int(b):
                    return True
            except ValueError:
                pass
        else:
            try:
                if int(part) == value:
                    return True
            except ValueError:
                pass
    return False


# ---------------------------------------------------------------------------
# Identity helpers
# ---------------------------------------------------------------------------

def _make_scheduled_identity(owner_identity_id: str, identity_registry=None) -> dict:
    """Build an identity dict for the workflow owner.

    Prefers the live identity from the registry.  Falls back to a minimal
    synthetic dict (scheduler cannot be blocked by a stale/unavailable registry).
    The synthetic identity is marked account_tier='user' and has no extra groups —
    OPA will evaluate it conservatively.
    """
    if identity_registry is not None:
        try:
            real = identity_registry.get_by_id(owner_identity_id)
            if real:
                d = real if isinstance(real, dict) else real.__dict__
                # Ensure the identity signals it is operating as a scheduled NHI.
                d = dict(d)
                d["_scheduled_workflow"] = True
                return d
        except Exception as exc:
            logger.warning(
                "workflow: identity registry lookup failed for %s: %s — using synthetic",
                owner_identity_id, exc,
            )
    # Synthetic minimal identity — conservative defaults.
    return {
        "identity_id": owner_identity_id,
        "slug": owner_identity_id,
        "account_tier": "user",
        "groups": [],
        "active": True,
        "_scheduled_workflow": True,
        "_synthetic": True,
    }


# ---------------------------------------------------------------------------
# Catalog builder for a single workflow step
# ---------------------------------------------------------------------------

def _build_step_catalog(step: WorkflowStep, agent_registry=None):
    """Build a minimal ToolCatalog for one workflow step.

    Contains the step actor + any declared ``uses`` MCPs / agents.
    The catalog is the assertion of authorisation — the executor enforces OPA
    independently on every hop; the catalog bounds what the model CAN name.
    """
    from yashigani.gateway.tool_catalog import (
        CatalogEntry, ToolCatalog, sanitise_tool_token, _TASK_SCHEMA,
    )

    name_map: dict[str, CatalogEntry] = {}
    tools: list[dict] = []

    def _add_agent(slug: str) -> None:
        tname = f"agent__{slug}"
        name_map[tname] = CatalogEntry(kind="agent", target=slug, parameters=_TASK_SCHEMA)
        tools.append({
            "type": "function",
            "function": {
                "name": tname,
                "description": f"Delegate task to agent @{slug}.",
                "parameters": _TASK_SCHEMA,
            },
        })

    def _add_mcp_server(server: str) -> None:
        # Placeholder entry — the actual tool list is expanded by the MCP broker
        # at self-call time.  We register a sentinel so the catalog is non-empty
        # and the executor can route to the correct kind.
        tname = f"mcp__{server}__dispatch"
        name_map[tname] = CatalogEntry(kind="mcp", target=server,
                                       mcp_tool="dispatch", parameters={})

    # Actor
    actor_slug = step.actor.lstrip("@").lower()
    if actor_slug:
        _add_agent(actor_slug)

    # Uses (@-handles)
    for use in (step.uses or []):
        slug = use.lstrip("@").lower()
        if not slug:
            continue
        # Detect agent vs MCP: check registry; fall back to agent.
        is_agent = True
        if agent_registry is not None:
            try:
                # AgentRegistry.list_all() returns list of dicts; check name match.
                for entry in agent_registry.list_all():
                    if entry.get("name", "").lower() == slug:
                        is_agent = True
                        break
                # If not found in agent registry treat as MCP server name.
                else:
                    is_agent = False
            except Exception:
                pass

        tname = sanitise_tool_token(slug)
        if is_agent:
            if f"agent__{tname}" not in name_map:
                _add_agent(tname)
        else:
            _add_mcp_server(tname)

    return ToolCatalog(tools=tools, name_map=name_map)


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------

def _audit(writer, event) -> None:
    if writer is None:
        return
    try:
        writer.write(event)
    except Exception as exc:
        logger.warning("workflow: audit write failed: %s", exc)


def _emit_run_started(writer, run: WorkflowRun, spec: WorkflowSpec) -> None:
    from yashigani.audit.schema import WorkflowRunStartedEvent
    _audit(writer, WorkflowRunStartedEvent(
        workflow_id=spec.workflow_id,
        run_id=run.run_id,
        identity_id=spec.owner_identity_id,
        session_id=spec.owner_identity_id,
        step_count=len(spec.steps),
        schedule_kind=spec.schedule.kind,
        trigger_kind=run.trigger_kind,
    ))


def _emit_step_completed(writer, run: WorkflowRun, step_rec: WorkflowStepRecord) -> None:
    from yashigani.audit.schema import WorkflowStepCompletedEvent
    _audit(writer, WorkflowStepCompletedEvent(
        workflow_id=run.workflow_id,
        run_id=run.run_id,
        identity_id=run.owner_identity_id,
        session_id=run.owner_identity_id,
        step_index=step_rec.step_index,
        actor=step_rec.actor,
        ingress_opa=step_rec.ingress_opa,
        egress_opa=step_rec.egress_opa,
        inspection_verdict=step_rec.inspection_verdict,
    ))


def _emit_step_denied(writer, run: WorkflowRun, step_rec: WorkflowStepRecord) -> None:
    from yashigani.audit.schema import WorkflowStepDeniedEvent
    _audit(writer, WorkflowStepDeniedEvent(
        workflow_id=run.workflow_id,
        run_id=run.run_id,
        identity_id=run.owner_identity_id,
        session_id=run.owner_identity_id,
        step_index=step_rec.step_index,
        actor=step_rec.actor,
        block_source=step_rec.block_source,
        ingress_opa=step_rec.ingress_opa,
        egress_opa=step_rec.egress_opa,
        inspection_verdict=step_rec.inspection_verdict,
    ))


def _emit_run_completed(writer, run: WorkflowRun) -> None:
    from yashigani.audit.schema import WorkflowRunCompletedEvent
    _audit(writer, WorkflowRunCompletedEvent(
        workflow_id=run.workflow_id,
        run_id=run.run_id,
        identity_id=run.owner_identity_id,
        session_id=run.owner_identity_id,
        steps_completed=sum(1 for s in run.steps if s.status == "completed"),
        steps_denied=sum(1 for s in run.steps if s.status == "denied"),
        elapsed_s=run.finished_at - run.started_at,
    ))


def _emit_run_failed(writer, run: WorkflowRun, reason: str) -> None:
    from yashigani.audit.schema import WorkflowRunFailedEvent
    _audit(writer, WorkflowRunFailedEvent(
        workflow_id=run.workflow_id,
        run_id=run.run_id,
        identity_id=run.owner_identity_id,
        session_id=run.owner_identity_id,
        reason=reason,
        elapsed_s=run.finished_at - run.started_at,
    ))


# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------

def _redis_set_spec(r, spec: WorkflowSpec) -> None:
    key = _KEY_SPEC.format(spec.workflow_id)
    r.set(key, json.dumps(spec.to_dict()).encode("utf-8"))
    if spec.enabled:
        r.sadd(_KEY_SCHED_INDEX, spec.workflow_id)
    else:
        r.srem(_KEY_SCHED_INDEX, spec.workflow_id)


def _redis_get_spec(r, workflow_id: str) -> Optional[WorkflowSpec]:
    raw = r.get(_KEY_SPEC.format(workflow_id))
    if raw is None:
        return None
    try:
        d = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
        return WorkflowSpec.from_dict(d)
    except Exception as exc:
        logger.warning("workflow: corrupt spec %s: %s", workflow_id, exc)
        return None


def _redis_get_all_enabled(r) -> list[str]:
    try:
        members = r.smembers(_KEY_SCHED_INDEX)
        return [m.decode("utf-8") if isinstance(m, bytes) else m for m in members]
    except Exception as exc:
        logger.warning("workflow: failed to read schedule index: %s", exc)
        return []


def _redis_get_next(r, workflow_id: str) -> float:
    raw = r.get(_KEY_SCHED_NEXT.format(workflow_id))
    if raw is None:
        return 0.0
    try:
        return float(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    except Exception:
        return 0.0


def _redis_set_next(r, workflow_id: str, next_ts: float) -> None:
    r.set(_KEY_SCHED_NEXT.format(workflow_id), str(next_ts).encode("utf-8"))


def _redis_acquire_lock(r, workflow_id: str) -> bool:
    """SETNX + EX lock.  Returns True if this caller acquired it."""
    result = r.set(
        _KEY_LOCK.format(workflow_id),
        b"1",
        nx=True,
        ex=_LOCK_TTL_S,
    )
    return result is not None and result


def _redis_release_lock(r, workflow_id: str) -> None:
    try:
        r.delete(_KEY_LOCK.format(workflow_id))
    except Exception as exc:
        logger.warning("workflow: lock release failed %s: %s", workflow_id, exc)


def _redis_save_run(r, run: WorkflowRun) -> None:
    key = _KEY_RUN.format(run.workflow_id, run.run_id)
    idx_key = _KEY_RUN_IDX.format(run.workflow_id)
    r.setex(key, _RUN_TTL_S, run.to_json().encode("utf-8"))
    r.zadd(idx_key, {run.run_id: run.started_at})
    r.expire(idx_key, _RUN_TTL_S)


def _redis_list_runs(r, workflow_id: str, limit: int = 50) -> list[WorkflowRun]:
    idx_key = _KEY_RUN_IDX.format(workflow_id)
    try:
        run_ids = r.zrevrange(idx_key, 0, limit - 1)
    except Exception as exc:
        logger.warning("workflow: run index read failed %s: %s", workflow_id, exc)
        return []
    runs = []
    for rid_raw in run_ids:
        rid = rid_raw.decode("utf-8") if isinstance(rid_raw, bytes) else rid_raw
        raw = r.get(_KEY_RUN.format(workflow_id, rid))
        if raw is None:
            continue
        try:
            runs.append(WorkflowRun.from_json(raw))
        except Exception as exc:
            logger.warning("workflow: corrupt run %s/%s: %s", workflow_id, rid, exc)
    return runs


def _redis_get_run(r, workflow_id: str, run_id: str) -> Optional[WorkflowRun]:
    raw = r.get(_KEY_RUN.format(workflow_id, run_id))
    if raw is None:
        return None
    try:
        return WorkflowRun.from_json(raw)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Governed step execution
# ---------------------------------------------------------------------------

async def _execute_tool_call(**kwargs):
    """Module-level hook — delegates to orchestrator._execute_tool_call.

    Declared at module scope so tests can patch
    ``yashigani.gateway.workflow_scheduler._execute_tool_call`` without
    needing to reach into the orchestrator module directly.
    The lazy import avoids a circular dependency at module load time.
    """
    from yashigani.gateway.orchestrator import _execute_tool_call as _real
    return await _real(**kwargs)


async def _execute_step(
    *,
    step: WorkflowStep,
    step_index: int,
    prev_output: str,
    run: WorkflowRun,
    identity: dict,
    root_rid: str,
    agent_registry=None,
) -> WorkflowStepRecord:
    """Execute one workflow step through the OPA-every-hop orchestrator path.

    Returns a WorkflowStepRecord with status 'completed' or 'denied'.
    A denied step is fail-closed: the caller must stop the run.
    """

    actor_slug = step.actor.lstrip("@").lower()
    tool_name = f"agent__{actor_slug}" if actor_slug else ""

    task_input = step.action
    if prev_output:
        task_input = f"{prev_output}\n\n{step.action}"

    args: dict[str, Any] = {"task": task_input}
    catalog = _build_step_catalog(step, agent_registry=agent_registry)

    step_rec = WorkflowStepRecord(
        step_index=step_index,
        actor=step.actor,
        action=step.action,
        status="pending",
        started_at=time.time(),
    )

    if not tool_name or tool_name not in catalog.name_map:
        # Actor not resolvable — treat as execution error (not a policy block)
        step_rec.status = "error"
        step_rec.block_source = "actor_not_found"
        step_rec.finished_at = time.time()
        logger.warning(
            "workflow: step %d actor %r not in catalog for run %s",
            step_index, step.actor, run.run_id,
        )
        return step_rec

    try:
        # Call through the module-level wrapper so tests can patch it.
        result = await _execute_tool_call(
            tool_name=tool_name,
            args=args,
            catalog=catalog,
            identity=identity,
            depth=_STEP_DEPTH,
            root_rid=root_rid,
            iteration=step_index,
        )
    except Exception as exc:
        logger.warning(
            "workflow: step %d raised during _execute_tool_call for run %s: %s",
            step_index, run.run_id, exc,
        )
        step_rec.status = "error"
        step_rec.block_source = "executor_exception"
        step_rec.finished_at = time.time()
        return step_rec

    step_rec.ingress_opa = result.ingress_opa
    step_rec.egress_opa = result.egress_opa
    step_rec.inspection_verdict = result.inspection_verdict
    step_rec.finished_at = time.time()

    if result.blocked:
        step_rec.status = "denied"
        step_rec.block_source = result.block_source or "opa_or_inspection"
        step_rec.output = ""   # never store a blocked payload
    else:
        step_rec.status = "completed"
        step_rec.output = result.text or ""

    return step_rec


# ---------------------------------------------------------------------------
# Governed workflow run
# ---------------------------------------------------------------------------

async def _execute_workflow_run(
    *,
    spec: WorkflowSpec,
    redis_client,
    audit_writer=None,
    identity_registry=None,
    agent_registry=None,
    trigger_kind: str = "scheduler",
) -> WorkflowRun:
    """Execute all steps of one workflow run under the owner's delegated context.

    Fail-closed: a denied step stops the run immediately.
    Per-step and per-run records are saved to Redis after each step so a crash
    mid-run leaves a partial record rather than silence.

    The identity used for every hop is the WORKFLOW OWNER'S identity (resolved
    from owner_identity_id), not a shared service account.  OPA evaluates the
    owner's tier, groups, and sensitivity ceiling on every hop.
    """
    run_id = str(uuid.uuid4())
    run = WorkflowRun(
        run_id=run_id,
        workflow_id=spec.workflow_id,
        owner_identity_id=spec.owner_identity_id,
        status="running",
        started_at=time.time(),
        trigger_kind=trigger_kind,
    )
    root_rid = f"wf-{spec.workflow_id[:8]}-{run_id[:8]}"

    _redis_save_run(redis_client, run)
    identity = _make_scheduled_identity(spec.owner_identity_id, identity_registry)
    _emit_run_started(audit_writer, run, spec)

    steps = spec.steps[:_MAX_STEPS]
    prev_output = ""

    for idx, step in enumerate(steps):
        step_rec = await _execute_step(
            step=step,
            step_index=idx,
            prev_output=prev_output,
            run=run,
            identity=identity,
            root_rid=root_rid,
            agent_registry=agent_registry,
        )
        run.steps.append(step_rec)

        if step_rec.status == "denied":
            _emit_step_denied(audit_writer, run, step_rec)
            run.status = "blocked"
            run.finished_at = time.time()
            _redis_save_run(redis_client, run)
            _emit_run_failed(audit_writer, run, reason=f"step_{idx}_denied")
            logger.info(
                "workflow: run %s blocked at step %d (actor=%r block_source=%r)",
                run_id, idx, step.actor, step_rec.block_source,
            )
            return run

        if step_rec.status == "error":
            run.status = "failed"
            run.finished_at = time.time()
            _redis_save_run(redis_client, run)
            _emit_run_failed(audit_writer, run, reason=f"step_{idx}_error")
            return run

        _emit_step_completed(audit_writer, run, step_rec)
        prev_output = step_rec.output
        # Persist partial progress so a crash leaves a recoverable record.
        _redis_save_run(redis_client, run)

    run.status = "completed"
    run.finished_at = time.time()
    _redis_save_run(redis_client, run)
    _emit_run_completed(audit_writer, run)
    logger.info(
        "workflow: run %s completed (%d steps, %.1f s)",
        run_id, len(steps), run.finished_at - run.started_at,
    )
    return run


# ---------------------------------------------------------------------------
# WorkflowScheduler
# ---------------------------------------------------------------------------

class WorkflowScheduler:
    """In-process asyncio workflow scheduler backed by Redis DB 6.

    Lifecycle:
      1. Call ``start()`` from the gateway lifespan.  This loads all enabled
         workflows from Redis and starts the background check loop.
      2. Call ``stop()`` from the lifespan teardown to cancel the loop cleanly.
      3. Use ``register_workflow()`` to add/update a workflow spec (Tom's backend
         calls this on workflow create/update/enable/disable).
      4. ``GET /user/workflows/{id}/runs`` reads from ``_redis_list_runs()``.

    The scheduler accepts an optional ``_time_fn`` for test clock injection.
    """

    def __init__(
        self,
        redis_client,
        *,
        audit_writer=None,
        identity_registry=None,
        agent_registry=None,
        _time_fn: Optional[Callable[[], float]] = None,
    ):
        self._r = redis_client
        self._audit_writer = audit_writer
        self._identity_registry = identity_registry
        self._agent_registry = agent_registry
        self._time_fn: Callable[[], float] = _time_fn or time.time
        self._task: Optional[asyncio.Task] = None
        self._running = False

    # ── Public API ─────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the background scheduler loop (call from gateway lifespan)."""
        if self._running:
            logger.warning("WorkflowScheduler.start() called while already running")
            return
        self._running = True
        self._task = asyncio.ensure_future(self._loop())
        logger.info("WorkflowScheduler: started (checking every %.0f s)", _LOOP_INTERVAL_S)

    async def stop(self) -> None:
        """Cancel the scheduler loop (call from gateway lifespan teardown)."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("WorkflowScheduler: stopped")

    def register_workflow(self, spec: WorkflowSpec) -> None:
        """Persist a workflow spec and (re)enable its schedule.

        Called by Tom's backend on POST/PATCH /user/workflows/{id}.
        If ``spec.enabled`` is False the workflow is removed from the schedule
        index (no future fires) but its spec and run history are preserved.
        """
        _redis_set_spec(self._r, spec)
        if spec.enabled:
            # Reset next-fire so the scheduler picks it up immediately on the
            # next check (a newly registered workflow fires at next interval).
            self._schedule_next(spec, force_from_now=True)
            logger.info(
                "WorkflowScheduler: registered %s (kind=%s enabled=True)",
                spec.workflow_id, spec.schedule.kind,
            )
        else:
            logger.info(
                "WorkflowScheduler: disabled %s", spec.workflow_id,
            )

    def deregister_workflow(self, workflow_id: str) -> None:
        """Remove a workflow from the schedule index (does not delete history)."""
        try:
            self._r.srem(_KEY_SCHED_INDEX, workflow_id)
        except Exception as exc:
            logger.warning("WorkflowScheduler.deregister: %s", exc)

    def get_run(self, workflow_id: str, run_id: str) -> Optional[WorkflowRun]:
        return _redis_get_run(self._r, workflow_id, run_id)

    def list_runs(self, workflow_id: str, limit: int = 50) -> list[WorkflowRun]:
        return _redis_list_runs(self._r, workflow_id, limit=limit)

    # ── Schedule computation ───────────────────────────────────────────────

    def _schedule_next(self, spec: WorkflowSpec, *, force_from_now: bool = False) -> float:
        """Compute and persist the next fire time for ``spec``.

        Returns the next fire Unix timestamp.
        """
        now = self._time_fn()
        existing = _redis_get_next(self._r, spec.workflow_id) if not force_from_now else 0.0
        sched = spec.schedule

        if sched.kind == "interval":
            interval = max(1, sched.seconds)
            if existing > now:
                # Already scheduled in the future; don't push it further.
                return existing
            next_ts = now + interval
        elif sched.kind == "cron":
            # For cron: advance by one-minute steps until the expression matches.
            # Start from ceiling of current minute.
            import math
            start = math.ceil(now / 60) * 60
            next_ts = start
            for _ in range(60 * 24 * 7):   # max 1-week search
                if _cron_matches(sched.cron, next_ts):
                    break
                next_ts += 60
        else:
            logger.warning("workflow: unknown schedule kind %r for %s", sched.kind, spec.workflow_id)
            next_ts = now + 600

        _redis_set_next(self._r, spec.workflow_id, next_ts)
        return next_ts

    def _is_due(self, workflow_id: str, spec: WorkflowSpec) -> bool:
        """Return True if this workflow is due to fire now."""
        now = self._time_fn()
        next_ts = _redis_get_next(self._r, workflow_id)
        if next_ts == 0.0:
            # No next-fire set yet — initialise and return not-due.
            self._schedule_next(spec)
            return False

        if spec.schedule.kind == "interval":
            return now >= next_ts

        if spec.schedule.kind == "cron":
            # For cron, check if the current minute matches.
            return _cron_matches(spec.schedule.cron, now)

        return False

    # ── Main loop ─────────────────────────────────────────────────────────

    async def _loop(self) -> None:
        """Background asyncio task — checks due workflows every _LOOP_INTERVAL_S."""
        logger.info("WorkflowScheduler: loop started")
        while self._running:
            try:
                await self._check_and_fire()
            except Exception as exc:
                logger.exception("WorkflowScheduler: loop error: %s", exc)
            await asyncio.sleep(_LOOP_INTERVAL_S)
        logger.info("WorkflowScheduler: loop exited")

    async def _check_and_fire(self) -> None:
        """One scheduler tick: fire any due workflows."""
        workflow_ids = _redis_get_all_enabled(self._r)
        for wf_id in workflow_ids:
            spec = _redis_get_spec(self._r, wf_id)
            if spec is None or not spec.enabled:
                continue
            if self._is_due(wf_id, spec):
                asyncio.ensure_future(self._fire_with_lock(spec))

    async def _fire_with_lock(self, spec: WorkflowSpec) -> None:
        """Acquire the per-workflow lock, then execute the run.

        If another replica already holds the lock, this call is a no-op (the
        other replica is already executing this run).  This prevents double-fire.
        """
        if not _redis_acquire_lock(self._r, spec.workflow_id):
            logger.debug(
                "WorkflowScheduler: lock held for %s — skipping (another replica is running it)",
                spec.workflow_id,
            )
            return

        try:
            # Advance the schedule BEFORE executing so a long-running step
            # doesn't cause a catch-up burst on the next check.
            self._schedule_next(spec)

            logger.info(
                "WorkflowScheduler: firing workflow %s (owner=%s steps=%d)",
                spec.workflow_id, spec.owner_identity_id, len(spec.steps),
            )
            await _execute_workflow_run(
                spec=spec,
                redis_client=self._r,
                audit_writer=self._audit_writer,
                identity_registry=self._identity_registry,
                agent_registry=self._agent_registry,
                trigger_kind="scheduler",
            )
        except Exception as exc:
            logger.exception(
                "WorkflowScheduler: run failed for %s: %s",
                spec.workflow_id, exc,
            )
        finally:
            _redis_release_lock(self._r, spec.workflow_id)

    # ── Startup reload ────────────────────────────────────────────────────

    def reload_from_redis(self) -> int:
        """Reload all enabled workflows from Redis on startup.

        Called by ``start()`` automatically; can also be called manually (e.g.
        after a config refresh).  Returns count of reloaded workflows.
        """
        ids = _redis_get_all_enabled(self._r)
        count = 0
        for wf_id in ids:
            spec = _redis_get_spec(self._r, wf_id)
            if spec is None:
                continue
            # Ensure next-fire is set (may have been cleared by a Redis flush).
            existing = _redis_get_next(self._r, wf_id)
            if existing == 0.0:
                self._schedule_next(spec, force_from_now=True)
            count += 1
        logger.info("WorkflowScheduler: reloaded %d workflow(s) from Redis", count)
        return count


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_workflow_scheduler(
    redis_client,
    *,
    audit_writer=None,
    identity_registry=None,
    agent_registry=None,
) -> WorkflowScheduler:
    """Construct a WorkflowScheduler for lifespan wiring (gateway entrypoint).

    Fails closed on construction error — a broken scheduler must not silently
    suppress the runtime failure.
    """
    scheduler = WorkflowScheduler(
        redis_client,
        audit_writer=audit_writer,
        identity_registry=identity_registry,
        agent_registry=agent_registry,
    )
    scheduler.reload_from_redis()
    return scheduler


__all__ = [
    "WorkflowSpec",
    "WorkflowStep",
    "WorkflowSchedule",
    "WorkflowRun",
    "WorkflowStepRecord",
    "WorkflowScheduler",
    "build_workflow_scheduler",
    "_execute_workflow_run",
    "_execute_tool_call",   # module-level patchable hook
    "_redis_list_runs",
    "_redis_get_run",
    "_redis_set_spec",
]
