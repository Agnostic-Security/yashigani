"""
Yashigani 4.0 — No-code WORKFLOW composer backend.

EU AI Act Art.14 human-in-the-loop:
  AI (governed LLM through gateway mesh) parses natural language into a
  governed workflow spec.  The human commits it explicitly via
  ``POST /user/workflows`` — no workflow is persisted without that step.

Routes (all ``require_user_session``, BOLA-scoped to caller's account_id):

  /user/mentions                       (extended in user_agents.py — see note)

  POST   /user/workflows/generate      NL description → governed LLM → draft spec
  POST   /user/workflows               human-commit draft → persisted workflow
  GET    /user/workflows               list caller's workflows
  GET    /user/workflows/{wf_id}       get workflow (full spec — executor contract)
  PATCH  /user/workflows/{wf_id}       enable/disable/rename
  DELETE /user/workflows/{wf_id}       delete workflow

PINNED SPEC CONTRACT (executor + UI build in parallel against this):

  WorkflowStep:
    actor:     str         @-handle of the entity executing this step
    action:    str         natural-language action description (≤ 2000 chars)
    uses:      list[str]   @-handles of MCPs / APIs / agents this step invokes
    output_to: str | null  @-handle to pipe step output to; null = terminal

  WorkflowSchedule:
    kind:    "interval" | "cron" | "none"
    seconds: int | null    (interval only; must be > 0)
    cron:    str | null    (cron only; 5-field POSIX expression)

  GET /user/workflows/{wf_id} shape:
    {
      "workflow_id": str,
      "name": str,
      "description": str,
      "owner_identity_id": str,
      "enabled": bool,
      "spec": {"steps": [...], "schedule": {...}},
      "created_at": str,
      "updated_at": str,
    }

Redis key design (db/3, ``wf:`` prefix):

  wf:workflows:{account_id}   Set   — wf_id values owned by this user
  wf:meta:{wf_id}             Hash  — account_id, name, description,
                                       spec (JSON), enabled ("1"|"0"),
                                       owner_identity_id,
                                       created_at, updated_at
  wf:draft:{draft_id}         Hash  — account_id, spec (JSON), description,
                                       summary, spec_hash, created_at
                                       TTL: 24 h (``_DRAFT_TTL_SECONDS``)

BOLA design:
  All 404 responses on ID-keyed paths return 404 (not 403) regardless of
  whether the resource exists but is owned by another user — OWASP API3.

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import uuid
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import UserSession
from yashigani.backoffice.state import backoffice_state

# Shared helpers from the user_agents module (pure functions, no circular import)
from yashigani.backoffice.routes.user_agents import (
    _call_governed_gateway_llm,
    _decode_hash,
    _decode_set,
    _extract_json_from_llm_response,
    _get_redis,
    _normalize_alias,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_WF_PREFIX = "wfl_"
_DRAFT_PREFIX = "wfd_"
_DRAFT_TTL_SECONDS = 86400  # 24 h


# ---------------------------------------------------------------------------
# ID + time helpers
# ---------------------------------------------------------------------------

def _new_wf_id() -> str:
    return f"{_WF_PREFIX}{uuid.uuid4().hex[:12]}"


def _new_draft_id() -> str:
    return f"{_DRAFT_PREFIX}{uuid.uuid4().hex[:12]}"


def _now_iso() -> str:
    return datetime.datetime.now(tz=datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Redis key helpers
# ---------------------------------------------------------------------------

def _wf_key(wf_id: str) -> str:
    return f"wf:meta:{wf_id}"


def _wf_index_key(account_id: str) -> str:
    return f"wf:workflows:{account_id}"


def _draft_key(draft_id: str) -> str:
    return f"wf:draft:{draft_id}"


# ---------------------------------------------------------------------------
# BOLA guards
# ---------------------------------------------------------------------------

def _get_workflow_or_404(r, wf_id: str, account_id: str) -> dict:
    """Return decoded wf:meta hash or raise 404.

    BOLA: returns 404 (not 403) when workflow exists but belongs to another
    user, so resource existence cannot be inferred (OWASP API3).
    """
    raw = r.hgetall(_wf_key(wf_id))
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found"},
        )
    meta = _decode_hash(raw)
    if meta.get("account_id") != account_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_found"},
        )
    return meta


def _get_draft_or_404(r, draft_id: str, account_id: str) -> dict:
    """Return decoded wf:draft hash or raise 404 (BOLA-safe)."""
    raw = r.hgetall(_draft_key(draft_id))
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "draft_not_found",
                "message": "Draft not found or expired. Generate a new workflow spec first.",
            },
        )
    meta = _decode_hash(raw)
    if meta.get("account_id") != account_id:
        # BOLA: return 404 — do not disclose draft existence to other users.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "draft_not_found"},
        )
    return meta


# ---------------------------------------------------------------------------
# Spec schema (pinned contract — executor and UI build against this shape)
# ---------------------------------------------------------------------------

class WorkflowStep(BaseModel):
    """A single step in a governed workflow spec.

    actor:     @-handle of the entity executing this step.
    action:    Natural-language description of what this step does (≤ 2000 chars).
    uses:      @-handles of MCPs / APIs / agents this step invokes.
    output_to: @-handle to pipe step output to; null = terminal (last step).
    """
    actor: str = Field(min_length=1, max_length=128)
    action: str = Field(min_length=1, max_length=2000)
    uses: list[str] = Field(default_factory=list, max_length=20)
    output_to: Optional[str] = Field(default=None, max_length=128)


class WorkflowSchedule(BaseModel):
    """Schedule descriptor for a governed workflow.

    kind:    "interval" — repeat every ``seconds`` seconds.
             "cron"     — run on a POSIX 5-field cron expression.
             "none"     — no scheduled execution (manual trigger only).
    seconds: Interval in seconds (interval kind only; must be > 0).
    cron:    POSIX 5-field cron expression (cron kind only).
    """
    kind: str = Field(default="none", pattern=r"^(interval|cron|none)$")
    seconds: Optional[int] = Field(default=None, ge=1)
    cron: Optional[str] = Field(default=None, max_length=128)


class WorkflowSpec(BaseModel):
    """The governed workflow spec — the pinned executor contract.

    Stored as JSON in ``wf:meta.spec`` and returned verbatim by
    ``GET /user/workflows/{wf_id}``.
    """
    steps: list[WorkflowStep] = Field(default_factory=list, max_length=32)
    schedule: WorkflowSchedule = Field(default_factory=WorkflowSchedule)


# ---------------------------------------------------------------------------
# Pydantic request bodies
# ---------------------------------------------------------------------------

class GenerateWorkflowBody(BaseModel):
    """Body for POST /user/workflows/generate."""

    description: str = Field(
        min_length=10,
        max_length=2000,
        description=(
            "Natural language description of the governed workflow, including @-handle "
            "references to agents, MCPs, and APIs. "
            "Example: '@Mimi using @mcp2 retrieve the payment information and push it "
            "to @api9 every 10 minutes.'"
        ),
    )


class CommitWorkflowBody(BaseModel):
    """Body for POST /user/workflows (human-decides commit step)."""

    draft_id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128, description="Display name for the workflow.")
    description: str = Field(default="", max_length=512)


class PatchWorkflowBody(BaseModel):
    """Body for PATCH /user/workflows/{wf_id}."""

    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=512)
    enabled: Optional[bool] = Field(default=None)


# ---------------------------------------------------------------------------
# Handle resolution helpers
# ---------------------------------------------------------------------------

def _build_valid_handles(r, account_id: str) -> dict[str, dict]:
    """Build a map of @-handle → mention-dict for the calling user.

    Returns all @-addressable entities available to this user:
      - kind:"agent"/"persona"  from ``ua:agents:{account_id}`` (BOLA-scoped)
      - kind:"mcp"              from YASHIGANI_MCP_SERVERS env (system-wide)
      - kind:"api"              from AgentRegistry.list_active() (system-wide)

    Used for @-handle validation when processing LLM-generated workflow specs.
    Fail-open for the system-wide sources (mcp/api): an env-parse error means
    those handles are absent from validation, not that the draft is rejected.
    """
    valid: dict[str, dict] = {}

    # 1. User-owned agents and personas (BOLA-scoped)
    _user_agents_key = f"ua:agents:{account_id}"
    try:
        raw_ids = r.smembers(_user_agents_key)
        ua_ids = _decode_set(raw_ids)
        for ua_id in ua_ids:
            raw = r.hgetall(f"ua:meta:{ua_id}")
            if not raw:
                continue
            meta = _decode_hash(raw)
            if meta.get("account_id") != account_id:
                continue  # BOLA guard
            alias = meta.get("alias", "")
            if alias:
                valid[alias] = {
                    "handle": alias,
                    "kind": meta.get("kind", "agent"),
                    "display": meta.get("name", ""),
                    "id": ua_id,
                }
    except Exception as exc:
        logger.warning("_build_valid_handles: failed to read ua:agents: %s", exc)

    # 2. MCP servers (system-wide)
    _mcp_raw = os.environ.get("YASHIGANI_MCP_SERVERS", "").strip()
    if _mcp_raw:
        try:
            for entry in json.loads(_mcp_raw):
                agent_name = entry.get("agent_name", "")
                if agent_name:
                    valid[agent_name] = {
                        "handle": agent_name,
                        "kind": "mcp",
                        "display": entry.get("display_name", agent_name),
                        "id": agent_name,
                    }
        except Exception as exc:
            logger.warning("_build_valid_handles: failed to parse YASHIGANI_MCP_SERVERS: %s", exc)

    # 3. API integrations (active agents from AgentRegistry, kind != nhi/langflow)
    _ar = getattr(backoffice_state, "agent_registry", None)
    if _ar is not None:
        try:
            for agent in _ar.list_active():
                _kind = agent.get("kind", "agent")
                if _kind in ("nhi", "langflow_callee", "persona"):
                    continue
                _name = agent.get("name", "")
                _aid = agent.get("agent_id", "") or agent.get("id", "")
                if not _name or not _aid:
                    continue
                _handle = _normalize_alias(_name)
                valid[_handle] = {
                    "handle": _handle,
                    "kind": "api",
                    "display": _name,
                    "id": _aid,
                }
        except Exception as exc:
            logger.warning("_build_valid_handles: failed to read agent_registry: %s", exc)

    return valid


def _validate_and_clamp_handles(
    spec: dict,
    valid_handles: dict[str, dict],
) -> tuple[dict, list[str]]:
    """Validate @-handles in a raw spec dict and clamp unknown ones.

    Rules:
    - ``step.actor`` unknown → step is removed; warning added.
    - ``step.uses[i]`` unknown → entry removed from uses; warning added.
    - ``step.output_to`` unknown → set to null; warning added.

    Returns (clamped_spec, warnings).
    """
    warnings: list[str] = []
    clamped_steps: list[dict] = []

    for i, step in enumerate(spec.get("steps", [])):
        actor = step.get("actor", "")
        # Strip leading '@' if the LLM included it
        actor_handle = actor.lstrip("@")
        if actor_handle not in valid_handles:
            warnings.append(
                f"step[{i}].actor {actor!r}: unknown or out-of-scope @-handle — step removed"
            )
            continue  # drop this step

        # Validate uses[]
        clamped_uses: list[str] = []
        for h in step.get("uses", []):
            h_clean = h.lstrip("@")
            if h_clean in valid_handles:
                clamped_uses.append(h_clean)
            else:
                warnings.append(
                    f"step[{i}].uses: {h!r} unknown or out-of-scope — removed"
                )

        # Validate output_to
        output_to_raw = step.get("output_to")
        output_to: Optional[str] = None
        if output_to_raw is not None:
            ot_clean = str(output_to_raw).lstrip("@")
            if ot_clean in valid_handles:
                output_to = ot_clean
            else:
                warnings.append(
                    f"step[{i}].output_to: {output_to_raw!r} unknown or out-of-scope — set to null"
                )

        clamped_steps.append({
            "actor": actor_handle,
            "action": str(step.get("action", ""))[:2000],
            "uses": clamped_uses,
            "output_to": output_to,
        })

    # Pass schedule through as-is (validated separately by _parse_schedule)
    clamped_spec = {
        "steps": clamped_steps,
        "schedule": spec.get("schedule", {"kind": "none"}),
    }
    return clamped_spec, warnings


def _parse_schedule(schedule_obj: Any) -> dict:
    """Validate and normalise an LLM-produced schedule dict.

    Raises ValueError if the schedule object is structurally invalid.
    Returns a clean dict with ``kind``, ``seconds`` (or null), ``cron`` (or null).
    """
    if not isinstance(schedule_obj, dict):
        return {"kind": "none", "seconds": None, "cron": None}

    kind = str(schedule_obj.get("kind", "none")).lower()
    if kind not in ("interval", "cron", "none"):
        raise ValueError(
            f"schedule.kind must be 'interval', 'cron', or 'none' — got {kind!r}"
        )

    seconds: Optional[int] = None
    cron: Optional[str] = None

    if kind == "interval":
        raw_seconds = schedule_obj.get("seconds")
        if raw_seconds is None:
            raise ValueError("schedule.seconds is required for kind='interval'")
        try:
            seconds = int(raw_seconds)
        except (TypeError, ValueError):
            raise ValueError(f"schedule.seconds must be an integer — got {raw_seconds!r}")
        if seconds <= 0:
            raise ValueError(f"schedule.seconds must be > 0 — got {seconds}")

    elif kind == "cron":
        cron = str(schedule_obj.get("cron", "")).strip()
        if not cron:
            raise ValueError("schedule.cron is required for kind='cron'")
        # Minimal POSIX cron validation: 5 fields, each non-empty
        fields = cron.split()
        if len(fields) != 5:
            raise ValueError(
                f"schedule.cron must be a 5-field POSIX expression — got {cron!r}"
            )

    return {"kind": kind, "seconds": seconds, "cron": cron}


# ---------------------------------------------------------------------------
# Governed LLM prompt for workflow generation
# ---------------------------------------------------------------------------

_WF_GEN_SYSTEM_PROMPT = (
    "You are a workflow parser for the Yashigani AI security gateway.\n"
    "Parse the natural language workflow description into a structured workflow spec.\n\n"
    "OUTPUT: return ONLY a valid JSON object — no markdown fences, no explanation.\n"
    "FORMAT:\n"
    "{\n"
    '  "steps": [\n'
    '    {\n'
    '      "actor": "<handle>",\n'
    '      "action": "<what this entity does>",\n'
    '      "uses": ["<handle>", ...],\n'
    '      "output_to": "<handle>" or null\n'
    "    }\n"
    "  ],\n"
    '  "schedule": {\n'
    '    "kind": "interval" | "cron" | "none",\n'
    '    "seconds": <int> or null,\n'
    '    "cron": "<5-field POSIX>" or null\n'
    "  }\n"
    "}\n\n"
    "Rules:\n"
    "- Use ONLY handles from the available handles list supplied in the user message.\n"
    "- Do NOT invent @-handles that are not in the list.\n"
    "- Schedule: 'every N minutes' → {kind:'interval', seconds:N*60}.\n"
    "  'every N hours' → {kind:'interval', seconds:N*3600}.\n"
    "  'every day at HH:MM' → {kind:'cron', cron:'MM HH * * *'}.\n"
    "  No schedule → {kind:'none'}.\n"
    "- For each step: actor = who acts, uses = tools/MCPs/APIs called, "
    "output_to = where output goes (null if terminal).\n"
    "- The output MUST start with { and end with }."
)


def _build_wf_gen_messages(
    description: str,
    available_handles: dict[str, dict],
) -> list[dict]:
    """Build the governed-LLM messages list for workflow generation.

    Includes the list of available @-handles so the LLM uses only valid ones.
    """
    handle_lines = "\n".join(
        f"  @{h} ({v['kind']}) — {v['display']}"
        for h, v in sorted(available_handles.items())
    )
    user_content = (
        f"Available @-handles:\n{handle_lines}\n\n"
        f"Workflow description:\n{description}\n\n"
        "Parse this into a workflow spec JSON object."
    )
    return [
        {"role": "system", "content": _WF_GEN_SYSTEM_PROMPT},
        {"role": "user",   "content": user_content},
    ]


# ---------------------------------------------------------------------------
# Serialiser
# ---------------------------------------------------------------------------

def _serialise_workflow(wf_id: str, meta: dict, include_spec: bool = True) -> dict:
    """Serialise a wf:meta hash to a dict for API responses.

    ``include_spec=True`` (default) — include full spec (for GET /{id} + POST response).
    ``include_spec=False`` — omit spec (for GET list, to keep response compact).
    """
    spec_raw = meta.get("spec", "{}")
    result: dict[str, Any] = {
        "workflow_id": wf_id,
        "name": meta.get("name", ""),
        "description": meta.get("description", ""),
        "owner_identity_id": meta.get("owner_identity_id", meta.get("account_id", "")),
        "enabled": meta.get("enabled", "1") == "1",
        "created_at": meta.get("created_at", ""),
        "updated_at": meta.get("updated_at", ""),
    }
    if include_spec:
        try:
            result["spec"] = json.loads(spec_raw)
        except Exception:
            result["spec"] = {"steps": [], "schedule": {"kind": "none"}}
    return result


# ===========================================================================
# POST /user/workflows/generate — NL → governed LLM → draft workflow spec
# ===========================================================================


@router.post("/user/workflows/generate")
async def generate_workflow(body: GenerateWorkflowBody, session: UserSession):
    """Parse a natural-language workflow description into a governed workflow spec.

    Pipeline:
      1. Build the caller's valid @-handle map (agents + MCPs + APIs).
      2. Emit ``WorkflowGenerationRequestedEvent`` (pre-LLM audit anchor).
      3. Call the governed LLM through the gateway mesh (OPA-adjudicated).
      4. Parse and extract JSON from the LLM response.
      5. Validate and clamp @-handles (remove unknown; add to warnings).
      6. Validate and normalise the schedule.
      7. Store a BOLA-scoped draft in Redis (TTL 24 h).
      8. Emit ``WorkflowGeneratedEvent``.
      9. Return ``{draft_id, summary, steps, schedule, warnings, draft: true}``.

    The draft is NOT committed.  The caller reviews the spec and explicitly
    commits via ``POST /user/workflows``.

    EU AI Act Art.14: AI generates; human decides.
    BOLA: draft is scoped to ``draft.account_id == session.account_id``.
    """
    r = _get_redis()

    # --- Step 1: build valid handle map ---
    valid_handles = _build_valid_handles(r, session.account_id)

    # --- Step 2: emit pre-LLM audit event ---
    aw = getattr(backoffice_state, "audit_writer", None)
    if aw is not None:
        try:
            from yashigani.audit.schema import WorkflowGenerationRequestedEvent
            aw.write(WorkflowGenerationRequestedEvent(
                owner_identity_id=session.account_id,
                description_length=len(body.description),
                available_handle_count=len(valid_handles),
            ))
        except Exception as exc:
            logger.warning("WorkflowGenerationRequestedEvent audit write failed: %s", exc)

    # --- Step 3: governed LLM call ---
    messages = _build_wf_gen_messages(body.description, valid_handles)
    llm_response = await _call_governed_gateway_llm(messages)

    # --- Step 4: parse JSON ---
    try:
        raw_spec = _extract_json_from_llm_response(llm_response)
    except ValueError as exc:
        logger.warning(
            "generate_workflow: LLM produced non-JSON for account=%r: %s",
            session.account_id, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "invalid_spec_generated",
                "message": (
                    "The AI could not produce a valid workflow spec for this description. "
                    "Try rephrasing or using explicit @-handle references."
                ),
            },
        )

    # --- Step 5: validate + clamp @-handles ---
    clamped_spec, warnings = _validate_and_clamp_handles(raw_spec, valid_handles)

    if not clamped_spec.get("steps"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "no_valid_steps",
                "message": (
                    "No valid steps remain after @-handle validation. "
                    "Ensure your description references valid @-handles. "
                    f"Warnings: {warnings}"
                ),
            },
        )

    # --- Step 6: validate + normalise schedule ---
    try:
        schedule = _parse_schedule(clamped_spec.get("schedule", {}))
    except ValueError as exc:
        warnings.append(f"schedule validation: {exc} — defaulting to no schedule")
        schedule = {"kind": "none", "seconds": None, "cron": None}

    clamped_spec["schedule"] = schedule

    # --- Step 7: store draft in Redis ---
    draft_id = _new_draft_id()
    now = _now_iso()
    spec_hash = "sha384:" + hashlib.sha384(
        json.dumps(clamped_spec, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    summary = (body.description[:200] + "…") if len(body.description) > 200 else body.description

    draft_mapping: dict[bytes, bytes] = {
        b"account_id":    session.account_id.encode(),
        b"description":   body.description.encode(),
        b"summary":       summary.encode(),
        b"spec":          json.dumps(clamped_spec).encode(),
        b"spec_hash":     spec_hash.encode(),
        b"created_at":    now.encode(),
    }
    pipe = r.pipeline()
    pipe.hset(_draft_key(draft_id), mapping=draft_mapping)
    pipe.expire(_draft_key(draft_id), _DRAFT_TTL_SECONDS)
    pipe.execute()

    # --- Step 8: emit WorkflowGeneratedEvent ---
    if aw is not None:
        try:
            from yashigani.audit.schema import WorkflowGeneratedEvent
            aw.write(WorkflowGeneratedEvent(
                owner_identity_id=session.account_id,
                draft_id=draft_id,
                spec_hash=spec_hash,
                step_count=len(clamped_spec.get("steps", [])),
                schedule_kind=schedule["kind"],
                clamped_handle_count=len([w for w in warnings if "removed" in w or "set to null" in w]),
            ))
        except Exception as exc:
            logger.warning("WorkflowGeneratedEvent audit write failed: %s", exc)

    logger.info(
        "user_workflows: generated draft_id=%s steps=%d schedule=%r "
        "warnings=%d for account=%r",
        draft_id,
        len(clamped_spec.get("steps", [])),
        schedule["kind"],
        len(warnings),
        session.account_id,
    )

    return {
        "draft_id": draft_id,
        "summary": summary,
        "steps": clamped_spec.get("steps", []),
        "schedule": schedule,
        "warnings": warnings,
        "draft": True,
    }


# ===========================================================================
# POST /user/workflows — human-commits a draft → persisted named workflow
# ===========================================================================


@router.post("/user/workflows", status_code=status.HTTP_201_CREATED)
async def commit_workflow(body: CommitWorkflowBody, session: UserSession):
    """Explicitly commit a generated draft workflow spec (human-decides step).

    THIS IS THE HUMAN-DECIDES AUDIT ANCHOR (EU AI Act Art.14).
    The LLM generated the spec; this endpoint records the human's explicit
    decision to persist it as a named, scheduled workflow.

    Steps:
      1. Look up ``wf:draft:{draft_id}`` (HTTP 404 if missing or expired).
      2. BOLA: verify ``draft.account_id == session.account_id`` (HTTP 404 on violation).
      3. Create ``wf:meta:{wf_id}`` hash.
      4. Add to ``wf:workflows:{account_id}`` set.
      5. Consume the draft (delete from Redis).
      6. Emit ``WorkflowCommittedEvent`` to the audit hash-chain.

    Returns ``{workflow_id, name, spec, schedule, enabled, created_at}``.
    """
    r = _get_redis()

    # --- Steps 1+2: look up draft + BOLA check ---
    draft = _get_draft_or_404(r, body.draft_id, session.account_id)

    spec_raw = draft.get("spec", "{}")
    spec_hash = draft.get("spec_hash", "")
    try:
        spec_obj = json.loads(spec_raw)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "draft_spec_corrupted",
                    "message": "Draft spec is corrupted. Generate a new workflow."},
        )

    schedule = spec_obj.get("schedule", {"kind": "none"})
    steps = spec_obj.get("steps", [])

    # --- Steps 3+4: create wf:meta + add to index ---
    wf_id = _new_wf_id()
    now = _now_iso()

    wf_mapping: dict[bytes, bytes] = {
        b"account_id":         session.account_id.encode(),
        b"owner_identity_id":  session.account_id.encode(),
        b"name":               body.name.encode(),
        b"description":        body.description.encode(),
        b"spec":               spec_raw.encode(),
        b"spec_hash":          spec_hash.encode(),
        b"enabled":            b"1",
        b"created_at":         now.encode(),
        b"updated_at":         now.encode(),
    }

    pipe = r.pipeline()
    pipe.hset(_wf_key(wf_id), mapping=wf_mapping)
    pipe.sadd(_wf_index_key(session.account_id), wf_id.encode())
    # --- Step 5: consume draft ---
    pipe.delete(_draft_key(body.draft_id))
    pipe.execute()

    # --- Step 6: emit WorkflowCommittedEvent (human-decides anchor) ---
    aw = getattr(backoffice_state, "audit_writer", None)
    if aw is not None:
        try:
            from yashigani.audit.schema import WorkflowCommittedEvent
            aw.write(WorkflowCommittedEvent(
                owner_identity_id=session.account_id,
                workflow_id=wf_id,
                draft_id=body.draft_id,
                workflow_name=body.name[:64],  # mask: truncate to 64 chars in audit
                spec_hash=spec_hash,
                step_count=len(steps),
                schedule_kind=schedule.get("kind", "none"),
                human_decided=True,
            ))
        except Exception as exc:
            logger.warning("WorkflowCommittedEvent audit write failed: %s", exc)

    logger.info(
        "user_workflows: committed wf_id=%s name=%r draft_id=%s steps=%d "
        "schedule=%r for account=%r",
        wf_id, body.name, body.draft_id, len(steps),
        schedule.get("kind", "none"), session.account_id,
    )

    return {
        "workflow_id": wf_id,
        "name": body.name,
        "description": body.description,
        "owner_identity_id": session.account_id,
        "enabled": True,
        "spec": spec_obj,
        "created_at": now,
    }


# ===========================================================================
# GET /user/workflows — list caller's workflows
# ===========================================================================


@router.get("/user/workflows")
async def list_workflows(session: UserSession):
    """List all workflows owned by the calling user.

    Returns a compact list (no spec field) for pagination efficiency.
    Use ``GET /user/workflows/{wf_id}`` to fetch the full spec.
    """
    r = _get_redis()
    raw_ids = r.smembers(_wf_index_key(session.account_id))
    wf_ids = _decode_set(raw_ids)

    workflows = []
    for wf_id in sorted(wf_ids):
        raw = r.hgetall(_wf_key(wf_id))
        if not raw:
            continue
        meta = _decode_hash(raw)
        if meta.get("account_id") != session.account_id:
            continue  # BOLA guard (stale index)
        workflows.append(_serialise_workflow(wf_id, meta, include_spec=False))

    return {"workflows": workflows, "count": len(workflows)}


# ===========================================================================
# GET /user/workflows/{wf_id} — full spec (executor contract)
# ===========================================================================


@router.get("/user/workflows/{wf_id}")
async def get_workflow(wf_id: str, session: UserSession):
    """Get a workflow including its full spec.

    This is the executor contract endpoint — the scheduler/executor reads the
    full spec (steps + schedule) from here.

    BOLA: 404 on violation.
    """
    r = _get_redis()
    meta = _get_workflow_or_404(r, wf_id, session.account_id)
    return _serialise_workflow(wf_id, meta, include_spec=True)


# ===========================================================================
# PATCH /user/workflows/{wf_id} — enable/disable/rename
# ===========================================================================


@router.patch("/user/workflows/{wf_id}")
async def patch_workflow(wf_id: str, body: PatchWorkflowBody, session: UserSession):
    """Update a workflow's name, description, or enabled state.

    BOLA: 404 on violation.
    Returns ``{workflow_id, updated: [...fields]}`` for the changed fields.
    """
    r = _get_redis()
    _get_workflow_or_404(r, wf_id, session.account_id)  # BOLA check

    updates: dict[bytes, bytes] = {b"updated_at": _now_iso().encode()}
    updated_fields: list[str] = []

    if body.name is not None:
        updates[b"name"] = body.name.encode()
        updated_fields.append("name")
    if body.description is not None:
        updates[b"description"] = body.description.encode()
        updated_fields.append("description")
    if body.enabled is not None:
        updates[b"enabled"] = b"1" if body.enabled else b"0"
        updated_fields.append("enabled")

    r.hset(_wf_key(wf_id), mapping=updates)
    logger.info(
        "user_workflows: patched wf_id=%s fields=%r for account=%r",
        wf_id, updated_fields, session.account_id,
    )
    return {"workflow_id": wf_id, "updated": updated_fields}


# ===========================================================================
# DELETE /user/workflows/{wf_id}
# ===========================================================================


@router.delete("/user/workflows/{wf_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_workflow(wf_id: str, session: UserSession):
    """Delete a workflow permanently.

    BOLA: 404 on violation.
    No undo — committed workflows are deleted from Redis immediately.
    """
    r = _get_redis()
    _get_workflow_or_404(r, wf_id, session.account_id)  # BOLA check

    pipe = r.pipeline()
    pipe.delete(_wf_key(wf_id))
    pipe.srem(_wf_index_key(session.account_id), wf_id.encode())
    pipe.execute()

    logger.info(
        "user_workflows: deleted wf_id=%s for account=%r",
        wf_id, session.account_id,
    )

# ===========================================================================
# 4.0 — Workflow run history (feat/4.0-wf-exec): /runs routes + helpers.
# Appended at merge: reuses this module's `router`, UserSession, status, HTTPException.
# ===========================================================================
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
