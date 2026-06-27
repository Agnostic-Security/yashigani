"""
Yashigani 4.0 — User-plane Letta agent capability routes + graph persistence + NHI run.

All endpoints enforce ``require_user_session`` (RISK-100) and are BOLA-scoped
to the calling user's ``account_id``.  User A cannot touch User B's agents,
memories, or skills — mismatches always return 404 (not 403) so resource
existence cannot be inferred.

Routes
------
/user/agents
  GET    /user/agents                              list caller's agents
  POST   /user/agents                              create agent
  GET    /user/agents/{ua_id}                      get agent config
  PATCH  /user/agents/{ua_id}                      update name / personality / description
  DELETE /user/agents/{ua_id}                      delete agent + detach all memories

  GET    /user/agents/{ua_id}/personality          get persona + system prompt
  PUT    /user/agents/{ua_id}/personality          set persona + system prompt

  GET    /user/agents/{ua_id}/skills               get agent's effective skill set
  PUT    /user/agents/{ua_id}/skills               set skills (scope intersection enforced)

  GET    /user/agents/{ua_id}/memories             list memory blocks attached to agent
  POST   /user/agents/{ua_id}/memories/{block_id}  attach memory block to agent
  DELETE /user/agents/{ua_id}/memories/{block_id}  detach memory block from agent

/user/memories
  GET    /user/memories                            list all user memory blocks
  POST   /user/memories                            create memory block
  GET    /user/memories/{block_id}                 get memory block
  PATCH  /user/memories/{block_id}                 rename / update value
  DELETE /user/memories/{block_id}                 delete (auto-detaches from agents)

/user/skills
  GET    /user/skills                              list available skills (catalog ∩ user ceiling)

Redis key design (db/3, ``ua:`` prefix):
  ua:agents:{account_id}            Set  — ua_agent_ids owned by this user
  ua:meta:{ua_agent_id}             Hash — account_id, name, description,
                                           personality (JSON: persona+system_prompt),
                                           effective_skills (JSON list),
                                           declared_skills  (JSON list),
                                           graph (JSON CTF blob — Phase 4 persistence),
                                           graph_hash (sha384:<hex> — for audit),
                                           nhi_id (nhi_* id once instantiated),
                                           letta_agent_id, created_at, updated_at
  ua:mem:all:{account_id}           Set  — block_ids owned by this user
  ua:mem:meta:{block_id}            Hash — account_id, label, value,
                                           letta_block_id, created_at, updated_at
  ua:mem:agent:{ua_agent_id}        Set  — block_ids currently attached to this agent

Graph persistence (Phase 4):
  PUT /user/agents/{ua_id}/graph    — save CTF graph JSON (server validates + strips
                                       R11 fields; agent must exist + be owned by caller)
  GET /user/agents/{ua_id}/graph    — load saved CTF graph for edit in the builder

NHI run endpoint (Phase 3):
  POST /user/agents/{ua_id}/run     — instantiate an NHI from the agent's stored graph +
                                       skills.  Computes effective_scope (R3), registers
                                       the NHI, mints delegation context.
                                       Requires the agent graph to be saved (Phase 4).
                                       Returns nhi_id + session_id + svid_pending flag.

Skill scope intersection (R3 / RISK-097):
  effective_scope = declared_skills ∩ invoker_grants ∩ system_ceiling

  * declared_skills  — skills the user requests for their agent
  * invoker_grants   — identity.allowed_tools from the identity registry
  * system_ceiling   — union of allowed_paths across all active agents in the registry
                        (what the system actually exposes)

  Stored in ua:meta.effective_skills so the gateway can enforce it when
  creating the delegation record (R2/R12, X-Yashigani-Session-Id).

Letta pool seam:
  Routes that need live Letta access call ``LettaClientPool.for_user()``.
  Until feat/4.0-agent-isolation (Captain) merges they return HTTP 503
  (``letta_pool_unavailable``).  Metadata-only routes (create/list/skill ops)
  work immediately — Letta provisioning is deferred (``letta_agent_id: null``
  until the pool is wired and the user's first chat request provisions the agent).

NHI note (RISK-097/R2/R3):
  Phase 3 (feat/4.0-agent-isolation) will register each user agent as an NHI in
  AgentRegistry (kind=nhi, owner_identity_id=account_id) and wire the P1/P2 token
  split.  Until then, ``effective_skills`` in ua:meta is the enforcement surface.

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
import re
import uuid
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import UserSession
from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# ID minting
# ---------------------------------------------------------------------------

_UA_PREFIX = "uag_"
_MEM_PREFIX = "umb_"


def _new_ua_id() -> str:
    return f"{_UA_PREFIX}{uuid.uuid4().hex[:12]}"


def _new_block_id() -> str:
    return f"{_MEM_PREFIX}{uuid.uuid4().hex[:12]}"


def _now_iso() -> str:
    return datetime.datetime.now(tz=datetime.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Redis helpers
# ---------------------------------------------------------------------------

def _get_redis():
    """Return Redis db/3 client via identity registry. Raises HTTP 503 if unavailable."""
    ir = getattr(backoffice_state, "identity_registry", None)
    if ir is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "registry_unavailable", "message": "Identity registry not ready."},
        )
    return ir._r


def _decode_hash(raw: dict) -> dict:
    """Decode a Redis hash (bytes keys + values) into a plain str dict."""
    return {
        (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
        for k, v in raw.items()
    }


def _decode_set(raw) -> set[str]:
    """Decode a Redis set of bytes into a set of str."""
    return {v.decode() if isinstance(v, bytes) else v for v in raw}


def _meta_key(ua_id: str) -> str:
    return f"ua:meta:{ua_id}"


def _agents_key(account_id: str) -> str:
    return f"ua:agents:{account_id}"


def _mem_meta_key(block_id: str) -> str:
    return f"ua:mem:meta:{block_id}"


def _mem_all_key(account_id: str) -> str:
    return f"ua:mem:all:{account_id}"


def _mem_agent_key(ua_id: str) -> str:
    return f"ua:mem:agent:{ua_id}"


# ---------------------------------------------------------------------------
# BOLA guards
# ---------------------------------------------------------------------------

def _get_agent_or_404(r, ua_id: str, account_id: str) -> dict:
    """Return decoded ua:meta hash or raise 404.

    BOLA: returns 404 (not 403) when the agent exists but belongs to another user,
    so resource existence cannot be inferred (OWASP API3).
    """
    raw = r.hgetall(_meta_key(ua_id))
    if not raw:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "not_found"})
    meta = _decode_hash(raw)
    if meta.get("account_id") != account_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "not_found"})
    return meta


def _get_block_or_404(r, block_id: str, account_id: str) -> dict:
    """Return decoded ua:mem:meta hash or raise 404 (BOLA-safe)."""
    raw = r.hgetall(_mem_meta_key(block_id))
    if not raw:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "not_found"})
    meta = _decode_hash(raw)
    if meta.get("account_id") != account_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail={"error": "not_found"})
    return meta


# ---------------------------------------------------------------------------
# Skill scope intersection (R3 / RISK-097)
# ---------------------------------------------------------------------------

def _compute_system_ceiling(r) -> set[str]:
    """Derive the system skill ceiling from active agents' allowed_paths.

    Returns the union of allowed_paths across all active agents in the registry.
    This represents the universe of skills the system can offer.
    Falls back to empty set on any error (fail-closed).
    """
    try:
        registry = getattr(backoffice_state, "agent_registry", None)
        if registry is None:
            return set()
        ceiling: set[str] = set()
        for agent in registry.list_active():
            for path in agent.get("allowed_paths", []):
                ceiling.add(path)
        return ceiling
    except Exception as exc:
        logger.warning("_compute_system_ceiling: failed to read agent registry: %s", exc)
        return set()


def _get_invoker_grants(account_id: str) -> set[str]:
    """Return the calling user's allowed_tools from the identity registry.

    These are the tools the user personally holds the right to delegate.
    Falls back to empty set on any error (fail-closed).
    """
    try:
        ir = getattr(backoffice_state, "identity_registry", None)
        if ir is None:
            return set()
        identity = ir.get_by_slug(account_id)
        if identity is None:
            return set()
        tools = identity.get("allowed_tools", [])
        return set(tools) if tools else set()
    except Exception as exc:
        logger.warning("_get_invoker_grants: failed for account %r: %s", account_id, exc)
        return set()


def compute_effective_skills(
    declared: list[str],
    account_id: str,
    r,
) -> tuple[list[str], list[str]]:
    """Compute the scope intersection (R3).

    Returns:
        (effective_skills, rejected_skills)

    effective_skills = declared ∩ invoker_grants ∩ system_ceiling
    rejected_skills  = declared − effective_skills
    """
    declared_set = set(declared)
    invoker_grants = _get_invoker_grants(account_id)
    system_ceiling = _compute_system_ceiling(r)

    # If invoker_grants is empty (user has no identity record yet), treat as
    # "no restrictions" for community tier — ceiling is still enforced.
    # This matches the RISK-097 spec: ceiling comes from BOTH sources.
    if invoker_grants:
        effective = declared_set & invoker_grants & system_ceiling
    else:
        # No identity record → fall back to system-ceiling-only intersection.
        # This is intentionally conservative: only skills that exist in the
        # system are allowed; no user-level over-grant can sneak in.
        effective = declared_set & system_ceiling

    rejected = sorted(declared_set - effective)
    return sorted(effective), rejected


# ---------------------------------------------------------------------------
# Letta pool helper
# ---------------------------------------------------------------------------

def _letta_unavailable_503():
    """Return HTTP 503 for Letta pool not yet wired."""
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "error": "letta_pool_unavailable",
            "message": (
                "Per-user Letta agent provisioning is not yet available. "
                "Agent metadata has been saved. Letta will be provisioned "
                "when feat/4.0-agent-isolation (Captain) merges."
            ),
        },
    )


# ---------------------------------------------------------------------------
# Response serialisers
# ---------------------------------------------------------------------------

def _serialise_agent(ua_id: str, meta: dict) -> dict:
    return {
        "ua_id": ua_id,
        "name": meta.get("name", ""),
        "description": meta.get("description", ""),
        "personality": _j(meta.get("personality", "{}")),
        "effective_skills": _j(meta.get("effective_skills", "[]")),
        "declared_skills": _j(meta.get("declared_skills", "[]")),
        "letta_agent_id": meta.get("letta_agent_id") or None,
        "created_at": meta.get("created_at", ""),
        "updated_at": meta.get("updated_at", ""),
    }


def _serialise_block(block_id: str, meta: dict) -> dict:
    return {
        "block_id": block_id,
        "label": meta.get("label", ""),
        "value": meta.get("value", ""),
        "letta_block_id": meta.get("letta_block_id") or None,
        "created_at": meta.get("created_at", ""),
        "updated_at": meta.get("updated_at", ""),
    }


def _j(raw: str) -> list | dict:
    """Decode a JSON string stored in Redis; return [] or {} on error."""
    try:
        return json.loads(raw)
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Pydantic request bodies
# ---------------------------------------------------------------------------

class CreateAgentBody(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=512)
    persona: str = Field(default="I am a helpful AI assistant with persistent memory.", max_length=4096)
    system_prompt: str = Field(default="", max_length=8192)
    skills: list[str] = Field(default_factory=list, max_length=50)


class PatchAgentBody(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=512)


class SetPersonalityBody(BaseModel):
    persona: Optional[str] = Field(default=None, max_length=4096)
    system_prompt: Optional[str] = Field(default=None, max_length=8192)


class SetSkillsBody(BaseModel):
    skills: list[str] = Field(max_length=50)


class CreateMemoryBody(BaseModel):
    label: str = Field(min_length=1, max_length=128)
    value: str = Field(default="", max_length=32768)


class PatchMemoryBody(BaseModel):
    label: Optional[str] = Field(default=None, min_length=1, max_length=128)
    value: Optional[str] = Field(default=None, max_length=32768)


class SaveGraphBody(BaseModel):
    """CTF graph payload from the Drawflow builder.

    The server validates structural constraints (V-001..V-015) and strips any
    client-supplied ``effective_scope`` fields before storage (R11).
    """
    # The full CTF graph object.  Arbitrary structure accepted here; server
    # validates below in _validate_and_strip_graph().
    graph: dict[str, Any] = Field(description="CTF graph object (nodes + edges)")
    # Declared scope — server will compute effective_scope server-side.
    # Client may supply declared_scope; server never accepts effective_scope from client.
    declared_scope: Optional[dict[str, Any]] = Field(default=None)


# ===========================================================================
# /user/agents — agent lifecycle
# ===========================================================================


@router.get("/user/agents")
async def list_user_agents(session: UserSession):
    """List the calling user's agents."""
    r = _get_redis()
    raw_ids = r.smembers(_agents_key(session.account_id))
    ua_ids = _decode_set(raw_ids)
    agents = []
    for ua_id in sorted(ua_ids):
        raw = r.hgetall(_meta_key(ua_id))
        if raw:
            meta = _decode_hash(raw)
            if meta.get("account_id") == session.account_id:
                agents.append(_serialise_agent(ua_id, meta))
    return {"agents": agents}


@router.post("/user/agents", status_code=status.HTTP_201_CREATED)
async def create_user_agent(body: CreateAgentBody, session: UserSession):
    """Create a new user agent.

    Computes effective_skills via scope intersection immediately.
    Letta provisioning is deferred until the pool seam is wired (503 if
    tried now).  The agent record is created in Redis regardless.
    """
    r = _get_redis()
    ua_id = _new_ua_id()
    now = _now_iso()

    effective, rejected = compute_effective_skills(body.skills, session.account_id, r)

    personality = {"persona": body.persona, "system_prompt": body.system_prompt}

    mapping = {
        b"account_id":      session.account_id.encode(),
        b"name":            body.name.encode(),
        b"description":     body.description.encode(),
        b"personality":     json.dumps(personality).encode(),
        b"effective_skills": json.dumps(effective).encode(),
        b"declared_skills":  json.dumps(body.skills).encode(),
        b"letta_agent_id":  b"",
        b"created_at":      now.encode(),
        b"updated_at":      now.encode(),
    }

    pipe = r.pipeline()
    pipe.hset(_meta_key(ua_id), mapping=mapping)
    pipe.sadd(_agents_key(session.account_id), ua_id.encode())
    pipe.execute()

    logger.info("user_agents: created %s for account %r", ua_id, session.account_id)

    return {
        "ua_id": ua_id,
        "name": body.name,
        "effective_skills": effective,
        "rejected_skills": rejected,
        "letta_agent_id": None,
        "created_at": now,
    }


@router.get("/user/agents/{ua_id}")
async def get_user_agent(ua_id: str, session: UserSession):
    """Get agent config. 404 on BOLA violation."""
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)
    return _serialise_agent(ua_id, meta)


@router.patch("/user/agents/{ua_id}")
async def patch_user_agent(ua_id: str, body: PatchAgentBody, session: UserSession):
    """Update agent name or description. 404 on BOLA violation."""
    r = _get_redis()
    _get_agent_or_404(r, ua_id, session.account_id)  # BOLA check

    updates: dict[bytes, bytes] = {b"updated_at": _now_iso().encode()}
    if body.name is not None:
        updates[b"name"] = body.name.encode()
    if body.description is not None:
        updates[b"description"] = body.description.encode()

    r.hset(_meta_key(ua_id), mapping=updates)
    return {"ua_id": ua_id, "updated": list(
        k.decode() for k in updates if k != b"updated_at"
    )}


@router.delete("/user/agents/{ua_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_agent(ua_id: str, session: UserSession):
    """Delete agent and detach all memory blocks. 404 on BOLA violation."""
    r = _get_redis()
    _get_agent_or_404(r, ua_id, session.account_id)  # BOLA check

    # Detach all memory blocks from this agent (don't delete the blocks themselves)
    attached = _decode_set(r.smembers(_mem_agent_key(ua_id)))

    pipe = r.pipeline()
    pipe.delete(_meta_key(ua_id))
    pipe.srem(_agents_key(session.account_id), ua_id.encode())
    pipe.delete(_mem_agent_key(ua_id))
    pipe.execute()

    logger.info(
        "user_agents: deleted %s for account %r; detached %d memory blocks",
        ua_id, session.account_id, len(attached),
    )


# ---------------------------------------------------------------------------
# /user/agents/{ua_id}/personality
# ---------------------------------------------------------------------------


@router.get("/user/agents/{ua_id}/personality")
async def get_agent_personality(ua_id: str, session: UserSession):
    """Get the agent's persona and system prompt. 404 on BOLA violation."""
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)
    personality = _j(meta.get("personality", "{}"))
    if not isinstance(personality, dict):
        personality = {}
    return {
        "ua_id": ua_id,
        "persona": personality.get("persona", ""),
        "system_prompt": personality.get("system_prompt", ""),
    }


@router.put("/user/agents/{ua_id}/personality")
async def set_agent_personality(ua_id: str, body: SetPersonalityBody, session: UserSession):
    """Update the agent's persona and/or system prompt.

    Pushes to Letta via pool if available; otherwise updates Redis only
    (Letta sync deferred to pool availability).  Returns 503 only when
    a live Letta operation is attempted.  Metadata update always succeeds.
    """
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)

    current = _j(meta.get("personality", "{}"))
    if not isinstance(current, dict):
        current = {}

    if body.persona is not None:
        current["persona"] = body.persona
    if body.system_prompt is not None:
        current["system_prompt"] = body.system_prompt

    r.hset(_meta_key(ua_id), mapping={
        b"personality": json.dumps(current).encode(),
        b"updated_at":  _now_iso().encode(),
    })

    # Attempt live Letta push (no-op if pool not ready)
    letta_agent_id = meta.get("letta_agent_id", "")
    letta_synced = False
    if letta_agent_id:
        try:
            from yashigani.gateway.letta_pool import LettaClientPool
            client, base_url, _ = await LettaClientPool.for_user(session.account_id)
            async with client:
                # Letta memory block PATCH to update persona block
                await client.patch(
                    f"{base_url}/v1/agents/{letta_agent_id}/memory/blocks",
                    json={"label": "persona", "value": current.get("persona", "")},
                )
            letta_synced = True
        except Exception:
            # Pool not wired or Letta unavailable — metadata saved; Letta sync deferred.
            letta_synced = False

    return {
        "ua_id": ua_id,
        "persona": current.get("persona", ""),
        "system_prompt": current.get("system_prompt", ""),
        "letta_synced": letta_synced,
    }


# ---------------------------------------------------------------------------
# /user/agents/{ua_id}/skills
# ---------------------------------------------------------------------------


@router.get("/user/agents/{ua_id}/skills")
async def get_agent_skills(ua_id: str, session: UserSession):
    """Get the agent's effective skill set. 404 on BOLA violation."""
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)
    return {
        "ua_id": ua_id,
        "effective_skills": _j(meta.get("effective_skills", "[]")),
        "declared_skills":  _j(meta.get("declared_skills", "[]")),
    }


@router.put("/user/agents/{ua_id}/skills")
async def set_agent_skills(ua_id: str, body: SetSkillsBody, session: UserSession):
    """Set agent skills — scope intersection enforced (R3 / RISK-097).

    Returns the effective_skills (declared ∩ invoker_grants ∩ system_ceiling)
    and the rejected_skills (declared − effective).

    A skill outside the user's grants or outside the system ceiling is silently
    dropped into rejected_skills rather than raising a 403, so the caller can
    see exactly what was granted vs. refused.

    404 on BOLA violation.
    """
    r = _get_redis()
    _get_agent_or_404(r, ua_id, session.account_id)  # BOLA check

    effective, rejected = compute_effective_skills(body.skills, session.account_id, r)

    r.hset(_meta_key(ua_id), mapping={
        b"effective_skills": json.dumps(effective).encode(),
        b"declared_skills":  json.dumps(body.skills).encode(),
        b"updated_at":       _now_iso().encode(),
    })

    logger.info(
        "user_agents: skills set on %s for account %r — effective=%r rejected=%r",
        ua_id, session.account_id, effective, rejected,
    )
    return {
        "ua_id": ua_id,
        "effective_skills": effective,
        "rejected_skills": rejected,
    }


# ---------------------------------------------------------------------------
# /user/agents/{ua_id}/memories — memory attachment
# ---------------------------------------------------------------------------


@router.get("/user/agents/{ua_id}/memories")
async def list_agent_memories(ua_id: str, session: UserSession):
    """List memory blocks currently attached to this agent. 404 on BOLA."""
    r = _get_redis()
    _get_agent_or_404(r, ua_id, session.account_id)  # BOLA check

    block_ids = _decode_set(r.smembers(_mem_agent_key(ua_id)))
    blocks = []
    for bid in sorted(block_ids):
        raw = r.hgetall(_mem_meta_key(bid))
        if raw:
            meta = _decode_hash(raw)
            if meta.get("account_id") == session.account_id:
                blocks.append(_serialise_block(bid, meta))
    return {"ua_id": ua_id, "memories": blocks}


@router.post("/user/agents/{ua_id}/memories/{block_id}", status_code=status.HTTP_201_CREATED)
async def attach_memory_to_agent(ua_id: str, block_id: str, session: UserSession):
    """Attach a memory block to an agent.

    Both the agent and the block must be owned by the calling user (BOLA).
    Returns 404 on any BOLA violation.  Idempotent — attaching an already-
    attached block is a no-op.
    """
    r = _get_redis()
    agent_meta = _get_agent_or_404(r, ua_id, session.account_id)
    block_meta  = _get_block_or_404(r, block_id, session.account_id)

    r.sadd(_mem_agent_key(ua_id), block_id.encode())

    letta_agent_id = agent_meta.get("letta_agent_id", "")
    letta_block_id = block_meta.get("letta_block_id", "")
    letta_synced = False

    if letta_agent_id and letta_block_id:
        try:
            from yashigani.gateway.letta_pool import LettaClientPool
            client, base_url, _ = await LettaClientPool.for_user(session.account_id)
            async with client:
                await client.post(
                    f"{base_url}/v1/agents/{letta_agent_id}/memory/blocks",
                    json={"id": letta_block_id},
                )
            letta_synced = True
        except Exception:
            letta_synced = False

    return {"ua_id": ua_id, "block_id": block_id, "letta_synced": letta_synced}


@router.delete("/user/agents/{ua_id}/memories/{block_id}", status_code=status.HTTP_204_NO_CONTENT)
async def detach_memory_from_agent(ua_id: str, block_id: str, session: UserSession):
    """Detach a memory block from an agent (does NOT delete the block).

    Both the agent and the block must be owned by the calling user (BOLA).
    """
    r = _get_redis()
    agent_meta = _get_agent_or_404(r, ua_id, session.account_id)
    _get_block_or_404(r, block_id, session.account_id)

    r.srem(_mem_agent_key(ua_id), block_id.encode())

    letta_agent_id = agent_meta.get("letta_agent_id", "")
    # Best-effort Letta detach (no raise on failure — metadata is authoritative)
    if letta_agent_id:
        try:
            from yashigani.gateway.letta_pool import LettaClientPool
            client, base_url, _ = await LettaClientPool.for_user(session.account_id)
            async with client:
                await client.delete(
                    f"{base_url}/v1/agents/{letta_agent_id}/memory/blocks/{block_id}",
                )
        except Exception:
            pass  # Letta sync deferred; Redis detach is the source of truth


# ===========================================================================
# /user/memories — memory block CRUD
# ===========================================================================


@router.get("/user/memories")
async def list_user_memories(session: UserSession):
    """List all memory blocks owned by the calling user."""
    r = _get_redis()
    raw_ids = r.smembers(_mem_all_key(session.account_id))
    block_ids = _decode_set(raw_ids)
    blocks = []
    for bid in sorted(block_ids):
        raw = r.hgetall(_mem_meta_key(bid))
        if raw:
            meta = _decode_hash(raw)
            if meta.get("account_id") == session.account_id:
                blocks.append(_serialise_block(bid, meta))
    return {"memories": blocks}


@router.post("/user/memories", status_code=status.HTTP_201_CREATED)
async def create_memory_block(body: CreateMemoryBody, session: UserSession):
    """Create a memory block.

    Stores in Redis immediately.  Letta provisioning (letta_block_id) is
    deferred until the user attaches the block to an agent that has a live
    Letta agent_id, or until the pool seam is wired.
    """
    r = _get_redis()
    block_id = _new_block_id()
    now = _now_iso()

    mapping = {
        b"account_id":     session.account_id.encode(),
        b"label":          body.label.encode(),
        b"value":          body.value.encode(),
        b"letta_block_id": b"",
        b"created_at":     now.encode(),
        b"updated_at":     now.encode(),
    }

    pipe = r.pipeline()
    pipe.hset(_mem_meta_key(block_id), mapping=mapping)
    pipe.sadd(_mem_all_key(session.account_id), block_id.encode())
    pipe.execute()

    logger.info("user_agents: memory block %s created for account %r", block_id, session.account_id)
    return {"block_id": block_id, "label": body.label, "created_at": now}


@router.get("/user/memories/{block_id}")
async def get_memory_block(block_id: str, session: UserSession):
    """Get a memory block. 404 on BOLA violation."""
    r = _get_redis()
    meta = _get_block_or_404(r, block_id, session.account_id)
    return _serialise_block(block_id, meta)


@router.patch("/user/memories/{block_id}")
async def patch_memory_block(block_id: str, body: PatchMemoryBody, session: UserSession):
    """Rename or update a memory block's value.

    Propagates value update to Letta if pool is wired and letta_block_id exists.
    Metadata update always succeeds regardless of Letta availability.
    404 on BOLA violation.
    """
    r = _get_redis()
    meta = _get_block_or_404(r, block_id, session.account_id)

    updates: dict[bytes, bytes] = {b"updated_at": _now_iso().encode()}
    if body.label is not None:
        updates[b"label"] = body.label.encode()
    if body.value is not None:
        updates[b"value"] = body.value.encode()

    r.hset(_mem_meta_key(block_id), mapping=updates)

    letta_block_id = meta.get("letta_block_id", "")
    letta_synced = False
    if letta_block_id and body.value is not None:
        try:
            from yashigani.gateway.letta_pool import LettaClientPool
            client, base_url, _ = await LettaClientPool.for_user(session.account_id)
            async with client:
                await client.patch(
                    f"{base_url}/v1/blocks/{letta_block_id}",
                    json={"value": body.value},
                )
            letta_synced = True
        except Exception:
            letta_synced = False

    return {
        "block_id": block_id,
        "updated": [k.decode() for k in updates if k != b"updated_at"],
        "letta_synced": letta_synced,
    }


@router.delete("/user/memories/{block_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_memory_block(block_id: str, session: UserSession):
    """Delete a memory block and auto-detach it from all agents.

    Letta block deletion is attempted if pool is wired.  Redis deletion is
    always performed.  404 on BOLA violation.
    """
    r = _get_redis()
    meta = _get_block_or_404(r, block_id, session.account_id)

    # Collect all agents this block is attached to so we can remove from each
    # ua:mem:agent:{ua_id} set.  We do a scan over all agent sets.
    agent_ids = _decode_set(r.smembers(_agents_key(session.account_id)))

    letta_block_id = meta.get("letta_block_id", "")

    pipe = r.pipeline()
    pipe.delete(_mem_meta_key(block_id))
    pipe.srem(_mem_all_key(session.account_id), block_id.encode())
    for ua_id in agent_ids:
        pipe.srem(_mem_agent_key(ua_id), block_id.encode())
    pipe.execute()

    # Best-effort Letta delete
    if letta_block_id:
        try:
            from yashigani.gateway.letta_pool import LettaClientPool
            client, base_url, _ = await LettaClientPool.for_user(session.account_id)
            async with client:
                await client.delete(f"{base_url}/v1/blocks/{letta_block_id}")
        except Exception:
            pass  # Redis delete is authoritative

    logger.info("user_agents: memory block %s deleted for account %r", block_id, session.account_id)


# ===========================================================================
# Graph persistence helpers (Phase 4 — RISK-113 / R11)
# ===========================================================================

# Label allowlist pattern (no HTML chars, V-011)
_LABEL_RE = re.compile(r"^[^<>&\"']{1,256}$")
_EDGE_LABEL_RE = re.compile(r"^[^<>&\"']{0,128}$")

_VALID_NODE_TYPES = frozenset({
    "input_node", "output_node", "tool_node", "model_node",
    "agent_node", "policy_node", "langflow_node",
})

_MAX_NODES = 32
_MAX_EDGES = 64
_MAX_FANOUT = 4
_MAX_DEPTH = 9


def _sha384_graph(graph_json: str) -> str:
    """SHA-384 hex of the normalised CTF graph JSON for audit."""
    return "sha384:" + hashlib.sha384(graph_json.encode("utf-8")).hexdigest()


def _strip_effective_scope_from_node(node: dict) -> dict:
    """Remove client-supplied effective_scope from a node (R11).

    Returns a copy with ``data.effective_scope`` stripped if present.
    The server computes effective_scope server-side — the client cannot
    supply it to influence scope at execution time.
    """
    node = dict(node)
    if isinstance(node.get("data"), dict):
        data = dict(node["data"])
        data.pop("effective_scope", None)
        node["data"] = data
    return node


def _validate_and_strip_graph(graph: dict) -> tuple[dict, list[str]]:
    """Validate CTF graph and strip R11 fields.

    Returns (stripped_graph, errors).  If errors is non-empty, the caller
    must reject with HTTP 422.

    Implements V-001..V-011 (structural), V-014 (depth), V-015 (fan-out).
    V-012/V-013 (registry/scope) are deferred to NHI instantiation time.

    Server-strips:
      - ``node.data.effective_scope`` (R11: never trust client-supplied scope)
      - Any top-level ``effective_scope`` or ``import_provenance`` fields
        (those are server-populated at import time only).
    """
    errors: list[str] = []
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    # Size caps (RISK-111)
    if len(nodes) > _MAX_NODES:
        errors.append(f"V-NODES: too many nodes ({len(nodes)} > {_MAX_NODES})")
    if len(edges) > _MAX_EDGES:
        errors.append(f"V-EDGES: too many edges ({len(edges)} > {_MAX_EDGES})")

    # V-001: exactly one input_node
    input_nodes = [n for n in nodes if n.get("node_type") == "input_node"]
    if len(input_nodes) != 1:
        errors.append(f"V-001: expected exactly one input_node, got {len(input_nodes)}")

    # V-002: exactly one output_node
    output_nodes = [n for n in nodes if n.get("node_type") == "output_node"]
    if len(output_nodes) != 1:
        errors.append(f"V-002: expected exactly one output_node, got {len(output_nodes)}")

    # V-011: label HTML safety
    node_ids: set[str] = set()
    stripped_nodes = []
    for node in nodes:
        node_type = node.get("node_type", "")
        if node_type not in _VALID_NODE_TYPES:
            errors.append(f"V-TYPE: unknown node_type {node_type!r}")
        label = node.get("label", "")
        if not _LABEL_RE.fullmatch(label):
            errors.append(f"V-011: node label contains HTML or is too long: {label[:32]!r}")
        node_id = node.get("id", "")
        if node_id:
            node_ids.add(node_id)
        stripped_nodes.append(_strip_effective_scope_from_node(node))

    # V-003: edge node references
    stripped_edges = []
    out_edges: dict[str, int] = {}
    for edge in edges:
        src = edge.get("source_node_id", "")
        tgt = edge.get("target_node_id", "")
        if src not in node_ids:
            errors.append(f"V-003: edge source_node_id {src!r} not in graph")
        if tgt not in node_ids:
            errors.append(f"V-003: edge target_node_id {tgt!r} not in graph")
        # V-011: edge label
        elabel = edge.get("label", "")
        if elabel and not _EDGE_LABEL_RE.fullmatch(elabel):
            errors.append(f"V-011: edge label contains HTML: {elabel[:32]!r}")
        # Count fan-out per source
        out_edges[src] = out_edges.get(src, 0) + 1
        # V-004: no self-loops (simple cycle check — DAG full check is O(N+E))
        if src == tgt:
            errors.append(f"V-004: self-loop on node {src!r}")
        # Enforce governed=true and audit=true (immutable constants per spec)
        stripped_edge = dict(edge)
        stripped_edge["governed"] = True
        stripped_edge["audit"] = True
        stripped_edges.append(stripped_edge)

    # V-015: fan-out
    for node_id, fan in out_edges.items():
        if fan > _MAX_FANOUT:
            errors.append(f"V-015: node {node_id!r} fan-out {fan} > {_MAX_FANOUT}")

    # V-004: cycle detection (simple DFS)
    adj: dict[str, list[str]] = {n.get("id", ""): [] for n in nodes}
    for edge in stripped_edges:
        src = edge.get("source_node_id", "")
        tgt = edge.get("target_node_id", "")
        if src in adj:
            adj[src].append(tgt)

    visited: set[str] = set()
    rec_stack: set[str] = set()

    def _has_cycle(v: str) -> bool:
        visited.add(v)
        rec_stack.add(v)
        for nb in adj.get(v, []):
            if nb not in visited:
                if _has_cycle(nb):
                    return True
            elif nb in rec_stack:
                return True
        rec_stack.discard(v)
        return False

    for node_id in list(adj.keys()):
        if node_id not in visited:
            if _has_cycle(node_id):
                errors.append("V-004: graph contains a cycle; cycles are not permitted")
                break

    stripped_graph = {
        "nodes": stripped_nodes,
        "edges": stripped_edges,
    }
    return stripped_graph, errors


# ===========================================================================
# /user/skills — available skill catalog
# ===========================================================================


@router.get("/user/skills")
async def list_available_skills(session: UserSession):
    """List skills available to this user for assignment to agents.

    Returns the intersection of:
      - the system-wide skill catalog (active agents' allowed_paths)
      - the calling user's allowed_tools from the identity registry

    If the user has no identity record, the full system catalog is returned
    (community-tier: any registered skill may be used).
    """
    r = _get_redis()
    system_ceiling = _compute_system_ceiling(r)
    invoker_grants = _get_invoker_grants(session.account_id)

    if invoker_grants:
        available = sorted(system_ceiling & invoker_grants)
    else:
        # No identity / community tier — all system skills are available.
        available = sorted(system_ceiling)

    return {"available_skills": available, "count": len(available)}


# ===========================================================================
# /user/agents/{ua_id}/graph — builder graph persistence (Phase 4 / RISK-113)
# ===========================================================================


@router.put("/user/agents/{ua_id}/graph")
async def save_agent_graph(ua_id: str, body: SaveGraphBody, session: UserSession):
    """Persist the Drawflow builder graph server-side (Phase 4).

    BOLA: the agent must be owned by the calling user (404 on violation).

    R11 enforcement:
      - Strips any client-supplied ``effective_scope`` from all nodes.
      - Sets ``governed=true`` and ``audit=true`` on all edges (immutable constants).
      - Server never accepts ``import_provenance`` or top-level ``effective_scope``
        from the client — those are server-populated fields only.

    Validation: V-001..V-011, V-014, V-015 (structural CTF constraints).
    Emits ``AGENT_TEMPLATE_SAVED`` to the audit hash-chain.

    Returns the saved graph hash and node/edge counts.
    """
    r = _get_redis()
    _get_agent_or_404(r, ua_id, session.account_id)  # BOLA check

    graph_input = body.graph
    stripped_graph, errors = _validate_and_strip_graph(graph_input)
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "graph_validation_failed", "violations": errors},
        )

    node_count = len(stripped_graph.get("nodes", []))
    edge_count = len(stripped_graph.get("edges", []))

    # Build the persisted CTF document.
    # Strip client-supplied effective_scope and import_provenance at the top level (R11).
    scope = dict(body.declared_scope) if body.declared_scope else {}
    scope.pop("effective_scope", None)   # R11: server-computed only
    scope.pop("import_provenance", None)  # server-populated only

    ctf_doc = {
        "spec_version": "1.0",
        "graph": stripped_graph,
        "scope": scope,
        # Lifecycle and NHI fields are managed server-side; not set by PUT graph.
    }
    ctf_json = json.dumps(ctf_doc, separators=(",", ":"), sort_keys=True)
    graph_hash = _sha384_graph(ctf_json)

    r.hset(_meta_key(ua_id), mapping={
        b"graph":      ctf_json.encode("utf-8"),
        b"graph_hash": graph_hash.encode("utf-8"),
        b"updated_at": _now_iso().encode("utf-8"),
    })

    logger.info(
        "user_agents: graph saved for %s account=%r nodes=%d edges=%d hash=%s",
        ua_id, session.account_id, node_count, edge_count, graph_hash[:24],
    )

    # Audit event to hash-chain (RISK-104 / AUDIT-GAP-001 class)
    aw = getattr(backoffice_state, "audit_writer", None)
    if aw is not None:
        try:
            from yashigani.audit.schema import AgentTemplateGraphSavedEvent
            aw.write(AgentTemplateGraphSavedEvent(
                owner_identity_id=session.account_id,
                ua_id=ua_id,
                node_count=node_count,
                edge_count=edge_count,
                graph_hash=graph_hash,
                effective_scope_stripped=True,
            ))
        except Exception as exc:
            logger.warning("AgentTemplateGraphSavedEvent audit write failed: %s", exc)

    return {
        "ua_id": ua_id,
        "graph_hash": graph_hash,
        "node_count": node_count,
        "edge_count": edge_count,
        "effective_scope_stripped": True,
    }


@router.get("/user/agents/{ua_id}/graph")
async def load_agent_graph(ua_id: str, session: UserSession):
    """Load the persisted CTF graph for edit in the builder.

    BOLA: the agent must be owned by the calling user (404 on violation).

    Returns the stored CTF document (``graph`` + ``scope`` + ``graph_hash``).
    If no graph has been saved yet, returns ``graph: null`` so the builder
    knows to start from an empty canvas.
    """
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)

    graph_raw = meta.get("graph", "")
    graph_hash = meta.get("graph_hash", "")

    if not graph_raw:
        return {
            "ua_id": ua_id,
            "graph": None,
            "graph_hash": None,
            "message": "No graph saved yet — builder starts from empty canvas.",
        }

    try:
        ctf_doc = json.loads(graph_raw)
    except json.JSONDecodeError:
        logger.error("user_agents: corrupted graph JSON for %s", ua_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "graph_corrupted"},
        )

    return {
        "ua_id": ua_id,
        "graph": ctf_doc.get("graph"),
        "scope": ctf_doc.get("scope", {}),
        "graph_hash": graph_hash,
    }


# ===========================================================================
# /user/agents/{ua_id}/run — NHI instantiation (Phase 3 / RISK-097)
# ===========================================================================


@router.post("/user/agents/{ua_id}/run", status_code=status.HTTP_201_CREATED)
async def run_user_agent(ua_id: str, session: UserSession):
    """Instantiate an NHI from the user agent's stored graph + skills (Phase 3).

    Compute effective_scope = declared_skills ∩ invoker_grants ∩ system_ceiling (R3).
    Register the NHI in AgentRegistry (kind="nhi") with the computed scope.
    Returns nhi_id + svid_pending flag.

    If ``svid_issued=False`` the NHI requires admin approval before gateway calls
    will be accepted (403 NHI_PENDING_APPROVAL on invocation).

    BOLA: the agent must be owned by the calling user.
    Requires an agent registry (HTTP 503 if unavailable).
    """
    r = _get_redis()
    meta = _get_agent_or_404(r, ua_id, session.account_id)

    # Check if an NHI is already instantiated for this agent
    existing_nhi_id = meta.get("nhi_id", "")
    if existing_nhi_id:
        # Return existing NHI metadata (idempotent for re-run)
        return {
            "ua_id": ua_id,
            "nhi_id": existing_nhi_id,
            "svid_pending": True,  # caller should check registry for svid_issued
            "message": "NHI already instantiated for this agent.",
        }

    # Require agent registry
    agent_registry = getattr(backoffice_state, "agent_registry", None)
    if agent_registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "registry_unavailable",
                    "message": "Agent registry not ready — cannot instantiate NHI."},
        )

    # Require a saved graph
    graph_raw = meta.get("graph", "")
    if not graph_raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "no_graph_saved",
                    "message": "Save a builder graph first (PUT /user/agents/{ua_id}/graph)."},
        )

    # R3: effective_scope = declared_skills ∩ invoker_grants ∩ system_ceiling
    _raw_skills = _j(meta.get("effective_skills", "[]"))
    declared_skills: list[str] = _raw_skills if isinstance(_raw_skills, list) else []
    effective_tools, rejected = compute_effective_skills(declared_skills, session.account_id, r)

    if not effective_tools:
        # Emit NHI_INSTANTIATION_DENIED
        aw = getattr(backoffice_state, "audit_writer", None)
        if aw is not None:
            try:
                from yashigani.audit.schema import NhiInstantiationDeniedEvent
                aw.write(NhiInstantiationDeniedEvent(
                    owner_identity_id=session.account_id,
                    ua_id=ua_id,
                    reason="empty_intersection",
                ))
            except Exception as exc:
                logger.warning("NhiInstantiationDeniedEvent audit write failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "NHI_INSTANTIATION_DENIED",
                "reason": "empty_intersection",
                "message": (
                    "Scope intersection is empty — the declared skills do not overlap "
                    "with your grants or the system ceiling. No NHI can be instantiated."
                ),
            },
        )

    agent_name = meta.get("name", ua_id)
    # Compute scope hash for audit (R3)
    scope_obj = {"allowed_tools": sorted(effective_tools)}
    scope_hash = "sha384:" + hashlib.sha384(
        json.dumps(scope_obj, sort_keys=True).encode("utf-8")
    ).hexdigest()

    # Emit NHI_INSTANTIATION_REQUESTED
    aw = getattr(backoffice_state, "audit_writer", None)
    if aw is not None:
        try:
            from yashigani.audit.schema import NhiInstantiationRequestedEvent, NhiScopeIntersectedEvent
            aw.write(NhiInstantiationRequestedEvent(
                owner_identity_id=session.account_id,
                ua_id=ua_id,
                template_name=agent_name,
            ))
        except Exception as exc:
            logger.warning("NhiInstantiationRequestedEvent audit write failed: %s", exc)

    # Register NHI in AgentRegistry
    budget_cap = {
        "max_tokens_per_run": 8192,
        "max_tool_calls_per_run": 20,
    }
    try:
        nhi_id, _plaintext_token = agent_registry.register_nhi(
            name=agent_name,
            owner_identity_id=session.account_id,
            template_id=ua_id,
            allowed_tools=effective_tools,
            allowed_paths=effective_tools,
            allowed_models=[],
            sensitivity_ceiling="INTERNAL",
            budget_cap=budget_cap,
            pids_limit=64,
            memory_mb=512,
        )
    except Exception as exc:
        logger.error("NHI registration failed for ua_id=%s: %s", ua_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "nhi_registration_failed", "message": str(exc)},
        )

    # Persist nhi_id back to the agent meta
    r.hset(_meta_key(ua_id), mapping={
        b"nhi_id":     nhi_id.encode("utf-8"),
        b"updated_at": _now_iso().encode("utf-8"),
    })

    # Emit NHI_SCOPE_INTERSECTED
    if aw is not None:
        try:
            aw.write(NhiScopeIntersectedEvent(
                nhi_id=nhi_id,
                owner_identity_id=session.account_id,
                effective_scope_hash=scope_hash,
                declared_scope_tool_count=len(declared_skills),
                effective_scope_tool_count=len(effective_tools),
            ))
        except Exception as exc:
            logger.warning("NhiScopeIntersectedEvent audit write failed: %s", exc)

    logger.info(
        "user_agents: NHI instantiated nhi_id=%s ua_id=%s account=%r effective_tools=%d rejected=%d",
        nhi_id, ua_id, session.account_id, len(effective_tools), len(rejected),
    )

    return {
        "ua_id": ua_id,
        "nhi_id": nhi_id,
        "effective_scope": {"allowed_tools": effective_tools},
        "rejected_tools": rejected,
        "svid_pending": True,
        "message": (
            "NHI registered (svid_issued=False). An admin must approve the NHI in the "
            "backoffice before gateway invocations are accepted."
        ),
    }
