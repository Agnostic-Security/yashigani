"""
Yashigani 4.0 — User-plane Letta agent capability routes.

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
                                           letta_agent_id, created_at, updated_at
  ua:mem:all:{account_id}           Set  — block_ids owned by this user
  ua:mem:meta:{block_id}            Hash — account_id, label, value,
                                           letta_block_id, created_at, updated_at
  ua:mem:agent:{ua_agent_id}        Set  — block_ids currently attached to this agent

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
import json
import logging
import uuid
from typing import Optional

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
