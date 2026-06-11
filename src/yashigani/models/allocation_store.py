"""
Yashigani Models — Redis-backed model-allocation store (Track B1).

Model allocations grant a model alias to a scope (org / group / user). They are
the admin-facing lever for model RBAC: an allocation of alias ``smart`` to group
``analysts`` means every identity in ``analysts`` may call the model behind
``smart`` — and (deny-by-default within an allocated scope) ONLY the models
allocated to a scope, once any allocation exists for that scope.

Durable source of truth: Redis db/3 (same instance + connection as the RBAC and
agent-registry stores; disjoint key namespace ``model:alloc:*``). This mirrors
the RBACStore durability pattern exactly — write-through to Redis, replay on
construction — so allocations survive a gateway/redis restart and are reconciled
to OPA on startup.

Redis key schema (db/3):
    model:alloc:{id}                 -> JSON {id, model_alias, target_type, target_id}
    model:alloc:index:{type}:{tid}   -> Redis SET of allocation ids for that scope
    model:alloc:seq                  -> integer counter for allocation ids

``target_type`` is one of ``org`` | ``group`` | ``user``.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_KEY_ALLOC = "model:alloc:{}"            # .format(alloc_id)
_KEY_INDEX = "model:alloc:index:{}:{}"   # .format(target_type, target_id)
_KEY_SEQ = "model:alloc:seq"
_SCAN_MATCH = "model:alloc:[0-9]*"       # only the primary records (not index sets)

VALID_TARGET_TYPES = ("org", "group", "user")


@dataclass
class ModelAllocation:
    """A grant of a model alias to a scope (org / group / user)."""

    id: str
    model_alias: str
    target_type: str   # org | group | user
    target_id: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ModelAllocation":
        return cls(
            id=str(d["id"]),
            model_alias=str(d["model_alias"]),
            target_type=str(d["target_type"]),
            target_id=str(d["target_id"]),
        )


class ModelAllocationStore:
    """
    Redis-backed (db/3) model-allocation store.

    Write-through with an in-memory replay cache, mirroring RBACStore: the
    constructor loads all existing allocations from Redis so a restart never
    loses data; every mutation updates the cache first then persists to Redis.

    The store is intentionally synchronous (the `redis` sync client) because it
    is consulted on the hot request path in the gateway and from the sync admin
    routes in the backoffice — matching ModelAliasStore / RBACStore.
    """

    def __init__(self, redis_client, durable_store=None) -> None:
        self._redis = redis_client
        # Optional Postgres durable mirror (AllocationDurableStore). When wired,
        # add/delete dual-write so allocations survive a redis recreate/restart
        # (Redis db/3 has no persistence). None = Redis-only (dev/test).
        self._durable = durable_store
        self._allocs: dict[str, ModelAllocation] = {}
        self._load_from_redis()

    # ------------------------------------------------------------------
    # Startup replay
    # ------------------------------------------------------------------

    def _load_from_redis(self) -> None:
        try:
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(cursor, match=_SCAN_MATCH, count=200)
                for key in keys:
                    raw = self._redis.get(key)
                    if raw is None:
                        continue
                    try:
                        d = json.loads(raw)
                        alloc = ModelAllocation.from_dict(d)
                        self._allocs[alloc.id] = alloc
                    except Exception as exc:
                        logger.error(
                            "ModelAllocationStore: failed to deserialise %s: %s", key, exc
                        )
                if cursor == 0:
                    break
        except Exception as exc:
            logger.error("ModelAllocationStore: load from Redis failed: %s", exc)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add(self, model_alias: str, target_type: str, target_id: str) -> ModelAllocation:
        """Create and persist an allocation. Returns the stored record.

        Raises ValueError on an invalid target_type (deny-by-default: never
        persist a malformed scope that a downstream resolver could misread).
        """
        if target_type not in VALID_TARGET_TYPES:
            raise ValueError(f"invalid target_type {target_type!r}")
        alloc_id = str(self._redis.incr(_KEY_SEQ))
        alloc = ModelAllocation(
            id=alloc_id,
            model_alias=model_alias,
            target_type=target_type,
            target_id=target_id,
        )
        self._allocs[alloc_id] = alloc
        self._redis.set(_KEY_ALLOC.format(alloc_id), json.dumps(alloc.to_dict()))
        self._redis.sadd(_KEY_INDEX.format(target_type, target_id), alloc_id)
        if self._durable is not None:
            try:
                self._durable.upsert(alloc_id, model_alias, target_type, target_id)
            except Exception as exc:
                # Best-effort durability: the Redis write already succeeded, but a
                # durable-write failure means this allocation would NOT survive a
                # redis recreate. Log loudly so the operator can investigate;
                # do not roll back the live (Redis) allocation.
                logger.warning(
                    "ModelAllocationStore: durable upsert failed for %s (%s) — "
                    "allocation is live in Redis but NOT durable", alloc_id, exc,
                )
        return alloc

    def restore(self, alloc_id: str, model_alias: str, target_type: str, target_id: str) -> None:
        """Re-hydrate a Redis allocation with a KNOWN id (reconcile path only).

        Unlike add(), this does NOT allocate a new id and does NOT dual-write to
        the durable store — the row already exists in Postgres; we are rebuilding
        the Redis view from it. It also bumps the Redis id counter past alloc_id
        so a subsequent add() never collides with a restored id.
        """
        if target_type not in VALID_TARGET_TYPES:
            raise ValueError(f"invalid target_type {target_type!r}")
        alloc = ModelAllocation(
            id=str(alloc_id), model_alias=model_alias,
            target_type=target_type, target_id=target_id,
        )
        self._allocs[alloc.id] = alloc
        self._redis.set(_KEY_ALLOC.format(alloc.id), json.dumps(alloc.to_dict()))
        self._redis.sadd(_KEY_INDEX.format(target_type, target_id), alloc.id)
        # Keep the INCR counter ahead of any restored numeric id.
        try:
            n = int(alloc_id)
            cur = self._redis.get(_KEY_SEQ)
            cur_n = int(cur) if cur is not None else 0
            if n > cur_n:
                self._redis.set(_KEY_SEQ, n)
        except (ValueError, TypeError):
            pass

    def delete(self, alloc_id: str) -> bool:
        """Delete an allocation. Returns True if it existed."""
        alloc = self._allocs.pop(alloc_id, None)
        if alloc is None:
            # Defensive: the primary key may exist in Redis even if not cached.
            raw = self._redis.get(_KEY_ALLOC.format(alloc_id))
            if raw is None:
                return False
            try:
                alloc = ModelAllocation.from_dict(json.loads(raw))
            except Exception:
                self._redis.delete(_KEY_ALLOC.format(alloc_id))
                return True
        self._redis.delete(_KEY_ALLOC.format(alloc_id))
        self._redis.srem(_KEY_INDEX.format(alloc.target_type, alloc.target_id), alloc_id)
        if self._durable is not None:
            try:
                self._durable.delete(alloc_id)
            except Exception as exc:
                logger.warning(
                    "ModelAllocationStore: durable delete failed for %s (%s) — "
                    "removed from Redis but durable row may persist", alloc_id, exc,
                )
        return True

    def get(self, alloc_id: str) -> Optional[ModelAllocation]:
        return self._allocs.get(alloc_id)

    def list_all(self) -> list[ModelAllocation]:
        """All allocations, sorted by numeric id for stable output."""
        def _key(a: ModelAllocation) -> tuple:
            try:
                return (0, int(a.id))
            except ValueError:
                return (1, a.id)
        return sorted(self._allocs.values(), key=_key)

    # ------------------------------------------------------------------
    # Query — used by the effective-allowed-models resolver
    # ------------------------------------------------------------------

    def aliases_for_scope(self, target_type: str, target_id: str) -> set[str]:
        """Model aliases allocated DIRECTLY to one (target_type, target_id).

        Reads the per-scope index SET from Redis LIVE so the gateway sees a
        backoffice allocation mutation immediately (the two run in separate
        processes with separate in-memory caches — a stale local cache would
        silently under/over-enforce). Falls back to the in-memory cache only if
        Redis is unavailable.
        """
        if not target_id:
            return set()
        try:
            ids = self._redis.smembers(_KEY_INDEX.format(target_type, target_id))
            aliases: set[str] = set()
            for raw_id in ids:
                aid = raw_id.decode("utf-8") if isinstance(raw_id, bytes) else raw_id
                raw = self._redis.get(_KEY_ALLOC.format(aid))
                if raw is None:
                    continue
                try:
                    aliases.add(ModelAllocation.from_dict(json.loads(raw)).model_alias)
                except Exception:
                    continue
            return aliases
        except Exception as exc:
            logger.warning(
                "ModelAllocationStore.aliases_for_scope live read failed (%s) — "
                "falling back to in-memory cache", exc,
            )
            return {
                a.model_alias
                for a in self._allocs.values()
                if a.target_type == target_type and a.target_id == target_id
            }

    def scope_has_allocation(self, target_type: str, target_id: str) -> bool:
        """True iff at least one allocation exists for this exact scope (live)."""
        if not target_id:
            return False
        try:
            return bool(self._redis.scard(_KEY_INDEX.format(target_type, target_id)))
        except Exception as exc:
            logger.warning(
                "ModelAllocationStore.scope_has_allocation live read failed (%s) — "
                "in-memory fallback", exc,
            )
            return any(
                a.target_type == target_type and a.target_id == target_id
                for a in self._allocs.values()
            )

    def all_allocated_aliases(self) -> set[str]:
        """Every alias allocated to ANY scope (the GLOBAL gated set).

        Once an alias is allocated anywhere it becomes allocation-gated: callers
        who are not allocated it (via org/group/user) must be DENIED that model,
        even if they are otherwise unrestricted. Read live from Redis (falls back
        to the in-memory cache on a blip).
        """
        try:
            out: set[str] = set()
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(cursor, match=_SCAN_MATCH, count=200)
                for key in keys:
                    raw = self._redis.get(key)
                    if raw is None:
                        continue
                    try:
                        out.add(ModelAllocation.from_dict(json.loads(raw)).model_alias)
                    except Exception:
                        continue
                if cursor == 0:
                    break
            return out
        except Exception as exc:
            logger.warning(
                "ModelAllocationStore.all_allocated_aliases live read failed (%s) — "
                "in-memory fallback", exc,
            )
            return {a.model_alias for a in self._allocs.values()}

    # ------------------------------------------------------------------
    # OPA / reconcile serialisation
    # ------------------------------------------------------------------

    def to_opa_document(self) -> dict:
        """Build the data document pushed to OPA at data.yashigani.allocations.

        Shape (informational mirror — enforcement is computed in the gateway and
        fed via input.identity.allowed_models; this document lets OPA / operators
        inspect the live allocation set and supports future in-rego use):

            {
              "by_scope": {
                "org":   {"<org_id>":   ["<alias>", ...], ...},
                "group": {"<group_id>": ["<alias>", ...], ...},
                "user":  {"<user_id>":  ["<alias>", ...], ...}
              }
            }
        """
        by_scope: dict[str, dict[str, list[str]]] = {"org": {}, "group": {}, "user": {}}
        for a in self._allocs.values():
            if a.target_type not in by_scope:
                continue
            bucket = by_scope[a.target_type].setdefault(a.target_id, [])
            if a.model_alias not in bucket:
                bucket.append(a.model_alias)
        for scope in by_scope.values():
            for ids in scope.values():
                ids.sort()
        return {"by_scope": by_scope}
