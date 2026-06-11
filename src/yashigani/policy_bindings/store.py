"""Yashigani policy-bindings — Redis-backed store (#16, OPA Phase 2).

Redis db/3 key schema (same db as RBACStore, disjoint key prefix):
    ysgbind:binding:{id}  — JSON-serialised PolicyBinding (all fields)

All mutations are write-through: the in-memory dict is updated first, then
persisted to Redis. The constructor replays the full state from Redis so a
restart does not lose any binding (OPA holds data in memory only, so the
backoffice re-pushes to_opa_document() on startup — see app.py lifespan).

A binding maps an activated client policy (OPA module data.clients.<name>) to a
subject scope and a direction. scope_key derivation:
    scope_id set   -> "<kind>:<id>"   (a specific subject)
    scope_id empty -> "<kind>:*"      (all subjects of that kind / wildcard)
direction "both" expands to BOTH ingress and egress lists in the OPA document.
"""
from __future__ import annotations

import json
import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_KEY_BINDING = "ysgbind:binding:{}"   # .format(binding_id)

VALID_SCOPE_KINDS = frozenset({"human", "service", "api_client", "mcp_server", "agent"})
VALID_DIRECTIONS = frozenset({"ingress", "egress", "both"})


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


@dataclass
class PolicyBinding:
    policy_name: str
    scope_kind: str
    direction: str
    scope_id: str = ""          # "" => wildcard (all subjects of scope_kind)
    enabled: bool = True
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created_at: str = field(default_factory=_now_iso)

    def scope_key(self) -> str:
        """OPA data key: '<kind>:<id>' for a specific subject, '<kind>:*' for all."""
        return f"{self.scope_kind}:{self.scope_id}" if self.scope_id else f"{self.scope_kind}:*"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "PolicyBinding":
        return cls(
            policy_name=d["policy_name"],
            scope_kind=d["scope_kind"],
            direction=d["direction"],
            scope_id=d.get("scope_id", ""),
            enabled=bool(d.get("enabled", True)),
            id=d.get("id") or uuid.uuid4().hex,
            created_at=d.get("created_at") or _now_iso(),
        )


class BindingStore:
    """Thread-safe client-policy binding store backed by Redis db/3.

    Mirrors RBACStore: write-through to Redis, replay-on-construct. Raises
    ValueError on invalid scope_kind/direction so a bad bind never reaches OPA.
    """

    def __init__(self, redis_client) -> None:
        """redis_client must be connected to Redis db/3."""
        self._redis = redis_client
        self._bindings: dict[str, PolicyBinding] = {}
        self._lock = threading.Lock()
        self._load_from_redis()

    # -- startup replay -----------------------------------------------------
    def _load_from_redis(self) -> None:
        try:
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(cursor, match="ysgbind:binding:*", count=200)
                for key in keys:
                    raw = self._redis.get(key)
                    if not raw:
                        continue
                    try:
                        b = PolicyBinding.from_dict(json.loads(raw))
                        self._bindings[b.id] = b
                    except Exception as exc:  # noqa: BLE001 — skip a corrupt row, keep the rest
                        logger.error("BindingStore: skipping unreadable %s: %s", key, exc)
                if cursor == 0:
                    break
            logger.info("BindingStore: loaded %d binding(s) from Redis", len(self._bindings))
        except Exception as exc:  # noqa: BLE001 — Redis down at boot must not crash startup
            logger.error("BindingStore: failed to load from Redis: %s", exc)

    # -- mutations (write-through) ------------------------------------------
    def add(self, binding: PolicyBinding) -> PolicyBinding:
        if binding.scope_kind not in VALID_SCOPE_KINDS:
            raise ValueError(f"invalid scope_kind: {binding.scope_kind!r}")
        if binding.direction not in VALID_DIRECTIONS:
            raise ValueError(f"invalid direction: {binding.direction!r}")
        if not binding.policy_name:
            raise ValueError("policy_name is required")
        with self._lock:
            self._bindings[binding.id] = binding
            self._redis.set(_KEY_BINDING.format(binding.id), json.dumps(binding.to_dict()))
        return binding

    def remove(self, binding_id: str) -> bool:
        with self._lock:
            existed = self._bindings.pop(binding_id, None) is not None
            self._redis.delete(_KEY_BINDING.format(binding_id))
        return existed

    def get(self, binding_id: str) -> Optional[PolicyBinding]:
        return self._bindings.get(binding_id)

    def list(self) -> list[PolicyBinding]:
        return list(self._bindings.values())

    # -- OPA document -------------------------------------------------------
    def to_opa_document(self) -> dict:
        """Build the data document OPA expects at data.client_bindings:

            {"client_bindings": {
                "<scope_key>": {"ingress": ["name", ...], "egress": ["name", ...]},
                ...
            }}

        Only ENABLED bindings are included. direction "both" lands in both lists.
        Names within a (scope_key, direction) are de-duplicated and sorted for a
        stable, diffable document.
        """
        doc: dict[str, dict[str, set]] = {}
        for b in self._bindings.values():
            if not b.enabled:
                continue
            sk = b.scope_key()
            slot = doc.setdefault(sk, {"ingress": set(), "egress": set()})
            directions = ("ingress", "egress") if b.direction == "both" else (b.direction,)
            for d in directions:
                slot[d].add(b.policy_name)
        return {
            "client_bindings": {
                sk: {"ingress": sorted(v["ingress"]), "egress": sorted(v["egress"])}
                for sk, v in doc.items()
            }
        }
