"""
Yashigani Document Enforcement — Redis-backed policy-matrix store (2.26).

The operator configures a document-enforcement policy MATRIX
(data_class × format × route → action, + pseudonymize mode A/B + small-set
escalation).  This module persists that matrix to Redis and serialises it into
the OPA data document at ``data.yashigani.document`` so the production rego
(policy/document.rego) evaluates the operator's live configuration.

It deliberately MIRRORS :class:`yashigani.rbac.store.RBACStore`:
  - Redis db/3 (same instance the RBAC store + agent registry use; a distinct
    key namespace so they coexist).
  - Write-through: the in-memory cache is updated first, then persisted.
  - ``_load_from_redis()`` replays the full state on construction so a restart
    never loses data.
  - ``to_opa_document()`` builds the document OPA expects, and the backoffice
    lifespan re-pushes it to OPA on startup (so policies survive a policy-
    container restart) — exactly the OPA-PERSIST pattern the RBAC store uses.

Redis key schema (db/3 — namespaced ``document:`` to coexist with ``rbac:``):
    document:policy:{id}   — JSON-serialised policy row
    document:config        — JSON: {detokenize_role, map_ttl_seconds, small_set_threshold}
    document:policy_seq    — integer counter for new policy ids
"""
from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

_KEY_POLICY = "document:policy:{}"   # .format(policy_id)
_KEY_CONFIG = "document:config"
_KEY_SEQ = "document:policy_seq"

# Allowed vocabularies — enforced on add (defence in depth alongside the route's
# pydantic validation; the store must never persist an out-of-vocab row that the
# rego cannot reason about).
_ACTIONS = frozenset({"LOG", "REDACT", "PSEUDONYMIZE", "BLOCK"})
_FORMATS = frozenset({"docx", "xlsx", "pptx", "pdf", "csv", "txt", "any"})
_ROUTES = frozenset({"ingress-upload", "egress-mcp-result", "json-attachment", "any"})
_DATA_CLASSES = frozenset({"PII", "QI", "PHID", "PHI", "PCI", "SECRET", "IP_MARKING"})
_MODES = frozenset({"A", "B"})

# Default config (fail-closed values mirror the rego defaults in document.rego).
_DEFAULT_CONFIG = {
    "detokenize_role": "doc-pseudonymize-reverser",
    "map_ttl_seconds": 300,
    "small_set_threshold": 20,
}

# Seeded on first boot when the namespace is empty.  Mirrors the demo matrix the
# UI shipped (routes/documents.py stub) so the UX is identical on the real store.
_DEFAULT_POLICIES: list[dict] = [
    {
        "id": "1",
        "data_class": "PCI",
        "format": "any",
        "route": "any",
        "action": "BLOCK",
        "pseudonymize_mode": "A",
        "small_set_escalation": True,
        "description": "Cardholder data anywhere -> BLOCK (fail-closed).",
    },
    {
        "id": "2",
        "data_class": "PII",
        "format": "xlsx",
        "route": "egress-mcp-result",
        "action": "PSEUDONYMIZE",
        "pseudonymize_mode": "A",
        "small_set_escalation": True,
        "description": "Names/IBANs leaving to cloud -> PSEUDONYMIZE (mode A, give user the table).",
    },
    {
        "id": "3",
        "data_class": "PII",
        "format": "any",
        "route": "any",
        "action": "LOG",
        "pseudonymize_mode": "A",
        "small_set_escalation": False,
        "description": "Internal PII -> LOG (passthrough + full audit).",
    },
]


class DocumentPolicyStore:
    """Thread-safe document-enforcement policy store backed by Redis db/3.

    All mutations are write-through: the in-memory cache is updated first, then
    persisted to Redis.  The constructor replays the full state from Redis so a
    restart does not lose any data.  ``seed_defaults()`` populates the demo
    matrix on first boot only (idempotent — never clobbers operator policies).
    """

    def __init__(self, redis_client) -> None:
        self._redis = redis_client
        self._policies: dict[str, dict] = {}
        self._config: dict = dict(_DEFAULT_CONFIG)
        self._load_from_redis()

    # ------------------------------------------------------------------
    # Startup: replay from Redis
    # ------------------------------------------------------------------

    def _load_from_redis(self) -> None:
        """Load all document:policy:* keys + config into the in-memory cache."""
        try:
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(cursor, match="document:policy:*", count=200)
                for key in keys:
                    raw = self._redis.get(key)
                    if raw is None:
                        continue
                    try:
                        d = json.loads(raw)
                        self._policies[d["id"]] = d
                    except Exception as exc:
                        logger.error("DocumentPolicyStore: failed to deserialise %s: %s", key, exc)
                if cursor == 0:
                    break
            raw_cfg = self._redis.get(_KEY_CONFIG)
            if raw_cfg is not None:
                try:
                    self._config = {**_DEFAULT_CONFIG, **json.loads(raw_cfg)}
                except Exception as exc:
                    logger.error("DocumentPolicyStore: failed to deserialise config: %s", exc)
        except Exception as exc:
            logger.error("DocumentPolicyStore: failed to load from Redis: %s", exc)

    # ------------------------------------------------------------------
    # Seeding (first boot only)
    # ------------------------------------------------------------------

    def seed_defaults(self) -> None:
        """Seed the demo matrix ONLY when the namespace is empty.

        Idempotent: if any policy already exists (operator-configured or a prior
        seed) this is a no-op so we never clobber live configuration."""
        if self._policies:
            return
        for p in _DEFAULT_POLICIES:
            self._policies[p["id"]] = dict(p)
            self._redis.set(_KEY_POLICY.format(p["id"]), json.dumps(p))
        # Advance the sequence past the seeded ids so new ids never collide.
        try:
            self._redis.set(_KEY_SEQ, len(_DEFAULT_POLICIES))
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("DocumentPolicyStore: failed to seed sequence: %s", exc)
        if _KEY_CONFIG and self._redis.get(_KEY_CONFIG) is None:
            self._redis.set(_KEY_CONFIG, json.dumps(self._config))
        logger.info("DocumentPolicyStore: seeded %d default policies", len(_DEFAULT_POLICIES))

    # ------------------------------------------------------------------
    # Policy CRUD
    # ------------------------------------------------------------------

    @staticmethod
    def _validate(policy: dict) -> None:
        """Reject out-of-vocab rows the rego cannot reason about (fail-closed)."""
        if policy["action"] not in _ACTIONS:
            raise ValueError(f"invalid action: {policy['action']!r}")
        if policy["format"] not in _FORMATS:
            raise ValueError(f"invalid format: {policy['format']!r}")
        if policy["route"] not in _ROUTES:
            raise ValueError(f"invalid route: {policy['route']!r}")
        if policy.get("pseudonymize_mode", "A") not in _MODES:
            raise ValueError(f"invalid pseudonymize_mode: {policy.get('pseudonymize_mode')!r}")

    def add_policy(
        self,
        *,
        data_class: str,
        format: str,
        route: str,
        action: str,
        pseudonymize_mode: str = "A",
        small_set_escalation: bool = True,
        description: str = "",
    ) -> dict:
        """Add a policy row with a fresh id (write-through).  Returns the row."""
        try:
            new_id = str(self._redis.incr(_KEY_SEQ))
        except Exception as exc:
            # Fail-closed: never silently mint a colliding id from a stale cache.
            raise RuntimeError(f"DocumentPolicyStore: id allocation failed: {exc}") from exc
        policy = {
            "id": new_id,
            "data_class": data_class,
            "format": format,
            "route": route,
            "action": action,
            "pseudonymize_mode": pseudonymize_mode,
            "small_set_escalation": bool(small_set_escalation),
            "description": description,
        }
        self._validate(policy)
        self._policies[new_id] = policy
        self._redis.set(_KEY_POLICY.format(new_id), json.dumps(policy))
        return policy

    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy.  Returns True if it existed, False otherwise."""
        existed = self._policies.pop(policy_id, None) is not None
        if existed:
            self._redis.delete(_KEY_POLICY.format(policy_id))
        return existed

    def list_policies(self) -> list[dict]:
        """Snapshot of all policies, sorted by numeric id where possible."""
        def _key(p: dict):
            try:
                return (0, int(p["id"]))
            except (ValueError, TypeError):
                return (1, p["id"])
        return sorted(self._policies.values(), key=_key)

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def get_config(self) -> dict:
        return dict(self._config)

    def set_config(self, **overrides) -> dict:
        """Update config (write-through).  Unknown keys are ignored."""
        for k in ("detokenize_role", "map_ttl_seconds", "small_set_threshold"):
            if k in overrides and overrides[k] is not None:
                self._config[k] = overrides[k]
        self._redis.set(_KEY_CONFIG, json.dumps(self._config))
        return dict(self._config)

    # ------------------------------------------------------------------
    # OPA serialisation
    # ------------------------------------------------------------------

    def to_opa_document(self) -> dict:
        """Build the document OPA expects at ``data.yashigani.document``.

        Shape consumed by policy/document.rego:
            {
                "policies": [ { data_class, format, route, action,
                                pseudonymize_mode, small_set_escalation }, ... ],
                "config": { detokenize_role, map_ttl_seconds, small_set_threshold }
            }
        """
        return {
            "policies": [
                {
                    "data_class": p["data_class"],
                    "format": p["format"],
                    "route": p["route"],
                    "action": p["action"],
                    "pseudonymize_mode": p.get("pseudonymize_mode", "A"),
                    "small_set_escalation": bool(p.get("small_set_escalation", True)),
                }
                for p in self.list_policies()
            ],
            "config": dict(self._config),
        }
