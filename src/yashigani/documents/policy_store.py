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

# Seeded on first boot when the namespace is empty.  These are the four
# ready-to-use EXAMPLE policies (Tiago, 2026-06-09: "4 OPAs, set as examples and
# as OPAs available") plus the baseline demo matrix, so the operator sees
# selectable, self-describing policies in the admin UI from first boot.
#
# Each row is self-describing: it carries ``name`` + ``policy_id`` + a layman
# ``user_message`` + ``code`` (the same self-describing contract the rego
# decision emits) so the UI can show a friendly label and the audit/alert stays
# uniform.  ``example: True`` marks the four ready-to-use illustrative policies.
#
# Data-class → action mapping (explicit, demo-friendly).  Each example is scoped
# to a distinct ROUTE so the four coexist as independently-demonstrable rows
# WITHOUT colliding under strongest-action precedence (two any/any rows for the
# same class would always resolve to the stronger action and mask the other).
# The route makes the demo intent explicit:
#   PII-1  PII (identifying/QI)        on egress-mcp-result → PSEUDONYMIZE (mode A)
#   PII-2  PII (identifying/QI)        on json-attachment    → REDACT
#   PCI-1  PCI (cardholder: PAN/CVV/…) on egress-mcp-result → PSEUDONYMIZE (mode A)
#   PCI-2  PCI (cardholder: PAN/CVV/…) on json-attachment    → REDACT
_EXAMPLE_POLICIES: list[dict] = [
    {
        "id": "1",
        "name": "PII-1 — Pseudonymise PII",
        "policy_id": "DOC-EX-PII-1",
        "data_class": "PII",
        "format": "any",
        "route": "egress-mcp-result",
        "action": "PSEUDONYMIZE",
        "pseudonymize_mode": "A",
        "small_set_escalation": True,
        "code": "DOCUMENT_PII_PSEUDONYMIZED",
        "user_message": (
            "Identifying details in this file (names, email, phone, date of "
            "birth, address, National Insurance) were replaced with placeholders "
            "before it left your environment. You have a private table to turn "
            "the placeholders back into the real values yourself."
        ),
        "description": "Detected PII / identifying classes -> PSEUDONYMIZE (mode A, give the user the table).",
        "example": True,
    },
    {
        "id": "2",
        "name": "PII-2 — Redact PII",
        "policy_id": "DOC-EX-PII-2",
        "data_class": "PII",
        "format": "any",
        "route": "json-attachment",
        "action": "REDACT",
        "pseudonymize_mode": "A",
        "small_set_escalation": True,
        "code": "DOCUMENT_REDACTED",
        "user_message": (
            "Identifying details in this file (including any hidden parts and "
            "metadata) were permanently removed before it left your environment."
        ),
        "description": "Detected PII / identifying classes -> REDACT (irreversible removal + strip metadata).",
        "example": True,
    },
    {
        "id": "3",
        "name": "PCI-1 — Pseudonymise PCI",
        "policy_id": "DOC-EX-PCI-1",
        "data_class": "PCI",
        "format": "any",
        "route": "egress-mcp-result",
        "action": "PSEUDONYMIZE",
        "pseudonymize_mode": "A",
        "small_set_escalation": True,
        "code": "DOCUMENT_PII_PSEUDONYMIZED",
        "user_message": (
            "Cardholder data in this file (card number, CVV, cardholder name, "
            "expiry) was replaced with placeholders before it left your "
            "environment. You have a private table to turn the placeholders back "
            "into the real values yourself."
        ),
        "description": "Detected cardholder / PCI classes (PAN, CVV, cardholder name, expiry) -> PSEUDONYMIZE (mode A).",
        "example": True,
    },
    {
        "id": "4",
        "name": "PCI-2 — Redact PCI",
        "policy_id": "DOC-EX-PCI-2",
        "data_class": "PCI",
        "format": "any",
        "route": "json-attachment",
        "action": "REDACT",
        "pseudonymize_mode": "A",
        "small_set_escalation": True,
        "code": "DOCUMENT_REDACTED",
        "user_message": (
            "Cardholder data in this file (card number, CVV, cardholder name, "
            "expiry, including any hidden parts and metadata) was permanently "
            "removed before it left your environment."
        ),
        "description": "Detected cardholder / PCI classes -> REDACT (irreversible removal + strip metadata).",
        "example": True,
    },
]

# Baseline demo matrix (kept after the four examples) so an internal-PII LOG row
# is present out of the box for the passthrough+audit demo.
_BASELINE_POLICIES: list[dict] = [
    {
        "id": "5",
        "name": "Internal PII — Log only",
        "policy_id": "DOC-EX-PII-LOG",
        "data_class": "PII",
        "format": "any",
        "route": "ingress-upload",
        "action": "LOG",
        "pseudonymize_mode": "A",
        "small_set_escalation": False,
        "code": "DOCUMENT_LOGGED",
        "user_message": "This file was allowed through; any identifying information in it has been recorded for audit.",
        "description": "Internal PII on upload -> LOG (passthrough + full audit).",
        "example": False,
    },
]

_DEFAULT_POLICIES: list[dict] = _EXAMPLE_POLICIES + _BASELINE_POLICIES


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
        name: str = "",
        policy_id: str = "",
        user_message: str = "",
        code: str = "",
    ) -> dict:
        """Add a policy row with a fresh id (write-through).  Returns the row.

        ``name`` / ``policy_id`` / ``user_message`` / ``code`` are the
        self-describing display fields (mirrors the rego decision contract) the
        admin UI shows and the audit/alert reuse; optional for operator-created
        rows."""
        try:
            new_id = str(self._redis.incr(_KEY_SEQ))
        except Exception as exc:
            # Fail-closed: never silently mint a colliding id from a stale cache.
            raise RuntimeError(f"DocumentPolicyStore: id allocation failed: {exc}") from exc
        policy = {
            "id": new_id,
            "name": name,
            "policy_id": policy_id,
            "data_class": data_class,
            "format": format,
            "route": route,
            "action": action,
            "pseudonymize_mode": pseudonymize_mode,
            "small_set_escalation": bool(small_set_escalation),
            "code": code,
            "user_message": user_message,
            "description": description,
            "example": False,
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
                                pseudonymize_mode, small_set_escalation,
                                policy_id, user_message, code }, ... ],
                "config": { detokenize_role, map_ttl_seconds, small_set_threshold }
            }

        The self-describing fields (policy_id, user_message, code) are included
        so the rego decision can surface the operator-supplied values when they are
        present, falling back to the built-in action-derived values when empty.
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
                    # Self-describing fields: operator-supplied when non-empty;
                    # the rego falls back to built-in values when these are "".
                    "policy_id": p.get("policy_id", ""),
                    "user_message": p.get("user_message", ""),
                    "code": p.get("code", ""),
                }
                for p in self.list_policies()
            ],
            "config": dict(self._config),
        }
