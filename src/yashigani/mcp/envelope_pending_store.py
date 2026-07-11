"""
MCP capability-envelope PENDING re-approval store — Redis db/3 (3.0).

Closes the operator-facing gap in the capability-envelope pin (YSG-RISK-060):
when a tool-surface refresh is BLOCKED (capability-expanding or sidecar-
uncertain), the broker latches the active envelope to ``blocked`` — but the
CANDIDATE (refreshed) surface that triggered the block is not, on its own,
persisted anywhere the operator can SEE it.  The blocked DB row still carries
the *old* approved envelope's typed dimensions, so without this store the
backoffice could show a diff *vs original* but could not mint the candidate on
approve (it would have nothing to mint).

This store persists the pending candidate envelope (the absolute new surface the
operator is being asked to approve) keyed by ``provenance_id``, so the
re-approval SPA can:

  1. LIST every imported MCP whose refresh is currently blocked + awaiting an
     operator decision (the pending queue).
  2. Show the field-level diff of the candidate vs the ORIGINAL approved
     envelope (the anti-rug-pull framing — never just vs prior).
  3. On step-up approve, hand the candidate to ``reapprove_envelope`` which
     mints the new chained baseline and clears the latched block.
  4. On reject/keep-blocked, drop the pending entry (the block stays latched).

Design discipline (mirrors documents/policy_store.py):
  * Redis db/3, key namespace ``mcp_envelope_pending:`` (disjoint from
    ``document:`` / ``rbac:`` / the agent registry).
  * Write-through: the in-memory cache is the source for reads; Redis is the
    durable mirror replayed on construction (a restart never loses the queue).
  * The candidate is serialised with the SAME serialise/deserialise functions
    the durable envelope table uses (``envelope_service.serialise_envelope`` /
    ``deserialise_envelope``), so a pending candidate round-trips into a real
    ``ServerEnvelope`` for the diff + the mint.

SECURITY:
  * The stored candidate is HOSTILE input — tool names / descriptions come from
    an untrusted upstream MCP.  Nothing here renders it; the backoffice JS
    escapes every field at the DOM sink (CWE-79).  This module only stores +
    returns JSON strings.
  * No secret, no envelope handle, no map material is stored here — only the
    public, typed capability dimensions + the triage metadata the operator
    needs to decide.
  * Tenant-scoped: every entry carries its ``tenant_id`` so a multi-tenant
    deployment lists only its own pending re-approvals (BOLA close, mirrors the
    envelope table's tenant scoping).

Redis key schema (db/3):
    mcp_envelope_pending:{provenance_id}   — JSON pending-candidate row

Last updated: 2026-06-10T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

from yashigani.mcp._envelope import ServerEnvelope
from yashigani.mcp.envelope_service import (
    deserialise_envelope,
    serialise_envelope,
)

logger = logging.getLogger("yashigani.mcp.envelope.pending")

_KEY = "mcp_envelope_pending:{}"   # .format(provenance_id)
_SCAN_MATCH = "mcp_envelope_pending:*"

# Triage classes that produce a pending re-approval (mirror _envelope_triage).
_BLOCK_CLASSES = frozenset({"expanding", "uncertain"})


def _now() -> float:
    return time.time()


class EnvelopePendingStore:
    """Redis-backed store of pending (blocked) capability-envelope re-approvals.

    Constructed in the backoffice lifespan with the shared Redis db/3 client
    (same instance as the RBAC / document stores, disjoint key namespace).  The
    broker writes a pending entry on every block; the backoffice reads the queue
    and drops an entry on approve/reject.
    """

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client
        self._pending: dict[str, dict] = {}
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
                        row = json.loads(raw)
                        self._pending[row["provenance_id"]] = row
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.error("EnvelopePendingStore: bad row %s: %s", key, exc)
                if cursor == 0:
                    break
        except Exception as exc:
            logger.error("EnvelopePendingStore: load from Redis failed: %s", exc)

    # ------------------------------------------------------------------
    # Write (broker block path)
    # ------------------------------------------------------------------

    def record_block(
        self,
        *,
        provenance_id: str,
        tenant_id: str,
        server_id: str,
        candidate: ServerEnvelope,
        triage_class: str,
        new_surface_hash: str,
        findings: Optional[list] = None,
    ) -> dict:
        """Persist a pending re-approval for a just-blocked tool-surface refresh.

        ``candidate`` is the absolute refreshed surface (what the operator is
        asked to approve).  ``triage_class`` is 'expanding' | 'uncertain'.
        ``findings`` is the list of DiffFinding-shaped dicts (dimension /
        tool_key / detail) for the audit + a fast pre-render; the authoritative
        diff is recomputed server-side vs the ORIGINAL baseline at view time.

        Idempotent on provenance_id: a re-block overwrites the prior pending
        candidate (the latest refresh is the one to decide on).  Returns the
        stored row (sans any internal-only fields)."""
        if triage_class not in _BLOCK_CLASSES:
            raise ValueError(f"triage_class must be a block class, got {triage_class!r}")
        payload = serialise_envelope(candidate)
        row = {
            "provenance_id": provenance_id,
            "tenant_id": tenant_id,
            "server_id": server_id,
            "triage_class": triage_class,
            "new_surface_hash": new_surface_hash,
            "blocked_at": _now(),
            # The candidate, serialised exactly as the durable table stores an
            # envelope — round-trips back into a ServerEnvelope for diff + mint.
            "candidate": {
                "provenance_id": candidate.provenance_id,
                "tenant_id": candidate.tenant_id,
                "effect_classes": payload["effect_classes"],
                "arg_shape_signatures": payload["arg_shape_signatures"],
                "data_scope": payload["data_scope"],
                "egress_posture": payload["egress_posture"],
                "surface_set_hash": payload["surface_set_hash"],
                "tool_set": payload["tool_set"],
            },
            # Findings are advisory pre-render only; never authoritative.
            "findings": list(findings or []),
        }
        self._pending[provenance_id] = row
        try:
            self._redis.set(_KEY.format(provenance_id), json.dumps(row))
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("EnvelopePendingStore: persist failed for %s: %s",
                         provenance_id, exc)
        logger.warning(
            "EnvelopePendingStore: pending re-approval recorded provenance=%.12s "
            "tenant=%s class=%s tools=%d",
            provenance_id, tenant_id, triage_class, len(candidate.tools),
        )
        return row

    # ------------------------------------------------------------------
    # Cross-process coherency — Redis refresh
    # ------------------------------------------------------------------

    def _refresh_from_redis(self) -> None:
        """Reload the in-memory cache with a fresh Redis scan.

        Called at the start of every read method so that entries written by
        a sibling process (e.g. the gateway writing a drift-triggered block)
        are visible to this process (e.g. the backoffice listing the pending
        queue) without requiring a restart.  The scan is fast: the queue is
        expected to hold at most a handful of entries at any time.

        On Redis failure the existing in-memory cache is kept unchanged (the
        operator sees a potentially stale but non-empty queue rather than an
        empty one that looks like no-block).
        """
        fresh: dict[str, dict] = {}
        try:
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(cursor, match=_SCAN_MATCH, count=200)
                for key in keys:
                    raw = self._redis.get(key)
                    if raw is None:
                        continue
                    try:
                        row = json.loads(raw)
                        fresh[row["provenance_id"]] = row
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.error("EnvelopePendingStore: bad row on refresh %s: %s", key, exc)
                if cursor == 0:
                    break
            self._pending = fresh
        except Exception as exc:
            logger.error(
                "EnvelopePendingStore: refresh from Redis failed — using stale cache: %s", exc
            )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def list_for_tenant(self, tenant_id: str) -> list[dict]:
        """All pending re-approvals for a tenant, newest-blocked first.

        Always reloads from Redis first (cross-process coherency: entries
        written by the gateway are visible here without a restart).
        Returns the metadata rows (no candidate body) for the queue list."""
        self._refresh_from_redis()
        rows = [
            self._summary(r)
            for r in self._pending.values()
            if r.get("tenant_id") == tenant_id
        ]
        rows.sort(key=lambda r: r.get("blocked_at", 0.0), reverse=True)
        return rows

    def get(self, provenance_id: str, tenant_id: str) -> Optional[dict]:
        """Return the full pending row (incl. candidate) IFF it belongs to the
        tenant.  Cross-tenant lookups fail closed (None) — BOLA close.

        Reloads from Redis first for cross-process coherency."""
        self._refresh_from_redis()
        row = self._pending.get(provenance_id)
        if row is None or row.get("tenant_id") != tenant_id:
            return None
        return row

    def get_candidate_envelope(
        self, provenance_id: str, tenant_id: str
    ) -> Optional[ServerEnvelope]:
        """Rehydrate the pending candidate into a ServerEnvelope (tenant-scoped)."""
        row = self.get(provenance_id, tenant_id)
        if row is None:
            return None
        c = row["candidate"]
        return deserialise_envelope(
            provenance_id=c["provenance_id"],
            tenant_id=c["tenant_id"],
            effect_classes=c["effect_classes"],
            arg_shape_signatures=c["arg_shape_signatures"],
            data_scope=c["data_scope"],
            egress_posture=c["egress_posture"],
            surface_set_hash=c["surface_set_hash"],
        )

    # ------------------------------------------------------------------
    # Resolve (approve / reject drops the pending entry)
    # ------------------------------------------------------------------

    def resolve(self, provenance_id: str, tenant_id: str) -> bool:
        """Drop a pending entry after an operator decision (approve or reject).

        Tenant-scoped: a cross-tenant resolve is a no-op (False).  On approve the
        new baseline is minted by the service; on reject the block stays latched
        in the DB — either way the *pending* entry is consumed."""
        row = self._pending.get(provenance_id)
        if row is None or row.get("tenant_id") != tenant_id:
            return False
        self._pending.pop(provenance_id, None)
        try:
            self._redis.delete(_KEY.format(provenance_id))
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("EnvelopePendingStore: delete failed for %s: %s",
                         provenance_id, exc)
        return True

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _summary(row: dict) -> dict:
        """Queue-list metadata row (no candidate body)."""
        cand = row.get("candidate", {})
        return {
            "provenance_id": row["provenance_id"],
            "tenant_id": row.get("tenant_id", ""),
            "server_id": row.get("server_id", ""),
            "triage_class": row.get("triage_class", ""),
            "new_surface_hash": row.get("new_surface_hash", ""),
            "blocked_at": row.get("blocked_at", 0.0),
            "candidate_tool_count": len(cand.get("tool_set", [])),
            "candidate_egress_posture": cand.get("egress_posture", "NONE"),
            "finding_count": len(row.get("findings", [])),
        }
