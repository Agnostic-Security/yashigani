"""
MCP capability-envelope service — append-only durable approval store.

Owns the ``mcp_tool_surface_pins`` rows (migration 0019).  Mirrors the
append-only / least-priv discipline of ``manifest_registry/service.py``:

  * mint_envelope() / reapprove()   → INSERT a new (chained) envelope version.
  * record_benign_repin()           → in-place UPDATE of current_surface_hash
                                       on the ACTIVE row (a byte-hash re-pin
                                       under the UNCHANGED envelope — Iris §2.2).
  * latch_block() / clear_block()   → status transitions (latch persists until
                                       a step-up re-approval — Laura §3 bypass B).
  * get_active_envelope()           → the single 'active' envelope for a
                                       provenance_id (the invocation-gate lookup).

The ENVELOPE itself is immutable until a step-up re-approval mints a new
version.  Auto-allow never mutates the typed dimensions; it only advances the
byte-hash change-detector.  DELETE is revoked at the DB level — no row is ever
purged, so the approval history is tamper-evident (Iris §2.3).

The pool is injected at construction (testable with a mock pool), exactly like
ManifestRegistryService.

Last updated: 2026-06-10T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from yashigani.mcp._envelope import (
    ArgShape,
    EffectClass,
    ServerEnvelope,
    ToolEnvelope,
)

_log = logging.getLogger("yashigani.mcp.envelope")


# Envelope lifecycle states (mirror the DB CHECK constraint).
STATUS_ACTIVE = "active"
STATUS_BLOCKED = "blocked"
STATUS_SUPERSEDED = "superseded"

TOPOLOGY_RING_FENCED = "ring_fenced"
TOPOLOGY_EXTERNAL_RELAY = "external_relay"


@dataclass
class EnvelopeRecord:
    """A single mcp_tool_surface_pins row, hydrated into a ServerEnvelope."""
    id: int
    provenance_id: str
    tenant_id: str
    server_id: str
    envelope_version: int
    previous_envelope_id: Optional[int]
    status: str
    egress_posture: str
    surface_set_hash: str
    current_surface_hash: str
    topology: str
    approved_by_operator_identity: str
    approved_at: datetime
    envelope: ServerEnvelope


# ---------------------------------------------------------------------------
# (De)serialisation between ServerEnvelope and JSONB columns
# ---------------------------------------------------------------------------

def _arg_shape_to_json(shape: ArgShape) -> dict:
    return {
        "type_name": shape.type_name,
        "required": shape.required,
        "enum": list(shape.enum) if shape.enum is not None else None,
        "has_pattern": shape.has_pattern,
        "has_format": shape.has_format,
        "has_bounds": shape.has_bounds,
        "additional_properties": shape.additional_properties,
        "unknown_flags": list(shape.unknown_flags),
    }


def _arg_shape_from_json(d: dict) -> ArgShape:
    return ArgShape(
        type_name=d.get("type_name", ""),
        required=bool(d.get("required", False)),
        enum=tuple(d["enum"]) if d.get("enum") is not None else None,
        has_pattern=bool(d.get("has_pattern", False)),
        has_format=bool(d.get("has_format", False)),
        has_bounds=bool(d.get("has_bounds", False)),
        additional_properties=bool(d.get("additional_properties", False)),
        unknown_flags=tuple(d.get("unknown_flags", [])),
    )


def serialise_envelope(env: ServerEnvelope) -> dict:
    """ServerEnvelope -> the four JSONB column payloads + egress + hash."""
    tool_set = sorted(env.tools.keys())
    effect_classes: dict = {}
    arg_shapes: dict = {}
    data_scope: dict = {}
    extras: dict = {}  # annotation_flags / output_open / unknown_dims per tool
    for tk, t in env.tools.items():
        effect_classes[tk] = sorted(e.value for e in t.effect_classes)
        arg_shapes[tk] = {name: _arg_shape_to_json(s) for name, s in t.arg_shapes.items()}
        data_scope[tk] = sorted(t.data_scopes)
        extras[tk] = {
            "annotation_flags": list(t.annotation_flags),
            "output_open": t.output_open,
            "unknown_dims": list(t.unknown_dims),
        }
    return {
        "tool_set": tool_set,
        "effect_classes": effect_classes,
        # arg_shape_signatures carries the per-tool shapes AND the extras so the
        # full ToolEnvelope round-trips from one JSONB column.
        "arg_shape_signatures": {"shapes": arg_shapes, "extras": extras},
        "data_scope": data_scope,
        "egress_posture": env.egress_posture,
        "surface_set_hash": env.surface_set_hash,
    }


def deserialise_envelope(
    provenance_id: str,
    tenant_id: str,
    effect_classes: dict,
    arg_shape_signatures: dict,
    data_scope: dict,
    egress_posture: str,
    surface_set_hash: str,
) -> ServerEnvelope:
    """Rehydrate a ServerEnvelope from the JSONB columns."""
    shapes = arg_shape_signatures.get("shapes", {})
    extras = arg_shape_signatures.get("extras", {})
    tools: dict = {}
    for tk in set(effect_classes) | set(shapes) | set(data_scope):
        tool_extras = extras.get(tk, {})
        tools[tk] = ToolEnvelope(
            tool_key=tk,
            effect_classes=frozenset(
                EffectClass(v) for v in effect_classes.get(tk, [])
            ),
            arg_shapes={
                name: _arg_shape_from_json(d)
                for name, d in shapes.get(tk, {}).items()
            },
            data_scopes=frozenset(data_scope.get(tk, [])),
            annotation_flags=tuple(tool_extras.get("annotation_flags", [])),
            output_open=bool(tool_extras.get("output_open", False)),
            unknown_dims=tuple(tool_extras.get("unknown_dims", [])),
        )
    return ServerEnvelope(
        provenance_id=provenance_id,
        tenant_id=tenant_id,
        tools=tools,
        egress_posture=egress_posture,
        surface_set_hash=surface_set_hash,
    )


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class CapabilityEnvelopeService:
    """
    Append-only durable store for imported-MCP capability envelopes.

    INSERT mints a new version; UPDATE only advances the byte-hash or flips
    status (append-only ENVELOPE — the typed dimensions never change in place).
    DELETE is revoked at the DB level (migration 0019).
    """

    def __init__(self, pool: Any) -> None:
        if pool is None:
            raise RuntimeError(
                "CapabilityEnvelopeService requires a non-None asyncpg pool. "
                "Ensure create_pool() has been called before constructing this service."
            )
        self._pool = pool

    # ------------------------------------------------------------------
    # Mint (import ceremony) + re-approval
    # ------------------------------------------------------------------

    async def mint_envelope(
        self,
        env: ServerEnvelope,
        *,
        server_id: str,
        operator_identity: str,
        topology: str = TOPOLOGY_RING_FENCED,
        sidecar_scan_verdict: Optional[dict] = None,
    ) -> int:
        """
        Mint the FIRST envelope (version 1) at the import ceremony, OR a new
        chained version on re-approval.  Supersedes any existing active row for
        the provenance_id in the same transaction (the single-active invariant).

        Returns the new row id.
        """
        if topology not in (TOPOLOGY_RING_FENCED, TOPOLOGY_EXTERNAL_RELAY):
            raise ValueError(f"invalid topology: {topology!r}")
        if not operator_identity:
            raise ValueError("operator_identity is required to mint an envelope")

        payload = serialise_envelope(env)
        verdict_json = (
            json.dumps(sidecar_scan_verdict, sort_keys=True)
            if sidecar_scan_verdict is not None else None
        )

        async with self._pool.acquire() as conn:
            async with conn.transaction():
                prev = await conn.fetchrow(
                    """
                    SELECT id, envelope_version
                    FROM   mcp_tool_surface_pins
                    WHERE  provenance_id = $1 AND status = 'active'
                    FOR UPDATE
                    """,
                    env.provenance_id,
                )
                prev_id: Optional[int] = prev["id"] if prev else None
                next_version = (prev["envelope_version"] + 1) if prev else 1

                if prev is not None:
                    # Supersede the prior active envelope (re-approval path).
                    await conn.execute(
                        """
                        UPDATE mcp_tool_surface_pins
                        SET    status = 'superseded'
                        WHERE  id = $1
                        """,
                        prev_id,
                    )

                row = await conn.fetchrow(
                    """
                    INSERT INTO mcp_tool_surface_pins (
                        provenance_id, tenant_id, server_id,
                        envelope_version, previous_envelope_id, status,
                        tool_set, effect_classes, arg_shape_signatures,
                        data_scope, egress_posture, surface_set_hash,
                        current_surface_hash, topology, sidecar_scan_verdict,
                        approved_by_operator_identity
                    ) VALUES (
                        $1, $2, $3, $4, $5, 'active',
                        $6::jsonb, $7::jsonb, $8::jsonb,
                        $9::jsonb, $10, $11,
                        $12, $13, $14::jsonb, $15
                    )
                    RETURNING id
                    """,
                    env.provenance_id,
                    env.tenant_id,
                    server_id,
                    next_version,
                    prev_id,
                    json.dumps(payload["tool_set"]),
                    json.dumps(payload["effect_classes"]),
                    json.dumps(payload["arg_shape_signatures"]),
                    json.dumps(payload["data_scope"]),
                    payload["egress_posture"],
                    payload["surface_set_hash"],
                    payload["surface_set_hash"],   # current == mint hash
                    topology,
                    verdict_json,
                    operator_identity,
                )
        new_id: int = row["id"]
        _log.info(
            "CapabilityEnvelope: minted v%d provenance=%.12s tenant=%s id=%d prev=%s topo=%s",
            next_version, env.provenance_id, env.tenant_id, new_id,
            str(prev_id), topology,
        )
        return new_id

    # ------------------------------------------------------------------
    # Benign auto-allow — advance the byte-hash under the UNCHANGED envelope
    # ------------------------------------------------------------------

    async def record_benign_repin(
        self, provenance_id: str, new_surface_hash: str
    ) -> bool:
        """
        Advance ``current_surface_hash`` on the ACTIVE envelope (a byte-hash
        re-pin under the unchanged typed dimensions — Iris §2.2).  Does NOT
        touch tool_set/effect_classes/arg_shapes/data_scope — the envelope is
        immutable.  Returns True if an active row was updated.
        """
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE mcp_tool_surface_pins
                SET    current_surface_hash = $2
                WHERE  provenance_id = $1 AND status = 'active'
                """,
                provenance_id,
                new_surface_hash,
            )
        # asyncpg returns e.g. "UPDATE 1"
        updated = result.endswith(" 1")
        if updated:
            _log.info(
                "CapabilityEnvelope: benign auto-allow re-pin provenance=%.12s hash=%.12s",
                provenance_id, new_surface_hash,
            )
        return updated

    # ------------------------------------------------------------------
    # Latch / clear a block (Laura §3 bypass B — reversion does NOT un-latch)
    # ------------------------------------------------------------------

    async def latch_block(self, provenance_id: str) -> bool:
        """
        Latch a block on the provenance: transition the ACTIVE envelope to
        'blocked'.  The block PERSISTS until a step-up re-approval (mint_envelope)
        clears it by minting a new active version — a surface reversion does NOT
        auto-clear it (closes the oscillation/flap bypass).

        Returns True if an active row was latched.  Idempotent: if already
        blocked, returns False (no active row to transition).
        """
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE mcp_tool_surface_pins
                SET    status = 'blocked'
                WHERE  provenance_id = $1 AND status = 'active'
                """,
                provenance_id,
            )
        latched = result.endswith(" 1")
        if latched:
            _log.warning(
                "CapabilityEnvelope: BLOCK LATCHED on provenance=%.12s "
                "(capability expansion or sidecar-uncertain; reversion will NOT clear)",
                provenance_id,
            )
        return latched

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get_active_envelope(
        self, provenance_id: str
    ) -> Optional[EnvelopeRecord]:
        """
        Return the single ACTIVE envelope for a provenance_id, or None.

        This is the invocation-gate lookup.  None ⇒ unpinned/blocked ⇒ the
        broker's hard gate fails closed (no active envelope = no approval).
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT * FROM mcp_tool_surface_pins
                WHERE  provenance_id = $1 AND status = 'active'
                """,
                provenance_id,
            )
        if row is None:
            return None
        return self._row_to_record(row)

    async def get_baseline_envelope(
        self, provenance_id: str
    ) -> Optional[EnvelopeRecord]:
        """
        Return the ORIGINAL (version 1) approved envelope for a provenance_id.

        Laura must-have #1 / Δ1: drift is measured against the ORIGINAL
        baseline, never the last auto-allowed state.  The triage diffs the
        refreshed surface against THIS, not against get_active_envelope() (the
        active row's typed dimensions equal v1's until a re-approval mints a new
        baseline — so get_active is correct for the *active* ceiling, but
        get_baseline is the explicit original-anchor for the drift report).
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT * FROM mcp_tool_surface_pins
                WHERE  provenance_id = $1 AND envelope_version = 1
                ORDER  BY id ASC
                LIMIT  1
                """,
                provenance_id,
            )
        if row is None:
            return None
        return self._row_to_record(row)

    async def history(
        self, tenant_id: str, limit: int = 50, offset: int = 0
    ) -> list[EnvelopeRecord]:
        """List envelope versions for a tenant, newest first (append-only ledger)."""
        limit = max(1, min(limit, 200))
        offset = max(0, offset)
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM mcp_tool_surface_pins
                WHERE  tenant_id = $1
                ORDER  BY approved_at DESC, id DESC
                LIMIT  $2 OFFSET $3
                """,
                tenant_id, limit, offset,
            )
        return [self._row_to_record(r) for r in rows]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _row_to_record(self, row: Any) -> EnvelopeRecord:
        effect_classes = _as_dict(row["effect_classes"])
        arg_shape_signatures = _as_dict(row["arg_shape_signatures"])
        data_scope = _as_dict(row["data_scope"])
        env = deserialise_envelope(
            provenance_id=row["provenance_id"],
            tenant_id=row["tenant_id"],
            effect_classes=effect_classes,
            arg_shape_signatures=arg_shape_signatures,
            data_scope=data_scope,
            egress_posture=row["egress_posture"],
            surface_set_hash=row["surface_set_hash"],
        )
        return EnvelopeRecord(
            id=row["id"],
            provenance_id=row["provenance_id"],
            tenant_id=row["tenant_id"],
            server_id=row["server_id"],
            envelope_version=row["envelope_version"],
            previous_envelope_id=row["previous_envelope_id"],
            status=row["status"],
            egress_posture=row["egress_posture"],
            surface_set_hash=row["surface_set_hash"],
            current_surface_hash=row["current_surface_hash"],
            topology=row["topology"],
            approved_by_operator_identity=row["approved_by_operator_identity"],
            approved_at=row["approved_at"],
            envelope=env,
        )


def _as_dict(value: Any) -> dict:
    """asyncpg returns JSONB as dict; TEXT-cast JSONB returns str."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return {}
    return value or {}
