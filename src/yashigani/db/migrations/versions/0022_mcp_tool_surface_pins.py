"""3.0 — YSG-RISK-060: imported-MCP capability-envelope tool-surface pins.

Revision ID: 0022
Revises: 0021
Create Date: 2026-06-10

Rationale (Iris `capability-envelope-pin-architecture-20260610.md` §2.3 +
Laura `laura-30-...-v2-20260610.md` R3-1/§8):

    The durable approval artefact for an imported MCP is a *capability
    envelope* (the tool set, each tool's argument-schema SHAPE, its effect
    class read/write/exec/network, its data scope, and the server egress
    posture) — NOT the bytes.  At import the operator approves an envelope
    which is stored append-only, bound to the P8 provenance pin
    (provenance_id = H(server_id ‖ pin-material)).  On every tool-surface
    refresh the broker projects the new surface to the envelope dimensions
    and diffs it against the APPROVED envelope (Laura must-have #1: diff is
    always vs the ORIGINAL baseline, never the last auto-allowed state).

    The byte-surface-hash is retained as a change-DETECTOR (re-pinned on
    every benign auto-allow), demoted from verdict to trigger.

    Compliance mapping (mirrors manifest_registrations / migration 0012):
      NIST 800-53 AU-2/AU-3/AU-12  — append-only ledger of every approval
      NIST 800-53 AC-6(9)          — privileged function logging (re-approve)
      CMMC AU.L2-3.3.1/3.3.2       — traceable, retained audit records
      SOC 2 CC6.2 / CC8.1          — change management: approvals documented
      ISO 42001 A.6.1.2 / A.6.2.6  — AI-system inventory + monitoring

Changes:

  1. CREATE TABLE mcp_tool_surface_pins — append-only envelope ledger.
     Each row is one envelope VERSION for a (provenance_id, tenant_id).
     A benign auto-allow does NOT insert a row (it only re-pins the
     byte-hash, recorded in current_surface_hash on the latest row's
     materialisation via the service layer's separate hash log — the
     ENVELOPE itself is immutable until a step-up re-approval mints a new
     version).  A capability-expanding re-approval INSERTs a new chained
     row (previous_envelope_id), so the approval history is tamper-evident.

     Columns:
       id                       BIGSERIAL PRIMARY KEY
       provenance_id            TEXT NOT NULL  — H(server_id ‖ pin-material);
                                                 binds the envelope to the P8
                                                 transport identity (closes A3).
       tenant_id                TEXT NOT NULL
       server_id                TEXT NOT NULL  — upstream MCP server id (audit).
       envelope_version         INT  NOT NULL  — 1 at import; bumped per
                                                 re-approval.
       previous_envelope_id     BIGINT         — chains to the prior version;
                                                 NULL on v1 (import).
       status                   TEXT NOT NULL  — 'active' | 'blocked' |
                                                 'superseded'.  Exactly one
                                                 'active' per provenance_id at a
                                                 time (enforced in service).
       tool_set                 JSONB NOT NULL — sorted list of
                                                 provenance_id::tool_name keys.
       effect_classes           JSONB NOT NULL — tool_key -> [READ,WRITE,...].
       arg_shape_signatures     JSONB NOT NULL — tool_key -> shape signatures.
       data_scope               JSONB NOT NULL — tool_key -> [scope strings].
       egress_posture           TEXT NOT NULL  — NONE | INTERNAL | OUTBOUND.
       surface_set_hash         TEXT NOT NULL  — byte-hash change-detector
                                                 (re-pinned on benign auto-allow
                                                 via current_surface_hash).
       current_surface_hash     TEXT NOT NULL  — the LATEST materialised
                                                 byte-hash under this envelope
                                                 (== surface_set_hash at mint,
                                                 advanced by benign auto-allow).
       topology                 TEXT NOT NULL  — 'ring_fenced' | 'external_relay'
                                                 (Laura Δ4 — external relay forces
                                                 conservative tiering).
       sidecar_scan_verdict     JSONB          — day-one-poison pre-approval scan.
       approved_by_operator_identity TEXT NOT NULL
       approved_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()

  2. Indexes:
       idx_mcp_pins_active   — (provenance_id) WHERE status='active'  (unique
                               partial: at most one active envelope per
                               provenance_id).
       idx_mcp_pins_tenant   — (tenant_id, approved_at DESC).

  3. Least-priv (YSG-RISK-059 / mirrors 0012):
       GRANT  SELECT, INSERT, UPDATE ON mcp_tool_surface_pins TO yashigani_app
       REVOKE DELETE                  ON mcp_tool_surface_pins FROM yashigani_app
     NOTE — UNLIKE manifest_registrations, this table needs UPDATE because:
       (a) benign auto-allow advances current_surface_hash on the active row
           (an in-place hash re-pin, NOT an envelope mutation), and
       (b) a re-approval/block transitions the prior 'active' row to
           'superseded'/'blocked'.
     DELETE is revoked — no row is ever purged (append-only history).
     The DDL itself runs as the install-admin role (the migration runner),
     not yashigani_app.

Downgrade: drops the table (CASCADE removes indexes).

Evidence artefact: reference this migration SHA in the 3.0 compliance pack
for YSG-RISK-060 closure.
"""
# Last updated: 2026-06-10T00:00:00+00:00
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0022"
down_revision: Union[str, None] = "0021"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_DDL_UP = """
-- ================================================================
-- YSG-RISK-060: imported-MCP capability-envelope tool-surface pins
-- ================================================================

CREATE TABLE mcp_tool_surface_pins (
    id                            BIGSERIAL PRIMARY KEY,
    provenance_id                 TEXT NOT NULL,
    tenant_id                     TEXT NOT NULL,
    server_id                     TEXT NOT NULL,
    envelope_version              INT  NOT NULL,
    previous_envelope_id          BIGINT,
    status                        TEXT NOT NULL DEFAULT 'active',
    tool_set                      JSONB NOT NULL,
    effect_classes                JSONB NOT NULL,
    arg_shape_signatures          JSONB NOT NULL,
    data_scope                    JSONB NOT NULL,
    egress_posture                TEXT NOT NULL DEFAULT 'NONE',
    surface_set_hash              TEXT NOT NULL,
    current_surface_hash          TEXT NOT NULL,
    topology                      TEXT NOT NULL DEFAULT 'ring_fenced',
    sidecar_scan_verdict          JSONB,
    approved_by_operator_identity TEXT NOT NULL,
    approved_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT mcp_pins_status_chk
        CHECK (status IN ('active', 'blocked', 'superseded')),
    CONSTRAINT mcp_pins_topology_chk
        CHECK (topology IN ('ring_fenced', 'external_relay')),
    CONSTRAINT mcp_pins_egress_chk
        CHECK (egress_posture IN ('NONE', 'INTERNAL', 'OUTBOUND'))
);

-- ================================================================
-- Indexes
-- ================================================================

-- At most ONE active envelope per provenance_id (the load-bearing invariant:
-- the invocation gate resolves a single active envelope).
CREATE UNIQUE INDEX idx_mcp_pins_active
    ON mcp_tool_surface_pins (provenance_id)
    WHERE status = 'active';

-- Tenant history queries, newest first.
CREATE INDEX idx_mcp_pins_tenant
    ON mcp_tool_surface_pins (tenant_id, approved_at DESC);

-- Chain navigation.
CREATE INDEX idx_mcp_pins_prov_version
    ON mcp_tool_surface_pins (provenance_id, envelope_version DESC);

-- ================================================================
-- Least-priv (YSG-RISK-059) — append-only history, no purge.
-- ================================================================
-- SELECT/INSERT for read + mint.  UPDATE is required ONLY to (a) advance
-- current_surface_hash on a benign auto-allow (a hash re-pin, not an envelope
-- mutation) and (b) transition status active->superseded/blocked on
-- re-approval.  DELETE is revoked: no envelope row is ever purged.
GRANT  SELECT, INSERT, UPDATE ON mcp_tool_surface_pins TO yashigani_app;
REVOKE DELETE                  ON mcp_tool_surface_pins FROM yashigani_app;

GRANT USAGE ON SEQUENCE mcp_tool_surface_pins_id_seq TO yashigani_app;
"""

_DDL_DOWN = """
DROP TABLE IF EXISTS mcp_tool_surface_pins CASCADE;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
