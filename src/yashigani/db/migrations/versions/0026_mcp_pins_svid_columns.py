"""v4.1 Phase 1c — per-instance SVID identity columns on MCP envelope pins.

Revision ID: 0026
Revises: 0025
Create Date: 2026-07-06

Rationale (SYNTHESIS.md Issue-1 step 2/6 — "approve = transaction"):

    The MCP approve/import ceremony now runs an ATOMIC transaction:
    mint per-instance leaf (pki.issuer.mint_agent_leaf, Nico's contract
    spiffe://<td>/agents/<tenant>/<server>/<nhi_id>) → codegen the Caddy-front
    wrap (approve_mcp_onboard) → write artifacts → caddy reload → durable
    envelope INSERT.  The envelope row is the durable registry, so the
    per-instance identity issued for the server rides ON that row:

      svid_instance_id  TEXT     — the stable instance UUID segment
                                   (nhi_<12 hex>) keyed into the SPIFFE URI
                                   and the cert/key filenames (GAP-1).
      svid_spiffe_id    TEXT     — the full minted SPIFFE URI (audit + the
                                   /auth/verify-mcp corroboration surface).
      svid_issued       BOOLEAN  — TRUE only when a real leaf cert exists on
                                   disk at INSERT time.  The envelope INSERT
                                   is the LAST transaction step, after the
                                   mint — svid_issued=TRUE can never be
                                   recorded without a cert (the BUG-A
                                   fail-open pattern must not reappear).

    Rows minted by the legacy DB-row-only path (pre-Phase-1c, or
    external_relay topology where no wrap exists) carry the defaults
    ('' / '' / FALSE) — an honest "no per-instance leaf" record.

Least-priv: no grant changes — columns live on mcp_tool_surface_pins whose
SELECT/INSERT/UPDATE grants (migration 0022) already cover them.

Downgrade: drops the three columns.
"""
# Last updated: 2026-07-06T00:00:00+00:00
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0026"
down_revision: Union[str, None] = "0025"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_DDL_UP = """
-- ================================================================
-- v4.1 Phase 1c: per-instance SVID identity on MCP envelope pins
-- ================================================================

ALTER TABLE mcp_tool_surface_pins
    ADD COLUMN svid_instance_id TEXT    NOT NULL DEFAULT '',
    ADD COLUMN svid_spiffe_id   TEXT    NOT NULL DEFAULT '',
    ADD COLUMN svid_issued      BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN mcp_tool_surface_pins.svid_instance_id IS
    'v4.1 GAP-1 per-instance segment (nhi_<12hex>) of the minted MCP leaf; empty = no wrap provisioned';
COMMENT ON COLUMN mcp_tool_surface_pins.svid_spiffe_id IS
    'Full SPIFFE URI of the per-instance leaf minted at approve time';
COMMENT ON COLUMN mcp_tool_surface_pins.svid_issued IS
    'TRUE only when a real leaf cert existed on disk at envelope INSERT (fail-closed; BUG-A guard)';
"""

_DDL_DOWN = """
ALTER TABLE mcp_tool_surface_pins
    DROP COLUMN IF EXISTS svid_issued,
    DROP COLUMN IF EXISTS svid_spiffe_id,
    DROP COLUMN IF EXISTS svid_instance_id;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
