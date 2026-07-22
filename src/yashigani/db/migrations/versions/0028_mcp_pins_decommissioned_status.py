"""FINDING-V412-ONBOARDING-ROBUSTNESS #4 — add 'decommissioned' status to
mcp_tool_surface_pins.

Revision ID: 0028
Revises: 0027
Create Date: 2026-07-21

Rationale:

    No supported admin-API remove/decommission flow existed for a
    ring_fenced MCP agent (Ava, testing_runs/yashigani/wt-fix-svid/evidence/
    ava-onboarding-e2e-final.md §7): teardown left two envelope rows
    permanently 'active' with no way to deactivate them short of a
    hand-edited DB write (explicitly refused as unsafe during that session).

    The new decommission transaction (mcp_onboard.py
    run_decommission_transaction) needs a status distinct from the two
    existing terminal-ish states:

      'blocked'    — an in-place OPA/sidecar block; CLEARS on a step-up
                     re-approval (mint_envelope). The agent is still
                     onboarded, just gated.
      'superseded' — a NEWER envelope version replaced this row (mint_envelope
                     chains: old row -> superseded, new row -> active). This
                     agent is still onboarded, just on a later version.
      'decommissioned' (NEW) — the agent was explicitly torn down. No newer
                     version exists and none is expected; get_active_envelope()
                     returns None exactly as it already does for 'blocked'/
                     'superseded' (verify-mcp fails closed unchanged), but the
                     audit trail records the TRUE reason distinctly rather
                     than overloading 'superseded' to mean two different
                     things (GRC-honesty: an auditor reading 'superseded'
                     with no newer version present would reasonably ask
                     "superseded by what?").

    Append-only / no-DELETE discipline (envelope_service.py module
    docstring) is unchanged — this is a new value in an existing CHECK
    constraint + status transition, never a schema shape change or a row
    purge.

Least-priv: no grant changes — the CHECK constraint covers the same column
whose SELECT/INSERT/UPDATE grants (migration 0022) already apply.

Downgrade: reverts the CHECK constraint to the pre-0028 three values. Any
row already carrying 'decommissioned' would violate the constraint on
downgrade — guarded explicitly (fails loudly rather than silently
corrupting data) per CLAUDE.md fail-closed discipline.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0028"
down_revision: Union[str, None] = "0027"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_DDL_UP = """
ALTER TABLE mcp_tool_surface_pins
    DROP CONSTRAINT mcp_pins_status_chk;

ALTER TABLE mcp_tool_surface_pins
    ADD CONSTRAINT mcp_pins_status_chk
        CHECK (status IN ('active', 'blocked', 'superseded', 'decommissioned'));

COMMENT ON COLUMN mcp_tool_surface_pins.status IS
    'active | blocked | superseded | decommissioned (0028: explicit teardown, distinct from superseded)';
"""

_DDL_DOWN = """
DO $$
DECLARE
    _stray_count INTEGER;
BEGIN
    SELECT count(*) INTO _stray_count
    FROM mcp_tool_surface_pins
    WHERE status = 'decommissioned';

    IF _stray_count > 0 THEN
        RAISE EXCEPTION
            'cannot downgrade 0028: % row(s) carry status=decommissioned, '
            'which the pre-0028 CHECK constraint does not allow. Reassign '
            'or archive those rows before downgrading.', _stray_count;
    END IF;
END $$;

ALTER TABLE mcp_tool_surface_pins
    DROP CONSTRAINT mcp_pins_status_chk;

ALTER TABLE mcp_tool_surface_pins
    ADD CONSTRAINT mcp_pins_status_chk
        CHECK (status IN ('active', 'blocked', 'superseded'));
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
