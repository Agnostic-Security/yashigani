"""v2.23.3 — FedRAMP AC-2(F2) inactive-account disable columns.

Revision ID: 0009
Revises: 0008
Create Date: 2026-05-08

Rationale:
    LU-YSG-002 (FedRAMP AC-2(F2)): accounts inactive for >= YASHIGANI_INACTIVE_DISABLE_DAYS
    must be automatically disabled. This migration adds two columns to admin_accounts:

    - last_login_at     TIMESTAMPTZ — stamped on every successful local-auth login.
                        NULL for accounts that have never logged in (treated as
                        inactive from account creation). Backfilled to created_at
                        epoch for existing rows so the first cron run uses creation
                        date rather than NULL as the inactivity baseline.
    - inactive_disabled_at TIMESTAMPTZ NULL — set when the automated cron task
                        disables an account; NULL if the account was not disabled
                        by the automated task. Distinct from operator-initiated
                        disable (disabled=true, inactive_disabled_at=NULL).

Backfill strategy:
    Existing rows have last_login_at set to their created_at epoch timestamp
    (converted from the existing DOUBLE PRECISION epoch column). This is
    conservative — it means the first cron run measures inactivity from when
    the account was *created*, not from "now". Operators who need to reset
    the baseline can UPDATE admin_accounts SET last_login_at = now() after
    the migration runs.

FedRAMP evidence:
    This migration is evidence artefact for LU-YSG-002 AC-2(F2).
    Lu: reference this migration SHA + 0009 revision in the v2.23.3 evidence pack.
"""
# Last updated: 2026-05-08T00:00:00+00:00
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_DDL_UP = """
-- FedRAMP AC-2(F2) — inactive-account audit columns

ALTER TABLE admin_accounts
    ADD COLUMN IF NOT EXISTS last_login_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS inactive_disabled_at TIMESTAMPTZ;

-- Backfill: use created_at epoch (DOUBLE PRECISION seconds since epoch) to
-- initialise last_login_at for existing rows.  New rows are stamped by the
-- application on each successful authentication.
UPDATE admin_accounts
SET last_login_at = to_timestamp(created_at)
WHERE last_login_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_admin_accounts_last_login
    ON admin_accounts (last_login_at)
    WHERE disabled = false;
"""

_DDL_DOWN = """
DROP INDEX IF EXISTS idx_admin_accounts_last_login;

ALTER TABLE admin_accounts
    DROP COLUMN IF EXISTS inactive_disabled_at,
    DROP COLUMN IF EXISTS last_login_at;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
