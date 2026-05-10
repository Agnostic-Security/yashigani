"""v2.23.3 — Password reuse history for IA.L2-3.5.8 (CMMC L2).

Revision ID: 0010
Revises: 0009
Create Date: 2026-05-09

Rationale:
    CMMC L2 control IA.L2-3.5.8 (NIST SP 800-171 IA-5(1)(e)) requires that
    systems prohibit the reuse of passwords for a specified number of
    generations. The default depth is 12 (NIST SP 800-63B Section 5.1.1.2
    recommendation for deployments that enforce reuse history).

Table: password_history
    - user_id         UUID FK → admin_accounts.account_id (CASCADE DELETE)
    - password_hash   TEXT    — Argon2id hash of the historical password
    - changed_at      TIMESTAMPTZ — when this password was set

    PRIMARY KEY (user_id, changed_at) — one entry per second per account.
    Index on (user_id, changed_at DESC) for efficient last-N lookups.

    The table does NOT store plaintext — only the Argon2id hash, identical
    to the storage format in admin_accounts.password_hash. The application
    layer prunes entries older than PASSWORD_HISTORY_DEPTH on each password
    change so the table stays bounded.

Downgrade: DROP TABLE password_history.

CMMC evidence:
    This migration is the evidence artefact for IA.L2-3.5.8.
    Reference migration SHA + 0010 revision in the v2.23.3 compliance pack.
"""
# Last updated: 2026-05-09T00:00:00+00:00
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_DDL_UP = """
-- ============================================================
-- PASSWORD HISTORY — CMMC L2 IA.L2-3.5.8 / NIST 800-171 IA-5
-- ============================================================

CREATE TABLE password_history (
    user_id       UUID        NOT NULL
                  REFERENCES admin_accounts (account_id) ON DELETE CASCADE,
    password_hash TEXT        NOT NULL,
    changed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, changed_at)
);

-- Efficient last-N lookups ordered newest-first per user.
CREATE INDEX idx_password_history_user_changed
    ON password_history (user_id, changed_at DESC);

GRANT SELECT, INSERT, DELETE ON password_history TO yashigani_app;
"""

_DDL_DOWN = """
DROP TABLE IF EXISTS password_history CASCADE;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
