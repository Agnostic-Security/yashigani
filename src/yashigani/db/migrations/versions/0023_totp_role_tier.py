"""Phase 13 — Role-tiered TOTP algorithm column.

Revision ID: 0023
Revises: 0022
Create Date: 2026-06-28

Rationale:
    Phase 13 (Yashigani 3.1): TOTP upgraded from SHA-1/6-digit (flat) to
    role-tiered:
        Users  → HMAC-SHA-256, 6 digits
        Admins → HMAC-SHA-512, 8 digits

    The new ``totp_algorithm`` column records which HMAC algorithm is active
    for each account's enrolment.  All existing rows receive DEFAULT 'SHA1',
    marking them as legacy enrolments.

MIGRATION STRATEGY — dual-admin safety:
    We do NOT force_totp_provision=true in SQL here.  Instead, the Python
    authenticate() path detects totp_algorithm='SHA1' at runtime (when the
    expected algorithm for the role differs) and sets force_totp_provision=true
    on the individual row at that moment.  This means:

    1. Pre-migration rows: totp_algorithm='SHA1', force_totp_provision=false.
    2. At first login post-migration, the server detects the mismatch, flips
       force_totp_provision=true, returns "totp_provision_required", and issues
       a restricted provisioning session.
    3. The admin (or user) scans the new QR code in agnosticOTP and confirms
       a code — at this point force_totp_provision=false, totp_algorithm='SHA512'
       (or 'SHA256' for users).
    4. All admins can be in this state simultaneously — no admin is locked out,
       because password authentication + provisioning session still works.
    5. Once at least one admin has re-enrolled, break-glass via the second admin
       is always available.

    This is a non-breaking additive migration — no data is deleted or locked.

Tables modified:
    admin_accounts — ADD COLUMN totp_algorithm TEXT NOT NULL DEFAULT 'SHA1'
"""
# Last updated: 2026-06-28T00:00:00+00:00
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0023"
down_revision: Union[str, None] = "0022"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_DDL_UP = """
-- Phase 13: role-tiered TOTP algorithm storage.
-- DEFAULT 'SHA1' marks all existing enrolments as legacy (SHA-1/6-digit).
-- The authenticate() path detects this and forces re-enrolment transparently.

ALTER TABLE admin_accounts
    ADD COLUMN IF NOT EXISTS totp_algorithm TEXT NOT NULL DEFAULT 'SHA1';

-- Explicit constraint: only valid algorithm names are stored.
ALTER TABLE admin_accounts
    ADD CONSTRAINT admin_accounts_totp_algorithm_check
    CHECK (totp_algorithm IN ('SHA1', 'SHA256', 'SHA512'));

-- Comment for clarity.
COMMENT ON COLUMN admin_accounts.totp_algorithm IS
    'TOTP HMAC algorithm for this enrolment: SHA1 (legacy/force-reprovision), '
    'SHA256 (user tier, Phase 13+), SHA512 (admin tier, Phase 13+).';
"""

_DDL_DOWN = """
ALTER TABLE admin_accounts
    DROP CONSTRAINT IF EXISTS admin_accounts_totp_algorithm_check;

ALTER TABLE admin_accounts
    DROP COLUMN IF EXISTS totp_algorithm;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
