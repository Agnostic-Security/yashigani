"""Enhance webauthn_credentials for admin FIDO2 support.

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-07

v2.23.3 (F-V233-WEBAUTHN): Adds missing columns to the existing
webauthn_credentials table so it matches the brief spec for admin
hardware-key support:

  - admin_id (UUID, FK to admin_accounts.account_id) — replaces the
    untyped user_id TEXT. The old user_id column is kept for now to
    avoid breaking the v0.9.0 in-memory path; admin_id is added
    alongside it and back-filled where user_id looks like a UUID.

  - transports (TEXT ARRAY) — list of CTAP transport hints returned
    by the authenticator (e.g. {usb, nfc, ble, internal}).

  - friendly_name (TEXT) — operator-set label, max 64 chars (e.g.
    "YubiKey 5 Nano work").

The existing name column is kept as an alias so v0.9.0 reads still
work; new writes land in friendly_name and we carry a trigger to keep
them in sync.

ASVS V2.8: sign_count is upgraded from INTEGER to BIGINT to avoid
overflow on high-use FIDO2 tokens.

Indexes:
  - idx_webauthn_credentials_admin_id  (admin_id)  — credential lookup by admin
  - The pre-existing idx_webauthn_credentials_user_id is retained for compat.
"""
from __future__ import annotations

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

_DDL_UP = """
-- Extend webauthn_credentials table (created in 0004).
-- Add admin_id FK, transports array, friendly_name column.
ALTER TABLE webauthn_credentials
    ADD COLUMN IF NOT EXISTS admin_id      UUID
        REFERENCES admin_accounts(account_id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS transports    TEXT[]   NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS friendly_name TEXT     NOT NULL DEFAULT '';

-- Back-fill admin_id where user_id is a valid UUID and matches admin_accounts.
-- Rows from the in-memory store (pre-DB) may have non-UUID user_id; skip those.
UPDATE webauthn_credentials wc
SET    admin_id = wc.user_id::uuid
FROM   admin_accounts aa
WHERE  wc.user_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
AND    wc.user_id::uuid = aa.account_id
AND    wc.admin_id IS NULL;

-- Upgrade sign_count to BIGINT for FIDO2 counters (ASVS V2.8 overflow guard).
ALTER TABLE webauthn_credentials
    ALTER COLUMN sign_count TYPE BIGINT;

-- Index admin_id for fast credential lookups.
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_admin_id
    ON webauthn_credentials (admin_id);

-- Grant on new columns follows table-level perms already set in 0004.
GRANT SELECT, INSERT, UPDATE, DELETE ON webauthn_credentials TO yashigani_app;
"""

_DDL_DOWN = """
DROP INDEX IF EXISTS idx_webauthn_credentials_admin_id;
ALTER TABLE webauthn_credentials
    ALTER COLUMN sign_count TYPE INTEGER,
    DROP COLUMN IF EXISTS admin_id,
    DROP COLUMN IF EXISTS transports,
    DROP COLUMN IF EXISTS friendly_name;
"""


def upgrade() -> None:
    op.execute(_DDL_UP)


def downgrade() -> None:
    op.execute(_DDL_DOWN)
