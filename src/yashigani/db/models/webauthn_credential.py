"""
Yashigani DB — WebAuthn credential typed row.
Not an ORM. asyncpg returns asyncpg.Record objects; this dataclass
provides a typed wrapper for the webauthn_credentials table.
SQL column definitions match models.py conventions ($N parameterization).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from yashigani.db.postgres import PGP_SYM_OPTS  # Issue #144: AES-256 cipher pin


@dataclass(frozen=True)
class WebAuthnCredentialRow:
    """
    Typed row for the webauthn_credentials table.

    Schema:
        id              UUID PRIMARY KEY
        user_id         TEXT NOT NULL          -- FK to admin / user account
        credential_id   BYTEA NOT NULL UNIQUE  -- raw credential_id from authenticator
        public_key      BYTEA NOT NULL         -- COSE-encoded public key
        sign_count      INTEGER NOT NULL       -- replay protection counter
        aaguid          TEXT NOT NULL          -- authenticator AAGUID (hex)
        name            TEXT NOT NULL          -- user-supplied label
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
        last_used_at    TIMESTAMPTZ
    """
    id: uuid.UUID
    user_id: str
    credential_id: bytes   # raw bytes from authenticator
    public_key: bytes      # COSE public key — encrypted at rest via pgp_sym_encrypt
    sign_count: int        # monotonically increasing; 0 means not tracked
    aaguid: str            # hex string, 36 chars (UUID format)
    name: str              # user-given name, e.g. "MacBook Touch ID"
    created_at: datetime
    last_used_at: Optional[datetime]


# ---------------------------------------------------------------------------
# Query helpers — $N parameterization only, no string interpolation
# ---------------------------------------------------------------------------

INSERT_WEBAUTHN_CREDENTIAL = f"""
INSERT INTO webauthn_credentials (
    id, user_id, credential_id, public_key,
    sign_count, aaguid, name
) VALUES (
    $1, $2, $3,
    pgp_sym_encrypt($4::text, current_setting('app.aes_key'), '{PGP_SYM_OPTS}')::bytea,
    $5, $6, $7
)
"""

SELECT_WEBAUTHN_CREDENTIALS_BY_USER = """
SELECT
    id,
    user_id,
    credential_id,
    pgp_sym_decrypt(public_key, current_setting('app.aes_key'))::bytea AS public_key,
    sign_count,
    aaguid,
    name,
    created_at,
    last_used_at
FROM webauthn_credentials
WHERE user_id = $1
ORDER BY created_at ASC
"""

SELECT_WEBAUTHN_CREDENTIAL_BY_CREDENTIAL_ID = """
SELECT
    id,
    user_id,
    credential_id,
    pgp_sym_decrypt(public_key, current_setting('app.aes_key'))::bytea AS public_key,
    sign_count,
    aaguid,
    name,
    created_at,
    last_used_at
FROM webauthn_credentials
WHERE credential_id = $1
"""

UPDATE_WEBAUTHN_SIGN_COUNT = """
UPDATE webauthn_credentials
SET sign_count   = $2,
    last_used_at = now()
WHERE credential_id = $1
"""

DELETE_WEBAUTHN_CREDENTIAL = """
DELETE FROM webauthn_credentials
WHERE id = $1
AND   user_id = $2
"""

MIGRATION_CREATE_WEBAUTHN_CREDENTIALS_TABLE = """
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         TEXT         NOT NULL,
    credential_id   BYTEA        NOT NULL,
    public_key      BYTEA        NOT NULL,
    sign_count      INTEGER      NOT NULL DEFAULT 0,
    aaguid          TEXT         NOT NULL DEFAULT '',
    name            TEXT         NOT NULL DEFAULT 'Passkey',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    CONSTRAINT uq_webauthn_credential_id UNIQUE (credential_id)
);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id
    ON webauthn_credentials (user_id);
"""
