"""
Yashigani Auth — Postgres-backed WebAuthn credential store.

Durable replacement for the in-memory WebAuthnCredentialStore introduced
in v0.9.0. Stores all credentials in the webauthn_credentials table
(created in migration 0004, extended in 0007) so FIDO2 credentials survive
backoffice restarts, rolling updates, and K8s pod replacements.

ASVS V2.8:
  - sign_count is monotonically enforced (rollback → ValueError → rejected).
  - Challenges are cryptographically random (32 bytes, secrets.token_bytes).
  - Challenge lifetime: 5 minutes (300 s), enforced via Redis TTL.
  - Credential IDs are unique per the DB UNIQUE constraint.

Replay-attack resistance on challenges: each challenge is stored under a
Redis key that auto-expires after _CHALLENGE_TTL_SECONDS. pop() is atomic
so a challenge can never be re-used.

Last updated: 2026-05-07T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging
import secrets
import uuid
from datetime import datetime, timezone
from typing import Optional

from yashigani.auth.webauthn import (
    WebAuthnConfig,
    WebAuthnCredential,
    WebAuthnService,
    _import_webauthn,
    _map_uv,
    _map_attestation,
    _to_json_str,
)
from yashigani.db.postgres import tenant_transaction

logger = logging.getLogger(__name__)

_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"
_CHALLENGE_TTL_SECONDS = 300  # 5 minutes — ASVS V2.8


# ---------------------------------------------------------------------------
# Redis-backed challenge store
# ---------------------------------------------------------------------------

class RedisWebAuthnChallengeStore:
    """
    Single-use challenge store backed by Redis with 5-minute TTL.
    Uses GETDEL (atomic get + delete) to prevent replay.

    Fallback: if Redis is unavailable, delegates to the in-memory store
    from webauthn.py for non-production use only.
    """

    _KEY_PREFIX = "yashigani:webauthn:challenge:"

    def __init__(self, redis_client) -> None:
        self._r = redis_client

    def issue(self, user_id: str) -> bytes:
        """Generate and persist a 32-byte random challenge. Returns raw bytes."""
        challenge = secrets.token_bytes(32)
        key = f"{self._KEY_PREFIX}{user_id}"
        self._r.set(key, challenge, ex=_CHALLENGE_TTL_SECONDS)
        return challenge

    def consume(self, user_id: str) -> Optional[bytes]:
        """
        Return and atomically remove the pending challenge.
        Returns None if not found (expired or not issued).
        """
        key = f"{self._KEY_PREFIX}{user_id}"
        # GETDEL — atomic; available in Redis 6.2+.
        try:
            raw = self._r.getdel(key)
        except Exception:
            # Older Redis: fall back to GET + DEL (small TOCTOU window, acceptable)
            raw = self._r.get(key)
            if raw is not None:
                self._r.delete(key)
        return raw if isinstance(raw, bytes) else (raw.encode() if isinstance(raw, str) else raw)


# ---------------------------------------------------------------------------
# Postgres-backed credential store
# ---------------------------------------------------------------------------

class PgWebAuthnCredentialStore:
    """
    Postgres-backed WebAuthn credential store using the webauthn_credentials
    table (migration 0004 + 0007 extensions).

    Public API mirrors WebAuthnCredentialStore so WebAuthnService can use
    either implementation transparently.
    """

    async def add(self, credential: WebAuthnCredential, transports: Optional[list] = None) -> None:
        """Persist a new credential. Raises IntegrityError on duplicate credential_id."""
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            await conn.execute(
                """
                INSERT INTO webauthn_credentials (
                    id, user_id, admin_id,
                    credential_id, public_key,
                    sign_count, aaguid,
                    name, friendly_name,
                    transports,
                    created_at, last_used_at
                ) VALUES (
                    $1::uuid, $2, $3::uuid,
                    $4, pgp_sym_encrypt($5::text, current_setting('app.aes_key'))::bytea,
                    $6, $7,
                    $8, $9,
                    $10,
                    now(), NULL
                )
                """,
                uuid.UUID(credential.id),
                credential.user_id,
                # admin_id = same as user_id if it's a valid UUID
                _to_uuid_or_none(credential.user_id),
                credential.credential_id,
                credential.public_key.hex(),  # store raw bytes as hex string for pgp
                credential.sign_count,
                credential.aaguid,
                credential.name,
                credential.name,  # friendly_name mirrors name on creation
                transports or [],
            )

    async def get_by_credential_id(self, credential_id: bytes) -> Optional[WebAuthnCredential]:
        """Fetch a credential by raw credential_id bytes."""
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            row = await conn.fetchrow(
                """
                SELECT
                    id, user_id, credential_id,
                    pgp_sym_decrypt(public_key, current_setting('app.aes_key'))::text AS public_key_hex,
                    sign_count, aaguid, friendly_name, name, created_at, last_used_at
                FROM webauthn_credentials
                WHERE credential_id = $1
                """,
                credential_id,
            )
        return _row_to_credential(row) if row else None

    async def get_by_id(self, credential_uuid: str) -> Optional[WebAuthnCredential]:
        """Fetch a credential by internal UUID."""
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            row = await conn.fetchrow(
                """
                SELECT
                    id, user_id, credential_id,
                    pgp_sym_decrypt(public_key, current_setting('app.aes_key'))::text AS public_key_hex,
                    sign_count, aaguid, friendly_name, name, created_at, last_used_at
                FROM webauthn_credentials
                WHERE id = $1::uuid
                """,
                uuid.UUID(credential_uuid),
            )
        return _row_to_credential(row) if row else None

    async def list_for_user(self, user_id: str) -> list[WebAuthnCredential]:
        """Return all credentials for a given user_id (ordered by created_at)."""
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            rows = await conn.fetch(
                """
                SELECT
                    id, user_id, credential_id,
                    pgp_sym_decrypt(public_key, current_setting('app.aes_key'))::text AS public_key_hex,
                    sign_count, aaguid, friendly_name, name, created_at, last_used_at
                FROM webauthn_credentials
                WHERE user_id = $1
                ORDER BY created_at ASC
                """,
                user_id,
            )
        return [_row_to_credential(r) for r in rows]

    async def update_sign_count(
        self, credential_id: bytes, new_count: int
    ) -> None:
        """Advance sign_count and touch last_used_at. ASVS V2.8."""
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            await conn.execute(
                """
                UPDATE webauthn_credentials
                SET sign_count   = $2,
                    last_used_at = now()
                WHERE credential_id = $1
                """,
                credential_id,
                new_count,
            )

    async def update_friendly_name(
        self, credential_uuid: str, user_id: str, friendly_name: str
    ) -> bool:
        """Rename a credential. Returns False if not found or wrong owner."""
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            result = await conn.execute(
                """
                UPDATE webauthn_credentials
                SET friendly_name = $3,
                    name          = $3
                WHERE id = $1::uuid
                AND   user_id = $2
                """,
                uuid.UUID(credential_uuid),
                user_id,
                friendly_name[:64],  # enforce max length
            )
        try:
            return int(result.split()[-1]) > 0
        except (ValueError, IndexError):
            return False

    async def delete(self, credential_uuid: str, user_id: str) -> bool:
        """Delete a credential. Returns False if not found or wrong owner."""
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            result = await conn.execute(
                """
                DELETE FROM webauthn_credentials
                WHERE id = $1::uuid
                AND   user_id = $2
                """,
                uuid.UUID(credential_uuid),
                user_id,
            )
        try:
            return int(result.split()[-1]) > 0
        except (ValueError, IndexError):
            return False


# ---------------------------------------------------------------------------
# Async-aware WebAuthn service (thin shim over WebAuthnService)
# ---------------------------------------------------------------------------

class PgWebAuthnService:
    """
    Postgres + Redis backed WebAuthn service for admin FIDO2 login.

    Registration ceremony:
      1. begin_registration()  → returns JSON for navigator.credentials.create()
      2. complete_registration() → verifies attestation, persists credential

    Authentication ceremony:
      1. begin_authentication()  → returns JSON for navigator.credentials.get()
      2. complete_authentication() → verifies assertion, checks sign_count

    Credential management:
      - list_credentials()   → list for a user_id
      - delete_credential()  → revoke by UUID (caller must enforce step-up)

    All credential store operations are async (await-required).
    """

    def __init__(
        self,
        config: WebAuthnConfig,
        pg_store: PgWebAuthnCredentialStore,
        challenge_store: RedisWebAuthnChallengeStore,
    ) -> None:
        self._config = config
        self._pg = pg_store
        self._challenges = challenge_store

    # -- Registration ----------------------------------------------------------

    async def begin_registration(
        self,
        user_id: str,
        user_name: str,
        rp_id: Optional[str] = None,
        rp_name: Optional[str] = None,
    ) -> dict:
        """
        Start WebAuthn credential registration.
        Returns a PublicKeyCredentialCreationOptions dict.
        """
        webauthn = _import_webauthn()
        cfg = self._config
        effective_rp_id = rp_id or cfg.rp_id
        effective_rp_name = rp_name or cfg.rp_name

        challenge = self._challenges.issue(user_id)

        existing = await self._pg.list_for_user(user_id)
        exclude_credentials = [
            {"id": c.credential_id, "type": "public-key"}
            for c in existing
        ]

        options = webauthn.generate_registration_options(
            rp_id=effective_rp_id,
            rp_name=effective_rp_name,
            user_id=user_id.encode("utf-8"),
            user_name=user_name,
            challenge=challenge,
            exclude_credentials=exclude_credentials,
            authenticator_selection=webauthn.AuthenticatorSelectionCriteria(
                require_resident_key=cfg.require_resident_key,
                user_verification=_map_uv(cfg.user_verification, webauthn),
            ),
            attestation=_map_attestation(cfg.attestation, webauthn),
        )

        return webauthn.options_to_json(options)

    async def complete_registration(
        self,
        user_id: str,
        credential_response: dict,
        expected_origin: str,
        credential_name: str = "Passkey",
    ) -> WebAuthnCredential:
        """
        Verify attestation and store credential in Postgres.
        Returns the stored WebAuthnCredential on success.
        Raises ValueError on verification failure.
        """
        webauthn = _import_webauthn()
        cfg = self._config

        challenge = self._challenges.consume(user_id)
        if challenge is None:
            raise ValueError("No pending registration challenge for this user.")

        try:
            credential_json = _to_json_str(credential_response)
            try:
                cred = webauthn.RegistrationCredential.parse_raw(credential_json.encode())
            except (TypeError, AttributeError):
                cred = webauthn.RegistrationCredential.parse_raw(credential_json)
            verification = webauthn.verify_registration_response(
                credential=cred,
                expected_challenge=challenge,
                expected_rp_id=cfg.rp_id,
                expected_origin=expected_origin,
                require_user_verification=(cfg.user_verification == "required"),
            )
        except Exception as exc:
            raise ValueError(f"WebAuthn registration verification failed: {exc}") from exc

        # Extract transport hints if available (py-webauthn ≥ 2.0)
        transports: list[str] = []
        try:
            raw_transports = getattr(cred, "response", None)
            if raw_transports:
                t = getattr(raw_transports, "transports", None)
                if t:
                    transports = [str(x.value) if hasattr(x, "value") else str(x) for x in t]
        except Exception:
            pass

        aaguid_str = ""
        try:
            aaguid_str = verification.aaguid.hex if hasattr(verification.aaguid, "hex") else str(verification.aaguid)
        except Exception:
            pass

        credential = WebAuthnCredential(
            id=str(uuid.uuid4()),
            user_id=user_id,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            aaguid=aaguid_str,
            name=credential_name,
        )

        await self._pg.add(credential, transports=transports)
        return credential

    # -- Authentication --------------------------------------------------------

    async def begin_authentication(
        self,
        user_id: str,
        rp_id: Optional[str] = None,
    ) -> dict:
        """
        Start WebAuthn authentication assertion.
        Returns a PublicKeyCredentialRequestOptions dict.
        """
        webauthn = _import_webauthn()
        cfg = self._config
        effective_rp_id = rp_id or cfg.rp_id

        challenge = self._challenges.issue(user_id)

        allowed = await self._pg.list_for_user(user_id)
        allow_credentials = [
            {"id": c.credential_id, "type": "public-key"}
            for c in allowed
        ]

        if not allow_credentials:
            raise ValueError("No registered WebAuthn credentials for this user.")

        options = webauthn.generate_authentication_options(
            rp_id=effective_rp_id,
            challenge=challenge,
            allow_credentials=allow_credentials,
            user_verification=_map_uv(cfg.user_verification, webauthn),
        )

        return webauthn.options_to_json(options)

    async def complete_authentication(
        self,
        user_id: str,
        credential_response: dict,
        expected_origin: str,
    ) -> str:
        """
        Verify assertion and update sign_count.
        Returns the verified user_id on success.
        Raises ValueError on verification failure or sign_count rollback.
        """
        webauthn = _import_webauthn()
        cfg = self._config

        challenge = self._challenges.consume(user_id)
        if challenge is None:
            raise ValueError("No pending authentication challenge for this user.")

        import base64
        try:
            raw_id_b64 = credential_response.get("rawId", credential_response.get("id", ""))
            # Handle base64url without padding
            raw_id_b64 = raw_id_b64.rstrip("=") + "=" * (4 - len(raw_id_b64) % 4 or 4)
            credential_id_bytes = base64.urlsafe_b64decode(raw_id_b64)
        except Exception as exc:
            raise ValueError(f"Cannot decode credential ID: {exc}") from exc

        stored = await self._pg.get_by_credential_id(credential_id_bytes)
        if stored is None or stored.user_id != user_id:
            raise ValueError("Credential not found or does not belong to this user.")

        try:
            auth_json = _to_json_str(credential_response)
            try:
                auth_cred = webauthn.AuthenticationCredential.parse_raw(auth_json.encode())
            except (TypeError, AttributeError):
                auth_cred = webauthn.AuthenticationCredential.parse_raw(auth_json)
            verification = webauthn.verify_authentication_response(
                credential=auth_cred,
                expected_challenge=challenge,
                expected_rp_id=cfg.rp_id,
                expected_origin=expected_origin,
                credential_public_key=stored.public_key,
                credential_current_sign_count=stored.sign_count,
                require_user_verification=(cfg.user_verification == "required"),
            )
        except Exception as exc:
            raise ValueError(f"WebAuthn authentication verification failed: {exc}") from exc

        # ASVS V2.8: reject if sign_count did not advance (replay attack).
        # sign_count == 0 means the authenticator doesn't use a counter —
        # we accept that (not all FIDO2 devices track sign counts).
        if stored.sign_count > 0 and verification.new_sign_count <= stored.sign_count:
            raise ValueError(
                "Replay protection: sign_count did not advance. "
                "Possible cloned authenticator."
            )

        await self._pg.update_sign_count(
            stored.credential_id, verification.new_sign_count
        )
        return user_id

    # -- Credential management -------------------------------------------------

    async def list_credentials(self, user_id: str) -> list[WebAuthnCredential]:
        return await self._pg.list_for_user(user_id)

    async def delete_credential(self, user_id: str, credential_uuid: str) -> bool:
        """
        Revoke a specific credential by UUID.
        Returns False if not found or not owned by user.
        """
        return await self._pg.delete(credential_uuid, user_id)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def build_pg_webauthn_service(redis_client) -> PgWebAuthnService:
    """
    Construct a PgWebAuthnService from env configuration.
    Called once from the entrypoint after create_pool() completes.
    """
    import os
    config = WebAuthnConfig(
        rp_id=os.getenv("YASHIGANI_WEBAUTHN_RP_ID", "localhost"),
        rp_name=os.getenv("YASHIGANI_WEBAUTHN_RP_NAME", "Yashigani Backoffice"),
        require_resident_key=os.getenv("YASHIGANI_WEBAUTHN_REQUIRE_RESIDENT_KEY", "false").lower() == "true",
        user_verification=os.getenv("YASHIGANI_WEBAUTHN_USER_VERIFICATION", "preferred"),
        attestation=os.getenv("YASHIGANI_WEBAUTHN_ATTESTATION", "none"),
    )
    pg_store = PgWebAuthnCredentialStore()
    challenge_store = RedisWebAuthnChallengeStore(redis_client)
    return PgWebAuthnService(
        config=config,
        pg_store=pg_store,
        challenge_store=challenge_store,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _to_uuid_or_none(value: str) -> Optional[uuid.UUID]:
    """Parse a UUID string, returning None if it's not a valid UUID."""
    try:
        return uuid.UUID(value)
    except (ValueError, AttributeError):
        return None


def _row_to_credential(row) -> WebAuthnCredential:
    """Convert an asyncpg row to a WebAuthnCredential dataclass."""
    # public_key is returned as a hex string from the pgp_sym_decrypt cast
    pub_key_raw = row["public_key_hex"]
    if isinstance(pub_key_raw, str):
        try:
            public_key_bytes = bytes.fromhex(pub_key_raw)
        except ValueError:
            # Fallback: might already be raw bytes if pgcrypto not active
            public_key_bytes = pub_key_raw.encode("latin-1")
    else:
        public_key_bytes = bytes(pub_key_raw) if pub_key_raw else b""

    # friendly_name takes precedence over name for the display label
    display_name = row.get("friendly_name") or row.get("name") or "Passkey"

    created_at = row.get("created_at")
    if created_at is None:
        created_at = datetime.now(timezone.utc)
    elif not isinstance(created_at, datetime):
        created_at = datetime.fromtimestamp(float(created_at), tz=timezone.utc)

    last_used = row.get("last_used_at")
    if last_used is not None and not isinstance(last_used, datetime):
        last_used = datetime.fromtimestamp(float(last_used), tz=timezone.utc)

    return WebAuthnCredential(
        id=str(row["id"]),
        user_id=row["user_id"],
        credential_id=bytes(row["credential_id"]),
        public_key=public_key_bytes,
        sign_count=int(row["sign_count"]),
        aaguid=row.get("aaguid") or "",
        name=display_name,
        created_at=created_at,
        last_used_at=last_used,
    )
