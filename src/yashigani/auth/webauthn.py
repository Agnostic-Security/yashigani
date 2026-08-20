"""
Yashigani Auth — WebAuthn/Passkey authentication (FIDO2).
Registration and authentication ceremonies per W3C WebAuthn Level 2.
OWASP ASVS V2.8: hardware-bound credential, replay prevention via sign_count.
"""
from __future__ import annotations

import os
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _import_webauthn():
    try:
        import webauthn
        # py-webauthn >= 2.x moved structs to webauthn.helpers.structs and no
        # longer re-exports them at the top-level module.  Patch them back so
        # call-sites that do ``webauthn.AuthenticatorSelectionCriteria(...)``
        # keep working regardless of installed version.
        if not hasattr(webauthn, "AuthenticatorSelectionCriteria"):
            from webauthn.helpers.structs import (
                AuthenticatorSelectionCriteria,
                UserVerificationRequirement,
                AttestationConveyancePreference,
            )
            webauthn.AuthenticatorSelectionCriteria = AuthenticatorSelectionCriteria
            webauthn.UserVerificationRequirement = UserVerificationRequirement
            webauthn.AttestationConveyancePreference = AttestationConveyancePreference
        return webauthn
    except ImportError as exc:
        raise ImportError(
            "py_webauthn is required. Install with: pip install py-webauthn"
        ) from exc


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class WebAuthnConfig:
    rp_id: str = os.getenv("YASHIGANI_WEBAUTHN_RP_ID", "localhost")
    rp_name: str = "Yashigani Backoffice"
    require_resident_key: bool = False
    user_verification: str = "preferred"   # "required" for high-assurance
    attestation: str = "none"              # "direct" for hardware key attestation


# ---------------------------------------------------------------------------
# Credential model
# ---------------------------------------------------------------------------

@dataclass
class WebAuthnCredential:
    id: str                             # unique UUID
    user_id: str                        # FK to account
    credential_id: bytes                # raw credential_id from authenticator
    public_key: bytes                   # COSE public key
    sign_count: int                     # replay protection counter
    aaguid: str                         # authenticator AAGUID (hex string)
    name: str                           # user-given name, e.g. "MacBook Touch ID"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_used_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# In-process credential store
# ---------------------------------------------------------------------------

class WebAuthnCredentialStore:
    """
    In-memory store for WebAuthn credentials.
    Production deployments replace this with a DB-backed implementation.
    Credentials are keyed by user_id (list) and by credential_id bytes (dict).
    """

    def __init__(self) -> None:
        # user_id -> list[WebAuthnCredential]
        self._by_user: dict[str, list[WebAuthnCredential]] = {}
        # credential_id (bytes) -> WebAuthnCredential
        self._by_credential_id: dict[bytes, WebAuthnCredential] = {}

    def add(self, credential: WebAuthnCredential) -> None:
        self._by_user.setdefault(credential.user_id, []).append(credential)
        self._by_credential_id[credential.credential_id] = credential

    def get_by_id(self, credential_uuid: str) -> Optional[WebAuthnCredential]:
        for cred in self._by_credential_id.values():
            if cred.id == credential_uuid:
                return cred
        return None

    def get_by_credential_id(self, credential_id: bytes) -> Optional[WebAuthnCredential]:
        return self._by_credential_id.get(credential_id)

    def list_for_user(self, user_id: str) -> list[WebAuthnCredential]:
        return list(self._by_user.get(user_id, []))

    def update_sign_count(self, credential_id: bytes, new_count: int) -> None:
        cred = self._by_credential_id.get(credential_id)
        if cred:
            cred.sign_count = new_count
            cred.last_used_at = datetime.now(timezone.utc)

    def delete(self, credential_uuid: str) -> bool:
        target = self.get_by_id(credential_uuid)
        if target is None:
            return False
        # Remove from user list
        user_list = self._by_user.get(target.user_id, [])
        self._by_user[target.user_id] = [c for c in user_list if c.id != credential_uuid]
        # Remove from credential_id index
        self._by_credential_id.pop(target.credential_id, None)
        return True


# ---------------------------------------------------------------------------
# Challenge store — ephemeral, keyed by user_id
# ---------------------------------------------------------------------------

class ChallengeStore:
    """
    Stores pending WebAuthn challenges. Each challenge is single-use.
    In production back this with Redis with a short TTL (< 5 minutes).
    ASVS V2.8: challenge is cryptographically random (32 bytes).
    """

    def __init__(self) -> None:
        self._challenges: dict[str, bytes] = {}  # user_id -> challenge bytes

    def issue(self, user_id: str) -> bytes:
        challenge = secrets.token_bytes(32)
        self._challenges[user_id] = challenge
        return challenge

    def consume(self, user_id: str) -> Optional[bytes]:
        """Return and remove the stored challenge. None if not found."""
        return self._challenges.pop(user_id, None)


# ---------------------------------------------------------------------------
# WebAuthn service
# ---------------------------------------------------------------------------

class WebAuthnService:
    """
    Stateless WebAuthn ceremony handler.
    Inject with credential_store and challenge_store at startup.
    """

    def __init__(
        self,
        config: WebAuthnConfig,
        credential_store: Optional[WebAuthnCredentialStore] = None,
        challenge_store: Optional[ChallengeStore] = None,
    ) -> None:
        self._config = config
        self._credential_store = credential_store or WebAuthnCredentialStore()
        self._challenge_store = challenge_store or ChallengeStore()

    # -- Registration ceremony -----------------------------------------------

    def begin_registration(
        self,
        user_id: str,
        user_name: str,
        rp_id: Optional[str] = None,
        rp_name: Optional[str] = None,
    ) -> dict:
        """
        Start WebAuthn credential registration.
        Returns a PublicKeyCredentialCreationOptions dict for the browser.
        """
        webauthn = _import_webauthn()
        cfg = self._config
        effective_rp_id = rp_id or cfg.rp_id
        effective_rp_name = rp_name or cfg.rp_name

        challenge = self._challenge_store.issue(user_id)

        # Build exclude list — prevent re-registering existing credentials
        existing = self._credential_store.list_for_user(user_id)
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

    def complete_registration(
        self,
        user_id: str,
        credential_response: dict,
        expected_origin: str,
        credential_name: str = "Passkey",
    ) -> WebAuthnCredential:
        """
        Verify attestation and store credential.
        Returns the stored WebAuthnCredential on success.
        Raises ValueError on verification failure.
        """
        webauthn = _import_webauthn()
        cfg = self._config

        challenge = self._challenge_store.consume(user_id)
        if challenge is None:
            raise ValueError("No pending registration challenge for this user.")

        try:
            credential_json = _to_json_str(credential_response)
            # py-webauthn v2.1+: parse_raw expects bytes; v1.x: expects str
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

        credential = WebAuthnCredential(
            id=str(uuid.uuid4()),
            user_id=user_id,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            aaguid=verification.aaguid.hex if hasattr(verification.aaguid, "hex") else str(verification.aaguid),
            name=credential_name,
        )
        self._credential_store.add(credential)
        return credential

    # -- Authentication ceremony ---------------------------------------------

    def begin_authentication(
        self,
        user_id: str,
        rp_id: Optional[str] = None,
    ) -> dict:
        """
        Start WebAuthn authentication assertion.
        Returns a PublicKeyCredentialRequestOptions dict for the browser.
        """
        webauthn = _import_webauthn()
        cfg = self._config
        effective_rp_id = rp_id or cfg.rp_id

        challenge = self._challenge_store.issue(user_id)

        # Allow any registered credential for this user
        allowed = self._credential_store.list_for_user(user_id)
        allow_credentials = [
            {"id": c.credential_id, "type": "public-key"}
            for c in allowed
        ]

        options = webauthn.generate_authentication_options(
            rp_id=effective_rp_id,
            challenge=challenge,
            allow_credentials=allow_credentials,
            user_verification=_map_uv(cfg.user_verification, webauthn),
        )

        return webauthn.options_to_json(options)

    def complete_authentication(
        self,
        user_id: str,
        credential_response: dict,
        expected_origin: str,
    ) -> str:
        """
        Verify assertion and update sign count for replay protection.
        Returns the user_id on success.
        Raises ValueError on verification failure or sign_count rollback.
        """
        webauthn = _import_webauthn()
        cfg = self._config

        challenge = self._challenge_store.consume(user_id)
        if challenge is None:
            raise ValueError("No pending authentication challenge for this user.")

        # Look up the credential by raw credential_id from the response
        try:
            import base64
            raw_id_b64 = credential_response.get("rawId", credential_response.get("id", ""))
            # Handle both base64url and standard base64
            padding = 4 - len(raw_id_b64) % 4
            if padding != 4:
                raw_id_b64 += "=" * padding
            credential_id_bytes = base64.urlsafe_b64decode(raw_id_b64)
        except Exception as exc:
            raise ValueError(f"Cannot decode credential ID: {exc}") from exc

        stored = self._credential_store.get_by_credential_id(credential_id_bytes)
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

        # ASVS V2.8: reject if sign_count did not increase (replay attack)
        if stored.sign_count > 0 and verification.new_sign_count <= stored.sign_count:
            raise ValueError(
                "Replay protection: sign_count did not advance. "
                "Possible cloned authenticator."
            )

        self._credential_store.update_sign_count(
            stored.credential_id, verification.new_sign_count
        )
        return user_id

    # -- Credential management -----------------------------------------------

    def list_credentials(self, user_id: str) -> list[WebAuthnCredential]:
        return self._credential_store.list_for_user(user_id)

    def delete_credential(self, user_id: str, credential_uuid: str) -> bool:
        """
        Delete a specific credential by UUID.
        Returns False if credential not found or does not belong to user.
        """
        cred = self._credential_store.get_by_id(credential_uuid)
        if cred is None or cred.user_id != user_id:
            return False
        return self._credential_store.delete(credential_uuid)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _map_uv(user_verification: str, webauthn):
    """Map string to py_webauthn UserVerificationRequirement enum."""
    mapping = {
        "required": webauthn.UserVerificationRequirement.REQUIRED,
        "preferred": webauthn.UserVerificationRequirement.PREFERRED,
        "discouraged": webauthn.UserVerificationRequirement.DISCOURAGED,
    }
    return mapping.get(user_verification, webauthn.UserVerificationRequirement.PREFERRED)


def _map_attestation(attestation: str, webauthn):
    """Map string to py_webauthn AttestationConveyancePreference enum."""
    mapping = {
        "none": webauthn.AttestationConveyancePreference.NONE,
        "indirect": webauthn.AttestationConveyancePreference.INDIRECT,
        "direct": webauthn.AttestationConveyancePreference.DIRECT,
        "enterprise": webauthn.AttestationConveyancePreference.ENTERPRISE,
    }
    return mapping.get(attestation, webauthn.AttestationConveyancePreference.NONE)


def _to_json_str(obj: dict) -> str:
    import json
    return json.dumps(obj)
