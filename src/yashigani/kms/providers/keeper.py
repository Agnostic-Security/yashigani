"""
Yashigani KSM — Keeper Security Secrets Manager provider.
Default provider for production / on-prem / cloud deployments.
SDK: keeper-secrets-manager-core
"""
from __future__ import annotations

import os
from typing import Optional, TYPE_CHECKING

from yashigani.kms.base import (
    KSMProvider,
    KeyNotFoundError,
    ProviderError,
    RotationError,
    SecretMetadata,
)

if TYPE_CHECKING:
    pass


def _import_ksm():
    try:
        from keeper_secrets_manager_core import SecretsManager
        from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage
        return SecretsManager, InMemoryKeyValueStorage
    except ImportError as exc:
        raise ImportError(
            "keeper-secrets-manager-core is required for KeeperKSMProvider. "
            "Install it with: pip install keeper-secrets-manager-core"
        ) from exc


class KeeperKSMProvider(KSMProvider):
    """
    Keeper Secrets Manager provider.
    Authenticates via a one-time access token stored as a Docker Secret
    or environment variable KSM_KEEPER_ONE_TIME_TOKEN.
    After first use the token is exchanged for app credentials stored
    in an in-memory key-value store.
    """

    def __init__(self, environment_scope: str) -> None:
        self._environment_scope = environment_scope
        self._manager = self._init_manager()

    def _init_manager(self):
        SecretsManager, InMemoryKeyValueStorage = _import_ksm()
        token = self._load_token()
        try:
            storage = InMemoryKeyValueStorage(token)
            manager = SecretsManager(config=storage)
            return manager
        except Exception as exc:
            raise ProviderError(
                f"Failed to initialise Keeper Secrets Manager: {exc}"
            ) from exc

    @staticmethod
    def _load_token() -> str:
        """
        Load the KSM one-time access token.
        Priority: Docker Secret file → environment variable.
        Never logs the token value.

        YSG-RISK-160: the Docker Secret file path is resolved via
        YASHIGANI_SECRETS_DIR (default /run/secrets) — was a bare literal
        with no override, the same convention-bypass class as YSG-RISK-150.
        """
        docker_secret_path = os.path.join(
            os.environ.get("YASHIGANI_SECRETS_DIR", "/run/secrets"),
            "KSM_KEEPER_ONE_TIME_TOKEN",
        )
        if os.path.exists(docker_secret_path):
            with open(docker_secret_path, encoding="utf-8") as f:
                return f.read().strip()
        token = os.environ.get("KSM_KEEPER_ONE_TIME_TOKEN", "")
        if not token:
            raise ProviderError(
                "Keeper one-time token not found. "
                "Provide via Docker Secret 'KSM_KEEPER_ONE_TIME_TOKEN' "
                "or environment variable KSM_KEEPER_ONE_TIME_TOKEN."
            )
        return token

    # -- KSMProvider ---------------------------------------------------------

    def get_secret(self, key: str) -> str:
        self._check_scope(key)
        try:
            secrets = self._manager.get_secrets([key])
            if not secrets:
                raise KeyNotFoundError(f"Secret '{key}' not found in Keeper KSM")
            field = secrets[0].field("password") or secrets[0].field("text")
            if field is None:
                raise ProviderError(f"Secret '{key}' has no readable field value")
            value = field[0] if isinstance(field, list) else field
            return str(value)
        except KeyNotFoundError:
            raise
        except Exception as exc:
            raise ProviderError(f"Failed to retrieve secret '{key}': {exc}") from exc

    def set_secret(self, key: str, value: str) -> None:
        self._check_scope(key)
        try:
            secrets = self._manager.get_secrets([key])
            if secrets:
                secrets[0].field("password", value)
                self._manager.save(secrets[0])
            else:
                raise ProviderError(
                    f"Creating new records is not supported via KSM SDK. "
                    f"Create the record '{key}' in Keeper Vault first."
                )
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(f"Failed to set secret '{key}': {exc}") from exc

    def rotate_secret(self, key: str, new_value: str) -> str:
        self._check_scope(key)
        try:
            self.set_secret(key, new_value)
            return f"keeper-rotated-{key}"
        except Exception as exc:
            raise RotationError(f"Rotation failed for '{key}': {exc}") from exc

    def revoke_token(self, key: str) -> None:
        self._check_scope(key)
        try:
            secrets = self._manager.get_secrets([key])
            if not secrets:
                raise KeyNotFoundError(f"Secret '{key}' not found")
            secrets[0].field("password", "")
            self._manager.save(secrets[0])
        except KeyNotFoundError:
            raise
        except Exception as exc:
            raise ProviderError(f"Failed to revoke token '{key}': {exc}") from exc

    def list_secrets(self, prefix: Optional[str] = None) -> list[SecretMetadata]:
        try:
            secrets = self._manager.get_secrets()
            result = []
            for s in secrets:
                uid = s.uid or ""
                title = s.title or uid
                if prefix and not title.startswith(prefix):
                    continue
                result.append(SecretMetadata(
                    key=title,
                    version=uid,
                    created_at="",
                    last_rotated_at=None,
                    expires_at=None,
                ))
            return result
        except Exception as exc:
            raise ProviderError(f"Failed to list secrets: {exc}") from exc

    def delete_secret(self, key: str) -> None:
        raise ProviderError(
            "Permanent deletion via KSM SDK is not supported. "
            "Delete the record in Keeper Vault manually."
        )

    def health_check(self) -> bool:
        try:
            self._manager.get_secrets()
            return True
        except Exception:
            return False

    @property
    def provider_name(self) -> str:
        return "keeper"

    @property
    def environment_scope(self) -> str:
        return self._environment_scope
