"""
HashiCorp Vault KMS provider — Phase 11.

Auth: AppRole (role_id + secret_id from Docker secrets files).
Engine: KV v2 only.
Dev-mode: VAULT_TOKEN env var for local development only.

Secret path: kv/data/yashigani/{key_name}, field "value".
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

from yashigani.kms.base import KSMProvider, KeyNotFoundError, ProviderError, SecretMetadata

logger = logging.getLogger(__name__)

_VAULT_ADDR_DEFAULT = "http://vault:8200"
_KV_MOUNT = "kv"
_SECRET_PREFIX = "yashigani"


class VaultKMSProvider(KSMProvider):

    def __init__(self, environment_scope: str = "production") -> None:
        self._environment_scope = environment_scope
        self._client: Optional[Any] = None
        self._vault_addr = os.getenv("VAULT_ADDR", _VAULT_ADDR_DEFAULT)
        self._namespace = os.getenv("VAULT_NAMESPACE")
        self._token = os.getenv("VAULT_TOKEN")
        # YSG-RISK-160: VAULT_ROLE_ID_FILE / VAULT_SECRET_ID_FILE remain the
        # primary (documented, working) override for a fully custom path —
        # unchanged, not broken. The DEFAULT (when neither is set) now routes
        # through YASHIGANI_SECRETS_DIR instead of a bare "/run/secrets/..."
        # literal, so a non-default secrets mount doesn't silently fall back
        # to the wrong directory (same class as YSG-RISK-150).
        _secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
        self._role_id_file = os.getenv(
            "VAULT_ROLE_ID_FILE", os.path.join(_secrets_dir, "vault_role_id")
        )
        self._secret_id_file = os.getenv(
            "VAULT_SECRET_ID_FILE", os.path.join(_secrets_dir, "vault_secret_id")
        )
        self._authenticate()

    # -- Identity properties -------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "vault"

    @property
    def environment_scope(self) -> str:
        return self._environment_scope

    # -- Internal auth -------------------------------------------------------

    def _authenticate(self) -> None:
        try:
            import hvac
        except ImportError:
            raise RuntimeError("hvac is required for Vault KMS. Install with: pip install yashigani[vault]")

        client = hvac.Client(url=self._vault_addr, namespace=self._namespace)
        if self._token:
            logger.warning("Vault: direct token auth (dev mode — NOT for production)")
            client.token = self._token
        else:
            role_id = _read_file(self._role_id_file)
            secret_id = _read_file(self._secret_id_file)
            result = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
            client.token = result["auth"]["client_token"]
            logger.info("Vault: AppRole authentication successful")

        if not client.is_authenticated():
            raise RuntimeError("Vault authentication failed")

        self._client = client
        logger.info("Vault KMS provider initialised: addr=%s", self._vault_addr)

    @property
    def _authenticated_client(self) -> Any:
        """Return the hvac client, guaranteed non-None after _ensure_authenticated()."""
        assert self._client is not None, "Vault client not authenticated"
        return self._client

    def _ensure_authenticated(self) -> None:
        if self._client is None or not self._client.is_authenticated():
            logger.info("Vault token expired — re-authenticating")
            self._authenticate()

    # -- Core operations -----------------------------------------------------

    def get_secret(self, key: str) -> str:
        self._check_scope(key)
        self._ensure_authenticated()
        key_name = key.split("/", 1)[-1] if "/" in key else key
        try:
            resp = self._authenticated_client.secrets.kv.v2.read_secret_version(
                path=f"{_SECRET_PREFIX}/{key_name}", mount_point=_KV_MOUNT
            )
            return resp["data"]["data"].get("value") or ""
        except Exception as exc:
            raise KeyNotFoundError(f"Vault get_secret failed for '{key}': {exc}") from exc

    def set_secret(self, key: str, value: str) -> None:
        self._check_scope(key)
        self._ensure_authenticated()
        key_name = key.split("/", 1)[-1] if "/" in key else key
        try:
            self._authenticated_client.secrets.kv.v2.create_or_update_secret(
                path=f"{_SECRET_PREFIX}/{key_name}",
                secret={"value": value},
                mount_point=_KV_MOUNT,
            )
            logger.info("Vault secret written: %s/%s", _SECRET_PREFIX, key_name)
        except Exception as exc:
            raise ProviderError(f"Vault set_secret failed for '{key}': {exc}") from exc

    def rotate_secret(self, key: str, new_value: str) -> str:
        self._check_scope(key)
        self._ensure_authenticated()
        key_name = key.split("/", 1)[-1] if "/" in key else key
        try:
            self._authenticated_client.secrets.kv.v2.create_or_update_secret(
                path=f"{_SECRET_PREFIX}/{key_name}",
                secret={"value": new_value},
                mount_point=_KV_MOUNT,
            )
            resp = self._authenticated_client.secrets.kv.v2.read_secret_version(
                path=f"{_SECRET_PREFIX}/{key_name}", mount_point=_KV_MOUNT
            )
            version = str(resp["data"]["metadata"].get("version", "unknown"))
            logger.info("Vault secret rotated: %s/%s to version %s", _SECRET_PREFIX, key_name, version)
            return version
        except Exception as exc:
            from yashigani.kms.base import RotationError
            raise RotationError(f"Vault rotate_secret failed for '{key}': {exc}") from exc

    def revoke_token(self, key: str) -> None:
        self._check_scope(key)
        self._ensure_authenticated()
        key_name = key.split("/", 1)[-1] if "/" in key else key
        try:
            self._authenticated_client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=f"{_SECRET_PREFIX}/{key_name}", mount_point=_KV_MOUNT
            )
            logger.info("Vault token/secret revoked: %s/%s", _SECRET_PREFIX, key_name)
        except Exception as exc:
            raise ProviderError(f"Vault revoke_token failed for '{key}': {exc}") from exc

    def list_secrets(self, prefix: Optional[str] = None) -> list[SecretMetadata]:
        self._ensure_authenticated()
        try:
            list_path = f"{_SECRET_PREFIX}/{prefix}" if prefix else _SECRET_PREFIX
            resp = self._authenticated_client.secrets.kv.v2.list_secrets(
                path=list_path, mount_point=_KV_MOUNT
            )
            keys: list[str] = resp["data"]["keys"]
            result: list[SecretMetadata] = []
            for k in keys:
                result.append(SecretMetadata(
                    key=k,
                    version="unknown",
                    created_at="",
                    last_rotated_at=None,
                    expires_at=None,
                ))
            return result
        except Exception as exc:
            logger.warning("Vault list_secrets failed: %s", exc)
            return []

    def delete_secret(self, key: str) -> None:
        self._check_scope(key)
        self._ensure_authenticated()
        key_name = key.split("/", 1)[-1] if "/" in key else key
        try:
            self._authenticated_client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=f"{_SECRET_PREFIX}/{key_name}", mount_point=_KV_MOUNT
            )
        except Exception as exc:
            raise KeyNotFoundError(f"Vault delete_secret failed for '{key}': {exc}") from exc

    def health_check(self) -> bool:
        try:
            self._ensure_authenticated()
            status = self._authenticated_client.sys.read_health_status(method="GET")
            initialized = status.get("initialized", False)
            sealed = status.get("sealed", True)
            return bool(initialized and not sealed)
        except Exception:
            return False


def _read_file(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError as exc:
        raise RuntimeError(f"Cannot read Vault secret file {path}: {exc}")
