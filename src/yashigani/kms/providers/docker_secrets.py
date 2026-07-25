"""
Yashigani KSM — Docker Secrets provider.
Reads secrets from /run/secrets/<key> (Docker/Podman native secrets).
Intended for local / dev / demo deployments only.

Cloud-key write support (DEMO/FREE tier — Tiago directive):
  In demo/free deployments there is no real KMS. Admins can still store cloud
  LLM provider API keys (openai_api_key, anthropic_api_key) via the admin UI.
  We handle this with a WRITABLE cloud-keys directory (distinct from the
  read-only /run/secrets mount) backed by a host-bind volume.

  - Only keys in _CLOUD_KEY_NAMES may be written; all other keys still raise
    ProviderError on set_secret (install-managed secrets remain read-only).
  - set_secret writes atomically: mktemp → write → chmod 0600 → rename.
    The rename is atomic on POSIX as long as src/dst are on the same device,
    which is guaranteed by placing the temp file in cloud_keys_dir.
  - get_secret checks cloud_keys_dir FIRST (so a runtime-set key overrides a
    pre-seeded /run/secrets value), then falls back to the read-only
    /run/secrets mount (so a key pre-seeded by install.sh into docker/secrets/
    still works without an admin UI action).
  - Path-traversal protection reuses _safe_filename() on every key before any
    filesystem access — the cloud-key namespace filter is enforced before the
    file write, and _safe_filename rejects any key whose basename contains
    ".." / "/" / "\\".

Crypto-shred KEK write support (YSG-GATE-V50-C, Tom 2026-07-25):
  ``audit/crypto_shred.py`` mints a per-tenant Data-Encryption-Key-wrapping
  KEK on first use (``cryptoshred:kek:<tenant>``) via ``get_secret`` /
  ``set_secret``.  crypto_shred_enabled defaults True in EVERY deployment
  mode (audit/config.py — a privacy control, unlike db_sink_enabled) and
  docker-compose.yml/Helm both default YASHIGANI_KMS_PROVIDER=docker, so this
  is a hard runtime requirement of the docker-secrets provider, not an
  optional extra. Before this fix, KEK keys fell through to the generic
  "not in the cloud-key namespace" rejection and sealing failed on every
  admin mutation (ERROR-spam finding).

  KEKs get their OWN writable directory (cryptoshred_keys_dir), physically
  separate from cloud_keys_dir:
  - Different security posture: cloud_keys_dir backs an admin-UI-listed,
    human-supplied LLM provider credential; cryptoshred_keys_dir backs a
    machine-generated wrapping key that must never appear in any "list your
    stored keys" inventory (list_secrets still enumerates it as a bare key
    name for operator/health visibility — no key MATERIAL is ever returned
    by list_secrets for either namespace).
  - Different write trigger: cloud keys are written on an explicit admin PUT;
    KEKs are minted lazily and silently the first time ANY admin mutation is
    audited, with no user-facing endpoint.
  - Keeping them separate means a future change to the cloud-key allowlist
    or its admin routes can never accidentally expose/rotate a crypto-shred
    KEK, and vice versa.

  Matches the cloud-key mechanism exactly: atomic mktemp→chmod 0600→rename
  write, prefix-gated (``cryptoshred:kek:``) rather than an exact-name
  allowlist (KEK keys are per-tenant: ``cryptoshred:kek:default``,
  ``cryptoshred:kek:<tenant-id>``, ...), same path-traversal guard via
  _safe_filename(). KEKs MUST persist across container restarts (losing a
  KEK renders every already-sealed subject field for that tenant permanently
  undecipherable — an unintended mass-shred) — cryptoshred_keys_dir must be
  backed by a durable volume, never emptyDir/tmpfs.
"""
from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import Optional

from yashigani.kms.base import (
    KSMProvider,
    KeyNotFoundError,
    ProviderError,
    SecretMetadata,
)

_SECRETS_DIR = Path("/run/secrets")
_CLOUD_KEYS_DIR = Path("/run/cloud-keys")

# Explicit allowlist of cloud-provider API key names that may be written at
# runtime.  All other keys remain read-only — install-managed secrets (postgres
# password, internal bearer, PKI material, etc.) cannot be overwritten via the
# admin UI.
_CLOUD_KEY_NAMES: frozenset[str] = frozenset({
    "openai_api_key",
    "anthropic_api_key",
})

# Prefix identifying a crypto-shred per-tenant KEK key
# (audit/crypto_shred.py CryptoShredKeyStore._KEK_KMS_KEY =
# "cryptoshred:kek:{tenant}"). Prefix-matched rather than an exact-name
# allowlist because the tenant id is dynamic.
_CRYPTOSHRED_KEK_PREFIX = "cryptoshred:kek:"


class DockerSecretsProvider(KSMProvider):
    """
    Reads secrets from the Docker/Podman secrets filesystem mount.

    Cloud API keys (openai_api_key, anthropic_api_key) can be stored at
    runtime via set_secret when cloud_keys_dir is provided (demo/free tier).
    Crypto-shred per-tenant KEKs (cryptoshred:kek:<tenant>) can be stored at
    runtime via set_secret when cryptoshred_keys_dir is provided. All other
    keys are read-only; set_secret on them raises ProviderError.

    get_secret resolution order (per matching namespace):
      1. cloud_keys_dir/<key>         — runtime-set cloud key (writable volume)
      2. cryptoshred_keys_dir/<key>   — runtime-set KEK (writable volume)
      3. secrets_dir/<key>            — install-provisioned key (read-only mount)
    """

    def __init__(
        self,
        environment_scope: str,
        secrets_dir: Path = _SECRETS_DIR,
        cloud_keys_dir: Optional[Path] = None,
        cryptoshred_keys_dir: Optional[Path] = None,
    ) -> None:
        self._environment_scope = environment_scope
        self._secrets_dir = secrets_dir
        self._cloud_keys_dir = cloud_keys_dir
        self._cryptoshred_keys_dir = cryptoshred_keys_dir

    # -- KSMProvider ---------------------------------------------------------

    def get_secret(self, key: str) -> str:
        self._check_scope(key)
        safe_key = self._safe_filename(key)

        # Cloud keys: check writable dir first (runtime-set overrides pre-seed).
        if safe_key in _CLOUD_KEY_NAMES and self._cloud_keys_dir is not None:
            cloud_path = self._cloud_keys_dir / safe_key
            if cloud_path.exists():
                try:
                    return cloud_path.read_text(encoding="utf-8").rstrip("\n")
                except OSError as exc:
                    raise ProviderError(
                        f"Failed to read cloud key '{key}' from {cloud_path}: {exc}"
                    ) from exc

        # Crypto-shred KEKs: check writable dir first (runtime-minted key).
        if safe_key.startswith(_CRYPTOSHRED_KEK_PREFIX) and self._cryptoshred_keys_dir is not None:
            kek_path = self._cryptoshred_keys_dir / safe_key
            if kek_path.exists():
                try:
                    return kek_path.read_text(encoding="utf-8").rstrip("\n")
                except OSError as exc:
                    raise ProviderError(
                        f"Failed to read crypto-shred KEK '{key}' from {kek_path}: {exc}"
                    ) from exc

        # Fall back to read-only Docker-secrets mount (pre-seeded or install-managed).
        secret_path = self._secrets_dir / safe_key
        if not secret_path.exists():
            raise KeyNotFoundError(f"Secret '{key}' not found in Docker Secrets")
        try:
            return secret_path.read_text(encoding="utf-8").rstrip("\n")
        except OSError as exc:
            raise ProviderError(f"Failed to read secret '{key}': {exc}") from exc

    def set_secret(self, key: str, value: str) -> None:
        """
        Write a cloud API key or a crypto-shred KEK atomically to its writable
        namespace directory.

        Only keys in _CLOUD_KEY_NAMES (openai_api_key, anthropic_api_key) or
        prefixed _CRYPTOSHRED_KEK_PREFIX (cryptoshred:kek:<tenant>) are
        accepted. All other keys raise ProviderError — this keeps
        install-managed secrets (postgres_password, internal_bearer, PKI
        material) permanently read-only even in demo/free deployments.

        The write is atomic on POSIX: mktemp in the target dir → write content
        → chmod 0600 → os.rename() to final name.  A reader can never see a
        partial write.
        """
        self._check_scope(key)
        safe_key = self._safe_filename(key)

        if safe_key in _CLOUD_KEY_NAMES:
            target_dir = self._cloud_keys_dir
            namespace_label = "cloud key"
            not_configured_msg = (
                "Docker Secrets provider: cloud-keys directory is not configured. "
                "Set YASHIGANI_CLOUD_KEYS_DIR or mount a writable volume and "
                "pass cloud_keys_dir to DockerSecretsProvider."
            )
            not_exist_msg = (
                f"Cloud-keys directory '{{dir}}' does not exist. "
                "Ensure the host directory is created and mounted (rw) before "
                "storing cloud API keys."
            )
            not_writable_msg = (
                f"Cloud-keys directory '{{dir}}' is not writable by the "
                "container process. Check volume mount mode and UID/GID mapping."
            )
        elif safe_key.startswith(_CRYPTOSHRED_KEK_PREFIX):
            target_dir = self._cryptoshred_keys_dir
            namespace_label = "crypto-shred KEK"
            not_configured_msg = (
                "Docker Secrets provider: crypto-shred-keys directory is not "
                "configured. Set YASHIGANI_CRYPTO_SHRED_KEKS_DIR or mount a "
                "writable volume and pass cryptoshred_keys_dir to "
                "DockerSecretsProvider."
            )
            not_exist_msg = (
                f"Crypto-shred-keys directory '{{dir}}' does not exist. "
                "Ensure the host directory is created and mounted (rw) before "
                "crypto-shred can mint per-tenant KEKs."
            )
            not_writable_msg = (
                f"Crypto-shred-keys directory '{{dir}}' is not writable by the "
                "container process. Check volume mount mode and UID/GID mapping."
            )
        else:
            raise ProviderError(
                f"Docker Secrets provider: key '{key}' is not in the cloud-key "
                "or crypto-shred-KEK namespace and cannot be set "
                "programmatically. Install-managed secrets (PKI, passwords, "
                "tokens) are read-only."
            )

        if target_dir is None:
            raise ProviderError(not_configured_msg)

        if not target_dir.exists():
            raise ProviderError(not_exist_msg.format(dir=target_dir))
        if not os.access(target_dir, os.W_OK):
            raise ProviderError(not_writable_msg.format(dir=target_dir))

        # Atomic write: temp file in the same directory → rename (same device).
        try:
            fd, tmp_path_str = tempfile.mkstemp(
                dir=target_dir,
                prefix=f".{safe_key}.",
                suffix=".tmp",
            )
            tmp_path = Path(tmp_path_str)
            try:
                os.chmod(fd, stat.S_IRUSR | stat.S_IWUSR)  # 0600 before write
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(value)
                fd = -1  # fdopen took ownership; don't close again
            except Exception:
                if fd >= 0:
                    os.close(fd)
                tmp_path.unlink(missing_ok=True)
                raise
            # Rename is atomic on POSIX (same device guaranteed by mkstemp dir).
            tmp_path.rename(target_dir / safe_key)
        except ProviderError:
            raise
        except OSError as exc:
            raise ProviderError(
                f"Failed to write {namespace_label} '{key}' to {target_dir}: {exc}"
            ) from exc

    def rotate_secret(self, key: str, new_value: str) -> str:
        raise ProviderError(
            "Docker Secrets does not support rotation. "
            "Update the secret via Docker/Podman and restart the container."
        )

    def revoke_token(self, key: str) -> None:
        raise ProviderError(
            "Docker Secrets does not support token revocation."
        )

    def list_secrets(self, prefix: Optional[str] = None) -> list[SecretMetadata]:
        if not self._secrets_dir.exists():
            raise ProviderError(f"Secrets directory '{self._secrets_dir}' does not exist")
        try:
            entries = []
            for path in self._secrets_dir.iterdir():
                if path.is_file():
                    name = path.name
                    if prefix and not name.startswith(prefix):
                        continue
                    stat_info = path.stat()
                    entries.append(SecretMetadata(
                        key=name,
                        version="docker-static",
                        created_at=_format_ts(stat_info.st_ctime),
                        last_rotated_at=None,
                        expires_at=None,
                    ))
            # Also list runtime-set cloud keys (from cloud_keys_dir) and
            # runtime-minted crypto-shred KEKs (from cryptoshred_keys_dir).
            # Names only — no key material is ever included in list_secrets().
            for rw_dir, version_label in (
                (self._cloud_keys_dir, "docker-runtime"),
                (self._cryptoshred_keys_dir, "docker-runtime-cryptoshred"),
            ):
                if rw_dir is None or not rw_dir.exists():
                    continue
                existing_names = {e.key for e in entries}
                for path in rw_dir.iterdir():
                    if path.is_file() and not path.name.startswith("."):
                        name = path.name
                        if name in existing_names:
                            continue  # already listed
                        if prefix and not name.startswith(prefix):
                            continue
                        stat_info = path.stat()
                        entries.append(SecretMetadata(
                            key=name,
                            version=version_label,
                            created_at=_format_ts(stat_info.st_ctime),
                            last_rotated_at=_format_ts(stat_info.st_mtime),
                            expires_at=None,
                        ))
            return entries
        except OSError as exc:
            raise ProviderError(f"Failed to list secrets: {exc}") from exc

    def delete_secret(self, key: str) -> None:
        raise ProviderError(
            "Docker Secrets does not support programmatic deletion. "
            "Remove the secret via Docker/Podman configuration."
        )

    def health_check(self) -> bool:
        try:
            ro_ok = self._secrets_dir.exists() and os.access(self._secrets_dir, os.R_OK)
            if not ro_ok:
                return False
            for rw_dir in (self._cloud_keys_dir, self._cryptoshred_keys_dir):
                if rw_dir is not None:
                    rw_ok = rw_dir.exists() and os.access(rw_dir, os.R_OK | os.W_OK)
                    if not rw_ok:
                        return False
            return True
        except Exception:
            return False

    @property
    def provider_name(self) -> str:
        return "docker"

    @property
    def environment_scope(self) -> str:
        return self._environment_scope

    # -- Helpers -------------------------------------------------------------

    @staticmethod
    def _safe_filename(key: str) -> str:
        """Strip scope prefix for filesystem lookup and sanitise path traversal."""
        name = key.split("/", 1)[-1] if "/" in key else key
        # Reject any path traversal attempt
        if ".." in name or "/" in name or "\\" in name:
            raise ProviderError(f"Invalid secret key: '{key}'")
        return name


def _format_ts(unix_ts: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(
        unix_ts, tz=datetime.timezone.utc
    ).isoformat()
