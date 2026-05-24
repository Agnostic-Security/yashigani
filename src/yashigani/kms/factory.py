"""
Yashigani KMS — Provider factory.
Selects and instantiates the correct KMSProvider based on environment variables.
"""
from __future__ import annotations

import logging
import os

from yashigani.kms.base import KSMProvider, ProviderError

_log = logging.getLogger(__name__)

_PROVIDER_MAP: dict[str, str] = {
    "keeper": "yashigani.kms.providers.keeper.KeeperKSMProvider",
    "docker": "yashigani.kms.providers.docker_secrets.DockerSecretsProvider",
    "aws":    "yashigani.kms.providers.aws.AWSSecretsManagerProvider",
    "azure":  "yashigani.kms.providers.azure.AzureKeyVaultProvider",
    "gcp":    "yashigani.kms.providers.gcp.GCPSecretManagerProvider",
    "vault":  "yashigani.kms.providers.vault.VaultKMSProvider",
}

_DEV_ENVS = {"dev", "development", "local", "test", "demo"}

# LIC-001 / LAURA-LICENSE-05: explicit allowlist of normalised YASHIGANI_ENV
# values.  Anything outside this set is rejected at startup so that typos or
# injected garbage strings (e.g. "Dev", "DEVELOPMENT", "prod", "0") can never
# accidentally match the "dev" branch and skip license integrity checks.
_VALID_ENV_VALUES = {"dev", "staging", "production"}


def _resolve_provider_env(default_provider: str) -> str:
    """
    Resolve the KMS provider name from environment variables.

    Canonical variable: YASHIGANI_KMS_PROVIDER
    Deprecated alias:   YASHIGANI_KSM_PROVIDER  (note: K-S-M, not K-M-S)

    Resolution order:
    1. If YASHIGANI_KMS_PROVIDER is set — use it (canonical).
       If YASHIGANI_KSM_PROVIDER is also set and differs — log a warning.
    2. Else if YASHIGANI_KSM_PROVIDER is set — use it and log a deprecation
       warning. Removal scheduled for v2.26.0.
    3. Else — use *default_provider*.
    """
    kms = os.environ.get("YASHIGANI_KMS_PROVIDER", "").strip().lower()
    ksm = os.environ.get("YASHIGANI_KSM_PROVIDER", "").strip().lower()

    if kms:
        if ksm and ksm != kms:
            _log.warning(
                "Both YASHIGANI_KMS_PROVIDER=%r and the deprecated "
                "YASHIGANI_KSM_PROVIDER=%r are set with different values. "
                "YASHIGANI_KMS_PROVIDER takes precedence. "
                "Remove YASHIGANI_KSM_PROVIDER to silence this warning.",
                kms,
                ksm,
            )
        elif ksm:
            _log.warning(
                "Both YASHIGANI_KMS_PROVIDER=%r and the deprecated "
                "YASHIGANI_KSM_PROVIDER=%r are set with the same value. "
                "Remove YASHIGANI_KSM_PROVIDER to silence this warning.",
                kms,
                ksm,
            )
        return kms

    if ksm:
        _log.warning(
            "YASHIGANI_KSM_PROVIDER is deprecated; rename it to "
            "YASHIGANI_KMS_PROVIDER. Support for the old name will be "
            "removed in v2.26.0.",
        )
        return ksm

    return default_provider


def create_provider() -> KSMProvider:
    """
    Instantiate and return a KMSProvider based on environment variables.

    YASHIGANI_KMS_PROVIDER  — provider name (default: 'keeper', or 'docker'
                               when YASHIGANI_ENV is dev/local/test).
                               The old name YASHIGANI_KSM_PROVIDER is
                               accepted with a deprecation warning.
    YASHIGANI_ENV           — environment scope label (required).
                              Permitted values: dev | staging | production.
                              Any other value is rejected at startup (LIC-001).
    """
    env_scope = os.environ.get("YASHIGANI_ENV", "").strip()
    if not env_scope:
        raise ProviderError(
            "YASHIGANI_ENV environment variable is required and must not be empty. "
            "Set it to e.g. 'production', 'staging', or 'dev'."
        )

    # LIC-001 / LAURA-LICENSE-05: normalise + validate against explicit allowlist.
    # Fail-closed: an unrecognised value is never treated as "dev" accidentally.
    env_scope_normalised = env_scope.lower()
    if env_scope_normalised not in _VALID_ENV_VALUES:
        raise ProviderError(
            f"YASHIGANI_ENV value '{env_scope}' is not in the permitted set "
            f"{sorted(_VALID_ENV_VALUES)}. Correct the value and restart."
        )
    env_scope = env_scope_normalised

    default_provider = "docker" if env_scope in _DEV_ENVS else "keeper"
    provider_name = _resolve_provider_env(default_provider)

    if provider_name not in _PROVIDER_MAP:
        raise ProviderError(
            f"Unknown KMS provider '{provider_name}'. "
            f"Valid values: {', '.join(sorted(_PROVIDER_MAP))}"
        )

    cls = _load_class(_PROVIDER_MAP[provider_name])
    instance: KSMProvider = cls(environment_scope=env_scope)

    if instance.provider_name != provider_name:
        raise ProviderError(
            f"Provider reported name '{instance.provider_name}' "
            f"but factory expected '{provider_name}'"
        )
    if not instance.environment_scope:
        raise ProviderError("Provider returned an empty environment_scope")

    return instance


def _load_class(dotted_path: str):
    """Lazily import a class by dotted module path."""
    module_path, class_name = dotted_path.rsplit(".", 1)
    import importlib
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name, None)
    if cls is None:
        raise ProviderError(f"Class '{class_name}' not found in module '{module_path}'")
    return cls
