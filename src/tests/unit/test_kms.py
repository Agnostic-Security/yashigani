"""
Unit tests for the Yashigani KMS module.
"""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from yashigani.kms.base import (
    KSMProvider,
    KeyNotFoundError,
    ProviderError,
    RotationError,
    ScopeViolationError,
    SecretMetadata,
)
from yashigani.kms.providers.docker_secrets import DockerSecretsProvider
from yashigani.kms.factory import create_provider, _resolve_provider_env
from yashigani.kms.rotation import KSMRotationScheduler, _validate_cron


# ---------------------------------------------------------------------------
# DockerSecretsProvider
# ---------------------------------------------------------------------------

class TestDockerSecretsProvider:
    def _make_provider(self, tmp_path: Path) -> DockerSecretsProvider:
        return DockerSecretsProvider(
            environment_scope="dev",
            secrets_dir=tmp_path,
        )

    def test_get_secret_success(self, tmp_path):
        (tmp_path / "mykey").write_text("s3cr3t\n", encoding="utf-8")
        provider = self._make_provider(tmp_path)
        assert provider.get_secret("mykey") == "s3cr3t"

    def test_get_secret_strips_scope_prefix(self, tmp_path):
        (tmp_path / "mykey").write_text("value", encoding="utf-8")
        provider = self._make_provider(tmp_path)
        assert provider.get_secret("dev/mykey") == "value"

    def test_get_secret_not_found(self, tmp_path):
        provider = self._make_provider(tmp_path)
        with pytest.raises(KeyNotFoundError):
            provider.get_secret("missing")

    def test_scope_violation(self, tmp_path):
        provider = self._make_provider(tmp_path)
        with pytest.raises(ScopeViolationError):
            provider.get_secret("production/secret")

    def test_set_secret_raises(self, tmp_path):
        provider = self._make_provider(tmp_path)
        with pytest.raises(ProviderError):
            provider.set_secret("k", "v")

    def test_rotate_raises(self, tmp_path):
        provider = self._make_provider(tmp_path)
        with pytest.raises(ProviderError):
            provider.rotate_secret("k", "v")

    def test_revoke_raises(self, tmp_path):
        provider = self._make_provider(tmp_path)
        with pytest.raises(ProviderError):
            provider.revoke_token("k")

    def test_health_check_exists(self, tmp_path):
        provider = self._make_provider(tmp_path)
        assert provider.health_check() is True

    def test_health_check_missing(self, tmp_path):
        provider = DockerSecretsProvider(
            environment_scope="dev",
            secrets_dir=tmp_path / "nonexistent",
        )
        assert provider.health_check() is False

    def test_list_secrets(self, tmp_path):
        (tmp_path / "alpha").write_text("a", encoding="utf-8")
        (tmp_path / "beta").write_text("b", encoding="utf-8")
        provider = self._make_provider(tmp_path)
        names = {m.key for m in provider.list_secrets()}
        assert names == {"alpha", "beta"}

    def test_list_secrets_with_prefix(self, tmp_path):
        (tmp_path / "alpha").write_text("a", encoding="utf-8")
        (tmp_path / "beta").write_text("b", encoding="utf-8")
        provider = self._make_provider(tmp_path)
        names = {m.key for m in provider.list_secrets(prefix="al")}
        assert names == {"alpha"}

    def test_path_traversal_rejected(self, tmp_path):
        provider = self._make_provider(tmp_path)
        with pytest.raises(ProviderError):
            provider.get_secret("../etc/passwd")

    def test_provider_name(self, tmp_path):
        provider = self._make_provider(tmp_path)
        assert provider.provider_name == "docker"

    def test_environment_scope(self, tmp_path):
        provider = self._make_provider(tmp_path)
        assert provider.environment_scope == "dev"


# ---------------------------------------------------------------------------
# KSMProviderFactory
# ---------------------------------------------------------------------------

class TestKMSProviderFactory:
    def _docker_patches(self):
        """Context manager that stubs out DockerSecretsProvider construction."""
        return (
            patch(
                "yashigani.kms.providers.docker_secrets.DockerSecretsProvider.__init__",
                return_value=None,
            ),
            patch.object(
                DockerSecretsProvider,
                "provider_name",
                new_callable=lambda: property(lambda self: "docker"),
            ),
            patch.object(
                DockerSecretsProvider,
                "environment_scope",
                new_callable=lambda: property(lambda self: "dev"),
            ),
        )

    def test_selects_docker_via_canonical_kms_provider(self, monkeypatch):
        """YASHIGANI_KMS_PROVIDER=docker loads docker provider — canonical name."""
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_KMS_PROVIDER", "docker")
        monkeypatch.delenv("YASHIGANI_KSM_PROVIDER", raising=False)
        p1, p2, p3 = self._docker_patches()
        with p1, p2, p3:
            provider = create_provider()
        assert provider.provider_name == "docker"

    def test_selects_docker_via_deprecated_ksm_provider(self, monkeypatch, caplog):
        """YASHIGANI_KSM_PROVIDER=docker loads docker provider + emits deprecation warning."""
        import logging
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.delenv("YASHIGANI_KMS_PROVIDER", raising=False)
        monkeypatch.setenv("YASHIGANI_KSM_PROVIDER", "docker")
        p1, p2, p3 = self._docker_patches()
        with caplog.at_level(logging.WARNING, logger="yashigani.kms.factory"):
            with p1, p2, p3:
                provider = create_provider()
        assert provider.provider_name == "docker"
        assert "YASHIGANI_KSM_PROVIDER is deprecated" in caplog.text
        assert "YASHIGANI_KMS_PROVIDER" in caplog.text

    def test_kms_wins_over_ksm_when_both_set_different_values(self, monkeypatch, caplog):
        """When both are set with different values, KMS_PROVIDER wins + warning emitted."""
        import logging
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_KMS_PROVIDER", "docker")
        monkeypatch.setenv("YASHIGANI_KSM_PROVIDER", "vault")
        p1, p2, p3 = self._docker_patches()
        with caplog.at_level(logging.WARNING, logger="yashigani.kms.factory"):
            with p1, p2, p3:
                provider = create_provider()
        assert provider.provider_name == "docker"
        assert "YASHIGANI_KMS_PROVIDER" in caplog.text
        assert "YASHIGANI_KSM_PROVIDER" in caplog.text

    def test_neither_set_uses_default(self, monkeypatch):
        """Setting neither KMS_PROVIDER nor KSM_PROVIDER falls back to default (docker for dev)."""
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.delenv("YASHIGANI_KMS_PROVIDER", raising=False)
        monkeypatch.delenv("YASHIGANI_KSM_PROVIDER", raising=False)
        p1, p2, p3 = self._docker_patches()
        with p1, p2, p3:
            provider = create_provider()
        assert provider.provider_name == "docker"

    def test_missing_env_raises(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_ENV", raising=False)
        with pytest.raises(ProviderError, match="YASHIGANI_ENV"):
            create_provider()

    def test_unknown_provider_raises(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_KMS_PROVIDER", "nonexistent")
        monkeypatch.delenv("YASHIGANI_KSM_PROVIDER", raising=False)
        with pytest.raises(ProviderError, match="Unknown KMS provider"):
            create_provider()


# ---------------------------------------------------------------------------
# _resolve_provider_env unit tests (white-box coverage of the shim logic)
# ---------------------------------------------------------------------------

class TestResolveProviderEnv:
    def test_canonical_only(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_KMS_PROVIDER", "vault")
        monkeypatch.delenv("YASHIGANI_KSM_PROVIDER", raising=False)
        assert _resolve_provider_env("docker") == "vault"

    def test_deprecated_only_returns_value(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_KMS_PROVIDER", raising=False)
        monkeypatch.setenv("YASHIGANI_KSM_PROVIDER", "aws")
        assert _resolve_provider_env("docker") == "aws"

    def test_both_same_value_canonical_wins(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_KMS_PROVIDER", "gcp")
        monkeypatch.setenv("YASHIGANI_KSM_PROVIDER", "gcp")
        assert _resolve_provider_env("docker") == "gcp"

    def test_both_different_canonical_wins(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_KMS_PROVIDER", "azure")
        monkeypatch.setenv("YASHIGANI_KSM_PROVIDER", "vault")
        assert _resolve_provider_env("docker") == "azure"

    def test_neither_returns_default(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_KMS_PROVIDER", raising=False)
        monkeypatch.delenv("YASHIGANI_KSM_PROVIDER", raising=False)
        assert _resolve_provider_env("keeper") == "keeper"


# ---------------------------------------------------------------------------
# ScopeViolationError enforcement
# ---------------------------------------------------------------------------

class TestScopeViolation:
    def test_mismatched_prefix_raises(self, tmp_path):
        provider = DockerSecretsProvider(environment_scope="dev", secrets_dir=tmp_path)
        with pytest.raises(ScopeViolationError):
            provider._check_scope("production/secret")

    def test_matching_prefix_passes(self, tmp_path):
        provider = DockerSecretsProvider(environment_scope="dev", secrets_dir=tmp_path)
        provider._check_scope("dev/secret")  # should not raise

    def test_no_prefix_passes(self, tmp_path):
        provider = DockerSecretsProvider(environment_scope="dev", secrets_dir=tmp_path)
        provider._check_scope("plainsecret")  # should not raise


# ---------------------------------------------------------------------------
# KSMRotationScheduler
# ---------------------------------------------------------------------------

class _MockProvider(KSMProvider):
    def __init__(self, scope: str = "dev"):
        self._scope = scope
        self.rotate_calls: list[tuple[str, str]] = []
        self.get_calls: list[str] = []
        self._stored: dict[str, str] = {}
        self.fail_rotate = False

    def get_secret(self, key: str) -> str:
        self.get_calls.append(key)
        if key not in self._stored:
            raise KeyNotFoundError(key)
        return self._stored[key]

    def set_secret(self, key: str, value: str) -> None:
        self._stored[key] = value

    def rotate_secret(self, key: str, new_value: str) -> str:
        if self.fail_rotate:
            raise RotationError("Simulated failure")
        self.rotate_calls.append((key, new_value))
        self._stored[key] = new_value
        return "v2"

    def revoke_token(self, key: str) -> None:
        pass

    def list_secrets(self, prefix=None):
        return []

    def delete_secret(self, key: str) -> None:
        pass

    def health_check(self) -> bool:
        return True

    @property
    def provider_name(self) -> str:
        return "mock"

    @property
    def environment_scope(self) -> str:
        return self._scope


class TestKSMRotationScheduler:
    def test_validate_cron_rejects_too_frequent(self):
        with pytest.raises(ValueError, match="frequently"):
            _validate_cron("* * * * *")  # every minute

    def test_validate_cron_accepts_hourly(self):
        _validate_cron("0 * * * *")  # every hour — should pass

    def test_trigger_now_rotates(self):
        provider = _MockProvider()
        provider._stored["dev/key"] = "old"
        events: list[tuple] = []
        scheduler = KSMRotationScheduler(
            provider=provider,
            secret_key="dev/key",
            cron_expr="0 2 * * *",
            on_event=lambda name, data: events.append((name, data)),
        )
        scheduler.trigger_now()
        assert len(provider.rotate_calls) == 1
        assert any(e[0] == "KSM_ROTATION_SUCCESS" for e in events)

    def test_rotation_lock_prevents_concurrent(self):
        provider = _MockProvider()
        provider._stored["dev/key"] = "old"
        scheduler = KSMRotationScheduler(
            provider=provider,
            secret_key="dev/key",
            cron_expr="0 2 * * *",
        )
        # Acquire lock manually to simulate in-progress rotation
        scheduler._lock.acquire()
        scheduler._rotate(rotation_type="manual")
        scheduler._lock.release()
        # Lock was held, so rotation should have been skipped
        assert len(provider.rotate_calls) == 0

    def test_retry_on_failure_emits_critical(self):
        provider = _MockProvider()
        provider._stored["dev/key"] = "old"
        provider.fail_rotate = True
        events: list[tuple] = []

        # Patch retry delays to zero for speed
        import yashigani.kms.rotation as rot_module
        original_delays = rot_module._RETRY_DELAYS_SECONDS
        rot_module._RETRY_DELAYS_SECONDS = [0, 0, 0]
        try:
            scheduler = KSMRotationScheduler(
                provider=provider,
                secret_key="dev/key",
                cron_expr="0 2 * * *",
                on_event=lambda name, data: events.append((name, data)),
            )
            scheduler._rotate_with_retry()
        finally:
            rot_module._RETRY_DELAYS_SECONDS = original_delays

        assert any(e[0] == "KSM_ROTATION_CRITICAL" for e in events)

    def test_set_schedule_rejects_invalid(self):
        provider = _MockProvider()
        provider._stored["dev/key"] = "old"
        scheduler = KSMRotationScheduler(
            provider=provider,
            secret_key="dev/key",
            cron_expr="0 2 * * *",
        )
        with pytest.raises(ValueError):
            scheduler.set_schedule("not-a-cron")

    def test_set_schedule_rejects_too_frequent(self):
        provider = _MockProvider()
        provider._stored["dev/key"] = "old"
        scheduler = KSMRotationScheduler(
            provider=provider,
            secret_key="dev/key",
            cron_expr="0 2 * * *",
        )
        with pytest.raises(ValueError, match="frequently"):
            scheduler.set_schedule("*/30 * * * *")  # every 30 min


# ---------------------------------------------------------------------------
# DockerSecretsProvider — cloud-key write support (demo/free tier)
# ---------------------------------------------------------------------------

class TestDockerSecretsProviderCloudKeys:
    """Tests for the writable cloud-keys extension (Tiago directive).

    Verifies:
    1. set_secret writes atomically (0600) for cloud keys.
    2. get_secret returns the runtime-set value (cloud_keys_dir first).
    3. get_secret falls back to read-only /run/secrets when cloud_keys_dir
       has no entry (pre-seeded key scenario).
    4. set_secret refuses non-cloud keys (install-managed secrets stay RO).
    5. set_secret raises when cloud_keys_dir is None.
    6. set_secret raises when cloud_keys_dir does not exist.
    7. Path-traversal is still rejected on both get and set.
    8. health_check requires rw on cloud_keys_dir when configured.
    9. Factory wires cloud_keys_dir from YASHIGANI_CLOUD_KEYS_DIR env var.
    10. Gateway _get_cloud_api_key() flow: set → persists → get returns it.
    """

    def _make_provider(
        self,
        secrets_dir: Path,
        cloud_keys_dir: Path | None = None,
    ) -> DockerSecretsProvider:
        return DockerSecretsProvider(
            environment_scope="dev",
            secrets_dir=secrets_dir,
            cloud_keys_dir=cloud_keys_dir,
        )

    # --- set_secret (cloud key namespace) -----------------------------------

    def test_set_secret_cloud_key_writes_atomically(self, tmp_path):
        """set_secret for openai_api_key writes the file with mode 0600."""
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()

        provider = self._make_provider(ro_dir, cloud_keys_dir=rw_dir)
        provider.set_secret("openai_api_key", "sk-test-value-123")

        written = rw_dir / "openai_api_key"
        assert written.exists(), "key file not created"
        assert written.read_text(encoding="utf-8") == "sk-test-value-123"
        # CWE-732: mode must be 0600 (owner rw only)
        file_mode = written.stat().st_mode & 0o777
        assert file_mode == 0o600, f"expected 0600, got {oct(file_mode)}"

    def test_set_secret_anthropic_key_writes(self, tmp_path):
        """set_secret for anthropic_api_key also works."""
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()

        provider = self._make_provider(ro_dir, cloud_keys_dir=rw_dir)
        provider.set_secret("anthropic_api_key", "ant-key-456")

        written = rw_dir / "anthropic_api_key"
        assert written.exists()
        assert written.read_text(encoding="utf-8") == "ant-key-456"

    def test_set_secret_overwrites_existing_value(self, tmp_path):
        """set_secret can update an already-stored key."""
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()

        provider = self._make_provider(ro_dir, cloud_keys_dir=rw_dir)
        provider.set_secret("openai_api_key", "first-value")
        provider.set_secret("openai_api_key", "second-value")

        written = rw_dir / "openai_api_key"
        assert written.read_text(encoding="utf-8") == "second-value"
        assert (written.stat().st_mode & 0o777) == 0o600

    # --- get_secret resolution order ----------------------------------------

    def test_get_secret_prefers_cloud_keys_dir(self, tmp_path):
        """get_secret returns cloud_keys_dir value, not the /run/secrets one."""
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()
        # Both directories have the key — cloud_keys_dir wins.
        (ro_dir / "openai_api_key").write_text("ro-value", encoding="utf-8")
        (rw_dir / "openai_api_key").write_text("rw-value", encoding="utf-8")

        provider = self._make_provider(ro_dir, cloud_keys_dir=rw_dir)
        assert provider.get_secret("openai_api_key") == "rw-value"

    def test_get_secret_falls_back_to_ro_secrets(self, tmp_path):
        """get_secret uses /run/secrets when cloud_keys_dir has no entry (pre-seeded)."""
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()
        # Only the read-only mount has the key (pre-seeded by install.sh).
        (ro_dir / "openai_api_key").write_text("preseed-value\n", encoding="utf-8")

        provider = self._make_provider(ro_dir, cloud_keys_dir=rw_dir)
        assert provider.get_secret("openai_api_key") == "preseed-value"

    def test_get_secret_no_cloud_keys_dir_reads_ro(self, tmp_path):
        """When cloud_keys_dir is None, get_secret reads from secrets_dir only."""
        ro_dir = tmp_path / "ro"
        ro_dir.mkdir()
        (ro_dir / "openai_api_key").write_text("env-value", encoding="utf-8")

        provider = self._make_provider(ro_dir, cloud_keys_dir=None)
        assert provider.get_secret("openai_api_key") == "env-value"

    def test_set_then_get_round_trip(self, tmp_path):
        """Full round-trip: set via demo provider → get returns the stored value."""
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()

        provider = self._make_provider(ro_dir, cloud_keys_dir=rw_dir)
        provider.set_secret("openai_api_key", "sk-roundtrip-key")
        result = provider.get_secret("openai_api_key")
        assert result == "sk-roundtrip-key"

    # --- install-managed secrets remain read-only ---------------------------

    def test_set_secret_refuses_non_cloud_key(self, tmp_path):
        """set_secret on postgres_password or any non-cloud key raises ProviderError."""
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()

        provider = self._make_provider(ro_dir, cloud_keys_dir=rw_dir)
        with pytest.raises(ProviderError, match="not in the cloud-key namespace"):
            provider.set_secret("postgres_password", "newpw")

    def test_set_secret_refuses_internal_bearer(self, tmp_path):
        """internal_bearer is install-managed and must not be writable."""
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()

        provider = self._make_provider(ro_dir, cloud_keys_dir=rw_dir)
        with pytest.raises(ProviderError, match="not in the cloud-key namespace"):
            provider.set_secret("yashigani_internal_bearer", "fake-bearer")

    def test_set_secret_refuses_ca_root(self, tmp_path):
        """ca_root.crt is PKI material and must not be writable."""
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()

        provider = self._make_provider(ro_dir, cloud_keys_dir=rw_dir)
        with pytest.raises(ProviderError, match="not in the cloud-key namespace"):
            provider.set_secret("ca_root.crt", "fake-cert")

    # --- error conditions ---------------------------------------------------

    def test_set_secret_raises_when_no_cloud_keys_dir(self, tmp_path):
        """set_secret for a cloud key raises when cloud_keys_dir is None."""
        ro_dir = tmp_path / "ro"
        ro_dir.mkdir()

        provider = self._make_provider(ro_dir, cloud_keys_dir=None)
        with pytest.raises(ProviderError, match="cloud-keys directory is not configured"):
            provider.set_secret("openai_api_key", "sk-key")

    def test_set_secret_raises_when_dir_missing(self, tmp_path):
        """set_secret raises ProviderError when cloud_keys_dir does not exist."""
        ro_dir = tmp_path / "ro"
        ro_dir.mkdir()
        missing_rw = tmp_path / "nonexistent-cloud-keys"

        provider = self._make_provider(ro_dir, cloud_keys_dir=missing_rw)
        with pytest.raises(ProviderError, match="does not exist"):
            provider.set_secret("openai_api_key", "sk-key")

    # --- path-traversal safety ----------------------------------------------

    def test_set_secret_path_traversal_rejected(self, tmp_path):
        """Path-traversal via key name is rejected before any filesystem access."""
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()

        provider = self._make_provider(ro_dir, cloud_keys_dir=rw_dir)
        with pytest.raises(ProviderError):
            provider.set_secret("../etc/passwd", "evil")

    def test_get_secret_path_traversal_rejected_with_cloud_dir(self, tmp_path):
        """Path-traversal via get_secret is still rejected when cloud_keys_dir is set."""
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()

        provider = self._make_provider(ro_dir, cloud_keys_dir=rw_dir)
        with pytest.raises(ProviderError):
            provider.get_secret("../../etc/shadow")

    # --- health_check -------------------------------------------------------

    def test_health_check_passes_when_rw_dir_writable(self, tmp_path):
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()

        provider = self._make_provider(ro_dir, cloud_keys_dir=rw_dir)
        assert provider.health_check() is True

    def test_health_check_fails_when_rw_dir_missing(self, tmp_path):
        ro_dir = tmp_path / "ro"
        ro_dir.mkdir()
        missing_rw = tmp_path / "nonexistent"

        provider = self._make_provider(ro_dir, cloud_keys_dir=missing_rw)
        assert provider.health_check() is False

    # --- factory wiring -----------------------------------------------------

    def test_factory_passes_cloud_keys_dir_to_docker_provider(self, tmp_path, monkeypatch):
        """Factory reads YASHIGANI_CLOUD_KEYS_DIR and passes it to DockerSecretsProvider."""
        rw_dir = tmp_path / "cloud-keys"
        rw_dir.mkdir()

        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_KMS_PROVIDER", "docker")
        monkeypatch.delenv("YASHIGANI_KSM_PROVIDER", raising=False)
        monkeypatch.setenv("YASHIGANI_CLOUD_KEYS_DIR", str(rw_dir))

        provider = create_provider()
        assert isinstance(provider, DockerSecretsProvider)
        assert provider._cloud_keys_dir == rw_dir

    def test_factory_no_cloud_keys_dir_env_gives_none(self, monkeypatch):
        """When YASHIGANI_CLOUD_KEYS_DIR is unset, cloud_keys_dir is None."""
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_KMS_PROVIDER", "docker")
        monkeypatch.delenv("YASHIGANI_KSM_PROVIDER", raising=False)
        monkeypatch.delenv("YASHIGANI_CLOUD_KEYS_DIR", raising=False)

        provider = create_provider()
        assert isinstance(provider, DockerSecretsProvider)
        assert provider._cloud_keys_dir is None

    # --- list_secrets includes cloud_keys_dir entries -----------------------

    def test_list_secrets_includes_runtime_cloud_keys(self, tmp_path):
        """list_secrets enumerates keys from both dirs; cloud-dir entries get version='docker-runtime'."""
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()
        (ro_dir / "postgres_password").write_text("pgpw", encoding="utf-8")
        (rw_dir / "openai_api_key").write_text("sk-list-test", encoding="utf-8")

        provider = self._make_provider(ro_dir, cloud_keys_dir=rw_dir)
        meta = {m.key: m for m in provider.list_secrets()}
        assert "postgres_password" in meta
        assert meta["postgres_password"].version == "docker-static"
        assert "openai_api_key" in meta
        assert meta["openai_api_key"].version == "docker-runtime"

    # --- gateway _get_cloud_api_key() integration path ----------------------

    def test_gateway_resolves_cloud_key_after_set(self, tmp_path, monkeypatch):
        """
        Simulates the gateway _get_cloud_api_key() flow:
        1. Admin stores the key via DockerSecretsProvider.set_secret.
        2. Gateway calls kms_provider.get_secret("openai_api_key").
        3. The returned value matches what was stored.

        The gateway caches for 60 s, but this test exercises the KMS path
        directly (cache already expired or first call) to confirm the demo
        provider path is wired correctly.
        """
        ro_dir = tmp_path / "ro"
        rw_dir = tmp_path / "rw"
        ro_dir.mkdir()
        rw_dir.mkdir()

        # Simulates backoffice DockerSecretsProvider (write side).
        backoffice_provider = DockerSecretsProvider(
            environment_scope="dev",
            secrets_dir=ro_dir,
            cloud_keys_dir=rw_dir,
        )
        backoffice_provider.set_secret("openai_api_key", "sk-gateway-test-key")

        # Simulates gateway DockerSecretsProvider (read side, same host dir).
        gateway_provider = DockerSecretsProvider(
            environment_scope="dev",
            secrets_dir=ro_dir,
            cloud_keys_dir=rw_dir,
        )
        resolved = gateway_provider.get_secret("openai_api_key")
        assert resolved == "sk-gateway-test-key"
