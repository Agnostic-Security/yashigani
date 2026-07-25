"""
YSG-GATE-V50-C — audit crypto-shred fails to seal on every admin mutation in
docker-secrets deployment mode.

Case determination: crypto_shred_enabled defaults True in EVERY deployment
mode (audit/config.py — a documented privacy control, not an opt-in feature,
unlike db_sink_enabled), and both docker-compose.yml and the Helm chart
default YASHIGANI_KMS_PROVIDER=docker. Therefore crypto-shred sealing is
SUPPOSED to work under the docker-secrets provider (Case A), not
cloud-KMS-only by design. The bug was that CryptoShredKeyStore._get_or_create_kek
tries KSMProvider.set_secret("cryptoshred:kek:<tenant>", ...) to mint the
per-tenant KEK, but DockerSecretsProvider treated every key as a read-only
install-managed secret except an explicit cloud-key allowlist — so minting
always raised ProviderError, which Shredder.seal() catches and logs as a
per-mutation ERROR (never a startup-time decision, hence the spam).

Fix: DockerSecretsProvider gained a second writable namespace
(cryptoshred_keys_dir, gated on a "cryptoshred:kek:" prefix match, physically
separate from cloud_keys_dir) mirroring the pre-existing cloud-key write
mechanism. These tests verify the fix end-to-end through
CryptoShredKeyStore + Shredder (the actual caller), not just the provider
in isolation.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from yashigani.audit.crypto_shred import CryptoShredKeyStore, Shredder, is_envelope
from yashigani.audit.schema import AdminLoginEvent
from yashigani.kms.base import ProviderError
from yashigani.kms.factory import create_provider
from yashigani.kms.providers.docker_secrets import DockerSecretsProvider


def _make_provider(tmp_path: Path, with_kek_dir: bool = True) -> DockerSecretsProvider:
    ro_dir = tmp_path / "secrets"
    ro_dir.mkdir()
    kek_dir = None
    if with_kek_dir:
        kek_dir = tmp_path / "cryptoshred-keys"
        kek_dir.mkdir()
    return DockerSecretsProvider(
        environment_scope="dev",
        secrets_dir=ro_dir,
        cloud_keys_dir=None,
        cryptoshred_keys_dir=kek_dir,
    )


def _admin_event(admin_account: str = "alice@example.com") -> AdminLoginEvent:
    return AdminLoginEvent(admin_account=admin_account, outcome="success")


class TestCryptoShredSealsUnderDockerSecrets:
    """Case A: sealing must succeed under the docker-secrets KMS provider."""

    def test_seal_succeeds_with_writable_kek_namespace(self, tmp_path, mock_redis):
        provider = _make_provider(tmp_path)
        key_store = CryptoShredKeyStore(mock_redis, provider, dsn=None)
        shredder = Shredder(key_store)

        event = _admin_event()
        sealed = shredder.seal(event)

        assert is_envelope(sealed.admin_account), (
            "admin_account was not sealed — reproduces YSG-GATE-V50-C if this fails"
        )

    def test_seal_mints_kek_file_on_disk_with_0600(self, tmp_path, mock_redis):
        provider = _make_provider(tmp_path)
        key_store = CryptoShredKeyStore(mock_redis, provider, dsn=None)
        Shredder(key_store).seal(_admin_event())

        kek_dir = provider._cryptoshred_keys_dir
        kek_files = list(kek_dir.iterdir())
        assert len(kek_files) == 1
        assert kek_files[0].name == "cryptoshred:kek:default"
        mode = kek_files[0].stat().st_mode & 0o777
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_kek_persists_across_key_store_restart(self, tmp_path, mock_redis):
        """Simulates a container restart: a fresh CryptoShredKeyStore pointed at
        the same on-disk KEK dir + same Redis DEK store must unseal what the
        first instance sealed — the KEK must not be re-minted per-process."""
        provider = _make_provider(tmp_path)

        key_store_1 = CryptoShredKeyStore(mock_redis, provider, dsn=None)
        shredder_1 = Shredder(key_store_1)
        event = _admin_event("bob@example.com")
        sealed = shredder_1.seal(event)
        sealed_value = sealed.admin_account

        # Fresh KeyStore/Shredder — same provider + same Redis (persistence
        # across the KEK cache being empty, i.e. after a restart).
        key_store_2 = CryptoShredKeyStore(mock_redis, provider, dsn=None)
        shredder_2 = Shredder(key_store_2)
        unsealed = shredder_2.unseal_value("default", sealed_value, "admin_account")

        assert unsealed == "bob@example.com"

    def test_kek_reused_not_reminted_across_two_provider_instances(self, tmp_path, mock_redis):
        """Two separate provider instances sharing the same cryptoshred_keys_dir
        (gateway process + backoffice process both reading the same bind-mounted
        host path) must resolve to the identical KEK bytes."""
        ro_dir = tmp_path / "secrets"
        ro_dir.mkdir()
        kek_dir = tmp_path / "cryptoshred-keys"
        kek_dir.mkdir()

        provider_a = DockerSecretsProvider(
            environment_scope="dev", secrets_dir=ro_dir, cryptoshred_keys_dir=kek_dir
        )
        provider_b = DockerSecretsProvider(
            environment_scope="dev", secrets_dir=ro_dir, cryptoshred_keys_dir=kek_dir
        )

        store_a = CryptoShredKeyStore(mock_redis, provider_a, dsn=None)
        store_b = CryptoShredKeyStore(mock_redis, provider_b, dsn=None)

        kek_a = store_a._get_or_create_kek("default")
        kek_b = store_b._get_or_create_kek("default")

        assert kek_a == kek_b, "second process minted a DIFFERENT KEK instead of reusing it"

    def test_seal_does_not_log_error_when_kek_dir_configured(self, tmp_path, mock_redis, caplog):
        import logging

        provider = _make_provider(tmp_path)
        key_store = CryptoShredKeyStore(mock_redis, provider, dsn=None)
        shredder = Shredder(key_store)

        with caplog.at_level(logging.ERROR, logger="yashigani.audit.crypto_shred"):
            shredder.seal(_admin_event())

        assert "seal failed" not in caplog.text


class TestInstallManagedSecretsStillReadOnly:
    """The KEK write path must not weaken the read-only guarantee for
    install-managed secrets (PKI, passwords, tokens, bearer)."""

    def test_postgres_password_still_read_only(self, tmp_path):
        provider = _make_provider(tmp_path)
        with pytest.raises(ProviderError, match="read-only"):
            provider.set_secret("postgres_password", "newpw")

    def test_ca_root_still_read_only(self, tmp_path):
        provider = _make_provider(tmp_path)
        with pytest.raises(ProviderError, match="read-only"):
            provider.set_secret("ca_root.crt", "fake-cert")

    def test_internal_bearer_still_read_only(self, tmp_path):
        provider = _make_provider(tmp_path)
        with pytest.raises(ProviderError, match="read-only"):
            provider.set_secret("yashigani_internal_bearer", "fake-bearer")

    def test_cloud_key_namespace_unaffected_by_kek_namespace(self, tmp_path):
        """cloud_keys_dir is None in _make_provider (only cryptoshred_keys_dir
        is configured) — a cloud-key-shaped key must still be routed to the
        cloud-key branch (and correctly rejected as unconfigured there), NOT
        silently accepted via the KEK namespace (namespaces stay separate)."""
        provider = _make_provider(tmp_path)
        with pytest.raises(ProviderError, match="cloud-keys directory is not configured"):
            provider.set_secret("openai_api_key", "sk-x")

    def test_kek_key_rejected_when_only_cloud_keys_dir_configured(self, tmp_path):
        """The inverse: cryptoshred_keys_dir is None (only cloud_keys_dir is
        configured) — a KEK-shaped key must NOT fall through to the cloud-key
        write path."""
        ro_dir = tmp_path / "ro"
        cloud_dir = tmp_path / "cloud"
        ro_dir.mkdir()
        cloud_dir.mkdir()
        provider = DockerSecretsProvider(
            environment_scope="dev", secrets_dir=ro_dir, cloud_keys_dir=cloud_dir
        )
        with pytest.raises(ProviderError, match="crypto-shred-keys directory is not configured"):
            provider.set_secret("cryptoshred:kek:default", "x" * 44)


class TestCryptoShredKekNamespaceProvider:
    """Provider-level unit tests for the new writable KEK namespace."""

    def test_get_secret_prefers_kek_dir_over_ro_secrets(self, tmp_path):
        ro_dir = tmp_path / "ro"
        kek_dir = tmp_path / "kek"
        ro_dir.mkdir()
        kek_dir.mkdir()
        (ro_dir / "cryptoshred:kek:default").write_text("ro-value", encoding="utf-8")
        (kek_dir / "cryptoshred:kek:default").write_text("rw-value", encoding="utf-8")

        provider = DockerSecretsProvider(
            environment_scope="dev", secrets_dir=ro_dir, cryptoshred_keys_dir=kek_dir
        )
        assert provider.get_secret("cryptoshred:kek:default") == "rw-value"

    def test_set_secret_raises_when_kek_dir_not_configured(self, tmp_path):
        provider = _make_provider(tmp_path, with_kek_dir=False)
        with pytest.raises(ProviderError, match="crypto-shred-keys directory is not configured"):
            provider.set_secret("cryptoshred:kek:default", base64.b64encode(b"x" * 32).decode())

    def test_set_secret_raises_when_kek_dir_missing_on_disk(self, tmp_path):
        ro_dir = tmp_path / "ro"
        ro_dir.mkdir()
        missing_kek_dir = tmp_path / "nonexistent-kek-dir"
        provider = DockerSecretsProvider(
            environment_scope="dev", secrets_dir=ro_dir, cryptoshred_keys_dir=missing_kek_dir
        )
        with pytest.raises(ProviderError, match="does not exist"):
            provider.set_secret("cryptoshred:kek:default", "x")

    def test_set_secret_path_traversal_rejected_for_kek_key(self, tmp_path):
        provider = _make_provider(tmp_path)
        with pytest.raises(ProviderError):
            provider.set_secret("cryptoshred:kek:../../etc/passwd", "evil")

    def test_health_check_requires_kek_dir_writable_when_configured(self, tmp_path):
        ro_dir = tmp_path / "ro"
        ro_dir.mkdir()
        missing_kek_dir = tmp_path / "nonexistent"
        provider = DockerSecretsProvider(
            environment_scope="dev", secrets_dir=ro_dir, cryptoshred_keys_dir=missing_kek_dir
        )
        assert provider.health_check() is False

    def test_health_check_passes_with_both_namespaces_writable(self, tmp_path):
        provider = _make_provider(tmp_path)
        assert provider.health_check() is True

    def test_list_secrets_includes_kek_entries_with_dedicated_version_label(self, tmp_path):
        provider = _make_provider(tmp_path)
        provider.set_secret("cryptoshred:kek:default", base64.b64encode(b"y" * 32).decode())
        entries = {e.key: e for e in provider.list_secrets()}
        assert "cryptoshred:kek:default" in entries
        assert entries["cryptoshred:kek:default"].version == "docker-runtime-cryptoshred"


class TestFactoryWiresCryptoShredKeksDir:
    def test_factory_passes_cryptoshred_keys_dir_env_var(self, tmp_path, monkeypatch):
        kek_dir = tmp_path / "cryptoshred-keys"
        kek_dir.mkdir()
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_KMS_PROVIDER", "docker")
        monkeypatch.delenv("YASHIGANI_KSM_PROVIDER", raising=False)
        monkeypatch.delenv("YASHIGANI_CLOUD_KEYS_DIR", raising=False)
        monkeypatch.setenv("YASHIGANI_CRYPTO_SHRED_KEKS_DIR", str(kek_dir))

        provider = create_provider()
        assert isinstance(provider, DockerSecretsProvider)
        assert provider._cryptoshred_keys_dir == kek_dir

    def test_factory_no_env_var_gives_none(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_ENV", "dev")
        monkeypatch.setenv("YASHIGANI_KMS_PROVIDER", "docker")
        monkeypatch.delenv("YASHIGANI_KSM_PROVIDER", raising=False)
        monkeypatch.delenv("YASHIGANI_CRYPTO_SHRED_KEKS_DIR", raising=False)

        provider = create_provider()
        assert isinstance(provider, DockerSecretsProvider)
        assert provider._cryptoshred_keys_dir is None


class TestPreFixBehaviourReproduced:
    """Documents the exact pre-fix failure mode (no cryptoshred_keys_dir
    configured) so a future regression re-fails this test rather than the
    live e2e finding."""

    def test_seal_without_kek_dir_logs_error_reproducing_original_finding(
        self, tmp_path, mock_redis, caplog
    ):
        import logging

        provider = _make_provider(tmp_path, with_kek_dir=False)
        key_store = CryptoShredKeyStore(mock_redis, provider, dsn=None)
        shredder = Shredder(key_store)

        with caplog.at_level(logging.ERROR, logger="yashigani.audit.crypto_shred"):
            sealed = shredder.seal(_admin_event())

        # Fail-open-safe by design: the event is never dropped, but the field
        # stays cleartext and an ERROR is logged — this IS the finding's
        # symptom when no writable KEK namespace is configured.
        assert not is_envelope(sealed.admin_account)
        assert "seal failed" in caplog.text
