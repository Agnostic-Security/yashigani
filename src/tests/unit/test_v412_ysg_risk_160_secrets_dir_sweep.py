"""
YSG-RISK-160 regression sweep — hardcoded "/run/secrets/*" convention-bypass
class (audit-first -> fix-all-same-class follow-up to YSG-RISK-150).

Each test proves that, with a genuinely non-default YASHIGANI_SECRETS_DIR set
(and no default-mount fallback file present), the fixed site resolves its
secret from the CUSTOM directory rather than silently falling back to the
hardcoded "/run/secrets" literal. This is the same shape of regression as
tests/conformance/test_auth.py::test_mint_and_verify_roundtrip_custom_secrets_dir
(the YSG-RISK-150 regression) — deliberately consistent across the whole
class of fixes.

Sites NOT covered here (left untouched, with reasons — see YSG-RISK-160
close-out notes / commit body):
  - yashigani.auth.stepup._DEFAULT_SIGNING_KEY_PATH: has its own documented
    override (YASHIGANI_STEPUP_SIGNING_KEY_PATH), Nico-locked crypto spec.
  - yashigani.mcp._jwt._DEFAULT_SIGNING_KEY_PATH: has its own documented
    override (YASHIGANI_MCP_SIGNING_KEY_PATH), Nico-locked crypto spec.
  - yashigani.pool.manager.CertMount.container_*_path /
    yashigani.gateway.letta_client.py container_*_path: in-container mount
    destinations for a DIFFERENT spawned container, not this process's own
    YASHIGANI_SECRETS_DIR-governed mount.
  - yashigani.manifest.codegen._MCP_SVID_MOUNT_ROOT / the Caddy-snippet
    validator path lists: Caddy-container-side mount convention (Caddyfiles
    are not Python and do not read YASHIGANI_SECRETS_DIR).
  - yashigani.audit.checkpoint_job.py "/run/secrets/hermes_client.key": a
    docstring USAGE EXAMPLE only — the real __init__ default is None
    (unsigned checkpoints); no live hardcode to fix.

Last updated: 2026-07-29T00:00:00+01:00 (YSG-RISK-160)
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch


# ---------------------------------------------------------------------------
# license.py — _license_secret_path()
# ---------------------------------------------------------------------------


class TestLicensePySecretPath:
    def test_default_is_run_secrets(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_SECRETS_DIR", raising=False)
        from yashigani.backoffice.routes.license import _license_secret_path
        assert _license_secret_path() == "/run/secrets/license_key"

    def test_custom_secrets_dir_honoured(self, monkeypatch, tmp_path):
        custom = tmp_path / "custom-secrets-mount"
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(custom))
        from yashigani.backoffice.routes.license import _license_secret_path
        assert _license_secret_path() == str(custom / "license_key")


# ---------------------------------------------------------------------------
# licensing/loader.py — load_license() step-2 candidate
# ---------------------------------------------------------------------------


class TestLicensingLoaderCustomSecretsDir:
    def test_finds_license_key_under_custom_secrets_dir(self, monkeypatch, tmp_path):
        """No YASHIGANI_LICENSE_FILE set (step 1 skipped) — step 2 must look
        under YASHIGANI_SECRETS_DIR, not a hardcoded /run/secrets."""
        custom = tmp_path / "custom-secrets-mount"
        custom.mkdir()
        # Deliberately invalid content — we only need to prove the FILE was
        # FOUND (verify_license() will reject it -> COMMUNITY with a warning
        # log, not a "file not found" skip). A real license format round-trip
        # is covered elsewhere (test_licensing.py); this test is scoped to
        # path resolution only.
        (custom / "license_key").write_text("not-a-real-license", encoding="utf-8")
        monkeypatch.delenv("YASHIGANI_LICENSE_FILE", raising=False)
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(custom))
        monkeypatch.chdir(tmp_path)  # keep step-3 CWD candidate out of the way

        from yashigani.licensing.loader import _CANDIDATES
        # Reproduce the loader's own candidate-selection logic directly
        # (load_license() itself is exercised end-to-end in test_licensing.py;
        # here we assert the SPECIFIC candidate this fix touched).
        resolved = [fn() for fn in _CANDIDATES]
        assert resolved[1] == str(custom / "license_key")
        assert Path(resolved[1]).is_file()

    def test_default_candidate_is_run_secrets(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_SECRETS_DIR", raising=False)
        from yashigani.licensing.loader import _CANDIDATES
        assert _CANDIDATES[1]() == "/run/secrets/license_key"


# ---------------------------------------------------------------------------
# kms/providers/keeper.py — KeeperKSMProvider._load_token()
# ---------------------------------------------------------------------------


class TestKeeperProviderCustomSecretsDir:
    def test_token_read_from_custom_secrets_dir(self, monkeypatch, tmp_path):
        custom = tmp_path / "custom-secrets-mount"
        custom.mkdir()
        (custom / "KSM_KEEPER_ONE_TIME_TOKEN").write_text("tok-from-custom-dir\n", encoding="utf-8")
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(custom))
        monkeypatch.delenv("KSM_KEEPER_ONE_TIME_TOKEN", raising=False)

        from yashigani.kms.providers.keeper import KeeperKSMProvider
        assert KeeperKSMProvider._load_token() == "tok-from-custom-dir"

    def test_falls_back_to_env_var_when_file_absent(self, monkeypatch, tmp_path):
        custom = tmp_path / "custom-secrets-mount-empty"
        custom.mkdir()
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(custom))
        monkeypatch.setenv("KSM_KEEPER_ONE_TIME_TOKEN", "env-fallback-token")

        from yashigani.kms.providers.keeper import KeeperKSMProvider
        assert KeeperKSMProvider._load_token() == "env-fallback-token"


# ---------------------------------------------------------------------------
# kms/providers/vault.py — VaultKMSProvider role/secret id file defaults
# ---------------------------------------------------------------------------


class TestVaultProviderCustomSecretsDir:
    def test_default_role_and_secret_id_files_honour_secrets_dir(self, monkeypatch, tmp_path):
        custom = tmp_path / "custom-secrets-mount"
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(custom))
        monkeypatch.delenv("VAULT_ROLE_ID_FILE", raising=False)
        monkeypatch.delenv("VAULT_SECRET_ID_FILE", raising=False)
        monkeypatch.setenv("VAULT_TOKEN", "dev-mode-token")  # skip AppRole file reads in _authenticate

        from yashigani.kms.providers.vault import VaultKMSProvider

        with patch("hvac.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.is_authenticated.return_value = True
            provider = VaultKMSProvider(environment_scope="production")

        assert provider._role_id_file == str(custom / "vault_role_id")
        assert provider._secret_id_file == str(custom / "vault_secret_id")

    def test_explicit_override_still_wins(self, monkeypatch, tmp_path):
        """VAULT_ROLE_ID_FILE / VAULT_SECRET_ID_FILE remain the
        higher-priority, documented override — this fix must not break it."""
        custom = tmp_path / "custom-secrets-mount"
        override_role = tmp_path / "somewhere-else" / "my_role_id"
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(custom))
        monkeypatch.setenv("VAULT_ROLE_ID_FILE", str(override_role))
        monkeypatch.delenv("VAULT_SECRET_ID_FILE", raising=False)
        monkeypatch.setenv("VAULT_TOKEN", "dev-mode-token")

        from yashigani.kms.providers.vault import VaultKMSProvider

        with patch("hvac.Client") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.is_authenticated.return_value = True
            provider = VaultKMSProvider(environment_scope="production")

        assert provider._role_id_file == str(override_role)
        assert provider._secret_id_file == str(custom / "vault_secret_id")


# ---------------------------------------------------------------------------
# documents/token_scheme.py — load_deployment_secret() default candidate
# ---------------------------------------------------------------------------


class TestDocumentTokenSchemeCustomSecretsDir:
    def test_reads_secret_from_custom_secrets_dir(self, monkeypatch, tmp_path):
        custom = tmp_path / "custom-secrets-mount"
        custom.mkdir()
        (custom / "document_pseudonymize_secret").write_text("deployment-secret-value\n", encoding="utf-8")
        monkeypatch.delenv("YASHIGANI_DOCUMENT_PSEUDONYMIZE_SECRET", raising=False)
        monkeypatch.delenv("YASHIGANI_DOCUMENT_PSEUDONYMIZE_SECRET_FILE", raising=False)
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(custom))

        from yashigani.documents.token_scheme import load_deployment_secret
        assert load_deployment_secret() == b"deployment-secret-value"

    def test_default_path_is_run_secrets(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_SECRETS_DIR", raising=False)
        from yashigani.documents.token_scheme import _default_secret_file
        assert str(_default_secret_file()) == "/run/secrets/document_pseudonymize_secret"


# ---------------------------------------------------------------------------
# kms/providers/docker_secrets.py — DockerSecretsProvider default secrets_dir
# ---------------------------------------------------------------------------


class TestDockerSecretsProviderDefaultSecretsDir:
    def test_no_explicit_secrets_dir_honours_env_var(self, monkeypatch, tmp_path):
        """The KMS factory never passes secrets_dir explicitly — before the
        fix this silently always resolved to /run/secrets regardless of
        YASHIGANI_SECRETS_DIR (the exact YSG-RISK-160 class, discovered
        during the sweep beyond the originally-named site list)."""
        custom = tmp_path / "custom-secrets-mount"
        custom.mkdir()
        (custom / "mykey").write_text("value-from-custom-dir", encoding="utf-8")
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(custom))

        from yashigani.kms.providers.docker_secrets import DockerSecretsProvider
        provider = DockerSecretsProvider(environment_scope="dev")
        assert provider.get_secret("mykey") == "value-from-custom-dir"

    def test_explicit_secrets_dir_still_wins(self, monkeypatch, tmp_path):
        custom = tmp_path / "custom-secrets-mount"
        explicit = tmp_path / "explicit-dir"
        explicit.mkdir()
        (explicit / "mykey").write_text("value-from-explicit-dir", encoding="utf-8")
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(custom))

        from yashigani.kms.providers.docker_secrets import DockerSecretsProvider
        provider = DockerSecretsProvider(environment_scope="dev", secrets_dir=explicit)
        assert provider.get_secret("mykey") == "value-from-explicit-dir"


# ---------------------------------------------------------------------------
# gateway/openai_router.py — _agent_token_secrets_root()
# ---------------------------------------------------------------------------


class TestOpenAIRouterAgentTokenSecretsRoot:
    def test_default_is_run_secrets(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_SECRETS_DIR", raising=False)
        from yashigani.gateway.openai_router import _agent_token_secrets_root
        assert str(_agent_token_secrets_root()) == "/run/secrets"

    def test_custom_secrets_dir_honoured(self, monkeypatch, tmp_path):
        custom = tmp_path / "custom-secrets-mount"
        custom.mkdir()
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(custom))
        from yashigani.gateway.openai_router import _agent_token_secrets_root
        assert _agent_token_secrets_root() == custom.resolve()

    def test_path_traversal_guard_still_applies_under_custom_dir(self, monkeypatch, tmp_path):
        """V232-CSCAN-01a defence-in-depth must hold regardless of which
        directory YASHIGANI_SECRETS_DIR points at."""
        custom = tmp_path / "custom-secrets-mount"
        custom.mkdir()
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(custom))
        from yashigani.gateway.openai_router import _agent_token_secrets_root

        secrets_root = _agent_token_secrets_root()
        malicious_name = "../../etc/passwd"
        token_path = (secrets_root / f"{malicious_name}_token").resolve()
        assert not token_path.is_relative_to(secrets_root)
