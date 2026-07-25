"""
Conformance group: SECRETS-PKI-VAULT.

Closes G1 (Lu audit YCS-20260723-v4.1.2-CONFORMANCE) for:
  routes/kms.py               (5 endpoints) — /admin/kms/*
  routes/secrets.py           (1 endpoint)  — /api/v1/admin/secrets/rotate
  routes/pki_v1.py            (4 endpoints) — /api/v1/admin/pki/*
  routes/crypto_inventory.py  (1 endpoint)  — /admin/crypto/inventory
  routes/cloud_keys.py        (2 endpoints) — /admin/cloud-keys*
  routes/hibp.py              (3 endpoints) — /api/v1/admin/auth/hibp/*
  routes/backup.py            (3 endpoints) — /admin/backup/*
  routes/manifest_history.py  (3 endpoints) — /admin/manifest-registrations*
Total: 22 endpoints.

Convention: see tests/conformance/conftest.py module docstring.

This is the highest-value security surface in the conformance sweep (key/secret/
cert material) — every mutation is StepUpAdminSession-gated and every genuine
positive-path assertion below uses REAL classes wherever an offline-safe
construction exists, never a rubber-stamped mock:

  - kms.py + cloud_keys.py: wired against the REAL DockerSecretsProvider
    (yashigani.kms.providers.docker_secrets) backed by a tmp_path filesystem —
    this is this codebase's own genuine offline/demo-tier KMS provider, not a
    test double. KSMRotationScheduler is also the REAL class (apscheduler is an
    installed dependency).
  - pki_v1.py: wired against the REAL InternalCADriver
    (yashigani.pki.drivers.internal_ca) with a REAL self-signed leaf certificate
    generated via the `cryptography` library at test time and written to a
    tmp_path secrets_dir + a REAL minimal service_identities.yaml manifest —
    genuine x509 parsing, genuine PEM bundle bytes, genuine CWE-200 private-key
    absence assertion (Laura live-PoC parity, matrix row 225). This is NOT a
    Yashigani-issued CA-chained cert (no intermediate signs it) — it proves the
    parsing/response-shape/security-invariant contract, not full chain-of-trust
    validation (that requires install.sh's live two-tier CA, out of scope for
    an offline suite).
  - secrets.py: wired against the REAL SecretRotator
    (yashigani.secrets.rotator) with YASHIGANI_SECRETS_DIR pointed at tmp_path —
    genuine file-based rotation for jwt_signing_key (no DB/Redis dependency);
    postgres_password exercises the genuine fail-closed path (no DSN
    configured offline).
  - backup.py: wired against REAL hashlib/HMAC verification logic with
    genuine backup directories built at test time (signed/unsigned/corrupt
    manifest states, a genuine symlink path-traversal escape attempt).
  - crypto_inventory.py: dispatched through the REAL app (not a mirrored
    router, per Lu's audit finding re: the existing unit tests in this repo).
  - manifest_history.py + hibp.py: `auth_settings_store` /
    ManifestRegistryService's asyncpg pool are Postgres-only — no fakeredis
    equivalent exists. MOCKED fakes are used, documented inline, implementing
    only the exact methods each route calls.

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.conformance

_GROUP_PREFIXES = (
    "/admin/kms/status",
    "/admin/kms/schedule",
    "/admin/kms/rotate-now",
    "/admin/kms/secrets",
    "/api/v1/admin/secrets/rotate",
    "/api/v1/admin/pki",
    "/admin/crypto/inventory",
    "/admin/cloud-keys",
    "/api/v1/admin/auth/hibp",
    "/admin/backup",
    "/admin/manifest-registrations",
)
# NOTE: kms.py routes use precise per-path prefixes rather than the coarse
# "/admin/kms" prefix — kms_vault.py (routes/kms_vault.py, NOT in this group's
# scope) registers /admin/kms/vault/status and /admin/kms/vault/secrets, which
# a naive "/admin/kms" prefix filter would also match, inflating this group's
# declared-route count above the true 22. Verified via `grep '@.*router\.' *`
# across every routes/*.py file (2026-07-23).


def test_group_covers_all_declared_routes(route_prefix_filter):
    declared = route_prefix_filter(*_GROUP_PREFIXES)
    declared_set = {(m, p) for (m, p, _r) in declared}
    assert len(declared_set) == 22, (
        f"Expected 22 declared routes under {_GROUP_PREFIXES}, found "
        f"{len(declared_set)}: {sorted(declared_set)}"
    )


# ---------------------------------------------------------------------------
# Shared fixtures — KMS (kms.py + cloud_keys.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def kms_state(tmp_path, monkeypatch):
    """Wires the REAL DockerSecretsProvider against a tmp_path filesystem.

    This is this codebase's genuine offline/demo-tier KMS provider (see
    docker_secrets.py module docstring) — not a mock of KMS behaviour. Files
    written under secrets_dir/cloud_keys_dir are obviously-fake test
    placeholders, never real secret material.
    """
    from yashigani.backoffice.state import backoffice_state
    from yashigani.kms.providers.docker_secrets import DockerSecretsProvider

    secrets_dir = tmp_path / "secrets"
    cloud_dir = tmp_path / "cloud-keys"
    secrets_dir.mkdir()
    cloud_dir.mkdir()
    provider = DockerSecretsProvider(
        environment_scope="conformance-test",
        secrets_dir=secrets_dir,
        cloud_keys_dir=cloud_dir,
    )
    monkeypatch.setattr(backoffice_state, "kms_provider", provider, raising=False)
    return provider, secrets_dir, cloud_dir


@pytest.fixture
def rotation_scheduler_state(kms_state, monkeypatch):
    """Wires the REAL KSMRotationScheduler (apscheduler is an installed dep)
    against the same tmp_path DockerSecretsProvider from kms_state."""
    from yashigani.backoffice.state import backoffice_state
    from yashigani.kms.rotation import KSMRotationScheduler

    provider, _secrets_dir, _cloud_dir = kms_state
    scheduler = KSMRotationScheduler(
        provider=provider,
        secret_key="conformance-test/dummy-secret",
        cron_expr="0 3 * * *",
        on_event=MagicMock(),
    )
    monkeypatch.setattr(backoffice_state, "rotation_scheduler", scheduler, raising=False)
    return scheduler


# ---------------------------------------------------------------------------
# kms.py — 5 endpoints
# ---------------------------------------------------------------------------


class TestKmsStatus:
    # GAP-CLOSED: GET /admin/kms/status
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/kms/status")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "authentication_required"

    def test_user_tier_403(self, user_client):
        r = user_client.get("/admin/kms/status")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "insufficient_tier"

    def test_admin_not_configured_503(self, admin_client):
        r = admin_client.get("/admin/kms/status")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "kms_not_configured"

    def test_admin_with_real_provider_200(self, admin_client, kms_state):
        _provider, _secrets_dir, _cloud_dir = kms_state
        r = admin_client.get("/admin/kms/status")
        assert r.status_code == 200
        body = r.json()
        assert body["provider"] == "docker"
        assert body["environment_scope"] == "conformance-test"
        assert body["healthy"] is True  # secrets_dir + cloud_keys_dir both exist+RW


class TestKmsSchedule:
    # GAP-CLOSED: GET /admin/kms/schedule
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/kms/schedule").status_code == 401

    def test_admin_no_scheduler_configured(self, admin_client):
        r = admin_client.get("/admin/kms/schedule")
        assert r.status_code == 200
        assert r.json() == {"configured": False}

    def test_admin_with_real_scheduler(self, admin_client, rotation_scheduler_state):
        r = admin_client.get("/admin/kms/schedule")
        assert r.status_code == 200
        body = r.json()
        assert body["configured"] is True
        assert body["cron_expr"] == "0 3 * * *"
        assert body["running"] is False  # scheduler.start() never called
        # Redaction check (P0-adjacent): the secret_key value must be masked,
        # not returned in full.
        assert "****" in body["secret_key"]
        assert "conformance-test/dummy-secret" not in body["secret_key"]

    # GAP-CLOSED: POST /admin/kms/schedule (step-up required)
    def test_post_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/kms/schedule", json={"cron_expr": "0 3 * * *"})
        assert r.status_code == 401

    def test_post_admin_without_stepup_401(self, admin_client):
        r = admin_client.post("/admin/kms/schedule", json={"cron_expr": "0 3 * * *"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_post_invalid_cron_interval_too_frequent_422(self, stepup_admin_client):
        """SPEC-CONFORMANCE: cron intervals under 1 hour are rejected — this
        validation runs BEFORE the scheduler-configured check, so no scheduler
        fixture is needed to exercise it."""
        r = stepup_admin_client.post("/admin/kms/schedule", json={"cron_expr": "* * * * *"})
        assert r.status_code == 422

    def test_post_no_scheduler_configured_503(self, stepup_admin_client):
        r = stepup_admin_client.post("/admin/kms/schedule", json={"cron_expr": "0 4 * * *"})
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "rotation_scheduler_not_configured"

    def test_post_success_updates_real_scheduler(
        self, stepup_admin_client, rotation_scheduler_state, mock_audit_writer
    ):
        r = stepup_admin_client.post("/admin/kms/schedule", json={"cron_expr": "30 4 * * *"})
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "cron_expr": "30 4 * * *"}
        assert rotation_scheduler_state._cron_expr == "30 4 * * *"
        mock_audit_writer.write.assert_called_once()


class TestKmsRotateNow:
    # GAP-CLOSED: POST /admin/kms/rotate-now (step-up required)
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/kms/rotate-now").status_code == 401

    def test_admin_without_stepup_401(self, admin_client):
        r = admin_client.post("/admin/kms/rotate-now")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_no_scheduler_configured_503(self, stepup_admin_client):
        r = stepup_admin_client.post("/admin/kms/rotate-now")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "rotation_scheduler_not_configured"

    def test_real_provider_rejects_rotation_500(self, stepup_admin_client, rotation_scheduler_state):
        """Offline reality: DockerSecretsProvider.rotate_secret() always raises
        ProviderError("Docker Secrets does not support rotation...") — the
        real, documented behaviour of this codebase's demo/free-tier KMS
        provider (docker_secrets.py:173-177), not a stub. The route's own
        except-clause converts this into HTTP 500 with a safe envelope."""
        r = stepup_admin_client.post("/admin/kms/rotate-now")
        assert r.status_code == 500
        assert r.json()["detail"]["error"] == "rotation failed"


class TestKmsSecrets:
    # GAP-CLOSED: GET /admin/kms/secrets
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/kms/secrets").status_code == 401

    def test_admin_not_configured_503(self, admin_client):
        r = admin_client.get("/admin/kms/secrets")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "kms_not_configured"

    def test_admin_lists_key_names_never_values(self, admin_client, kms_state):
        """P0 security assertion: secret VALUES must never appear in the
        response — only key names. Uses obviously-fake placeholder content."""
        _provider, secrets_dir, _cloud_dir = kms_state
        (secrets_dir / "postgres_password").write_text("CONFORMANCE-FAKE-VALUE-DO-NOT-USE\n")
        (secrets_dir / "jwt_signing_key").write_text("CONFORMANCE-FAKE-JWT-VALUE\n")

        r = admin_client.get("/admin/kms/secrets")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 2
        names = {s["key"] for s in body["secrets"]}
        assert names == {"postgres_password", "jwt_signing_key"}
        assert "CONFORMANCE-FAKE-VALUE-DO-NOT-USE" not in r.text
        assert "CONFORMANCE-FAKE-JWT-VALUE" not in r.text


# ---------------------------------------------------------------------------
# cloud_keys.py — 2 endpoints
# ---------------------------------------------------------------------------


class TestCloudKeysList:
    # GAP-CLOSED: GET /admin/cloud-keys
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/cloud-keys").status_code == 401

    def test_admin_no_kms_configured_false(self, admin_client):
        """No 503 here — cloud_keys degrades to configured=False per provider
        when kms_provider is None (cloud_keys.py:61-66), unlike kms.py."""
        r = admin_client.get("/admin/cloud-keys")
        assert r.status_code == 200
        providers = {p["provider"]: p["configured"] for p in r.json()["providers"]}
        assert providers == {"openai": False, "anthropic": False}


class TestCloudKeysSet:
    # GAP-CLOSED: PUT /admin/cloud-keys (step-up required)
    def test_unauth_401(self, unauth_client):
        r = unauth_client.put("/admin/cloud-keys", json={"provider": "openai", "api_key": "x"})
        assert r.status_code == 401

    def test_admin_without_stepup_401(self, admin_client):
        r = admin_client.put("/admin/cloud-keys", json={"provider": "openai", "api_key": "x"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_kms_unavailable_503(self, stepup_admin_client):
        r = stepup_admin_client.put("/admin/cloud-keys", json={"provider": "openai", "api_key": "x"})
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "kms_unavailable"

    def test_invalid_provider_422(self, stepup_admin_client, kms_state):
        r = stepup_admin_client.put(
            "/admin/cloud-keys", json={"provider": "bogus-provider", "api_key": "x" * 10}
        )
        assert r.status_code == 422

    def test_real_round_trip_never_leaks_value(self, stepup_admin_client, admin_client, kms_state, mock_audit_writer):
        """Genuine round trip through the REAL DockerSecretsProvider.set_secret
        (atomic mktemp -> chmod 0600 -> rename) — the key value is an
        obviously-fake test placeholder, never a real credential."""
        fake_key = "sk-conformance-FAKE-0000000000000000"
        r = stepup_admin_client.put(
            "/admin/cloud-keys", json={"provider": "openai", "api_key": fake_key}
        )
        assert r.status_code == 200
        assert r.json() == {"status": "stored", "provider": "openai", "kms_key": "openai_api_key"}
        assert fake_key not in r.text
        mock_audit_writer.write.assert_called_once()

        # Persistence assertion — GET must now report configured=True for openai.
        r2 = admin_client.get("/admin/cloud-keys")
        providers = {p["provider"]: p["configured"] for p in r2.json()["providers"]}
        assert providers["openai"] is True
        assert fake_key not in r2.text


# ---------------------------------------------------------------------------
# secrets.py — 1 endpoint (POST /api/v1/admin/secrets/rotate)
# ---------------------------------------------------------------------------


@pytest.fixture
def secrets_dir_env(tmp_path, monkeypatch):
    """SecretRotator() reads YASHIGANI_SECRETS_DIR fresh at construction time
    inside the route handler (constructed per-request) — no module reload
    needed, a plain env var monkeypatch suffices."""
    monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(tmp_path))
    return tmp_path


class TestSecretsRotate:
    # GAP-CLOSED: POST /api/v1/admin/secrets/rotate
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/api/v1/admin/secrets/rotate", json={"secret": "jwt_signing_key"})
        assert r.status_code == 401

    def test_admin_without_stepup_401(self, admin_client):
        r = admin_client.post("/api/v1/admin/secrets/rotate", json={"secret": "jwt_signing_key"})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_invalid_secret_name_422(self, stepup_admin_client):
        r = stepup_admin_client.post("/api/v1/admin/secrets/rotate", json={"secret": "bogus"})
        assert r.status_code == 422

    def test_jwt_signing_key_real_rotation_success(
        self, stepup_admin_client, secrets_dir_env, mock_audit_writer
    ):
        """Genuine positive path: REAL SecretRotator, REAL file write to a
        tmp_path secrets dir — no DB/Redis dependency for jwt_signing_key, so
        this is a true end-to-end success, not a mocked stub."""
        r = stepup_admin_client.post(
            "/api/v1/admin/secrets/rotate", json={"secret": "jwt_signing_key"}
        )
        assert r.status_code == 200
        body = r.json()
        assert body["secret"] == "jwt_signing_key"
        assert body["success"] is True
        assert body["reverted"] is False
        written = (secrets_dir_env / "jwt_signing_key").read_text().strip()
        assert len(written) == 128  # 64-byte hex per rotator.py docstring
        # REQUESTED + SUCCEEDED audit events.
        assert mock_audit_writer.write.call_count == 2

    def test_postgres_password_fails_closed_offline(
        self, stepup_admin_client, secrets_dir_env, mock_audit_writer, monkeypatch
    ):
        """Genuine fail-closed path: no YASHIGANI_DB_DSN_DIRECT configured and
        no pre-seeded postgres_password file offline -> RotationResult with
        success=False (never raises, route always returns HTTP 200 per its
        documented contract — caller inspects the `success` field)."""
        monkeypatch.delenv("YASHIGANI_DB_DSN_DIRECT", raising=False)
        r = stepup_admin_client.post(
            "/api/v1/admin/secrets/rotate", json={"secret": "postgres_password"}
        )
        assert r.status_code == 200
        body = r.json()
        assert body["success"] is False
        assert body["error"]
        # REQUESTED + FAILED audit events.
        assert mock_audit_writer.write.call_count == 2

    def test_audit_write_failure_is_fail_closed(self, stepup_admin_client, secrets_dir_env):
        """SPEC-CONFORMANCE: if the audit sink write fails on the REQUESTED
        event, the route must refuse to proceed with rotation at all
        (secrets.py:105-122 — 'Cannot proceed: audit log write failed
        (fail-closed)') rather than rotating silently."""
        from yashigani.backoffice.state import backoffice_state

        failing_writer = MagicMock()
        failing_writer.write.side_effect = RuntimeError("audit sink down")
        backoffice_state.audit_writer = failing_writer
        try:
            r = stepup_admin_client.post(
                "/api/v1/admin/secrets/rotate", json={"secret": "jwt_signing_key"}
            )
            assert r.status_code == 500
            assert r.json()["detail"]["error"] == "audit_failure"
        finally:
            backoffice_state.audit_writer = None


# ---------------------------------------------------------------------------
# pki_v1.py — 4 endpoints
# ---------------------------------------------------------------------------


def _make_self_signed_cert_pem(common_name: str) -> bytes:
    """Generate a REAL self-signed leaf certificate via `cryptography` at test
    time. NOT chained to a real CA — proves the parsing/response-shape/CWE-200
    contract, not full mesh trust (that needs install.sh's live two-tier CA)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=89))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM)


_PKI_SERVICE = "conformance-svc"


@pytest.fixture
def pki_real_cert_state(tmp_path, monkeypatch):
    """Writes a REAL self-signed leaf cert into a tmp secrets_dir so
    InternalCADriver's genuine x509 parsing code path (internal_ca.py) is
    exercised end-to-end offline, with no mocking of PKI parsing logic."""
    monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(tmp_path))
    monkeypatch.delenv("YASHIGANI_PKI_CA_MODE", raising=False)  # defaults to "internal"
    pem = _make_self_signed_cert_pem(_PKI_SERVICE)
    (tmp_path / f"{_PKI_SERVICE}_client.crt").write_bytes(pem)
    return _PKI_SERVICE, pem


@pytest.fixture
def pki_manifest_state(tmp_path, monkeypatch):
    """Writes a REAL minimal service_identities.yaml (schema_version 1, one
    service) so pki_status's _live_service_names() genuinely parses a manifest
    rather than degrading to the empty-list fallback."""
    manifest_path = tmp_path / "service_identities.yaml"
    manifest_path.write_text(
        "schema_version: 1\n"
        "services:\n"
        f"  - name: {_PKI_SERVICE}\n"
        f"    dns_sans: [{_PKI_SERVICE}.local]\n"
        "    purpose: conformance-test\n"
        "    revoked: false\n"
    )
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(manifest_path))
    return manifest_path


class TestPkiChain:
    # GAP-CLOSED: GET /api/v1/admin/pki/chain/{service}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get(f"/api/v1/admin/pki/chain/{_PKI_SERVICE}").status_code == 401

    def test_user_tier_403(self, user_client):
        r = user_client.get(f"/api/v1/admin/pki/chain/{_PKI_SERVICE}")
        assert r.status_code == 403

    def test_invalid_service_name_422(self, admin_client):
        r = admin_client.get("/api/v1/admin/pki/chain/BAD-Name!")
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_service_name"

    def test_no_cert_file_503(self, admin_client, monkeypatch, tmp_path):
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(tmp_path))
        r = admin_client.get("/api/v1/admin/pki/chain/no-such-service")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "pki_driver_error"

    def test_real_cert_parsed_genuine_positive_path(self, admin_client, pki_real_cert_state):
        service, _pem = pki_real_cert_state
        r = admin_client.get(f"/api/v1/admin/pki/chain/{service}")
        assert r.status_code == 200
        body = r.json()
        assert body["subject_cn"] == service
        assert body["chain_depth"] == 1
        assert body["ca_mode"] == "internal"
        assert len(body["fingerprint_sha256"]) == 64
        assert "PRIVATE KEY" not in r.text


class TestPkiRotate:
    # GAP-CLOSED: POST /api/v1/admin/pki/rotate/{service} (step-up required)
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post(f"/api/v1/admin/pki/rotate/{_PKI_SERVICE}").status_code == 401

    def test_admin_without_stepup_401(self, admin_client):
        r = admin_client.post(f"/api/v1/admin/pki/rotate/{_PKI_SERVICE}")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_invalid_name_422(self, stepup_admin_client):
        r = stepup_admin_client.post("/api/v1/admin/pki/rotate/BAD!")
        assert r.status_code == 422

    def test_no_manifest_degrades_to_business_failure_not_500(
        self, stepup_admin_client, monkeypatch, tmp_path
    ):
        """Offline reality: without a live manifest + intermediate CA key
        material, rotate_leaves() cannot succeed. InternalCADriver.rotate()'s
        own broad except-clause (internal_ca.py:160-164) converts this into
        RotateResult(success=False, error=...) rather than raising — the route
        then returns HTTP 200 with success=False (never 500). This is the
        genuine, documented degrade behaviour, not a stub."""
        monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(tmp_path / "missing.yaml"))
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(tmp_path))
        r = stepup_admin_client.post(f"/api/v1/admin/pki/rotate/{_PKI_SERVICE}")
        assert r.status_code == 200
        body = r.json()
        assert body["success"] is False
        assert body["error"]


class TestPkiBundle:
    # GAP-CLOSED: GET /api/v1/admin/pki/bundle/{service}  (matrix row 225 — Laura live PoC parity)
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get(f"/api/v1/admin/pki/bundle/{_PKI_SERVICE}").status_code == 401

    def test_invalid_name_422(self, admin_client):
        r = admin_client.get("/api/v1/admin/pki/bundle/BAD!")
        assert r.status_code == 422

    def test_no_cert_503(self, admin_client, monkeypatch, tmp_path):
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(tmp_path))
        r = admin_client.get("/api/v1/admin/pki/bundle/no-such-service")
        assert r.status_code == 503

    def test_real_bundle_download_never_contains_private_key(self, admin_client, pki_real_cert_state):
        """P0 security assertion (Laura live-PoC parity, matrix row 225): the
        PEM bundle download must NEVER include private key material — proven
        here against a genuine offline-generated leaf cert, not a mock."""
        service, _pem = pki_real_cert_state
        r = admin_client.get(f"/api/v1/admin/pki/bundle/{service}")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/x-pem-file"
        assert f'attachment; filename="{service}_cert_bundle.pem"' in r.headers["content-disposition"]
        assert b"BEGIN CERTIFICATE" in r.content
        assert b"PRIVATE KEY" not in r.content

    def test_defence_in_depth_aborts_if_driver_leaks_private_key(self, admin_client, monkeypatch):
        """Regression guard for pki_v1.py:301-309 (CWE-200 sanity check): if a
        (buggy or malicious) CA driver ever returned private-key material in
        the bundle, the route must abort with 500 rather than serve it. Proven
        with a fake driver since the real InternalCADriver never reads key
        files for get_pem_bundle() — this exercises the defence-in-depth check
        itself, the last line of a P0 CWE-200 defence."""

        class _LeakyDriver:
            def get_pem_bundle(self, service_name):
                return b"-----BEGIN PRIVATE KEY-----\nMOCKFAKEKEYBYTES\n-----END PRIVATE KEY-----\n"

        monkeypatch.setattr(
            "yashigani.backoffice.routes.pki_v1.get_ca_driver",
            lambda: _LeakyDriver(),
        )
        r = admin_client.get(f"/api/v1/admin/pki/bundle/{_PKI_SERVICE}")
        assert r.status_code == 500
        assert r.json()["detail"]["error"] == "internal_error"
        assert "PRIVATE KEY" not in r.text


class TestPkiStatus:
    # GAP-CLOSED: GET /api/v1/admin/pki/status
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/api/v1/admin/pki/status").status_code == 401

    def test_status_no_manifest_degrades_empty(self, admin_client, monkeypatch, tmp_path):
        monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(tmp_path / "does-not-exist.yaml"))
        r = admin_client.get("/api/v1/admin/pki/status")
        assert r.status_code == 200
        body = r.json()
        assert body["services"] == []
        assert body["ca_mode"] == "internal"

    def test_status_with_real_manifest_and_cert(self, admin_client, pki_manifest_state, pki_real_cert_state):
        service, _pem = pki_real_cert_state
        r = admin_client.get("/api/v1/admin/pki/status")
        assert r.status_code == 200
        rows = {row["service"]: row for row in r.json()["services"]}
        assert service in rows
        assert rows[service]["error"] is None
        assert rows[service]["fingerprint_sha256"]

    def test_status_manifest_service_missing_cert_reports_row_error_not_500(
        self, admin_client, pki_manifest_state, monkeypatch, tmp_path
    ):
        """A per-service failure (missing cert file) must surface as a row-
        level `error` field, not a 500 for the whole endpoint (pki_v1.py:340-348)."""
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(tmp_path))
        r = admin_client.get("/api/v1/admin/pki/status")
        assert r.status_code == 200
        rows = r.json()["services"]
        assert len(rows) == 1
        assert rows[0]["error"] is not None


# ---------------------------------------------------------------------------
# crypto_inventory.py — 1 endpoint
# ---------------------------------------------------------------------------


class TestCryptoInventory:
    # GAP-CLOSED: GET /admin/crypto/inventory
    #
    # This is dispatched through the REAL app (bo_app + TestClient), not a
    # mirrored router — closing Lu's audit note that the existing unit tests
    # (src/tests/unit/test_admin_crypto_inventory_requires_session.py,
    # test_crypto_inventory_fips_attestation.py) are AST/mirrored-router style.
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/crypto/inventory").status_code == 401

    def test_user_tier_403(self, user_client):
        r = user_client.get("/admin/crypto/inventory")
        assert r.status_code == 403

    def test_admin_200_shape_and_content(self, admin_client):
        r = admin_client.get("/admin/crypto/inventory")
        assert r.status_code == 200
        body = r.json()
        for key in ("algorithms", "deprecated", "post_quantum", "compliance",
                    "fips_mode_active", "cmvp_cert"):
            assert key in body
        algo_names = {a["name"] for a in body["algorithms"]}
        # PKI-002 (2026-07-02): stale HMAC-SHA-1 TOTP entry must remain removed.
        assert not any("SHA-1" in name or "SHA1" in name for name in algo_names)
        assert "HMAC-SHA-256" in algo_names
        assert "HMAC-SHA-512" in algo_names

    def test_fips_attestation_reflects_module_load_env(self, admin_client, monkeypatch):
        """FIPS attestation fields are set at MODULE LOAD time from env vars
        (crypto_inventory.py docstring, 2026-05-27 note) — monkeypatching the
        module-level globals directly (rather than the env var + a reload)
        exercises the exact runtime read path the route performs without risk
        of leaking reloaded-module state into other test files sharing this
        process."""
        import yashigani.backoffice.routes.crypto_inventory as ci

        monkeypatch.setattr(ci, "_FIPS_MODE_ACTIVE", True, raising=False)
        monkeypatch.setattr(ci, "_CMVP_CERT", "#4985", raising=False)
        r = admin_client.get("/admin/crypto/inventory")
        assert r.status_code == 200
        body = r.json()
        assert body["fips_mode_active"] is True
        assert body["cmvp_cert"] == "#4985"

    def test_fips_attestation_default_off(self, admin_client, monkeypatch):
        import yashigani.backoffice.routes.crypto_inventory as ci

        monkeypatch.setattr(ci, "_FIPS_MODE_ACTIVE", False, raising=False)
        monkeypatch.setattr(ci, "_CMVP_CERT", None, raising=False)
        r = admin_client.get("/admin/crypto/inventory")
        body = r.json()
        assert body["fips_mode_active"] is False
        assert body["cmvp_cert"] is None


# ---------------------------------------------------------------------------
# hibp.py — 3 endpoints
# ---------------------------------------------------------------------------


class _FakeAuthSettingsStore:
    """MOCKED: AuthSettingsStore requires live Postgres+pgcrypto — not
    available offline. Implements only get_setting/get_metadata/set_setting,
    the exact surface hibp.py calls (verified by reading that file)."""

    def __init__(self) -> None:
        self._settings: dict[str, str] = {}
        self._meta: dict[str, dict] = {}

    async def get_setting(self, key: str) -> str:
        return self._settings.get(key, "")

    async def get_metadata(self, key: str):
        return self._meta.get(key)

    async def set_setting(self, key: str, value: str, updated_by: str) -> None:
        self._settings[key] = value
        self._meta[key] = {
            "updated_at": "2026-07-23T00:00:00+00:00",
            "updated_by": updated_by,
        }


@pytest.fixture
def hibp_store_state(monkeypatch):
    from yashigani.backoffice.state import backoffice_state

    store = _FakeAuthSettingsStore()
    monkeypatch.setattr(backoffice_state, "auth_settings_store", store, raising=False)
    return store


class TestHibpStatus:
    # GAP-CLOSED: GET /api/v1/admin/auth/hibp/status
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/api/v1/admin/auth/hibp/status").status_code == 401

    def test_store_unavailable_503(self, admin_client):
        r = admin_client.get("/api/v1/admin/auth/hibp/status")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "settings_store_unavailable"

    def test_not_configured(self, admin_client, hibp_store_state, monkeypatch):
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)
        r = admin_client.get("/api/v1/admin/auth/hibp/status")
        assert r.status_code == 200
        body = r.json()
        assert body["configured"] is False
        assert body["source"] == "none"
        assert body["masked_value"] is None

    def test_configured_masks_full_key(self, admin_client, hibp_store_state, monkeypatch):
        monkeypatch.delenv("YASHIGANI_HIBP_API_KEY", raising=False)
        secret = "conformance-fake-hibp-key-0000000000"
        hibp_store_state._settings["hibp_api_key"] = secret
        hibp_store_state._meta["hibp_api_key"] = {"updated_at": None, "updated_by": "admin1"}
        r = admin_client.get("/api/v1/admin/auth/hibp/status")
        assert r.status_code == 200
        body = r.json()
        assert body["configured"] is True
        assert body["source"] == "admin_panel"
        assert secret not in r.text


class TestHibpSetKey:
    # GAP-CLOSED: PUT /api/v1/admin/auth/hibp/key (step-up required)
    def test_unauth_401(self, unauth_client):
        r = unauth_client.put("/api/v1/admin/auth/hibp/key", json={"api_key": "x" * 10})
        assert r.status_code == 401

    def test_admin_without_stepup_401(self, admin_client, hibp_store_state):
        r = admin_client.put("/api/v1/admin/auth/hibp/key", json={"api_key": "x" * 10})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_invalid_format_422(self, stepup_admin_client, hibp_store_state):
        r = stepup_admin_client.put(
            "/api/v1/admin/auth/hibp/key", json={"api_key": "bad key with spaces!"}
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_key_format"

    def test_real_round_trip_never_leaks_full_key(
        self, stepup_admin_client, hibp_store_state, mock_audit_writer
    ):
        secret = "conformance-fake-hibp-put-00000000"
        r = stepup_admin_client.put("/api/v1/admin/auth/hibp/key", json={"api_key": secret})
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["hibp_key"]["configured"] is True
        assert secret not in r.text
        assert hibp_store_state._settings["hibp_api_key"] == secret  # genuine persistence
        mock_audit_writer.write.assert_called_once()


class TestHibpClearKey:
    # GAP-CLOSED: DELETE /api/v1/admin/auth/hibp/key (step-up required)
    def test_unauth_401(self, unauth_client):
        assert unauth_client.delete("/api/v1/admin/auth/hibp/key").status_code == 401

    def test_admin_without_stepup_401(self, admin_client, hibp_store_state):
        r = admin_client.delete("/api/v1/admin/auth/hibp/key")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_real_clear(self, stepup_admin_client, hibp_store_state, mock_audit_writer):
        hibp_store_state._settings["hibp_api_key"] = "conformance-fake-existing-key-000"
        r = stepup_admin_client.delete("/api/v1/admin/auth/hibp/key")
        assert r.status_code == 200
        body = r.json()
        assert body["hibp_key"]["configured"] is False
        assert hibp_store_state._settings["hibp_api_key"] == ""
        mock_audit_writer.write.assert_called_once()


# ---------------------------------------------------------------------------
# backup.py — 3 endpoints
# ---------------------------------------------------------------------------


@pytest.fixture
def backup_dir_state(tmp_path, monkeypatch):
    """backup.py's `_BACKUPS_DIR` is a module-level Path bound ONCE at import
    time from an env var (not re-read per-request) — env var monkeypatching
    alone would not take effect. Patching the module attribute directly works
    because the route functions look up `_BACKUPS_DIR` as a module global at
    call time, regardless of which already-built router object holds them."""
    import yashigani.backoffice.routes.backup as backup_mod

    backups_dir = tmp_path / "backups"
    backups_dir.mkdir()
    monkeypatch.setattr(backup_mod, "_BACKUPS_DIR", backups_dir, raising=False)
    return backups_dir


def _write_backup_dir(base: Path, name: str, *, sign: bool = True, tamper: bool = False) -> Path:
    d = base / name
    d.mkdir()
    (d / "bundle.enc").write_bytes(b"conformance-fake-encrypted-bundle-bytes")
    (d / "backup-meta.json").write_text('{"version":"ondemand-v1"}')
    if sign:
        checksums = {}
        for fname in ("bundle.enc", "backup-meta.json"):
            checksums[fname] = hashlib.sha256((d / fname).read_bytes()).hexdigest()
        if tamper:
            checksums["bundle.enc"] = "0" * 64
        manifest_text = "".join(f"{h}  {fname}\n" for fname, h in checksums.items())
        (d / "MANIFEST.sha256").write_text(manifest_text)
        (d / "MANIFEST.sha256.sig").write_bytes(b"conformance-fake-hmac-signature-hex")
    return d


class TestBackupStatus:
    # GAP-CLOSED: GET /admin/backup/status
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/backup/status").status_code == 401

    def test_no_backups_dir_never_leaks_absolute_path(self, admin_client, monkeypatch, tmp_path):
        import yashigani.backoffice.routes.backup as backup_mod

        monkeypatch.setattr(backup_mod, "_BACKUPS_DIR", tmp_path / "does-not-exist", raising=False)
        r = admin_client.get("/admin/backup/status")
        assert r.status_code == 200
        assert r.json() == {"backups": [], "latest": None, "backups_dir": "backups"}

    def test_real_signed_backup_listed_no_absolute_path_leak(self, admin_client, backup_dir_state):
        _write_backup_dir(backup_dir_state, "install-001", sign=True)
        r = admin_client.get("/admin/backup/status")
        assert r.status_code == 200
        body = r.json()
        assert body["backups_dir"] == "backups"  # CWE-200: never str(_BACKUPS_DIR)
        assert str(backup_dir_state) not in r.text
        entry = body["backups"][0]
        assert entry["name"] == "install-001"
        assert entry["manifest_state"] == "signed"
        assert entry["type"] == "install"


class TestBackupVerify:
    # GAP-CLOSED: POST /admin/backup/verify
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/backup/verify", json={"backup_name": "x"})
        assert r.status_code == 401

    def test_invalid_name_traversal_attempt_422(self, admin_client, backup_dir_state):
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "../../etc/passwd"})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_backup_name"

    def test_symlink_escape_rejected_422(self, admin_client, backup_dir_state, tmp_path):
        """Genuine defence-in-depth proof: a regex-valid backup_name that is a
        symlink resolving OUTSIDE backups_dir must be rejected (ASVS 9.2.1),
        not followed."""
        target = tmp_path / "outside_target"
        target.mkdir()
        (backup_dir_state / "escaped").symlink_to(target)
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "escaped"})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "path_traversal_rejected"

    def test_not_found_404(self, admin_client, backup_dir_state):
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "does-not-exist"})
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "backup_not_found"

    def test_real_signed_backup_ok(self, admin_client, backup_dir_state):
        """Genuine SHA-256 verification — real files, real hashlib, no mocks."""
        _write_backup_dir(backup_dir_state, "install-002", sign=True)
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "install-002"})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["manifest_state"] == "signed"
        assert body["mismatches"] == []

    def test_tampered_manifest_detected(self, admin_client, backup_dir_state):
        _write_backup_dir(backup_dir_state, "install-003", sign=True, tamper=True)
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "install-003"})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is False
        assert any(m["issue"] == "checksum_mismatch" for m in body["mismatches"])

    def test_unsigned_backup_ok_with_warning_state(self, admin_client, backup_dir_state):
        d = backup_dir_state / "install-004"
        d.mkdir()
        (d / "some_file.bin").write_bytes(b"conformance-fake-data")
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "install-004"})
        body = r.json()
        assert r.status_code == 200
        assert body["ok"] is True
        assert body["manifest_state"] == "unsigned"

    def test_corrupt_manifest_state(self, admin_client, backup_dir_state):
        d = backup_dir_state / "install-005"
        d.mkdir()
        (d / "MANIFEST.sha256").write_text("deadbeef  bundle.enc\n")
        r = admin_client.post("/admin/backup/verify", json={"backup_name": "install-005"})
        body = r.json()
        assert r.status_code == 200
        assert body["ok"] is False
        assert body["manifest_state"] == "corrupt"


class TestBackupCreate:
    # GAP-CLOSED: POST /admin/backup/create (step-up required)
    def test_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/backup/create").status_code == 401

    def test_admin_without_stepup_401(self, admin_client):
        r = admin_client.post("/admin/backup/create")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_no_dsn_configured_503(self, stepup_admin_client, monkeypatch):
        for var in ("YASHIGANI_DB_DSN_ADMIN_DIRECT", "YASHIGANI_DB_DSN_DIRECT", "YASHIGANI_DB_DSN"):
            monkeypatch.delenv(var, raising=False)
        r = stepup_admin_client.post("/admin/backup/create")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "db_dsn_unavailable"

    def test_pg_dump_unavailable_503(self, stepup_admin_client, monkeypatch):
        """pg_dump is genuinely absent from this offline conformance venv
        (verified via `which pg_dump` -> not found, 2026-07-23) — shutil.which
        is monkeypatched to guarantee this holds deterministically on any CI
        box, not relying on the ambient environment."""
        monkeypatch.setenv("YASHIGANI_DB_DSN_DIRECT", "postgresql://fake-conformance-test/db")
        monkeypatch.setattr("shutil.which", lambda _cmd: None)
        r = stepup_admin_client.post("/admin/backup/create")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "pg_dump_unavailable"


# ---------------------------------------------------------------------------
# manifest_history.py — 3 endpoints
# ---------------------------------------------------------------------------


class _FakeAcquireCtx:
    def __init__(self, conn) -> None:
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *_exc):
        return False


class FakeManifestPool:
    """MOCKED: ManifestRegistryService requires a live asyncpg pool — no
    fakeredis equivalent exists (Postgres-only, per manifest_registry/service.py
    module docstring). Implements only the 4 SQL query shapes that service.py
    and manifest_history.py actually issue (verified by reading both files):
      1. SELECT manifest_sha256 ... WHERE agent_id = $1 (lookup prev sha)
      2. INSERT INTO manifest_registrations ... RETURNING id
      3. SELECT ... WHERE id = $1 (single record)
      4. SELECT ... WHERE tenant_id = $1 ... LIMIT $2 OFFSET $3 (history)
      5. SELECT COUNT(*) ... WHERE tenant_id = $1 (total count, used directly
         by the route, not the service)
    """

    def __init__(self) -> None:
        self._rows: list[dict] = []
        self._next_id = 1

    def acquire(self):
        return _FakeAcquireCtx(self)

    async def fetchrow(self, query: str, *args):
        q = " ".join(query.split())
        if q.startswith("SELECT manifest_sha256"):
            agent_id = args[0]
            matches = [r for r in self._rows if r["agent_id"] == agent_id]
            if not matches:
                return None
            latest = max(matches, key=lambda r: r["id"])
            return {"manifest_sha256": latest["manifest_sha256"]}
        if q.startswith("INSERT INTO manifest_registrations"):
            tenant_id, agent_id, sha, blob, operator, prev_sha, prov_json = args
            row = {
                "id": self._next_id,
                "tenant_id": tenant_id,
                "agent_id": agent_id,
                "manifest_sha256": sha,
                "manifest_yaml_blob": blob,
                "registered_by_operator_identity": operator,
                "registered_at": datetime.datetime.now(tz=datetime.UTC),
                "previous_manifest_sha256": prev_sha,
                "signature_provenance": json.loads(prov_json) if prov_json else None,
            }
            self._rows.append(row)
            self._next_id += 1
            return {"id": row["id"]}
        if q.startswith("SELECT id, tenant_id, agent_id, manifest_sha256,") and "WHERE id = $1" in q:
            record_id = args[0]
            for r in self._rows:
                if r["id"] == record_id:
                    return dict(r)
            return None
        if q.startswith("SELECT COUNT(*)"):
            tenant_id = args[0]
            n = len([r for r in self._rows if r["tenant_id"] == tenant_id])
            return {"n": n}
        raise AssertionError(f"FakeManifestPool.fetchrow: unrecognised query: {query!r}")

    async def fetch(self, query: str, *args):
        q = " ".join(query.split())
        if q.startswith("SELECT id, tenant_id, agent_id, manifest_sha256,") and "WHERE tenant_id = $1" in q:
            tenant_id, limit, offset = args
            matches = sorted(
                [r for r in self._rows if r["tenant_id"] == tenant_id],
                key=lambda r: r["id"],
                reverse=True,
            )
            return [dict(r) for r in matches[offset : offset + limit]]
        raise AssertionError(f"FakeManifestPool.fetch: unrecognised query: {query!r}")


@pytest.fixture
def manifest_pool_state(monkeypatch):
    import yashigani.db as db_module

    pool = FakeManifestPool()
    monkeypatch.setattr(db_module, "get_pool", lambda: pool, raising=False)
    return pool


_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


def _ceremony_body(**overrides) -> dict:
    manifest_yaml = overrides.pop("manifest_yaml", "name: conformance-agent\nupstream: http://x\n")
    body = {
        "tenant_id": _PLATFORM_TENANT_ID,
        "agent_id": "conformance-agent",
        "manifest_yaml": manifest_yaml,
        "operator_identity": "conformance-admin1",
        "manifest_sha256": hashlib.sha256(manifest_yaml.encode("utf-8")).hexdigest(),
        "confirmed_at": "2026-07-23T00:00:00+00:00",
        "ack_text_shown": "I confirm this manifest is correct.",
        "ack_response": "Y",
        "signature_provenance": {"alg": "ed25519", "signer": "spiffe://yashigani/cli", "sig": "deadbeef" * 8},
    }
    body.update(overrides)
    return body


class TestManifestRegistrationsList:
    # GAP-CLOSED: GET /admin/manifest-registrations
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/manifest-registrations").status_code == 401

    def test_no_pool_returns_500_not_503_SPEC_DIVERGENCE(self, bo_app, session_store, caddy_headers):
        """SPEC-CONFORMANCE DIVERGENCE (manifest_history.py:48-56): `_get_pool()`
        checks `if pool is None: raise HTTPException(503, database_unavailable)`,
        but the underlying `yashigani.db.get_pool()` (postgres.py:177-180) itself
        raises RuntimeError when the pool is uninitialised — it NEVER returns
        None. The `if pool is None` branch is therefore dead code; the actual,
        observable behaviour offline (and in any deployment where the DB pool
        genuinely failed to initialise) is an unhandled RuntimeError caught by
        the app's generic Exception handler (app.py:1244-1249), producing
        HTTP 500 {"error": "internal_error"} — NOT the documented 503. Reported
        as a real finding, not silently worked around.

        Uses a LOCAL TestClient(raise_server_exceptions=False) rather than the
        shared admin_client fixture: Starlette's ServerErrorMiddleware always
        re-raises after building the response (starlette/middleware/errors.py
        'We always continue to raise the exception ... allows test clients to
        optionally raise the error within the test case') — with the conftest
        fixtures' default raise_server_exceptions=True, TestClient re-raises
        the RuntimeError into the test process itself even though a real
        deployment (uvicorn) only ever sees the properly-formed 500 JSON
        response. This one test opts out of that TestClient convenience to
        observe what a real client actually receives."""
        from fastapi.testclient import TestClient

        session = session_store.create(
            account_id="conformance-admin-divergence", account_tier="admin", client_ip="127.0.0.1"
        )
        with TestClient(bo_app, headers=caddy_headers, raise_server_exceptions=False) as client:
            client.cookies.set("__Host-yashigani_admin_session", session.token)
            r = client.get("/admin/manifest-registrations")
            assert r.status_code == 500
            assert r.json()["error"] == "internal_error"

    def test_real_pool_empty_list(self, admin_client, manifest_pool_state):
        r = admin_client.get("/admin/manifest-registrations")
        assert r.status_code == 200
        body = r.json()
        assert body == {"items": [], "total": 0, "limit": 50, "offset": 0}

    def test_real_pool_lists_registered_record(self, admin_client, stepup_admin_client, manifest_pool_state, mock_audit_writer):
        stepup_admin_client.post("/admin/manifest-registrations/ceremony", json=_ceremony_body())
        r = admin_client.get("/admin/manifest-registrations")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        item = body["items"][0]
        assert item["agent_id"] == "conformance-agent"
        assert item["has_signature_provenance"] is True


class TestManifestRegistrationDetail:
    # GAP-CLOSED: GET /admin/manifest-registrations/{record_id}
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/manifest-registrations/1").status_code == 401

    def test_not_found_404(self, admin_client, manifest_pool_state):
        r = admin_client.get("/admin/manifest-registrations/999")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "record_not_found"

    def test_real_pool_returns_full_detail(self, admin_client, stepup_admin_client, manifest_pool_state, mock_audit_writer):
        create = stepup_admin_client.post(
            "/admin/manifest-registrations/ceremony", json=_ceremony_body()
        )
        record_id = create.json()["manifest_registration_id"]
        r = admin_client.get(f"/admin/manifest-registrations/{record_id}")
        assert r.status_code == 200
        body = r.json()
        assert body["agent_id"] == "conformance-agent"
        assert body["manifest_yaml_blob"] == "name: conformance-agent\nupstream: http://x\n"
        assert body["signature_provenance"]["alg"] == "ed25519"


class TestManifestRegistrationCeremony:
    # GAP-CLOSED: POST /admin/manifest-registrations/ceremony (step-up required)
    def test_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/manifest-registrations/ceremony", json=_ceremony_body())
        assert r.status_code == 401

    def test_admin_without_stepup_401(self, admin_client, manifest_pool_state):
        r = admin_client.post("/admin/manifest-registrations/ceremony", json=_ceremony_body())
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "step_up_required"

    def test_ack_not_y_rejected_422(self, stepup_admin_client, manifest_pool_state):
        r = stepup_admin_client.post(
            "/admin/manifest-registrations/ceremony",
            json=_ceremony_body(ack_response="N"),
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "ceremony_ack_required"

    def test_sha256_mismatch_rejected_422(self, stepup_admin_client, manifest_pool_state):
        r = stepup_admin_client.post(
            "/admin/manifest-registrations/ceremony",
            json=_ceremony_body(manifest_sha256="0" * 64),
        )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "manifest_sha256_mismatch"

    def test_real_pool_ceremony_success(self, stepup_admin_client, manifest_pool_state, mock_audit_writer):
        r = stepup_admin_client.post(
            "/admin/manifest-registrations/ceremony", json=_ceremony_body()
        )
        assert r.status_code == 201
        body = r.json()
        assert body["manifest_registration_id"] == 1
        assert body["audit_event_id"]
        mock_audit_writer.write.assert_called_once()
        from yashigani.audit.schema import ManifestCeremonyEvent

        event = mock_audit_writer.write.call_args[0][0]
        assert isinstance(event, ManifestCeremonyEvent)
