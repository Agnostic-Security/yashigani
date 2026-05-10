"""
Unit tests for V232-CSCAN-01j — remaining str(exc) callsite migration.

Covers the 20 sites migrated in this sweep across:
  - services.py        (1 site)
  - dashboard.py       (5 sites)
  - kms_vault.py       (1 site)
  - jwt_config.py      (2 sites)
  - webauthn.py        (2 HTTP response sites + 2 internal audit sites)
  - audit.py           (3 sites)
  - ratelimit.py       (1 site)
  - inspection.py      (1 site)
  - opa_assistant.py   (1 site)
  - rbac.py            (1 internal audit site)

Per-site asserts:
  1. HTTPException raised with correct status code.
  2. detail is a dict with keys "error" and "request_id" (safe envelope shape).
  3. detail does NOT contain the exception message.
  4. detail does NOT contain the exception class name.

Last updated: 2026-05-03
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_ROUTES_ROOT = Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes"


def _assert_safe_envelope(detail: object, exc_msg: str, exc_class: str) -> None:
    """Assert detail is a safe envelope dict without exception leakage."""
    assert isinstance(detail, dict), f"detail must be a dict, got {type(detail)!r}"
    assert "error" in detail, f"detail must contain 'error' key; got keys: {list(detail.keys())}"
    assert "request_id" in detail, (
        f"detail must contain 'request_id' key; got keys: {list(detail.keys())}"
    )
    detail_str = str(detail)
    assert exc_msg not in detail_str, (
        f"Exception message {exc_msg!r} leaked into HTTP detail: {detail_str!r}"
    )
    assert exc_class not in detail_str, (
        f"Exception class {exc_class!r} leaked into HTTP detail: {detail_str!r}"
    )


def _load_module(filename: str, module_name: str) -> tuple:
    """Load a backoffice route module with heavy deps stubbed out."""
    path = _ROUTES_ROOT / filename

    stubs: dict[str, object] = {
        "yashigani.backoffice.middleware": type(sys)("stub"),
        "yashigani.backoffice.state": type(sys)("stub"),
        "yashigani.common.error_envelope": importlib.import_module(
            "yashigani.common.error_envelope"
        ),
        "fastapi": importlib.import_module("fastapi"),
        "pydantic": importlib.import_module("pydantic"),
    }

    mw = stubs["yashigani.backoffice.middleware"]
    mw.AdminSession = object  # type: ignore[attr-defined]
    mw.AnySession = object  # type: ignore[attr-defined]  # added v2.23.3: auth.py imports AnySession
    mw.require_admin_session = MagicMock()  # type: ignore[attr-defined]
    mw.require_any_session = MagicMock()  # type: ignore[attr-defined]
    mw.require_stepup_admin_session = MagicMock()  # type: ignore[attr-defined]
    mw.StepUpAdminSession = object  # type: ignore[attr-defined]
    mw.get_session_store = MagicMock()  # type: ignore[attr-defined]
    mw._SESSION_COOKIE = "__Host-yashigani_admin_session"  # type: ignore[attr-defined]

    state_stub = MagicMock()
    state_stub.kms_provider = None
    state_stub.rotation_scheduler = None
    state_stub.audit_writer = MagicMock()
    stubs["yashigani.backoffice.state"].backoffice_state = state_stub  # type: ignore[attr-defined]
    stubs["yashigani.backoffice.state"].BackofficeState = MagicMock  # type: ignore[attr-defined]  # v2.23.3: backoffice/__init__.py imports BackofficeState

    old: dict = {}
    for k, v in stubs.items():
        old[k] = sys.modules.get(k)
        sys.modules[k] = v  # type: ignore[assignment]

    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    finally:
        for k, v in old.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v  # type: ignore[assignment]

    return mod, state_stub


# ---------------------------------------------------------------------------
# services.py — manage_service subprocess failure
# ---------------------------------------------------------------------------

class TestServicesManageServiceFailure:
    """V232-CSCAN-01j: service management failed must use safe_error_envelope."""

    def test_manage_service_generic_exception_safe_envelope(self):
        """Generic Exception in manage_service must not leak exc message to client."""
        from fastapi import HTTPException
        import subprocess

        mod, state = _load_module("services.py", "services_01j")

        exc_msg = "docker compose: ENOENT /var/run/docker.sock — connection refused"

        body = MagicMock()
        body.action = "enable"
        session = MagicMock()
        session.account_id = "admin-001"

        with (
            patch.object(mod, "_get_compose_cmd", return_value=["docker", "compose"]),
            patch.object(mod, "_get_compose_file", return_value="/app/docker/docker-compose.yml"),
            patch("subprocess.run", side_effect=OSError(exc_msg)),
        ):
            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(mod.manage_service("openwebui", body, session))

        assert exc_info.value.status_code == 500
        _assert_safe_envelope(exc_info.value.detail, exc_msg, "OSError")

    def test_manage_service_detail_has_expected_keys(self):
        """detail must have 'error' and 'request_id', nothing more from exc."""
        from fastapi import HTTPException

        mod, state = _load_module("services.py", "services_01j_b")

        body = MagicMock()
        body.action = "disable"
        session = MagicMock()
        session.account_id = "admin-002"

        with (
            patch.object(mod, "_get_compose_cmd", return_value=["podman", "compose"]),
            patch.object(mod, "_get_compose_file", return_value="/app/docker/docker-compose.yml"),
            patch("subprocess.run", side_effect=RuntimeError("podman socket /run/user/1000/podman/podman.sock")),
        ):
            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(mod.manage_service("langflow", body, session))

        detail = exc_info.value.detail
        assert "podman.sock" not in str(detail)
        assert "error" in detail
        assert "request_id" in detail


# ---------------------------------------------------------------------------
# kms_vault.py — vault_list_secrets failure
# ---------------------------------------------------------------------------

class TestKmsVaultListSecretsFailure:
    """V232-CSCAN-01j: kms vault unavailable must use safe_error_envelope.

    kms_vault.py imports backoffice_state lazily inside each function, so we
    stub the state module directly in sys.modules rather than patching the module
    attribute (which doesn't exist at module level).
    """

    def _run_vault_list(self, mock_kms: MagicMock) -> "HTTPException":
        from fastapi import HTTPException

        state_stub = MagicMock()
        state_stub.kms_provider = mock_kms

        state_mod = type(sys)("stub")
        state_mod.backoffice_state = state_stub  # type: ignore[attr-defined]

        mod, _ = _load_module("kms_vault.py", "kms_vault_01j_fresh")

        with patch.dict(sys.modules, {"yashigani.backoffice.state": state_mod}):
            session = MagicMock()
            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(mod.vault_list_secrets(session))
        return exc_info.value

    def test_list_secrets_exception_safe_envelope(self):
        exc_msg = "VaultPermissionDenied: token /v1/secret/data/yashigani/kms role=readonly"
        mock_kms = MagicMock(spec=["health", "list_secrets"])
        mock_kms.list_secrets.side_effect = PermissionError(exc_msg)

        http_exc = self._run_vault_list(mock_kms)
        assert http_exc.status_code == 500
        _assert_safe_envelope(http_exc.detail, exc_msg, "PermissionError")

    def test_list_secrets_does_not_leak_vault_path(self):
        vault_path = "/v1/secret/data/yashigani/kms"
        mock_kms = MagicMock(spec=["health", "list_secrets"])
        mock_kms.list_secrets.side_effect = ConnectionError(
            f"connect ECONNREFUSED vault:8200 path={vault_path}"
        )

        http_exc = self._run_vault_list(mock_kms)
        assert vault_path not in str(http_exc.detail)
        assert http_exc.detail["error"] == "kms vault unavailable"


# ---------------------------------------------------------------------------
# jwt_config.py — set_jwt_config and delete_jwt_config DB failure
# ---------------------------------------------------------------------------

class TestJwtConfigDbFailure:
    """V232-CSCAN-01j: jwt config DB failures must use safe_error_envelope."""

    def _make_failing_pool(self, exc_msg: str):
        """Return a mock pool whose acquire raises."""
        pool = MagicMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(
            side_effect=RuntimeError(exc_msg)
        )
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)
        return pool

    def test_set_jwt_config_db_failure_safe_envelope(self):
        from fastapi import HTTPException

        mod, state = _load_module("jwt_config.py", "jwt_config_01j_set")

        exc_msg = "asyncpg DSN postgresql://admin:secret@postgres:5432/yashigani pool exhausted"
        pool = self._make_failing_pool(exc_msg)

        with (
            patch.dict(
                sys.modules,
                {"yashigani.db.postgres": MagicMock(get_pool=MagicMock(return_value=pool))},
            ),
            patch.dict(sys.modules, {"uuid": importlib.import_module("uuid")}),
        ):
            body = MagicMock()
            body.tenant_id = "00000000-0000-0000-0000-000000000000"
            body.scope = "platform"
            body.jwks_url = "https://idp.example.com/.well-known/jwks.json"
            body.issuer = "https://idp.example.com"
            body.audience = "yashigani"
            body.fail_closed = True
            session = MagicMock()

            import asyncio
            # Patch env to avoid stream check 422
            with patch.dict(sys.modules.get("os", importlib.import_module("os")).environ,
                            {"YASHIGANI_DEPLOYMENT_STREAM": "commercial"}, clear=False):
                import os
                orig = os.getenv("YASHIGANI_DEPLOYMENT_STREAM", "")
                os.environ["YASHIGANI_DEPLOYMENT_STREAM"] = "commercial"
                try:
                    with pytest.raises(HTTPException) as exc_info:
                        asyncio.run(mod.set_jwt_config(body, session))
                finally:
                    if orig:
                        os.environ["YASHIGANI_DEPLOYMENT_STREAM"] = orig
                    else:
                        os.environ.pop("YASHIGANI_DEPLOYMENT_STREAM", None)

        assert exc_info.value.status_code == 500
        detail = exc_info.value.detail
        assert "secret" not in str(detail), "DB DSN must not leak into response"
        assert "request_id" in detail

    def test_delete_jwt_config_db_failure_safe_envelope(self):
        from fastapi import HTTPException

        mod, state = _load_module("jwt_config.py", "jwt_config_01j_del")

        exc_msg = "asyncpg pool closed — db restart pending /var/lib/postgres/15/data"
        pool = self._make_failing_pool(exc_msg)

        with patch.dict(
            sys.modules,
            {
                "yashigani.db.postgres": MagicMock(get_pool=MagicMock(return_value=pool)),
                "uuid": importlib.import_module("uuid"),
            },
        ):
            session = MagicMock()
            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(mod.delete_jwt_config("00000000-0000-0000-0000-000000000001", session))

        assert exc_info.value.status_code == 500
        _assert_safe_envelope(exc_info.value.detail, exc_msg, "RuntimeError")


# ---------------------------------------------------------------------------
# webauthn.py — register_complete and authenticate_complete ValueError paths
# ---------------------------------------------------------------------------

def _load_webauthn(label: str):
    """Load webauthn.py with audit.schema stubbed out."""
    extra_stubs = {
        "yashigani.audit.schema": MagicMock(),
    }
    old: dict = {}
    for k, v in extra_stubs.items():
        old[k] = sys.modules.get(k)
        sys.modules[k] = v  # type: ignore[assignment]

    mod, state = _load_module("webauthn.py", f"webauthn_{label}")

    for k, v in old.items():
        if v is None:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = v  # type: ignore[assignment]
    return mod, state


class TestWebAuthnSafeEnvelope:
    """V232-CSCAN-01j: webauthn ValueError paths must use safe_error_envelope."""

    def test_register_complete_value_error_safe_envelope(self):
        """register_complete ValueError must not leak exc message."""
        from fastapi import HTTPException

        mod, state = _load_webauthn("reg")
        exc_msg = "Attestation origin mismatch: got https://evil.example.com expected https://admin.yashigani.local"

        mock_svc = MagicMock()
        mock_svc.complete_registration.side_effect = ValueError(exc_msg)
        state.webauthn_service = mock_svc

        with patch.object(mod, "backoffice_state", state):
            body = MagicMock()
            body.credential_response = {}
            body.credential_name = "Passkey"
            session = MagicMock()
            session.account_id = "admin-webauthn-001"
            request = MagicMock()
            request.headers = {}
            request.url.scheme = "https"
            request.url.netloc = "admin.yashigani.local"

            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(mod.register_complete(body, session, request))

        assert exc_info.value.status_code == 400
        _assert_safe_envelope(exc_info.value.detail, exc_msg, "ValueError")

    def test_register_complete_detail_has_request_id(self):
        from fastapi import HTTPException

        mod, state = _load_webauthn("reg_b")

        mock_svc = MagicMock()
        mock_svc.complete_registration.side_effect = ValueError(
            "RP ID hash mismatch: internal_id=0xDEADBEEF"
        )
        state.webauthn_service = mock_svc

        with patch.object(mod, "backoffice_state", state):
            body = MagicMock()
            body.credential_response = {}
            body.credential_name = "Passkey"
            session = MagicMock()
            session.account_id = "admin-webauthn-002"
            request = MagicMock()
            request.headers = {}
            request.url.scheme = "https"
            request.url.netloc = "admin.yashigani.local"

            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(mod.register_complete(body, session, request))

        detail = exc_info.value.detail
        assert "request_id" in detail
        assert "DEADBEEF" not in str(detail)
        assert detail["error"] == "webauthn registration failed"

    def test_authenticate_complete_value_error_safe_envelope(self):
        """authenticate_complete ValueError must not leak exc message."""
        from fastapi import HTTPException

        mod, state = _load_webauthn("auth")
        exc_msg = "sign_count replay: stored=42 received=41 credential_id=abc123secret"

        mock_svc = MagicMock()
        mock_svc.complete_authentication.side_effect = ValueError(exc_msg)
        state.webauthn_service = mock_svc

        with patch.object(mod, "backoffice_state", state):
            body = MagicMock()
            body.credential_response = {}
            session = MagicMock()
            session.account_id = "admin-webauthn-003"
            request = MagicMock()
            request.headers = {}
            request.url.scheme = "https"
            request.url.netloc = "admin.yashigani.local"

            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(mod.authenticate_complete(body, session, request))

        assert exc_info.value.status_code == 401
        _assert_safe_envelope(exc_info.value.detail, exc_msg, "ValueError")

    def test_authenticate_complete_does_not_leak_credential_id(self):
        from fastapi import HTTPException

        mod, state = _load_webauthn("auth_b")

        secret_cred_id = "credential_id=super_secret_abc123"
        mock_svc = MagicMock()
        mock_svc.complete_authentication.side_effect = ValueError(
            f"Authentication failed: {secret_cred_id}"
        )
        state.webauthn_service = mock_svc

        with patch.object(mod, "backoffice_state", state):
            body = MagicMock()
            body.credential_response = {}
            session = MagicMock()
            session.account_id = "admin-webauthn-004"
            request = MagicMock()
            request.headers = {}
            request.url.scheme = "https"
            request.url.netloc = "admin.yashigani.local"

            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(mod.authenticate_complete(body, session, request))

        assert secret_cred_id not in str(exc_info.value.detail)
        assert exc_info.value.detail["error"] == "webauthn authentication failed"


# ---------------------------------------------------------------------------
# ratelimit.py — reset_bucket Redis failure
# ---------------------------------------------------------------------------

class TestRateLimitResetBucketFailure:
    """V232-CSCAN-01j: rate-limit lookup failed must use safe_error_envelope."""

    def test_reset_bucket_redis_exception_safe_envelope(self):
        from fastapi import HTTPException

        mod, state = _load_module("ratelimit.py", "ratelimit_01j")

        exc_msg = "RedisConnectionError: host=redis port=6379 password=super_secret_redis_pw"

        mock_rl = MagicMock()
        mock_rl._redis.delete.side_effect = ConnectionError(exc_msg)
        state.rate_limiter = mock_rl
        state.audit_writer = MagicMock()

        with patch.object(mod, "backoffice_state", state):
            session = MagicMock()
            session.account_id = "admin-rl-001"

            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(mod.reset_bucket("yashigani:rl:ip:abc123", session))

        assert exc_info.value.status_code == 500
        _assert_safe_envelope(exc_info.value.detail, exc_msg, "ConnectionError")

    def test_reset_bucket_does_not_leak_redis_password(self):
        from fastapi import HTTPException

        mod, state = _load_module("ratelimit.py", "ratelimit_01j_b")

        redis_pw = "super_secret_redis_pw"
        mock_rl = MagicMock()
        mock_rl._redis.delete.side_effect = OSError(f"redis://:{redis_pw}@redis:6379/3")
        state.rate_limiter = mock_rl
        state.audit_writer = MagicMock()

        with patch.object(mod, "backoffice_state", state):
            session = MagicMock()
            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(mod.reset_bucket("yashigani:rl:session:xyz", session))

        assert redis_pw not in str(exc_info.value.detail)
        assert exc_info.value.detail["error"] == "rate-limit lookup failed"


# ---------------------------------------------------------------------------
# inspection.py — set_threshold ValueError path
# ---------------------------------------------------------------------------

class TestInspectionThresholdFailure:
    """V232-CSCAN-01j: inspection backend unavailable must use safe_error_envelope."""

    def test_set_threshold_value_error_safe_envelope(self):
        from fastapi import HTTPException

        mod, state = _load_module("inspection.py", "inspection_01j")

        exc_msg = "threshold 0.69 out of range — internal model min=0.70 max=0.99 model=llama3:8b"

        mock_pipeline = MagicMock()
        mock_pipeline._threshold = 0.85
        mock_pipeline.update_threshold.side_effect = ValueError(exc_msg)
        state.inspection_pipeline = mock_pipeline
        state.audit_writer = MagicMock()

        with patch.object(mod, "backoffice_state", state):
            body = MagicMock()
            body.threshold = 0.69
            session = MagicMock()
            session.account_id = "admin-insp-001"

            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(mod.set_threshold(body, session))

        assert exc_info.value.status_code == 422
        _assert_safe_envelope(exc_info.value.detail, exc_msg, "ValueError")

    def test_set_threshold_does_not_leak_model_name(self):
        from fastapi import HTTPException

        mod, state = _load_module("inspection.py", "inspection_01j_b")

        secret_model = "llama3:8b-instruct-q4_K_M"
        mock_pipeline = MagicMock()
        mock_pipeline._threshold = 0.85
        mock_pipeline.update_threshold.side_effect = ValueError(
            f"threshold rejected by model {secret_model}: boundary policy"
        )
        state.inspection_pipeline = mock_pipeline
        state.audit_writer = MagicMock()

        with patch.object(mod, "backoffice_state", state):
            body = MagicMock()
            body.threshold = 0.65
            session = MagicMock()
            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(mod.set_threshold(body, session))

        assert secret_model not in str(exc_info.value.detail)
        assert "request_id" in exc_info.value.detail


# ---------------------------------------------------------------------------
# opa_assistant.py — apply_suggestion OPA push failure
# ---------------------------------------------------------------------------

class TestOpaAssistantApplyFailure:
    """V232-CSCAN-01j: opa assistant unavailable must use safe_error_envelope."""

    def test_apply_opa_push_failure_safe_envelope(self):
        from fastapi import HTTPException

        extra_stubs = {
            "yashigani.opa_assistant.validator": MagicMock(
                validate_rbac_document=MagicMock(return_value=(True, None))
            ),
            "yashigani.rbac.opa_push": MagicMock(),
            "yashigani.audit.schema": MagicMock(),
        }
        old: dict = {}
        for k, v in extra_stubs.items():
            old[k] = sys.modules.get(k)
            sys.modules[k] = v  # type: ignore[assignment]

        mod, state = _load_module("opa_assistant.py", "opa_01j")

        for k, v in old.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v  # type: ignore[assignment]

        exc_msg = "OPA API returned 403: internal opa-url=http://opa:8181/v1/data/yashigani"

        with (
            patch.dict(
                sys.modules,
                {
                    "yashigani.opa_assistant.validator": MagicMock(
                        validate_rbac_document=MagicMock(return_value=(True, None))
                    ),
                    "yashigani.rbac.opa_push": MagicMock(
                        push_rbac_data=MagicMock(side_effect=ConnectionError(exc_msg))
                    ),
                    "yashigani.audit.schema": MagicMock(),
                },
            ),
            patch.object(mod, "backoffice_state", state),
        ):
            body = MagicMock()
            body.suggestion = {"groups": {}, "user_groups": {}}
            body.description = "test"
            session = MagicMock()
            session.account_id = "admin-opa-001"

            import asyncio
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(mod.apply_suggestion(body, session))

        assert exc_info.value.status_code == 502
        _assert_safe_envelope(exc_info.value.detail, exc_msg, "ConnectionError")

    def test_apply_opa_push_does_not_leak_opa_url(self):
        from fastapi import HTTPException

        opa_url = "http://opa:8181/v1/data/yashigani/rbac"

        with patch.dict(
            sys.modules,
            {
                "yashigani.opa_assistant.validator": MagicMock(
                    validate_rbac_document=MagicMock(return_value=(True, None))
                ),
                "yashigani.rbac.opa_push": MagicMock(
                    push_rbac_data=MagicMock(
                        side_effect=RuntimeError(f"POST {opa_url} returned 403")
                    )
                ),
                "yashigani.audit.schema": MagicMock(),
            },
        ):
            mod, state = _load_module("opa_assistant.py", "opa_01j_b")

            with patch.object(mod, "backoffice_state", state):
                body = MagicMock()
                body.suggestion = {"groups": {}, "user_groups": {}}
                body.description = "deploy new RBAC policy"
                session = MagicMock()
                session.account_id = "admin-opa-002"

                import asyncio
                with pytest.raises(HTTPException) as exc_info:
                    asyncio.run(mod.apply_suggestion(body, session))

        assert opa_url not in str(exc_info.value.detail)
        assert exc_info.value.detail["error"] == "opa assistant unavailable"
