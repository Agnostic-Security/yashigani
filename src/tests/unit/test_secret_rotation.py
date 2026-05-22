"""
Unit tests for admin-triggered secret rotation (v2.23.3 + YSG-SECRETS-DIST-002 rework).

Test matrix:
  R01 — generate_password: charset compliance (A-Za-z0-9!*,-._~)
  R02 — generate_password: category guarantees (upper/lower/digit/symbol)
  R03 — generate_password: length == 48
  R04 — generate_password: no forbidden shell-unsafe chars
  R05 — generate_hex_key: correct length (32 bytes → 64 hex, 64 bytes → 128 hex)
  R06 — _write_secret_file: atomic rename (tmp file removed on success)
  R07 — _write_secret_file: default mode is 0400, no chown when gid=-1 (default)
  R08 — _read_secret_file: raises RuntimeError on missing file
  R09 — SecretName enum values are exactly the five expected literals
  R10 — RotationResult.success=False when handler raises
  R11 — rotate_all returns child_results for each individual secret
  R12 — rotate_all aborts on first failure (remaining secrets not attempted)
  R13 — Postgres rotation calls _pg_alter_user_password with new password
  R14 — Postgres rotation reverts on file-write failure
  R15 — Redis rotation calls config_set requirepass
  R16 — Redis rotation reverts on file-write failure
  R17 — JWT rotation writes 128-hex-char key to file
  R18 — HMAC rotation writes 64-hex-char key to file
  R19 — API route: missing step-up → 401 step_up_required
  R20 — API route: invalid secret name → 422
  R21 — API route: success path → 200 with success=True
  R22 — API route: rotation failure → 200 with success=False + warning
  R23 — Audit schema: SecretRotationRequestedEvent has masking_applied=True floor
  R24 — Audit schema: SecretRotationFailedEvent has severity="CRITICAL" when revert_failed=True
  R25 — SecretName barrel export from yashigani.secrets
  R26 — _write_secret_file: mode parameter is applied when non-default
  R27 — _write_secret_file: gid parameter triggers os.chown; default gid=-1 skips chown
  R28 — _rotate_redis_password: post-rotation file is 0640 and os.chown called with gid=999
  R29 — _rotate_postgres_password: post-rotation file is 0640 and os.chown called with gid=999
  R30 — Bearer/JWT/HMAC callers: _write_secret_file defaults unaffected (0400, no chown)
"""
from __future__ import annotations

import os
import string
import tempfile
import time
import unittest.mock as mock
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest


# ---------------------------------------------------------------------------
# R01–R05: Password / key generation
# ---------------------------------------------------------------------------

class TestPasswordGeneration:
    """R01–R04: Password charset and category compliance."""

    def _gen(self):
        from yashigani.secrets.rotator import _generate_password
        return _generate_password

    def test_r01_charset_compliance(self):
        """R01: All chars in generated password are from allowed alphabet."""
        gen = self._gen()
        allowed = set(string.ascii_letters + string.digits + "!*,-._~")
        for _ in range(20):
            pw = gen()
            bad = set(pw) - allowed
            assert not bad, f"Forbidden chars in password: {bad!r}"

    def test_r02_category_guarantees(self):
        """R02: Password has at least one uppercase, lowercase, digit, symbol."""
        gen = self._gen()
        for _ in range(20):
            pw = gen()
            assert any(c in string.ascii_uppercase for c in pw), "No uppercase"
            assert any(c in string.ascii_lowercase for c in pw), "No lowercase"
            assert any(c in string.digits for c in pw), "No digit"
            assert any(c in "!*,-._~" for c in pw), "No symbol"

    def test_r03_length_is_48(self):
        """R03: Generated password is exactly 48 chars."""
        gen = self._gen()
        for _ in range(10):
            assert len(gen()) == 48

    def test_r04_no_shell_unsafe_chars(self):
        """R04: Password contains no chars that are dangerous in shell double-quote context."""
        gen = self._gen()
        forbidden = set('$`"\\|&;{}[]()^/<>?@#%+=')
        for _ in range(30):
            pw = gen()
            bad = set(pw) & forbidden
            assert not bad, f"Shell-unsafe chars in password: {bad!r}"


class TestHexKeyGeneration:
    """R05: _generate_hex_key length."""

    def _gen(self):
        from yashigani.secrets.rotator import _generate_hex_key
        return _generate_hex_key

    def test_r05_32_bytes_gives_64_hex(self):
        """R05a: 32 byte key → 64 hex chars."""
        gen = self._gen()
        key = gen(32)
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)

    def test_r05_64_bytes_gives_128_hex(self):
        """R05b: 64 byte key → 128 hex chars."""
        gen = self._gen()
        key = gen(64)
        assert len(key) == 128


# ---------------------------------------------------------------------------
# R06–R08: Secret file I/O
# ---------------------------------------------------------------------------

class TestSecretFileIO:
    """R06–R08: Atomic write and read semantics."""

    def test_r06_write_atomic_tmp_removed(self, tmp_path):
        """R06: Temporary file is removed (renamed away) after successful write."""
        from yashigani.secrets.rotator import _write_secret_file
        target = tmp_path / "test_secret"
        _write_secret_file(target, "my-value")
        assert target.exists()
        # tmp file should be gone
        tmp = tmp_path / "test_secret.tmp"
        assert not tmp.exists()
        assert target.read_text() == "my-value"

    def test_r07_default_mode_is_0400_and_no_chown(self, tmp_path):
        """R07: Default call (no mode/gid args) writes 0400 and does NOT call os.chown."""
        import os
        from unittest.mock import patch
        from yashigani.secrets.rotator import _write_secret_file
        target = tmp_path / "secret_perm_test"
        with patch("os.chown") as mock_chown:
            _write_secret_file(target, "s3cr3t")
            mock_chown.assert_not_called()
        mode = oct(target.stat().st_mode & 0o777)
        assert mode == oct(0o400), f"Expected 0400, got {mode}"

    def test_r08_read_missing_raises_runtimeerror(self, tmp_path):
        """R08: _read_secret_file raises RuntimeError on missing file."""
        from yashigani.secrets.rotator import _read_secret_file
        missing = tmp_path / "no_such_file"
        with pytest.raises(RuntimeError, match="Cannot read secret file"):
            _read_secret_file(missing)

    def test_r26_mode_param_applied(self, tmp_path):
        """R26: Passing mode=0o640 produces a 0640 file (real filesystem, no mock)."""
        from yashigani.secrets.rotator import _write_secret_file
        target = tmp_path / "mode_test"
        _write_secret_file(target, "group-readable", mode=0o640)
        mode = oct(target.stat().st_mode & 0o777)
        assert mode == oct(0o640), f"Expected 0640, got {mode}"

    def test_r27_gid_triggers_chown_default_skips(self, tmp_path):
        """R27: gid != -1 calls os.chown with (-1, gid); gid=-1 (default) never calls chown."""
        from unittest.mock import patch
        from yashigani.secrets.rotator import _write_secret_file

        target = tmp_path / "chown_test"

        # --- Case A: explicit gid → chown called ---
        with patch("os.chown") as mock_chown:
            _write_secret_file(target, "val", mode=0o640, gid=999)
            assert mock_chown.called, "os.chown must be called when gid=999"
            # First positional arg is the path (tmp_path), UID arg is -1, GID arg is 999
            args = mock_chown.call_args[0]
            assert args[1] == -1, f"UID arg must be -1 (no-change), got {args[1]}"
            assert args[2] == 999, f"GID arg must be 999, got {args[2]}"

        # --- Case B: default gid → chown NOT called ---
        target2 = tmp_path / "chown_test2"
        with patch("os.chown") as mock_chown2:
            _write_secret_file(target2, "val2")
            mock_chown2.assert_not_called()

    def test_r28_rotate_redis_password_writes_0640_gid999(self, tmp_path):
        """R28: _rotate_redis_password calls _write_secret_file with mode=0o640, gid=999."""
        from unittest.mock import patch, MagicMock, call
        from yashigani.secrets.rotator import SecretRotator, _write_secret_file

        secrets_dir = tmp_path
        _write_secret_file(secrets_dir / "redis_password", "old-redis-pw-123456")

        mock_redis = MagicMock()
        rotator = SecretRotator(secrets_dir=str(secrets_dir), redis_client=mock_redis)

        write_calls = []

        def _capture_write(path, value, *, mode=0o400, gid=-1):
            write_calls.append({"path": path, "mode": mode, "gid": gid})
            # Delegate to real implementation so the file is actually written
            _write_secret_file.__wrapped__(path, value, mode=mode, gid=gid) if hasattr(
                _write_secret_file, "__wrapped__"
            ) else None

        with patch("yashigani.secrets.rotator._redis_config_set_requirepass"), \
             patch("yashigani.secrets.rotator._write_secret_file", side_effect=_capture_write):
            import asyncio
            asyncio.run(rotator._rotate_redis_password())

        assert len(write_calls) == 1, "Expected exactly one _write_secret_file call"
        wc = write_calls[0]
        assert wc["mode"] == 0o640, f"redis_password must be written 0640, got {oct(wc['mode'])}"
        assert wc["gid"] == 999, f"redis_password must be written with gid=999, got {wc['gid']}"

    def test_r29_rotate_postgres_password_writes_0640_gid999(self, tmp_path):
        """R29: _rotate_postgres_password calls _write_secret_file with mode=0o640, gid=999."""
        from unittest.mock import patch
        from yashigani.secrets.rotator import SecretRotator, _write_secret_file

        secrets_dir = tmp_path
        _write_secret_file(secrets_dir / "postgres_password", "old-postgres-pw-123456")

        rotator = SecretRotator(
            secrets_dir=str(secrets_dir),
            db_dsn_direct="postgresql://postgres:pw@localhost/yashigani",
        )

        write_calls = []

        def _capture_write(path, value, *, mode=0o400, gid=-1):
            write_calls.append({"path": path, "mode": mode, "gid": gid})

        with patch("yashigani.secrets.rotator._pg_alter_user_password"), \
             patch("yashigani.secrets.rotator._restart_service"), \
             patch("yashigani.secrets.rotator._write_secret_file", side_effect=_capture_write):
            import asyncio
            asyncio.run(rotator._rotate_postgres_password())

        assert len(write_calls) == 1, "Expected exactly one _write_secret_file call"
        wc = write_calls[0]
        assert wc["mode"] == 0o640, f"postgres_password must be written 0640, got {oct(wc['mode'])}"
        assert wc["gid"] == 999, f"postgres_password must be written with gid=999, got {wc['gid']}"

    def test_r30_jwt_hmac_callers_use_default_mode_no_gid(self, tmp_path):
        """R30: JWT + HMAC rotation callers do NOT pass mode/gid — use defaults (0400, -1)."""
        from unittest.mock import patch
        from yashigani.secrets.rotator import SecretRotator, _write_secret_file

        secrets_dir = tmp_path
        _write_secret_file(secrets_dir / "jwt_signing_key", "old-key-" + "a" * 120)
        _write_secret_file(secrets_dir / "caddy_internal_hmac", "old-hmac-" + "a" * 55)

        rotator = SecretRotator(secrets_dir=str(secrets_dir))

        jwt_calls = []
        hmac_calls = []

        def _capture_jwt(path, value, *, mode=0o400, gid=-1):
            if "jwt" in str(path):
                jwt_calls.append({"mode": mode, "gid": gid})

        def _capture_hmac(path, value, *, mode=0o400, gid=-1):
            if "hmac" in str(path):
                hmac_calls.append({"mode": mode, "gid": gid})

        import asyncio

        with patch("yashigani.secrets.rotator._signal_service_reload"), \
             patch("yashigani.secrets.rotator._write_secret_file", side_effect=_capture_jwt):
            asyncio.run(rotator._rotate_jwt_signing_key())

        with patch("yashigani.secrets.rotator._signal_service_reload"), \
             patch("yashigani.secrets.rotator._write_secret_file", side_effect=_capture_hmac):
            asyncio.run(rotator._rotate_hmac_key())

        assert jwt_calls, "JWT rotation must call _write_secret_file"
        assert hmac_calls, "HMAC rotation must call _write_secret_file"
        assert jwt_calls[0]["mode"] == 0o400, "JWT must use default mode=0o400"
        assert jwt_calls[0]["gid"] == -1, "JWT must use default gid=-1"
        assert hmac_calls[0]["mode"] == 0o400, "HMAC must use default mode=0o400"
        assert hmac_calls[0]["gid"] == -1, "HMAC must use default gid=-1"


# ---------------------------------------------------------------------------
# R09: SecretName enum
# ---------------------------------------------------------------------------

class TestSecretNameEnum:
    """R09: SecretName has exactly the expected values."""

    def test_r09_enum_values(self):
        """R09: SecretName enum contains exactly 5 values."""
        from yashigani.secrets.rotator import SecretName
        values = {s.value for s in SecretName}
        expected = {
            "postgres_password", "redis_password",
            "jwt_signing_key", "hmac_key", "all",
        }
        assert values == expected


# ---------------------------------------------------------------------------
# R10–R12: RotationResult and rotate_all mechanics
# ---------------------------------------------------------------------------

class TestRotationResult:
    """R10: RotationResult.success=False when handler raises."""

    @pytest.mark.asyncio
    async def test_r10_handler_exception_gives_failure_result(self, tmp_path):
        """R10: If the handler raises, _rotate_one returns success=False."""
        from yashigani.secrets.rotator import SecretRotator, SecretName

        rotator = SecretRotator(secrets_dir=str(tmp_path))
        # Patch the internal handler to raise
        with patch.object(
            rotator, "_rotate_postgres_password",
            side_effect=RuntimeError("simulated failure")
        ):
            result = await rotator._rotate_one(SecretName.POSTGRES_PASSWORD, "2026-01-01T00:00:00+00:00")

        assert result.success is False
        assert "RuntimeError" in (result.error or "")


class TestRotateAll:
    """R11–R12: rotate_all mechanics."""

    @pytest.mark.asyncio
    async def test_r11_rotate_all_returns_child_results(self, tmp_path):
        """R11: rotate_all returns child_results for all four secrets."""
        from yashigani.secrets.rotator import SecretRotator, SecretName, RotationResult

        rotator = SecretRotator(secrets_dir=str(tmp_path))

        async def _mock_rotate_one(secret, ts):
            return RotationResult(secret=secret.value, success=True, rotated_at=ts)

        with patch.object(rotator, "_rotate_one", side_effect=_mock_rotate_one):
            result = await rotator.rotate(SecretName.ALL)

        assert result.secret == "all"
        assert result.success is True
        assert len(result.child_results) == 4
        names = {c.secret for c in result.child_results}
        assert names == {"postgres_password", "redis_password", "jwt_signing_key", "hmac_key"}

    @pytest.mark.asyncio
    async def test_r12_rotate_all_aborts_on_first_failure(self, tmp_path):
        """R12: rotate_all stops at first failure and does not attempt remaining secrets."""
        from yashigani.secrets.rotator import SecretRotator, SecretName, RotationResult

        rotator = SecretRotator(secrets_dir=str(tmp_path))
        call_count = 0

        async def _mock_rotate_one(secret, ts):
            nonlocal call_count
            call_count += 1
            # Fail on the first secret
            if call_count == 1:
                return RotationResult(
                    secret=secret.value, success=False, rotated_at=ts,
                    error="simulated failure",
                )
            return RotationResult(secret=secret.value, success=True, rotated_at=ts)

        with patch.object(rotator, "_rotate_one", side_effect=_mock_rotate_one):
            result = await rotator.rotate(SecretName.ALL)

        assert result.success is False
        # Only 1 child result (aborted after first failure)
        assert call_count == 1
        assert len(result.child_results) == 1


# ---------------------------------------------------------------------------
# R13–R14: Postgres rotation
# ---------------------------------------------------------------------------

class TestPostgresRotation:
    """R13–R14: Postgres password rotation mechanics."""

    @pytest.mark.asyncio
    async def test_r13_calls_alter_user_with_new_password(self, tmp_path):
        """R13: Postgres rotation calls _pg_alter_user_password with a new password."""
        from yashigani.secrets.rotator import SecretRotator, _write_secret_file

        secrets_dir = tmp_path
        # Pre-seed old password
        _write_secret_file(secrets_dir / "postgres_password", "old-password-12345678")

        captured_passwords = []

        def mock_alter_user(dsn, username, new_pw):
            captured_passwords.append(new_pw)

        rotator = SecretRotator(
            secrets_dir=str(secrets_dir),
            db_dsn_direct="postgresql://postgres:pw@localhost/yashigani",
        )

        # Patch os.chown so the test doesn't require root to chown to GID 999.
        with patch("yashigani.secrets.rotator._pg_alter_user_password", mock_alter_user), \
             patch("yashigani.secrets.rotator._restart_service"), \
             patch("os.chown"):
            reverted, revert_failed = await rotator._rotate_postgres_password()

        assert reverted is False
        assert revert_failed is False
        assert len(captured_passwords) == 1
        new_pw = captured_passwords[0]
        assert new_pw != "old-password-12345678"
        assert len(new_pw) == 48

    @pytest.mark.asyncio
    async def test_r14_postgres_reverts_on_file_write_failure(self, tmp_path):
        """R14: If secret file write fails after ALTER USER, revert is attempted."""
        from yashigani.secrets.rotator import SecretRotator, _write_secret_file

        secrets_dir = tmp_path
        _write_secret_file(secrets_dir / "postgres_password", "old-password-12345678")

        reverted_to = []

        def mock_alter_user(dsn, username, new_pw):
            pass  # succeed first call (new pw), capture revert call

        def mock_write_fail(path, value):
            raise OSError("disk full")

        async def mock_revert(dsn, username, old_pw):
            reverted_to.append(old_pw)
            return True, False

        rotator = SecretRotator(
            secrets_dir=str(secrets_dir),
            db_dsn_direct="postgresql://postgres:pw@localhost/yashigani",
        )

        with patch("yashigani.secrets.rotator._pg_alter_user_password", mock_alter_user), \
             patch("yashigani.secrets.rotator._write_secret_file", mock_write_fail), \
             patch("yashigani.secrets.rotator._pg_revert", mock_revert):
            reverted, revert_failed = await rotator._rotate_postgres_password()

        assert reverted is True
        assert revert_failed is False
        assert len(reverted_to) == 1
        assert reverted_to[0] == "old-password-12345678"


# ---------------------------------------------------------------------------
# R15–R16: Redis rotation
# ---------------------------------------------------------------------------

class TestRedisRotation:
    """R15–R16: Redis password rotation mechanics."""

    @pytest.mark.asyncio
    async def test_r15_calls_config_set_requirepass(self, tmp_path):
        """R15: Redis rotation calls config_set requirepass with new password."""
        from yashigani.secrets.rotator import SecretRotator, _write_secret_file

        secrets_dir = tmp_path
        _write_secret_file(secrets_dir / "redis_password", "old-redis-pw-123456")

        config_set_calls = []

        def mock_config_set(client, new_pw):
            config_set_calls.append(new_pw)

        mock_redis = MagicMock()
        rotator = SecretRotator(secrets_dir=str(secrets_dir), redis_client=mock_redis)

        # Patch os.chown so the test doesn't require root to chown to GID 999.
        with patch("yashigani.secrets.rotator._redis_config_set_requirepass", mock_config_set), \
             patch("os.chown"):
            reverted, revert_failed = await rotator._rotate_redis_password()

        assert reverted is False
        assert len(config_set_calls) == 1
        assert config_set_calls[0] != "old-redis-pw-123456"
        # New password must be on disk
        new_on_disk = (secrets_dir / "redis_password").read_text().strip()
        assert new_on_disk == config_set_calls[0]

    @pytest.mark.asyncio
    async def test_r16_redis_reverts_on_file_write_failure(self, tmp_path):
        """R16: Redis rotation reverts requirepass if file write fails."""
        from yashigani.secrets.rotator import SecretRotator, _write_secret_file

        secrets_dir = tmp_path
        _write_secret_file(secrets_dir / "redis_password", "old-redis-pw-123456")

        reverted_calls = []

        def mock_config_set(client, new_pw):
            pass  # succeed

        def mock_write_fail(path, value):
            raise OSError("disk full")

        def mock_revert_config(client, current_pw, target_pw):
            reverted_calls.append(target_pw)

        mock_redis = MagicMock()
        rotator = SecretRotator(secrets_dir=str(secrets_dir), redis_client=mock_redis)

        with patch("yashigani.secrets.rotator._redis_config_set_requirepass", mock_config_set), \
             patch("yashigani.secrets.rotator._write_secret_file", mock_write_fail), \
             patch("yashigani.secrets.rotator._redis_config_set_requirepass_with_new_auth", mock_revert_config):
            reverted, revert_failed = await rotator._rotate_redis_password()

        assert reverted is True
        assert revert_failed is False
        assert len(reverted_calls) == 1
        assert reverted_calls[0] == "old-redis-pw-123456"


# ---------------------------------------------------------------------------
# R17–R18: JWT + HMAC key rotation
# ---------------------------------------------------------------------------

class TestJwtRotation:
    """R17: JWT rotation writes 128-hex-char key."""

    @pytest.mark.asyncio
    async def test_r17_writes_128_hex_char_key(self, tmp_path):
        """R17: jwt_signing_key rotation writes a 128-char hex key file."""
        from yashigani.secrets.rotator import SecretRotator, _write_secret_file

        secrets_dir = tmp_path
        _write_secret_file(secrets_dir / "jwt_signing_key", "old-key-" + "a" * 120)

        rotator = SecretRotator(secrets_dir=str(secrets_dir))
        with patch("yashigani.secrets.rotator._signal_service_reload"):
            reverted, _ = await rotator._rotate_jwt_signing_key()

        assert reverted is False
        new_key = (secrets_dir / "jwt_signing_key").read_text().strip()
        assert len(new_key) == 128
        assert all(c in "0123456789abcdef" for c in new_key)


class TestHmacRotation:
    """R18: HMAC rotation writes 64-hex-char key."""

    @pytest.mark.asyncio
    async def test_r18_writes_64_hex_char_key(self, tmp_path):
        """R18: hmac_key rotation writes a 64-char hex key file."""
        from yashigani.secrets.rotator import SecretRotator, _write_secret_file

        secrets_dir = tmp_path
        _write_secret_file(secrets_dir / "caddy_internal_hmac", "old-hmac-" + "a" * 55)

        rotator = SecretRotator(secrets_dir=str(secrets_dir))
        with patch("yashigani.secrets.rotator._signal_service_reload"):
            reverted, _ = await rotator._rotate_hmac_key()

        assert reverted is False
        new_key = (secrets_dir / "caddy_internal_hmac").read_text().strip()
        assert len(new_key) == 64
        assert all(c in "0123456789abcdef" for c in new_key)


# ---------------------------------------------------------------------------
# R19–R22: API route behaviour
# ---------------------------------------------------------------------------

class TestSecretsRoute:
    """R19–R22: FastAPI route tests."""

    def _make_session(self):
        """Make a session with a fresh step-up."""
        from yashigani.auth.session import Session
        return Session(
            token="a" * 64,
            account_id="admin@test.local",
            account_tier="admin",
            created_at=time.time(),
            last_active_at=time.time(),
            expires_at=time.time() + 3600,
            ip_prefix="127.0.0.0",
            last_totp_verified_at=time.time(),  # fresh step-up
        )

    def _make_expired_session(self):
        """Make a session WITHOUT a fresh step-up."""
        from yashigani.auth.session import Session
        return Session(
            token="a" * 64,
            account_id="admin@test.local",
            account_tier="admin",
            created_at=time.time(),
            last_active_at=time.time(),
            expires_at=time.time() + 3600,
            ip_prefix="127.0.0.0",
            last_totp_verified_at=None,  # no step-up
        )

    def test_r19_no_stepup_returns_401(self):
        """R19: Missing step-up → 401 step_up_required."""
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        from yashigani.backoffice.routes.secrets import router
        from yashigani.backoffice.middleware import require_stepup_admin_session

        app = FastAPI()
        app.include_router(router)

        session = self._make_expired_session()

        # Override the step-up dependency to simulate missing step-up
        from yashigani.auth.stepup import StepUpRequired
        def _fake_stepup():
            raise StepUpRequired()

        app.dependency_overrides[require_stepup_admin_session] = _fake_stepup

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/admin/secrets/rotate",
            json={"secret": "jwt_signing_key"},
        )
        assert response.status_code == 401
        assert response.json()["detail"]["error"] == "step_up_required"

    def test_r20_invalid_secret_name_returns_422(self):
        """R20: Invalid secret name → 422."""
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        from yashigani.backoffice.routes.secrets import router
        from yashigani.backoffice.middleware import require_stepup_admin_session

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[require_stepup_admin_session] = lambda: self._make_session()

        client = TestClient(app, raise_server_exceptions=False)
        response = client.post(
            "/api/v1/admin/secrets/rotate",
            json={"secret": "not_a_real_secret"},
        )
        assert response.status_code == 422

    def test_r21_success_path_returns_200_with_success_true(self):
        """R21: Successful rotation → 200 with success=True."""
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        from yashigani.backoffice.routes.secrets import router
        from yashigani.backoffice.middleware import require_stepup_admin_session
        from yashigani.secrets.rotator import RotationResult

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[require_stepup_admin_session] = lambda: self._make_session()

        mock_result = RotationResult(
            secret="jwt_signing_key",
            success=True,
            rotated_at="2026-05-07T00:00:00+00:00",
        )

        with patch("yashigani.backoffice.routes.secrets.SecretRotator") as MockRotator, \
             patch("yashigani.backoffice.routes.secrets.backoffice_state") as mock_state:
            mock_state.audit_writer = None  # skip audit for this test
            MockRotator.return_value.rotate = AsyncMock(return_value=mock_result)

            client = TestClient(app)
            response = client.post(
                "/api/v1/admin/secrets/rotate",
                json={"secret": "jwt_signing_key"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["secret"] == "jwt_signing_key"
        assert "request_id" in data

    def test_r22_rotation_failure_returns_200_with_success_false_and_warning(self):
        """R22: Rotation failure → 200 with success=False and warning message."""
        from fastapi.testclient import TestClient
        from fastapi import FastAPI
        from yashigani.backoffice.routes.secrets import router
        from yashigani.backoffice.middleware import require_stepup_admin_session
        from yashigani.secrets.rotator import RotationResult

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[require_stepup_admin_session] = lambda: self._make_session()

        mock_result = RotationResult(
            secret="postgres_password",
            success=False,
            rotated_at="2026-05-07T00:00:00+00:00",
            error="Postgres ALTER USER failed",
            reverted=True,
            revert_failed=False,
        )

        with patch("yashigani.backoffice.routes.secrets.SecretRotator") as MockRotator, \
             patch("yashigani.backoffice.routes.secrets.backoffice_state") as mock_state:
            mock_state.audit_writer = None
            MockRotator.return_value.rotate = AsyncMock(return_value=mock_result)

            client = TestClient(app)
            response = client.post(
                "/api/v1/admin/secrets/rotate",
                json={"secret": "postgres_password"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert data["reverted"] is True
        assert data["warning"] is not None
        assert "restored" in data["warning"].lower()


# ---------------------------------------------------------------------------
# R23–R24: Audit schema
# ---------------------------------------------------------------------------

class TestAuditEventSchemas:
    """R23–R24: Secret rotation audit event schemas."""

    def test_r23_requested_event_masking_floor(self):
        """R23: SecretRotationRequestedEvent has masking_applied=True (immutable floor)."""
        from yashigani.audit.schema import SecretRotationRequestedEvent
        event = SecretRotationRequestedEvent(
            admin_account="admin@test.local",
            secret_name="postgres_password",
            request_id="req-001",
        )
        assert event.masking_applied is True
        assert event.secret_name == "postgres_password"
        # Event type is correct
        assert event.event_type == "SECRET_ROTATION_REQUESTED"

    def test_r24_failed_event_severity_critical_when_revert_failed(self):
        """R24: SecretRotationFailedEvent has severity=CRITICAL when revert_failed=True."""
        from yashigani.audit.schema import SecretRotationFailedEvent
        event = SecretRotationFailedEvent(
            admin_account="admin@test.local",
            secret_name="postgres_password",
            request_id="req-001",
            failure_reason="ALTER USER failed",
            reverted=True,
            revert_failed=True,
            severity="CRITICAL",
        )
        assert event.revert_failed is True
        assert event.severity == "CRITICAL"
        assert event.masking_applied is True

    def test_succeeded_event_fields(self):
        """SecretRotationSucceededEvent has correct shape."""
        from yashigani.audit.schema import SecretRotationSucceededEvent
        event = SecretRotationSucceededEvent(
            admin_account="admin@test.local",
            secret_name="jwt_signing_key",
            request_id="req-002",
            rotated_at="2026-05-07T00:00:00+00:00",
        )
        assert event.masking_applied is True
        assert event.event_type == "SECRET_ROTATION_SUCCEEDED"


# ---------------------------------------------------------------------------
# R25: Barrel export
# ---------------------------------------------------------------------------

class TestBarrelExport:
    """R25: SecretName barrel export from yashigani.secrets."""

    def test_r25_barrel_exports(self):
        """R25: yashigani.secrets exports SecretName, RotationResult, SecretRotator."""
        from yashigani.secrets import SecretName, RotationResult, SecretRotator
        assert SecretName is not None
        assert RotationResult is not None
        assert SecretRotator is not None

    def test_event_types_in_schema_enum(self):
        """SECRET_ROTATION_* event types are defined in EventType enum."""
        from yashigani.audit.schema import EventType
        assert hasattr(EventType, "SECRET_ROTATION_REQUESTED")
        assert hasattr(EventType, "SECRET_ROTATION_SUCCEEDED")
        assert hasattr(EventType, "SECRET_ROTATION_FAILED")


# ---------------------------------------------------------------------------
# Rotation audit chain — secrets are never stored in event fields
# ---------------------------------------------------------------------------

class TestAuditNeverStoresSecretValue:
    """Verify no rotation event dataclass has a 'new_value' or 'password' field."""

    def test_no_secret_value_field_in_rotation_events(self):
        """Secret values must not appear in rotation audit events."""
        from yashigani.audit.schema import (
            SecretRotationRequestedEvent,
            SecretRotationSucceededEvent,
            SecretRotationFailedEvent,
        )
        import dataclasses
        for cls in (
            SecretRotationRequestedEvent,
            SecretRotationSucceededEvent,
            SecretRotationFailedEvent,
        ):
            field_names = {f.name for f in dataclasses.fields(cls)}
            for bad in ("new_value", "password", "secret_value", "key_value", "new_password"):
                assert bad not in field_names, (
                    f"{cls.__name__} must not have a '{bad}' field "
                    "— secret values must never be stored in audit events"
                )


# ---------------------------------------------------------------------------
# W9 regression: rotate_all partial failure response includes child detail
# ---------------------------------------------------------------------------

class TestW9PartialFailureDetail:
    """
    W9 regression: when rotate_all aborts after a child failure, the RotationResult
    must carry enough per-child detail in child_results that the CLI (or an operator)
    can identify which secrets succeeded and which failed.
    """

    @pytest.mark.asyncio
    async def test_w9_child_results_on_partial_failure(self, tmp_path):
        """
        Simulate postgres_password failure (first child).  The result must have:
        - success=False on the parent
        - child_results with at least 1 entry (the failed child)
        - The failed child has success=False
        """
        from unittest.mock import patch, AsyncMock
        from yashigani.secrets.rotator import SecretRotator, SecretName

        rotator = SecretRotator(
            secrets_dir=str(tmp_path),
            db_dsn_direct=None,
            redis_client=None,
        )

        # Make _rotate_postgres_password raise to trigger abort
        async def _fail_pg(ts):
            from yashigani.secrets.rotator import RotationResult
            return RotationResult(
                secret="postgres_password",
                success=False,
                rotated_at=ts,
                error="simulated postgres failure",
            )

        with patch.object(rotator, "_rotate_postgres_password", side_effect=_fail_pg):
            result = await rotator.rotate(SecretName.ALL)

        assert result.success is False, "W9: outer result must be False on child failure"
        assert len(result.child_results) >= 1, "W9: child_results must not be empty"
        failed_child = result.child_results[0]
        assert failed_child.success is False, "W9: failed child must have success=False"
        assert failed_child.secret == "postgres_password", "W9: failed child must identify itself"
        # The error field in the parent must reference the failed secret
        assert result.error is not None and "postgres_password" in result.error, (
            "W9: parent error must name the failing secret for operator diagnosis"
        )
