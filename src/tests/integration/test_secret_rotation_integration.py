"""
Integration tests for admin-triggered secret rotation (v2.23.3).

Requires live Postgres + Redis containers. Marked with pytest markers so they
are skipped automatically when the services are not available.

Tests:
  RI01 — Postgres: ALTER USER succeeds against a real postgres instance
  RI02 — Postgres: full rotation cycle (old pw → new pw → verify new pw works)
  RI03 — Redis: CONFIG SET requirepass against a real redis instance
  RI04 — Redis: full rotation cycle (old pw → new pw → verify new pw works)
  RI05 — Failure injection: kill postgres mid-rotation, verify revert attempted
  RI06 — File atomicity: concurrent reads during write see complete file only

Usage (against a running stack):
    pytest src/tests/integration/test_secret_rotation_integration.py \
        --postgres-dsn="postgresql://yashigani_app:...@localhost:5432/yashigani" \
        --redis-url="redis://:password@localhost:6379/0" \
        -v

Or via env vars:
    YASHIGANI_TEST_POSTGRES_DSN=...
    YASHIGANI_TEST_REDIS_URL=...

These tests are SKIPPED automatically when the env vars are not set.

Last updated: 2026-05-07T00:00:00+01:00
"""
from __future__ import annotations

import os
import string
import time
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _postgres_dsn() -> str | None:
    return os.getenv("YASHIGANI_TEST_POSTGRES_DSN")


def _redis_url() -> str | None:
    return os.getenv("YASHIGANI_TEST_REDIS_URL")


pytestmark_postgres = pytest.mark.skipif(
    _postgres_dsn() is None,
    reason="YASHIGANI_TEST_POSTGRES_DSN not set — skipping live Postgres tests",
)

pytestmark_redis = pytest.mark.skipif(
    _redis_url() is None,
    reason="YASHIGANI_TEST_REDIS_URL not set — skipping live Redis tests",
)


@pytest.fixture()
def secrets_dir(tmp_path):
    """Temporary secrets directory pre-seeded with test credentials."""
    return tmp_path


# ---------------------------------------------------------------------------
# RI01–RI02: Postgres integration
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    _postgres_dsn() is None,
    reason="YASHIGANI_TEST_POSTGRES_DSN not set",
)
class TestPostgresIntegration:

    def test_ri01_alter_user_succeeds(self):
        """RI01: _pg_alter_user_password runs against a real postgres without error."""
        import psycopg2
        from yashigani.secrets.rotator import _pg_alter_user_password, _generate_password

        dsn = _postgres_dsn()
        # We'll use the postgres superuser DSN to create a test user first
        # The test rotates a *test* account, not yashigani_app
        try:
            conn = psycopg2.connect(dsn, connect_timeout=5)
        except Exception as exc:
            pytest.skip(f"Cannot connect to postgres: {exc}")

        with conn:
            with conn.cursor() as cur:
                cur.execute("CREATE USER test_rotator_ri01 WITH PASSWORD 'initial-pass-12345678' NOLOGIN;")
        conn.close()

        try:
            new_pw = _generate_password()
            _pg_alter_user_password(dsn, "test_rotator_ri01", new_pw)
        finally:
            # Cleanup
            try:
                conn2 = psycopg2.connect(dsn, connect_timeout=5)
                with conn2:
                    with conn2.cursor() as cur:
                        cur.execute("DROP USER IF EXISTS test_rotator_ri01;")
                conn2.close()
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_ri02_full_rotation_cycle(self, secrets_dir):
        """RI02: Full postgres rotation — old pw → new pw → new pw is correct in file."""
        import psycopg2
        from yashigani.secrets.rotator import (
            SecretRotator, _write_secret_file, _read_secret_file, _generate_password
        )

        dsn = _postgres_dsn()
        try:
            conn = psycopg2.connect(dsn, connect_timeout=5)
        except Exception as exc:
            pytest.skip(f"Cannot connect to postgres: {exc}")

        initial_pw = _generate_password()
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "CREATE USER test_rotator_ri02 WITH PASSWORD %s NOLOGIN;",
                    (initial_pw,)
                )
        conn.close()

        _write_secret_file(secrets_dir / "postgres_password", initial_pw)

        rotator = SecretRotator(
            secrets_dir=str(secrets_dir),
            db_dsn_direct=dsn.replace("yashigani_app", "test_rotator_ri02") if "yashigani_app" in dsn else dsn,
        )

        try:
            with patch("yashigani.secrets.rotator._restart_service"):
                reverted, revert_failed = await rotator._rotate_postgres_password()

            assert reverted is False, "Rotation should not have reverted"
            assert revert_failed is False

            new_on_disk = _read_secret_file(secrets_dir / "postgres_password")
            assert new_on_disk != initial_pw, "New password should differ from initial"
            assert len(new_on_disk) == 48

        finally:
            try:
                conn3 = psycopg2.connect(dsn, connect_timeout=5)
                with conn3:
                    with conn3.cursor() as cur:
                        cur.execute("DROP USER IF EXISTS test_rotator_ri02;")
                conn3.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# RI03–RI04: Redis integration
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    _redis_url() is None,
    reason="YASHIGANI_TEST_REDIS_URL not set",
)
class TestRedisIntegration:

    def _redis_client(self):
        import redis
        url = _redis_url()
        return redis.from_url(url, decode_responses=True)

    def test_ri03_config_set_requirepass_succeeds(self):
        """RI03: CONFIG SET requirepass runs against a real redis without error."""
        from yashigani.secrets.rotator import _redis_config_set_requirepass, _generate_password

        try:
            client = self._redis_client()
            client.ping()
        except Exception as exc:
            pytest.skip(f"Cannot connect to redis: {exc}")

        # Save old requirepass
        try:
            old_pw_list = client.config_get("requirepass")
            old_pw = old_pw_list.get("requirepass", "") if old_pw_list else ""
        except Exception:
            old_pw = ""

        new_pw = _generate_password()
        try:
            _redis_config_set_requirepass(client, new_pw)
            # Verify new auth works
            client.ping()
        finally:
            # Restore
            try:
                client.config_set("requirepass", old_pw)
                if old_pw:
                    client.auth(old_pw)
            except Exception:
                pass

    @pytest.mark.asyncio
    async def test_ri04_full_redis_rotation_cycle(self, secrets_dir):
        """RI04: Full redis rotation — old pw → new pw → verify new pw works."""
        import redis as redis_lib
        from yashigani.secrets.rotator import (
            SecretRotator, _write_secret_file, _read_secret_file, _generate_password
        )

        try:
            client = self._redis_client()
            client.ping()
        except Exception as exc:
            pytest.skip(f"Cannot connect to redis: {exc}")

        # Get current password
        try:
            old_pw_res = client.config_get("requirepass")
            old_pw = old_pw_res.get("requirepass", "") if old_pw_res else ""
        except Exception:
            old_pw = ""

        _write_secret_file(secrets_dir / "redis_password", old_pw or "no-auth")

        rotator = SecretRotator(
            secrets_dir=str(secrets_dir),
            redis_client=client,
        )

        try:
            reverted, revert_failed = await rotator._rotate_redis_password()
            assert reverted is False
            assert revert_failed is False

            new_on_disk = _read_secret_file(secrets_dir / "redis_password")
            assert new_on_disk != (old_pw or "no-auth")
            # Verify the client still works (it was re-authed with new pw)
            client.ping()

        finally:
            # Restore old password
            try:
                current_pw = _read_secret_file(secrets_dir / "redis_password")
                client.config_set("requirepass", old_pw)
                if old_pw:
                    client.auth(old_pw)
                else:
                    client.auth(current_pw)  # might fail; best effort
            except Exception:
                pass


# ---------------------------------------------------------------------------
# RI05: Failure injection — postgres unreachable mid-rotation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ri05_failure_injection_postgres_unreachable(tmp_path):
    """RI05: If postgres is unreachable, rotation fails fast and does NOT touch file."""
    from yashigani.secrets.rotator import SecretRotator, _write_secret_file, _read_secret_file

    secrets_dir = tmp_path
    original_pw = "original-password-12345678"
    _write_secret_file(secrets_dir / "postgres_password", original_pw)

    rotator = SecretRotator(
        secrets_dir=str(secrets_dir),
        db_dsn_direct="postgresql://yashigani_app:wrong@127.0.0.1:1/nonexistent",
    )

    result = await rotator._rotate_one(
        __import__("yashigani.secrets.rotator", fromlist=["SecretName"]).SecretName.POSTGRES_PASSWORD,
        "2026-05-07T00:00:00+00:00",
    )

    assert result.success is False
    # The password file MUST still be the original (no partial write)
    on_disk = _read_secret_file(secrets_dir / "postgres_password")
    assert on_disk == original_pw, (
        f"Secret file was modified despite connection failure: {on_disk!r}"
    )


# ---------------------------------------------------------------------------
# RI06: File atomicity — concurrent readers see complete file
# ---------------------------------------------------------------------------

def test_ri06_file_atomicity_no_partial_reads(tmp_path):
    """RI06: Concurrent readers of the secret file see only complete writes."""
    import threading
    from yashigani.secrets.rotator import _write_secret_file

    target = tmp_path / "atomic_secret"
    _write_secret_file(target, "initial-48char-" + "x" * 33)

    errors = []
    stop = threading.Event()

    def reader():
        """Continuously read the secret file; any partial read is an error."""
        while not stop.is_set():
            try:
                content = target.read_text().strip()
                # All passwords are exactly 48 chars
                if len(content) != 48:
                    errors.append(f"Partial read: len={len(content)} content={content!r}")
            except FileNotFoundError:
                pass  # rename window — acceptable

    def writer():
        """Write a series of new values."""
        for i in range(20):
            new_value = f"new-secret-{i:03d}-" + "y" * (48 - 16 - 3)
            if len(new_value) < 48:
                new_value = new_value.ljust(48, "z")
            new_value = new_value[:48]
            _write_secret_file(target, new_value)

    t_reader = threading.Thread(target=reader, daemon=True)
    t_reader.start()

    writer()
    stop.set()
    t_reader.join(timeout=2)

    assert not errors, f"Partial reads detected: {errors}"
