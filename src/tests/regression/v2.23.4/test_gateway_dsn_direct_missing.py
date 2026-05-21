"""
Regression test — BUG-GATEWAY-DSN-DIRECT-MISSING (v2.23.4).

Proves two things:

1. Config-level: gateway service in docker-compose.yml defines
   YASHIGANI_DB_DSN_DIRECT, so run_migrations() uses a direct postgres
   connection for its advisory lock — not a pgbouncer-recycled one.

2. Code-level (unit): run_migrations() prefers YASHIGANI_DB_DSN_DIRECT over
   YASHIGANI_DB_DSN when choosing the lock_dsn.  Verified without a live DB
   by patching at the connect call and asserting which DSN was used.

Root cause: pgbouncer transaction-pool mode recycles backend connections but
does NOT release session-scoped advisory locks (DISCARD ALL is issued on the
client side; the backend pid stays alive and keeps the lock).  When the
asyncpg pool later lands on the same recycled backend, the lock persists and
deadlocks the backoffice lifespan pg_advisory_lock() call.

Fix: add YASHIGANI_DB_DSN_DIRECT to the gateway service in docker-compose.yml,
pointing at postgres:5432 directly.  Matches backoffice line ~306 and
Helm gateway.yaml:141 (which already had DSN_DIRECT).
"""
# Last updated: 2026-05-15T00:00:00+01:00 — v2.23.4 regression: BUG-GATEWAY-DSN-DIRECT-MISSING
from __future__ import annotations

import os
import pathlib
import re
import unittest.mock as mock

import pytest

# ---------------------------------------------------------------------------
# Config-level test: docker-compose.yml must declare YASHIGANI_DB_DSN_DIRECT
# for the gateway service, pointing to postgres:5432 (not pgbouncer:5432).
# ---------------------------------------------------------------------------

COMPOSE_FILE = pathlib.Path(__file__).parents[4] / "docker" / "docker-compose.yml"


def _parse_gateway_env(compose_text: str) -> dict[str, str]:
    """Extract env key=value pairs from the gateway: block in the compose file.

    We look for the first 'gateway:' service block and harvest every line of
    the form '      KEY: value' until the next top-level service or end.  This
    is intentionally simple — we only need to catch the DSN vars.
    """
    in_gateway = False
    in_env = False
    env: dict[str, str] = {}

    for line in compose_text.splitlines():
        # Detect service boundary (2-space indented top-level key with colon)
        if re.match(r"^  \w[\w-]*:$", line):
            service = line.strip().rstrip(":")
            in_gateway = service == "gateway"
            in_env = False
            continue

        if not in_gateway:
            continue

        # Detect environment: block inside gateway
        if re.match(r"^    environment:", line):
            in_env = True
            continue

        if in_env:
            # 6-space indent = env key-value pair
            m = re.match(r"^      (YASHIGANI_DB_DSN[^:]*): (.+)$", line)
            if m:
                env[m.group(1).strip()] = m.group(2).strip()
            # 4-space indent = new gateway block key, not an env var
            elif re.match(r"^    \w", line):
                in_env = False

    return env


def test_gateway_has_dsn_direct_in_compose() -> None:
    """docker-compose.yml gateway service must declare YASHIGANI_DB_DSN_DIRECT."""
    assert COMPOSE_FILE.exists(), f"docker-compose.yml not found at {COMPOSE_FILE}"
    text = COMPOSE_FILE.read_text()
    env = _parse_gateway_env(text)

    assert "YASHIGANI_DB_DSN" in env, "gateway service missing YASHIGANI_DB_DSN"
    assert "YASHIGANI_DB_DSN_DIRECT" in env, (
        "gateway service missing YASHIGANI_DB_DSN_DIRECT — "
        "this causes pg_advisory_lock deadlock via pgbouncer session recycling "
        "(BUG-GATEWAY-DSN-DIRECT-MISSING)"
    )


def test_gateway_dsn_direct_bypasses_pgbouncer() -> None:
    """YASHIGANI_DB_DSN_DIRECT must target postgres:5432, not pgbouncer:5432."""
    assert COMPOSE_FILE.exists(), f"docker-compose.yml not found at {COMPOSE_FILE}"
    text = COMPOSE_FILE.read_text()
    env = _parse_gateway_env(text)

    direct = env.get("YASHIGANI_DB_DSN_DIRECT", "")
    assert direct, "YASHIGANI_DB_DSN_DIRECT must be set in gateway service"

    # Must contain @postgres:5432 (direct) not @pgbouncer:5432
    assert "@postgres:5432" in direct, (
        f"YASHIGANI_DB_DSN_DIRECT must route to postgres:5432 directly; "
        f"got: {direct!r}"
    )
    assert "@pgbouncer:" not in direct, (
        "YASHIGANI_DB_DSN_DIRECT must bypass pgbouncer; got pgbouncer in DSN"
    )


def test_backoffice_also_has_dsn_direct_in_compose() -> None:
    """Backoffice service must also have YASHIGANI_DB_DSN_DIRECT (baseline check).

    Backoffice had DSN_DIRECT before this bug was fixed.  This test ensures
    it hasn't accidentally been removed.
    """
    assert COMPOSE_FILE.exists(), f"docker-compose.yml not found at {COMPOSE_FILE}"
    text = COMPOSE_FILE.read_text()

    # Simpler check for backoffice — just assert line presence
    lines = text.splitlines()
    in_backoffice = False
    found = False
    for line in lines:
        if re.match(r"^  backoffice:$", line):
            in_backoffice = True
        if in_backoffice and "YASHIGANI_DB_DSN_DIRECT" in line:
            found = True
            break
        # Stop at next top-level service
        if in_backoffice and re.match(r"^  \w[\w-]*:$", line) and "backoffice" not in line:
            break

    assert found, (
        "backoffice service is missing YASHIGANI_DB_DSN_DIRECT — "
        "regression: this var was added in v2.23.3 B4 fix (PR #60)"
    )


# ---------------------------------------------------------------------------
# Code-level test: run_migrations() uses DSN_DIRECT when set.
# ---------------------------------------------------------------------------


def _make_fake_conn() -> mock.MagicMock:
    """Return a mock psycopg2-style connection."""
    conn = mock.MagicMock()
    conn.autocommit = False
    cursor = mock.MagicMock()
    cursor.__enter__ = lambda s: s
    cursor.__exit__ = mock.MagicMock(return_value=False)
    cursor.execute = mock.MagicMock()
    conn.cursor.return_value = cursor
    return conn


def _inject_alembic_stub() -> None:
    """Inject a minimal alembic stub into sys.modules if alembic is absent.

    run_migrations() imports alembic lazily (inside the function body).  On a
    macOS dev machine running Python 3.9 (pre-container), alembic may not be
    installed.  Inject lightweight stubs so the unit tests can run without a
    full environment.  In CI (Python 3.12 container) alembic is present and the
    stub is a no-op (sys.modules already has 'alembic').
    """
    import sys
    import types

    if "alembic" not in sys.modules:
        alembic_mod = types.ModuleType("alembic")
        alembic_config_mod = types.ModuleType("alembic.config")
        alembic_command_mod = types.ModuleType("alembic.command")

        class FakeConfig:
            def set_main_option(self, *args: object, **kwargs: object) -> None:
                pass

            def get_main_option(self, *args: object, **kwargs: object) -> str:
                return ""

        alembic_config_mod.Config = FakeConfig  # type: ignore[attr-defined]
        alembic_command_mod.upgrade = mock.MagicMock()  # type: ignore[attr-defined]

        alembic_mod.config = alembic_config_mod  # type: ignore[attr-defined]
        alembic_mod.command = alembic_command_mod  # type: ignore[attr-defined]

        sys.modules["alembic"] = alembic_mod
        sys.modules["alembic.config"] = alembic_config_mod
        sys.modules["alembic.command"] = alembic_command_mod
        sys.modules["alembic.runtime"] = types.ModuleType("alembic.runtime")
        sys.modules["alembic.runtime.plugins"] = types.ModuleType("alembic.runtime.plugins")


def test_run_migrations_uses_dsn_direct_for_lock() -> None:
    """run_migrations() must use YASHIGANI_DB_DSN_DIRECT (not YASHIGANI_DB_DSN)
    for the advisory lock connection when DSN_DIRECT is set.

    This is the code-level guard ensuring the db/__init__.py logic routes the
    lock connection to postgres:5432 when the env var is present.
    """
    _inject_alembic_stub()

    direct_dsn = "postgresql://yashigani_app:testpw@postgres:5432/yashigani"
    bouncer_dsn = "postgresql://yashigani_app:testpw@pgbouncer:5432/yashigani"

    captured: list[str] = []

    def fake_connect(dsn: str, **kwargs: object) -> mock.MagicMock:  # noqa: ARG001
        captured.append(dsn)
        return _make_fake_conn()

    env_patch = {
        "YASHIGANI_DB_DSN": bouncer_dsn,
        "YASHIGANI_DB_DSN_DIRECT": direct_dsn,
    }

    with mock.patch.dict(os.environ, env_patch, clear=False):
        with mock.patch(
            "yashigani.db.connect_with_retry_sync",
            side_effect=fake_connect,
        ):
            with mock.patch("alembic.command.upgrade"):
                from yashigani.db import run_migrations

                run_migrations()

    assert captured, "connect_with_retry_sync was never called"
    lock_dsn_used = captured[0]
    assert "@postgres:5432" in lock_dsn_used, (
        f"run_migrations() used DSN {lock_dsn_used!r} for the advisory lock "
        f"— expected DSN_DIRECT (@postgres:5432), not pgbouncer DSN. "
        f"This is BUG-GATEWAY-DSN-DIRECT-MISSING."
    )
    assert "@pgbouncer:" not in lock_dsn_used, (
        f"run_migrations() routed advisory lock through pgbouncer — deadlock risk. "
        f"DSN used: {lock_dsn_used!r}"
    )


def test_run_migrations_falls_back_to_dsn_when_direct_absent() -> None:
    """When YASHIGANI_DB_DSN_DIRECT is absent, run_migrations() falls back to
    YASHIGANI_DB_DSN.  This covers bare-metal or minimal-config scenarios.
    """
    _inject_alembic_stub()

    bouncer_dsn = "postgresql://yashigani_app:testpw@pgbouncer:5432/yashigani"
    captured: list[str] = []

    def fake_connect(dsn: str, **kwargs: object) -> mock.MagicMock:  # noqa: ARG001
        captured.append(dsn)
        return _make_fake_conn()

    # Remove DSN_DIRECT from environment, leave only YASHIGANI_DB_DSN
    env_patch = {"YASHIGANI_DB_DSN": bouncer_dsn}
    env_clean = {k: v for k, v in os.environ.items() if k != "YASHIGANI_DB_DSN_DIRECT"}
    env_clean.update(env_patch)

    with mock.patch.dict(os.environ, env_clean, clear=True):
        with mock.patch(
            "yashigani.db.connect_with_retry_sync",
            side_effect=fake_connect,
        ):
            with mock.patch("alembic.command.upgrade"):
                from yashigani.db import run_migrations

                run_migrations()

    assert captured, "connect_with_retry_sync was never called"
    assert "@pgbouncer:5432" in captured[0], (
        f"Without DSN_DIRECT, run_migrations() should fall back to YASHIGANI_DB_DSN "
        f"(pgbouncer); got: {captured[0]!r}"
    )
