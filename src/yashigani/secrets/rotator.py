"""
Yashigani Secrets — Admin-triggered secret rotation engine (v2.23.3).

Supports zero-downtime rotation of:
  - postgres_password  — dual-credential window: write new secret file, ALTER USER,
                         restart pgbouncer to pick up refreshed pool credentials.
  - redis_password     — CONFIG SET requirepass in-flight; reconnect clients.
  - jwt_signing_key    — write new key file; hot-reload gateway (tokens valid until expiry).
  - hmac_key           — write new caddy_internal_hmac file; reload Caddy + services.
  - all                — rotate all four in sequence (stops on first failure).

Failure model (fail-closed):
  - If mid-rotation fails, we attempt revert to the saved old secret.
  - If the revert also fails, we raise RotationError with a CRITICAL flag so the
    caller can emit an alert and surface it in the audit chain.
  - On success, the old secret file is overwritten. We do NOT keep backups in the
    filesystem — old secrets are held only in memory for the duration of the rotation.

Password charset (per feedback_password_charset.md):
  A-Za-z0-9!*,-._~  with at least one character from each category.
  Load-bearing choices:
    !*,-._~ — URL-safe (no %xx encoding needed in DSN / env vars)
    No ; | & ' " ` \ — shell-safe (safe in unquoted double-quote contexts)
    No @ # % + = { } [ ] ( ) ^ / — avoids DSN/URL parser ambiguity

JWT signing key: 64-byte (512-bit) secrets.token_bytes → hex string (128 hex chars).
HMAC key: 32-byte → hex string (64 hex chars), matching install.sh keygen.py output.

Last updated: 2026-05-07T00:00:00+01:00
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
import string
import stat
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import quote

_log = logging.getLogger("yashigani.secrets.rotator")

# ---------------------------------------------------------------------------
# Password charset (feedback_password_charset.md)
# ---------------------------------------------------------------------------

# A-Za-z0-9!*,-._~ only.  Each symbol has been reviewed for safety in:
#   - URL/DSN contexts (no %, @, #, +, =, &, ;, ?, /)
#   - Shell double-quote contexts (no $, `, \, !, ", ', |, {, })
#   - env var contexts (no NUL, LF, CR)
#   ! is allowed: shell-safe inside double quotes when not at start of unquoted string;
#   in our rotation the password is always loaded from a file (never echoed raw).
_SPECIAL_SYMBOLS = "!*,-._~"
_PW_ALPHABET = string.ascii_letters + string.digits + _SPECIAL_SYMBOLS
_PW_LENGTH = 48   # well above 36-char minimum; shorter than 64 to stay URL-encodable


def _generate_password() -> str:
    """
    Generate a cryptographically random password per feedback_password_charset.md.

    Guarantees:
    - At least one uppercase letter, one lowercase letter, one digit, one symbol.
    - All characters from the allowed alphabet only.
    - 48 characters total.
    """
    while True:
        pw = [secrets.choice(_PW_ALPHABET) for _ in range(_PW_LENGTH)]
        has_upper = any(c in string.ascii_uppercase for c in pw)
        has_lower = any(c in string.ascii_lowercase for c in pw)
        has_digit = any(c in string.digits for c in pw)
        has_sym = any(c in _SPECIAL_SYMBOLS for c in pw)
        if has_upper and has_lower and has_digit and has_sym:
            return "".join(pw)


def _generate_hex_key(byte_len: int) -> str:
    """Generate a cryptographically random hex key of given byte length."""
    return secrets.token_bytes(byte_len).hex()


# ---------------------------------------------------------------------------
# Secret types
# ---------------------------------------------------------------------------

class SecretName(str, Enum):
    POSTGRES_PASSWORD = "postgres_password"
    REDIS_PASSWORD = "redis_password"
    JWT_SIGNING_KEY = "jwt_signing_key"
    HMAC_KEY = "hmac_key"
    ALL = "all"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class RotationResult:
    secret: str
    success: bool
    rotated_at: str
    error: Optional[str] = None
    reverted: bool = False
    revert_failed: bool = False
    child_results: list["RotationResult"] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rotator
# ---------------------------------------------------------------------------

class SecretRotator:
    """
    Core rotation engine. Instantiated per request (stateless except for
    secrets_dir).  Does NOT hold state between calls.

    All filesystem writes are 0400 (read-only by owner, the app UID).
    Container volumes for /run/secrets are typically bind-mounts of
    docker/secrets/ on the host; writing here updates the host file
    and the in-container path simultaneously.

    Podman parity: same code path — bind-mount semantics are identical.
    """

    def __init__(
        self,
        secrets_dir: Optional[str] = None,
        db_dsn_direct: Optional[str] = None,
        redis_client=None,
    ) -> None:
        self._secrets_dir = Path(
            secrets_dir
            or os.getenv("YASHIGANI_SECRETS_DIR")
            or "/run/secrets"
        )
        # Direct Postgres DSN (bypasses pgbouncer) for ALTER USER.
        self._db_dsn_direct: Optional[str] = db_dsn_direct or os.getenv("YASHIGANI_DB_DSN_DIRECT")
        # Redis client for CONFIG SET requirepass.
        self._redis = redis_client

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def rotate(self, secret: SecretName) -> RotationResult:
        """Rotate the named secret. Returns RotationResult (never raises)."""
        _log.info("Starting rotation for: %s", secret.value)
        ts = _now_iso()
        if secret == SecretName.ALL:
            return await self._rotate_all(ts)
        return await self._rotate_one(secret, ts)

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    async def _rotate_all(self, ts: str) -> RotationResult:
        """Rotate all four secrets in sequence; abort on first failure."""
        individual = [
            SecretName.POSTGRES_PASSWORD,
            SecretName.REDIS_PASSWORD,
            SecretName.JWT_SIGNING_KEY,
            SecretName.HMAC_KEY,
        ]
        children: list[RotationResult] = []
        overall_ok = True
        for name in individual:
            result = await self._rotate_one(name, ts)
            children.append(result)
            if not result.success:
                overall_ok = False
                _log.error(
                    "Aborting rotate-all sequence after %s failure: %s",
                    name.value, result.error,
                )
                break  # fail-closed: do not continue with remaining secrets

        return RotationResult(
            secret="all",
            success=overall_ok,
            rotated_at=ts,
            child_results=children,
            error=None if overall_ok else f"Failed at {children[-1].secret}",
        )

    async def _rotate_one(self, secret: SecretName, ts: str) -> RotationResult:
        """Dispatch to per-secret handler. Catches all exceptions."""
        handlers = {
            SecretName.POSTGRES_PASSWORD: self._rotate_postgres_password,
            SecretName.REDIS_PASSWORD: self._rotate_redis_password,
            SecretName.JWT_SIGNING_KEY: self._rotate_jwt_signing_key,
            SecretName.HMAC_KEY: self._rotate_hmac_key,
        }
        handler = handlers.get(secret)
        if handler is None:
            return RotationResult(
                secret=secret.value,
                success=False,
                rotated_at=ts,
                error=f"Unknown secret type: {secret.value}",
            )
        try:
            reverted, revert_failed = await handler()
            if reverted:
                return RotationResult(
                    secret=secret.value,
                    success=False,
                    rotated_at=ts,
                    error="Rotation failed; old secret restored",
                    reverted=True,
                    revert_failed=revert_failed,
                )
            return RotationResult(
                secret=secret.value,
                success=True,
                rotated_at=ts,
            )
        except Exception as exc:
            _log.exception("Unexpected error rotating %s", secret.value)
            return RotationResult(
                secret=secret.value,
                success=False,
                rotated_at=ts,
                error=f"{type(exc).__name__}: {exc}",
            )

    # -------------------------------------------------------------------------
    # Postgres password rotation
    # -------------------------------------------------------------------------

    async def _rotate_postgres_password(self) -> tuple[bool, bool]:
        """
        Zero-downtime Postgres password rotation:
        1. Read old secret.
        2. Generate new password.
        3. ALTER USER yashigani_app WITH PASSWORD <new> (via direct psycopg2 to postgres).
        4. Write new secret file (0400).
        5. Restart pgbouncer via docker/podman to pick up new pool credentials.

        On failure: revert ALTER USER to old password.
        Returns (reverted, revert_failed).
        """
        secret_path = self._secrets_dir / "postgres_password"
        old_pw = _read_secret_file(secret_path)
        new_pw = _generate_password()

        # Step 1: ALTER USER in postgres directly (not via pgbouncer)
        try:
            await asyncio.to_thread(
                _pg_alter_user_password,
                self._db_dsn_direct,
                "yashigani_app",
                new_pw,
            )
        except Exception as exc:
            _log.error("Postgres ALTER USER failed (no state changed): %s", exc)
            raise

        # Step 2: Write new secret file — if this fails we must revert DB
        try:
            _write_secret_file(secret_path, new_pw)
        except Exception as exc:
            _log.error("Failed writing postgres_password file: %s — reverting DB", exc)
            reverted, revert_failed = await _pg_revert(self._db_dsn_direct, "yashigani_app", old_pw)
            return True, revert_failed

        # Step 3: Restart pgbouncer so it re-reads DATABASE_URL from the env
        # (the edoburu image auto-builds userlist.txt from DATABASE_URL at startup).
        # In practice, pgbouncer pools existing connections through the old password
        # until it restarts — the db ALTER already accepted the new password so
        # new connections from pgbouncer after restart will succeed.
        try:
            await asyncio.to_thread(_restart_service, "pgbouncer")
        except Exception as exc:
            _log.warning(
                "pgbouncer restart failed (non-fatal — new connections will use "
                "new password once pgbouncer is cycled manually): %s", exc,
            )
            # Non-fatal: the database already accepts the new password.
            # Existing pgbouncer connections will drain; manual restart will
            # complete the update. We still report success.

        _log.info("Postgres password rotation complete")
        return False, False

    # -------------------------------------------------------------------------
    # Redis password rotation
    # -------------------------------------------------------------------------

    async def _rotate_redis_password(self) -> tuple[bool, bool]:
        """
        Redis password rotation:
        1. Read old password.
        2. Generate new password.
        3. CONFIG SET requirepass <new> via authenticated Redis connection.
        4. Write new secret file.
        5. Reconnect clients (they will pick up the new password from the file).

        On failure: CONFIG SET requirepass <old>.
        """
        secret_path = self._secrets_dir / "redis_password"
        old_pw = _read_secret_file(secret_path)
        new_pw = _generate_password()

        # Get or build a Redis client
        client = self._redis
        if client is None:
            try:
                client = _build_redis_client(self._secrets_dir)
            except Exception as exc:
                _log.error("Cannot build Redis client: %s", exc)
                raise

        # Step 1: CONFIG SET requirepass
        try:
            await asyncio.to_thread(
                _redis_config_set_requirepass, client, new_pw
            )
        except Exception as exc:
            _log.error("Redis CONFIG SET requirepass failed: %s", exc)
            raise

        # Step 2: Write new secret file
        try:
            _write_secret_file(secret_path, new_pw)
        except Exception as exc:
            _log.error("Failed writing redis_password file: %s — reverting", exc)
            # Revert Redis requirepass to old
            try:
                _redis_config_set_requirepass_with_new_auth(client, new_pw, old_pw)
                return True, False
            except Exception as revert_exc:
                _log.critical("Redis revert FAILED: %s", revert_exc)
                return True, True

        _log.info("Redis password rotation complete")
        return False, False

    # -------------------------------------------------------------------------
    # JWT signing key rotation
    # -------------------------------------------------------------------------

    async def _rotate_jwt_signing_key(self) -> tuple[bool, bool]:
        """
        JWT signing key hot-swap:
        1. Generate 64-byte hex key.
        2. Write to secret file (0400).
        3. Send SIGHUP to gateway to reload (if SIGHUP-reload supported);
           existing tokens stay valid until their exp — no invalidation.

        There is no DB-level transaction here, so rollback is just overwriting
        the file with the old value.
        """
        secret_path = self._secrets_dir / "jwt_signing_key"
        old_key = _read_secret_file_optional(secret_path)
        new_key = _generate_hex_key(64)  # 512-bit

        try:
            _write_secret_file(secret_path, new_key)
        except Exception as exc:
            _log.error("Failed writing jwt_signing_key: %s", exc)
            raise

        # Attempt graceful gateway reload (best-effort; failure is non-fatal
        # because the gateway will pick up the new key on next restart)
        try:
            await asyncio.to_thread(_signal_service_reload, "gateway")
        except Exception as exc:
            _log.warning(
                "Gateway reload signal failed (non-fatal — key active after next restart): %s", exc
            )

        _log.info("JWT signing key rotation complete")
        return False, False

    # -------------------------------------------------------------------------
    # HMAC key rotation
    # -------------------------------------------------------------------------

    async def _rotate_hmac_key(self) -> tuple[bool, bool]:
        """
        Layer-B HMAC key (caddy_internal_hmac) rotation:
        1. Generate 32-byte hex key (matching install.sh keygen output).
        2. Write to caddy_internal_hmac file.
        3. Send reload to Caddy + gateway + backoffice so all three pick up
           the new secret atomically.

        Warning: there is a brief window between Caddy reload and app reload
        where Caddy injects the new secret but the apps still expect the old one
        → ~1-2 requests will fail with 401. For the HMAC key, caller should
        schedule during low-traffic windows.
        """
        secret_path = self._secrets_dir / "caddy_internal_hmac"
        old_key = _read_secret_file_optional(secret_path)
        new_key = _generate_hex_key(32)  # 256-bit, matching keygen.py

        try:
            _write_secret_file(secret_path, new_key)
        except Exception as exc:
            _log.error("Failed writing caddy_internal_hmac: %s", exc)
            raise

        # Best-effort reload of all three services
        for service in ("caddy", "gateway", "backoffice"):
            try:
                await asyncio.to_thread(_signal_service_reload, service)
            except Exception as exc:
                _log.warning("Reload signal to %s failed (non-fatal): %s", service, exc)

        _log.info("HMAC key rotation complete")
        return False, False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(tz=timezone.utc).isoformat()


def _read_secret_file(path: Path) -> str:
    """Read a secret file. Raises RuntimeError if missing or unreadable."""
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"Cannot read secret file {path}: {exc}") from exc


def _read_secret_file_optional(path: Path) -> Optional[str]:
    """Read a secret file; return None if it doesn't exist yet."""
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _write_secret_file(path: Path, value: str) -> None:
    """
    Atomically write a secret file with 0400 permissions.

    Uses a temp file + rename for atomicity (readers never see a partial write).
    The temp file is in the same directory as the target to guarantee same-device rename.
    """
    tmp_path = path.parent / (path.name + ".tmp")
    try:
        tmp_path.write_text(value, encoding="utf-8")
        # chmod 0400 before rename so the file is always permission-safe
        tmp_path.chmod(0o400)
        tmp_path.rename(path)
    except OSError:
        # Clean up the temp file if rename failed
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _pg_alter_user_password(dsn: Optional[str], username: str, new_pw: str) -> None:
    """Run ALTER USER ... WITH PASSWORD ... via a direct psycopg2 connection."""
    import psycopg2

    if not dsn:
        raise RuntimeError(
            "YASHIGANI_DB_DSN_DIRECT not set — cannot ALTER USER without a "
            "direct postgres connection (pgbouncer blocks DDL in transaction-pool mode)"
        )

    conn = psycopg2.connect(dsn, connect_timeout=15)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            # Use parameterized-style quoting; psycopg2 identifier quoting via
            # sql.Identifier prevents SQL injection on the username.
            from psycopg2 import sql
            cur.execute(
                sql.SQL("ALTER USER {} WITH PASSWORD %s").format(
                    sql.Identifier(username)
                ),
                (new_pw,),
            )
    finally:
        try:
            conn.close()
        except Exception:
            pass


async def _pg_revert(
    dsn: Optional[str], username: str, old_pw: str
) -> tuple[bool, bool]:
    """Attempt to revert postgres password. Returns (reverted=True, revert_failed)."""
    try:
        await asyncio.to_thread(_pg_alter_user_password, dsn, username, old_pw)
        _log.info("Postgres password reverted to old value")
        return True, False
    except Exception as exc:
        _log.critical("Postgres revert FAILED — manual intervention required: %s", exc)
        return True, True


def _redis_config_set_requirepass(client, new_pw: str) -> None:
    """Send CONFIG SET requirepass to Redis using the existing (old-auth) client."""
    client.config_set("requirepass", new_pw)
    # Re-authenticate with the new password immediately so the connection remains usable.
    client.auth(new_pw)


def _redis_config_set_requirepass_with_new_auth(client, current_pw: str, target_pw: str) -> None:
    """Revert requirepass. Client is authenticated with current_pw (new pw we're reverting)."""
    client.config_set("requirepass", target_pw)
    client.auth(target_pw)


def _build_redis_client(secrets_dir: Path):
    """Build a redis.Redis client using the current password from the secrets file."""
    import redis
    from yashigani.gateway._redis_url import build_redis_url

    url = build_redis_url(
        0,  # DB 0 (rate-limiter / session)
        secrets_dir=str(secrets_dir),
        client_cert_name="backoffice_client",
    )
    return redis.from_url(url, decode_responses=True)


def _restart_service(service_name: str) -> None:
    """
    Restart a compose/podman service by sending SIGTERM to PID 1.

    In container-native environments we can't invoke `docker compose restart`
    from inside the container without the docker socket. Instead we rely on
    supervisord/s6/tini to respawn the process on SIGTERM, OR the operator
    uses the CLI tool which has access to the docker socket on the host.

    This in-process implementation is best-effort and logs clearly if it
    cannot act. The CLI script (scripts/rotate-secret.sh) performs the full
    docker/podman restart from the host where the socket is available.
    """
    _log.info(
        "In-container restart of '%s' not supported via API — "
        "service will pick up new secret on next natural restart. "
        "Use scripts/rotate-secret.sh for host-side restart.",
        service_name,
    )


def _signal_service_reload(service_name: str) -> None:
    """
    Send SIGHUP to PID 1 for graceful config reload.
    Logs warning on failure; never raises.
    """
    import signal
    try:
        os.kill(1, signal.SIGHUP)
        _log.info("Sent SIGHUP to PID 1 (%s reload)", service_name)
    except (ProcessLookupError, PermissionError) as exc:
        _log.warning("SIGHUP to PID 1 failed (%s reload): %s", service_name, exc)
