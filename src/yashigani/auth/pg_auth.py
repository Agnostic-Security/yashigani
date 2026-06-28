"""
Yashigani Auth — Postgres-backed local authentication service.

Durable replacement for LocalAuthService. Same public semantics, but every
AccountRecord mutation commits to admin_accounts via asyncpg so password
rotations and TOTP re-enrolments survive backoffice restart.

Resolves P0-2 (YCS-20260423-v2.23.1-OWASP-3X): in-memory dict lost state
on restart, violating ASVS V2.1 and V2.8.

All DB operations run inside tenant_transaction() against the platform
sentinel tenant 00000000-0000-0000-0000-000000000000 — admin usernames
are platform-scoped, not per-tenant.

v2.23.3 — Password reuse history (CMMC L2 IA.L2-3.5.8):
  change_password() checks the last PASSWORD_HISTORY_DEPTH hashes from the
  password_history table, rejects on match, and records the old hash after a
  successful change. Emits PASSWORD_REUSE_REJECTED audit event on rejection.
"""

# Last updated: 2026-05-09T00:00:00+00:00
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from typing import Optional

import asyncpg

from yashigani.auth.local_auth import (
    AccountRecord,
    _MAX_FAILED_ATTEMPTS,
    _LOCKOUT_SECONDS,
    _TOTP_BACKOFF_SECONDS,
    _get_history_depth,
)
from yashigani.auth.password import (
    generate_password,
    hash_password,
    verify_password,
)
from yashigani.auth.totp import (
    LEGACY_TOTP_ALGO,
    ROLE_TOTP_ALGO,
    ROLE_TOTP_DIGITS,
    RecoveryCodeSet,
    TotpProvisioning,
    generate_provisioning,
    generate_recovery_code_set,
    verify_totp,
)
from yashigani.db.postgres import tenant_transaction

logger = logging.getLogger(__name__)

_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"

# TOTP replay cache lives at most 60 s — a valid TOTP window is 30 s and we
# accept ±1 window, so 60 s is sufficient to defeat replay across all
# accepted windows.
_TOTP_REPLAY_TTL_SECONDS = 60

# LAURA-3X-002: a constant argon2 hash used to equalize authentication timing on
# the non-existent/disabled-user path (ASVS V2.2.1). Computed lazily once so the
# argon2 cost is not paid at import time, then reused for every dummy verify.
_DUMMY_PASSWORD_HASH: Optional[str] = None


def _dummy_password_hash() -> str:
    """Return (computing once) a valid argon2 hash for timing-equalization.

    Verifying a real password against this hash takes ~the same wall-clock as a
    genuine wrong-password verify, so a non-existent username cannot be told apart
    from a real one by response timing.
    """
    global _DUMMY_PASSWORD_HASH
    if _DUMMY_PASSWORD_HASH is None:
        # NB: must be >=36 chars and must NOT contain product/company/common
        # terms (validate_password_context rejects e.g. "yashigani"); check_breach
        # is disabled — this is never a real account password.
        _DUMMY_PASSWORD_HASH = hash_password(
            "constant-timing-equalizer-placeholder-row-0000",
            check_breach=False,
        )
    return _DUMMY_PASSWORD_HASH


class PostgresLocalAuthService:
    """
    Postgres-backed account store. Mirrors LocalAuthService's public API
    but returns awaitables for every method.

    All methods operate on a single shared pool injected at construction.
    The pool must already be created (yashigani.db.create_pool) before any
    method is invoked — callers on startup should await create_pool() in
    the FastAPI lifespan before constructing this service.
    """

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool  # kept for API symmetry; tenant_transaction uses global pool

    # -- Account lifecycle --------------------------------------------------

    async def create_admin(
        self,
        username: str,
        auto_generate: bool = True,
        plaintext_password: Optional[str] = None,
        *,
        force_password_change: bool = True,
        force_totp_provision: bool = True,
    ) -> tuple[AccountRecord, Optional[str]]:
        """Create an admin account.

        force_password_change / force_totp_provision default to True — the
        normal human-admin posture (ASVS V2.1.x forced first-login rotation +
        TOTP enrolment).

        The install-path bootstrap service account (see
        backoffice.app._bootstrap_admin_accounts) passes both as False. That
        account is NON-INTERACTIVE: it is never logged into by a human, its
        credential lives only in docker/secrets/ (CSPRNG-generated), and it is
        used solely by install.sh's programmatic admin-API operations (agent
        registration, RBAC seeding). Because no human ever rotates it, the
        on-disk secret never goes stale — making install/agent-registration
        re-runs robust against the human admin's first-login rotation. This
        does NOT weaken the human's forced rotation, which still applies to
        every account created with the defaults.
        """
        plaintext = plaintext_password or (generate_password(36) if auto_generate else None)
        if plaintext is None:
            raise ValueError("Must provide password or set auto_generate=True")

        record = AccountRecord(
            account_id=str(uuid.uuid4()),
            username=username,
            # check_breach=False: system-generated password, not user-chosen.
            # HIBP check applies to user-chosen passwords only (ASVS V2.1.7).
            password_hash=hash_password(plaintext, check_breach=False),
            totp_secret="",
            recovery_codes=None,
            account_tier="admin",
            email=username,
            force_password_change=force_password_change,
            force_totp_provision=force_totp_provision,
        )
        await self._insert(record)
        return record, plaintext if auto_generate else None

    async def create_user(
        self,
        username: str,
        plaintext_password: str,
    ) -> AccountRecord:
        record = AccountRecord(
            account_id=str(uuid.uuid4()),
            username=username,
            # check_breach=False: admin-generated temp password, not user-chosen.
            # HIBP check applies to user-chosen passwords only (ASVS V2.1.7).
            password_hash=hash_password(plaintext_password, check_breach=False),
            totp_secret="",
            recovery_codes=None,
            account_tier="user",
            force_password_change=True,
            force_totp_provision=True,
        )
        await self._insert(record)
        return record

    # -- Authentication -----------------------------------------------------

    async def authenticate(
        self,
        username: str,
        password: str,
        totp_code: str,
        *,
        audit_writer=None,
    ) -> tuple[bool, Optional[AccountRecord], str]:
        """
        Authenticate an admin account with password + TOTP.

        audit_writer — optional AuditLogWriter instance. When supplied, emits
        an ACCOUNT_LOCKOUT event whenever a lockout is triggered by this call.
        ACS gap #95: lockout events were previously only logged (logger.warning)
        with no structured audit trail.
        """
        generic_fail = "invalid_credentials"

        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            record = await self._fetch_by_username(conn, username)
            if record is None or record.disabled:
                # LAURA-3X-002 (ASVS V2.2.1): equalize timing. A non-existent or
                # disabled username must take ~the same wall-clock as a wrong
                # password for a real account, otherwise the ~130ms argon2 delta
                # leaks valid usernames (timing enumeration). Run one real argon2
                # verify against a constant dummy hash and discard the result.
                # Best-effort: timing-equalization must NEVER break the auth path,
                # so any error here is swallowed and we still fail closed.
                try:
                    verify_password(password, _dummy_password_hash())
                except Exception:  # noqa: BLE001 — hardening only, never fail auth
                    pass
                return False, None, generic_fail

            if _is_locked(record):
                return False, None, generic_fail

            if not verify_password(password, record.password_hash):
                record.failed_attempts += 1
                if record.failed_attempts >= _MAX_FAILED_ATTEMPTS:
                    record.locked_until = time.time() + _LOCKOUT_SECONDS
                    logger.warning(
                        "Account locked after %d failures: %s",
                        _MAX_FAILED_ATTEMPTS,
                        username,
                    )
                    # ACS gap #95: emit structured ACCOUNT_LOCKOUT event.
                    _emit_lockout_event(audit_writer, username, "password", record.failed_attempts, account_tier=record.account_tier)
                await self._update(conn, record)
                return False, None, generic_fail

            if record.force_totp_provision:
                record.failed_attempts = 0
                await self._update(conn, record)
                return True, record, "totp_provision_required"

            # Phase 13: legacy SHA-1 enrolment — force re-enrolment transparently.
            # The expected algorithm for this role differs from what was enrolled.
            expected_algo = ROLE_TOTP_ALGO.get(record.account_tier, LEGACY_TOTP_ALGO)
            if record.totp_secret and record.totp_algorithm != expected_algo:
                record.force_totp_provision = True
                record.failed_attempts = 0
                await self._update(conn, record)
                return True, record, "totp_provision_required"

            if record.totp_backoff_until > time.time():
                return False, None, generic_fail

            role_digits = ROLE_TOTP_DIGITS.get(record.account_tier, 6)
            totp_ok = await self._verify_totp_with_replay(
                conn,
                record.totp_secret,
                totp_code,
                algorithm=record.totp_algorithm,
                digits=role_digits,
            )

            if not totp_ok:
                record.totp_failed_attempts += 1
                n = record.totp_failed_attempts
                if n >= _MAX_FAILED_ATTEMPTS:
                    record.locked_until = time.time() + _LOCKOUT_SECONDS
                    record.totp_failed_attempts = 0
                    record.totp_backoff_until = 0.0
                    logger.warning(
                        "Account locked after %d TOTP failures: %s",
                        _MAX_FAILED_ATTEMPTS,
                        username,
                    )
                    # ACS gap #95: emit structured ACCOUNT_LOCKOUT event.
                    _emit_lockout_event(audit_writer, username, "totp", _MAX_FAILED_ATTEMPTS, account_tier=record.account_tier)
                else:
                    delay = _TOTP_BACKOFF_SECONDS[min(n, len(_TOTP_BACKOFF_SECONDS) - 1)]
                    record.totp_backoff_until = time.time() + delay
                    logger.info(
                        "TOTP backoff applied: %ds for %s (attempt %d)",
                        delay,
                        username,
                        n,
                    )
                await self._update(conn, record)
                return False, None, generic_fail

            # Full success — stamp last_login_at for AC-2(F2) inactivity tracking
            record.failed_attempts = 0
            record.totp_failed_attempts = 0
            record.totp_backoff_until = 0.0
            record.last_login_at = time.time()
            await self._update(conn, record)
            return True, record, "ok"

    # -- TOTP provisioning --------------------------------------------------

    async def provision_totp_start(self, username: str) -> tuple[TotpProvisioning, RecoveryCodeSet]:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            record = await self._fetch_by_username(conn, username)
            if record is None:
                raise KeyError(username)

            # Phase 13: choose algorithm and digit count based on account tier.
            algo = ROLE_TOTP_ALGO.get(record.account_tier, LEGACY_TOTP_ALGO)
            digits = ROLE_TOTP_DIGITS.get(record.account_tier, 6)
            prov = generate_provisioning(account_name=username, algorithm=algo, digits=digits)
            code_set = generate_recovery_code_set(prov.recovery_codes)
            record.totp_secret = prov.secret_b32
            record.totp_algorithm = algo
            record.recovery_codes = code_set
            record.force_totp_provision = True
            await self._update(conn, record)
            return prov, code_set

    async def provision_totp_confirm(self, username: str, totp_code: str) -> tuple[bool, str]:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            record = await self._fetch_by_username(conn, username)
            if record is None:
                return False, "account_not_found"
            if not record.totp_secret:
                return False, "no_pending_enrolment"
            role_digits = ROLE_TOTP_DIGITS.get(record.account_tier, 6)
            if not await self._verify_totp_with_replay(
                conn,
                record.totp_secret,
                totp_code,
                algorithm=record.totp_algorithm,
                digits=role_digits,
            ):
                return False, "invalid_totp_code"
            record.force_totp_provision = False
            await self._update(conn, record)
            return True, "ok"

    async def provision_totp(self, username: str) -> tuple[TotpProvisioning, RecoveryCodeSet]:
        # Back-compat wrapper — callers must still call provision_totp_confirm
        # to flip force_totp_provision = False.
        prov, code_set = await self.provision_totp_start(username)
        return prov, code_set

    # -- Password change ----------------------------------------------------

    async def change_password(
        self,
        username: str,
        current_password: str,
        totp_code: str,
        new_password: str,
        *,
        audit_writer=None,
    ) -> tuple[bool, str]:
        """
        Self-service password change with reuse history enforcement.

        CMMC L2 IA.L2-3.5.8: checks new password against the last
        PASSWORD_HISTORY_DEPTH hashes from password_history.  Rejects with
        reason "password_reuse" on match; emits PASSWORD_REUSE_REJECTED
        audit event via audit_writer if supplied.

        Returns (success, reason).
        """
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            record = await self._fetch_by_username(conn, username)
            if record is None:
                return False, "invalid_credentials"
            if not verify_password(current_password, record.password_hash):
                return False, "invalid_credentials"
            role_digits = ROLE_TOTP_DIGITS.get(record.account_tier, 6)
            if not await self._verify_totp_with_replay(
                conn,
                record.totp_secret,
                totp_code,
                algorithm=record.totp_algorithm,
                digits=role_digits,
            ):
                return False, "invalid_totp"

            # -- Reuse history check (IA.L2-3.5.8) --------------------------
            depth = _get_history_depth()
            reuse = await self._check_password_history(conn, record.account_id, new_password, depth)
            if reuse:
                logger.info(
                    "Password change rejected — reuse detected (user_id=%s, depth=%d)",
                    record.account_id,
                    depth,
                )
                if audit_writer is not None:
                    from yashigani.audit.schema import PasswordReuseRejectedEvent

                    try:
                        evt = PasswordReuseRejectedEvent(
                            user_id=record.account_id,
                            history_depth_checked=depth,
                        )
                        await audit_writer.write(evt)
                    except Exception:
                        logger.warning(
                            "Failed to emit PASSWORD_REUSE_REJECTED audit event",
                            exc_info=True,
                        )
                return False, "password_reuse"

            # -- Commit change + record history ------------------------------
            old_hash = record.password_hash
            record.password_hash = hash_password(new_password)
            record.force_password_change = False
            record.password_changed_at = time.time()
            await self._update(conn, record)

            # Insert old hash into history, then prune oldest beyond depth.
            await self._record_password_history(conn, record.account_id, old_hash, depth)

            return True, "ok"

    async def _check_password_history(
        self,
        conn: asyncpg.Connection,
        account_id: str,
        new_password: str,
        depth: int,
    ) -> bool:
        """
        Returns True if new_password matches any of the last `depth` hashes.

        Argon2id verify is used (constant-time-ish within each verify call).
        We iterate at most `depth` hashes — bounded work per request.
        """
        rows = await conn.fetch(
            """
            SELECT password_hash FROM password_history
            WHERE user_id = $1
            ORDER BY changed_at DESC
            LIMIT $2
            """,
            uuid.UUID(account_id),
            depth,
        )
        for row in rows:
            if verify_password(new_password, row["password_hash"]):
                return True
        return False

    async def _record_password_history(
        self,
        conn: asyncpg.Connection,
        account_id: str,
        old_hash: str,
        depth: int,
    ) -> None:
        """
        Insert the old hash into password_history, then delete entries
        older than the most-recent `depth` rows (keeps the table bounded).
        """
        import datetime as _dt

        now_ts = _dt.datetime.now(_dt.timezone.utc)
        uid = uuid.UUID(account_id)
        await conn.execute(
            """
            INSERT INTO password_history (user_id, password_hash, changed_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id, changed_at) DO NOTHING
            """,
            uid,
            old_hash,
            now_ts,
        )
        # Prune: keep only the most-recent `depth` rows per user.
        await conn.execute(
            """
            DELETE FROM password_history
            WHERE user_id = $1
              AND changed_at NOT IN (
                  SELECT changed_at FROM password_history
                  WHERE user_id = $1
                  ORDER BY changed_at DESC
                  LIMIT $2
              )
            """,
            uid,
            depth,
        )

    # -- Admin actions ------------------------------------------------------

    async def full_reset_user(
        self,
        username: str,
        admin_totp_secret: str,
        admin_totp_code: str,
        admin_totp_algorithm: str = LEGACY_TOTP_ALGO,
        admin_totp_digits: int = 8,
    ) -> tuple[bool, str]:
        """
        Full-reset a user account. Requires admin TOTP re-verification.

        admin_totp_algorithm / admin_totp_digits — must match the algorithm and
        digit count on the acting admin's AccountRecord (from ``totp_algorithm``
        and ``ROLE_TOTP_DIGITS[account_tier]``). Callers must pass these
        explicitly; the defaults are conservative fail-safe values only.
        """
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            if not await self._verify_totp_with_replay(
                conn,
                admin_totp_secret,
                admin_totp_code,
                algorithm=admin_totp_algorithm,
                digits=admin_totp_digits,
            ):
                return False, "invalid_admin_totp"

            record = await self._fetch_by_username(conn, username)
            if record is None:
                return False, "user_not_found"

            record.totp_secret = ""
            record.totp_algorithm = LEGACY_TOTP_ALGO  # sentinel — requires re-enrolment
            record.recovery_codes = None
            record.force_password_change = True
            record.force_totp_provision = True
            record.failed_attempts = 0
            record.locked_until = 0.0
            # check_breach=False: system-generated temp password, not user-chosen.
            temp_password = generate_password(36)
            record.password_hash = hash_password(temp_password, check_breach=False)
            await self._update(conn, record)
            return True, "ok"

    async def disable(self, username: str) -> bool:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            record = await self._fetch_by_username(conn, username)
            if record is None:
                return False
            record.disabled = True
            await self._update(conn, record)
            return True

    async def enable(self, username: str) -> bool:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            record = await self._fetch_by_username(conn, username)
            if record is None:
                return False
            record.disabled = False
            await self._update(conn, record)
            return True

    # -- FedRAMP AC-2(F2) inactive-account disable --------------------------

    async def list_inactive_accounts(
        self,
        threshold_days: int,
        exempt_ids: frozenset[str],
    ) -> list[AccountRecord]:
        """
        Return all non-disabled accounts whose last_login_at is older than
        threshold_days. Exempts account_ids listed in exempt_ids.

        Used by the inactive-account cron task to calculate the disable set
        before applying the safety rail (max-percent check).
        """
        import datetime as _dt

        cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=threshold_days)
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM admin_accounts
                WHERE disabled = false
                  AND last_login_at IS NOT NULL
                  AND last_login_at < $1
                ORDER BY last_login_at ASC
                """,
                cutoff,
            )
            candidates = [_row_to_record(r) for r in rows]
            return [r for r in candidates if r.account_id not in exempt_ids]

    async def disable_inactive(
        self,
        account_id: str,
    ) -> bool:
        """
        Atomically set disabled=true and inactive_disabled_at=now() for a
        single account identified by account_id.  Returns True if the row
        was updated, False if not found or already disabled.

        This is the only path that sets inactive_disabled_at; operator-initiated
        disable uses the existing disable() method which does NOT touch this column.
        """
        import datetime as _dt

        now_ts = _dt.datetime.now(_dt.timezone.utc)
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            res = await conn.execute(
                """
                UPDATE admin_accounts
                SET disabled = true,
                    inactive_disabled_at = $2
                WHERE account_id = $1
                  AND disabled = false
                """,
                uuid.UUID(account_id),
                now_ts,
            )
            try:
                return int(res.split()[-1]) > 0
            except (ValueError, IndexError):
                return False

    async def total_account_count(self) -> int:
        """Total number of accounts (both admin and user, disabled and active)."""
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            val = await conn.fetchval("SELECT COUNT(*) FROM admin_accounts")
            return int(val or 0)

    # -- Counters / listing -------------------------------------------------

    async def active_admin_count(self) -> int:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            val = await conn.fetchval(
                "SELECT COUNT(*) FROM admin_accounts WHERE account_tier = 'admin' AND disabled = false"
            )
            return int(val or 0)

    async def total_admin_count(self) -> int:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            val = await conn.fetchval("SELECT COUNT(*) FROM admin_accounts WHERE account_tier = 'admin'")
            return int(val or 0)

    async def total_user_count(self) -> int:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            val = await conn.fetchval("SELECT COUNT(*) FROM admin_accounts WHERE account_tier = 'user'")
            return int(val or 0)

    async def list_accounts(self) -> list[AccountRecord]:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            rows = await conn.fetch("SELECT * FROM admin_accounts ORDER BY created_at")
            return [_row_to_record(r) for r in rows]

    async def get_account(self, username: str) -> Optional[AccountRecord]:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            return await self._fetch_by_username(conn, username)

    async def get_account_by_id(self, account_id: str) -> Optional[AccountRecord]:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            row = await conn.fetchrow(
                "SELECT * FROM admin_accounts WHERE account_id = $1",
                uuid.UUID(account_id),
            )
            return _row_to_record(row) if row else None

    async def get_account_by_email(self, email: str) -> Optional[AccountRecord]:
        """
        SoD-001..SoD-004: cross-store collision check.
        Returns the admin_accounts record whose email column matches the given
        email (case-insensitive), or None if not found.
        Used by SCIM and SSO paths to verify no admin account exists with the
        same email before provisioning a user identity.
        """
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            row = await conn.fetchrow(
                "SELECT * FROM admin_accounts WHERE lower(email) = lower($1)",
                email.strip(),
            )
            return _row_to_record(row) if row else None

    async def delete_account(self, username: str) -> bool:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            res = await conn.execute(
                "DELETE FROM admin_accounts WHERE username = $1",
                username,
            )
            # asyncpg returns "DELETE N"
            try:
                return int(res.split()[-1]) > 0
            except (ValueError, IndexError):
                return False

    async def set_email(self, username: str, email: str) -> bool:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            res = await conn.execute(
                "UPDATE admin_accounts SET email = $1 WHERE username = $2",
                email,
                username,
            )
            try:
                return int(res.split()[-1]) > 0
            except (ValueError, IndexError):
                return False

    async def force_password_change(self, username: str) -> bool:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            res = await conn.execute(
                "UPDATE admin_accounts SET force_password_change = true WHERE username = $1",
                username,
            )
            try:
                return int(res.split()[-1]) > 0
            except (ValueError, IndexError):
                return False

    async def force_totp_reprovision(self, username: str) -> bool:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            res = await conn.execute(
                "UPDATE admin_accounts SET "
                "totp_secret = '', recovery_codes = NULL, "
                "force_totp_provision = true, "
                "totp_algorithm = 'SHA1' "  # sentinel — next provision_totp_start sets role algo
                "WHERE username = $1",
                username,
            )
            try:
                return int(res.split()[-1]) > 0
            except (ValueError, IndexError):
                return False

    async def set_totp_secret_direct(
        self,
        username: str,
        totp_secret: str,
        algorithm: str = LEGACY_TOTP_ALGO,
    ) -> bool:
        """
        INSTALLER-PRIVILEGED bootstrap-only path.

        Writes a pre-provisioned TOTP secret (supplied out-of-band by the
        installer via /run/secrets/adminN_totp_secret) directly onto an
        account, bypassing the user-driven provisioning + confirmation
        flow. Clears force_totp_provision because the installer is trusted
        to have delivered the secret to the admin via a separate channel
        (printed to stdout during install).

        algorithm — the HMAC algorithm that was used to generate the URI
        delivered to the admin ("SHA512" for admin-tier bootstrap paths in
        3.1+). Callers MUST pass the correct algorithm so the stored
        totp_algorithm column matches what the authenticator app was
        configured with.

        This is the ONLY place in the codebase that should call this
        method — user-facing flows MUST go through
        provision_totp_start + provision_totp_confirm.
        """
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            res = await conn.execute(
                "UPDATE admin_accounts SET "
                "totp_secret = $1, force_totp_provision = false, totp_algorithm = $3 "
                "WHERE username = $2",
                totp_secret,
                username,
                algorithm.upper(),
            )
            try:
                return int(res.split()[-1]) > 0
            except (ValueError, IndexError):
                return False

    # -- Internal helpers ---------------------------------------------------

    async def _insert(self, record: AccountRecord) -> None:
        import datetime as _dt

        last_login_ts = (
            _dt.datetime.fromtimestamp(record.last_login_at, tz=_dt.timezone.utc)
            if record.last_login_at is not None
            else None
        )
        inactive_disabled_ts = (
            _dt.datetime.fromtimestamp(record.inactive_disabled_at, tz=_dt.timezone.utc)
            if record.inactive_disabled_at is not None
            else None
        )
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            await conn.execute(
                """
                INSERT INTO admin_accounts (
                    account_id, tenant_id, username, password_hash,
                    totp_secret, totp_algorithm, recovery_codes, account_tier, email,
                    force_password_change, force_totp_provision, disabled,
                    failed_attempts, locked_until,
                    totp_failed_attempts, totp_backoff_until,
                    created_at, password_changed_at,
                    last_login_at, inactive_disabled_at
                ) VALUES (
                    $1, $2::uuid, $3, $4,
                    $5, $6, $7::jsonb, $8, $9,
                    $10, $11, $12,
                    $13, $14,
                    $15, $16,
                    $17, $18,
                    $19, $20
                )
                """,
                uuid.UUID(record.account_id),
                _PLATFORM_TENANT_ID,
                record.username,
                record.password_hash,
                record.totp_secret,
                record.totp_algorithm,
                _serialise_recovery(record.recovery_codes),
                record.account_tier,
                record.email,
                record.force_password_change,
                record.force_totp_provision,
                record.disabled,
                record.failed_attempts,
                record.locked_until,
                record.totp_failed_attempts,
                record.totp_backoff_until,
                record.created_at,
                record.password_changed_at,
                last_login_ts,
                inactive_disabled_ts,
            )

    async def _update(self, conn: asyncpg.Connection, record: AccountRecord) -> None:
        import datetime as _dt

        last_login_ts = (
            _dt.datetime.fromtimestamp(record.last_login_at, tz=_dt.timezone.utc)
            if record.last_login_at is not None
            else None
        )
        inactive_disabled_ts = (
            _dt.datetime.fromtimestamp(record.inactive_disabled_at, tz=_dt.timezone.utc)
            if record.inactive_disabled_at is not None
            else None
        )
        await conn.execute(
            """
            UPDATE admin_accounts SET
                password_hash = $2,
                totp_secret = $3,
                totp_algorithm = $4,
                recovery_codes = $5::jsonb,
                email = $6,
                force_password_change = $7,
                force_totp_provision = $8,
                disabled = $9,
                failed_attempts = $10,
                locked_until = $11,
                totp_failed_attempts = $12,
                totp_backoff_until = $13,
                password_changed_at = $14,
                last_login_at = $15,
                inactive_disabled_at = $16
            WHERE username = $1
            """,
            record.username,
            record.password_hash,
            record.totp_secret,
            record.totp_algorithm,
            _serialise_recovery(record.recovery_codes),
            record.email,
            record.force_password_change,
            record.force_totp_provision,
            record.disabled,
            record.failed_attempts,
            record.locked_until,
            record.totp_failed_attempts,
            record.totp_backoff_until,
            record.password_changed_at,
            last_login_ts,
            inactive_disabled_ts,
        )

    async def _fetch_by_username(self, conn: asyncpg.Connection, username: str) -> Optional[AccountRecord]:
        row = await conn.fetchrow(
            "SELECT * FROM admin_accounts WHERE username = $1",
            username,
        )
        return _row_to_record(row) if row else None

    async def _verify_totp_with_replay(
        self,
        conn: asyncpg.Connection,
        secret_b32: str,
        totp_code: str,
        algorithm: str = LEGACY_TOTP_ALGO,
        digits: int = 6,
    ) -> bool:
        """
        Wrap verify_totp() with a Postgres-backed replay cache.

        algorithm / digits — must match the algorithm and digit count stored on
        the AccountRecord.  Callers must pass these explicitly; the defaults are
        conservative legacy values for the migration window.

        Loads the set of code_hashes that are still within the replay
        window, invokes verify_totp() with that local set, and if the set
        grew (i.e. the code was valid and just-consumed) INSERTs the new
        hash with a short TTL.
        """
        if not secret_b32:
            return False
        # GC expired entries inline — used_totp_codes is small and bounded
        # by (window_size × concurrent_users).
        await conn.execute("DELETE FROM used_totp_codes WHERE expires_at < now()")
        rows = await conn.fetch("SELECT code_hash FROM used_totp_codes")
        cache: set[str] = {r["code_hash"] for r in rows}
        # Translate the opaque window_key verify_totp() uses into a sha256
        # digest so plaintext secrets never land in the DB.
        translation: dict[str, str] = {}

        class _HashingSet(set):
            def __contains__(self, key: object) -> bool:
                if isinstance(key, str):
                    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
                    translation[digest] = key
                    return digest in cache
                return False

            def add(self, key: object) -> None:  # type: ignore[override]
                if isinstance(key, str):
                    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
                    cache.add(digest)
                    translation[digest] = key
                    super().add(digest)

        proxy = _HashingSet()
        before = len(cache)
        ok = verify_totp(secret_b32, totp_code, proxy, algorithm=algorithm, digits=digits)
        if ok and len(cache) > before:
            # Insert only the newly consumed hash(es) — expiration is
            # short (60s) which covers the full valid-window set of three
            # 30s slots.
            for new_hash in cache - {r["code_hash"] for r in rows}:
                await conn.execute(
                    "INSERT INTO used_totp_codes (code_hash, expires_at) "
                    "VALUES ($1, now() + ($2 || ' seconds')::interval) "
                    "ON CONFLICT (code_hash) DO NOTHING",
                    new_hash,
                    str(_TOTP_REPLAY_TTL_SECONDS),
                )
        return ok


# ---------------------------------------------------------------------------
# Row <-> record marshalling
# ---------------------------------------------------------------------------


def _serialise_recovery(code_set: Optional[RecoveryCodeSet]) -> Optional[str]:
    if code_set is None:
        return None
    return json.dumps({"hashes": code_set.hashes, "used": code_set.used})


def _deserialise_recovery(raw: object) -> Optional[RecoveryCodeSet]:
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        data = json.loads(raw)
    elif isinstance(raw, dict):
        data = raw
    else:
        return None
    return RecoveryCodeSet(
        hashes=list(data.get("hashes", [])),
        used=list(data.get("used", [])),
    )


def _row_to_record(row) -> AccountRecord:
    # last_login_at and inactive_disabled_at are TIMESTAMPTZ — convert to epoch float.
    # Columns may not exist in pre-migration schemas (None if missing from SELECT *).
    def _ts_to_epoch(ts) -> "Optional[float]":
        if ts is None:
            return None
        if hasattr(ts, "timestamp"):
            return ts.timestamp()
        return float(ts)

    return AccountRecord(
        account_id=str(row["account_id"]),
        username=row["username"],
        password_hash=row["password_hash"],
        totp_secret=row["totp_secret"] or "",
        recovery_codes=_deserialise_recovery(row["recovery_codes"]),
        account_tier=row["account_tier"],
        email=row["email"],
        force_password_change=row["force_password_change"],
        force_totp_provision=row["force_totp_provision"],
        disabled=row["disabled"],
        failed_attempts=row["failed_attempts"],
        locked_until=float(row["locked_until"]),
        totp_failed_attempts=row["totp_failed_attempts"],
        totp_backoff_until=float(row["totp_backoff_until"]),
        created_at=float(row["created_at"]),
        password_changed_at=float(row["password_changed_at"]),
        last_login_at=_ts_to_epoch(row["last_login_at"]) if "last_login_at" in row.keys() else None,
        inactive_disabled_at=_ts_to_epoch(row["inactive_disabled_at"])
        if "inactive_disabled_at" in row.keys()
        else None,
        # Phase 13: totp_algorithm column (migration 0023); fall back to SHA1 for
        # pre-migration rows that don't yet have the column.
        totp_algorithm=row["totp_algorithm"] if "totp_algorithm" in row.keys() else LEGACY_TOTP_ALGO,
    )


def _is_locked(record: AccountRecord) -> bool:
    return record.locked_until > time.time()


def _emit_lockout_event(
    audit_writer,
    username: str,
    lockout_type: str,
    failed_attempts: int,
    account_tier: str = "admin",
) -> None:
    """
    Emit an ACCOUNT_LOCKOUT audit event.  ACS gap #95 (auth_log).

    Called inside authenticate() when a lockout is triggered.  Swallows
    exceptions so an audit failure never blocks the auth response.

    account_tier is derived from the fetched AccountRecord at call site —
    defence-in-depth: RBAC bypass visible in audit (ASVS V7.3.4).
    """
    if audit_writer is None:
        return
    try:
        from yashigani.audit.schema import AccountLockoutEvent

        evt = AccountLockoutEvent(
            account_tier=account_tier,
            admin_account=username,
            lockout_type=lockout_type,
            failed_attempts=failed_attempts,
            lockout_duration_seconds=_LOCKOUT_SECONDS,
        )
        audit_writer.write(evt)
    except Exception:
        logger.warning("Failed to emit ACCOUNT_LOCKOUT audit event", exc_info=True)
