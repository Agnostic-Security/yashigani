"""
Yashigani Auth — Local authentication handler.
Covers admin and user accounts in YASHIGANI_AUTH_MODE=local.
OWASP ASVS V2.1, V2.4, V2.8, V3.2, V3.3, V5 (TOTP exponential backoff).

TOTP backoff schedule (v0.2.0, ASVS v5 V2 compensating control):
  1st failure → 1 s
  2nd failure → 2 s
  3rd failure → 4 s
  4th failure → 8 s
  5th failure → 1800 s (30-minute hard lockout, same as password lockout)
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from yashigani.auth.password import hash_password, verify_password, generate_password
from yashigani.auth.totp import (
    generate_provisioning,
    generate_recovery_code_set,
    verify_totp,
    verify_recovery_code,
    codes_remaining,
    TotpProvisioning,
    RecoveryCodeSet,
)

logger = logging.getLogger(__name__)

_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_SECONDS = 1800   # 30 minutes

# TOTP exponential backoff delays (seconds) indexed by failure count 1-4.
# 5th failure triggers the same hard lockout as password failures.
_TOTP_BACKOFF_SECONDS = [0, 1, 2, 4, 8]   # index = failure count (0 = unused)


@dataclass
class AccountRecord:
    account_id: str
    username: str
    password_hash: str
    totp_secret: str
    recovery_codes: Optional[RecoveryCodeSet]
    account_tier: str                       # "admin" | "user"
    email: Optional[str] = None             # explicit email; falls back to username@yashigani.local
    force_password_change: bool = True
    force_totp_provision: bool = True
    disabled: bool = False
    failed_attempts: int = 0
    locked_until: float = 0.0
    # TOTP-specific exponential backoff (independent of password lockout)
    totp_failed_attempts: int = 0
    totp_backoff_until: float = 0.0
    created_at: float = field(default_factory=time.time)
    password_changed_at: float = field(default_factory=time.time)
    # v2.23.3 — FedRAMP AC-2(F2) inactive-account tracking (LU-YSG-002)
    # last_login_at: None means never logged in (backfilled to created_at on migration).
    # Use Optional[float] (epoch seconds) for symmetry with other time fields.
    last_login_at: Optional[float] = None
    inactive_disabled_at: Optional[float] = None


class LocalAuthService:
    """
    In-memory account store for local auth mode.
    Production deployments back this with a database — this implementation
    uses a dict as a starting point for testing and local dev.
    """

    def __init__(self, used_totp_codes: Optional[set] = None) -> None:
        self._accounts: dict[str, AccountRecord] = {}       # username → record
        self._used_totp_codes: set[str] = used_totp_codes or set()

    # -- Account lifecycle ---------------------------------------------------

    def create_admin(
        self,
        username: str,
        auto_generate: bool = True,
        plaintext_password: Optional[str] = None,
    ) -> tuple[AccountRecord, Optional[str]]:
        """
        Create an admin account.
        If auto_generate=True: generate a 36-char password, hash it,
        and return the plaintext once (caller prints to stdout).
        Returns (record, plaintext_password_or_None).
        """
        plaintext = plaintext_password or (generate_password(36) if auto_generate else None)
        if plaintext is None:
            raise ValueError("Must provide password or set auto_generate=True")

        record = AccountRecord(
            account_id=_new_id(),
            username=username,
            # check_breach=False: system-generated password, not user-chosen.
            # HIBP check applies to user-chosen passwords only (ASVS V2.1.7).
            password_hash=hash_password(plaintext, check_breach=False),
            totp_secret="",              # set at first login via provisioning
            recovery_codes=None,
            account_tier="admin",
            email=username,              # admin usernames are already emails
            force_password_change=True,
            force_totp_provision=True,
        )
        self._accounts[username] = record
        # Return plaintext only to caller — caller must print once and discard
        return record, plaintext if auto_generate else None

    def create_user(
        self,
        username: str,
        plaintext_password: str,
    ) -> AccountRecord:
        record = AccountRecord(
            account_id=_new_id(),
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
        self._accounts[username] = record
        return record

    # -- Authentication ------------------------------------------------------

    def authenticate(
        self,
        username: str,
        password: str,
        totp_code: str,
    ) -> tuple[bool, Optional[AccountRecord], str]:
        """
        Verify username, password, and TOTP.
        Returns (success, record_or_None, failure_reason).
        """
        record = self._accounts.get(username)
        # Use same error message for unknown user, wrong password, locked account
        # to prevent username enumeration (ASVS V2.1)
        generic_fail = "invalid_credentials"

        if record is None or record.disabled:
            return False, None, generic_fail

        if _is_locked(record):
            return False, None, generic_fail

        if not verify_password(password, record.password_hash):
            record.failed_attempts += 1
            if record.failed_attempts >= _MAX_FAILED_ATTEMPTS:
                record.locked_until = time.time() + _LOCKOUT_SECONDS
                logger.warning("Account locked after %d failures: %s",
                               _MAX_FAILED_ATTEMPTS, username)
            return False, None, generic_fail

        # Password OK — check TOTP
        if record.force_totp_provision:
            # TOTP not yet provisioned — let caller handle provisioning flow
            record.failed_attempts = 0
            return True, record, "totp_provision_required"

        # Exponential backoff check — ASVS v5 V2 compensating control
        if record.totp_backoff_until > time.time():
            return False, None, generic_fail

        if not verify_totp(record.totp_secret, totp_code, self._used_totp_codes):
            record.totp_failed_attempts += 1
            n = record.totp_failed_attempts
            if n >= _MAX_FAILED_ATTEMPTS:
                # 5th failure → hard lockout (same as password lockout)
                record.locked_until = time.time() + _LOCKOUT_SECONDS
                record.totp_failed_attempts = 0
                record.totp_backoff_until = 0.0
                logger.warning(
                    "Account locked after %d TOTP failures: %s",
                    _MAX_FAILED_ATTEMPTS, username,
                )
            else:
                delay = _TOTP_BACKOFF_SECONDS[min(n, len(_TOTP_BACKOFF_SECONDS) - 1)]
                record.totp_backoff_until = time.time() + delay
                logger.info(
                    "TOTP backoff applied: %ds for %s (attempt %d)",
                    delay, username, n,
                )
            return False, None, generic_fail

        # Full success — clear all failure counters
        record.failed_attempts = 0
        record.totp_failed_attempts = 0
        record.totp_backoff_until = 0.0
        return True, record, "ok"

    # -- TOTP provisioning ---------------------------------------------------

    def provision_totp_start(
        self, username: str
    ) -> tuple[TotpProvisioning, RecoveryCodeSet]:
        """
        Begin TOTP enrolment. Generates the seed + recovery codes and stores
        them against the account, but leaves ``force_totp_provision=True``
        so the account still cannot complete authenticated actions until
        the user proves possession of the seed via
        :meth:`provision_totp_confirm`.

        Part of the split-enrolment flow added for QA Wave 2 Issue C: the
        previous atomic ``provision_totp`` required a ``totp_code`` on the
        same call that returned the seed — impossible for a first-time
        client.
        """
        record = self._accounts[username]
        prov = generate_provisioning(account_name=username)
        code_set = generate_recovery_code_set(prov.recovery_codes)

        record.totp_secret = prov.secret_b32
        record.recovery_codes = code_set
        # Leave force_totp_provision=True — only provision_totp_confirm
        # (with a valid code) may clear it.
        record.force_totp_provision = True
        return prov, code_set

    def provision_totp_confirm(
        self, username: str, totp_code: str
    ) -> tuple[bool, str]:
        """
        Finalise TOTP enrolment by verifying the user's code against the
        seed stored during :meth:`provision_totp_start`. On success the
        account is considered enrolled and
        ``force_totp_provision`` is cleared. On failure the seed is left
        in place so the user can retry without losing their QR/recovery
        codes.

        Returns ``(True, "ok")`` on success, ``(False, reason)`` on failure.
        """
        record = self._accounts.get(username)
        if record is None:
            return False, "account_not_found"
        if not record.totp_secret:
            return False, "no_pending_enrolment"
        if not verify_totp(record.totp_secret, totp_code, self._used_totp_codes):
            return False, "invalid_totp_code"
        record.force_totp_provision = False
        return True, "ok"

    def provision_totp(
        self, username: str
    ) -> tuple[TotpProvisioning, RecoveryCodeSet]:
        """
        Back-compat wrapper around :meth:`provision_totp_start`.

        The historical behaviour was to clear ``force_totp_provision``
        immediately on seed generation, which made the confirmation step
        in the route handler cosmetic. Callers that want the old atomic
        behaviour (e.g. CLI provisioning where the seed is already handed
        to the client) should call ``provision_totp_start`` followed by
        ``provision_totp_confirm`` with a locally-computed code. This
        wrapper is kept so existing integrations do not break.
        """
        prov, code_set = self.provision_totp_start(username)
        # Matching the pre-split default: caller is responsible for calling
        # provision_totp_confirm separately. We do NOT auto-clear the flag
        # here — the HTTP layer enforces the confirmation contract.
        return prov, code_set

    # -- Password change -----------------------------------------------------

    def change_password(
        self,
        username: str,
        current_password: str,
        totp_code: str,
        new_password: str,
    ) -> tuple[bool, str]:
        """
        Self-service password change. All sessions must be invalidated by caller.
        Returns (success, reason).
        """
        record = self._accounts.get(username)
        if record is None:
            return False, "invalid_credentials"

        if not verify_password(current_password, record.password_hash):
            return False, "invalid_credentials"

        if not verify_totp(record.totp_secret, totp_code, self._used_totp_codes):
            return False, "invalid_totp"

        record.password_hash = hash_password(new_password)
        record.force_password_change = False
        return True, "ok"

    # -- Admin actions -------------------------------------------------------

    def full_reset_user(
        self,
        username: str,
        admin_totp_secret: str,
        admin_totp_code: str,
    ) -> tuple[bool, str]:
        """
        Admin full-reset a user account (strips all access).
        Requires admin's TOTP re-verification (ASVS V2.8).
        """
        if not verify_totp(admin_totp_secret, admin_totp_code, self._used_totp_codes):
            return False, "invalid_admin_totp"

        record = self._accounts.get(username)
        if record is None:
            return False, "user_not_found"

        # Strip all access
        record.totp_secret = ""
        record.recovery_codes = None
        record.force_password_change = True
        record.force_totp_provision = True
        record.failed_attempts = 0
        record.locked_until = 0.0
        # Password is reset by generating a new temporary one.
        # check_breach=False: system-generated temp password, not user-chosen.
        temp_password = generate_password(36)
        record.password_hash = hash_password(temp_password, check_breach=False)

        return True, "ok"

    def disable(self, username: str) -> bool:
        record = self._accounts.get(username)
        if record:
            record.disabled = True
            return True
        return False

    def enable(self, username: str) -> bool:
        record = self._accounts.get(username)
        if record:
            record.disabled = False
            return True
        return False

    def active_admin_count(self) -> int:
        return sum(
            1 for r in self._accounts.values()
            if r.account_tier == "admin" and not r.disabled
        )

    def total_admin_count(self) -> int:
        return sum(
            1 for r in self._accounts.values()
            if r.account_tier == "admin"
        )

    def total_user_count(self) -> int:
        return sum(
            1 for r in self._accounts.values()
            if r.account_tier == "user"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_locked(record: AccountRecord) -> bool:
    return record.locked_until > time.time()


def _new_id() -> str:
    import uuid
    return str(uuid.uuid4())
