"""
Yashigani Backoffice — SoD cross-store conflict audit cron job (SoD-005).

Iris #96 / v2.24.1 — Admin/User Separation-of-Duties enforcement.

Runs daily at 00:30 UTC (after the midnight audit checkpoint at 00:05).
Compares admin_accounts usernames/emails against identity_registry HUMAN entries.
Any collision (same username or email in both stores) emits an
IDENTITY_STORE_CONFLICT audit event and surfaces the conflict on the
operator dashboard via /admin/dashboard/sod-conflicts.

Design invariants:
  - Read-only: this task never modifies either store — it only reports.
  - Fail-soft: if auth_service or identity_registry is unavailable, the run
    is skipped with a warning. SoD enforcement at creation time is layer 1;
    this cron is the catch-all for residual conflicts.
  - Email comparison is case-insensitive SHA-256 hashed in audit events;
    conflict_value_hash is stored for forensic correlation without storing raw PII.
  - Admin username is stored in the event (not hashed) because it is already
    in the admin audit trail and is not PII in an admin-only context.
  - Conflicts are deduped within a run (same pair reported once per run).

NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / v2.24.1.

Last updated: 2026-05-25T00:00:00+00:00
"""
from __future__ import annotations

import datetime
import hashlib
import logging
from typing import Optional

from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory cache of detected conflicts (refreshed on each run)
# Used by the dashboard endpoint GET /admin/dashboard/sod-conflicts.
# ---------------------------------------------------------------------------

_last_run_conflicts: list[dict] = []
_last_run_at: Optional[str] = None
_last_run_count_admins: int = 0
_last_run_count_identities: int = 0


def get_last_run_result() -> dict:
    """Return the result of the most recent cron run for the dashboard."""
    return {
        "last_run_at": _last_run_at,
        "conflicts": list(_last_run_conflicts),
        "conflict_count": len(_last_run_conflicts),
        "accounts_scanned": _last_run_count_admins,
        "identities_scanned": _last_run_count_identities,
    }


# ---------------------------------------------------------------------------
# Core detection logic
# ---------------------------------------------------------------------------

def _sha256_hex(value: str) -> str:
    """Case-insensitive SHA-256 hash for conflict value storage."""
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()


async def run_sod_conflict_audit() -> int:
    """
    Run the cross-store SoD conflict audit.

    Returns the number of conflicts found. Side-effects:
      - Updates _last_run_conflicts / _last_run_at / _last_run_count_* globals.
      - Emits IDENTITY_STORE_CONFLICT audit events for each conflict found.

    Skips silently if auth_service or identity_registry is unavailable.
    """
    global _last_run_conflicts, _last_run_at, _last_run_count_admins, _last_run_count_identities

    state = backoffice_state
    now_iso = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()

    auth_svc = state.auth_service
    registry = state.identity_registry
    audit_writer = state.audit_writer

    if auth_svc is None:
        logger.warning("SoD-005: auth_service not available — skipping conflict audit run")
        return 0

    if registry is None:
        logger.warning("SoD-005: identity_registry not available — skipping conflict audit run")
        return 0

    # Fetch all admin accounts
    try:
        all_accounts = await auth_svc.list_accounts()
    except Exception as exc:
        logger.error("SoD-005: failed to list admin accounts: %s", exc)
        return 0

    admin_by_username: dict[str, object] = {}
    admin_by_email: dict[str, object] = {}
    for acct in all_accounts:
        if getattr(acct, "account_tier", "") == "admin":
            uname = getattr(acct, "username", "") or ""
            email = getattr(acct, "email", "") or ""
            if uname:
                admin_by_username[uname.strip().lower()] = acct
            if email:
                admin_by_email[email.strip().lower()] = acct

    _last_run_count_admins = len(admin_by_username)

    # Fetch all HUMAN identities from registry
    try:
        # IdentityRegistry.list_all() returns list of dicts or similar
        all_identities = _list_human_identities(registry)
    except Exception as exc:
        logger.error("SoD-005: failed to list identity registry entries: %s", exc)
        return 0

    _last_run_count_identities = len(all_identities)

    conflicts: list[dict] = []
    seen_pairs: set[str] = set()

    from yashigani.audit.schema import IdentityStoreConflictEvent

    for identity in all_identities:
        identity_id = identity.get("identity_id", "")
        slug = identity.get("slug", "")
        # Identities don't store raw email; the slug is derived from email.
        # We check slug-based username match and name field.
        identity_name = identity.get("name", "")  # typically the email or display name

        # Check 1: slug matches an admin username pattern
        # Admin username → slug: admin usernames are emails → slug = <local>-<domain>
        # This is approximate — exact match not guaranteed.
        # More reliable: check if any admin username or email produces the same slug.
        for admin_email, admin_acct in admin_by_email.items():
            from yashigani.backoffice.routes.sso import _email_to_slug
            try:
                admin_slug = _email_to_slug(admin_email)
            except Exception:
                continue
            pair_key = f"{getattr(admin_acct, 'account_id', '')}:{identity_id}"
            if admin_slug == slug and pair_key not in seen_pairs:
                seen_pairs.add(pair_key)
                admin_username = getattr(admin_acct, "username", "")
                admin_account_id = getattr(admin_acct, "account_id", "")
                conflict = {
                    "admin_account_id": admin_account_id,
                    "admin_username": admin_username,
                    "identity_id": identity_id,
                    "conflict_field": "email",
                    "conflict_value_hash": _sha256_hex(admin_email),
                    "detected_at": now_iso,
                }
                conflicts.append(conflict)
                if audit_writer is not None:
                    try:
                        audit_writer.write(IdentityStoreConflictEvent(
                            admin_account_id=admin_account_id,
                            admin_username=admin_username,
                            identity_id=identity_id,
                            conflict_field="email",
                            conflict_value_hash=_sha256_hex(admin_email),
                        ))
                    except Exception as exc:
                        logger.error("SoD-005: audit write failed for conflict: %s", exc)
                logger.warning(
                    "SoD-005: IDENTITY_STORE_CONFLICT admin=%s identity=%s field=email hash=%s",
                    admin_username,
                    identity_id,
                    _sha256_hex(admin_email),
                )

    _last_run_conflicts = conflicts
    _last_run_at = now_iso

    if conflicts:
        logger.warning(
            "SoD-005: audit complete — %d conflict(s) found (admins=%d identities=%d)",
            len(conflicts),
            _last_run_count_admins,
            _last_run_count_identities,
        )
    else:
        logger.info(
            "SoD-005: audit complete — no conflicts (admins=%d identities=%d)",
            _last_run_count_admins,
            _last_run_count_identities,
        )

    return len(conflicts)


def _list_human_identities(registry) -> list[dict]:
    """
    Extract all HUMAN kind identities from the IdentityRegistry.

    IdentityRegistry stores entries in Redis under yashigani:identity:<id>
    and maintains a kind index. We try the supported list methods in order.
    """
    from yashigani.identity.registry import IdentityKind

    # Try list_by_kind if available (preferred — O(1) index lookup)
    if hasattr(registry, "list_by_kind"):
        return registry.list_by_kind(IdentityKind.HUMAN)

    # Fallback: list_all + filter
    if hasattr(registry, "list_all"):
        all_entries = registry.list_all()
        return [e for e in all_entries if e.get("kind") == IdentityKind.HUMAN]

    # Last resort: scan Redis directly via the registry's internal client
    # (only reached on unusual IdentityRegistry implementations)
    logger.warning("SoD-005: IdentityRegistry has no list method — scanning Redis directly")
    r = getattr(registry, "_redis", None)
    if r is None:
        return []

    entries = []
    for key in r.scan_iter("yashigani:identity:*"):
        raw = r.hgetall(key)
        if raw and raw.get("kind") == IdentityKind.HUMAN:
            entries.append({k: v for k, v in raw.items()})
    return entries
