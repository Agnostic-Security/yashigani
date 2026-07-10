"""
Gap 1 / v2.23.4 data migration: backfill email field for user-tier accounts.

Gap 1 design intent (Tiago, 2026-05-14):
    "email as the username for normal users"

Admin_accounts table has an `email` column (nullable, added in migration 0006).
Prior to v2.23.4 the `email` column was optional — new user creation via
POST /admin/users could create user-tier records with email=NULL.

This script backfills `email` for all user-tier records in admin_accounts
using the decision table below:

| Existing state | Action |
|---|---|
| username looks like email (contains `@`) AND email IS NULL | Set email = username (auto-backfill) |
| username looks like email AND email IS SET AND matches username | No action |
| username looks like email AND email IS SET AND differs | Log + flag for admin attention; keep as-is |
| username is NOT email-shaped AND email IS NULL | Log + flag for admin attention; do NOT auto-synthesise |
| username is NOT email-shaped AND email IS SET | No action — admin already curated |

The script is IDEMPOTENT — safe to run multiple times.
It produces a clear report of every record changed and every record flagged.

Usage:
    python3 -m yashigani.migrations.v2234_email_as_username [--dry-run]

Requirements:
    - DATABASE_URL environment variable pointing at the platform Postgres instance.
    - Platform tenant 00000000-0000-0000-0000-000000000000 (set by default).
    - asyncpg installed (always present in yashigani deps).

Last updated: 2026-05-14T00:00:00+01:00
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import sys
from typing import Any

_log = logging.getLogger("yashigani.migrations.v2234")

# Minimal email-shape check: must contain '@' and have a valid-looking domain.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


def _looks_like_email(s: str) -> bool:
    return bool(_EMAIL_RE.match(s))


async def _run(dry_run: bool = False) -> None:
    import asyncpg

    db_url = os.environ.get("DATABASE_URL", "")
    if not db_url:
        _log.error("DATABASE_URL not set — aborting.")
        sys.exit(1)

    _log.info("Connecting to database (dry_run=%s)...", dry_run)
    conn = await asyncpg.connect(db_url)

    try:
        # Set tenant context for RLS.
        await conn.execute(f"SET app.tenant_id = '{_PLATFORM_TENANT_ID}'")  # nosem: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query -- PostgreSQL SET command (not DML); _PLATFORM_TENANT_ID is a module-level constant UUID ("00000000-0000-0000-0000-000000000000"), not user-supplied input

        # Fetch all user-tier records.
        rows: list[Any] = await conn.fetch(
            """
            SELECT account_id, username, email
            FROM admin_accounts
            WHERE account_tier = 'user'
            ORDER BY username
            """
        )

        _log.info("Found %d user-tier records.", len(rows))

        auto_backfilled: list[str] = []
        already_ok: list[str] = []
        conflicts: list[tuple[str, str, str]] = []   # (username, existing_email, username_as_email)
        needs_admin: list[str] = []                   # no email, username not email-shaped

        for row in rows:
            username: str = row["username"]
            email: str | None = row["email"]
            account_id: str = str(row["account_id"])

            if _looks_like_email(username):
                if email is None:
                    # Case 1: username looks like email, email is NULL → auto-backfill.
                    if not dry_run:
                        await conn.execute(
                            "UPDATE admin_accounts SET email = $1 WHERE account_id = $2",
                            username,
                            account_id,
                        )
                    _log.info("[AUTO-BACKFILL] username=%s → email set to username", username)
                    auto_backfilled.append(username)
                elif email.lower() == username.lower():
                    # Case 2: email matches username — nothing to do.
                    _log.debug("[OK] username=%s email already matches", username)
                    already_ok.append(username)
                else:
                    # Case 3: email differs from username — admin must resolve.
                    _log.warning(
                        "[FLAG-CONFLICT] username=%s has email=%s which differs from username-as-email. "
                        "Manual admin review required — keeping as-is.",
                        username,
                        email,
                    )
                    conflicts.append((username, email, username))
            else:
                if email is None:
                    # Case 4: username not email-shaped, no email — admin must backfill.
                    _log.warning(
                        "[FLAG-NEEDS-ADMIN] username=%s has no email set and username is not email-shaped. "
                        "Admin must supply a real email address for this account via "
                        "PUT /admin/users/{username}/email (once that route exists) or direct DB update.",
                        username,
                    )
                    needs_admin.append(username)
                else:
                    # Case 5: username not email-shaped but email is set — OK.
                    _log.debug("[OK] username=%s email=%s (admin-curated)", username, email)
                    already_ok.append(username)

        # Summary report.
        print("\n" + "=" * 60)
        print(f"  v2234 email-as-username migration report (dry_run={dry_run})")
        print("=" * 60)
        print(f"  Total user-tier records:   {len(rows)}")
        print(f"  Auto-backfilled:           {len(auto_backfilled)}")
        print(f"  Already OK:                {len(already_ok)}")
        print(f"  Conflict (manual needed):  {len(conflicts)}")
        print(f"  No email, bad username:    {len(needs_admin)}")

        if conflicts:
            print("\n  CONFLICTS (admin action required):")
            for uname, existing_email, _ in conflicts:
                print(f"    username={uname!r}  existing_email={existing_email!r}")

        if needs_admin:
            print("\n  NEEDS ADMIN EMAIL BACKFILL:")
            for uname in needs_admin:
                print(f"    username={uname!r}")

        if auto_backfilled:
            print("\n  AUTO-BACKFILLED (username → email):")
            for uname in auto_backfilled:
                print(f"    username={uname!r}")

        if dry_run:
            print("\n  DRY RUN — no changes written to database.")
        else:
            print("\n  Changes committed.")
        print("=" * 60 + "\n")

        if (conflicts or needs_admin) and not dry_run:
            _log.warning(
                "%d record(s) require admin attention before Gap 1 is fully closed. "
                "See CONFLICTS / NEEDS ADMIN sections above.",
                len(conflicts) + len(needs_admin),
            )

    finally:
        await conn.close()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )
    parser = argparse.ArgumentParser(
        description="v2234 Gap 1 migration: backfill email for user-tier accounts."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Preview changes without writing to the database.",
    )
    args = parser.parse_args()
    asyncio.run(_run(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
