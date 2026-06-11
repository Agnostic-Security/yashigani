#!/usr/bin/env python3
"""
Bootstrap Postgres for Yashigani.

Runs Alembic migrations, then sets the yashigani_app runtime role password to the
SINGLE install-generated credential (docker/secrets/postgres_password, written by
install.sh's `_gen_password` — the one and only password generator). It does NOT
mint a password of its own: migration 0001 creates yashigani_app with the literal
placeholder PASSWORD 'PLACEHOLDER_REPLACED_BY_BOOTSTRAP', and this script (or the
equivalent ALTER in install.sh's bootstrap_postgres step) swaps in the real one.

A second, independent generator here was the root cause of "SASL authentication
failed": it ALTERed the role to a freshly-minted token while the app's DSN used
install.sh's credential, so the SCRAM verifier never matched. Single source only.

Must run as a one-shot init step before the application starts.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


SECRETS_DIR = Path(os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets"))
SENTINEL = SECRETS_DIR / ".postgres_bootstrapped"
DB_DSN_ENV = "YASHIGANI_DB_DSN"


def _read_app_password() -> str:
    """Read the single install-generated credential. Never generate one here."""
    pw_file = SECRETS_DIR / "postgres_password"
    if not pw_file.exists():
        print(
            f"[bootstrap_postgres] {pw_file} missing — install.sh must write the "
            "single postgres_password secret before bootstrap.",
            file=sys.stderr,
        )
        sys.exit(1)
    pw = pw_file.read_text().strip()
    if not pw:
        print(f"[bootstrap_postgres] {pw_file} is empty.", file=sys.stderr)
        sys.exit(1)
    return pw


def main() -> None:
    if SENTINEL.exists():
        print("[bootstrap_postgres] Already bootstrapped — skipping.", flush=True)
        return

    SECRETS_DIR.mkdir(parents=True, exist_ok=True)

    # The single install-generated runtime credential (do not generate here).
    pg_password = _read_app_password()

    # Ensure license_key secret file exists (empty = Community edition).
    # Docker Compose requires the file to exist even if unused.
    license_key_file = SECRETS_DIR / "license_key"
    if not license_key_file.exists():
        license_key_file.touch()
        license_key_file.chmod(0o600)

    # Build DSN for migration
    pg_host = os.getenv("POSTGRES_HOST", "postgres")
    pg_port = os.getenv("POSTGRES_PORT", "5432")
    pg_db = os.getenv("POSTGRES_DB", "yashigani")
    # Use superuser for initial setup, then app role for runtime
    pg_superuser = os.getenv("POSTGRES_SUPERUSER", "postgres")
    pg_superuser_pw = os.getenv("POSTGRES_SUPERUSER_PASSWORD", "")
    migration_dsn = (
        f"postgresql://{pg_superuser}:{pg_superuser_pw}@{pg_host}:{pg_port}/{pg_db}"
    )

    # Run Alembic migrations
    env = os.environ.copy()
    env[DB_DSN_ENV] = migration_dsn
    result = subprocess.run(
        ["python", "-m", "alembic", "upgrade", "head"],
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("[bootstrap_postgres] Alembic migration FAILED:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    print("[bootstrap_postgres] Migrations applied successfully.", flush=True)

    # Replace the migration-0001 placeholder on yashigani_app with the single
    # install-generated credential. Parameterise via psql variable so the password
    # is never shell- or SQL-interpolated.
    update_pw_sql = (
        "ALTER ROLE yashigani_app WITH PASSWORD :'pw';"
    )
    result2 = subprocess.run(
        ["psql", migration_dsn, "-v", f"pw={pg_password}", "-c", update_pw_sql],
        capture_output=True,
        text=True,
    )
    if result2.returncode != 0:
        print("[bootstrap_postgres] Password update FAILED:", file=sys.stderr)
        print(result2.stderr, file=sys.stderr)
        sys.exit(1)
    print(
        "[bootstrap_postgres] yashigani_app runtime credential set "
        "(migration-0001 placeholder replaced).",
        flush=True,
    )

    # Mark bootstrapped
    SENTINEL.touch()
    print("[bootstrap_postgres] Bootstrap complete.", flush=True)


if __name__ == "__main__":
    main()
