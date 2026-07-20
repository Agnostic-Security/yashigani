"""
Yashigani Auth — First-run bootstrap credential generator.

Generates strong random passwords for all infrastructure services on first run
and prints them once to stdout in a clearly delimited block. Credentials are
never stored in plaintext after this point — callers must route them to Docker
Secrets or the KSM provider immediately.

Rule: every service that requires a password uses this module.
      No service ships with a default or hardcoded credential.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Optional

from yashigani.auth.password import generate_password


@dataclass
class BootstrapCredentials:
    """All credentials generated during first-run bootstrap."""
    admin_username: str
    admin_password: str
    grafana_admin_password: str
    prometheus_password: str
    redis_password: str
    # Any additional service passwords added here in future versions
    extras: dict[str, str] = field(default_factory=dict)


_SENTINEL_FILE = "/data/bootstrap/.bootstrap_complete"
_PASSWORD_LENGTH = 36


def already_bootstrapped() -> bool:
    """Return True if bootstrap has already run (sentinel file exists)."""
    return os.path.exists(_SENTINEL_FILE)


def mark_bootstrapped() -> None:
    """Write sentinel file so bootstrap does not repeat on container restart."""
    sentinel = os.path.dirname(_SENTINEL_FILE)
    os.makedirs(sentinel, exist_ok=True)
    with open(_SENTINEL_FILE, "w") as f:
        f.write("1")


def generate_credentials(admin_username: str) -> BootstrapCredentials:
    """
    Generate all first-run credentials.
    Each password is 36 characters, cryptographically random.
    """
    return BootstrapCredentials(
        admin_username=admin_username,
        admin_password=generate_password(_PASSWORD_LENGTH),
        grafana_admin_password=generate_password(_PASSWORD_LENGTH),
        prometheus_password=generate_password(_PASSWORD_LENGTH),
        redis_password=generate_password(_PASSWORD_LENGTH),
    )


def prometheus_basicauth_hash(password: str) -> str:
    """
    Generate a Caddy-compatible bcrypt hash for the Prometheus basic auth block.
    Caddy uses bcrypt for its basicauth directive.
    Returns the hash string to be set as PROMETHEUS_BASICAUTH_HASH in .env.
    """
    try:
        import bcrypt
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    except ImportError:
        # Fallback: instruct operator to run caddy hash-password manually
        return "REPLACE_WITH: caddy hash-password --plaintext " + password


def print_credentials(creds: BootstrapCredentials) -> None:
    """
    Print all generated credentials to stdout in a clearly delimited block.
    Called exactly once during first-run bootstrap.
    """
    border = "═" * 58
    sep    = "─" * 58
    lines = [
        f"╔{border}╗",
        f"║{'  YASHIGANI FIRST-RUN CREDENTIALS':^58}║",
        f"║{'  Store these securely — NOT shown again':^58}║",
        f"╠{border}╣",
        f"║  Admin account  : {creds.admin_username:<38}║",
        f"║  Admin password : {creds.admin_password:<38}║",
        f"╠{sep}╣",
        f"║  Grafana admin  : {creds.grafana_admin_password:<38}║",
        f"╠{sep}╣",
        f"║  Prometheus     : {creds.prometheus_password:<38}║",
        f"╠{sep}╣",
        f"║  Redis          : {creds.redis_password:<38}║",
    ]
    prom_hash = prometheus_basicauth_hash(creds.prometheus_password)
    lines.append(f"╠{sep}╣")
    lines.append(f"║  Prometheus bcrypt hash (set as PROMETHEUS_BASICAUTH_HASH):  ║")
    lines.append(f"║  {prom_hash:<58}║")
    for name, pwd in creds.extras.items():
        lines.append(f"╠{sep}╣")
        lines.append(f"║  {name:<15}: {pwd:<38}║")
    lines.append(f"╚{border}╝")

    output = "\n".join(lines)
    print("\n" + output + "\n", file=sys.stdout, flush=True)


def write_docker_secrets(creds: BootstrapCredentials, secrets_dir: str = "/run/secrets") -> None:
    """
    Write credentials to Docker secret files if the directory is writable.
    Used in local/dev mode — in production secrets are managed by the KSM provider.

    FINDING-LIC-012 (2026-07-20): docker-compose.yml/values.yaml now mount the
    shared secrets directory read-only to backoffice, with individual RW
    shadow-mounts for exactly the filenames this function legitimately
    writes (admin_initial_password, grafana_admin_password, redis_password,
    license_key) — CA/root/intermediate/leaf trust material is never
    writable here. prometheus_password is NOT given an RW shadow-mount
    (nothing in the codebase reads it back — see the class docstring above;
    it is retained only for backward-compatible credential printing). Any
    per-file write can therefore now legitimately hit a read-only
    filesystem in normal operation (not just a misconfiguration) — catch it
    per field so one unwritable field never aborts bootstrap for the
    others (fail-loud via stderr, fail-open for the process as a whole:
    the credential was still generated and printed by print_credentials()).
    """
    mapping = {
        "admin_initial_password": creds.admin_password,
        "grafana_admin_password": creds.grafana_admin_password,
        "prometheus_password": creds.prometheus_password,
        "redis_password": creds.redis_password,
    }
    mapping.update({f"extra_{k}": v for k, v in creds.extras.items()})

    os.makedirs(secrets_dir, exist_ok=True)
    for name, value in mapping.items():
        path = os.path.join(secrets_dir, name)
        if os.path.exists(path):
            continue
        try:
            with open(path, "w") as f:
                f.write(value)
            os.chmod(path, 0o400)
        except OSError as exc:
            print(
                f"write_docker_secrets: could not write {path!r} ({exc}) — "
                "skipping (this mount may be intentionally read-only for "
                "this field; see FINDING-LIC-012)",
                file=sys.stderr,
                flush=True,
            )


def load_or_generate(
    admin_username: str,
    secrets_dir: str = "/run/secrets",
) -> Optional[BootstrapCredentials]:
    """
    Load existing credentials from secrets_dir if present, or generate new ones.
    Returns None if all credentials already exist (no-op path).
    Returns BootstrapCredentials if any new credential was generated.
    """
    admin_pwd_file = os.path.join(secrets_dir, "admin_initial_password")

    # If the admin password secret already exists, bootstrap already ran
    if os.path.exists(admin_pwd_file):
        return None

    creds = generate_credentials(admin_username)
    return creds
