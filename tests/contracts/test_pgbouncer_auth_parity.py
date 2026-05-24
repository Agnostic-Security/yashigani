# Last updated: 2026-05-24T00:00:00+00:00
"""
PgBouncer auth_query compose-Helm parity tests — drift audit finding #8.

Asserts that:
  1. Both compose pgbouncer.ini files (main + letta) use auth_query — not auth_type=plain
     or auth_type=md5 alone.
  2. The main compose pgbouncer.ini does NOT contain an explicit auth_file directive
     (compose-Helm parity: helm/yashigani/files/pgbouncer.ini has no auth_file).
  3. Both Helm pgbouncer ini files (main + letta) use auth_query.
  4. The Helm main pgbouncer.ini does NOT contain an explicit auth_file directive
     (reference baseline; this is the Helm posture compose now aligns to).
  5. auth_user = pgbouncer_authenticator is present in all four ini files
     (SECURITY DEFINER role — YSG-RISK-049 close).
  6. auth_dbname = yashigani is present in all four ini files
     (Amendment C6 — both instances auth via the yashigani database).

YSG-RISK-049: SECURITY DEFINER ysg_pgbouncer_get_auth + pgbouncer_authenticator role.
Drift audit finding #8: compose pgbouncer.ini had auth_file=; Helm did not.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent

# Compose ini paths
COMPOSE_PGBOUNCER_INI = REPO_ROOT / "docker" / "pgbouncer" / "pgbouncer.ini"
COMPOSE_LETTA_INI = REPO_ROOT / "docker" / "pgbouncer" / "pgbouncer-letta.ini"

# Helm ini paths (files/ directory — baked into ConfigMap by the chart)
HELM_PGBOUNCER_INI = REPO_ROOT / "helm" / "yashigani" / "files" / "pgbouncer.ini"
HELM_LETTA_INI = REPO_ROOT / "helm" / "yashigani" / "files" / "pgbouncer-letta.ini"

ALL_INI_FILES = [
    ("compose-main", COMPOSE_PGBOUNCER_INI),
    ("compose-letta", COMPOSE_LETTA_INI),
    ("helm-main", HELM_PGBOUNCER_INI),
    ("helm-letta", HELM_LETTA_INI),
]

# Ini files that MUST NOT have an explicit auth_file directive (drift #8 parity set)
# Helm-main has no auth_file (Iris §5). Compose-main must now match.
# Helm-letta and compose-letta both have auth_file — they are at parity with each other.
NO_EXPLICIT_AUTH_FILE = [
    ("compose-main", COMPOSE_PGBOUNCER_INI),
    ("helm-main", HELM_PGBOUNCER_INI),
]

# Ini files that DO have auth_file (letta pair — both have it; parity maintained)
WITH_AUTH_FILE = [
    ("compose-letta", COMPOSE_LETTA_INI),
    ("helm-letta", HELM_LETTA_INI),
]


def _read_ini(path: Path) -> str:
    assert path.exists(), f"ini file missing: {path}"
    return path.read_text()


def _active_lines(content: str) -> list[str]:
    """Return non-comment, non-empty lines (strips ; and # comments)."""
    lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(";") and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: auth_query present in all four ini files
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("label,path", ALL_INI_FILES)
def test_auth_query_present(label: str, path: Path) -> None:
    """All four pgbouncer ini files must use auth_query (YSG-RISK-049 CLOSED)."""
    content = _read_ini(path)
    active = _active_lines(content)
    auth_query_lines = [l for l in active if re.match(r"^auth_query\s*=", l)]
    assert auth_query_lines, (
        f"{label} ({path.name}): auth_query directive missing. "
        "YSG-RISK-049 SECURITY DEFINER pattern requires auth_query in all pgbouncer ini files."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: No explicit auth_file in compose-main and helm-main (drift #8)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("label,path", NO_EXPLICIT_AUTH_FILE)
def test_no_explicit_auth_file(label: str, path: Path) -> None:
    """compose-main and helm-main must NOT have an explicit auth_file directive.

    Drift audit finding #8: compose pgbouncer.ini had auth_file= while
    helm/yashigani/files/pgbouncer.ini did not. Fix: remove auth_file from
    compose-main, aligning it with Helm. pgbouncer 1.25.1 defaults to
    /etc/pgbouncer/userlist.txt when auth_file is absent from the ini.
    """
    content = _read_ini(path)
    active = _active_lines(content)
    auth_file_lines = [l for l in active if re.match(r"^auth_file\s*=", l)]
    assert not auth_file_lines, (
        f"{label} ({path.name}): explicit auth_file directive found: {auth_file_lines}. "
        "Drift audit finding #8: compose-main and helm-main must not have auth_file. "
        "pgbouncer 1.25.1 defaults to /etc/pgbouncer/userlist.txt."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: letta pair both have auth_file (parity maintained, not regressed)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("label,path", WITH_AUTH_FILE)
def test_letta_auth_file_present(label: str, path: Path) -> None:
    """compose-letta and helm-letta both have auth_file — parity maintained.

    Both letta ini files have auth_file = /etc/pgbouncer/userlist.txt.
    This test guards against accidentally removing it from one without the other.
    """
    content = _read_ini(path)
    active = _active_lines(content)
    auth_file_lines = [l for l in active if re.match(r"^auth_file\s*=", l)]
    assert auth_file_lines, (
        f"{label} ({path.name}): auth_file directive missing. "
        "compose-letta and helm-letta are expected to have auth_file at parity."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: auth_user = pgbouncer_authenticator in all four ini files
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("label,path", ALL_INI_FILES)
def test_auth_user_is_pgbouncer_authenticator(label: str, path: Path) -> None:
    """All four ini files must use auth_user = pgbouncer_authenticator.

    YSG-RISK-049: SECURITY DEFINER role grant is to pgbouncer_authenticator only.
    Any other auth_user would not have EXECUTE on ysg_pgbouncer_get_auth.
    """
    content = _read_ini(path)
    active = _active_lines(content)
    auth_user_lines = [l for l in active if re.match(r"^auth_user\s*=", l)]
    assert auth_user_lines, (
        f"{label} ({path.name}): auth_user directive missing."
    )
    for line in auth_user_lines:
        value = line.split("=", 1)[1].strip()
        assert value == "pgbouncer_authenticator", (
            f"{label} ({path.name}): auth_user = '{value}', expected 'pgbouncer_authenticator'. "
            "YSG-RISK-049 SECURITY DEFINER grant is to pgbouncer_authenticator only."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: auth_dbname = yashigani in all four ini files (Amendment C6)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("label,path", ALL_INI_FILES)
def test_auth_dbname_is_yashigani(label: str, path: Path) -> None:
    """All four ini files must use auth_dbname = yashigani (Amendment C6).

    pg_shadow is a global catalog view. ysg_pgbouncer_get_auth lives in the
    yashigani database. Both pgbouncer instances (main + letta) must point
    auth_dbname at yashigani — NOT letta (prior Iris §6 was wrong, corrected C6).
    """
    content = _read_ini(path)
    active = _active_lines(content)
    dbname_lines = [l for l in active if re.match(r"^auth_dbname\s*=", l)]
    assert dbname_lines, (
        f"{label} ({path.name}): auth_dbname directive missing."
    )
    for line in dbname_lines:
        value = line.split("=", 1)[1].strip()
        assert value == "yashigani", (
            f"{label} ({path.name}): auth_dbname = '{value}', expected 'yashigani'. "
            "Amendment C6: ysg_pgbouncer_get_auth lives in yashigani database."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Test 6: auth_type = scram-sha-256 in all four ini files
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("label,path", ALL_INI_FILES)
def test_auth_type_is_scram(label: str, path: Path) -> None:
    """All four ini files must use auth_type = scram-sha-256.

    Plain and md5 are cleartext-equivalent credential exposure vectors.
    YSG-RISK-049 mandates scram-sha-256 on both instances.
    """
    content = _read_ini(path)
    active = _active_lines(content)
    auth_type_lines = [l for l in active if re.match(r"^auth_type\s*=", l)]
    assert auth_type_lines, (
        f"{label} ({path.name}): auth_type directive missing."
    )
    for line in auth_type_lines:
        value = line.split("=", 1)[1].strip()
        assert value == "scram-sha-256", (
            f"{label} ({path.name}): auth_type = '{value}', expected 'scram-sha-256'. "
            "YSG-RISK-049 mandates scram-sha-256."
        )
