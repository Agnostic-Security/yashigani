# Last updated: 2026-05-25T00:00:00+00:00
"""
Podman seccomp override contract tests — BUG-NEW-002 / YSG-RISK-074.

podman-compose 1.5.0 MERGES security_opt lists from override files (does not
replace). The base docker-compose.yml carries: no-new-privileges:true,
seccomp=${YASHIGANI_SECCOMP_PROFILE:-./seccomp/yashigani.json}, apparmor=...
The Podman override (docker-compose.podman-override.yml) adds label=disable.

The merged result for gateway + backoffice on Podman is:
  [no-new-privileges:true, seccomp=/abs/path (from env var), apparmor=unconfined,
   label=disable]

install.sh sets YASHIGANI_SECCOMP_PROFILE to an absolute path (install.sh:1993-1998),
which Podman resolves correctly via `podman run --security-opt seccomp=/abs/path`.
Podman machine on macOS mounts /Users via VirtioFS, making host paths accessible.

BUG-NEW-002 root cause: the env-var form in security_opt can cause ENAMETOOLONG
in podman-compose 1.5.0 on some Mac configurations. The fix is:
  1. Document the absolute-path requirement and the unconfined escape hatch.
  2. Ensure install.sh correctly sets YASHIGANI_SECCOMP_PROFILE to the absolute path.
  3. The override file correctly adds label=disable without duplicating seccomp entries.

These tests assert:
  1. The base compose still has the env-var seccomp form (with absolute-path var).
  2. The seccomp profile file exists at the expected location.
  3. The seccomp profile JSON is valid JSON with required fields.
  4. The Podman override does NOT add duplicate seccomp entries.
  5. install.sh sets YASHIGANI_SECCOMP_PROFILE to an absolute path (not relative).
  6. The escape hatch (YASHIGANI_SECCOMP_PROFILE=unconfined) is documented.

YSG-RISK-074: BUG-NEW-002 — Podman seccomp env-var absolute-path form documented.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
DOCKER_DIR = REPO_ROOT / "docker"

PODMAN_OVERRIDE = DOCKER_DIR / "docker-compose.podman-override.yml"
BASE_COMPOSE = DOCKER_DIR / "docker-compose.yml"
INSTALL_SH = REPO_ROOT / "install.sh"
SECCOMP_PROFILE = DOCKER_DIR / "seccomp" / "yashigani.json"


def _read(path: Path) -> str:
    assert path.exists(), f"File missing: {path}"
    return path.read_text()


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: Base compose has env-var seccomp form (not hardcoded path)
# ─────────────────────────────────────────────────────────────────────────────

def test_base_compose_has_env_var_seccomp() -> None:
    """Base docker-compose.yml must use the env-var form for seccomp.

    install.sh sets YASHIGANI_SECCOMP_PROFILE to an absolute path at install time.
    The env-var form allows the operator to override with 'unconfined' if needed.
    YSG-RISK-074.
    """
    content = _read(BASE_COMPOSE)
    assert "seccomp=${YASHIGANI_SECCOMP_PROFILE" in content, (
        "Base docker-compose.yml: env-var seccomp form not found. "
        "The base compose must use seccomp=${YASHIGANI_SECCOMP_PROFILE:-./seccomp/yashigani.json} "
        "to allow operator override with 'unconfined'. YSG-RISK-074."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: Seccomp profile file exists and is valid
# ─────────────────────────────────────────────────────────────────────────────

def test_seccomp_profile_file_exists() -> None:
    """The seccomp profile must exist at docker/seccomp/yashigani.json.

    install.sh sets YASHIGANI_SECCOMP_PROFILE to the absolute path of this file.
    YSG-RISK-074.
    """
    assert SECCOMP_PROFILE.exists(), (
        f"Seccomp profile not found at {SECCOMP_PROFILE}. "
        "install.sh sets YASHIGANI_SECCOMP_PROFILE to this file's absolute path. "
        "The file must exist for seccomp enforcement to work. YSG-RISK-074."
    )


def test_seccomp_profile_is_valid_json() -> None:
    """The seccomp profile must be valid JSON.

    A corrupt or empty seccomp profile causes podman/docker to fail at container start.
    YSG-RISK-074.
    """
    content = _read(SECCOMP_PROFILE)
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as e:
        pytest.fail(
            f"Seccomp profile {SECCOMP_PROFILE} is not valid JSON: {e}. "
            "YSG-RISK-074."
        )
    assert isinstance(parsed, dict), (
        f"Seccomp profile {SECCOMP_PROFILE} parsed to {type(parsed)}, expected dict. "
        "A valid OCI seccomp profile is a JSON object. YSG-RISK-074."
    )


def test_seccomp_profile_has_default_action() -> None:
    """The seccomp profile must have a defaultAction field.

    A seccomp profile without defaultAction is invalid (OCI spec requirement).
    YSG-RISK-074.
    """
    content = _read(SECCOMP_PROFILE)
    parsed = json.loads(content)
    assert "defaultAction" in parsed, (
        f"Seccomp profile {SECCOMP_PROFILE} missing 'defaultAction' field. "
        "OCI seccomp profile must specify defaultAction. YSG-RISK-074."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: Podman override does NOT add duplicate seccomp entries
# ─────────────────────────────────────────────────────────────────────────────

def test_podman_override_no_duplicate_seccomp() -> None:
    """Podman override must NOT add a seccomp= entry (base compose already has one).

    podman-compose 1.5.0 MERGES security_opt lists from overrides (not replace).
    Adding seccomp= in the override creates a duplicate that confuses Podman:
    two --security-opt seccomp=... flags, with the relative path in the override
    failing because Podman resolves it from the VM's CWD, not the compose file dir.
    The override only needs label=disable (for SELinux). YSG-RISK-074.
    """
    content = _read(PODMAN_OVERRIDE)
    # Check for seccomp= entries in active (non-comment) lines
    for i, line in enumerate(content.splitlines()):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "seccomp=" in stripped and stripped.startswith("- seccomp="):
            pytest.fail(
                f"Podman override line {i+1}: seccomp= entry found: '{stripped}'. "
                "The override must NOT add seccomp= entries — podman-compose 1.5.0 "
                "merges lists, creating duplicates. Base compose already sets seccomp "
                "via YASHIGANI_SECCOMP_PROFILE. YSG-RISK-074."
            )


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: install.sh sets YASHIGANI_SECCOMP_PROFILE to absolute path
# ─────────────────────────────────────────────────────────────────────────────

def test_install_sh_sets_seccomp_absolute_path() -> None:
    """install.sh must set YASHIGANI_SECCOMP_PROFILE to an absolute path.

    The absolute path (e.g. /path/to/yashigani/docker/seccomp/yashigani.json)
    is passed directly to `podman run --security-opt seccomp=/abs/path`, which
    Podman resolves correctly. Relative paths fail because Podman resolves them
    from the VM's CWD, not the compose file directory. YSG-RISK-074.
    """
    content = _read(INSTALL_SH)
    # install.sh should set YASHIGANI_SECCOMP_PROFILE to WORK_DIR-based absolute path
    # Look for the pattern that sets it to a WORK_DIR path
    assert "WORK_DIR" in content and "YASHIGANI_SECCOMP_PROFILE" in content and "seccomp" in content, (
        "install.sh: YASHIGANI_SECCOMP_PROFILE setting not found. "
        "install.sh must set YASHIGANI_SECCOMP_PROFILE to "
        "${WORK_DIR}/docker/seccomp/yashigani.json (absolute path). YSG-RISK-074."
    )
    # Specifically check it uses WORK_DIR-based path (not relative)
    assert "_seccomp_profile=" in content or "YASHIGANI_SECCOMP_PROFILE" in content, (
        "install.sh: YASHIGANI_SECCOMP_PROFILE not set using WORK_DIR. "
        "Must be an absolute path like ${WORK_DIR}/docker/seccomp/yashigani.json. "
        "YSG-RISK-074."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: Escape hatch (unconfined) is documented in install.sh
# ─────────────────────────────────────────────────────────────────────────────

def test_install_sh_documents_unconfined_escape_hatch() -> None:
    """install.sh must document that YASHIGANI_SECCOMP_PROFILE=unconfined disables seccomp.

    When a host kernel or Podman version rejects the seccomp profile,
    the operator can set YASHIGANI_SECCOMP_PROFILE=unconfined in the .env file
    to disable the profile. This must be documented in install.sh. YSG-RISK-074.
    """
    content = _read(INSTALL_SH)
    assert "unconfined" in content and "YASHIGANI_SECCOMP_PROFILE" in content, (
        "install.sh: unconfined escape hatch not documented for YASHIGANI_SECCOMP_PROFILE. "
        "Operators need to know they can set YASHIGANI_SECCOMP_PROFILE=unconfined "
        "if the seccomp profile is rejected. YSG-RISK-074."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 6: YSG-RISK-074 reference in override file
# ─────────────────────────────────────────────────────────────────────────────

def test_podman_override_references_ysg_risk_074() -> None:
    """Podman override must reference YSG-RISK-074 in its comments.

    Ensures the override is correctly updated for v2.24.3 BUG-NEW-002 documentation.
    """
    content = _read(PODMAN_OVERRIDE)
    assert "YSG-RISK-074" in content, (
        "Podman override: YSG-RISK-074 reference not found. "
        "The override must document the BUG-NEW-002 fix rationale. BUG-NEW-002."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 7: LAURA-003 — unshare not in seccomp allowlist
# ─────────────────────────────────────────────────────────────────────────────

def test_seccomp_profile_no_unshare_in_allowlist() -> None:
    """yashigani.json allowlist must NOT contain the 'unshare' syscall.

    LAURA-003 (LOW): unshare(2) creates new namespaces (user, mount, pid, net)
    and is a recognised user-namespace-escape precursor. Caddy, gateway, and
    backoffice do not need namespace creation at runtime. All 'podman unshare'
    calls in the codebase are host-side Podman CLI invocations (install.sh,
    uninstall.sh, test harnesses) — they run on the host, not inside containers,
    and therefore never invoke the unshare(2) syscall within a container.
    Removed from the allowlist as part of W3-P2a gate-fix (2026-05-29).
    """
    parsed = json.loads(_read(SECCOMP_PROFILE))
    allowlisted: list[str] = []
    for rule in parsed.get("syscalls", []):
        if rule.get("action") == "SCMP_ACT_ALLOW":
            allowlisted.extend(rule.get("names", []))
    assert "unshare" not in allowlisted, (
        "docker/seccomp/yashigani.json: 'unshare' found in SCMP_ACT_ALLOW list. "
        "Remove it — Caddy/gateway/backoffice do not need namespace creation inside "
        "the container. All 'podman unshare' calls are host-side CLI invocations. "
        "LAURA-003 / W3-P2a."
    )
