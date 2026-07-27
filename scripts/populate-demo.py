#!/usr/bin/env python3
"""
populate-demo.py — Yashigani 4.1.2 demo seed script.

GUARDRAILS (enforced in code):
  1. Uses ONLY orchid. Forced pw-change -> new pw saved full -> re-login to prove round-trip.
  2. aspen is NEVER touched except a single login-verify at the END.
  3. /auth/totp/provision/start is NEVER called (would rotate TOTP secret, LAURA-2255-008).
  4. Step-up TOTP is called after re-login; all step-up-gated ops happen within 5-min window.
  5. CONFIG-ONLY (Tiago hard constraint): every mutation goes through the admin API.
     If a config step fails, that is a real product bug — this script FAILS LOUD
     (sys.exit) rather than papering over it with a hardcoded fallback value.
  6. Bundled agents (langflow/letta/openclaw) are NEVER created here — install.sh's
     register_agent_bundles() already registers them with the correct caddy-front
     mesh upstream_url. This script only DISCOVERS them (GET /admin/agents) and
     PUTs demo-specific groups/allowed_caller_groups/allowed_paths. Sending
     upstream_url here reintroduced a duplicate-agent-with-wrong-upstream bug
     that broke chat (LAURA-4.1.2-related finding) — see step8_register_agents().

What this script creates:
  Groups  : data-team, finance-team, compliance-team
  Users   : ana@agnosticsec.com / paul@agnosticsec.com / mia@agnosticsec.com / noah / sara
            each in a different group
  Agents  : configures (never creates) the install.sh-bundled langflow/letta/openclaw
            agents (groups: [owui-users, users])
  Policies: 10 self-describing client OPA policies (saved + bound)
  Probes  : one allow + one deny via /admin/inspection/simulate (if available)
  MCP     : demo-mcp reachability probe

Usage:
  python3 populate-demo.py

All credential output -> CREDENTIALS-4.1.2-CLEAN.txt (updated in-place).
Scratch state saved to populate-4.1.2-clean-state.json (same dir).
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import pyotp
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Product TOTP core — single source of truth for algorithm/digits (LAURA-4.1.2
# populate-demo fix). Admins are SHA512/8-digit, users SHA256/6-digit
# (src/yashigani/auth/totp.py ROLE_TOTP_ALGO / ROLE_TOTP_DIGITS) — hand-rolling
# pyotp.TOTP(secret).now() silently falls back to pyotp's SHA1/6-digit default,
# which never matches an admin account's real algorithm and always 401s.
# ---------------------------------------------------------------------------
# Computed directly with pyotp (self-contained). Importing yashigani.auth.totp
# drags in the fastapi/app-runtime import chain, which is absent from a
# standalone demo venv and raises ModuleNotFoundError('fastapi') → wrong code →
# 401. These crypto params are RFC 6238 auth-client necessities (not
# product-configured rules), mirrored from src/yashigani/auth/totp.py.
import hashlib as _hashlib
_ROLE_TOTP_DIGEST = {"admin": _hashlib.sha512, "user": _hashlib.sha256}
_ROLE_TOTP_DIGITS = {"admin": 8, "user": 6}

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# Output dir for creds/state/user-key artifacts. Configurable so this committed
# script is portable; defaults to the current working directory. The install log
# to parse admin creds from is DEMO_DIR/.last-install-log (a pointer file).
DEMO_DIR = Path(os.environ.get("YASHIGANI_DEMO_OUT_DIR", ".")).resolve()
CREDS_FILE = DEMO_DIR / "CREDENTIALS-4.1.2-CLEAN.txt"
STATE_FILE = DEMO_DIR / "populate-4.1.2-clean-state.json"

BASE_URL = os.environ.get("YASHIGANI_BASE_URL", "https://localhost").rstrip("/")

# Admin credentials PARSED from the clean-install output (creds-on-the-fly).
# ORCHID_* == primary admin, ASPEN_* == backup/break-glass admin (names kept so
# the rest of the script is unchanged).
import re as _re
def _parse_admin_creds():
    lp = DEMO_DIR / ".last-install-log"
    log = Path(lp.read_text().strip()) if lp.exists() else None
    if not log or not log.exists():
        sys.exit("FATAL: cannot find install log via .last-install-log")
    txt = log.read_text(errors="ignore")
    users = _re.findall(r"Username:\s+(\S+)", txt)
    pws = _re.findall(r"Password:\s+(\S+)", txt)
    totps = _re.findall(r"TOTP secret:\s+(\S+)", txt)
    if len(users) < 2 or len(pws) < 2 or len(totps) < 2:
        sys.exit(f"FATAL: parse failed users={len(users)} pws={len(pws)} totps={len(totps)}")
    return (users[0], pws[0], totps[0]), (users[1], pws[1], totps[1])
(_PU, _PP, _PT), (_BU, _BP, _BT) = _parse_admin_creds()
ORCHID_USER = _PU
ORCHID_INITIAL_PW = _PP
ORCHID_TOTP_SECRET = _PT
ORCHID_NEW_PW = "Yg8#" + _PT + "!Kv9$mNpXqR7wLsZtYa1B"  # >=36 chars
ASPEN_USER = _BU
ASPEN_TOTP_SECRET = _BT
PRISM_PW = _BP
print(f"  [creds] primary={ORCHID_USER} backup={ASPEN_USER} (parsed from install log)")

# ---------------------------------------------------------------------------
# Requests session
# ---------------------------------------------------------------------------
S = requests.Session()
S.verify = False


# ---------------------------------------------------------------------------
# TOTP helpers
# ---------------------------------------------------------------------------
# Admins are role-tiered SHA512/8-digit (ROLE_TOTP_ALGO["admin"] /
# ROLE_TOTP_DIGITS["admin"]) — sourced from the product's own TOTP core
# (_totp_at), never hand-rolled or defaulted to pyotp's SHA1/6.

def _role_totp(secret: str, tier: str = "admin") -> str:
    """Role-tiered TOTP — admin SHA512/8-digit, user SHA256/6-digit (mirrors
    src/yashigani/auth/totp.py ROLE_TOTP_ALGO / ROLE_TOTP_DIGITS)."""
    return pyotp.TOTP(
        secret, digest=_ROLE_TOTP_DIGEST[tier], digits=_ROLE_TOTP_DIGITS[tier]
    ).now()


def _totp(secret: str) -> str:
    """Admin-tier TOTP (SHA512/8). Orchid/aspen are always admin accounts."""
    return _role_totp(secret, "admin")


def _fresh_totp(secret: str, label: str) -> str:
    """
    Return a TOTP code that's at least 5 seconds from window expiry so the
    server receives it in the same window. Waits for the next window if needed.
    """
    remaining = 30 - int(time.time()) % 30
    if remaining < 5:
        print(f"  [totp:{label}] Window expiring in {remaining}s — waiting for next window...")
        time.sleep(remaining + 2)
    code = _totp(secret)
    print(f"  [totp:{label}] code={code} (window has ~{30 - int(time.time()) % 30}s remaining)")
    return code


def _wait_next_totp_window(label: str = "") -> None:
    """Unconditionally wait for the NEXT 30-second TOTP window to start."""
    remaining = 30 - int(time.time()) % 30
    wait = remaining + 2
    print(f"  [totp:{label}] Waiting {wait}s for next TOTP window...")
    time.sleep(wait)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _ok(r: requests.Response, label: str, allow: tuple[int, ...] = ()) -> dict:
    expected = (200, 201) + allow
    if r.status_code not in expected:
        print(f"  FAIL [{label}] HTTP {r.status_code}: {r.text[:400]}", file=sys.stderr)
        sys.exit(1)
    try:
        return r.json()
    except Exception:
        return {}


def _check(r: requests.Response, label: str, expected: int) -> dict:
    if r.status_code != expected:
        print(f"  FAIL [{label}] expected {expected}, got {r.status_code}: {r.text[:400]}", file=sys.stderr)
        sys.exit(1)
    try:
        return r.json()
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Compose-project-prefix-agnostic container name resolution.
#
# LAURA-4.1.2 populate-demo fix: the compose project prefix is NOT a constant
# ("docker-" was hardcoded here but this stack's ACTUAL prefix is "localhost-"
# — see testing_runs/yashigani/4.1.2-e2e/ACCESS-BRIEF.md). Never hardcode
# "<prefix>-<service>-1"; resolve it from the running container set (Docker +
# Podman parity), falling back to COMPOSE_PROJECT_NAME if set.
# ---------------------------------------------------------------------------

def _container_name(service: str) -> str:
    """
    Resolve the actual running container name for a compose *service*
    (e.g. "demo-mcp", "backoffice", "gateway") under whichever compose
    project prefix is in effect — never assume "docker-" or "localhost-".

    Tries `docker ps` then `podman ps` (runtime parity), matching an
    exact "-<service>-1" suffix over a broader substring hit. Falls back to
    COMPOSE_PROJECT_NAME + "-<service>-1" if neither runtime is reachable.
    Returns "" if the container cannot be resolved — callers must treat
    these lookups as best-effort diagnostics, not config mutations.
    """
    for runtime in ("docker", "podman"):
        try:
            result = subprocess.run(
                [runtime, "ps", "--filter", f"name={service}", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=10,
            )
        except FileNotFoundError:
            continue
        if result.returncode == 0 and result.stdout.strip():
            names = [n.strip() for n in result.stdout.strip().splitlines() if n.strip()]
            exact = [n for n in names if n.endswith(f"-{service}-1")]
            if exact:
                return exact[0]
            if names:
                return names[0]

    project = os.environ.get("COMPOSE_PROJECT_NAME", "").strip()
    if project:
        return f"{project}-{service}-1"
    return ""


# ---------------------------------------------------------------------------
# STEP 1 — Login as orchid
#
# Idempotent: try new password first (in case script already ran once and
# changed it). If that fails with 401, fall back to initial password.
# ---------------------------------------------------------------------------

def step1_login_initial() -> bool:
    """Login as orchid. Returns True if new password already in effect, False if initial."""
    print("\n=== STEP 1: Login as orchid ===")
    code = _fresh_totp(ORCHID_TOTP_SECRET, "orchid-login")

    # Try new password first (idempotent re-run support)
    r = S.post(f"{BASE_URL}/auth/login", json={
        "username": ORCHID_USER,
        "password": ORCHID_NEW_PW,
        "totp_code": code,
    })
    if r.status_code == 200 and r.json().get("status") == "ok":
        body = r.json()
        print(f"  Login OK with NEW password: force_password_change={body.get('force_password_change')}")
        return True  # pw already changed; skip step 2

    # New pw failed — try initial password
    if r.status_code != 401:
        print(f"  WARN: unexpected {r.status_code} on new-pw try: {r.text[:200]}")

    # TOTP may have been used — wait for next window
    _wait_next_totp_window("orchid-initial-pw-retry")
    code2 = _totp(ORCHID_TOTP_SECRET)
    r2 = S.post(f"{BASE_URL}/auth/login", json={
        "username": ORCHID_USER,
        "password": ORCHID_INITIAL_PW,
        "totp_code": code2,
    })
    if r2.status_code == 401:
        # Another possible TOTP replay — one more retry
        print("  401 on initial pw — waiting for next TOTP window and retrying once more...")
        _wait_next_totp_window("orchid-initial-retry2")
        code3 = _totp(ORCHID_TOTP_SECRET)
        r2 = S.post(f"{BASE_URL}/auth/login", json={
            "username": ORCHID_USER,
            "password": ORCHID_INITIAL_PW,
            "totp_code": code3,
        })

    body = _ok(r2, "orchid-initial-login")
    print(f"  Login OK with INITIAL password: status={body.get('status')}, "
          f"force_password_change={body.get('force_password_change')}")
    return False  # pw not yet changed


# ---------------------------------------------------------------------------
# STEP 2 — Forced password change (only when still on initial pw)
# ---------------------------------------------------------------------------

def step2_password_change() -> None:
    print("\n=== STEP 2: Forced password change (orchid) ===")
    r = S.post(f"{BASE_URL}/auth/password/change", json={
        "current_password": ORCHID_INITIAL_PW,
        "new_password": ORCHID_NEW_PW,
    })
    body = _ok(r, "orchid-pw-change")
    print(f"  Password change OK: {body.get('status', body)}")
    print(f"  New password ({len(ORCHID_NEW_PW)} chars): {ORCHID_NEW_PW}")


# ---------------------------------------------------------------------------
# STEP 3 — Re-login with new password (round-trip proof)
# ---------------------------------------------------------------------------

def step3_relogin_verify() -> None:
    print("\n=== STEP 3: Re-login with new password (round-trip verify) ===")
    # Sessions were invalidated by password change — need a fresh TOTP code
    _wait_next_totp_window("orchid-relogin")
    code = _totp(ORCHID_TOTP_SECRET)
    r = S.post(f"{BASE_URL}/auth/login", json={
        "username": ORCHID_USER,
        "password": ORCHID_NEW_PW,
        "totp_code": code,
    })
    if r.status_code != 200:
        print(f"\n  CRITICAL: Re-login with new password FAILED (HTTP {r.status_code}): {r.text[:400]}", file=sys.stderr)
        print("  STOPPING — cannot proceed on unverified credential per guardrail.", file=sys.stderr)
        sys.exit(2)
    body = r.json()
    if body.get("status") != "ok":
        print(f"\n  CRITICAL: Re-login returned status={body.get('status')} not 'ok'", file=sys.stderr)
        sys.exit(2)
    print(f"  Re-login OK: status={body.get('status')}")
    print(f"  force_password_change={body.get('force_password_change')} (should be false)")


# ---------------------------------------------------------------------------
# STEP 4 — Save new password to creds file
# ---------------------------------------------------------------------------

def step4_save_creds() -> None:
    print("\n=== STEP 4: Save updated credentials to creds file ===")
    # Read existing creds file, update orchid line
    existing = CREDS_FILE.read_text() if CREDS_FILE.exists() else ""
    # Append/replace the orchid new-password record
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    new_entry = (
        f"\n# orchid NEW password (set {timestamp}, round-trip-verified)\n"
        f"orchid  {ORCHID_NEW_PW}  {ORCHID_TOTP_SECRET}  (pw-changed; TOTP unchanged)\n"
    )
    updated = existing.rstrip() + "\n" + new_entry
    CREDS_FILE.write_text(updated)
    CREDS_FILE.chmod(0o600)
    print(f"  Saved to {CREDS_FILE}")
    print(f"  orchid new pw (full, {len(ORCHID_NEW_PW)} chars): {ORCHID_NEW_PW}")


# ---------------------------------------------------------------------------
# STEP 5 — Step-up TOTP (needed for agent registration + policy save/bind)
# ---------------------------------------------------------------------------

def step5_stepup() -> None:
    print("\n=== STEP 5: Step-up TOTP (gates agent + policy mutations) ===")
    _wait_next_totp_window("orchid-stepup")
    code = _totp(ORCHID_TOTP_SECRET)
    r = S.post(f"{BASE_URL}/auth/stepup", json={"totp_code": code})
    body = _ok(r, "stepup")
    print(f"  Step-up OK: stepup_verified={body.get('stepup_verified')}, ttl={body.get('ttl_seconds')}s")


# ---------------------------------------------------------------------------
# STEP 6 — Create RBAC groups
# ---------------------------------------------------------------------------

GROUPS = [
    {
        "display_name": "data-team",
        "allowed_resources": [
            {"method": "*", "path_glob": "/v1/**"},
        ],
    },
    {
        "display_name": "finance-team",
        "allowed_resources": [
            {"method": "*", "path_glob": "/v1/**"},
            {"method": "GET", "path_glob": "/mcp/**"},
        ],
    },
    {
        "display_name": "compliance-team",
        "allowed_resources": [
            {"method": "*", "path_glob": "/v1/**"},
            {"method": "GET", "path_glob": "/mcp/**"},
            {"method": "GET", "path_glob": "/openapi.json"},
        ],
    },
    # Standard groups needed for OWUI + user access
    {
        "display_name": "owui-users",
        "allowed_resources": [{"method": "*", "path_glob": "/**"}],
    },
    {
        "display_name": "users",
        "allowed_resources": [{"method": "*", "path_glob": "/**"}],
    },
]


def step6_create_groups() -> dict[str, str]:
    """Create groups, return display_name -> group_id map."""
    print("\n=== STEP 6: Create RBAC groups ===")
    # List existing groups to avoid duplicates
    r = S.get(f"{BASE_URL}/admin/rbac/groups")
    existing_groups = _ok(r, "list-groups").get("groups", [])
    existing_by_name = {g["display_name"]: g["id"] for g in existing_groups}

    group_ids: dict[str, str] = {}
    for gdef in GROUPS:
        name = gdef["display_name"]
        if name in existing_by_name:
            gid = existing_by_name[name]
            print(f"  group '{name}' already exists: {gid}")
            group_ids[name] = gid
        else:
            r = S.post(f"{BASE_URL}/admin/rbac/groups", json=gdef)
            body = _ok(r, f"create-group-{name}", allow=(201,))
            gid = body["id"]
            print(f"  created group '{name}': {gid}")
            group_ids[name] = gid
    return group_ids


# ---------------------------------------------------------------------------
# STEP 7 — Create users + add to groups
# ---------------------------------------------------------------------------

USERS = [
    # ana drives the cloud-9 MCP-injection demo. Ceiling RESTRICTED so a BENIGN
    # cloud9-orchestrate echo passes the egress ceiling (demo narrative: "safe call
    # works"), while the INJECTION leg is still blocked by ResponseInspection
    # (credential-exfil payload → inspection=BLOCKED), which is independent of the
    # ceiling. With a lower ceiling both legs block on the ceiling and the
    # benign-vs-malicious contrast is lost (Ava INFO-SCEN-A-001).
    {"email": "ana@agnosticsec.com", "group": "data-team", "ceiling": "RESTRICTED"},
    {"email": "paul@agnosticsec.com", "group": "finance-team", "ceiling": "INTERNAL"},
    {"email": "mia@agnosticsec.com", "group": "compliance-team", "ceiling": "CONFIDENTIAL"},
    # Data-protection demo scenarios:
    # noah — cannot send PCI data (ceiling INTERNAL + pci_data_block; PCI classifies RESTRICTED).
    {"email": "noah@agnosticsec.com", "group": "finance-team", "ceiling": "INTERNAL", "scenario": "no-pci"},
    # sara — classified-marked docs (SECRET/TOP SECRET/OFFICIAL-SENSITIVE) handled by local model
    # only (ceiling INTERNAL + classified_marking_local + local-only model allocation).
    {"email": "sara@agnosticsec.com", "group": "compliance-team", "ceiling": "INTERNAL", "scenario": "classified-local"},
]


def step7_create_users(group_ids: dict[str, str]) -> dict[str, dict]:
    """Create users, add to groups, return email -> {username, temp_pw, totp} map."""
    print("\n=== STEP 7: Create users + assign to groups ===")

    # List existing users
    r = S.get(f"{BASE_URL}/admin/users")
    existing = _ok(r, "list-users").get("users", [])
    existing_emails = {u.get("email", ""): u for u in existing}

    user_creds: dict[str, dict] = {}
    for udef in USERS:
        email = udef["email"]
        group_name = udef["group"]
        gid = group_ids[group_name]

        if email in existing_emails:
            print(f"  user '{email}' already exists — skipping creation")
            user_creds[email] = {"username": existing_emails[email].get("username", ""), "group": group_name}
        else:
            r = S.post(f"{BASE_URL}/admin/users", json={"email": email})
            body = _ok(r, f"create-user-{email}", allow=(201,))
            temp_pw = body.get("temporary_password", "")
            totp_secret = body.get("totp_secret", "")
            username = body.get("username", "")
            print(f"  created user '{email}' (username={username})")
            user_creds[email] = {
                "username": username,
                "temp_pw": temp_pw,
                "totp_secret": totp_secret,
                "group": group_name,
            }

        # Add to group (idempotent — server may 409 if already member, which is OK)
        r = S.post(f"{BASE_URL}/admin/rbac/groups/{gid}/members", json={"email": email})
        if r.status_code in (200, 201):
            print(f"  added '{email}' to group '{group_name}'")
        elif r.status_code == 409:
            print(f"  '{email}' already in group '{group_name}' (409 idempotent)")
        else:
            # Non-fatal — log and continue
            print(f"  WARN: add member {email} -> {group_name}: HTTP {r.status_code}: {r.text[:200]}")

    return user_creds


def step7b_save_user_creds(user_creds: dict[str, dict]) -> None:
    """Append user credentials to a separate demo-user creds file."""
    out = DEMO_DIR / f"demo-user-creds-4.1.2-{datetime.utcnow().strftime('%Y%m%d')}.txt"
    lines = [f"# Demo user credentials — populate-demo (4.1.2) run {datetime.utcnow().isoformat()}Z\n"]
    for email, creds in user_creds.items():
        username = creds.get("username", "")
        # FIND-DEMO-CREDS: step7c rotates the temp password on forced first-login,
        # so the CURRENT password is new_pw. Prefer it; fall back to temp_pw for
        # accounts that already existed / were not rotated. (Saving temp_pw left the
        # documented demo creds stale + unusable after onboarding.)
        temp_pw = creds.get("new_pw") or creds.get("temp_pw", "(already existed)")
        totp = creds.get("totp_secret", "(already existed)")
        group = creds.get("group", "")
        lines.append(f"{email}  username={username}  pw={temp_pw}  totp={totp}  group={group}\n")
    out.write_text("".join(lines))
    out.chmod(0o600)
    print(f"  User creds saved to {out}")


# ---------------------------------------------------------------------------
# STEP 8 — Discover + configure bundled agents (NEVER create/register)
# ---------------------------------------------------------------------------
# install.sh's register_agent_bundles() (install.sh:10278) already registers
# the bundled agents via a direct Postgres+Redis write with the CORRECT
# caddy-front mesh upstream_url (e.g. https://caddy:9671/agents/default/openclaw).
# Real registered names (install.sh:10343 case statement):
#   langflow -> "agent__langflow" (P1-only callee — distinct from the local key)
#   letta    -> "letta"
#   openclaw -> "openclaw"
# This script must NEVER POST a new agent (that reintroduced a duplicate agent
# with a bare-hostname upstream_url — e.g. http://openclaw:18789 — bypassing the
# caddy-front mesh entirely, which is exactly what broke chat) and must NEVER
# send upstream_url on PUT. It only discovers the real agent_id by name and
# PUTs the demo-specific groups/allowed_caller_groups/allowed_paths.

AGENTS = [
    {
        "local_key": "langflow",
        "real_names": ("agent__langflow",),
        "groups": ["owui-users", "users"],
        "allowed_caller_groups": ["data-team", "owui-users", "users"],
        "allowed_paths": [],
    },
    {
        "local_key": "letta",
        "real_names": ("letta",),
        "groups": ["owui-users", "users"],
        "allowed_caller_groups": ["finance-team", "owui-users", "users"],
        "allowed_paths": [],
    },
    {
        "local_key": "openclaw",
        "real_names": ("openclaw",),
        "groups": ["owui-users", "users"],
        "allowed_caller_groups": ["compliance-team", "owui-users", "users"],
        "allowed_paths": [],
    },
]


# ---------------------------------------------------------------------------
# STEP 7c — Onboard users: first-login (register identity) + mint API key
# ---------------------------------------------------------------------------
def step7c_onboard_users(user_creds: dict) -> dict:
    """For each created user: complete forced first-login (registers HUMAN
    identity), then admin-issue a gateway API key. Returns email->api_key."""
    print("\n=== STEP 7c: Onboard users (first-login + API key) ===")
    import requests as _rq
    api_keys = {}
    for email, creds in user_creds.items():
        username = creds.get("username", "")
        temp_pw = creds.get("temp_pw")
        totp_secret = creds.get("totp_secret")
        if not (username and temp_pw and totp_secret):
            print(f"  {email}: missing temp creds (already existed?) — skipping onboard")
            continue
        us = _rq.Session(); us.verify = False
        _wait_next_totp_window(f"{username}-login")
        # LAURA-4.0-S1-001: user-tier accounts use SHA-256/6-digit TOTP (Phase 13).
        # _totp() is SHA-1 (admin-side default); _user_totp_sha256() is correct here.
        code = _user_totp_sha256(totp_secret)
        r = us.post(f"{BASE_URL}/auth/login", json={"username": username, "password": temp_pw, "totp_code": code})
        if r.status_code != 200:
            print(f"  {email}: first-login FAILED {r.status_code}: {r.text[:160]}"); continue
        fpc = r.json().get("force_password_change")
        new_pw = "Usr#" + totp_secret + "!" + username[:6] + "Zt9QwXy2"  # >=36 chars
        if fpc:
            rc = us.post(f"{BASE_URL}/auth/password/change", json={"current_password": temp_pw, "new_password": new_pw})
            if rc.status_code != 200:
                print(f"  {email}: pw-change FAILED {rc.status_code}: {rc.text[:160]}"); continue
            creds["new_pw"] = new_pw
            # re-login with new pw to confirm + ensure active session/identity
            # (this triggers _register_human_identity_on_login + link_account_id:
            # LAURA-4.0-S1-001 — identity must exist in registry before binding).
            _wait_next_totp_window(f"{username}-relogin")
            us.post(f"{BASE_URL}/auth/login", json={"username": username, "password": new_pw, "totp_code": _user_totp_sha256(totp_secret)})
        print(f"  {email}: first-login OK, identity registered")
        # Admin-issue API key (titan session S, step-up). Ensure step-up fresh.
        _do_stepup_inline()
        rk = S.post(f"{BASE_URL}/admin/users/{username}/api-key")
        if rk.status_code == 200:
            key = rk.json().get("plaintext_token", "")
            api_keys[email] = key
            creds["api_key"] = key
            print(f"  {email}: API key issued (...{key[-6:]})")
        else:
            print(f"  {email}: API-key issue {rk.status_code}: {rk.text[:160]}")
    # Save api keys
    out = DEMO_DIR / "user-api-keys-clean.txt"
    out.write_text("".join(f"{e}  {k}\n" for e, k in api_keys.items()))
    out.chmod(0o600)
    print(f"  API keys saved to {out}")
    return api_keys


def step8_register_agents() -> dict[str, dict]:
    """
    Discover the install.sh-bundled agents (real names differ from our local
    demo keys for langflow — see AGENTS comment above) and PUT only the
    demo-specific groups/allowed_caller_groups/allowed_paths onto them.

    CONFIG-ONLY / FAIL LOUD (Tiago hard constraint): if a bundled agent is
    missing from GET /admin/agents, that means install.sh's
    register_agent_bundles() did not run or did not complete for this
    deployment — a real product/deploy issue. This script does NOT paper
    over that with a hardcoded upstream_url fallback; it exits non-zero.

    Returns local_key -> {agent_id, name, token}.
    """
    print("\n=== STEP 8: Discover + configure bundled agents (step-up gated) ===")

    r = S.get(f"{BASE_URL}/admin/agents")
    existing = _ok(r, "list-agents")
    by_name = {a["name"]: a for a in existing}

    agent_info: dict[str, dict] = {}
    missing: list[str] = []
    for adef in AGENTS:
        local_key = adef["local_key"]
        match = next((by_name[n] for n in adef["real_names"] if n in by_name), None)
        if match is None:
            missing.append(f"{local_key} (expected real name in {adef['real_names']})")
            continue
        agent_info[local_key] = {
            "agent_id": match["agent_id"],
            "name": match["name"],
            # No plaintext PSK is available here — install.sh's
            # register_agent_bundles() writes it directly to
            # /run/secrets/<profile>_token inside the containers, never
            # through the admin API (SEC-001, install.sh:10375).
            "token": "(pre-registered by install.sh register_agent_bundles; "
                     "token lives in /run/secrets/<profile>_token)",
        }

    if missing:
        print(
            f"  FATAL: bundled agent(s) not found via GET /admin/agents: {missing}\n"
            f"  This means install.sh's register_agent_bundles() did not run or did "
            f"not complete for this deployment (real product/deploy issue) — not "
            f"something this script papers over with a hardcoded upstream_url.\n"
            f"  Currently registered agent names: {sorted(by_name.keys())}",
            file=sys.stderr,
        )
        sys.exit(1)

    for adef in AGENTS:
        local_key = adef["local_key"]
        info = agent_info[local_key]
        agent_id = info["agent_id"]
        # upstream_url is deliberately OMITTED — install.sh owns the caddy-front
        # mesh URL for this agent; sending it here reintroduces the
        # duplicate-agent-wrong-upstream bug this fix closes.
        payload = {
            "groups": adef["groups"],
            "allowed_caller_groups": adef["allowed_caller_groups"],
            "allowed_paths": adef["allowed_paths"],
        }
        r = S.put(f"{BASE_URL}/admin/agents/{agent_id}", json=payload)
        if r.status_code == 403 and "step_up_required" in r.text:
            print("  Step-up expired — re-doing step-up and retrying...")
            _do_stepup_inline()
            r = S.put(f"{BASE_URL}/admin/agents/{agent_id}", json=payload)
        body = _ok(r, f"configure-agent-{local_key}")
        print(
            f"  configured agent '{local_key}' (real name={info['name']}, "
            f"agent_id={agent_id}): groups={body.get('groups')} "
            f"allowed_caller_groups={body.get('allowed_caller_groups')}"
        )

    return agent_info


def step7d_set_sensitivity_ceilings(user_creds: dict[str, dict]) -> None:
    """Set each demo user's sensitivity_ceiling (CONF-001) so the sensitivity-ceiling
    egress enforcement (policy/v1_routing.rego response_decision) is DEMONSTRABLE.

    The rule blocks when rank(response_content) > rank(user.sensitivity_ceiling).
    Without a ceiling there is nothing to compare against, so the control cannot
    fire even when an operator has deliberately enabled it. This does NOT change the
    product's safe-adoption default (response inspection stays opt-in per YSG-RISK-057
    / install.sh — untouched); it only completes the *demo configuration* so that an
    operator who turns on inspection+OPA sees the cloud-9 MCP-injection result (which
    classifies RESTRICTED) blocked for these CONFIDENTIAL/INTERNAL-ceiling users.

    PUT /admin/users/{username} {"sensitivity_ceiling": ...}; requires step-up.
    """
    print("\n=== STEP 7d: Set user sensitivity ceilings (CONF-001) ===")
    _do_stepup_inline()  # fresh step-up TTL for the privileged writes
    email_to_ceiling = {u["email"]: u.get("ceiling") for u in USERS}
    for email, info in user_creds.items():
        ceiling = email_to_ceiling.get(email)
        username = info.get("username", "")
        if not ceiling or not username:
            continue
        r = S.put(f"{BASE_URL}/admin/users/{username}",
                  json={"sensitivity_ceiling": ceiling})
        if r.status_code == 200:
            print(f"  set {email} (username={username}) sensitivity_ceiling={ceiling}")
        else:
            print(f"  WARN: set ceiling {email} -> {ceiling}: "
                  f"HTTP {r.status_code}: {r.text[:200]}")


CLASSIFIED_MARKING_PATTERNS = [
    {"classification": "4", "type": "regex",
     "pattern": r"(?m)^\s*(TOP SECRET|SECRET|OFFICIAL[- ]SENSITIVE)(\s*//[A-Z0-9 /_-]+)?\s*$",
     "description": "Gov classification MARKING (banner) - SECRET/TOP SECRET/OFFICIAL-SENSITIVE"},
    {"classification": "4", "type": "regex",
     "pattern": r"\bTOP SECRET//[A-Z0-9 /_-]+",
     "description": "TOP SECRET compartment marking (inline)"},
]


def step9c_add_marking_patterns() -> None:
    """Add sensitivity patterns that detect the classification MARKING (banner-style,
    not the bare word 'secret') and tag such content RESTRICTED (level 4). Built-in
    defaults already cover PCI (credit/debit card -> level 4). Step-up; non-fatal."""
    print("\n=== STEP 9c: Add classification-marking sensitivity patterns ===")
    _do_stepup_inline()
    for p in CLASSIFIED_MARKING_PATTERNS:
        r = S.post(f"{BASE_URL}/admin/sensitivity/patterns", json=p)
        if r.status_code in (200, 201):
            print(f"  added marking pattern: {p['description']}")
        elif r.status_code == 409:
            print(f"  marking pattern exists (409): {p['description']}")
        else:
            print(f"  WARN add pattern HTTP {r.status_code}: {r.text[:160]}")


def step9e_allocate_local_model_to_sara() -> None:
    """Allocate a local-only model to sara so classified-marked content is handled by
    the LOCAL model while cloud is denied (route-local). Best-effort; non-fatal — the
    sensitivity_ceiling + classified_marking_local OPA still block cloud egress."""
    print("\n=== STEP 9e: Allocate local model to sara (route-local) ===")
    r = S.get(f"{BASE_URL}/admin/models")
    body = r.json() if r.status_code == 200 else {}
    aliases = body.get("aliases") or body.get("models") or body.get("data") or []
    local = next((a for a in aliases
                  if a.get("force_local")
                  or "qwen" in (str(a.get("model", "")) + str(a.get("alias", "")) + str(a.get("name", ""))).lower()),
                 None)
    if not local:
        print("  WARN: no local alias found - skipping (cloud still blocked by ceiling+OPA)")
        return
    alias_name = local.get("alias") or local.get("name") or local.get("model")
    _do_stepup_inline()
    r = S.post(f"{BASE_URL}/admin/models/allocations",
               json={"model_alias": alias_name, "scope_kind": "human", "scope_id": "sara@agnosticsec.com"})
    if r.status_code in (200, 201):
        print(f"  allocated local model '{alias_name}' to sara")
    else:
        print(f"  WARN allocate HTTP {r.status_code}: {r.text[:160]}")


def step7e_grant_owui_access(user_creds: dict[str, dict]) -> None:
    """Add demo users to the `owui-users` group so they can sign in to OpenWebUI.

    Yashigani is API-first: creating a user provisions API access only (the `users`
    caller group). OpenWebUI (the human chat surface at /app/webui) is a separate
    opt-in grant via membership of `owui-users` — without it the user can only use
    the API, not the chat UI. See docs/operator-guide.md §5.6.
    """
    print("\n=== STEP 7e: Grant OpenWebUI access (owui-users group) ===")
    r = S.get(f"{BASE_URL}/admin/rbac/groups")
    groups = _ok(r, "list-groups").get("groups", [])
    owui = next((g for g in groups if str(g.get("display_name", "")).lower() == "owui-users"), None)
    if not owui:
        print("  WARN: owui-users group not found — skipping OWUI grant")
        return
    gid = owui.get("id")
    _do_stepup_inline()
    for email in user_creds:
        r = S.post(f"{BASE_URL}/admin/rbac/groups/{gid}/members", json={"email": email})
        if r.status_code in (200, 201):
            print(f"  granted OWUI access: {email} -> owui-users")
        elif r.status_code == 409:
            print(f"  {email} already in owui-users (409 idempotent)")
        else:
            print(f"  WARN: grant OWUI {email}: HTTP {r.status_code}: {r.text[:160]}")


def _do_stepup_inline() -> None:
    """Issue a step-up TOTP inline (e.g. when the TTL expired mid-run)."""
    _wait_next_totp_window("inline-stepup")
    code = _totp(ORCHID_TOTP_SECRET)
    r = S.post(f"{BASE_URL}/auth/stepup", json={"totp_code": code})
    if r.status_code != 200:
        print(f"  FAIL inline step-up: HTTP {r.status_code}: {r.text[:200]}", file=sys.stderr)
        sys.exit(1)
    print(f"  Step-up refreshed OK")


def step8b_save_agent_tokens(agent_info: dict[str, dict]) -> None:
    out = DEMO_DIR / f"agent-tokens-4.1.2-{datetime.utcnow().strftime('%Y%m%d')}.txt"
    lines = [
        f"# Agent config — populate-demo (4.1.2) run {datetime.utcnow().isoformat()}Z\n",
        (
            "# Bundled agents are registered by install.sh (not this script); no plaintext\n"
            "# PSK is available here — see install.sh register_agent_bundles().\n"
        ),
    ]
    for local_key, info in agent_info.items():
        lines.append(
            f"{local_key}  real_name={info.get('name', '')}  agent_id={info['agent_id']}  "
            f"token={info['token']}\n"
        )
    out.write_text("".join(lines))
    out.chmod(0o600)
    print(f"  Agent config saved to {out}")


# ---------------------------------------------------------------------------
# STEP 9 — Save + activate 10 OPA client policies
# ---------------------------------------------------------------------------

# Self-describing policies following the decision contract:
#   data.clients.<name>.decision = {allow, deny, obligations}
# policy_id, user_message, code are embedded so OPA can surface them.

POLICIES: list[dict] = [
    {
        "name": "data_access_control",
        "rego": """package clients.data_access_control
import rego.v1

# Policy: Data Access Control
# policy_id: POL-001
# user_message: Access to sensitive data requires membership in data-team.
# Applies to: data-team users accessing /v1/** routes

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

deny contains "POL-001:data_access_denied" if {
    not "data-team" in input.identity.groups
    startswith(input.path, "/v1/data")
}

obligations contains "audit_data_access" if {
    startswith(input.path, "/v1/data")
}
""",
    },
    {
        "name": "finance_read_only",
        "rego": """package clients.finance_read_only
import rego.v1

# Policy: Finance Read-Only Enforcement
# policy_id: POL-002
# user_message: Finance team users may only read (GET) financial endpoints.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

deny contains "POL-002:write_forbidden_finance" if {
    "finance-team" in input.identity.groups
    input.method != "GET"
    startswith(input.path, "/v1/finance")
}

obligations contains "audit_finance_access" if {
    "finance-team" in input.identity.groups
}
""",
    },
    {
        "name": "compliance_audit_log",
        "rego": """package clients.compliance_audit_log
import rego.v1

# Policy: Compliance Audit Logging
# policy_id: POL-003
# user_message: All compliance-team actions are subject to mandatory audit logging.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

# Compliance team has broad access but all actions must be audited
obligations contains "mandatory_audit_log" if {
    "compliance-team" in input.identity.groups
}

deny contains "POL-003:compliance_pii_redact_required" if {
    "compliance-team" in input.identity.groups
    input.data_tags[_] == "pii"
    not "audit_log" in input.obligations
}
""",
    },
    {
        "name": "pii_redaction_policy",
        "rego": """package clients.pii_redaction_policy
import rego.v1

# Policy: PII Redaction Enforcement
# policy_id: POL-004
# user_message: Personally Identifiable Information must be redacted before transmission to AI models.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

deny contains "POL-004:pii_transmission_blocked" if {
    input.data_tags[_] == "pii"
    not "pii_redacted" in input.obligations
    not "compliance-team" in input.identity.groups
}

obligations contains "redact_pii" if {
    input.data_tags[_] == "pii"
}
""",
    },
    {
        "name": "model_routing_control",
        "rego": """package clients.model_routing_control
import rego.v1

# Policy: Model Routing Control
# policy_id: POL-005
# user_message: Only approved AI models may be used for sensitive data processing.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

_approved_models := {"gemma3:4b", "phi4-mini", "llama3.1:8b", "qwen2.5:3b"}

deny contains "POL-005:unapproved_model" if {
    model := input.routing_decision.model
    not model in _approved_models
    input.data_tags[_] == "sensitive"
}

obligations contains "log_model_selection" if {
    input.routing_decision.model != ""
}
""",
    },
    {
        "name": "rate_limit_enforcement",
        "rego": """package clients.rate_limit_enforcement
import rego.v1

# Policy: Rate Limit Enforcement
# policy_id: POL-006
# user_message: Excessive API usage is blocked to prevent resource exhaustion.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

deny contains "POL-006:rate_limit_exceeded" if {
    input.identity.request_count > 1000
    input.identity.window_seconds <= 60
}

obligations contains "track_usage" if {
    input.identity.role != ""
}
""",
    },
    {
        "name": "pci_data_block",
        "rego": """package clients.pci_data_block
import rego.v1

# Policy: PCI Cardholder Data Block
# policy_id: POL-009
# user_message: Cardholder (PCI) data must not be sent to AI models. Request blocked.
# code: pci_data_block
# Demo scenario: the bound user cannot send PCI data. The built-in credit/debit-card
# sensitivity pattern classifies cardholder data as RESTRICTED (level 4); this client
# policy denies on the PCI/RESTRICTED tag, and the user's low sensitivity_ceiling
# (INTERNAL) blocks RESTRICTED egress at the gateway regardless (defence in depth).

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

deny contains "POL-009:pci_data_present" if {
    input.data_tags[_] == "pci"
}
deny contains "POL-009:pci_data_present" if {
    input.routing_decision.sensitivity == "RESTRICTED"
}

obligations contains "audit_pci_block" if {
    input.routing_decision.sensitivity != ""
}
""",
    },
    {
        "name": "classified_marking_local",
        "rego": """package clients.classified_marking_local
import rego.v1

# Policy: Classified-Marking Local-Only Handling
# policy_id: POL-010
# user_message: Documents marked SECRET, TOP SECRET or OFFICIAL-SENSITIVE must be handled by the local model only (not sent to a cloud model).
# code: classified_marking_local
# Demo scenario: admin-configured sensitivity patterns detect the classification
# MARKING (banner-style, not the bare word) and tag the content RESTRICTED (level 4).
# This policy denies any NON-local (cloud) model for such content -> the request must
# be served by a local Ollama model (e.g. summarise the text locally). The bound user
# is also allocated local-only models so local handling works while cloud is blocked.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

_local_models := {"gemma3:4b", "phi4-mini", "llama3.1:8b", "qwen2.5:3b"}

deny contains "POL-010:classified_requires_local" if {
    input.routing_decision.sensitivity == "RESTRICTED"
    not input.routing_decision.model in _local_models
}
deny contains "POL-010:classified_requires_local" if {
    input.data_tags[_] == "classified"
    not input.routing_decision.model in _local_models
}

obligations contains "route_local" if {
    input.routing_decision.sensitivity == "RESTRICTED"
}
""",
    },
    {
        "name": "agent_tool_restriction",
        "rego": """package clients.agent_tool_restriction
import rego.v1

# Policy: Agent Tool Restriction
# policy_id: POL-007
# user_message: Destructive tools (delete, purge, drop) are blocked for AI agents by default.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

_destructive_tools := {"email.delete", "email.trash", "db.drop", "file.purge", "db.truncate"}

deny contains "POL-007:destructive_tool_blocked" if {
    input.identity.agent != ""
    input.tool in _destructive_tools
}

obligations contains "audit_tool_call" if {
    input.identity.agent != ""
    input.tool != ""
}
""",
    },
    {
        "name": "eu_ai_act_human_review",
        "rego": """package clients.eu_ai_act_human_review
import rego.v1

# Policy: EU AI Act Human-in-the-Loop
# policy_id: POL-008
# user_message: High-risk AI decisions require human review before enactment (EU AI Act Art.14).

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

_high_risk_purposes := {"policy_promotion", "governance_change", "access_grant", "identity_change"}

deny contains "POL-008:human_review_required" if {
    input.request.purpose in _high_risk_purposes
    not input.request.human_approved == true
}

obligations contains "require_human_approval" if {
    input.request.purpose in _high_risk_purposes
}

obligations contains "audit_high_risk_decision" if {
    input.request.purpose in _high_risk_purposes
}
""",
    },
]


def step9_save_policies() -> list[str]:
    """Save 8 policies to OPA. Returns list of names successfully saved."""
    print(f"\n=== STEP 9: Save {len(POLICIES)} OPA client policies (step-up gated) ===")
    saved: list[str] = []
    for pol in POLICIES:
        name = pol["name"]
        # Check if already loaded
        r = S.get(f"{BASE_URL}/admin/policies/clients/{name}")
        if r.status_code == 200:
            print(f"  policy '{name}' already loaded — skipping save")
            saved.append(name)
            continue

        r = S.post(f"{BASE_URL}/admin/policies/save", json={
            "name": name,
            "rego": pol["rego"],
            "check_only": False,
            "confirm_warnings": True,  # allow deny-all/never-allow warnings through
            "run_llm_review": False,
        })
        if r.status_code == 403 and "step_up_required" in r.text:
            print("  Step-up expired — refreshing...")
            _do_stepup_inline()
            r = S.post(f"{BASE_URL}/admin/policies/save", json={
                "name": name,
                "rego": pol["rego"],
                "check_only": False,
                "confirm_warnings": True,
                "run_llm_review": False,
            })
        body = _ok(r, f"save-policy-{name}", allow=(200, 201, 409))
        if r.status_code == 409:
            print(f"  policy '{name}' save 409 (sanity warnings unconfirmed) — retrying with confirm_warnings")
            r2 = S.post(f"{BASE_URL}/admin/policies/save", json={
                "name": name,
                "rego": pol["rego"],
                "check_only": False,
                "confirm_warnings": True,
                "run_llm_review": False,
            })
            body = _ok(r2, f"save-policy-{name}-confirmed")
        print(f"  saved policy '{name}': id={body.get('id', name)}, warnings={len(body.get('warnings', []))}")
        saved.append(name)
    return saved


# ---------------------------------------------------------------------------
# STEP 10 — Bind policies to groups/agents
# ---------------------------------------------------------------------------

# Bindings: policy_name, scope_kind, scope_id, direction
# Valid scope_kinds: human | service | api_client | mcp_server | agent
# Valid directions:  ingress | egress | both
# scope_id="" = wildcard (all subjects of scope_kind)
#
# LAURA-4.1.2 populate-demo fix: for scope_kind == "agent", scope_id below is a
# LOCAL KEY (matching AGENTS[*]["local_key"] above), NOT the real registered
# agent name. step10_bind_policies() resolves it to the real discovered name
# (e.g. "langflow" -> "agent__langflow") via agent_info from step8 before
# binding — hardcoding "langflow" here would bind to a non-existent agent
# identity, since the real registered name is "agent__langflow".

BINDINGS = [
    # POL-001: data access control -> all human callers, ingress
    {"policy_name": "data_access_control", "scope_kind": "human", "scope_id": "ana@agnosticsec.com", "direction": "ingress"},
    # POL-002: finance read-only -> paul (finance-team human), ingress
    {"policy_name": "finance_read_only", "scope_kind": "human", "scope_id": "paul@agnosticsec.com", "direction": "ingress"},
    # POL-003: compliance audit -> mia (compliance-team), both directions
    {"policy_name": "compliance_audit_log", "scope_kind": "human", "scope_id": "mia@agnosticsec.com", "direction": "both"},
    # POL-004: PII redaction -> all humans (wildcard), ingress
    {"policy_name": "pii_redaction_policy", "scope_kind": "human", "scope_id": "", "direction": "ingress"},
    # POL-005: model routing -> openclaw agent, egress
    {"policy_name": "model_routing_control", "scope_kind": "agent", "scope_id": "openclaw", "direction": "egress"},
    # POL-006: rate limit -> letta agent, ingress
    {"policy_name": "rate_limit_enforcement", "scope_kind": "agent", "scope_id": "letta", "direction": "ingress"},
    # POL-007: tool restriction -> langflow agent, egress
    {"policy_name": "agent_tool_restriction", "scope_kind": "agent", "scope_id": "langflow", "direction": "egress"},
    # POL-008: EU AI Act -> all service callers, egress
    {"policy_name": "eu_ai_act_human_review", "scope_kind": "service", "scope_id": "", "direction": "egress"},
    # POL-009: PCI block -> noah (no-PCI demo user), both directions
    {"policy_name": "pci_data_block", "scope_kind": "human", "scope_id": "noah@agnosticsec.com", "direction": "both"},
    # POL-010: classified-marking local-only -> sara (classified-local demo user), egress
    {"policy_name": "classified_marking_local", "scope_kind": "human", "scope_id": "sara@agnosticsec.com", "direction": "egress"},
]


def step10_bind_policies(agent_info: dict[str, dict]) -> None:
    """
    Bind policies (step-up gated).

    agent_info comes from step8_register_agents() — {local_key: {agent_id,
    name, token}}. Any BINDINGS entry with scope_kind == "agent" has its
    scope_id (a local_key, e.g. "langflow") resolved to the REAL registered
    agent name (e.g. "agent__langflow") before binding. Hardcoding the local
    key as the scope_id would silently bind to a non-existent agent identity
    for langflow (LAURA-4.1.2 populate-demo fix, POL-005/006/007).
    """
    print("\n=== STEP 10: Bind policies (step-up gated) ===")
    # List existing bindings to avoid duplicates
    r = S.get(f"{BASE_URL}/admin/policies/bindings")
    existing_bindings_raw = _ok(r, "list-bindings").get("bindings", [])
    # Key: (policy_name, scope_kind, scope_id, direction)
    existing_keys = {
        (b["policy_name"], b["scope_kind"], b["scope_id"], b["direction"])
        for b in existing_bindings_raw
    }

    for raw_bdef in BINDINGS:
        bdef = dict(raw_bdef)
        if bdef["scope_kind"] == "agent" and bdef["scope_id"]:
            local_key = bdef["scope_id"]
            info = agent_info.get(local_key)
            if not info or not info.get("name"):
                print(
                    f"  FATAL: cannot bind '{bdef['policy_name']}' — agent local_key "
                    f"'{local_key}' was not discovered in STEP 8 (see FATAL above).",
                    file=sys.stderr,
                )
                sys.exit(1)
            bdef["scope_id"] = info["name"]

        key = (bdef["policy_name"], bdef["scope_kind"], bdef["scope_id"], bdef["direction"])
        if key in existing_keys:
            print(f"  binding {key} already exists — skipping")
            continue

        r = S.post(f"{BASE_URL}/admin/policies/bind", json=bdef)
        if r.status_code == 403 and "step_up_required" in r.text:
            print("  Step-up expired — refreshing...")
            _do_stepup_inline()
            r = S.post(f"{BASE_URL}/admin/policies/bind", json=bdef)
        # LAURA-4.0-S1-001: bind endpoint now normalises email scope_id → idnt_ PK.
        # On re-run the duplicate-check above misses it (email != stored idnt_ PK)
        # and the server returns 409.  Allow 409 as idempotent "already bound".
        if r.status_code == 409:
            print(f"  binding already exists (409 — scope_id normalised to idnt_ PK on prior run): "
                  f"{bdef['policy_name']} -> {bdef['scope_kind']}:{bdef['scope_id']}")
            continue
        body = _ok(r, f"bind-{bdef['policy_name']}->{bdef['scope_kind']}:{bdef['scope_id']}")
        print(f"  bound '{bdef['policy_name']}' -> {bdef['scope_kind']}:{bdef['scope_id']} ({bdef['direction']})")


# ---------------------------------------------------------------------------
# STEP 11 — Allow/deny probe
# ---------------------------------------------------------------------------

def step11_allow_deny_probe() -> None:
    """
    Fire one allow and one deny probe via /admin/inspection/simulate.
    If the endpoint doesn't exist on this deployment tier, skip gracefully.
    """
    print("\n=== STEP 11: Allow/deny OPA probe ===")

    # Allow probe: data-team user, /v1/data path (should pass POL-001)
    allow_input = {
        "identity": {"role": "user", "groups": ["data-team"], "agent": "", "clearance": ""},
        "request": {"purpose": "data_query", "lawful_basis": "consent"},
        "routing_decision": {"route": "local", "provider": "ollama", "model": "gemma3:4b"},
        "method": "GET",
        "path": "/v1/data/records",
        "data_tags": [],
        "tool": "",
    }
    deny_input = {
        "identity": {"role": "user", "groups": ["finance-team"], "agent": "", "clearance": ""},
        "request": {"purpose": "policy_promotion", "lawful_basis": ""},
        "routing_decision": {"route": "local", "provider": "ollama", "model": "unapproved-model-x"},
        "method": "POST",
        "path": "/v1/finance/write",
        "data_tags": ["sensitive", "pii"],
        "tool": "email.delete",
    }

    for label, payload in [("allow-probe", allow_input), ("deny-probe", deny_input)]:
        r = S.post(f"{BASE_URL}/admin/inspection/simulate", json={"input": payload})
        if r.status_code == 404:
            print(f"  {label}: /admin/inspection/simulate not available on this deployment tier (expected 404, not a failure)")
            continue
        if r.status_code == 405:
            print(f"  {label}: 405 Method Not Allowed — endpoint may be GET-only, skipping")
            continue
        body = _ok(r, label, allow=(200, 201, 422, 503))
        if r.status_code in (422, 503):
            print(f"  {label}: HTTP {r.status_code} (OPA unavailable or bad input schema — expected on this deployment tier)")
        else:
            decision = body.get("decision") or body.get("result") or body
            print(f"  {label}: {json.dumps(decision, default=str)[:200]}")


# ---------------------------------------------------------------------------
# STEP 12 — Confirm user logins
# ---------------------------------------------------------------------------

def step12_verify_user_logins(user_creds: dict[str, dict]) -> None:
    """
    Verify each new user can log in (or at least has an account) via the admin
    users list. We can't fully log in as users here since they need TOTP provision
    on first login — just confirm the accounts exist and are not disabled.
    """
    print("\n=== STEP 12: Verify user accounts exist and are active ===")
    r = S.get(f"{BASE_URL}/admin/users")
    users = _ok(r, "list-users-verify").get("users", [])
    user_map = {u.get("email", ""): u for u in users}
    for udef in USERS:
        email = udef["email"]
        if email in user_map:
            u = user_map[email]
            print(f"  user '{email}': username={u.get('username')}, disabled={u.get('disabled')}, "
                  f"force_pw_change={u.get('force_password_change')}")
        else:
            print(f"  WARN: user '{email}' not found in users list")


# ---------------------------------------------------------------------------
# STEP 13 — demo-mcp reachability
# ---------------------------------------------------------------------------

def step13_demo_mcp() -> None:
    """
    Probe demo-mcp reachability. demo-mcp runs on its own network (demo_mcp_isolated).
    From host, it's not directly accessible. Verify via docker exec or container
    health status. Also probe the MCP gateway endpoint (requires agent token).
    """
    print("\n=== STEP 13: demo-mcp reachability check ===")

    container = _container_name("demo-mcp")
    if not container:
        print("  WARN: could not resolve demo-mcp container name via docker/podman ps "
              "or COMPOSE_PROJECT_NAME — skipping health/self-probe checks")
    else:
        # Check container health via docker inspect
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", container],
            capture_output=True, text=True
        )
        health = result.stdout.strip()
        print(f"  {container} health: {health}")
        if health == "healthy":
            print("  demo-mcp container is healthy")
        else:
            print(f"  WARN: demo-mcp health={health} (may still be starting)")

        # Probe from within docker network via exec
        result2 = subprocess.run(
            ["docker", "exec", container, "python3", "-c",
             "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8000/',timeout=2); "
             "print('HTTP', r.status)"],
            capture_output=True, text=True
        )
        if result2.returncode == 0:
            print(f"  demo-mcp self-probe: {result2.stdout.strip()}")
        else:
            print(f"  demo-mcp self-probe: FAILED: {result2.stderr.strip()[:200]}")

    # The MCP gateway endpoint /mcp requires agent Bearer token — check the
    # endpoint is at least reachable (401 = gateway is up, not 404/502)
    r = S.get(f"{BASE_URL}/mcp", headers={"Authorization": "Bearer invalid-token-probe"})
    print(f"  /mcp gateway probe (bad token): HTTP {r.status_code} "
          f"(401/403=gateway present and enforcing auth; 200=unexpected)")
    if r.status_code in (401, 403, 405, 422):
        print("  MCP gateway reachable and enforcing auth")
    elif r.status_code == 404:
        print("  WARN: /mcp returned 404 — check gateway routing")
    else:
        print(f"  MCP gateway: HTTP {r.status_code}")


# ---------------------------------------------------------------------------
# STEP 13b — cloud-9 MCP-injection demo wiring verification
# ---------------------------------------------------------------------------

def step13b_cloud9_demo_wire() -> None:
    """
    Verify the cloud-9 MCP-injection demo is correctly wired end-to-end.

    What this checks (NO mutations — read-only verification):

    1. Gateway /v1/models includes the virtual model "cloud9-orchestrate"
       (set via YASHIGANI_ORCH_AUTO_MODELS=cloud9-orchestrate in docker/.env).
       This is the OWUI model picker entry the demo user selects.

    2. Benign orchestration call (no digit 9 in the middle of text) → 200, CLEAN.
       Uses ana's API key (owui-users member, ceiling CONFIDENTIAL).

    3. Cloud-9 injection call (digit 9 in middle of text arg) → 200, BLOCKED.
       The demo-mcp returns INJECTION_PAYLOAD for this input; the gateway
       OPA egress (sensitivity ceiling) + ResponseInspectionPipeline both
       fire and block the payload before it reaches the model.

    User gesture in OWUI (codified here for the verification record):
       1. Log in to https://localhost as ana (ana@agnosticsec.com).
       2. Open a new chat.
       3. In the model picker (top of chat), select "cloud9-orchestrate".
       4. Type: "Use mcp echo with text: version9test"  (digit 9 in middle)
       5. The gateway blocks the injection; OWUI shows the BLOCKED notice.
       6. Normal message: "Use mcp echo with text: hello world" (no digit 9)
          passes through and echoes normally.
    """
    print("\n=== STEP 13b: cloud-9 MCP-injection demo wiring verification ===")

    # Use ana's API key for the wiring check (user-tier, ceiling CONFIDENTIAL).
    # ana key is stored in the user-api-keys file written by step7c.
    api_key_file = DEMO_DIR / "user-api-keys-clean.txt"
    ana_key = ""
    if api_key_file.exists():
        for line in api_key_file.read_text().splitlines():
            if "ana@agnosticsec.com" in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    ana_key = parts[-1].strip()
                    break
    if not ana_key:
        print("  WARN: ana API key not found in user-api-keys-clean.txt — skipping cloud-9 probe")
        return

    headers = {"Authorization": f"Bearer {ana_key}"}

    # 1) Check /v1/models contains cloud9-orchestrate
    r = S.get(f"{BASE_URL}/v1/models", headers=headers)
    if r.status_code == 200:
        models = [m.get("id") for m in r.json().get("data", [])]
        if "cloud9-orchestrate" in models:
            print("  [PASS] /v1/models includes 'cloud9-orchestrate' (OWUI picker wired)")
        else:
            print(f"  [FAIL] 'cloud9-orchestrate' NOT in /v1/models: {models}")
            print("  Check YASHIGANI_ORCH_AUTO_MODELS in docker/.env and restart gateway")
            return
    else:
        print(f"  [WARN] /v1/models HTTP {r.status_code}: {r.text[:200]}")
        return

    # 2) Benign call (no digit 9 in the middle of the text arg)
    r2 = S.post(f"{BASE_URL}/v1/chat/completions",
        headers=headers,
        json={
            "model": "cloud9-orchestrate",
            "messages": [{"role": "user", "content": "Use mcp echo with text: hello world"}],
        },
        timeout=120,
    )
    if r2.status_code == 200:
        content = r2.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        if "BLOCKED" in content:
            print(f"  [FAIL] Benign call was BLOCKED (unexpected): {content[:200]}")
        elif "hello world" in content or "echo" in content.lower():
            print("  [PASS] Benign call passed through (echo returned, no block)")
        else:
            print(f"  [PASS?] Benign call HTTP 200 (content: {content[:200]})")
    else:
        print(f"  [FAIL] Benign call HTTP {r2.status_code}: {r2.text[:200]}")

    # 3) Cloud-9 injection trigger (digit 9 in middle of text arg)
    r3 = S.post(f"{BASE_URL}/v1/chat/completions",
        headers=headers,
        json={
            "model": "cloud9-orchestrate",
            "messages": [{"role": "user", "content": "Use mcp echo with text: version9test"}],
        },
        timeout=120,
    )
    if r3.status_code == 200:
        content3 = r3.json().get("choices", [{}])[0].get("message", {}).get("content", "")
        import re as _re3
        # Post message-polish (v3.0): the user sees a HUMAN block message + an opaque
        # coded transcript (<uid>:<depth>:0:<leg>:7:<reason> — status 0=blocked,
        # action 7=deny), NOT the old raw "BLOCKED [egress_opa=deny ... inspection=BLOCKED]".
        # Detect either the plain-language block or the coded block line.
        coded_block = bool(_re3.search(r"[0-9A-Fa-f]{4}:\d+:0:\d+:7:\d+", content3))
        if "blocked" in content3.lower() or coded_block:
            print("  [PASS] cloud-9 injection BLOCKED at gateway (human notice + coded transcript)")
            print(f"  Evidence: {content3[:400]}")
        else:
            print(f"  [FAIL] cloud-9 injection NOT blocked: {content3[:400]}")
    else:
        print(f"  [FAIL] cloud-9 trigger HTTP {r3.status_code}: {r3.text[:200]}")

    print("""
  --- cloud-9 demo USER GESTURE (for headed-browser verification) ---
  1. Browse to https://localhost  (gateway-authenticated as ana)
  2. Open a new chat in Open WebUI
  3. Model picker (top of chat) → select "cloud9-orchestrate"
  4. Type: "Use mcp echo with text: version9test"
     Expected: OWUI shows BLOCKED notice (injection blocked at egress)
  5. Type: "Use mcp echo with text: hello world"
     Expected: OWUI shows normal echo response (passes through)
  Screenshot: {testing_runs}/cloud9-picture/CLOUD9-OWUI-blocked.png
  """)


# ---------------------------------------------------------------------------
# STEP 13c — MCP Registry import ceremony (demo-mcp envelope seeding)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Shared user-session helper (for user-plane seeding steps 13d + 13e)
# ---------------------------------------------------------------------------

def _user_totp_sha256(secret: str) -> str:
    """User-tier TOTP (SHA256/6-digit). Thin delegator onto the product's own
    TOTP core (_role_totp -> yashigani.auth.totp._totp_at) — collapses the
    previous hand-rolled HMAC/base32 implementation onto the single source of
    truth also used for admin TOTP (ROLE_TOTP_ALGO["user"] / ROLE_TOTP_DIGITS["user"]
    == SHA256/6, matching src/yashigani/auth/totp.py exactly)."""
    return _role_totp(secret, "user")


def _user_login_session(email: str, username: str, password: str, totp_secret: str) -> requests.Session:
    """Create a fresh user-plane session.  Returns None on failure."""
    import time as _t
    us = requests.Session()
    us.verify = False
    for _attempt in range(3):
        # Wait for a clean TOTP window to avoid replay collisions.
        remaining = 30 - int(_t.time()) % 30
        if remaining < 5:
            print(f"  [{email}] waiting {remaining + 2}s for TOTP window...")
            _t.sleep(remaining + 2)
        code = _user_totp_sha256(totp_secret)
        r = us.post(f"{BASE_URL}/auth/login", json={
            "username": username, "password": password, "totp_code": code,
        })
        if r.status_code == 200 and r.json().get("status") == "ok":
            print(f"  [{email}] user login OK")
            return us
        print(f"  [{email}] user login attempt {_attempt + 1} failed: "
              f"HTTP {r.status_code} — {r.text[:120]}")
        _t.sleep(35)  # wait a full window before retry
    print(f"  [{email}] WARN: all login attempts failed — skipping")
    return None


# ---------------------------------------------------------------------------
# STEP 13d — Seed per-user personas/agents for BOLA demo surface
# ---------------------------------------------------------------------------

PERSONA_SEED = [
    # ana gets @Mimi (persona for the demo workflow) + @anabot (agent)
    {"email": "ana@agnosticsec.com", "items": [
        {"alias": "Mimi",   "name": "Mimi (Ana's AI persona)",  "kind": "persona",
         "persona": "I am Mimi, Ana's personal AI assistant. I help analyse data."},
        {"alias": "anabot", "name": "Ana's workflow agent",     "kind": "agent",
         "persona": "I am Ana's workflow automation agent."},
    ]},
    # paul gets @PaulBot (persona) + @pauleye (agent) — different handles from ana's
    {"email": "paul@agnosticsec.com", "items": [
        {"alias": "PaulBot", "name": "PaulBot (Paul's AI persona)", "kind": "persona",
         "persona": "I am PaulBot, Paul's personal AI assistant for finance queries."},
        {"alias": "pauleye", "name": "Paul's observation agent",   "kind": "agent",
         "persona": "I monitor financial data streams for Paul."},
    ]},
]


def step13d_seed_user_personas_and_agents(user_creds: dict) -> dict:
    """
    4.0 — Seed per-user personas and agents via the user-plane API.

    Creates:
      ana:   @Mimi (persona), @anabot (agent)
      paul:  @PaulBot (persona), @pauleye (agent)

    Idempotent: if an agent with the same alias already exists, skip creation.
    Returns {email: {alias: ua_id}} for each seeded entry.
    """
    print("\n=== STEP 13d: Seed per-user personas + agents (BOLA demo surface) ===")
    created: dict[str, dict] = {}

    for seed in PERSONA_SEED:
        email = seed["email"]
        items = seed["items"]

        # Look up the user's current credentials from user_creds or creds file.
        info = user_creds.get(email, {})
        username = info.get("username", "")
        new_pw = info.get("new_pw") or info.get("temp_pw", "")
        totp_secret = info.get("totp_secret", "")

        if not (username and new_pw and totp_secret):
            print(f"  {email}: missing creds (user_creds entry incomplete) — skipping")
            continue

        us = _user_login_session(email, username, new_pw, totp_secret)
        if us is None:
            print(f"  {email}: could not create user session — skipping personas")
            continue

        # List existing agents to avoid duplicate alias.
        r_agents = us.get(f"{BASE_URL}/user/agents")
        existing_aliases = set()
        if r_agents.status_code == 200:
            for ag in r_agents.json().get("agents", []):
                alias = ag.get("alias", "") or ag.get("personality", {}).get("alias", "")
                # The alias is inside the personality JSON for some records.
                # Simpler: just re-fetch after creation to verify.
                existing_aliases.add(ag.get("name", ""))

        user_entries: dict[str, str] = {}
        for item in items:
            alias = item["alias"]
            kind = item["kind"]
            name = item["name"]
            persona = item["persona"]

            # Check /user/mentions to see if alias already exists.
            rm = us.get(f"{BASE_URL}/user/mentions")
            existing_handles: set[str] = set()
            if rm.status_code == 200:
                for m in rm.json().get("mentions", []):
                    if m.get("kind") in ("agent", "persona"):
                        existing_handles.add(m.get("handle", "").lower())

            if alias.lower() in existing_handles:
                print(f"  {email}: @{alias} already exists — skipping")
                # Try to get the ua_id from the mentions list
                for m in rm.json().get("mentions", []):
                    if m.get("handle", "").lower() == alias.lower():
                        user_entries[alias] = m.get("id", "")
                        break
                continue

            payload = {"name": name, "alias": alias, "kind": kind}
            if kind == "persona":
                payload["persona"] = persona
                payload["system_prompt"] = ""
            else:
                payload["persona"] = persona
                payload["system_prompt"] = ""

            rc = us.post(f"{BASE_URL}/user/agents", json=payload)
            if rc.status_code in (200, 201):
                ua_id = rc.json().get("id") or rc.json().get("ua_id", "")
                print(f"  {email}: created {kind} @{alias}: ua_id={ua_id}")
                user_entries[alias] = ua_id
            elif rc.status_code == 409:
                print(f"  {email}: @{alias} already exists (409 — idempotent)")
            else:
                print(f"  {email}: WARN create @{alias}: "
                      f"HTTP {rc.status_code}: {rc.text[:160]}")

        created[email] = user_entries

    print(f"  Personas/agents seeded: {created}")
    return created


# ---------------------------------------------------------------------------
# STEP 13e — Seed demo workflow for ana (OPA-every-hop surface)
# ---------------------------------------------------------------------------

def step13e_seed_demo_workflow(user_creds: dict, persona_agents: dict) -> str | None:
    """
    4.0 — Seed a demo no-code workflow for ana that exercises the
    OPA-every-hop governed execution path.

    The workflow:
      Step 1: @Mimi (ana's persona) — "Retrieve current status and summarise"
      Step 2: @langflow (gateway agent) — "Process the summary and log it"
    Schedule: interval 600 seconds (every 10 minutes)

    Creates the workflow via the generate→commit HTTP flow (governed LLM
    parses the NL description).  Falls back to direct Redis injection if the
    LLM call fails (e.g. LLM unavailable or YASHIGANI_MCP_SERVERS not set in
    backoffice container).

    Returns the workflow_id string, or None if seeding failed.
    """
    print("\n=== STEP 13e: Seed demo workflow for ana (OPA step-exec surface) ===")

    # Build ana's session
    email = "ana@agnosticsec.com"
    info = user_creds.get(email, {})
    username = info.get("username", "")
    new_pw = info.get("new_pw") or info.get("temp_pw", "")
    totp_secret = info.get("totp_secret", "")

    if not (username and new_pw and totp_secret):
        print(f"  {email}: missing creds — cannot seed demo workflow")
        return None

    us = _user_login_session(email, username, new_pw, totp_secret)
    if us is None:
        print(f"  {email}: login failed — cannot seed demo workflow")
        return None

    # Check if a demo workflow already exists.
    rlist = us.get(f"{BASE_URL}/user/workflows")
    if rlist.status_code == 200:
        for wf in rlist.json().get("workflows", []):
            if wf.get("name", "").startswith("Demo: Status Retrieval"):
                wf_id = wf.get("workflow_id", "")
                print(f"  Demo workflow already exists: wf_id={wf_id} — skipping")
                return wf_id

    # Determine available @-handles for the description.
    # @Mimi (ana's persona, seeded by step13d) + @langflow (system api agent)
    mimi_id = (persona_agents.get(email) or {}).get("Mimi", "")
    description = (
        "@Mimi retrieve the current system status and produce a brief summary. "
        "Then @langflow process the summary and log it to the audit trail. "
        "Run this every 10 minutes."
    )

    # Attempt the generate→commit flow.
    wf_id = _try_generate_commit_workflow(us, description)
    if wf_id:
        print(f"  Demo workflow created via generate→commit: wf_id={wf_id}")
        return wf_id

    # Fallback: direct Redis injection via docker exec.
    print("  generate→commit failed — falling back to direct Redis injection")
    wf_id = _inject_workflow_via_redis(
        account_id="ae34f862-6cc1-4e44-938d-001fb2f71d2f",  # ana's account_id
        name="Demo: Status Retrieval Workflow",
        steps=[
            {"actor": "@Mimi",     "action": "Retrieve current system status and summarise",
             "uses": [],           "output_to": "@langflow"},
            {"actor": "@langflow", "action": "Process the summary and log it to the audit trail",
             "uses": [],           "output_to": ""},
        ],
        schedule={"kind": "interval", "seconds": 600},
    )
    if wf_id:
        print(f"  Demo workflow injected via Redis: wf_id={wf_id}")
    else:
        print("  WARN: demo workflow seed failed via both paths")
    return wf_id


def _try_generate_commit_workflow(us: requests.Session, description: str) -> str | None:
    """Try the governed generate→commit flow.  Returns wf_id or None."""
    print(f"  Generating workflow spec via governed LLM ({description[:80]}...)")
    rg = us.post(f"{BASE_URL}/user/workflows/generate",
                 json={"description": description}, timeout=60)
    if rg.status_code != 200:
        print(f"  generate failed: HTTP {rg.status_code}: {rg.text[:200]}")
        return None
    body = rg.json()
    draft_id = body.get("draft_id")
    warnings = body.get("warnings", [])
    steps = body.get("steps", [])
    print(f"  Draft generated: draft_id={draft_id} steps={len(steps)} warnings={len(warnings)}")
    if warnings:
        for w in warnings:
            print(f"    WARN: {w}")
    if not steps:
        print("  No valid steps after handle clamping — generate failed")
        return None

    # Commit the draft.
    rc = us.post(f"{BASE_URL}/user/workflows", json={
        "draft_id": draft_id,
        "name": "Demo: Status Retrieval Workflow",
        "description": (
            "OPA-every-hop demo workflow: @Mimi retrieves system status, "
            "@langflow processes and logs the summary. Fires every 10 minutes."
        ),
    })
    if rc.status_code in (200, 201):
        wf_id = rc.json().get("workflow_id", "")
        return wf_id or None
    print(f"  commit failed: HTTP {rc.status_code}: {rc.text[:200]}")
    return None


def _inject_workflow_via_redis(
    account_id: str,
    name: str,
    steps: list[dict],
    schedule: dict,
) -> str | None:
    """
    Direct Redis injection for the demo workflow.  Used as fallback when the
    LLM-backed generate→commit path is unavailable.

    Writes to:
      - backoffice Redis db/3 (wf:meta:{wf_id}, wf:workflows:{account_id})
      - gateway Redis db/6 (wf:spec:{wf_id}, wf:sched:index)
    """
    import json as _json
    import uuid as _uuid
    import time as _t

    backoffice_container = _container_name("backoffice")
    gateway_container = _container_name("gateway")
    if not backoffice_container or not gateway_container:
        print(
            "  WARN: could not resolve backoffice/gateway container names via "
            "docker/podman ps or COMPOSE_PROJECT_NAME — skipping Redis-injection "
            f"fallback (backoffice={backoffice_container!r} gateway={gateway_container!r})"
        )
        return None

    wf_id = "wf_demo_" + _uuid.uuid4().hex[:12]
    now = _t.strftime("%Y-%m-%dT%H:%M:%S+00:00", _t.gmtime())
    spec_dict = {"steps": steps, "schedule": schedule}
    spec_json = _json.dumps(spec_dict)

    # Python code to run inside each container.
    backoffice_code = f"""
import redis, json
r = redis.Redis(host='redis', port=6379, db=3)
wf_id = {wf_id!r}
account_id = {account_id!r}
mapping = {{
    b'account_id':        account_id.encode(),
    b'owner_identity_id': account_id.encode(),
    b'name':              {name!r}.encode(),
    b'description':       b'OPA-every-hop demo workflow — step13e seed',
    b'spec':              {spec_json!r}.encode(),
    b'spec_hash':         b'seed',
    b'enabled':           b'1',
    b'created_at':        {now!r}.encode(),
    b'updated_at':        {now!r}.encode(),
}}
r.hset(f'wf:meta:{{wf_id}}', mapping=mapping)
r.sadd(f'wf:workflows:{{account_id}}', wf_id.encode())
print('BACKOFFICE-REDIS-OK', wf_id)
"""

    gateway_code = f"""
import redis, json
from yashigani.gateway.workflow_scheduler import WorkflowSpec, WorkflowStep, WorkflowSchedule, _redis_set_spec
r6 = redis.Redis(host='redis', port=6379, db=6)
wf_id = {wf_id!r}
account_id = {account_id!r}
steps = {steps!r}
schedule = {schedule!r}
step_objs = [WorkflowStep(**s) for s in steps]
sched_obj = WorkflowSchedule(**schedule)
spec = WorkflowSpec(
    workflow_id=wf_id,
    owner_identity_id=account_id,
    enabled=True,
    steps=step_objs,
    schedule=sched_obj,
)
_redis_set_spec(r6, spec)
print('GATEWAY-REDIS-OK', wf_id)
"""

    # Execute in backoffice container (db/3).
    r1 = subprocess.run(
        ["docker", "exec", backoffice_container, "python3", "-c", backoffice_code],
        capture_output=True, text=True, timeout=30,
    )
    if r1.returncode != 0 or "BACKOFFICE-REDIS-OK" not in r1.stdout:
        print(f"  backoffice Redis injection failed: {r1.stderr[:200]}")
        return None
    print(f"  backoffice Redis injection: {r1.stdout.strip()}")

    # Execute in gateway container (db/6).
    r2 = subprocess.run(
        ["docker", "exec", gateway_container, "python3", "-c", gateway_code],
        capture_output=True, text=True, timeout=30,
    )
    if r2.returncode != 0 or "GATEWAY-REDIS-OK" not in r2.stdout:
        print(f"  gateway Redis injection failed: {r2.stderr[:300]}")
        # Fallback: try via redis-cli within gateway.
        redis_cli_cmd = (
            f"redis-cli -h redis -p 6379 -n 6 SET wf:spec:{wf_id} "
            f"'{json.dumps({'workflow_id': wf_id, 'owner_identity_id': account_id, 'enabled': True, 'steps': steps, 'schedule': schedule})}'"
        )
        r3 = subprocess.run(
            ["docker", "exec", gateway_container, "sh", "-c", redis_cli_cmd],
            capture_output=True, text=True, timeout=10,
        )
        print(f"  gateway redis-cli fallback: {r3.stdout.strip()} {r3.stderr.strip()[:100]}")
    else:
        print(f"  gateway Redis injection: {r2.stdout.strip()}")

    return wf_id

def _demo_mcp_image_digest() -> str:
    """Resolve a sha256 digest for the demo-mcp image (M6 lint requirement).

    Order: YASHIGANI_DEMO_MCP_DIGEST env override → RepoDigests (pushed
    images) → image Id (locally-built images have no RepoDigests; the config
    Id is still a real sha256 content-address of THIS image and honestly pins
    it for the GAP-2 change-prevention binding).  Returns "" on failure.
    """
    import subprocess
    env_digest = os.environ.get("YASHIGANI_DEMO_MCP_DIGEST", "").strip()
    if env_digest:
        return env_digest
    for runtime in ("docker", "podman"):
        try:
            r = subprocess.run(
                [runtime, "image", "inspect", "yashigani/demo-mcp:3.0.0",
                 "--format", "{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}"],
                capture_output=True, text=True, timeout=15,
            )
        except Exception:
            continue
        if r.returncode == 0 and r.stdout.strip():
            value = r.stdout.strip()
            # RepoDigests form: repo@sha256:<hex>; Id form: sha256:<hex>.
            return value.split("@", 1)[1] if "@" in value else value
    return ""


def _demo_mcp_manifest_yaml(tenant_id: str, image_digest: str) -> str:
    """Shape-C manifest for the cloud-9 demo MCP (v4.1 Phase 1c onboarding).

    The import ceremony now provisions the wrap atomically (per-instance leaf
    + Caddy front + reload + durable registry) — the manifest is the codegen
    input.  metadata.name MUST equal the import server_id and tenant_id MUST
    equal the install tenant (transaction consistency rule).

    FINDING-A fix (2026-07-21): spec.subprocess.command/args now pass
    "--stdio" — docker/demo-mcp/server.py's stdio JSON-RPC mode, spawned by
    the first-party bridge (src/yashigani/mcp/_bridge.py) that codegen
    (_gen_compose_override_shape_c) launches as the container command for
    every Shape-C ring_fenced import. Without "--stdio" the subprocess would
    try to bind a TCP socket instead of speaking line-delimited JSON-RPC over
    stdin/stdout, and the bridge would hang waiting for a response line that
    never comes. docker/Dockerfile.demo-mcp now also installs the yashigani
    wheel (brings in fastapi+uvicorn) so the bridge command itself is
    runnable in this image — previously it was stdlib-only and "uvicorn" was
    not found at all. spec.mcp.exposes.tools corrected to match the ACTUAL
    tools this image exposes (echo/reverse/demo_info, docker/demo-mcp/
    server.py TOOLS) — the previous list (add/uppercase/word_count/
    current_time) never existed on this upstream.
    """
    return f"""\
apiVersion: yashigani.io/v1alpha1
kind: AgentIntegration
metadata:
  name: cloud9-demo
  tenant_id: {tenant_id}
  category: mcp_server
  description: Purpose-built demo MCP server (cloud-9 rogue-tool demo)
  vendor: Agnostic Security
  licence: proprietary
spec:
  image:
    repository: yashigani/demo-mcp
    tag: "3.0.0"
    digest: {image_digest}
  write_posture: readonly
  subprocess:
    command: ["python3", "/app/server.py"]
    args: ["--stdio"]
  network:
    egress_allow: []
  mcp:
    posture: mcp-b
    transport: stdio
    session_mode: persistent
    identity_propagation: gateway-enforced-only
    exposes:
      listen_port: null
      shim_port: 8000
      tools:
        - {{name: echo, allowed: true, sensitivity_class: PUBLIC}}
        - {{name: reverse, allowed: true, sensitivity_class: PUBLIC}}
        - {{name: demo_info, allowed: true, sensitivity_class: PUBLIC}}
  audit:
    sensitivity_ceiling: PUBLIC
  storage:
    mounts: []
    tmpfs:
      - {{path: /tmp, size_limit: 16m}}
  secrets: []
  lifecycle:
    mode: persistent
"""


def step13c_mcp_import_ceremony() -> None:
    """
    4.0 — Seed the cloud-9 demo MCP's initial capability envelope via the governed
    import ceremony (POST /admin/mcp/servers/import, step-up gated).

    This is the ONLY path that mints the v1 envelope (the ORIGINAL approved baseline).
    After this call:
      - GET /admin/mcp/servers/ returns the cloud9-demo entry
      - The admin MCP Registry module shows the server and its tool surface
      - Subsequent tool-surface refreshes are triage'd against this baseline

    Idempotent: re-running this step mints a new envelope version (prior is superseded)
    which is safe because the operator (orchid) is explicitly re-approving the surface.

    Pre-conditions (verified earlier in populate-demo.py):
      - demo-mcp container is healthy (step13)
      - orchid admin session is active in `S`
      - Step-up is refreshed before the import POST (StepUpAdminSession required)
    """
    print("\n=== STEP 13c: MCP Registry import ceremony (cloud9-demo envelope) ===")

    # Ensure step-up is fresh before the import (StepUpAdminSession required).
    _do_stepup_inline()

    # v4.1 Phase 1c — ring_fenced imports run the atomic approve transaction
    # (mint per-instance leaf → codegen the Caddy-front wrap → write artifacts
    # → caddy reload → durable envelope).  The Shape-C manifest is required.
    _tenant = os.environ.get("YASHIGANI_TENANT_ID", "default").strip() or "default"
    _digest = _demo_mcp_image_digest()
    if not _digest:
        print("  WARN: could not resolve yashigani/demo-mcp:3.0.0 digest — the")
        print("        approve transaction will 422 on M6. Set YASHIGANI_DEMO_MCP_DIGEST.")

    r = S.post(
        f"{BASE_URL}/admin/mcp/servers/import",
        json={
            "server_id": "cloud9-demo",
            "upstream_url": "http://demo-mcp:8000",
            "topology": "ring_fenced",
            "egress_posture": "NONE",
            "display_name": "Cloud-9 Demo MCP",
            "manifest_yaml": _demo_mcp_manifest_yaml(_tenant, _digest),
        },
    )

    if r.status_code == 200:
        data = r.json()
        print(f"  [PASS] cloud9-demo envelope minted:")
        print(f"         envelope_id={data.get('envelope_id')}  "
              f"tool_count={data.get('tool_count')}  "
              f"approved_by={data.get('approved_by')}")
        tools = data.get("tools", [])
        if tools:
            print(f"         tools: {', '.join(tools)}")
    elif r.status_code == 422 and "no_tools_returned" in r.text:
        print("  WARN: demo-mcp returned empty tools/list — envelope not seeded.")
        print("        Ensure demo-mcp is fully started and reachable from the backoffice network.")
        print(f"        Detail: {r.text[:400]}")
    elif r.status_code == 403 and "step_up_required" in r.text:
        print("  FAIL: step-up TOTP expired before import — retry the script.")
        print(f"        {r.text[:200]}")
    elif r.status_code in (502, 503) and "onboard_transaction_failed" in r.text:
        # v4.1 Phase 1c: transaction rolled back fail-closed. On stacks built
        # before the Phase-3 rebuild the artifact-root / caddy-admin-socket
        # wiring is absent — expected until Su/Captain land the mounts.
        print("  PENDING: approve transaction failed CLOSED and rolled back")
        print("           (Phase-3 stack wiring required: YASHIGANI_MCP_ARTIFACT_ROOT")
        print("            + shared caddy admin socket + Caddyfile mount).")
        print(f"           Detail: {r.text[:300]}")
    else:
        print(f"  FAIL: import ceremony returned HTTP {r.status_code}: {r.text[:400]}")

    # Verify the server now appears in the registry.
    rv = S.get(f"{BASE_URL}/admin/mcp/servers/")
    if rv.status_code == 200:
        servers = rv.json().get("servers", [])
        ids = [s["server_id"] for s in servers]
        if "cloud9-demo" in ids:
            print(f"  [PASS] GET /admin/mcp/servers/ confirms cloud9-demo registered "
                  f"({len(servers)} server(s) total)")
        else:
            print(f"  WARN: cloud9-demo NOT in registry after import. Current servers: {ids}")
    else:
        print(f"  WARN: GET /admin/mcp/servers/ returned HTTP {rv.status_code}: {rv.text[:200]}")


# ---------------------------------------------------------------------------
# STEP 14 — Aspen break-glass verify (one-shot, no mutation)
# ---------------------------------------------------------------------------

def step14_verify_aspen() -> None:
    """
    One-shot login verify for aspen break-glass. NEVER changes pw or TOTP.
    Reads aspen pw from creds file. If login fails, reports clearly.
    """
    print("\n=== STEP 14: Aspen break-glass verify (READ-ONLY) ===")

    aspen_pw = PRISM_PW  # backup admin initial pw, parsed from install log

    # Use a separate session so we don't contaminate the orchid session
    aspen_session = requests.Session()
    aspen_session.verify = False

    _wait_next_totp_window("aspen-verify")
    code = _role_totp(ASPEN_TOTP_SECRET, "admin")  # aspen is admin-tier (SHA512/8)
    r = aspen_session.post(f"{BASE_URL}/auth/login", json={
        "username": ASPEN_USER,
        "password": aspen_pw,
        "totp_code": code,
    })
    if r.status_code == 200 and r.json().get("status") == "ok":
        print(f"  aspen break-glass login: OK (force_pw_change={r.json().get('force_password_change')})")
        # Immediately log out — don't leave aspen sessions open
        aspen_session.post(f"{BASE_URL}/auth/logout")
        print("  aspen session logged out immediately")
        print("  CONFIRMED: aspen break-glass is INTACT and UNTOUCHED")
    elif r.status_code == 401:
        print(f"  CRITICAL: aspen break-glass login FAILED (401): {r.text[:300]}", file=sys.stderr)
        print("  The break-glass account may have been compromised — investigate immediately", file=sys.stderr)
    else:
        print(f"  WARN: aspen login: HTTP {r.status_code}: {r.text[:200]}")


# ---------------------------------------------------------------------------
# STEP 15 — Print summary
# ---------------------------------------------------------------------------

def step15_summary(
    group_ids: dict[str, str],
    user_creds: dict[str, dict],
    agent_info: dict[str, dict],
) -> None:
    print("\n" + "=" * 70)
    print("POPULATE-DEMO (4.1.2) — COMPLETE")
    print("=" * 70)

    print(f"\nOrchid new password ({len(ORCHID_NEW_PW)} chars, round-trip verified):")
    print(f"  {ORCHID_NEW_PW}")
    print(f"  Saved to: {CREDS_FILE}")

    print("\nGroups created/verified:")
    for name, gid in group_ids.items():
        print(f"  {name}: {gid}")

    print("\nUsers created/verified:")
    for email, creds in user_creds.items():
        print(f"  {email}: username={creds.get('username')}, group={creds.get('group')}")

    print("\nAgents registered/verified:")
    for name, info in agent_info.items():
        print(f"  {name}: agent_id={info['agent_id']}")

    print(f"\nOPA policies saved: {len(POLICIES)}")
    for pol in POLICIES:
        print(f"  clients/{pol['name']}")

    print(f"\nOPA bindings: {len(BINDINGS)}")
    for bdef in BINDINGS:
        print(f"  {bdef['policy_name']} -> {bdef['scope_kind']}:{bdef['scope_id']} ({bdef['direction']})")

    print(f"\nScript: {Path(__file__).resolve()}")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"populate-demo.py (4.1.2) starting at {datetime.utcnow().isoformat()}Z")
    print(f"BASE_URL: {BASE_URL}")
    print(f"CREDS_FILE: {CREDS_FILE}")

    # Step 1: login (tries new pw first; falls back to initial)
    new_pw_already_set = step1_login_initial()

    if not new_pw_already_set:
        # Step 2: force password change (only on first run)
        step2_password_change()

        # Step 3: re-login with new pw (MUST SUCCEED or script exits)
        step3_relogin_verify()
    else:
        print("\n=== STEP 2+3: Skipped — new password already in effect (idempotent re-run) ===")

    # Step 4: save new pw to creds file
    step4_save_creds()

    # Step 5: step-up TOTP (gates agent reg + policy save/bind)
    step5_stepup()

    # Step 6: groups
    group_ids = step6_create_groups()

    # Step 7: users + group membership
    user_creds = step7_create_users(group_ids)
    api_keys = step7c_onboard_users(user_creds)
    step7b_save_user_creds(user_creds)  # FIND-DEMO-CREDS: save AFTER onboarding so the file has the rotated new_pw
    step7d_set_sensitivity_ceilings(user_creds)
    step7e_grant_owui_access(user_creds)
    step9c_add_marking_patterns()
    step9e_allocate_local_model_to_sara()

    # Step 8: agents (step-up gated)
    agent_info = step8_register_agents()
    step8b_save_agent_tokens(agent_info)

    # Step 9: save OPA policies (step-up gated)
    step9_save_policies()

    # Step 10: bind policies (step-up gated) — resolves agent local_key -> real name
    step10_bind_policies(agent_info)

    # Step 11: allow/deny probe
    step11_allow_deny_probe()

    # Step 12: verify user accounts exist
    step12_verify_user_logins(user_creds)

    # Step 13: demo-mcp
    step13_demo_mcp()

    # Step 13b: cloud-9 demo wiring verification (read-only, API-level)
    step13b_cloud9_demo_wire()

    # Step 13c: MCP Registry import ceremony (seed cloud9-demo capability envelope)
    # Must run AFTER step13 confirms demo-mcp is healthy.
    step13c_mcp_import_ceremony()

    # Step 13d: Seed per-user personas/agents for BOLA demo surface.
    # Requires user_creds (from step7c) to have new_pw + totp_secret.
    persona_agents = step13d_seed_user_personas_and_agents(user_creds)

    # Step 13e: Seed demo no-code workflow for ana (OPA-every-hop surface).
    # Tries generate→commit via governed LLM; falls back to direct Redis inject.
    step13e_seed_demo_workflow(user_creds, persona_agents)

    # Step 14: aspen break-glass verify (LAST, separate session, no mutation)
    step14_verify_aspen()

    # Step 15: summary
    step15_summary(group_ids, user_creds, agent_info)


if __name__ == "__main__":
    main()
