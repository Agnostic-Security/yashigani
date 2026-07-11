#!/usr/bin/env python3
"""
populate-2255-protocol2.py — Yashigani 2.25.5 PROTOCOL2 seed script.

GUARDRAILS (enforced in code):
  1. Uses ONLY orchid. Forced pw-change -> new pw saved full -> re-login to prove round-trip.
  2. aspen is NEVER touched except a single login-verify at the END.
  3. /auth/totp/provision/start is NEVER called (would rotate TOTP secret, LAURA-2255-008).
  4. Step-up TOTP is called after re-login; all step-up-gated ops happen within 5-min window.

What this script creates:
  Groups  : data-team, finance-team, compliance-team
  Users   : ana@agnosticsec.local / paul@agnosticsec.local / mia@agnosticsec.local
            each in a different group
  Agents  : langflow, letta, openclaw  (groups: [owui-users, users])
  Policies: 8 self-describing client OPA policies (saved + bound)
  Probes  : one allow + one deny via /admin/inspection/simulate (if available)
  MCP     : demo-mcp reachability probe

Usage:
  python3 populate-2255-protocol2.py

All credential output -> CREDENTIALS-2255-PROTOCOL2-20260619.txt (updated in-place).
Scratch state saved to populate-2255-protocol2-state.json (same dir).
"""

from __future__ import annotations

import json
import hashlib
import os
import stat
import sys
import time
from datetime import datetime
from pathlib import Path

import pyotp
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# Output dir for creds/state/user-key artifacts. Configurable so this committed
# script is portable; defaults to the current working directory. The install log
# to parse admin creds from is DEMO_DIR/.last-install-log (a pointer file).
DEMO_DIR = Path(os.environ.get("YASHIGANI_DEMO_OUT_DIR", ".")).resolve()
CREDS_FILE = DEMO_DIR / "CREDENTIALS-3.0.0-CLEAN.txt"
STATE_FILE = DEMO_DIR / "populate-3.0.0-clean-state.json"

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
ORCHID_NEW_PW = "Yg8#Kv9$mNpXqR7wLsZtYa1B-Prim4ry0wner!2026Xj"  # >=36, no banned word/secret
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

def _totp(secret: str, digest=None, digits: int = 6) -> str:
    # Role-tiered TOTP (3.1): admins are SHA512/8, users SHA256/6. pyotp defaults
    # to SHA1/6, which 401s the admin login — callers pass the right algo/digits.
    return pyotp.TOTP(secret, digest=digest or hashlib.sha1, digits=digits).now()


def _admin_totp(secret: str) -> str:
    return _totp(secret, hashlib.sha512, 8)


def _user_totp(secret: str) -> str:
    return _totp(secret, hashlib.sha256, 6)


def _fresh_totp(secret: str, label: str, digest=None, digits: int = 6) -> str:
    """
    Return a TOTP code that's at least 5 seconds from window expiry so the
    server receives it in the same window. Waits for the next window if needed.
    """
    remaining = 30 - int(time.time()) % 30
    if remaining < 5:
        print(f"  [totp:{label}] Window expiring in {remaining}s — waiting for next window...")
        time.sleep(remaining + 2)
    code = _totp(secret, digest, digits)
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
# STEP 1 — Login as orchid
#
# Idempotent: try new password first (in case script already ran once and
# changed it). If that fails with 401, fall back to initial password.
# ---------------------------------------------------------------------------

def step1_login_initial() -> bool:
    """Login as orchid. Returns True if new password already in effect, False if initial."""
    print("\n=== STEP 1: Login as orchid ===")
    code = _fresh_totp(ORCHID_TOTP_SECRET, "orchid-login", hashlib.sha512, 8)

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
    code2 = _admin_totp(ORCHID_TOTP_SECRET)
    r2 = S.post(f"{BASE_URL}/auth/login", json={
        "username": ORCHID_USER,
        "password": ORCHID_INITIAL_PW,
        "totp_code": code2,
    })
    if r2.status_code == 401:
        # Another possible TOTP replay — one more retry
        print("  401 on initial pw — waiting for next TOTP window and retrying once more...")
        _wait_next_totp_window("orchid-initial-retry2")
        code3 = _admin_totp(ORCHID_TOTP_SECRET)
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
    code = _admin_totp(ORCHID_TOTP_SECRET)
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
    code = _admin_totp(ORCHID_TOTP_SECRET)
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
    {"email": "mia@agnosticsec.com", "group": "compliance-team", "ceiling": "RESTRICTED"},
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
    out = DEMO_DIR / f"demo-user-creds-protocol2-{datetime.utcnow().strftime('%Y%m%d')}.txt"
    lines = [f"# Demo user credentials — populate-2255-protocol2 run {datetime.utcnow().isoformat()}Z\n"]
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
# STEP 8 — Register agents
# ---------------------------------------------------------------------------

AGENT_HOSTNAMES_ENV = "langflow,letta,openclaw"  # matches YASHIGANI_AGENT_UPSTREAM_HOSTNAMES


AGENTS = [
    {
        "name": "langflow",
        "upstream_url": "http://langflow:7860",
        "protocol": "openai",
        "groups": ["owui-users", "users"],
        "allowed_caller_groups": ["data-team", "owui-users", "users"],
        "allowed_paths": [],
    },
    {
        "name": "letta",
        "upstream_url": "http://letta:8283",
        "protocol": "openai",
        "groups": ["owui-users", "users"],
        "allowed_caller_groups": ["finance-team", "owui-users", "users"],
        "allowed_paths": [],
    },
    {
        "name": "openclaw",
        "upstream_url": "http://openclaw:18789",
        "protocol": "openai",
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
        code = _user_totp(totp_secret)
        r = us.post(f"{BASE_URL}/auth/login", json={"username": username, "password": temp_pw, "totp_code": code})
        if r.status_code != 200:
            print(f"  {email}: first-login FAILED {r.status_code}: {r.text[:160]}"); continue
        fpc = r.json().get("force_password_change")
        # Derive from the email local-part (ana/paul/...), NOT the email-derived
        # username (e.g. "anaagnosticsec"), which embeds the banned word "agnostic".
        _uid = email.split("@")[0]
        new_pw = "MockPw!" + _uid + "-Zt9QwXy2-Rnd7Kv3pLqWx-2026Yg8Kv"  # >=36, no banned word/secret
        if fpc:
            rc = us.post(f"{BASE_URL}/auth/password/change", json={"current_password": temp_pw, "new_password": new_pw})
            if rc.status_code != 200:
                print(f"  {email}: pw-change FAILED {rc.status_code}: {rc.text[:160]}"); continue
            creds["new_pw"] = new_pw
            # re-login with new pw to confirm + ensure active session/identity
            _wait_next_totp_window(f"{username}-relogin")
            us.post(f"{BASE_URL}/auth/login", json={"username": username, "password": new_pw, "totp_code": _user_totp(totp_secret)})
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
    """Register agents (step-up gated). Return name -> {agent_id, token}."""
    print("\n=== STEP 8: Register agents (step-up gated) ===")

    # List existing agents
    r = S.get(f"{BASE_URL}/admin/agents")
    existing = _ok(r, "list-agents")
    existing_by_name = {a["name"]: a["agent_id"] for a in existing}

    agent_info: dict[str, dict] = {}
    for adef in AGENTS:
        name = adef["name"]
        if name in existing_by_name:
            print(f"  agent '{name}' already registered: {existing_by_name[name]}")
            agent_info[name] = {"agent_id": existing_by_name[name], "token": "(already existed)"}
            continue

        r = S.post(f"{BASE_URL}/admin/agents", json={
            "name": name,
            "upstream_url": adef["upstream_url"],
            "protocol": adef["protocol"],
            "groups": adef["groups"],
            "allowed_caller_groups": adef["allowed_caller_groups"],
            "allowed_paths": adef["allowed_paths"],
        })
        if r.status_code == 403 and "step_up_required" in r.text:
            print("  Step-up expired — re-doing step-up and retrying...")
            _do_stepup_inline()
            r = S.post(f"{BASE_URL}/admin/agents", json={
                "name": name,
                "upstream_url": adef["upstream_url"],
                "protocol": adef["protocol"],
                "groups": adef["groups"],
                "allowed_caller_groups": adef["allowed_caller_groups"],
                "allowed_paths": adef["allowed_paths"],
            })
        body = _ok(r, f"register-agent-{name}", allow=(201,))
        agent_id = body.get("agent_id", "")
        token = body.get("token", "")
        print(f"  registered agent '{name}': agent_id={agent_id}")
        agent_info[name] = {"agent_id": agent_id, "token": token}

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
    code = _admin_totp(ORCHID_TOTP_SECRET)
    r = S.post(f"{BASE_URL}/auth/stepup", json={"totp_code": code})
    if r.status_code != 200:
        print(f"  FAIL inline step-up: HTTP {r.status_code}: {r.text[:200]}", file=sys.stderr)
        sys.exit(1)
    print(f"  Step-up refreshed OK")


def step8b_save_agent_tokens(agent_info: dict[str, dict]) -> None:
    out = DEMO_DIR / f"agent-tokens-protocol2-{datetime.utcnow().strftime('%Y%m%d')}.txt"
    lines = [f"# Agent tokens — populate-2255-protocol2 run {datetime.utcnow().isoformat()}Z\n",
             "# Tokens are show-once. Store securely.\n"]
    for name, info in agent_info.items():
        lines.append(f"{name}  agent_id={info['agent_id']}  token={info['token']}\n")
    out.write_text("".join(lines))
    out.chmod(0o600)
    print(f"  Agent tokens saved to {out}")


# ---------------------------------------------------------------------------
# STEP 9 — Save + activate 8 OPA client policies
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
# LAURA-31DR-003 fix: input.identity.groups is not synced from RBAC; use
# data.yashigani.rbac to check data-team membership.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

# True when the requesting identity is a member of "data-team" via RBAC.
# input.identity.agent holds the identity_id (idnt_<12hex>) which is the key in
# data.yashigani.rbac.user_groups after the 3.1 UID migration.
_data_team_member if {
    gid := data.yashigani.rbac.user_groups[input.identity.agent][_]
    data.yashigani.rbac.groups[gid].display_name == "data-team"
}

deny contains "POL-001:data_access_denied" if {
    not _data_team_member
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
# LAURA-31DR-003 fix: input.identity.groups is not synced from RBAC; use
# data.yashigani.rbac to check finance-team membership.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

# True when the requesting identity is a member of "finance-team" via RBAC.
# input.identity.agent holds the identity_id (idnt_<12hex>) which is the key in
# data.yashigani.rbac.user_groups after the 3.1 UID migration.
_finance_team_member if {
    gid := data.yashigani.rbac.user_groups[input.identity.agent][_]
    data.yashigani.rbac.groups[gid].display_name == "finance-team"
}

deny contains "POL-002:write_forbidden_finance" if {
    _finance_team_member
    input.method != "GET"
    startswith(input.path, "/v1/finance")
}

obligations contains "audit_finance_access" if {
    _finance_team_member
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
# LAURA-31DR-001 fix: use object.get(input, "obligations", set()) instead of bare
# input.obligations so the Rego check is never undefined when the field is absent.
# LAURA-31DR-003 fix: input.identity.groups is not synced from RBAC; use
# data.yashigani.rbac to check compliance-team membership.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

# True when the requesting identity is a member of "compliance-team" via RBAC.
_compliance_team_member if {
    gid := data.yashigani.rbac.user_groups[input.identity.agent][_]
    data.yashigani.rbac.groups[gid].display_name == "compliance-team"
}

# Compliance team has broad access but all actions must be audited
obligations contains "mandatory_audit_log" if {
    _compliance_team_member
}

deny contains "POL-003:compliance_pii_redact_required" if {
    _compliance_team_member
    input.data_tags[_] == "pii"
    not "audit_log" in object.get(input, "obligations", set())
}
""",
    },
    {
        "name": "pii_redaction_policy",
        "rego": """package clients.pii_redaction_policy
import rego.v1

# Policy: PII Transmission Block
# policy_id: POL-004
# user_message: Content containing PII is blocked. Remove the personal information and try again.
# LAURA-31DR-001 fix: use object.get(input, "obligations", set()) instead of bare
# input.obligations.  In Rego v1, "pii_redacted" in undefined evaluates to
# undefined -> not undefined -> rule body undefined -> deny never fires -> silent
# allow-bypass.  object.get defaults to set() when the key is absent, so the
# check evaluates deterministically (false -> deny fires as designed).
# LAURA-31DR-003 fix: input.identity.groups is not synced from RBAC; use
# data.yashigani.rbac to check compliance-team membership.

default decision := {"allow": false, "deny": set(), "obligations": set()}
decision := {"allow": count(deny) == 0, "deny": deny, "obligations": obligations}

# True when the requesting identity is a member of "compliance-team" via RBAC.
# input.identity.agent holds the identity_id (idnt_<12hex>) which is the key in
# data.yashigani.rbac.user_groups after the 3.1 UID migration.
_compliance_team_member if {
    gid := data.yashigani.rbac.user_groups[input.identity.agent][_]
    data.yashigani.rbac.groups[gid].display_name == "compliance-team"
}

deny contains "POL-004:pii_transmission_blocked" if {
    input.data_tags[_] == "pii"
    not "pii_redacted" in object.get(input, "obligations", set())
    not _compliance_team_member
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
    print("\n=== STEP 9: Save 8 OPA client policies (step-up gated) ===")
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


def step10_bind_policies() -> None:
    print("\n=== STEP 10: Bind policies (step-up gated) ===")
    # List existing bindings to avoid duplicates
    r = S.get(f"{BASE_URL}/admin/policies/bindings")
    existing_bindings_raw = _ok(r, "list-bindings").get("bindings", [])
    # Key: (policy_name, scope_kind, scope_id, direction)
    existing_keys = {
        (b["policy_name"], b["scope_kind"], b["scope_id"], b["direction"])
        for b in existing_bindings_raw
    }

    for bdef in BINDINGS:
        key = (bdef["policy_name"], bdef["scope_kind"], bdef["scope_id"], bdef["direction"])
        if key in existing_keys:
            print(f"  binding {key} already exists — skipping")
            continue

        r = S.post(f"{BASE_URL}/admin/policies/bind", json=bdef)
        if r.status_code == 403 and "step_up_required" in r.text:
            print("  Step-up expired — refreshing...")
            _do_stepup_inline()
            r = S.post(f"{BASE_URL}/admin/policies/bind", json=bdef)
        body = _ok(r, f"bind-{bdef['policy_name']}->{bdef['scope_kind']}:{bdef['scope_id']}")
        print(f"  bound '{bdef['policy_name']}' -> {bdef['scope_kind']}:{bdef['scope_id']} ({bdef['direction']})")


# ---------------------------------------------------------------------------
# STEP 11 — Allow/deny probe
# ---------------------------------------------------------------------------

def step11_allow_deny_probe() -> None:
    """
    Fire one allow and one deny probe via /admin/inspection/simulate.
    If the endpoint doesn't exist (2.25.5 subset), skip gracefully.
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
            print(f"  {label}: /admin/inspection/simulate not available on 2.25.5 (expected 404, not a failure)")
            continue
        if r.status_code == 405:
            print(f"  {label}: 405 Method Not Allowed — endpoint may be GET-only, skipping")
            continue
        body = _ok(r, label, allow=(200, 201, 422, 503))
        if r.status_code in (422, 503):
            print(f"  {label}: HTTP {r.status_code} (OPA unavailable or bad input schema — expected on 2.25.5 subset)")
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

    # Check container health via docker inspect
    import subprocess
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Health.Status}}", "docker-demo-mcp-1"],
        capture_output=True, text=True
    )
    health = result.stdout.strip()
    print(f"  docker-demo-mcp-1 health: {health}")
    if health == "healthy":
        print("  demo-mcp container is healthy")
    else:
        print(f"  WARN: demo-mcp health={health} (may still be starting)")

    # Probe from within docker network via exec
    result2 = subprocess.run(
        ["docker", "exec", "docker-demo-mcp-1", "python3", "-c",
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
    code = pyotp.TOTP(ASPEN_TOTP_SECRET).now()
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
    print("POPULATE 2.25.5 PROTOCOL2 — COMPLETE")
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
    print(f"populate-2255-protocol2.py starting at {datetime.utcnow().isoformat()}Z")
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

    # Step 9: save 8 OPA policies (step-up gated)
    step9_save_policies()

    # Step 10: bind policies (step-up gated)
    step10_bind_policies()

    # Step 11: allow/deny probe
    step11_allow_deny_probe()

    # Step 12: verify user accounts exist
    step12_verify_user_logins(user_creds)

    # Step 13: demo-mcp
    step13_demo_mcp()

    # Step 13b: cloud-9 demo wiring verification (read-only, API-level)
    step13b_cloud9_demo_wire()

    # Step 14: aspen break-glass verify (LAST, separate session, no mutation)
    step14_verify_aspen()

    # Step 15: summary
    step15_summary(group_ids, user_creds, agent_info)


if __name__ == "__main__":
    main()
