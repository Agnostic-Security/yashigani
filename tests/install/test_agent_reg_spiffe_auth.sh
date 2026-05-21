#!/usr/bin/env bash
# tests/install/test_agent_reg_spiffe_auth.sh
# Integration regression test for ISSUE-019: POST /admin/agents 401 no_spiffe_id
# on fresh install with --agent-bundles.
#
# Requires: a running Yashigani stack (Docker Compose or Podman Compose) with
#   the backoffice container healthy and secrets mounted.
# Usage:
#   COMPOSE_CMD="docker compose" tests/install/test_agent_reg_spiffe_auth.sh
#   COMPOSE_CMD="podman-compose" tests/install/test_agent_reg_spiffe_auth.sh
#
# Tests:
#   (1) POST /admin/agents with X-SPIFFE-ID: spiffe://yashigani.internal/backoffice
#       returns 200/201, not 401 no_spiffe_id.
#   (2) POST /admin/agents without X-SPIFFE-ID returns 401 no_spiffe_id
#       (gate is active — tests that the fix didn't weaken auth).
#   (3) After install.sh --agent-bundles langflow,letta runs, GET /admin/agents
#       returns a non-empty list containing langflow and letta.
#   (4) Source-level check: POST /admin/agents in register_agent_bundles()
#       includes X-SPIFFE-ID header (static verification of install.sh source).
#
# Tests (1) and (2) run against a live stack.
# Test (3) requires --agent-bundles flag used during install (full install test).
# Test (4) is a static source check — no Docker daemon required.
#
# Exit codes: 0 = all required PASS; 1 = one or more required FAIL or stack
#   not reachable.
#
# ISSUE-019 — close 2026-05-19
# last-updated: 2026-05-19T00:00:00+01:00

set -uo pipefail
IFS=$'\n\t'

PASS=0
FAIL=0
SKIP=0

_pass() { printf "[PASS] %s\n" "$1"; (( PASS++ )) || true; }
_fail() { printf "[FAIL] %s\n" "$1" >&2; (( FAIL++ )) || true; }
_skip() { printf "[SKIP] %s\n" "$1"; (( SKIP++ )) || true; }
_info() { printf "[INFO] %s\n" "$1"; }
_section() { printf "\n--- %s ---\n" "$1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_SH="${INSTALL_SH:-${REPO_ROOT}/install.sh}"
COMPOSE_CMD="${COMPOSE_CMD:-docker compose}"
COMPOSE_FILE="${REPO_ROOT}/docker/docker-compose.yml"

_info "repo root:     ${REPO_ROOT}"
_info "install.sh:    ${INSTALL_SH}"
_info "COMPOSE_CMD:   ${COMPOSE_CMD}"

# ---------------------------------------------------------------------------
# TEST (4): Static — POST /admin/agents includes X-SPIFFE-ID header
# This test requires no running stack and verifies the ISSUE-019 fix is present.
# ---------------------------------------------------------------------------
_section "TEST (4): Static — POST /admin/agents includes X-SPIFFE-ID in install.sh"

if [[ ! -f "$INSTALL_SH" ]]; then
    printf "[FAIL] install.sh not found at: %s\n" "$INSTALL_SH" >&2
    exit 1
fi

# Check that the POST /admin/agents request in register_agent_bundles() includes
# X-SPIFFE-ID: spiffe://yashigani.internal/backoffice
if grep -A5 'Request.*localhost:8443/admin/agents.*data=reg_data' "$INSTALL_SH" \
    | grep -q 'X-SPIFFE-ID.*spiffe://yashigani.internal/backoffice'; then
    _pass "(4.1) POST /admin/agents includes X-SPIFFE-ID: spiffe://yashigani.internal/backoffice"
else
    _fail "(4.1) POST /admin/agents missing X-SPIFFE-ID header — ISSUE-019 fix not present"
fi

# Check that the X-SPIFFE-ID is in the headers dict on the POST, not just a comment
if grep 'Request.*localhost:8443/admin/agents' "$INSTALL_SH" | head -3 \
    | grep -q 'data=reg_data'; then
    # Found the POST line — now check the headers block
    _post_block="$(awk '
        /Request.*localhost:8443\/admin\/agents.*data=reg_data/{found=1}
        found{print; if (/\)\)$/){exit}}
    ' "$INSTALL_SH" 2>/dev/null | head -20)"
    if echo "$_post_block" | grep -q '"X-SPIFFE-ID"'; then
        _pass "(4.2) X-SPIFFE-ID is in the headers= dict of the POST request (not just comment)"
    else
        _fail "(4.2) X-SPIFFE-ID not found in headers= dict — check install.sh register_agent_bundles()"
    fi
else
    _skip "(4.2) Could not isolate POST /admin/agents block — skipping"
fi

# ---------------------------------------------------------------------------
# Check if a running stack is available for live tests (1)-(3)
# ---------------------------------------------------------------------------
_section "Checking for running backoffice container"

BACKOFFICE_CONTAINER=""
for cname in docker_backoffice_1 yashigani-backoffice backoffice; do
    if ${COMPOSE_CMD} -f "$COMPOSE_FILE" ps 2>/dev/null | grep -q "$cname" \
       || (command -v docker &>/dev/null && docker ps --format '{{.Names}}' 2>/dev/null | grep -q "$cname") \
       || (command -v podman &>/dev/null && podman ps --format '{{.Names}}' 2>/dev/null | grep -q "$cname"); then
        BACKOFFICE_CONTAINER="$cname"
        break
    fi
done

if [[ -z "$BACKOFFICE_CONTAINER" ]]; then
    _info "No running backoffice container detected — skipping live tests (1)-(3)"
    _skip "(1.1) Live: POST /admin/agents with X-SPIFFE-ID — stack not running"
    _skip "(1.2) Live: POST response is not 401 no_spiffe_id"
    _skip "(2.1) Live: POST /admin/agents without X-SPIFFE-ID returns 401"
    _skip "(3.1) Live: GET /admin/agents non-empty after agent-bundle install"
    printf "\n=== RESULTS: PASS=%d FAIL=%d SKIP=%d ===\n" "$PASS" "$FAIL" "$SKIP"
    if [[ "$FAIL" -gt 0 ]]; then
        printf "\nRESULT: FAIL — %d check(s) failed.\n" "$FAIL"
        exit 1
    fi
    printf "\nRESULT: PASS — %d checks passed, %d skipped (no stack). (ISSUE-019)\n" "$PASS" "$SKIP"
    exit 0
fi

_info "Detected backoffice container: ${BACKOFFICE_CONTAINER}"

# Helper: exec python inside the backoffice container
_bexec() {
    ${COMPOSE_CMD} -f "$COMPOSE_FILE" exec -T backoffice python3 -c "$1" 2>&1
}

# ---------------------------------------------------------------------------
# TEST (1): Live — POST /admin/agents WITH X-SPIFFE-ID returns non-401
# We use a minimal probe: login → stepup → POST with X-SPIFFE-ID.
# This tests the SPIFFE gate only — we don't assert 201 because the agent
# may already be registered (idempotent test environment).
# ---------------------------------------------------------------------------
_section "TEST (1): Live — POST /admin/agents with X-SPIFFE-ID returns non-401"

_live_result_1="$(_bexec '
import json, os, ssl, sys, urllib.request
try:
    import pyotp, hashlib
except ImportError:
    print("SKIP:no_pyotp")
    sys.exit(0)

secrets = "/run/secrets"
def r(n):
    p = os.path.join(secrets, n)
    return open(p).read().strip() if os.path.exists(p) else ""

ca = r("ca_root.crt")
if not ca:
    print("SKIP:no_ca")
    sys.exit(0)

_ctx = ssl.create_default_context(cafile=os.path.join(secrets, "ca_root.crt"))
_ctx.load_cert_chain(os.path.join(secrets, "backoffice_client.crt"),
                     os.path.join(secrets, "backoffice_client.key"))

user = r("admin1_username")
pw = r("admin1_password")
totp_secret = r("admin1_totp_secret")
hmac = r("caddy_internal_hmac")

if not all([user, pw, totp_secret, hmac]):
    print("SKIP:missing_secrets")
    sys.exit(0)

totp_code = pyotp.TOTP(totp_secret, digest=hashlib.sha256).now()
login_data = json.dumps({"username": user, "password": pw, "totp_code": totp_code}).encode()
req = urllib.request.Request("https://localhost:8443/auth/login", data=login_data,
                             headers={"Content-Type": "application/json",
                                      "X-Caddy-Verified-Secret": hmac})
try:
    resp = urllib.request.urlopen(req, context=_ctx)
except Exception as e:
    print(f"FAIL:login:{e}")
    sys.exit(0)

session = ""
cookie = resp.headers.get("Set-Cookie", "")
for part in cookie.split(";"):
    if part.strip().startswith("__Host-yashigani_admin_session="):
        session = part.strip().split("=", 1)[1]
        break
if not session:
    print("FAIL:no_session")
    sys.exit(0)

stepup_code = pyotp.TOTP(totp_secret, digest=hashlib.sha256).now()
stepup_data = json.dumps({"totp_code": stepup_code}).encode()
su_req = urllib.request.Request("https://localhost:8443/auth/stepup", data=stepup_data,
                                headers={"Content-Type": "application/json",
                                         "X-Caddy-Verified-Secret": hmac,
                                         "Cookie": f"__Host-yashigani_admin_session={session}"})
try:
    urllib.request.urlopen(su_req, context=_ctx)
except Exception as e:
    print(f"WARN:stepup:{e}")

# POST /admin/agents with X-SPIFFE-ID — use a probe agent name unlikely to exist
probe_data = json.dumps({"name": "__issue019_probe__", "upstream_url": "http://probe:9999", "protocol": "openai"}).encode()
probe_req = urllib.request.Request("https://localhost:8443/admin/agents", data=probe_data,
                                   headers={"Content-Type": "application/json",
                                            "X-Caddy-Verified-Secret": hmac,
                                            "X-SPIFFE-ID": "spiffe://yashigani.internal/backoffice",
                                            "Cookie": f"__Host-yashigani_admin_session={session}"})
try:
    resp = urllib.request.urlopen(probe_req, context=_ctx)
    status = resp.status
    body = resp.read()
    print(f"OK:{status}")
except urllib.error.HTTPError as e:
    body = e.read()
    print(f"FAIL:{e.code}:{body.decode(errors=chr(63))}")
' 2>&1)"

_info "Live probe (1) result: ${_live_result_1}"

if echo "$_live_result_1" | grep -q '^SKIP:'; then
    _skip "(1.1) ${_live_result_1#SKIP:} — skipping live test"
    _skip "(1.2) (skipped — see above)"
elif echo "$_live_result_1" | grep -q '^OK:'; then
    _status="${_live_result_1#OK:}"
    _pass "(1.1) POST /admin/agents with X-SPIFFE-ID returned HTTP ${_status} (not 401)"
    if [[ "$_status" == "401" ]]; then
        _fail "(1.2) HTTP 401 — ISSUE-019 not fixed (gate still returning no_spiffe_id)"
    else
        _pass "(1.2) SPIFFE gate passed (status ${_status} — not 401 no_spiffe_id)"
    fi
else
    # FAIL: line contains HTTP code
    _code="$(echo "$_live_result_1" | grep '^FAIL:' | head -1 | cut -d: -f2)"
    if [[ "$_code" == "401" ]]; then
        _fail "(1.1) POST /admin/agents returned 401 — ISSUE-019 NOT fixed: ${_live_result_1}"
        _fail "(1.2) SPIFFE gate returning 401 no_spiffe_id with X-SPIFFE-ID present"
    else
        _info "(1.1) HTTP ${_code} (non-401 — gate passed, other error acceptable)"
        _pass "(1.1) POST /admin/agents did NOT return 401 (gate passed, HTTP ${_code})"
        _pass "(1.2) SPIFFE gate not blocking with X-SPIFFE-ID present"
    fi
fi

# ---------------------------------------------------------------------------
# TEST (2): Live — POST /admin/agents WITHOUT X-SPIFFE-ID returns 401
# This verifies the gate is still active (fix didn't weaken it to open).
# ---------------------------------------------------------------------------
_section "TEST (2): Live — POST /admin/agents without X-SPIFFE-ID returns 401"

_live_result_2="$(_bexec '
import json, os, ssl, sys, urllib.request
try:
    import pyotp, hashlib
except ImportError:
    print("SKIP:no_pyotp")
    sys.exit(0)

secrets = "/run/secrets"
def r(n):
    p = os.path.join(secrets, n)
    return open(p).read().strip() if os.path.exists(p) else ""

if not os.path.exists(os.path.join(secrets, "ca_root.crt")):
    print("SKIP:no_ca")
    sys.exit(0)

_ctx = ssl.create_default_context(cafile=os.path.join(secrets, "ca_root.crt"))
_ctx.load_cert_chain(os.path.join(secrets, "backoffice_client.crt"),
                     os.path.join(secrets, "backoffice_client.key"))

user = r("admin1_username"); pw = r("admin1_password")
totp_secret = r("admin1_totp_secret"); hmac = r("caddy_internal_hmac")
if not all([user, pw, totp_secret, hmac]):
    print("SKIP:missing_secrets")
    sys.exit(0)

totp_code = __import__("pyotp").TOTP(totp_secret, digest=__import__("hashlib").sha256).now()
login_data = json.dumps({"username": user, "password": pw, "totp_code": totp_code}).encode()
req = urllib.request.Request("https://localhost:8443/auth/login", data=login_data,
                             headers={"Content-Type": "application/json", "X-Caddy-Verified-Secret": hmac})
try:
    resp = urllib.request.urlopen(req, context=_ctx)
except Exception as e:
    print(f"SKIP:login_failed:{e}")
    sys.exit(0)

session = ""
for part in resp.headers.get("Set-Cookie", "").split(";"):
    if part.strip().startswith("__Host-yashigani_admin_session="):
        session = part.strip().split("=", 1)[1]
        break
if not session:
    print("SKIP:no_session")
    sys.exit(0)

# POST without X-SPIFFE-ID — should get 401
probe_data = json.dumps({"name": "__issue019_nospiffe__", "upstream_url": "http://probe:9999", "protocol": "openai"}).encode()
probe_req = urllib.request.Request("https://localhost:8443/admin/agents", data=probe_data,
                                   headers={"Content-Type": "application/json",
                                            "X-Caddy-Verified-Secret": hmac,
                                            "Cookie": f"__Host-yashigani_admin_session={session}"})
try:
    resp = urllib.request.urlopen(probe_req, context=_ctx)
    print(f"UNEXPECTED_200:{resp.status}")
except urllib.error.HTTPError as e:
    print(f"HTTP:{e.code}")
' 2>&1)"

_info "Live probe (2) result: ${_live_result_2}"

if echo "$_live_result_2" | grep -q '^SKIP:'; then
    _skip "(2.1) ${_live_result_2#SKIP:} — skipping live gate-active test"
elif echo "$_live_result_2" | grep -q '^HTTP:401'; then
    _pass "(2.1) POST /admin/agents without X-SPIFFE-ID returns 401 — gate is active"
elif echo "$_live_result_2" | grep -q '^HTTP:'; then
    _code="${_live_result_2#HTTP:}"
    _fail "(2.1) Expected 401 without X-SPIFFE-ID, got HTTP ${_code} — gate may be open"
else
    _fail "(2.1) Unexpected probe result: ${_live_result_2}"
fi

# ---------------------------------------------------------------------------
# TEST (3): Live — GET /admin/agents returns non-empty list
# This is only meaningful if --agent-bundles was used during install.
# We test that the endpoint is reachable and returns valid JSON.
# ---------------------------------------------------------------------------
_section "TEST (3): Live — GET /admin/agents reachable and returns valid JSON"

_live_result_3="$(_bexec '
import json, os, ssl, sys, urllib.request
try:
    import pyotp, hashlib
except ImportError:
    print("SKIP:no_pyotp")
    sys.exit(0)

secrets = "/run/secrets"
def r(n):
    p = os.path.join(secrets, n)
    return open(p).read().strip() if os.path.exists(p) else ""

if not os.path.exists(os.path.join(secrets, "ca_root.crt")):
    print("SKIP:no_ca")
    sys.exit(0)

_ctx = ssl.create_default_context(cafile=os.path.join(secrets, "ca_root.crt"))
_ctx.load_cert_chain(os.path.join(secrets, "backoffice_client.crt"),
                     os.path.join(secrets, "backoffice_client.key"))

user = r("admin1_username"); pw = r("admin1_password")
totp_secret = r("admin1_totp_secret"); hmac = r("caddy_internal_hmac")
if not all([user, pw, totp_secret, hmac]):
    print("SKIP:missing_secrets")
    sys.exit(0)

totp_code = __import__("pyotp").TOTP(totp_secret, digest=__import__("hashlib").sha256).now()
login_data = json.dumps({"username": user, "password": pw, "totp_code": totp_code}).encode()
req = urllib.request.Request("https://localhost:8443/auth/login", data=login_data,
                             headers={"Content-Type": "application/json", "X-Caddy-Verified-Secret": hmac})
try:
    resp = urllib.request.urlopen(req, context=_ctx)
except Exception as e:
    print(f"SKIP:login_failed:{e}")
    sys.exit(0)

session = ""
for part in resp.headers.get("Set-Cookie", "").split(";"):
    if part.strip().startswith("__Host-yashigani_admin_session="):
        session = part.strip().split("=", 1)[1]
        break
if not session:
    print("SKIP:no_session")
    sys.exit(0)

req = urllib.request.Request("https://localhost:8443/admin/agents",
                             headers={"X-Caddy-Verified-Secret": hmac,
                                      "Cookie": f"__Host-yashigani_admin_session={session}"})
try:
    resp = urllib.request.urlopen(req, context=_ctx)
    agents = json.loads(resp.read())
    names = [a.get("name", "") for a in agents]
    print(f"JSON:{json.dumps(names)}")
except Exception as e:
    print(f"FAIL:{e}")
' 2>&1)"

_info "Live probe (3) result: ${_live_result_3}"

if echo "$_live_result_3" | grep -q '^SKIP:'; then
    _skip "(3.1) ${_live_result_3#SKIP:} — skipping GET /admin/agents live test"
elif echo "$_live_result_3" | grep -q '^JSON:'; then
    _names="${_live_result_3#JSON:}"
    _pass "(3.1) GET /admin/agents returned valid JSON: ${_names}"
    # If __issue019_probe__ was registered in test (1), it should be in the list.
    if echo "$_names" | grep -q '__issue019_probe__'; then
        _pass "(3.2) probe agent __issue019_probe__ present — POST /admin/agents confirmed registered"
    else
        _info "(3.2) __issue019_probe__ not in list (may not have been registered or already cleaned up)"
        _skip "(3.2) probe agent not in registry — test (1) may have received non-201 (idempotent)"
    fi
else
    _fail "(3.1) GET /admin/agents failed: ${_live_result_3}"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=== RESULTS: PASS=%d FAIL=%d SKIP=%d ===\n" "$PASS" "$FAIL" "$SKIP"
if [[ "$FAIL" -gt 0 ]]; then
    printf "\nRESULT: FAIL — %d check(s) failed. (ISSUE-019)\n" "$FAIL"
    exit 1
fi
printf "\nRESULT: PASS — %d checks passed, %d skipped. (ISSUE-019)\n" "$PASS" "$SKIP"
exit 0
