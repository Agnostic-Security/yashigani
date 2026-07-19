"""
Yashigani Backoffice — Authentication routes.
POST /auth/login                   — username + password + TOTP (returns redirect_to for role routing)
POST /auth/logout                  — invalidate session (any session tier — single-logout fix)
GET  /auth/logout-redirect         — browser-navigable single-logout (Phase 2: OWUI signout redirect target)
GET  /auth/status                  — check session validity
GET  /auth/verify                  — Caddy forward_auth for data-plane (user sessions only)
GET  /auth/verify-admin            — Caddy forward_auth for /admin/* (admin sessions only)
GET  /auth/verify-user             — Caddy forward_auth for /app/webui and user paths (user sessions only; rejects admin)
POST /auth/password/change         — forced change on first login
POST /auth/totp/provision          — TOTP + recovery codes provisioning
POST /auth/stepup                  — V6.8.4 step-up TOTP verification for high-value flows
GET  /auth/post-login-redirect     — server-side next= validator + redirect (drift audit #6)

Phase 1 changes (2026-06-12, feat/2.25.5-auth-ingress):
  - login() now returns redirect_to ("/admin/" for admin, "/app/webui" for user) so the
    login JS can navigate role-appropriately without a separate server roundtrip.
  - logout() changed from AdminSession → AnySession: user-tier sessions were trapped
    because the admin-only guard prevented logout (the "no end-user logout" bug).
  - verify-user endpoint added: accepts user-tier sessions, explicitly rejects admin
    sessions.  Caddy uses it for the /app/webui forward_auth leg.
  - Both /auth/verify and /auth/verify-user reject admin sessions (SoD-003 preserved).

Phase 2 changes (2026-06-13, feat/2.25.5-auth-ingress):
  - logout-redirect endpoint added: GET version of logout for browser navigation.
    OWUI's WEBUI_AUTH_SIGNOUT_REDIRECT_URL points here so its logout button clears
    the Yashigani session cookie.  See Phase 2 notes.

WA-10 fix (2026-07-15, fix/v412-wa10-logout):
  - Both logout() and logout_redirect() now enumerate ALL cookie slots and
    revoke every distinct session token present in the request — not just the
    single token resolved by the AnySession/cookie-priority logic.  Holding
    both __Host-yashigani_admin_session and __Host-yashigani_session (dual-
    session browser state) previously left one session live after logout.
  - Every __Host- cookie clearance now emits Secure; HttpOnly; SameSite=Strict;
    Path=/ — symmetric with the SET path (_set_session_cookie).  Starlette's
    bare delete_cookie() omits Secure, so the browser silently ignores the
    Max-Age=0 directive, leaving the original token in place.
  - change_password() clearance extended: previously only cleared the admin
    cookie; now clears both cookies with the correct attributes.
  - _clear_session_cookie() helper added adjacent to _set_session_cookie() so
    the two paths can never drift independently.  (WA-10 / ASVS V3.4.1)

LAURA-412-CRITICAL fix (2026-07-19, fix/v412-auth-throttle-hardening):
  - Auth-throttle redesigned: a per-ACCOUNT bucket (username-keyed, IP-
    independent) is now the sole pre-auth GATE; the per-IP bucket becomes a
    severity modifier only, never an independent gate.  A clean account can
    no longer be locked out by unrelated noise sharing its apparent IP
    (podman-pasta NAT, CGNAT, corporate proxy/LB — Laura proved a stranger's
    4 garbage-credential requests 429'd an uninvolved, credential-correct
    admin, podman r4, 2026-07-19).
  - The GLOBAL (any-IP) bucket is REMOVED — on a self-hosted single-tenant
    gateway it had no upside that offset letting any unauthenticated caller
    contribute to blocking every other caller.
  - Escalation is bounded at 900s (15 min); the old permanent-block tail
    (`auth:blocked:{ip}` set with no TTL) is removed — no unrecoverable
    state is ever reached without an explicit admin action.
  - Self-heal: a successful login now clears both the account gate and the
    IP severity bucket.  Previously the pre-auth block could prevent a
    legitimate, credential-correct login from ever reaching the success
    path that would have triggered the reset.
  - See AgnosticSecurity memory project_v412_design_conflict_xrealip_podman_nat.md
    and testing_runs/yashigani/v412r4-podman-20260719/laura/laura-podman-pentest.md.

LAURA-412-HIGH / LAURA-412-MEDIUM fix (2026-07-19, fix/v412-auth-throttle-hardening,
round 2 — Laura re-attack, testing_runs/yashigani/v412r5-podman-throttlefix-20260719/):
  - HIGH — TOCTOU race: the round-1 design read the current fail-count/level
    in _apply_auth_throttle() and only incremented it LATER in
    _record_auth_failure(), after authenticate() resolved.  25 concurrent
    wrong-password requests against one real account all read the
    pre-increment state and all passed the gate (none of their own
    siblings' failures had been recorded yet).  Fixed by collapsing the
    check-and-increment into ONE atomic Redis Lua script
    (_THROTTLE_ADMIT_LUA / _throttle_admit()) executed BEFORE
    authenticate() runs, for every attempt (not just confirmed failures).
    Redis executes Lua scripts as a single atomic, non-interleaved unit, so
    concurrent callers are strictly serialised by Redis itself — the
    threshold can no longer be "outrun" by concurrency.  _record_auth_failure()
    is removed; counting now happens unconditionally in the atomic
    admission step, with self-heal (_reset_auth_failures) deleting the
    whole bucket on success regardless of how it was populated.
  - MEDIUM — casefold-collision: round 1's `_hash_account()` casefolded the
    username before hashing, but this system's actual identity model is
    CASE-SENSITIVE (admin_accounts.username is a case-sensitive UNIQUE TEXT
    column; _fetch_by_username does an exact `= $1` match; neither
    create_admin() nor create_user() perform any case-insensitive collision
    check) — so "collision-probe-a" and "COLLISION-PROBE-A" are two real,
    independent accounts that casefolding collapsed into one shared bucket,
    reintroducing the same cross-account-lockout failure class. Fixed by
    keying the account bucket on the account's stable, opaque account_id
    (resolved via _resolve_account_id_for_bucket()) whenever the account
    exists — immune to ANY normalisation choice (case, unicode, whitespace)
    by construction, since account_id never derives from the display
    username. Falls back to a hashed, casefolded username ONLY for
    nonexistent usernames, which cannot collide with any real account_id.
  - See testing_runs/yashigani/v412r5-podman-throttlefix-20260719/laura/laura-reattack-throttle.md.

Last updated: 2026-07-19T00:00:00+00:00
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse as _RedirectResponse
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession, AnySession, get_session_store, _SESSION_COOKIE
from yashigani.backoffice.state import backoffice_state
from yashigani.db.postgres import tenant_transaction as _pg_tenant_transaction_impl

_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


def _pg_tenant_transaction():
    """Shorthand: open a platform-scoped transaction on the shared pool."""
    return _pg_tenant_transaction_impl(_PLATFORM_TENANT_ID)


router = APIRouter()

# ---------------------------------------------------------------------------
# TOTP step-up failure counter (SEC-4 / ASVS V6.3.5)
#
# Migrated from module-level Python dict to Redis so the counter survives
# process restarts and is consistent across multi-replica deployments.
#
# Key:   yashigani:totp_fail:<session_prefix>
# TTL:   _TOTP_FAILURE_TTL_SECONDS (1800 s) — gives a >30-min window per
#        RFC 6238 clock-skew allowance while still expiring eventually.
# Limit: _TOTP_FAILURE_LIMIT (3) — unchanged from previous in-memory behaviour.
#
# Fail-closed: if Redis is unavailable the helper raises RuntimeError which
# the route handler converts to HTTP 503 (same fail-closed stance as login
# rate limiter).
# ---------------------------------------------------------------------------

_TOTP_FAILURE_LIMIT = 3
_TOTP_FAILURE_TTL_SECONDS = 1800  # 30-minute window; covers RFC 6238 clock skew

_log = logging.getLogger("yashigani.auth")


def _totp_fail_key(session_prefix: str) -> str:
    """Redis key for the TOTP step-up failure counter for a session prefix."""
    return f"yashigani:totp_fail:{session_prefix}"


def _totp_incr_failure(session_prefix: str) -> int:
    """
    Increment TOTP step-up failure counter for *session_prefix* and return the
    new count.  Sets TTL to _TOTP_FAILURE_TTL_SECONDS on first increment.

    Fail-closed: raises RuntimeError if Redis is unavailable.
    """
    r = _get_throttle_redis()
    key = _totp_fail_key(session_prefix)
    pipe = r.pipeline()
    pipe.incr(key)
    pipe.expire(key, _TOTP_FAILURE_TTL_SECONDS)
    results = pipe.execute()
    return int(results[0])


def _totp_get_count(session_prefix: str) -> int:
    """Return current failure count for *session_prefix* (0 if key absent)."""
    r = _get_throttle_redis()
    raw = r.get(_totp_fail_key(session_prefix))
    return int(raw) if raw else 0


def _totp_reset(session_prefix: str) -> None:
    """Delete the TOTP step-up failure counter for *session_prefix* on success."""
    r = _get_throttle_redis()
    r.delete(_totp_fail_key(session_prefix))

# ---------------------------------------------------------------------------
# Auth brute-force throttle (ASVS 6.3.5) — LAURA-412-CRITICAL redesign
#
# Dual-bucket, ACCOUNT-GATED design (2026-07-19):
#
#   * Per-ACCOUNT bucket (username-keyed, IP-independent) is the sole GATE.
#     A login attempt is only ever pre-auth-throttled if the SPECIFIC
#     account being logged into already has its own recorded failures.
#     A clean account can never be blocked by another account's — or
#     another caller's — noise, even when they share an apparent IP.
#   * Per-IP bucket is retained as a SEVERITY MODIFIER only, never an
#     independent gate: once an account is implicated, the effective delay
#     also reflects how hot its source IP looks, but the IP bucket alone
#     can never trigger a 429.  This is what makes the design correct
#     regardless of whether client-IP attribution is trustworthy — see
#     project_v412_design_conflict_xrealip_podman_nat.md.  Under a NAT/
#     proxy/CGNAT/podman-pasta topology many distinct legitimate callers
#     collapse onto one apparent address; treating that shared bucket as a
#     gate let one attacker's garbage credentials lock out every other
#     account behind it (Laura, podman r4, 2026-07-19 — an uninvolved,
#     credential-correct admin got 429'd by a stranger's 4 failed attempts).
#   * The GLOBAL (any-IP) bucket is REMOVED.  On a self-hosted single-
#     tenant gateway a global-failure bucket has no upside that offsets
#     letting ANY unauthenticated caller, anywhere, contribute to blocking
#     EVERY other caller — exactly the DoS primitive Laura proved.
#   * Escalation is BOUNDED at 900s (15 min) — see _THROTTLE_DELAYS below.
#     There is no permanent-block tail: the old design set
#     `auth:blocked:{ip}` with no TTL once escalation exhausted the delay
#     table, recoverable only by manual Redis surgery.  That branch is
#     removed entirely.  900s is long enough to meaningfully slow a
#     scripted brute-force loop (~96 guesses/day at sustained max delay vs
#     ~2 880/day unthrottled) and short enough that a legitimately-
#     throttled admin recovers automatically, with no operator action,
#     well inside a working session.  It is deliberately SHORTER than the
#     Postgres-backed per-account hard lockout (`_LOCKOUT_SECONDS` = 1800s,
#     auth/local_auth.py / auth/pg_auth.py) so this Redis layer stays the
#     "soft" first line of friction and the DB layer remains the
#     authoritative "hard" backstop for a confirmed real-account attack —
#     the two layers reinforce rather than fight each other.  The DB layer
#     already self-heals (failed_attempts reset to 0 on success) and is
#     already bounded (30 min, not permanent) — it needed no change here.
#   * Self-heal: a SUCCESSFUL login clears both the account gate and the
#     IP severity bucket immediately (`_reset_auth_failures`).  Under the
#     old design the IP bucket was reset on success too, but a legitimate
#     caller could never REACH success in the first place — the pre-auth
#     block fired before authenticate() ever ran.  Gating on the account
#     bucket (which starts clean for every account) is what makes the
#     success path reachable again for anyone not actually implicated.
#
# Round 2 (Laura re-attack, 2026-07-19, see module docstring for full detail):
#
#   * ATOMIC admission (LAURA-412-HIGH).  Checking the current count and
#     incrementing it later (after authenticate() resolves) is a TOCTOU
#     race under concurrency: N simultaneous requests can all observe the
#     pre-increment state and all pass the gate.  _throttle_admit() runs a
#     single Redis Lua script that increments BOTH bucket dimensions and
#     reads their PRIOR level in one atomic round-trip, BEFORE
#     authenticate() is ever called.  Redis executes Lua scripts
#     non-interleaved, so concurrent callers are strictly serialised by
#     Redis itself — the Nth-ordered request to cross the threshold is the
#     only one that (as a side-effect of its own atomic call) escalates the
#     level, and every subsequent request correctly observes that
#     already-escalated state.  There is no longer a separate
#     "record failure after the fact" step — every ATTEMPT (not just a
#     confirmed failure) claims a slot; a real success immediately deletes
#     the whole bucket via self-heal regardless of how it was populated,
#     so this has no visible effect on normal sequential use.
#   * ID-KEYED account bucket (LAURA-412-MEDIUM).  This system's identity
#     model is CASE-SENSITIVE (admin_accounts.username is a case-sensitive
#     UNIQUE TEXT column; every lookup is an exact match; account creation
#     performs no case-insensitive collision check) — so "alice" and
#     "ALICE" can be two REAL, independent accounts.  Casefolding the
#     username before hashing (round 1) collapsed such pairs into one
#     bucket, reintroducing cross-account lockout for a narrower
#     prerequisite (account-creation privilege or SSO/SCIM case variance).
#     _account_bucket_key() keys on the account's stable, opaque
#     account_id whenever the account exists — immune to ANY
#     normalisation choice by construction — and only falls back to a
#     hashed, casefolded username for a NONEXISTENT username (which cannot
#     collide with any real account_id).
#
# Redis keys:
#   auth:fail:ip:{ip}        — INCR on every attempt, EXPIRE 900s (severity signal)
#   auth:throttle:ip:{ip}    — current delay level for this IP     (severity signal)
#   auth:fail:acct:{b}       — INCR on every attempt, EXPIRE 900s (gating signal)
#   auth:throttle:acct:{b}   — current delay level for this account (gating signal)
#   auth:blocked:{ip}        — admin-managed manual block (GET/DELETE
#                              /blocked-ips below); no longer auto-populated
#                              by escalation.
#   b = "id:{account_id}" when the account exists (stable, opaque —
#       immune to case/unicode/whitespace normalisation tricks), else
#       "unk:{sha256(username.strip().casefold())[:16]}" for a nonexistent
#       username (cannot collide with any real account_id — different
#       key namespace entirely).  The raw username is never stored as a
#       Redis key either way (no plaintext identity leakage from a
#       `redis-cli KEYS` dump; mirrors the _hash_ip() style used elsewhere
#       in this module for the same reason).
# ---------------------------------------------------------------------------

_THROTTLE_IP_THRESHOLD = 3       # per-IP consecutive failures before it adds severity
_THROTTLE_ACCOUNT_THRESHOLD = 3  # per-account consecutive failures before the account is gated
_THROTTLE_WINDOW_SECONDS = 900   # 15-minute rolling window for counters

# Bounded escalation schedule — capped at 900s (15 min).  Index = level-1.
# The last entry is a CEILING: further failures within the window refresh
# the TTL (holding the account/IP at the max delay) but never escalate
# past it and never convert into a separate unrecoverable state.
_THROTTLE_DELAYS = [30, 60, 180, 450, 900]

# ---------------------------------------------------------------------------
# LAURA-412-HIGH (r5, 2026-07-19): atomic admit — a single Redis Lua script
# that increments BOTH bucket dimensions and reads their PRIOR (pre-this-
# call) level in one atomic round-trip.  Redis executes Lua scripts as a
# single, non-interleaved unit — concurrent callers are strictly serialised
# by Redis itself, so no window exists for two-phase "read, decide later,
# increment" races.  KEYS: 1=ip_fail 2=ip_throttle 3=acct_fail 4=acct_throttle.
# ARGV: 1=ip_threshold 2=acct_threshold 3=window_seconds 4=max_level.
# Returns {ip_fails, ip_level_before, acct_fails, acct_level_before} — the
# "_before" values reflect whether the bucket was ALREADY escalated prior
# to this specific attempt (so attempt 1/2/3 still proceed to real auth,
# matching the pre-existing "3 genuine attempts before throttling" contract
# — see _throttle_admit() docstring for the full reasoning).
# ---------------------------------------------------------------------------
_THROTTLE_ADMIT_LUA = """
local ip_threshold   = tonumber(ARGV[1])
local acct_threshold = tonumber(ARGV[2])
local window         = tonumber(ARGV[3])
local max_level      = tonumber(ARGV[4])

local ip_fails = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], window)
local ip_level_before = tonumber(redis.call('GET', KEYS[2]) or '0')
if ip_fails >= ip_threshold then
    if ip_level_before < max_level then
        redis.call('SET', KEYS[2], ip_level_before + 1, 'EX', window)
    else
        redis.call('EXPIRE', KEYS[2], window)
    end
end

local acct_fails = redis.call('INCR', KEYS[3])
redis.call('EXPIRE', KEYS[3], window)
local acct_level_before = tonumber(redis.call('GET', KEYS[4]) or '0')
if acct_fails >= acct_threshold then
    if acct_level_before < max_level then
        redis.call('SET', KEYS[4], acct_level_before + 1, 'EX', window)
    else
        redis.call('EXPIRE', KEYS[4], window)
    end
end

return {ip_fails, ip_level_before, acct_fails, acct_level_before}
"""


def _get_throttle_redis():
    """Return the Redis client used by the session store (reuse existing connection)."""
    return backoffice_state.session_store._redis


def _throttle_admit(
    r,
    ip_fail_key: str,
    ip_throttle_key: str,
    acct_fail_key: str,
    acct_throttle_key: str,
) -> tuple[int, int, int, int]:
    """
    Atomically admit one login attempt against both the IP severity bucket
    and the account gate bucket, in a single Redis round-trip.

    LAURA-412-HIGH fix (r5, 2026-07-19): the round-1 design read the
    current fail-count/level in _apply_auth_throttle(), then incremented
    it SEPARATELY, later, in _record_auth_failure() — only after
    authenticate() had resolved.  Laura proved 25 concurrent wrong-password
    requests against one real account all observed the pre-increment state
    (0 failures) and ALL passed the gate, because none of their own
    siblings' failures had been recorded yet at the moment each one
    checked — a textbook TOCTOU/CWE-362 window.  No amount of reordering
    two separate Python-level round-trips can close this; the read and the
    write must be ONE atomic operation.

    A Redis Lua script is exactly that: Redis executes it as a single,
    non-interleaved unit (Redis is single-threaded for script execution),
    so N concurrent callers are strictly SERIALISED into some strict order
    by Redis itself, with no possibility of two of them observing the same
    "pre-increment" state.  Whichever request happens to be the Nth to
    cross the threshold is the only one whose own atomic call performs the
    escalation; every request ordered after it correctly observes the
    already-escalated level — regardless of how "concurrent" the arrival
    was at the network layer.

    Every attempt (not just a confirmed failure) claims a slot here, ahead
    of the expensive authenticate() call — this is what makes the fix
    correct: counting can only be made concurrency-safe by moving it before
    the point where its outcome is still unknown.  A genuine success
    deletes the whole bucket via self-heal (_reset_auth_failures)
    regardless of how many slots were claimed on the way there, so this has
    no visible effect on normal sequential use (a user who fails twice
    then succeeds sees exactly the same end state as before: an absent
    bucket).

    Returns (ip_fails, ip_level_before, acct_fails, acct_level_before).
    """
    result = r.eval(
        _THROTTLE_ADMIT_LUA,
        4,
        ip_fail_key,
        ip_throttle_key,
        acct_fail_key,
        acct_throttle_key,
        _THROTTLE_IP_THRESHOLD,
        _THROTTLE_ACCOUNT_THRESHOLD,
        _THROTTLE_WINDOW_SECONDS,
        len(_THROTTLE_DELAYS),
    )
    return (int(result[0]), int(result[1]), int(result[2]), int(result[3]))


def _hash_account(username: str) -> str:
    """SHA-256 hex digest (first 16 chars) of a normalised username.

    Used ONLY as the fallback bucket component for a NONEXISTENT username
    (see _account_bucket_key()) — a real account is keyed on its stable
    account_id instead (LAURA-412-MEDIUM, r5 2026-07-19).  Normalisation
    (strip + casefold) is safe here specifically because a bogus username
    can never collide with any real account's "id:{account_id}" bucket —
    different key namespace entirely.  Mirrors _hash_ip()'s style further
    down this module: never store the raw identity as a Redis key or in a
    log line.
    """
    return hashlib.sha256(username.strip().casefold().encode()).hexdigest()[:16]


def _account_bucket_key(username: str, account_id: Optional[str]) -> str:
    """
    Stable per-identity throttle bucket key (LAURA-412-MEDIUM fix, r5,
    2026-07-19).

    Account-identity model confirmed in code before choosing this fix:
    usernames in this system are CASE-SENSITIVE, mutually distinct
    identities — ``admin_accounts.username`` is a case-sensitive
    ``UNIQUE TEXT`` column (db/migrations/versions/0006_admin_accounts.py),
    every username lookup (``_fetch_by_username``) is an exact ``= $1``
    match, and neither ``create_admin()`` nor ``create_user()`` perform any
    case-insensitive collision check (only ``get_account_by_email()``
    case-folds, and only for admin/user cross-tier SoD — not same-tier
    username collisions).  So "collision-probe-a" and "COLLISION-PROBE-A"
    are two REAL, independent, simultaneously-valid accounts in this model
    — Laura proved exactly this live (r5, 2026-07-19): casefolding the
    username for the throttle key (the r4 design) collapsed them into one
    shared bucket, reintroducing the same cross-account-lockout failure
    class the r4 fix was meant to close, just with a narrower prerequisite.

    Keying on ``account_id`` sidesteps the whole class of normalisation
    questions (case, unicode, whitespace, homoglyphs) rather than chasing
    an ever-more-precise string-canonicalisation rule — it is immune by
    construction, since ``account_id`` is assigned once at creation and
    never derived from the display username.

    A nonexistent username has no ``account_id`` to key on; falling back
    to a hash of the normalised username is safe in that case because a
    bogus username can never collide with any REAL account's
    ``"id:..."``-prefixed key (different key namespace entirely, via the
    ``"unk:"`` prefix).
    """
    if account_id:
        return f"id:{account_id}"
    return f"unk:{_hash_account(username)}"


def _throttle_delay_for_level(level: int) -> int:
    """Return delay in seconds for a given throttle level (1-indexed)."""
    if level <= 0:
        return 0
    idx = min(level - 1, len(_THROTTLE_DELAYS) - 1)
    return _THROTTLE_DELAYS[idx]


def _check_ip_access(client_ip: str) -> None:
    """
    Check IP allowlist and blocklist BEFORE any auth processing.
    Order: allowlist (if non-empty, reject unlisted) → blocklist → proceed.
    Supports IPv4, IPv6, and CIDR ranges.

    LAURA-412-CRITICAL (2026-07-19): `auth:blocked:{ip}` is no longer
    auto-populated by escalating login failures (see _throttle_admit) —
    the old design's unbounded permanent-block tail is removed.  This check
    still exists to enforce a DELIBERATE, admin-managed block (an operator
    with a threat-intel-driven reason to hard-block a specific address); it
    is populated/cleared via the GET/DELETE /blocked-ips endpoints below.
    """
    import ipaddress

    r = _get_throttle_redis()

    # 1. Check blocklist first (admin-managed manual bans — see docstring)
    if r.exists(f"auth:blocked:{client_ip}"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "ip_blocked",
                "message": "This IP has been blocked. Contact your administrator.",
            },
        )

    # 2. Check allowlist (if non-empty, only listed IPs/CIDRs can login)
    allowlist = r.smembers("auth:allowlist")
    if allowlist:
        try:
            addr = ipaddress.ip_address(client_ip)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={"error": "ip_not_allowed"})
        allowed = False
        for entry in allowlist:
            entry_str = entry if isinstance(entry, str) else entry.decode()
            try:
                if "/" in entry_str:
                    if addr in ipaddress.ip_network(entry_str, strict=False):
                        allowed = True
                        break
                else:
                    if addr == ipaddress.ip_address(entry_str):
                        allowed = True
                        break
            except ValueError:
                continue
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "ip_not_allowed", "message": "Login not permitted from this IP address."},
            )


def _real_client_ip(request: Request) -> str:
    """Real client IP for per-IP throttle + audit keys (LAURA-3X-001).

    Caddy is the SOLE ingress and overwrites ``X-Real-IP`` with the actual TCP
    peer (``{remote_host}``) on every proxied request, so it is trustworthy and
    NOT client-spoofable.  ``X-Forwarded-For`` is deliberately NOT used here: Caddy
    *appends* the peer to any client-supplied XFF, so ``XFF.split(',')[0]`` is
    attacker-controlled and unsafe for a throttle key.  ``request.client.host`` is
    the Caddy container IP behind the proxy and MUST NOT be used for per-IP
    throttling — it collapses every client to one key, letting any single source
    lock out all admin logins for the throttle window (LAURA-3X-001, DoS).
    """
    xri = request.headers.get("x-real-ip", "").strip()
    if xri:
        return xri.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _resolve_account_id_for_bucket(username: str) -> Optional[str]:
    """
    Resolve ``username`` to its stable ``account_id`` for throttle-bucket
    keying (LAURA-412-MEDIUM fix, r5 2026-07-19).  Looked up
    UNCONDITIONALLY — any tier, disabled or not — because bucket IDENTITY
    correctness does not depend on login ELIGIBILITY; a disabled account is
    still a real, distinct identity that must not share a bucket with an
    unrelated one.

    Fails open to ``None`` (falls back to the safe username-hash bucket,
    see ``_account_bucket_key``) on any DB error — the account-existence
    LOOKUP failing does not weaken authentication itself (``authenticate()``
    still hits the DB directly and fails closed there); it only means this
    one request's throttle bucket temporarily can't be identity-precise.
    Mirrors the same fail-open posture the pre-existing
    ``webauthn_v1._resolve_admin_id()`` helper already takes.
    """
    from yashigani.db.postgres import tenant_transaction

    try:
        async with tenant_transaction(_PLATFORM_TENANT_ID) as conn:
            row = await conn.fetchrow(
                "SELECT account_id FROM admin_accounts WHERE username = $1",
                username,
            )
        return str(row["account_id"]) if row else None
    except Exception:
        _log.exception("Failed to resolve account_id for throttle bucket keying")
        return None


def _apply_auth_throttle(
    client_ip: str,
    username: str,
    account_id: Optional[str],
    response: Response,
) -> None:
    """
    Account-gated brute-force throttle.  Raises HTTP 429 with a ``Retry-After``
    header (RFC 6585) and a user-facing banner ONLY when the specific account
    being logged into already has recorded attempts of its own past the
    threshold.  An implicated IP alone — with zero attempts recorded against
    THIS account's bucket — is never sufficient to block the request; see
    the module docstring above for the full rationale (NAT/proxy IP-collapse
    cannot be allowed to lock out clean accounts).  The caller never
    proceeds past this point while its account is gated.

    Every call to this function ATOMICALLY claims a slot in both bucket
    dimensions via ``_throttle_admit`` (LAURA-412-HIGH fix, r5 2026-07-19) —
    this must run before any credential verification, not after, or the
    TOCTOU race Laura proved (25 concurrent requests all observing the
    pre-increment state) reopens.  ``account_id`` — resolved by the caller
    via ``_resolve_account_id_for_bucket`` (both the password route and, as
    of the Captain merge-review fix, the WebAuthn routes — never the
    admin-tier-only ``_resolve_admin_id``, which would leave disabled/user-
    tier accounts keyed on the ``unk:`` fallback) — selects the identity-
    stable bucket key (LAURA-412-MEDIUM fix); see ``_account_bucket_key``
    for the full rationale.

    ASVS 6.3.5: brute-force mitigation via rate-limiting and account lockout.

    Fail-closed (Captain merge-review, 2026-07-19): if Redis is unavailable,
    ``_throttle_admit`` propagates the underlying error — caught here and
    converted to an explicit HTTP 503, matching this module's established
    fail-closed pattern (see ``_totp_incr_failure`` call sites) rather than
    falling through to FastAPI's generic 500 handler.
    """
    r = _get_throttle_redis()
    bucket_key = _account_bucket_key(username, account_id)

    ip_fail_key = f"auth:fail:ip:{client_ip}"
    ip_throttle_key = f"auth:throttle:ip:{client_ip}"
    acct_fail_key = f"auth:fail:acct:{bucket_key}"
    acct_throttle_key = f"auth:throttle:acct:{bucket_key}"

    try:
        ip_fails, ip_level, acct_fails, acct_level = _throttle_admit(
            r, ip_fail_key, ip_throttle_key, acct_fail_key, acct_throttle_key,
        )
    except Exception as exc:
        # Fail-closed per SOP 1: Redis unavailable must not silently allow
        # (nor silently deny with an opaque 500) — an explicit 503 tells the
        # caller and any monitoring exactly what happened.
        _log.error("Auth throttle: Redis unavailable during atomic admit: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "auth_throttle_unavailable",
                "message": "Authentication service temporarily unavailable.",
            },
        )

    # Account-gated: an implicated IP with no attempts recorded against THIS
    # account's bucket must never block the request on its own.
    if acct_level <= 0:
        return

    effective_level = max(acct_level, ip_level)
    delay = _throttle_delay_for_level(effective_level)
    _log.warning(
        "Auth throttle: account=%s ip=%s acct_level=%d ip_level=%d delay=%ds",
        bucket_key,
        client_ip,
        acct_level,
        ip_level,
        delay,
    )

    state = backoffice_state
    if state.audit_writer is not None:
        from yashigani.audit.schema import AuthThrottleTriggeredEvent
        from yashigani.auth.session import _mask_ip

        state.audit_writer.write(
            AuthThrottleTriggeredEvent(
                admin_account=username,
                client_ip_prefix=_mask_ip(client_ip),
                account_throttle_level=acct_level,
                ip_throttle_level=ip_level,
                delay_seconds=delay,
            )
        )

    # RFC 6585 §4 — Retry-After header on 429.
    # Set on the response object so the header is present on the HTTPException
    # response (FastAPI propagates headers set before raise).
    response.headers["Retry-After"] = str(delay)
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        headers={"Retry-After": str(delay)},
        detail={
            "error": "too_many_requests",
            "retry_after_seconds": delay,
            "banner": (
                f"Too many failed login attempts. "
                f"Please wait {delay} second{'s' if delay != 1 else ''} before trying again."
            ),
        },
    )


def _reset_auth_failures(client_ip: str, username: str, account_id: Optional[str]) -> None:
    """On successful login, clear both the account gate and the IP severity
    bucket.  A successful login proves the specific account is not currently
    under active compromise; clearing the shared IP bucket too means the
    NEXT (possibly different, legitimate) caller behind the same collapsed
    address is not held back by stale severity from an unrelated attacker.

    ``account_id`` must resolve to the SAME bucket key used by
    ``_apply_auth_throttle`` for this login (LAURA-412-MEDIUM, r5
    2026-07-19) — pass the authoritative ``record.account_id`` returned by
    a successful ``authenticate()``/WebAuthn completion, not a stale
    pre-lookup value, so the reset always targets the bucket that was
    actually gated."""
    r = _get_throttle_redis()
    bucket_key = _account_bucket_key(username, account_id)
    r.delete(
        f"auth:fail:ip:{client_ip}",
        f"auth:throttle:ip:{client_ip}",
        f"auth:fail:acct:{bucket_key}",
        f"auth:throttle:acct:{bucket_key}",
    )


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1)
    # Phase 13: accept 6 digits (users/SHA-256) or 8 digits (admins/SHA-512).
    # The server validates the exact count against the account's totp_algorithm
    # after role resolution — the route cannot know the tier before looking up
    # the account.
    totp_code: str = Field(min_length=6, max_length=8, pattern=r"^\d{6,8}$")


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=36)


class TotpConfirmRequest(BaseModel):
    # Phase 13: accept 6 (user) or 8 (admin) digit codes.
    totp_code: str = Field(min_length=6, max_length=8, pattern=r"^\d{6,8}$")


class SelfServiceResetRequest(BaseModel):
    username: str = Field(min_length=3)
    # Phase 13: accept 6 (user) or 8 (admin) digit codes.
    totp_code: str = Field(min_length=6, max_length=8, pattern=r"^\d{6,8}$")


@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response):
    """
    Authenticate with username + password + TOTP.
    Issues a session cookie on success.
    Returns 401 for any failure (no credential enumeration).
    Includes brute-force throttle per ASVS 6.3.5.
    """
    client_ip = _real_client_ip(request)  # LAURA-3X-001: real peer, not Caddy IP

    # Check order: allowlist → blocklist → throttle (account-gated, atomic) → auth
    _check_ip_access(client_ip)
    # LAURA-412-MEDIUM: resolve the identity-stable bucket key BEFORE the
    # throttle check so the gate never keys on a normalised display string.
    account_id = await _resolve_account_id_for_bucket(body.username)
    # LAURA-412-HIGH: this atomically claims a slot in both bucket
    # dimensions BEFORE any credential verification runs — see
    # _apply_auth_throttle / _throttle_admit docstrings.
    _apply_auth_throttle(client_ip, body.username, account_id, response)

    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup

    # ACS gap #95 (auth_log): emit AUTH_LOGIN_ATTEMPT before result so forensic
    # queries can reconstruct the full attempt timeline even when the outcome is
    # not yet known. CMMC AU.L2-3.3.1 / ASVS V7.2.1.
    state.audit_writer.write(_make_login_attempt_event(body.username, client_ip))

    try:
        success, record, reason = await state.auth_service.authenticate(
            body.username,
            body.password,
            body.totp_code,
            audit_writer=state.audit_writer,  # ACS gap #95: propagate for ACCOUNT_LOCKOUT
        )
    except (ValueError, TypeError):
        # LAURA-412-HIGH: no separate _record_auth_failure call — the
        # attempt was already atomically counted by _apply_auth_throttle
        # above, before this exception could even occur.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_credentials_format"},
        )

    if not success:
        state.audit_writer.write(_make_login_event(body.username, "failure", reason))
        try:
            from yashigani.metrics.registry import auth_login_attempts_total
            auth_login_attempts_total.labels(outcome="failure").inc()
        except Exception:  # noqa: BLE001 — metric must never break auth
            pass
        # QA Wave 2 Issue 7 — do NOT disclose server_time to unauthenticated
        # callers. TOTP drift diagnostics only belong in authenticated flows
        # (/auth/password/change, /auth/totp/provision/confirm) where the
        # client has already proved they own an account.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_credentials",
                "hint": "If using TOTP, ensure your device clock is synchronised.",
            },
        )

    # Success — self-heal: clear both the account gate and the IP severity
    # bucket.  Use record.account_id (authoritative, just-confirmed) rather
    # than the earlier pre-auth lookup, so the reset always targets the
    # bucket that was actually gated (LAURA-412-MEDIUM).
    _reset_auth_failures(client_ip, body.username, record.account_id)

    # LAURA-V232-003: when force_totp_provision=True, authenticate() returns
    # reason="totp_provision_required" meaning the account has NOT yet set up
    # TOTP (or has been reset). Issue a RESTRICTED session with
    # account_tier="totp_provisioning" — accepted by require_any_session
    # (for /auth/totp/provision/* and /auth/password/change) but REJECTED by
    # require_admin_session (account_tier must be "admin"). This prevents an
    # attacker from using the provisioning-state bypass to gain a full admin
    # session before completing TOTP setup.
    #
    # The client must:
    #   1. POST /auth/totp/provision/start → QR code + seed
    #   2. POST /auth/totp/provision/confirm {totp_code} → clears flag
    #   3. Log out and log in again → authenticates with full TOTP → gets admin session
    if reason == "totp_provision_required":
        session = state.session_store.create(
            account_id=record.account_id,
            account_tier="totp_provisioning",
            client_ip=client_ip,
        )
        state.audit_writer.write(_make_login_event(body.username, "totp_provision_restricted", None, account_tier=record.account_tier))
        _log.info(
            "TOTP provisioning session issued for %s (force_totp_provision=True). "
            "Full admin access blocked until TOTP is provisioned.",
            body.username,
        )
        _set_session_cookie(response, session.token, "totp_provisioning")
        return {
            "status": "totp_provision_required",
            "force_password_change": record.force_password_change,
            "force_totp_provision": True,
            "message": (
                "Your account requires TOTP provisioning before you can "
                "access admin functions. POST to /auth/totp/provision/start "
                "to begin enrolment."
            ),
        }

    # Check password age against admin-configurable policy.
    #
    # YASHIGANI_PASSWORD_MAX_AGE_DAYS — explicit override. If set, it wins.
    # YASHIGANI_PROFILE — compliance profile that sets sensible defaults:
    #     "pci"    → 90 days (PCI DSS 8.3.9)
    #     "nist"   → 0 days / no expiry (NIST 800-63B discourages rotation)
    #     unset    → 0 days / no expiry (NIST-aligned default)
    # Hard cap: 395 days (13 months). Compliance review finding #9 — PCI-scoped
    # deployments need a ≤90d option without editing code.
    max_age_env = os.getenv("YASHIGANI_PASSWORD_MAX_AGE_DAYS")
    if max_age_env is not None:
        max_age_days = int(max_age_env)
    else:
        profile = os.getenv("YASHIGANI_PROFILE", "").strip().lower()
        if profile == "pci":
            max_age_days = 90
        else:
            max_age_days = 0  # NIST-aligned default (no forced rotation)
    if max_age_days > 395:
        max_age_days = 395  # Hard cap: 13 months
    if max_age_days > 0 and hasattr(record, "password_changed_at"):
        age_days = (time.time() - record.password_changed_at) / 86400
        if age_days > max_age_days:
            record.force_password_change = True
            _log.info("Password expired: user=%s age=%d days, max=%d", record.username, int(age_days), max_age_days)

    # LAURA-V400-NEW-002 (ASVS V2.1.7): enforce force_password_change server-side
    # for user-tier accounts.  A user whose account has force_password_change=True
    # (set by an admin force-reset or by password expiry above) receives a
    # RESTRICTED session with account_tier="password_change_required".
    #
    # This mirrors the totp_provisioning tier pattern:
    #   - "password_change_required" sessions are accepted by require_any_session
    #     (so /auth/password/change and /auth/logout remain reachable).
    #   - "password_change_required" sessions are REJECTED by require_user_session
    #     (all /user/* and data-plane endpoints are blocked).
    #   - Once the user changes their password (/auth/password/change), ALL sessions
    #     are invalidated (ASVS V2.1.4); the user must log in again to get a full
    #     session.
    #
    # LAURA-411-003 (ASVS V2.1.7): enforce force_password_change for ADMIN accounts.
    # A session issued with force_password_change=True is a restricted
    # account_tier="admin_password_change_required" — accepted by require_any_session
    # (so /auth/password/change and /auth/logout remain reachable) but REJECTED by
    # require_admin_session (so all /admin/* GET/POST endpoints are blocked until
    # the password is changed and the admin re-authenticates for a full session).
    # Mirrors the totp_provisioning pattern at lines 428-450 above.
    if record.force_password_change and record.account_tier == "admin":
        restricted_session = state.session_store.create(
            account_id=record.account_id,
            account_tier="admin_password_change_required",
            client_ip=client_ip,
        )
        state.audit_writer.write(
            _make_login_event(
                body.username,
                "admin_password_change_restricted",
                None,
                account_tier=record.account_tier,
            )
        )
        _log.info(
            "LAURA-411-003: admin_password_change_required session issued for %s "
            "(force_password_change=True). All /admin/* endpoints blocked until "
            "password is changed via /auth/password/change.",
            body.username,
        )
        _set_session_cookie(response, restricted_session.token, "admin_password_change_required")
        return {
            "status": "admin_password_change_required",
            "force_password_change": True,
            "force_totp_provision": record.force_totp_provision,
            "message": (
                "Your password must be changed before you can access admin functions. "
                "POST to /auth/password/change to set a new password."
            ),
        }

    # User-tier force-password-change restriction (LAURA-V400-NEW-002).
    if record.force_password_change and record.account_tier == "user":
        restricted_session = state.session_store.create(
            account_id=record.account_id,
            account_tier="password_change_required",
            client_ip=client_ip,
        )
        state.audit_writer.write(
            _make_login_event(
                body.username,
                "password_change_restricted",
                None,
                account_tier=record.account_tier,
            )
        )
        _log.info(
            "LAURA-V400-NEW-002: password_change_required session issued for %s "
            "(force_password_change=True). All /user/* endpoints blocked until "
            "password is changed via /auth/password/change.",
            body.username,
        )
        _set_session_cookie(response, restricted_session.token, "password_change_required")
        return {
            "status": "ok",
            "force_password_change": True,
            "force_totp_provision": record.force_totp_provision,
            "redirect_to": "/chat",
            "message": (
                "Your password must be changed before you can access this account. "
                "POST to /auth/password/change to set a new password."
            ),
        }

    # Gap 3 / v2.23.4 arch-completion: register HUMAN identity before session
    # creation so a seat-limit rejection prevents session issuance (fail-closed).
    # Skips silently when identity_registry is None (community-tier).
    # Raises HTTPException(403) when the licence seat limit is exhausted.
    _register_human_identity_on_login(record, state)

    session = state.session_store.create(
        account_id=record.account_id,
        account_tier=record.account_tier,
        client_ip=client_ip,
    )

    state.audit_writer.write(_make_login_event(body.username, "success", None, account_tier=record.account_tier))
    try:
        from yashigani.metrics.registry import auth_login_attempts_total
        auth_login_attempts_total.labels(outcome="success").inc()
    except Exception:  # noqa: BLE001 — metric must never break auth
        pass

    # Phase 1 / 2.25.5-auth-ingress: single portal, role-based redirect.
    # admin → /admin/  (admin console)
    # user  → /chat    (4.0 user chat SPA; avoids false-positive OPEN_REDIRECT audit
    #                   and the 3-hop redirect that / → catch-all → /chat produces)
    # Any other tier (totp_provisioning is handled above) → /chat as safe fallback.
    if record.account_tier == "admin":
        redirect_to = "/admin/"
    elif record.account_tier == "user":
        redirect_to = "/chat"
    else:
        redirect_to = "/chat"

    _set_session_cookie(response, session.token, record.account_tier)
    return {
        "status": "ok",
        "force_password_change": record.force_password_change,
        "force_totp_provision": record.force_totp_provision,
        # role-based redirect destination for the login JS; validated server-side
        # by /auth/post-login-redirect when following the normal login flow.
        "redirect_to": redirect_to,
    }


@router.post("/logout")
async def logout(
    request: Request,  # WA-10: enumerate ALL cookie slots for full revocation
    session: AnySession,  # Phase 1 fix: was AdminSession — user-tier sessions were trapped (no end-user logout bug)
    response: Response,
    store=Depends(get_session_store),
):
    """
    Single-logout endpoint.  Clears ALL sessions regardless of tier (admin or user).

    Phase 1 / 2.25.5-auth-ingress: changed from AdminSession → AnySession so
    user-tier accounts can reach this endpoint.  Previously a user-tier session
    received HTTP 403 from require_admin_session and was permanently trapped
    (no working end-user logout).

    WA-10 fix: when a browser holds BOTH an admin cookie (__Host-yashigani_admin_session)
    and a user cookie (__Host-yashigani_session), the AnySession dependency resolves
    only the FIRST matching token (admin-cookie preferred by _resolve_token).  The
    other session would remain live in Redis after the first token is invalidated,
    and a follow-up request using that cookie would pass /auth/verify-admin with HTTP
    200.  This handler now enumerates every cookie slot and revokes each distinct
    token independently.

    Security: all distinct session tokens present in the request are invalidated in
    Redis.  BOTH __Host- cookies are cleared with Secure; HttpOnly; Path=/ (symmetric
    with _set_session_cookie — bare delete_cookie() omits Secure, causing browsers to
    ignore the Max-Age=0 clearance for __Host- cookies).  An expired/invalidated
    session calling this endpoint returns HTTP 401 from require_any_session before
    reaching this handler — no unauthenticated session-clearing is possible.
    """
    # WA-10: collect every distinct session token present in the request.
    # _resolve_token (used by AnySession) picks admin-cookie first; if the
    # browser also holds a user-cookie backed by a DIFFERENT session, that
    # second session must also be revoked.
    tokens_to_revoke: set[str] = {session.token}
    for _cookie_name in (_SESSION_COOKIE, _USER_SESSION_COOKIE):
        _raw = request.cookies.get(_cookie_name)
        if _raw and _raw not in tokens_to_revoke:
            tokens_to_revoke.add(_raw)

    for _tok in tokens_to_revoke:
        try:
            store.invalidate(_tok)
        except Exception:
            pass  # already expired / gone — cookie clearance still proceeds

    # WA-10: use _clear_session_cookie (not delete_cookie) so the clearance
    # directive carries Secure; HttpOnly; Path=/ — required for __Host- cookies.
    _clear_session_cookie(response, _SESSION_COOKIE)
    _clear_session_cookie(response, _USER_SESSION_COOKIE)
    # AU.L2-3.3.1 / OWASP A09: emit audit event for every auth lifecycle action.
    state = backoffice_state
    if state.audit_writer is not None:
        state.audit_writer.write(_make_login_event(session.account_id, "logout", None, account_tier=session.account_tier))
    return {"status": "ok"}


@router.get("/logout-redirect")
async def logout_redirect(
    request: Request,
    response: Response,
    store=Depends(get_session_store),
):
    """
    Browser-navigable single-logout endpoint.

    Phase 2 / 2.25.5-auth-ingress: OWUI (with WEBUI_AUTH=false) calls its own
    /api/v1/auths/signout endpoint, which — when WEBUI_AUTH_SIGNOUT_REDIRECT_URL is
    set — returns {"status": true, "redirect_url": "<url>"} to the SvelteKit client.
    The client then navigates the browser to that URL.  We point it here so clicking
    the logout button inside /app/webui actually clears the Yashigani session cookie.

    Behaviour:
      - Valid session (admin or user): invalidate in Redis, clear both cookies,
        redirect to /login.
      - No session / expired session: clear cookies defensively, redirect to /login.
        (Not a security issue: if there is nothing to invalidate, forcing the user
        back to /login is correct.)

    Security: this is a GET handler that modifies state.  The CSRF risk is accepted
    because:
      1. Logging out is not a sensitive state change (worst-case: nuisance logout).
      2. OWUI does NOT support submitting a POST form redirect via WEBUI_AUTH_SIGNOUT_REDIRECT_URL;
         it only performs a browser navigation (window.location).
      3. The action is idempotent — a forged logout just forces a re-login.

    WA-10 fix: previously only one token was resolved (user-cookie preferred) and
    only that one session was revoked.  Now BOTH cookie slots are checked and every
    distinct token is independently invalidated server-side.
    """
    # WA-10: collect every distinct session token present in the request.
    # The original code used user-cookie-first priority, leaving the admin session
    # live when both cookies were present.  Enumerate ALL slots.
    tokens_to_revoke: set[str] = set()
    for _cookie_name in (_USER_SESSION_COOKIE, _SESSION_COOKIE):
        _raw = request.cookies.get(_cookie_name)
        if _raw:
            tokens_to_revoke.add(_raw)

    state = backoffice_state
    for _tok in tokens_to_revoke:
        try:
            # Resolve account_id BEFORE invalidation (store.get returns None after).
            _session_data = store.get(_tok)
            _account_id = _session_data.account_id if _session_data else "unknown"
            store.invalidate(_tok)
            if state.audit_writer is not None:
                state.audit_writer.write(
                    _make_login_event(_account_id, "logout", None)
                )
        except Exception:
            # Session already expired / gone — still clear the cookies.
            pass

    redirect = _RedirectResponse(url="/login", status_code=302)
    # WA-10: use _clear_session_cookie (not delete_cookie) so the clearance
    # directive carries Secure; HttpOnly; Path=/ — required for __Host- cookies.
    _clear_session_cookie(redirect, _SESSION_COOKIE)
    _clear_session_cookie(redirect, _USER_SESSION_COOKIE)
    return redirect


@router.get("/status")
async def session_status(session: AdminSession):
    return {
        "account_id": session.account_id,
        "account_tier": session.account_tier,
        "expires_at": session.expires_at,
    }


@router.post("/password/self-reset")
async def self_service_password_reset(body: SelfServiceResetRequest):
    """
    Self-service password reset — no session required.
    User proves identity via username + TOTP code, receives a new temporary password.
    ASVS V2.1: authenticated password reset without admin intervention.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    record = await state.auth_service.get_account(body.username)

    # Same generic error for unknown user or wrong TOTP (prevent enumeration).
    # QA Wave 2 Issue 7 — self-service password reset is unauthenticated by
    # design; do NOT leak server_time to callers who have not proved identity.
    generic_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": "invalid_credentials",
            "hint": "If using TOTP, ensure your device clock is synchronised.",
        },
    )

    if record is None or record.disabled:
        raise generic_error

    if not record.totp_secret:
        raise generic_error

    # Use the auth service's Postgres-backed replay cache so the self-service
    # path can't be abused for TOTP replay.
    # Phase 13: pass the account's enrolled algorithm and role digit count.
    # pylint: disable=protected-access
    from yashigani.auth.totp import ROLE_TOTP_DIGITS as _SELF_RESET_ROLE_DIGITS
    _self_reset_digits = _SELF_RESET_ROLE_DIGITS.get(record.account_tier, 6)
    async with _pg_tenant_transaction() as conn:
        if not await state.auth_service._verify_totp_with_replay(
            conn,
            record.totp_secret,
            body.totp_code,
            algorithm=record.totp_algorithm,
            digits=_self_reset_digits,
        ):
            raise generic_error

    # TOTP valid — generate new temporary password and persist via the
    # Postgres-backed auth service so the reset survives restart (P0-2).
    from yashigani.auth.password import generate_password, hash_password

    temp_password = generate_password(36)
    try:
        # check_breach=False: temp password is system-generated, not user-chosen.
        # HIBP check applies to user-chosen passwords only (ASVS V2.1.7).
        new_hash = hash_password(temp_password, check_breach=False)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_credentials_format"},
        )
    # Apply the new password hash + force-change flag durably.
    async with _pg_tenant_transaction() as conn:
        await conn.execute(
            "UPDATE admin_accounts SET password_hash = $1, "
            "force_password_change = true, password_changed_at = $2 "
            "WHERE username = $3",
            new_hash,
            time.time(),
            record.username,
        )

    # Invalidate all sessions
    state.session_store.invalidate_all_for_account(record.account_id)

    state.audit_writer.write(_make_login_event(body.username, "self_reset", None, account_tier=record.account_tier))
    # ACS gap #95 (auth_log): SESSIONS_INVALIDATED event for session lifecycle audit.
    state.audit_writer.write(
        _make_sessions_invalidated_event(
            admin_account=body.username,
            acting_admin="",  # self-service reset
            reason="self_reset",
            account_tier=record.account_tier,
        )
    )

    return {
        "status": "ok",
        "temporary_password": temp_password,
        "force_password_change": True,
        "message": "Log in with this temporary password. You will be required to change it.",
    }


@router.get("/verify")
async def verify_session(request: Request):
    """
    Caddy forward_auth endpoint. Validates the session cookie and returns
    the authenticated user's identity in response headers.
    200 + X-Forwarded-User header → Caddy proceeds with the request.
    401 → Caddy redirects to login.
    Checks both user cookie (__Host-yashigani_session) and admin cookie (__Host-yashigani_admin_session).
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    token = request.cookies.get(_USER_SESSION_COOKIE) or request.cookies.get(_SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    session = state.session_store.get(token)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    # SoD-003: admin sessions MUST NOT traverse the data plane.
    # Admins authenticate to port 8443 (backoffice) only. Any admin session
    # presented to /auth/verify (Caddy forward_auth) is categorically rejected.
    # This is layer 2 of the SoD-004 defence (layer 1 = SoD-002c in sso.py).
    # NIST AC-5 / OWASP ASVS V4.1.2 / ISO 27001 A.5.16 / v2.24.1 Iris #96.
    if session.account_tier == "admin":
        from yashigani.audit.schema import AuthVerifyRejectedAdminSessionEvent
        _client_ip = _real_client_ip(request)  # LAURA-3X-001
        from yashigani.auth.session import _mask_ip as _verify_mask_ip
        if state.audit_writer is not None:
            state.audit_writer.write(AuthVerifyRejectedAdminSessionEvent(
                account_id=session.account_id,
                client_ip_prefix=_verify_mask_ip(_client_ip),
            ))
        _log.warning(
            "SoD-003: /auth/verify rejected admin session account_id=%s — admins cannot use the data plane",
            session.account_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "admin_session_not_allowed_data_plane",
                "message": (
                    "Admin accounts cannot access the data plane. "
                    "If you need user-tier access, create a separate user account with a different username."
                ),
            },
        )

    # LAURA-V400-NEW-002: defence-in-depth — block password_change_required sessions
    # at the Caddy forward_auth layer so they cannot reach any data-plane resource.
    # The primary enforcement is at require_user_session in middleware.py; this is
    # the early-rejection layer (Caddy sees 403 → does not forward the request).
    if session.account_tier == "password_change_required":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "password_change_required",
                "message": (
                    "You must change your password before accessing this resource. "
                    "POST to /auth/password/change to set a new password."
                ),
            },
        )

    # Resolve account from account_id
    record = await state.auth_service.get_account_by_id(session.account_id)

    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    from starlette.responses import Response as StarletteResponse

    resp = StarletteResponse(status_code=200)
    email = record.email or f"{record.username}@yashigani.local"
    resp.headers["X-Forwarded-User"] = email
    resp.headers["X-Forwarded-Name"] = record.username
    resp.headers["X-Forwarded-Email"] = email
    # 4.1 SEC-GAP-1: inject X-Yashigani-Identity-Id for the gateway boundary resolver.
    # Caddy propagates this via copy_headers in the forward_auth block.
    _idreg = getattr(state, "identity_registry", None)
    if _idreg is not None:
        try:
            _iid = _idreg.get_by_account_id(session.account_id)
            if _iid:
                resp.headers["X-Yashigani-Identity-Id"] = _iid
        except Exception as _idreg_exc:
            _log.debug("verify: identity_registry lookup failed for %s: %s",
                       session.account_id, _idreg_exc)
    return resp


@router.get("/verify-admin")
async def verify_admin_session(request: Request):
    """
    Caddy forward_auth for ADMIN-only operator proxies (Grafana / Wazuh / Prometheus
    under /admin/*). This is the INVERSE of /auth/verify: it REQUIRES a valid admin
    session (account_tier == "admin") and rejects user-tier, provisioning-state, and
    anonymous requests.

    SoD-003 bars admins from the DATA plane (/auth/verify), but the operator
    monitoring dashboards are an ADMIN function — admins must reach them and normal
    users must not. Using /auth/verify here (the bug) rejected admins outright.
    200 + identity headers → Caddy proceeds. 401 → redirect to /admin/login.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup
    token = request.cookies.get(_SESSION_COOKIE)  # admin cookie only
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    session = state.session_store.get(token)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    if session.account_tier != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "admin_session_required",
                "message": "These operator dashboards require an admin session.",
            },
        )
    record = await state.auth_service.get_account_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    from starlette.responses import Response as StarletteResponse

    resp = StarletteResponse(status_code=200)
    email = record.email or f"{record.username}@yashigani.local"
    resp.headers["X-Forwarded-User"] = email
    resp.headers["X-Forwarded-Name"] = record.username
    resp.headers["X-Forwarded-Email"] = email
    # 4.1 SEC-GAP-1: inject identity_id for forward_auth copy_headers propagation.
    _idreg_a = getattr(state, "identity_registry", None)
    if _idreg_a is not None:
        try:
            _iid_a = _idreg_a.get_by_account_id(session.account_id)
            if _iid_a:
                resp.headers["X-Yashigani-Identity-Id"] = _iid_a
        except Exception as _idreg_a_exc:
            _log.debug("verify-admin: identity_registry lookup failed for %s: %s",
                       session.account_id, _idreg_a_exc)
    return resp


@router.get("/verify-user")
async def verify_user_session(request: Request):
    """
    Caddy forward_auth endpoint for USER paths (/app/webui and its sub-paths).

    Phase 1 / 2.25.5-auth-ingress.  The split-verify pattern:
      /auth/verify-admin → admin sessions only  (for /admin/*)
      /auth/verify       → user sessions only   (existing data-plane / OWUI catch-all)
      /auth/verify-user  → user sessions only   (this endpoint, for /app/webui)

    Accepts any authenticated SESSION with account_tier == "user".
    Rejects admin sessions with HTTP 403 (SoD preserved — admins never reach the
    user/OWUI path, even if they have a valid session).
    Rejects unauthenticated or expired sessions with HTTP 401.

    On 200: sets X-Forwarded-User/Name/Email headers for OWUI trusted-header auth.
    On 401: Caddy redirects to /login?next=<path>.
    On 403: Caddy surfaces an authorization error (not a login redirect).

    NIST AC-5 / ASVS V4.1.2 / design: auth-ingress-architecture-20260612.md
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.session_store is not None  # set unconditionally at startup

    # Accept both user cookie and admin cookie names for flexibility; the tier
    # check below enforces the actual restriction.
    token = request.cookies.get(_USER_SESSION_COOKIE) or request.cookies.get(_SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    session = state.session_store.get(token)
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    # Admin sessions MUST NOT access user paths.
    # This is the /app/webui-side mirror of SoD-003 (which blocks admin on /auth/verify).
    if session.account_tier == "admin":
        _log.warning(
            "verify-user: rejected admin session account_id=%s — "
            "admins cannot access user paths (/app/webui)",
            session.account_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "admin_session_not_allowed_user_path",
                "message": (
                    "Admin accounts cannot access user paths. "
                    "Use your admin console at /admin/."
                ),
            },
        )

    # Reject provisioning-state sessions (must finish TOTP enrolment first).
    if session.account_tier == "totp_provisioning":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "totp_provisioning_incomplete",
                "message": "Complete TOTP enrolment before accessing this resource.",
            },
        )

    # LAURA-V400-NEW-002: reject password_change_required sessions.
    # User must change their temporary/expired password via /auth/password/change
    # before accessing any data-plane resource.
    if session.account_tier == "password_change_required":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "password_change_required",
                "message": (
                    "You must change your password before accessing this resource. "
                    "POST to /auth/password/change to set a new password."
                ),
            },
        )

    # Only user-tier sessions proceed past this point.
    if session.account_tier != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "insufficient_tier",
                "message": "This path requires a user-tier session.",
            },
        )

    record = await state.auth_service.get_account_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    # OWUI access is OPT-IN (Yashigani is API-first). A user-tier session is
    # provisioned for the API by default (the `users` caller group); reaching
    # OpenWebUI (served at root) additionally requires membership of the
    # `owui-users` RBAC group. Membership lives in the RBAC store
    # (group.members = emails), NOT identity_registry.groups (empty for RBAC
    # members). Skip-allow when the RBAC store or owui-users group is absent
    # (community/non-standard deploy) — never lock everyone out. (YSG 2.25.5
    # a64331e + c751e15; see docs/operator-guide.md §5.6.)
    _rbac = getattr(state, "rbac_store", None)
    if _rbac is not None:
        _email = (record.email or f"{record.username}@yashigani.local").strip().lower()
        _owui_grp = next(
            (grp for grp in _rbac.list_groups()
             if str(getattr(grp, "display_name", "")).lower() == "owui-users"),
            None,
        )
        if _owui_grp is not None:
            _members = {str(m).strip().lower() for m in (_owui_grp.members or set())}
            if _email not in _members:
                _log.info(
                    "verify-user: user %s not in owui-users RBAC group — denying "
                    "OpenWebUI access (API-first; user has API access only)",
                    record.username,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "owui_access_required",
                        "message": (
                            "Your account does not have OpenWebUI access. Ask an "
                            "administrator to add you to the owui-users group."
                        ),
                    },
                    headers={"X-Authz-Reason": "owui_access_required"},
                )

    from starlette.responses import Response as StarletteResponse

    resp = StarletteResponse(status_code=200)
    email = record.email or f"{record.username}@yashigani.local"
    resp.headers["X-Forwarded-User"] = email
    resp.headers["X-Forwarded-Name"] = record.username
    resp.headers["X-Forwarded-Email"] = email
    # 4.1 SEC-GAP-1: inject identity_id for forward_auth copy_headers propagation.
    _idreg_u = getattr(state, "identity_registry", None)
    if _idreg_u is not None:
        try:
            _iid_u = _idreg_u.get_by_account_id(session.account_id)
            if _iid_u:
                resp.headers["X-Yashigani-Identity-Id"] = _iid_u
        except Exception as _idreg_u_exc:
            _log.debug("verify-user: identity_registry lookup failed for %s: %s",
                       session.account_id, _idreg_u_exc)
    return resp


# ---------------------------------------------------------------------------
# v4.1 Phase 1c — /auth/verify-mcp: forward_auth gate for the per-MCP wrap
# ---------------------------------------------------------------------------

# server_id / tenant_id slugs (mirrors mcp_servers._SAFE_SERVER_ID_RE — 1–63
# chars, alphanumeric start, [-_] allowed). Anything else is denied outright.
_VERIFY_MCP_SLUG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-_]{0,62}$")

# v4.1 §2.5 — backoffice transport-subject allow (CLOSED allowlist, Lu-review
# item): the backoffice mesh leaf (spiffe://<td>/backoffice) is a legitimate
# dispatcher ONLY toward the bundled langflow front (user_agents draft-flow
# creation + langflow_client.create_flow via YASHIGANI_LANGFLOW_URL).  Every
# other (subject=backoffice, server) pair keeps the deny — this is a
# positive, server-scoped grant, not a blanket transport identity.  The
# tenant conjunct is enforced in the route (must equal the install tenant).
# No OPA/rego change: this gate is Python-only (mcp.rego governs egress
# grants + broker tool results, not the §2.5 ingress transport subjects).
_VERIFY_MCP_BACKOFFICE_ALLOWED_SERVERS: frozenset[str] = frozenset({"langflow"})


def _verify_mcp_install_tenant() -> str:
    """This install's tenant id (mirrors mcp_servers._install_tenant)."""
    return os.environ.get("YASHIGANI_TENANT_ID", "default").strip() or "default"


def _verify_mcp_envelope_service():
    """Live CapabilityEnvelopeService over the asyncpg pool (patchable in tests)."""
    from yashigani.db import get_pool
    from yashigani.mcp.envelope_service import CapabilityEnvelopeService
    return CapabilityEnvelopeService(get_pool())


def _verify_mcp_audit_deny(
    reason: str, subject: str, tenant: str, server: str,
) -> None:
    """Best-effort MCP_INGRESS_DENIED audit write (never raises)."""
    aw = backoffice_state.audit_writer
    if aw is None:
        return
    try:
        from yashigani.audit.schema import McpIngressDeniedEvent
        aw.write(McpIngressDeniedEvent(
            subject_spiffe_id=subject,
            tenant_id=tenant,
            server_id=server,
            reason=reason,
        ))
    except Exception as exc:  # noqa: BLE001 — audit must never mask the deny
        _log.error("verify-mcp: MCP_INGRESS_DENIED audit write failed: %s", exc)


def _verify_mcp_deny(
    status_code: int, reason: str, subject: str, tenant: str, server: str,
) -> HTTPException:
    """Audit + build the deny response (Caddy treats any non-2xx as DENY)."""
    _verify_mcp_audit_deny(reason, subject, tenant, server)
    _log.warning(
        "verify-mcp: DENY reason=%s subject=%r tenant=%r server=%r",
        reason, subject, tenant, server,
    )
    return HTTPException(
        status_code=status_code,
        detail={"error": reason},
        headers={"X-Authz-Reason": reason},
    )


@router.get("/verify-mcp")
async def verify_mcp_ingress(request: Request, tenant: str = "", server: str = ""):
    """
    Caddy forward_auth gate for the per-MCP Caddy-front wrap (v4.1 Phase 1c,
    SYNTHESIS.md Issue-1 step 3/6; snippet contract in codegen
    ``_gen_caddy_snippet_mcp`` / tests/contracts/test_codegen_mcp_caddy_front.py).

    Trust model — the subject identity is NEVER a spoofable client header:
      * The per-MCP mesh listener terminates mTLS ``require_and_verify``
        against the internal intermediate CA, then STRIP-BEFORE-SETS
        ``X-SPIFFE-ID`` from the VERIFIED peer cert URI SAN.
      * The forward_auth hop to this endpoint presents caddy_client.crt
        (backoffice mTLS, ``--ssl-cert-reqs 2``) and carries
        ``X-Caddy-Verified-Secret`` (Layer B HMAC).  ``CaddyVerifiedMiddleware``
        401s any request without the valid secret, and
        ``SpiffePeerCertMiddleware`` (Option C) strips ``x-spiffe-id`` unless
        the secret validated — so an ``x-spiffe-id`` value observed here is
        Caddy-set-from-verified-peer by construction.

    Authorisation (fail-closed at every step):
      * Subject == ``spiffe://<td>/gateway`` → ALLOW (the broker's mesh
        transport identity; per-tool authz stays with the broker's OPA leg —
        SYNTHESIS Issue-2 role split; per-instance grant objects land in
        Phase 2 with Lu's rego).
      * Subject == ``spiffe://<td>/backoffice`` → ALLOW only toward the
        bundled langflow front in this install's tenant (v4.1 §2.5 closed
        allowlist — the backoffice dispatches draft-flow creation through
        langflow's ingress front); every other target denies
        ``transport_subject_not_allowed``.
      * Subject matching Nico's per-instance contract
        ``spiffe://<td>/agents/<tenant>/<name>/<nhi_id>`` → ALLOW only when
        the instance segment is present, the URI tenant equals the route
        ``tenant``, the NHI exists in the registry with ``svid_issued`` set,
        and the registered SPIFFE matches the presented one exactly.
      * The target ``(tenant, server)`` must have an ACTIVE capability
        envelope (durable registry) — un-onboarded servers deny.
      * Registry / envelope store unavailable → 503 (deny, fail-closed).

    Denies are audited (``MCP_INGRESS_DENIED``); allows are data-plane volume
    and stay in app logs at DEBUG.
    """
    # 0. Route params must be sane slugs (they come from the generated snippet,
    #    but validate anyway — zero-trust on our own config surface).
    if not _VERIFY_MCP_SLUG_RE.match(tenant) or not _VERIFY_MCP_SLUG_RE.match(server):
        raise _verify_mcp_deny(
            status.HTTP_403_FORBIDDEN, "invalid_target", "", tenant, server,
        )

    # 1. Subject identity — Caddy-set from the VERIFIED peer cert (see above).
    #    x-spiffe-id-peer-cert (this hop's own TLS peer = Caddy) is not the
    #    subject; the wrap's verified client rides in x-spiffe-id.
    subject = request.headers.get("x-spiffe-id", "").strip()
    if not subject:
        raise _verify_mcp_deny(
            status.HTTP_401_UNAUTHORIZED, "no_spiffe_id", "", tenant, server,
        )

    from yashigani.identity.trust_domain import (
        parse_agent_spiffe_uri,
        trust_domain,
    )

    # 2a. Broker transport identity (gateway mesh leaf) — allowed.
    if subject == f"spiffe://{trust_domain()}/gateway":
        _log.debug(
            "verify-mcp: ALLOW gateway transport tenant=%r server=%r",
            tenant, server,
        )
    # 2a-ii. Backoffice transport identity (v4.1 §2.5) — allowed ONLY toward
    # the bundled langflow front in this install's tenant (closed allowlist,
    # _VERIFY_MCP_BACKOFFICE_ALLOWED_SERVERS).  Any other target keeps the
    # deny (fail-closed).  Step 3's envelope requirement still applies.
    elif subject == f"spiffe://{trust_domain()}/backoffice":
        if (
            server not in _VERIFY_MCP_BACKOFFICE_ALLOWED_SERVERS
            or tenant != _verify_mcp_install_tenant()
        ):
            raise _verify_mcp_deny(
                status.HTTP_403_FORBIDDEN, "transport_subject_not_allowed",
                subject, tenant, server,
            )
        _log.debug(
            "verify-mcp: ALLOW backoffice transport tenant=%r server=%r",
            tenant, server,
        )
    else:
        # 2b. Per-instance agent identity (Nico's contract, GAP-1).
        parsed_subject = parse_agent_spiffe_uri(subject)
        if parsed_subject is None:
            # Foreign trust domain or not under /agents/ — reject-foreign exact.
            raise _verify_mcp_deny(
                status.HTTP_403_FORBIDDEN, "foreign_identity",
                subject, tenant, server,
            )
        subj_tenant, _subj_name, subj_instance = parsed_subject
        if not subj_instance:
            # Legacy 2-segment URI — per-instance identity is REQUIRED at the
            # wrap (two same-named agents must not share an ingress identity).
            raise _verify_mcp_deny(
                status.HTTP_403_FORBIDDEN, "legacy_identity",
                subject, tenant, server,
            )
        if subj_tenant != tenant:
            raise _verify_mcp_deny(
                status.HTTP_403_FORBIDDEN, "cross_tenant",
                subject, tenant, server,
            )

        registry = backoffice_state.agent_registry
        if registry is None:
            # Fail-closed: cannot corroborate the identity → deny, not allow.
            raise _verify_mcp_deny(
                status.HTTP_503_SERVICE_UNAVAILABLE, "registry_unavailable",
                subject, tenant, server,
            )
        nhi = registry.get(subj_instance)
        if nhi is None or nhi.get("kind") != "nhi":
            raise _verify_mcp_deny(
                status.HTTP_403_FORBIDDEN, "nhi_not_found",
                subject, tenant, server,
            )
        if not nhi.get("svid_issued"):
            raise _verify_mcp_deny(
                status.HTTP_403_FORBIDDEN, "nhi_not_approved",
                subject, tenant, server,
            )
        registered_spiffe = (nhi.get("spiffe_id") or "").strip()
        if registered_spiffe != subject:
            # The presented (cert-verified) URI must match the registered
            # identity byte-for-byte — a valid mesh cert for a DIFFERENT
            # instance must not authorise this one.
            raise _verify_mcp_deny(
                status.HTTP_403_FORBIDDEN, "spiffe_mismatch",
                subject, tenant, server,
            )

    # 3. Target must be onboarded: ACTIVE capability envelope for
    #    (tenant, server) in the durable registry.
    try:
        svc = _verify_mcp_envelope_service()
        rec = await svc.get_active_envelope(f"{tenant}:{server}")
    except Exception as exc:  # noqa: BLE001 — store down ⇒ deny, never allow
        _log.error("verify-mcp: envelope store unavailable: %s", exc)
        raise _verify_mcp_deny(
            status.HTTP_503_SERVICE_UNAVAILABLE, "envelope_store_unavailable",
            subject, tenant, server,
        )
    if rec is None or rec.tenant_id != tenant:
        raise _verify_mcp_deny(
            status.HTTP_403_FORBIDDEN, "server_not_onboarded",
            subject, tenant, server,
        )

    _log.debug(
        "verify-mcp: ALLOW subject=%r tenant=%r server=%r envelope_id=%d",
        subject, tenant, server, rec.id,
    )
    from starlette.responses import Response as StarletteResponse
    resp = StarletteResponse(status_code=200)
    # Copied upstream by Caddy's forward_auth copy_headers if configured;
    # also useful in access logs.
    resp.headers["X-Yashigani-Mcp-Caller"] = subject
    resp.headers["X-Yashigani-Mcp-Envelope"] = str(rec.id)
    return resp


# ---------------------------------------------------------------------------
# v4.1 Phase 2b — /auth/verify-webhook: forward_auth gate for openclaw webhook
# ingress (Caddyfile.openclaw-webhooks / LAURA-I1-03 / FP-05).
# ---------------------------------------------------------------------------

_SLACK_SIG_RE = re.compile(r"^v0=[0-9a-f]{64}$")
_WEBHOOK_RATE_IP_LIMIT = 60        # per-IP per 60s
_WEBHOOK_RATE_GLOBAL_LIMIT = 300   # global per 60s
_WEBHOOK_RATE_WINDOW = 60          # seconds
_WEBHOOK_REPLAY_TTL = 600          # Slack sig replay-dedup window (seconds)
_TELEGRAM_SECRET_PATH = "/run/secrets/openclaw_telegram_webhook_secret"


def _webhook_audit_deny(provider: str, reason: str, client_ip: str) -> None:
    """Best-effort WEBHOOK_INGRESS_DENIED audit write (never raises)."""
    aw = backoffice_state.audit_writer
    if aw is None:
        return
    try:
        from yashigani.audit.schema import WebhookIngressDeniedEvent
        aw.write(WebhookIngressDeniedEvent(
            provider=provider,
            reason=reason,
            client_ip=client_ip,
        ))
    except Exception as exc:  # noqa: BLE001 — audit must never mask the deny
        _log.error("verify-webhook: WEBHOOK_INGRESS_DENIED audit write failed: %s", exc)


def _webhook_deny(status_code: int, reason: str, provider: str, client_ip: str):
    """Audit + build deny response for verify-webhook."""
    _webhook_audit_deny(provider, reason, client_ip)
    _log.warning(
        "verify-webhook: DENY reason=%s provider=%r ip=%s",
        reason, provider, client_ip,
    )
    from fastapi import HTTPException as _HTTPException
    raise _HTTPException(
        status_code=status_code,
        detail={"error": reason},
        headers={"X-Authz-Reason": reason},
    )


def _webhook_rate_check(client_ip: str, provider: str) -> None:
    """Per-IP + global rate-limit via Redis (fail-closed: 429 on Redis error)."""
    try:
        r = _get_throttle_redis()
        import time as _time
        _now = int(_time.time())
        _window = _now // _WEBHOOK_RATE_WINDOW
        ip_key = f"webhook:rate:ip:{client_ip}:{_window}"
        global_key = f"webhook:rate:global:{_window}"
        pipe = r.pipeline()
        pipe.incr(ip_key)
        pipe.expire(ip_key, _WEBHOOK_RATE_WINDOW + 5)
        pipe.incr(global_key)
        pipe.expire(global_key, _WEBHOOK_RATE_WINDOW + 5)
        results = pipe.execute()
        ip_count = int(results[0])
        global_count = int(results[2])
        if ip_count > _WEBHOOK_RATE_IP_LIMIT:
            _webhook_deny(429, "rate_limit_ip", provider, client_ip)
        if global_count > _WEBHOOK_RATE_GLOBAL_LIMIT:
            _webhook_deny(429, "rate_limit_global", provider, client_ip)
    except Exception as exc:  # noqa: BLE001 — Redis down → fail-closed
        _log.error("verify-webhook: rate-limit Redis unavailable — denying: %s", exc)
        from fastapi import HTTPException as _HTTPException
        raise _HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "rate_limit_store_unavailable"},
        )


def _slack_replay_dedup(sig: str, provider: str, client_ip: str) -> None:
    """SETNX sha256(X-Slack-Signature) with TTL=600s; duplicate → 401."""
    from fastapi import HTTPException as _HTTPException
    import hashlib as _hashlib
    sig_hash = _hashlib.sha256(sig.encode("utf-8")).hexdigest()
    try:
        r = _get_throttle_redis()
        replay_key = f"webhook:slack:replay:{sig_hash}"
        inserted = r.setnx(replay_key, "1")
        if inserted:
            r.expire(replay_key, _WEBHOOK_REPLAY_TTL)
        else:
            _webhook_deny(401, "slack_replay_detected", provider, client_ip)
    except _HTTPException:
        raise  # deny decisions must propagate, not be masked as 503
    except Exception as exc:  # noqa: BLE001 — Redis down → fail-closed
        _log.error("verify-webhook: replay-dedup Redis unavailable — denying: %s", exc)
        raise _HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "replay_store_unavailable"},
        )


@router.get("/verify-webhook")
async def verify_webhook_ingress(request: Request, provider: str = ""):
    """
    Caddy forward_auth gate for openclaw inbound webhooks (v4.1 Phase 2b,
    LAURA-I1-03 / FP-05; contract in Caddyfile.openclaw-webhooks header).

    Fail-closed at every step — any missing or malformed header is 401; any
    store unavailability is 503.  Caddy treats any non-2xx as DENY.

    Layer-B HMAC (X-Caddy-Verified-Secret):
      CaddyVerifiedMiddleware already enforces this globally for ALL backoffice
      routes — a direct public call to this endpoint without the per-install
      secret is 401 before reaching this handler.

    Step 0: X-Forwarded-Method must be POST (Caddy sets this on the subrequest).
    Step 1: provider must be "slack" or "telegram".
    Step 2 (slack): timestamp freshness (±300s) + signature shape + replay dedupe.
    Step 2 (telegram): constant-time compare of X-Telegram-Bot-Api-Secret-Token
                       against /run/secrets/openclaw_telegram_webhook_secret.
    Step 3: per-IP + global rate-limit buckets in Redis.
    Step 4: audit every deny (WEBHOOK_INGRESS_DENIED).

    Body-MAC split (Caddyfile.openclaw-webhooks §76-85):
      Caddy's forward_auth strips the body → full Slack HMAC (v0:ts:body) lives
      with openclaw's Slack SDK channel integration.  This gate enforces:
        * freshness (timestamp window guards replay without the body), and
        * exact-replay dedupe (deterministic MAC over v0:ts:body makes the sig
          a unique per-request token within the freshness window).
      Telegram token verification is COMPLETE here (no body dependency).
    """
    import hmac as _hmac
    import time as _time

    client_ip = _real_client_ip(request)

    # Step 0 — method check (forward_auth sets X-Forwarded-Method)
    fwd_method = request.headers.get("x-forwarded-method", "").strip().upper()
    if fwd_method != "POST":
        _webhook_deny(401, "method_not_post", provider, client_ip)

    # Step 1 — provider validation
    if provider not in ("slack", "telegram"):
        _webhook_deny(401, "unknown_provider", provider or "", client_ip)

    # Step 3 — rate-limit (early, before doing crypto work on attacker input)
    _webhook_rate_check(client_ip, provider)

    if provider == "slack":
        # Step 2a — Slack: timestamp freshness
        ts_raw = request.headers.get("x-slack-request-timestamp", "").strip()
        if not ts_raw:
            _webhook_deny(401, "slack_timestamp_missing", provider, client_ip)
        try:
            ts = int(ts_raw)
        except ValueError:
            _webhook_deny(401, "slack_timestamp_invalid", provider, client_ip)
        now = int(_time.time())
        if abs(now - ts) > 300:
            _webhook_deny(401, "slack_timestamp_stale", provider, client_ip)

        # Step 2b — Slack: signature shape (v0=<64 hex>)
        sig = request.headers.get("x-slack-signature", "").strip()
        if not sig:
            _webhook_deny(401, "slack_signature_missing", provider, client_ip)
        if not _SLACK_SIG_RE.match(sig):
            _webhook_deny(401, "slack_signature_malformed", provider, client_ip)

        # Step 2c — Slack: replay dedup (SETNX sha256(sig) TTL 600s)
        _slack_replay_dedup(sig, provider, client_ip)

    else:  # telegram
        # Step 2 — Telegram: constant-time token compare
        presented = request.headers.get("x-telegram-bot-api-secret-token", "")
        if not presented:
            _webhook_deny(401, "telegram_token_missing", provider, client_ip)
        try:
            expected = open(_TELEGRAM_SECRET_PATH).read().strip()  # noqa: WPS515
        except OSError as exc:
            _log.error(
                "verify-webhook: cannot read Telegram webhook secret at %r: %s — "
                "denying (fail-closed; mount the secret in install.sh)",
                _TELEGRAM_SECRET_PATH, exc,
            )
            from fastapi import HTTPException as _HTTPException
            raise _HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "telegram_secret_unavailable"},
            )
        if not _hmac.compare_digest(presented, expected):
            _webhook_deny(401, "telegram_token_mismatch", provider, client_ip)

    _log.debug("verify-webhook: ALLOW provider=%r ip=%s", provider, client_ip)
    from starlette.responses import Response as StarletteResponse
    return StarletteResponse(status_code=200)


@router.post("/password/change")
async def change_password(
    body: PasswordChangeRequest,
    session: AnySession,
    response: Response,
    store=Depends(get_session_store),
):
    """Force-change password. Invalidates ALL sessions (ASVS V2.1.4)."""
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    # Find account by account_id
    record = await _get_record_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "account_not_found"})

    from yashigani.auth.password import verify_password, hash_password, PasswordBreachedError

    if not verify_password(body.current_password, record.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "invalid_current_password"})

    old_hash = record.password_hash
    old_hash_tail = old_hash[-8:] if old_hash else ""
    try:
        new_hash = hash_password(body.new_password)
    except PasswordBreachedError as exc:
        # ASVS V2.1.7: breached passwords are rejected with a clear user-facing message.
        # 422 Unprocessable Entity — the request is structurally valid but semantically rejected.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "password_breached",
                "message": str(exc),
            },
        )
    except (ValueError, TypeError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "password_rejected"})
    new_hash_tail = new_hash[-8:]

    # -- CMMC L2 IA.L2-3.5.8: password reuse history check ------------------
    from yashigani.auth.local_auth import _get_history_depth
    from yashigani.auth.password import verify_password as _verify_pw

    history_depth = _get_history_depth()
    async with _pg_tenant_transaction() as conn:
        _history_rows = await conn.fetch(
            """
            SELECT password_hash FROM password_history
            WHERE user_id = $1::uuid
            ORDER BY changed_at DESC
            LIMIT $2
            """,
            record.account_id,
            history_depth,
        )
    for _hr in _history_rows:
        if _verify_pw(body.new_password, _hr["password_hash"]):
            # Emit audit event — user_id only, never password or hash.
            from yashigani.audit.schema import PasswordReuseRejectedEvent

            try:
                _evt = PasswordReuseRejectedEvent(
                    user_id=record.account_id,
                    history_depth_checked=history_depth,
                )
                state.audit_writer.write(_evt)
            except Exception:
                _log.warning("Failed to emit PASSWORD_REUSE_REJECTED event", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "password_reuse",
                    "message": (
                        f"Password has been used recently. "
                        f"Choose a password not used in the last {history_depth} change(s)."
                    ),
                },
            )

    # -- Durable update via Postgres -----------------------------------------
    import datetime as _dt

    _now_ts = _dt.datetime.now(_dt.timezone.utc)
    _now_epoch = _now_ts.timestamp()
    async with _pg_tenant_transaction() as conn:
        await conn.execute(
            "UPDATE admin_accounts SET "
            "password_hash = $1, force_password_change = false, "
            "password_changed_at = $2 WHERE username = $3",
            new_hash,
            _now_epoch,
            record.username,
        )
        # Record old hash in history.
        await conn.execute(
            """
            INSERT INTO password_history (user_id, password_hash, changed_at)
            VALUES ($1::uuid, $2, $3)
            ON CONFLICT (user_id, changed_at) DO NOTHING
            """,
            record.account_id,
            old_hash,
            _now_ts,
        )
        # Prune oldest beyond depth.
        await conn.execute(
            """
            DELETE FROM password_history
            WHERE user_id = $1::uuid
              AND changed_at NOT IN (
                  SELECT changed_at FROM password_history
                  WHERE user_id = $1::uuid
                  ORDER BY changed_at DESC
                  LIMIT $2
              )
            """,
            record.account_id,
            history_depth,
        )
    record.password_hash = new_hash
    record.force_password_change = False
    record.password_changed_at = _now_epoch

    # Invalidate ALL sessions including current (ASVS V2.1.4)
    store.invalidate_all_for_account(session.account_id)
    # WA-10: clear BOTH cookie slots with proper __Host- attributes.
    # The previous call only cleared the admin cookie and omitted Secure.
    _clear_session_cookie(response, _SESSION_COOKIE)
    _clear_session_cookie(response, _USER_SESSION_COOKIE)

    # ACS gap #95 (auth_log): dedicated PASSWORD_CHANGED event replaces the
    # generic ConfigChangedEvent, providing cleaner forensic queries.
    # ASVS 6.3.7: hash tails for forensics / reuse detection.
    state.audit_writer.write(
        _make_password_changed_event(
            record.username,
            change_type="forced" if record.force_password_change else "self_service",
            old_hash_tail=old_hash_tail,
            new_hash_tail=new_hash_tail,
            account_tier=record.account_tier,
        )
    )
    # ACS gap #95 (auth_log): SESSIONS_INVALIDATED event for session lifecycle audit.
    state.audit_writer.write(
        _make_sessions_invalidated_event(
            admin_account=record.username,
            acting_admin="",  # self-service password change
            reason="password_change",
            account_tier=record.account_tier,
        )
    )
    return {"status": "ok", "sessions_invalidated": True, "re_authentication_required": True}


@router.post("/totp/provision/start")
async def provision_totp_start(
    session: AnySession,
):
    """
    Start TOTP enrolment for the current account.

    Generates a fresh TOTP seed + recovery codes and returns the QR code
    + provisioning URI for the client to display. Does NOT clear
    ``force_totp_provision`` — the account cannot complete authenticated
    actions until :func:`provision_totp_confirm` verifies a code derived
    from the returned seed.

    Part of the split-enrolment flow (QA Wave 2 Issue C). The previous
    atomic ``/totp/provision`` required a ``totp_code`` on the same call
    that returned the seed, which was impossible for a first-time client.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    record = await _get_record_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})

    if record.totp_secret and not record.force_totp_provision:
        # YSG-RISK-082: re-provisioning an already-enrolled authenticator
        # requires a fresh step-up — blocks a hijacked session from silently
        # rotating TOTP and locking out the legitimate owner.
        from yashigani.auth.stepup import assert_fresh_stepup

        assert_fresh_stepup(session)

    prov, _code_set = await state.auth_service.provision_totp_start(record.username)

    # Phase 13: include algorithm and digit count in the response so the client
    # can display role-appropriate instructions.
    _digit_word = f"{prov.digits}-digit"
    _algo_note = (
        "IMPORTANT: Classic Google Authenticator (SHA-1 only) is not compatible "
        "with this account's TOTP tier. Use agnosticOTP (iOS/Android), Aegis, "
        "or any authenticator that reads the 'algorithm' field from the "
        "otpauth:// URI."
    )

    return {
        "status": "pending_confirmation",
        "qr_code_png_b64": prov.qr_code_png_b64,
        "provisioning_uri": prov.provisioning_uri,
        "recovery_codes": prov.recovery_codes,  # shown once — client must acknowledge
        "recovery_codes_count": len(prov.recovery_codes),
        "totp_algorithm": prov.algorithm,
        "totp_digits": prov.digits,
        "message": (
            f"Scan the QR code with agnosticOTP or a compatible authenticator app, "
            f"then POST the current {_digit_word} code to "
            f"/auth/totp/provision/confirm to complete enrolment. "
            f"Store the recovery codes securely — they will not be shown again. "
            f"{_algo_note}"
        ),
    }


@router.post("/totp/provision/confirm")
async def provision_totp_confirm(
    body: TotpConfirmRequest,
    session: AnySession,
):
    """
    Finalise TOTP enrolment by confirming a code generated from the seed
    returned by :func:`provision_totp_start`.

    On success the account is fully enrolled
    (``force_totp_provision=False``). On failure the seed is preserved
    so the client can retry without losing the QR code / recovery codes
    (protects against time-drift and typo retries).
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    record = await _get_record_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})

    if record.totp_secret and not record.force_totp_provision:
        # YSG-RISK-082: confirming a re-provision against an already-enrolled
        # authenticator requires a fresh step-up.
        from yashigani.auth.stepup import assert_fresh_stepup

        assert_fresh_stepup(session)

    ok, reason = await state.auth_service.provision_totp_confirm(record.username, body.totp_code)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": reason,
                "message": (
                    "TOTP code did not match the seed issued by "
                    "/auth/totp/provision/start. Ensure your authenticator "
                    "app clock is synchronised and retry with a fresh code."
                ),
            },
        )

    state.audit_writer.write(_make_provision_event(record.username, account_tier=record.account_tier))

    return {"status": "ok", "message": "TOTP enrolment complete."}


@router.post("/totp/provision")
async def provision_totp(
    body: TotpConfirmRequest,
    session: AnySession,
    response: Response,
):
    """
    Atomic TOTP enrolment — back-compat for clients that already hold
    the seed (e.g. CLI provisioning flows where the secret is delivered
    out-of-band). Generates a fresh seed, verifies the provided code
    against it, and on success commits the enrolment in one call.

    For the first-time web-UI flow, prefer the split endpoints:
    :func:`provision_totp_start` + :func:`provision_totp_confirm`
    (QA Wave 2 Issue C).
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup
    record = await _get_record_by_id(session.account_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"error": "account_not_found"})

    if record.totp_secret and not record.force_totp_provision:
        # YSG-RISK-082: atomic re-provision of an already-enrolled
        # authenticator requires a fresh step-up.
        from yashigani.auth.stepup import assert_fresh_stepup

        assert_fresh_stepup(session)

    prov, _code_set = await state.auth_service.provision_totp_start(record.username)

    # Verify the user-supplied code against the freshly-stored seed.
    ok, reason = await state.auth_service.provision_totp_confirm(record.username, body.totp_code)
    if not ok:
        # Rollback — clear the newly-set seed in the durable store so the
        # account is back to its pre-call state and the client can retry
        # cleanly.
        await state.auth_service.force_totp_reprovision(record.username)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_totp_code", "message": "TOTP code did not match. Re-scan the QR code."},
        )

    state.audit_writer.write(_make_provision_event(record.username, account_tier=record.account_tier))

    return {
        "status": "ok",
        "qr_code_png_b64": prov.qr_code_png_b64,
        "provisioning_uri": prov.provisioning_uri,
        "recovery_codes": prov.recovery_codes,  # shown once — client must acknowledge
        "recovery_codes_count": len(prov.recovery_codes),
        "message": "Store these recovery codes securely. They will not be shown again.",
    }


# ---------------------------------------------------------------------------
# Step-up TOTP verification (ASVS V6.8.4)
# ---------------------------------------------------------------------------


class StepUpRequest(BaseModel):
    # Phase 13: accept 6 (user) or 8 (admin) digit codes.
    totp_code: str = Field(min_length=6, max_length=8, pattern=r"^\d{6,8}$")


@router.post("/stepup")
async def stepup_verify(
    body: StepUpRequest,
    session: AnySession,
    store=Depends(get_session_store),
):
    """
    Step-up TOTP verification for high-value flows (ASVS V6.8.4).

    Accepts any authenticated session (admin OR regular user) so that
    user-tier accounts can satisfy the assert_fresh_stepup prerequisite
    required by POST /me/api-key.  Anonymous and expired sessions are
    rejected by the AnySession dependency before this handler runs.

    The caller submits their current TOTP code.  On success, the session's
    last_totp_verified_at is updated.  The caller may then retry the
    high-value endpoint that returned step_up_required.  The verification
    window is YASHIGANI_STEPUP_TTL_SECONDS (default 300 s / 5 min).

    Security guarantees:
    - Replay prevention: codes are checked against the Postgres-backed
      used_totp_codes table (same mechanism as login TOTP).
    - Wrong code: 401, session is NOT updated, TOTP failure counter is
      incremented on the session prefix.
    - No credential enumeration: same HTTP 401 body for wrong code or
      no session.
    - Cross-tenant isolation: account is resolved by session.account_id
      against the platform DB; a session with a fabricated/wrong-tenant
      account_id will find no record → 403 totp_not_configured.
    - Tier scope: widened from admin-only to any-session. Admin step-up
      semantics (audit events, replay cache, failure counter) are identical.
    """
    state = backoffice_state
    assert state.auth_service is not None  # set unconditionally at startup
    assert state.audit_writer is not None  # set unconditionally at startup

    # Resolve the admin record to get the TOTP secret.
    admin_record = await state.auth_service.get_account_by_id(session.account_id)
    if admin_record is None or not admin_record.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "totp_not_configured"},
        )

    # Check per-session step-up failure counter.
    # SEC-4 / ASVS V6.3.5: migrated from module-level dict to Redis so the
    # counter survives process restarts and is consistent across replicas.
    session_prefix = session.token[:8]
    try:
        failure_count = _totp_get_count(session_prefix)
    except Exception as exc:
        # Redis unavailable — fail-closed per SOP 1 (no silent allow).
        _log.error("SEC-4: Redis unavailable for TOTP step-up counter check: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "totp_service_unavailable",
                "message": "Authentication service temporarily unavailable.",
            },
        )

    if failure_count >= _TOTP_FAILURE_LIMIT:
        # Emit lockout audit event with full forensic context.
        from yashigani.audit.schema import AdminSessionTotpLockoutEvent
        state.audit_writer.write(
            AdminSessionTotpLockoutEvent(
                account_tier=admin_record.account_tier,
                admin_account=admin_record.username,
                endpoint="/auth/stepup",
                consecutive_failures=failure_count,
            )
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "stepup_attempts_exceeded",
                "message": "Too many failed step-up attempts. Please log out and log in again.",
            },
        )

    # Verify against Postgres-backed replay cache (same path as login).
    # Phase 13: pass the account's enrolled algorithm and role digit count.
    from yashigani.auth.totp import ROLE_TOTP_DIGITS as _ROLE_TOTP_DIGITS
    _stepup_digits = _ROLE_TOTP_DIGITS.get(admin_record.account_tier, 6)
    async with _pg_tenant_transaction() as conn:
        ok = await state.auth_service._verify_totp_with_replay(
            conn,
            admin_record.totp_secret,
            body.totp_code,
            algorithm=admin_record.totp_algorithm,
            digits=_stepup_digits,
        )

    if not ok:
        try:
            _totp_incr_failure(session_prefix)
        except Exception as exc:
            _log.error("SEC-4: Redis unavailable for TOTP failure increment: %s", exc)
            # Still reject the bad TOTP code even if we can't count it.
            # (fail-closed on the auth result; counter loss is the lesser evil)
        state.audit_writer.write(_make_stepup_event(admin_record.username, "failure", admin_record.account_tier))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "invalid_totp_code",
                "hint": "Ensure your device clock is synchronised.",
            },
        )

    # Success — record step-up timestamp in Redis session, clear failure counter.
    try:
        _totp_reset(session_prefix)
    except Exception as exc:
        _log.warning("SEC-4: Redis unavailable for TOTP counter reset: %s", exc)
        # Non-fatal: successful auth proceeds; counter will expire via TTL.
    store.record_totp_stepup(session.token)
    state.audit_writer.write(_make_stepup_event(admin_record.username, "success", admin_record.account_tier))

    from yashigani.auth.stepup import STEPUP_TTL_SECONDS

    return {
        "status": "ok",
        "stepup_verified": True,
        "ttl_seconds": STEPUP_TTL_SECONDS,
        "message": "Step-up verified. You may now retry the high-value action.",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_USER_SESSION_COOKIE = "__Host-yashigani_session"


def _set_session_cookie(response: Response, token: str, account_tier: str = "admin") -> None:
    if account_tier == "admin":
        response.set_cookie(
            key=_SESSION_COOKIE,
            value=token,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=14400,  # 4 hours absolute
            path="/",  # __Host- prefix requires Path=/
        )
        # RISK-100 SoD: admins get ONLY the admin-plane cookie. OWUI is removed in
        # 4.0, so the legacy "always set the user cookie for forward_auth" line is
        # dead — and issuing a user-plane cookie to an admin let the admin session
        # pass the /chat presence gate and load the user UI. Admins must not hold a
        # user-plane session at all.
        return
    # User / totp_provisioning tiers get ONLY the user-plane cookie.
    response.set_cookie(
        key=_USER_SESSION_COOKIE,
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=14400,
        path="/",
    )


def _clear_session_cookie(response: Response, name: str) -> None:
    """Clear a __Host- prefixed session cookie, symmetric with _set_session_cookie.

    The __Host- cookie prefix mandates that EVERY Set-Cookie directive for that
    cookie — including clearance (Max-Age=0) — carries Secure=True and Path=/.
    Starlette/FastAPI's Response.delete_cookie() does NOT include Secure by
    default, so a bare delete_cookie() call produces:

        Set-Cookie: __Host-yashigani_admin_session=""; Max-Age=0; Path=/; SameSite=lax

    Browsers validate the __Host- prefix constraints on the clearance response
    exactly as they do on the original Set-Cookie, and silently ignore the
    Max-Age=0 when Secure is absent — leaving the original valid token in place.

    This helper mirrors the exact attribute set used by _set_session_cookie so
    the two paths are always in lockstep and cannot drift independently.
    (WA-10 / ASVS V3.4.1 / RFC 6265bis §4.1.3)
    """
    response.set_cookie(
        key=name,
        value="",
        max_age=0,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )


# ---------------------------------------------------------------------------
# Admin IP access control — blocklist + allowlist (fail2ban-style)
# ---------------------------------------------------------------------------
# LU-AMEND-04: Operator identity attestation token for yashigani onboard
# ---------------------------------------------------------------------------

# Short-lived operator token TTL: 15 minutes. Enough for a single onboard
# ceremony; short enough to minimise the value of a leaked token.
_OPERATOR_TOKEN_TTL_SECONDS: int = int(os.getenv("YASHIGANI_OPERATOR_TOKEN_TTL", "900"))


class OperatorTokenRequest(BaseModel):
    """Request body for POST /auth/operator-token."""

    issued_for: str = Field(
        default="",
        max_length=256,
        description="Optional free-text note describing the onboard ceremony (e.g. agent name).",
    )


@router.post("/operator-token")
async def issue_operator_token(
    body: OperatorTokenRequest,
    session: AdminSession,
    request: Request,
):
    """
    Issue a short-lived operator identity token for use with `yashigani onboard`.

    Prerequisites:
      - Active admin session (AdminSession dependency — cookie auth).
      - Fresh step-up TOTP (assert_fresh_stepup — within YASHIGANI_STEPUP_TTL_SECONDS).

    Returns a signed JWT with:
      - sub:  admin username (the issuing operator identity)
      - jti:  UUID4 (enables cross-correlation in the audit log)
      - iat:  issued-at (Unix timestamp)
      - exp:  expiry = iat + _OPERATOR_TOKEN_TTL_SECONDS
      - iss:  "yashigani.backoffice"
      - purpose: "operator-onboard"

    Security invariants:
      - Step-up required: prevents a hijacked session from silently issuing tokens.
      - Token is signed with HS256 using the caddy_internal_hmac (already available
        at runtime via /run/secrets/caddy_internal_hmac).
      - The token value is NEVER written to the audit log — only the jti and TTL.
      - Verify endpoint: GET /auth/operator-token/verify (used by the CLI).

    ASVS V7.2.1 + NIST IA-2/AU-3 + CMMC IA.L2-3.5.1/3 + SOC 2 CC6.1
    + ISO 27001 A.5.16/A.5.17 / LU-AMEND-04.
    """
    from yashigani.auth.stepup import assert_fresh_stepup

    assert_fresh_stepup(session)

    state = backoffice_state
    assert state.auth_service is not None
    assert state.audit_writer is not None

    admin_record = await state.auth_service.get_account_by_id(session.account_id)
    if admin_record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    import uuid
    import time as _time

    import jwt as _pyjwt

    # Signing key: reuse caddy_internal_hmac (already a 32+ byte secret at runtime).
    # Fail closed if the secret file is not readable.
    _hmac_path = "/run/secrets/caddy_internal_hmac"
    try:
        with open(_hmac_path) as _f:
            _signing_key = _f.read().strip()
    except OSError:
        _log.error("LU-AMEND-04: cannot read %s — operator-token issuance refused", _hmac_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "signing_key_unavailable"},
        )

    _jti = str(uuid.uuid4())
    _now = int(_time.time())
    _payload = {
        "sub": admin_record.username,
        "jti": _jti,
        "iat": _now,
        "exp": _now + _OPERATOR_TOKEN_TTL_SECONDS,
        "iss": "yashigani.backoffice",
        "purpose": "operator-onboard",
        "issued_for": body.issued_for[:256],
    }
    _token = _pyjwt.encode(_payload, _signing_key, algorithm="HS256")

    from yashigani.audit.schema import OperatorTokenIssuedEvent

    state.audit_writer.write(
        OperatorTokenIssuedEvent(
            admin_account=admin_record.username,
            token_jti=_jti,
            token_ttl_seconds=_OPERATOR_TOKEN_TTL_SECONDS,
            issued_for=body.issued_for[:256],
        )
    )

    _log.info(
        "LU-AMEND-04: operator token issued by %s jti=%s ttl=%ds issued_for=%r",
        admin_record.username,
        _jti,
        _OPERATOR_TOKEN_TTL_SECONDS,
        body.issued_for[:64],
    )

    return {
        "token": _token,
        "jti": _jti,
        "expires_in": _OPERATOR_TOKEN_TTL_SECONDS,
        "token_type": "Bearer",
        "purpose": "operator-onboard",
    }


@router.get("/operator-token/verify")
async def verify_operator_token(
    request: Request,
):
    """
    Verify an operator onboard token presented in the Authorization header.

    Used by `yashigani onboard --token <tok>` to validate the token before
    proceeding with the onboard ceremony.  The CLI POSTs the agent registration
    only after this endpoint returns 200.

    Authorization: Bearer <token>

    Returns 200 + {sub, jti, exp, issued_for} on success.
    Returns 401 on invalid/expired/wrong-purpose token.
    Returns 400 if the header is absent or malformed.

    Security invariants:
      - This endpoint does NOT require an admin session cookie — it is the
        bearer-token validation surface for headless CLI callers.
      - The endpoint is on the internal backoffice path (:8443) — it is NOT
        reachable from the public Caddy edge without admin session + mTLS.
      - No audit event emitted here (verify is low-value; ONBOARD_ATTEMPTED
        in the CLI captures the full ceremony outcome).

    LU-AMEND-04 / v2.24.1.
    """
    import jwt as _pyjwt

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "missing_bearer_token"},
        )
    _raw_token = auth_header[len("Bearer "):].strip()

    _hmac_path = "/run/secrets/caddy_internal_hmac"
    try:
        with open(_hmac_path) as _f:
            _signing_key = _f.read().strip()
    except OSError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "signing_key_unavailable"},
        )

    try:
        _payload = _pyjwt.decode(
            _raw_token,
            _signing_key,
            algorithms=["HS256"],
            options={"require": ["sub", "jti", "exp", "iat", "iss", "purpose"]},
        )
    except _pyjwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "token_expired"},
        )
    except _pyjwt.InvalidTokenError as _e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token", "detail": str(_e)},
        )

    if _payload.get("purpose") != "operator-onboard":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "wrong_token_purpose"},
        )
    if _payload.get("iss") != "yashigani.backoffice":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "wrong_token_issuer"},
        )

    return {
        "valid": True,
        "sub": _payload["sub"],
        "jti": _payload["jti"],
        "exp": _payload["exp"],
        "issued_for": _payload.get("issued_for", ""),
    }


# ---------------------------------------------------------------------------
# MI-4 (YSG-RISK-061): privileged-mutation step-up PROOF token mint
#
# The headless counterpart of the in-session step-up gate.  After a fresh TOTP
# step-up, an operator mints a short-lived proof token bound to a specific
# destructive lifecycle op (e.g. "add-component"), then hands it to install.sh
# (--stepup-token).  install.sh verifies it against the SAME shared gate
# (auth.stepup.verify_stepup_proof) before mutating a running stack.
#
# Prereqs: AdminSession + fresh step-up (assert_fresh_stepup) — a hijacked
# session that has not re-proven TOTP cannot mint a proof.
# ---------------------------------------------------------------------------


class StepUpProofRequest(BaseModel):
    """Request body for POST /auth/stepup-proof."""

    op: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
        description="Lifecycle op the proof authorises, e.g. 'add-component'.",
    )


@router.post("/stepup-proof")
async def issue_stepup_proof(
    body: StepUpProofRequest,
    session: AdminSession,
):
    """
    Mint a privileged-mutation step-up proof token (MI-4 / YSG-RISK-061).

    Prerequisites:
      - Active admin session (AdminSession dependency — cookie auth).
      - Fresh step-up TOTP (assert_fresh_stepup — within YASHIGANI_STEPUP_TTL_SECONDS).

    The proof is an HS256 JWT (signed with caddy_internal_hmac, the same per-install
    key the gate verifies with) carrying purpose="privileged-mutation" and the
    bound op label.  TTL = YASHIGANI_STEPUP_PROOF_TTL_SECONDS (default 300 s).

    The token is NEVER written to the audit log — only the jti + op + TTL.
    """
    from yashigani.auth.stepup import (
        assert_fresh_stepup,
        mint_stepup_proof,
        STEPUP_PROOF_TTL_SECONDS,
    )

    assert_fresh_stepup(session)

    state = backoffice_state
    assert state.auth_service is not None
    assert state.audit_writer is not None

    admin_record = await state.auth_service.get_account_by_id(session.account_id)
    if admin_record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    try:
        token, jti = mint_stepup_proof(subject=admin_record.username, op=body.op)
    except Exception as exc:  # StepUpProofInvalid(signing_key_unavailable) etc.
        _log.error("MI-4: step-up proof mint failed for %s: %s", admin_record.username, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "signing_key_unavailable"},
        )

    from yashigani.audit.schema import PrivilegedMutationEvent

    state.audit_writer.write(
        PrivilegedMutationEvent(
            reason=f"stepup_proof.mint.{body.op}",
            principal=admin_record.username,
            target=body.op,
            justification=f"jti={jti} ttl={STEPUP_PROOF_TTL_SECONDS}",
        )
    )

    _log.info(
        "MI-4: step-up proof minted by %s op=%s jti=%s ttl=%ds",
        admin_record.username, body.op, jti, STEPUP_PROOF_TTL_SECONDS,
    )

    return {
        "token": token,
        "jti": jti,
        "op": body.op,
        "expires_in": STEPUP_PROOF_TTL_SECONDS,
        "token_type": "Bearer",
        "purpose": "privileged-mutation",
    }


# ---------------------------------------------------------------------------
# LU-AMEND-04: Internal onboard audit endpoint
#
# Called by the yashigani-onboard CLI to emit an ONBOARD_ATTEMPTED event after
# verifying (or not) the operator token.  Mounted at /auth/onboard-event via
# the /auth prefix in app.py.  The full path is /auth/onboard-event.
#
# Security: requires AdminSession (session cookie from the CLI --session-cookie
# flag) + X-Caddy-Verified-Secret HMAC (same Layer B gate as all direct backoffice
# calls).  No step-up required — this is an audit-write path, not a mutation.
# ---------------------------------------------------------------------------


class OnboardEventBody(BaseModel):
    """Request body for POST /auth/onboard-event."""

    identity_quality: str = Field(
        ...,
        pattern="^(attested|weak)$",
        description="'attested' when a valid token was supplied; 'weak' otherwise.",
    )
    operator_identity: str = Field(default="unknown", max_length=256)
    token_jti: str = Field(default="", max_length=64)
    agent_name: str = Field(..., max_length=256)
    agent_url: str = Field(..., max_length=512)
    client_ip: str = Field(default="", max_length=64)


@router.post("/onboard-event")
async def record_onboard_event(
    body: OnboardEventBody,
    session: AdminSession,
):
    """
    Record an ONBOARD_ATTEMPTED audit event emitted by the yashigani-onboard CLI.

    Security invariants:
      - Requires AdminSession — callers must present a valid admin session cookie.
      - identity_quality is constrained to "attested" | "weak" by Pydantic validation.
      - Raw token values are NEVER accepted in this payload.
      - Only jti (cross-reference ID) and operator_identity (sub claim) are stored.

    LU-AMEND-04 / v2.24.1.
    """
    state = backoffice_state
    assert state.audit_writer is not None

    from yashigani.audit.schema import OnboardAttemptedEvent

    state.audit_writer.write(
        OnboardAttemptedEvent(
            identity_quality=body.identity_quality,
            operator_identity=body.operator_identity,
            token_jti=body.token_jti,
            agent_name=body.agent_name,
            agent_url=body.agent_url,
            client_ip=body.client_ip,
        )
    )

    _log.info(
        "LU-AMEND-04: ONBOARD_ATTEMPTED audit event recorded "
        "identity_quality=%s operator=%s agent=%r jti=%s",
        body.identity_quality,
        body.operator_identity,
        body.agent_name,
        body.token_jti or "(none)",
    )

    return {"status": "ok", "identity_quality": body.identity_quality}


# ---------------------------------------------------------------------------


@router.get("/blocked-ips")
async def list_blocked_ips(request: Request, session: AdminSession):
    """List permanently blocked IPs AND currently soft-throttled IPs.

    Previously only returned permanent blocks, which gave operators no
    self-visibility when they were themselves being slow-throttled
    (QA Wave 2 Issue F). Now includes:

      * ``blocked_ips`` — permanent blocks (auth:blocked:*)
      * ``throttled_ips`` — IPs with a current non-zero throttle level
        (auth:throttle:ip:* > 0), mapped to {level, delay_s, fail_count}
      * ``self`` — the caller's own IP + throttle state so an admin
        can see if they are throttled from the UI (fixes the "login
        page hangs and /auth/blocked-ips says {}" diagnostic gap)
    """
    import json

    r = _get_throttle_redis()

    # Permanent blocks (existing behaviour)
    blocked: dict = {}
    for key in r.scan_iter("auth:blocked:*"):
        ip = key.decode().split("auth:blocked:")[-1] if isinstance(key, bytes) else key.split("auth:blocked:")[-1]
        data = r.get(key)
        try:
            blocked[ip] = json.loads(data) if data else {"reason": "unknown"}
        except (json.JSONDecodeError, TypeError):
            blocked[ip] = {"reason": str(data)}

    # Soft-throttle state — every IP with a non-zero throttle level
    throttled: dict = {}
    for key in r.scan_iter("auth:throttle:ip:*"):
        key_str = key.decode() if isinstance(key, bytes) else key
        ip = key_str.split("auth:throttle:ip:")[-1]
        level_raw = r.get(key_str)
        level = int(level_raw or 0)
        if level <= 0:
            continue
        fail_raw = r.get(f"auth:fail:ip:{ip}")
        throttled[ip] = {
            "level": level,
            "delay_s": _throttle_delay_for_level(level),
            "fail_count": int(fail_raw or 0),
        }

    # Caller's own state — resolved from request headers so the admin
    # sees exactly what server-side records about their IP, even when
    # they are being throttled (non-200 paths still emit this view).
    caller_ip = _real_client_ip(request)  # LAURA-3X-001: match the throttle key written at login
    caller_level = int(r.get(f"auth:throttle:ip:{caller_ip}") or 0)
    caller_fails = int(r.get(f"auth:fail:ip:{caller_ip}") or 0)
    caller_blocked_data = r.get(f"auth:blocked:{caller_ip}")
    self_state = {
        "ip": caller_ip,
        "fail_count": caller_fails,
        "throttle_level": caller_level,
        "delay_s": _throttle_delay_for_level(caller_level) if caller_level > 0 else 0,
        "permanently_blocked": caller_blocked_data is not None,
    }

    return {
        "blocked_ips": blocked,
        "throttled_ips": throttled,
        "self": self_state,
        "total": len(blocked),
        "total_throttled": len(throttled),
    }


@router.delete("/blocked-ips/{ip}")
async def unblock_ip(ip: str, session: AdminSession):
    """Remove an IP from the permanent blocklist (admin only)."""
    r = _get_throttle_redis()
    key = f"auth:blocked:{ip}"
    if r.exists(key):
        r.delete(key)
        _log.info("Admin %s unblocked IP: %s", session.account_id, ip)
        return {"status": "ok", "unblocked": ip}
    raise HTTPException(status_code=404, detail={"error": "ip_not_found"})


@router.get("/allowed-ips")
async def list_allowed_ips(session: AdminSession):
    """List all IPs/CIDRs in the login allowlist. Empty = allow all."""
    r = _get_throttle_redis()
    entries = r.smembers("auth:allowlist")
    allowed = [e.decode() if isinstance(e, bytes) else e for e in entries]
    return {
        "allowed_ips": sorted(allowed),
        "total": len(allowed),
        "mode": "restrict" if allowed else "open (all IPs permitted)",
    }


@router.post("/allowed-ips")
async def add_allowed_ip(request: Request, session: AdminSession):
    """Add an IP or CIDR to the login allowlist. Supports IPv4 and IPv6."""
    import ipaddress

    body = await request.json()
    entry = body.get("ip", "").strip()
    if not entry:
        raise HTTPException(status_code=400, detail={"error": "ip_required"})
    # Validate IPv4/IPv6 address or network
    try:
        if "/" in entry:
            ipaddress.ip_network(entry, strict=False)
        else:
            ipaddress.ip_address(entry)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_ip", "message": f"'{entry}' is not a valid IPv4/IPv6 address or CIDR range"},
        )
    r = _get_throttle_redis()
    r.sadd("auth:allowlist", entry)
    _log.info("Admin %s added IP to allowlist: %s", session.account_id, entry)
    return {"status": "ok", "added": entry}


@router.delete("/allowed-ips/{ip_or_cidr:path}")
async def remove_allowed_ip(ip_or_cidr: str, session: AdminSession):
    """Remove an IP/CIDR from the allowlist."""
    r = _get_throttle_redis()
    removed = r.srem("auth:allowlist", ip_or_cidr)
    if removed:
        _log.info("Admin %s removed IP from allowlist: %s", session.account_id, ip_or_cidr)
        return {"status": "ok", "removed": ip_or_cidr}
    raise HTTPException(status_code=404, detail={"error": "entry_not_found"})


# ---------------------------------------------------------------------------
# drift audit finding #6 — server-side next= redirect validator
#
# The JS guard in login.js (safeNext()) runs at the client trust boundary;
# this server-side validator enforces the same rules at the HTTP trust boundary
# so that a browser with JS disabled, a headless client, or a browser quirk
# that bypasses the JS cannot exploit a reflected open redirect.
#
# Rules mirror the JS Layer 1 regex precisely (same source of truth):
#   1. Must not be empty.
#   2. Must start with exactly one `/` NOT followed by `/` or `\`.
#   3. Must not contain any `\` character (IE/Edge normalise `/\` → `//`).
#   4. Must not contain `//` after the leading `/` (protocol-relative).
#   5. Must not start with an absolute URL scheme (http:, https:, ftp:, etc.).
#   6. Must not contain `@` (URL-userinfo trick: /foo@evil.com → evil.com host).
#   7. Must not exceed 2 048 characters.
#
# On rejection: redirect to `/` + emit OPEN_REDIRECT_ATTEMPT_BLOCKED audit event.
# On acceptance: redirect to the validated path (302).
#
# References: CWE-601 / ASVS V5.1.5 / OWASP A01:2021.
# ---------------------------------------------------------------------------

# Absolute URL scheme pattern — catches http:, https:, ftp:, javascript:, etc.
_ABSOLUTE_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+\-.]*:", re.ASCII)

_NEXT_MAX_LENGTH = 2048


def _validate_next(raw: str) -> tuple[bool, str]:
    """
    Validate a next= redirect target.

    Returns (True, sanitised_path) when the value is safe to redirect to, or
    (False, reason) when the value must be rejected.

    Rules — in check order:
      empty            : empty / falsy string
      too_long         : exceeds _NEXT_MAX_LENGTH characters
      not_relative     : does not start with `/`
      double_slash     : starts with `//` or `/\\` (protocol-relative bypass)
      backslash        : contains any backslash anywhere in the string
      absolute_url     : matches an absolute URL scheme (http:, javascript:, …)
      userinfo_at      : contains `@` (URL-userinfo open redirect trick)
    """
    if not raw:
        return False, "empty"
    if len(raw) > _NEXT_MAX_LENGTH:
        return False, "too_long"
    if not raw.startswith("/"):
        # Catches https://evil.com, //evil.com without starting slash check
        if _ABSOLUTE_SCHEME_RE.match(raw):
            return False, "absolute_url"
        return False, "not_relative"
    # Starts with `/` — check for double-slash / backslash as second char.
    if len(raw) >= 2 and raw[1] in ("/", "\\"):
        return False, "double_slash"
    # Full-string backslash check (catches /path\..\ traversal attempts).
    if "\\" in raw:
        return False, "backslash"
    # Absolute-URL check (catches edge cases where the leading / was spoofed).
    if _ABSOLUTE_SCHEME_RE.match(raw):
        return False, "absolute_url"
    # @-userinfo trick: /user@evil.com is parsed as authority=user@evil.com.
    if "@" in raw:
        return False, "userinfo_at"
    return True, raw


def _hash_ip(ip: str) -> str:
    """Return SHA-256 hex digest of an IP address, first 16 chars for brevity."""
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


def _sanitise_for_audit(raw: str) -> str:
    """Truncate and replace non-printable/non-ASCII chars for safe audit logging."""
    truncated = raw[:128]
    # Replace any char outside printable ASCII with '?'
    return "".join(c if 0x20 <= ord(c) < 0x7F else "?" for c in truncated)


@router.get("/post-login-redirect")
async def post_login_redirect(
    request: Request,
    next: str = Query(default="", alias="next"),
):
    """
    Server-side next= redirect validator — drift audit finding #6.

    Called by the login.js after a successful /auth/login response.
    Validates the next= parameter against the same rules as the JS safeNext()
    guard and issues a server-side 302 redirect.

    Security:
      - No session required: the browser calls this endpoint immediately after
        /auth/login sets the session cookie; the redirect itself does not require
        an existing session.  The cookie will be present on the follow-up
        navigation because it was just set.
      - On rejection: redirects to '/' and emits OPEN_REDIRECT_ATTEMPT_BLOCKED.
      - The raw `next` value is NEVER logged — only a truncated sanitised form.
      - Client IP is SHA-256 hashed (first 16 chars) in the audit record.

    ASVS V5.1.5 / CWE-601 / OWASP A01:2021.
    """
    client_ip = _real_client_ip(request)  # LAURA-3X-001
    ok, result = _validate_next(next)

    if not ok:
        # Emit audit event before redirecting.
        state = backoffice_state
        if state.audit_writer is not None:
            from yashigani.audit.schema import OpenRedirectAttemptBlockedEvent

            state.audit_writer.write(
                OpenRedirectAttemptBlockedEvent(
                    client_ip_hash=_hash_ip(client_ip),
                    attempted_next_truncated=_sanitise_for_audit(next),
                    reason=result,
                )
            )
        _log.warning(
            "OPEN_REDIRECT_BLOCKED: ip_hash=%s reason=%s attempted=%r",
            _hash_ip(client_ip),
            result,
            _sanitise_for_audit(next)[:64],
        )
        return _RedirectResponse(url="/", status_code=302)

    return _RedirectResponse(url=result, status_code=302)


async def _get_record_by_id(account_id: str):
    state = backoffice_state
    if state.auth_service is None:
        return None
    return await state.auth_service.get_account_by_id(account_id)


def _make_login_event(username: str, outcome: str, reason, account_tier: str = "admin"):
    """ASVS V7.3.4: account_tier reflects the actual session/record tier.

    Safe default "admin" is intentional for the pre-auth failure call site at
    login() line ~299 where authenticate() returned (False, None, reason) and
    no record is available.  All post-auth call sites MUST pass
    record.account_tier or session.account_tier explicitly.
    """
    from yashigani.audit.schema import AdminLoginEvent

    return AdminLoginEvent(
        account_tier=account_tier,
        admin_account=username,
        outcome=outcome,
        failure_reason=reason,
    )


def _make_config_event(username: str, setting: str, prev: str, new: str, account_tier: str = "admin"):
    """ASVS V7.3.4: account_tier reflects the actual session tier, not a hardcoded value.

    This helper is currently unused (callers construct ConfigChangedEvent directly),
    but the parameter is wired for defence-in-depth: if RBAC gates break, an audit
    record constructed via this helper will still record the actual tier.
    Safe default "admin" matches the admin-only routes that would use this helper.
    """
    from yashigani.audit.schema import ConfigChangedEvent

    return ConfigChangedEvent(
        account_tier=account_tier,
        admin_account=username,
        setting=setting,
        previous_value=prev,
        new_value=new,
    )


def _make_provision_event(username: str, account_tier: str = "admin"):
    """ASVS V7.3.4: account_tier reflects the actual session tier, not a hardcoded value."""
    from yashigani.audit.schema import TotpProvisionCompletedEvent

    return TotpProvisionCompletedEvent(
        account_tier=account_tier,
        user_handle=username,
    )


def _make_stepup_event(username: str, outcome: str, account_tier: str = "admin"):
    from yashigani.audit.schema import AdminLoginEvent

    return AdminLoginEvent(
        account_tier=account_tier,
        admin_account=username,
        outcome=f"stepup_{outcome}",
        failure_reason=None if outcome == "success" else "invalid_totp",
    )


def _make_login_attempt_event(username: str, client_ip: str, account_tier: str = "admin"):
    """ACS gap #95: emit AUTH_LOGIN_ATTEMPT before auth result.

    account_tier defaults to "admin" for the pre-auth call site in login() where
    the account record has not yet been fetched.  Pass record.account_tier
    explicitly wherever the record is already in scope.
    """
    from yashigani.audit.schema import AuthLoginAttemptEvent

    # Mask the last octet of the IP for lower-assurance sinks.
    # IPv4: a.b.c.d → a.b.c.0   IPv6: strip last group.
    parts = client_ip.rsplit(".", 1)
    ip_prefix = f"{parts[0]}.0" if len(parts) == 2 else client_ip
    return AuthLoginAttemptEvent(
        account_tier=account_tier,
        admin_account=username,
        client_ip_prefix=ip_prefix,
        outcome="attempt",
    )


def _make_password_changed_event(
    username: str,
    *,
    change_type: str,
    old_hash_tail: str,
    new_hash_tail: str,
    account_tier: str = "admin",
):
    """ACS gap #95: dedicated PASSWORD_CHANGED event.
    ASVS V7.3.4: account_tier reflects the actual session tier, not a hardcoded value."""
    from yashigani.audit.schema import PasswordChangedEvent

    return PasswordChangedEvent(
        account_tier=account_tier,
        admin_account=username,
        change_type=change_type,
        old_hash_tail=old_hash_tail,
        new_hash_tail=new_hash_tail,
        sessions_invalidated=True,
    )


def _make_sessions_invalidated_event(
    *,
    admin_account: str,
    acting_admin: str,
    reason: str,
    sessions_count: int = -1,
    account_tier: str = "admin",
):
    """ACS gap #95: SESSIONS_INVALIDATED event for session lifecycle audit.
    ASVS V7.3.4: account_tier reflects the actual session tier, not a hardcoded value."""
    from yashigani.audit.schema import SessionsInvalidatedEvent

    return SessionsInvalidatedEvent(
        account_tier=account_tier,
        admin_account=admin_account,
        acting_admin=acting_admin,
        reason=reason,
        sessions_count=sessions_count,
    )


# ---------------------------------------------------------------------------
# Gap 3 / v2.23.4 arch-completion: HUMAN identity registration on local-auth login
#
# SSO callbacks create a HUMAN identity in identity_registry (sso.py:271).
# Local-auth login (username + password + TOTP) did not — leaving users without
# a Bearer-issuable identity for /v1/*.  This helper closes that gap.
#
# Security invariants:
#   - Only account_tier == "user" triggers registration. admins MUST NOT be
#     registered as HUMAN identities (Gap 2 indirect separation).
#   - Idempotent: get_by_slug() check prevents duplicate entries on re-login.
#   - Seat-limit hard error: LicenseLimitExceeded → 403, login rejected.
#   - Community-tier graceful-skip: identity_registry is None → skip, allow login.
#   - Legacy account with no email: falls back to {username}@yashigani.local
#     (mirrors existing pattern at auth.py:533 / /auth/verify).  This
#     preserves backward compatibility with pre-email-as-username accounts while
#     still giving them a stable, deterministic slug.  The fallback email is
#     logged at WARNING so operators can backfill real emails during a Gap 1
#     migration.
# ---------------------------------------------------------------------------

def _auth_email_to_slug(email: str) -> str:
    """
    Derive a stable registry slug from an email address.

    B5 (2.25.5): delegates to yashigani.identity.slug.email_to_slug — the single
    canonical implementation.  All slug-derivation sites (auth.py, sso.py,
    openai_router.py, users.py, me.py) produce the SAME slug for any given email.

    e.g. dana.lee@example.com → dana-lee-example-com
    """
    from yashigani.identity.slug import email_to_slug as _canonical_slug
    return _canonical_slug(email)


def _register_human_identity_on_login(record, state) -> None:
    """
    Register a HUMAN identity in the identity_registry for a successfully
    authenticated local-auth user (account_tier == "user").

    Called BEFORE session creation in the login handler so that a seat-limit
    rejection prevents the session from being issued (fail-closed).

    Raises HTTPException(403) if the licence seat limit is exhausted.
    Silently skips if identity_registry is None (community-tier deployment).
    """
    # Only user-tier accounts get HUMAN identities.
    # Admin and totp_provisioning tiers must NOT be registered here.
    if record.account_tier != "user":
        return

    registry = getattr(state, "identity_registry", None)
    if registry is None:
        # Community-tier or pre-init: identity stack not available.
        # Preserve today's behaviour — login succeeds without Bearer identity.
        _log.warning(
            "identity_registry unavailable on login for %s — "
            "HUMAN identity not created (community-tier or pre-init); "
            "user will have no Bearer identity for /v1/*",
            record.username,
        )
        return

    from yashigani.identity.registry import IdentityKind
    from yashigani.licensing.enforcer import LicenseLimitExceeded

    # Resolve the email for the slug.  Use the record email if set; otherwise
    # fall back to the @yashigani.local synthetic email (Gap 1 legacy accounts).
    email = record.email
    if not email:
        email = f"{record.username}@yashigani.local"
        _log.warning(
            "User %s has no email set — using synthetic slug email %s for "
            "identity_registry. Backfill real email to resolve (Gap 1).",
            record.username,
            email,
        )

    slug = _auth_email_to_slug(email)

    # Idempotency guard: if already registered, check status.
    # Q3 / v2.23.4 (Tiago directive 2026-05-15): auto-reactivate on login
    # REVERTED. A suspended identity is an admin-action-only reactivation.
    # If identity is suspended/inactive:
    #   - Block the login (403)
    #   - Audit-log LOGIN_BLOCKED_SUSPENDED_IDENTITY
    #   - Do NOT reactivate, do NOT issue session
    # Admin must call POST /admin/users/{username}/reactivate (StepUp required)
    # to restore access.
    existing = registry.get_by_slug(slug)
    if existing is not None:
        identity_id = existing.get("identity_id", "")
        existing_status = existing.get("status", "active")
        if existing_status in ("suspended", "inactive"):
            # Audit-log before raising so the forensic record is present
            # even if an upstream exception handler swallows the 403.
            from yashigani.audit.schema import LoginBlockedSuspendedIdentityEvent
            _blocked_state = state
            if getattr(_blocked_state, "audit_writer", None) is not None:
                _blocked_state.audit_writer.write(LoginBlockedSuspendedIdentityEvent(
                    username=record.username,
                    identity_id=identity_id,
                    identity_status=existing_status,
                    slug=slug,
                ))
            _log.warning(
                "Q3 LOGIN BLOCKED: user=%s identity_id=%s status=%s slug=%s — "
                "admin must reactivate via POST /admin/users/%s/reactivate",
                record.username,
                identity_id,
                existing_status,
                slug,
                record.username,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "account_suspended",
                    "message": (
                        "Account suspended. Contact your administrator to restore access."
                    ),
                },
            )
        _log.debug(
            "HUMAN identity already active for %s (slug=%s, identity_id=%s) — skip re-register",
            record.username,
            slug,
            identity_id,
        )
        # LAURA-4.0-S1-001: ensure account_id → idnt_ index is populated even
        # for users whose identity already existed before this fix was deployed.
        # link_account_id is idempotent — safe to call on every login.
        try:
            registry.link_account_id(record.account_id, identity_id)
        except Exception as exc:
            _log.warning(
                "link_account_id failed for existing identity %s (account_id=%s): %s — "
                "workflow scheduler may not resolve this user until next login",
                identity_id, record.account_id, exc,
            )
        return

    # New user — register with HUMAN kind.
    # description carries the account_id for cross-system linkage (Gap 3 / v2.23.4).
    try:
        identity_id, _plaintext_key = registry.register(
            kind=IdentityKind.HUMAN,
            name=record.username,
            slug=slug,
            description=f"local-auth user; account_id={record.account_id}",
        )
    except LicenseLimitExceeded as exc:
        _log.warning(
            "Seat limit reached: cannot register HUMAN identity for %s "
            "(%d/%d used). Login rejected.",
            record.username,
            exc.current,
            exc.max_val,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "seat_limit_exceeded",
                "message": (
                    "The maximum number of user seats for this licence has been reached. "
                    "Contact your administrator to increase the seat limit."
                ),
                "current": exc.current,
                "max": exc.max_val,
            },
        ) from exc

    # LAURA-4.0-S1-001: store account_id → identity_id mapping so the workflow
    # scheduler can resolve owner_identity_id (stored as account_id UUID) to the
    # real identity PK that OPA scope keys are built from (human:{idnt_...}).
    try:
        registry.link_account_id(record.account_id, identity_id)
    except Exception as exc:
        _log.warning(
            "link_account_id failed for new identity %s (account_id=%s): %s — "
            "workflow scheduler may not resolve this user",
            identity_id, record.account_id, exc,
        )

    _log.info(
        "HUMAN identity registered on local-auth login: "
        "identity_id=%s slug=%s account_id=%s",
        identity_id,
        slug,
        record.account_id,
    )
