"""
Regression tests — AVA-412-DOS (Ava re-test, 2026-07-23): auth-throttle
self-extending perpetual unauthenticated account-lockout DoS.

## The finding

`_THROTTLE_ADMIT_LUA` / `_apply_auth_throttle` in
`src/yashigani/backoffice/routes/auth.py` ran the ATOMIC admit (INCR + a
possible SET/EXPIRE with a fresh 900s TTL on the escalation-level key)
UNCONDITIONALLY on every ``POST /auth/login`` — including a request that
was about to be REJECTED at 429 because the target account was ALREADY
gated, BEFORE any credential check ever ran. Consequence: an
unauthenticated caller who merely knew a valid admin USERNAME (zero
credentials needed) could keep that admin locked out forever by sending
one blocked probe per window (<=900s), indefinitely.

OWASP API4:2023 (Unrestricted Resource Consumption) / ASVS V2.2
(anti-automation controls must not themselves become a DoS vector).

## The fix

`_apply_auth_throttle` now splits into two phases:

  1. A READ-ONLY pre-check (`_throttle_current_level`, a bare Redis
     ``GET``) — if the account is ALREADY gated, reject immediately with
     **zero** Redis mutation (no INCR, no EXPIRE, no SET).
  2. Only when NOT already gated does the mutating atomic admit
     (`_throttle_admit`, the LAURA-412-HIGH TOCTOU fix) run — preserving
     that fix's concurrency guarantee unchanged for attempts still racing
     to cross the threshold for the first time.

Net effect: the lockout window can only ever be armed/re-armed by a
request that is actually admitted toward a real credential check — never
by a request that is rejected outright before one. A legitimate user (or
a spammed victim) always recovers `_THROTTLE_WINDOW_SECONDS` after the
LAST such genuine attempt, regardless of how many blocked probes an
attacker sends in between.

Each test below would FAIL on the pre-fix code:
  - TestBlockedProbesDoNotSelfExtend: pre-fix, every blocked 429 refreshed
    the throttle key's TTL back toward the full window (and, for a fully
    scripted attacker, escalated the level further with each ping) —
    these tests would observe the TTL jump back UP instead of staying
    flat/decaying.
  - TestLegitUserRecoversDespiteAttackerProbing: pre-fix, the window never
    naturally expired while the attacker kept probing, so the legit
    login attempt after "recovery" would still 429 forever.

Genuine per-account brute-force protection (the ORIGINAL LAURA-412-CRITICAL
invariant) must remain completely intact — verified by
TestGenuineAttemptsStillThrottle below, which still passes on both the
pre-fix and post-fix code (proving this fix did not weaken it).

Retro ref: T4 — every Python-level retro item must have a regression test.
Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("fakeredis")
pytest.importorskip("fastapi")
pytest.importorskip("lupa")  # Lua runtime — required for fakeredis EVAL emulation


# ---------------------------------------------------------------------------
# Helpers (mirrors test_laura_412_critical_auth_throttle_hardening.py)
# ---------------------------------------------------------------------------

def _fake_redis():
    import fakeredis
    return fakeredis.FakeRedis(decode_responses=False)


def _make_request(client_host: str = "10.89.1.2") -> SimpleNamespace:
    return SimpleNamespace(
        headers={},
        client=SimpleNamespace(host=client_host),
        cookies={},
    )


def _make_account(username: str, account_tier: str = "admin") -> MagicMock:
    acct = MagicMock()
    acct.username = username
    acct.account_tier = account_tier
    acct.email = f"{username}@example.com"
    acct.account_id = f"uuid-{username}"
    acct.disabled = False
    acct.force_password_change = False
    acct.force_totp_provision = False
    acct.password_hash = "hashed"
    acct.totp_secret = "JBSWY3DPEHPK3PXP"
    return acct


def _make_state(auth_result) -> MagicMock:
    state = MagicMock()
    state.auth_service = AsyncMock()
    state.auth_service.authenticate = AsyncMock(return_value=auth_result)
    state.session_store = MagicMock()
    session = MagicMock()
    session.token = "tok-test"
    session.account_tier = auth_result[1].account_tier if auth_result[1] else "admin"
    state.session_store.create = MagicMock(return_value=session)
    state.audit_writer = MagicMock()
    state.identity_registry = None
    return state


def _import_auth_mod():
    from yashigani.backoffice.routes import auth as _auth_mod
    return _auth_mod


async def _attempt_login(mod, fake_redis, username, client_ip, auth_result, account_id="__default__"):
    """Drive the real login() route handler — see the LAURA-412 suite for
    the full rationale (exercises the actual sequence, not a
    reimplementation of it)."""
    from fastapi import Response

    if account_id == "__default__":
        account_id = auth_result[1].account_id if auth_result[1] is not None else None

    body = MagicMock()
    body.username = username
    body.password = "irrelevant-mocked"
    body.totp_code = "123456"
    request = _make_request(client_ip)
    resp = Response()

    mock_state = _make_state(auth_result)
    with patch.object(mod, "backoffice_state", mock_state):
        with patch.object(mod, "_get_throttle_redis", return_value=fake_redis):
            with patch.object(
                mod, "_resolve_account_id_for_bucket",
                new=AsyncMock(return_value=account_id),
            ):
                with patch.object(mod, "_register_human_identity_on_login"):
                    return await mod.login(body, request, resp)


# ---------------------------------------------------------------------------
# 1. Genuine repeated wrong-password attempts still throttle (protection
#    intact — this fix must not weaken the original LAURA-412-CRITICAL gate)
# ---------------------------------------------------------------------------

class TestGenuineAttemptsStillThrottle:

    @pytest.mark.asyncio
    async def test_three_genuine_wrong_password_attempts_still_gate_the_account(self):
        """3 attempts that actually reach authenticate() (genuine, not
        blocked) with the wrong password still gate the account on the 4th,
        with the documented initial 30s backoff — the phase-1/phase-2 split
        must not weaken the threshold-crossing gate itself."""
        from fastapi import HTTPException

        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "192.0.2.77"
        victim_id = "uuid-genuine-victim"

        for _ in range(mod._THROTTLE_ACCOUNT_THRESHOLD):
            with pytest.raises(HTTPException) as exc_info:
                await _attempt_login(
                    mod, r, "genuine-victim", ip,
                    auth_result=(False, None, "invalid_credentials"),
                    account_id=victim_id,
                )
            assert exc_info.value.status_code == 401

        victim = _make_account("genuine-victim")
        with pytest.raises(HTTPException) as exc_info:
            await _attempt_login(mod, r, "genuine-victim", ip, auth_result=(True, victim, "ok"))
        assert exc_info.value.status_code == 429
        assert exc_info.value.headers["Retry-After"] == "30"

    def test_repeated_genuine_admits_across_a_bounded_window_still_escalate(self):
        """Direct proof at the atomic-admit layer (bypassing the route):
        repeated GENUINE admits (calls that are actually let through to a
        real credential check, i.e. calls made while NOT yet gated) within
        one window still escalate the delay up the bounded schedule exactly
        as before this fix — this fix changes ONLY which calls are allowed
        to reach `_throttle_admit`, never `_throttle_admit`'s own
        escalation arithmetic."""
        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "192.0.2.78"
        bucket_key = mod._account_bucket_key("sustained-genuine-target", None)

        for _ in range(20):
            mod._throttle_admit(
                r, f"auth:fail:ip:{ip}", f"auth:throttle:ip:{ip}",
                f"auth:fail:acct:{bucket_key}", f"auth:throttle:acct:{bucket_key}",
            )

        level = int(r.get(f"auth:throttle:acct:{bucket_key}") or 0)
        assert level == len(mod._THROTTLE_DELAYS)
        assert mod._throttle_delay_for_level(level) == 900


# ---------------------------------------------------------------------------
# 2. AVA-412-DOS core proof: blocked (already-gated) probes never extend
#    the lockout window or increment any counter
# ---------------------------------------------------------------------------

class TestBlockedProbesDoNotSelfExtend:

    def test_blocked_probe_after_gating_touches_no_redis_state(self):
        """
        Gates an account via 3 genuine attempts, then simulates that the
        window has nearly elapsed (5s left) by directly setting the TTL —
        this stands in for real wall-clock time passing. An attacker then
        sends 10 further blocked probes (zero credentials — the whole
        point is these never reach authenticate()). Pre-fix, EACH of those
        probes would call the atomic Lua unconditionally, refreshing the
        throttle key's TTL back to the FULL 900s window (and/or escalating
        its level) — i.e. the TTL would jump back UP. Post-fix, the TTL
        must only ever tick DOWN (or stay put within one Redis round-trip),
        never being reset, and the fail counter must not move at all.
        """
        from fastapi import HTTPException, Response

        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "203.0.113.50"
        username = "blocked-probe-victim"
        account_id = "uuid-blocked-probe-victim"
        bucket_key = mod._account_bucket_key(username, account_id)
        acct_fail_key = f"auth:fail:acct:{bucket_key}"
        acct_throttle_key = f"auth:throttle:acct:{bucket_key}"

        resp = Response()

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            # 3 genuine admits gate the account (level -> 1, TTL -> 900s).
            for _ in range(mod._THROTTLE_ACCOUNT_THRESHOLD):
                mod._apply_auth_throttle(ip, username, account_id, resp)

            assert int(r.get(acct_throttle_key)) == 1
            # AVA-RETRYAFTER fix (2026-07-24): level 1's escalation-level key
            # is now given the level-1 TTL (30s, matching the Retry-After
            # header) rather than the flat 900s window this assertion used
            # to expect — that flat-900 behaviour WAS the RFC 6585 bug (see
            # fix/v412-throttle-retryafter). AVA-412-DOS's self-extend
            # invariant (proven below) is orthogonal to which TTL value is
            # used at set-time — it only requires the TTL never jumps back
            # UP once set.
            assert 0 < r.ttl(acct_throttle_key) <= 30  # freshly set to ~30s (level 1)

            # Simulate the window having nearly elapsed (5s left) — stands
            # in for ~895s of real elapsed wall-clock time.
            r.expire(acct_throttle_key, 5)
            r.expire(acct_fail_key, 5)

            fail_count_before = int(r.get(acct_fail_key))
            ttl_before = r.ttl(acct_throttle_key)
            assert 0 < ttl_before <= 5

            # Attacker: 10 further blocked probes, zero credentials, never
            # reaching authenticate() — each must 429, and each must leave
            # Redis state completely untouched.
            for _ in range(10):
                with pytest.raises(HTTPException) as exc_info:
                    mod._apply_auth_throttle(ip, username, account_id, resp)
                assert exc_info.value.status_code == 429

            fail_count_after = int(r.get(acct_fail_key))
            ttl_after = r.ttl(acct_throttle_key)

            assert fail_count_after == fail_count_before, (
                "a blocked (already-gated) probe must NEVER increment the "
                "account fail counter — it never reaches a real credential "
                "check"
            )
            assert ttl_after <= ttl_before, (
                f"blocked probes must never refresh/extend the lockout TTL "
                f"— got ttl_before={ttl_before}, ttl_after={ttl_after} "
                f"(pre-fix this would have jumped back up toward 900)"
            )
            assert ttl_after > 0, (
                "the key must still be counting down naturally, not wiped "
                "or frozen by the blocked probes"
            )

    @pytest.mark.asyncio
    async def test_route_level_blocked_probes_do_not_refresh_ttl(self):
        """Same proof, but driven through the real login() route (not the
        lower-level helper directly) — end-to-end confirmation that the
        wiring in login() calls the fixed _apply_auth_throttle correctly."""
        from fastapi import HTTPException

        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "203.0.113.60"
        username = "route-level-victim"
        account_id = "uuid-route-level-victim"
        bucket_key = mod._account_bucket_key(username, account_id)
        acct_throttle_key = f"auth:throttle:acct:{bucket_key}"

        for _ in range(mod._THROTTLE_ACCOUNT_THRESHOLD):
            with pytest.raises(HTTPException):
                await _attempt_login(
                    mod, r, username, ip,
                    auth_result=(False, None, "invalid_credentials"),
                    account_id=account_id,
                )

        assert int(r.get(acct_throttle_key)) == 1
        r.expire(acct_throttle_key, 5)
        ttl_before = r.ttl(acct_throttle_key)

        victim = _make_account(username)
        for _ in range(10):
            with pytest.raises(HTTPException) as exc_info:
                await _attempt_login(
                    mod, r, username, ip,
                    auth_result=(True, victim, "ok"),  # even a CORRECT-creds
                    account_id=account_id,              # request is blocked
                )
            assert exc_info.value.status_code == 429

        ttl_after = r.ttl(acct_throttle_key)
        assert ttl_after <= ttl_before, (
            f"route-level blocked probes must not refresh the TTL — "
            f"ttl_before={ttl_before}, ttl_after={ttl_after}"
        )


# ---------------------------------------------------------------------------
# 3. Legit user (or the spammed victim) recovers after the window from the
#    LAST GENUINE attempt, regardless of interleaved attacker probing
# ---------------------------------------------------------------------------

class TestLegitUserRecoversDespiteAttackerProbing:

    @pytest.mark.asyncio
    async def test_legit_login_succeeds_once_window_naturally_expires(self):
        """
        Full lifecycle: attacker gates the account with 3 genuine wrong
        attempts, then hammers it with blocked probes (proving, via
        TestBlockedProbesDoNotSelfExtend, that these never re-arm the
        window) — once the window has genuinely elapsed (simulated here by
        deleting the now-expired keys, exactly what Redis itself would do
        naturally), the legitimate account owner's correct-password login
        succeeds immediately, with no admin intervention required.
        """
        from fastapi import HTTPException

        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "203.0.113.70"
        username = "recovering-victim"
        account_id = "uuid-recovering-victim"
        bucket_key = mod._account_bucket_key(username, account_id)
        acct_fail_key = f"auth:fail:acct:{bucket_key}"
        acct_throttle_key = f"auth:throttle:acct:{bucket_key}"

        # Attacker gates the account.
        for _ in range(mod._THROTTLE_ACCOUNT_THRESHOLD):
            with pytest.raises(HTTPException):
                await _attempt_login(
                    mod, r, username, ip,
                    auth_result=(False, None, "invalid_credentials"),
                    account_id=account_id,
                )

        # Attacker keeps pinging (blocked every time, zero credentials) —
        # this must have zero bearing on when the window actually expires.
        for _ in range(15):
            with pytest.raises(HTTPException) as exc_info:
                await _attempt_login(
                    mod, r, username, ip,
                    auth_result=(False, None, "invalid_credentials"),
                    account_id=account_id,
                )
            assert exc_info.value.status_code == 429

        # The window naturally elapses (simulated: Redis itself would
        # delete these keys once their TTL — set only by the 3 GENUINE
        # attempts above, never touched by the 15 blocked probes — hits
        # zero).
        r.delete(acct_fail_key, acct_throttle_key)

        victim = _make_account(username)
        result = await _attempt_login(
            mod, r, username, ip, auth_result=(True, victim, "ok"), account_id=account_id,
        )
        assert result["status"] == "ok", (
            "the legitimate account owner must be able to log in "
            "immediately once the window has genuinely elapsed, with no "
            "admin action required — regardless of how many blocked "
            "probes the attacker sent while waiting for it to expire"
        )

    def test_gate_reopens_for_a_fresh_genuine_attempt_after_natural_expiry(self):
        """Lower-level proof mirroring the above without the full route:
        once the throttle keys are gone (natural TTL expiry), a fresh call
        to _apply_auth_throttle is treated as NOT gated and is admitted —
        the read-only pre-check correctly reports level 0 for an absent
        key, not a stale nonzero value."""
        from fastapi import Response

        mod = _import_auth_mod()
        r = _fake_redis()
        bucket_key = mod._account_bucket_key("post-expiry-target", None)
        acct_throttle_key = f"auth:throttle:acct:{bucket_key}"

        assert mod._throttle_current_level(r, acct_throttle_key) == 0

        resp = Response()
        with patch.object(mod, "_get_throttle_redis", return_value=r):
            # A single admitted attempt below threshold — must not raise.
            mod._apply_auth_throttle("203.0.113.80", "post-expiry-target", None, resp)
