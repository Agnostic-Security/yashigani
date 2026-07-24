"""
Regression tests — LAURA-412-CRITICAL / HIGH / MEDIUM (podman r4/r5 pentest,
2026-07-19).

## Round 1 (r4) — LAURA-412-CRITICAL

`_apply_auth_throttle` / `_record_auth_failure` / `_real_client_ip` keyed
every failed login attempt SOLELY on the apparent client IP.  Under a
NAT/proxy/CGNAT/podman-pasta topology many distinct legitimate callers
collapse onto one apparent address (proven live by Laura on podman r4, and
independently root-caused by Su at the TCP/NAT layer — see
project_v412_design_conflict_xrealip_podman_nat.md).  Four unauthenticated
garbage-credential requests from a stranger 429'd an uninvolved,
credential-correct admin account (cross-account lockout).  The escalation
also had an unbounded permanent-block tail (`auth:blocked:{ip}` with no TTL)
and the pre-auth block fired BEFORE authenticate() ever ran, so a legitimate
caller could never reach the success path that would have self-healed the
counter.

Fix: dual-bucket, ACCOUNT-GATED design — per-account bucket is the sole
gate, per-IP bucket is a severity modifier only, global bucket removed,
escalation bounded at 900s, successful auth self-heals both buckets.

## Round 2 (r5) — LAURA-412-HIGH / LAURA-412-MEDIUM (Laura re-attack)

Laura confirmed the round-1 CRITICAL closed (K=2), then found two new
issues attacking the NEW design:

  - HIGH (TOCTOU race): 25 concurrent wrong-password requests against one
    real account ALL returned 401 — none were throttled; the gate only
    escalated after the whole burst had landed (round-1 read the count,
    then incremented it SEPARATELY after authenticate() resolved — a
    classic check-then-act race under concurrency, CWE-362).  Fixed with
    `_throttle_admit()`: one atomic Redis Lua script that increments BOTH
    buckets and returns their PRIOR level in a single round-trip, called
    BEFORE authenticate() runs for every attempt.

  - MEDIUM (casefold-collision): round 1's `_hash_account()` casefolded
    the username before hashing, but this system's identity model is
    CASE-SENSITIVE — two accounts differing only by case
    ("collision-probe-a" / "COLLISION-PROBE-A") are genuinely distinct,
    independently-valid accounts that shared one bucket, reintroducing
    cross-account lockout.  Fixed by keying the bucket on the account's
    stable `account_id` (via `_account_bucket_key`) whenever the account
    exists.

Each test below would FAIL on the round-1 (post-CRITICAL-fix,
pre-HIGH/MEDIUM-fix) code:
  - TestConcurrentBurstDoesNotBypassGate: round 1's check-then-increment
    let all 25 concurrent requests pass the gate.
  - TestCaseVariantAccountsDoNotShareBucket: round 1's casefolded hash
    collapsed two distinct accounts into one bucket.

Each test in the original four classes below still passes post-round-2 —
proving the original CRITICAL fix, self-heal, bounded escalation, and
per-account brute-force protection all remain intact after the HIGH/MEDIUM
fixes (the coordinator's "original Critical stays closed" requirement).

Retro ref: T4 — every Python-level retro item must have a regression test.
Last updated: 2026-07-19T00:00:00+00:00
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("fakeredis")
pytest.importorskip("fastapi")
pytest.importorskip("lupa")  # Lua runtime — required for fakeredis EVAL emulation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_redis():
    import fakeredis
    return fakeredis.FakeRedis(decode_responses=False)


def _make_request(client_host: str = "10.89.1.2") -> SimpleNamespace:
    """
    A minimal request double.  login() only ever calls
    _real_client_ip(request), which reads request.headers.get(...) and
    request.client.host — both are plain, real objects here (no MagicMock
    autospec quirks around __getitem__/truthiness).
    """
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
    """auth_result: tuple(success, record_or_None, reason) as returned by
    PostgresLocalAuthService.authenticate()."""
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


def _account_id_for(username: str, exists: bool) -> str | None:
    """Mirror _make_account's account_id convention, or None for a bogus user."""
    return f"uuid-{username}" if exists else None


async def _attempt_login(
    mod, fake_redis, username: str, client_ip: str, auth_result,
    account_id: str | None = "__default__", response=None,
):
    """
    Drive the real login() route handler with a fake Redis backing the
    throttle and a fully mocked backoffice_state/auth_service — exercises
    the actual _check_ip_access -> _resolve_account_id_for_bucket ->
    _apply_auth_throttle -> authenticate -> _reset_auth_failures sequence
    exactly as the HTTP route does, not a re-implementation of it.

    account_id: the value _resolve_account_id_for_bucket should return for
    this username (patched out — this test suite is not exercising the
    Postgres lookup itself, only the throttle logic that consumes it).
    "__default__" derives it from auth_result's record (if any) so most
    call sites don't need to specify it explicitly.
    """
    from fastapi import Response

    if account_id == "__default__":
        account_id = auth_result[1].account_id if auth_result[1] is not None else None

    body = MagicMock()
    body.username = username
    body.password = "irrelevant-mocked"
    body.totp_code = "123456"
    request = _make_request(client_ip)
    resp = response if response is not None else Response()

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
# 1. Shared/collapsed IP must not lock out a clean, uninvolved account
# ---------------------------------------------------------------------------

class TestSharedIpDoesNotLockOutCleanAccount:
    """Reproduces Laura's exact podman r4 exploit shape at the route level."""

    @pytest.mark.asyncio
    async def test_shared_ip_does_not_lock_out_clean_account(self):
        from fastapi import HTTPException

        mod = _import_auth_mod()
        r = _fake_redis()
        attacker_ip = "10.89.1.2"  # the collapsed/shared address (Caddy's own
        # container IP under podman-pasta NAT, per Laura's live evidence)

        # Attacker: 4 garbage-credential attempts against the SAME
        # non-existent account, from the shared IP — mirrors Laura's
        # reproduction exactly (4x POST /auth/login, same garbage
        # username/password/TOTP each time). The first 3 fail with 401; the
        # 4th correctly trips THAT account's own gate (per-account brute-
        # force protection working as intended — this is not the bug).
        for i in range(4):
            with pytest.raises(HTTPException) as exc_info:
                await _attempt_login(
                    mod, r, "nonexistent_attacker_probe", attacker_ip,
                    auth_result=(False, None, "invalid_credentials"),
                    account_id=None,
                )
            if i < 3:
                assert exc_info.value.status_code == 401, f"attempt {i + 1}: expected 401"
            else:
                assert exc_info.value.status_code == 429, (
                    "attempt 4 against the SAME repeatedly-failing account "
                    "correctly trips its own gate — this is genuine "
                    "brute-force protection, not the collateral-lockout bug"
                )

        # The actual CRITICAL: a completely different, uninvolved account
        # (cedar) with CORRECT credentials, from the SAME apparent IP that
        # just produced 4 failures against an unrelated account — must
        # succeed, not 429.
        cedar = _make_account("cedar", "admin")
        result = await _attempt_login(
            mod, r, "cedar", attacker_ip,
            auth_result=(True, cedar, "ok"),
        )
        assert result["status"] == "ok", (
            f"cedar (clean account, correct creds) must log in successfully "
            f"despite sharing an apparent IP with an attacker's noise — got {result!r}"
        )

    @pytest.mark.asyncio
    async def test_ip_wide_noise_alone_never_produces_429(self):
        """
        Even well past the old per-IP threshold (3) — many DIFFERENT clean
        accounts attempted once each from the same IP — no account is ever
        gated, because no single account accumulates its own attempts.
        """
        mod = _import_auth_mod()
        r = _fake_redis()
        shared_ip = "10.89.1.2"

        for i in range(10):
            username = f"clean-account-{i}"
            result = await _attempt_login(
                mod, r, username, shared_ip,
                auth_result=(True, _make_account(username), "ok"),
            )
            assert result["status"] == "ok", f"{username} must not be throttled"


# ---------------------------------------------------------------------------
# 2. Self-heal on successful authentication
# ---------------------------------------------------------------------------

class TestSelfHealOnSuccess:

    @pytest.mark.asyncio
    async def test_successful_login_self_heals_account_counter(self):
        """
        An account gated by its own prior attempts must be able to recover
        via a single correct login — not via manual Redis surgery.
        """
        from fastapi import HTTPException

        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "203.0.113.5"
        bob = _make_account("bob")
        bob_id = bob.account_id

        # 3 failed attempts against bob's OWN account trip the account gate
        # (threshold = 3).
        for _ in range(3):
            with pytest.raises(HTTPException):
                await _attempt_login(
                    mod, r, "bob", ip, auth_result=(False, None, "invalid_credentials"),
                    account_id=bob_id,
                )

        # 4th attempt (even with correct creds) is now gated pre-auth.
        with pytest.raises(HTTPException) as exc_info:
            await _attempt_login(mod, r, "bob", ip, auth_result=(True, bob, "ok"))
        assert exc_info.value.status_code == 429

        # Directly exercise the reset helper (mirrors what a real successful
        # authenticate() call does inside login() once the gate reopens —
        # e.g. after the bounded window elapses, or via WebAuthn which is
        # keyed on the same account bucket).
        with patch.object(mod, "_get_throttle_redis", return_value=r):
            mod._reset_auth_failures(ip, "bob", bob_id)

        bucket_key = mod._account_bucket_key("bob", bob_id)
        assert r.get(f"auth:fail:acct:{bucket_key}") is None
        assert r.get(f"auth:throttle:acct:{bucket_key}") is None
        assert r.get(f"auth:fail:ip:{ip}") is None
        assert r.get(f"auth:throttle:ip:{ip}") is None

        # Gate is now open again — bob can log in.
        result = await _attempt_login(mod, r, "bob", ip, auth_result=(True, bob, "ok"))
        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_login_route_clears_counters_on_success_without_manual_reset(self):
        """
        End-to-end via the real route: after a below-threshold failure, a
        SUCCESSFUL login (still 2 attempts short of the account gate) must
        leave the account with a zeroed counter afterward — proving
        login()'s own success path (not a test helper) performs the heal.
        """
        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "203.0.113.9"
        alice = _make_account("alice")
        alice_id = alice.account_id

        # 2 failures — below the threshold (3), account not yet gated.
        for _ in range(2):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                await _attempt_login(
                    mod, r, "alice", ip, auth_result=(False, None, "invalid_credentials"),
                    account_id=alice_id,
                )
            assert exc_info.value.status_code == 401

        bucket_key = mod._account_bucket_key("alice", alice_id)
        assert int(r.get(f"auth:fail:acct:{bucket_key}") or 0) == 2

        # Successful login — login()'s own _reset_auth_failures call must fire.
        result = await _attempt_login(mod, r, "alice", ip, auth_result=(True, alice, "ok"))
        assert result["status"] == "ok"
        assert r.get(f"auth:fail:acct:{bucket_key}") is None, (
            "login() must clear the account failure counter on success "
            "without any manual/test intervention"
        )


# ---------------------------------------------------------------------------
# 3. Escalation is bounded — no permanent-block tail
# ---------------------------------------------------------------------------

class TestBoundedMaxDelayNotPermanent:

    def test_escalation_caps_at_900s_and_never_writes_permanent_block(self):
        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "198.51.100.20"
        bucket_key = mod._account_bucket_key("attacked-account", None)

        # Drive far past the old 6-level escalation table (20 rounds of
        # 3 attempts each = 60 recorded attempts against one account).
        with patch.object(mod, "_get_throttle_redis", return_value=r):
            for _ in range(20):
                mod._throttle_admit(
                    r, f"auth:fail:ip:{ip}", f"auth:throttle:ip:{ip}",
                    f"auth:fail:acct:{bucket_key}", f"auth:throttle:acct:{bucket_key}",
                )

        level = int(r.get(f"auth:throttle:acct:{bucket_key}") or 0)
        assert level == len(mod._THROTTLE_DELAYS), (
            f"level must cap at {len(mod._THROTTLE_DELAYS)}, got {level}"
        )
        delay = mod._throttle_delay_for_level(level)
        assert delay == 900, f"bounded max delay must be 900s, got {delay}"

        # The old permanent-block key must NEVER be written by this path.
        assert r.exists(f"auth:blocked:{ip}") == 0, (
            "auth:blocked:{ip} must never be auto-populated — the permanent-"
            "block escalation tail is removed"
        )
        assert list(r.scan_iter("auth:blocked:*")) == [], (
            "no auth:blocked:* key of any kind should exist after pure "
            "escalation — only an explicit admin action may create one"
        )

    def test_throttle_keys_carry_a_bounded_ttl_not_persistent(self):
        """
        Every key written by the throttle must have a finite TTL (recovers
        automatically) — none may be persistent (ttl() == -1).
        """
        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "198.51.100.21"
        bucket_key = mod._account_bucket_key("another-attacked-account", None)

        for _ in range(10):
            mod._throttle_admit(
                r, f"auth:fail:ip:{ip}", f"auth:throttle:ip:{ip}",
                f"auth:fail:acct:{bucket_key}", f"auth:throttle:acct:{bucket_key}",
            )

        for key in (
            f"auth:fail:ip:{ip}",
            f"auth:throttle:ip:{ip}",
            f"auth:fail:acct:{bucket_key}",
            f"auth:throttle:acct:{bucket_key}",
        ):
            ttl = r.ttl(key)
            assert ttl is not None and ttl > 0, (
                f"{key} must carry a finite positive TTL, got {ttl!r} "
                "(-1 would mean persistent/never-expiring, i.e. unrecoverable "
                "without an explicit admin action)"
            )
            assert ttl <= mod._THROTTLE_WINDOW_SECONDS


# ---------------------------------------------------------------------------
# 4. Per-account brute-force protection is preserved
# ---------------------------------------------------------------------------

class TestPerAccountThrottleStopsBruteForce:

    @pytest.mark.asyncio
    async def test_repeated_failures_against_one_account_eventually_throttle_it(self):
        """
        A real attacker who correctly targets ONE specific account (unlike
        the noisy multi-account spray in TestSharedIpDoesNotLockOutCleanAccount)
        must still be slowed down — this is the ASVS 6.3.5 protection the
        redesign is not allowed to throw away.
        """
        from fastapi import HTTPException

        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "192.0.2.50"
        victim_id = "uuid-targeted-victim"

        # First 3 attempts fail normally (401) — below threshold.
        for _ in range(3):
            with pytest.raises(HTTPException) as exc_info:
                await _attempt_login(
                    mod, r, "targeted-victim", ip, auth_result=(False, None, "invalid_credentials"),
                    account_id=victim_id,
                )
            assert exc_info.value.status_code == 401

        # 4th attempt (even with the RIGHT credentials this time — attacker
        # got lucky, or this is the legitimate owner) is now gated: the
        # account itself is under active attack and must be throttled
        # regardless of who is asking.
        victim = _make_account("targeted-victim")
        with pytest.raises(HTTPException) as exc_info:
            await _attempt_login(mod, r, "targeted-victim", ip, auth_result=(True, victim, "ok"))
        assert exc_info.value.status_code == 429
        assert exc_info.value.headers["Retry-After"] == "30"

    def test_account_threshold_matches_documented_value(self):
        mod = _import_auth_mod()
        assert mod._THROTTLE_ACCOUNT_THRESHOLD == 3

    def test_different_ip_same_account_still_throttled(self):
        """
        Brute force distributed across many source IPs against ONE account
        (the classic bypass for a naive per-IP-only design) is still caught,
        because the gate is keyed on the account, not the source IP.
        """
        mod = _import_auth_mod()
        r = _fake_redis()
        bucket_key = mod._account_bucket_key("distributed-target", None)

        resp = MagicMock()
        resp.headers = {}
        from fastapi import HTTPException
        with patch.object(mod, "_get_throttle_redis", return_value=r):
            for i in range(3):
                ip = f"203.0.113.{100 + i}"
                mod._throttle_admit(
                    r, f"auth:fail:ip:{ip}", f"auth:throttle:ip:{ip}",
                    f"auth:fail:acct:{bucket_key}", f"auth:throttle:acct:{bucket_key}",
                )

            with pytest.raises(HTTPException) as exc_info:
                # A 4th attempt from yet ANOTHER new IP is still gated —
                # the account bucket doesn't care which IP is asking.
                mod._apply_auth_throttle("203.0.113.200", "distributed-target", None, resp)
        assert exc_info.value.status_code == 429


# ---------------------------------------------------------------------------
# 5. LAURA-412-HIGH (r5) — concurrent burst does NOT bypass the gate
# ---------------------------------------------------------------------------

class TestConcurrentBurstDoesNotBypassGate:
    """
    Laura's r5 reproduction: 25 concurrent wrong-password requests against
    one real account all returned 401 under the round-1 (check-then-later-
    increment) design — none were throttled, and the DB-side counter lost
    updates too (25 real failures recorded as 5).  These tests exercise the
    ACTUAL _throttle_admit()/_apply_auth_throttle() code (not a
    reimplementation) under real concurrency and assert the gate holds.
    """

    def test_atomic_admit_under_real_concurrent_threads_never_loses_a_count(self):
        """
        Fires 25 concurrent calls to the real _throttle_admit() (the atomic
        Lua-script helper) against a shared fakeredis instance using actual
        OS threads (ThreadPoolExecutor) — this is what genuinely exercises
        concurrency (unlike asyncio's single-threaded cooperative
        scheduling, which would never reproduce the interleaving Laura's
        live multi-connection PoC hit). Asserts: (a) the final count is
        EXACTLY 25 — no lost updates (the round-1 bug's Postgres-side
        symptom, mirrored here at the Redis layer) — and (b) EXACTLY
        _THROTTLE_ACCOUNT_THRESHOLD requests observed "not yet gated"
        (acct_level_before <= 0), matching the documented 3-genuine-
        attempts-before-throttle contract even under full concurrency.
        """
        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "10.89.9.9"
        bucket_key = mod._account_bucket_key("nexus", "uuid-nexus")

        def admit(_):
            return mod._throttle_admit(
                r, f"auth:fail:ip:{ip}", f"auth:throttle:ip:{ip}",
                f"auth:fail:acct:{bucket_key}", f"auth:throttle:acct:{bucket_key}",
            )

        with ThreadPoolExecutor(max_workers=25) as ex:
            results = list(ex.map(admit, range(25)))

        final_acct_fails = int(r.get(f"auth:fail:acct:{bucket_key}"))
        assert final_acct_fails == 25, (
            f"expected exactly 25 recorded attempts (no lost updates under "
            f"concurrency — CWE-362), got {final_acct_fails}"
        )

        admitted = sum(1 for res in results if res[3] <= 0)  # acct_level_before
        assert admitted == mod._THROTTLE_ACCOUNT_THRESHOLD, (
            f"expected exactly {mod._THROTTLE_ACCOUNT_THRESHOLD} of 25 concurrent "
            f"requests to be admitted to real credential verification, got "
            f"{admitted} — the gate was bypassed under concurrency"
        )

    @pytest.mark.asyncio
    async def test_route_level_concurrent_burst_caps_authenticate_calls(self):
        """
        End-to-end via the real login() route: 25 concurrent wrong-password
        requests against one real account, all sharing one fake Redis and
        one mocked (but genuinely async, yielding) authenticate(), must
        result in authenticate() being called AT MOST
        _THROTTLE_ACCOUNT_THRESHOLD times — every request beyond that must
        be gated with 429 BEFORE authenticate() is ever invoked.

        Captain merge-review (2026-07-19): the original version of this test
        entered/exited ``patch.object(mod, ...)`` ONCE PER concurrent
        coroutine (25 nested enter/exit pairs racing on the SAME shared
        module attributes via asyncio.gather).  ``unittest.mock.patch``'s
        context-manager protocol is NOT safe for that: each ``__enter__``
        records "whatever the attribute currently is" as the value to
        restore on ``__exit__``.  If coroutine B enters after coroutine A
        has already patched the attribute, B records A's mock as its own
        "original" — so whichever coroutine's ``__exit__`` runs LAST
        restores the attribute to another coroutine's mock, not the true
        pre-test value, leaking a patched ``backoffice_state`` (etc.) past
        this test's teardown and corrupting unrelated tests that run
        afterward in the same session (confirmed: 3 net-new failures in
        test_v2234_gap3_human_identity_on_login.py on the full suite).

        Fix: patch EXACTLY ONCE, wrapping the whole ``asyncio.gather(...)``
        call — all 25 tasks share the same patched values for the duration
        of a single enter/exit pair, so there is no interleaving and no
        leak, regardless of how the 25 coroutines are scheduled internally.
        """
        from fastapi import HTTPException, Response

        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "10.89.9.10"
        nexus_id = "uuid-nexus"

        call_count = 0

        async def _slow_fail(*_a, **_kw):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.01)  # force a genuine yield/interleaving window
            return (False, None, "invalid_credentials")

        mock_state = _make_state((False, None, "invalid_credentials"))
        mock_state.auth_service.authenticate = AsyncMock(side_effect=_slow_fail)

        async def _one_attempt():
            body = MagicMock()
            body.username = "nexus"
            body.password = "wrong-password-guess"
            body.totp_code = "000000"
            request = _make_request(ip)
            resp = Response()
            try:
                await mod.login(body, request, resp)
                return "unexpected_success"
            except HTTPException as exc:
                return exc.status_code

        with patch.object(mod, "backoffice_state", mock_state), \
                patch.object(mod, "_get_throttle_redis", return_value=r), \
                patch.object(
                    mod, "_resolve_account_id_for_bucket",
                    new=AsyncMock(return_value=nexus_id),
                ), \
                patch.object(mod, "_register_human_identity_on_login"):
            results = await asyncio.gather(*[_one_attempt() for _ in range(25)])

        assert set(results) <= {401, 429}, f"unexpected outcomes: {results}"
        assert results.count(401) + results.count(429) == 25
        assert call_count == results.count(401), (
            "authenticate() must be called exactly once per admitted "
            "(non-gated) attempt — every gated attempt must short-circuit "
            "BEFORE authenticate() runs"
        )
        assert call_count <= mod._THROTTLE_ACCOUNT_THRESHOLD, (
            f"expected authenticate() to be called at most "
            f"{mod._THROTTLE_ACCOUNT_THRESHOLD} times across 25 concurrent "
            f"requests, got {call_count} — the gate was bypassed under "
            f"concurrency (this is the exact shape of Laura's r5 finding)"
        )


# ---------------------------------------------------------------------------
# 6. LAURA-412-MEDIUM (r5) — case-variant distinct accounts do NOT share a bucket
# ---------------------------------------------------------------------------

class TestCaseVariantAccountsDoNotShareBucket:
    """
    Laura's r5 reproduction: two genuinely distinct accounts differing only
    by case ("collision-probe-a" / "COLLISION-PROBE-A") shared one bucket
    under round 1's casefolded-hash key — flooding one 429'd the other.
    This system's identity model is CASE-SENSITIVE (confirmed via
    db/migrations/versions/0006_admin_accounts.py: username is a
    case-sensitive UNIQUE TEXT column; _fetch_by_username does an exact
    match; create_admin/create_user perform no case-insensitive collision
    check) — so these two usernames really can be two independent,
    simultaneously-valid accounts.
    """

    @pytest.mark.asyncio
    async def test_flooding_one_case_variant_does_not_lock_out_the_other(self):
        from fastapi import HTTPException

        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "203.0.113.222"

        account_a_id = "aaaaaaaa-0000-0000-0000-000000000001"
        account_b_id = "bbbbbbbb-0000-0000-0000-000000000002"

        # 3 wrong-password attempts against "collision-probe-a" trips ITS
        # OWN gate — genuine per-account protection, not the bug.
        for _ in range(3):
            with pytest.raises(HTTPException):
                await _attempt_login(
                    mod, r, "collision-probe-a", ip,
                    auth_result=(False, None, "invalid_credentials"),
                    account_id=account_a_id,
                )

        # "COLLISION-PROBE-A" — a DIFFERENT, distinct account (different
        # account_id) that merely happens to differ only by case — must
        # NOT be affected. Correct creds → success, not 429.
        variant_b = _make_account("COLLISION-PROBE-A")
        variant_b.account_id = account_b_id
        result = await _attempt_login(
            mod, r, "COLLISION-PROBE-A", ip,
            auth_result=(True, variant_b, "ok"),
            account_id=account_b_id,
        )
        assert result["status"] == "ok", (
            "a case-variant but genuinely DISTINCT account (different "
            "account_id) must not be locked out by the other variant's "
            "failures — this is the casefold-collision Laura proved live"
        )

    def test_bucket_keys_differ_for_distinct_account_ids(self):
        mod = _import_auth_mod()
        key_a = mod._account_bucket_key("collision-probe-a", "aaaaaaaa-0000-0000-0000-000000000001")
        key_b = mod._account_bucket_key("COLLISION-PROBE-A", "bbbbbbbb-0000-0000-0000-000000000002")
        assert key_a != key_b

    def test_atomic_admit_keeps_distinct_counters_for_case_variant_ids(self):
        """
        Direct proof at the Redis layer: flooding the bucket for account_id
        A must leave account_id B's bucket completely untouched, even
        though both derive from usernames that only differ by case.
        """
        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "203.0.113.223"

        key_a = mod._account_bucket_key("collision-probe-a", "aaaaaaaa-0000-0000-0000-000000000001")
        key_b = mod._account_bucket_key("COLLISION-PROBE-A", "bbbbbbbb-0000-0000-0000-000000000002")

        for _ in range(5):
            mod._throttle_admit(
                r, f"auth:fail:ip:{ip}", f"auth:throttle:ip:{ip}",
                f"auth:fail:acct:{key_a}", f"auth:throttle:acct:{key_a}",
            )

        assert int(r.get(f"auth:fail:acct:{key_a}")) == 5
        assert r.get(f"auth:fail:acct:{key_b}") is None, (
            "account B's bucket must remain completely untouched by "
            "account A's failures despite the case-only username difference"
        )


# ---------------------------------------------------------------------------
# 7. Captain merge-review — WebAuthn must use the UNCONDITIONAL bucket resolve
# ---------------------------------------------------------------------------

class TestWebAuthnBucketKeyingUsesUnconditionalResolve:
    """
    Captain merge-review (2026-07-19): webauthn_v1.py originally keyed the
    throttle bucket on ``_resolve_admin_id()`` (filters
    ``disabled=false AND account_tier='admin'``) — correct for deciding
    whether the WebAuthn business logic should proceed, but WRONG for
    throttle-bucket identity: a disabled admin account or a user-tier
    account attempting this endpoint resolves to ``None`` from
    ``_resolve_admin_id()`` and would fall through to the ``unk:``
    casefold-hash bucket fallback, narrowly reopening the LAURA-412-MEDIUM
    collision class for exactly those account states. Fixed by resolving
    the bucket key via ``_resolve_account_id_for_bucket()`` (unconditional —
    any tier, disabled or not) SEPARATELY from ``admin_id``.
    """

    def test_login_start_imports_and_uses_unconditional_resolve(self):
        import inspect
        from yashigani.backoffice.routes import webauthn_v1
        source = inspect.getsource(webauthn_v1)
        assert "_resolve_account_id_for_bucket" in source, (
            "webauthn_v1 must import _resolve_account_id_for_bucket for "
            "unconditional (any tier/disabled-state) bucket keying"
        )

    def test_login_start_resolves_bucket_id_before_throttle_and_before_admin_id(self):
        import inspect
        from yashigani.backoffice.routes import webauthn_v1
        source = inspect.getsource(webauthn_v1.login_start)
        bucket_idx = source.find("_resolve_account_id_for_bucket(")
        throttle_idx = source.find("_apply_auth_throttle(")
        admin_idx = source.find("_resolve_admin_id(")
        assert bucket_idx != -1 and throttle_idx != -1 and admin_idx != -1
        assert bucket_idx < throttle_idx, (
            "the unconditional bucket resolve must run before the throttle "
            "check, exactly like the password route"
        )

    def test_login_finish_resolves_bucket_id_before_throttle(self):
        import inspect
        from yashigani.backoffice.routes import webauthn_v1
        source = inspect.getsource(webauthn_v1.login_finish)
        bucket_idx = source.find("_resolve_account_id_for_bucket(")
        throttle_idx = source.find("_apply_auth_throttle(")
        assert bucket_idx != -1 and throttle_idx != -1
        assert bucket_idx < throttle_idx

    def test_reset_uses_bucket_account_id_not_admin_id(self):
        """
        The self-heal reset must key on the SAME identity that was checked/
        incremented (bucket_account_id), not admin_id — they coincide on the
        success path here, but the invariant must hold structurally.
        """
        import inspect
        from yashigani.backoffice.routes import webauthn_v1
        source = inspect.getsource(webauthn_v1.login_finish)
        assert "_reset_auth_failures(client_ip, body.username, bucket_account_id)" in source

    @pytest.mark.asyncio
    async def test_disabled_admin_account_gets_id_keyed_bucket_not_unk_fallback(self):
        """
        Live-shaped proof: an account that _resolve_admin_id() would REJECT
        (disabled, or wrong tier — simulated here by having it return None)
        must still have its throttle bucket keyed on its real, stable
        account_id via _resolve_account_id_for_bucket() — never the unk:
        casefold-hash fallback that a normalisation-collision could exploit.

        Asserts this by capturing the ARGUMENTS webauthn_v1 actually passes
        to _apply_auth_throttle, rather than exercising the real Redis atomic
        admit — this keeps the test focused purely on the WIRING regression
        Captain flagged (which resolver feeds which parameter) and immune to
        an unrelated cross-file test-order fragility: some other module in
        this suite (test_sec4_totp_redis_counter.py) legitimately
        importlib.reload()s auth.py to prove Redis-backed counters survive a
        process restart; that reload can rebind auth.py's module-level
        function objects out from under a same-process patch.object() aimed
        at auth.py's globals when reached via a cross-module call chain
        (webauthn_v1 -> auth._apply_auth_throttle -> auth._get_throttle_redis).
        Patching webauthn_v1's OWN _apply_auth_throttle attribute directly
        sidesteps that entirely — the atomic-admit Redis mechanics themselves
        are already proven correct by TestConcurrentBurstDoesNotBypassGate
        and the _account_bucket_key unit tests above.
        """
        from fastapi import HTTPException, Response
        from yashigani.backoffice.routes import webauthn_v1

        disabled_admin_id = "uuid-disabled-admin-real-id"

        body = MagicMock()
        body.username = "disabled-or-usertier-account"
        request = _make_request("203.0.113.240")
        resp = Response()

        captured: dict = {}

        def _capture_throttle(client_ip, username, account_id, response):
            captured["client_ip"] = client_ip
            captured["username"] = username
            captured["account_id"] = account_id
            return None  # do not gate — let login_start proceed to the admin_id check

        with patch.object(webauthn_v1, "_check_ip_access"):
            with patch.object(webauthn_v1, "_apply_auth_throttle", side_effect=_capture_throttle):
                # _resolve_admin_id rejects this account (disabled/wrong tier)
                with patch.object(
                    webauthn_v1, "_resolve_admin_id",
                    new=AsyncMock(return_value=None),
                ):
                    # but the account DOES exist — _resolve_account_id_for_bucket
                    # unconditionally resolves it
                    with patch.object(
                        webauthn_v1, "_resolve_account_id_for_bucket",
                        new=AsyncMock(return_value=disabled_admin_id),
                    ):
                        with pytest.raises(HTTPException) as exc_info:
                            await webauthn_v1.login_start(body, request, resp)
                        # 400 no_credentials_registered — admin_id was None,
                        # exactly as _resolve_admin_id said; but the captured
                        # call below must show the REAL account_id was used
                        # for the throttle bucket regardless.
                        assert exc_info.value.status_code == 400

        assert captured.get("account_id") == disabled_admin_id, (
            "_apply_auth_throttle must be called with the UNCONDITIONALLY "
            "resolved account_id (from _resolve_account_id_for_bucket), "
            "even though _resolve_admin_id separately rejected this account "
            "— otherwise the throttle bucket falls back to the unk: "
            "casefold-hash key, reopening LAURA-412-MEDIUM for disabled/"
            "user-tier accounts"
        )
        assert captured.get("username") == "disabled-or-usertier-account"


# ---------------------------------------------------------------------------
# 8. Captain merge-review — atomic admit fails closed (503) on Redis error
# ---------------------------------------------------------------------------

class TestThrottleAdmitFailsClosedOn503:
    """
    Captain flagged (Low, non-blocking but cheap): a Redis error inside
    _throttle_admit() previously propagated uncaught out of
    _apply_auth_throttle(), landing on FastAPI's generic 500 handler.  This
    module's established fail-closed pattern (see _totp_incr_failure call
    sites) is to catch the error and raise an explicit 503 instead, so
    monitoring/clients get an accurate signal rather than an opaque crash.
    """

    def test_apply_auth_throttle_returns_503_on_redis_error(self):
        """
        AVA-412-DOS (2026-07-23) split the single Redis round-trip into a
        read-only pre-check (``GET``) followed, only when not already
        gated, by the mutating atomic admit (``EVAL``) — a real Redis
        outage can surface at either call, so both are faulted here to
        prove the 503 fail-closed path holds regardless of which one a
        live outage happens to hit first.
        """
        from fastapi import HTTPException, Response

        mod = _import_auth_mod()
        broken_redis = MagicMock()
        broken_redis.get.side_effect = ConnectionError("redis unreachable")
        broken_redis.eval.side_effect = ConnectionError("redis unreachable")
        resp = Response()

        with patch.object(mod, "_get_throttle_redis", return_value=broken_redis):
            with pytest.raises(HTTPException) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", "someone", "uuid-someone", resp)

        assert exc_info.value.status_code == 503
        assert exc_info.value.detail.get("error") == "auth_throttle_unavailable"

    def test_apply_auth_throttle_returns_503_when_only_atomic_admit_fails(self):
        """
        Companion case: the read-only pre-check succeeds (fakeredis-style
        real GET on an empty/not-yet-gated key), but the mutating atomic
        admit itself fails — must still 503, not fall through to a 500 or
        silently admit the request.
        """
        from fastapi import HTTPException, Response

        mod = _import_auth_mod()
        broken_redis = MagicMock()
        broken_redis.get.return_value = None  # not gated — phase 1 passes
        broken_redis.eval.side_effect = ConnectionError("redis unreachable")
        resp = Response()

        with patch.object(mod, "_get_throttle_redis", return_value=broken_redis):
            with pytest.raises(HTTPException) as exc_info:
                mod._apply_auth_throttle("1.2.3.4", "someone", "uuid-someone", resp)

        assert exc_info.value.status_code == 503
        assert exc_info.value.detail.get("error") == "auth_throttle_unavailable"
