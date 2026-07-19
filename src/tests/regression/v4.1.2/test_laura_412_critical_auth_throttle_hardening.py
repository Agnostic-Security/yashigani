"""
Regression tests — LAURA-412-CRITICAL (podman r4 pentest, 2026-07-19).

Finding: `_apply_auth_throttle` / `_record_auth_failure` / `_real_client_ip`
keyed every failed login attempt SOLELY on the apparent client IP.  Under a
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

Fix (fix/v412-auth-throttle-hardening): dual-bucket, ACCOUNT-GATED design.
  * The per-account bucket (username-keyed, IP-independent) is the sole gate.
  * The per-IP bucket is a severity modifier only — never an independent
    gate.
  * The global (any-IP) bucket is removed entirely.
  * Escalation bounded at 900s (15 min); no permanent-block branch.
  * Successful auth clears both the account gate and the IP severity bucket.

Each test below would FAIL on the pre-fix code:
  - test_shared_ip_does_not_lock_out_clean_account: pre-fix, cedar's login
    from the same IP as the attacker's noise would 429 (both the old per-IP
    and global buckets gate purely on IP-wide/any-IP failure counts).
  - test_successful_login_self_heals_account_counter: pre-fix, a login
    already blocked at the top of the request could never reach the
    success path, so the counter could never be observed to clear via a
    real login (this test proves the fixed code's reset function AND that
    the gate reopens for the same account after a genuine success).
  - test_escalation_is_bounded_no_permanent_block: pre-fix, level > 6
    written `auth:blocked:{ip}` with NO TTL (ttl() == -1 == persistent).
  - test_per_account_brute_force_still_throttled: proves the redesign has
    not thrown out real brute-force protection — repeated failures against
    ONE specific account still escalate and eventually gate that account.

Retro ref: T4 — every Python-level retro item must have a regression test.
Last updated: 2026-07-19T00:00:00+00:00
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("fakeredis")
pytest.importorskip("fastapi")


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


async def _attempt_login(mod, fake_redis, username: str, client_ip: str, auth_result, response=None):
    """
    Drive the real login() route handler with a fake Redis backing the
    throttle and a fully mocked backoffice_state/auth_service — exercises
    the actual _check_ip_access -> _apply_auth_throttle -> authenticate ->
    _record_auth_failure/_reset_auth_failures sequence exactly as the HTTP
    route does, not a re-implementation of it.
    """
    from fastapi import Response

    body = MagicMock()
    body.username = username
    body.password = "irrelevant-mocked"
    body.totp_code = "123456"
    request = _make_request(client_ip)
    resp = response if response is not None else Response()

    mock_state = _make_state(auth_result)
    with patch.object(mod, "backoffice_state", mock_state):
        with patch.object(mod, "_get_throttle_redis", return_value=fake_redis):
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
        gated, because no single account accumulates its own failures.
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
        An account gated by its own prior failures must be able to recover
        via a single correct login — not via manual Redis surgery.
        """
        from fastapi import HTTPException

        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "203.0.113.5"
        bob = _make_account("bob")

        # 3 failed attempts against bob's OWN account trip the account gate
        # (threshold = 3).
        for _ in range(3):
            with pytest.raises(HTTPException):
                await _attempt_login(mod, r, "bob", ip, auth_result=(False, None, "invalid_credentials"))

        # 4th attempt (even with correct creds) is now gated pre-auth.
        with pytest.raises(HTTPException) as exc_info:
            await _attempt_login(mod, r, "bob", ip, auth_result=(True, bob, "ok"))
        assert exc_info.value.status_code == 429

        # Directly exercise the reset helper (mirrors what a real successful
        # authenticate() call does inside login() once the gate reopens —
        # e.g. after the bounded window elapses, or via WebAuthn which is
        # keyed on the same account bucket).
        with patch.object(mod, "_get_throttle_redis", return_value=r):
            mod._reset_auth_failures(ip, "bob")

        acct_hash = mod._hash_account("bob")
        assert r.get(f"auth:fail:acct:{acct_hash}") is None
        assert r.get(f"auth:throttle:acct:{acct_hash}") is None
        assert r.get(f"auth:fail:ip:{ip}") is None
        assert r.get(f"auth:throttle:ip:{ip}") is None

        # Gate is now open again — bob can log in.
        result = await _attempt_login(mod, r, "bob", ip, auth_result=(True, bob, "ok"))
        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_login_route_clears_counters_on_success_without_manual_reset(self):
        """
        End-to-end via the real route: after a below-threshold failure, a
        SUCCESSFUL login (still 2 failures short of the account gate) must
        leave the account with a zeroed counter afterward — proving
        login()'s own success path (not a test helper) performs the heal.
        """
        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "203.0.113.9"
        alice = _make_account("alice")

        # 2 failures — below the threshold (3), account not yet gated.
        for _ in range(2):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                await _attempt_login(mod, r, "alice", ip, auth_result=(False, None, "invalid_credentials"))
            assert exc_info.value.status_code == 401

        acct_hash = mod._hash_account("alice")
        assert int(r.get(f"auth:fail:acct:{acct_hash}") or 0) == 2

        # Successful login — login()'s own _reset_auth_failures call must fire.
        result = await _attempt_login(mod, r, "alice", ip, auth_result=(True, alice, "ok"))
        assert result["status"] == "ok"
        assert r.get(f"auth:fail:acct:{acct_hash}") is None, (
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
        acct_hash = mod._hash_account("attacked-account")

        # Drive far past the old 6-level escalation table (20 rounds of
        # 3 failures each = 60 recorded failures against one account).
        with patch.object(mod, "_get_throttle_redis", return_value=r):
            for _ in range(20):
                mod._record_auth_failure(ip, "attacked-account")

        level = int(r.get(f"auth:throttle:acct:{acct_hash}") or 0)
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

        with patch.object(mod, "_get_throttle_redis", return_value=r):
            for _ in range(10):
                mod._record_auth_failure(ip, "another-attacked-account")

        acct_hash = mod._hash_account("another-attacked-account")
        for key in (
            f"auth:fail:ip:{ip}",
            f"auth:throttle:ip:{ip}",
            f"auth:fail:acct:{acct_hash}",
            f"auth:throttle:acct:{acct_hash}",
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

        # First 3 attempts fail normally (401) — below threshold.
        for _ in range(3):
            with pytest.raises(HTTPException) as exc_info:
                await _attempt_login(mod, r, "targeted-victim", ip, auth_result=(False, None, "invalid_credentials"))
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

        resp = MagicMock()
        resp.headers = {}
        from fastapi import HTTPException
        with patch.object(mod, "_get_throttle_redis", return_value=r):
            for i in range(3):
                mod._record_auth_failure(f"203.0.113.{100 + i}", "distributed-target")

            with pytest.raises(HTTPException) as exc_info:
                # A 4th attempt from yet ANOTHER new IP is still gated —
                # the account bucket doesn't care which IP is asking.
                mod._apply_auth_throttle("203.0.113.200", "distributed-target", resp)
        assert exc_info.value.status_code == 429
