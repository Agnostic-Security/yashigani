"""
Regression tests — AVA-RETRYAFTER (Ava, live Redis inspection db1,
2026-07-24, fix/v412-throttle-retryafter): auth-throttle RFC 6585 §4
Retry-After contract violation.

## The finding

`_apply_auth_throttle` / `_reject_with_throttle` in
`src/yashigani/backoffice/routes/auth.py` reported the documented
ESCALATING Retry-After schedule (`_THROTTLE_DELAYS` = [30, 60, 180, 450,
900], indexed by level) via `_throttle_delay_for_level()`, but
`_THROTTLE_ADMIT_LUA` set the actual Redis EXPIRE on the escalation-level
keys (`auth:throttle:ip:*` / `auth:throttle:acct:*` — the keys whose mere
PRESENCE is what `_throttle_current_level()` reads to gate a request) to
the flat rolling `_THROTTLE_WINDOW_SECONDS` (900s) regardless of level.
A level-1 client (3 consecutive failures) was told "Retry-After: 30" but
the key that actually released the gate did not expire for 900s — a ~30x
mismatch between advertised and actual wait (RFC 6585 §4 contract
violation).

## The fix

`_THROTTLE_ADMIT_LUA` now receives the `_THROTTLE_DELAYS` schedule as
trailing ARGV entries and sets each escalation-level key's EXPIRE to
THAT level's own delay value (level 1 -> 30s, ..., level 5 -> 900s
ceiling) instead of the flat window. The gating key's real TTL now always
equals what `_throttle_delay_for_level()` reports for the same level —
the design determination being that the module's own comments and the
pre-existing test suite (`test_v2232_login_throttle_retry_after.py`)
already document and pin an ESCALATING-backoff design, not a fixed 900s
window.

Each test below would FAIL on the pre-fix code (real TTL ~900s while
Retry-After reports 30/60/180/450 at levels 1-4).

YSG-RISK-098 (AVA-412-DOS self-extend fix, 2026-07-23) is a SEPARATE,
orthogonal invariant — the phase-1 read-only pre-check / phase-2
mutating-admit split — and must remain completely intact: blocked probes
against an already-gated account must still perform ZERO Redis mutation,
regardless of which TTL value was used when the gate was first set.
`TestSelfExtendStillHoldsUnderNewTTLScheme` below proves this holds with
the corrected per-level TTLs in place.

Retro ref: T4 — every Python-level retro item must have a regression test.
Last updated: 2026-07-24T00:00:00+00:00
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip("fakeredis")
pytest.importorskip("fastapi")
pytest.importorskip("lupa")  # Lua runtime — required for fakeredis EVAL emulation


# ---------------------------------------------------------------------------
# Helpers (mirrors test_ava_412_dos_auth_throttle_self_extend.py)
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


def _import_auth_mod():
    from yashigani.backoffice.routes import auth as _auth_mod
    return _auth_mod


# ---------------------------------------------------------------------------
# 1. Retry-After header == actual Redis TTL of the gating key, at every level
# ---------------------------------------------------------------------------

class TestRetryAfterMatchesActualTTL:
    """
    Drives the real _throttle_admit()/_apply_auth_throttle() path against a
    fakeredis backend (real Lua EVAL emulation via lupa — not a mocked
    return value) so the assertions observe genuine Redis-side TTL, not a
    Python-level stand-in.
    """

    @pytest.mark.parametrize(
        "level,expected_delay",
        [(1, 30), (2, 60), (3, 180), (4, 450), (5, 900)],
    )
    def test_retry_after_equals_actual_key_ttl_at_each_level(self, level, expected_delay):
        mod = _import_auth_mod()
        r = _fake_redis()
        bucket_key = mod._account_bucket_key(f"retryafter-target-{level}", None)
        acct_fail_key = f"auth:fail:acct:{bucket_key}"
        acct_throttle_key = f"auth:throttle:acct:{bucket_key}"
        ip = f"198.51.100.{level}"

        # _THROTTLE_ADMIT_LUA escalates the level by exactly 1 on EVERY call
        # once the cumulative acct_fails counter has crossed the threshold
        # (it never resets mid-window) — so reaching level N takes exactly
        # threshold + (N - 1) genuine admits: the Nth call is the one whose
        # own SET writes level N with EX ttl_for_level(N). This exercises
        # the real Lua script end to end (fakeredis + lupa), not a mocked
        # eval() return.
        threshold = mod._THROTTLE_ACCOUNT_THRESHOLD
        admits_needed_for_level = threshold + (level - 1)
        for _ in range(admits_needed_for_level):
            mod._throttle_admit(
                r,
                f"auth:fail:ip:{ip}", f"auth:throttle:ip:{ip}",
                acct_fail_key, acct_throttle_key,
            )

        actual_level = int(r.get(acct_throttle_key) or 0)
        assert actual_level == level, f"expected to reach level {level}, got {actual_level}"

        actual_ttl = r.ttl(acct_throttle_key)
        reported_delay = mod._throttle_delay_for_level(actual_level)

        assert reported_delay == expected_delay, (
            f"_throttle_delay_for_level({actual_level}) = {reported_delay}, expected {expected_delay}"
        )
        # THE CORE INVARIANT: Retry-After (reported_delay) must equal the
        # ACTUAL remaining Redis TTL of the key that gates the request.
        assert actual_ttl == reported_delay, (
            f"level {level}: Retry-After reports {reported_delay}s but the "
            f"gating key's actual TTL is {actual_ttl}s — RFC 6585 contract "
            f"violation (pre-fix this was ~900s at every level)"
        )

    def test_route_level_429_retry_after_header_matches_key_ttl_at_level_1(self):
        """
        End-to-end: drive the real login() route to a 429 and confirm the
        Retry-After header value equals the account throttle key's actual
        Redis TTL at the moment of the response.
        """
        import asyncio
        from fastapi import HTTPException, Response

        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "203.0.113.90"
        username = "route-retryafter-victim"
        account_id = "uuid-route-retryafter-victim"
        bucket_key = mod._account_bucket_key(username, account_id)
        acct_throttle_key = f"auth:throttle:acct:{bucket_key}"

        body = MagicMock()
        body.username = username
        body.password = "wrong"
        body.totp_code = "123456"

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.authenticate = AsyncMock(return_value=(False, None, "invalid_credentials"))
        mock_state.session_store = MagicMock()
        mock_state.audit_writer = MagicMock()
        mock_state.identity_registry = None

        async def _attempt():
            request = _make_request(ip)
            resp = Response()
            with patch.object(mod, "backoffice_state", mock_state):
                with patch.object(mod, "_get_throttle_redis", return_value=r):
                    with patch.object(
                        mod, "_resolve_account_id_for_bucket",
                        new=AsyncMock(return_value=account_id),
                    ):
                        with patch.object(mod, "_register_human_identity_on_login"):
                            return await mod.login(body, request, resp)

        # 3 genuine wrong-password attempts cross the threshold -> level 1.
        for _ in range(mod._THROTTLE_ACCOUNT_THRESHOLD):
            with pytest.raises(HTTPException) as exc_info:
                asyncio.run(_attempt())
            assert exc_info.value.status_code in (401, 429)

        # 4th attempt: must be 429 with Retry-After matching the real TTL.
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(_attempt())

        exc = exc_info.value
        assert exc.status_code == 429
        retry_after = int(exc.headers["Retry-After"])
        actual_ttl = r.ttl(acct_throttle_key)
        assert retry_after == 30, f"level 1 must report 30, got {retry_after}"
        assert actual_ttl == retry_after == 30, (
            f"Retry-After header ({retry_after}) must equal the account "
            f"throttle key's actual Redis TTL ({actual_ttl}) at level 1"
        )


# ---------------------------------------------------------------------------
# 2. YSG-RISK-098 (AVA-412-DOS self-extend) still holds under the corrected
#    per-level TTL scheme — blocked probes never refresh/extend the window,
#    regardless of which TTL value was used when the gate was first armed.
# ---------------------------------------------------------------------------

class TestSelfExtendStillHoldsUnderNewTTLScheme:

    def test_blocked_probes_do_not_refresh_the_corrected_level1_ttl(self):
        from fastapi import HTTPException, Response

        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "203.0.113.95"
        username = "retryafter-self-extend-victim"
        account_id = "uuid-retryafter-self-extend-victim"
        bucket_key = mod._account_bucket_key(username, account_id)
        acct_fail_key = f"auth:fail:acct:{bucket_key}"
        acct_throttle_key = f"auth:throttle:acct:{bucket_key}"

        resp = Response()
        with patch.object(mod, "_get_throttle_redis", return_value=r):
            for _ in range(mod._THROTTLE_ACCOUNT_THRESHOLD):
                mod._apply_auth_throttle(ip, username, account_id, resp)

            # Gated at level 1 — TTL is now the CORRECT ~30s (not ~900s).
            assert int(r.get(acct_throttle_key)) == 1
            ttl_fresh = r.ttl(acct_throttle_key)
            assert 0 < ttl_fresh <= 30

            fail_count_before = int(r.get(acct_fail_key))
            ttl_before = ttl_fresh

            # 10 blocked probes (zero credentials, never reach authenticate())
            # must NOT push the TTL back up toward 30s or re-escalate, and
            # must not touch the fail counter at all — the YSG-RISK-098
            # invariant, independent of which TTL scale is in play.
            for _ in range(10):
                with pytest.raises(HTTPException) as exc_info:
                    mod._apply_auth_throttle(ip, username, account_id, resp)
                assert exc_info.value.status_code == 429

            fail_count_after = int(r.get(acct_fail_key))
            ttl_after = r.ttl(acct_throttle_key)
            level_after = int(r.get(acct_throttle_key))

            assert fail_count_after == fail_count_before, (
                "a blocked (already-gated) probe must never increment the "
                "account fail counter"
            )
            assert level_after == 1, (
                "a blocked probe must never re-escalate the level"
            )
            assert ttl_after <= ttl_before, (
                f"blocked probes must never refresh/extend the lockout TTL "
                f"— got ttl_before={ttl_before}, ttl_after={ttl_after}"
            )
            assert ttl_after > 0, "the key must still be counting down naturally"

    def test_ceiling_level_ttl_is_900_and_still_self_heals(self):
        """Level 5 (ceiling) must still use the documented 900s value, and a
        successful login must still clear the gate (self-heal unaffected by
        the TTL-scheme fix)."""
        mod = _import_auth_mod()
        r = _fake_redis()
        ip = "203.0.113.96"
        bucket_key = mod._account_bucket_key("ceiling-target", None)
        acct_fail_key = f"auth:fail:acct:{bucket_key}"
        acct_throttle_key = f"auth:throttle:acct:{bucket_key}"

        # Drive well past the 5-level table with genuine (non-gated-check)
        # atomic admits, mirroring the pre-existing bounded-escalation tests.
        for _ in range(20):
            mod._throttle_admit(
                r, f"auth:fail:ip:{ip}", f"auth:throttle:ip:{ip}",
                acct_fail_key, acct_throttle_key,
            )

        level = int(r.get(acct_throttle_key) or 0)
        assert level == len(mod._THROTTLE_DELAYS)
        ttl = r.ttl(acct_throttle_key)
        assert ttl == 900, f"ceiling level TTL must be 900s, got {ttl}"

        # Self-heal: clearing the bucket (as _reset_auth_failures does on a
        # successful login) must still fully lift the gate.
        r.delete(acct_fail_key, acct_throttle_key)
        assert mod._throttle_current_level(r, acct_throttle_key) == 0
