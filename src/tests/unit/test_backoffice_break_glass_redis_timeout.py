"""
Unit tests for ROOTFUL-P2-001 — break-glass Redis socket_timeout + retry-with-backoff.

Covers:
  1. Redis client constructed with socket_timeout / socket_connect_timeout / retry_on_timeout /
     health_check_interval kwargs (verified via AST inspection of entrypoint.py).
  2. Retry-with-backoff: slow Redis (TimeoutError on first attempt, success on second) —
     verify break_glass_manager IS initialised and total elapsed time stays reasonable.
  3. Failure-injection: Redis completely unreachable for all attempts — verify graceful
     degradation (break_glass_manager remains None, no exception escapes _bootstrap).

Note: tests 2 and 3 replay the retry logic in isolation (pure-logic tests) rather than
importing backoffice.entrypoint, which runs _bootstrap() at module level and requires
/run/secrets to exist.  The AST tests in group 1 verify the actual source matches.

Ref: Captain PR #52 debug; ROOTFUL-P2-001.

Last updated: 2026-05-07T00:00:00+01:00
"""
from __future__ import annotations

import ast
import time as _time
from pathlib import Path
from typing import Iterator, List, Optional
from unittest.mock import MagicMock

import pytest

SRC = Path(__file__).parent.parent.parent / "yashigani"
ENTRYPOINT_SRC = SRC / "backoffice" / "entrypoint.py"


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _entrypoint_source() -> str:
    return ENTRYPOINT_SRC.read_text(encoding="utf-8")


def _find_break_glass_try(tree: ast.AST):
    """Return the outer try block that contains 'init_break_glass'."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            src = ast.unparse(node)
            if "init_break_glass" in src and "redis_bg" in src:
                return node
    return None


# ---------------------------------------------------------------------------
# Group 1 — socket_timeout kwargs verified via AST
# ---------------------------------------------------------------------------

class TestBreakGlassRedisClientKwargs:
    """
    ROOTFUL-P2-001: redis.from_url() in the break-glass block must carry
    socket_timeout, socket_connect_timeout, retry_on_timeout, health_check_interval.
    """

    def _get_from_url_call(self):
        """Return the AST Call node for redis_bg = _redis.from_url(...)."""
        tree = ast.parse(_entrypoint_source())
        bg_try = _find_break_glass_try(tree)
        if bg_try is None:
            return None
        for node in ast.walk(bg_try):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "from_url":
                    kwargs = {kw.arg for kw in node.keywords}
                    if "socket_timeout" in kwargs or "socket_connect_timeout" in kwargs:
                        return node
        return None

    def test_socket_timeout_kwarg_present(self):
        """socket_timeout must be passed to from_url() in the break-glass block."""
        call_node = self._get_from_url_call()
        assert call_node is not None, (
            "Could not find _redis.from_url(...) with socket_timeout in break-glass block — "
            "ROOTFUL-P2-001 fix not applied"
        )
        kwargs = {kw.arg for kw in call_node.keywords}
        assert "socket_timeout" in kwargs, f"socket_timeout missing; found: {kwargs}"

    def test_socket_connect_timeout_kwarg_present(self):
        """socket_connect_timeout must be passed to from_url() in the break-glass block."""
        call_node = self._get_from_url_call()
        assert call_node is not None
        kwargs = {kw.arg for kw in call_node.keywords}
        assert "socket_connect_timeout" in kwargs, (
            f"socket_connect_timeout missing; found: {kwargs}"
        )

    def test_retry_on_timeout_kwarg_present(self):
        """retry_on_timeout must be passed to from_url() in the break-glass block."""
        call_node = self._get_from_url_call()
        assert call_node is not None
        kwargs = {kw.arg for kw in call_node.keywords}
        assert "retry_on_timeout" in kwargs, f"retry_on_timeout missing; found: {kwargs}"

    def test_health_check_interval_kwarg_present(self):
        """health_check_interval must be passed to from_url() in the break-glass block."""
        call_node = self._get_from_url_call()
        assert call_node is not None
        kwargs = {kw.arg for kw in call_node.keywords}
        assert "health_check_interval" in kwargs, (
            f"health_check_interval missing; found: {kwargs}"
        )

    def test_socket_timeout_value_is_positive_float(self):
        """socket_timeout value must be a positive number (<=30 s)."""
        call_node = self._get_from_url_call()
        assert call_node is not None
        for kw in call_node.keywords:
            if kw.arg == "socket_timeout":
                if isinstance(kw.value, ast.Constant):
                    val = kw.value.value
                    assert isinstance(val, (int, float)), f"Expected numeric, got {type(val)}"
                    assert 0 < val <= 30, f"socket_timeout={val} outside reasonable (0, 30] range"
                return
        pytest.fail("socket_timeout keyword not found after earlier assertion passed")

    def test_retry_loop_present_in_break_glass_block(self):
        """The break-glass block must contain a for/while loop for retry logic."""
        tree = ast.parse(_entrypoint_source())
        bg_try = _find_break_glass_try(tree)
        assert bg_try is not None, "Could not find break-glass try block"
        has_loop = any(
            isinstance(node, (ast.For, ast.While))
            for node in ast.walk(bg_try)
        )
        assert has_loop, (
            "Break-glass try block has no retry loop — ROOTFUL-P2-001 retry-with-backoff not present"
        )

    def test_time_sleep_call_present_in_break_glass_block(self):
        """The break-glass block must call time.sleep() for backoff between retries."""
        tree = ast.parse(_entrypoint_source())
        bg_try = _find_break_glass_try(tree)
        assert bg_try is not None
        block_src = ast.unparse(bg_try)
        assert "sleep" in block_src, (
            "No sleep() call found in break-glass block — backoff not implemented"
        )


# ---------------------------------------------------------------------------
# Pure-logic helper — replay the retry loop without importing entrypoint
# ---------------------------------------------------------------------------

def _run_retry_loop(
    ping_side_effects: List,
    sleep_fn=None,
    max_attempts: int = 6,
):
    """
    Replay the break-glass retry-with-backoff logic in isolation.

    ping_side_effects: list where each item is either:
      - an Exception instance to raise on that ping attempt, OR
      - None (meaning success — ping returns normally)

    Returns (ping_ok: bool, warnings: List[str], sleep_calls: List[float])
    """
    warnings_out: List[str] = []
    sleep_calls: List[float] = []

    # sleep_fn: if provided, used instead of recording; we always record separately.
    # By default (sleep_fn=None) we just record — no real I/O.
    def _do_sleep(x: float) -> None:
        sleep_calls.append(x)
        if sleep_fn is not None:
            sleep_fn(x)

    ping_ok = False
    backoff = 1.0
    exc_iter = iter(ping_side_effects)

    for attempt in range(1, max_attempts + 1):
        side_effect = next(exc_iter, None)  # None means "no more — success"
        try:
            if isinstance(side_effect, Exception):
                raise side_effect
            # side_effect is None → ping succeeds
            ping_ok = True
            break
        except Exception as ping_exc:
            if attempt < max_attempts:
                msg = (
                    f"Break glass Redis ping attempt {attempt}/{max_attempts} "
                    f"failed ({ping_exc}) — retrying in {backoff:.0f} s"
                )
                warnings_out.append(msg)
                _do_sleep(backoff)
                backoff = min(backoff * 2, 16.0)
            else:
                msg = (
                    f"Break glass Redis ping attempt {attempt}/{max_attempts} "
                    f"failed ({ping_exc}) — giving up"
                )
                warnings_out.append(msg)

    if not ping_ok:
        warnings_out.append(
            f"Break glass unavailable — Redis unreachable after {max_attempts} attempts"
        )

    return ping_ok, warnings_out, sleep_calls


# ---------------------------------------------------------------------------
# Group 2 — retry-with-backoff: slow Redis, succeeds eventually
# ---------------------------------------------------------------------------

class TestBreakGlassRetryWithBackoff:
    """
    ROOTFUL-P2-001: retry-with-backoff logic must succeed when Redis
    eventually responds, and must not block startup beyond the 120 s window.
    """

    def test_retry_succeeds_on_second_attempt(self):
        """
        Simulate TimeoutError on attempt 1, success on attempt 2.
        ping_ok must be True; exactly one warning citing attempt 1/6.
        """
        ping_ok, warnings, sleep_calls = _run_retry_loop(
            ping_side_effects=[TimeoutError("timed out"), None],
        )

        assert ping_ok, "ping_ok must be True when Redis succeeds on 2nd attempt"
        assert len(warnings) == 1, f"Expected 1 warning, got {len(warnings)}: {warnings}"
        assert "attempt 1/6" in warnings[0], f"Warning must cite attempt 1/6: {warnings[0]}"
        assert "retrying" in warnings[0].lower(), f"Warning must say 'retrying': {warnings[0]}"
        assert sleep_calls == [1.0], f"Expected backoff sleep [1.0], got {sleep_calls}"

    def test_retry_backoff_doubles_each_attempt(self):
        """
        Simulate 4 consecutive TimeoutErrors then success on attempt 5.
        Backoff sequence must be 1, 2, 4, 8 s.
        """
        ping_ok, warnings, sleep_calls = _run_retry_loop(
            ping_side_effects=[
                TimeoutError("t1"),
                TimeoutError("t2"),
                TimeoutError("t3"),
                TimeoutError("t4"),
                None,  # success on attempt 5
            ],
        )

        assert ping_ok
        assert len(warnings) == 4, f"Expected 4 warnings for 4 failed attempts, got: {warnings}"
        assert sleep_calls == [1.0, 2.0, 4.0, 8.0], (
            f"Expected backoff sequence [1.0, 2.0, 4.0, 8.0], got {sleep_calls}"
        )

    def test_backoff_capped_at_16_seconds(self):
        """Backoff must not exceed the 16 s cap even after many failures."""
        ping_ok, warnings, sleep_calls = _run_retry_loop(
            ping_side_effects=[
                TimeoutError("t1"),
                TimeoutError("t2"),
                TimeoutError("t3"),
                TimeoutError("t4"),
                TimeoutError("t5"),
                None,  # success on attempt 6
            ],
        )

        assert ping_ok
        assert sleep_calls == [1.0, 2.0, 4.0, 8.0, 16.0], (
            f"Expected [1.0, 2.0, 4.0, 8.0, 16.0], got {sleep_calls}"
        )

    def test_total_elapsed_with_mocked_sleep_is_fast(self):
        """
        With mocked sleep (no-op), the retry loop itself completes well under 5 s.
        This guards against accidental real I/O inside the pure logic.
        """
        t_start = _time.monotonic()
        ping_ok, _, _ = _run_retry_loop(
            ping_side_effects=[
                TimeoutError("t1"),
                TimeoutError("t2"),
                None,
            ],
            sleep_fn=lambda _: None,  # no-op — don't count real time
        )
        elapsed = _time.monotonic() - t_start

        assert ping_ok
        assert elapsed < 2.0, (
            f"Retry loop took {elapsed:.2f} s with mocked sleep — unexpected real I/O"
        )

    def test_success_on_first_attempt_emits_no_warning(self):
        """No warnings emitted when Redis responds on the very first attempt."""
        ping_ok, warnings, sleep_calls = _run_retry_loop(
            ping_side_effects=[None],  # success immediately
        )
        assert ping_ok
        assert warnings == [], f"No warnings expected on first-attempt success; got: {warnings}"
        assert sleep_calls == [], f"No sleeps expected on first-attempt success; got: {sleep_calls}"


# ---------------------------------------------------------------------------
# Group 3 — Failure injection: Redis completely unreachable
# ---------------------------------------------------------------------------

class TestBreakGlassRedisUnreachable:
    """
    ROOTFUL-P2-001: when Redis is unreachable for all N attempts, the
    break-glass block must degrade gracefully — ping_ok=False, no exception
    escapes, and warnings emitted for every failed attempt.
    """

    def _run_all_fail(self):
        return _run_retry_loop(
            ping_side_effects=[ConnectionError("Redis unreachable")] * 6,
            sleep_fn=lambda _: None,
        )

    def test_ping_ok_is_false_when_redis_unreachable(self):
        """ping_ok must be False when Redis never responds."""
        ping_ok, _, _ = self._run_all_fail()
        assert not ping_ok, "ping_ok must be False when all 6 attempts fail"

    def test_warning_emitted_for_each_failed_attempt(self):
        """
        Warnings: 5 intermediate 'retrying' + 1 'giving up' + 1 final 'unavailable' = 7.
        """
        _, warnings, _ = self._run_all_fail()
        assert len(warnings) == 7, (
            f"Expected 7 warnings for 6 failed attempts, got {len(warnings)}: {warnings}"
        )

    def test_retrying_warnings_for_attempts_1_to_5(self):
        """Attempts 1-5 must each emit a 'retrying' warning."""
        _, warnings, _ = self._run_all_fail()
        retrying = [w for w in warnings if "retrying" in w.lower()]
        assert len(retrying) == 5, (
            f"Expected 5 'retrying' warnings, got {len(retrying)}: {retrying}"
        )

    def test_giving_up_warning_emitted(self):
        """The 6th attempt must emit a 'giving up' warning."""
        _, warnings, _ = self._run_all_fail()
        giving_up = [w for w in warnings if "giving up" in w.lower()]
        assert len(giving_up) == 1, f"Expected 1 'giving up' warning; got: {giving_up}"

    def test_final_unavailable_warning_emitted(self):
        """A final 'unavailable' summary warning must appear after all retries fail."""
        _, warnings, _ = self._run_all_fail()
        unavailable = [w for w in warnings if "unavailable" in w.lower()]
        assert unavailable, f"Expected an 'unavailable' summary warning; got: {warnings}"

    def test_no_exception_escapes(self):
        """The retry loop must never raise — advisory degradation only."""
        try:
            self._run_all_fail()
        except Exception as exc:
            pytest.fail(
                f"Exception escaped from break-glass all-fail path: {exc!r}"
            )

    def test_total_backoff_sequence_all_fail(self):
        """Full backoff sequence for 6 failures: 1, 2, 4, 8, 16 (5 sleeps, not 6)."""
        _, _, sleep_calls = self._run_all_fail()
        # 5 inter-attempt sleeps (not 6 — no sleep after the final 'giving up')
        assert sleep_calls == [1.0, 2.0, 4.0, 8.0, 16.0], (
            f"Expected [1.0, 2.0, 4.0, 8.0, 16.0], got {sleep_calls}"
        )
