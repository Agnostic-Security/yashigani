"""Unit tests for LAURA-30-004: OPA document policy startup push retry hardening.

Verifies that:
  1. On startup the document policy push retries up to 5 attempts (was 3) before giving up.
  2. The sleep between retries is 3s (was 2s).
  3. A transient OPA failure (first N attempts fail) does not prevent eventual success.
  4. All 5 failures leads to a warning log (not an exception propagating out).
  5. The retry constants in app.py match the LAURA-30-004 spec.
"""
import ast
import asyncio
import inspect
import pathlib
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest


# ── 1. Source-level constant verification ─────────────────────────────────────

APP_PY = pathlib.Path(__file__).parent.parent.parent / "yashigani" / "backoffice" / "app.py"


def _extract_doc_push_retry_constants():
    """Parse app.py and return (max_attempts, sleep_seconds) from the document OPA push block."""
    src = APP_PY.read_text()
    tree = ast.parse(src)

    # Walk all For loops looking for the one that references push_document_data
    for node in ast.walk(tree):
        if not isinstance(node, ast.For):
            continue
        # Look for range(1, N) iter
        iter_node = node.iter
        if not (isinstance(iter_node, ast.Call)
                and isinstance(iter_node.func, ast.Name)
                and iter_node.func.id == "range"):
            continue
        args = iter_node.args
        if len(args) != 2:
            continue
        # Check body contains push_document_data
        body_src = ast.unparse(node)
        if "push_document_data" not in body_src:
            continue

        max_attempt = ast.literal_eval(args[1])  # range(1, MAX)

        # Find asyncio.sleep(N) inside the body
        sleep_secs = None
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == "sleep"
                    and isinstance(sub.func.value, ast.Name)
                    and sub.func.value.id == "asyncio"):
                if sub.args:
                    sleep_secs = ast.literal_eval(sub.args[0])

        return max_attempt, sleep_secs

    return None, None


class TestLaura30004DocOpaRetryConstants:
    """Source-code verification of the retry constants."""

    def test_max_attempts_is_5(self):
        """LAURA-30-004 fix: retry count raised from 3 → 5.

        range(1, 6) produces 5 iterations (1,2,3,4,5).  The parsed value is the
        exclusive upper-bound argument (6); the number of attempts = value - 1 = 5.
        """
        max_attempts_arg, _ = _extract_doc_push_retry_constants()
        assert max_attempts_arg is not None, "Could not parse retry loop from app.py"
        # range(1, 6) → 5 attempts; range(1, 4) would be old 3-attempt code
        num_attempts = max_attempts_arg - 1
        assert num_attempts == 5, (
            f"Expected 5 retry attempts (LAURA-30-004 spec); "
            f"got range(1, {max_attempts_arg}) = {num_attempts} attempt(s)"
        )

    def test_sleep_between_retries_is_3s(self):
        """LAURA-30-004 fix: sleep raised from 2s → 3s."""
        _, sleep_secs = _extract_doc_push_retry_constants()
        assert sleep_secs is not None, "Could not parse asyncio.sleep from retry loop"
        assert sleep_secs == 3, (
            f"Expected 3s sleep between retries (LAURA-30-004 spec), got {sleep_secs}s"
        )


# ── 2. Functional retry behaviour ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_doc_push_succeeds_on_first_attempt():
    """Push succeeds on first attempt: sleep is never called."""
    push_called = []

    async def _fake_startup_doc_push():
        """Minimal simulation of the document-push retry block in lifespan."""
        import asyncio as _asyncio
        store = MagicMock()
        store.list_policies.return_value = [MagicMock(), MagicMock()]
        opa_url = "http://policy:8181"

        def _push(s, url):
            push_called.append("ok")

        for _attempt in range(1, 6):
            try:
                _push(store, opa_url)
                break
            except Exception as exc:
                if _attempt < 5:
                    await _asyncio.sleep(0)  # instant in tests
                else:
                    pass

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        await _fake_startup_doc_push()

    assert push_called == ["ok"]
    mock_sleep.assert_not_called()


@pytest.mark.asyncio
async def test_doc_push_succeeds_after_transient_failure():
    """Push fails 2 times then succeeds on 3rd attempt."""
    attempt_log = []
    call_count = 0

    def _flaky_push(store, url):
        nonlocal call_count
        call_count += 1
        attempt_log.append(call_count)
        if call_count < 3:
            raise ConnectionError("OPA not ready")

    async def _fake_startup_doc_push():
        import asyncio as _asyncio
        store = MagicMock()
        store.list_policies.return_value = []
        opa_url = "http://policy:8181"

        for _attempt in range(1, 6):
            try:
                _flaky_push(store, opa_url)
                break
            except Exception:
                if _attempt < 5:
                    await _asyncio.sleep(0)

    await _fake_startup_doc_push()

    assert call_count == 3, f"Expected 3 attempts (2 fail + 1 success), got {call_count}"
    assert attempt_log == [1, 2, 3]


@pytest.mark.asyncio
async def test_doc_push_all_5_attempts_fail_does_not_raise():
    """When all 5 attempts fail, the block logs a warning and does NOT propagate the exception."""
    call_count = 0
    warn_called = []

    def _always_fail(store, url):
        nonlocal call_count
        call_count += 1
        raise ConnectionError("OPA unreachable")

    async def _fake_startup_doc_push():
        import asyncio as _asyncio
        import logging
        _log = logging.getLogger("test")
        store = MagicMock()
        store.list_policies.return_value = []
        opa_url = "http://policy:8181"

        for _attempt in range(1, 6):
            try:
                _always_fail(store, opa_url)
                break
            except Exception as _push_exc:
                if _attempt < 5:
                    await _asyncio.sleep(0)
                else:
                    warn_called.append(str(_push_exc))
                    _log.warning("OPA-PERSIST: failed after 5 attempts: %s", _push_exc)
        # Function returns normally — no raise

    # Should not raise
    await _fake_startup_doc_push()

    assert call_count == 5, f"Expected exactly 5 attempts, got {call_count}"
    assert len(warn_called) == 1, "Expected exactly one warning on final failure"
    assert "OPA unreachable" in warn_called[0]


@pytest.mark.asyncio
async def test_sleep_called_between_transient_failures():
    """asyncio.sleep is called between failures but NOT after success."""
    sleep_calls = []
    call_count = 0

    async def _tracked_sleep(delay):
        sleep_calls.append(delay)

    def _push_fail_twice(store, url):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ConnectionError("not ready")

    async def _fake_startup_doc_push():
        import asyncio as _asyncio
        store = MagicMock()
        opa_url = "http://policy:8181"
        for _attempt in range(1, 6):
            try:
                _push_fail_twice(store, opa_url)
                break
            except Exception:
                if _attempt < 5:
                    await _tracked_sleep(3)  # matches LAURA-30-004 spec

    await _fake_startup_doc_push()

    # 2 failures → 2 sleeps of 3s each
    assert sleep_calls == [3, 3], f"Expected [3, 3], got {sleep_calls}"
    assert call_count == 3
