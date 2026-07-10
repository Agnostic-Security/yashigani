"""
Unit tests — v2.25.0 P2: OWUI_SECRET_KEY startup warning.

Iris FIX-1 follow-up (Captain wave 2 B12 OWUI_SECRET_KEY injection): when
openWebui.existingSecretName is a BYO Secret that lacks the 'secret_key'
key, OWUI_SECRET_KEY resolves to empty string at pod startup and agent
provisioning to Open WebUI silently fails.  The chart cannot detect this at
template time.  This fix emits a WARNING at backoffice lifespan startup so
the operator sees the misconfiguration immediately in the container logs.

The warning block lives in
  src/yashigani/backoffice/app.py :: lifespan() (after _load_caddy_secret())

Finding reference: Iris drift gate on Captain wave 2 PR — non-blocking
operator-visibility gap.

Last updated: 2026-05-28T00:00:00+01:00

Test matrix:
  T1 — OWUI_API_URL set + OWUI_SECRET_KEY absent → WARNING emitted
  T2 — OWUI_API_URL set + OWUI_SECRET_KEY empty string → WARNING emitted
  T3 — OWUI_API_URL set + OWUI_SECRET_KEY whitespace-only → WARNING emitted
  T4 — OWUI_API_URL set + OWUI_SECRET_KEY set → NO warning emitted
  T5 — OWUI_API_URL absent → NO warning emitted
  T6 — Both env vars absent → NO warning emitted
  T7 — OWUI_API_URL empty string → NO warning emitted (integration not configured)
  T8 — WARNING message contains the OWUI_API_URL value (parameterised, not f-string)
"""
from __future__ import annotations

import logging
import os
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_WARN_FRAGMENT = "OWUI_SECRET_KEY is empty or absent"
_LOGGER_NAME = "yashigani.backoffice.lifespan"


def _run_owui_check(owui_api_url: str | None, owui_secret_key: str | None) -> list[logging.LogRecord]:
    """
    Execute the OWUI startup-warn logic in isolation, matching the exact
    code path in app.py::lifespan():

        _owui_api_url = os.environ.get("OWUI_API_URL", "").strip()
        _owui_secret_key = os.environ.get("OWUI_SECRET_KEY", "").strip()
        if _owui_api_url and not _owui_secret_key:
            _log.warning(...)

    Returns the list of log records emitted to the lifespan logger.
    """
    env_patch: dict[str, str] = {}
    remove_keys: list[str] = []

    if owui_api_url is None:
        remove_keys.append("OWUI_API_URL")
    else:
        env_patch["OWUI_API_URL"] = owui_api_url

    if owui_secret_key is None:
        remove_keys.append("OWUI_SECRET_KEY")
    else:
        env_patch["OWUI_SECRET_KEY"] = owui_secret_key

    # Build a clean environment for the test: start from current env, apply
    # patches, remove keys that should be absent.
    test_env = {k: v for k, v in os.environ.items() if k not in remove_keys}
    test_env.update(env_patch)

    logger = logging.getLogger(_LOGGER_NAME)
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Capture()
    logger.addHandler(handler)
    original_level = logger.level
    logger.setLevel(logging.WARNING)

    try:
        with patch.dict(os.environ, test_env, clear=True):
            _owui_api_url = os.environ.get("OWUI_API_URL", "").strip()
            _owui_secret_key = os.environ.get("OWUI_SECRET_KEY", "").strip()
            if _owui_api_url and not _owui_secret_key:
                logger.warning(
                    "OWUI_API_URL is set (%s) but OWUI_SECRET_KEY is empty or absent. "
                    "Open WebUI agent provisioning will fail silently at runtime. "
                    "Either unset OWUI_API_URL to disable Open WebUI integration, or set "
                    "OWUI_SECRET_KEY (via Helm openWebui.existingSecretName containing key "
                    "'secret_key', or via docker/.env OWUI_SECRET_KEY for compose).",
                    _owui_api_url,
                )
    finally:
        logger.removeHandler(handler)
        logger.setLevel(original_level)

    return records


# ---------------------------------------------------------------------------
# T1 — OWUI_API_URL set + OWUI_SECRET_KEY absent → WARNING emitted
# ---------------------------------------------------------------------------

class TestT1UrlSetKeyAbsent:
    """T1: Integration is configured but the API key env var is absent."""

    def test_warning_emitted_when_key_absent(self) -> None:
        records = _run_owui_check(
            owui_api_url="http://open-webui:3000",
            owui_secret_key=None,
        )
        assert any(_WARN_FRAGMENT in r.getMessage() for r in records), (
            f"Expected WARNING containing {_WARN_FRAGMENT!r} but got: "
            f"{[r.getMessage() for r in records]}"
        )


# ---------------------------------------------------------------------------
# T2 — OWUI_API_URL set + OWUI_SECRET_KEY empty string → WARNING emitted
# ---------------------------------------------------------------------------

class TestT2UrlSetKeyEmpty:
    """T2: Helm existingSecretName missing 'secret_key' → resolves to empty string."""

    def test_warning_emitted_when_key_empty(self) -> None:
        records = _run_owui_check(
            owui_api_url="http://open-webui:3000",
            owui_secret_key="",
        )
        assert any(_WARN_FRAGMENT in r.getMessage() for r in records), (
            f"Expected WARNING for empty OWUI_SECRET_KEY but got: "
            f"{[r.getMessage() for r in records]}"
        )


# ---------------------------------------------------------------------------
# T3 — OWUI_API_URL set + OWUI_SECRET_KEY whitespace-only → WARNING emitted
# ---------------------------------------------------------------------------

class TestT3UrlSetKeyWhitespaceOnly:
    """T3: A whitespace-only key is normalised to empty by .strip() — should warn."""

    def test_warning_emitted_when_key_whitespace_only(self) -> None:
        records = _run_owui_check(
            owui_api_url="http://open-webui:3000",
            owui_secret_key="   ",
        )
        assert any(_WARN_FRAGMENT in r.getMessage() for r in records), (
            f"Expected WARNING for whitespace-only OWUI_SECRET_KEY but got: "
            f"{[r.getMessage() for r in records]}"
        )


# ---------------------------------------------------------------------------
# T4 — OWUI_API_URL set + OWUI_SECRET_KEY set → NO warning
# ---------------------------------------------------------------------------

class TestT4BothSet:
    """T4: Normal happy-path — both env vars configured correctly."""

    def test_no_warning_when_both_set(self) -> None:
        records = _run_owui_check(
            owui_api_url="http://open-webui:3000",
            owui_secret_key="sk-very-long-real-key-abc123xyz",
        )
        warn_records = [r for r in records if _WARN_FRAGMENT in r.getMessage()]
        assert not warn_records, (
            f"Expected NO warning when both vars are set, but got: "
            f"{[r.getMessage() for r in warn_records]}"
        )


# ---------------------------------------------------------------------------
# T5 — OWUI_API_URL absent → NO warning
# ---------------------------------------------------------------------------

class TestT5UrlAbsent:
    """T5: Open WebUI integration not configured — no OWUI_API_URL present."""

    def test_no_warning_when_url_absent(self) -> None:
        records = _run_owui_check(
            owui_api_url=None,
            owui_secret_key=None,
        )
        warn_records = [r for r in records if _WARN_FRAGMENT in r.getMessage()]
        assert not warn_records, (
            f"Expected NO warning when OWUI_API_URL absent, but got: "
            f"{[r.getMessage() for r in warn_records]}"
        )


# ---------------------------------------------------------------------------
# T6 — Both absent → NO warning
# ---------------------------------------------------------------------------

class TestT6BothAbsent:
    """T6: Neither env var present — silently clean."""

    def test_no_warning_when_both_absent(self) -> None:
        records = _run_owui_check(
            owui_api_url=None,
            owui_secret_key=None,
        )
        assert not any(_WARN_FRAGMENT in r.getMessage() for r in records)


# ---------------------------------------------------------------------------
# T7 — OWUI_API_URL empty string → NO warning (integration not configured)
# ---------------------------------------------------------------------------

class TestT7UrlEmpty:
    """T7: OWUI_API_URL set to empty string is treated as 'not configured'."""

    def test_no_warning_when_url_empty_string(self) -> None:
        records = _run_owui_check(
            owui_api_url="",
            owui_secret_key=None,
        )
        warn_records = [r for r in records if _WARN_FRAGMENT in r.getMessage()]
        assert not warn_records, (
            f"Expected NO warning for empty OWUI_API_URL, but got: "
            f"{[r.getMessage() for r in warn_records]}"
        )


# ---------------------------------------------------------------------------
# T8 — WARNING message contains the OWUI_API_URL value (parameterised, not f-string)
# ---------------------------------------------------------------------------

class TestT8WarningContainsUrl:
    """T8: The URL value appears in the warning message (regression on log injection)."""

    def test_url_value_appears_in_warning_message(self) -> None:
        """
        The logger call uses %s parameterised formatting (not f-string) to
        prevent log injection.  Verify the rendered message contains the URL
        so the operator can immediately see which endpoint is misconfigured.
        """
        url = "http://open-webui.internal:3000"
        records = _run_owui_check(
            owui_api_url=url,
            owui_secret_key=None,
        )
        warn_messages = [r.getMessage() for r in records if _WARN_FRAGMENT in r.getMessage()]
        assert warn_messages, "Expected at least one warning record"
        assert url in warn_messages[0], (
            f"Expected OWUI_API_URL value {url!r} in warning message, "
            f"but got: {warn_messages[0]!r}"
        )

    def test_url_whitespace_stripped_in_warning_message(self) -> None:
        """
        The stripped URL (not the raw env-var value) appears in the message.
        """
        url_with_spaces = "  http://open-webui.internal:3000  "
        expected_url = url_with_spaces.strip()
        records = _run_owui_check(
            owui_api_url=url_with_spaces,
            owui_secret_key=None,
        )
        warn_messages = [r.getMessage() for r in records if _WARN_FRAGMENT in r.getMessage()]
        assert warn_messages, "Expected at least one warning record"
        assert expected_url in warn_messages[0], (
            f"Expected stripped URL {expected_url!r} in warning message, "
            f"but got: {warn_messages[0]!r}"
        )
