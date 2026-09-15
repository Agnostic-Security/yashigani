# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Single pivot for the inference-engine URL — the YSG-RISK-274 guard.

YSG-RISK-274: `KUROSHIO_BASE_URL` was put into compose while `src/` had no
reader for it, so the gateway's suspicion-escalated inspection leg fail-closed
with CLASSIFIER_ERROR on every escalated prompt. The rename was right; doing it
without readers on both sides was not.

These tests exist so that cannot recur: the new names must be read, the old
names must keep working, and there must be exactly ONE place that resolves this
URL — eight call sites with eight slightly different fallback chains is how the
drift happened in the first place.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from yashigani.inspection._ollama_transport import (
    DEFAULT_ENGINE_MODEL,
    DEFAULT_ENGINE_URL,
    resolve_engine_model,
    resolve_engine_url,
)

_SRC = Path(__file__).resolve().parents[2] / "yashigani"


@pytest.fixture(autouse=True)
def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    for n in (
        "YASHIGANI_KUROSHIO_URL",
        "KUROSHIO_BASE_URL",
        "YASHIGANI_OLLAMA_URL",
        "OLLAMA_BASE_URL",
        "YASHIGANI_KUROSHIO_MODEL",
        "KUROSHIO_MODEL",
        "OLLAMA_MODEL",
    ):
        monkeypatch.delenv(n, raising=False)


# --- the new names are actually read (the half YSG-RISK-274 got wrong) ------


@pytest.mark.parametrize("name", ["YASHIGANI_KUROSHIO_URL", "KUROSHIO_BASE_URL"])
def test_kuroshio_names_are_read(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setenv(name, "https://caddy:11436/kuroshio")
    assert resolve_engine_url() == "https://caddy:11436/kuroshio"


# --- the old names keep working (so no deployment breaks on upgrade) -------


@pytest.mark.parametrize("name", ["YASHIGANI_OLLAMA_URL", "OLLAMA_BASE_URL"])
def test_deprecated_names_still_honoured(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setenv(name, "https://caddy:11435/ollama")
    assert resolve_engine_url() == "https://caddy:11435/ollama"


def test_new_name_wins_over_deprecated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("YASHIGANI_OLLAMA_URL", "https://old/x")
    monkeypatch.setenv("KUROSHIO_BASE_URL", "https://new/y")
    assert resolve_engine_url() == "https://new/y"


def test_deprecated_use_warns(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    monkeypatch.setenv("OLLAMA_BASE_URL", "https://x/y")
    with caplog.at_level("WARNING"):
        resolve_engine_url()
    assert "deprecated" in caplog.text.lower()


# --- renaming must not also change behaviour -------------------------------


def test_unset_default_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """A rename that silently moves the unset-default is two changes in one
    commit, and the second is invisible."""
    assert resolve_engine_url() == DEFAULT_ENGINE_URL == "http://ollama:11434"


def test_blank_is_treated_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUROSHIO_BASE_URL", "   ")
    monkeypatch.setenv("OLLAMA_BASE_URL", "https://real/z")
    assert resolve_engine_url() == "https://real/z"


def test_trailing_slash_normalised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUROSHIO_BASE_URL", "https://caddy:11436/kuroshio/")
    assert resolve_engine_url() == "https://caddy:11436/kuroshio"


# --- there must be exactly ONE resolver ------------------------------------


def test_no_module_resolves_the_engine_url_independently() -> None:
    """The drift guard. Eight call sites each had their own fallback chain, and
    two read only OLLAMA_BASE_URL while six read YASHIGANI_OLLAMA_URL first —
    so repointing one and not the other left live paths on the old service.
    """
    hits = subprocess.run(
        ["grep", "-rn", "-E", r'getenv\("(YASHIGANI_)?(OLLAMA|KUROSHIO)_(BASE_)?URL"', str(_SRC)],
        capture_output=True,
        text=True,
    ).stdout.strip().splitlines()
    offenders = [h for h in hits if "_ollama_transport.py" not in h]
    assert not offenders, (
        "the engine URL must be resolved ONLY by resolve_engine_url(); "
        "these read it directly:\n  " + "\n  ".join(offenders)
    )


# --- the MODEL pivot: same problem, and the 5.0 -> 6.0 stitch depends on it ---


@pytest.mark.parametrize("name", ["YASHIGANI_KUROSHIO_MODEL", "KUROSHIO_MODEL"])
def test_kuroshio_model_names_are_read(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setenv(name, "qwen3.8:27b")
    assert resolve_engine_model() == "qwen3.8:27b"


def test_deprecated_model_name_still_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:7b")
    assert resolve_engine_model() == "qwen2.5:7b"


def test_new_model_name_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLLAMA_MODEL", "old:1b")
    monkeypatch.setenv("KUROSHIO_MODEL", "new:27b")
    assert resolve_engine_model() == "new:27b"


def test_model_default_unchanged_by_the_rename(monkeypatch: pytest.MonkeyPatch) -> None:
    """Licence-ineligible (YSG-RISK-312) and must move before commercial ship —
    but moving it HERE would bundle a behaviour change into a rename."""
    assert resolve_engine_model() == DEFAULT_ENGINE_MODEL == "qwen2.5:3b"


def test_no_module_resolves_the_engine_model_independently() -> None:
    """The stitch guard. The default model was hardcoded in FIVE places, two of
    them licence-ineligible. Five places is five chances to miss one at the
    5.0 -> 6.0 cutover, and a missed site fails silently — it just keeps
    serving the old model."""
    hits = subprocess.run(
        ["grep", "-rn", "-E", r'getenv\("(YASHIGANI_KUROSHIO_MODEL|KUROSHIO_MODEL|OLLAMA_MODEL)"', str(_SRC)],
        capture_output=True,
        text=True,
    ).stdout.strip().splitlines()
    offenders = [h for h in hits if "_ollama_transport.py" not in h]
    assert not offenders, (
        "the engine model must be resolved ONLY by resolve_engine_model(); "
        "these read it directly:\n  " + "\n  ".join(offenders)
    )
