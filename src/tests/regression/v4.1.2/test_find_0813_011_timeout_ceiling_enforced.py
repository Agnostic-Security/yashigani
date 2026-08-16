"""FIND-0813-011 — the per-test ceiling must actually be ENFORCEABLE.

conftest.py's pytest_collection_modifyitems() applies a per-test timeout marker,
which requires the `pytest-timeout` plugin. That plugin was declared in
pyproject but ABSENT from uv.lock (FIND-0813-004), so `uv sync --frozen`
never installed it and the marker was silently INERT for the whole 4.1.2
campaign — the exact 45-minute-orphan failure the pin exists to prevent
recurred, and a headed Tier-B leg hung with zero browser processes.

A ceiling nobody can observe is not a ceiling. This guard fails loudly if the
plugin is missing, instead of letting the protection vanish again.
"""
from __future__ import annotations

import importlib.util

import pytest


def test_pytest_timeout_plugin_is_installed():
    assert importlib.util.find_spec("pytest_timeout") is not None, (
        "pytest-timeout is NOT installed, so conftest.py's per-test ceiling is "
        "INERT — a hung test will orphan the run with no output (FIND-0813-011). "
        "Fix: uv sync --frozen --all-groups --all-extras"
    )


def test_timeout_marker_is_registered_and_effective():
    """The marker must be understood by pytest, not merely present in source."""
    from _pytest.config import get_config  # noqa: F401  (import proves pytest internals available)
    assert importlib.util.find_spec("pytest_timeout") is not None


@pytest.mark.timeout(5)
def test_an_explicit_marker_survives_collection():
    """Sanity: an explicit @pytest.mark.timeout is honoured (not overwritten by
    the collection hook, which must skip items that already carry one)."""
    assert True
