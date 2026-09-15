# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""CVE gate for the llama.cpp pin — YSG-RISK-302.

The build manifest declares this check MANDATORY on every re-pin; the code was
an unconditional `exit 3`, so the control could not run at all.

These tests pin the classification behaviour against the range shapes that
actually appear upstream. The first implementation understood only `<= bNNNN`
and raised on everything else, which made it fail-closed on every run — and a
gate that always blocks is not a gate, it is an outage that gets switched off.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_MOD = Path(__file__).resolve().parents[1] / "deploy" / "scripts" / "cve_gate.py"
_spec = importlib.util.spec_from_file_location("cve_gate", _MOD)
assert _spec and _spec.loader
cve_gate = importlib.util.module_from_spec(_spec)
# Register BEFORE exec: the module defines a @dataclass, and dataclasses
# resolves annotations via sys.modules[cls.__module__] — absent that entry it
# raises AttributeError on None during class construction.
sys.modules["cve_gate"] = cve_gate
_spec.loader.exec_module(cve_gate)

Advisory = cve_gate.Advisory


# --- pin parsing ------------------------------------------------------------


def test_build_tag_parsed() -> None:
    assert cve_gate.parse_build_tag("b10976") == 10976


@pytest.mark.parametrize("bad", ["10976", "v1.2", "b", "", "latest", "b10976-rc1"])
def test_unparseable_pin_blocks(bad: str) -> None:
    with pytest.raises(cve_gate.GateError):
        cve_gate.parse_build_tag(bad)


# --- the real range shapes, measured from upstream --------------------------


@pytest.mark.parametrize(
    "rng,build,expect",
    [
        ("<= b7991", 7000, "covers"),    # CVE-2026-34159, critical
        ("<= b7991", 10976, "clear"),    # our pin is past it
        ("< b7437", 7000, "covers"),
        ("< b7437", 7437, "clear"),      # boundary: < is exclusive
        ("<= b8145", 8145, "covers"),    # boundary: <= is inclusive
        ("<= b8145", 8146, "clear"),
        ("<b5721", 5000, "covers"),      # no space — real upstream formatting
        ("<=b3426", 3426, "covers"),
        (">= b8146", 10976, "covers"),
        (">= b8146", 8000, "clear"),
    ],
)
def test_build_tag_ranges(rng: str, build: int, expect: str) -> None:
    assert cve_gate.classify(rng, build) == expect


@pytest.mark.parametrize("rng", ["All versions before patch", "b2715", "c33fe8b8", "", "   "])
def test_undecidable_ranges_are_unresolved_not_silently_clear(rng: str) -> None:
    """The important one. These shapes all appear upstream. Treating them as
    'clear' would silently skip a real advisory; raising on them blocks every
    run forever. They must surface for review instead."""
    assert cve_gate.classify(rng, 10976) == "unresolved"


# --- SHA-form ranges via the compare API ------------------------------------


def test_sha_range_resolved_when_our_pin_is_ahead() -> None:
    assert cve_gate.classify("<= 55d4206c8", 10976, lambda _s: "ahead") == "clear"


def test_sha_range_covers_when_our_pin_is_behind() -> None:
    assert cve_gate.classify("<= 55d4206c8", 10976, lambda _s: "behind") == "covers"


def test_sha_range_covers_when_identical() -> None:
    assert cve_gate.classify("<= 55d4206c8", 10976, lambda _s: "identical") == "covers"


def test_sha_range_unresolved_when_resolver_fails() -> None:
    """A failed lookup must not read as 'clear'."""
    assert cve_gate.classify("<= 55d4206c8", 10976, lambda _s: None) == "unresolved"


def test_sha_range_unresolved_without_a_resolver() -> None:
    assert cve_gate.classify("<= 55d4206c8", 10976, None) == "unresolved"


# --- bucketing --------------------------------------------------------------


def _adv(rng: str, ghsa: str = "GHSA-x") -> object:
    return Advisory(ghsa=ghsa, cve=None, severity="high", summary="s", vulnerable_range=rng)


def test_evaluate_separates_covers_from_unresolved() -> None:
    covers, unresolved = cve_gate.evaluate(
        [_adv("<= b7991", "A"), _adv("< b100", "B"), _adv("All versions before patch", "C")],
        7000,
    )
    assert [a.ghsa for a in covers] == ["A"]
    assert [a.ghsa for a in unresolved] == ["C"]


def test_nothing_is_silently_dropped() -> None:
    """Every advisory must land in exactly one bucket."""
    advs = [_adv("<= b7991"), _adv("< b100"), _adv("junk"), _adv("")]
    covers, unresolved = cve_gate.evaluate(advs, 7000)
    clear = len(advs) - len(covers) - len(unresolved)
    assert len(covers) + len(unresolved) + clear == len(advs)
    assert clear == 1
