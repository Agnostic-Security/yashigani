"""
Regression tests — FIND-INSPECTION-NONDETERMINISTIC (2026-08-07).

## Root cause

``SensitivityClassifier.classify()`` (src/yashigani/optimization/
sensitivity_classifier.py) merges three layers — regex (Layer 1,
deterministic), sklearn (Layer 2, deterministic given fixed weights), and
ollama (Layer 3, an LLM — NOT guaranteed bit-for-bit deterministic even at
temperature 0, due to batched-inference floating-point reduction order).

Two concrete, code-level gaps combined to make the overall response-
inspection verdict non-deterministic for identical input text:

  1. ``_scan_ollama`` (this classifier's Layer 3) did not pin
     ``options: {"temperature": 0.0}`` on its ``/api/generate`` call —
     unlike the sibling ``PromptInjectionClassifier._call_model`` (used by
     ``ResponseInspectionPipeline``), which already pinned temperature to
     0.0. This was the ONE ollama-backed classifier in the codebase left at
     the backend's sampling default, adding unnecessary run-to-run label
     drift on top of the LLM's own residual non-determinism.
  2. Although ``classify()`` already merges via ``max(regex, sklearn,
     ollama)`` (regex-authoritative by construction), that invariant was
     never actually asserted or regression-tested, so a future refactor to
     a vote/average/"2-of-3" scheme could silently let a noisy ML layer
     downgrade a deterministic PII/PCI/injection regex hit without any test
     failing.

## The fix

  - ``_scan_ollama`` now pins ``temperature: 0.0`` (defence-in-depth; does
    not eliminate LLM non-determinism, reduces it).
  - ``classify()`` now carries an explicit runtime assertion
    (``final_level >= regex_level``) plus this regression suite, which
    fuzzes the sklearn/ollama layers across many iterations (including
    genuinely nondeterministic/flaky fakes) and proves the merged result
    NEVER drops below the deterministic regex floor, and is IDENTICAL
    across all iterations whenever regex fires — the property demanded by
    FIND-INSPECTION-NONDETERMINISTIC ("same input -> same verdict, every
    time"), achieved by making the noisy layers structurally unable to
    downgrade the result rather than by trying to make an LLM
    deterministic.

Fail-before/pass-after: reverting just the `final_level = max(...)` line to
`final_level = ollama_level` (simulating an "ensemble vote" refactor that
lets a noisy layer win) makes test_regex_floor_never_downgraded and
test_final_level_deterministic_despite_flaky_ollama fail — see commit body
for the exact `git stash` verification transcript.
"""
from __future__ import annotations

from dataclasses import dataclass

from yashigani.optimization.sensitivity_classifier import (
    SensitivityClassifier,
    SensitivityLevel,
)


@dataclass
class _FakeSklearnResult:
    label: str
    confidence: float


class _FlakySklearnBackend:
    """Returns a DIFFERENT (always non-authoritative) label on every call —
    simulates a genuinely non-deterministic ML backend."""

    def __init__(self, labels):
        self._labels = labels
        self._i = 0

    def classify(self, text):
        label = self._labels[self._i % len(self._labels)]
        self._i += 1
        return _FakeSklearnResult(label=label, confidence=0.9)


def _flaky_ollama_factory(levels):
    """Return a bound-method replacement for _scan_ollama that cycles through
    *levels* (ints) and NEVER raises (i.e. ollama is "available" every call,
    ruling out the fail-closed-elevate-to-5 path so we're purely testing the
    max() merge, not the unavailable/uncertain fail-closed branch)."""
    state = {"i": 0}

    def _fake(self, text, triggers):
        lvl = levels[state["i"] % len(levels)]
        state["i"] += 1
        if lvl > SensitivityLevel.PUBLIC:
            triggers.append(f"ollama:FAKE({lvl})")
        return lvl

    return _fake


# A prompt that ALWAYS trips the deterministic regex Layer 1 at SENSITIVE (5)
# — a Luhn-formatted-looking credit card number.
_CARD_TEXT = "Card on file: 4111 1111 1111 1111"
# A prompt with no regex hits at all.
_CLEAN_TEXT = "The quarterly report is due next Friday."


def test_regex_floor_never_downgraded_by_flaky_ensemble(monkeypatch):
    """Even when sklearn/ollama are wildly inconsistent (including reporting
    PUBLIC/CLEAN), a deterministic regex SENSITIVE hit is NEVER cleared."""
    clf = SensitivityClassifier(
        enable_sklearn=True,
        sklearn_backend=_FlakySklearnBackend(["CLEAN", "UNSAFE", "CLEAN", "UNCERTAIN"]),
        enable_ollama=True,
    )
    monkeypatch.setattr(
        SensitivityClassifier, "_scan_ollama",
        _flaky_ollama_factory([1, 5, 2, 1, 3, 1]),
    )

    results = [clf.classify(_CARD_TEXT) for _ in range(30)]
    levels = [r.level for r in results]

    assert all(lvl == SensitivityLevel.SENSITIVE for lvl in levels), (
        f"regex-authoritative invariant violated — a flaky sklearn/ollama "
        f"layer downgraded a deterministic card-number regex hit: {levels}"
    )


def test_final_level_deterministic_despite_flaky_ollama(monkeypatch):
    """FIND-INSPECTION-NONDETERMINISTIC's actual demanded property: identical
    input -> identical verdict, every time — even though the ollama layer
    underneath is deliberately jittering between every possible level."""
    clf = SensitivityClassifier(
        enable_sklearn=False,
        enable_ollama=True,
    )
    all_levels = [1, 2, 3, 4, 5]
    monkeypatch.setattr(
        SensitivityClassifier, "_scan_ollama",
        _flaky_ollama_factory(all_levels),
    )

    seen = {clf.classify(_CARD_TEXT).level for _ in range(50)}
    assert seen == {SensitivityLevel.SENSITIVE}, (
        f"same input produced multiple distinct verdicts across repeated "
        f"calls: {seen} — determinism invariant violated"
    )


def test_clean_text_unaffected_by_regex_floor(monkeypatch):
    """Sanity: the regex floor must not force everything to SENSITIVE — text
    with no deterministic hits still reflects the (here: also-clean) ensemble."""
    clf = SensitivityClassifier(enable_sklearn=False, enable_ollama=True)
    monkeypatch.setattr(
        SensitivityClassifier, "_scan_ollama",
        _flaky_ollama_factory([1, 1, 1]),
    )
    for _ in range(10):
        result = clf.classify(_CLEAN_TEXT)
        assert result.level == SensitivityLevel.PUBLIC


def test_scan_ollama_pins_temperature_zero():
    """FIND-INSPECTION-NONDETERMINISTIC root-cause fix #1: the ollama
    sensitivity layer must pin temperature=0.0, matching the sibling
    PromptInjectionClassifier._call_model pattern — asserted directly against
    the outgoing request payload so a regression silently re-introducing the
    backend's sampling default is caught."""
    captured = {}

    class _FakeResp:
        status_code = 200

        def json(self):
            return {"response": "PUBLIC"}

    class _FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json):
            captured["json"] = json
            return _FakeResp()

    clf = SensitivityClassifier(enable_sklearn=False, enable_ollama=True)

    import yashigani.inspection._ollama_transport as transport_mod
    original = transport_mod.ollama_sync_client
    transport_mod.ollama_sync_client = lambda *a, **kw: _FakeClient()
    try:
        clf._scan_ollama("some text", [])
    finally:
        transport_mod.ollama_sync_client = original

    assert captured["json"].get("options") == {"temperature": 0.0}, (
        f"expected temperature=0.0 pinned on the sensitivity-classifier "
        f"ollama call, got options={captured['json'].get('options')!r}"
    )
