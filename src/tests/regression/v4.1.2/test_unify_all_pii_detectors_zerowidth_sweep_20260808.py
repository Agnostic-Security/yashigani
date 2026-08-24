"""
Regression tests — unify-all-PAN/PII-detectors sweep (2026-08-08).

This class has recurred 3x from incomplete sweeps: YSG-RISK-057 (M4 content
filter) -> YSG-RISK-095 (pii/detector.py) -> FIND-LAURA-412-CRIT-001 (ingress
sensitivity_classifier, closed in commit b2ee46a6). YSG-RISK-095's retro
explicitly flagged "pattern-sweep miss — not swept into all detectors."

This session audited every regex/Luhn-based card/PAN/SSN/IBAN/PII detection
call-site in the tree (src + helm + docker + policy + scripts + tests) for
the SAME zero-width (U+200B et al, category Cf) / NFKC-compatibility-form
(fullwidth digit) evasion FIND-LAURA-412-CRIT-001 closed for the ingress
sensitivity_classifier and the egress contains_pci_pan block. Two additional
un-normalized/mismatched call-sites were found and fixed:

  1. ``yashigani.documents.qi_context`` (column-semantic QI/PCI detector for
     spreadsheets/CSVs) matched column HEADER text (``classify_columns``) and
     cell VALUE text (``_value_plausible``'s DOB/CVV/expiry/name shape
     regexes) directly against raw, un-normalized text. A header like
     "SSN<ZWSP>" or a CVV value "1<ZWSP>0<ZWSP>0" would silently evade
     classification — and per this module's own docstring, DOB/CVV/name
     columns have NO distinctive per-VALUE form at all, so a header-evasion
     attack here has no other detection layer to fall back on. Fixed: both
     now match against ``normalize_for_pattern_matching()`` — the SAME
     NFKC + Cf-strip routine ``contains_pci_pan`` and the ingress regex
     floor use. No second, divergent normalizer.

  2. ``POST /admin/sensitivity/test`` (``yashigani.backoffice.routes
     .sensitivity``) did not classify sensitivity/PAN/PII AT ALL — it only
     ran the prompt-injection/credential-exfil pipeline
     (``InspectionPipeline.process``), a completely different detector. An
     admin pasting a Luhn-valid PAN into this "test a sample" box got back
     an injection verdict with no signal about whether production PAN/PII
     enforcement (``SensitivityClassifier`` — POL-009 ``pci_data_present``)
     would ever have seen it, let alone whether the zero-width bypass would
     have defeated it. Fixed: the endpoint now ALSO runs a fresh
     ``SensitivityClassifier`` (regex layer only — the one layer guaranteed
     identical between the backoffice and gateway processes) built from the
     SAME ``_DEFAULT_PATTERNS`` + any admin-created custom patterns, and
     returns ``sensitivity_level``/``sensitivity_label``/
     ``sensitivity_triggers`` alongside the existing injection fields.

Every other candidate call-site found by the sweep (``pii/detector.py``
core ``_scan``, ``optimization/sensitivity_classifier.py`` ``_scan_regex``,
``gateway/openai_router.py``, ``gateway/proxy.py``, ``gateway/orchestrator.py``,
``backoffice/routes/pii.py`` ``/admin/pii/test``,
``inspection/pipeline.py::ResponseInspectionPipeline.inspect``) was already
normalized/unified as of b2ee46a6, or is a different detection class
entirely (``inspection/secret_detector.py`` — API keys/tokens, not PCI/PII;
``mcp/_content_filter.py`` — injection heuristics; OPA ``policy/*.rego`` —
consumes pre-computed booleans, does no text matching of its own) — see the
dispatch report for the full per-site inventory.

Test PAN: a Luhn-valid Visa test number with BOTH evasions combined in one
payload — some digits substituted with their NFKC-foldable fullwidth form
(U+FF10-U+FF19) AND a zero-width space (U+200B) interleaved between every
character — the worst case FIND-LAURA-412-CRIT-001 named explicitly.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from yashigani.documents.qi_context import (
    classify_columns,
    header_driven_matches,
)
from yashigani.documents.segment import Segment, SegmentKind
from yashigani.optimization.sensitivity_classifier import (
    SensitivityClassifier,
    SensitivityLevel,
)
from yashigani.pii.detector import contains_pci_pan

_VISA_TEST_PAN = "4111111111111111"  # Luhn-valid Visa test PAN
_ZERO_WIDTH = "​"  # ZERO WIDTH SPACE


def _fullwidth_digit(d: str) -> str:
    return chr(0xFF10 + int(d))


def _worst_case_evasive_pan(pan: str = _VISA_TEST_PAN) -> str:
    """Every other digit swapped for its fullwidth NFKC-foldable form, with
    a zero-width space interleaved between EVERY character."""
    chars = [
        _fullwidth_digit(d) if i % 2 == 0 else d
        for i, d in enumerate(pan)
    ]
    return _ZERO_WIDTH.join(chars)


_EVASIVE_PAN = _worst_case_evasive_pan()


def _xlsx(headers, rows, sheet="S"):
    cols = "ABCDEFGH"
    segs = []
    for c, h in enumerate(headers):
        segs.append(Segment(text=h, kind=SegmentKind.TABLE_CELL,
                             location=f"sheet={sheet}!{cols[c]}1"))
    for r, row in enumerate(rows, start=2):
        for c, cell in enumerate(row):
            segs.append(Segment(text=cell, kind=SegmentKind.TABLE_CELL,
                                 location=f"sheet={sheet}!{cols[c]}{r}"))
    return segs


class TestEntryPoint1SensitivityClassifierRegexFloor:
    """Already-hardened by b2ee46a6 — pinned here as part of the full sweep
    so a future regression on this entry point trips THIS suite too."""

    def test_worst_case_evasive_pan_detected(self):
        clf = SensitivityClassifier(enable_sklearn=False, enable_ollama=False)
        result = clf.classify(f"Card: {_EVASIVE_PAN}")
        assert result.level == int(SensitivityLevel.SENSITIVE)
        assert any("Credit/debit card" in t for t in result.triggers)


class TestEntryPoint2ContainsPciPan:
    """Already-hardened by b2ee46a6 (egress absolute-PCI block)."""

    def test_worst_case_evasive_pan_detected(self):
        assert contains_pci_pan(f"Card number: {_EVASIVE_PAN}") is True


class TestEntryPoint3QiContextColumnHeaderEvasion:
    """NEW fix (this sweep): a zero-width char inside the HEADER text used
    to silently defeat column classification entirely — with no per-value
    fallback for DOB/CVV/name classes."""

    def test_zero_width_header_still_classified(self):
        evasive_header = _ZERO_WIDTH.join(list("CVV"))
        segs = _xlsx([evasive_header], [["100"]])
        cls = {k: v.data_class for k, v in classify_columns(segs).items()}
        assert cls[("S", "A")] == "PCI.CVV"

    def test_zero_width_header_data_cell_tagged(self):
        evasive_header = _ZERO_WIDTH.join(list("SSN"))
        segs = _xlsx([evasive_header], [["AA 10 10 10 A"]])
        matches = header_driven_matches(segs)
        assert len(matches) == 1
        assert matches[0].data_class == "PII.NATIONAL_INSURANCE"
        assert matches[0].qi is True

    def test_pan_column_header_evasion_with_evasive_value(self):
        """Combined worst case: BOTH the header ("Card Number") and the PAN
        VALUE carry the zero-width/fullwidth evasion."""
        evasive_header = _ZERO_WIDTH.join(list("Card Number"))
        segs = _xlsx([evasive_header], [[_EVASIVE_PAN]])
        matches = header_driven_matches(segs)
        assert len(matches) == 1
        assert matches[0].data_class == "PCI.PAN"


class TestEntryPoint3bQiContextValueShapeEvasion:
    """NEW fix (this sweep): a zero-width char inside a CVV/DOB/expiry/name
    VALUE (header already classified) used to defeat the plausibility guard
    even though the column-level context was correctly identified."""

    def test_zero_width_cvv_value_still_plausible(self):
        evasive_cvv = _ZERO_WIDTH.join(list("100"))
        segs = _xlsx(["CVV"], [[evasive_cvv]])
        matches = header_driven_matches(segs)
        assert len(matches) == 1
        assert matches[0].data_class == "PCI.CVV"

    def test_zero_width_dob_value_still_plausible(self):
        evasive_dob = _ZERO_WIDTH.join(list("01/01/1960"))
        segs = _xlsx(["Date of Birth"], [[evasive_dob]])
        matches = header_driven_matches(segs)
        assert len(matches) == 1
        assert matches[0].data_class == "PII.DATE_OF_BIRTH"

    def test_stray_non_conforming_cell_still_rejected_no_over_block(self):
        """No-over-block regression: a genuinely non-conforming cell under a
        classified header must still be rejected after normalization."""
        segs = _xlsx(["CVV"], [["n/a"]])
        matches = header_driven_matches(segs)
        assert matches == []


class TestEntryPoint4AdminSensitivityTestEndpoint:
    """NEW fix (this sweep): POST /admin/sensitivity/test previously ran
    ONLY the injection pipeline — never PAN/PII sensitivity classification
    at all. Now it also runs the SAME unified regex-floor SensitivityClassifier
    the gateway enforces with, so admin test results match enforcement."""

    @pytest.fixture(autouse=True)
    def _wire_fake_injection_pipeline(self, monkeypatch):
        from yashigani.backoffice.state import backoffice_state

        class _FakeInjectionPipeline:
            def process(self, raw_query, session_id, agent_id, user_id):
                return SimpleNamespace(action="PASS", confidence=0.1, classification="CLEAN")

        monkeypatch.setattr(backoffice_state, "inspection_pipeline", _FakeInjectionPipeline(), raising=False)

    def test_worst_case_evasive_pan_flagged_sensitive(self):
        from yashigani.backoffice.routes.sensitivity import (
            TestClassifyRequest,
            test_classify,
        )

        body = TestClassifyRequest(text=f"Please charge card {_EVASIVE_PAN} now")
        result = asyncio.run(test_classify(body, session=object()))  # type: ignore[arg-type]

        assert result["sensitivity_level"] == int(SensitivityLevel.SENSITIVE)
        assert result["sensitivity_label"] is not None
        assert any("Credit/debit card" in t for t in result["sensitivity_triggers"])
        # Injection fields are still present and independent — no regression
        # on the pre-existing contract (tests/conformance/test_sensitivity_pii_docs.py).
        assert result["is_injection"] is False
        assert result["action"] == "PASS"

    def test_clean_text_no_over_block(self):
        from yashigani.backoffice.routes.sensitivity import (
            TestClassifyRequest,
            test_classify,
        )

        body = TestClassifyRequest(text="hello, how are you today?")
        result = asyncio.run(test_classify(body, session=object()))  # type: ignore[arg-type]

        assert result["sensitivity_level"] == int(SensitivityLevel.PUBLIC)
        assert result["sensitivity_triggers"] == []

    def test_no_pipeline_still_503_gate_unchanged(self, monkeypatch):
        """Pre-existing 503-when-no-pipeline contract
        (tests/conformance/test_sensitivity_pii_docs.py::test_test_without_pipeline_503)
        must not regress — the sensitivity classification addition must not
        bypass the existing availability gate."""
        from fastapi import HTTPException

        from yashigani.backoffice.routes.sensitivity import (
            TestClassifyRequest,
            test_classify,
        )
        from yashigani.backoffice.state import backoffice_state

        monkeypatch.setattr(backoffice_state, "inspection_pipeline", None, raising=False)
        body = TestClassifyRequest(text="hello world")
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(test_classify(body, session=object()))  # type: ignore[arg-type]
        assert exc_info.value.status_code == 503
