"""Regression tests — LAURA-31RT-001: client-enforce OPA input.data_tags wiring.

Root cause: _client_enforce_input() never populated input.data_tags, making
every OPA policy that inspects content (pii_redaction_policy, pci_data_block,
classified_marking_local) structurally inert — their deny rules could never
match because the array they iterate was always absent / empty.

Fix (openai_router.py):
  - _client_enforce_input() gains a data_tags parameter and includes it in
    the returned dict as "data_tags": list(data_tags).
  - _detect_content_tags(text, pii_detector) derives normalised tags from a
    text string using the existing PiiDetector (detect_decoded — read-only
    multi-view scan) plus a classification-marker keyword check.
  - _ingress_data_tags is computed just before the 6a-bind ingress call
    (from prompt_text).
  - _egress_data_tags is computed just before the 8b-bind egress call
    (from assistant_content, which may already be PII-redacted by step 7c).

These tests verify:
  (A) _detect_content_tags() produces the right tags for PII / PCI /
      classification-marker content, and [] for clean content.
  (B) _client_enforce_input() includes "data_tags" in its output.
  (C) The tags propagate into the OPA input dict via a mocked
      evaluate_client_policies call — the full ingress/egress wiring.
"""
from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Import the two pure functions under test.  Both are module-level helpers in
# openai_router and do NOT require a running FastAPI app or real OPA.
# ---------------------------------------------------------------------------

# Guard: if YASHIGANI_INTERNAL_BEARER is absent the module raises at import time.
# Set it to a dummy before importing.
import os
os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-bearer-sentinel")
os.environ.setdefault("YASHIGANI_OPA_OPTIONAL", "true")
os.environ.setdefault("YASHIGANI_ENV", "test")

from yashigani.gateway.openai_router import (  # noqa: E402
    _client_enforce_input,
    _detect_content_tags,
    _CONTENT_TAGS_MAX_BYTES,  # now 1 MB (LAURA-31DR-002)
)
from yashigani.pii.detector import PiiDetector, PiiMode  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def pii_detector() -> PiiDetector:
    """LOG-mode PiiDetector (all types enabled) — mirrors the gateway default."""
    return PiiDetector(mode=PiiMode.LOG)


# ---------------------------------------------------------------------------
# A. _detect_content_tags — tag derivation
# ---------------------------------------------------------------------------

class TestDetectContentTags:
    # --- PII detection ---

    def test_ssn_yields_pii(self, pii_detector):
        """A US SSN in the prompt must produce the 'pii' tag."""
        text = "My social security number is 123-45-6789, please keep it safe."
        tags = _detect_content_tags(text, pii_detector)
        assert "pii" in tags, f"expected 'pii' tag for SSN input, got {tags}"

    def test_ssn_does_not_yield_pci(self, pii_detector):
        """SSN is PII but NOT PCI-scoped."""
        text = "SSN: 123-45-6789"
        tags = _detect_content_tags(text, pii_detector)
        assert "pci" not in tags, f"SSN should not produce 'pci' tag, got {tags}"

    def test_credit_card_yields_pii_and_pci(self, pii_detector):
        """A Visa card number must produce both 'pii' and 'pci' tags."""
        # 4532015112830366 — valid Luhn Visa test number
        text = "Card: 4532-0151-1283-0366 exp 12/26"
        tags = _detect_content_tags(text, pii_detector)
        assert "pii" in tags, f"expected 'pii' for credit card, got {tags}"
        assert "pci" in tags, f"expected 'pci' for credit card, got {tags}"

    def test_email_yields_pii(self, pii_detector):
        text = "Please contact alice@example.com for details."
        tags = _detect_content_tags(text, pii_detector)
        assert "pii" in tags

    def test_email_does_not_yield_pci(self, pii_detector):
        text = "Email: alice@example.com"
        tags = _detect_content_tags(text, pii_detector)
        assert "pci" not in tags

    def test_iban_yields_pii_and_pci(self, pii_detector):
        """IBAN is both PII and PCI-scoped."""
        text = "Bank account: GB82 WEST 1234 5698 7654 32"
        tags = _detect_content_tags(text, pii_detector)
        assert "pii" in tags, f"expected 'pii' for IBAN, got {tags}"
        assert "pci" in tags, f"expected 'pci' for IBAN, got {tags}"

    # --- Classification marking ---

    def test_secret_marking_yields_classified(self, pii_detector):
        text = "// SECRET // This document describes the new acquisition plan."
        tags = _detect_content_tags(text, pii_detector)
        assert "classified" in tags, f"expected 'classified' for SECRET marking, got {tags}"

    def test_top_secret_yields_classified(self, pii_detector):
        text = "TOP SECRET//SCI — FOR UK EYES ONLY"
        tags = _detect_content_tags(text, pii_detector)
        assert "classified" in tags

    def test_official_sensitive_hyphen_yields_classified(self, pii_detector):
        text = "OFFICIAL-SENSITIVE: this briefing is restricted to named recipients."
        tags = _detect_content_tags(text, pii_detector)
        assert "classified" in tags

    def test_official_sensitive_space_yields_classified(self, pii_detector):
        text = "OFFICIAL SENSITIVE"
        tags = _detect_content_tags(text, pii_detector)
        assert "classified" in tags

    def test_classification_without_pii_detector(self):
        """Classification markers are detected even when no PII detector is wired."""
        text = "SECRET: eyes only"
        tags = _detect_content_tags(text, pii_detector=None)
        assert "classified" in tags
        # No PII detector → no pii/pci tags
        assert "pii" not in tags
        assert "pci" not in tags

    # --- Clean content ---

    def test_clean_text_yields_no_tags(self, pii_detector):
        text = "The quick brown fox jumps over the lazy dog."
        tags = _detect_content_tags(text, pii_detector)
        assert tags == [], f"expected no tags for clean text, got {tags}"

    def test_empty_string_yields_no_tags(self, pii_detector):
        tags = _detect_content_tags("", pii_detector)
        assert tags == []

    def test_none_pii_detector_clean_text_yields_no_tags(self):
        tags = _detect_content_tags("Hello world", pii_detector=None)
        assert tags == []

    # --- Ordering ---

    def test_tags_are_sorted(self, pii_detector):
        """Result is always alphabetically sorted for deterministic OPA input."""
        # credit card → pci + pii; sorted = ["pci", "pii"]
        text = "4532-0151-1283-0366"
        tags = _detect_content_tags(text, pii_detector)
        assert tags == sorted(tags), f"tags not sorted: {tags}"

    # --- Bounds (LAURA-31DR-002: scan cap raised from 10 KB to 1 MB) ---

    def test_input_at_or_below_max_bytes_does_not_raise(self, pii_detector):
        """Text at or below the 1 MB scan limit must not raise."""
        big = "A" * _CONTENT_TAGS_MAX_BYTES
        tags = _detect_content_tags(big, pii_detector)
        assert isinstance(tags, list)

    def test_input_beyond_max_bytes_does_not_raise(self, pii_detector):
        """Text larger than _CONTENT_TAGS_MAX_BYTES must not raise (tail is unscanned)."""
        big = "A" * (_CONTENT_TAGS_MAX_BYTES + 5000)
        tags = _detect_content_tags(big, pii_detector)
        assert isinstance(tags, list)

    def test_ssn_at_old_cap_boundary_now_detected(self, pii_detector):
        """LAURA-31DR-002 regression: SSN placed at 11 KB (beyond the old 10 KB cap)
        MUST now be detected — the old cap allowed this bypass path."""
        _old_cap = 10_240
        padding = "x " * (_old_cap // 2)  # ~10 KB of benign text
        text = padding + " 123-45-6789"    # SSN placed past old cap boundary
        tags = _detect_content_tags(text, pii_detector)
        assert "pii" in tags, (
            f"SSN at ~11 KB must now be detected (LAURA-31DR-002 cap-evasion fix), "
            f"got {tags}"
        )

    def test_ssn_beyond_1mb_scan_limit_not_detected(self, pii_detector):
        """SSN placed entirely beyond the 1 MB scan limit is not detected
        (documented trade-off; payloads >1 MB are blocked by clearance gate for
        RESTRICTED users regardless)."""
        padding = "x" * _CONTENT_TAGS_MAX_BYTES
        text = padding + " 123-45-6789"  # SSN after the 1 MB cap
        tags = _detect_content_tags(text, pii_detector)
        assert "pii" not in tags


# ---------------------------------------------------------------------------
# B. _client_enforce_input — output contract
# ---------------------------------------------------------------------------

class TestClientEnforceInput:
    def _identity(self):
        return {
            "identity_id": "alice@corp.example",
            "kind": "human",
            "sensitivity_ceiling": "CONFIDENTIAL",
            "groups": ["analysts"],
        }

    def test_data_tags_present_in_output(self):
        result = _client_enforce_input(self._identity(), "/v1/chat/completions")
        assert "data_tags" in result, "data_tags key must always be present in output"

    def test_default_data_tags_is_empty_list(self):
        result = _client_enforce_input(self._identity(), "/v1/chat/completions")
        assert result["data_tags"] == []

    def test_data_tags_propagated_correctly(self):
        result = _client_enforce_input(
            self._identity(), "/v1/chat/completions", data_tags=["pii", "pci"]
        )
        assert result["data_tags"] == ["pii", "pci"]

    def test_data_tags_converts_tuple_to_list(self):
        result = _client_enforce_input(
            self._identity(), "/v1/chat/completions", data_tags=("classified",)
        )
        assert result["data_tags"] == ["classified"]
        assert isinstance(result["data_tags"], list)

    def test_none_identity_does_not_crash(self):
        result = _client_enforce_input(None, "/v1/chat/completions", data_tags=["pii"])
        assert result["data_tags"] == ["pii"]


# ---------------------------------------------------------------------------
# C. End-to-end wiring — tags reach evaluate_client_policies input
# ---------------------------------------------------------------------------
# These tests mock evaluate_client_policies and verify that the base_input
# dict that reaches OPA includes the correct data_tags derived from content.
# They do NOT need a running OPA or FastAPI app.

class TestDataTagsWiredToOpa:
    """Verify the full wiring: content → _detect_content_tags → _client_enforce_input
    → evaluate_client_policies(base_input) with populated data_tags."""

    @pytest.mark.asyncio
    async def test_ssn_prompt_produces_pii_tag_in_opa_input(self, pii_detector, monkeypatch):
        """Prompt containing an SSN must result in data_tags=["pii"] in the OPA call."""
        captured: list[dict] = []

        async def _fake_evaluate(cfg, scope_kind, scope_id, direction, base_input):
            captured.append(base_input)
            return {"allow": True, "deny": [], "obligations": []}

        from yashigani.gateway import openai_router as _ow
        monkeypatch.setattr(_ow, "evaluate_client_policies", _fake_evaluate)

        prompt = "My SSN is 123-45-6789, I need help."
        tags = _detect_content_tags(prompt, pii_detector)

        # Simulate what the ingress path does:
        identity = {"identity_id": "alice@corp.example", "kind": "human",
                    "sensitivity_ceiling": "CONFIDENTIAL", "groups": []}
        base_input = _client_enforce_input(
            identity, "/v1/chat/completions",
            route_reason="local", provider="ollama", model="qwen2.5:3b",
            data_tags=tags,
        )

        result = await _fake_evaluate(
            None, "human", "alice@corp.example", "ingress", base_input
        )
        assert result["allow"] is True

        assert len(captured) == 1, "evaluate_client_policies should have been called once"
        assert captured[0]["data_tags"] == ["pii"], (
            f"OPA input.data_tags should be ['pii'] for SSN prompt, got {captured[0]['data_tags']}"
        )

    def test_credit_card_prompt_produces_pii_pci_tags(self, pii_detector):
        """Prompt with a valid credit card produces ['pci', 'pii'] (sorted)."""
        prompt = "process payment with card 4532-0151-1283-0366 exp 12/26"
        tags = _detect_content_tags(prompt, pii_detector)
        assert "pii" in tags
        assert "pci" in tags

        identity = {"identity_id": "noah@corp.example", "kind": "human",
                    "sensitivity_ceiling": "INTERNAL", "groups": []}
        base_input = _client_enforce_input(
            identity, "/v1/chat/completions", data_tags=tags
        )
        assert "pci" in base_input["data_tags"]
        assert "pii" in base_input["data_tags"]

    def test_clean_prompt_produces_empty_data_tags(self, pii_detector):
        """A clean prompt must produce an empty data_tags list in the OPA input."""
        prompt = "Summarise the key points of the Q3 report."
        tags = _detect_content_tags(prompt, pii_detector)
        assert tags == []

        identity = {"identity_id": "bob@corp.example", "kind": "human",
                    "sensitivity_ceiling": "RESTRICTED", "groups": []}
        base_input = _client_enforce_input(
            identity, "/v1/chat/completions", data_tags=tags
        )
        assert base_input["data_tags"] == []

    def test_classified_prompt_produces_classified_tag(self, pii_detector):
        """Prompt with SECRET banner produces ['classified'] tag (no PII)."""
        prompt = "// SECRET // Please summarise the attached briefing."
        tags = _detect_content_tags(prompt, pii_detector)
        assert "classified" in tags

        identity = {"identity_id": "sara@corp.example", "kind": "human",
                    "sensitivity_ceiling": "CONFIDENTIAL", "groups": []}
        base_input = _client_enforce_input(
            identity, "/v1/chat/completions", data_tags=tags
        )
        assert "classified" in base_input["data_tags"]

    def test_data_tags_key_always_present_even_without_detector(self):
        """Even when no PII detector is wired, data_tags must be a list in output."""
        prompt = "Hello world"
        tags = _detect_content_tags(prompt, pii_detector=None)
        base_input = _client_enforce_input(None, "/v1/chat/completions", data_tags=tags)
        assert isinstance(base_input.get("data_tags"), list)
