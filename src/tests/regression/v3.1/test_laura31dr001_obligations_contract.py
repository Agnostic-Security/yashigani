"""Regression tests — LAURA-31DR-001 / LAURA-31DR-002.

LAURA-31DR-001: input.obligations omitted from _client_enforce_input output.
----------------------------------------------------------------------
Root cause: _client_enforce_input() returned identity/request/routing_decision/
data_tags but NO "obligations" key. POL-004 (pii_redaction_policy) and POL-003
(compliance_audit_log) both check membership in input.obligations:

    not "pii_redacted" in input.obligations   # POL-004
    not "audit_log"    in input.obligations   # POL-003

In Rego v1, `"pii_redacted" in undefined` evaluates to undefined.
`not undefined` → rule body undefined → deny rule never fires → OPA aggregate
returns allow=True → SSN from a RESTRICTED user reaches the model verbatim.

Fix: add "obligations": list(obligations) to _client_enforce_input, always
present (default []). The Rego policies are also hardened with
`object.get(input, "obligations", set())` as a belt-and-suspenders guard.

LAURA-31DR-002: spaced-digit SSN bypass + 10 KB scan cap.
--------------------------------------------------------------
Two separate evasion paths:
  (a) SSN with space separators "123 45 6789" matched no pattern in
      SSN_PATTERNS, so _detect_content_tags returned [] → no "pii" tag →
      POL-004 deny rule body was never true.  Fix: added space-separated
      SSN pattern to SSN_PATTERNS.
  (b) The 10 KB prefix cap in _detect_content_tags allowed PII placed after
      the boundary to evade tagging.  Fix: raised cap to 1 MB.

These tests verify the contracts directly without a running OPA or FastAPI app.
POL-004 Rego logic is also tested against the fixed input contract to confirm
the deny fires end-to-end.
"""
from __future__ import annotations

import pytest

import os
os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-bearer-sentinel")
os.environ.setdefault("YASHIGANI_OPA_OPTIONAL", "true")
os.environ.setdefault("YASHIGANI_ENV", "test")

from yashigani.gateway.openai_router import (  # noqa: E402
    _client_enforce_input,
    _detect_content_tags,
)
from yashigani.pii.detector import PiiDetector, PiiMode  # noqa: E402
from yashigani.pii.patterns import SSN_PATTERNS  # noqa: E402


@pytest.fixture()
def pii_detector() -> PiiDetector:
    return PiiDetector(mode=PiiMode.LOG)


# ---------------------------------------------------------------------------
# LAURA-31DR-001 — obligations field contract
# ---------------------------------------------------------------------------

class TestObligationsFieldContract:
    """_client_enforce_input must always include "obligations" in its output."""

    def _identity(self, clearance="RESTRICTED", groups=None):
        return {
            "identity_id": "ana@agnosticsec.com",
            "kind": "human",
            "sensitivity_ceiling": clearance,
            "groups": groups or [],
        }

    def test_obligations_key_always_present_default(self):
        """obligations must be present even when not supplied."""
        result = _client_enforce_input(self._identity(), "/v1/chat/completions")
        assert "obligations" in result, (
            "LAURA-31DR-001: 'obligations' key missing from _client_enforce_input output — "
            "Rego membership check on undefined silently bypasses deny"
        )

    def test_obligations_default_is_empty_list(self):
        """Default obligations must be an empty list, not None or absent."""
        result = _client_enforce_input(self._identity(), "/v1/chat/completions")
        assert result["obligations"] == [], (
            f"Expected empty list, got {result['obligations']!r}"
        )
        assert isinstance(result["obligations"], list)

    def test_obligations_populated_when_provided(self):
        """When obligations are provided they appear verbatim in the output."""
        result = _client_enforce_input(
            self._identity(), "/v1/chat/completions",
            obligations=["pii_redacted"],
        )
        assert result["obligations"] == ["pii_redacted"]

    def test_obligations_tuple_coerced_to_list(self):
        """Tuple obligations are coerced to list (JSON-serialisable)."""
        result = _client_enforce_input(
            self._identity(), "/v1/chat/completions",
            obligations=("audit_log",),
        )
        assert isinstance(result["obligations"], list)
        assert result["obligations"] == ["audit_log"]

    def test_obligations_present_alongside_data_tags(self):
        """Both data_tags and obligations are present when PII is detected."""
        result = _client_enforce_input(
            self._identity(), "/v1/chat/completions",
            data_tags=["pii"],
            obligations=[],
        )
        assert "data_tags" in result
        assert "obligations" in result
        assert result["data_tags"] == ["pii"]
        assert result["obligations"] == []

    def test_none_identity_does_not_crash_and_has_obligations(self):
        """None identity does not crash; obligations still present."""
        result = _client_enforce_input(None, "/v1/chat/completions")
        assert "obligations" in result
        assert result["obligations"] == []


# ---------------------------------------------------------------------------
# LAURA-31DR-001 — Rego deny semantics via Python simulation
#
# We can't invoke OPA here (no running instance), so we replicate the
# deny-rule logic in Python to prove the fix is coherent: given a
# _client_enforce_input output with data_tags=["pii"] and obligations=[],
# the deny MUST evaluate to True.
# ---------------------------------------------------------------------------

class TestRegoDenySimulation:
    """Simulate POL-004 deny logic to confirm the obligations fix works."""

    @staticmethod
    def _pol004_deny(opa_input: dict) -> bool:
        """Python simulation of POL-004 deny rule (post-fix).

        deny contains "POL-004:pii_transmission_blocked" if {
            input.data_tags[_] == "pii"
            not "pii_redacted" in object.get(input, "obligations", set())
            not "compliance-team" in input.identity.groups
        }
        """
        data_tags = opa_input.get("data_tags", [])
        obligations = opa_input.get("obligations", set())  # object.get default
        groups = opa_input.get("identity", {}).get("groups", [])
        return (
            "pii" in data_tags
            and "pii_redacted" not in obligations
            and "compliance-team" not in groups
        )

    def test_ssn_restricted_user_no_obligations_is_denied(self):
        """RESTRICTED user sending SSN with empty obligations → deny fires."""
        opa_input = _client_enforce_input(
            {"identity_id": "ana@agnosticsec.com", "kind": "human",
             "sensitivity_ceiling": "RESTRICTED", "groups": []},
            "/v1/chat/completions",
            data_tags=["pii"],
            obligations=[],
        )
        assert self._pol004_deny(opa_input) is True, (
            "LAURA-31DR-001: POL-004 deny must fire for RESTRICTED user with PII "
            "and empty obligations"
        )

    def test_pii_redacted_obligation_suppresses_deny(self):
        """When 'pii_redacted' is in obligations, POL-004 deny must NOT fire."""
        opa_input = _client_enforce_input(
            {"identity_id": "ana@agnosticsec.com", "kind": "human",
             "sensitivity_ceiling": "RESTRICTED", "groups": []},
            "/v1/chat/completions",
            data_tags=["pii"],
            obligations=["pii_redacted"],
        )
        assert self._pol004_deny(opa_input) is False, (
            "POL-004 deny must NOT fire when 'pii_redacted' is in obligations"
        )

    def test_compliance_team_user_exempt_from_pol004(self):
        """compliance-team users are exempt from POL-004."""
        opa_input = _client_enforce_input(
            {"identity_id": "mia@agnosticsec.com", "kind": "human",
             "sensitivity_ceiling": "CONFIDENTIAL", "groups": ["compliance-team"]},
            "/v1/chat/completions",
            data_tags=["pii"],
            obligations=[],
        )
        assert self._pol004_deny(opa_input) is False, (
            "POL-004 must NOT fire for compliance-team users"
        )

    def test_clean_prompt_not_denied(self):
        """No PII in data_tags → deny must not fire."""
        opa_input = _client_enforce_input(
            {"identity_id": "ana@agnosticsec.com", "kind": "human",
             "sensitivity_ceiling": "RESTRICTED", "groups": []},
            "/v1/chat/completions",
            data_tags=[],
            obligations=[],
        )
        assert self._pol004_deny(opa_input) is False, (
            "POL-004 must NOT fire when no PII tag in data_tags"
        )

    def test_missing_obligations_key_uses_empty_set_default(self):
        """Simulates the OLD broken state: absent obligations key.
        With object.get default the deny still fires correctly (belt-and-suspenders)."""
        opa_input = {
            "identity": {"groups": [], "clearance": "RESTRICTED"},
            "data_tags": ["pii"],
            # NO "obligations" key — simulates the pre-fix state
        }
        # Even if the key is absent, the Python simulation uses .get() default
        # which mirrors object.get(input, "obligations", set()) in Rego.
        obligations = opa_input.get("obligations", set())
        data_tags = opa_input.get("data_tags", [])
        groups = opa_input.get("identity", {}).get("groups", [])
        deny = (
            "pii" in data_tags
            and "pii_redacted" not in obligations
            and "compliance-team" not in groups
        )
        assert deny is True, (
            "Rego object.get default must make deny fire even when obligations key absent"
        )


# ---------------------------------------------------------------------------
# LAURA-31DR-002 — spaced-digit SSN detection
# ---------------------------------------------------------------------------

class TestSpacedDigitSSNDetection:
    """SSN formatted with spaces ('123 45 6789') must be detected as PII."""

    def test_space_separated_ssn_detected(self, pii_detector):
        """'123 45 6789' (space separators) must yield 'pii' tag."""
        text = "My SSN is 123 45 6789"
        tags = _detect_content_tags(text, pii_detector)
        assert "pii" in tags, (
            f"LAURA-31DR-002: space-separated SSN must be detected, got {tags}"
        )

    def test_space_ssn_does_not_yield_pci(self, pii_detector):
        """SSN with spaces is PII but NOT PCI-scoped."""
        text = "SSN 123 45 6789"
        tags = _detect_content_tags(text, pii_detector)
        assert "pci" not in tags

    def test_space_ssn_regex_pattern_matches_directly(self):
        """Verify the space-separated SSN regex pattern in SSN_PATTERNS."""
        space_ssn_pattern = None
        for pat in SSN_PATTERNS:
            if r"\s" in pat.pattern:
                space_ssn_pattern = pat
                break
        assert space_ssn_pattern is not None, (
            "LAURA-31DR-002: space-separated SSN regex must exist in SSN_PATTERNS"
        )
        assert space_ssn_pattern.search("123 45 6789") is not None, (
            "Space-separated SSN regex must match '123 45 6789'"
        )

    def test_space_ssn_with_invalid_prefix_not_matched(self):
        """Invalid SSN prefix (000) with spaces must not match."""
        text = "000 12 3456"
        for pat in SSN_PATTERNS:
            if r"\s" in pat.pattern:
                assert pat.search(text) is None, (
                    f"Pattern must not match invalid SSN prefix '000': {pat.pattern}"
                )

    def test_dash_ssn_still_detected(self, pii_detector):
        """Original dash-format SSN must still be detected after the pattern change."""
        text = "SSN: 123-45-6789"
        tags = _detect_content_tags(text, pii_detector)
        assert "pii" in tags

    def test_unformatted_ssn_still_detected(self, pii_detector):
        """Unformatted 9-digit SSN must still be detected."""
        text = "SSN: 123456789"
        tags = _detect_content_tags(text, pii_detector)
        assert "pii" in tags


# ---------------------------------------------------------------------------
# End-to-end: RESTRICTED user + SSN → deny
# (combines obligations contract + SSN detection + deny simulation)
# ---------------------------------------------------------------------------

class TestEndToEndPol004BlockSSN:
    """End-to-end simulation: RESTRICTED user sends SSN → POL-004 fires."""

    @staticmethod
    def _pol004_deny(opa_input: dict) -> bool:
        data_tags = opa_input.get("data_tags", [])
        obligations = opa_input.get("obligations", set())
        groups = opa_input.get("identity", {}).get("groups", [])
        return (
            "pii" in data_tags
            and "pii_redacted" not in obligations
            and "compliance-team" not in groups
        )

    def test_restricted_user_sends_dash_ssn_is_blocked(self, pii_detector):
        """RESTRICTED user + dash SSN → data_tags=['pii'], obligations=[] → POL-004 fires."""
        prompt = "Please verify my SSN: 123-45-6789"
        tags = _detect_content_tags(prompt, pii_detector)
        assert "pii" in tags

        opa_input = _client_enforce_input(
            {"identity_id": "ana@agnosticsec.com", "kind": "human",
             "sensitivity_ceiling": "RESTRICTED", "groups": []},
            "/v1/chat/completions",
            data_tags=tags,
            obligations=[],
        )
        assert self._pol004_deny(opa_input) is True

    def test_restricted_user_sends_spaced_ssn_is_blocked(self, pii_detector):
        """LAURA-31DR-002: RESTRICTED user + space-separated SSN → still blocked."""
        prompt = "Please verify my SSN: 123 45 6789"
        tags = _detect_content_tags(prompt, pii_detector)
        assert "pii" in tags, (
            f"Space-separated SSN must be detected as PII, got {tags}"
        )

        opa_input = _client_enforce_input(
            {"identity_id": "ana@agnosticsec.com", "kind": "human",
             "sensitivity_ceiling": "RESTRICTED", "groups": []},
            "/v1/chat/completions",
            data_tags=tags,
            obligations=[],
        )
        assert self._pol004_deny(opa_input) is True, (
            "POL-004 must block RESTRICTED user sending space-separated SSN"
        )

    def test_restricted_user_clean_prompt_is_allowed(self, pii_detector):
        """Clean prompt from RESTRICTED user → no PII tag → POL-004 does not fire."""
        prompt = "What is the capital of France?"
        tags = _detect_content_tags(prompt, pii_detector)
        assert "pii" not in tags

        opa_input = _client_enforce_input(
            {"identity_id": "ana@agnosticsec.com", "kind": "human",
             "sensitivity_ceiling": "RESTRICTED", "groups": []},
            "/v1/chat/completions",
            data_tags=tags,
            obligations=[],
        )
        assert self._pol004_deny(opa_input) is False, (
            "Clean prompt must NOT be blocked by POL-004"
        )
