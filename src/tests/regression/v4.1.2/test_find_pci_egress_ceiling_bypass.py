"""
Regression tests — FIND-PCI-EGRESS-CEILING-BYPASS (CRITICAL, 2026-08-07).

## Root cause

``_client_enforce_input()`` (src/yashigani/gateway/openai_router.py) builds
the shared input document for BOTH the ingress and egress
``evaluate_client_policies()`` calls in ``chat_completions()``. The seeded
demo client policy POL-009 (``pci_data_block``, package
``clients.pci_data_block``) is bound WILDCARD to every human, both
directions, and denies when ``input.data_tags[_] == "pci"`` OR
``input.routing_decision.sensitivity == "RESTRICTED"``.

``_client_enforce_input()`` NEVER populated ``data_tags`` or
``routing_decision.sensitivity`` at all (they were entirely absent from the
returned dict) — so BOTH of POL-009's deny-rule bodies evaluated against an
undefined ``input`` field. In Rego, iterating/comparing against an
undefined field produces no results for that rule (not an error), so
``deny`` stayed empty and ``decision.allow`` was always ``true`` regardless
of whether the request or response actually contained cardholder data. A
caller with a RESTRICTED sensitivity_ceiling (e.g. "ana") could therefore
send AND receive a Luhn-valid PAN verbatim — the ceiling gate legitimately
permits RESTRICTED content, but POL-009's job was to make PCI cardholder
data an ABSOLUTE block regardless of ceiling, and it structurally never
fired.

## The fix

  1. ``_client_enforce_input()`` now accepts and threads through
     ``sensitivity`` and ``data_tags``.
  2. The INGRESS call site derives ``data_tags`` from the request prompt's
     own regex-authoritative sensitivity triggers via
     ``_derive_pci_data_tags()`` (Layer-1-only — never sklearn:/ollama:
     triggers, per FIND-INSPECTION-NONDETERMINISTIC's regex-authoritative
     invariant).
  3. The EGRESS call site derives the "pci" tag from an ALWAYS-ON,
     config-independent Luhn-valid PAN scan
     (``yashigani.pii.contains_pci_pan``) run directly on
     ``assistant_content`` — NOT gated behind the optional
     ``response_inspection_pipeline`` / ``pii_detector`` toggles
     (YSG-RISK-057), so the PCI DSS control is genuinely absolute.
  4. POL-009's own seeded rego (scripts/populate-demo.py) is narrowed to
     drop the bare ``sensitivity == "RESTRICTED"`` deny branch — see that
     policy's comment for why: post-R14/R15, RESTRICTED(4) (SSN/phone/IBAN)
     and SENSITIVE(5) (PCI) both collapse to the legacy string
     "RESTRICTED", so leaving that branch in would have made the newly-
     wired ``routing_decision.sensitivity`` field turn POL-009 into a
     blanket "deny all RESTRICTED content" rule for every human — silently
     defeating a caller's legitimately-granted RESTRICTED ceiling for
     non-PCI content. POL-010 (classified_marking_local) had the identical
     latent issue and is narrowed the same way.

Live verification (>=5x repeated trials, both stream modes, rebuilt+
recreated gateway image): see the commit body / testing_runs log — ana's
PCI payload denies 5/5 with ``POL-009:pci_data_present`` at INGRESS (before
generation) on both stream=false and stream=true; paul (unaffected,
ceiling-only) still denies 5/5; benign "Say hello" still 200 5/5 for both
users, both modes.

Fail-before/pass-after (git stash) — see commit body for the exact
transcript.
"""
from __future__ import annotations

import inspect
import re

from yashigani.gateway.openai_router import (
    _client_enforce_input,
    _derive_pci_data_tags,
)
from yashigani.pii import contains_pci_pan


# ---------------------------------------------------------------------------
# 1. _client_enforce_input — schema now carries sensitivity + data_tags
# ---------------------------------------------------------------------------

def test_client_enforce_input_carries_sensitivity_and_data_tags():
    doc = _client_enforce_input(
        {"identity_id": "u1", "kind": "human", "sensitivity_ceiling": "RESTRICTED", "groups": []},
        "/v1/chat/completions",
        sensitivity="RESTRICTED",
        data_tags=["pci"],
    )
    assert doc["routing_decision"]["sensitivity"] == "RESTRICTED"
    assert doc["data_tags"] == ["pci"]


def test_client_enforce_input_defaults_are_empty_not_missing():
    """Pre-fix, these keys were ENTIRELY ABSENT. Post-fix, callers that don't
    pass them get an explicit empty value — never a missing key — so
    `input.data_tags[_]` is always a defined-but-empty array (no results,
    same net effect) rather than an undefined field. Also guards against a
    future refactor accidentally dropping the keys again."""
    doc = _client_enforce_input({"identity_id": "u1"}, "/v1/chat/completions")
    assert "data_tags" in doc
    assert doc["data_tags"] == []
    assert "sensitivity" in doc["routing_decision"]
    assert doc["routing_decision"]["sensitivity"] == ""


# ---------------------------------------------------------------------------
# 2. _derive_pci_data_tags — Layer-1-only, regex-authoritative
# ---------------------------------------------------------------------------

def test_derive_pci_data_tags_fires_on_regex_credit_card_trigger():
    triggers = ["regex:Credit/debit card", "regex:US SSN"]
    assert _derive_pci_data_tags(triggers) == ["pci"]


def test_derive_pci_data_tags_ignores_ml_layer_triggers():
    """A sklearn/ollama trigger claiming "sensitive"/high confidence must
    NEVER assert the "pci" tag on its own — only the deterministic regex
    layer may (regex-authoritative, FIND-INSPECTION-NONDETERMINISTIC)."""
    triggers = ["sklearn:UNSAFE(0.99)", "ollama:SENSITIVE"]
    assert _derive_pci_data_tags(triggers) == []


def test_derive_pci_data_tags_empty_for_no_triggers():
    assert _derive_pci_data_tags([]) == []
    assert _derive_pci_data_tags(None) == []


def test_derive_pci_data_tags_does_not_tag_other_restricted_content():
    """SSN/phone/IBAN are genuinely NOT PCI — must not get the "pci" tag
    (that would make POL-009 over-block non-cardholder RESTRICTED content,
    defeating a caller's legitimate RESTRICTED ceiling)."""
    triggers = ["regex:US SSN", "regex:US/CA phone", "regex:IBAN"]
    assert _derive_pci_data_tags(triggers) == []


# ---------------------------------------------------------------------------
# 3. contains_pci_pan — always-on, config-independent Luhn-valid PAN scan
# ---------------------------------------------------------------------------

def test_contains_pci_pan_true_for_luhn_valid_card():
    assert contains_pci_pan("Card on file: 4111 1111 1111 1111") is True


def test_contains_pci_pan_false_for_luhn_invalid_digit_run():
    # 16 digits, fails Luhn check.
    assert contains_pci_pan("Reference number: 1234 5678 9012 3456") is False


def test_contains_pci_pan_false_for_clean_text():
    assert contains_pci_pan("The quarterly report is due next Friday.") is False


def test_contains_pci_pan_false_for_empty():
    assert contains_pci_pan("") is False
    assert contains_pci_pan(None) is False  # type: ignore[arg-type]


def test_contains_pci_pan_independent_of_any_pii_detector_config():
    """This is the "absolute" property: contains_pci_pan takes no
    PiiDetector/config argument at all — it cannot be disabled by an
    operator toggling _state.pii_detector or
    _state.response_inspection_pipeline off."""
    sig = inspect.signature(contains_pci_pan)
    assert list(sig.parameters) == ["text"]


# ---------------------------------------------------------------------------
# 4. Source-inspection guards — POL-009/POL-010 seed rego no longer contains
#    the overbroad bare-"RESTRICTED" deny branch that would have turned the
#    newly-wired routing_decision.sensitivity field into a regression
#    (blanket deny of all RESTRICTED content for every bound human).
# ---------------------------------------------------------------------------

def _populate_demo_source() -> str:
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[4]
    path = repo_root / "scripts" / "populate-demo.py"
    assert path.exists(), f"expected populate-demo.py at {path}"
    return path.read_text()


def _non_comment_lines(rego: str) -> list[str]:
    """Strip Rego comment lines so a source-code assertion cannot be
    accidentally satisfied by a Python docstring/# comment describing the
    OLD (removed) code, only by an actual, still-live code line."""
    return [ln for ln in rego.splitlines() if not ln.strip().startswith("#")]


def test_pol009_rego_denies_only_on_pci_tag():
    src = _populate_demo_source()
    m = re.search(r'"name": "pci_data_block".*?"""\s*,', src, re.DOTALL)
    assert m, "pci_data_block policy block not found in populate-demo.py"
    code_lines = _non_comment_lines(m.group(0))
    code = "\n".join(code_lines)
    assert 'input.data_tags[_] == "pci"' in code
    assert 'input.routing_decision.sensitivity == "RESTRICTED"' not in code, (
        "POL-009 must not deny on the bare collapsed 'RESTRICTED' string — "
        "that string covers BOTH genuine PCI (SENSITIVE/level-5, mapped down "
        "for OPA back-compat) AND ordinary RESTRICTED content (SSN/phone/"
        "IBAN, level-4) that a caller's ceiling legitimately permits."
    )


def test_pol010_rego_denies_only_on_classified_tag():
    src = _populate_demo_source()
    m = re.search(r'"name": "classified_marking_local".*?"""\s*,', src, re.DOTALL)
    assert m, "classified_marking_local policy block not found in populate-demo.py"
    code_lines = _non_comment_lines(m.group(0))
    code = "\n".join(code_lines)
    assert 'input.data_tags[_] == "classified"' in code
    assert 'input.routing_decision.sensitivity == "RESTRICTED"' not in code, (
        "POL-010 must not deny on the bare collapsed 'RESTRICTED' string "
        "either, for the same reason as POL-009 (see test above) — it would "
        "force local-only routing for every RESTRICTED response for every "
        "bound human, not just genuinely classified-marked content."
    )


# ---------------------------------------------------------------------------
# 5. Source-inspection guard — the egress call site actually wires the new
#    parameters (prevents a future edit from silently reverting to the old
#    2-arg call, which would compile fine and re-open the bypass silently).
# ---------------------------------------------------------------------------

def test_egress_call_site_wires_data_tags_and_sensitivity():
    import yashigani.gateway.openai_router as router_mod

    src = inspect.getsource(router_mod)
    egress_block_match = re.search(
        r"8b-bind\. Client-policy enforcement — EGRESS.*?_ce_eg = await evaluate_client_policies\(.*?\)\n",
        src, re.DOTALL,
    )
    assert egress_block_match, "EGRESS client-policy enforcement block not found"
    block = egress_block_match.group(0)
    assert "contains_pci_pan(assistant_content)" in block
    assert "data_tags=_ce_eg_data_tags" in block
    assert "sensitivity=response_content_sensitivity or sensitivity_level" in block
