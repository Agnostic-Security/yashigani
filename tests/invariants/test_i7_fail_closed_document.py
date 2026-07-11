"""
I7 — Fail-closed everywhere (document-OPA default-BLOCK + the 4 actions).

INVARIANT (must ALWAYS hold): the document-OPA policy is **default-deny**. With no
input, malformed input, incomplete extraction, an unpoliced match, or a
re-identification escalation, the disposition is **BLOCK**. A policy author can
LOWER strictness for a clean/policed document (LOG / PSEUDONYMIZE / ROUTE_LOCAL /
REDACT) but can NEVER make "fail to inspect" mean "let it through".

Why an invariant: doc-OPA gates document content leaving the estate. If the
default ever flips permissive, an extraction failure (a format we can't parse, a
truncated read) would silently exfiltrate uninspected content. This must hold on
every release.

Asserted here: the rego carries ``default action := "BLOCK"`` and the
BLOCK-on-incomplete / unpoliced / reid override rules; the four supported actions
exist. Text-level so it is stable across rego refactors of the *implementation* of
each rule while pinning the load-bearing default + override posture.

LIVE-PROOF (#44): a real document round-trip post-converge (truncated/unparseable
input ⇒ BLOCK over the wire) is the live VM item; this asserts the policy contract.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCUMENT_REGO = REPO_ROOT / "policy" / "document.rego"


@pytest.fixture(scope="module")
def rego_text() -> str:
    assert DOCUMENT_REGO.exists(), f"document.rego missing: {DOCUMENT_REGO}"
    return DOCUMENT_REGO.read_text(encoding="utf-8")


def test_default_action_is_block(rego_text: str) -> None:
    """The document disposition defaults to BLOCK (fail-closed, F9)."""
    assert re.search(r'default\s+action\s*:?=\s*"BLOCK"', rego_text), (
        "document.rego must declare `default action := \"BLOCK\"` — the doc-OPA "
        "fail-closed default. Without it, an uninspected document is permitted."
    )


def test_incomplete_extraction_forces_block(rego_text: str) -> None:
    """Incomplete extraction ⇒ BLOCK (cannot inspect ⇒ cannot release)."""
    assert re.search(
        r'action\s*:?=\s*"BLOCK"\s+if\s+not\s+_extraction_complete', rego_text
    ), (
        "document.rego must force BLOCK when extraction is incomplete — a "
        "partially-parsed document must never pass."
    )


def test_unpoliced_match_forces_block(rego_text: str) -> None:
    """A matched-but-unpoliced sensitive class ⇒ BLOCK (no silent pass-through)."""
    assert "_unpoliced_match" in rego_text, (
        "document.rego must reference _unpoliced_match — a sensitive match with no "
        "configured handling must BLOCK, not fall through to LOG."
    )
    # the unpoliced override must resolve to BLOCK, not a softer action
    assert re.search(r'action\s*:?=\s*"BLOCK"\s+if\s*\{[^}]*_unpoliced_match', rego_text, re.S), (
        "_unpoliced_match must force the BLOCK branch."
    )


def test_reid_escalation_forces_block(rego_text: str) -> None:
    """Re-identification escalation ⇒ BLOCK."""
    assert re.search(r'action\s*:?=\s*"BLOCK"\s+if\s+_reid_escalation', rego_text), (
        "document.rego must force BLOCK on re-identification escalation."
    )


def test_four_actions_defined(rego_text: str) -> None:
    """The four document actions exist (LOG / PSEUDONYMIZE / ROUTE_LOCAL / REDACT)
    in addition to the BLOCK default — the strictness ladder is complete."""
    for action in ("LOG", "PSEUDONYMIZE", "ROUTE_LOCAL", "REDACT", "BLOCK"):
        assert f'"{action}"' in rego_text, (
            f"document.rego must define the {action} action."
        )


def test_block_is_strongest_in_rank(rego_text: str) -> None:
    """BLOCK ranks strictest in the precedence ladder — nothing overrides BLOCK
    down to a softer action."""
    m = re.search(r'_rank\s*:?=\s*\{([^}]*)\}', rego_text)
    assert m, "document.rego must define a _rank precedence map for the actions."
    ranks_blob = m.group(1)
    rank = {
        k: int(v)
        for k, v in re.findall(r'"([A-Z_]+)"\s*:\s*(\d+)', ranks_blob)
    }
    assert "BLOCK" in rank, "_rank must include BLOCK."
    assert rank["BLOCK"] == max(rank.values()), (
        f"BLOCK must be the strictest action in _rank (got {rank}); a lower rank "
        f"would let another action override a BLOCK."
    )
