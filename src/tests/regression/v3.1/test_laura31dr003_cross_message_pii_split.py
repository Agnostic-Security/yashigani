"""Regression tests — LAURA-31DR-003 / OBS-3.1-001.

LAURA-31DR-003: cross-message PII fragmentation evades ingress content-tag scan.
----------------------------------------------------------------------
Root cause: _detect_content_tags() received prompt_text built as
``"\\n".join(m.content for m in body.messages if m.content)``.  A PII value
spanning a message boundary is broken by the "\\n" separator — the SSN regex
`\\d{3}-\\d{2}-\\d{4}` fails to match "123-45-\\n6789" (newline mid-pattern) or
"123-45\\n6789" (newline where the second dash should be).  POL-004 never fired
because input.data_tags stayed empty → the full SSN reached the model
(escalates to a real DLP gap on cloud models where egress inspection is absent).

Fix: _detect_content_tags() now also scans two separator-collapsed views when
the text contains a newline:
  - replace("\\n", "")  — "123-45-\\n6789" → "123-45-6789" → dashed SSN match
  - replace("\\n", "-") — "123-45\\n6789"  → "123-45-6789" → dashed SSN match
Tags are unioned across all three views; classification keyword scan is
unchanged (left on original text only — classification markers are not
typically split across messages).

OBS-3.1-001: `import os` scope shadow in chat_completions().
----------------------------------------------------------------------
Root cause: a bare `import os` inside the agent-routing else-branch (line ~2578)
made Python treat `os` as a LOCAL variable for the ENTIRE chat_completions()
function scope.  Any reference to `os` BEFORE that line (e.g.
os.getenv("YASHIGANI_ORG_ID") in the identity-resolution block) raised
`UnboundLocalError: cannot access local variable 'os' before assignment`,
so request.state.ysg_principal was never set on chat requests
(fallback to anonymous, 10+ log lines per run, occasional opa_unreachable).

Fix: changed `import os` to `import os as _os` (aliased import) and updated
the one immediately-following `os.getenv(...)` call to `_os.getenv(...)`.
Module-level `import os` at line 61 is the sole module-scope binding; no other
bare in-function `import os` remains.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-bearer-sentinel")
os.environ.setdefault("YASHIGANI_OPA_OPTIONAL", "true")
os.environ.setdefault("YASHIGANI_ENV", "test")

from yashigani.gateway.openai_router import _detect_content_tags  # noqa: E402
from yashigani.pii.detector import PiiDetector, PiiMode  # noqa: E402


@pytest.fixture()
def pii_detector() -> PiiDetector:
    return PiiDetector(mode=PiiMode.LOG)


# ---------------------------------------------------------------------------
# LAURA-31DR-003 — cross-message PII fragmentation
# ---------------------------------------------------------------------------

class TestCrossMessagePiiSplit:
    """_detect_content_tags must detect PII that straddles a message boundary."""

    # --- Dash-boundary split: attacker keeps the dash at end of msg1 ---

    def test_dash_boundary_split_ssn_detected(self, pii_detector):
        """'123-45-' | '6789' joined by newline: SSN must be detected.

        The attacker splits the SSN so the second dash and the 4-digit suffix
        start at the beginning of msg2.  The newline after '123-45-' breaks the
        regex; the fix scans a collapse-to-'' view that reassembles '123-45-6789'.
        """
        # Simulates prompt_text built by "\n".join(m.content ...)
        joined = "my ssn 123-45-\n6789 please process"
        tags = _detect_content_tags(joined, pii_detector)
        assert "pii" in tags, (
            "LAURA-31DR-003 regression: dash-boundary SSN split across messages "
            f"must produce 'pii' tag, got {tags}"
        )

    def test_dash_boundary_split_with_leading_context(self, pii_detector):
        """Longer prefix in msg1 should not prevent detection."""
        joined = "here is my social security number 123-45-\n6789 keep it safe"
        tags = _detect_content_tags(joined, pii_detector)
        assert "pii" in tags, f"expected 'pii' for dash-boundary SSN, got {tags}"

    # --- Cross-message split: attacker removes the joining dash from msg1 ---

    def test_cross_message_split_ssn_detected(self, pii_detector):
        """'123-45' | '6789' joined by newline: SSN must be detected.

        The attacker omits the second dash so the two fragments alone are not
        valid SSNs.  The fix scans a collapse-to-'-' view that inserts the dash:
        '123-45\\n6789' → '123-45-6789' → dashed SSN match.
        """
        joined = "ssn: 123-45\n6789 is my number"
        tags = _detect_content_tags(joined, pii_detector)
        assert "pii" in tags, (
            "LAURA-31DR-003 regression: cross-message SSN split (missing dash) "
            f"must produce 'pii' tag, got {tags}"
        )

    def test_cross_message_split_ssn_no_leading_text(self, pii_detector):
        """SSN split with no context words — only the digit fragments."""
        joined = "123-45\n6789"
        tags = _detect_content_tags(joined, pii_detector)
        assert "pii" in tags, (
            f"expected 'pii' for bare SSN cross-message split, got {tags}"
        )

    # --- Existing single-message behaviour must be preserved ---

    def test_single_message_ssn_still_detected(self, pii_detector):
        """Existing single-message SSN detection must be unaffected by the fix."""
        text = "my ssn is 123-45-6789 please help"
        tags = _detect_content_tags(text, pii_detector)
        assert "pii" in tags, f"single-message SSN regression, got {tags}"

    def test_single_message_spaced_ssn_still_detected(self, pii_detector):
        """LAURA-31DR-002: spaced-digit SSN '123 45 6789' must still be detected."""
        text = "ssn 123 45 6789 is mine"
        tags = _detect_content_tags(text, pii_detector)
        assert "pii" in tags, f"spaced SSN regression (LAURA-31DR-002), got {tags}"

    # --- Clean multi-message prompt must NOT trigger a false positive ---

    def test_clean_multi_message_no_false_positive(self, pii_detector):
        """A clean two-message prompt must return [] — no false deny."""
        joined = "please summarise the quarterly report\nfocus on Q3 revenue only"
        tags = _detect_content_tags(joined, pii_detector)
        assert tags == [], (
            f"clean multi-message prompt must produce no tags, got {tags}"
        )

    def test_numbers_in_separate_messages_no_false_positive(self, pii_detector):
        """Unrelated short digit sequences across messages must not falsely tag.

        If msg1='the value is 42' and msg2='result: 7', collapsing '42\\n7'
        to '42-7' does not match the 3-2-4-digit SSN format.  Must return [].
        """
        joined = "the value is 42\nresult: 7 units"
        tags = _detect_content_tags(joined, pii_detector)
        assert tags == [], f"unrelated numbers across messages produced false tag: {tags}"

    def test_classification_split_across_messages_detected(self, pii_detector):
        """A classification marker entirely in one message is still detected
        even when the text has a cross-message newline separator."""
        joined = "please review this document\nSECRET: not for distribution"
        tags = _detect_content_tags(joined, pii_detector)
        assert "classified" in tags, (
            f"classification marker after newline must still be detected, got {tags}"
        )

    def test_no_newline_no_extra_scans_overhead(self, pii_detector):
        """Single-message text (no newline) must still work correctly and not raise."""
        text = "plain chat: what is the capital of France?"
        tags = _detect_content_tags(text, pii_detector)
        assert tags == [], f"clean single-message must return [], got {tags}"


# ---------------------------------------------------------------------------
# OBS-3.1-001 — import os scope shadow
# ---------------------------------------------------------------------------

class TestOsImportScopeShadow:
    """Verify that the module-level `os` is accessible in chat_completions scope.

    The original bug: a bare `import os` at line ~2578 (agent-routing else-branch)
    inside chat_completions() caused Python to treat `os` as a LOCAL variable for
    the entire function.  Any reference to `os` before that line raised:
        UnboundLocalError: cannot access local variable 'os' before assignment

    The unit-testable proxy: verify that `openai_router.os` is the stdlib module
    (i.e., the module-level import is intact and not shadowed), AND that no other
    bare `import os` exists inside chat_completions (checked via source inspection).
    The live proof is the absence of "cannot access local variable 'os'" in
    gateway logs after a chat request (verified in the live verification section).
    """

    def test_module_level_os_is_stdlib(self):
        """openai_router must expose the stdlib `os` module at module level."""
        import yashigani.gateway.openai_router as ow
        import os as stdlib_os
        assert ow.os is stdlib_os, (
            "openai_router.os is not the stdlib os module — scope shadow still present"
        )

    def test_no_bare_import_os_in_function_bodies(self):
        """No bare `import os` (without alias) must appear inside any function body
        in openai_router.py.  Any such import would re-shadow the module-level name
        and reproduce OBS-3.1-001.

        We inspect the source: any line containing `import os` that is indented
        (inside a function) must use an alias (`import os as ...`).
        """
        import inspect
        import yashigani.gateway.openai_router as ow
        source_lines = inspect.getsource(ow).splitlines()
        violations = []
        for lineno, line in enumerate(source_lines, start=1):
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            # Look for indented `import os` WITHOUT an alias
            if (
                indent > 0
                and stripped.startswith("import os")
                and " as " not in stripped
            ):
                violations.append((lineno, line.rstrip()))
        assert not violations, (
            "OBS-3.1-001 regression: bare `import os` found inside a function body "
            "(would shadow module-level os):\n"
            + "\n".join(f"  line {ln}: {src}" for ln, src in violations)
        )
