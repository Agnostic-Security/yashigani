"""
Unit tests — OPA assistant apply endpoint step-up requirement (RISK-103).

Verifies that:
  1. POST /admin/opa-assistant/apply uses StepUpAdminSession (not AdminSession).
  2. The /suggest, /reject, /schema routes still use plain AdminSession.
  3. The apply and suggest dependencies are different.

Note: because opa_assistant.py uses ``from __future__ import annotations``,
all parameter annotations are strings at runtime. We verify the string name
of the session annotation directly.

Last updated: 2026-06-28T00:00:00+00:00
"""
from __future__ import annotations

import inspect

import pytest


def _session_annotation_str(fn) -> str:
    """Return the string annotation of the 'session' parameter of fn."""
    sig = inspect.signature(fn)
    param = sig.parameters.get("session")
    assert param is not None, f"{fn.__name__} has no 'session' parameter"
    ann = param.annotation
    # With PEP 563 (from __future__ import annotations) annotations are strings.
    return ann if isinstance(ann, str) else ann.__name__


class TestOpaAssistantApplyStepUp:
    """apply_suggestion must require StepUpAdminSession (RISK-103 / EU AI Act Art.14)."""

    def test_apply_uses_stepup_admin_session(self):
        from yashigani.backoffice.routes.opa_assistant import apply_suggestion

        ann = _session_annotation_str(apply_suggestion)
        assert ann == "StepUpAdminSession", (
            f"apply_suggestion session must be StepUpAdminSession, got: {ann!r}"
        )

    def test_suggest_uses_plain_admin_session(self):
        """suggest uses plain AdminSession (step-up not required for LLM call)."""
        from yashigani.backoffice.routes.opa_assistant import suggest

        ann = _session_annotation_str(suggest)
        assert ann == "AdminSession", (
            f"suggest session must be AdminSession, got: {ann!r}"
        )

    def test_reject_uses_plain_admin_session(self):
        """reject uses plain AdminSession (audit-log-only, no state mutation)."""
        from yashigani.backoffice.routes.opa_assistant import reject_suggestion

        ann = _session_annotation_str(reject_suggestion)
        assert ann == "AdminSession"

    def test_schema_uses_plain_admin_session(self):
        """get_schema uses plain AdminSession (read-only)."""
        from yashigani.backoffice.routes.opa_assistant import get_schema

        ann = _session_annotation_str(get_schema)
        assert ann == "AdminSession"

    def test_apply_and_suggest_have_different_session_annotations(self):
        """apply_suggestion and suggest must have different session annotations."""
        from yashigani.backoffice.routes.opa_assistant import apply_suggestion, suggest

        apply_ann = _session_annotation_str(apply_suggestion)
        suggest_ann = _session_annotation_str(suggest)
        assert apply_ann != suggest_ann, (
            "apply_suggestion and suggest must require different session types"
        )
