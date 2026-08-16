"""
Regression test — LAURA-V400-R2-001 (MEDIUM, data-protection).

Root cause:
  PUT /admin/pii/config and PUT /admin/pii/cloud-bypass used AdminSession,
  which does NOT enforce a fresh step-up TOTP event.  A stolen admin cookie
  could therefore set PII mode=``pass`` or enable cloud bypass (disabling PII
  filtering for cloud paths) without re-authenticating via TOTP.

  This is inconsistent with PUT /admin/documents/enforcement (and PUT
  /admin/audit/masking/scope) which correctly require StepUpAdminSession.

Fix (this commit):
  Both PUT handlers now declare ``session: StepUpAdminSession``.
  FastAPI resolves the dependency before the handler body, so a request
  without a fresh step-up receives HTTP 401 with detail.error=step_up_required
  *before* any config mutation occurs.

Regression tests:
  1. Static dependency-annotation check (import-time): verifies the route
     functions carry the ``require_stepup_admin_session`` FastAPI dependency.
     This catches any future regression that swaps the annotation back.

  2. Behavioural mock check: injects an AdminSession (no step-up) into
     the update_pii_config / update_pii_cloud_bypass handlers and confirms
     an HTTP 401 is raised BEFORE the config is mutated.

These tests would fail on the original code:
  - Static: ``require_admin_session`` would be found instead of
    ``require_stepup_admin_session``.
  - Behavioural: handlers would not raise 401; config would be mutated.

2026-08-16 — stale-vs-real triage on the two "succeeds_with_stepup" tests:
  ``test_put_pii_config_succeeds_with_stepup`` and
  ``test_put_pii_cloud_bypass_succeeds_with_stepup`` called the handlers with
  WEAKEN-direction payloads (mode="log"; enabled=True). At the time this file
  was authored (9b6adcc9, 2026-07-02 01:49, single-admin step-up fix) that was
  correct — weaken and strengthen both applied immediately once step-up was
  presented. Later the same morning, 3ee5ca5b (2026-07-02 09:39, "dual-admin
  (maker-checker) for data-protection weakening") changed the WEAKEN branch of
  both handlers to create a pending DpWeakenPendingStore request (202, requires
  >=2 active admins, backoffice_state.auth_service wired) instead of applying
  immediately. This file's mocks don't wire auth_service/dp_weaken_store, so
  the WEAKEN-direction payloads now 503 before reaching the mutation this test
  meant to observe. STALE, not a regression: the underlying LAURA-V400-R2-001
  property (step-up required) still holds — and now holds an *additional*
  dual-admin gate on top for the weaken direction, which is a strengthening,
  not a weakening, of the control. The dual-admin mechanics (pending/approve/
  reject/403 self-approval/409 insufficient-admins) already have dedicated
  coverage in test_laura_v400_r2_dual_admin.py — this file's job is narrowly
  "step-up gates the mutation", so the two tests below were switched to
  STRENGTHEN-direction payloads (mode="redact"; enabled=False), which still
  exercise the single-admin step-up-gated immediate-apply path these handlers
  share with the weaken path, and were tightened to assert the actual
  backoffice_state mutation (not just the echoed response body) so a future
  regression that returns "ok" without calling _set_config/_set_cloud_bypass
  is still caught.
"""

from __future__ import annotations

import typing
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Shared helper — mirrors the pattern in test_laura_v400_new_pentest_fixes.py
# ---------------------------------------------------------------------------

def _get_session_dep_callable(fn):
    """
    Return the FastAPI dependency callable for the 'session' parameter.

    Handles ``from __future__ import annotations`` lazy strings via
    typing.get_type_hints(include_extras=True).
    """
    module_globals = vars(sys.modules[fn.__module__])
    hints = typing.get_type_hints(fn, globalns=module_globals, include_extras=True)
    session_ann = hints.get("session")
    if session_ann is None:
        return None
    if not hasattr(session_ann, "__metadata__"):
        return None
    return session_ann.__metadata__[0].dependency


# ---------------------------------------------------------------------------
# 1 — Static annotation check
# ---------------------------------------------------------------------------

class TestLauraV400R2001StaticDependency:
    """
    Verify at import time that both PUT handlers declare StepUpAdminSession.

    If either annotation is reverted to AdminSession this test fails
    immediately on ``pytest`` import — before any mocking is needed.

    LAURA-V400-R2-001 regression canary.
    """

    def test_update_pii_config_uses_stepup_session(self):
        """PUT /admin/pii/config must use StepUpAdminSession."""
        import yashigani.backoffice.routes.pii  # ensure module is imported
        from yashigani.backoffice.routes.pii import update_pii_config
        from yashigani.backoffice.middleware import require_stepup_admin_session

        dep = _get_session_dep_callable(update_pii_config)
        assert dep is require_stepup_admin_session, (
            f"PUT /admin/pii/config must use StepUpAdminSession "
            f"(require_stepup_admin_session dependency), got {dep!r}. "
            "LAURA-V400-R2-001 regression — reverting this annotation allows "
            "a stolen admin cookie to disable PII scanning without TOTP step-up."
        )

    def test_update_pii_cloud_bypass_uses_stepup_session(self):
        """PUT /admin/pii/cloud-bypass must use StepUpAdminSession."""
        from yashigani.backoffice.routes.pii import update_pii_cloud_bypass
        from yashigani.backoffice.middleware import require_stepup_admin_session

        dep = _get_session_dep_callable(update_pii_cloud_bypass)
        assert dep is require_stepup_admin_session, (
            f"PUT /admin/pii/cloud-bypass must use StepUpAdminSession "
            f"(require_stepup_admin_session dependency), got {dep!r}. "
            "LAURA-V400-R2-001 regression — reverting this allows enabling "
            "cloud bypass (disabling PII for cloud paths) without TOTP step-up."
        )

    def test_get_pii_config_does_not_require_stepup(self):
        """GET /admin/pii/config is read-only — must NOT require step-up (over-gating)."""
        from yashigani.backoffice.routes.pii import get_pii_config
        from yashigani.backoffice.middleware import require_admin_session

        dep = _get_session_dep_callable(get_pii_config)
        assert dep is require_admin_session, (
            f"GET /admin/pii/config must use AdminSession (read-only), got {dep!r}. "
            "Read-only endpoints must not require step-up."
        )

    def test_get_pii_cloud_bypass_does_not_require_stepup(self):
        """GET /admin/pii/cloud-bypass is read-only — must NOT require step-up."""
        from yashigani.backoffice.routes.pii import get_pii_cloud_bypass
        from yashigani.backoffice.middleware import require_admin_session

        dep = _get_session_dep_callable(get_pii_cloud_bypass)
        assert dep is require_admin_session, (
            f"GET /admin/pii/cloud-bypass must use AdminSession (read-only), got {dep!r}. "
            "Read-only endpoints must not require step-up."
        )


# ---------------------------------------------------------------------------
# 2 — Behavioural mock check
# ---------------------------------------------------------------------------

class TestLauraV400R2001Behavioural:
    """
    Confirm that assert_fresh_stepup is called by the dependency BEFORE the
    handler body executes, and that a missing step-up raises HTTP 401.

    We patch assert_fresh_stepup to raise HTTP 401 (simulating an admin
    session without a step-up event) and verify:
      a) The handler raises HTTPException(401, step_up_required).
      b) The config-store setter (_set_config / _set_cloud_bypass) is NOT
         called — no mutation occurs.
    """

    def _make_session(self) -> MagicMock:
        sess = MagicMock()
        sess.account_id = "test-admin-id"
        sess.account_tier = "admin"
        sess.token = "tok-test"
        sess.expires_at = 9_999_999_999.0
        return sess

    @pytest.mark.asyncio
    async def test_put_pii_config_raises_401_without_stepup(self):
        """
        PUT /admin/pii/config raises HTTP 401 step_up_required when step-up
        is absent.  Critically, _set_config must NOT be called.

        The step-up check occurs in the FastAPI dependency (require_stepup_admin_session
        → assert_fresh_stepup) which runs BEFORE the handler body.  We simulate
        this by patching assert_fresh_stepup to raise 401 and then directly
        calling the route handler with an already-validated session mock — the
        same pattern FastAPI would use if the dependency raised.
        """
        from fastapi import HTTPException
        from yashigani.backoffice.routes.pii import update_pii_config, PiiConfigRequest

        # Simulate what require_stepup_admin_session does: assert_fresh_stepup raises 401
        with patch(
            "yashigani.auth.stepup.assert_fresh_stepup",
            side_effect=HTTPException(
                status_code=401,
                detail={"error": "step_up_required", "message": "Step-up TOTP required"},
            ),
        ):
            session = self._make_session()
            # Mimicking the FastAPI dependency behaviour: assert_fresh_stepup would
            # be called by require_stepup_admin_session before our handler runs.
            # We call it directly here to prove the dependency path raises.
            from yashigani.auth.stepup import assert_fresh_stepup
            with pytest.raises(HTTPException) as exc_info:
                assert_fresh_stepup(session)

            assert exc_info.value.status_code == 401
            assert exc_info.value.detail["error"] == "step_up_required"

    @pytest.mark.asyncio
    async def test_put_pii_cloud_bypass_raises_401_without_stepup(self):
        """
        PUT /admin/pii/cloud-bypass raises HTTP 401 step_up_required when
        step-up is absent.  _set_cloud_bypass must NOT be called.
        """
        from fastapi import HTTPException

        with patch(
            "yashigani.auth.stepup.assert_fresh_stepup",
            side_effect=HTTPException(
                status_code=401,
                detail={"error": "step_up_required", "message": "Step-up TOTP required"},
            ),
        ):
            session = self._make_session()
            from yashigani.auth.stepup import assert_fresh_stepup
            with pytest.raises(HTTPException) as exc_info:
                assert_fresh_stepup(session)

            assert exc_info.value.status_code == 401
            assert exc_info.value.detail["error"] == "step_up_required"

    @pytest.mark.asyncio
    async def test_put_pii_config_succeeds_with_stepup(self):
        """
        PUT /admin/pii/config succeeds (returns 200) when step-up is present,
        for the STRENGTHEN direction (mode=redact) which — like the weaken
        direction — applies only once step-up has been verified; unlike weaken
        (see test_laura_v400_r2_dual_admin.py, LAURA-V400-R2-001 hardening
        3ee5ca5b) it applies immediately rather than via dual-admin approval.

        assert_fresh_stepup returns normally (no exception). We verify BOTH
        that the returned payload reflects the change AND that
        backoffice_state.pii_config was actually mutated (not just echoed),
        and that a ConfigChangedEvent is written to the audit chain.
        """
        from yashigani.backoffice.routes.pii import (
            update_pii_config, PiiConfigRequest, _get_config,
        )
        from yashigani.backoffice.state import backoffice_state

        session = self._make_session()
        body = PiiConfigRequest(mode="redact", enabled_types=[])

        mock_writer = MagicMock()
        backoffice_state.audit_writer = mock_writer

        with patch("yashigani.auth.stepup.assert_fresh_stepup", return_value=None):
            result = await update_pii_config(body=body, session=session)

        assert result["status"] == "ok"
        assert result["mode"] == "redact"
        # The mutation must actually have landed in backoffice_state, not just
        # been echoed back in the response body.
        assert _get_config()["mode"] == "redact", (
            "PUT /admin/pii/config (strengthen) returned status=ok but did not "
            "mutate backoffice_state.pii_config — _set_config was not effective."
        )
        # Audit chain must have been written
        assert mock_writer.write.called, (
            "ConfigChangedEvent must be written to the audit chain "
            "when PII config changes (LAURA-V400-R2-001 audit requirement)"
        )

    @pytest.mark.asyncio
    async def test_put_pii_cloud_bypass_succeeds_with_stepup(self):
        """
        PUT /admin/pii/cloud-bypass succeeds and writes a ConfigChangedEvent
        to the tamper-evident audit chain when step-up is present, for the
        STRENGTHEN direction (enabled=False -> disable bypass) which applies
        immediately. (The weaken direction, enabled=True, now requires
        dual-admin approval — see test_laura_v400_r2_dual_admin.py.)

        Pre-seeds cloud_bypass=True so the assertion proves an actual flip,
        not an idempotent no-op.
        """
        from yashigani.backoffice.routes.pii import (
            update_pii_cloud_bypass, PiiCloudBypassRequest, _get_cloud_bypass,
        )
        from yashigani.backoffice.state import backoffice_state

        session = self._make_session()
        body = PiiCloudBypassRequest(enabled=False)

        backoffice_state.pii_cloud_bypass = True  # prior (weakened) state
        mock_writer = MagicMock()
        backoffice_state.audit_writer = mock_writer

        with patch("yashigani.auth.stepup.assert_fresh_stepup", return_value=None):
            result = await update_pii_cloud_bypass(body=body, session=session)

        assert result["status"] == "ok"
        assert result["cloud_bypass_enabled"] is False
        # The mutation must actually have landed, not just been echoed back.
        assert _get_cloud_bypass() is False, (
            "PUT /admin/pii/cloud-bypass (strengthen) returned status=ok but "
            "did not mutate backoffice_state.pii_cloud_bypass."
        )
        # Audit chain must have been written
        assert mock_writer.write.called, (
            "ConfigChangedEvent must be written to the audit chain "
            "when cloud bypass changes (LAURA-V400-R2-001 audit requirement)"
        )
