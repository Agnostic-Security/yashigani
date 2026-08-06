"""
Regression test -- FIND-WEBAUTHN-REVOKE-AUDIT-OUTCOME (ASVS V7.1.2).

`test_v233_webauthn_e2e.py::test_wa_revoke_03_audit_event_credential_revoked`
(live-stack Playwright E2E) failed:

    assert event.get("outcome") == "success"

Root cause: `webauthn_v1.py::_write_audit()` built a
`WebAuthnCredentialRevokedEvent` WITHOUT passing through the `outcome`
kwarg it received -- and `WebAuthnCredentialRevokedEvent` (audit/schema.py)
had NO `outcome` field at all (unlike its sibling
`WebAuthnCredentialRegisteredEvent`, which carries `outcome: str =
"success"`). `dataclasses.asdict()` (AuditEvent.to_dict()) therefore never
serialised an `outcome` key for this event type -- `event.get("outcome")`
was always `None`.

Fix (this commit):
  - `WebAuthnCredentialRevokedEvent` gained `outcome: str = "success"`,
    matching the pattern already used by
    `WebAuthnCredentialRegisteredEvent` / `WebAuthnLoginSuccessEvent`-style
    events for consistency.
  - `_write_audit()`'s `WEBAUTHN_CREDENTIAL_REVOKED` branch now passes
    `outcome=outcome` through to the dataclass constructor.
  - `revoke_credential()`'s 404 (`credential_not_found`) branch now also
    emits a `WEBAUTHN_CREDENTIAL_REVOKED` audit event with
    `outcome="failure"`, matching the failure-path audit pattern already
    used by `register_finish()` for its ValueError/invalid-origin branches
    -- previously a failed revoke attempt left NO audit trail at all.

This test reproduces the bug at the unit level (no live stack / Playwright
required) by monkeypatching `backoffice_state.audit_writer` with an
in-memory capture double and driving `_write_audit()` directly, plus
asserting the dataclass shape.

Last updated: 2026-08-06T00:00:00+00:00
"""
from __future__ import annotations

import dataclasses

import pytest

from yashigani.audit.schema import WebAuthnCredentialRevokedEvent
from yashigani.backoffice.routes import webauthn_v1


class _CaptureAuditWriter:
    """Minimal double for AuditLogWriter -- captures every event.to_dict()
    passed to .write() without touching disk/SIEM."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def write(self, event) -> None:
        self.events.append(event.to_dict())


class TestWebAuthnCredentialRevokedEventHasOutcomeField:
    """Dataclass-shape regression: WebAuthnCredentialRevokedEvent must carry
    an `outcome` field, matching its sibling credential-lifecycle events."""

    def test_outcome_field_exists_defaults_success(self):
        event = WebAuthnCredentialRevokedEvent(
            admin_account="admin-1",
            credential_uuid="cred-1",
        )
        assert hasattr(event, "outcome"), (
            "WebAuthnCredentialRevokedEvent has no `outcome` field -- "
            "ASVS V7.1.2 regression FIND-WEBAUTHN-REVOKE-AUDIT-OUTCOME."
        )
        assert event.outcome == "success"

    def test_outcome_field_is_settable_and_serialises(self):
        event = WebAuthnCredentialRevokedEvent(
            admin_account="admin-1",
            credential_uuid="cred-1",
            outcome="failure",
        )
        as_dict = dataclasses.asdict(event)
        assert as_dict["outcome"] == "failure"


class TestWriteAuditWiresOutcomeThroughForRevocation:
    """_write_audit() must propagate the caller-supplied `outcome` into the
    WebAuthnCredentialRevokedEvent it constructs -- this is the exact path
    test_wa_revoke_03 (live Playwright E2E) exercises against a running
    stack; here we drive it directly against an in-memory audit writer
    double so the fix is provable without a live stack."""

    def test_success_outcome_propagates(self, monkeypatch):
        capture = _CaptureAuditWriter()
        monkeypatch.setattr(webauthn_v1.backoffice_state, "audit_writer", capture)

        webauthn_v1._write_audit(
            "admin-1",
            "WEBAUTHN_CREDENTIAL_REVOKED",
            outcome="success",
            detail="credential_id=cred-123",
        )

        assert len(capture.events) == 1
        event = capture.events[0]
        assert event["event_type"] == "WEBAUTHN_CREDENTIAL_REVOKED"
        assert event.get("outcome") == "success", (
            f"WA-REVOKE-03 regression: expected outcome=success, got {event}"
        )
        assert event["credential_uuid"] == "cred-123"

    def test_failure_outcome_propagates(self, monkeypatch):
        capture = _CaptureAuditWriter()
        monkeypatch.setattr(webauthn_v1.backoffice_state, "audit_writer", capture)

        webauthn_v1._write_audit(
            "admin-1",
            "WEBAUTHN_CREDENTIAL_REVOKED",
            outcome="failure",
            detail="credential_id=cred-999",
        )

        assert len(capture.events) == 1
        event = capture.events[0]
        assert event.get("outcome") == "failure"
        assert event["credential_uuid"] == "cred-999"


class TestRevokeCredentialAuditsNotFoundAsFailure:
    """The 404 credential_not_found branch previously wrote NO audit event
    at all. Now it must audit WEBAUTHN_CREDENTIAL_REVOKED with
    outcome="failure", matching the pattern already used by
    register_finish()'s failure branches."""

    @pytest.mark.asyncio
    async def test_not_found_writes_failure_audit(self, monkeypatch):
        capture = _CaptureAuditWriter()
        monkeypatch.setattr(webauthn_v1.backoffice_state, "audit_writer", capture)

        class _FakeSvc:
            async def delete_credential(self, user_id, credential_uuid):
                return False  # not found / not owned by this user

        monkeypatch.setattr(webauthn_v1, "_get_pg_service", lambda: _FakeSvc())

        class _FakeSession:
            account_id = "admin-1"

        from fastapi import HTTPException

        with pytest.raises(HTTPException) as excinfo:
            await webauthn_v1.revoke_credential(
                credential_id="nonexistent-cred",
                session=_FakeSession(),
            )
        assert excinfo.value.status_code == 404

        assert len(capture.events) == 1, (
            "revoke_credential's 404 branch must write a "
            "WEBAUTHN_CREDENTIAL_REVOKED outcome=failure audit event."
        )
        event = capture.events[0]
        assert event["event_type"] == "WEBAUTHN_CREDENTIAL_REVOKED"
        assert event.get("outcome") == "failure"
        assert event["credential_uuid"] == "nonexistent-cred"
