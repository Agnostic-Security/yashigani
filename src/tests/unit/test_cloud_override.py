"""#25 — unit tests for the dual-admin cloud-LLM override manager.

Covers:
  - Existing happy-path and guard-rail behaviour (justification, TTL, dual-admin).
  - SOD-1 regression (YCS-20260705-v4.1.2-SOD-1): swap attack via state mutation
    after propose() and second propose() while PENDING.
  - SOD-2 regression (YCS-20260705-v4.1.2-SOD-2): audit fail-closed — activation
    and proposal are NOT committed when the audit write fails.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from yashigani.optimization.cloud_override import (
    ApprovalError,
    CloudLlmOverrideManager,
    JustificationRequiredError,
    TTLRangeError,
    _KEY_PENDING,
    _KEY_STATE,
    compute_proposal_fingerprint,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

class _FakeRedis:
    """In-memory Redis stand-in (set/get/delete/ttl). TTL not time-evolved."""

    def __init__(self):
        self.kv = {}
        self.ttls = {}

    def set(self, k, v, ex=None):
        self.kv[k] = v
        if ex is not None:
            self.ttls[k] = ex

    def get(self, k):
        return self.kv.get(k)

    def delete(self, k):
        self.kv.pop(k, None)
        self.ttls.pop(k, None)

    def ttl(self, k):
        return self.ttls.get(k, -1)


class _RaisingAuditWriter:
    """Audit writer that always raises — simulates a durable-write failure."""

    def write(self, event):
        raise OSError("audit backend unreachable")


class _CountingAuditWriter:
    """Records every write call without raising."""

    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)


def _mgr(audit_writer=None):
    return CloudLlmOverrideManager(_FakeRedis(), audit_writer=audit_writer)


def _fp(provider="openai", model="gpt-4o", justification="contract ACME-2026"):
    return compute_proposal_fingerprint(provider, model, justification)


# ---------------------------------------------------------------------------
# Existing guard-rail tests (updated to pass confirming_fingerprint)
# ---------------------------------------------------------------------------

def test_propose_requires_justification():
    m = _mgr()
    with pytest.raises(JustificationRequiredError):
        m.propose("admin1", "openai", "gpt-4o", justification="", ttl_hours=4)
    with pytest.raises(JustificationRequiredError):
        m.propose("admin1", "openai", "gpt-4o", justification="x", ttl_hours=4)  # too short


def test_propose_validates_ttl_and_target():
    m = _mgr()
    with pytest.raises(TTLRangeError):
        m.propose("admin1", "openai", "gpt-4o", justification="TICKET-123", ttl_hours=999)
    with pytest.raises(Exception):
        m.propose("admin1", "", "gpt-4o", justification="TICKET-123", ttl_hours=4)


def test_pending_is_not_active_until_second_admin_approves():
    m = _mgr()
    m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    # PENDING -> not active yet (dual-control)
    assert m.get_active() is None
    assert m.status()["status"] == "PENDING_APPROVAL"


def test_self_approval_rejected():
    m = _mgr()
    m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    fp = _fp()
    with pytest.raises(ApprovalError):
        m.approve("admin1", fp)  # same admin cannot self-approve
    assert m.get_active() is None


def test_dual_admin_approval_activates_with_full_record():
    m = _mgr()
    m.propose("admin1", "openai", "gpt-4o", justification="CEO email 2026-06-07", ttl_hours=6)
    fp = compute_proposal_fingerprint("openai", "gpt-4o", "CEO email 2026-06-07")
    m.approve("admin2", fp)
    active = m.get_active()
    assert active is not None
    assert active["provider"] == "openai" and active["model"] == "gpt-4o"
    assert active["initiated_by"] == "admin1" and active["approver"] == "admin2"
    assert active["justification"] == "CEO email 2026-06-07"


def test_approve_without_pending_fails():
    m = _mgr()
    with pytest.raises(ApprovalError):
        m.approve("admin2", "any-fingerprint")


def test_revoke_clears_active():
    m = _mgr()
    m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    m.approve("admin2", _fp())
    assert m.get_active() is not None
    m.revoke("admin1")
    assert m.get_active() is None
    assert m.status()["status"] == "INACTIVE"


# ---------------------------------------------------------------------------
# SOD-1 regression: swap-attack prevention
# ---------------------------------------------------------------------------

def test_swap_attack_state_mutated_after_propose_rejected():
    """SOD-1: B computes fingerprint of X; state+pending are mutated to Y by attacker;
    B's approve(confirming_fingerprint=fp_X) must be REJECTED.  Override must NOT activate."""
    r = _FakeRedis()
    m = CloudLlmOverrideManager(r, audit_writer=None)

    # A proposes X (openai/gpt-4o)
    m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    fp_x = _fp("openai", "gpt-4o", "contract ACME-2026")

    # Attacker overwrites pending + state to Y (anthropic/claude-opus-4) AFTER B
    # has already read and computed the fingerprint for X.
    fp_y = compute_proposal_fingerprint("anthropic", "claude-opus-4", "contract ACME-2026")
    r.set(_KEY_PENDING, json.dumps({"initiated_by": "admin1", "proposal_fingerprint": fp_y}))
    r.set(_KEY_STATE, json.dumps({
        "status": "PENDING_APPROVAL",
        "provider": "anthropic",
        "model": "claude-opus-4",
        "justification": "contract ACME-2026",
        "initiated_by": "admin1",
        "initiated_at": "2026-07-05T00:00:00+00:00",
        "approver": "",
        "ttl_hours": 4,
        "expires_at": "2026-07-05T04:00:00+00:00",
        "proposal_fingerprint": fp_y,
    }))

    # B approves using fingerprint of the original proposal X — must be rejected
    with pytest.raises(ApprovalError, match="[Ff]ingerprint mismatch"):
        m.approve("admin2", fp_x)

    # Override must NOT be active; state remains PENDING
    assert m.get_active() is None
    state = json.loads(r.get(_KEY_STATE))
    assert state["status"] == "PENDING_APPROVAL"


def test_second_propose_while_pending_rejected():
    """SOD-1: a second propose() while a proposal is PENDING must be rejected —
    prevents the pending record from being silently overwritten."""
    m = _mgr()
    m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    with pytest.raises(ApprovalError, match="[Pp]ending"):
        m.propose("admin3", "anthropic", "claude-opus-4", justification="TICKET-999", ttl_hours=2)
    # Original proposal is still intact
    assert m.status()["status"] == "PENDING_APPROVAL"
    assert m.status()["provider"] == "openai"


def test_fingerprint_returned_in_propose_response():
    """SOD-1: propose() response carries proposal_fingerprint so the approver can
    use it directly without needing to call compute_proposal_fingerprint()."""
    m = _mgr()
    result = m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    assert "proposal_fingerprint" in result
    expected = compute_proposal_fingerprint("openai", "gpt-4o", "contract ACME-2026")
    assert result["proposal_fingerprint"] == expected


def test_wrong_fingerprint_rejected():
    """SOD-1: a wrong (but non-empty) fingerprint is rejected even without a swap attack."""
    m = _mgr()
    m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    with pytest.raises(ApprovalError, match="[Ff]ingerprint mismatch"):
        m.approve("admin2", "0" * 64)  # wrong SHA-256 hex


def test_confirming_fingerprint_recorded_in_active_state():
    """SOD-1: the ACTIVE state must record the confirming_fingerprint that B approved."""
    m = _mgr()
    m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    fp = _fp()
    m.approve("admin2", fp)
    active = m.get_active()
    assert active["confirming_fingerprint"] == fp


# ---------------------------------------------------------------------------
# SOD-2 regression: write-ahead audit (fail-closed)
# ---------------------------------------------------------------------------

def test_audit_fail_closed_activation():
    """SOD-2: if the ACTIVATED audit write fails, approve() raises and the state
    is NOT committed ACTIVE — state must remain PENDING_APPROVAL."""
    r = _FakeRedis()
    # propose() with no audit writer (succeeds; state written to Redis)
    m = CloudLlmOverrideManager(r, audit_writer=None)
    m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    fp = _fp()

    # Attach a failing writer AFTER propose() — simulates audit backend going down
    # between proposal and approval.
    m._audit = _RaisingAuditWriter()
    with pytest.raises(OSError, match="audit backend unreachable"):
        m.approve("admin2", fp)

    # State must still be PENDING_APPROVAL, not ACTIVE
    assert m.get_active() is None
    raw = r.get(_KEY_STATE)
    assert raw is not None
    assert json.loads(raw)["status"] == "PENDING_APPROVAL"


def test_audit_fail_closed_propose():
    """SOD-2: if the PROPOSED audit write fails, propose() raises and the state
    is NOT committed to Redis — no state or pending key exists."""
    r = _FakeRedis()
    m = CloudLlmOverrideManager(r, audit_writer=_RaisingAuditWriter())
    with pytest.raises(OSError, match="audit backend unreachable"):
        m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    # Neither state nor pending keys should have been written
    assert r.get(_KEY_STATE) is None
    assert r.get(_KEY_PENDING) is None


def test_audit_events_recorded_happy_path():
    """SOD-2: both PROPOSED and ACTIVATED events are recorded on the happy path,
    and ACTIVATED carries the confirming_fingerprint."""
    r = _FakeRedis()
    audit = _CountingAuditWriter()
    m = CloudLlmOverrideManager(r, audit_writer=audit)
    m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    fp = _fp()
    m.approve("admin2", fp)

    event_types = [e.override_event for e in audit.events]
    assert "CLOUD_OVERRIDE_PROPOSED" in event_types
    assert "CLOUD_OVERRIDE_ACTIVATED" in event_types

    activated = next(e for e in audit.events if e.override_event == "CLOUD_OVERRIDE_ACTIVATED")
    assert activated.confirming_fingerprint == fp
    assert activated.provider == "openai"
    assert activated.model == "gpt-4o"
    assert activated.approver == "admin2"


def test_audit_revoke_recorded():
    """SOD-2: REVOKED event is recorded; confirming_fingerprint is empty (not applicable)."""
    r = _FakeRedis()
    audit = _CountingAuditWriter()
    m = CloudLlmOverrideManager(r, audit_writer=audit)
    m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
    m.approve("admin2", _fp())
    audit.events.clear()  # reset — focus on revoke event only

    m.revoke("admin1")
    assert len(audit.events) == 1
    assert audit.events[0].override_event == "CLOUD_OVERRIDE_REVOKED"


# ---------------------------------------------------------------------------
# BUG-C regression (4.1.2 live): cloud_override_approve ROUTE level
#
# Pre-fix: route called _mgr().approve(session.account_id)  — one arg.
#          CloudOverrideManager.approve() requires TWO args (approver_id,
#          confirming_fingerprint) since the SOD-1 fix (fc7edfb2).
#          TypeError → uncaught → FastAPI 500.
# Post-fix: route accepts ApproveRequest body with confirming_fingerprint;
#          calls _mgr().approve(account_id, body.confirming_fingerprint).
#
# These tests verify the ROUTE handler, not just the manager (the manager
# tests above already exist — the gap was the route layer).
# ---------------------------------------------------------------------------

class TestCloudOverrideApproveRoute:
    """Route-level tests for POST /cloud-override/approve (Bug C regression)."""

    def _make_session(self, account_id="admin2"):
        """Minimal StepUpAdminSession-like object (duck-typed)."""
        session = MagicMock()
        session.account_id = account_id
        return session

    @pytest.mark.asyncio
    async def test_correct_fingerprint_returns_active(self):
        """Correct confirming_fingerprint → route calls approve(account_id, fp) → 200-equivalent."""
        from yashigani.backoffice.routes.cloud_override import (
            cloud_override_approve,
            ApproveRequest,
        )

        fp = _fp("openai", "gpt-4o", "contract ACME-2026")
        body = ApproveRequest(confirming_fingerprint=fp)
        session = self._make_session("admin2")

        mock_mgr = MagicMock()
        mock_mgr.approve.return_value = {
            "status": "ACTIVE", "provider": "openai", "model": "gpt-4o",
        }

        with patch(
            "yashigani.backoffice.routes.cloud_override.backoffice_state"
        ) as mock_bs:
            mock_bs.cloud_override_manager = mock_mgr
            result = await cloud_override_approve(body=body, session=session)

        # Route must pass BOTH args to approve()
        mock_mgr.approve.assert_called_once_with("admin2", fp)
        assert result["status"] == "active"
        assert result["state"]["provider"] == "openai"

    @pytest.mark.asyncio
    async def test_fingerprint_mismatch_returns_409(self):
        """Mismatched confirming_fingerprint → ApprovalError → route raises 409 HTTPException."""
        import pytest
        from fastapi import HTTPException
        from yashigani.optimization.cloud_override import ApprovalError
        from yashigani.backoffice.routes.cloud_override import (
            cloud_override_approve,
            ApproveRequest,
        )

        body = ApproveRequest(confirming_fingerprint="0" * 64)   # wrong hash
        session = self._make_session("admin2")

        mock_mgr = MagicMock()
        mock_mgr.approve.side_effect = ApprovalError(
            "Fingerprint mismatch: possible swap attack."
        )

        with patch(
            "yashigani.backoffice.routes.cloud_override.backoffice_state"
        ) as mock_bs:
            mock_bs.cloud_override_manager = mock_mgr
            with pytest.raises(HTTPException) as exc_info:
                await cloud_override_approve(body=body, session=session)

        assert exc_info.value.status_code == 409, (
            f"Fingerprint mismatch must return 409, got {exc_info.value.status_code}"
        )
        detail = exc_info.value.detail or {}
        assert detail.get("error") == "approval_failed", (
            f"Expected error='approval_failed', got {detail!r}"
        )

    def test_missing_confirming_fingerprint_raises_validation_error(self):
        """Missing body field → Pydantic ValidationError (FastAPI renders as 422).
        Pre-fix there was no body at all → route accepted one-arg call → TypeError → 500."""
        from pydantic import ValidationError
        from yashigani.backoffice.routes.cloud_override import ApproveRequest

        with pytest.raises(ValidationError):
            ApproveRequest()   # confirming_fingerprint is required, no default

    def test_approve_model_rejects_empty_fingerprint(self):
        """confirming_fingerprint must be non-empty (min_length=1 on the field)."""
        from pydantic import ValidationError
        from yashigani.backoffice.routes.cloud_override import ApproveRequest

        with pytest.raises(ValidationError):
            ApproveRequest(confirming_fingerprint="")

    def test_old_one_arg_call_raises_type_error(self):
        """Regression proof: the pre-fix call approve(account_id) [one arg] raises TypeError.
        This is exactly what caused the 500 in production — the route did not pass the
        required confirming_fingerprint arg introduced by the SOD-1 fix (fc7edfb2)."""
        # Use a real manager instance (FakeRedis) to show the TypeError is a real API contract.
        m = CloudLlmOverrideManager(_FakeRedis(), audit_writer=None)
        m.propose("admin1", "openai", "gpt-4o", justification="contract ACME-2026", ttl_hours=4)
        with pytest.raises(TypeError):
            m.approve("admin2")   # missing confirming_fingerprint — exactly the pre-fix bug
