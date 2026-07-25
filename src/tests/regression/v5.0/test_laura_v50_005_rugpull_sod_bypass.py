"""
Regression test — LAURA-V50-005 (High): rug-pull manifest re-approval
dual-control was bypassable by a single admin (identity-namespace type
confusion).

Root cause: `ManifestReapprovalGate.approve()` rejects self-approval by
comparing `rec["registered_by"] == approver_id`. But the two call sites fed
it mismatched identity NAMESPACES:

  - registration (POST /admin/manifest-registrations/ceremony ->
    ManifestRegistryService.register() -> gate.note_registration()) used
    the client-supplied free-text `CeremonyRequest.operator_identity`
    (a JWT-sub string, or the literal "unknown") as `registered_by`.
  - approval (POST /admin/model-security/manifest/approve ->
    gate.approve()) used the caller's `StepUpAdminSession.account_id`
    (a session UUID) as `approver_id`.

A free-text label and a session UUID can never coincide, so the SoD check
was vacuously satisfied regardless of who approved — a single stepped-up
admin could register a manifest delta (rug-pull) and immediately approve
their own change.

Fix: `ManifestRegistryService.register()` gained a `registrant_account_id`
parameter; `POST /admin/manifest-registrations/ceremony` now passes
`session.account_id` (the SAME identity namespace the approve route already
used) as the gate's `registered_by`, instead of the free-text
`operator_identity`. `operator_identity` remains a free-text audit/
provenance annotation stored verbatim in `registered_by_operator_identity`
(DB column) — it is simply no longer the SoD comparison key. Defense-in-
depth: both `note_registration()` and `approve()` now fail closed
(`ManifestReapprovalError`) if handed a non-string/empty identity, and
`register()` fails closed (`ValueError`) if a reapproval_gate is wired but
no `registrant_account_id` was supplied — so a type-mismatch can never
silently pass the SoD check again.

This test drives the REAL call-site plumbing end to end: the actual
`record_ceremony` route handler (registration) and the actual
`manifest_approve` route handler (approval), against a real
`ManifestReapprovalGate` backed by a fake Redis — not the gate in
isolation. This is deliberate: the original bug lived in the callers, not
in the gate's own self-approval comparison (which was always correct given
matching inputs).
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class _FakeRedis:
    def __init__(self):
        self.kv = {}

    def get(self, k):
        return self.kv.get(k)

    def set(self, k, v, ex=None, nx=False):
        if nx and k in self.kv:
            return False
        self.kv[k] = v
        return True

    def delete(self, k):
        self.kv.pop(k, None)


class _Sess:
    """Mirrors the real yashigani.auth.session.Session shape closely enough
    for the routes under test (they only read .account_id)."""
    def __init__(self, account_id: str):
        self.account_id = account_id


def _make_two_register_pool(record_ids=(1, 2)):
    """A mock asyncpg pool that services exactly two sequential
    ManifestRegistryService.register() calls for the SAME agent_id: the
    first has no previous manifest (TOFU baseline), the second observes the
    first's sha as previous_manifest_sha256 (a genuine delta)."""
    conn = AsyncMock()
    pool = MagicMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=cm)

    baseline_yaml = "name: cloud9-demo\ntools:\n  - search_docs"
    baseline_sha = hashlib.sha256(baseline_yaml.encode("utf-8")).hexdigest()

    conn.fetchrow.side_effect = [
        None,                                        # call 1: no prev manifest
        {"id": record_ids[0]},                        # call 1: INSERT RETURNING id
        {"manifest_sha256": baseline_sha},             # call 2: prev = baseline sha
        {"id": record_ids[1]},                         # call 2: INSERT RETURNING id
    ]
    return pool, conn, baseline_yaml


def _ceremony_body(agent_id: str, manifest_yaml: str, operator_identity: str):
    from yashigani.backoffice.routes.manifest_history import CeremonyRequest
    sha = hashlib.sha256(manifest_yaml.encode("utf-8")).hexdigest()
    return CeremonyRequest(
        tenant_id="00000000-0000-0000-0000-000000000000",
        agent_id=agent_id,
        manifest_yaml=manifest_yaml,
        operator_identity=operator_identity,
        manifest_sha256=sha,
        confirmed_at=datetime.now(tz=timezone.utc).isoformat(),
        ack_text_shown="You are about to register a manifest delta.",
        ack_response="Y",
        signature_provenance={"alg": "spiffe-internal-hmac", "signer": "spiffe://test", "sig": "deadbeef"},
    )


@pytest.mark.asyncio
class TestRugPullSodFullCallPath:
    """Exercises the real registration + approval route handlers together,
    reproducing LAURA-V50-005's PoC shape: baseline registration, then a
    rug-pull delta (a NEW tool), then an approval attempt."""

    async def _register_baseline_and_delta(self, gate, registrant_session):
        """Registers a TOFU baseline then a delta for agent 'cloud9-demo',
        both via the real record_ceremony route handler, with
        operator_identity intentionally set to a free-text label that will
        NEVER equal any session.account_id — proving the SoD key is now
        session.account_id, not operator_identity."""
        from yashigani.backoffice.routes.manifest_history import record_ceremony
        from yashigani.backoffice.state import backoffice_state

        pool, conn, baseline_yaml = _make_two_register_pool()
        delta_yaml = baseline_yaml + "\n  - exec_shell   # rug-pull payload"

        backoffice_state.manifest_reapproval_gate = gate

        with patch(
            "yashigani.backoffice.routes.manifest_history._get_pool",
            return_value=pool,
        ):
            # 1. Baseline (TOFU-active) — operator_identity is free text,
            #    deliberately never matching any account_id.
            baseline_body = _ceremony_body(
                "cloud9-demo", baseline_yaml, operator_identity="unknown")
            await record_ceremony(body=baseline_body, session=registrant_session)

            # 2. Delta registration (the rug-pull payload) by the SAME
            #    registrant_session — operator_identity again free text.
            delta_body = _ceremony_body(
                "cloud9-demo", delta_yaml, operator_identity="laura-ceremony-op")
            await record_ceremony(body=delta_body, session=registrant_session)

        assert gate.is_blocked("cloud9-demo") is True
        assert gate.is_active("cloud9-demo", baseline_body.manifest_sha256) is True
        assert gate.is_active("cloud9-demo", delta_body.manifest_sha256) is False
        return delta_body.manifest_sha256

    async def test_self_approval_by_registering_admin_is_rejected(self):
        """LAURA-V50-005 PoC: a single admin registers the delta AND
        attempts to approve it. Before the fix, this succeeded (200)
        because registered_by="laura-ceremony-op" (free text) never equalled
        approver_id=<session UUID>. After the fix, both are the SAME
        session.account_id, so the approval MUST be rejected."""
        from yashigani.mcp.manifest_reapproval import ManifestReapprovalGate
        from yashigani.backoffice.routes.model_security import manifest_approve, ManifestApproveRequest
        from yashigani.mcp.manifest_reapproval import ManifestReapprovalError
        from fastapi import HTTPException

        gate = ManifestReapprovalGate(_FakeRedis())
        fern = _Sess("91e40904-de8e-4c7e-8cb6-ab867bddab91")  # the ONLY admin in this PoC

        delta_sha = await self._register_baseline_and_delta(gate, registrant_session=fern)

        with pytest.raises(HTTPException) as exc_info:
            await manifest_approve(
                body=ManifestApproveRequest(agent_id="cloud9-demo", confirming_sha=delta_sha),
                session=fern,   # SAME admin that registered it
            )
        assert exc_info.value.status_code == 400
        assert "DIFFERENT admin" in str(exc_info.value.detail)

        # The rug-pulled delta must still NOT be active — the bypass is closed.
        assert gate.is_blocked("cloud9-demo") is True
        assert gate.is_active("cloud9-demo", delta_sha) is False

    async def test_different_admin_approval_is_allowed(self):
        """A genuinely different admin's approval must still succeed —
        the fix must not turn this into a fail-closed-everything regression."""
        from yashigani.mcp.manifest_reapproval import ManifestReapprovalGate
        from yashigani.backoffice.routes.model_security import manifest_approve, ManifestApproveRequest

        gate = ManifestReapprovalGate(_FakeRedis())
        fern = _Sess("91e40904-de8e-4c7e-8cb6-ab867bddab91")   # registers
        maren = _Sess("a1b2c3d4-1111-2222-3333-444455556666")  # approves (different admin)

        delta_sha = await self._register_baseline_and_delta(gate, registrant_session=fern)

        result = await manifest_approve(
            body=ManifestApproveRequest(agent_id="cloud9-demo", confirming_sha=delta_sha),
            session=maren,
        )
        assert result["status"] == "approved"
        assert result["active_sha"] == delta_sha
        assert gate.is_blocked("cloud9-demo") is False
        assert gate.is_active("cloud9-demo", delta_sha) is True


@pytest.mark.asyncio
class TestRegistrationFailsClosedWithoutCanonicalIdentity:
    """LAURA-V50-005 recommendation #3 — defense-in-depth: if the
    registration call site doesn't supply a server-verified
    registrant_account_id while a reapproval_gate is wired, the service
    must fail closed rather than silently fall back to the free-text
    operator_identity for the SoD comparison key."""

    async def test_register_without_registrant_account_id_raises(self):
        from yashigani.manifest_registry import ManifestRegistryService
        from yashigani.mcp.manifest_reapproval import ManifestReapprovalGate

        pool, conn, baseline_yaml = _make_two_register_pool()
        gate = ManifestReapprovalGate(_FakeRedis())
        svc = ManifestRegistryService(pool=pool, reapproval_gate=gate)

        with pytest.raises(ValueError, match="registrant_account_id is required"):
            await svc.register(
                tenant_id="t", agent_id="cloud9-demo", manifest_yaml=baseline_yaml,
                operator_identity="unknown",
                # registrant_account_id intentionally omitted
            )

    async def test_register_without_gate_does_not_require_registrant_account_id(self):
        """No reapproval_gate wired (e.g. a deployment with the feature off)
        -> registrant_account_id stays optional; no behaviour change for
        that configuration."""
        from yashigani.manifest_registry import ManifestRegistryService

        pool, conn, baseline_yaml = _make_two_register_pool()
        svc = ManifestRegistryService(pool=pool, reapproval_gate=None)

        record_id = await svc.register(
            tenant_id="t", agent_id="cloud9-demo", manifest_yaml=baseline_yaml,
            operator_identity="unknown",
        )
        assert record_id == 1


class TestGateLevelDefenseInDepth:
    """LAURA-V50-005 recommendation #3 at the gate's own boundary — an
    unnormalizable identity must fail closed even if some future caller
    bypasses the service-layer check."""

    def test_note_registration_rejects_empty_registered_by(self):
        from yashigani.mcp.manifest_reapproval import ManifestReapprovalGate, ManifestReapprovalError
        gate = ManifestReapprovalGate(_FakeRedis())
        with pytest.raises(ManifestReapprovalError, match="non-empty"):
            gate.note_registration("agentX", "SHA1", registered_by="")

    def test_note_registration_rejects_non_string_registered_by(self):
        from yashigani.mcp.manifest_reapproval import ManifestReapprovalGate, ManifestReapprovalError
        gate = ManifestReapprovalGate(_FakeRedis())
        with pytest.raises(ManifestReapprovalError, match="non-empty"):
            gate.note_registration("agentX", "SHA1", registered_by=None)  # type: ignore[arg-type]

    def test_approve_rejects_empty_approver_id(self):
        from yashigani.mcp.manifest_reapproval import ManifestReapprovalGate, ManifestReapprovalError
        gate = ManifestReapprovalGate(_FakeRedis())
        gate.note_registration("agentX", "SHA1", registered_by="alice-account-id")
        gate.note_registration("agentX", "SHA2", registered_by="alice-account-id")
        with pytest.raises(ManifestReapprovalError, match="non-empty"):
            gate.approve("agentX", approver_id="", confirming_sha="SHA2")
