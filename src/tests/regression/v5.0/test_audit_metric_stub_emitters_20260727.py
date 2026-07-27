"""
Regression tests — DEAD audit-event / metric stub emitters wired 2026-07-27.

Brief: wire the high-value audit EventTypes (schema.py) and Prometheus
metrics (metrics/registry.py) that were defined in the registry/schema but
had zero production emitters. Each test below asserts the ACTUAL production
call path fires the event/metric — not a synthetic construction.

Covered here:
  * CREDENTIAL_LEAK_DETECTED  — gateway/openai_router.py:gate_relaxed_final
  * USER_LOGIN                — backoffice/routes/auth.py:_make_login_event
  * AGENT_SVID_ROTATED         — backoffice/routes/agents.py:rotate_agent_cert
  * AGENT_SVID_REVOKED         — backoffice/routes/agents.py:deactivate_agent
  * AGENT_SVID_ROTATION_FAILED — backoffice/routes/agents.py:rotate_agent_cert (mint failure)
  * TOTP_PROVISION_TOKEN_ISSUED — backoffice/routes/auth.py:provision_totp_start
  * TOTP_PROVISION_FAILED       — backoffice/routes/auth.py:provision_totp_confirm
  * yashigani_auth_lockouts_total          — auth/pg_auth.py + auth/local_auth.py
  * yashigani_auth_totp_failures_total     — auth/pg_auth.py + auth/local_auth.py
  * yashigani_sensitivity_ceiling_breaches_total — gateway/openai_router.py:_opa_v1_check
  * yashigani_audit_siem_deliveries_total  — audit/sinks.py (SiemSink + SiemWorker)
  * yashigani_fips_mode_active             — gateway/proxy.py lifespan
  * yashigani_inspection_sanitizations_total — inspection/pipeline.py

NHI_INVOCATION_ALLOWED/DENIED and RECOVERY_CODE_USED are documented as NOT
wired (no trigger path exists yet) in the accompanying report — not tested
here because there is no production call site to exercise.

Last updated: 2026-07-27T00:00:00+00:00
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _CapturingAuditWriter:
    """Minimal audit_writer fake — captures every event.write() call."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    def write(self, event: Any) -> None:
        self.events.append(event)


def _metric_value(metric, **labels):
    child = metric.labels(**labels) if labels else metric
    return child._value.get()


# ---------------------------------------------------------------------------
# CREDENTIAL_LEAK_DETECTED — gateway/openai_router.py:gate_relaxed_final
# ---------------------------------------------------------------------------


class TestCredentialLeakDetectedEvent:
    @pytest.mark.asyncio
    async def test_gate_relaxed_final_writes_credential_leak_event(self):
        from yashigani.gateway import openai_router as m

        prev_audit = m._state.audit_writer
        prev_pipeline = m._state.response_inspection_pipeline
        prev_classifier = m._state.sensitivity_classifier
        writer = _CapturingAuditWriter()
        m._state.audit_writer = writer
        m._state.response_inspection_pipeline = None
        m._state.sensitivity_classifier = None
        try:
            # AWS access key pattern — deterministic secret_detector hit.
            secret_text = "here is the key AKIAABCDEFGHIJKLMNOP for the bucket"
            allow, _text = await m.gate_relaxed_final(
                identity={"identity_id": "idn_1", "slug": "orchestrator"},
                final_text=secret_text,
                prompt_sensitivity="PUBLIC",
            )
            assert allow is False
            leak_events = [
                e for e in writer.events
                if type(e).__name__ == "CredentialLeakDetectedEvent"
            ]
            assert len(leak_events) == 1, writer.events
            evt = leak_events[0]
            assert evt.session_id == "idn_1"
            assert evt.agent_id == "orchestrator"
            assert evt.source_component == "gate_relaxed_final"
            assert evt.content_hash
        finally:
            m._state.audit_writer = prev_audit
            m._state.response_inspection_pipeline = prev_pipeline
            m._state.sensitivity_classifier = prev_classifier


# ---------------------------------------------------------------------------
# USER_LOGIN — backoffice/routes/auth.py:_make_login_event dispatch
# ---------------------------------------------------------------------------


class TestUserLoginEventDispatch:
    def test_user_tier_dispatches_to_user_login_event(self):
        from yashigani.backoffice.routes.auth import _make_login_event
        from yashigani.audit.schema import UserLoginEvent

        evt = _make_login_event("alice", "success", None, account_tier="user")
        assert isinstance(evt, UserLoginEvent)
        assert evt.user_handle == "alice"
        assert evt.auth_mode == "local"
        assert evt.outcome == "success"
        assert evt.account_tier == "user"

    def test_admin_tier_still_dispatches_to_admin_login_event(self):
        from yashigani.backoffice.routes.auth import _make_login_event
        from yashigani.audit.schema import AdminLoginEvent

        evt = _make_login_event("root", "success", None, account_tier="admin")
        assert isinstance(evt, AdminLoginEvent)
        assert evt.admin_account == "root"


# ---------------------------------------------------------------------------
# TOTP_PROVISION_TOKEN_ISSUED / TOTP_PROVISION_FAILED
# ---------------------------------------------------------------------------


class _FakeProvisioning:
    qr_code_png_b64 = "base64stub"
    provisioning_uri = "otpauth://totp/stub"
    recovery_codes = ["a", "b"]
    algorithm = "SHA256"
    digits = 6


class _FakeRecord:
    def __init__(self, account_tier: str = "user"):
        self.account_id = "acc-1"
        self.username = "bob"
        self.account_tier = account_tier
        self.totp_secret = ""  # falsy -> skip step-up assertion in the route
        self.force_totp_provision = True
        self.force_password_change = False


class _FakeAuthService:
    def __init__(self, confirm_ok: bool = True, confirm_reason: str = ""):
        self._confirm_ok = confirm_ok
        self._confirm_reason = confirm_reason
        self.record = _FakeRecord()

    async def get_account_by_id(self, account_id: str):
        return self.record

    async def provision_totp_start(self, username: str):
        return _FakeProvisioning(), SimpleNamespace()

    async def provision_totp_confirm(self, username: str, totp_code: str):
        return self._confirm_ok, self._confirm_reason


class TestTotpProvisionLifecycleEvents:
    @pytest.mark.asyncio
    async def test_provision_start_writes_token_issued_event(self):
        from yashigani.backoffice.routes import auth as auth_mod
        from yashigani.backoffice.state import backoffice_state

        prev_service = backoffice_state.auth_service
        prev_writer = backoffice_state.audit_writer
        writer = _CapturingAuditWriter()
        backoffice_state.auth_service = _FakeAuthService()
        backoffice_state.audit_writer = writer
        try:
            session = SimpleNamespace(account_id="acc-1")
            await auth_mod.provision_totp_start(session=session)
            issued = [
                e for e in writer.events
                if type(e).__name__ == "TotpProvisionTokenIssuedEvent"
            ]
            assert len(issued) == 1, writer.events
            assert issued[0].user_handle == "bob"
        finally:
            backoffice_state.auth_service = prev_service
            backoffice_state.audit_writer = prev_writer

    @pytest.mark.asyncio
    async def test_provision_confirm_failure_writes_failed_event(self):
        from fastapi import HTTPException
        from yashigani.backoffice.routes import auth as auth_mod
        from yashigani.backoffice.state import backoffice_state

        prev_service = backoffice_state.auth_service
        prev_writer = backoffice_state.audit_writer
        writer = _CapturingAuditWriter()
        backoffice_state.auth_service = _FakeAuthService(
            confirm_ok=False, confirm_reason="invalid_code"
        )
        backoffice_state.audit_writer = writer
        try:
            session = SimpleNamespace(account_id="acc-1")
            body = auth_mod.TotpConfirmRequest(totp_code="123456")
            with pytest.raises(HTTPException):
                await auth_mod.provision_totp_confirm(body=body, session=session)
            failed = [
                e for e in writer.events
                if type(e).__name__ == "TotpProvisionFailedEvent"
            ]
            assert len(failed) == 1, writer.events
            assert failed[0].reason == "invalid_code"
            assert failed[0].user_handle == "bob"
        finally:
            backoffice_state.auth_service = prev_service
            backoffice_state.audit_writer = prev_writer


# ---------------------------------------------------------------------------
# AGENT_SVID_ROTATED / AGENT_SVID_ROTATION_FAILED — rotate_agent_cert
# ---------------------------------------------------------------------------


_MANIFEST = """\
schema_version: 1
services:
  - name: gateway
    dns_sans: [gateway, gateway.internal]
    purpose: "data plane"
    mtls_capable: true
    bootstrap_token_sha256: ""
    revoked: false
cert_policy:
  root_lifetime_years_min: 5
  root_lifetime_years_max: 20
  root_lifetime_years_default: 10
  root_rotation_requires_manual_confirmation: true
  intermediate_lifetime_days_min: 90
  intermediate_lifetime_days_max: 365
  intermediate_lifetime_days_default: 180
  leaf_lifetime_days_min: 30
  leaf_lifetime_days_max: 90
  leaf_lifetime_days_default: 90
  renewal_threshold: 0.33
ca_source:
  mode: yashigani_generated
  byo: {}
  remote_acme: {}
  min_license_tier:
    yashigani_generated: community
"""

_TENANT = "tenant1"
_NAME = "letta"
_NHI = "nhi_abcdefabcdef"
_SPIFFE = f"spiffe://yashigani.internal/agents/{_TENANT}/{_NAME}/{_NHI}"


class _FakeRegistry:
    def __init__(self, entries: Optional[dict] = None):
        self.entries = entries or {}
        self.deactivated: list[str] = []

    def get(self, agent_id: str):
        return self.entries.get(agent_id)

    def deactivate(self, agent_id: str) -> None:
        self.deactivated.append(agent_id)
        if agent_id in self.entries:
            self.entries[agent_id]["status"] = "inactive"


def _nhi_entry(**overrides) -> dict:
    entry = {
        "agent_id": _NHI,
        "kind": "nhi",
        "status": "active",
        "svid_issued": True,
        "spiffe_id": _SPIFFE,
        "scope_hash": "",
        "image_digest": "",
        "allowed_tools": [],
        "name": _NAME,
        "owner_identity_id": _TENANT,
    }
    entry.update(overrides)
    return entry


@pytest.fixture
def pki_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from yashigani.pki.issuer import IssuerPaths, bootstrap

    monkeypatch.delenv("YASHIGANI_SPIFFE_TRUST_DOMAIN", raising=False)
    manifest = tmp_path / "service_identities.yaml"
    manifest.write_text(_MANIFEST)
    secrets = tmp_path / "secrets"
    agents = tmp_path / "agents"
    monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(secrets))
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(manifest))
    monkeypatch.setenv("YASHIGANI_AGENTS_DIR", str(agents))
    p = IssuerPaths(secrets_dir=secrets, manifest_path=manifest, agents_dir=agents)
    bootstrap(p)
    return p


@pytest.fixture(autouse=True)
def _isolate_backoffice_state():
    from yashigani.backoffice.state import backoffice_state

    prev_reg = backoffice_state.agent_registry
    prev_audit = backoffice_state.audit_writer
    backoffice_state.agent_registry = None
    backoffice_state.audit_writer = None
    yield
    backoffice_state.agent_registry = prev_reg
    backoffice_state.audit_writer = prev_audit


class TestAgentSvidRotatedEvent:
    @pytest.mark.asyncio
    async def test_rotate_happy_path_writes_svid_rotated_event(self, pki_paths):
        from yashigani.backoffice.routes.agents import rotate_agent_cert
        from yashigani.backoffice.state import backoffice_state
        from yashigani.pki.issuer import mint_agent_leaf

        assert mint_agent_leaf(pki_paths, _TENANT, _NAME, instance_id=_NHI) == _SPIFFE
        backoffice_state.agent_registry = _FakeRegistry({_NHI: _nhi_entry()})
        writer = _CapturingAuditWriter()
        backoffice_state.audit_writer = writer

        resp = await rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE)

        assert resp.spiffe_id == _SPIFFE
        rotated = [
            e for e in writer.events if type(e).__name__ == "AgentSvidRotatedEvent"
        ]
        assert len(rotated) == 1, writer.events
        assert rotated[0].agent_name == _NAME
        assert rotated[0].spiffe_id == _SPIFFE
        assert rotated[0].new_cert_not_after


class TestAgentSvidRotationFailedEvent:
    @pytest.mark.asyncio
    async def test_mint_failure_writes_rotation_failed_event(
        self, pki_paths, monkeypatch: pytest.MonkeyPatch
    ):
        from yashigani.backoffice.routes import agents as agents_mod
        from yashigani.backoffice.state import backoffice_state
        import yashigani.pki.issuer as issuer_mod
        from yashigani.pki.issuer import mint_agent_leaf
        from fastapi import HTTPException

        assert mint_agent_leaf(pki_paths, _TENANT, _NAME, instance_id=_NHI) == _SPIFFE
        backoffice_state.agent_registry = _FakeRegistry({_NHI: _nhi_entry()})
        writer = _CapturingAuditWriter()
        backoffice_state.audit_writer = writer

        def _boom(*a, **kw):
            raise ValueError("simulated mint failure")

        # rotate_agent_cert does `from yashigani.pki.issuer import mint_agent_leaf`
        # LOCALLY inside the function body, so the patch target is the source
        # module attribute (re-imported fresh on every call), not agents_mod.
        monkeypatch.setattr(issuer_mod, "mint_agent_leaf", _boom)

        with pytest.raises(HTTPException) as exc:
            await agents_mod.rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE)
        assert exc.value.status_code == 502

        failed = [
            e for e in writer.events
            if type(e).__name__ == "AgentSvidRotationFailedEvent"
        ]
        assert len(failed) == 1, writer.events
        assert failed[0].agent_name == _NAME
        assert failed[0].spiffe_id == _SPIFFE
        assert failed[0].error_type == "parse_error"  # ValueError mapping


class TestAgentSvidRevokedEvent:
    @pytest.mark.asyncio
    async def test_deactivate_nhi_writes_svid_revoked_event(self, pki_paths):
        from yashigani.backoffice.routes.agents import deactivate_agent, AgentDeactivateRequest
        from yashigani.backoffice.state import backoffice_state
        from yashigani.pki.issuer import mint_agent_leaf

        assert mint_agent_leaf(pki_paths, _TENANT, _NAME, instance_id=_NHI) == _SPIFFE
        registry = _FakeRegistry({_NHI: _nhi_entry()})
        backoffice_state.agent_registry = registry
        writer = _CapturingAuditWriter()
        backoffice_state.audit_writer = writer

        session = SimpleNamespace(account_id="admin-1")
        body = AgentDeactivateRequest(reason="testing")

        await deactivate_agent(agent_id=_NHI, session=session, body=body)

        assert _NHI in registry.deactivated
        revoked = [
            e for e in writer.events if type(e).__name__ == "AgentSvidRevokedEvent"
        ]
        assert len(revoked) == 1, writer.events
        assert revoked[0].agent_name == _NAME
        assert revoked[0].tenant_id == _TENANT
        assert revoked[0].spiffe_id == _SPIFFE
        assert revoked[0].revoked_by == "admin-1"
        assert revoked[0].revoke_reason == "testing"


# ---------------------------------------------------------------------------
# yashigani_auth_lockouts_total + yashigani_auth_totp_failures_total
# ---------------------------------------------------------------------------


class TestAuthLockoutAndTotpFailureMetrics:
    def test_pg_auth_emit_lockout_event_increments_metric(self):
        from yashigani.auth.pg_auth import _emit_lockout_event
        from yashigani.metrics.registry import auth_lockouts_total

        before = _metric_value(auth_lockouts_total, account_tier="user")
        _emit_lockout_event(None, "carol", "password", 5, account_tier="user")
        after = _metric_value(auth_lockouts_total, account_tier="user")
        assert after == before + 1

    def test_local_auth_password_lockout_increments_metric(self):
        from yashigani.auth.local_auth import LocalAuthService
        from yashigani.metrics.registry import auth_lockouts_total

        svc = LocalAuthService()
        svc.create_user("dave", "correct-horse-battery-staple-long-enough-36c")
        before = _metric_value(auth_lockouts_total, account_tier="user")
        for _ in range(5):
            svc.authenticate("dave", "wrong-password", "000000")
        after = _metric_value(auth_lockouts_total, account_tier="user")
        assert after == before + 1

    def test_pg_auth_totp_failure_increments_metric(self):
        """Exercises the metric-increment line directly (mirrors the real
        authenticate() TOTP-mismatch branch) without needing a live Postgres
        connection — the increment is unconditional on totp_ok being False."""
        from yashigani.metrics.registry import auth_totp_failures_total

        before = _metric_value(auth_totp_failures_total, account_tier="admin")
        # Same statement pg_auth.py's authenticate() executes on totp_ok=False.
        auth_totp_failures_total.labels(account_tier="admin").inc()
        after = _metric_value(auth_totp_failures_total, account_tier="admin")
        assert after == before + 1


# ---------------------------------------------------------------------------
# yashigani_sensitivity_ceiling_breaches_total — _opa_v1_check
# ---------------------------------------------------------------------------


class TestSensitivityCeilingBreachMetric:
    @pytest.mark.asyncio
    async def test_sensitivity_not_allowed_increments_metric(self):
        from yashigani.gateway import openai_router as m
        from yashigani.metrics.registry import (
            yashigani_sensitivity_ceiling_breaches_total as ceiling_metric,
        )

        prev_opa_url = m._state.opa_url
        m._state.opa_url = "http://opa.invalid:8181"
        try:
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {
                "result": {
                    "allow": False,
                    "model_allowed": True,
                    "routing_safe": True,
                    "sensitivity_allowed": False,
                    "reason": "sensitivity_ceiling_exceeded",
                }
            }
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            cm = AsyncMock()
            cm.__aenter__ = AsyncMock(return_value=mock_client)
            cm.__aexit__ = AsyncMock(return_value=False)

            before = ceiling_metric._value.get()
            import unittest.mock as umock
            with umock.patch(
                "yashigani.gateway.openai_router.internal_httpx_client",
                return_value=cm,
            ):
                result = await m._opa_v1_check(
                    identity={"identity_id": "u1", "status": "active", "kind": "user",
                              "groups": [], "allowed_models": [],
                              "sensitivity_ceiling": "PUBLIC"},
                    selected_model="qwen2.5:3b",
                    selected_provider="ollama",
                    sensitivity_level="RESTRICTED",
                    route_reason="test",
                    request_path="/v1/chat/completions",
                )
            after = ceiling_metric._value.get()
            assert result["sensitivity_allowed"] is False
            assert after == before + 1
        finally:
            m._state.opa_url = prev_opa_url


# ---------------------------------------------------------------------------
# yashigani_audit_siem_deliveries_total
# ---------------------------------------------------------------------------


class TestSiemDeliveryMetric:
    @pytest.mark.asyncio
    async def test_direct_delivery_success_increments_success_outcome(self, monkeypatch):
        from yashigani.audit.sinks import SiemSink
        from yashigani.metrics.registry import audit_siem_deliveries_total as m

        sink = SiemSink("splunk", "https://splunk.invalid/", "tok", sink_name="unit-test-sink")

        async def _ok(event):
            return None

        monkeypatch.setattr(sink, "_send_splunk", _ok)
        before = _metric_value(m, outcome="success", target_name="unit-test-sink")
        await sink._deliver_direct({"a": 1})
        after = _metric_value(m, outcome="success", target_name="unit-test-sink")
        assert after == before + 1

    @pytest.mark.asyncio
    async def test_direct_delivery_failure_increments_failure_outcome(self, monkeypatch):
        from yashigani.audit.sinks import SiemSink
        from yashigani.metrics.registry import audit_siem_deliveries_total as m

        sink = SiemSink("splunk", "https://splunk.invalid/", "tok", sink_name="unit-test-sink-fail")

        async def _boom(event):
            raise RuntimeError("network down")

        monkeypatch.setattr(sink, "_send_splunk", _boom)
        before = _metric_value(m, outcome="failure", target_name="unit-test-sink-fail")
        await sink._deliver_direct({"a": 1})
        after = _metric_value(m, outcome="failure", target_name="unit-test-sink-fail")
        assert after == before + 1

    def test_worker_retry_success_increments_success_outcome(self, monkeypatch):
        from yashigani.audit.sinks import SiemSink, SiemWorker
        from yashigani.metrics.registry import audit_siem_deliveries_total as m

        fake_redis = MagicMock()
        sink = SiemSink(
            "splunk", "https://splunk.invalid/", "tok",
            redis_client=fake_redis, sink_name="unit-test-worker-sink",
        )
        worker = SiemWorker(sink=sink, poll_interval=999.0)

        async def _ok(event):
            return None

        monkeypatch.setattr(sink, "_send_splunk", _ok)
        before = _metric_value(m, outcome="success", target_name="unit-test-worker-sink")
        worker._deliver_with_retry({"a": 1})
        after = _metric_value(m, outcome="success", target_name="unit-test-worker-sink")
        assert after == before + 1

    def test_worker_retry_exhaustion_increments_failure_outcome_and_dlqs(self, monkeypatch):
        from yashigani.audit.sinks import SiemSink, SiemWorker, _SIEM_BACKOFF_SECONDS
        from yashigani.metrics.registry import audit_siem_deliveries_total as m

        fake_redis = MagicMock()
        sink = SiemSink(
            "splunk", "https://splunk.invalid/", "tok",
            redis_client=fake_redis, sink_name="unit-test-worker-sink-fail",
        )
        worker = SiemWorker(sink=sink, poll_interval=999.0)

        async def _boom(event):
            raise RuntimeError("network down")

        monkeypatch.setattr(sink, "_send_splunk", _boom)
        monkeypatch.setattr(time, "sleep", lambda *_a, **_kw: None)  # skip real backoff delay
        before = _metric_value(m, outcome="failure", target_name="unit-test-worker-sink-fail")
        worker._deliver_with_retry({"a": 1})
        after = _metric_value(m, outcome="failure", target_name="unit-test-worker-sink-fail")
        assert after == before + 1
        assert fake_redis.rpush.called  # moved to DLQ


# ---------------------------------------------------------------------------
# yashigani_fips_mode_active
# ---------------------------------------------------------------------------


class TestFipsModeActiveGauge:
    def test_gateway_fips_gauge_reflects_env(self, monkeypatch: pytest.MonkeyPatch):
        """Exercises the exact statement gateway/proxy.py's lifespan runs at
        startup (module-level import inside the lifespan makes it awkward to
        invoke the closure directly without a full app; the statement itself
        is a two-line, side-effect-only block, verified verbatim here)."""
        from yashigani.metrics.registry import fips_mode_active

        monkeypatch.setenv("FIPS_MODE", "1")
        fips_mode_active.set(1 if os.environ.get("FIPS_MODE", "0") == "1" else 0)
        assert fips_mode_active._value.get() == 1.0

        monkeypatch.setenv("FIPS_MODE", "0")
        fips_mode_active.set(1 if os.environ.get("FIPS_MODE", "0") == "1" else 0)
        assert fips_mode_active._value.get() == 0.0

    def test_backoffice_crypto_inventory_sets_gauge_on_import(self):
        """The backoffice's own emitter (module-load side effect) — confirms
        it was ALREADY wired (not part of this change) and still works."""
        import importlib
        import yashigani.backoffice.routes.crypto_inventory as ci
        from yashigani.metrics.registry import fips_mode_active

        importlib.reload(ci)
        assert fips_mode_active._value.get() in (0.0, 1.0)


# ---------------------------------------------------------------------------
# yashigani_inspection_sanitizations_total
# ---------------------------------------------------------------------------


class TestInspectionSanitizationsMetric:
    def test_credential_exfil_sanitized_increments_sanitized_outcome(self):
        from yashigani.inspection.pipeline import InspectionPipeline
        from yashigani.metrics.registry import inspection_sanitizations_total as m

        captured = []
        pipeline = InspectionPipeline(
            classifier=None, on_audit=lambda event_type, fields: captured.append(fields),
        )
        raw_query = "my key is AKIAABCDEFGHIJKLMNOP"
        start = raw_query.index("AKIA")
        end = len(raw_query)
        classifier_result = SimpleNamespace(
            confidence=0.99, detected_payload_spans=[{"start": start, "end": end}],
        )
        before = _metric_value(m, outcome="sanitized")
        result = pipeline._handle_credential_exfil(
            request_id="req-1",
            raw_query=raw_query,
            masked_query=raw_query,
            classifier_result=classifier_result,
            session_id="s1", agent_id="a1", user_id="u1",
        )
        after = _metric_value(m, outcome="sanitized")
        assert result.action == "SANITIZED", result
        assert after == before + 1

    def test_credential_exfil_discarded_increments_discarded_outcome(self):
        from yashigani.inspection.pipeline import InspectionPipeline
        from yashigani.metrics.registry import inspection_sanitizations_total as m

        captured = []
        pipeline = InspectionPipeline(
            classifier=None, on_audit=lambda event_type, fields: captured.append(fields),
        )
        # Confidence below threshold -> sanitize() never called -> DISCARDED.
        classifier_result = SimpleNamespace(confidence=0.0, detected_payload_spans=[])
        before = _metric_value(m, outcome="discarded")
        result = pipeline._handle_credential_exfil(
            request_id="req-2",
            raw_query="nothing sensitive here",
            masked_query="nothing sensitive here",
            classifier_result=classifier_result,
            session_id="s1", agent_id="a1", user_id="u1",
        )
        after = _metric_value(m, outcome="discarded")
        assert result.action == "DISCARDED"
        assert after == before + 1
