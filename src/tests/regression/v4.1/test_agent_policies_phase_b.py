"""
Regression tests — v4.1 Phase B: Agent Policy Template admin surface.

Design: AgnosticSecurity/Products/Yashigani/agent-admin-policy-templates-design-20260708.md

Test matrix (8 required cases):
  1. apply-writes-grant+audit     — _run_apply writes grant to store and emits audit events
  2. revoke-calls-verify-push     — revoke_grant calls push_and_verify with must_be_absent (Lu R1)
  3. tenant-scope-authz-reject    — path tenant != YASHIGANI_TENANT_ID → 403 (Laura F8)
  4. connect_hosts-admin-supplied-422 — overrides with connect_hosts key → 422 (Laura F2)
  5. IP-literal-reject            — _validate_connect_host rejects IPv4, IPv6, mapped literals
  6. prefix-disjointness          — same prefix in Mode A + Mode B → ValueError (Lu MF-4)
  7. reconciler-inert-no-grant-widen — run_langflow_discovery never widens grant (Nico Q-N1)
  8. XSS-payload-in-flow-name-output-encoded — flow name stored raw, not HTML-stripped

Additional coverage:
  - R2 LKG cache: transient Redis failure falls back to last-good snapshot
  - Mode-B (connect) reject in Track 1: template with mode:connect → 422
  - compute_graph_hash: noise-key stripping + SHA-256 canonical JSON (Nico Q-N3)
  - template applies_to mismatch → 422
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from yashigani.backoffice.routes.agent_policies import (
    _assert_tenant_scope,
    _check_prefix_disjointness,
    _get_claimed_spiffes_lkg,
    _resolve_bundled_spiffe,
    _validate_connect_host,
    ApplyTemplateRequest,
    AcknowledgementEntry,
)
from yashigani.backoffice.langflow_reconciler import (
    compute_graph_hash,
    run_langflow_discovery,
    MAX_FLOWS,
    MAX_FLOW_BYTES,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_session(account_id: str = "admin@test") -> SimpleNamespace:
    """Minimal stand-in for StepUpAdminSession."""
    return SimpleNamespace(account_id=account_id)


def _make_store(
    *,
    grants: dict | None = None,
    descriptors: dict | None = None,
    claimed: frozenset | None = None,
) -> MagicMock:
    """Return a mock DurableMcpRegistryStore with a pre-populated in-memory state."""
    store = MagicMock()
    _grants: dict = dict(grants or {})
    _descriptors: dict = dict(descriptors or {})
    _applications: dict = {}
    _claimed: frozenset = frozenset(claimed or set())

    def get_egress_grant(tenant: str, system: str):
        return _grants.get(f"{tenant}:{system}")

    def put_egress_grant(tenant: str, system: str, data: dict):
        _grants[f"{tenant}:{system}"] = data
        nonlocal _claimed
        spiffe = data.get("spiffe", "")
        if spiffe:
            _claimed = _claimed | frozenset([spiffe])

    def delete_egress_grant(tenant: str, system: str):
        _grants.pop(f"{tenant}:{system}", None)

    def get(tenant: str, system: str):
        return _descriptors.get(f"{tenant}:{system}")

    def put(tenant: str, system: str, data: dict):
        _descriptors[f"{tenant}:{system}"] = data

    def delete(tenant: str, system: str):
        _descriptors.pop(f"{tenant}:{system}", None)

    def get_template_application(tenant: str, system: str):
        return _applications.get(f"{tenant}:{system}")

    def put_template_application(tenant: str, system: str, data: dict):
        _applications[f"{tenant}:{system}"] = data

    def delete_template_application(tenant: str, system: str):
        _applications.pop(f"{tenant}:{system}", None)

    def get_claimed_egress_seed_spiffes() -> frozenset:
        return _claimed

    def list_all() -> list:
        return list(_descriptors.values())

    def build_egress_grants_data() -> dict:
        result = {}
        for key, grant in _grants.items():
            spiffe = grant.get("spiffe", "")
            if spiffe:
                result[spiffe] = {
                    "allowed_prefixes": sorted(grant.get("prefixes", [])),
                }
        return result

    store.get_egress_grant.side_effect = get_egress_grant
    store.put_egress_grant.side_effect = put_egress_grant
    store.delete_egress_grant.side_effect = delete_egress_grant
    store.get.side_effect = get
    store.put.side_effect = put
    store.delete.side_effect = delete
    store.get_template_application.side_effect = get_template_application
    store.put_template_application.side_effect = put_template_application
    store.delete_template_application.side_effect = delete_template_application
    store.get_claimed_egress_seed_spiffes.side_effect = get_claimed_egress_seed_spiffes
    store.list_all.side_effect = list_all
    store.build_egress_grants_data.side_effect = build_egress_grants_data

    # Expose internal state for assertions
    store._grants = _grants
    store._descriptors = _descriptors
    store._applications = _applications
    return store


def _make_minimal_template(
    template_id: str = "tmpl-langflow-default",
    applies_to: str = "langflow",
    egress_entries: list | None = None,
) -> dict:
    """Build a minimal in-memory template dict matching the YAML schema."""
    if egress_entries is None:
        egress_entries = [
            {"prefix": "llm", "mode": "reverse_proxy", "ceiling": "PUBLIC"},
        ]
    return {
        "metadata": {
            "template_id": template_id,
            "version": 1,
            "applies_to": applies_to,
            "description": "Test template",
        },
        "spec": {
            "egress": egress_entries,
            "disclosure": {
                "enforced": [],
                "residuals": [],
            },
        },
    }


# ---------------------------------------------------------------------------
# Test 1: apply writes grant + audit
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_apply_writes_grant_and_audit(monkeypatch):
    """apply → put_egress_grant written to store; audit emits both events."""
    store = _make_store()
    audit = MagicMock()

    # Patch out the module-level backoffice_state dependency
    monkeypatch.setenv("YASHIGANI_TENANT_ID", "acme")
    monkeypatch.setenv("YASHIGANI_LANGFLOW_SPIFFE_ID", "spiffe://yashigani.internal/langflow")

    templates = {"tmpl-langflow-default": _make_minimal_template()}

    from yashigani.backoffice.routes import agent_policies as ap
    from fastapi import HTTPException

    # backoffice_state is imported BY NAME in agent_policies (from ... import backoffice_state),
    # so we must patch the name in agent_policies' own namespace, not in the state module.
    mock_state = MagicMock()
    mock_state.audit_writer = audit
    mock_state.mcp_registry_store = None

    with (
        patch.object(ap, "_registry_store", return_value=store),
        patch.object(ap, "_load_templates", return_value=templates),
        patch.object(ap, "backoffice_state", mock_state),
        patch("yashigani.mcp._opa_push.push_and_verify_egress_grants"),
        patch("yashigani.mcp._egress_grants.build_egress_grants_doc", return_value={}),
    ):
        body = ApplyTemplateRequest(template_id="tmpl-langflow-default")
        session = _make_session("admin@acme")

        result = await ap._run_apply("acme", "langflow", body, session)

    # Grant must be written
    assert "acme:langflow" in store._grants
    grant = store._grants["acme:langflow"]
    assert grant["spiffe"] == "spiffe://yashigani.internal/langflow"
    assert "llm" in grant["prefixes"]

    # Template application record must be present
    assert "acme:langflow" in store._applications
    assert store._applications["acme:langflow"]["template_id"] == "tmpl-langflow-default"
    assert store._applications["acme:langflow"]["applied_by"] == "admin@acme"

    # Both audit events must have been emitted
    assert audit.write.call_count >= 2
    call_types = [type(c.args[0]).__name__ for c in audit.write.call_args_list]
    assert "McpEgressGrantWrittenEvent" in call_types
    assert "AgentPolicyTemplateAppliedEvent" in call_types

    # identity_basis must be "ringfence-position" (Lu MF-6)
    applied_event = next(
        c.args[0]
        for c in audit.write.call_args_list
        if type(c.args[0]).__name__ == "AgentPolicyTemplateAppliedEvent"
    )
    assert applied_event.identity_basis == "ringfence-position"

    # Result shape
    assert result["status"] == "applied"
    assert result["tenant_id"] == "acme"
    assert result["system_id"] == "langflow"


# ---------------------------------------------------------------------------
# Test 2: revoke calls push_and_verify with must_be_absent (Lu R1)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_revoke_calls_push_and_verify_with_must_be_absent(monkeypatch):
    """revoke_grant MUST call push_and_verify_egress_grants with must_be_absent (Lu R1)."""
    spiffe = "spiffe://yashigani.internal/langflow"
    store = _make_store(
        grants={"acme:langflow": {"spiffe": spiffe, "prefixes": ["llm"]}},
    )
    audit = MagicMock()

    monkeypatch.setenv("YASHIGANI_TENANT_ID", "acme")
    monkeypatch.setenv("YASHIGANI_LANGFLOW_SPIFFE_ID", spiffe)

    verify_calls: list = []

    def _mock_verify(opa_url: str, doc: dict, must_be_absent=None):
        verify_calls.append({"opa_url": opa_url, "must_be_absent": must_be_absent})

    from yashigani.backoffice.routes import agent_policies as ap

    mock_state = MagicMock()
    mock_state.audit_writer = audit
    mock_state.mcp_registry_store = None

    with (
        patch.object(ap, "_registry_store", return_value=store),
        patch.object(ap, "backoffice_state", mock_state),
        patch("yashigani.mcp._opa_push.push_and_verify_egress_grants", side_effect=_mock_verify),
        patch("yashigani.mcp._egress_grants.build_egress_grants_doc", return_value={}),
        patch("yashigani.mcp._egress_grants.transitional_egress_seed", return_value={}),
    ):
        session = _make_session("admin@acme")
        result = await ap.revoke_grant("acme", "langflow", session)

    assert result["status"] == "revoked"

    # MUST have called push_and_verify — plain push (push_egress_grants) is NEVER acceptable
    assert len(verify_calls) == 1, "push_and_verify_egress_grants must be called exactly once"

    # must_be_absent MUST include the revoked SPIFFE (Lu R1 HARD GATE)
    must_absent = verify_calls[0]["must_be_absent"]
    assert must_absent is not None, "must_be_absent must not be None"
    assert spiffe in must_absent, f"Revoked SPIFFE {spiffe!r} must be in must_be_absent"


# ---------------------------------------------------------------------------
# Test 3: tenant-scope authz rejects mismatched tenant (Laura F8)
# ---------------------------------------------------------------------------

def test_tenant_scope_authz_rejects_wrong_tenant(monkeypatch):
    """_assert_tenant_scope raises 403 when path tenant != YASHIGANI_TENANT_ID."""
    from fastapi import HTTPException

    monkeypatch.setenv("YASHIGANI_TENANT_ID", "acme")

    with pytest.raises(HTTPException) as exc_info:
        _assert_tenant_scope("other-tenant")

    assert exc_info.value.status_code == 403
    detail = exc_info.value.detail
    assert detail["error"] == "tenant_scope_violation"
    assert "other-tenant" in detail["message"]
    assert "acme" in detail["message"]


def test_tenant_scope_authz_accepts_correct_tenant(monkeypatch):
    """_assert_tenant_scope is a no-op when the tenant matches."""
    monkeypatch.setenv("YASHIGANI_TENANT_ID", "acme")
    _assert_tenant_scope("acme")  # must not raise


def test_tenant_scope_defaults_to_default(monkeypatch):
    """If YASHIGANI_TENANT_ID is unset, the default tenant is 'default'."""
    monkeypatch.delenv("YASHIGANI_TENANT_ID", raising=False)
    _assert_tenant_scope("default")  # must not raise
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        _assert_tenant_scope("not-default")


# ---------------------------------------------------------------------------
# Test 4: admin-supplied connect_hosts → 422 (Laura F2)
# ---------------------------------------------------------------------------

def test_connect_hosts_override_rejected():
    """ApplyTemplateRequest.overrides with connect_hosts key → 422 ValidationError."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        ApplyTemplateRequest(
            template_id="tmpl-langflow-default",
            overrides={"connect_hosts": ["evil.example.com:443"]},
        )

    errors = exc_info.value.errors()
    # At least one error must reference connect_hosts / Laura F2
    messages = " ".join(str(e) for e in errors)
    assert "connect_hosts" in messages or "Laura F2" in messages


def test_apply_with_mode_b_template_returns_422(monkeypatch):
    """A template with mode:connect entries must be rejected 422 in Track 1."""
    from fastapi import HTTPException

    monkeypatch.setenv("YASHIGANI_TENANT_ID", "acme")
    monkeypatch.setenv("YASHIGANI_LANGFLOW_SPIFFE_ID", "spiffe://yashigani.internal/langflow")

    tmpl_with_connect = _make_minimal_template(
        template_id="tmpl-connect",
        applies_to="langflow",
        egress_entries=[
            {"prefix": "slack", "mode": "connect", "connect_hosts": ["slack.com:443"]},
        ],
    )
    store = _make_store()
    body = ApplyTemplateRequest(template_id="tmpl-connect")
    session = _make_session()

    from yashigani.backoffice.routes import agent_policies as ap

    mock_state = MagicMock()
    mock_state.audit_writer = None
    mock_state.mcp_registry_store = None

    with (
        patch.object(ap, "_registry_store", return_value=store),
        patch.object(ap, "_load_templates", return_value={"tmpl-connect": tmpl_with_connect}),
        patch.object(ap, "backoffice_state", mock_state),
    ):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.get_event_loop().run_until_complete(
                ap._run_apply("acme", "langflow", body, session)
            )

    assert exc_info.value.status_code == 422
    assert "mode_b_not_available" in str(exc_info.value.detail)


# ---------------------------------------------------------------------------
# Test 5: IP-literal rejection in _validate_connect_host (Lu MF-3 + Laura F7)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip_literal", [
    "192.168.1.1:443",
    "10.0.0.1:443",
    "8.8.8.8:443",
    "127.0.0.1:443",
    "::1:443",
    "[::1]:443",
    "[2001:db8::1]:443",
    "::ffff:192.168.1.1:443",
    "0x7f000001:443",   # hex IP (ipaddress.ip_address parses this in Python 3.9-)
])
def test_validate_connect_host_rejects_ip_literals(ip_literal: str):
    """_validate_connect_host must reject all IP literal forms (Lu MF-3 + Laura F7)."""
    with pytest.raises(ValueError):
        _validate_connect_host(ip_literal)


@pytest.mark.parametrize("valid_host", [
    "slack.com:443",
    "hooks.slack.com:443",
    "api.openai.com:443",
    "x.example.co.uk:443",
])
def test_validate_connect_host_accepts_valid_fqdns(valid_host: str):
    """_validate_connect_host must accept valid lowercase FQDN:443 entries."""
    result = _validate_connect_host(valid_host)
    assert result == valid_host.lower()


@pytest.mark.parametrize("bad_host", [
    "slack.com:80",         # wrong port
    "slack.com:8443",       # wrong port
    "SLACK.COM:443",        # uppercase
    "slack.com.:443",       # trailing dot
    "slack:443",            # no dot (bare hostname)
    "*.slack.com:443",      # wildcard
    ":443",                 # empty host
    "slack.com",            # no port
])
def test_validate_connect_host_rejects_invalid_formats(bad_host: str):
    """_validate_connect_host rejects malformed entries."""
    with pytest.raises(ValueError):
        _validate_connect_host(bad_host)


# ---------------------------------------------------------------------------
# Test 6: prefix disjointness (Lu MF-4)
# ---------------------------------------------------------------------------

def test_check_prefix_disjointness_rejects_overlap():
    """Same prefix in Mode A and Mode B must raise ValueError (Lu MF-4)."""
    entries = [
        {"prefix": "llm", "mode": "reverse_proxy"},
        {"prefix": "llm", "mode": "connect"},  # overlap!
    ]
    with pytest.raises(ValueError) as exc_info:
        _check_prefix_disjointness(entries)
    assert "llm" in str(exc_info.value)
    assert "MF-4" in str(exc_info.value) or "Mode A" in str(exc_info.value) or "Mode B" in str(exc_info.value)


def test_check_prefix_disjointness_allows_distinct_prefixes():
    """Distinct prefixes in Mode A and Mode B must pass."""
    entries = [
        {"prefix": "llm", "mode": "reverse_proxy"},
        {"prefix": "slack", "mode": "connect"},
    ]
    _check_prefix_disjointness(entries)  # must not raise


def test_check_prefix_disjointness_mode_a_only():
    """All Mode-A entries (no Mode-B) must always pass."""
    entries = [
        {"prefix": "llm", "mode": "reverse_proxy"},
        {"prefix": "tools", "mode": "reverse_proxy"},
        {"prefix": "slack", "mode": "reverse_proxy"},
    ]
    _check_prefix_disjointness(entries)  # must not raise


# ---------------------------------------------------------------------------
# Test 7: reconciler — INERT records only, NEVER widens union grant (Nico Q-N1)
# ---------------------------------------------------------------------------

def test_reconciler_inert_no_grant_widen():
    """run_langflow_discovery never writes a grant or widens an existing grant (Nico Q-N1)."""
    store = _make_store(
        grants={"default:langflow": {"spiffe": "spiffe://yashigani.internal/langflow", "prefixes": ["llm"]}},
    )
    audit = MagicMock()

    # Fake two discovered flows
    fake_flows = [
        {"id": "flow-aaa-111", "name": "My Flow", "data": {"nodes": [], "edges": []}},
        {"id": "flow-bbb-222", "name": "Second Flow", "data": {"nodes": [{"type": "llm"}]}},
    ]

    with patch(
        "yashigani.backoffice.langflow_reconciler._fetch_flows",
        return_value=fake_flows,
    ):
        result = run_langflow_discovery(
            registry_store=store,
            audit_writer=audit,
            tenant_id="default",
            langflow_system="langflow",
        )

    # no_grant_widen MUST be True (B5 invariant surfaced in return value)
    assert result["no_grant_widen"] is True

    # The union grant for langflow must be unchanged
    langflow_grant = store._grants.get("default:langflow")
    assert langflow_grant is not None
    assert langflow_grant["prefixes"] == ["llm"], "Reconciler must not widen the union grant"

    # put_egress_grant must NOT have been called (inert records only)
    store.put_egress_grant.assert_not_called()

    # Discovered NHI records must be INERT: svid_issued=False, no grant
    for record in store._descriptors.values():
        assert record.get("svid_issued") is False, "Discovered flow must be INERT (svid_issued=False)"
        assert record.get("spiffe_id", "") == "", "Discovered flow must have empty spiffe_id"


def test_reconciler_caps_flow_count():
    """_fetch_flows caps at MAX_FLOWS; reconciler processes exactly what _fetch_flows returns (Laura F9).

    The cap lives inside _fetch_flows (which slices the API response to MAX_FLOWS).
    We test by giving _fetch_flows a mock HTTP response with MAX_FLOWS+10 entries and
    verifying it returns exactly MAX_FLOWS after slicing.
    """
    import json as _json
    import httpx

    # Build a list with more than MAX_FLOWS entries
    oversized_list = [
        {"id": f"flow-{i:04d}", "name": f"Flow {i}", "data": {}}
        for i in range(MAX_FLOWS + 10)
    ]
    body_bytes = _json.dumps(oversized_list).encode()

    from yashigani.backoffice.langflow_reconciler import _fetch_flows

    # Mock httpx.Client so _fetch_flows runs its own cap logic
    mock_response = MagicMock()
    mock_response.content = body_bytes
    mock_response.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.get = MagicMock(return_value=mock_response)

    with patch("httpx.Client", return_value=mock_client):
        result = _fetch_flows("http://langflow:7860", "test-bearer")

    assert len(result) == MAX_FLOWS, (
        f"_fetch_flows must cap at MAX_FLOWS={MAX_FLOWS}; got {len(result)}"
    )


def test_reconciler_skips_oversized_flow():
    """run_langflow_discovery skips flows with bodies over MAX_FLOW_BYTES (Laura F9)."""
    store = _make_store()
    audit = MagicMock()

    # One huge flow (graph_data exceeding MAX_FLOW_BYTES)
    huge_graph = "x" * (MAX_FLOW_BYTES + 1)
    flows = [
        {"id": "flow-small", "name": "Small", "data": {}},
        {"id": "flow-huge", "name": "Huge", "data": {"nodes": huge_graph}},
    ]

    with patch(
        "yashigani.backoffice.langflow_reconciler._fetch_flows",
        return_value=flows,
    ):
        result = run_langflow_discovery(
            registry_store=store,
            audit_writer=audit,
        )

    # At least one flow must have been skipped as oversized
    assert result["skipped_oversized"] >= 1


# ---------------------------------------------------------------------------
# Test 8: XSS payload in flow name stored raw (B4 — encoding at render, not input)
# ---------------------------------------------------------------------------

def test_xss_payload_in_flow_name_stored_raw():
    """Flow names with XSS payloads are stored raw; encoding is the UI layer's job (B4).

    The reconciler must NOT HTML-strip or escape flow names at input time.
    Output encoding (textContent semantics via Lit html``) is enforced in
    agent-policies.js, not here.  Stripping at input is a bypass risk (double-decode).
    """
    store = _make_store()
    audit = MagicMock()

    xss_name = '<script>alert("xss")</script>'
    flows = [
        {"id": "flow-xss-001", "name": xss_name, "data": {"nodes": []}},
    ]

    with patch(
        "yashigani.backoffice.langflow_reconciler._fetch_flows",
        return_value=flows,
    ):
        run_langflow_discovery(
            registry_store=store,
            audit_writer=audit,
        )

    # The flow name must be stored raw — HTML encoding must NOT happen at input
    records = list(store._descriptors.values())
    assert len(records) == 1
    stored_name = records[0]["langflow_flow_name"]

    # Must contain the angle bracket characters (raw storage)
    assert "<" in stored_name, (
        "Flow name must be stored raw (context-aware output encoding happens at the "
        "UI render layer via Lit html`` — input-stripping bypasses double-decode risk)"
    )
    assert "script" in stored_name, "XSS payload must be stored verbatim, not stripped"

    # Must NOT have been HTML-entity-escaped by the reconciler
    assert "&lt;" not in stored_name, (
        "Reconciler must not HTML-escape at input — that is the UI render layer's job (B4)"
    )


# ---------------------------------------------------------------------------
# Additional: R2 LKG cache
# ---------------------------------------------------------------------------

def test_r2_lkg_cache_falls_back_on_redis_failure():
    """_get_claimed_spiffes_lkg falls back to last-good snapshot on transient failure (R2)."""
    import yashigani.backoffice.routes.agent_policies as ap

    # Seed the module-level LKG cache with a known set
    known_spiffes = frozenset(["spiffe://yashigani.internal/langflow"])
    with ap._lkg_claimed_lock:
        ap._lkg_claimed_spiffes = known_spiffes

    # Store that raises on get_claimed_egress_seed_spiffes
    store = MagicMock()
    store.get_claimed_egress_seed_spiffes.side_effect = RuntimeError("Redis down")

    result = _get_claimed_spiffes_lkg(store)

    # Must return the last-known-good snapshot, not raise or return empty
    assert result == known_spiffes, (
        "R2: transient Redis failure must return LKG snapshot, not empty set or raise"
    )


def test_r2_lkg_cache_updates_on_success():
    """_get_claimed_spiffes_lkg updates the cache on successful read."""
    import yashigani.backoffice.routes.agent_policies as ap

    # Reset cache
    with ap._lkg_claimed_lock:
        ap._lkg_claimed_spiffes = frozenset()

    new_spiffes = frozenset(["spiffe://yashigani.internal/openclaw"])

    store = MagicMock()
    store.get_claimed_egress_seed_spiffes.return_value = new_spiffes

    result = _get_claimed_spiffes_lkg(store)

    assert result == new_spiffes
    with ap._lkg_claimed_lock:
        assert ap._lkg_claimed_spiffes == new_spiffes, "LKG must be updated after successful read"


# ---------------------------------------------------------------------------
# Additional: compute_graph_hash (Nico Q-N3)
# ---------------------------------------------------------------------------

def test_compute_graph_hash_strips_noise_keys():
    """Noise keys (position, viewport, ts, …) are stripped before hashing."""
    flow_with_noise = {
        "data": {
            "nodes": [{"type": "llm", "position": {"x": 100, "y": 200}, "id": "n1"}],
            "edges": [],
            "viewport": {"x": 0, "y": 0, "zoom": 1},
        }
    }
    flow_without_noise = {
        "data": {
            "nodes": [{"type": "llm"}],
            "edges": [],
        }
    }
    h1 = compute_graph_hash(flow_with_noise)
    h2 = compute_graph_hash(flow_without_noise)
    assert h1 == h2, "Noise keys must be stripped; hash must be identical after stripping"
    assert h1.startswith("sha256:")


def test_compute_graph_hash_detects_structural_change():
    """A structural change (different node type) must produce a different hash."""
    flow_a = {"data": {"nodes": [{"type": "llm"}]}}
    flow_b = {"data": {"nodes": [{"type": "mcp_tool"}]}}
    assert compute_graph_hash(flow_a) != compute_graph_hash(flow_b)


def test_compute_graph_hash_stable_across_runs():
    """compute_graph_hash must be deterministic (canonical JSON, sorted keys)."""
    flow = {"data": {"b": 2, "a": 1, "nodes": [{"z": 9, "a": 1}]}}
    h1 = compute_graph_hash(flow)
    h2 = compute_graph_hash(flow)
    assert h1 == h2


# ---------------------------------------------------------------------------
# Additional: _resolve_bundled_spiffe (Nico gap-4)
# ---------------------------------------------------------------------------

def test_resolve_bundled_spiffe_uses_env_var(monkeypatch):
    """_resolve_bundled_spiffe reads YASHIGANI_<SYSTEM>_SPIFFE_ID first (Nico gap-4)."""
    monkeypatch.setenv("YASHIGANI_OPENCLAW_SPIFFE_ID", "spiffe://custom.domain/openclaw")
    result = _resolve_bundled_spiffe("openclaw")
    assert result == "spiffe://custom.domain/openclaw"


def test_resolve_bundled_spiffe_falls_back_to_derived(monkeypatch):
    """Falls back to spiffe://<trust_domain>/<system> when env var is absent."""
    monkeypatch.delenv("YASHIGANI_LANGFLOW_SPIFFE_ID", raising=False)
    result = _resolve_bundled_spiffe("langflow")
    assert result.startswith("spiffe://")
    assert result.endswith("/langflow")


# ---------------------------------------------------------------------------
# R2 integration test: real build_egress_grants_doc + LKG wiring
# ---------------------------------------------------------------------------

def test_r2_lkg_suppresses_revoked_spiffe_on_transient_failure(monkeypatch):
    """R2 integration: real build_egress_grants_doc uses LKG-resolved claimed set.

    Drives the REAL build_egress_grants_doc (NOT patched to {}).

    Scenario: openclaw SPIFFE was previously claimed (put_egress_grant was called).
    Admin revokes the grant (delete_egress_grant).  During the subsequent OPA push,
    get_claimed_egress_seed_spiffes raises (transient Redis failure).
    _get_claimed_spiffes_lkg falls back to the LKG snapshot → returns the
    claimed set including openclaw's SPIFFE → build_egress_grants_doc suppresses
    the openclaw seed entry → OPA doc does NOT contain openclaw's SPIFFE.

    This is the R2 wiring fix: without it, build_egress_grants_doc would drop
    suppression on the transient failure and resurface the revoked seed grant.
    """
    import yashigani.backoffice.routes.agent_policies as ap
    from yashigani.mcp._egress_grants import build_egress_grants_doc

    openclaw_spiffe = "spiffe://yashigani.test.r2/openclaw"
    langflow_spiffe = "spiffe://yashigani.test.r2/langflow"
    letta_spiffe = "spiffe://yashigani.test.r2/letta"

    monkeypatch.setenv("YASHIGANI_OPENCLAW_SPIFFE_ID", openclaw_spiffe)
    monkeypatch.setenv("YASHIGANI_LANGFLOW_SPIFFE_ID", langflow_spiffe)
    monkeypatch.setenv("YASHIGANI_LETTA_SPIFFE_ID", letta_spiffe)
    monkeypatch.setenv("YASHIGANI_TENANT_ID", "r2-test")

    # Prime the LKG: openclaw was claimed (a prior successful read saw it)
    with ap._lkg_claimed_lock:
        ap._lkg_claimed_spiffes = frozenset([openclaw_spiffe])

    # Store: transient Redis failure on get_claimed_egress_seed_spiffes.
    # No grants remain (admin already deleted openclaw's grant).
    store = MagicMock()
    store.get_claimed_egress_seed_spiffes.side_effect = RuntimeError(
        "Redis transient: ECONNRESET"
    )
    store.build_egress_grants_data.return_value = {}  # grant deleted

    # _get_claimed_spiffes_lkg must return LKG (containing openclaw) on failure
    claimed = ap._get_claimed_spiffes_lkg(store)
    assert openclaw_spiffe in claimed, (
        "R2: LKG must return openclaw SPIFFE on transient get_claimed_egress_seed_spiffes failure"
    )

    # Drive the REAL build_egress_grants_doc with the LKG-resolved claimed set.
    # This is the path that _run_apply and revoke_grant now take (Fix 1).
    doc = build_egress_grants_doc(store, claimed_spiffes=claimed)

    # CRITICAL: openclaw's seed entry must be suppressed (revoke enforced)
    assert openclaw_spiffe not in doc, (
        f"R2: revoked openclaw SPIFFE {openclaw_spiffe!r} must remain suppressed "
        "from the transitional seed even when get_claimed_egress_seed_spiffes fails "
        "(transient Redis failure must NOT drop suppression to fail-open)"
    )

    # langflow and letta seeds must still be present (not claimed/revoked)
    assert langflow_spiffe in doc, (
        "langflow unclaimed seed must not be suppressed"
    )
    assert letta_spiffe in doc, (
        "letta unclaimed seed must not be suppressed"
    )

    # Verify the function used claimed_spiffes (not the store call)
    store.get_claimed_egress_seed_spiffes.assert_called_once()  # called by _get_claimed_spiffes_lkg
    # build_egress_grants_doc itself must NOT have called get_claimed_egress_seed_spiffes
    # again (it uses the passed claimed_spiffes parameter instead)
    assert store.get_claimed_egress_seed_spiffes.call_count == 1, (
        "build_egress_grants_doc must not call get_claimed_egress_seed_spiffes when "
        "claimed_spiffes is provided — exactly one call (from _get_claimed_spiffes_lkg)"
    )


# ---------------------------------------------------------------------------
# Fix 2: requires_acknowledgement fail-closed gate (Nico latent bypass)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_requires_acknowledgement_active_entry_rejected_at_apply(monkeypatch):
    """Active entry with requires_acknowledgement:true → 422 before any grant write (Nico)."""
    from fastapi import HTTPException

    monkeypatch.setenv("YASHIGANI_TENANT_ID", "acme")
    monkeypatch.setenv("YASHIGANI_LANGFLOW_SPIFFE_ID", "spiffe://yashigani.internal/langflow")

    # Template with an active (enabled, not track_2_only) entry requiring acknowledgement
    tmpl = _make_minimal_template(
        template_id="tmpl-ack-gate-test",
        applies_to="langflow",
        egress_entries=[
            {"prefix": "llm", "mode": "reverse_proxy", "ceiling": "PUBLIC"},
            {
                "prefix": "slack",
                "mode": "reverse_proxy",
                "enabled": True,
                # NOT track_2_only — this is an active entry
                "requires_acknowledgement": True,
            },
        ],
    )
    store = _make_store()
    body = ApplyTemplateRequest(template_id="tmpl-ack-gate-test")
    session = _make_session()

    from yashigani.backoffice.routes import agent_policies as ap

    mock_state = MagicMock()
    mock_state.audit_writer = None
    mock_state.mcp_registry_store = None

    with (
        patch.object(ap, "_registry_store", return_value=store),
        patch.object(ap, "_load_templates", return_value={"tmpl-ack-gate-test": tmpl}),
        patch.object(ap, "backoffice_state", mock_state),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await ap._run_apply("acme", "langflow", body, session)

    assert exc_info.value.status_code == 422
    assert "acknowledgement_ceremony_required" in str(exc_info.value.detail)

    # No grant must have been written (fail-closed = reject BEFORE grant write)
    assert "acme:langflow" not in store._grants, (
        "requires_acknowledgement gate must reject BEFORE any grant write"
    )


@pytest.mark.asyncio
async def test_requires_acknowledgement_inert_entry_skipped_at_apply(monkeypatch):
    """track_2_only/disabled entries with requires_acknowledgement are skipped — NOT rejected.

    The openclaw slack entry is track_2_only AND enabled:false AND requires_acknowledgement.
    It must not trigger the fail-closed gate; the template's enabled Mode-A entries apply.
    """
    monkeypatch.setenv("YASHIGANI_TENANT_ID", "acme")
    monkeypatch.setenv("YASHIGANI_OPENCLAW_SPIFFE_ID", "spiffe://yashigani.internal/openclaw")

    # In-memory representation of the openclaw template structure
    openclaw_tmpl = _make_minimal_template(
        template_id="tmpl-openclaw-default",
        applies_to="openclaw",
        egress_entries=[
            {"prefix": "llm", "mode": "reverse_proxy", "ceiling": "PUBLIC", "scan_secrets": True},
            {"prefix": "telegram", "mode": "reverse_proxy", "ceiling": "PUBLIC", "scan_secrets": True},
            {
                "prefix": "slack",
                "mode": "connect",
                "track_2_only": True,
                "enabled": False,
                "requires_acknowledgement": True,
                "connect_hosts": ["slack.com:443", "hooks.slack.com:443"],
            },
        ],
    )
    store = _make_store()
    body = ApplyTemplateRequest(template_id="tmpl-openclaw-default")
    session = _make_session()

    from yashigani.backoffice.routes import agent_policies as ap

    mock_state = MagicMock()
    mock_state.audit_writer = None
    mock_state.mcp_registry_store = None

    with (
        patch.object(ap, "_registry_store", return_value=store),
        patch.object(ap, "_load_templates", return_value={"tmpl-openclaw-default": openclaw_tmpl}),
        patch.object(ap, "backoffice_state", mock_state),
        patch("yashigani.mcp._opa_push.push_and_verify_egress_grants"),
        patch("yashigani.mcp._egress_grants.build_egress_grants_doc", return_value={}),
    ):
        result = await ap._run_apply("acme", "openclaw", body, session)

    # Mode-A grants must be written
    grant = store._grants.get("acme:openclaw")
    assert grant is not None, "Grant must be written for openclaw"
    assert "llm" in grant["prefixes"], "llm (Mode A) must be in granted prefixes"
    assert "telegram" in grant["prefixes"], "telegram (Mode A) must be in granted prefixes"

    # Mode-B connect (slack) must NOT appear in granted prefixes
    assert "slack" not in grant["prefixes"], (
        "slack (Mode B / track_2_only / disabled) must NOT be in granted prefixes"
    )

    assert result["status"] == "applied"


# ---------------------------------------------------------------------------
# Additional: template applies_to mismatch → 422
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_apply_rejects_template_mismatch(monkeypatch):
    """Applying a template for the wrong system → 422 template_mismatch."""
    from fastapi import HTTPException

    monkeypatch.setenv("YASHIGANI_TENANT_ID", "acme")
    monkeypatch.setenv("YASHIGANI_OPENCLAW_SPIFFE_ID", "spiffe://yashigani.internal/openclaw")

    tmpl = _make_minimal_template(template_id="tmpl-openclaw-default", applies_to="openclaw")
    store = _make_store()

    from yashigani.backoffice.routes import agent_policies as ap

    mock_state = MagicMock()
    mock_state.audit_writer = None
    mock_state.mcp_registry_store = None

    with (
        patch.object(ap, "_registry_store", return_value=store),
        patch.object(ap, "_load_templates", return_value={"tmpl-openclaw-default": tmpl}),
        patch.object(ap, "backoffice_state", mock_state),
    ):
        body = ApplyTemplateRequest(template_id="tmpl-openclaw-default")

        with pytest.raises(HTTPException) as exc_info:
            await ap._run_apply("acme", "langflow", body, _make_session())  # wrong system

    assert exc_info.value.status_code == 422
    assert "template_mismatch" in str(exc_info.value.detail)
