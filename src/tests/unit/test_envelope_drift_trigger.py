"""
3.1 / YSG-RISK-060 FULL-CLOSE — capability-envelope drift-detection wiring test.

Verifies the two runtime seams that were previously design-only:

  Seam A — pending_block_sink injection (registry.py → McpBrokerConfig):
    When build_registry_from_env receives a pending_store, each broker is wired
    with a pending_block_sink closure that calls pending_store.record_block(...)
    on EXPANDING / UNCERTAIN drift.

  Seam B — refresh_and_triage_tools trigger (mcp_router_runtime.py tools/list path):
    When an external client issues a tools/list request for a pinned server whose
    tool surface has DRIFTED from the approved baseline, dispatch_mcp_call():
      1. Calls broker.refresh_and_triage_tools(agent_name, raw_tools).
      2. The broker latches a block (latch_block awaited on the envelope_service).
      3. The pending_block_sink fires → pending_store.record_block() is called.
      4. store.list_for_tenant(tenant) returns the pending entry.
    The no-drift case (identical surface) writes nothing.

  Cross-process coherency (envelope_pending_store._refresh_from_redis):
    list_for_tenant and get always reload from Redis so gateway-written entries
    are visible to a backoffice-side store instance without restart.

Run:
  cd /path/to/yashigani
  uv run pytest src/tests/unit/test_envelope_drift_trigger.py -q

Last updated: 2026-07-01
"""
from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import pytest

from yashigani.mcp._envelope import compute_provenance_id, project_surface
from yashigani.mcp.broker import McpBroker, McpBrokerConfig
from yashigani.mcp.envelope_pending_store import EnvelopePendingStore
from yashigani.mcp.envelope_service import EnvelopeRecord
from yashigani.mcp import UpstreamPinConfig

TENANT = "default"
SERVER = "github-mcp"
PROV = compute_provenance_id(SERVER, "sha256:deadbeef")


# ── Shared tool fixtures ────────────────────────────────────────────────────

def _tool(name: str, *, effect: str = "READ", props: dict | None = None) -> dict:
    schema = {"type": "object", "properties": props or {}, "additionalProperties": False}
    raw: dict = {"name": name, "description": f"{name} tool", "inputSchema": schema}
    if effect in ("WRITE", "EXEC"):
        raw["annotations"] = {"destructiveHint": True}
    return raw


BASELINE_TOOLS = [_tool("read_file", props={"path": {"type": "string"}})]
DRIFTED_TOOLS = BASELINE_TOOLS + [
    _tool("delete_file", effect="WRITE", props={"path": {"type": "string"}}),
]


def _baseline_env():
    return project_surface(PROV, TENANT, BASELINE_TOOLS, egress_posture="NONE")


def _envelope_record(env, version: int = 1) -> EnvelopeRecord:
    return EnvelopeRecord(
        id=version,
        provenance_id=PROV,
        tenant_id=TENANT,
        server_id=SERVER,
        envelope_version=version,
        previous_envelope_id=None,
        status="active",
        egress_posture=env.egress_posture,
        surface_set_hash=env.surface_set_hash,
        current_surface_hash=env.surface_set_hash,
        topology="ring_fenced",
        approved_by_operator_identity="admin1",
        approved_at=time.time(),
        envelope=env,
    )


def _stub_envelope_service(base_env=None) -> MagicMock:
    """Stub CapabilityEnvelopeService that returns a real baseline."""
    base = base_env or _baseline_env()
    svc = MagicMock()
    svc.get_baseline_envelope = AsyncMock(return_value=_envelope_record(base, 1))
    svc.get_active_envelope = AsyncMock(return_value=_envelope_record(base, 1))
    svc.latch_block = AsyncMock(return_value=True)
    svc.record_benign_repin = AsyncMock(return_value=True)
    return svc


def _pin() -> UpstreamPinConfig:
    return UpstreamPinConfig(
        server_id=SERVER,
        host="gh",
        port=443,
        cert_fingerprint_sha256="sha256:deadbeef",
    )


# ── Seam A: registry pending_block_sink injection ───────────────────────────

class TestSinkInjection:
    """Seam A — build_registry_from_env wires pending_block_sink when
    pending_store is supplied."""

    def test_registry_wires_sink_when_pending_store_provided(self):
        """When build_registry_from_env receives a pending_store, the brokers
        it builds must have a non-None _pending_block_sink."""
        import os
        fake = fakeredis.FakeStrictRedis()
        store = EnvelopePendingStore(redis_client=fake)

        servers = json.dumps([{
            "agent_name": SERVER,
            "upstream_url": "http://github-mcp:8000",
            "tenant_id": TENANT,
            "cert_fingerprint_sha256": "sha256:deadbeef",
        }])

        from yashigani.mcp.registry import build_registry_from_env
        with patch.dict(os.environ, {"YASHIGANI_MCP_SERVERS": servers}):
            registry, _ = build_registry_from_env(
                opa_url="http://opa:8181",
                pending_store=store,
            )

        brokers = registry.all_brokers()
        assert len(brokers) == 1
        broker = brokers[0]
        assert broker._pending_block_sink is not None, (  # type: ignore[attr-defined]
            "broker must have a pending_block_sink when pending_store is supplied"
        )

    def test_registry_no_sink_when_pending_store_absent(self):
        """When pending_store is None (dev/test), _pending_block_sink stays None."""
        import os
        servers = json.dumps([{
            "agent_name": SERVER,
            "upstream_url": "http://github-mcp:8000",
            "tenant_id": TENANT,
        }])

        from yashigani.mcp.registry import build_registry_from_env
        with patch.dict(os.environ, {"YASHIGANI_MCP_SERVERS": servers}):
            registry, _ = build_registry_from_env(
                opa_url="http://opa:8181",
                pending_store=None,
            )

        brokers = registry.all_brokers()
        assert len(brokers) == 1
        assert brokers[0]._pending_block_sink is None  # type: ignore[attr-defined]


# ── Seam A+broker: broker block populates store ─────────────────────────────

@pytest.mark.asyncio
async def test_broker_expanding_drift_populates_pending_store():
    """When broker.refresh_and_triage_tools detects EXPANDING drift AND a
    pending_block_sink is wired, the sink must write to the store so that
    list_for_tenant returns the pending entry."""
    fake = fakeredis.FakeStrictRedis()
    store = EnvelopePendingStore(redis_client=fake)

    svc = _stub_envelope_service()

    captured: dict = {}

    def _sink(**kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        store.record_block(**kwargs)

    cfg = McpBrokerConfig(
        opa_url="http://opa:8181",
        tenant_id=TENANT,
        upstream_pin_configs=[_pin()],
        envelope_service=svc,
        enforce_capability_envelope=True,
        pending_block_sink=_sink,
        audit_writer=None,
    )
    broker = McpBroker(cfg)

    outcome = await broker.refresh_and_triage_tools(SERVER, DRIFTED_TOOLS, [])

    assert outcome is not None and outcome.should_block, "outcome must be blocking"
    svc.latch_block.assert_awaited_once()

    # Sink must have fired with correct provenance + triage_class.
    assert captured.get("provenance_id") == PROV
    assert captured.get("triage_class") == "expanding"
    assert captured.get("server_id") == SERVER
    assert captured.get("tenant_id") == TENANT

    # The candidate must include BOTH tools (the new expanding tool).
    # Tool keys are provenance_id-prefixed: "<prov>::<name>".
    cand = captured["candidate"]
    assert len(cand.tools) == 2, "candidate must carry both tools"
    assert any("delete_file" in tk for tk in cand.tools)

    # list_for_tenant must return the entry.
    pending = store.list_for_tenant(TENANT)
    assert len(pending) == 1
    assert pending[0]["provenance_id"] == PROV
    assert pending[0]["candidate_tool_count"] == 2
    assert pending[0]["triage_class"] == "expanding"


@pytest.mark.asyncio
async def test_broker_no_drift_does_not_populate_store():
    """When the refreshed surface is identical to the active hash, no pending
    entry is written and latch_block is not called."""
    fake = fakeredis.FakeStrictRedis()
    store = EnvelopePendingStore(redis_client=fake)

    base = _baseline_env()
    svc = _stub_envelope_service(base)

    def _sink(**kwargs):  # type: ignore[no-untyped-def]
        store.record_block(**kwargs)

    cfg = McpBrokerConfig(
        opa_url="http://opa:8181",
        tenant_id=TENANT,
        upstream_pin_configs=[_pin()],
        envelope_service=svc,
        enforce_capability_envelope=True,
        pending_block_sink=_sink,
        audit_writer=None,
    )
    broker = McpBroker(cfg)

    # Refresh with the SAME surface as the active hash → byte-hash identical → no-op.
    # The active mock returns surface_set_hash == base.surface_set_hash.
    outcome = await broker.refresh_and_triage_tools(SERVER, BASELINE_TOOLS, [])

    # No drift → outcome is None (early exit before triage) or BENIGN.
    # Either way, latch_block must NOT have been called.
    svc.latch_block.assert_not_awaited()

    # No pending entry must appear.
    pending = store.list_for_tenant(TENANT)
    assert len(pending) == 0


# ── Cross-process coherency: _refresh_from_redis ───────────────────────────

class TestCrossProcessCoherency:
    """EnvelopePendingStore._refresh_from_redis ensures that an entry written
    by a gateway-side store instance is visible via a backoffice-side instance
    sharing the same Redis connection."""

    def _seed_entry(self, fake_redis: fakeredis.FakeStrictRedis) -> str:
        """Write a pending entry directly into Redis (simulating the gateway)."""
        gateway_store = EnvelopePendingStore(redis_client=fake_redis)
        cand = project_surface(PROV, TENANT, DRIFTED_TOOLS, egress_posture="NONE")
        gateway_store.record_block(
            provenance_id=PROV,
            tenant_id=TENANT,
            server_id=SERVER,
            candidate=cand,
            triage_class="expanding",
            new_surface_hash="h_new",
            findings=[{"dimension": "tool_set", "tool_key": "delete_file", "detail": "new tool"}],
        )
        return PROV

    def test_backoffice_store_sees_gateway_written_entry(self):
        """A second EnvelopePendingStore instance (backoffice) constructed
        BEFORE the gateway writes must still see the entry on list_for_tenant
        because list_for_tenant reloads from Redis."""
        fake = fakeredis.FakeStrictRedis()

        # Construct the "backoffice" store first (empty cache at this point).
        backoffice_store = EnvelopePendingStore(redis_client=fake)
        assert backoffice_store.list_for_tenant(TENANT) == []

        # Now simulate the gateway writing a drift-triggered block.
        self._seed_entry(fake)

        # The backoffice store reloads from Redis on list_for_tenant.
        pending = backoffice_store.list_for_tenant(TENANT)
        assert len(pending) == 1
        assert pending[0]["provenance_id"] == PROV

    def test_get_cross_process_coherency(self):
        """get() also reloads from Redis so the backoffice can fetch the full row
        written by the gateway."""
        fake = fakeredis.FakeStrictRedis()
        backoffice_store = EnvelopePendingStore(redis_client=fake)

        # Initially nothing.
        assert backoffice_store.get(PROV, TENANT) is None

        # Gateway writes.
        self._seed_entry(fake)

        # Backoffice store must return the row via Redis reload.
        row = backoffice_store.get(PROV, TENANT)
        assert row is not None
        assert row["provenance_id"] == PROV
        assert row["triage_class"] == "expanding"

    def test_resolve_clears_across_instances(self):
        """After the backoffice resolves (approve/reject) an entry, the gateway
        store sees it as gone on next reload."""
        fake = fakeredis.FakeStrictRedis()
        self._seed_entry(fake)

        backoffice_store = EnvelopePendingStore(redis_client=fake)
        assert len(backoffice_store.list_for_tenant(TENANT)) == 1

        backoffice_store.resolve(PROV, TENANT)

        # A fresh gateway store sees nothing.
        gateway_store2 = EnvelopePendingStore(redis_client=fake)
        assert gateway_store2.list_for_tenant(TENANT) == []


# ── Seam B: tools/list trigger in runtime router ────────────────────────────

@pytest.mark.asyncio
async def test_tools_list_triggers_drift_triage_and_populates_queue():
    """End-to-end Seam B: an external tools/list call for a drifted pinned server
    causes dispatch_mcp_call to call refresh_and_triage_tools, which populates
    the pending re-approval queue.

    Runtime trigger path:
      External client issues tools/list → dispatch_mcp_call → session branch →
      upstream forward (mocked) → refresh_and_triage_tools(agent_name, tools) →
      broker latches block + sink → pending queue populated.
    """
    from unittest.mock import AsyncMock, MagicMock, patch

    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient
    from yashigani.gateway.mcp_router_runtime import create_mcp_call_router
    from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig

    # Build a real broker with a real EnvelopePendingStore over fakeredis.
    fake = fakeredis.FakeStrictRedis()
    store = EnvelopePendingStore(redis_client=fake)
    svc = _stub_envelope_service()

    def _sink(**kwargs):  # type: ignore[no-untyped-def]
        store.record_block(**kwargs)

    cfg = McpBrokerConfig(
        opa_url="http://opa:8181",
        tenant_id=TENANT,
        upstream_pin_configs=[_pin()],
        envelope_service=svc,
        enforce_capability_envelope=True,
        pending_block_sink=_sink,
        audit_writer=None,
    )
    broker = McpBroker(cfg)

    # The upstream tools/list response (drifted surface).
    tools_list_response = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": DRIFTED_TOOLS,
        },
    })

    # Build a minimal McpBrokerRegistry containing our broker.
    registry = McpBrokerRegistry()
    server_cfg = McpBrokerServerConfig(
        upstream_url="http://github-mcp:8000",
        is_filesystem_agent=False,
        is_git_agent=False,
        tenant_id=TENANT,
        agent_name=SERVER,
    )
    registry.register(SERVER, broker, server_cfg)

    # Patch verify_upstream to be a no-op (no real TLS peer).
    with patch.object(broker, "verify_upstream", return_value=None):
        # Patch McpHttpTransport.forward to return the drifted surface.
        with patch(
            "yashigani.gateway.mcp_router_runtime.McpHttpTransport"
        ) as _MockTransport:
            _mock_transport_instance = MagicMock()
            _mock_transport_instance.__aenter__ = AsyncMock(
                return_value=_mock_transport_instance
            )
            _mock_transport_instance.__aexit__ = AsyncMock(return_value=False)
            _mock_transport_instance.forward = AsyncMock(
                return_value=tools_list_response
            )
            _mock_transport_instance.derive_posture = MagicMock(
                return_value=(
                    __import__(
                        "yashigani.mcp._types", fromlist=["McpPosture"]
                    ).McpPosture.MCP_B,
                    MagicMock(to_dict=MagicMock(return_value={})),
                )
            )
            _MockTransport.return_value = _mock_transport_instance

            # Mount the router and issue the tools/list request.
            app = FastAPI()
            mcp_router = create_mcp_call_router(registry=registry)
            app.include_router(mcp_router)

            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
            client = TestClient(app, raise_server_exceptions=True)
            response = client.post(f"/mcp/{SERVER}", content=body)

    # The tools/list response must have been forwarded (the call succeeds).
    assert response.status_code == 200
    data = response.json()
    assert data.get("result", {}).get("tools") is not None

    # The drift must have been detected and the pending queue populated.
    svc.latch_block.assert_awaited_once()
    pending = store.list_for_tenant(TENANT)
    assert len(pending) == 1, (
        "pending re-approval queue must have exactly one entry after drift"
    )
    assert pending[0]["provenance_id"] == PROV
    assert pending[0]["triage_class"] == "expanding"
    assert pending[0]["candidate_tool_count"] == 2


@pytest.mark.asyncio
async def test_tools_list_no_drift_does_not_populate_queue():
    """A tools/list call with the SAME surface as the approved baseline must NOT
    populate the pending queue and must NOT call latch_block."""
    from unittest.mock import AsyncMock, MagicMock, patch

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from yashigani.gateway.mcp_router_runtime import create_mcp_call_router
    from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig

    fake = fakeredis.FakeStrictRedis()
    store = EnvelopePendingStore(redis_client=fake)
    base = _baseline_env()
    svc = _stub_envelope_service(base)

    def _sink(**kwargs):  # type: ignore[no-untyped-def]
        store.record_block(**kwargs)

    cfg = McpBrokerConfig(
        opa_url="http://opa:8181",
        tenant_id=TENANT,
        upstream_pin_configs=[_pin()],
        envelope_service=svc,
        enforce_capability_envelope=True,
        pending_block_sink=_sink,
        audit_writer=None,
    )
    broker = McpBroker(cfg)

    # Upstream returns the SAME surface as the approved baseline → no drift.
    tools_list_response = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"tools": BASELINE_TOOLS},
    })

    registry = McpBrokerRegistry()
    server_cfg = McpBrokerServerConfig(
        upstream_url="http://github-mcp:8000",
        is_filesystem_agent=False,
        is_git_agent=False,
        tenant_id=TENANT,
        agent_name=SERVER,
    )
    registry.register(SERVER, broker, server_cfg)

    with patch.object(broker, "verify_upstream", return_value=None):
        with patch(
            "yashigani.gateway.mcp_router_runtime.McpHttpTransport"
        ) as _MockTransport:
            _mock_transport_instance = MagicMock()
            _mock_transport_instance.__aenter__ = AsyncMock(
                return_value=_mock_transport_instance
            )
            _mock_transport_instance.__aexit__ = AsyncMock(return_value=False)
            _mock_transport_instance.forward = AsyncMock(
                return_value=tools_list_response
            )
            _mock_transport_instance.derive_posture = MagicMock(
                return_value=(
                    __import__(
                        "yashigani.mcp._types", fromlist=["McpPosture"]
                    ).McpPosture.MCP_B,
                    MagicMock(to_dict=MagicMock(return_value={})),
                )
            )
            _MockTransport.return_value = _mock_transport_instance

            app = FastAPI()
            mcp_router = create_mcp_call_router(registry=registry)
            app.include_router(mcp_router)

            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
            client = TestClient(app, raise_server_exceptions=True)
            response = client.post(f"/mcp/{SERVER}", content=body)

    assert response.status_code == 200
    svc.latch_block.assert_not_awaited()
    assert store.list_for_tenant(TENANT) == []
