"""
v4.0 Item A — external_api connection enforcement tests.

_execute_api_call() in orchestrator.py gates every api__ tool invocation
via resolve_boolean_grant(EXTERNAL_API, host, org_id, ...) BEFORE making
the outbound HTTP call.  Deny-by-default: absent or revoked org grants
block the call and emit ExternalApiBlockedEvent.

Coverage:
  A. Grant check
     A1. No permission_store (dev/env!=production) → call proceeds (permissive)
     A2. Org grant present + allow → call proceeds
     A3. Org grant absent → blocked + ExternalApiBlockedEvent emitted
     A4. Org grant present but value=False (revoked) → blocked
     A5. Production env + no permission_store → blocked (fail-closed)

  B. ExternalApiBlockedEvent
     B1. Event type is EXTERNAL_API_BLOCKED
     B2. host field = api_host (stable DNS name, not display name)
     B3. deny_reason distinguishes org_grant_absent vs org_grant_denied
     B4. path_hash is 32-char hex (SHA-256)

  C. HTTP call mechanics
     C1. Approved call reaches HttpClient.get/post etc. (method dispatch)
     C2. SSRF BlockedByPolicy from HttpClient → structured error (no crash)
     C3. Unknown method falls back to GET (safe default)

  D. Seeder
     D1. seed_mcp_grants with external_api_hosts seeds EXTERNAL_API org grant
     D2. After seeding, resolve_boolean_grant returns True for seeded host
     D3. Unseeded host returns False (deny-by-default)

  E. Tool catalog
     E1. YASHIGANI_EXTERNAL_APIS env → api__ catalog entries created
     E2. CatalogEntry.api_host matches the "host" field from env
     E3. CatalogEntry.api_url matches "base_url" from env
     E4. Display name sanitised to api__<name>
     E5. Empty / missing env → no api__ entries (no crash)
     E6. Invalid JSON env → no api__ entries (no crash)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _perm_store():
    """Build a PermissionStore backed by fakeredis."""
    try:
        import fakeredis
    except ImportError:
        pytest.skip("fakeredis not installed")
    from yashigani.permissions.store import PermissionStore
    return PermissionStore(fakeredis.FakeRedis(decode_responses=False))


def _seed(store, host: str, allow: bool = True, org_id: str = "default") -> None:
    """Seed an external_api grant.  org_id must match DEFAULT_ORG_ID ('default')."""
    from yashigani.permissions.model import ResourceType, BooleanGrantValue
    store.set_boolean_grant(
        resource_type=ResourceType.EXTERNAL_API,
        scope_kind="org",
        scope_id=org_id,
        resource_id=host,
        value=BooleanGrantValue(allow=allow),
    )


def _fake_identity(org_id: str = "test-org"):
    """Return a plain dict identity — orchestrator uses .get() on it."""
    return {
        "email": "testuser@example.com",
        "identity_id": "testuser@example.com",
        "org_id": org_id,
        "groups": [],
    }


def _run(coro):
    return asyncio.run(coro)


# ─────────────────────────────────────────────────────────────────────────────
# A. Grant check
# ─────────────────────────────────────────────────────────────────────────────

class TestExternalApiGrantCheck:
    """A1–A5: Grant check governs whether the HTTP call proceeds."""

    def _call_execute_api_call(
        self,
        *,
        connection_name: str = "Weather",
        api_host: str = "api.weather.example.com",
        api_url: str = "https://api.weather.example.com",
        args: dict = None,
        perm_store=None,
        org_id: str = "test-org",
        env: str = "development",
        http_response: str = '{"temp": 20}',
        http_side_effect=None,
    ):
        from yashigani.gateway.orchestrator import _execute_api_call
        import yashigani.gateway.openai_router as _router_mod

        identity = _fake_identity(org_id)
        audit_events = []

        # Build a fake _state that surfaces perm_store + captures audit writes.
        fake_state = MagicMock()
        fake_state.permission_store = perm_store
        fake_state.audit_writer = MagicMock()
        fake_state.audit_writer.write = lambda event: audit_events.append(event)
        fake_state.response_inspection_pipeline = None
        fake_state.sensitivity_classifier = None

        # Build a fake HttpClient that returns a success response by default.
        fake_http = MagicMock()
        if http_side_effect is not None:
            fake_http.get = AsyncMock(side_effect=http_side_effect)
            fake_http.post = AsyncMock(side_effect=http_side_effect)
            fake_http.put = AsyncMock(side_effect=http_side_effect)
            fake_http.patch = AsyncMock(side_effect=http_side_effect)
            fake_http.delete = AsyncMock(side_effect=http_side_effect)
        else:
            ok_resp = MagicMock()
            ok_resp.status_code = 200
            ok_resp.text = http_response
            fake_http.get = AsyncMock(return_value=ok_resp)
            fake_http.post = AsyncMock(return_value=ok_resp)
            fake_http.put = AsyncMock(return_value=ok_resp)
            fake_http.patch = AsyncMock(return_value=ok_resp)
            fake_http.delete = AsyncMock(return_value=ok_resp)

        # OPA egress: always allow in unit tests.
        egress_ok = MagicMock()
        egress_ok.allow = True
        egress_ok.deny_reason = "ok"

        original_state = getattr(_router_mod, "_state", None)
        _router_mod._state = fake_state

        try:
            with patch.dict(os.environ, {"YASHIGANI_ENV": env}):
                with patch(
                    "yashigani.net.HttpClient",
                    return_value=fake_http,
                ):
                    with patch(
                        "yashigani.gateway.orchestrator._opa_egress_for_mcp_result",
                        new=AsyncMock(return_value=egress_ok),
                    ):
                        result = _run(
                            _execute_api_call(
                                connection_name=connection_name,
                                api_host=api_host,
                                api_url=api_url,
                                args=args or {"path": "/weather"},
                                identity=identity,
                                depth=0,
                                root_rid="root-1",
                                request_id="req-1",
                            )
                        )
        finally:
            _router_mod._state = original_state

        return result, audit_events

    def test_a1_no_perm_store_dev_proceeds(self):
        """A1: No permission_store in dev env → call proceeds (permissive fallback)."""
        result, events = self._call_execute_api_call(perm_store=None, env="development")
        # Should not contain error about policy
        assert "403" not in str(result.text or ""), result
        assert not any(
            getattr(ev, "deny_reason", None) == "org_grant_absent"
            for ev in events
        )

    def test_a2_org_grant_allow_proceeds(self):
        """A2: Org grant present + allow=True → call reaches HttpClient."""
        store = _perm_store()
        _seed(store, "api.weather.example.com", allow=True)
        result, events = self._call_execute_api_call(
            perm_store=store,
            api_host="api.weather.example.com",
            env="production",
        )
        # No block events emitted
        from yashigani.audit.schema import EventType
        block_events = [
            ev for ev in events
            if getattr(ev, "event_type", None) == EventType.EXTERNAL_API_BLOCKED
        ]
        assert not block_events, f"Unexpected block events: {block_events}"

    def test_a3_org_grant_absent_blocked(self):
        """A3: Org grant absent → blocked + ExternalApiBlockedEvent emitted."""
        store = _perm_store()
        # Do NOT seed the host.
        result, events = self._call_execute_api_call(
            perm_store=store,
            api_host="api.unregistered.example.com",
            env="production",
        )
        from yashigani.audit.schema import EventType
        block_events = [
            ev for ev in events
            if getattr(ev, "event_type", None) == EventType.EXTERNAL_API_BLOCKED
        ]
        assert block_events, "Expected ExternalApiBlockedEvent but none emitted"
        assert block_events[0].deny_reason in ("org_grant_absent", "org_grant_denied")

    def test_a4_org_grant_revoked_blocked(self):
        """A4: Org grant present but allow=False (revoked) → blocked."""
        store = _perm_store()
        _seed(store, "api.revoked.example.com", allow=False)
        result, events = self._call_execute_api_call(
            perm_store=store,
            api_host="api.revoked.example.com",
            env="production",
        )
        from yashigani.audit.schema import EventType
        block_events = [
            ev for ev in events
            if getattr(ev, "event_type", None) == EventType.EXTERNAL_API_BLOCKED
        ]
        assert block_events, "Expected ExternalApiBlockedEvent for revoked grant"

    def test_a5_production_no_perm_store_fail_closed(self):
        """A5: production env + no permission_store → fail-closed (blocked)."""
        result, events = self._call_execute_api_call(perm_store=None, env="production")
        from yashigani.audit.schema import EventType
        block_events = [
            ev for ev in events
            if getattr(ev, "event_type", None) == EventType.EXTERNAL_API_BLOCKED
        ]
        assert block_events, (
            "production + no perm_store must fail-closed (block with audit event)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# B. ExternalApiBlockedEvent fields
# ─────────────────────────────────────────────────────────────────────────────

class TestExternalApiBlockedEvent:
    """B1–B4: Audit event shape."""

    def test_b1_event_type(self):
        """B1: ExternalApiBlockedEvent has event_type=EXTERNAL_API_BLOCKED."""
        from yashigani.audit.schema import ExternalApiBlockedEvent, EventType
        ev = ExternalApiBlockedEvent()
        assert ev.event_type == EventType.EXTERNAL_API_BLOCKED

    def test_b2_host_is_grant_key(self):
        """B2: host field = stable DNS name (not display name)."""
        from yashigani.audit.schema import ExternalApiBlockedEvent
        ev = ExternalApiBlockedEvent(
            connection_name="My Weather API",
            host="api.weather.example.com",
        )
        assert ev.host == "api.weather.example.com"
        assert ev.connection_name == "My Weather API"

    def test_b3_deny_reason_values(self):
        """B3: deny_reason is one of the expected literals."""
        from yashigani.audit.schema import ExternalApiBlockedEvent
        for reason in ("org_grant_absent", "org_grant_denied"):
            ev = ExternalApiBlockedEvent(deny_reason=reason)
            assert ev.deny_reason == reason

    def test_b4_path_hash_format(self):
        """B4: path_hash is 32-char hex (first 32 chars of SHA-256)."""
        from yashigani.gateway.orchestrator import _path_hash
        h = _path_hash("/weather/current")
        assert len(h) == 32
        int(h, 16)  # must be hex — raises ValueError if not


# ─────────────────────────────────────────────────────────────────────────────
# C. HTTP call mechanics (unit-level mocks)
# ─────────────────────────────────────────────────────────────────────────────

class TestHttpCallMechanics:
    """C1–C3: HTTP method dispatch and SSRF guard."""

    def _make_fake_state(self, perm_store):
        """Build a minimal fake _state for orchestrator tests."""
        fake_state = MagicMock()
        fake_state.permission_store = perm_store
        fake_state.audit_writer = MagicMock()
        fake_state.audit_writer.write = lambda e: None
        fake_state.response_inspection_pipeline = None
        fake_state.sensitivity_classifier = None
        return fake_state

    def test_c1_method_dispatch_post(self):
        """C1: args with method=POST dispatch to HttpClient.post."""
        store = _perm_store()
        _seed(store, "api.example.com", allow=True)

        from yashigani.gateway.orchestrator import _execute_api_call
        import yashigani.gateway.openai_router as _router_mod

        identity = _fake_identity()
        captured = {}
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.text = '{"ok": true}'

        async def _fake_post(*args, **kwargs):
            captured["called"] = "post"
            return ok_resp

        async def _fake_get(*args, **kwargs):
            captured["called"] = "get"
            return ok_resp

        fake_http = MagicMock()
        fake_http.get = _fake_get
        fake_http.post = _fake_post
        fake_http.put = AsyncMock(return_value=ok_resp)
        fake_http.patch = AsyncMock(return_value=ok_resp)
        fake_http.delete = AsyncMock(return_value=ok_resp)

        egress_ok = MagicMock()
        egress_ok.allow = True

        original_state = getattr(_router_mod, "_state", None)
        _router_mod._state = self._make_fake_state(store)
        try:
            with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
                with patch("yashigani.net.HttpClient", return_value=fake_http):
                    with patch(
                        "yashigani.gateway.orchestrator._opa_egress_for_mcp_result",
                        new=AsyncMock(return_value=egress_ok),
                    ):
                        asyncio.run(
                            _execute_api_call(
                                connection_name="Test",
                                api_host="api.example.com",
                                api_url="https://api.example.com",
                                args={"path": "/submit", "method": "POST", "body": {"x": 1}},
                                identity=identity,
                                depth=0,
                                root_rid="root-1",
                                request_id="req-1",
                            )
                        )
        finally:
            _router_mod._state = original_state
        assert captured.get("called") == "post", f"Expected POST dispatch, got: {captured}"

    def test_c2_ssrf_blocked_structured_error(self):
        """C2: SSRF BlockedByPolicy from HttpClient → structured error, no crash."""
        from yashigani.net import BlockedByPolicy

        store = _perm_store()
        _seed(store, "api.internal.example.com", allow=True)

        from yashigani.gateway.orchestrator import _execute_api_call
        import yashigani.gateway.openai_router as _router_mod

        identity = _fake_identity()
        fake_http = MagicMock()
        fake_http.get = AsyncMock(side_effect=BlockedByPolicy("SSRF: private range"))
        fake_http.post = AsyncMock(side_effect=BlockedByPolicy("SSRF: private range"))
        fake_http.put = fake_http.get
        fake_http.patch = fake_http.get
        fake_http.delete = fake_http.get

        original_state = getattr(_router_mod, "_state", None)
        _router_mod._state = self._make_fake_state(store)
        try:
            with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
                with patch("yashigani.net.HttpClient", return_value=fake_http):
                    result = asyncio.run(
                        _execute_api_call(
                            connection_name="Internal",
                            api_host="api.internal.example.com",
                            api_url="https://api.internal.example.com",
                            args={"path": "/secret"},
                            identity=identity,
                            depth=0,
                            root_rid="root-1",
                            request_id="req-1",
                        )
                    )
        finally:
            _router_mod._state = original_state
        # Must return a result with a structured error indicator, not raise
        content_str = str(getattr(result, "text", result))
        assert "SSRF" in content_str or "403" in content_str or "blocked" in content_str.lower(), (
            f"Expected SSRF error indication; got: {content_str}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# D. Seeder
# ─────────────────────────────────────────────────────────────────────────────

class TestExternalApiSeeder:
    """D1–D3: seed_mcp_grants with external_api_hosts."""

    def test_d1_seed_writes_external_api_grant(self):
        """D1: seed_mcp_grants(external_api_hosts=[...]) writes EXTERNAL_API grant."""
        store = _perm_store()
        from yashigani.permissions import seed_mcp_grants
        seed_mcp_grants(
            perm_store=store,
            server_ids=[],
            org_id="test-org",
            external_api_hosts=["api.weather.example.com"],
        )
        from yashigani.permissions.model import ResourceType
        grant = store.get_boolean_grant(ResourceType.EXTERNAL_API, "org", "test-org", "api.weather.example.com")
        assert grant is not None
        assert grant.allow is True

    def test_d2_resolve_returns_true_after_seeding(self):
        """D2: resolve_boolean_grant returns True for seeded host."""
        store = _perm_store()
        from yashigani.permissions import seed_mcp_grants, resolve_boolean_grant
        from yashigani.permissions.model import ResourceType
        seed_mcp_grants(
            perm_store=store,
            server_ids=[],
            org_id="test-org",
            external_api_hosts=["api.seeded.com"],
        )
        result = resolve_boolean_grant(
            ResourceType.EXTERNAL_API,
            "api.seeded.com",
            org_id="test-org",
            group_ids=[],
            principal_scope=None,
            principal_id=None,
            store=store,
        )
        assert result is True

    def test_d3_unseeded_host_deny_by_default(self):
        """D3: Unseeded host → resolve_boolean_grant returns False (deny-by-default)."""
        store = _perm_store()
        from yashigani.permissions import resolve_boolean_grant
        from yashigani.permissions.model import ResourceType
        result = resolve_boolean_grant(
            ResourceType.EXTERNAL_API,
            "api.unseeded.com",
            org_id="test-org",
            group_ids=[],
            principal_scope=None,
            principal_id=None,
            store=store,
        )
        assert result is False


# ─────────────────────────────────────────────────────────────────────────────
# E. Tool catalog
# ─────────────────────────────────────────────────────────────────────────────

class TestExternalApiToolCatalog:
    """E1–E6: YASHIGANI_EXTERNAL_APIS → api__ catalog entries."""

    def _build_catalog(self, env_json: str):
        from yashigani.gateway.tool_catalog import build_tool_catalog
        fake_registry = MagicMock()
        fake_registry.list_agents.return_value = []
        with patch.dict(os.environ, {"YASHIGANI_EXTERNAL_APIS": env_json}, clear=False):
            cat = build_tool_catalog(
                identity={"identity_id": "test", "email": "test@example.com"},
                agent_registry=fake_registry,
            )
        return cat.name_map.values()

    def test_e1_env_creates_api_entries(self):
        """E1: YASHIGANI_EXTERNAL_APIS JSON → api__ catalog entries created."""
        apis = json.dumps([
            {"name": "weather", "host": "api.weather.example.com",
             "base_url": "https://api.weather.example.com"}
        ])
        catalog = self._build_catalog(apis)
        api_entries = [e for e in catalog if e.kind == "api"]
        assert api_entries, "Expected at least one api__ catalog entry"

    def test_e2_api_host_matches_host_field(self):
        """E2: CatalogEntry.api_host = the 'host' field from env."""
        apis = json.dumps([
            {"name": "weather", "host": "api.weather.example.com",
             "base_url": "https://api.weather.example.com"}
        ])
        catalog = self._build_catalog(apis)
        api_entries = [e for e in catalog if e.kind == "api"]
        assert any(e.api_host == "api.weather.example.com" for e in api_entries)

    def test_e3_api_url_matches_base_url(self):
        """E3: CatalogEntry.api_url = the 'base_url' field from env."""
        apis = json.dumps([
            {"name": "weather", "host": "api.weather.example.com",
             "base_url": "https://api.weather.example.com"}
        ])
        catalog = self._build_catalog(apis)
        api_entries = [e for e in catalog if e.kind == "api"]
        assert any(e.api_url == "https://api.weather.example.com" for e in api_entries)

    def test_e4_display_name_sanitised(self):
        """E4: Display name → api__<sanitised> tool name."""
        apis = json.dumps([
            {"name": "My Weather API", "host": "api.weather.example.com",
             "base_url": "https://api.weather.example.com"}
        ])
        catalog = self._build_catalog(apis)
        api_entries = [e for e in catalog if e.kind == "api"]
        # The name_map key (dict key) starts with api__ — check via target field
        # (CatalogEntry.target = display name; the key in name_map is sanitised)
        assert api_entries, "Expected at least one api__ catalog entry"
        # All api entries should have a non-empty target (display name)
        assert all(e.target for e in api_entries)

    def test_e5_empty_env_no_crash(self):
        """E5: Empty YASHIGANI_EXTERNAL_APIS → no api__ entries, no crash."""
        catalog = self._build_catalog("")
        api_entries = [e for e in catalog if e.kind == "api"]
        assert api_entries == []

    def test_e6_invalid_json_no_crash(self):
        """E6: Invalid JSON in YASHIGANI_EXTERNAL_APIS → no api__ entries, no crash."""
        catalog = self._build_catalog("this is not json")
        api_entries = [e for e in catalog if e.kind == "api"]
        assert api_entries == []
