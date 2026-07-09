"""
Regression tests — v4.1 F-G (langflow auth) and F-H (flood cap).

Design: AgnosticSecurity/Products/Yashigani/langflow-letta-default-availability-design-20260709.md

Test matrix:
  1. langflow_auth_init_list_delete_create — list→delete→create (Laura constraint 2,
     one-key invariant): verifies auto_login called, existing key deleted, new key returned
  2. langflow_auth_one_key_invariant — multiple existing 'yashigani-service' keys are
     ALL deleted before creating a new one
  3. langflow_auth_cache — second call returns cached key without hitting langflow again
  4. reconciler_uses_x_api_key_not_bearer — _fetch_flows uses x-api-key header, not
     Authorization: Bearer
  5. fh_large_response_discovers_flows — a response > 3.2 MB (old pre-parse cap) but
     with valid per-flow sizes is discovered (not discarded)
  6. fh_oom_guard_fires_above_13mb — response > 13 MiB is still rejected
  7. disclosure_string_in_audit_event — LangflowFlowDiscoveredEvent has egress_attribution
  8. disclosure_in_nhi_residuals — agent_policies row for NHI discovered flow includes
     egress_attribution_note in residuals
"""
from __future__ import annotations

import json
import threading
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_flow(
    flow_id: str | None = None,
    name: str = "test-flow",
    data_size: int = 100,
) -> dict:
    """Build a minimal langflow flow dict under the per-flow size cap."""
    return {
        "id": flow_id or str(uuid.uuid4()),
        "name": name,
        "data": {"nodes": [{"k": "x" * data_size}], "edges": []},
    }


def _make_large_flow_payload(n_flows: int = 52, per_flow_size: int = 63_500) -> bytes:
    """Build a JSON list of flows; each flow is ~per_flow_size bytes, total > 3.2 MB.

    With n_flows=52, per_flow_size=63_500:
      - per-flow JSON ≈ 63,600 bytes < 65,536 (per-flow cap) ✓
      - total ≈ 52 × 63,600 = 3,307,200 bytes > 3,276,800 (old 3.2 MB cap) ✓
      - flow count capped at MAX_FLOWS=50 inside _fetch_flows; 50 flows discovered.

    The old pre-parse total-body cap (50 × 64 KiB = 3,276,800) would have discarded
    this entire response.  The new code (F-H) relies only on the per-flow cap and
    count cap, so the 50 flows within the count cap are discovered.
    """
    flows = []
    for i in range(n_flows):
        flows.append({
            "id": str(uuid.uuid4()),
            "name": f"flow-{i}",
            "data": {"nodes": [{"k": "x" * per_flow_size}], "edges": []},
        })
    raw = json.dumps(flows).encode()
    # Sanity checks: each flow < 64 KiB cap, total > 3.2 MB (old cap = 50 × 64 KiB = 3,276,800)
    per_flow = len(json.dumps(flows[0]).encode())
    assert per_flow < 65536, f"per-flow too large: {per_flow}"
    assert len(raw) > 3_276_800, f"total too small: {len(raw)} — increase per_flow_size"
    return raw


class _FakeResponse:
    def __init__(self, status_code: int = 200, body: Any = None):
        self.status_code = status_code
        self._body = body if body is not None else {}

    def json(self) -> Any:
        return self._body

    @property
    def content(self) -> bytes:
        return json.dumps(self._body).encode() if isinstance(self._body, (dict, list)) else self._body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


class _FakeClient:
    """Minimal fake for internal_httpx_sync_client context manager."""
    def __init__(self, responses: list):
        self._responses = list(responses)
        self._idx = 0
        self.calls: list[tuple[str, str, dict]] = []

    def _next(self, method: str, url: str, **kwargs) -> _FakeResponse:
        self.calls.append((method, url, kwargs))
        resp = self._responses[self._idx]
        self._idx += 1
        return resp

    def get(self, url: str, **kwargs) -> _FakeResponse:
        return self._next("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> _FakeResponse:
        return self._next("POST", url, **kwargs)

    def delete(self, url: str, **kwargs) -> _FakeResponse:
        return self._next("DELETE", url, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


# ---------------------------------------------------------------------------
# Tests: langflow_auth.py (F-G, Laura constraint 2)
# ---------------------------------------------------------------------------

class TestLangflowAuthInit:
    """langflow_auth.py — list → delete → create (one-key invariant)."""

    def setup_method(self):
        # Reset module-level cache before each test
        from yashigani.backoffice import langflow_auth
        langflow_auth._reset_cache_for_testing()

    def _responses_no_existing_key(self) -> list:
        """auto_login + list (empty) + create."""
        return [
            _FakeResponse(200, {"access_token": "session-tok"}),  # auto_login
            _FakeResponse(200, []),                                 # list keys (empty)
            _FakeResponse(200, {"api_key": "new-api-key-abc"}),   # create key
        ]

    def _responses_one_existing_key(self, key_id: str = "key-id-1") -> list:
        """auto_login + list (1 existing key) + delete + create."""
        return [
            _FakeResponse(200, {"access_token": "session-tok"}),
            _FakeResponse(200, [{"id": key_id, "name": "yashigani-service"}]),
            _FakeResponse(200, {}),                                  # delete
            _FakeResponse(200, {"api_key": "fresh-key-xyz"}),       # create
        ]

    def _responses_two_existing_keys(self) -> list:
        """auto_login + list (2 existing keys) + 2 deletes + create."""
        return [
            _FakeResponse(200, {"access_token": "session-tok"}),
            _FakeResponse(200, [
                {"id": "key-id-1", "name": "yashigani-service"},
                {"id": "key-id-2", "name": "yashigani-service"},
                {"id": "other-id",  "name": "other-key"},           # different name → not deleted
            ]),
            _FakeResponse(200, {}),                                  # delete key-id-1
            _FakeResponse(200, {}),                                  # delete key-id-2
            _FakeResponse(200, {"api_key": "fresh-key-xyz"}),       # create
        ]

    def test_init_no_existing_key(self, monkeypatch):
        """Happy path: no existing key → auto_login + create (no delete)."""
        client = _FakeClient(self._responses_no_existing_key())

        monkeypatch.setenv("YASHIGANI_LANGFLOW_INTERNAL_URL", "http://langflow:7860")
        with patch("yashigani.pki.client.internal_httpx_sync_client", return_value=client):
            from yashigani.backoffice.langflow_auth import get_langflow_api_headers
            headers = get_langflow_api_headers()

        assert headers == {"x-api-key": "new-api-key-abc"}
        methods = [c[0] for c in client.calls]
        assert methods == ["GET", "GET", "POST"], f"expected [GET,GET,POST], got {methods}"
        # No DELETE
        assert not any(m == "DELETE" for m in methods)

    def test_init_one_existing_key_is_deleted(self, monkeypatch):
        """Existing 'yashigani-service' key is deleted before creating new one."""
        key_id = "key-id-1"
        client = _FakeClient(self._responses_one_existing_key(key_id))

        monkeypatch.setenv("YASHIGANI_LANGFLOW_INTERNAL_URL", "http://langflow:7860")
        with patch("yashigani.pki.client.internal_httpx_sync_client", return_value=client):
            from yashigani.backoffice.langflow_auth import get_langflow_api_headers
            headers = get_langflow_api_headers()

        assert headers == {"x-api-key": "fresh-key-xyz"}
        methods = [c[0] for c in client.calls]
        # GET(auto_login) + GET(list) + DELETE(key-id-1) + POST(create)
        assert methods == ["GET", "GET", "DELETE", "POST"], methods
        delete_url = client.calls[2][1]
        assert key_id in delete_url, f"DELETE URL {delete_url!r} should contain {key_id!r}"

    def test_init_two_existing_keys_both_deleted(self, monkeypatch):
        """ALL existing 'yashigani-service' keys are deleted (one-key invariant)."""
        client = _FakeClient(self._responses_two_existing_keys())

        monkeypatch.setenv("YASHIGANI_LANGFLOW_INTERNAL_URL", "http://langflow:7860")
        with patch("yashigani.pki.client.internal_httpx_sync_client", return_value=client):
            from yashigani.backoffice.langflow_auth import get_langflow_api_headers
            headers = get_langflow_api_headers()

        assert headers == {"x-api-key": "fresh-key-xyz"}
        methods = [c[0] for c in client.calls]
        # GET + GET + DELETE + DELETE + POST — 'other-key' is NOT deleted
        assert methods == ["GET", "GET", "DELETE", "DELETE", "POST"], methods

    def test_cache_avoids_second_init(self, monkeypatch):
        """Second call returns cached key — no additional langflow calls."""
        client = _FakeClient(self._responses_no_existing_key())

        monkeypatch.setenv("YASHIGANI_LANGFLOW_INTERNAL_URL", "http://langflow:7860")
        with patch("yashigani.pki.client.internal_httpx_sync_client", return_value=client):
            from yashigani.backoffice.langflow_auth import get_langflow_api_headers
            h1 = get_langflow_api_headers()
            h2 = get_langflow_api_headers()

        assert h1 == h2 == {"x-api-key": "new-api-key-abc"}
        # internal_httpx_sync_client entered only once (cache hit on second call)
        assert client._idx == 3  # exactly 3 requests: auto_login + list + create

    def test_auto_login_failure_raises(self, monkeypatch):
        """auto_login 401 → RuntimeError raised (not silenced)."""
        client = _FakeClient([_FakeResponse(401, {"detail": "Not authenticated"})])
        monkeypatch.setenv("YASHIGANI_LANGFLOW_INTERNAL_URL", "http://langflow:7860")
        with patch("yashigani.pki.client.internal_httpx_sync_client", return_value=client):
            from yashigani.backoffice.langflow_auth import _init_api_key
            with pytest.raises(RuntimeError, match="auto_login failed"):
                _init_api_key()


# ---------------------------------------------------------------------------
# Tests: reconciler uses x-api-key (F-G) not bearer
# ---------------------------------------------------------------------------

class TestReconcilerAuthHeader:
    """_fetch_flows must send x-api-key, not Authorization: Bearer."""

    def test_fetch_flows_uses_x_api_key(self, monkeypatch):
        flow = _make_flow()
        raw = json.dumps([flow]).encode()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.content = raw
        fake_resp.raise_for_status = MagicMock()

        captured_headers: dict = {}

        def fake_get(url, **kwargs):
            captured_headers.update(kwargs.get("headers", {}))
            return fake_resp

        fake_client = MagicMock()
        fake_client.__enter__ = MagicMock(return_value=fake_client)
        fake_client.__exit__ = MagicMock(return_value=False)
        fake_client.get = fake_get

        monkeypatch.setenv("YASHIGANI_LANGFLOW_INTERNAL_URL", "http://langflow:7860")

        with (
            patch("yashigani.pki.client.internal_httpx_sync_client", return_value=fake_client),
            patch(
                "yashigani.backoffice.langflow_auth.get_langflow_api_headers",
                return_value={"x-api-key": "test-service-key"},
            ),
        ):
            from yashigani.backoffice.langflow_reconciler import _fetch_flows
            result = _fetch_flows("http://langflow:7860")

        assert result == [flow]
        assert "x-api-key" in captured_headers, (
            f"Expected x-api-key in headers; got {list(captured_headers)}"
        )
        assert captured_headers["x-api-key"] == "test-service-key"
        assert "Authorization" not in captured_headers, (
            "Authorization: Bearer must NOT be present (F-G fix)"
        )

    def test_reconciler_no_longer_reads_bearer_env(self, monkeypatch):
        """run_langflow_discovery does not bail on missing YASHIGANI_INTERNAL_BEARER."""
        monkeypatch.delenv("YASHIGANI_INTERNAL_BEARER", raising=False)
        monkeypatch.setenv("YASHIGANI_LANGFLOW_INTERNAL_URL", "http://langflow:7860")

        flow = _make_flow()
        raw = json.dumps([flow]).encode()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.content = raw
        fake_resp.raise_for_status = MagicMock()

        fake_client = MagicMock()
        fake_client.__enter__ = MagicMock(return_value=fake_client)
        fake_client.__exit__ = MagicMock(return_value=False)
        fake_client.get = MagicMock(return_value=fake_resp)

        registry_store = MagicMock()
        registry_store.get = MagicMock(return_value=None)
        registry_store.put = MagicMock()

        with (
            patch("yashigani.pki.client.internal_httpx_sync_client", return_value=fake_client),
            patch(
                "yashigani.backoffice.langflow_auth.get_langflow_api_headers",
                return_value={"x-api-key": "k"},
            ),
        ):
            from yashigani.backoffice.langflow_reconciler import run_langflow_discovery
            stats = run_langflow_discovery(registry_store, audit_writer=None)

        assert stats["discovered"] == 1, f"Expected discovered=1, got {stats}"


# ---------------------------------------------------------------------------
# Tests: F-H — flood cap removed; OOM guard at 13 MiB
# ---------------------------------------------------------------------------

class TestFloodCap:
    """F-H: total-body pre-parse cap (3.2 MB) is removed; per-flow caps remain."""

    def test_large_response_discovers_flows(self, monkeypatch):
        """A response >3.2 MB with valid per-flow sizes must discover flows (not discard).

        F-H regression: the OLD pre-parse total-body cap (50 × 64 KiB = 3,276,800 bytes)
        would have returned discovered=0.  The new code relies only on the per-flow cap
        and count cap, so flows within MAX_FLOWS=50 AND under 64 KiB each are discovered.

        The payload has 52 flows (above MAX_FLOWS=50), each ~63.6 KiB (below per-flow
        64 KiB cap), total ~3.3 MB (above the old 3.2 MB cap).  After _fetch_flows count-
        caps at MAX_FLOWS=50, exactly 50 flows are discovered and none are skipped as
        oversized.
        """
        from yashigani.backoffice.langflow_reconciler import MAX_FLOWS
        raw = _make_large_flow_payload()   # n_flows=52, per_flow_size=63_500 (defaults)
        total_bytes = len(raw)
        assert total_bytes > 3_276_800, f"Test precondition: {total_bytes} > 3.2 MB"

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.content = raw
        fake_resp.raise_for_status = MagicMock()

        fake_client = MagicMock()
        fake_client.__enter__ = MagicMock(return_value=fake_client)
        fake_client.__exit__ = MagicMock(return_value=False)
        fake_client.get = MagicMock(return_value=fake_resp)

        registry_store = MagicMock()
        registry_store.get = MagicMock(return_value=None)
        registry_store.put = MagicMock()

        monkeypatch.setenv("YASHIGANI_LANGFLOW_INTERNAL_URL", "http://langflow:7860")

        with (
            patch("yashigani.pki.client.internal_httpx_sync_client", return_value=fake_client),
            patch(
                "yashigani.backoffice.langflow_auth.get_langflow_api_headers",
                return_value={"x-api-key": "k"},
            ),
        ):
            from yashigani.backoffice.langflow_reconciler import run_langflow_discovery
            stats = run_langflow_discovery(registry_store, audit_writer=None)

        # Old 3.2 MB cap would have returned discovered=0.  New code discovers up to MAX_FLOWS.
        assert stats["discovered"] == MAX_FLOWS, (
            f"Expected {MAX_FLOWS} discovered (count cap), got {stats['discovered']}. "
            f"Response was {total_bytes} bytes — old 3.2 MB cap would have returned 0."
        )
        assert stats["skipped_oversized"] == 0, (
            "No flow should be skipped for oversized body — all flows are within the "
            f"per-flow {MAX_FLOWS * 65536 // MAX_FLOWS}-byte cap."
        )

    def test_oom_guard_fires_above_13mb(self, monkeypatch):
        """A response > 13 MiB is still rejected (OOM guard, not semantic cap)."""
        # Build a response that's just over 13 MB
        big_flow = {"id": str(uuid.uuid4()), "name": "big", "data": "x" * (14 * 1024 * 1024)}
        raw = json.dumps([big_flow]).encode()
        assert len(raw) > 13 * 1024 * 1024

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.content = raw
        fake_resp.raise_for_status = MagicMock()

        fake_client = MagicMock()
        fake_client.__enter__ = MagicMock(return_value=fake_client)
        fake_client.__exit__ = MagicMock(return_value=False)
        fake_client.get = MagicMock(return_value=fake_resp)

        monkeypatch.setenv("YASHIGANI_LANGFLOW_INTERNAL_URL", "http://langflow:7860")

        with (
            patch("yashigani.pki.client.internal_httpx_sync_client", return_value=fake_client),
            patch(
                "yashigani.backoffice.langflow_auth.get_langflow_api_headers",
                return_value={"x-api-key": "k"},
            ),
        ):
            from yashigani.backoffice.langflow_reconciler import _fetch_flows
            result = _fetch_flows("http://langflow:7860")

        assert result == [], "OOM guard should return empty list for > 13 MiB response"

    def test_per_flow_cap_still_enforced(self, monkeypatch):
        """Per-flow cap (64 KiB) is still enforced — oversized flows are skipped."""
        oversized_flow = {
            "id": str(uuid.uuid4()),
            "name": "oversized",
            "data": "x" * 70_000,   # > 64 KiB per-flow cap
        }
        ok_flow = _make_flow()
        raw = json.dumps([oversized_flow, ok_flow]).encode()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.content = raw
        fake_resp.raise_for_status = MagicMock()

        fake_client = MagicMock()
        fake_client.__enter__ = MagicMock(return_value=fake_client)
        fake_client.__exit__ = MagicMock(return_value=False)
        fake_client.get = MagicMock(return_value=fake_resp)

        registry_store = MagicMock()
        registry_store.get = MagicMock(return_value=None)
        registry_store.put = MagicMock()

        monkeypatch.setenv("YASHIGANI_LANGFLOW_INTERNAL_URL", "http://langflow:7860")

        with (
            patch("yashigani.pki.client.internal_httpx_sync_client", return_value=fake_client),
            patch(
                "yashigani.backoffice.langflow_auth.get_langflow_api_headers",
                return_value={"x-api-key": "k"},
            ),
        ):
            from yashigani.backoffice.langflow_reconciler import run_langflow_discovery
            stats = run_langflow_discovery(registry_store, audit_writer=None)

        assert stats["discovered"] == 1
        assert stats["skipped_oversized"] == 1


# ---------------------------------------------------------------------------
# Tests: Lu disclosure string
# ---------------------------------------------------------------------------

class TestDisclosure:
    """Egress-attribution disclosure is present in audit event and residuals."""

    def test_langflow_flow_discovered_event_has_egress_attribution(self):
        """LangflowFlowDiscoveredEvent carries egress_attribution (Lu disclosure)."""
        from yashigani.audit.schema import LangflowFlowDiscoveredEvent
        evt = LangflowFlowDiscoveredEvent(
            tenant_id="default",
            flow_id="abc-123",
            flow_name_truncated="My Flow",
            graph_hash="sha256:aabbcc",
            parser_version=1,
            langflow_instance="langflow",
        )
        assert hasattr(evt, "egress_attribution"), (
            "LangflowFlowDiscoveredEvent must have egress_attribution field"
        )
        attr = evt.egress_attribution
        assert "INSTANCE-LEVEL" in attr, f"disclosure missing 'INSTANCE-LEVEL': {attr!r}"
        assert "NOT per-flow" in attr, f"disclosure missing 'NOT per-flow': {attr!r}"

    def test_nhi_discovered_row_has_egress_attribution_note(self):
        """agent_policies status row for an NHI discovered flow includes egress_attribution_note."""
        from yashigani.backoffice.routes.agent_policies import get_status_rows  # type: ignore[attr-defined]

        nhi_desc = {
            "agent_name": "langflow-nhi-abc123",
            "tenant_id": "default",
            "kind": "nhi",
            "langflow_flow_id": "abc-123-full-flow-id",
            "svid_issued": False,
            "spiffe_id": "",
        }
        # Non-NHI descriptor (no langflow_flow_id)
        plain_desc = {
            "agent_name": "my-mcp-server",
            "tenant_id": "default",
            "kind": "onboarded",
            "svid_issued": True,
            "spiffe_id": "spiffe://td/my-mcp",
        }

        mock_store = MagicMock()
        mock_store.list_all = MagicMock(return_value=[nhi_desc, plain_desc])
        mock_store.get_egress_grant = MagicMock(return_value=None)
        mock_store.get_template_application = MagicMock(return_value=None)
        mock_store.get = MagicMock(return_value=None)

        import os
        with (
            patch("yashigani.backoffice.routes.agent_policies._registry_store", return_value=mock_store),
            patch("yashigani.backoffice.routes.agent_policies._load_templates", return_value=[]),
            patch.dict(os.environ, {"YASHIGANI_TENANT_ID": "default"}),
            patch("yashigani.backoffice.routes.agent_policies._resolve_bundled_spiffe", return_value=""),
        ):
            rows = get_status_rows()

        # Find the NHI row
        nhi_rows = [r for r in rows if r.get("system_id") == "langflow-nhi-abc123"]
        assert nhi_rows, f"NHI row not found in: {[r['system_id'] for r in rows]}"
        nhi_row = nhi_rows[0]

        residuals = nhi_row.get("residuals", {})
        assert "egress_attribution_note" in residuals, (
            f"NHI row residuals missing egress_attribution_note: {residuals}"
        )
        note = residuals["egress_attribution_note"]
        assert "INSTANCE-LEVEL" in note, f"note missing 'INSTANCE-LEVEL': {note!r}"
        assert "NOT per-flow" in note, f"note missing 'NOT per-flow': {note!r}"

        # Non-NHI row must NOT have the note
        plain_rows = [r for r in rows if r.get("system_id") == "my-mcp-server"]
        if plain_rows:
            plain_residuals = plain_rows[0].get("residuals", {})
            assert "egress_attribution_note" not in plain_residuals, (
                "Non-NHI row should not have egress_attribution_note"
            )

    def test_reconciler_audit_event_has_egress_attribution(self, monkeypatch):
        """run_langflow_discovery writes LangflowFlowDiscoveredEvent with egress_attribution."""
        flow = _make_flow()
        raw = json.dumps([flow]).encode()

        fake_resp = MagicMock()
        fake_resp.status_code = 200
        fake_resp.content = raw
        fake_resp.raise_for_status = MagicMock()

        fake_client = MagicMock()
        fake_client.__enter__ = MagicMock(return_value=fake_client)
        fake_client.__exit__ = MagicMock(return_value=False)
        fake_client.get = MagicMock(return_value=fake_resp)

        registry_store = MagicMock()
        registry_store.get = MagicMock(return_value=None)
        registry_store.put = MagicMock()

        audit_writer = MagicMock()
        written_events: list = []
        audit_writer.write = lambda evt: written_events.append(evt)

        monkeypatch.setenv("YASHIGANI_LANGFLOW_INTERNAL_URL", "http://langflow:7860")

        with (
            patch("yashigani.pki.client.internal_httpx_sync_client", return_value=fake_client),
            patch(
                "yashigani.backoffice.langflow_auth.get_langflow_api_headers",
                return_value={"x-api-key": "k"},
            ),
        ):
            from yashigani.backoffice.langflow_reconciler import run_langflow_discovery
            run_langflow_discovery(registry_store, audit_writer=audit_writer)

        assert len(written_events) == 1
        evt = written_events[0]
        assert hasattr(evt, "egress_attribution")
        assert "INSTANCE-LEVEL" in evt.egress_attribution
