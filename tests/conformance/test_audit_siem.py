"""
Conformance group: AUDIT-SIEM.

Closes G1 (Lu audit YCS-20260723-v4.1.2-CONFORMANCE) for:
  routes/audit.py          (13 endpoints) — /admin/audit/{export/raw, masking/scope*, siem*}
  routes/audit_search.py    (3 endpoints) — /admin/audit/{facets, search, export}
  routes/events.py          (1 endpoint)  — /admin/events/inspection-feed
  routes/csp_report.py      (1 endpoint)  — /admin/csp-report
Total: 18 endpoints (Lu matrix rows 52-64, 65-67, 161, 127).

Convention: see tests/conformance/conftest.py module docstring.

audit.py's own `_audit_writer()` helper does `assert writer is not None` (no
graceful 503 degrade — audit.py assumes the writer is ALWAYS configured at
startup, unlike audit_search.py's `_get_log_path()` which tolerates None).
This means every admin-tier positive-path test against audit.py MUST wire a
real (or mock) `backoffice_state.audit_writer` — an unwired admin_client call
raises AssertionError inside the route body (surfaces as a raw exception
through TestClient, not a 503), which is itself a conformance-relevant
divergence from audit_search.py's fail-closed pattern (noted below).

This suite constructs a REAL `AuditLogWriter` (yashigani.audit.writer)
pointed at a pytest `tmp_path` log file wherever positive-path assertions
need genuine persistence (export/raw, masking scope mutation, SIEM target
CRUD, and audit_search's search/export which reads straight from this
writer's `_config.log_path` — verified in audit_search.py:_get_log_path()).
No fakeredis-injectable equivalent exists for AuditLogWriter (it is a
file-backed writer, not Redis-backed) — this is the file-backed-service
pattern flagged in conftest.py's module docstring point 3, except a REAL
instance is fully constructible offline (tmp_path is local disk), so no
duck-typed fake is needed here.

SIEM "test connection" (POST /siem/{name}/test) makes a REAL
`urllib.request.urlopen()` call with no mock hook (audit.py:408-409) — this
suite monkeypatches `urllib.request.urlopen` directly (the function performs
a local import of `urllib.request` but references the same module object) to
stay offline-safe, and sets `YASHIGANI_TEST_MODE=1` (the writer's own
documented test escape hatch — validate_siem_url still enforces https, only
skips the DNS/private-IP resolution check) so SIEM target creation doesn't
require live DNS.

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

from typing import Self

import pytest

pytestmark = pytest.mark.conformance

_GROUP_PREFIXES = (
    "/admin/audit",
    "/admin/events/inspection-feed",
    "/admin/csp-report",
)

# audit_sinks.py (a DIFFERENT group's file) declares its own full absolute
# paths under /admin/audit/* (audit_sinks.py:54,65,76,115) and is mounted
# with NO prefix — so its routes collide with our "/admin/audit" prefix
# filter above. Verified via `grep -n '@audit_sinks_router\.' audit_sinks.py`
# 2026-07-23: exactly these 4 (method, path) pairs. Excluded here so this
# group's coverage-completeness check does not silently absorb another
# group's routes.
_NOT_OUR_GROUP = {
    ("GET", "/admin/audit/sinks"),
    ("GET", "/admin/audit/siem/config"),
    ("PUT", "/admin/audit/siem/config"),
    ("POST", "/admin/audit/siem/config/test"),
    # YSG-RISK-148 (queue-drain implementation, merged v4.1.2 integrated
    # fixbatch 2026-07-30): audit_sinks.py gained a 5th own-route since this
    # exclusion set was last updated (2026-07-23) — DELETE /admin/audit/sinks/queue
    # (audit_sinks.py:159). Same no-prefix-mount collision as the other 4.
    ("DELETE", "/admin/audit/sinks/queue"),
}


# ---------------------------------------------------------------------------
# Group-specific state wiring
# ---------------------------------------------------------------------------


@pytest.fixture
def real_audit_writer(tmp_path, monkeypatch):
    """Wires a REAL AuditLogWriter (yashigani.audit.writer.AuditLogWriter)
    pointed at a pytest tmp_path log file into backoffice_state.audit_writer.

    File-backed, not Redis-backed — fully constructible offline with no
    fakeredis equivalent needed (see module docstring)."""
    from yashigani.audit.config import AuditConfig
    from yashigani.audit.writer import AuditLogWriter
    from yashigani.backoffice.state import backoffice_state

    config = AuditConfig(
        log_path=str(tmp_path / "audit.log"),
        max_file_size_mb=100,
        retention_days=90,
    )
    writer = AuditLogWriter(config)
    monkeypatch.setattr(backoffice_state, "audit_writer", writer, raising=False)
    yield writer
    writer.close()


class _FakeHTTPResponse:
    """Context-manager stand-in for urllib.request.urlopen()'s return value."""

    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


# ---------------------------------------------------------------------------
# Route-completeness check (this IS the coverage gate for this group)
# ---------------------------------------------------------------------------


def test_group_covers_all_declared_routes(route_prefix_filter):
    declared = route_prefix_filter(*_GROUP_PREFIXES)
    declared_set = {(m, p) for (m, p, _r) in declared if (m, p) not in _NOT_OUR_GROUP}
    assert len(declared_set) == 18, (
        f"Expected 18 declared routes under {_GROUP_PREFIXES} (excluding "
        f"audit_sinks.py's {_NOT_OUR_GROUP}), found {len(declared_set)}: "
        f"{sorted(declared_set)}"
    )


# ---------------------------------------------------------------------------
# audit.py — GET /admin/audit/export/raw
# ---------------------------------------------------------------------------


class TestAuditExportRaw:
    # GAP-CLOSED: GET /admin/audit/export/raw
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/audit/export/raw")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "authentication_required"

    def test_user_tier_403(self, user_client, real_audit_writer):
        r = user_client.get("/admin/audit/export/raw")
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "insufficient_tier"

    def test_admin_ndjson_contains_written_event(self, admin_client, real_audit_writer):
        from yashigani.audit.schema import ConfigChangedEvent

        real_audit_writer.write(
            ConfigChangedEvent(
                admin_account="export-raw-probe",
                setting="masking.default",
                previous_value="true",
                new_value="false",
            )
        )
        r = admin_client.get("/admin/audit/export/raw")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/x-ndjson"
        assert "export-raw-probe" in r.text

    def test_admin_csv_format(self, admin_client, real_audit_writer):
        from yashigani.audit.schema import ConfigChangedEvent

        real_audit_writer.write(ConfigChangedEvent(admin_account="csv-probe"))
        r = admin_client.get("/admin/audit/export/raw", params={"output_format": "csv"})
        assert r.status_code == 200
        assert r.headers["content-type"] == "text/csv; charset=utf-8"
        assert "csv-probe" in r.text

    def test_invalid_format_422(self, admin_client, real_audit_writer):
        r = admin_client.get("/admin/audit/export/raw", params={"output_format": "xml"})
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# audit.py — masking scope: global default
# ---------------------------------------------------------------------------


class TestMaskingScopeDefault:
    # GAP-CLOSED: GET /admin/audit/masking/scope
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/audit/masking/scope").status_code == 401

    def test_user_tier_403(self, user_client, real_audit_writer):
        r = user_client.get("/admin/audit/masking/scope")
        assert r.status_code == 403

    def test_admin_defaults(self, admin_client, real_audit_writer):
        r = admin_client.get("/admin/audit/masking/scope")
        assert r.status_code == 200
        body = r.json()
        assert body == {
            "mask_all_by_default": True,
            "agent_overrides": {},
            "user_overrides": {},
            "component_overrides": {},
        }

    # GAP-CLOSED: PUT /admin/audit/masking/scope
    def test_put_unauth_401(self, unauth_client):
        r = unauth_client.put("/admin/audit/masking/scope", json={"mask_all_by_default": False})
        assert r.status_code == 401

    def test_put_updates_real_writer_state(self, admin_client, real_audit_writer):
        r = admin_client.put("/admin/audit/masking/scope", json={"mask_all_by_default": False})
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "mask_all_by_default": False}
        # Genuine mutation assertion against the real writer instance.
        assert real_audit_writer._masking_scope.mask_all_by_default is False
        # And the config-change event was actually persisted to the real log.
        r2 = admin_client.get("/admin/audit/export/raw")
        assert "masking.default" in r2.text


# ---------------------------------------------------------------------------
# audit.py — masking scope: per-agent override
# ---------------------------------------------------------------------------


class TestMaskingScopeAgent:
    # GAP-CLOSED: POST /admin/audit/masking/scope/agent
    def test_post_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/audit/masking/scope/agent", json={"agent_id": "agent-1", "mask": True}
        )
        assert r.status_code == 401

    def test_post_sets_override(self, admin_client, real_audit_writer):
        r = admin_client.post(
            "/admin/audit/masking/scope/agent", json={"agent_id": "agent-1", "mask": False}
        )
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}
        assert real_audit_writer._masking_scope.agent_overrides["agent-1"] is False

    # GAP-CLOSED: DELETE /admin/audit/masking/scope/agent/{agent_id}
    def test_delete_unauth_401(self, unauth_client):
        r = unauth_client.delete("/admin/audit/masking/scope/agent/agent-1")
        assert r.status_code == 401

    def test_delete_nonexistent_404(self, admin_client, real_audit_writer):
        r = admin_client.delete("/admin/audit/masking/scope/agent/does-not-exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "override_not_found"

    def test_delete_removes_real_override(self, admin_client, real_audit_writer):
        admin_client.post(
            "/admin/audit/masking/scope/agent", json={"agent_id": "agent-2", "mask": True}
        )
        r = admin_client.delete("/admin/audit/masking/scope/agent/agent-2")
        assert r.status_code == 200
        assert "agent-2" not in real_audit_writer._masking_scope.agent_overrides
        # Second delete of the same key must 404, not silently 200 again.
        r2 = admin_client.delete("/admin/audit/masking/scope/agent/agent-2")
        assert r2.status_code == 404


# ---------------------------------------------------------------------------
# audit.py — masking scope: per-user override
# ---------------------------------------------------------------------------


class TestMaskingScopeUser:
    # GAP-CLOSED: POST /admin/audit/masking/scope/user
    def test_post_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/audit/masking/scope/user", json={"user_handle": "alice", "mask": True}
        )
        assert r.status_code == 401

    def test_post_sets_override(self, admin_client, real_audit_writer):
        r = admin_client.post(
            "/admin/audit/masking/scope/user", json={"user_handle": "alice", "mask": False}
        )
        assert r.status_code == 200
        assert real_audit_writer._masking_scope.user_overrides["alice"] is False

    # GAP-CLOSED: DELETE /admin/audit/masking/scope/user/{handle}
    def test_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/audit/masking/scope/user/alice").status_code == 401

    def test_delete_nonexistent_404(self, admin_client, real_audit_writer):
        r = admin_client.delete("/admin/audit/masking/scope/user/does-not-exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "override_not_found"

    def test_delete_removes_real_override(self, admin_client, real_audit_writer):
        admin_client.post(
            "/admin/audit/masking/scope/user", json={"user_handle": "bob", "mask": True}
        )
        r = admin_client.delete("/admin/audit/masking/scope/user/bob")
        assert r.status_code == 200
        assert "bob" not in real_audit_writer._masking_scope.user_overrides


# ---------------------------------------------------------------------------
# audit.py — masking scope: per-component override
# ---------------------------------------------------------------------------


class TestMaskingScopeComponent:
    # GAP-CLOSED: POST /admin/audit/masking/scope/component
    def test_post_unauth_401(self, unauth_client):
        r = unauth_client.post(
            "/admin/audit/masking/scope/component", json={"component": "ratelimit", "mask": True}
        )
        assert r.status_code == 401

    def test_post_sets_override(self, admin_client, real_audit_writer):
        r = admin_client.post(
            "/admin/audit/masking/scope/component", json={"component": "ratelimit", "mask": False}
        )
        assert r.status_code == 200
        assert real_audit_writer._masking_scope.component_overrides["ratelimit"] is False

    # GAP-CLOSED: DELETE /admin/audit/masking/scope/component/{component}
    def test_delete_unauth_401(self, unauth_client):
        r = unauth_client.delete("/admin/audit/masking/scope/component/ratelimit")
        assert r.status_code == 401

    def test_delete_nonexistent_404(self, admin_client, real_audit_writer):
        r = admin_client.delete("/admin/audit/masking/scope/component/does-not-exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "override_not_found"

    def test_delete_removes_real_override(self, admin_client, real_audit_writer):
        admin_client.post(
            "/admin/audit/masking/scope/component", json={"component": "budget", "mask": True}
        )
        r = admin_client.delete("/admin/audit/masking/scope/component/budget")
        assert r.status_code == 200
        assert "budget" not in real_audit_writer._masking_scope.component_overrides


# ---------------------------------------------------------------------------
# audit.py — SIEM targets
# ---------------------------------------------------------------------------


class TestSiemTargets:
    # GAP-CLOSED: GET /admin/audit/siem
    def test_list_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/audit/siem").status_code == 401

    def test_list_empty(self, admin_client, real_audit_writer):
        r = admin_client.get("/admin/audit/siem")
        assert r.status_code == 200
        assert r.json() == {"siem_targets": [], "total": 0}

    # GAP-CLOSED: POST /admin/audit/siem
    def test_add_unauth_401(self, unauth_client):
        r = unauth_client.post("/admin/audit/siem", json={
            "name": "wazuh", "target_type": "webhook", "url": "https://siem.example.com/hook",
            "auth_value": "secret-token",
        })
        assert r.status_code == 401

    def test_add_rejects_non_https_422(self, admin_client, real_audit_writer):
        """SPEC-CONFORMANCE (SSRF hardening, CWE-918/YSG-RISK-007.C): scheme
        must be https — real validate_siem_url() call, not a stub."""
        r = admin_client.post("/admin/audit/siem", json={
            "name": "insecure", "target_type": "webhook", "url": "http://siem.example.com/hook",
            "auth_value": "secret-token",
        })
        assert r.status_code == 422

    def test_add_then_list_bopla_excludes_auth_value(self, admin_client, real_audit_writer, monkeypatch):
        """BOPLA (#90): SiemTargetPublic never returns auth_value."""
        monkeypatch.setenv("YASHIGANI_TEST_MODE", "1")
        r = admin_client.post("/admin/audit/siem", json={
            "name": "wazuh", "target_type": "webhook", "url": "https://siem.example.com/hook",
            "auth_value": "super-secret-token",
        })
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "name": "wazuh"}

        r2 = admin_client.get("/admin/audit/siem")
        assert r2.status_code == 200
        targets = r2.json()["siem_targets"]
        assert len(targets) == 1
        assert targets[0]["name"] == "wazuh"
        assert "auth_value" not in targets[0]

    def test_add_duplicate_name_409(self, admin_client, real_audit_writer, monkeypatch):
        monkeypatch.setenv("YASHIGANI_TEST_MODE", "1")
        payload = {
            "name": "dup-target", "target_type": "webhook", "url": "https://siem.example.com/hook",
            "auth_value": "tok",
        }
        assert admin_client.post("/admin/audit/siem", json=payload).status_code == 200
        r2 = admin_client.post("/admin/audit/siem", json=payload)
        assert r2.status_code == 409
        assert r2.json()["detail"]["error"] == "siem_target_name_taken"

    # GAP-CLOSED: DELETE /admin/audit/siem/{name}
    def test_delete_unauth_401(self, unauth_client):
        assert unauth_client.delete("/admin/audit/siem/wazuh").status_code == 401

    def test_delete_nonexistent_404(self, admin_client, real_audit_writer):
        r = admin_client.delete("/admin/audit/siem/does-not-exist")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "siem_target_not_found"

    def test_delete_existing_200(self, admin_client, real_audit_writer, monkeypatch):
        monkeypatch.setenv("YASHIGANI_TEST_MODE", "1")
        admin_client.post("/admin/audit/siem", json={
            "name": "to-remove", "target_type": "webhook", "url": "https://siem.example.com/hook",
            "auth_value": "tok",
        })
        r = admin_client.delete("/admin/audit/siem/to-remove")
        assert r.status_code == 200
        r2 = admin_client.get("/admin/audit/siem")
        assert r2.json()["total"] == 0

    # GAP-CLOSED: POST /admin/audit/siem/{name}/test
    def test_test_connection_unauth_401(self, unauth_client):
        assert unauth_client.post("/admin/audit/siem/wazuh/test").status_code == 401

    def test_test_connection_nonexistent_404(self, admin_client, real_audit_writer):
        r = admin_client.post("/admin/audit/siem/does-not-exist/test")
        assert r.status_code == 404
        assert r.json()["detail"]["error"] == "siem_target_not_found"

    def test_test_connection_success_200(self, admin_client, real_audit_writer, monkeypatch):
        """Offline-safe: monkeypatches urllib.request.urlopen (audit.py has no
        transport-injection hook — this is a real httptest of the route's own
        _format_for_target + validate_siem_url re-check logic, only the final
        socket call is stubbed)."""
        monkeypatch.setenv("YASHIGANI_TEST_MODE", "1")
        admin_client.post("/admin/audit/siem", json={
            "name": "wazuh", "target_type": "webhook", "url": "https://siem.example.com/hook",
            "auth_value": "tok",
        })

        import urllib.request

        monkeypatch.setattr(
            urllib.request, "urlopen", lambda *a, **kw: _FakeHTTPResponse(200)
        )
        r = admin_client.post("/admin/audit/siem/wazuh/test")
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "http_status": 200}

    def test_test_connection_upstream_failure_502(self, admin_client, real_audit_writer, monkeypatch):
        monkeypatch.setenv("YASHIGANI_TEST_MODE", "1")
        admin_client.post("/admin/audit/siem", json={
            "name": "wazuh", "target_type": "webhook", "url": "https://siem.example.com/hook",
            "auth_value": "tok",
        })

        import urllib.error
        import urllib.request

        def _raise(*_a, **_kw):
            raise urllib.error.HTTPError(
                "https://siem.example.com/hook", 500, "Internal Server Error", {}, None
            )

        monkeypatch.setattr(urllib.request, "urlopen", _raise)
        r = admin_client.post("/admin/audit/siem/wazuh/test")
        assert r.status_code == 502
        assert r.json()["detail"]["http_status"] == 500


# ---------------------------------------------------------------------------
# audit_search.py — facets
# ---------------------------------------------------------------------------


class TestAuditFacets:
    # GAP-CLOSED: GET /admin/audit/facets
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/audit/facets").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/audit/facets").status_code == 403

    def test_admin_200_shape(self, admin_client):
        r = admin_client.get("/admin/audit/facets")
        assert r.status_code == 200
        body = r.json()
        assert {"value": "deny", "label": "Deny"} in body["verdicts"]
        assert {"value": "AGENT", "label": "Agent"} in body["source_types"]


# ---------------------------------------------------------------------------
# audit_search.py — search
# ---------------------------------------------------------------------------


class TestAuditSearch:
    # GAP-CLOSED: GET /admin/audit/search
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/audit/search").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/audit/search").status_code == 403

    def test_admin_503_without_writer(self, admin_client):
        """SPEC-CONFORMANCE: unlike audit.py's assert-based hard-fail,
        audit_search.py's _get_log_path() gracefully degrades to a 503
        `audit_log_not_configured` when backoffice_state.audit_writer is
        None — a documented divergence between the two sibling route files
        (audit.py:49-53 vs audit_search.py:492-500)."""
        r = admin_client.get("/admin/audit/search")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "audit_log_not_configured"

    def test_admin_finds_written_event_by_user_filter(self, admin_client, real_audit_writer):
        from yashigani.audit.schema import ConfigChangedEvent

        real_audit_writer.write(ConfigChangedEvent(admin_account="alice-search-target"))
        real_audit_writer.write(ConfigChangedEvent(admin_account="bob-other-account"))

        r = admin_client.get("/admin/audit/search", params={"user": "alice-search-target"})
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 1
        assert body["rows"][0]["admin_account"] == "alice-search-target"
        assert body["has_more"] is False

    def test_admin_event_type_filter(self, admin_client, real_audit_writer):
        from yashigani.audit.schema import ConfigChangedEvent

        real_audit_writer.write(ConfigChangedEvent(admin_account="event-type-probe"))
        r = admin_client.get("/admin/audit/search", params={"event_type": "CONFIG_CHANGED"})
        assert r.status_code == 200
        assert r.json()["count"] >= 1
        assert all(row["event_type"] == "CONFIG_CHANGED" for row in r.json()["rows"])

    def test_admin_no_match_empty_rows(self, admin_client, real_audit_writer):
        r = admin_client.get("/admin/audit/search", params={"user": "nobody-matches-this"})
        assert r.status_code == 200
        assert r.json() == {
            "rows": [], "count": 0, "total_scanned": 0, "cursor": None, "has_more": False,
        }


# ---------------------------------------------------------------------------
# audit_search.py — filtered export
# ---------------------------------------------------------------------------


class TestAuditExportFiltered:
    # GAP-CLOSED: GET /admin/audit/export
    def test_unauth_401(self, unauth_client):
        assert unauth_client.get("/admin/audit/export").status_code == 401

    def test_user_tier_403(self, user_client):
        assert user_client.get("/admin/audit/export").status_code == 403

    def test_admin_503_without_writer(self, admin_client):
        r = admin_client.get("/admin/audit/export")
        assert r.status_code == 503
        assert r.json()["detail"]["error"] == "audit_log_not_configured"

    def test_admin_ndjson_default(self, admin_client, real_audit_writer):
        from yashigani.audit.schema import ConfigChangedEvent

        real_audit_writer.write(ConfigChangedEvent(admin_account="export-filtered-probe"))
        r = admin_client.get("/admin/audit/export")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/x-ndjson"
        assert "export-filtered-probe" in r.text

    def test_admin_csv_format(self, admin_client, real_audit_writer):
        from yashigani.audit.schema import ConfigChangedEvent

        real_audit_writer.write(ConfigChangedEvent(admin_account="csv-filtered-probe"))
        r = admin_client.get("/admin/audit/export", params={"output_format": "csv"})
        assert r.status_code == 200
        assert r.headers["content-type"] == "text/csv; charset=utf-8"
        assert "csv-filtered-probe" in r.text

    def test_invalid_format_422(self, admin_client, real_audit_writer):
        r = admin_client.get("/admin/audit/export", params={"output_format": "xml"})
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# events.py — SSE inspection feed
# ---------------------------------------------------------------------------


class TestEventsInspectionFeed:
    # GAP-CLOSED: GET /admin/events/inspection-feed
    def test_unauth_401(self, unauth_client):
        r = unauth_client.get("/admin/events/inspection-feed")
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "authentication_required"

    def test_user_tier_403(self, user_client):
        r = user_client.get("/admin/events/inspection-feed")
        assert r.status_code == 403

    def test_admin_clears_gate_sse_headers(self, admin_client, monkeypatch):
        """Positive-path: clears the AdminSession auth gate and returns a real
        text/event-stream response.

        MOCKED: `_sse_generator` is stubbed to a single-yield generator.
        `_sse_generator` is architecturally infinite (15s heartbeat loop that
        only terminates on `request.is_disconnected()` — verified empirically
        2026-07-23 that `httpx`'s ASGITransport in this pinned version does
        NOT reliably deliver an early-close signal to the app before the next
        `is_disconnected()` poll, so a real `client.stream(...)` + early-close
        round-trip against the live generator hung the suite indefinitely).
        The route itself (auth gate, StreamingResponse construction, header
        wiring) is exercised for real — only the inner infinite loop is
        stubbed, mirroring conftest.py's documented duck-typed-fake pattern
        for classes with no offline-safe real equivalent."""
        import yashigani.backoffice.routes.events as events_routes

        async def _fake_sse_generator(_request):
            yield ": connected\n\n"

        monkeypatch.setattr(events_routes, "_sse_generator", _fake_sse_generator)
        r = admin_client.get("/admin/events/inspection-feed")
        assert r.status_code == 200
        assert r.headers["content-type"] == "text/event-stream; charset=utf-8"
        # SPEC-CONFORMANCE (real divergence, harmless): the route itself sets
        # Cache-Control: no-cache (events.py:50), but app.py's global
        # `security_headers` middleware (app.py:1108-1110, ASVS 3.4 / ZAP
        # 10015-10049 hardening) unconditionally overwrites Cache-Control to
        # "no-store" + adds Pragma: no-cache for every non-/static/ path,
        # running AFTER call_next. The delivered header is stricter than the
        # route's own documented value, never weaker — not a security bug,
        # but the route's own header is dead code in practice. Verified
        # 2026-07-23 against app.py:1108.
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["pragma"] == "no-cache"
        assert r.text == ": connected\n\n"


# ---------------------------------------------------------------------------
# csp_report.py — CSP violation report ingest
# ---------------------------------------------------------------------------


class TestCspReport:
    # GAP-CLOSED: POST /admin/csp-report
    def test_valid_report_204_no_auth_required(self, unauth_client):
        """SPEC-CONFORMANCE (documented, deliberate): this endpoint carries no
        AdminSession dependency (csp_report.py:17-18) — browsers POST CSP
        violation reports automatically and cannot attach cookies/CSRF tokens,
        so authentication is intentionally absent. Asserting 204 on the
        UNAUTH client pins this as an intentional public endpoint, not a
        missed auth-gate."""
        r = unauth_client.post(
            "/admin/csp-report",
            json={"csp-report": {
                "blocked-uri": "https://evil.example.com/x.js",
                "violated-directive": "script-src",
                "document-uri": "https://app.example.com/dashboard",
            }},
        )
        assert r.status_code == 204
        assert r.content == b""

    def test_malformed_json_still_204(self, unauth_client):
        """Documented fail-safe: malformed body is logged and discarded, never
        surfaced as a 4xx/5xx to the reporting browser (csp_report.py:24-29)."""
        r = unauth_client.post(
            "/admin/csp-report",
            content=b"not json at all",
            headers={"Content-Type": "application/csp-report"},
        )
        assert r.status_code == 204

    def test_bare_report_without_wrapper_204(self, unauth_client):
        """Body without the standard `csp-report` wrapper key is still
        accepted (report = body.get("csp-report", body) — csp_report.py:32)."""
        r = unauth_client.post(
            "/admin/csp-report",
            json={"blocked-uri": "https://evil.example.com/x.js"},
        )
        assert r.status_code == 204

    def test_get_method_not_allowed_405(self, unauth_client):
        r = unauth_client.get("/admin/csp-report")
        assert r.status_code == 405
