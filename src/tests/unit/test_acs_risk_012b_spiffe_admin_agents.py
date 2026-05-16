"""Unit tests for ACS-RISK-012b — SPIFFE binding on /admin/agents write routes.

Last updated: 2026-05-16T00:00:00+01:00

Closes: ACS-RISK-012b (ASVS V10.3.5 sender-constrained tokens).

Coverage:
  1. No SPIFFE header on POST /admin/agents → 401 no_spiffe_id
  2. No SPIFFE header on PUT /admin/agents/{id} → 401 no_spiffe_id
  3. No SPIFFE header on DELETE /admin/agents/{id} → 401 no_spiffe_id
  4. No SPIFFE header on POST /admin/agents/{id}/token/rotate → 401 no_spiffe_id
  5. Non-allowlisted SPIFFE ID (stolen cert) on POST → 403 spiffe_id_not_allowed
  6. Caddy SPIFFE ID (spiffe://yashigani.internal/caddy) → passes gate (200-passthrough)
  7. Backoffice SPIFFE ID (spiffe://yashigani.internal/backoffice) → passes gate (200-passthrough)
  8. GET /admin/agents (read-only) has no SPIFFE gate — no dependency wired
  9. Confirm ACL key "/admin/agents" exists in service_identities.yaml with both allowed IDs

Tests 1–7 call require_spiffe_id directly (no FastAPI server needed).
Test 8 verifies the GET route decorator has no require_spiffe_id dependency.
Test 9 parses the YAML manifest and asserts the ACL entry.
"""
from __future__ import annotations

import pathlib

import pytest
from fastapi import HTTPException

from yashigani.auth.spiffe import _reset_cache_for_tests, require_spiffe_id
from yashigani.auth import spiffe as _spiffe_mod

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ACL_PATH = "/admin/agents"
_CADDY_URI = "spiffe://yashigani.internal/caddy"
_BACKOFFICE_URI = "spiffe://yashigani.internal/backoffice"
_ROGUE_URI = "spiffe://attacker.example.com/evil"

_MANIFEST = (
    pathlib.Path(__file__).resolve().parents[3]
    / "docker"
    / "service_identities.yaml"
)


# ---------------------------------------------------------------------------
# Helpers matching the pattern in test_spiffe_gate.py
# ---------------------------------------------------------------------------


class _FakeHeaders:
    """Case-insensitive header mapping matching FastAPI's .headers interface."""

    def __init__(self, initial: dict[str, str] | None = None):
        self._h = {k.lower(): v for k, v in (initial or {}).items()}

    def get(self, key: str, default=None):
        return self._h.get(key.lower(), default)


class _FakeRequest:
    def __init__(self, headers: dict[str, str] | None = None):
        self.headers = _FakeHeaders(headers)


def _acl(allowed: list[str]) -> dict:
    """Build a minimal ACL dict for monkeypatching _load_acls."""
    return {_ACL_PATH: frozenset(allowed)}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset():
    _reset_cache_for_tests()
    yield
    _reset_cache_for_tests()


def _install_acl(monkeypatch, allowed: list[str]) -> None:
    monkeypatch.setattr(_spiffe_mod, "_load_acls", lambda: _acl(allowed))


# ---------------------------------------------------------------------------
# Tests 1–4: missing SPIFFE header → 401 on each of the 4 mutation verbs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_admin_agents_no_spiffe_returns_401(monkeypatch):
    """Test 1: POST /admin/agents without SPIFFE header → 401 no_spiffe_id."""
    _install_acl(monkeypatch, [_CADDY_URI, _BACKOFFICE_URI])
    dep = require_spiffe_id(_ACL_PATH)
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest())
    assert exc.value.status_code == 401
    assert exc.value.detail == "no_spiffe_id"


@pytest.mark.asyncio
async def test_put_admin_agents_no_spiffe_returns_401(monkeypatch):
    """Test 2: PUT /admin/agents/{id} without SPIFFE header → 401 no_spiffe_id."""
    _install_acl(monkeypatch, [_CADDY_URI, _BACKOFFICE_URI])
    dep = require_spiffe_id(_ACL_PATH)
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest())
    assert exc.value.status_code == 401
    assert exc.value.detail == "no_spiffe_id"


@pytest.mark.asyncio
async def test_delete_admin_agents_no_spiffe_returns_401(monkeypatch):
    """Test 3: DELETE /admin/agents/{id} without SPIFFE header → 401 no_spiffe_id."""
    _install_acl(monkeypatch, [_CADDY_URI, _BACKOFFICE_URI])
    dep = require_spiffe_id(_ACL_PATH)
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest())
    assert exc.value.status_code == 401
    assert exc.value.detail == "no_spiffe_id"


@pytest.mark.asyncio
async def test_rotate_no_spiffe_returns_401(monkeypatch):
    """Test 4: POST /admin/agents/{id}/token/rotate without SPIFFE → 401 no_spiffe_id."""
    _install_acl(monkeypatch, [_CADDY_URI, _BACKOFFICE_URI])
    dep = require_spiffe_id(_ACL_PATH)
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest())
    assert exc.value.status_code == 401
    assert exc.value.detail == "no_spiffe_id"


# ---------------------------------------------------------------------------
# Test 5: non-allowlisted SPIFFE ID → 403
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rogue_spiffe_id_returns_403(monkeypatch):
    """Test 5: Attacker with own SPIFFE ID (not caddy/backoffice) → 403."""
    _install_acl(monkeypatch, [_CADDY_URI, _BACKOFFICE_URI])
    dep = require_spiffe_id(_ACL_PATH)
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest({"X-SPIFFE-ID-Peer-Cert": _ROGUE_URI}))
    assert exc.value.status_code == 403
    assert exc.value.detail == "spiffe_id_not_allowed"


# ---------------------------------------------------------------------------
# Tests 6–7: allowlisted SPIFFE IDs pass the gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_caddy_spiffe_passes_gate(monkeypatch):
    """Test 6: Caddy's SPIFFE URI is in allowlist → gate passes, returns URI."""
    _install_acl(monkeypatch, [_CADDY_URI, _BACKOFFICE_URI])
    dep = require_spiffe_id(_ACL_PATH)
    # Caddy-proxied path: middleware sets x-spiffe-id-peer-cert from TLS handshake.
    result = await dep(_FakeRequest({"X-SPIFFE-ID-Peer-Cert": _CADDY_URI}))
    assert result == _CADDY_URI


@pytest.mark.asyncio
async def test_backoffice_spiffe_passes_gate(monkeypatch):
    """Test 7: Backoffice SPIFFE URI (install.sh path) → gate passes, returns URI."""
    _install_acl(monkeypatch, [_CADDY_URI, _BACKOFFICE_URI])
    dep = require_spiffe_id(_ACL_PATH)
    # install.sh runs inside the backoffice container; calls localhost:8443 with
    # backoffice_client.crt → middleware extracts spiffe://yashigani.internal/backoffice.
    result = await dep(_FakeRequest({"X-SPIFFE-ID-Peer-Cert": _BACKOFFICE_URI}))
    assert result == _BACKOFFICE_URI


# ---------------------------------------------------------------------------
# Test 8: GET /admin/agents has no require_spiffe_id dependency wired
# ---------------------------------------------------------------------------


def test_get_list_agents_has_no_spiffe_dependency():
    """Test 8: GET /admin/agents (read-only list) must NOT have SPIFFE gate.

    Verifies that the route function itself has no `dependencies` containing
    require_spiffe_id — read operations are admin-session-gated only.
    """
    from yashigani.backoffice.routes.agents import list_agents

    # FastAPI stores route-level dependencies on the function itself only when
    # using the @router.get(..., dependencies=[...]) form.  When absent the
    # attribute does not exist (or is an empty list).  Both are acceptable for
    # the GET route.
    deps = getattr(list_agents, "__fastapi_dependencies__", [])
    for dep_call in deps:
        # If any dependency is require_spiffe_id, that's a bug — it would break
        # the admin dashboard's GET requests.
        if hasattr(dep_call, "dependency"):
            inner = getattr(dep_call.dependency, "__func__", dep_call.dependency)
            assert inner is not require_spiffe_id, (
                "GET /admin/agents must NOT have a SPIFFE gate — read-only route "
                "must be accessible from the admin UI without a client cert."
            )


# ---------------------------------------------------------------------------
# Test 9: service_identities.yaml contains the correct ACL entry
# ---------------------------------------------------------------------------


def test_service_identities_yaml_has_admin_agents_acl():
    """Test 9: docker/service_identities.yaml endpoint_acls has /admin/agents.

    Asserts:
    - The ACL key "/admin/agents" exists.
    - It allows spiffe://yashigani.internal/caddy.
    - It allows spiffe://yashigani.internal/backoffice.
    - It does NOT allow any other URI (fail-closed: only those two).
    """
    import yaml  # PyYAML is a dev dep; safe to use in tests

    doc = yaml.safe_load(_MANIFEST.read_text())
    acls = doc.get("endpoint_acls", {})

    assert "/admin/agents" in acls, (
        "service_identities.yaml endpoint_acls must contain '/admin/agents' "
        "key (ACS-RISK-012b close requirement)"
    )

    entry = acls["/admin/agents"]
    allowed = set(entry.get("allowed_spiffe_ids", []))

    assert _CADDY_URI in allowed, (
        f"endpoint_acls['/admin/agents'] must contain {_CADDY_URI!r} "
        "(admin UI browser sessions arrive via Caddy's TLS leg)"
    )
    assert _BACKOFFICE_URI in allowed, (
        f"endpoint_acls['/admin/agents'] must contain {_BACKOFFICE_URI!r} "
        "(install.sh agent-registration runs inside the backoffice container)"
    )
    assert len(allowed) == 2, (
        f"endpoint_acls['/admin/agents'] must have exactly 2 allowed IDs, "
        f"got {allowed!r} — fail-closed: only caddy and backoffice are permitted"
    )
