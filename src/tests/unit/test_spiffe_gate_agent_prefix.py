"""Unit tests — SPIFFE ACL gate agent-prefix grant (v4.1 Phase 1, Nico Q1).

The ``/admin/agents/*/cert/rotate`` rule in service_identities.yaml declared
``allowed_spiffe_prefix`` + ``verify_spiffe_matches_agent_id`` since 4.0
Phase 0, but the manifest parser silently dropped both fields and the gate
only ever did exact-id matching — the sidecar self-rotation grant could never
work.  These tests pin the new behaviour:

  * EndpointAcl parsing (prefix + verify flag; verify-without-prefix rejected)
  * exact-id callers still pass
  * prefix-matched agent callers pass ONLY when the {agent_id} path param
    equals their SPIFFE agent_name or instance_id segment
  * cross-agent rotation attempts 403 (spiffe_id_agent_mismatch)
  * legacy frozenset-shaped ACL injection stays supported (back-compat)
  * the REAL docker/ + helm/ manifests parse with the full rule

Last updated: 2026-07-06T00:00:00+00:00
"""
from __future__ import annotations

from pathlib import Path

import pytest

from fastapi import HTTPException

from yashigani.auth.spiffe import _reset_cache_for_tests, require_spiffe_id
from yashigani.auth import spiffe as _spiffe_mod
from yashigani.pki.identity import EndpointAcl, ManifestError, _parse_endpoint_acls


_REPO_ROOT = Path(__file__).resolve().parents[3]

_PATH = "/admin/agents/*/cert/rotate"
_PREFIX = "spiffe://yashigani.internal/agents/"
_BACKOFFICE = "spiffe://yashigani.internal/backoffice"
_AGENT_LEGACY = "spiffe://yashigani.internal/agents/tenant1/letta"
_AGENT_INSTANCED = "spiffe://yashigani.internal/agents/tenant1/letta/nhi_abcdefabcdef"

_RULE = EndpointAcl(
    allowed_spiffe_ids=frozenset({_BACKOFFICE}),
    allowed_spiffe_prefix=_PREFIX,
    verify_spiffe_matches_agent_id=True,
)


class _FakeHeaders:
    def __init__(self, initial=None):
        self._h = {k.lower(): v for k, v in (initial or {}).items()}

    def get(self, key, default=None):
        return self._h.get(key.lower(), default)


class _FakeRequest:
    def __init__(self, headers=None, path_params=None):
        self.headers = _FakeHeaders(headers)
        self.path_params = path_params or {}


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("YASHIGANI_SPIFFE_TRUST_DOMAIN", raising=False)
    _reset_cache_for_tests()
    yield
    _reset_cache_for_tests()


def _install_acl(monkeypatch, acls):
    monkeypatch.setattr(_spiffe_mod, "_load_acls", lambda: acls)


# ---------------------------------------------------------------------------
# Gate behaviour
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_exact_id_still_passes(monkeypatch):
    _install_acl(monkeypatch, {_PATH: _RULE})
    dep = require_spiffe_id(_PATH)
    result = await dep(_FakeRequest({"x-spiffe-id": _BACKOFFICE}))
    assert result == _BACKOFFICE


@pytest.mark.asyncio
async def test_agent_prefix_passes_when_path_param_is_agent_name(monkeypatch):
    """AGENT_ID env (codegen.py) is the server/agent NAME — must be accepted."""
    _install_acl(monkeypatch, {_PATH: _RULE})
    dep = require_spiffe_id(_PATH)
    req = _FakeRequest({"x-spiffe-id": _AGENT_INSTANCED}, {"agent_id": "letta"})
    assert await dep(req) == _AGENT_INSTANCED


@pytest.mark.asyncio
async def test_agent_prefix_passes_when_path_param_is_instance_id(monkeypatch):
    _install_acl(monkeypatch, {_PATH: _RULE})
    dep = require_spiffe_id(_PATH)
    req = _FakeRequest(
        {"x-spiffe-id": _AGENT_INSTANCED}, {"agent_id": "nhi_abcdefabcdef"}
    )
    assert await dep(req) == _AGENT_INSTANCED


@pytest.mark.asyncio
async def test_legacy_two_segment_agent_passes_on_name(monkeypatch):
    _install_acl(monkeypatch, {_PATH: _RULE})
    dep = require_spiffe_id(_PATH)
    req = _FakeRequest({"x-spiffe-id": _AGENT_LEGACY}, {"agent_id": "letta"})
    assert await dep(req) == _AGENT_LEGACY


@pytest.mark.asyncio
async def test_cross_agent_rotation_denied(monkeypatch):
    """One agent must never rotate another agent's cert."""
    _install_acl(monkeypatch, {_PATH: _RULE})
    dep = require_spiffe_id(_PATH)
    req = _FakeRequest({"x-spiffe-id": _AGENT_INSTANCED}, {"agent_id": "langflow"})
    with pytest.raises(HTTPException) as exc:
        await dep(req)
    assert exc.value.status_code == 403
    assert exc.value.detail == "spiffe_id_agent_mismatch"


@pytest.mark.asyncio
async def test_missing_path_param_denied(monkeypatch):
    _install_acl(monkeypatch, {_PATH: _RULE})
    dep = require_spiffe_id(_PATH)
    req = _FakeRequest({"x-spiffe-id": _AGENT_INSTANCED}, {})
    with pytest.raises(HTTPException) as exc:
        await dep(req)
    assert exc.value.status_code == 403
    assert exc.value.detail == "spiffe_id_agent_mismatch"


@pytest.mark.asyncio
async def test_non_prefix_caller_denied(monkeypatch):
    _install_acl(monkeypatch, {_PATH: _RULE})
    dep = require_spiffe_id(_PATH)
    req = _FakeRequest(
        {"x-spiffe-id": "spiffe://yashigani.internal/rogue"}, {"agent_id": "letta"}
    )
    with pytest.raises(HTTPException) as exc:
        await dep(req)
    assert exc.value.status_code == 403
    assert exc.value.detail == "spiffe_id_not_allowed"


@pytest.mark.asyncio
async def test_foreign_trust_domain_prefix_denied(monkeypatch):
    """A cert from another trust domain must not satisfy the prefix grant."""
    _install_acl(monkeypatch, {_PATH: _RULE})
    dep = require_spiffe_id(_PATH)
    req = _FakeRequest(
        {"x-spiffe-id": "spiffe://evil.example/agents/tenant1/letta"},
        {"agent_id": "letta"},
    )
    with pytest.raises(HTTPException) as exc:
        await dep(req)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_prefix_without_verify_flag_passes_any_agent(monkeypatch):
    rule = EndpointAcl(
        allowed_spiffe_ids=frozenset(),
        allowed_spiffe_prefix=_PREFIX,
        verify_spiffe_matches_agent_id=False,
    )
    _install_acl(monkeypatch, {"/internal/agents/ping": rule})
    dep = require_spiffe_id("/internal/agents/ping")
    assert await dep(_FakeRequest({"x-spiffe-id": _AGENT_LEGACY})) == _AGENT_LEGACY


@pytest.mark.asyncio
async def test_bare_frozenset_rule_back_compat(monkeypatch):
    """Legacy {path: frozenset(ids)} ACL shape (test-injected) still enforced."""
    _install_acl(monkeypatch, {_PATH: frozenset({_BACKOFFICE})})
    dep = require_spiffe_id(_PATH)
    assert await dep(_FakeRequest({"x-spiffe-id": _BACKOFFICE})) == _BACKOFFICE
    with pytest.raises(HTTPException) as exc:
        await dep(_FakeRequest({"x-spiffe-id": _AGENT_INSTANCED}, {"agent_id": "letta"}))
    assert exc.value.status_code == 403
    assert exc.value.detail == "spiffe_id_not_allowed"


# ---------------------------------------------------------------------------
# Parser behaviour
# ---------------------------------------------------------------------------

def test_parser_reads_prefix_and_verify_flag():
    acls = _parse_endpoint_acls({
        _PATH: {
            "allowed_spiffe_ids": [_BACKOFFICE],
            "allowed_spiffe_prefix": _PREFIX,
            "verify_spiffe_matches_agent_id": True,
        }
    })
    rule = acls[_PATH]
    assert isinstance(rule, EndpointAcl)
    assert rule.allowed_spiffe_ids == frozenset({_BACKOFFICE})
    assert rule.allowed_spiffe_prefix == _PREFIX
    assert rule.verify_spiffe_matches_agent_id is True


def test_parser_defaults_without_prefix_fields():
    acls = _parse_endpoint_acls({"/x": {"allowed_spiffe_ids": [_BACKOFFICE]}})
    rule = acls["/x"]
    assert rule.allowed_spiffe_prefix == ""
    assert rule.verify_spiffe_matches_agent_id is False


def test_parser_rejects_verify_flag_without_prefix():
    with pytest.raises(ManifestError):
        _parse_endpoint_acls({
            "/x": {
                "allowed_spiffe_ids": [_BACKOFFICE],
                "verify_spiffe_matches_agent_id": True,
            }
        })


def test_parser_rejects_non_spiffe_prefix():
    with pytest.raises(ManifestError):
        _parse_endpoint_acls({
            "/x": {
                "allowed_spiffe_ids": [],
                "allowed_spiffe_prefix": "https://evil.example/",
            }
        })


@pytest.mark.parametrize("manifest_rel", [
    "docker/service_identities.yaml",
    "helm/yashigani/files/service_identities.yaml",
])
def test_real_manifests_carry_cert_rotate_rule(manifest_rel):
    """docker + helm manifests (parity) parse and expose the full rule."""
    from yashigani.pki.identity import load_manifest

    manifest = load_manifest(str(_REPO_ROOT / manifest_rel))
    rule = manifest.endpoint_acls[_PATH]
    assert _BACKOFFICE in rule.allowed_spiffe_ids
    assert "spiffe://yashigani.internal/caddy" in rule.allowed_spiffe_ids
    assert rule.allowed_spiffe_prefix == _PREFIX
    assert rule.verify_spiffe_matches_agent_id is True
