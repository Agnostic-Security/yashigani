"""
Regression — Track C (F-B): per-user identity through Open WebUI.

THE GAP (F-B): OWUI authenticated to the gateway with the shared
yashigani_internal_bearer and the resolver mapped that bearer to a flat
`internal` service identity (RESTRICTED, empty allowed_models) BEFORE any
per-user path. So per-user/group/org RBAC NEVER applied to OWUI traffic —
every OWUI user was `internal`.

THE FIX: the internal bearer establishes OWUI as a TRUSTED FORWARDER. Under
(and only under) the bearer, the resolver honours the OWUI forwarded-user
header (X-OpenWebUI-User-Email) and resolves the ACTUAL per-user Yashigani
identity so per-user/group/org RBAC applies.

THE LOAD-BEARING SECURITY PROPERTY: the forwarded-user header is honoured ONLY
under the internal bearer. A direct/external caller WITHOUT the bearer cannot
set X-OpenWebUI-User-* to impersonate a user — the header is never consulted
off the internal-bearer path. Fail-closed: an unmatched/missing/malformed
forwarded user under the bearer resolves to the baseline-RESTRICTED default,
NEVER to a higher privilege.

PRESERVE: the brain/orchestration path. The brain self-call carries NO
forwarded-user header, so it falls through to the flat `internal` identity and
the brain-reasoning marker (keys on identity_id == "internal") still functions.

Test matrix:
  T1 — bearer + email matching a registered identity -> that per-user identity
  T2 — bearer + email of a DIFFERENT registered identity -> the OTHER identity
       (two different users get two different RBAC records)
  T3 — bearer + email with NO matching identity, default slug registered ->
       the default-slug identity
  T4 — bearer + email with NO match and NO default registered -> synthetic
       baseline-RESTRICTED (never `internal`, never elevated)
  T5 — bearer + NO forwarded user header -> flat `internal` (brain/orch path
       preserved); identity_id == "internal" so the brain marker still keys
  T6 — NO bearer + spoofed X-OpenWebUI-User-Email -> header IGNORED; resolves
       by API key to the caller's OWN identity, not the spoofed user
  T7 — NO bearer + spoofed header + no API key -> None (no impersonation)
  T8 — bearer + explicit slug-map override -> the mapped slug's identity
  T9 — bearer + malformed/empty email -> treated as "no forwarded user" ->
       flat internal (NOT elevated)
"""
from __future__ import annotations

import importlib
import os
import sys
import unittest.mock as mock


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeRequest:
    """Minimal Request stand-in exposing .headers (case-insensitive)."""

    def __init__(self, headers: dict[str, str]):
        # Starlette headers are case-insensitive; emulate via lowercase keys.
        self._h = {k.lower(): v for k, v in headers.items()}

    @property
    def headers(self):
        return self  # acts as the mapping

    def get(self, key, default=""):
        return self._h.get(key.lower(), default)


class _FakeRegistry:
    """Registry stub keyed by slug and api_key."""

    def __init__(self, by_slug: dict[str, dict], by_key: dict[str, dict] | None = None):
        self._by_slug = by_slug
        self._by_key = by_key or {}

    def get_by_slug(self, slug):
        return self._by_slug.get(slug)

    def get_by_api_key(self, key):
        return self._by_key.get(key)


def _load_router_with_env(env: dict[str, str]):
    """Reload openai_router with the given env so module-level OWUI config
    (slug map, default slug, enabled flag, internal bearer) re-evaluates."""
    base = {
        "YASHIGANI_INTERNAL_BEARER": "test-internal-bearer-xyz",
        "LETTA_LLM_MODEL": "qwen2.5:3b",
    }
    base.update(env)
    for key in list(sys.modules.keys()):
        if key.startswith("yashigani.gateway.openai_router"):
            del sys.modules[key]
    with mock.patch.dict(os.environ, base, clear=True):
        mod = importlib.import_module("yashigani.gateway.openai_router")
    return mod


def _mk_identity(slug, **over):
    base = {
        "identity_id": f"id-{slug}",
        "slug": slug,
        "status": "active",
        "kind": "human",
        "groups": [],
        "allowed_models": [],
        "sensitivity_ceiling": "PUBLIC",
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

BEARER = "test-internal-bearer-xyz"
AUTH = {"Authorization": f"Bearer {BEARER}"}


def test_t1_bearer_plus_email_resolves_registered_user():
    """B5 fix: slug is now canonical email_to_slug("alice@corp.example")
    = "alice-corp-example", not the local-part "alice"."""
    mod = _load_router_with_env({})
    # Register under the canonical slug, as the login handler does.
    alice = _mk_identity("alice-corp-example", groups=["engineering"],
                         allowed_models=["gpt-4o"], sensitivity_ceiling="CONFIDENTIAL")
    mod._state.identity_registry = _FakeRegistry({"alice-corp-example": alice})
    req = _FakeRequest({**AUTH, "X-OpenWebUI-User-Email": "alice@corp.example"})
    out = mod._resolve_identity(req)
    assert out is not None
    assert out["identity_id"] == "id-alice-corp-example"
    assert out["allowed_models"] == ["gpt-4o"]
    assert out["sensitivity_ceiling"] == "CONFIDENTIAL"
    assert out["_owui_forwarded"] is True


def test_t2_two_users_get_two_different_rbac():
    """B5 fix: slugs are canonical email_to_slug values, not local-parts."""
    mod = _load_router_with_env({})
    alice = _mk_identity("alice-corp-example", groups=["eng"], allowed_models=["gpt-4o"])
    bob = _mk_identity("bob-corp-example", groups=["sales"], allowed_models=["qwen2.5:3b"])
    mod._state.identity_registry = _FakeRegistry({
        "alice-corp-example": alice,
        "bob-corp-example": bob,
    })

    out_a = mod._resolve_identity(
        _FakeRequest({**AUTH, "X-OpenWebUI-User-Email": "alice@corp.example"}))
    out_b = mod._resolve_identity(
        _FakeRequest({**AUTH, "X-OpenWebUI-User-Email": "bob@corp.example"}))
    assert out_a["identity_id"] == "id-alice-corp-example"
    assert out_b["identity_id"] == "id-bob-corp-example"
    assert out_a["allowed_models"] != out_b["allowed_models"]
    assert out_a["groups"] != out_b["groups"]


def test_t3_no_match_uses_registered_default_slug():
    mod = _load_router_with_env({"YASHIGANI_OWUI_DEFAULT_SLUG": "owui-users"})
    default = _mk_identity("owui-users", kind="service",
                           groups=["owui-users"], allowed_models=["qwen2.5:3b"],
                           sensitivity_ceiling="INTERNAL")
    mod._state.identity_registry = _FakeRegistry({"owui-users": default})
    req = _FakeRequest({**AUTH, "X-OpenWebUI-User-Email": "nobody@corp.example"})
    out = mod._resolve_identity(req)
    assert out["identity_id"] == "id-owui-users"
    assert out["_owui_default"] is True
    assert out["sensitivity_ceiling"] == "INTERNAL"


def test_t4_no_match_no_default_falls_to_baseline_restricted():
    mod = _load_router_with_env({"YASHIGANI_OWUI_DEFAULT_SLUG": "owui-users"})
    # Empty registry — neither user slug nor default slug registered.
    mod._state.identity_registry = _FakeRegistry({})
    req = _FakeRequest({**AUTH, "X-OpenWebUI-User-Email": "ghost@corp.example"})
    out = mod._resolve_identity(req)
    assert out["sensitivity_ceiling"] == "RESTRICTED"
    assert out["allowed_models"] == []
    assert out["_owui_baseline"] is True
    # CRITICAL: never the `internal` privileged identity.
    assert out["identity_id"] != "internal"


def test_t5_bearer_without_forwarded_user_is_flat_internal_brain_preserved():
    mod = _load_router_with_env({})
    mod._state.identity_registry = _FakeRegistry({})
    req = _FakeRequest({**AUTH})  # no X-OpenWebUI-User-* at all
    out = mod._resolve_identity(req)
    assert out["identity_id"] == "internal"
    assert out["kind"] == "service"
    # Brain-reasoning marker keys on identity_id == "internal".
    assert mod.is_brain_reasoning_leg(out, "qwen2.5:3b") is False  # no open round-trip
    # But the identity is the right shape for the marker to engage when a
    # round-trip IS open:
    assert out["identity_id"] == "internal"


def test_t6_no_bearer_spoofed_email_ignored_resolves_own_apikey_identity():
    mod = _load_router_with_env({})
    victim = _mk_identity("alice", allowed_models=["gpt-4o"],
                          sensitivity_ceiling="CONFIDENTIAL")
    attacker = _mk_identity("mallory", allowed_models=[],
                            sensitivity_ceiling="PUBLIC")
    mod._state.identity_registry = _FakeRegistry(
        by_slug={"alice": victim, "mallory": attacker},
        by_key={"attacker-api-key": attacker},
    )
    # Attacker presents their OWN api key (NOT the internal bearer) and tries to
    # spoof alice via the forwarded-user header.
    req = _FakeRequest({
        "Authorization": "Bearer attacker-api-key",
        "X-OpenWebUI-User-Email": "alice@corp.example",
    })
    out = mod._resolve_identity(req)
    # Header IGNORED — resolves to the attacker's own identity, not alice's.
    assert out["identity_id"] == "id-mallory"
    assert out["allowed_models"] == []
    assert out["sensitivity_ceiling"] == "PUBLIC"
    assert "_owui_forwarded" not in out


def test_t7_no_bearer_spoofed_email_no_apikey_is_none():
    mod = _load_router_with_env({})
    mod._state.identity_registry = _FakeRegistry(
        by_slug={"alice": _mk_identity("alice")})
    # No valid bearer, no valid api key — only a spoofed header.
    req = _FakeRequest({"X-OpenWebUI-User-Email": "alice@corp.example"})
    out = mod._resolve_identity(req)
    assert out is None  # anonymous — no impersonation


def test_t8_slug_map_override():
    mod = _load_router_with_env(
        {"YASHIGANI_OWUI_SLUG_MAP": '{"weird.login@corp.example": "alice"}'})
    alice = _mk_identity("alice", allowed_models=["gpt-4o"])
    mod._state.identity_registry = _FakeRegistry({"alice": alice})
    req = _FakeRequest({**AUTH, "X-OpenWebUI-User-Email": "weird.login@corp.example"})
    out = mod._resolve_identity(req)
    assert out["identity_id"] == "id-alice"


def test_t9_malformed_empty_email_is_flat_internal_not_elevated():
    mod = _load_router_with_env({})
    mod._state.identity_registry = _FakeRegistry({})
    # Empty email value -> treated as "no forwarded user" -> flat internal.
    req = _FakeRequest({**AUTH, "X-OpenWebUI-User-Email": "   "})
    out = mod._resolve_identity(req)
    assert out["identity_id"] == "internal"
    assert out["sensitivity_ceiling"] == "RESTRICTED"


def test_t10_registry_unavailable_under_bearer_fails_closed_to_baseline():
    mod = _load_router_with_env({})
    mod._state.identity_registry = None
    req = _FakeRequest({**AUTH, "X-OpenWebUI-User-Email": "alice@corp.example"})
    out = mod._resolve_identity(req)
    # Fail-closed: baseline-RESTRICTED, NEVER internal/elevated.
    assert out["sensitivity_ceiling"] == "RESTRICTED"
    assert out["allowed_models"] == []
    assert out["identity_id"] != "internal"
    assert out["_owui_baseline"] is True
