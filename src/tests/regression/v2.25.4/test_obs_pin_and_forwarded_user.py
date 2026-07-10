"""
Regression — LAURA-B1-OBS-A + LAURA-OBS-B (v2.25.4 pre-tag hardening).

Two distinct Laura findings against the model-RBAC / identity-resolution path,
both fixed in openai_router.py and asserted here byte-for-byte.

──────────────────────────────────────────────────────────────────────────────
LAURA-B1-OBS-A — an EXPLICIT model-pin you are not allocated must DENY VISIBLY.

THE GAP: the OBS-1 local-default fallback silently substitutes an ALLOCATED
model when the global default would be denied to the caller.  That substitution
is correct for AUTO/DEFAULT selection (the caller never asked for the denied
model).  But it was ALSO masking an EXPLICIT pin: a caller who PINNED a concrete
model they are not allocated (``body.model`` truthy) was silently served an
allocated substitute with HTTP 200 — a security product hiding its own
enforcement.

THE FIX: when the CALLER pinned the model (``body.model`` truthy) and that model
is denied to them, return a VISIBLE ``403 model_not_allocated`` — byte-for-byte
the verdict the orchestrate-seed path already returns — instead of a silent
substitute.  AUTO/default selection (``body.model`` falsy) keeps the OBS-1
substitute.  The discriminator is the caller's own request body (forgery-proof;
a deny only ever REMOVES access).  No non-allocated model is served on EITHER
branch.

  T_obsa_1 — pinned + denied -> 403 model_not_allocated + X-Yashigani-OPA-Reason
  T_obsa_2 — pinned + ALLOWED -> NOT denied (no false-positive 403; request flows)

──────────────────────────────────────────────────────────────────────────────
LAURA-OBS-B — X-Forwarded-User must be trust-gated behind X-Caddy-Verified-Secret.

THE GAP: X-OpenWebUI-User-* is honoured ONLY inside the proven internal-bearer
branch, but X-Forwarded-User (the SSO identity Caddy re-injects after forward_auth)
was honoured UNCONDITIONALLY in the registry path.  On the mesh listener (8081)
CaddyVerifiedMiddleware is NOT active, so a raw in-mesh caller could set
``X-Forwarded-User: <victim>`` and be served the victim's identity — an in-mesh
identity-reassignment primitive.  (Caddy strips it at the public edge, so it is
not edge-exploitable today; the latent asymmetry is closed regardless.)

THE FIX: honour X-Forwarded-User ONLY when the request also carries a VALID
X-Caddy-Verified-Secret (the per-install caddy_internal_hmac) — the SAME
cryptographic trust proof that anchors the legitimate Caddy forward_auth path.
``validate_caddy_secret`` fail-closes when the secret is unloaded, so this never
fail-opens.

  T_obsb_1 — X-Forwarded-User + VALID secret -> resolves the SSO user
  T_obsb_2 — X-Forwarded-User + NO secret    -> IGNORED (no impersonation)
  T_obsb_3 — X-Forwarded-User + WRONG secret -> IGNORED (no impersonation)
  T_obsb_4 — X-Forwarded-User + secret UNLOADED (None) -> IGNORED (fail-closed)
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import sys
import unittest.mock as mock
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# openai_router fail-closes at import if the internal bearer is absent.
os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-internal-bearer-obs")

from yashigani.models.effective import EffectiveModels  # noqa: E402


# ════════════════════════════════════════════════════════════════════════════
# LAURA-B1-OBS-A — explicit-pin deny is VISIBLE (403), route-level
# ════════════════════════════════════════════════════════════════════════════

def _stub_engine():
    """An optimisation engine whose route() ALWAYS substitutes the allocated
    model 'fast'.  This is the masking scenario OBS-A closes: without OBS-A, a
    pinned-denied model would be silently re-routed to 'fast' and served 200, so
    the downstream alloc-bind would never see the denied model.  We record whether
    route() is reached — if OBS-A fires it must NOT be."""
    eng = MagicMock()
    eng._default_model = "qwen2.5:3b"
    eng._resolve_alias = lambda m: (None, m, None)
    eng.route = MagicMock(return_value=SimpleNamespace(
        provider="ollama", model="fast", rule="r", reason="substituted"))
    return eng


def _stub_classifier_scorer(mod):
    from yashigani.optimization.sensitivity_classifier import (
        SensitivityLevel, SensitivityResult)
    from yashigani.optimization.complexity_scorer import (
        ComplexityLevel, ComplexityResult)
    cls = MagicMock()
    cls.classify_decoded = lambda text: SensitivityResult(level=SensitivityLevel.PUBLIC)
    sco = MagicMock()
    sco.score = lambda text, n: ComplexityResult(
        level=ComplexityLevel.MEDIUM, token_count=n, heuristic_score=0.0, reasons=[])
    return cls, sco


def _import_router_fresh(*, engine_active: bool):
    """Load openai_router into a fresh module object.

    engine_active=True wires a substitute-engine + classifier + scorer so the
    OBS-1 fallback path (line 1362) is LIVE — the only configuration in which
    OBS-A's "deny BEFORE the silent substitute" is observable."""
    src_root = Path(__file__).parents[3]  # regression/v2.25.4 -> tests -> src
    router_path = src_root / "yashigani" / "gateway" / "openai_router.py"
    mod_name = "yashigani.gateway.openai_router._test_obs_a"
    spec = importlib.util.spec_from_file_location(mod_name, router_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)

    s = mod._state
    s.streaming_enabled = False
    s.streaming_inspect_interval = 200
    s.ddos_protector = None
    s.identity_registry = None
    s.budget_enforcer = None
    s.token_counter = None
    s.audit_writer = None
    s.content_relay_detector = None
    s.ollama_url = "http://ollama-test:11434"
    s.default_model = "test-model"
    s.available_models = []
    s.agent_registry = None
    s.response_inspection_pipeline = None
    s.pii_detector = None
    s.pii_cloud_bypass = False
    s.model_alias_store = None
    s.opa_url = ""  # OPA off for this unit path
    if engine_active:
        s.optimization_engine = _stub_engine()
        s.sensitivity_classifier, s.complexity_scorer = _stub_classifier_scorer(mod)
    else:
        s.optimization_engine = None
        s.sensitivity_classifier = None
        s.complexity_scorer = None
    os.environ["YASHIGANI_OPA_OPTIONAL"] = "true"
    os.environ.setdefault("YASHIGANI_ENV", "test")
    return mod


def _internal_request():
    """A request authenticated as the internal service account (so
    _resolve_identity does not 401 before the OBS-A branch)."""
    bearer = os.environ["YASHIGANI_INTERNAL_BEARER"]
    headers = {"authorization": f"Bearer {bearer}"}
    hmock = MagicMock()
    hmock.get = lambda key, default="": headers.get(key.lower(), default)
    req = MagicMock()
    req.headers = hmock
    req.client = MagicMock()
    req.client.host = "127.0.0.1"
    return req


@pytest.mark.asyncio
async def test_t_obsa_1_pinned_denied_model_denies_before_silent_substitute():
    """Pinned a non-allocated model -> visible 403 model_not_allocated, returned
    BEFORE the optimiser runs.  Specificity: the substitute-engine's route() must
    NOT be reached — proving the deny is OBS-A (line 1322), not the downstream
    alloc-bind that would only fire on the substituted model.  Without OBS-A,
    route() would re-route to 'fast' and the request would be served HTTP 200."""
    mod = _import_router_fresh(engine_active=True)
    # Caller is restricted to {"fast"}; "gpt-4o" is therefore denied.
    mod._effective_allowed_models = lambda identity: EffectiveModels(
        allowed={"fast"}, has_restriction=True
    )
    body = mod.ChatCompletionRequest(
        model="gpt-4o",  # EXPLICIT pin of a denied model
        messages=[mod.ChatMessage(role="user", content="hi")],
    )
    result = await mod.chat_completions(body, _internal_request())

    assert getattr(result, "status_code", None) == 403, (
        "explicit-pin of a denied model must DENY visibly (403), not silently "
        "substitute an allocated model"
    )
    import json
    payload = json.loads(bytes(result.body))
    assert payload["error"]["code"] == "model_not_allocated"
    assert payload["error"]["type"] == "policy_denied"
    assert result.headers.get("X-Yashigani-OPA-Reason") == "model_not_allocated"
    # THE discriminator: OBS-A returns before the optimiser's silent substitute.
    mod._state.optimization_engine.route.assert_not_called()


@pytest.mark.asyncio
async def test_t_obsa_2_pinned_allowed_model_is_not_denied():
    """Pinning a model the caller IS allocated must NOT 403 (no false-deny); the
    request flows on through the optimiser to the upstream."""
    mod = _import_router_fresh(engine_active=True)
    mod._effective_allowed_models = lambda identity: EffectiveModels(
        allowed={"fast"}, has_restriction=True
    )
    captured = []

    async def _fake_post(url, json=None, **kwargs):
        captured.append(json)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {
            "message": {"content": "ok"},
            "prompt_eval_count": 1,
            "eval_count": 1,
        }
        return resp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = _fake_post

    body = mod.ChatCompletionRequest(
        model="fast",  # EXPLICIT pin of an ALLOWED model
        messages=[mod.ChatMessage(role="user", content="hi")],
    )
    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await mod.chat_completions(body, _internal_request())

    # Must NOT be the OBS-A 403 — an allowed pin proceeds past OBS-A to routing.
    assert getattr(result, "status_code", 200) != 403, (
        "pinning an ALLOWED model must not trigger the OBS-A deny"
    )
    mod._state.optimization_engine.route.assert_called_once()


# ════════════════════════════════════════════════════════════════════════════
# LAURA-OBS-B — X-Forwarded-User trust-gate (unit, _resolve_identity)
# ════════════════════════════════════════════════════════════════════════════

class _FakeRequest:
    """Minimal Request stand-in exposing case-insensitive .headers."""

    def __init__(self, headers: dict[str, str]):
        self._h = {k.lower(): v for k, v in headers.items()}

    @property
    def headers(self):
        return self

    def get(self, key, default=""):
        return self._h.get(key.lower(), default)


class _FakeRegistry:
    def __init__(self, by_slug=None, by_key=None):
        self._by_slug = by_slug or {}
        self._by_key = by_key or {}

    def get_by_slug(self, slug):
        return self._by_slug.get(slug)

    def get_by_api_key(self, key):
        return self._by_key.get(key)


def _load_router_with_env(env: dict[str, str]):
    base = {
        "YASHIGANI_INTERNAL_BEARER": "test-internal-bearer-obs",
        "LETTA_LLM_MODEL": "qwen2.5:3b",
    }
    base.update(env)
    for key in list(sys.modules.keys()):
        if key.startswith("yashigani.gateway.openai_router"):
            del sys.modules[key]
    with mock.patch.dict(os.environ, base, clear=True):
        return importlib.import_module("yashigani.gateway.openai_router")


SECRET = "a" * 64  # 64-char hex shape, matches caddy_internal_hmac


def _mk_user(slug):
    return {
        "identity_id": f"id-{slug}", "slug": slug, "status": "active",
        "kind": "human", "groups": ["eng"], "allowed_models": ["gpt-4o"],
        "sensitivity_ceiling": "CONFIDENTIAL",
    }


def test_t_obsb_1_forwarded_user_with_valid_secret_resolves_sso_user():
    mod = _load_router_with_env({})
    mod._state.identity_registry = _FakeRegistry(by_slug={"coderuser": _mk_user("coderuser")})
    import yashigani.auth.caddy_verified as cv
    with mock.patch.object(cv, "_caddy_secret", SECRET):
        req = _FakeRequest({
            "X-Forwarded-User": "coderuser",
            "X-Caddy-Verified-Secret": SECRET,
        })
        out = mod._resolve_identity(req)
    assert out is not None and out["identity_id"] == "id-coderuser"


def test_t_obsb_2_forwarded_user_without_secret_is_ignored():
    mod = _load_router_with_env({})
    mod._state.identity_registry = _FakeRegistry(by_slug={"coderuser": _mk_user("coderuser")})
    import yashigani.auth.caddy_verified as cv
    with mock.patch.object(cv, "_caddy_secret", SECRET):
        # No X-Caddy-Verified-Secret header at all + no API key -> anonymous.
        req = _FakeRequest({"X-Forwarded-User": "coderuser"})
        out = mod._resolve_identity(req)
    assert out is None, "X-Forwarded-User without the verified secret must be ignored"


def test_t_obsb_3_forwarded_user_with_wrong_secret_is_ignored():
    mod = _load_router_with_env({})
    mod._state.identity_registry = _FakeRegistry(by_slug={"coderuser": _mk_user("coderuser")})
    import yashigani.auth.caddy_verified as cv
    with mock.patch.object(cv, "_caddy_secret", SECRET):
        req = _FakeRequest({
            "X-Forwarded-User": "coderuser",
            "X-Caddy-Verified-Secret": "b" * 64,  # wrong
        })
        out = mod._resolve_identity(req)
    assert out is None, "a mismatched verified secret must not honour X-Forwarded-User"


def test_t_obsb_4_forwarded_user_secret_unloaded_fails_closed():
    mod = _load_router_with_env({})
    mod._state.identity_registry = _FakeRegistry(by_slug={"coderuser": _mk_user("coderuser")})
    import yashigani.auth.caddy_verified as cv
    with mock.patch.object(cv, "_caddy_secret", None):  # lifespan not run
        req = _FakeRequest({
            "X-Forwarded-User": "coderuser",
            "X-Caddy-Verified-Secret": SECRET,
        })
        out = mod._resolve_identity(req)
    assert out is None, "secret unloaded -> validate_caddy_secret False -> fail-closed"
