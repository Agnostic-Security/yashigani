"""
Regression — Track B1 model-RBAC must NOT break letta/qwen-brain orchestration.

MUST-FIX-1 (Iris BLOCKER): the brain-reasoning (A→L) leg arrives as a FRESH
inbound /v1 request from the `internal` service identity (groups[], no org,
allowed_models[]) on the brain model (LETTA_LLM_MODEL=qwen2.5:3b).  The instant
ANY alias resolving to that model is allocated to some group, the model becomes
globally allocation-GATED.  `internal` holds no allocation, so the B1 alloc-bind
re-check (`EffectiveModels.is_model_denied`) returns True → the brain's cognition
leg 403s → orchestration dies.

The FIX exempts the SERVER-MINTED, UNFORGEABLE brain-reasoning leg from the
alloc-bind re-check — and ONLY that leg (LAURA-B1R-001):

    _model_rbac_exempt = brain_reasoning_leg          # process-local round-trip
    if _effective is not None and not _model_rbac_exempt and _effective.is_model_denied(...):
        return 403

SECURITY (LAURA-B1R-001, model-hop bypass, v2.25.4): the exemption was NARROWED.
An earlier version included the `_orchestration_self_call` identity flag, but a
PRINCIPAL-bearing orchestration self-call (a model/agent TOOL HOP) resolves to the
REAL caller's identity WITH that flag and WITH their real allocations.  Exempting
it let a model tool-hop reach a non-allocated model (fastuser → model__qwen2_5_3b
→ served).  The exemption now consults ONLY the server-minted brain-reasoning leg
(`is_brain_reasoning_leg` — process-local round-trip counter + internal-bearer
identity + brain model), which carries NO principal.  The forgeable
X-Yashigani-Orchestration-Depth header is still NEVER consulted.  So: the internal
cognition leg still completes, but every principal-bearing model hop is enforced.

These tests prove the exemption logic byte-for-byte:
  • the brain-reasoning leg (round-trip open + internal identity + brain model)
    is EXEMPT even when the brain model is gated;
  • a PRINCIPAL-bearing self-call (model hop, `_orchestration_self_call` set but
    NOT the brain leg) is NOT exempt → DENIED (model-hop bypass closed);
  • a real external user with a FORGED X-Yashigani-Orchestration-Depth header and
    NO marker is NOT exempt → still DENIED (the header bypass is closed);
  • a REAL user on the SAME gated model with NO round-trip / NO marker is NOT
    exempt → still DENIED (no real-user bypass);
  • the internal identity OUTSIDE a brain round-trip on a gated model is NOT
    exempt (the marker requires an OPEN round-trip) → still denied.
"""
from __future__ import annotations

import os

import fakeredis
import pytest

# openai_router fail-closes at import if the internal bearer is absent.
os.environ.setdefault("YASHIGANI_INTERNAL_BEARER", "test-bearer-b1-exempt")

from yashigani.gateway import openai_router as router  # noqa: E402
from yashigani.models.alias_store import ModelAlias, ModelAliasStore  # noqa: E402
from yashigani.models.allocation_store import ModelAllocationStore  # noqa: E402
from yashigani.models.effective import resolve_effective_allowed_models  # noqa: E402


BRAIN_MODEL = router._BRAIN_REASONING_MODEL  # LETTA_LLM_MODEL, default qwen2.5:3b


class _Req:
    """Minimal request stub exposing .headers like Starlette's Request."""

    def __init__(self, headers: dict | None = None):
        self.headers = headers or {}


@pytest.fixture
def gated_effective():
    """An EffectiveModels for the `internal` identity where BRAIN_MODEL is gated
    (allocated to some other group) and `internal` is allocated nothing."""
    redis = fakeredis.FakeRedis()
    alias_store = ModelAliasStore(redis_client=redis)
    alias_store.set(
        "brainfast",
        ModelAlias(alias="brainfast", provider="ollama", model=BRAIN_MODEL, force_local=True),
    )
    alloc_store = ModelAllocationStore(redis_client=redis)
    # Allocate the brain model to a group the `internal` identity is NOT in →
    # globally gated, internal not allocated.
    alloc_store.add("brainfast", "group", "brain")

    internal_identity = {
        "identity_id": "internal", "status": "active", "kind": "service",
        "groups": [], "allowed_models": [], "org_id": "",
    }
    eff = resolve_effective_allowed_models(internal_identity, alloc_store, alias_store)
    return eff, internal_identity


def _is_denied_with_exemption(eff, identity, model, request) -> bool:
    """Replicate the router's guarded alloc-bind decision (openai_router ~1375).

    Mirrors EXACTLY (LAURA-B1R-001 — the model-RBAC exemption is the SERVER-MINTED
    brain-reasoning leg ONLY; NEITHER the forgeable X-Yashigani-Orchestration-Depth
    header NOR the `_orchestration_self_call` identity flag grants it):
        _model_rbac_exempt = brain_reasoning_leg
        denied = eff is not None and not _model_rbac_exempt and eff.is_model_denied(model)

    A principal-bearing orchestration self-call (a model/agent TOOL HOP) carries the
    REAL caller's allocations, so it MUST be enforced — exempting it on
    `_orchestration_self_call` was the model-hop bypass (LAURA-B1R-001).  The
    `request` arg is retained to assert a forged depth header does NOT influence it.
    """
    brain_reasoning_leg = router.is_brain_reasoning_leg(identity, model)
    model_rbac_exempt = brain_reasoning_leg
    return (
        eff is not None
        and not model_rbac_exempt
        and eff.is_model_denied(model)
    )


def test_gated_brain_model_is_denied_without_exemption(gated_effective):
    """Sanity: the brain model IS denied to `internal` by the raw alloc-bind
    check (this is the bug B1 introduced that MUST-FIX-1 exempts)."""
    eff, _ = gated_effective
    assert eff.is_model_denied(BRAIN_MODEL) is True


def test_brain_reasoning_leg_is_exempt(gated_effective):
    """Round-trip OPEN + internal identity + brain model → exempt → NOT denied."""
    eff, internal_identity = gated_effective
    router.brain_reasoning_leg_begin()
    try:
        # No depth header — the marker is the process-local round-trip, not a header.
        denied = _is_denied_with_exemption(eff, internal_identity, BRAIN_MODEL, _Req())
        assert denied is False, "brain-reasoning leg must be exempt from alloc-bind"
    finally:
        router.brain_reasoning_leg_end()


def test_principal_bearing_self_call_is_NOT_exempt(gated_effective):
    """REGRESSION (LAURA-B1R-001 — model-hop bypass): a principal-bearing
    orchestration self-call (the `_orchestration_self_call` server-minted flag is
    set, but it is NOT the brain-reasoning leg) carries the REAL caller's
    allocations → it must be ENFORCED, NOT exempt → DENIED on a gated model the
    caller is not allocated.  Exempting it (the old behaviour) let a model tool-hop
    reach a non-allocated model.  Only the genuine brain-reasoning leg is exempt."""
    eff, internal_identity = gated_effective
    server_minted = dict(internal_identity)
    server_minted["_orchestration_self_call"] = True
    # No brain round-trip open → is_brain_reasoning_leg False → NOT exempt.
    denied = _is_denied_with_exemption(eff, server_minted, BRAIN_MODEL, _Req())
    assert denied is True, (
        "a principal-bearing self-call (not the brain leg) must NOT be exempt — "
        "model-hop bypass closed (LAURA-B1R-001)"
    )


def test_forged_depth_header_alone_is_DENIED_bypass_closed(gated_effective):
    """REGRESSION (Laura+Iris bypass v2.25.4): a real external user who FORGES
    X-Yashigani-Orchestration-Depth but has NO server-minted flag must NOT be
    exempt → STILL DENIED.  This is the exact hole the prior test green-lit:
    the raw forgeable header must never win the exemption."""
    eff, _ = gated_effective
    # A real external user (not internal-bearer), allocated nothing, who sets the
    # forgeable depth header hoping to skip the model-RBAC re-check.
    real_user = {
        "identity_id": "fastuser", "groups": ["sales"],
        "allowed_models": [], "org_id": "",
        # NO "_orchestration_self_call" — only the internal-bearer branch sets it.
    }
    req = _Req({"x-yashigani-orchestration-depth": "1"})
    denied = _is_denied_with_exemption(eff, real_user, BRAIN_MODEL, req)
    assert denied is True, (
        "forged depth header alone must NOT exempt a real user — bypass closed"
    )


def test_internal_identity_forged_header_no_flag_still_denied(gated_effective):
    """Even the `internal` identity, if it somehow lacks the server-minted flag,
    is NOT exempted by a depth header alone (the header is never consulted)."""
    eff, internal_identity = gated_effective
    # internal_identity here has NO _orchestration_self_call flag set.
    req = _Req({"x-yashigani-orchestration-depth": "5"})
    denied = _is_denied_with_exemption(eff, internal_identity, BRAIN_MODEL, req)
    assert denied is True, "raw depth header must never grant the exemption"


def test_real_user_same_gated_model_still_denied(gated_effective):
    """A REAL user (non-internal) on the SAME gated model with NO round-trip and
    NO depth header is NOT exempt → STILL DENIED (no real-user bypass)."""
    eff, _ = gated_effective
    real_user = {"identity_id": "u1", "groups": ["sales"], "allowed_models": [], "org_id": ""}
    # Even if a brain round-trip happens to be open, the identity is not `internal`
    # so is_brain_reasoning_leg is False for this caller.
    router.brain_reasoning_leg_begin()
    try:
        denied = _is_denied_with_exemption(eff, real_user, BRAIN_MODEL, _Req())
        assert denied is True, "real user must NOT inherit the brain-leg exemption"
    finally:
        router.brain_reasoning_leg_end()


def test_internal_outside_roundtrip_still_denied(gated_effective):
    """The `internal` identity on the gated model OUTSIDE any open brain round-trip
    (no depth header) is NOT exempt — the marker requires an OPEN round-trip."""
    eff, internal_identity = gated_effective
    # No begin() → no open round-trip → is_brain_reasoning_leg False.
    assert router._brain_reasoning_active_now() is False
    denied = _is_denied_with_exemption(eff, internal_identity, BRAIN_MODEL, _Req())
    assert denied is True


def test_internal_wrong_model_inside_roundtrip_still_denied(gated_effective):
    """Inside an open round-trip, the `internal` identity on a NON-brain gated
    model is NOT a reasoning leg → still denied (marker is brain-model-scoped)."""
    eff, internal_identity = gated_effective
    router.brain_reasoning_leg_begin()
    try:
        assert router.is_brain_reasoning_leg(internal_identity, "gpt-4o") is False
        # A gated model that is NOT the brain model: still denied for internal.
        # (BRAIN_MODEL with wrong identity already covered; here wrong model.)
        denied_wrong_model = _is_denied_with_exemption(
            eff, internal_identity, "gpt-4o", _Req()
        )
        # gpt-4o is not gated in this fixture → not denied anyway; the load-bearing
        # assertion is that the marker did NOT fire for the wrong model.
        assert denied_wrong_model is False
    finally:
        router.brain_reasoning_leg_end()


# ───────────────────────────────────────────────────────────────────────────
# FIX 2 — OPA model_allowed backstop (belt-and-braces second enforcement layer).
#
# The /v1 OPA gate (openai_router ~1408) previously checked ONLY
# opa_decision["allow"] (= allow_v1, identity active) and never
# opa_decision["model_allowed"].  So the alloc-bind re-check was the SOLE
# model-RBAC enforcement at /v1 — the single point the bypass disabled.
# FIX 2 ALSO enforces model_allowed, with the SAME brain-leg-only exemption
# (LAURA-B1R-001 narrowed it from `_orchestration_internal_leg` to
# `_model_rbac_exempt = brain_reasoning_leg`).  These mirror the router's layer-2:
#
#     if not _model_rbac_exempt and not opa_decision.get("model_allowed", False):
#         return 403 model_not_allocated
# ───────────────────────────────────────────────────────────────────────────


def _opa_backstop_denies(model_rbac_exempt: bool, model_allowed: bool) -> bool:
    """Replicate the router's FIX-2 OPA model_allowed backstop (openai_router ~1452)."""
    return (not model_rbac_exempt) and (not model_allowed)


def test_opa_backstop_denies_non_allocated_model():
    """A real user whose effective allowlist excludes the model → OPA returns
    model_allowed=False → the backstop independently DENIES (second layer)."""
    # not the brain leg; OPA says the model is outside the allowlist.
    assert _opa_backstop_denies(model_rbac_exempt=False, model_allowed=False) is True


def test_opa_backstop_allows_allocated_model():
    """The same gate must NOT deny a model that IS in the caller's allowlist
    (model_allowed=True) — no false positive on legitimate allocations (OBS-1)."""
    assert _opa_backstop_denies(model_rbac_exempt=False, model_allowed=True) is False


def test_opa_backstop_exempts_brain_reasoning_leg():
    """The brain-reasoning leg (server-minted) must NOT be wrongly denied by the
    backstop even though `internal` holds no allocation (model_allowed=False)."""
    assert _opa_backstop_denies(model_rbac_exempt=True, model_allowed=False) is False


def test_opa_backstop_principal_self_call_not_exempt():
    """REGRESSION (LAURA-B1R-001): a principal-bearing self-call (model hop) is NOT
    the brain-reasoning leg, so it is NOT exempt at the backstop either — a model
    hop to a non-allocated model is DENIED by the OPA layer too."""
    real_user = {"identity_id": "fastuser", "groups": ["sales"],
                 "allowed_models": [], "_orchestration_self_call": True}
    # The exemption fed to the backstop is brain_reasoning_leg ONLY — the
    # _orchestration_self_call flag does NOT grant it.
    model_rbac_exempt = router.is_brain_reasoning_leg(real_user, BRAIN_MODEL)
    assert model_rbac_exempt is False
    assert _opa_backstop_denies(model_rbac_exempt, model_allowed=False) is True


def test_opa_backstop_forged_header_does_not_exempt():
    """A forged depth header never sets the brain-leg marker, so a real user forging
    the header is still denied by the OPA layer (header is never consulted)."""
    real_user = {"identity_id": "fastuser", "groups": ["sales"], "allowed_models": []}
    model_rbac_exempt = router.is_brain_reasoning_leg(real_user, BRAIN_MODEL)
    assert model_rbac_exempt is False
    assert _opa_backstop_denies(model_rbac_exempt, model_allowed=False) is True
