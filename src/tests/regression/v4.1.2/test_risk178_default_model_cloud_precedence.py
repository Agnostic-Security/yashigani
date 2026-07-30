"""
Regression tests — YSG-RISK-178 (default-model / cloud-precedence bug,
2026-07-30, product-correctness fix per Tiago's design rule).

RULE: "the default model is ALWAYS the local model, UNLESS a cloud model is
configured with an API key AND set as default."

Root cause: on a fresh LOCAL install (no cloud API key configured anywhere --
no KMS secret, no ANTHROPIC_API_KEY/OPENAI_API_KEY env var), a plain chat
request with NO explicit model and NO @mention resolves at the gateway to
``_state.default_model`` (the local ollama model, correctly). But
``OptimizationEngine.route()`` then evaluates P1-P9 and, whenever the
complexity scorer rated the prompt HIGH (P6), OR an identity carried
``force_cloud`` (P5), OR an admin had configured a trusted-cloud provider for
a sensitivity level (P1) -- ALL THREE unconditionally substituted the
DEFAULT cloud provider/model (``claude-sonnet-4-6``/anthropic) for the
ollama-resolved request, with ZERO check that an API key was actually
configured for it. On a fresh local/demo stack this silently routed a
no-mention, no-explicit-model chat to a cloud model that then 422/503'd
downstream (``_get_cloud_api_key`` correctly refuses, but only AFTER the
engine had already committed to cloud) -- the exact opposite of the intended
"local first" default.

This had previously been triaged as an EXPECTED non-issue in
YSG-RISK-175's "Confirmed non-issues" note ("Direct-cloud-model
422/model_not_found ... is EXPECTED on this local-only demo stack") --
that triage was WRONG; it is a real product-correctness bug, corrected here.

FIX (``src/yashigani/optimization/engine.py``): ``OptimizationEngine`` gained
a ``cloud_key_available: Callable[[], bool] | None`` constructor param.
P1 (trusted-cloud), P5 (force_cloud) and P6 (complexity HIGH) -- the three
points where the engine substitutes ``default_cloud_provider``/
``default_cloud_model`` for an ollama-resolved request without the caller
having explicitly pinned a cloud model -- now consult
``self._default_cloud_usable()`` first; when it returns False they fall back
to the LOCAL default (`P5-DEGRADED`/`P6-DEGRADED` rules, or straight through
to the existing local branch for P1) instead of silently handing back an
unusable cloud decision. ``cloud_key_available=None`` (not wired) preserves
legacy-permissive behaviour for callers that construct the engine directly
(unit tests, any code predating this fix).

Production wiring (``src/yashigani/gateway/entrypoint.py``): the engine is
now constructed with a real ``cloud_key_available`` callable that lazily
calls ``openai_router._get_cloud_api_key(default_cloud_provider)`` -- the
SAME KMS-then-env-var resolution the actual cloud HTTP call uses, so "is a
key configured" has one source of truth.

An EXPLICIT cloud pin (the caller/alias resolves to a non-ollama provider
BEFORE reaching these rules, e.g. ``model: "smart"``) is NEVER gated by this
-- that path already correctly surfaces a clear 503
("Cloud provider ... is not configured") from
``openai_router.py``'s existing ``_get_cloud_api_key`` check, which is
honest signalling for a request the caller explicitly asked to route to
cloud, not the silent-default bug this fix closes.
"""
from __future__ import annotations

from yashigani.optimization.engine import OptimizationEngine
from yashigani.optimization.sensitivity_classifier import SensitivityLevel, SensitivityResult
from yashigani.optimization.complexity_scorer import ComplexityLevel, ComplexityResult
from yashigani.billing.budget_enforcer import BudgetSignal, BudgetState


def _sens(level: SensitivityLevel = SensitivityLevel.PUBLIC) -> SensitivityResult:
    return SensitivityResult(level=level, triggers=[], layer_results={"regex": level})


def _comp(level: ComplexityLevel = ComplexityLevel.MEDIUM) -> ComplexityResult:
    return ComplexityResult(level=level, token_count=500, heuristic_score=0.0, reasons=[])


def _budget(signal: BudgetSignal = BudgetSignal.NORMAL, pct: int = 0) -> BudgetState:
    return BudgetState(identity_id="test", provider="anthropic", used=pct * 100, total=10000,
                        signal=signal, pct=pct)


class TestRisk178DefaultModelPrecedence:
    """(1) no cloud key + no explicit model -> resolves to the local model."""

    def test_fresh_local_install_high_complexity_no_mention_stays_local(self):
        # Simulates a fresh LOCAL install: no cloud key configured anywhere.
        engine = OptimizationEngine(
            default_model="qwen2.5:3b",
            default_cloud_provider="anthropic",
            default_cloud_model="claude-sonnet-4-6",
            cloud_key_available=lambda: False,
        )
        # Gateway already resolved "no explicit model" -> the local default
        # (_state.default_model) BEFORE calling route() -- requested_model is
        # therefore the local model name, exactly as openai_router.py:1856
        # (`selected_model = body.model or _state.default_model`) produces
        # for a bare no-mention, no-model chat send.
        d = engine.route(
            requested_model="qwen2.5:3b",
            sensitivity=_sens(),
            complexity=_comp(ComplexityLevel.HIGH),  # would have triggered P6
            budget=_budget(),
        )
        assert d.is_local, (
            "YSG-RISK-178 regression: a no-mention/no-explicit-model chat on "
            "a stack with NO cloud key configured must resolve LOCAL, never "
            "silently substitute the default cloud model."
        )
        assert d.provider == "ollama"
        assert d.model == "qwen2.5:3b"
        assert d.rule == "P6-DEGRADED"

    def test_fresh_local_install_never_surfaces_unusable_cloud_default(self):
        """No rule may return the configured cloud default when no key is
        configured, for any of the three implicit-substitution rules."""
        engine = OptimizationEngine(
            default_model="qwen2.5:3b",
            default_cloud_provider="anthropic",
            default_cloud_model="claude-sonnet-4-6",
            trusted_cloud_providers={"CONFIDENTIAL": "anthropic"},
            cloud_key_available=lambda: False,
        )
        decisions = [
            engine.route("qwen2.5:3b", _sens(), _comp(ComplexityLevel.HIGH), _budget()),
            engine.route("qwen2.5:3b", _sens(), _comp(), _budget(), force_cloud=True),
            engine.route("qwen2.5:3b", _sens(SensitivityLevel.CONFIDENTIAL), _comp(), _budget()),
        ]
        for d in decisions:
            assert d.model != "claude-sonnet-4-6", (
                f"YSG-RISK-178 regression: rule {d.rule} surfaced the unusable "
                f"cloud default with no key configured"
            )
            assert d.is_local


class TestRisk178CloudDefaultWithKeyStillWorks:
    """(2) cloud model set as default WITH a key -> uses cloud (unchanged)."""

    def test_high_complexity_with_key_configured_routes_cloud(self):
        engine = OptimizationEngine(
            default_model="qwen2.5:3b",
            default_cloud_provider="anthropic",
            default_cloud_model="claude-sonnet-4-6",
            cloud_key_available=lambda: True,
        )
        d = engine.route("qwen2.5:3b", _sens(), _comp(ComplexityLevel.HIGH), _budget())
        assert not d.is_local
        assert d.provider == "anthropic"
        assert d.model == "claude-sonnet-4-6"
        assert d.rule == "P6"


class TestRisk178CloudDefaultWithoutKeyFallsBackNoError:
    """(3) cloud set as default WITHOUT a key -> falls back to local, no error
    (never raises, never returns a decision that would 422/503 downstream)."""

    def test_force_cloud_identity_without_key_degrades_cleanly(self):
        engine = OptimizationEngine(
            default_model="qwen2.5:3b",
            default_cloud_provider="anthropic",
            default_cloud_model="claude-sonnet-4-6",
            cloud_key_available=lambda: False,
        )
        d = engine.route("qwen2.5:3b", _sens(), _comp(), _budget(), force_cloud=True)
        assert d.is_local
        assert d.provider == "ollama"
        assert d.rule == "P5-DEGRADED"

    def test_broken_key_checker_fails_closed_not_open(self):
        """A checker that raises must be treated as 'unavailable', never
        misread as 'available' -- fail-closed, not fail-open."""
        def _boom():
            raise RuntimeError("KMS unreachable")

        engine = OptimizationEngine(
            default_model="qwen2.5:3b",
            default_cloud_provider="anthropic",
            default_cloud_model="claude-sonnet-4-6",
            cloud_key_available=_boom,
        )
        d = engine.route("qwen2.5:3b", _sens(), _comp(ComplexityLevel.HIGH), _budget())
        assert d.is_local
        assert d.rule == "P6-DEGRADED"


class TestRisk178ProductionWiring:
    """entrypoint.py must actually wire cloud_key_available -- not just leave
    the engine capability unused (the bug is only closed end-to-end if the
    real gateway boot path passes a real checker)."""

    def test_entrypoint_source_wires_cloud_key_available(self):
        # Read the source directly rather than importing the module: importing
        # yashigani.gateway.entrypoint executes _build_app() at import time
        # (module-level `app = _build_app(...)`), which needs a live
        # environment (writable /var/log/yashigani, Redis, etc.) not available
        # in a unit-test sandbox. A static source check is sufficient here —
        # this is a wiring-presence regression guard, not a behavioural test
        # (behaviour is fully covered by the OptimizationEngine tests above).
        import os

        entrypoint_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "..", "yashigani",
            "gateway", "entrypoint.py",
        )
        with open(entrypoint_path, "r", encoding="utf-8") as fh:
            src = fh.read()
        assert "cloud_key_available=" in src, (
            "YSG-RISK-178 regression: gateway/entrypoint.py must construct "
            "OptimizationEngine with a real cloud_key_available callable "
            "(not rely on the permissive None default) so a fresh install "
            "with no cloud key actually degrades P1/P5/P6 to local."
        )
        assert "_get_cloud_api_key" in src, (
            "cloud_key_available should reuse openai_router._get_cloud_api_key "
            "(single source of truth for 'is a key configured for provider X')"
        )
