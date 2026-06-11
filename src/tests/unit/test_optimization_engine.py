"""Tests for the Optimization Engine routing logic."""
from __future__ import annotations

import pytest

from yashigani.optimization.engine import OptimizationEngine, RoutingDecision
from yashigani.optimization.sensitivity_classifier import SensitivityLevel, SensitivityResult
from yashigani.optimization.complexity_scorer import ComplexityLevel, ComplexityResult
from yashigani.billing.budget_enforcer import BudgetSignal, BudgetState


def _sens(level: SensitivityLevel = SensitivityLevel.PUBLIC, triggers=None) -> SensitivityResult:
    return SensitivityResult(level=level, triggers=triggers or [], layer_results={"regex": level})


def _comp(level: ComplexityLevel = ComplexityLevel.MEDIUM, token_count: int = 500) -> ComplexityResult:
    return ComplexityResult(level=level, token_count=token_count, heuristic_score=0.0, reasons=[])


def _budget(signal: BudgetSignal = BudgetSignal.NORMAL, pct: int = 0) -> BudgetState:
    return BudgetState(identity_id="test", provider="anthropic", used=pct * 100, total=10000, signal=signal, pct=pct)


@pytest.fixture
def engine():
    return OptimizationEngine(
        default_model="qwen2.5:3b",
        default_cloud_provider="anthropic",
        default_cloud_model="claude-sonnet-4-6",
        model_aliases={
            "fast": ("ollama", "qwen2.5:3b", True),
            "smart": ("anthropic", "claude-opus-4-6", False),
            "secure": ("ollama", "qwen2.5:3b", True),
        },
    )


class TestOptimizationEngine:
    # ── P1: Sensitivity ──────────────────────────────────────────────

    def test_p1_confidential_routes_local(self, engine):
        d = engine.route("gpt-4o", _sens(SensitivityLevel.CONFIDENTIAL), _comp(), _budget())
        assert d.rule == "P1"
        assert d.is_local
        assert d.provider == "ollama"

    def test_p1_restricted_routes_local(self, engine):
        d = engine.route("gpt-4o", _sens(SensitivityLevel.RESTRICTED), _comp(), _budget())
        assert d.rule == "P1"
        assert d.is_local

    def test_p1_trusted_cloud_if_configured(self):
        engine = OptimizationEngine(
            trusted_cloud_providers={"CONFIDENTIAL": "azure"},
        )
        d = engine.route("model", _sens(SensitivityLevel.CONFIDENTIAL), _comp(), _budget())
        assert d.rule == "P1"
        assert d.provider == "azure"
        assert not d.is_local

    # ── P2: Budget exhausted ─────────────────────────────────────────

    def test_p2_budget_exhausted_routes_local(self, engine):
        d = engine.route("gpt-4o", _sens(), _comp(ComplexityLevel.HIGH),
                        _budget(BudgetSignal.EXHAUSTED, 100))
        assert d.rule == "P2"
        assert d.is_local

    def test_p2_never_rejects(self, engine):
        d = engine.route("gpt-4o", _sens(), _comp(ComplexityLevel.HIGH),
                        _budget(BudgetSignal.EXHAUSTED, 150))
        # Should route local, not raise an error
        assert d.is_local
        assert d.route == "local"

    # ── P3: Budget warning ───────────────────────────────────────────

    def test_p3_budget_warn_prefers_local(self, engine):
        d = engine.route("gpt-4o", _sens(), _comp(), _budget(BudgetSignal.WARN, 85))
        assert d.rule == "P3"
        assert d.is_local

    # ── P4: Force local ──────────────────────────────────────────────

    def test_p4_force_local(self, engine):
        d = engine.route("gpt-4o", _sens(), _comp(), _budget(), force_local=True)
        assert d.rule == "P4"
        assert d.is_local

    def test_p4_alias_force_local(self, engine):
        d = engine.route("secure", _sens(), _comp(), _budget())
        assert d.rule == "P4"
        assert d.is_local

    # ── P5: Force cloud ──────────────────────────────────────────────

    def test_p5_force_cloud(self, engine):
        d = engine.route("gpt-4o", _sens(), _comp(), _budget(), force_cloud=True)
        assert d.rule == "P5"
        assert not d.is_local

    def test_p5_sensitivity_overrides_force_cloud(self, engine):
        # P1 beats P5
        d = engine.route("gpt-4o", _sens(SensitivityLevel.RESTRICTED), _comp(), _budget(), force_cloud=True)
        assert d.rule == "P1"
        assert d.is_local

    def test_p5_budget_exhausted_overrides_force_cloud(self, engine):
        # P2 beats P5
        d = engine.route("gpt-4o", _sens(), _comp(), _budget(BudgetSignal.EXHAUSTED, 100), force_cloud=True)
        assert d.rule == "P2"
        assert d.is_local

    # ── P6: Complexity HIGH ──────────────────────────────────────────

    def test_p6_high_complexity_prefers_cloud(self, engine):
        d = engine.route("model", _sens(), _comp(ComplexityLevel.HIGH), _budget())
        assert d.rule == "P6"
        assert not d.is_local

    # ── P7: Complexity LOW ───────────────────────────────────────────

    def test_p7_low_complexity_prefers_local(self, engine):
        d = engine.route("model", _sens(), _comp(ComplexityLevel.LOW), _budget())
        assert d.rule == "P7"
        assert d.is_local

    # ── P8: Complexity MEDIUM ────────────────────────────────────────

    def test_p8_medium_uses_requested_cloud_model(self, engine):
        d = engine.route("anthropic/claude-opus-4-6", _sens(), _comp(ComplexityLevel.MEDIUM), _budget())
        assert d.rule == "P8"
        assert d.provider == "anthropic"

    def test_p8_medium_alias_resolves(self, engine):
        d = engine.route("smart", _sens(), _comp(ComplexityLevel.MEDIUM), _budget())
        assert d.rule == "P8"
        assert d.provider == "anthropic"
        assert d.model == "claude-opus-4-6"

    # ── P9: Fallback ─────────────────────────────────────────────────

    def test_p9_fallback_local(self, engine):
        d = engine.route("qwen2.5:3b", _sens(), _comp(ComplexityLevel.MEDIUM), _budget())
        assert d.rule == "P9"
        assert d.is_local

    # ── General ──────────────────────────────────────────────────────

    def test_decision_has_all_fields(self, engine):
        d = engine.route("model", _sens(), _comp(), _budget())
        assert d.provider
        assert d.model
        assert d.route in ("local", "cloud")
        assert d.rule.startswith("P")
        assert d.reason
        assert d.elapsed_us >= 0

    def test_alias_resolution(self, engine):
        d = engine.route("fast", _sens(), _comp(ComplexityLevel.LOW), _budget())
        assert d.model == "qwen2.5:3b"
        assert d.is_local

    def test_update_aliases(self, engine):
        engine.update_aliases({"ultra": ("openai", "gpt-4o", False)})
        d = engine.route("ultra", _sens(), _comp(ComplexityLevel.MEDIUM), _budget())
        assert d.provider == "openai"
        assert d.model == "gpt-4o"

    def test_priority_order_p1_beats_all(self, engine):
        # RESTRICTED + force_cloud + budget ok + HIGH complexity
        # P1 should still win
        d = engine.route("gpt-4o", _sens(SensitivityLevel.RESTRICTED),
                        _comp(ComplexityLevel.HIGH), _budget(), force_cloud=True)
        assert d.rule == "P1"
        assert d.is_local


class TestAllowedLocalDefaultSubstitution:
    """LAURA-B1-OBS-1 — the optimiser substitutes the caller's allowed local
    model (not the global default) in every LOCAL-route rule when supplied.

    allowed_local_default=None ⇒ legacy global-default behaviour (byte-for-byte).
    A non-None value ⇒ that model replaces the global default in P1/P2/P3/P4/P7/P9.
    Cloud rules (P5/P6/P8) are unaffected — they never use the local default.
    """

    def test_none_keeps_global_default_p9(self, engine):
        d = engine.route("unknown-x", _sens(), _comp(ComplexityLevel.MEDIUM), _budget(),
                         allowed_local_default=None)
        assert d.rule == "P9"
        assert d.model == "qwen2.5:3b"

    def test_p9_substitutes_allowed_local(self, engine):
        d = engine.route("unknown-x", _sens(), _comp(ComplexityLevel.MEDIUM), _budget(),
                         allowed_local_default="phi3.5")
        assert d.rule == "P9"
        assert d.model == "phi3.5"
        assert d.is_local

    def test_p7_low_complexity_substitutes(self, engine):
        d = engine.route("x", _sens(), _comp(ComplexityLevel.LOW), _budget(),
                         allowed_local_default="phi3.5")
        assert d.rule == "P7"
        assert d.model == "phi3.5"

    def test_p1_confidential_substitutes(self, engine):
        d = engine.route("gpt-4o", _sens(SensitivityLevel.CONFIDENTIAL), _comp(), _budget(),
                         allowed_local_default="phi3.5")
        assert d.rule == "P1"
        assert d.model == "phi3.5"
        assert d.is_local

    def test_p2_budget_exhausted_substitutes(self, engine):
        d = engine.route("gpt-4o", _sens(), _comp(ComplexityLevel.HIGH),
                         _budget(BudgetSignal.EXHAUSTED, 100), allowed_local_default="phi3.5")
        assert d.rule == "P2"
        assert d.model == "phi3.5"

    def test_p3_budget_warn_substitutes(self, engine):
        d = engine.route("gpt-4o", _sens(), _comp(ComplexityLevel.MEDIUM),
                         _budget(BudgetSignal.WARN, 85), allowed_local_default="phi3.5")
        assert d.rule == "P3"
        assert d.model == "phi3.5"

    def test_p4_force_local_default_substitutes(self, engine):
        # force_local with a requested model resolving to a NON-ollama provider
        # ('smart' → anthropic) → engine falls back to the local default → must use
        # the caller's allowed local model, not the global default.
        d = engine.route("smart", _sens(), _comp(ComplexityLevel.MEDIUM), _budget(),
                         force_local=True, allowed_local_default="phi3.5")
        assert d.rule == "P4"
        assert d.model == "phi3.5"

    def test_cloud_rules_unaffected_by_local_default(self, engine):
        # P6 (HIGH complexity → cloud) must NOT pick up the local-default substitute.
        d = engine.route("x", _sens(), _comp(ComplexityLevel.HIGH), _budget(),
                         allowed_local_default="phi3.5")
        assert d.rule == "P6"
        assert not d.is_local
        assert d.model != "phi3.5"
