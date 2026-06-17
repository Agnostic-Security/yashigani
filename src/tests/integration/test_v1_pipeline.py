"""
Integration tests for the v1.0 pipeline.

Tests the full flow: identity -> sensitivity -> complexity -> budget -> OE routing.
Uses in-memory/fake backends (no Docker, no network).
"""
from __future__ import annotations

import fakeredis
import pytest

from yashigani.identity import IdentityRegistry, IdentityKind
from yashigani.billing.token_counter import TokenCounter
from yashigani.billing.budget_enforcer import BudgetEnforcer, BudgetSignal
from yashigani.optimization.sensitivity_classifier import SensitivityClassifier, SensitivityLevel
from yashigani.optimization.complexity_scorer import ComplexityScorer, ComplexityLevel
from yashigani.optimization.engine import OptimizationEngine


@pytest.fixture
def identity_redis():
    return fakeredis.FakeRedis()


@pytest.fixture
def budget_redis():
    return fakeredis.FakeRedis()


@pytest.fixture
def registry(identity_redis):
    return IdentityRegistry(identity_redis)


@pytest.fixture
def enforcer(budget_redis):
    return BudgetEnforcer(budget_redis)


@pytest.fixture
def classifier():
    return SensitivityClassifier(enable_sklearn=False, enable_ollama=False)


@pytest.fixture
def scorer():
    return ComplexityScorer(token_threshold=2000)


@pytest.fixture
def engine():
    return OptimizationEngine(
        default_model="qwen2.5:3b",
        default_cloud_provider="anthropic",
        default_cloud_model="claude-sonnet-4-6",
    )


@pytest.fixture
def counter():
    return TokenCounter()


class TestFullPipeline:
    """Test the full v1.0 request pipeline with all components wired together."""

    def test_public_simple_query_routes_local(self, registry, classifier, scorer, engine, enforcer):
        """A simple public query should route to local Ollama."""
        # Register identity
        identity_id, key = registry.register(
            kind=IdentityKind.HUMAN, name="Alice", slug="alice",
        )

        # Classify sensitivity
        prompt = "What is the capital of France?"
        sens = classifier.classify(prompt)
        assert sens.level == SensitivityLevel.PUBLIC

        # Score complexity
        comp = scorer.score(prompt)
        assert comp.level == ComplexityLevel.LOW

        # Check budget (no budget configured = NORMAL)
        budget = enforcer.check(identity_id, "anthropic", budget_total=0)
        assert budget.signal == BudgetSignal.NORMAL

        # Route
        decision = engine.route("qwen2.5:3b", sens, comp, budget)
        assert decision.is_local
        assert decision.rule in ("P7", "P9")  # LOW complexity or fallback

    def test_confidential_data_always_local(self, registry, classifier, scorer, engine, enforcer):
        """A prompt with SSN must route local regardless of complexity."""
        identity_id, _ = registry.register(
            kind=IdentityKind.HUMAN, name="Bob", slug="bob",
        )

        prompt = "Review employee record for John Smith, SSN 123-45-6789"
        sens = classifier.classify(prompt)
        assert sens.level == SensitivityLevel.CONFIDENTIAL

        comp = scorer.score(prompt)
        budget = enforcer.check(identity_id, "anthropic", budget_total=100000)

        decision = engine.route("claude-opus-4-6", sens, comp, budget)
        assert decision.is_local
        assert decision.rule == "P1"

    def test_budget_exhausted_degrades_to_local(self, registry, classifier, scorer, engine, enforcer, budget_redis):
        """When cloud budget is exhausted, even complex queries route local."""
        identity_id, _ = registry.register(
            kind=IdentityKind.HUMAN, name="Charlie", slug="charlie",
        )

        # Exhaust budget
        from yashigani.billing.budget_enforcer import _period_key
        pk = _period_key("monthly")
        budget_redis.set(f"budget:identity:{identity_id}:anthropic:{pk}", 100000)

        prompt = "Analyse this complex codebase and provide a detailed architecture review. " * 200
        sens = classifier.classify(prompt)
        comp = scorer.score(prompt)
        assert comp.level == ComplexityLevel.HIGH

        budget = enforcer.check(identity_id, "anthropic", budget_total=100000)
        assert budget.signal == BudgetSignal.EXHAUSTED

        decision = engine.route("claude-opus-4-6", sens, comp, budget)
        assert decision.is_local
        assert decision.rule == "P2"

    def test_high_complexity_routes_cloud_when_budget_ok(self, registry, classifier, scorer, engine, enforcer):
        """Complex queries route to cloud when budget is healthy."""
        identity_id, _ = registry.register(
            kind=IdentityKind.HUMAN, name="Diana", slug="diana",
        )

        prompt = "Analyse this: " + "x " * 10000  # > 2000 tokens estimated
        sens = classifier.classify(prompt)
        comp = scorer.score(prompt)
        assert comp.level == ComplexityLevel.HIGH

        budget = enforcer.check(identity_id, "anthropic", budget_total=100000)
        assert budget.signal == BudgetSignal.NORMAL

        decision = engine.route("claude-opus-4-6", sens, comp, budget)
        assert not decision.is_local
        assert decision.rule == "P6"

    def test_token_counting_after_response(self, counter):
        """Verify token counting from different providers."""
        # OpenAI response
        openai_resp = {"usage": {"prompt_tokens": 150, "completion_tokens": 200, "total_tokens": 350}}
        usage = counter.count("openai", "gpt-4o", openai_resp)
        assert usage.total_tokens == 350

        # Ollama response
        ollama_resp = {"prompt_eval_count": 50, "eval_count": 100}
        usage = counter.count("ollama", "qwen2.5:3b", ollama_resp)
        assert usage.total_tokens == 150
        assert usage.is_local

    def test_budget_recording_updates_all_tiers(self, enforcer, budget_redis):
        """Recording usage updates identity, group, and org counters."""
        enforcer.record(
            identity_id="alice",
            provider="anthropic",
            tokens=1000,
            group_ids=["engineering"],
            org_id="acme",
        )

        from yashigani.billing.budget_enforcer import _period_key
        pk = _period_key("monthly")

        assert int(budget_redis.get(f"budget:identity:alice:anthropic:{pk}")) == 1000
        assert int(budget_redis.get(f"budget:group:engineering:anthropic:{pk}")) == 1000
        assert int(budget_redis.get(f"budget:org:acme:anthropic:{pk}")) == 1000

    def test_service_identity_with_autonomous_budget(self, registry, classifier, scorer, engine, enforcer):
        """A service identity consuming tokens on its own budget."""
        identity_id, _ = registry.register(
            kind=IdentityKind.SERVICE,
            name="Research Bot",
            slug="research-bot",
            upstream_url="http://research-bot:8080",
        )

        # Long prompt -> HIGH complexity -> P6 (prefer cloud)
        prompt = "Summarise recent papers on transformer architectures. " * 200
        sens = classifier.classify(prompt)
        comp = scorer.score(prompt)
        assert comp.level == ComplexityLevel.HIGH
        budget = enforcer.check(identity_id, "anthropic", budget_total=50000)

        decision = engine.route("claude-sonnet-4-6", sens, comp, budget)
        assert decision.provider == "anthropic"
        assert decision.rule == "P6"

        # Record usage against the service identity's budget
        enforcer.record(identity_id, "anthropic", tokens=500)
        summary = enforcer.get_usage_summary(identity_id)
        assert summary.get("anthropic", 0) == 500

    def test_sensitivity_overrides_everything(self, classifier, scorer, engine, enforcer):
        """P1 (sensitivity) beats P5 (force_cloud) and P6 (high complexity)."""
        prompt = "Process this payment: card 4111111111111111 expiry 12/28"
        sens = classifier.classify(prompt)
        assert sens.level == SensitivityLevel.RESTRICTED

        comp = scorer.score(prompt * 20)  # Make it HIGH complexity
        budget = enforcer.check("test", "openai", budget_total=999999)

        decision = engine.route("gpt-4o", sens, comp, budget, force_cloud=True)
        assert decision.is_local
        assert decision.rule == "P1"


class TestIdentityLifecycle:
    """Test identity creation, suspension, deactivation."""

    def test_full_lifecycle(self, registry):
        identity_id, key = registry.register(
            kind=IdentityKind.HUMAN,
            name="Test User",
            slug="test-user",
            allowed_models=["qwen2.5:3b", "claude-opus-4-6"],
            sensitivity_ceiling="CONFIDENTIAL",
        )

        # Active
        identity = registry.get(identity_id)
        assert identity["status"] == "active"
        assert registry.verify_key(identity_id, key)

        # Suspend
        registry.suspend(identity_id)
        assert registry.get(identity_id)["status"] == "suspended"
        assert registry.count(status="active") == 0

        # Reactivate
        registry.reactivate(identity_id)
        assert registry.get(identity_id)["status"] == "active"
        assert registry.count(status="active") == 1

        # Rotate key
        new_key = registry.rotate_key(identity_id)
        assert new_key != key
        assert registry.verify_key(identity_id, new_key)
        assert registry.verify_key(identity_id, key)  # Grace period

        # Deactivate
        registry.deactivate(identity_id)
        assert registry.get(identity_id)["status"] == "deactivated"
        assert not registry.verify_key(identity_id, new_key)
        assert registry.get_by_slug("test-user") is None
