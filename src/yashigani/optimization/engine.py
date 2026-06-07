"""
Yashigani Optimization Engine — Deterministic, auditable routing.

Evaluates four signals (sensitivity, complexity, budget, cost) and applies
the P1-P9 priority matrix to select the optimal backend for each request.

Every routing decision is logged as an audit event with full reasoning.

Routing Priority (first match wins):
  P1  CONFIDENTIAL/RESTRICTED           -> LOCAL or trusted cloud (IMMUTABLE)
  P2  Cloud budget exhausted            -> LOCAL (IMMUTABLE — never reject)
  P3  Budget >80% used                  -> PREFER LOCAL
  P4  Identity force_local              -> LOCAL
  P5  Identity force_cloud + budget ok  -> CLOUD
  P6  Complexity HIGH + budget ok       -> PREFER CLOUD
  P7  Complexity LOW                    -> PREFER LOCAL
  P8  Complexity MEDIUM                 -> TENANT DEFAULT
  P9  Fallback                          -> LOCAL
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from yashigani.optimization.sensitivity_classifier import SensitivityLevel, SensitivityResult
from yashigani.optimization.complexity_scorer import ComplexityLevel, ComplexityResult
from yashigani.billing.budget_enforcer import BudgetSignal, BudgetState

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RoutingDecision:
    """The output of the Optimization Engine for a single request."""
    provider: str               # 'ollama', 'anthropic', 'openai', etc.
    model: str                  # Resolved model name
    route: str                  # 'local' or 'cloud'
    rule: str                   # Which P-rule matched (P1-P9)
    reason: str                 # Human-readable explanation
    sensitivity: str            # Sensitivity level detected
    complexity: str             # Complexity level scored
    budget_signal: str          # Budget state
    budget_pct: int             # Budget usage percentage
    is_local: bool              # True if routed to local model
    elapsed_us: int = 0         # Decision time in microseconds
    sensitivity_triggers: list[str] = field(default_factory=list)
    complexity_reasons: list[str] = field(default_factory=list)


class OptimizationEngine:
    """
    Deterministic routing engine. Evaluates P1-P9 in order, first match wins.

    All rules are evaluated synchronously in-process (Decision 2).
    CONFIDENTIAL/RESTRICTED routing is immutable (Decision 7).
    Budget exhaustion degrades to local, never rejects (Decision 7).
    """

    def __init__(
        self,
        default_model: str = "qwen2.5:3b",
        default_cloud_provider: str = "anthropic",
        default_cloud_model: str = "claude-sonnet-4-6",
        trusted_cloud_providers: dict[str, str] | None = None,
        model_aliases: dict[str, tuple[str, str, bool]] | None = None,
        cloud_override_getter=None,
    ) -> None:
        """
        Args:
            default_model: Default local model
            default_cloud_provider: Default cloud provider
            default_cloud_model: Default cloud model
            trusted_cloud_providers: {sensitivity_level: provider} for CONFIDENTIAL/RESTRICTED fallback
            model_aliases: {alias: (provider, model, force_local)} DB-driven aliases
        """
        self._default_model = default_model
        self._default_cloud_provider = default_cloud_provider
        self._default_cloud_model = default_cloud_model
        self._trusted_cloud = trusted_cloud_providers or {}
        self._aliases = model_aliases or {}
        # #25: zero-arg callable -> the ACTIVE dual-admin cloud-LLM override
        # ({"provider","model",...}) or None. When active it lets the named cloud
        # LLM serve P1 (CONFIDENTIAL/RESTRICTED) traffic the engine would otherwise
        # pin local — the customer has a cloud agreement and accepts the P1-P9 risk.
        self._cloud_override_getter = cloud_override_getter
        logger.info(
            "OptimizationEngine: default_local=%s, default_cloud=%s/%s, trusted_cloud=%d",
            default_model, default_cloud_provider, default_cloud_model, len(self._trusted_cloud),
        )

    def route(
        self,
        requested_model: str,
        sensitivity: SensitivityResult,
        complexity: ComplexityResult,
        budget: BudgetState,
        force_local: bool = False,
        force_cloud: bool = False,
    ) -> RoutingDecision:
        """
        Evaluate all routing rules and return the optimal backend.

        Args:
            requested_model: Model requested by the caller (may be an alias)
            sensitivity: Result from SensitivityClassifier
            complexity: Result from ComplexityScorer
            budget: Current budget state from BudgetEnforcer
            force_local: Identity-level override
            force_cloud: Identity-level override

        Returns:
            RoutingDecision with provider, model, and full reasoning
        """
        start = time.monotonic_ns()

        # Resolve model alias
        provider, model, alias_force_local = self._resolve_alias(requested_model)

        # P1: CONFIDENTIAL/RESTRICTED -> LOCAL (IMMUTABLE)
        if sensitivity.level in (SensitivityLevel.CONFIDENTIAL, SensitivityLevel.RESTRICTED):
            # #25 risk-accepted cloud override (dual-admin, justified, TTL'd): if an
            # override is ACTIVE, the named cloud LLM may serve this sensitive request
            # instead of being pinned local. The customer has a cloud agreement and
            # has accepted the P1-P9 risk; the grant + justification are audited.
            ov = self._cloud_override_getter() if self._cloud_override_getter else None
            if ov and ov.get("provider") and ov.get("model"):
                return self._decide(
                    provider=ov["provider"],
                    model=ov["model"],
                    route="cloud",
                    rule="P1-OVERRIDE",
                    reason=(f"Sensitivity {sensitivity.level.value} routed to cloud "
                            f"{ov['provider']}/{ov['model']} under dual-admin risk-accepted "
                            f"override (justification: {ov.get('justification','')[:80]})"),
                    sensitivity=sensitivity,
                    complexity=complexity,
                    budget=budget,
                    start_ns=start,
                )
            # Check if admin configured a trusted cloud provider for this level
            trusted = self._trusted_cloud.get(sensitivity.level.value)
            if trusted:
                return self._decide(
                    provider=trusted,
                    model=self._default_cloud_model,
                    route="cloud",
                    rule="P1",
                    reason=f"Sensitivity {sensitivity.level.value} — trusted cloud ({trusted})",
                    sensitivity=sensitivity,
                    complexity=complexity,
                    budget=budget,
                    start_ns=start,
                )
            return self._decide(
                provider="ollama",
                model=self._default_model,
                route="local",
                rule="P1",
                reason=f"Sensitivity {sensitivity.level.value} — local only",
                sensitivity=sensitivity,
                complexity=complexity,
                budget=budget,
                start_ns=start,
            )

        # P2: Cloud budget exhausted -> LOCAL (IMMUTABLE, never reject)
        if budget.signal == BudgetSignal.EXHAUSTED:
            return self._decide(
                provider="ollama",
                model=self._default_model,
                route="local",
                rule="P2",
                reason=f"Cloud budget exhausted ({budget.pct}%) — local only",
                sensitivity=sensitivity,
                complexity=complexity,
                budget=budget,
                start_ns=start,
            )

        # P3: Budget warning -> PREFER LOCAL
        if budget.signal == BudgetSignal.WARN:
            return self._decide(
                provider="ollama",
                model=self._default_model,
                route="local",
                rule="P3",
                reason=f"Budget warning ({budget.pct}%) — prefer local",
                sensitivity=sensitivity,
                complexity=complexity,
                budget=budget,
                start_ns=start,
            )

        # P4: Identity force_local or alias force_local
        if force_local or alias_force_local:
            return self._decide(
                provider="ollama",
                model=model if provider == "ollama" else self._default_model,
                route="local",
                rule="P4",
                reason="Identity or alias force_local",
                sensitivity=sensitivity,
                complexity=complexity,
                budget=budget,
                start_ns=start,
            )

        # P5: Identity force_cloud + budget ok
        if force_cloud:
            return self._decide(
                provider=provider if provider != "ollama" else self._default_cloud_provider,
                model=model if provider != "ollama" else self._default_cloud_model,
                route="cloud",
                rule="P5",
                reason="Identity force_cloud",
                sensitivity=sensitivity,
                complexity=complexity,
                budget=budget,
                start_ns=start,
            )

        # P6: Complexity HIGH + budget ok -> PREFER CLOUD
        if complexity.level == ComplexityLevel.HIGH:
            return self._decide(
                provider=provider if provider != "ollama" else self._default_cloud_provider,
                model=model if provider != "ollama" else self._default_cloud_model,
                route="cloud",
                rule="P6",
                reason=f"Complexity HIGH — prefer cloud",
                sensitivity=sensitivity,
                complexity=complexity,
                budget=budget,
                start_ns=start,
            )

        # P7: Complexity LOW -> PREFER LOCAL
        if complexity.level == ComplexityLevel.LOW:
            return self._decide(
                provider="ollama",
                model=self._default_model,
                route="local",
                rule="P7",
                reason="Complexity LOW — prefer local",
                sensitivity=sensitivity,
                complexity=complexity,
                budget=budget,
                start_ns=start,
            )

        # P8: Complexity MEDIUM -> USE requested model or tenant default
        if provider and provider != "ollama":
            return self._decide(
                provider=provider,
                model=model,
                route="cloud",
                rule="P8",
                reason=f"Complexity MEDIUM — using requested model ({provider}/{model})",
                sensitivity=sensitivity,
                complexity=complexity,
                budget=budget,
                start_ns=start,
            )

        # P9: Fallback -> LOCAL
        return self._decide(
            provider="ollama",
            model=self._default_model,
            route="local",
            rule="P9",
            reason="Fallback — local default",
            sensitivity=sensitivity,
            complexity=complexity,
            budget=budget,
            start_ns=start,
        )

    def _resolve_alias(self, requested_model: str) -> tuple[str, str, bool]:
        """
        Resolve a model alias to (provider, model, force_local).
        Returns the original model if no alias found.
        """
        if requested_model in self._aliases:
            provider, model, force_local = self._aliases[requested_model]
            return provider, model, force_local

        # Check if it looks like a provider/model format
        if "/" in requested_model:
            parts = requested_model.split("/", 1)
            return parts[0], parts[1], False

        # Assume local Ollama model
        return "ollama", requested_model, False

    def _decide(
        self,
        provider: str,
        model: str,
        route: str,
        rule: str,
        reason: str,
        sensitivity: SensitivityResult,
        complexity: ComplexityResult,
        budget: BudgetState,
        start_ns: int,
    ) -> RoutingDecision:
        elapsed_us = (time.monotonic_ns() - start_ns) // 1000

        decision = RoutingDecision(
            provider=provider,
            model=model,
            route=route,
            rule=rule,
            reason=reason,
            sensitivity=sensitivity.level.value,
            complexity=complexity.level.value,
            budget_signal=budget.signal.value,
            budget_pct=budget.pct,
            is_local=(route == "local"),
            elapsed_us=elapsed_us,
            sensitivity_triggers=sensitivity.triggers,
            complexity_reasons=complexity.reasons,
        )

        logger.info(
            "OE decision: %s/%s (%s) rule=%s reason=%s [%dus]",
            provider, model, route, rule, reason, elapsed_us,
        )
        return decision

    def update_aliases(self, aliases: dict[str, tuple[str, str, bool]]) -> None:
        """Hot-reload model aliases (admin action)."""
        self._aliases = aliases
        logger.info("OptimizationEngine: reloaded %d aliases", len(aliases))

    def update_trusted_cloud(self, trusted: dict[str, str]) -> None:
        """Hot-reload trusted cloud providers (admin action)."""
        self._trusted_cloud = trusted
        logger.info("OptimizationEngine: reloaded %d trusted cloud providers", len(trusted))
