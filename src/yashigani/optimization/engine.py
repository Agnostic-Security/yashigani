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
from typing import Callable, Optional

from yashigani.optimization.sensitivity_classifier import (
    SensitivityLevel,
    SensitivityResult,
    _LEVEL_TO_LEGACY_STRING,
)
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
        cloud_key_available: Optional[Callable[[], bool]] = None,
    ) -> None:
        """
        Args:
            default_model: Default local model
            default_cloud_provider: Default cloud provider
            default_cloud_model: Default cloud model
            trusted_cloud_providers: {sensitivity_level: provider} for CONFIDENTIAL/RESTRICTED fallback
            model_aliases: {alias: (provider, model, force_local)} DB-driven aliases
            cloud_key_available: zero-arg callable returning True iff a valid API
                key is actually configured for ``default_cloud_provider``.
                YSG-RISK-178 (product-correctness / default-model precedence):
                the engine substitutes ``default_cloud_provider``/``default_cloud_model``
                for an OLLAMA-resolved request in three places (P1 trusted-cloud,
                P5 force_cloud, P6 complexity-HIGH) whenever the caller did not
                explicitly pin a cloud model — i.e. the engine is choosing a
                DEFAULT on the caller's behalf. Per the product rule ("the
                default model is ALWAYS local UNLESS a cloud model is configured
                with an API key AND set as default"), that implicit substitution
                must never fire when no key is actually configured — doing so
                silently 422/503s a request the caller never asked to route to
                cloud. ``None`` (not wired) preserves legacy-permissive behaviour
                (assume available) for callers that construct the engine directly
                without wiring the check (unit tests, any deployment predating
                this fix) — production wiring (gateway/entrypoint.py) always
                passes a real callable backed by the same KMS/env-var resolution
                the actual cloud call uses (openai_router._get_cloud_api_key).
                An EXPLICIT cloud pin (caller/alias resolved to a non-ollama
                provider BEFORE reaching these rules) is never gated by this —
                only the implicit "engine chose cloud for you" substitution is.
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
        self._cloud_key_available = cloud_key_available
        logger.info(
            "OptimizationEngine: default_local=%s, default_cloud=%s/%s, trusted_cloud=%d",
            default_model, default_cloud_provider, default_cloud_model, len(self._trusted_cloud),
        )

    def _default_cloud_usable(self) -> bool:
        """True iff ``default_cloud_provider``/``default_cloud_model`` may be
        silently substituted as an IMPLICIT default for an ollama-resolved
        request (P1 trusted-cloud / P5 / P6).

        YSG-RISK-178: when ``cloud_key_available`` was not wired at
        construction time, legacy-permissive behaviour applies (assume
        usable) — unchanged for existing callers. When it WAS wired but
        raises, fail-closed to "not usable" — a broken checker must never be
        read as "a key is configured".
        """
        if self._cloud_key_available is None:
            return True
        try:
            return bool(self._cloud_key_available())
        except Exception as exc:  # noqa: BLE001 — never fail-open the route
            logger.warning(
                "OptimizationEngine: cloud_key_available() raised (%s) — "
                "treating default cloud as unavailable (fail-closed)", exc,
            )
            return False

    def route(
        self,
        requested_model: str,
        sensitivity: SensitivityResult,
        complexity: ComplexityResult,
        budget: BudgetState,
        force_local: bool = False,
        force_cloud: bool = False,
        allowed_local_default: str | None = None,
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
            allowed_local_default: LAURA-B1-OBS-1 — the local model the engine
                must substitute for ``self._default_model`` whenever a local-route
                rule (P1/P2/P3/P4/P7/P9) falls back to the local default.  The
                router resolves this to a LOCAL model the caller is ACTUALLY
                allocated (or to None when the caller is unrestricted/entitled to
                the global default).  Without this, a caller allocated only a
                NON-default local model (e.g. ``phi3.5``) — or a cloud-only caller
                with no force_cloud — gets rewritten to the global ``default_local``
                (``qwen2.5:3b``) and then DENIED by the B1 alloc-bind re-check for a
                model they never asked for.  Over-restriction, not over-grant (the
                security bar holds: we only ever substitute a model the caller is
                allocated), but broken UX.  Substituting the caller's OWN allowed
                local model serves them a model they are entitled to.  When None,
                behaviour is BYTE-FOR-BYTE the legacy global-default path.

        Returns:
            RoutingDecision with provider, model, and full reasoning
        """
        start = time.monotonic_ns()

        # LAURA-B1-OBS-1: the local default this caller may actually be served.
        # Falls back to the global default for unrestricted/entitled callers
        # (allowed_local_default=None) — legacy behaviour unchanged.
        local_default = allowed_local_default or self._default_model

        # Resolve model alias
        provider, model, alias_force_local = self._resolve_alias(requested_model)

        # P1: CONFIDENTIAL/RESTRICTED/SENSITIVE (levels 4–5) -> LOCAL (IMMUTABLE)
        # R14/R15 (v2.25.5): level is now int 1–5; levels >= 4 are cloud-blocked.
        if sensitivity.level >= SensitivityLevel.CONFIDENTIAL:
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
                    reason=(f"Sensitivity {sensitivity.level} routed to cloud "
                            f"{ov['provider']}/{ov['model']} under dual-admin risk-accepted "
                            f"override (justification: {ov.get('justification','')[:80]})"),
                    sensitivity=sensitivity,
                    complexity=complexity,
                    budget=budget,
                    start_ns=start,
                )
            # Check if admin configured a trusted cloud provider for this level
            # _trusted_cloud is keyed by legacy string (e.g. "CONFIDENTIAL").
            # Convert numeric level to legacy key for backward-compat lookup.
            _level_key: str = _LEVEL_TO_LEGACY_STRING.get(
                int(sensitivity.level), str(sensitivity.level)
            )
            trusted = self._trusted_cloud.get(_level_key)
            # YSG-RISK-178: trusted-cloud substitutes the DEFAULT cloud model —
            # never silently attempt it when no API key is actually configured
            # (falls through to the local decision below instead of a
            # downstream 503 the caller never asked to hit).
            if trusted and self._default_cloud_usable():
                return self._decide(
                    provider=trusted,
                    model=self._default_cloud_model,
                    route="cloud",
                    rule="P1",
                    reason=f"Sensitivity {sensitivity.level} — trusted cloud ({trusted})",
                    sensitivity=sensitivity,
                    complexity=complexity,
                    budget=budget,
                    start_ns=start,
                )
            return self._decide(
                provider="ollama",
                model=local_default,
                route="local",
                rule="P1",
                reason=f"Sensitivity {sensitivity.level} — local only",
                sensitivity=sensitivity,
                complexity=complexity,
                budget=budget,
                start_ns=start,
            )

        # P2: Cloud budget exhausted -> LOCAL (IMMUTABLE, never reject)
        if budget.signal == BudgetSignal.EXHAUSTED:
            return self._decide(
                provider="ollama",
                model=local_default,
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
                model=local_default,
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
                model=model if provider == "ollama" else local_default,
                route="local",
                rule="P4",
                reason="Identity or alias force_local",
                sensitivity=sensitivity,
                complexity=complexity,
                budget=budget,
                start_ns=start,
            )

        # P5: Identity force_cloud + budget ok
        # YSG-RISK-178: when the resolved model is already an EXPLICIT cloud
        # pin (provider != "ollama"), always honour it — this is not the
        # engine choosing a default. Only the "ollama -> substitute the
        # DEFAULT cloud model" branch is gated on a configured API key; absent
        # one, degrade to local instead of silently handing the caller a
        # model that will 503 downstream (never asked for, never configured).
        if force_cloud:
            if provider != "ollama" or self._default_cloud_usable():
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
            return self._decide(
                provider="ollama",
                model=local_default,
                route="local",
                rule="P5-DEGRADED",
                reason=(
                    "Identity force_cloud but default cloud model has no "
                    "configured API key — local fallback (YSG-RISK-178)"
                ),
                sensitivity=sensitivity,
                complexity=complexity,
                budget=budget,
                start_ns=start,
            )

        # P6: Complexity HIGH + budget ok -> PREFER CLOUD
        # YSG-RISK-178: same guard as P5 — an implicit "prefer cloud" upgrade
        # of an ollama-resolved (i.e. no explicit model requested) request
        # must never silently pick the default cloud model when no API key
        # is configured for it. This was the concrete out-of-box bug: a
        # fresh LOCAL install (no cloud key) scored a plain, no-@mention chat
        # as HIGH complexity and got auto-upgraded to the cloud default
        # (claude-sonnet-4-6), which then 422/503'd with zero cloud config.
        if complexity.level == ComplexityLevel.HIGH:
            if provider != "ollama" or self._default_cloud_usable():
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
            return self._decide(
                provider="ollama",
                model=local_default,
                route="local",
                rule="P6-DEGRADED",
                reason=(
                    "Complexity HIGH would prefer cloud but default cloud model "
                    "has no configured API key — local fallback (YSG-RISK-178)"
                ),
                sensitivity=sensitivity,
                complexity=complexity,
                budget=budget,
                start_ns=start,
            )

        # P7: Complexity LOW -> PREFER LOCAL
        if complexity.level == ComplexityLevel.LOW:
            return self._decide(
                provider="ollama",
                model=local_default,
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
            model=local_default,
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

        # R14/R15 (v2.25.5): SensitivityResult.level is int (1–5).
        # str(int) produces "4" not "RESTRICTED"; use the legacy-string map so
        # RoutingDecision.sensitivity and the Prometheus label keep the historical
        # string form (audit records, dashboards, downstream consumers expect strings).
        _sens_label: str = _LEVEL_TO_LEGACY_STRING.get(int(sensitivity.level), "RESTRICTED")

        decision = RoutingDecision(
            provider=provider,
            model=model,
            route=route,
            rule=rule,
            reason=reason,
            sensitivity=_sens_label,
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

        # Emit Prometheus metrics for every routing decision (best-effort).
        try:
            from yashigani.metrics.registry import (
                yashigani_routing_decisions_total,
                yashigani_sensitivity_detections_total,
                yashigani_complexity_scores_total,
                yashigani_budget_exhausted_total,
                yashigani_routing_p1_events_info,
            )
            yashigani_routing_decisions_total.labels(
                rule=rule, route=route
            ).inc()
            yashigani_sensitivity_detections_total.labels(
                level=_sens_label
            ).inc()
            yashigani_complexity_scores_total.labels(
                level=complexity.level.value
            ).inc()
            # P2 = cloud budget exhausted → forced local; increment the exhausted counter.
            if rule == "P2":
                yashigani_budget_exhausted_total.inc()
            # P1 = OPA routing safety-net (sensitive data blocked from cloud).
            # Update the info gauge so the "P1 Routing Events" dashboard table is populated.
            if rule == "P1":
                yashigani_routing_p1_events_info.labels(
                    identity_id=str(budget.identity_id),
                    provider=str(provider),
                    sensitivity_level=str(sensitivity.level),
                ).set(1)
        except Exception:  # noqa: BLE001 — metric must never break routing
            pass

        return decision

    def update_aliases(self, aliases: dict[str, tuple[str, str, bool]]) -> None:
        """Hot-reload model aliases (admin action)."""
        self._aliases = aliases
        logger.info("OptimizationEngine: reloaded %d aliases", len(aliases))

    def update_trusted_cloud(self, trusted: dict[str, str]) -> None:
        """Hot-reload trusted cloud providers (admin action)."""
        self._trusted_cloud = trusted
        logger.info("OptimizationEngine: reloaded %d trusted cloud providers", len(trusted))
