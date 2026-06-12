"""
Yashigani Billing — Budget enforcer.

Three-tier budget hierarchy: org cap -> group -> individual.
Counters stored in budget-redis (noeviction). Budget signals drive
routing decisions in the Optimization Engine.

Invariants:
  - Sum of individual budgets <= group budget
  - Sum of group budgets <= org cap
  - System enforces on every mutation
  - Budget exhausted -> graceful degradation to local (never reject)
"""
from __future__ import annotations

import enum
import json
import logging
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


class BudgetSignal(str, enum.Enum):
    """Budget state signal for the Optimization Engine."""
    NORMAL = "normal"           # < 80% used
    WARN = "warn"               # 80-99% used — prefer local
    EXHAUSTED = "exhausted"     # >= 100% — local only


@dataclass(frozen=True)
class BudgetState:
    """Current budget state for an identity + provider."""
    identity_id: str
    provider: str
    used: int           # tokens consumed in current period
    total: int          # token budget for current period
    signal: BudgetSignal
    pct: int            # percentage used (0-100+)

    @property
    def remaining(self) -> int:
        return max(0, self.total - self.used)


# Redis key patterns for budget-redis
# budget:identity:{identity_id}:{provider}:{period_key}  -> int (used tokens)
# budget:group:{group_id}:{provider}:{period_key}        -> int (used tokens)
# budget:org:{org_id}:{provider}:{period_key}             -> int (used tokens)

_WARN_PCT = 80


def _period_key(period: str = "monthly") -> str:
    """Generate the current period key for budget counters."""
    t = time.gmtime()
    if period == "daily":
        return f"{t.tm_year}-{t.tm_mon:02d}-{t.tm_mday:02d}"
    if period == "weekly":
        # ISO week number
        import datetime
        d = datetime.date(t.tm_year, t.tm_mon, t.tm_mday)
        return f"{d.isocalendar()[0]}-W{d.isocalendar()[1]:02d}"
    # monthly (default)
    return f"{t.tm_year}-{t.tm_mon:02d}"


class BudgetEnforcer:
    """
    Enforces the three-tier budget hierarchy.

    Uses a dedicated Redis instance (budget-redis) with noeviction policy.
    Counters are atomic (INCRBY) and reset automatically when the period key changes.
    """

    def __init__(self, redis_client, warn_pct: int = _WARN_PCT) -> None:
        """
        Args:
            redis_client: Redis connection to budget-redis (NOT the main Redis)
            warn_pct: Percentage threshold for WARN signal (default 80)
        """
        self._r = redis_client
        self._warn_pct = warn_pct
        logger.info("BudgetEnforcer initialised (warn_pct=%d%%)", warn_pct)

    def get_allocation(self, identity_id: str, provider: str = "cloud") -> int:
        """
        Get the budget allocation for an identity from Redis.
        Returns 0 if no allocation is configured (unlimited / Community tier).
        Allocations are synced to Redis by the budget admin API.
        """
        key = f"budget:allocation:{identity_id}:{provider}"
        val = self._r.get(key)
        return int(val) if val else 0

    def set_allocation(self, identity_id: str, provider: str, token_budget: int) -> None:
        """Cache a budget allocation in Redis (called by the budget admin API)."""
        key = f"budget:allocation:{identity_id}:{provider}"
        self._r.set(key, str(token_budget))

    def sync_allocations(self, allocations: list[dict]) -> int:
        """
        Bulk-sync budget allocations from Postgres to Redis.
        Called at gateway startup to restore allocations after restart.
        Returns count of allocations synced.
        """
        count = 0
        pipe = self._r.pipeline(transaction=False)
        for alloc in allocations:
            key = f"budget:allocation:{alloc['identity_id']}:{alloc['provider']}"
            pipe.set(key, str(alloc['token_budget']))
            count += 1
        pipe.execute()
        if count:
            logger.info("Budget allocations synced from DB: %d", count)
        return count

    def check(
        self,
        identity_id: str,
        provider: str,
        budget_total: int = 0,
        period: str = "monthly",
    ) -> BudgetState:
        """
        Check current budget state for an identity + provider.

        Args:
            identity_id: The identity consuming tokens
            provider: Cloud provider name (anthropic, openai, etc.)
            budget_total: The identity's allocated budget (from individual_budgets)
            period: Budget period (daily, weekly, monthly)

        Returns:
            BudgetState with signal for the Optimization Engine
        """
        if budget_total <= 0:
            # No budget configured — unlimited (Community tier default)
            return BudgetState(
                identity_id=identity_id,
                provider=provider,
                used=0,
                total=0,
                signal=BudgetSignal.NORMAL,
                pct=0,
            )

        pk = _period_key(period)
        key = f"budget:identity:{identity_id}:{provider}:{pk}"
        used = int(self._r.get(key) or 0)
        pct = min(int((used / budget_total) * 100), 999) if budget_total > 0 else 0

        if pct >= 100:
            signal = BudgetSignal.EXHAUSTED
        elif pct >= self._warn_pct:
            signal = BudgetSignal.WARN
        else:
            signal = BudgetSignal.NORMAL

        return BudgetState(
            identity_id=identity_id,
            provider=provider,
            used=used,
            total=budget_total,
            signal=signal,
            pct=pct,
        )

    def record(
        self,
        identity_id: str,
        provider: str,
        tokens: int,
        group_ids: list[str] | None = None,
        org_id: str = "",
        period: str = "monthly",
    ) -> None:
        """
        Record token usage at all three tiers atomically.

        Args:
            identity_id: The identity that consumed tokens
            provider: Cloud provider
            tokens: Number of tokens consumed
            group_ids: Groups this identity belongs to (for group counter)
            org_id: Organisation (for org counter)
            period: Budget period
        """
        if tokens <= 0:
            return

        # Emit Prometheus budget metrics inline (fast — no Redis round-trip needed here).
        # route is "cloud" for all providers except ollama/agent (which use the local path).
        _route = "local" if provider in ("ollama", "agent") else "cloud"
        try:
            from yashigani.metrics.registry import (
                yashigani_budget_tokens_total,
                yashigani_budget_cost_usd_total,
            )
            yashigani_budget_tokens_total.labels(
                provider=provider, kind="identity", route=_route, identity_id=identity_id
            ).inc(tokens)
            # Cost estimation: look up model pricing if possible (best-effort)
            cost_usd = 0.0
            try:
                price_key = f"pricing:{provider}:per_1k_tokens"
                price_val = self._r.get(price_key)
                if price_val:
                    cost_usd = (tokens / 1000.0) * float(price_val)
            except Exception:  # noqa: BLE001
                pass
            if cost_usd > 0:
                yashigani_budget_cost_usd_total.labels(
                    provider=provider, identity_id=identity_id
                ).inc(cost_usd)
        except Exception:  # noqa: BLE001 — metric must never break the hot path
            pass

        pk = _period_key(period)
        pipe = self._r.pipeline()

        # Individual counter
        pipe.incrby(f"budget:identity:{identity_id}:{provider}:{pk}", tokens)

        # Group counters
        for gid in (group_ids or []):
            pipe.incrby(f"budget:group:{gid}:{provider}:{pk}", tokens)

        # Org counter
        if org_id:
            pipe.incrby(f"budget:org:{org_id}:{provider}:{pk}", tokens)

        pipe.execute()

        logger.debug(
            "Budget recorded: identity=%s provider=%s tokens=%d",
            identity_id, provider, tokens,
        )

    def check_group(
        self,
        group_id: str,
        provider: str,
        budget_total: int,
        period: str = "monthly",
    ) -> BudgetState:
        """Check budget state for a group."""
        pk = _period_key(period)
        key = f"budget:group:{group_id}:{provider}:{pk}"
        used = int(self._r.get(key) or 0)
        pct = min(int((used / budget_total) * 100), 999) if budget_total > 0 else 0

        if pct >= 100:
            signal = BudgetSignal.EXHAUSTED
        elif pct >= self._warn_pct:
            signal = BudgetSignal.WARN
        else:
            signal = BudgetSignal.NORMAL

        return BudgetState(
            identity_id=group_id,
            provider=provider,
            used=used,
            total=budget_total,
            signal=signal,
            pct=pct,
        )

    def check_org(
        self,
        org_id: str,
        provider: str,
        cap: int,
        period: str = "monthly",
    ) -> BudgetState:
        """Check budget state for an organisation cloud cap."""
        pk = _period_key(period)
        key = f"budget:org:{org_id}:{provider}:{pk}"
        used = int(self._r.get(key) or 0)
        pct = min(int((used / cap) * 100), 999) if cap > 0 else 0

        if pct >= 100:
            signal = BudgetSignal.EXHAUSTED
        elif pct >= self._warn_pct:
            signal = BudgetSignal.WARN
        else:
            signal = BudgetSignal.NORMAL

        return BudgetState(
            identity_id=org_id,
            provider=provider,
            used=used,
            total=cap,
            signal=signal,
            pct=pct,
        )

    def get_usage_summary(
        self,
        identity_id: str,
        period: str = "monthly",
    ) -> dict[str, int]:
        """Get token usage across all providers for an identity."""
        pk = _period_key(period)
        pattern = f"budget:identity:{identity_id}:*:{pk}"
        result = {}
        for key in self._r.scan_iter(pattern):
            key_str = key.decode("utf-8") if isinstance(key, bytes) else key
            parts = key_str.split(":")
            if len(parts) >= 4:
                provider = parts[3]
                result[provider] = int(self._r.get(key) or 0)
        return result

    def list_group_utilisation(self, period: str = "monthly") -> dict[str, float]:
        """Return {group_id: utilisation_pct} for all groups with active allocations.

        Scans budget:allocation:group:* keys (set by set_group_allocation) to
        discover group IDs, then divides current usage by allocation.  Groups
        with zero allocation are reported as 0.0 (not 100%).

        Used by MetricsCollector to update yashigani_budget_utilisation_pct{group_id}.
        """
        pk = _period_key(period)
        result: dict[str, float] = {}
        # Discover group IDs from allocation keys
        for key in self._r.scan_iter("budget:allocation:group:*"):
            key_str = key.decode("utf-8") if isinstance(key, bytes) else key
            # key format: budget:allocation:group:{group_id}:{provider}
            parts = key_str.split(":")
            if len(parts) < 5:
                continue
            group_id = parts[3]
            provider = parts[4]
            alloc_val = self._r.get(key)
            allocation = int(alloc_val) if alloc_val else 0
            if allocation <= 0:
                result.setdefault(group_id, 0.0)
                continue
            usage_key = f"budget:group:{group_id}:{provider}:{pk}"
            used = int(self._r.get(usage_key) or 0)
            pct = min((used / allocation) * 100.0, 999.0)
            # Use max across providers for the group
            result[group_id] = max(result.get(group_id, 0.0), pct)
        return result

    def emit_identity_utilisation(
        self,
        identity_id: str,
        provider: str,
        pct: float,
    ) -> None:
        """Update the yashigani_budget_utilisation_pct metric for an identity.

        Called inline at budget-check time (per-request) so the Grafana panel
        always shows the current utilisation without waiting for the poll cycle.
        """
        try:
            from yashigani.metrics.registry import yashigani_budget_utilisation_pct
            yashigani_budget_utilisation_pct.labels(
                identity_id=identity_id, group_id=""
            ).set(pct)
        except Exception:  # noqa: BLE001 — metric must never break the hot path
            pass
