"""
Yashigani Optimization Engine — Deterministic, auditable routing.

Four-signal routing: sensitivity + complexity + budget + cost.
Every decision is logged as an audit event.

Modules:
  optimization.engine                -- Core routing engine (P1-P9 priority matrix)
  optimization.sensitivity_classifier -- Three-layer PII/PCI/IP/PHI detection
  optimization.complexity_scorer     -- Token count + content heuristics
  optimization.routing_policy        -- Admin-configurable routing rules
"""

from yashigani.optimization.sensitivity_classifier import (
    SensitivityClassifier,
    SensitivityLevel,
    SensitivityResult,
    _STRING_TO_LEVEL,
    _LEVEL_TO_LEGACY_STRING,
)
from yashigani.optimization.complexity_scorer import (
    ComplexityScorer,
    ComplexityLevel,
)
from yashigani.optimization.engine import (
    OptimizationEngine,
    RoutingDecision,
)
from yashigani.optimization.taxonomy_store import (
    TaxonomyStore,
    DEFAULT_TAXONOMY,
    VALID_COLOUR_CLASSES,
)

__all__ = [
    "SensitivityClassifier",
    "SensitivityLevel",
    "SensitivityResult",
    "_STRING_TO_LEVEL",
    "_LEVEL_TO_LEGACY_STRING",
    "ComplexityScorer",
    "ComplexityLevel",
    "OptimizationEngine",
    "RoutingDecision",
    "TaxonomyStore",
    "DEFAULT_TAXONOMY",
    "VALID_COLOUR_CLASSES",
]
