"""
Yashigani Inspection — Abstract base for classifier backends.

All concrete backends (Ollama, future cloud backends, stubs) implement
ClassifierBackend. The BackendRegistry selects and falls back between them.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class ClassifierResult:
    label: str           # CLEAN | CREDENTIAL_EXFIL | PROMPT_INJECTION_ONLY | CLASSIFIER_ERROR
    confidence: float    # 0.0–1.0
    backend: str         # name of backend that produced this result
    latency_ms: int      # time taken in milliseconds
    raw_response: Optional[str] = None  # for debugging; never logged


class BackendUnavailableError(Exception):
    """
    Raised when a backend is unreachable, times out, or returns a
    non-parseable response. The BackendRegistry catches this and moves
    to the next backend in the fallback chain.
    """
    pass


class ClassifierBackend(ABC):
    name: str  # class-level constant — must be unique across all backends

    @abstractmethod
    def classify(self, content: str) -> ClassifierResult:
        """
        Classify content for prompt injection / credential exfiltration.
        Raises BackendUnavailableError on unreachable/timeout/parse failure.
        Never raises for classification decisions (those are returned as results).
        """
        ...

    @abstractmethod
    def health_check(self) -> bool:
        """
        Return True if the backend is reachable and responding.
        Must never raise — catches all exceptions internally.
        """
        ...
