"""
Yashigani Inspection — Ollama pool for StatefulSet failover.

Maintains a list of Ollama replica endpoints and distributes classify()
calls via round-robin. Automatically removes unhealthy members and
re-adds them after recovery (liveness_check_interval seconds).

In K8s: endpoints are the per-pod DNS names from the headless Service:
  ollama-0.ollama-headless.yashigani.svc.cluster.local:11434
  ollama-1.ollama-headless.yashigani.svc.cluster.local:11434
"""
from __future__ import annotations

from yashigani.inspection._ollama_transport import (
    resolve_engine_model,
    resolve_engine_url,
)
import logging
import os
import threading
import time
import urllib.request
import urllib.error
from typing import Optional

from yashigani.inspection.backend_base import ClassifierBackend, ClassifierResult, BackendUnavailableError
from yashigani.inspection.backends.ollama import OllamaBackend

logger = logging.getLogger(__name__)

_GPU_UNAVAILABLE_SIGNAL = threading.Event()


class OllamaPool(ClassifierBackend):
    """
    Round-robin pool across multiple Ollama replicas.

    # NDC-SWEEP-C (2026-07-31, Tom): STATUS = DEFERRED-PENDING-PREREQUISITE,
    # NOT dead code, NOT currently wired anywhere.
    #
    # Investigated per the NDC (No-Dead-Controls) gate — this class is never
    # instantiated (grep confirms zero non-docstring, non-test call sites of
    # OllamaPool(...) or .from_env() across the whole repo). All 3 real
    # entrypoints (gateway/entrypoint.py, backoffice/entrypoint.py,
    # backoffice/routes/inspection_backend.py) construct a single
    # OllamaBackend(base_url=..., model=...) and wire it into
    # inspection/backend_registry.py::BackendRegistry as the sole "ollama"
    # entry — a DIFFERENT, actually-live HA/fallback mechanism (named
    # fallback chain + circuit breaker + audit events + metrics), not this
    # class's endpoint-list round-robin.
    #
    # This is NOT a silent rug-pull of a control that was supposed to be
    # protecting something today. It is a half-built SCALE-OUT feature for a
    # Kubernetes topology (StatefulSet + `ollama-headless` per-pod DNS —
    # helm/charts/ollama/templates/service.yaml + statefulset.yaml) that DOES
    # exist in Helm, but whose `replicaCount` was deliberately pinned to 1 by
    # a live incident fix (NEW-K8S-OLLAMA-REPLICA-MODEL-ASYMMETRY-001, Ava,
    # 2026-07-28 — see helm/yashigani/values.yaml `ollama:` block): the model
    # pull (helm/yashigani/templates/ollama.yaml Job `yashigani-ollama-init`)
    # only ever pulls via the round-robin ClusterIP Service, landing the
    # model on ONE replica's PVC while a 2nd+ replica's PVC stays empty —
    # multi-replica is UNSAFE until that init job is made per-pod-aware
    # (iterating ollama-0.<headless>, ollama-1.<headless>, ...). That values.yaml
    # comment explicitly documents this as the prerequisite for
    # `replicaCount > 1` ever being safe again.
    #
    # Wiring OllamaPool in NOW would be both unsafe (no live topology has
    # >1 healthy-with-model replica to round-robin over) and pointless
    # (replicaCount is 1). Retiring/deleting it would throw away a correctly
    # hardened (v0.9.3 fixed a thread-unsafe iterator + an infinite-recursion
    # bug in this exact class), ready-to-wire consumption-side half of the
    # eventual multi-GPU scale-out story once the init-job prerequisite
    # lands — Petra/Tiago's deletion policy (never delete without explicit
    # instruction) applies regardless.
    #
    # ACTION TAKEN: docstring below corrected — the previous text claimed
    # "The BackendRegistry reads this [GPU_UNAVAILABLE] signal and applies
    # the configured gpu_failover_policy." That is FALSE today: grep confirms
    # ZERO references to `_GPU_UNAVAILABLE_SIGNAL` or `gpu_failover_policy`
    # anywhere outside this file — BackendRegistry has no such read, and no
    # `gpu_failover_policy` config surface exists anywhere in the codebase.
    # Left AS INERT rather than wired, per the safety argument above.
    #
    # RECOMMENDATION for whoever picks up the scale-out ticket: (1) make
    # ollama.yaml's init Job per-pod-aware, (2) THEN either wire OllamaPool
    # into BackendRegistry as a named backend (its ClassifierBackend
    # interface already fits — see backend_registry.py's all_backends dict
    # shape) or fold its round-robin+health-check logic directly into
    # BackendRegistry's existing fallback-chain model rather than running
    # two independent HA mechanisms side by side.

    Round-robin pool across multiple Ollama replicas (K8s StatefulSet +
    headless-Service per-pod DNS topology). Automatically removes unhealthy
    members and re-adds them after recovery. Sets an internal
    GPU_UNAVAILABLE threading.Event when ALL active pool members go offline
    (see _mark_inactive) — currently observed by NOTHING outside this file;
    do not assume any consumer reacts to it.
    """
    name = "ollama_pool"

    def __init__(
        self,
        endpoints: list[str],
        model: str = "qwen2.5:3b",
        liveness_check_interval: int = 30,
    ) -> None:
        self._all_endpoints = list(endpoints)
        self._model = model
        self._liveness_interval = liveness_check_interval
        self._lock = threading.Lock()
        self._active: list[OllamaBackend] = [
            OllamaBackend(base_url=ep, model=model) for ep in endpoints
        ]
        self._inactive: list[tuple[OllamaBackend, float]] = []  # (backend, removed_at)
        self._index = 0
        self._stop = threading.Event()
        self._health_thread = threading.Thread(
            target=self._health_loop, daemon=True, name="ollama-pool-health"
        )
        self._health_thread.start()

    @classmethod
    def from_env(cls) -> "OllamaPool":
        """
        Build pool from environment variables.
        OLLAMA_POOL_ENDPOINTS: comma-separated URLs (e.g. http://ollama-0:11434,http://ollama-1:11434)
        Falls back to single OLLAMA_BASE_URL if OLLAMA_POOL_ENDPOINTS not set.
        """
        pool_env = os.getenv("OLLAMA_POOL_ENDPOINTS", "")
        if pool_env:
            endpoints = [ep.strip() for ep in pool_env.split(",") if ep.strip()]
        else:
            endpoints = [resolve_engine_url()]
        model = resolve_engine_model()
        return cls(endpoints=endpoints, model=model)

    def classify(self, content: str) -> ClassifierResult:
        max_retries = len(self._all_endpoints)
        for attempt in range(max_retries):
            with self._lock:
                if not self._active:
                    raise BackendUnavailableError("All Ollama pool members are unhealthy")
                backend = self._get_next_backend()
            try:
                return backend.classify(content)
            except BackendUnavailableError:
                self._mark_inactive(backend)
                if attempt == max_retries - 1:
                    raise
        raise BackendUnavailableError("All Ollama pool members are unhealthy")

    def _get_next_backend(self) -> OllamaBackend:
        """Thread-safe round-robin. Must be called under self._lock."""
        backend = self._active[self._index % len(self._active)]
        self._index += 1
        return backend

    def health_check(self) -> bool:
        with self._lock:
            return len(self._active) > 0

    def _mark_inactive(self, backend: OllamaBackend) -> None:
        with self._lock:
            if backend in self._active:
                self._active.remove(backend)
                self._inactive.append((backend, time.time()))
                self._index = 0
                logger.warning(
                    "Ollama pool member removed: %s (active=%d)",
                    backend._base_url, len(self._active),
                )
                if not self._active:
                    _GPU_UNAVAILABLE_SIGNAL.set()
                    logger.error("All Ollama pool members offline — GPU_UNAVAILABLE signal emitted")

    def _health_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(timeout=self._liveness_interval)
            self._check_inactive_members()

    def _check_inactive_members(self) -> None:
        recovered = []
        with self._lock:
            for backend, removed_at in list(self._inactive):
                if backend.health_check():
                    recovered.append((backend, removed_at))

        if recovered:
            with self._lock:
                for backend, _ in recovered:
                    self._inactive = [(b, t) for b, t in self._inactive if b is not backend]
                    self._active.append(backend)
                    self._index = 0
                    logger.info(
                        "Ollama pool member recovered: %s (active=%d)",
                        backend._base_url, len(self._active),
                    )
                if self._active and _GPU_UNAVAILABLE_SIGNAL.is_set():
                    _GPU_UNAVAILABLE_SIGNAL.clear()
                    logger.info("GPU_UNAVAILABLE signal cleared — pool has active members")

    def stop(self) -> None:
        self._stop.set()
