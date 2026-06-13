"""
Yashigani Metrics — Background Prometheus metric collectors.

Polls internal service state at a configurable interval and updates
Gauge metrics. Runs as a daemon thread — safe to start and forget.

Usage:
    collector = MetricsCollector(
        resource_monitor=monitor,
        rate_limiter=limiter,
        chs=chs_service,
        rotation_scheduler=scheduler,
        backend_registry=backend_registry,
    )
    collector.start()
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)


class MetricsCollector:
    """
    Polls all internal services and updates Prometheus Gauge metrics.
    Counter metrics are updated inline (at the point of event) — only
    Gauges need polling since they represent current state.
    """

    def __init__(
        self,
        resource_monitor=None,
        rate_limiter=None,
        chs=None,
        rotation_scheduler=None,
        inspection_pipeline=None,
        rbac_store=None,
        agent_registry=None,
        backend_registry=None,
        pool_manager=None,
        budget_enforcer=None,
        session_store=None,
        poll_interval_seconds: int = 15,
    ) -> None:
        self._monitor = resource_monitor
        self._limiter = rate_limiter
        self._chs = chs
        self._scheduler = rotation_scheduler
        self._pipeline = inspection_pipeline
        self._rbac_store = rbac_store
        self._agent_registry = agent_registry
        self._backend_registry = backend_registry
        self._pool_manager = pool_manager
        self._budget_enforcer = budget_enforcer
        self._session_store = session_store
        self._interval = poll_interval_seconds
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="metrics-collector"
        )
        self._thread.start()
        logger.info("Metrics collector started (interval=%ds)", self._interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    # -- Poll loop -----------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._collect()
            except Exception as exc:
                logger.warning("Metrics collection error: %s", exc)
            self._stop.wait(timeout=self._interval)

    def _collect(self) -> None:
        from yashigani.metrics.registry import (
            resource_pressure_index,
            resource_memory_pressure,
            resource_cpu_throttle,
            resource_gpu_pressure,
            resource_gpu_utilisation,
            resource_gpu_memory_pressure,
            resource_memory_used_bytes,
            chs_handles_active,
            chs_current_ttl_seconds,
            ratelimit_multiplier,
            ratelimit_effective_rps,
            ratelimit_config_last_updated_timestamp,
            inspection_threshold,
            inspection_model,
        )

        # ── Resource monitor ────────────────────────────────────────────────
        if self._monitor is not None:
            try:
                m = self._monitor.get_metrics()
                resource_pressure_index.set(m.pressure_index)
                resource_memory_pressure.set(m.memory_pressure)
                resource_cpu_throttle.set(m.cpu_throttle)
                resource_gpu_pressure.set(m.gpu_pressure)
                resource_memory_used_bytes.set(m.memory_used_bytes)
                chs_current_ttl_seconds.set(self._monitor.current_ttl_seconds)
            except Exception as exc:
                logger.debug("Resource monitor metrics error: %s", exc)

        # ── GPU per-device ───────────────────────────────────────────────────
        if self._monitor is not None:
            try:
                from yashigani.chs.gpu_monitor import read_gpu_metrics
                gpu = read_gpu_metrics(
                    ollama_base_url=getattr(self._monitor, "_ollama_base_url", None)
                )
                for dev in gpu.devices:
                    idx = str(dev.get("index", 0))
                    name = dev.get("name", "unknown")
                    backend = gpu.backend
                    resource_gpu_utilisation.labels(
                        device_index=idx, device_name=name, backend=backend
                    ).set(dev.get("gpu_utilisation", 0.0))
                    resource_gpu_memory_pressure.labels(
                        device_index=idx, device_name=name, backend=backend
                    ).set(dev.get("memory_pressure", 0.0))
            except Exception as exc:
                logger.debug("GPU per-device metrics error: %s", exc)

        # ── CHS handles ─────────────────────────────────────────────────────
        if self._chs is not None:
            try:
                active = len([
                    h for h in self._chs._handles.values()
                    if not h.get("revoked") and h.get("expires_at", 0) > time.time()
                ])
                chs_handles_active.set(active)
            except Exception as exc:
                logger.debug("CHS handle metrics error: %s", exc)

        # ── Rate limiter ─────────────────────────────────────────────────────
        if self._limiter is not None:
            try:
                mult = self._limiter.current_rpi_multiplier()
                ratelimit_multiplier.set(mult)
                cfg = self._limiter.current_config()
                ratelimit_effective_rps.labels(dimension="global").set(cfg.global_rps * mult)
                ratelimit_effective_rps.labels(dimension="ip").set(cfg.per_ip_rps * mult)
                ratelimit_effective_rps.labels(dimension="agent").set(cfg.per_agent_rps * mult)
                ratelimit_effective_rps.labels(dimension="session").set(cfg.per_session_rps * mult)
                updated_at = getattr(cfg, "updated_at", None)
                if updated_at is not None:
                    ratelimit_config_last_updated_timestamp.set(updated_at)
            except Exception as exc:
                logger.debug("Rate limiter metrics error: %s", exc)

        # ── Inspection pipeline ──────────────────────────────────────────────
        if self._pipeline is not None:
            try:
                inspection_threshold.set(self._pipeline._threshold)
                model_name = self._pipeline._classifier._model
                # Use info pattern: set gauge to 1 with model label
                inspection_model.labels(model=model_name).set(1)
            except Exception as exc:
                logger.debug("Inspection pipeline metrics error: %s", exc)

        # ── Backend registry — active backend info metric ────────────────────
        if self._backend_registry is not None:
            try:
                from yashigani.metrics.registry import inspection_active_backend
                active = self._backend_registry.get_active_backend_name()
                inspection_active_backend.labels(backend=active).set(1)
            except Exception as exc:
                logger.debug("Backend registry metrics error: %s", exc)

        # ── RBAC store ───────────────────────────────────────────────────────
        if self._rbac_store is not None:
            try:
                from yashigani.metrics.registry import rbac_groups_total
                rbac_groups_total.set(len(self._rbac_store.list_groups()))
            except Exception as exc:
                logger.debug("RBAC store metrics error: %s", exc)

        # ── Agent registry ───────────────────────────────────────────────────
        if self._agent_registry is not None:
            try:
                from yashigani.metrics.registry import agent_registry_size
                agent_registry_size.labels(status="active").set(
                    self._agent_registry.count("active")
                )
                agent_registry_size.labels(status="inactive").set(
                    self._agent_registry.count("inactive")
                )
            except Exception as exc:
                logger.debug("Agent registry metrics error: %s", exc)

        # ── Pool Manager ─────────────────────────────────────────────────────
        if self._pool_manager is not None:
            try:
                from yashigani.metrics.registry import (
                    yashigani_pool_containers_active,
                    yashigani_pool_containers_active_by_service,
                    yashigani_pool_ollama_instances,
                    yashigani_pool_container_info,
                )
                containers = self._pool_manager.list_all()
                yashigani_pool_containers_active.set(len(containers))

                # Per-service counts
                svc_counts: dict[str, int] = {}
                for cinfo in containers:
                    svc = getattr(cinfo, "service_slug", "unknown")
                    svc_counts[svc] = svc_counts.get(svc, 0) + 1
                for svc, cnt in svc_counts.items():
                    yashigani_pool_containers_active_by_service.labels(service=svc).set(cnt)

                # Ollama instance count
                ollama_count = sum(
                    1 for c in containers
                    if "ollama" in getattr(c, "service_slug", "").lower()
                )
                yashigani_pool_ollama_instances.set(ollama_count)

                # Per-container info gauge
                for cinfo in containers:
                    yashigani_pool_container_info.labels(
                        container_id=getattr(cinfo, "container_id", "")[:32],
                        service=getattr(cinfo, "service_slug", ""),
                        agent_id=getattr(cinfo, "identity_id", ""),
                        status=getattr(cinfo, "status", ""),
                    ).set(1)
            except Exception as exc:
                logger.debug("Pool Manager metrics error: %s", exc)

        # ── Budget utilisation (group-level) ─────────────────────────────────
        # Identity-level utilisation is updated inline by the budget enforcer.
        # We poll group-level utilisation here (periodic, not per-request).
        if self._budget_enforcer is not None:
            try:
                from yashigani.metrics.registry import yashigani_budget_utilisation_pct
                groups = self._budget_enforcer.list_group_utilisation()
                for group_id, pct in groups.items():
                    yashigani_budget_utilisation_pct.labels(
                        identity_id="", group_id=group_id
                    ).set(pct)
            except Exception as exc:
                logger.debug("Budget group utilisation metrics error: %s", exc)

        # ── Active sessions ───────────────────────────────────────────────────
        # Polls the session store for a live count of valid Redis session keys.
        # Wires yashigani_auth_active_sessions used by the Security Overview
        # dashboard "Active Sessions" stat panel.
        if self._session_store is not None:
            try:
                from yashigani.metrics.registry import auth_active_sessions
                auth_active_sessions.set(self._session_store.count_active_all())
            except Exception as exc:
                logger.debug("Session store active-sessions metrics error: %s", exc)
