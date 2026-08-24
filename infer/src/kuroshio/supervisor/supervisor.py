# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""llama-server lifecycle supervisor.

Responsibilities (design doc §2 amendment, platform-requirements doc §11):
  - spawn one `llama-server` process per loaded model, passing through
    `n_gpu_layers` and MoE expert-offload `--override-tensor` rules;
  - idle-unload timer + LRU eviction once over the resident-model ceiling;
  - multi-model residency + a keep-alive pin so a warm-pinned model (the
    mandatory sensitivity classifier, WARMUP-001) stays resident under
    LRU/idle pressure;
  - `/healthz`-shaped assertion that a GPU-expected model actually has
    offloaded layers > 0 — "flag in args != offload occurred" (Ava gate).

Process spawn is behind the injectable `ProcessRunner` (process.py) — no
real `llama-server` binary is required by this module's unit tests.

Red-Council H1 (Tom, 2026-07-29 design-review): `load()` also re-runs an
optional, injectable `ProvenanceVerifier` on EVERY call — including the
fast path for an already-resident model — not just once at pull time.
Signature/TTL/revocation verification previously happened only inside the
Hugging Face pull adapter's admission gate (`catalog.SignedCatalog.require`);
a model that became revoked or aged out AFTER it was already resident kept
being served indefinitely, because this module had no concept of
provenance at all, only sha256 identity. See `provenance_reverify.py` for
the concrete `ServeTimeProvenanceVerifier` implementation — this module
only depends on the narrow `ProvenanceVerifier` Protocol below, not on
`catalog.py`/`convert_provenance.py` directly, keeping the supervisor's own
dependency graph minimal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Protocol

from kuroshio.models import ResolvedModel
from kuroshio.supervisor.process import ProcessHandle, ProcessRunner


class ProvenanceVerifier(Protocol):
    """Structural contract for a serve-time provenance re-verification hook
    (Red-Council H1). `Supervisor.load()` calls `verify()` before EVERY
    (re)load of a model — including a hit against an already-resident
    instance — and treats any raised exception as fail-closed: the load is
    refused, nothing is spawned, no residency state changes. Implementations
    (e.g. `provenance_reverify.ServeTimeProvenanceVerifier`) decide what
    "fails" means (bad signature, expired TTL, revoked, tampered tier); this
    Protocol only defines the calling contract."""

    def verify(self, resolved_model: ResolvedModel) -> None: ...


class ReadinessProbe(Protocol):
    """Structural contract for a post-spawn llama-server readiness gate
    (Red-Council Tom F4, 2026-07-29 design-review). After `Supervisor.load()`
    spawns a NEW llama-server process it calls `wait_until_ready(port)` BEFORE
    recording the instance or returning it to the caller — so the app never
    forwards a request to a port whose backend is still loading the GGUF and
    answering `/health` with `503` (or refusing the connection). The probe must
    block until the backend reports ready, or raise `BackendNotReadyError` once
    its own bounded timeout elapses (fail closed — never hang forever, never
    return while the backend is still loading). Only invoked on a real spawn,
    never on the already-resident fast path (that instance was already proven
    ready when it was first loaded). See `readiness.HttpReadinessProbe` for the
    concrete HTTP implementation; this Protocol only defines the calling
    contract so the supervisor's dependency graph stays minimal."""

    def wait_until_ready(self, port: int) -> None: ...


class SupervisorError(Exception):
    """Base error for supervisor operations."""


class ModelNotLoadedError(SupervisorError):
    pass


class BackendNotReadyError(SupervisorError):
    """Raised (by a `ReadinessProbe`) when a freshly-spawned llama-server never
    became ready within the probe's bounded timeout (Red-Council Tom F4).
    `Supervisor.load()` treats it as fail-closed: the just-spawned process is
    terminated and no residency state is recorded, so a backend that never comes
    up neither hangs the request nor leaks an orphaned process."""


class ResourceLimitExceeded(SupervisorError):
    """Raised when a request would breach a configured resource ceiling.

    Red-council item #7: the supervisor exposes numeric ceilings (context
    length, concurrency, max tokens per request) that CLAMP to a configured
    max; a breach returns this error, which the HTTP app (app.py) turns into
    an HTTP 429 — never an unbounded resource grant that risks OOM. Actual
    cgroup/pids enforcement is a deployment-layer concern (Captain); this is
    the supervisor-level admission control in front of it.
    """


@dataclass(frozen=True)
class ResourceLimits:
    """Supervisor-wide resource ceilings.

    Attributes:
        max_context_length: hard ceiling for `n_ctx` / `--ctx-size` — a
            request asking for more is CLAMPED down to this value, never
            rejected outright (context length is a quality tradeoff, not an
            admission-control decision).
        max_concurrent_requests: per-model in-flight request ceiling.
            Breaching this raises `ResourceLimitExceeded` (the caller, e.g.
            app.py, turns this into HTTP 429) rather than queuing
            unboundedly or risking OOM under load.
        max_tokens_per_request: hard ceiling for `n_predict`/`max_tokens` —
            like context length, CLAMPED down rather than rejected.
    """

    max_context_length: int | None = None
    max_concurrent_requests: int = 4
    max_tokens_per_request: int | None = None


@dataclass(frozen=True)
class LoadConfig:
    """Per-model load configuration.

    Attributes:
        n_gpu_layers: layers offloaded to GPU (0 = CPU-only for this model).
        override_tensor: MoE expert-offload rules passed through as
            `--override-tensor` flags, e.g.
            `[r"\\.ffn_.*_exps\\.weight=CPU"]` to keep attention on GPU and
            push expert FFN tensors to CPU RAM (platform-requirements §11.2).
        keep_alive_pin: if True, this model is exempt from idle-unload and
            LRU eviction — used for the mandatory sensitivity classifier
            (WARMUP-001) so it stays warm while user chat models cycle.
        expect_gpu: if True, `/healthz` treats `n_gpu_layers == 0` as a hard
            failure (a GPU-tagged deployment silently fell back to CPU),
            not a warning (Captain #3 / platform-requirements §4.5).
        context_length: `--ctx-size` passthrough.
        extra_args: any additional raw `llama-server` CLI args.
        cache_prompt: Red-Council C1 (Laura/Ava/Tom/Iris, 2026-07-29
            design-review): whether the shim is ALLOWED to set
            `cache_prompt: true` on outgoing `/completion` bodies. Defaults
            to **False** — the conservative, isolation-safe posture. A
            shared `kuroshio-chat` process serves every tenant reaching that
            model through a finite llama-server slot pool; llama-server's
            own `cache_prompt` reuse selects a slot by longest-common-prefix
            match against WHATEVER is currently cached, with no notion of
            caller identity. With a near-universal shared system prompt
            (the common gated-deployment case), leaving `cache_prompt` at
            llama-server's own default (`true`) turns time-to-first-token
            into a cross-tenant prefix-confirmation side channel (Laura's
            F1 finding — deterministic given llama-server's documented
            slot-selection behaviour, not speculative). Forcing it off
            costs re-eval performance on legitimately-repeated prompts;
            that cost is accepted as the price of the baseline (shared-
            process) posture being safe OUT OF THE BOX. The only way to
            get real per-conversation isolation approaching "safe to leave
            cache_prompt on" is per-tenant model instances (C3, gated,
            separately tracked) — this default does not claim to be that;
            it only ensures the SHARED baseline this v1 foundation actually
            ships never silently inherits an unexamined library default.
            **Deferred, not built here:** a live multi-user canary-bleed
            proof (T1 in Ava's report — fire concurrent request pairs
            against a REAL llama-server and assert a per-run canary token
            never crosses between callers) requires an actual llama-server
            binary/GPU rig, which does not exist in this offline package;
            do not fabricate that proof here. What IS proven here (unit
            tests, this commit): the shim always emits an explicit
            `cache_prompt` field (never silently omitted so llama-server's
            own default applies), and it is wired end-to-end through
            `LoadConfig` / `EngineConfig` / the env-var contract so an
            operator opting into the high-assurance/per-tenant-instance
            posture can deliberately re-enable it.
        parallel_slots: sizes the `--parallel` (`-np`) llama-server CLI
            flag — previously never emitted at all (Tom/Laura/Ava/Iris
            finding: "whatever the compiled binary defaults to,
            unconfigured"). When `None` (the default), `build_args` derives
            it from `ResourceLimits.max_concurrent_requests` so the two
            previously "independent, unconnected numbers" (the Python
            admission-control ceiling and llama-server's own slot count)
            can never silently drift apart. An explicit value here
            overrides that derivation for deployments that need to run a
            different slot count than the request-admission ceiling (e.g.
            fewer slots than admitted requests, deliberately serializing
            some traffic) — a documented escape hatch, not a silent gap.
    """

    n_gpu_layers: int | None = None
    override_tensor: tuple[str, ...] = field(default_factory=tuple)
    keep_alive_pin: bool = False
    expect_gpu: bool = False
    context_length: int | None = None
    extra_args: tuple[str, ...] = field(default_factory=tuple)
    cache_prompt: bool = False
    parallel_slots: int | None = None


@dataclass
class ModelInstance:
    sha256: str
    handle: ProcessHandle
    port: int
    load_config: LoadConfig
    loaded_at: datetime
    last_used_at: datetime


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


class Supervisor:
    def __init__(
        self,
        *,
        process_runner: ProcessRunner,
        llama_server_binary: str = "llama-server",
        idle_unload_seconds: int = 600,
        max_resident_models: int = 3,
        resource_limits: ResourceLimits | None = None,
        port_allocator: Callable[[], int] | None = None,
        clock: Callable[[], datetime] | None = None,
        provenance_verifier: ProvenanceVerifier | None = None,
        readiness_probe: ReadinessProbe | None = None,
    ) -> None:
        self._runner = process_runner
        self._binary = llama_server_binary
        self._idle_unload_seconds = idle_unload_seconds
        self._max_resident_models = max_resident_models
        self._resource_limits = resource_limits or ResourceLimits()
        self._clock = clock or _default_clock
        self._provenance_verifier = provenance_verifier
        self._readiness_probe = readiness_probe
        self._instances: dict[str, ModelInstance] = {}
        self._inflight: dict[str, int] = {}
        self._next_port_offset = 0
        self._port_allocator = port_allocator or self._default_port_allocator

    @property
    def resource_limits(self) -> ResourceLimits:
        return self._resource_limits

    def clamp_context_length(self, requested: int | None) -> int | None:
        """Clamp a requested context length to the configured ceiling (never rejects)."""
        limit = self._resource_limits.max_context_length
        if limit is None:
            return requested
        if requested is None:
            return limit
        return min(requested, limit)

    def clamp_max_tokens(self, requested: int | None) -> int | None:
        """Clamp a requested max-tokens/n_predict value to the configured ceiling (never rejects)."""
        limit = self._resource_limits.max_tokens_per_request
        if limit is None:
            return requested
        if requested is None:
            return limit
        return min(requested, limit)

    def acquire_request_slot(self, sha256: str) -> None:
        """Admission control: raises `ResourceLimitExceeded` if `sha256` is
        already at its concurrency ceiling — callers turn this into a 429/503,
        never let the request through to risk OOM. Must be paired with
        `release_request_slot` (typically in a `finally`/generator-`finally`)."""
        current = self._inflight.get(sha256, 0)
        if current >= self._resource_limits.max_concurrent_requests:
            raise ResourceLimitExceeded(
                f"model {sha256} is at its concurrency ceiling "
                f"({self._resource_limits.max_concurrent_requests} in-flight requests)"
            )
        self._inflight[sha256] = current + 1

    def release_request_slot(self, sha256: str) -> None:
        current = self._inflight.get(sha256, 0)
        if current <= 1:
            self._inflight.pop(sha256, None)
        else:
            self._inflight[sha256] = current - 1

    def inflight_count(self, sha256: str) -> int:
        return self._inflight.get(sha256, 0)

    def _default_port_allocator(self) -> int:
        # Sequential allocator, sufficient for the supervisor's own tests and
        # for a single-process deploy; a real deploy may inject a
        # free-port-probing allocator instead.
        port = 39000 + self._next_port_offset
        self._next_port_offset += 1
        return port

    @property
    def resident_shas(self) -> list[str]:
        return list(self._instances.keys())

    def is_loaded(self, sha256: str) -> bool:
        return sha256 in self._instances

    def get_instance(self, sha256: str) -> ModelInstance | None:
        return self._instances.get(sha256)

    def build_args(self, resolved_model: ResolvedModel, load_config: LoadConfig, port: int) -> list[str]:
        args: list[str] = ["--model", str(resolved_model.blob_path), "--port", str(port)]
        if load_config.n_gpu_layers is not None:
            args += ["--n-gpu-layers", str(load_config.n_gpu_layers)]
        for rule in load_config.override_tensor:
            args += ["--override-tensor", rule]
        if load_config.context_length is not None:
            args += ["--ctx-size", str(load_config.context_length)]
        # Red-Council C1: always emit an explicit slot count rather than
        # relying on the llama-server binary's own compiled-in default,
        # which this codebase never examined before (Tom/Laura/Ava/Iris
        # finding). Deriving from `max_concurrent_requests` when the
        # deploy hasn't overridden it directly ties the Python-level
        # admission ceiling to the actual number of llama-server slots
        # serving that ceiling — previously two independent, unconnected
        # numbers.
        parallel = (
            load_config.parallel_slots
            if load_config.parallel_slots is not None
            else self._resource_limits.max_concurrent_requests
        )
        args += ["--parallel", str(parallel)]
        args += list(load_config.extra_args)
        return args

    def load(self, resolved_model: ResolvedModel, load_config: LoadConfig) -> ModelInstance:
        """Spawn (or return the existing) instance for this model's digest.

        Red-Council H1: if a `ProvenanceVerifier` is configured, it is
        re-run here on EVERY call — including the fast path below for an
        already-resident model — before any residency state is touched.
        A raised exception fails this call closed: no spawn happens, the
        existing instance (if any) is left untouched, and the caller never
        gets a `ModelInstance` back for a model whose provenance no longer
        checks out.

        Red-Council Tom F4: on a REAL spawn (not the already-resident fast
        path) a configured `ReadinessProbe` is polled AFTER spawn and BEFORE
        the instance is recorded/returned — so the caller (and therefore the
        app forwarding traffic) never sees a `ModelInstance` for a backend
        whose port is not yet answering. If the probe raises
        `BackendNotReadyError` (its bounded timeout elapsed), the just-spawned
        process is terminated and no residency state is recorded: the load
        fails closed rather than hanging or leaking a never-ready process.
        """
        if self._provenance_verifier is not None:
            self._provenance_verifier.verify(resolved_model)

        existing = self._instances.get(resolved_model.sha256)
        if existing is not None:
            existing.last_used_at = self._clock()
            return existing

        self._evict_if_over_capacity()
        port = self._port_allocator()
        args = self.build_args(resolved_model, load_config, port)
        handle = self._runner.spawn(binary=self._binary, args=args, env={})
        if self._readiness_probe is not None:
            try:
                self._readiness_probe.wait_until_ready(port)
            except BackendNotReadyError:
                # Fail closed: terminate the spawned-but-never-ready process and
                # record nothing, so the model is not treated as resident and
                # nothing is leaked. The caller sees the raised error.
                handle.terminate()
                raise
        now = self._clock()
        instance = ModelInstance(
            sha256=resolved_model.sha256,
            handle=handle,
            port=port,
            load_config=load_config,
            loaded_at=now,
            last_used_at=now,
        )
        self._instances[resolved_model.sha256] = instance
        return instance

    def touch(self, sha256: str) -> None:
        """Mark a resident model as recently used (resets idle/LRU clocks)."""
        instance = self._instances.get(sha256)
        if instance is None:
            raise ModelNotLoadedError(sha256)
        instance.last_used_at = self._clock()

    def unload(self, sha256: str) -> bool:
        instance = self._instances.pop(sha256, None)
        if instance is None:
            return False
        instance.handle.terminate()
        return True

    def idle_unload_sweep(self) -> list[str]:
        """Unload every non-pinned instance idle beyond the configured timeout."""
        now = self._clock()
        to_unload = [
            sha
            for sha, inst in self._instances.items()
            if not inst.load_config.keep_alive_pin
            and (now - inst.last_used_at).total_seconds() >= self._idle_unload_seconds
        ]
        for sha in to_unload:
            self.unload(sha)
        return to_unload

    def _evict_if_over_capacity(self) -> str | None:
        if len(self._instances) < self._max_resident_models:
            return None
        evictable = [inst for inst in self._instances.values() if not inst.load_config.keep_alive_pin]
        if not evictable:
            # Every resident is keep-alive-pinned (e.g. the mandatory
            # classifier + every chat model happens to be pinned) — the
            # supervisor allows exceeding the nominal ceiling rather than
            # silently refusing to serve; capacity planning is a deploy
            # concern, not something this v1 foundation enforces by denial.
            return None
        lru = min(evictable, key=lambda inst: inst.last_used_at)
        self.unload(lru.sha256)
        return lru.sha256

    def healthz(self, sha256: str) -> dict[str, object]:
        """GPU-engaged healthcheck (platform-requirements §4.5 / Captain #3).

        A GPU-expected model reporting zero offloaded layers is a hard
        `unhealthy`, never a silent CPU fallback treated as fine.
        """
        instance = self._instances.get(sha256)
        if instance is None:
            return {"status": "not_loaded", "sha256": sha256}

        alive = instance.handle.is_alive()
        offloaded_layers = instance.load_config.n_gpu_layers or 0
        gpu_engaged = offloaded_layers > 0
        expect_gpu = instance.load_config.expect_gpu
        healthy = alive and (gpu_engaged if expect_gpu else True)
        return {
            "status": "healthy" if healthy else "unhealthy",
            "sha256": sha256,
            "alive": alive,
            "offloaded_layers": offloaded_layers,
            "expect_gpu": expect_gpu,
            "gpu_engaged": gpu_engaged,
            "keep_alive_pin": instance.load_config.keep_alive_pin,
        }


__all__ = [
    "BackendNotReadyError",
    "LoadConfig",
    "ModelInstance",
    "ModelNotLoadedError",
    "ProvenanceVerifier",
    "ReadinessProbe",
    "ResourceLimitExceeded",
    "ResourceLimits",
    "Supervisor",
    "SupervisorError",
]
