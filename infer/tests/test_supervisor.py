# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for the llama-server lifecycle supervisor. No real llama-server binary —
ProcessRunner is faked (see conftest.FakeProcessRunner)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.conftest import FakeProcessRunner
from kuroshio.models import Provenance, ProvenanceKind, ResolvedModel
from kuroshio.supervisor.supervisor import (
    LoadConfig,
    ModelNotLoadedError,
    ResourceLimitExceeded,
    ResourceLimits,
    Supervisor,
)


class _FakeProvenanceVerifier:
    """Test double for the `ProvenanceVerifier` Protocol (Red-Council H1) —
    records every `verify()` call and can be configured to raise on a
    specific call number (1-indexed), so tests can assert re-verification
    happens on EVERY `Supervisor.load()` call, not just the first."""

    class VerificationFailed(RuntimeError):
        pass

    def __init__(self, *, fail_on_call: int | None = None) -> None:
        self.calls: list[ResolvedModel] = []
        self._fail_on_call = fail_on_call

    def verify(self, resolved_model: ResolvedModel) -> None:
        self.calls.append(resolved_model)
        if self._fail_on_call is not None and len(self.calls) == self._fail_on_call:
            raise self.VerificationFailed(f"forced failure on call {len(self.calls)}")


def _resolved_model(sha: str) -> ResolvedModel:
    return ResolvedModel(
        sha256=sha,
        blob_path=Path(f"/blobs/{sha}.gguf"),  # never actually read by these tests — no real llama-server spawn
        metadata={"name": f"model-{sha}"},
        provenance=Provenance(kind=ProvenanceKind.LOCAL_FILE, origin="x", sha256=sha),
    )


class _FakeClock:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture()
def clock() -> _FakeClock:
    return _FakeClock(datetime(2026, 1, 1, tzinfo=timezone.utc))


def test_load_spawns_via_process_runner(fake_process_runner: FakeProcessRunner, clock: _FakeClock) -> None:
    supervisor = Supervisor(process_runner=fake_process_runner, clock=clock)
    model = _resolved_model("a" * 64)

    instance = supervisor.load(model, LoadConfig())

    assert supervisor.is_loaded("a" * 64)
    assert len(fake_process_runner.spawned) == 1
    assert "--model" in fake_process_runner.spawned[0]["args"]
    assert instance.port >= 39000


def test_load_is_idempotent_for_an_already_resident_model(
    fake_process_runner: FakeProcessRunner, clock: _FakeClock
) -> None:
    supervisor = Supervisor(process_runner=fake_process_runner, clock=clock)
    model = _resolved_model("a" * 64)

    first = supervisor.load(model, LoadConfig())
    second = supervisor.load(model, LoadConfig())

    assert first.port == second.port
    assert len(fake_process_runner.spawned) == 1  # never spawned twice


def test_build_args_passes_through_gpu_layers_and_moe_offload(fake_process_runner: FakeProcessRunner) -> None:
    supervisor = Supervisor(process_runner=fake_process_runner)
    model = _resolved_model("a" * 64)
    config = LoadConfig(n_gpu_layers=20, override_tensor=(r"\.ffn_.*_exps\.weight=CPU",), context_length=8192)

    args = supervisor.build_args(model, config, port=40000)

    assert "--n-gpu-layers" in args and "20" in args
    assert "--override-tensor" in args and r"\.ffn_.*_exps\.weight=CPU" in args
    assert "--ctx-size" in args and "8192" in args


def test_unload_terminates_the_process_handle(fake_process_runner: FakeProcessRunner, clock: _FakeClock) -> None:
    supervisor = Supervisor(process_runner=fake_process_runner, clock=clock)
    model = _resolved_model("a" * 64)
    supervisor.load(model, LoadConfig())

    assert supervisor.unload("a" * 64) is True
    assert not supervisor.is_loaded("a" * 64)
    assert supervisor.unload("a" * 64) is False  # already gone


def test_touch_updates_last_used_and_raises_if_not_loaded(
    fake_process_runner: FakeProcessRunner, clock: _FakeClock
) -> None:
    supervisor = Supervisor(process_runner=fake_process_runner, clock=clock)
    model = _resolved_model("a" * 64)
    supervisor.load(model, LoadConfig())
    clock.advance(30)
    supervisor.touch("a" * 64)
    assert supervisor.get_instance("a" * 64).last_used_at == clock.now  # type: ignore[union-attr]

    with pytest.raises(ModelNotLoadedError):
        supervisor.touch("b" * 64)


def test_idle_unload_sweep_unloads_only_non_pinned_idle_models(
    fake_process_runner: FakeProcessRunner, clock: _FakeClock
) -> None:
    supervisor = Supervisor(process_runner=fake_process_runner, clock=clock, idle_unload_seconds=60)
    idle_model = _resolved_model("a" * 64)
    pinned_model = _resolved_model("b" * 64)
    supervisor.load(idle_model, LoadConfig())
    supervisor.load(pinned_model, LoadConfig(keep_alive_pin=True))

    clock.advance(120)
    unloaded = supervisor.idle_unload_sweep()

    assert unloaded == ["a" * 64]
    assert not supervisor.is_loaded("a" * 64)
    assert supervisor.is_loaded("b" * 64)  # pinned model survives the sweep


def test_lru_eviction_when_over_capacity(fake_process_runner: FakeProcessRunner, clock: _FakeClock) -> None:
    supervisor = Supervisor(process_runner=fake_process_runner, clock=clock, max_resident_models=2)
    supervisor.load(_resolved_model("a" * 64), LoadConfig())
    clock.advance(10)
    supervisor.load(_resolved_model("b" * 64), LoadConfig())
    clock.advance(10)

    # third load exceeds capacity -> evicts the least-recently-used (a)
    supervisor.load(_resolved_model("c" * 64), LoadConfig())

    assert not supervisor.is_loaded("a" * 64)
    assert supervisor.is_loaded("b" * 64)
    assert supervisor.is_loaded("c" * 64)


def test_lru_eviction_never_evicts_keep_alive_pinned_models(
    fake_process_runner: FakeProcessRunner, clock: _FakeClock
) -> None:
    supervisor = Supervisor(process_runner=fake_process_runner, clock=clock, max_resident_models=1)
    supervisor.load(_resolved_model("a" * 64), LoadConfig(keep_alive_pin=True))  # e.g. the mandatory classifier
    clock.advance(10)

    # Loading a second model would normally evict the LRU resident, but the
    # only resident is pinned — the supervisor allows exceeding the nominal
    # ceiling rather than unloading a pinned model.
    supervisor.load(_resolved_model("b" * 64), LoadConfig())

    assert supervisor.is_loaded("a" * 64)
    assert supervisor.is_loaded("b" * 64)


def test_healthz_reports_not_loaded() -> None:
    supervisor = Supervisor(process_runner=FakeProcessRunner())
    health = supervisor.healthz("f" * 64)
    assert health["status"] == "not_loaded"


def test_healthz_gpu_expected_but_zero_layers_is_hard_unhealthy(fake_process_runner: FakeProcessRunner) -> None:
    """Captain #3 / platform-requirements §4.5: a GPU-tagged deployment
    silently falling back to CPU must be a hard fail, not a warning."""
    supervisor = Supervisor(process_runner=fake_process_runner)
    model = _resolved_model("a" * 64)
    supervisor.load(model, LoadConfig(n_gpu_layers=0, expect_gpu=True))

    health = supervisor.healthz("a" * 64)
    assert health["status"] == "unhealthy"
    assert health["gpu_engaged"] is False


def test_healthz_gpu_engaged_when_layers_offloaded(fake_process_runner: FakeProcessRunner) -> None:
    supervisor = Supervisor(process_runner=fake_process_runner)
    model = _resolved_model("a" * 64)
    supervisor.load(model, LoadConfig(n_gpu_layers=32, expect_gpu=True))

    health = supervisor.healthz("a" * 64)
    assert health["status"] == "healthy"
    assert health["gpu_engaged"] is True
    assert health["offloaded_layers"] == 32


def test_healthz_cpu_only_model_without_gpu_expectation_is_healthy(fake_process_runner: FakeProcessRunner) -> None:
    supervisor = Supervisor(process_runner=fake_process_runner)
    model = _resolved_model("a" * 64)
    supervisor.load(model, LoadConfig(n_gpu_layers=0, expect_gpu=False))

    health = supervisor.healthz("a" * 64)
    assert health["status"] == "healthy"


# --- resource limits (red-council item #7) ---


def test_clamp_context_length_caps_at_configured_max(fake_process_runner: FakeProcessRunner) -> None:
    limits = ResourceLimits(max_context_length=4096)
    supervisor = Supervisor(process_runner=fake_process_runner, resource_limits=limits)
    assert supervisor.clamp_context_length(8192) == 4096
    assert supervisor.clamp_context_length(1024) == 1024  # below ceiling, unchanged
    assert supervisor.clamp_context_length(None) == 4096  # unset request defaults to the ceiling


def test_clamp_context_length_passthrough_when_no_limit_configured(fake_process_runner: FakeProcessRunner) -> None:
    supervisor = Supervisor(process_runner=fake_process_runner)
    assert supervisor.clamp_context_length(999_999) == 999_999


def test_clamp_max_tokens_caps_at_configured_max(fake_process_runner: FakeProcessRunner) -> None:
    limits = ResourceLimits(max_tokens_per_request=512)
    supervisor = Supervisor(process_runner=fake_process_runner, resource_limits=limits)
    assert supervisor.clamp_max_tokens(2048) == 512


def test_acquire_request_slot_raises_at_concurrency_ceiling(fake_process_runner: FakeProcessRunner) -> None:
    limits = ResourceLimits(max_concurrent_requests=2)
    supervisor = Supervisor(process_runner=fake_process_runner, resource_limits=limits)
    sha = "a" * 64

    supervisor.acquire_request_slot(sha)
    supervisor.acquire_request_slot(sha)
    assert supervisor.inflight_count(sha) == 2

    with pytest.raises(ResourceLimitExceeded):
        supervisor.acquire_request_slot(sha)


def test_release_request_slot_frees_capacity(fake_process_runner: FakeProcessRunner) -> None:
    limits = ResourceLimits(max_concurrent_requests=1)
    supervisor = Supervisor(process_runner=fake_process_runner, resource_limits=limits)
    sha = "a" * 64

    supervisor.acquire_request_slot(sha)
    with pytest.raises(ResourceLimitExceeded):
        supervisor.acquire_request_slot(sha)

    supervisor.release_request_slot(sha)
    supervisor.acquire_request_slot(sha)  # capacity freed, must not raise
    assert supervisor.inflight_count(sha) == 1


def test_release_request_slot_is_safe_when_nothing_inflight(fake_process_runner: FakeProcessRunner) -> None:
    supervisor = Supervisor(process_runner=fake_process_runner)
    supervisor.release_request_slot("never-acquired")  # must not raise
    assert supervisor.inflight_count("never-acquired") == 0


# --- Red-Council C1 (2026-07-29): session-isolation config surface ---


def test_build_args_always_emits_an_explicit_parallel_flag(fake_process_runner: FakeProcessRunner) -> None:
    """Previously `--parallel` was never emitted at all — llama-server's own
    compiled-in default applied completely unexamined (Tom/Laura/Ava/Iris
    finding). This must never regress to silent omission."""
    supervisor = Supervisor(process_runner=fake_process_runner)
    model = _resolved_model("a" * 64)
    args = supervisor.build_args(model, LoadConfig(), port=40000)
    assert "--parallel" in args


def test_build_args_sizes_parallel_from_max_concurrent_requests_by_default(
    fake_process_runner: FakeProcessRunner,
) -> None:
    """The Python-level admission ceiling and llama-server's own slot count
    must never be two independent, silently-drifting numbers."""
    limits = ResourceLimits(max_concurrent_requests=6)
    supervisor = Supervisor(process_runner=fake_process_runner, resource_limits=limits)
    model = _resolved_model("a" * 64)

    args = supervisor.build_args(model, LoadConfig(), port=40000)

    idx = args.index("--parallel")
    assert args[idx + 1] == "6"


def test_build_args_honours_explicit_parallel_slots_override(fake_process_runner: FakeProcessRunner) -> None:
    """An explicit LoadConfig.parallel_slots overrides the ResourceLimits-derived
    default — a documented escape hatch for deployments that want a different
    slot count than the admission ceiling."""
    limits = ResourceLimits(max_concurrent_requests=6)
    supervisor = Supervisor(process_runner=fake_process_runner, resource_limits=limits)
    model = _resolved_model("a" * 64)

    args = supervisor.build_args(model, LoadConfig(parallel_slots=2), port=40000)

    idx = args.index("--parallel")
    assert args[idx + 1] == "2"


def test_load_config_cache_prompt_defaults_to_false() -> None:
    """Isolation-safe default: a caller that forgets to set this explicitly
    must never accidentally inherit a permissive value."""
    assert LoadConfig().cache_prompt is False


def test_load_config_parallel_slots_defaults_to_none() -> None:
    assert LoadConfig().parallel_slots is None


# --- Red-Council H1 (2026-07-29): serve-time provenance re-verification ---


def test_load_without_verifier_configured_behaves_exactly_as_before(fake_process_runner: FakeProcessRunner) -> None:
    supervisor = Supervisor(process_runner=fake_process_runner)
    model = _resolved_model("a" * 64)
    instance = supervisor.load(model, LoadConfig())
    assert supervisor.is_loaded("a" * 64)
    assert instance is not None


def test_load_calls_the_provenance_verifier_before_spawning(fake_process_runner: FakeProcessRunner) -> None:
    verifier = _FakeProvenanceVerifier()
    supervisor = Supervisor(process_runner=fake_process_runner, provenance_verifier=verifier)
    model = _resolved_model("a" * 64)

    supervisor.load(model, LoadConfig())

    assert len(verifier.calls) == 1
    assert verifier.calls[0].sha256 == "a" * 64


def test_load_fails_closed_and_never_spawns_when_verifier_raises(fake_process_runner: FakeProcessRunner) -> None:
    verifier = _FakeProvenanceVerifier(fail_on_call=1)
    supervisor = Supervisor(process_runner=fake_process_runner, provenance_verifier=verifier)
    model = _resolved_model("a" * 64)

    with pytest.raises(_FakeProvenanceVerifier.VerificationFailed):
        supervisor.load(model, LoadConfig())

    assert fake_process_runner.spawned == []  # never spawned — fail closed BEFORE the process runner is touched
    assert not supervisor.is_loaded("a" * 64)


def test_load_re_verifies_on_every_call_including_the_already_resident_fast_path(
    fake_process_runner: FakeProcessRunner,
) -> None:
    """H1's core claim: a model that becomes revoked/expired WHILE already
    resident must fail on the very next load() call, not keep serving until
    the process happens to restart. The verifier must fire on the fast-path
    hit too, not just on first spawn."""
    verifier = _FakeProvenanceVerifier(fail_on_call=2)
    supervisor = Supervisor(process_runner=fake_process_runner, provenance_verifier=verifier)
    model = _resolved_model("a" * 64)

    first = supervisor.load(model, LoadConfig())  # call 1 — verifier passes, spawns
    assert first is not None
    assert len(fake_process_runner.spawned) == 1

    with pytest.raises(_FakeProvenanceVerifier.VerificationFailed):
        supervisor.load(model, LoadConfig())  # call 2 — verifier fails on the ALREADY-RESIDENT fast path

    assert len(verifier.calls) == 2
    assert (
        len(fake_process_runner.spawned) == 1
    )  # still only ever spawned once — the failure is at the gate, not a respawn
