# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""GPU is a minimum system requirement — YSG-RISK-301.

Tiago 2026-09-15: "no point in using yashigani, or kuroshio in cpu, just does
not work" / "we support so many gpu types that supporting cpu usage is not
something i want to do, the system minimal requirements must include one gpu".

The defect this closes: `/healthz` computed

    gpu_engaged = (load_config.n_gpu_layers or 0) > 0

which is the value we PASSED to llama-server, never a value read back. So a
host with no GPU — or a binary built without the backend compiled in — ran on
CPU and reported `gpu_engaged: true, healthy`. Given CPU-only is unusable
rather than merely slow, that is a dead deployment showing green.

Two faults, same symptom, neither visible from the flag:
  1. host has no GPU
  2. binary has no GPU backend

`--list-devices` is the only device signal llama-server exposes; its HTTP API
carries none.
"""

from __future__ import annotations

import pytest

from pathlib import Path
from typing import Any

from kuroshio.models import Provenance, ProvenanceKind, ResolvedModel
from kuroshio.supervisor.process import DeviceProbe, is_accelerator
from kuroshio.supervisor.supervisor import LoadConfig, Supervisor, SupervisorError

from tests.conftest import FakeProcessRunner


def resolved_model(digest: str = "a" * 64) -> ResolvedModel:
    return ResolvedModel(
        sha256=digest,
        blob_path=Path(f"/blobs/{digest}.gguf"),
        metadata={"name": "m"},
        provenance=Provenance(kind=ProvenanceKind.LOCAL_FILE, origin="x", sha256=digest),
    )


def make_supervisor(*, device_probe: Any) -> Supervisor:
    return Supervisor(
        process_runner=FakeProcessRunner(),
        llama_server_binary="llama-server",
        device_probe=device_probe,
    )


class FakeProbe(DeviceProbe):
    def __init__(self, devices: list[str]) -> None:
        self.devices = devices
        self.calls = 0

    def list_devices(self, binary: str) -> list[str]:
        self.calls += 1
        return self.devices


# --- device classification, measured against real `--list-devices` output ---


@pytest.mark.parametrize("name", ["MTL0", "CUDA0", "ROCm0", "Vulkan0", "SYCL0", "CANN0"])
def test_accelerators_recognised(name: str) -> None:
    assert is_accelerator(name)


@pytest.mark.parametrize("name", ["BLAS", "CPU", "RPC0", ""])
def test_cpu_side_devices_are_not_accelerators(name: str) -> None:
    """BLAS is the crux. On an M4 `--list-devices` prints BOTH:

        MTL0: Apple M4 (16384 MiB, 16383 MiB free)
        BLAS: Accelerate

    Counting BLAS as an accelerator would let every CPU-only Mac pass the
    requirement, which is exactly the deployment we are refusing.
    """
    assert not is_accelerator(name)


# --- the requirement is enforced at load, before anything is spawned --------


def test_cpu_only_host_is_refused() -> None:
    probe = FakeProbe(["BLAS"])
    sup = make_supervisor(device_probe=probe)
    with pytest.raises(SupervisorError, match="minimum system requirement"):
        sup.load(resolved_model(), LoadConfig(n_gpu_layers=99))


def test_refusal_happens_before_any_spawn() -> None:
    """It must refuse rather than start and then report unhealthy — a process
    that is up is a process something will route traffic to."""
    probe = FakeProbe([])
    sup = make_supervisor(device_probe=probe)
    with pytest.raises(SupervisorError):
        sup.load(resolved_model(), LoadConfig(n_gpu_layers=99))
    assert sup._runner.spawned == []  # type: ignore[attr-defined,union-attr]


def test_unreadable_probe_refuses_rather_than_assuming_gpu() -> None:
    """"I could not tell" must never resolve to "GPU present"."""
    probe = FakeProbe([])  # SubprocessDeviceProbe returns [] on OSError too
    sup = make_supervisor(device_probe=probe)
    with pytest.raises(SupervisorError):
        sup.load(resolved_model(), LoadConfig(n_gpu_layers=99))


def test_accelerator_present_loads_normally() -> None:
    probe = FakeProbe(["MTL0", "BLAS"])
    sup = make_supervisor(device_probe=probe)
    inst = sup.load(resolved_model(), LoadConfig(n_gpu_layers=99))
    assert inst is not None


def test_gpu_is_required_by_default() -> None:
    """The default must be "required". A default of False would mean every
    caller that forgets the flag silently accepts a CPU deployment."""
    assert LoadConfig().expect_gpu is True


def test_probe_is_not_rerun_per_load() -> None:
    """Devices are a property of (binary, host); probing spawns a process, so
    doing it per load would add a subprocess to every model load."""
    probe = FakeProbe(["MTL0"])
    sup = make_supervisor(device_probe=probe)
    sup.load(resolved_model(), LoadConfig(n_gpu_layers=99))
    sup.load(resolved_model(digest="b" * 64), LoadConfig(n_gpu_layers=99))
    assert probe.calls == 1


# --- healthz reports the observed device, not the flag we passed -----------


def test_healthz_does_not_call_it_engaged_without_a_real_device() -> None:
    """The original defect, pinned directly: n_gpu_layers=99 on a CPU-only
    host must NOT read as gpu_engaged."""
    probe = FakeProbe(["MTL0"])
    sup = make_supervisor(device_probe=probe)
    sup.load(resolved_model(), LoadConfig(n_gpu_layers=99))

    probe.devices = ["BLAS"]  # device vanished / was never there
    sup._device_cache = None  # type: ignore[attr-defined]
    health = sup.healthz(resolved_model().sha256)
    assert health["gpu_engaged"] is False
    assert health["status"] == "unhealthy"


def test_healthz_surfaces_which_accelerators_were_seen() -> None:
    probe = FakeProbe(["MTL0", "BLAS"])
    sup = make_supervisor(device_probe=probe)
    sup.load(resolved_model(), LoadConfig(n_gpu_layers=99))
    assert sup.healthz(resolved_model().sha256)["accelerators"] == ["MTL0"]
