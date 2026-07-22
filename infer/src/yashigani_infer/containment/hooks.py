# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""No-op containment seam points.

Each hook's type alias documents WHERE a future containment mechanism would
attach and WHAT shape it would need to conform to — nothing more. The
default implementations are pure identity passthroughs; wiring an actual
mechanism behind these hooks is deliberately out of scope for this v1
commodity foundation (see package docstring in `__init__.py`).
"""

from __future__ import annotations

from typing import Any, Callable

# Seam: called with a shim-translated response chunk (e.g. one ollama NDJSON
# chunk dict) before it is written to the wire. A future output-path DLP /
# secret-exfil scanner (council review §1a layer 2, R2 §A P0 gate) would
# attach here. v1: identity passthrough.
OutputInspectionHook = Callable[[dict[str, Any]], dict[str, Any]]


def noop_output_inspection_hook(chunk: dict[str, Any]) -> dict[str, Any]:
    """Identity passthrough. No inspection, no redaction, no blocking."""
    return chunk


# Seam: called once when a model is first resolved into the blob store,
# before it is ever loaded/served. A future quarantine->canary->promote gate
# (council review §1a layer 4) would attach here to decide whether the
# model may serve traffic yet. v1: always returns True (unconditionally
# promoted; no quarantine tier exists in this commodity foundation).
OnboardingGateHook = Callable[[str], bool]  # arg: model sha256; return: "may serve"


def noop_onboarding_gate_hook(sha256: str) -> bool:
    """Always allows — no quarantine/canary mechanism exists in this package."""
    return True


# Seam: called before a source-adapter's `resolve()` step is allowed to
# parse an untrusted file's content (GGUF header, safetensors header, or —
# in a hostile-input worst case — bytes that turn out not to be either). A
# future SANDBOXED first-parse jail (seccomp/namespace-isolated parser
# process, deployment-layer mechanism, Captain/Su territory — NOT built in
# this Python package) would attach here to run the first byte-level parse
# out-of-process. v1: identity passthrough — this package's own defensive,
# bounds-checked pure-Python parsers (gguf/header.py, adapters/convert.py's
# guard_safetensors_only) are the ONLY parse-time protection that exists
# today; there is no process-isolation jail around them yet.
FirstParseJailHook = Callable[[bytes], bytes]  # arg/return: the raw header bytes about to be parsed


def noop_first_parse_jail_hook(header_bytes: bytes) -> bytes:
    """Identity passthrough. No sandboxing, no process isolation."""
    return header_bytes


# Seam: called before a model is scheduled onto its own isolated runtime
# unit (a dedicated container/pod per model, council review Medium finding
# "classifier-vs-user-model process isolation" — Laura F7, Captain+Tom).
# A future per-model container/pod ORCHESTRATOR would attach here. v1:
# identity passthrough — the supervisor spawns every `llama-server` process
# in the SAME runtime scope it itself runs in (no per-model container/pod
# boundary). **Deliberately NOT building this myself**: granting this
# process a Docker socket or Kubernetes RBAC to spawn per-model
# containers/pods is exactly the kind of naive orchestration-privilege grab
# that is itself a CRITICAL finding class (unscoped `docker.sock` access =
# host-root; overbroad K8s RBAC = cluster-wide blast radius) — that
# capability, if and when it is built, belongs to Captain's deployment
# layer with its own least-privilege design, not bolted on here.
ContainerOrchestrationHook = Callable[[str], None]  # arg: model sha256 about to be scheduled


def noop_container_orchestration_hook(sha256: str) -> None:
    """No-op. This package never requests docker.sock / K8s RBAC access."""
    return None


__all__ = [
    "OutputInspectionHook",
    "OnboardingGateHook",
    "FirstParseJailHook",
    "ContainerOrchestrationHook",
    "noop_output_inspection_hook",
    "noop_onboarding_gate_hook",
    "noop_first_parse_jail_hook",
    "noop_container_orchestration_hook",
]
