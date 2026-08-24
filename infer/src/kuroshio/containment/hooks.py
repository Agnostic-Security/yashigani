# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Containment seam points.

Each hook's type alias documents WHERE a future containment mechanism would
attach and WHAT shape it would need to conform to. Most of these are pure
identity passthroughs; wiring a real IP-gated mechanism behind them is
deliberately out of scope for this v1 commodity foundation (see package
docstring in `__init__.py`).

`FirstParseJailHook` is the one exception (Iris integration-seam audit,
2026-07-22, finding F3): the hook itself is not a no-op — it is wired to
every GGUF-parsing `SourceAdapter.resolve()` call site
(`adapters/base.py::SourceAdapter._first_parse_gguf_header`) and, by
default, runs this package's own defensive, bounds-checked pure-Python GGUF
header parser (`gguf/header.py`) as the v1 "jail." There is still no
process-isolation boundary (seccomp/namespace/`network=none` container)
around that parse — that remains Captain/Su's deployment-layer territory
(C3, `ContainerOrchestrationHook` below, shipped-disabled) — but the seam
is now CONNECTED rather than orphaned. See `select_first_parse_jail_hook`'s
docstring for the v1-vs-orchestrated split.
"""

from __future__ import annotations

from typing import Any, Callable

from kuroshio.gguf.header import parse_gguf_header

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
    """Identity passthrough. No sandboxing, no process isolation, NO validation
    at all. Kept for tests / callers that explicitly want "no guard whatsoever"
    — no production call site should use this; adapters default to
    `default_first_parse_jail_hook` instead (see `SourceAdapter.__init__`)."""
    return header_bytes


def default_first_parse_jail_hook(header_bytes: bytes) -> bytes:
    """v1 first-parse jail — the only containment that exists today for the
    first untrusted-file parse.

    Runs this package's own bounded, pure-Python GGUF header parser
    (`gguf/header.py`) against `header_bytes` in-process — i.e. in the SAME
    runtime scope as the caller, with no seccomp/namespace/`network=none`
    isolation. That process-isolation boundary is what the compose
    `invoke-first-parse-jail` service / Helm `job-first-parse-jail.yaml`
    exist to eventually provide once container-per-model orchestration
    privilege (C3, `ContainerOrchestrationHook`) is actually built —
    deliberately NOT this Python package's job (see that hook's docstring).

    Fails closed: a header that does not parse as a structurally valid GGUF
    raises `GGUFParseError` (the same error type `gguf/header.py` already
    raises directly) rather than silently admitting a malformed/hostile
    file. On success, returns `header_bytes` unchanged — an intentional
    identity-shaped return so a caller's own subsequent
    `parse_gguf_header()` call (for real metadata extraction) is guaranteed
    to succeed against the exact bytes this hook already validated.
    """
    parse_gguf_header(header_bytes)
    return header_bytes


def unimplemented_orchestrated_first_parse_jail_hook(header_bytes: bytes) -> bytes:
    """Placeholder for the v2 out-of-process jail-container hook.

    C3 (`ContainerOrchestrationHook`, shipped-disabled) is Captain/Su's
    deployment-layer territory — granting this Python control plane a
    Docker socket or Kubernetes RBAC to spawn per-model
    containers/pods is itself a CRITICAL finding class (see
    `ContainerOrchestrationHook`'s docstring below) and is deliberately NOT
    built in this package. If a deploy ever flips an orchestration-enabled
    switch before the real out-of-process jail lands, this stub raises
    rather than silently downgrading to the weaker v1 in-process guard —
    a caller that believes it is getting jailed process isolation must
    never silently get less than it asked for.
    """
    raise NotImplementedError(
        "container-per-model first-parse jail orchestration (C3) is not yet implemented in "
        "this Python package — it is Captain/Su's deployment-layer territory. "
        "docker-compose.kuroshio.yml's `invoke-first-parse-jail` service and Helm's "
        "job-first-parse-jail.yaml are shape references only (see infer/deploy/README.md's "
        "'C3 threat model' section); disable orchestration mode or wait for the real "
        "implementation before enabling it."
    )


def select_first_parse_jail_hook(*, container_orchestration_enabled: bool = False) -> FirstParseJailHook:
    """Choose the v1 in-process guard (default posture, always true today) or
    the not-yet-built orchestrated out-of-process jail.

    No caller in this package sets `container_orchestration_enabled=True`
    today — `entrypoint.py` does not wire any source adapter yet (see its
    module docstring), and C3 orchestration is shipped-disabled at the
    deploy layer (`profiles: ["orchestration-v2"]` / `supervisorRbac.enabled:
    false`). This function exists so the switch point is explicit and
    testable ahead of that follow-up increment, not so it is reachable yet.
    """
    if container_orchestration_enabled:
        return unimplemented_orchestrated_first_parse_jail_hook
    return default_first_parse_jail_hook


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
    "default_first_parse_jail_hook",
    "unimplemented_orchestrated_first_parse_jail_hook",
    "select_first_parse_jail_hook",
    "noop_container_orchestration_hook",
]
