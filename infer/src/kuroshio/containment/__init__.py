# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Containment/moat seam points — mostly NO-OP in this package, by design.

This package is COMMODITY-ONLY. It contains ZERO containment/moat
mechanism: no output-path DLP / secret-exfil scanning, no
quarantine->canary->promote onboarding gate, no digest-revocation/
kill-switch, no per-model-identity/argument-level OPA authz, no behavioral
baselining. Those are IP-gated (council review §1a — "the strongest
novelty in the design") and are built later, in a separate package.

Most hooks below exist ONLY as clearly-named, empty attachment points so the
later containment package has an obvious, stable seam to wire into without
this control plane needing to change shape — every one of those is an
identity passthrough that does exactly nothing.

`FirstParseJailHook` is the exception (Iris integration-seam audit F3,
2026-07-22): it IS wired to every GGUF-parsing `SourceAdapter.resolve()`
call site, defaulting to `default_first_parse_jail_hook` (v1 in-process
bounded parse) rather than the identity `noop_first_parse_jail_hook`. See
`hooks.py`'s module docstring for the v1-vs-orchestrated split.
"""

from __future__ import annotations

from kuroshio.containment.hooks import (
    ContainerOrchestrationHook,
    FirstParseJailHook,
    OnboardingGateHook,
    OutputInspectionHook,
    default_first_parse_jail_hook,
    noop_container_orchestration_hook,
    noop_first_parse_jail_hook,
    noop_onboarding_gate_hook,
    noop_output_inspection_hook,
    select_first_parse_jail_hook,
    unimplemented_orchestrated_first_parse_jail_hook,
)

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
