# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Containment/moat seam points — NO-OP in this package, by design.

This package is COMMODITY-ONLY. It contains ZERO containment/moat
mechanism: no output-path DLP / secret-exfil scanning, no
quarantine->canary->promote onboarding gate, no digest-revocation/
kill-switch, no per-model-identity/argument-level OPA authz, no behavioral
baselining. Those are IP-gated (council review §1a — "the strongest
novelty in the design") and are built later, in a separate package.

The hooks below exist ONLY as clearly-named, empty attachment points so the
later containment package has an obvious, stable seam to wire into without
this control plane needing to change shape. Every hook here is an identity
passthrough — it does exactly nothing.
"""

from __future__ import annotations

from yashigani_infer.containment.hooks import (
    ContainerOrchestrationHook,
    FirstParseJailHook,
    OnboardingGateHook,
    OutputInspectionHook,
    noop_container_orchestration_hook,
    noop_first_parse_jail_hook,
    noop_onboarding_gate_hook,
    noop_output_inspection_hook,
)

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
