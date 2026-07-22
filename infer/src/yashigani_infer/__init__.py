# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Yashigani first-party inference-engine control plane (commodity layer).

This package is a thin, self-contained control plane over ``llama-server``
(llama.cpp, MIT) running GGUF models. It is COMMODITY-ONLY: it contains no
containment/moat mechanism (output-path DLP, quarantine/canary, digest
revocation, per-model-identity OPA, behavioral baselining). Those are
IP-gated and land later, in a separate package, wired through the seam
points in :mod:`yashigani_infer.containment`.

Design references (AgnosticSecurity ops repo, Products/Yashigani/):
  - inference-engine-design-20260714.md (v1 scope)
  - inference-engine-council-review-20260714.md (source-adapter table §3a,
    convert-to-GGUF security gates §3b)
  - inference-engine-platform-requirements-20260722.md (per-runtime matrix)

Self-contained: this package does not import from ``yashigani`` (the 5.0
gateway tree). It has no dependency on the running Yashigani stack.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
