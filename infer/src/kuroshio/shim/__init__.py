# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Ollama-native-API <-> llama-server translation shim.

Highest implementation-risk piece (council review): ollama's native
`/api/chat` streams bare NDJSON with a final `"done": true` line;
llama-server streams Server-Sent Events. This is a full re-framing, not a
pass-through. `/api/tags` `details.{family,parameter_size,
quantization_level,digest}` must be synthesized from the GGUF header — a
null field silently breaks existing consumers (44 `/api/chat`, 21
`/api/tags`, 16 `/api/generate` call sites, per the design doc's footprint
scan).
"""

from __future__ import annotations

__all__: list[str] = []
