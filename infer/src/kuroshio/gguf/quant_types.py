# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Public, stable GGUF/llama.cpp enum tables used to derive human-readable
quantization names for /api/tags synthesis.

These tables reflect the published llama.cpp `enum llama_ftype` (general
file-type — the value stored under the `general.file_type` GGUF metadata
key) and `enum ggml_type` (per-tensor storage type). Both are stable public
enums, not implementation details of this package. New quantization schemes
land upstream over time; unknown values fall back to a clearly-labelled
"UNKNOWN(n)" string rather than raising, so a newer model family never hard-
breaks metadata synthesis (Ava's "coverage honesty" principle applied to
metadata, not just conversion).
"""

from __future__ import annotations

# enum llama_ftype (general.file_type GGUF metadata value -> ollama-style name).
LLAMA_FTYPE_NAMES: dict[int, str] = {
    0: "F32",
    1: "F16",
    2: "Q4_0",
    3: "Q4_1",
    7: "Q8_0",
    8: "Q5_0",
    9: "Q5_1",
    10: "Q2_K",
    11: "Q3_K_S",
    12: "Q3_K_M",
    13: "Q3_K_L",
    14: "Q4_K_S",
    15: "Q4_K_M",
    16: "Q5_K_S",
    17: "Q5_K_M",
    18: "Q6_K",
    19: "IQ2_XXS",
    20: "IQ2_XS",
    21: "Q2_K_S",
    22: "IQ3_XS",
    23: "IQ3_XXS",
    24: "IQ1_S",
    25: "IQ4_NL",
    26: "IQ3_S",
    27: "IQ3_M",
    28: "IQ2_S",
    29: "IQ2_M",
    30: "IQ4_XS",
    31: "IQ1_M",
    32: "BF16",
    33: "TQ1_0",
    34: "TQ2_0",
    1024: "GUESSED",
}

# enum ggml_type (per-tensor storage type -> ollama-style name). Used as a
# fallback when general.file_type is absent: we take the majority tensor
# type across the tensor-info table.
GGML_TYPE_NAMES: dict[int, str] = {
    0: "F32",
    1: "F16",
    2: "Q4_0",
    3: "Q4_1",
    6: "Q5_0",
    7: "Q5_1",
    8: "Q8_0",
    9: "Q8_1",
    10: "Q2_K",
    11: "Q3_K",
    12: "Q4_K",
    13: "Q5_K",
    14: "Q6_K",
    15: "Q8_K",
    16: "IQ2_XXS",
    17: "IQ2_XS",
    18: "IQ3_XXS",
    19: "IQ1_S",
    20: "IQ4_NL",
    21: "IQ3_S",
    22: "IQ2_S",
    23: "IQ4_XS",
    24: "I8",
    25: "I16",
    26: "I32",
    27: "I64",
    28: "F64",
    29: "IQ1_M",
    30: "BF16",
}


def ftype_name(value: int | None) -> str:
    if value is None:
        return "unknown"
    return LLAMA_FTYPE_NAMES.get(value, f"UNKNOWN({value})")


def ggml_type_name(value: int) -> str:
    return GGML_TYPE_NAMES.get(value, f"UNKNOWN({value})")


__all__ = ["LLAMA_FTYPE_NAMES", "GGML_TYPE_NAMES", "ftype_name", "ggml_type_name"]
