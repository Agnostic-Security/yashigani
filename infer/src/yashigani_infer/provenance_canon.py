# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Canonical-JSON encoding shared by every counter-signed manifest format in
this package.

Both `catalog.py` (`SignedCatalogEntry` — network-pull admission manifests)
and `convert_provenance.py` (`ConvertedManifestEntry` — converted-GGUF
provenance manifests) sign over the bytes this module produces. Using one
shared canonicalization routine for both formats means a signature-format
bug fixed here is fixed everywhere at once, rather than needing the same fix
applied twice in step.

**JCS-compatible subset (RFC 8785):** sorted object keys, no insignificant
whitespace, UTF-8 (via `ensure_ascii=True`, which produces a pure-ASCII byte
stream — a stricter, unambiguous subset of JCS's UTF-8 requirement). This
module deliberately restricts payload values to `str` / `int` / `bool` /
`None` and REFUSES `float` — RFC 8785's ECMAScript-number serialization
rules are exactly the kind of subtle cross-implementation/cross-language
ambiguity a signature format must never depend on, and nothing in either
manifest format needs a float (every numeric field here is an integer count
of seconds, never a fraction). Nested containers are refused too: every
payload signed in this codebase is a flat field->value mapping — nesting
would only reintroduce the same canonicalization questions one level down.
"""

from __future__ import annotations

import json
from typing import Mapping

_ALLOWED_SCALAR_TYPES = (str, int, bool)


class NonCanonicalPayloadError(TypeError):
    """Raised when a payload contains a value that canonical-JSON signing refuses
    (float, nested dict/list, or any other type outside the str/int/bool/None set)."""


def canonical_json_bytes(payload: Mapping[str, object]) -> bytes:
    """Encode `payload` as canonical JSON bytes suitable for signing/verifying.

    Deterministic across processes/machines for the same logical payload:
    sorted keys, minimal separators, ASCII-only output. Call this with the
    SAME field set on both the mint side (sign) and the verify side (verify)
    — any drift in which fields are included changes the signed bytes and
    the signature will not verify, which is the point (fail closed, not a
    partial match).
    """
    _reject_non_canonical_values(payload)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _reject_non_canonical_values(payload: Mapping[str, object]) -> None:
    for key, value in payload.items():
        if isinstance(value, bool):
            continue  # bool is an int subclass in Python; explicit allow, checked before the float test below
        if isinstance(value, float):
            raise NonCanonicalPayloadError(
                f"field {key!r} is a float ({value!r}) — floats are refused in canonical manifest "
                "payloads (RFC 8785 ECMAScript-number serialization is ambiguous across "
                "implementations); use an int or a str"
            )
        if value is None:
            continue
        if not isinstance(value, _ALLOWED_SCALAR_TYPES):
            raise NonCanonicalPayloadError(
                f"field {key!r} has non-canonical type {type(value).__name__} — only str/int/bool/None "
                "are permitted in a signed manifest payload"
            )


__all__ = ["canonical_json_bytes", "NonCanonicalPayloadError"]
