# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Model-licence classification + non-blocking import alert (Tiago 2026-07-31).

Policy: only models whose licence is FREE for commercial use may be bundled,
defaulted, or catalogued by Yashigani — but a client may import ANY model at
their own risk via the universal-import adapters. When an imported model's
licence is not a recognised commercial-free licence (or declares none at
all), the import proceeds and the engine emits a non-blocking licence ALERT
("this model may require a licence"). We warn, we never block.

The verdict here is deliberately conservative: the allowlist below contains
only licences that are unambiguously free for commercial use. Anything not
recognised — including family-specific licences (Llama community licence,
Gemma licence, Qwen License), research-only licences, and every unknown
string — gets the alert. Licences are non-uniform even within a model
family (e.g. Qwen2.5 7B/1.5B are Apache-2.0 but 3B/72B are Qwen License),
so classification always runs on the individual model's declared licence,
never on family reputation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

# Normalized licence identifiers that are unambiguously free for commercial
# use. Deliberately short: expanding it requires positive verification of
# the licence text, not vibes. Note the ABSENCE of: openrail* (use
# restrictions), llama* (community licence), gemma (Gemma licence), qwen*
# (Qwen License), cc-by-nc* (non-commercial), "other".
KNOWN_COMMERCIAL_FREE_LICENCES = frozenset(
    {
        "apache-2.0",
        "mit",
        "bsd-2-clause",
        "bsd-3-clause",
        "isc",
        "mpl-2.0",
        "unlicense",
        "cc0-1.0",
        "zlib",
        "cc-by-4.0",
    }
)

# Common spellings -> canonical id, applied AFTER structural normalization
# (lowercase, whitespace/underscores -> hyphens, "license"/"licence" tokens
# dropped). Structural normalization already maps e.g. "Apache License 2.0"
# and "apache_2_0" onto "apache-2.0"; this table catches the remaining
# well-known shorthands only.
_ALIASES: dict[str, str] = {
    "apache2": "apache-2.0",
    "apache-2": "apache-2.0",
    "apache2.0": "apache-2.0",
    "apache-2-0": "apache-2.0",
    "cc0": "cc0-1.0",
    "bsd-2": "bsd-2-clause",
    "bsd-3": "bsd-3-clause",
    "mpl2": "mpl-2.0",
    "mpl-2": "mpl-2.0",
}

_SEPARATOR_RUN = re.compile(r"[\s_/]+")
_HYPHEN_RUN = re.compile(r"-{2,}")


def normalize_licence(raw: str) -> str:
    """Normalize a declared licence string to a canonical lowercase id.

    "Apache License 2.0" / "apache_2_0" / "MIT License" all normalize onto
    their SPDX-style ids. Unknown strings normalize structurally but stay
    unknown — normalization never invents commercial-freeness.
    """
    value = _SEPARATOR_RUN.sub("-", raw.strip().lower())
    # Drop standalone "license"/"licence" tokens ("mit-license" -> "mit",
    # "apache-license-2.0" -> "apache-2.0").
    parts = [p for p in value.split("-") if p not in ("license", "licence")]
    value = _HYPHEN_RUN.sub("-", "-".join(parts)).strip("-")
    return _ALIASES.get(value, value)


@dataclass(frozen=True)
class LicenceVerdict:
    """Classification of one model's declared licence at import time.

    Attributes:
        raw: the licence string as declared by the model (GGUF
            ``general.license``), or None when nothing was declared.
        normalized: canonical id after :func:`normalize_licence`, or None.
        commercial_free: True only when `normalized` is on the
            recognised-commercial-free allowlist.
        alert: the non-blocking alert text to surface to the importer, or
            None when no alert is warranted. The alert never blocks the
            import — policy is warn-not-block for client-imported models.
    """

    raw: str | None
    normalized: str | None
    commercial_free: bool
    alert: str | None


def assess_licence(raw: str | None) -> LicenceVerdict:
    """Classify a declared licence; produce the non-blocking alert if warranted."""
    if raw is None or not raw.strip():
        return LicenceVerdict(
            raw=raw,
            normalized=None,
            commercial_free=False,
            alert=(
                "no licence declared in the model's metadata — this model may require "
                "a licence for commercial use; imported at your own risk"
            ),
        )
    normalized = normalize_licence(raw)
    if normalized in KNOWN_COMMERCIAL_FREE_LICENCES:
        return LicenceVerdict(raw=raw, normalized=normalized, commercial_free=True, alert=None)
    return LicenceVerdict(
        raw=raw,
        normalized=normalized,
        commercial_free=False,
        alert=(
            f"licence {raw!r} is not a recognised commercial-free licence — this model "
            "may require a licence for commercial use; imported at your own risk"
        ),
    )


def licence_verdict_for_model_metadata(metadata: Mapping[str, Any]) -> LicenceVerdict:
    """Assess the licence recorded in a ResolvedModel's normalized metadata.

    Adapters record the GGUF-declared licence id under the ``license`` key
    (ollama-shim spelling — `/api/show` already surfaces that key); absent
    or blank means the model declared nothing.
    """
    value = metadata.get("license")
    return assess_licence(value if isinstance(value, str) else None)


__all__ = [
    "KNOWN_COMMERCIAL_FREE_LICENCES",
    "LicenceVerdict",
    "assess_licence",
    "licence_verdict_for_model_metadata",
    "normalize_licence",
]
