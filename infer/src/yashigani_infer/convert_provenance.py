# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Converted-GGUF provenance chain — verify-side + measurement helpers for
safetensors -> GGUF conversions.

Nico's provenance red-team (2026-07-22, `nico-infer-engine-provenance-
redteam-20260722.md`, finding #4): the design's §3b converted-GGUF
provenance record is reconstructable-on-paper but forgeable in practice
unless two things hold:

  1. **The source digest must be MEASURED by the convert pipeline itself**,
     on the actual bytes fed to `convert_hf_to_gguf.py`, at convert time —
     never accepted as an operator/adapter-asserted string. Otherwise an
     attacker who controls what is actually fed to the converter can write
     a benign source digest into the record while converting different
     (poisoned) bytes: a clean provenance-laundering vector. See
     `measure_conversion_tuple`.

  2. **The whole tuple is signed as ONE unit** —
     `sign(source_sha256 ‖ convert_tool_commit ‖ quant ‖ output_sha256)` —
     never written as independently-editable sibling metadata next to an
     independently-computed output hash. See `ConvertedManifestEntry`.

Two further requirements from the same finding are enforced here:

  - **Pin the convert tool's exact commit, never a release tag** — same
    discipline as the HF-pull revision pin elsewhere in this engine
    (`_CONVERT_TOOL_COMMIT_RE` below mirrors `catalog._REVISION_RE`).
  - **TOCTOU on the write path** — `verify_converted_manifest` re-measures
    the output file's digest from the bytes AT THE PATH THE SUPERVISOR IS
    ABOUT TO LOAD, rather than trusting a caller-supplied "I already
    measured it" string. This closes the "signer hashed bytes that are no
    longer the bytes on disk" window the finding describes; combined with
    the existing verify-then-atomic-rename discipline in the blob store,
    there is no gap between "convert job produced bytes" and "the bytes
    that get loaded."

This module is the verify-side (and shared measurement-helper) counterpart
to `catalog.py`'s `SignedCatalogEntry` for network-pulled models;
`ConvertedManifestEntry` is the equivalent signed format for LOCALLY-
CONVERTED artifacts. Mint-side signing (the private-key half) lives in
`scripts/manifest_signer.py` — Yashigani signing infra only, never imported
by this runtime package. `provenance_tier` for every entry minted here is
expected to be `"converted-derived"` (red-team finding #5): a converted
artifact is honestly a step further removed from the original network
provenance than a directly counter-signed HF pull, and that distinction is
signed INTO the record, not left to a display-layer label.

The actual conversion invocation (`convert_hf_to_gguf.py` + `llama-
quantize`) remains a v2 stub in `adapters/convert.py` — this module defines
the provenance contract that invocation MUST satisfy once it is wired in,
and is fully unit-testable today against fixture files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from yashigani_infer.blobstore.store import sha256_file
from yashigani_infer.catalog import RevocationSource, StaticRevocationSource
from yashigani_infer.provenance_canon import canonical_json_bytes

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

# Exact commit, never a release tag — a "tool version" string does not
# distinguish two builds of the same tag with different local patches
# (finding #4, third bullet).
_CONVERT_TOOL_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")

_QUANT_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")

# Same no-eternal-trust ceiling as catalog.py, applied to converted-GGUF
# manifests for consistency across both signed formats.
_MAX_TRUST_AGE_CEILING_SECONDS = 180 * 24 * 3600


class ConvertedManifestVerificationError(ValueError):
    """Raised when a converted-GGUF manifest's signature does not verify,
    its embedded output digest does not match the bytes on disk, it has
    exceeded its max trust age, or it is on the deny-list."""


def _parse_issued_at(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"issued_at {value!r} is not a valid ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"issued_at {value!r} must be timezone-aware (e.g. end in 'Z' or '+00:00')")
    return parsed


def measure_source_digest(path: Path) -> str:
    """Measure a file's sha256 from its actual bytes on disk.

    Used for BOTH the convert pipeline's source-file digest and its
    output-file digest (see `measure_conversion_tuple` and
    `verify_converted_manifest`) — the same measuring function on both
    sides of the conversion is the point: neither digest is ever an
    operator-asserted string, both come from actually reading the bytes.
    """
    return sha256_file(path)


@dataclass(frozen=True)
class ConversionMeasurement:
    """The UNSIGNED result of measuring one convert-job's inputs/outputs.

    Produced by `measure_conversion_tuple` — this is deliberately a plain
    dataclass with no signature; it is the input to
    `scripts/manifest_signer.py:ConvertedManifestSigner.mint()`, which signs
    it into a `ConvertedManifestEntry`. Keeping the unsigned measurement
    separate from the signed entry makes explicit that measurement (this
    class) and attestation (the signature) are two different steps that
    must both happen inside the same ephemeral convert job, before teardown.
    """

    source_sha256: str
    convert_tool_commit: str
    quant: str
    output_sha256: str


def measure_conversion_tuple(
    source_path: Path,
    output_path: Path,
    *,
    convert_tool_commit: str,
    quant: str,
) -> ConversionMeasurement:
    """Measure BOTH digests from the actual bytes on disk, at the point the
    convert job produced them.

    Call this INSIDE the same ephemeral job that ran the conversion,
    BEFORE the job tears down (finding #4's TOCTOU requirement) — never
    accept either digest as a caller-supplied string, and never measure the
    output from a blob-store path reached after the job has already
    exited (that reopens exactly the substitution window the finding
    describes).
    """
    if not _CONVERT_TOOL_COMMIT_RE.match(convert_tool_commit):
        raise ValueError(
            f"convert_tool_commit {convert_tool_commit!r} is not a pinned commit hash (7-40 hex chars) — "
            "a release tag or branch name is refused; pin the exact commit"
        )
    if not _QUANT_RE.match(quant):
        raise ValueError(f"quant {quant!r} failed the allowlist guard")
    return ConversionMeasurement(
        source_sha256=measure_source_digest(source_path),
        convert_tool_commit=convert_tool_commit,
        quant=quant,
        output_sha256=measure_source_digest(output_path),
    )


@dataclass(frozen=True)
class ConvertedManifestEntry:
    """Signed provenance record for one safetensors -> GGUF conversion.

    The whole tuple is signed as ONE unit (finding #4) — `source_sha256`,
    `convert_tool_commit`, `quant`, and `output_sha256` are all inside
    `signed_payload()`; none of them is editable independently of the
    others without invalidating the signature.

    Attributes:
        source_sha256: sha256 of the actual safetensors bytes fed to the
            converter, MEASURED by the convert pipeline itself (never an
            operator/adapter-asserted string — see `measure_source_digest`).
        convert_tool_commit: exact git commit hash of the convert tool
            (`convert_hf_to_gguf.py` + `llama-quantize`) used, never a
            release tag.
        quant: quantization params used for this conversion (e.g. `"Q4_K_M"`).
        output_sha256: sha256 of the produced GGUF bytes, measured the same
            way as `source_sha256`.
        provenance_tier: expected to be `"converted-derived"` for every
            entry minted here (finding #5) — carried inside the signed
            payload, not a separately-editable label.
        issued_at: ISO 8601 UTC timestamp this manifest was minted.
        max_trust_age_seconds: maximum age before this manifest must be
            refreshed; enforced at every `verify_converted_manifest` call.
        signature: raw ECDSA signature (DER-encoded) over `signed_payload()`.
        signer_key_id: opaque identifier for which signing key produced
            `signature` (rotation bookkeeping only, not itself signed over).
    """

    source_sha256: str
    convert_tool_commit: str
    quant: str
    output_sha256: str
    provenance_tier: str
    issued_at: str
    max_trust_age_seconds: int
    signature: bytes
    signer_key_id: str

    def __post_init__(self) -> None:
        if not _SHA256_HEX.match(self.source_sha256.lower()):
            raise ValueError(f"source_sha256 is not a 64-char hex digest: {self.source_sha256!r}")
        if not _SHA256_HEX.match(self.output_sha256.lower()):
            raise ValueError(f"output_sha256 is not a 64-char hex digest: {self.output_sha256!r}")
        if not _CONVERT_TOOL_COMMIT_RE.match(self.convert_tool_commit):
            raise ValueError(
                f"convert_tool_commit {self.convert_tool_commit!r} is not a pinned commit hash "
                "(7-40 hex chars) — a release tag or branch name is refused"
            )
        if not _QUANT_RE.match(self.quant):
            raise ValueError(f"quant {self.quant!r} failed the allowlist guard")
        _parse_issued_at(self.issued_at)
        if self.max_trust_age_seconds <= 0:
            raise ValueError(
                f"max_trust_age_seconds must be positive, got {self.max_trust_age_seconds!r} — "
                "there is no 'disable TTL' value"
            )
        if self.max_trust_age_seconds > _MAX_TRUST_AGE_CEILING_SECONDS:
            raise ValueError(
                f"max_trust_age_seconds={self.max_trust_age_seconds} exceeds the "
                f"{_MAX_TRUST_AGE_CEILING_SECONDS}s ceiling — no eternal-trust manifests"
            )

    def signed_payload(self) -> bytes:
        payload = {
            "source_sha256": self.source_sha256.lower(),
            "convert_tool_commit": self.convert_tool_commit,
            "quant": self.quant,
            "output_sha256": self.output_sha256.lower(),
            "provenance_tier": self.provenance_tier,
            "issued_at": self.issued_at,
            "max_trust_age_seconds": self.max_trust_age_seconds,
        }
        return canonical_json_bytes(payload)

    def is_expired(self, now: datetime | None = None) -> bool:
        moment = now if now is not None else datetime.now(timezone.utc)
        issued = _parse_issued_at(self.issued_at)
        age_seconds = (moment - issued).total_seconds()
        return age_seconds > self.max_trust_age_seconds

    def to_json_dict(self) -> dict[str, object]:
        """On-disk manifest-file representation — same shape convention as
        `catalog.SignedCatalogEntry.to_json_dict`."""
        import base64

        return {
            "source_sha256": self.source_sha256,
            "convert_tool_commit": self.convert_tool_commit,
            "quant": self.quant,
            "output_sha256": self.output_sha256,
            "provenance_tier": self.provenance_tier,
            "issued_at": self.issued_at,
            "max_trust_age_seconds": self.max_trust_age_seconds,
            "signer_key_id": self.signer_key_id,
            "signature": base64.b64encode(self.signature).decode("ascii"),
        }

    @classmethod
    def from_json_dict(cls, data: dict[str, object]) -> "ConvertedManifestEntry":
        """Inverse of `to_json_dict`. Does NOT verify the signature — callers
        must run it through a `ConvertedManifestVerifier` (or
        `verify_converted_manifest`) before trusting it."""
        import base64

        fields = dict(data)
        signature_b64 = fields.pop("signature")
        assert isinstance(signature_b64, str)
        return cls(signature=base64.b64decode(signature_b64), **fields)  # type: ignore[arg-type]


class ConvertedManifestVerifier:
    """Verify-side ECDSA signature check for `ConvertedManifestEntry`. Holds
    a PUBLIC key only — mirrors `catalog.CatalogVerifier` exactly, over a
    different signed payload shape."""

    def __init__(self, public_key: ec.EllipticCurvePublicKey) -> None:
        self._public_key = public_key

    def verify(self, entry: ConvertedManifestEntry) -> None:
        try:
            self._public_key.verify(entry.signature, entry.signed_payload(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise ConvertedManifestVerificationError(
                f"signature verification failed for converted-GGUF manifest "
                f"(convert_tool_commit={entry.convert_tool_commit!r})"
            ) from exc


def verify_converted_manifest(
    entry: ConvertedManifestEntry,
    *,
    output_path: Path,
    verifier: ConvertedManifestVerifier,
    revocation_source: RevocationSource | None = None,
    now: datetime | None = None,
) -> None:
    """The verify hook the (future, v2) convert-invocation call site MUST
    call before the supervisor loads `output_path`.

    Order of checks (fail closed on the first failure):
      1. Signature verification.
      2. Re-measure `output_path`'s sha256 from the bytes actually on disk
         RIGHT NOW and compare against `entry.output_sha256` — this is the
         TOCTOU close: we never trust a pre-computed digest string, we read
         the file that is about to be loaded (finding #4's write-path gap).
      3. TTL check (`is_expired`).
      4. Deny-list check via the pluggable `RevocationSource` (same
         interface as the HF-pull catalog's revocation hook, keyed here by
         `(convert_tool_commit, source_sha256, output_sha256)`).
    """
    verifier.verify(entry)

    live_digest = measure_source_digest(output_path)
    if live_digest.lower() != entry.output_sha256.lower():
        raise ConvertedManifestVerificationError(
            f"{output_path}: on-disk sha256 {live_digest!r} does not match the signed manifest's "
            f"output_sha256 {entry.output_sha256!r} — refusing to load (possible substitution "
            "between conversion and load)"
        )

    moment = now if now is not None else datetime.now(timezone.utc)
    if entry.is_expired(moment):
        raise ConvertedManifestVerificationError(
            f"converted-GGUF manifest for {output_path} exceeded its max trust age "
            f"(issued_at={entry.issued_at}, max_trust_age_seconds={entry.max_trust_age_seconds}) — "
            "mint a fresh signed manifest; there is no override"
        )

    source = revocation_source or StaticRevocationSource()
    denial_key = (entry.convert_tool_commit, entry.source_sha256, entry.output_sha256)
    if source.is_revoked(*denial_key):
        raise ConvertedManifestVerificationError(
            f"converted-GGUF manifest for {output_path} is on the deny-list — refusing"
        )


__all__ = [
    "ConversionMeasurement",
    "ConvertedManifestEntry",
    "ConvertedManifestVerifier",
    "ConvertedManifestVerificationError",
    "measure_source_digest",
    "measure_conversion_tuple",
    "verify_converted_manifest",
]
