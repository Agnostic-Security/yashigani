# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Signed-catalog admission gate for network model sources (Hugging Face).

Red-council hardening (item #4): a network-sourced model's sha256 must come
from a COUNTER-SIGNED manifest entry, never be re-derived from the source at
pull time (re-deriving verifies the attacker's file against the attacker's
own hash — the exact council-review High finding this whole engine already
flags for HF pulls). Admission for network sources hard-requires a valid
signature; there is no free-text override / bypass flag. `provenance_tier`
is a field carried INSIDE the signed struct (so it cannot be forged or
tampered independently of the signature).

**Verify-side only.** This module holds a PUBLIC key and verifies
signatures. Signing, key generation, and key rotation/distribution are a
separate key-management component (Nico), NOT built here — the engine never
holds a private key.

If no `SignedCatalog` is configured for the Hugging Face adapter, admission
falls back to the v1-foundation "derive sha256 from the download, record
honestly" behaviour (see `adapters/huggingface.py`) — this is an explicit
pre-catalog dev-mode, not a silent downgrade: it is opt-in by simply not
wiring a catalog, and every caller that constructs the adapter directly sees
this documented in the adapter's own docstring.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class CatalogVerificationError(ValueError):
    """Raised when a catalog entry's signature does not verify, or no
    admitted entry exists for the requested (repo_id, revision, filename)."""


@dataclass(frozen=True)
class SignedCatalogEntry:
    """One counter-signed admission record for a network model pull.

    Attributes:
        repo_id: Hugging Face repo id (`namespace/name` or `name`).
        revision: pinned commit hash (never a floating branch).
        filename: the exact GGUF filename within the repo.
        sha256: the AUTHORITATIVE digest — used as `expected_sha256` for the
            download, never re-derived from what was actually downloaded.
        provenance_tier: e.g. `"vetted"` / `"community"` — carried INSIDE
            the signed payload so it cannot be edited independently of the
            signature.
        signature: raw ECDSA signature (DER-encoded) over `signed_payload()`.
        signer_key_id: opaque identifier for which signing key produced
            `signature` (key rotation bookkeeping; verification itself uses
            whichever public key the `CatalogVerifier` was constructed
            with — matching `signer_key_id` against an expected value is a
            deploy-time policy decision, not enforced by this dataclass).
    """

    repo_id: str
    revision: str
    filename: str
    sha256: str
    provenance_tier: str
    signature: bytes
    signer_key_id: str

    def __post_init__(self) -> None:
        if not _SHA256_HEX.match(self.sha256.lower()):
            raise ValueError(f"catalog entry sha256 is not a 64-char hex digest: {self.sha256!r}")

    def signed_payload(self) -> bytes:
        """Canonical bytes that were signed: deterministic field order via
        JSON with sorted keys and no whitespace ambiguity. Only the fields
        that are part of the admission covenant are included — the
        signature and signer_key_id themselves are excluded (they are not
        signed OVER, they carry the signature)."""
        payload = {
            "repo_id": self.repo_id,
            "revision": self.revision,
            "filename": self.filename,
            "sha256": self.sha256.lower(),
            "provenance_tier": self.provenance_tier,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class CatalogVerifier:
    """Verify-side ECDSA signature check. Holds a PUBLIC key only.

    Signing (the private-key half) is Nico's key-management component —
    this class exists so THIS package can independently verify without ever
    holding, generating, or needing access to a private key.
    """

    def __init__(self, public_key: ec.EllipticCurvePublicKey) -> None:
        self._public_key = public_key

    def verify(self, entry: SignedCatalogEntry) -> None:
        try:
            self._public_key.verify(entry.signature, entry.signed_payload(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise CatalogVerificationError(
                f"signature verification failed for {entry.repo_id}@{entry.revision}/{entry.filename}"
            ) from exc


class SignedCatalog:
    """Lookup table of verified admission entries, keyed by (repo_id, revision, filename).

    Every entry is verified at `load_entries()` time — an entry whose
    signature does not verify is refused (fail closed) and never enters the
    lookup table; there is no "load anyway" override.
    """

    def __init__(self, verifier: CatalogVerifier) -> None:
        self._verifier = verifier
        self._entries: dict[tuple[str, str, str], SignedCatalogEntry] = {}

    def load_entries(self, entries: Iterable[SignedCatalogEntry]) -> None:
        """Verify every entry FIRST, then admit them all — atomically per
        batch. A single badly-signed entry anywhere in the batch refuses the
        WHOLE batch (fail closed), never a partial admit of the entries that
        happened to verify before the bad one was reached."""
        entries = list(entries)
        for entry in entries:
            self._verifier.verify(entry)  # fail closed: refuse the whole batch on any bad signature
        for entry in entries:
            key = (entry.repo_id, entry.revision, entry.filename)
            self._entries[key] = entry

    def require(self, repo_id: str, revision: str, filename: str) -> SignedCatalogEntry:
        """Look up an admitted entry. Raises `CatalogVerificationError` if
        absent — there is no free-text override / bypass path; a caller
        that wants to pull a model not yet in the catalog must get it
        counter-signed and added, not skip this check."""
        entry = self._entries.get((repo_id, revision, filename))
        if entry is None:
            raise CatalogVerificationError(
                f"no signed catalog entry for {repo_id}@{revision}/{filename} — network pulls "
                "require an admin-provisioned, counter-signed manifest entry; there is no override"
            )
        return entry


__all__ = ["SignedCatalogEntry", "CatalogVerifier", "SignedCatalog", "CatalogVerificationError"]
