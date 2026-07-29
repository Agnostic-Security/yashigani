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

**Nico provenance red-team (2026-07-22, `nico-infer-engine-provenance-
redteam-20260722.md`) hardening — findings #2, #3, #5:**
  - **Finding #3:** the manifest schema is exactly
    `(repo, revision_commit, lfs_object_id, filename, quant, sha256)`, all
    computed by Yashigani's ingestion at MINT time and frozen — the
    download-and-verify path is pure bytes-vs-embedded-hash comparison,
    never a live HF hash lookup. `revision` and `lfs_object_id` are
    structurally validated here (commit-hash / hex-digest shape) as a second,
    independent gate alongside the adapter's own allowlist checks.
  - **Finding #2:** a signature alone has no natural expiry. Every entry
    carries `issued_at` + `max_trust_age_seconds`; `SignedCatalog.require()`
    re-checks both the TTL and a pluggable `RevocationSource` on EVERY call
    (i.e. at pull time, not just once at `load_entries()` time) — a manifest
    admitted this morning that is later found tainted, or that simply ages
    out, stops being usable without needing to touch the cached entry.
  - **Finding #5:** `provenance_tier` remains a field INSIDE the signed
    payload (unchanged from the original design) — never a separately-
    editable catalog/UI annotation.

**Verify-side only.** This module holds a PUBLIC key and verifies
signatures. Signing (minting new entries) is a separate component —
`scripts/manifest_signer.py`, Yashigani signing infra only — and key
generation is `scripts/keygen_manifest.py`; neither is importable from this
runtime package. The engine never holds a private key.

If no `SignedCatalog` is configured for the Hugging Face adapter, admission
falls back to the v1-foundation "derive sha256 from the download, record
honestly" behaviour (see `adapters/huggingface.py`) — this is an explicit
pre-catalog dev-mode, not a silent downgrade: it is opt-in by simply not
wiring a catalog, and every caller that constructs the adapter directly sees
this documented in the adapter's own docstring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from yashigani_infer.provenance_canon import canonical_json_bytes

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

# Pinned-revision guard, mirrored from adapters/huggingface.py's own check:
# a git commit hash (short or full), never a floating branch name. Validated
# HERE too (not just at the adapter boundary) because the signed manifest
# itself is the authoritative record — a manifest that could be minted
# against a floating branch would reopen the exact class this format exists
# to close, regardless of what the adapter separately enforces.
_REVISION_RE = re.compile(r"^[0-9a-f]{7,40}$")

# Git-LFS object id: the pointer file's own `oid sha256:<hex>` value (minus
# the "sha256:" prefix, which callers strip before constructing the entry —
# same convention as the `sha256` field). This is the actual content-address
# guarantee for the large model bytes; the commit hash only secures the
# tree/pointer-file layer above it (red-team finding #3, second bullet).
_LFS_OBJECT_ID_RE = _SHA256_HEX

# Quant label, e.g. "Q4_K_M", "Q8_0", "F16" — matches the llama.cpp naming
# convention used elsewhere in this package (gguf/quant_types.py).
_QUANT_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")

# No eternal-trust window (red-team finding #2: "a signed manifest needs a
# short TTL"). 180 days is a generous ceiling for a commodity-engine mint
# cadence, not a target — mint-time tooling should set something far
# shorter in practice. A longer window is a deliberate code change to this
# constant, never a runtime config knob.
_MAX_TRUST_AGE_CEILING_SECONDS = 180 * 24 * 3600

# Crypto-agility (Nico rec, 2026-07-29 design-review): the DEFAULT and only
# implemented signature algorithm today. `sig_alg` is a field on the SIGNED
# payload itself (not just a loose annotation) so a future entry minted
# under a different algorithm (e.g. "ml-dsa-65", once `cryptography` ships
# ML-DSA/FIPS-204 support) can coexist in the same manifest format during a
# staged fleet rotation, rather than forcing a hard, simultaneous cutover
# the day that support lands. `CatalogVerifier.verify()` DISPATCHES on this
# field; an entry claiming an algorithm this verify-side build doesn't
# implement fails closed (never silently falls back to ECDSA).
ECDSA_P256_SHA256 = "ecdsa-p256-sha256"


class CatalogVerificationError(ValueError):
    """Raised when a catalog entry's signature does not verify, no admitted
    entry exists for the requested (repo_id, revision, filename), the entry
    has aged past its max-trust-age, or the entry is on the deny-list."""


def _parse_issued_at(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"issued_at {value!r} is not a valid ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"issued_at {value!r} must be timezone-aware (e.g. end in 'Z' or '+00:00')")
    return parsed


@dataclass(frozen=True)
class SignedCatalogEntry:
    """One counter-signed admission record for a network model pull.

    Schema per Nico's provenance red-team finding #3: `(repo_id, revision,
    lfs_object_id, filename, quant, sha256)`, all frozen at mint time by
    Yashigani's own ingestion — plus `provenance_tier` (finding #5, inside
    the signature) and `issued_at`/`max_trust_age_seconds` (finding #2, the
    TTL / revocation-check gate).

    Attributes:
        repo_id: Hugging Face repo id (`namespace/name` or `name`).
        revision: pinned commit hash (never a floating branch).
        filename: the exact GGUF filename within the repo.
        quant: the quantization label asserted for this file (e.g.
            `"Q4_K_M"`) — part of the signed tuple per finding #3's schema.
        sha256: the AUTHORITATIVE digest — used as `expected_sha256` for the
            download, never re-derived from what was actually downloaded.
        lfs_object_id: the Git-LFS pointer's own object id (hex, no
            `sha256:` prefix) for the specific quant file — the actual
            content-identity guarantee, one layer more indirect than the
            wrapping commit hash (finding #3, second bullet).
        provenance_tier: e.g. `"vetted"` / `"community"` / `"converted-
            derived"` — carried INSIDE the signed payload so it cannot be
            edited independently of the signature.
        issued_at: ISO 8601 UTC timestamp this manifest was minted.
        max_trust_age_seconds: maximum age (from `issued_at`) before this
            manifest must be refreshed; enforced at every `require()` call,
            not just once at load time (finding #2).
        signature: raw ECDSA signature (DER-encoded) over `signed_payload()`.
        signer_key_id: opaque identifier for which signing key produced
            `signature` (key rotation bookkeeping; verification itself uses
            whichever public key the `CatalogVerifier` was constructed
            with — matching `signer_key_id` against an expected value is a
            deploy-time policy decision, not enforced by this dataclass).
        sig_alg: which signature algorithm `signature` was produced with
            (Nico crypto-agility rec, 2026-07-29). Defaults to
            `ECDSA_P256_SHA256` — the only algorithm this build implements
            today. Part of the SIGNED payload (see `signed_payload`), so an
            attacker cannot downgrade/relabel the claimed algorithm without
            invalidating the signature. `CatalogVerifier.verify()` dispatches
            on this field and fails closed on any value it does not
            recognise — never assumes ECDSA for an unrecognised string.
    """

    repo_id: str
    revision: str
    filename: str
    quant: str
    sha256: str
    lfs_object_id: str
    provenance_tier: str
    issued_at: str
    max_trust_age_seconds: int
    signature: bytes
    signer_key_id: str
    sig_alg: str = ECDSA_P256_SHA256

    def __post_init__(self) -> None:
        if not self.sig_alg.strip():
            raise ValueError("catalog entry sig_alg must not be blank")
        if not _SHA256_HEX.match(self.sha256.lower()):
            raise ValueError(f"catalog entry sha256 is not a 64-char hex digest: {self.sha256!r}")
        if not _LFS_OBJECT_ID_RE.match(self.lfs_object_id.lower()):
            raise ValueError(f"catalog entry lfs_object_id is not a 64-char hex digest: {self.lfs_object_id!r}")
        if not _REVISION_RE.match(self.revision):
            raise ValueError(
                f"catalog entry revision {self.revision!r} is not a pinned commit hash (7-40 hex chars) — "
                "floating branches/tags are refused at the manifest level, not just the adapter"
            )
        if not _QUANT_RE.match(self.quant):
            raise ValueError(f"catalog entry quant {self.quant!r} failed the allowlist guard")
        _parse_issued_at(self.issued_at)  # raises ValueError on malformed/naive timestamps
        if self.max_trust_age_seconds <= 0:
            raise ValueError(
                f"catalog entry max_trust_age_seconds must be positive, got {self.max_trust_age_seconds!r} — "
                "there is no 'disable TTL' value"
            )
        if self.max_trust_age_seconds > _MAX_TRUST_AGE_CEILING_SECONDS:
            raise ValueError(
                f"catalog entry max_trust_age_seconds={self.max_trust_age_seconds} exceeds the "
                f"{_MAX_TRUST_AGE_CEILING_SECONDS}s ceiling — no eternal-trust manifests"
            )

    def signed_payload(self) -> bytes:
        """Canonical bytes that were signed (see `provenance_canon`). Only
        the fields that are part of the admission covenant are included —
        the signature and signer_key_id themselves are excluded (they are
        not signed OVER, they carry the signature)."""
        payload = {
            "repo_id": self.repo_id,
            "revision": self.revision,
            "filename": self.filename,
            "quant": self.quant,
            "sha256": self.sha256.lower(),
            "lfs_object_id": self.lfs_object_id.lower(),
            "provenance_tier": self.provenance_tier,
            "issued_at": self.issued_at,
            "max_trust_age_seconds": self.max_trust_age_seconds,
            "sig_alg": self.sig_alg,
        }
        return canonical_json_bytes(payload)

    def is_expired(self, now: datetime | None = None) -> bool:
        """True once `now` is past `issued_at + max_trust_age_seconds`."""
        moment = now if now is not None else datetime.now(timezone.utc)
        issued = _parse_issued_at(self.issued_at)
        age_seconds = (moment - issued).total_seconds()
        return age_seconds > self.max_trust_age_seconds

    def to_json_dict(self) -> dict[str, object]:
        """On-disk manifest-file representation (the counter-signed manifest
        FORMAT): every signed field plus the signature, base64-encoded, and
        `signer_key_id` for rotation bookkeeping. This is the shape
        `scripts/manifest_signer.py` writes and `from_json_dict` reads back —
        the same shape a fleet-distributed catalog file uses on disk."""
        import base64

        return {
            "repo_id": self.repo_id,
            "revision": self.revision,
            "filename": self.filename,
            "quant": self.quant,
            "sha256": self.sha256,
            "lfs_object_id": self.lfs_object_id,
            "provenance_tier": self.provenance_tier,
            "issued_at": self.issued_at,
            "max_trust_age_seconds": self.max_trust_age_seconds,
            "signer_key_id": self.signer_key_id,
            "sig_alg": self.sig_alg,
            "signature": base64.b64encode(self.signature).decode("ascii"),
        }

    @classmethod
    def from_json_dict(cls, data: dict[str, object]) -> "SignedCatalogEntry":
        """Inverse of `to_json_dict` — parses a manifest-file record back
        into a `SignedCatalogEntry`. Does NOT verify the signature; callers
        must still run it through a `CatalogVerifier` (e.g. via
        `SignedCatalog.load_entries`) before trusting it."""
        import base64

        fields = dict(data)
        signature_b64 = fields.pop("signature")
        assert isinstance(signature_b64, str)
        return cls(signature=base64.b64decode(signature_b64), **fields)  # type: ignore[arg-type]


class CatalogVerifier:
    """Verify-side ECDSA signature check. Holds a PUBLIC key only.

    Signing (the private-key half) is `scripts/manifest_signer.py`
    (Yashigani signing infra only) — this class exists so THIS package can
    independently verify without ever holding, generating, or needing
    access to a private key.
    """

    def __init__(self, public_key: ec.EllipticCurvePublicKey) -> None:
        self._public_key = public_key

    def verify(self, entry: SignedCatalogEntry) -> None:
        if entry.sig_alg != ECDSA_P256_SHA256:
            # Crypto-agility (Nico rec): an entry claiming an algorithm this
            # verify-side build does not implement fails closed — it is
            # NEVER assumed to be ECDSA regardless of what `signature`
            # contains. This is what makes a future staged ML-DSA rotation
            # safe: old verifiers refuse new-algorithm entries loudly rather
            # than mis-verifying them.
            raise CatalogVerificationError(
                f"catalog entry for {entry.repo_id}@{entry.revision}/{entry.filename} claims sig_alg "
                f"{entry.sig_alg!r}, which this build does not implement (supported: {ECDSA_P256_SHA256!r}) — "
                "refusing to verify rather than guessing"
            )
        try:
            self._public_key.verify(entry.signature, entry.signed_payload(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise CatalogVerificationError(
                f"signature verification failed for {entry.repo_id}@{entry.revision}/{entry.filename}"
            ) from exc


class RevocationSource(Protocol):
    """Pluggable deny-list check (red-team finding #2/#6). Implementations
    can be as simple as a static in-memory set (tests, air-gapped/offline
    default) or as involved as a periodically-refreshed, itself-signed
    deny-list document fetched from a Yashigani-maintained source — the
    contract here does not care which, only that `SignedCatalog.require()`
    calls it on every use, not just once at load time."""

    def is_revoked(self, repo_id: str, revision: str, filename: str) -> bool: ...


class StaticRevocationSource:
    """In-memory deny-list keyed by (repo_id, revision, filename). This is
    the offline/air-gapped-friendly default — it denies nothing on its own.
    It is NOT a fail-closed revocation control by itself: an empty
    `StaticRevocationSource` (the default `SignedCatalog` wires in when no
    `revocation_source` is supplied) means "no deny-list wired," not "no
    model is ever revoked." Production/fleet deployments that want a live
    revocation control MUST wire a real `RevocationSource` implementation
    (e.g. one that re-fetches a signed deny-list on a schedule) — this
    class only makes the interface usable and testable without one."""

    def __init__(self, denied: Iterable[tuple[str, str, str]] = ()) -> None:
        self._denied: frozenset[tuple[str, str, str]] = frozenset(denied)

    def is_revoked(self, repo_id: str, revision: str, filename: str) -> bool:
        return (repo_id, revision, filename) in self._denied


class SignedCatalog:
    """Lookup table of verified admission entries, keyed by (repo_id, revision, filename).

    Every entry is verified at `load_entries()` time — an entry whose
    signature does not verify is refused (fail closed) and never enters the
    lookup table; there is no "load anyway" override. `require()` performs
    two FURTHER checks on every call (not cached from load time): the
    manifest's TTL, and the configured `RevocationSource` — a manifest that
    was valid when loaded can still be refused later if it has aged out or
    been added to the deny-list since (red-team finding #2).
    """

    def __init__(self, verifier: CatalogVerifier, revocation_source: RevocationSource | None = None) -> None:
        self._verifier = verifier
        self._revocation_source: RevocationSource = revocation_source or StaticRevocationSource()
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

    def require(
        self,
        repo_id: str,
        revision: str,
        filename: str,
        *,
        now: datetime | None = None,
    ) -> SignedCatalogEntry:
        """Look up an admitted entry. Raises `CatalogVerificationError` if
        absent, expired, or revoked — there is no free-text override / bypass
        path; a caller that wants to pull a model not yet in the catalog (or
        whose manifest has aged out) must get a fresh counter-signed
        manifest and reload it, not skip this check."""
        entry = self._entries.get((repo_id, revision, filename))
        if entry is None:
            raise CatalogVerificationError(
                f"no signed catalog entry for {repo_id}@{revision}/{filename} — network pulls "
                "require an admin-provisioned, counter-signed manifest entry; there is no override"
            )
        moment = now if now is not None else datetime.now(timezone.utc)
        if entry.is_expired(moment):
            raise CatalogVerificationError(
                f"signed catalog entry for {repo_id}@{revision}/{filename} exceeded its max trust age "
                f"(issued_at={entry.issued_at}, max_trust_age_seconds={entry.max_trust_age_seconds}) — "
                "mint and load a fresh counter-signed manifest; there is no override"
            )
        if self._revocation_source.is_revoked(repo_id, revision, filename):
            raise CatalogVerificationError(
                f"signed catalog entry for {repo_id}@{revision}/{filename} is on the deny-list — refusing"
            )
        return entry


__all__ = [
    "ECDSA_P256_SHA256",
    "CatalogVerificationError",
    "CatalogVerifier",
    "RevocationSource",
    "SignedCatalog",
    "SignedCatalogEntry",
    "StaticRevocationSource",
]
