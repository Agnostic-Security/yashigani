# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Serve-time / read-time provenance re-verification (Red-Council 6.0
design-review, 2026-07-29 — Tom finding H1, Nico/Tom finding H2).

Two closely-related gaps, one mechanism:

  - **H2 (provenance tier at-rest):** `blobstore/store.py` used to persist
    `provenance_tier` as a plain, UNSIGNED sidecar field — the ECDSA
    signature that vouched for it existed only transiently during the
    admission call (`HuggingFaceAdapter.resolve()`); nothing re-checked it
    afterward. Adapters now persist the RAW signed manifest alongside the
    blob (`Provenance.extra["signed_manifest"]`, see
    `adapters/huggingface.py`) — this module is what actually RE-VERIFIES
    that stored signature (and binds it to the resident blob's own digest
    and sidecar tier field) rather than trusting the plaintext sidecar.

  - **H1 (serve-time revocation):** `CatalogVerifier`/`ConvertedManifestVerifier`
    were previously invoked ONLY at pull-time (`SignedCatalog.require()` /
    the future convert-invocation call site) — never again once a blob was
    resident. A model admitted this morning that is added to a deny-list
    (or simply ages out) this afternoon kept being served indefinitely,
    because the actual serve path (`Supervisor.load()`) has no concept of
    provenance at all, only sha256 identity. `Supervisor` (see
    `supervisor/supervisor.py`) calls `ServeTimeProvenanceVerifier.verify()`
    on EVERY `load()` call — including the fast path for an
    already-resident model — so a revoked/expired/tampered model fails
    closed on the very next request, not only "the next time the process
    happens to restart."

Models with no stored `signed_manifest` (operator-supplied local imports —
LOCAL_FILE/LOCAL_OLLAMA/LOCAL_LMSTUDIO, or the Hugging Face adapter's
documented "unverified-dev-mode" fallback when no catalog is wired at all)
are passed through unchanged: there is nothing signed to re-check, and that
is the existing, honestly-labelled trust model (nothing new here) — this
module's job is only to make sure that whenever a record CLAIMS to be
signed, that claim is actually re-proven, every time it matters.

**Deployment wiring note:** this module builds and unit-tests the full
mechanism (ephemeral in-memory test keypairs, same convention as
`test_catalog.py`/`test_manifest_signing.py` — never a real production
key). Wiring a REAL `ServeTimeProvenanceVerifier` backed by a real embedded
public key into `entrypoint.create_asgi_app` is deferred to the same future
increment that wires real Hugging Face pulls (`pull_resolver` is `None` in
every role today, per `entrypoint.py`'s own docstring, and no
`MODEL_MANIFEST_PUBLIC_KEY_PEM` constant is embedded anywhere in this
package yet — inventing one here would be fabricating infrastructure that
does not exist, not implementing this fix). `Supervisor`'s default
`provenance_verifier=None` means today's behaviour is unchanged; the gate
this closes is that the MECHANISM exists and is proven correct, ready to be
wired the moment a real catalog/public key lands.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from yashigani_infer.catalog import CatalogVerificationError, CatalogVerifier, RevocationSource, SignedCatalogEntry
from yashigani_infer.convert_provenance import (
    ConvertedManifestEntry,
    ConvertedManifestVerificationError,
    ConvertedManifestVerifier,
    verify_converted_manifest,
)
from yashigani_infer.models import ProvenanceKind, ResolvedModel


class ServeTimeVerificationError(RuntimeError):
    """Raised when serve-time re-verification of a resident/stored model's
    provenance fails. The caller (`Supervisor.load`) MUST fail closed —
    refuse to (re)serve — on this; never log-and-continue."""


def _default_clock() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class ServeTimeProvenanceVerifier:
    """Re-runs signature + digest/tier-binding + TTL + revocation checks
    against a model's STORED signed manifest.

    Attributes:
        catalog_verifier: verifies `SignedCatalogEntry` (Hugging Face pulls).
            Required to serve-time-verify a HUGGINGFACE-provenance model
            that carries a `signed_manifest` — if absent, verification
            fails closed rather than silently skipping (see class docstring).
        converted_verifier: verifies `ConvertedManifestEntry` (converted-GGUF).
        revocation_source: shared deny-list check (same `RevocationSource`
            protocol as pull-time admission) — re-checked on EVERY call,
            same discipline as `SignedCatalog.require()`.
        clock: injectable for deterministic TTL-expiry testing.
    """

    catalog_verifier: CatalogVerifier | None = None
    converted_verifier: ConvertedManifestVerifier | None = None
    revocation_source: RevocationSource | None = None
    clock: Callable[[], datetime] = _default_clock

    def verify(self, resolved_model: ResolvedModel) -> None:
        provenance = resolved_model.provenance
        extra = provenance.extra or {}
        signed_manifest = extra.get("signed_manifest")
        if signed_manifest is None:
            return  # nothing signed to re-check — operator-supplied / dev-mode, unchanged trust model

        if provenance.kind is ProvenanceKind.HUGGINGFACE:
            self._verify_huggingface(resolved_model, signed_manifest)
        elif provenance.kind is ProvenanceKind.CONVERTED:
            self._verify_converted(resolved_model, signed_manifest)
        else:
            # No adapter ever attaches a signed_manifest to a LOCAL_* record —
            # fail closed on the unexpected combination rather than silently
            # trust it.
            raise ServeTimeVerificationError(
                f"model {resolved_model.sha256} carries a signed_manifest but its provenance kind "
                f"{provenance.kind.value!r} has no known serve-time verification path — refusing to serve"
            )

    def _verify_huggingface(self, resolved_model: ResolvedModel, signed_manifest: dict[str, object]) -> None:
        if self.catalog_verifier is None:
            raise ServeTimeVerificationError(
                f"model {resolved_model.sha256} carries a signed Hugging Face catalog manifest but no "
                "CatalogVerifier is configured for serve-time re-verification — refusing to serve "
                "('cannot verify' must never be treated as 'verified')"
            )
        try:
            entry = SignedCatalogEntry.from_json_dict(signed_manifest)
        except Exception as exc:
            raise ServeTimeVerificationError(
                f"model {resolved_model.sha256}: stored signed_manifest is malformed: {exc}"
            ) from exc

        try:
            self.catalog_verifier.verify(entry)
        except CatalogVerificationError as exc:
            raise ServeTimeVerificationError(
                f"model {resolved_model.sha256}: stored signed manifest failed re-verification: {exc}"
            ) from exc

        if entry.sha256.lower() != resolved_model.sha256.lower():
            raise ServeTimeVerificationError(
                f"model {resolved_model.sha256}: stored signed manifest's digest {entry.sha256!r} does not "
                "match the resident blob's own digest — refusing to serve (tier/manifest binding failure)"
            )

        stored_tier = (resolved_model.provenance.extra or {}).get("provenance_tier")
        if stored_tier != entry.provenance_tier:
            raise ServeTimeVerificationError(
                f"model {resolved_model.sha256}: sidecar provenance_tier {stored_tier!r} does not match the "
                f"signed manifest's provenance_tier {entry.provenance_tier!r} — the sidecar tier field was "
                "relabelled independently of the signature; refusing to serve"
            )

        now = self.clock()
        if entry.is_expired(now):
            raise ServeTimeVerificationError(
                f"model {resolved_model.sha256}: signed catalog manifest exceeded its max trust age "
                f"(issued_at={entry.issued_at}) — refusing to serve a resident model whose admission "
                "manifest has since expired"
            )
        if self.revocation_source is not None and self.revocation_source.is_revoked(
            entry.repo_id, entry.revision, entry.filename
        ):
            raise ServeTimeVerificationError(
                f"model {resolved_model.sha256}: {entry.repo_id}@{entry.revision}/{entry.filename} is on "
                "the deny-list — refusing to serve a resident model that has since been revoked"
            )

    def _verify_converted(self, resolved_model: ResolvedModel, signed_manifest: dict[str, object]) -> None:
        if self.converted_verifier is None:
            raise ServeTimeVerificationError(
                f"model {resolved_model.sha256} carries a signed converted-GGUF manifest but no "
                "ConvertedManifestVerifier is configured for serve-time re-verification — refusing to serve"
            )
        try:
            entry = ConvertedManifestEntry.from_json_dict(signed_manifest)
        except Exception as exc:
            raise ServeTimeVerificationError(
                f"model {resolved_model.sha256}: stored signed_manifest is malformed: {exc}"
            ) from exc

        stored_tier = (resolved_model.provenance.extra or {}).get("provenance_tier")
        if stored_tier != entry.provenance_tier:
            raise ServeTimeVerificationError(
                f"model {resolved_model.sha256}: sidecar provenance_tier {stored_tier!r} does not match the "
                f"signed manifest's provenance_tier {entry.provenance_tier!r} — refusing to serve"
            )

        try:
            # Re-uses the TOCTOU-closing re-measurement built for pull-time
            # verification — measures the ACTUAL bytes at `blob_path` right
            # now, not a cached digest, so this also catches a substitution
            # that happened after the blob was originally admitted.
            verify_converted_manifest(
                entry,
                output_path=resolved_model.blob_path,
                verifier=self.converted_verifier,
                revocation_source=self.revocation_source,
                now=self.clock(),
            )
        except ConvertedManifestVerificationError as exc:
            raise ServeTimeVerificationError(
                f"model {resolved_model.sha256}: stored converted-GGUF manifest failed re-verification: {exc}"
            ) from exc


__all__ = ["ServeTimeProvenanceVerifier", "ServeTimeVerificationError"]
