# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for the first-parse jail seam (Iris integration-seam audit F3,
2026-07-22): `FirstParseJailHook` used to have zero callers. These tests cover
both the hook implementations themselves (`containment/hooks.py`) and the
wired call site every GGUF-parsing `SourceAdapter` now goes through
(`adapters/base.py::SourceAdapter._first_parse_gguf_header`)."""

from __future__ import annotations

from pathlib import Path

import pytest

from yashigani_infer.adapters.local_file import LocalFileAdapter, LocalFileAdapterError
from yashigani_infer.blobstore.store import BlobStore
from yashigani_infer.containment.hooks import (
    default_first_parse_jail_hook,
    select_first_parse_jail_hook,
    unimplemented_orchestrated_first_parse_jail_hook,
)
from yashigani_infer.gguf.header import GGUFParseError

# ── default_first_parse_jail_hook (the v1 in-process guard) ─────────────────


def test_default_hook_passes_through_valid_gguf_bytes(minimal_gguf_bytes: bytes) -> None:
    result = default_first_parse_jail_hook(minimal_gguf_bytes)
    assert result == minimal_gguf_bytes  # identity-shaped return on success


def test_default_hook_fails_closed_on_malformed_gguf_bytes() -> None:
    with pytest.raises(GGUFParseError):
        default_first_parse_jail_hook(b"this is not a gguf file at all")


def test_default_hook_fails_closed_on_empty_bytes() -> None:
    with pytest.raises(GGUFParseError):
        default_first_parse_jail_hook(b"")


# ── select_first_parse_jail_hook (v1-vs-orchestrated switch) ────────────────


def test_select_returns_default_hook_when_orchestration_disabled() -> None:
    hook = select_first_parse_jail_hook(container_orchestration_enabled=False)
    assert hook is default_first_parse_jail_hook


def test_select_defaults_to_disabled_when_unspecified() -> None:
    hook = select_first_parse_jail_hook()
    assert hook is default_first_parse_jail_hook


def test_select_returns_orchestrated_stub_when_enabled() -> None:
    hook = select_first_parse_jail_hook(container_orchestration_enabled=True)
    assert hook is unimplemented_orchestrated_first_parse_jail_hook


def test_orchestrated_stub_refuses_rather_than_silently_downgrading() -> None:
    with pytest.raises(NotImplementedError, match="C3"):
        unimplemented_orchestrated_first_parse_jail_hook(b"anything")


# ── wired call site: SourceAdapter._first_parse_gguf_header via LocalFileAdapter ──


def test_adapter_defaults_to_the_v1_guard_not_the_identity_noop(tmp_blob_store: BlobStore) -> None:
    adapter = LocalFileAdapter(tmp_blob_store)
    assert adapter._first_parse_jail_hook is default_first_parse_jail_hook


def test_hook_fires_on_first_load_of_a_local_gguf(
    tmp_blob_store: BlobStore, minimal_gguf_file: Path, minimal_gguf_bytes: bytes
) -> None:
    calls: list[bytes] = []

    def _spy_hook(header_bytes: bytes) -> bytes:
        calls.append(header_bytes)
        return default_first_parse_jail_hook(header_bytes)

    adapter = LocalFileAdapter(tmp_blob_store, first_parse_jail_hook=_spy_hook)
    resolved = adapter.resolve(path=minimal_gguf_file)

    assert len(calls) == 1  # fired exactly once, on this first (only) load
    assert calls[0].startswith(b"GGUF")  # the raw header bytes, not a summary
    assert resolved.sha256  # resolve still completed successfully


def test_hook_fails_closed_on_a_malformed_gguf_via_adapter(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    bogus = tmp_path / "not-a-model.gguf"
    bogus.write_bytes(b"this is not a gguf file at all")
    adapter = LocalFileAdapter(tmp_blob_store)

    with pytest.raises(LocalFileAdapterError, match="not a valid GGUF"):
        adapter.resolve(path=bogus)


def test_injected_hook_refusal_propagates_as_the_adapters_own_refusal(
    tmp_blob_store: BlobStore, minimal_gguf_file: Path
) -> None:
    """A hook that itself refuses (simulating a real jail's own rejection,
    v2) must still result in the adapter's normal fail-closed refusal path —
    not a silently-swallowed pass."""

    def _refusing_hook(header_bytes: bytes) -> bytes:
        raise GGUFParseError("simulated jail refusal")

    adapter = LocalFileAdapter(tmp_blob_store, first_parse_jail_hook=_refusing_hook)
    with pytest.raises(LocalFileAdapterError, match="not a valid GGUF"):
        adapter.resolve(path=minimal_gguf_file)
