# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Licence-alert-on-import (Tiago 2026-07-31): classification + wiring.

Policy under test: bundle/default/catalog = recognised-commercial-free
licences only; client imports of anything else proceed (warn-not-block)
with a non-blocking licence alert on the pull stream.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kuroshio.adapters.local_file import LocalFileAdapter
from kuroshio.blobstore.store import BlobStore
from kuroshio.gguf.header import parse_gguf_header
from kuroshio.licensing import (
    KNOWN_COMMERCIAL_FREE_LICENCES,
    assess_licence,
    licence_verdict_for_model_metadata,
    normalize_licence,
)
from tests.fixtures.gguf_builder import build_minimal_gguf


# ── normalization ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Apache License 2.0", "apache-2.0"),
        ("apache-2.0", "apache-2.0"),
        ("apache_2_0", "apache-2.0"),
        ("Apache 2.0", "apache-2.0"),
        ("MIT License", "mit"),
        ("MIT", "mit"),
        ("CC0", "cc0-1.0"),
        ("BSD 3 Clause", "bsd-3-clause"),
        ("Qwen License", "qwen"),
        ("llama3.1", "llama3.1"),
    ],
)
def test_normalize_licence(raw: str, expected: str) -> None:
    assert normalize_licence(raw) == expected


# ── classification ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("raw", ["Apache License 2.0", "MIT", "bsd-3-clause", "mpl-2.0", "CC0"])
def test_commercial_free_licences_get_no_alert(raw: str) -> None:
    verdict = assess_licence(raw)
    assert verdict.commercial_free is True
    assert verdict.alert is None


@pytest.mark.parametrize(
    "raw",
    [
        # Family-specific / restricted licences — never on the allowlist.
        "Qwen License",
        "llama3.1",
        "gemma",
        "cc-by-nc-4.0",
        "openrail",
        "other",
        "some-brand-new-licence",
    ],
)
def test_unrecognised_licences_alert_but_never_block(raw: str) -> None:
    verdict = assess_licence(raw)
    assert verdict.commercial_free is False
    assert verdict.alert is not None
    assert "at your own risk" in verdict.alert
    assert "may require a licence" in verdict.alert


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_missing_licence_alerts(raw: str | None) -> None:
    verdict = assess_licence(raw)
    assert verdict.commercial_free is False
    assert verdict.alert is not None
    assert "no licence declared" in verdict.alert


def test_allowlist_contains_no_restricted_families() -> None:
    # The allowlist is the load-bearing artifact — a family/restricted id
    # sneaking on silently defeats the whole policy.
    for banned in ("qwen", "llama", "gemma", "openrail", "other"):
        assert not any(banned in entry for entry in KNOWN_COMMERCIAL_FREE_LICENCES)


def test_metadata_verdict_reads_license_key() -> None:
    assert licence_verdict_for_model_metadata({"license": "apache-2.0"}).commercial_free is True
    assert licence_verdict_for_model_metadata({"license": "qwen"}).alert is not None
    assert licence_verdict_for_model_metadata({}).alert is not None
    # A non-string value is treated as undeclared, not coerced.
    assert licence_verdict_for_model_metadata({"license": 42}).alert is not None


# ── GGUF extraction + adapter propagation ──────────────────────────────────


def test_gguf_header_license_property() -> None:
    header = parse_gguf_header(build_minimal_gguf(license="apache-2.0"))
    assert header.license == "apache-2.0"
    assert parse_gguf_header(build_minimal_gguf()).license is None


def test_local_file_adapter_records_declared_licence(tmp_path: Path) -> None:
    gguf = tmp_path / "model.gguf"
    gguf.write_bytes(build_minimal_gguf(license="Qwen License"))
    store = BlobStore(tmp_path / "store")
    resolved = LocalFileAdapter(store).resolve(path=gguf)
    assert resolved.metadata["license"] == "Qwen License"
    # ...and the stored sidecar round-trips it for later surfacing.
    stored = store.get_resolved_model(resolved.sha256)
    assert stored is not None and stored.metadata["license"] == "Qwen License"


def test_local_file_adapter_records_absent_licence_as_none(tmp_path: Path) -> None:
    gguf = tmp_path / "model.gguf"
    gguf.write_bytes(build_minimal_gguf())
    resolved = LocalFileAdapter(BlobStore(tmp_path / "store")).resolve(path=gguf)
    assert resolved.metadata["license"] is None


# ── pull-stream alert (warn-not-block) ─────────────────────────────────────


def _pull_statuses(metadata: dict[str, object]) -> list[dict[str, object]]:
    from kuroshio.models import Provenance, ProvenanceKind, ResolvedModel
    from kuroshio.shim.pull import iter_pull_progress

    resolved = ResolvedModel(
        sha256="a" * 64,
        blob_path=Path("/blobs/a.gguf"),
        metadata=metadata,
        provenance=Provenance(kind=ProvenanceKind.LOCAL_FILE, origin="/x.gguf", sha256="a" * 64),
    )
    return [json.loads(line) for line in iter_pull_progress(lambda: resolved)]


def test_pull_stream_emits_licence_alert_for_unrecognised_licence() -> None:
    events = _pull_statuses({"name": "x", "license": "Qwen License"})
    alert_events = [e for e in events if e["status"] == "licence alert"]
    assert len(alert_events) == 1
    assert alert_events[0]["licence"] == "Qwen License"
    assert "at your own risk" in str(alert_events[0]["detail"])
    # Warn-not-block: the pull still succeeds after the alert.
    assert events[-1]["status"] == "success"
    assert events.index(alert_events[0]) < events.index(events[-1])


def test_pull_stream_emits_licence_alert_when_no_licence_declared() -> None:
    events = _pull_statuses({"name": "x"})
    assert any(e["status"] == "licence alert" for e in events)
    assert events[-1]["status"] == "success"


def test_pull_stream_stays_quiet_for_commercial_free_licence() -> None:
    events = _pull_statuses({"name": "x", "license": "apache-2.0"})
    assert not any(e["status"] == "licence alert" for e in events)
    assert [e["status"] for e in events] == [
        "pulling manifest",
        "verifying sha256 digest",
        "writing manifest",
        "success",
    ]
