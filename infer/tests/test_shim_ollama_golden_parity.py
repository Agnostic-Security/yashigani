# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Golden-fixture parity regression tests for the ollama-API shim.

The fixtures under ``tests/fixtures/ollama-golden/`` were captured this cycle
from a REAL ollama (``qwen2.5:3b`` / ``qwen2.5:7b``) via a live parity run and
copied verbatim into the repo. They pin the byte-SHAPE (field set / envelope
keys) of ollama's responses so the shim's synthesized envelopes cannot silently
drift out of parity.

Token *content*, durations, digests etc. legitimately differ between a live
model and the shim — these tests assert on envelope KEY SETS only, never on
values.
"""

from __future__ import annotations

import json
from pathlib import Path

from kuroshio.blobstore.store import BlobStore
from kuroshio.models import Provenance, ProvenanceKind
from kuroshio.shim.generate import generate_event_to_ndjson
from kuroshio.shim.show import synthesize_show
from kuroshio.shim.tags import synthesize_tag_entry

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "ollama-golden"


def _golden_tags() -> dict:
    return json.loads((GOLDEN_DIR / "tags.json").read_text())


def _golden_generate_chunks() -> list[dict]:
    text = (GOLDEN_DIR / "generate_stream.ndjson").read_text()
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _golden_show() -> dict:
    return json.loads((GOLDEN_DIR / "show.json").read_text())


def _ingest(tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes, name: str):
    src = tmp_path / f"{name.replace(':', '_')}.gguf"
    src.write_bytes(minimal_gguf_bytes)
    provenance = Provenance(kind=ProvenanceKind.LOCAL_FILE, origin=str(src), sha256="")
    return tmp_blob_store.put_from_path(
        src,
        metadata={"name": name, "family": "qwen2", "parameter_size": "3.1B", "quantization_level": "Q4_K_M"},
        provenance=provenance,
    )


# --- /api/generate streaming envelope -------------------------------------


def test_generate_stream_chunk_field_set_matches_golden() -> None:
    """Non-final chunk: shim must emit exactly {model, created_at, response, done}."""
    golden_non_final = next(c for c in _golden_generate_chunks() if not c["done"])
    line, is_final = generate_event_to_ndjson({"content": "Hi", "stop": False}, "qwen2.5:3b")
    assert is_final is False
    obj = json.loads(line)
    assert set(obj.keys()) == set(golden_non_final.keys())


def test_generate_done_object_field_set_matches_golden() -> None:
    """Final done-object: shim must emit the full ollama done envelope, including
    prompt_eval_duration and load_duration (the parity gaps this cycle fixed)."""
    golden_final = next(c for c in _golden_generate_chunks() if c["done"])
    event = {
        "content": "",
        "stop": True,
        "tokens_cached_ids": [1, 2, 3],
        "tokens_evaluated": 34,
        "tokens_predicted": 3,
        "timings": {"predicted_ms": 47.7, "prompt_ms": 157.2},
    }
    line, is_final = generate_event_to_ndjson(event, "qwen2.5:3b")
    assert is_final is True
    obj = json.loads(line)
    assert set(obj.keys()) == set(golden_final.keys())
    # regression guards for the two fields that were MISSING pre-fix:
    assert "prompt_eval_duration" in obj
    assert "load_duration" in obj
    # prompt_eval_duration is emitted in nanoseconds (prompt_ms * 1e6):
    assert obj["prompt_eval_duration"] == int(157.2 * 1_000_000)


# --- /api/tags envelope ----------------------------------------------------


def test_tags_model_entry_field_set_matches_golden(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    """Each /api/tags models[] entry must carry the same top-level keys ollama
    emits — including `capabilities` (the parity gap this cycle fixed)."""
    golden_entry = _golden_tags()["models"][0]
    resolved = _ingest(tmp_blob_store, tmp_path, minimal_gguf_bytes, "qwen2.5:3b")
    entry = synthesize_tag_entry(resolved)
    assert set(entry.keys()) == set(golden_entry.keys())
    assert "capabilities" in entry
    assert isinstance(entry["capabilities"], list) and entry["capabilities"]


# --- /api/show envelope ----------------------------------------------------


def test_show_envelope_parity_against_golden(
    tmp_blob_store: BlobStore, tmp_path: Path, minimal_gguf_bytes: bytes
) -> None:
    """Characterization + parity test for /api/show.

    The shim already emits the core show keys in parity with ollama. This test
    pins that overlap AND documents the residual top-level divergence explicitly
    so any future drift (in either direction) trips the assertion. The residual
    gap (capabilities/license/system/tensors not yet synthesized; an extra
    `parameters` key) was NOT in this cycle's fix scope — it is tracked here as a
    known, deliberate divergence for a follow-up parity pass.
    """
    golden = _golden_show()
    resolved = _ingest(tmp_blob_store, tmp_path, minimal_gguf_bytes, "qwen2.5:3b")
    body = synthesize_show(resolved)

    golden_keys = set(golden.keys())
    shim_keys = set(body.keys())

    # Keys the shim emits in parity with ollama's /api/show today:
    assert {"modelfile", "template", "details", "model_info", "modified_at"} <= (shim_keys & golden_keys)

    # Documented, out-of-scope residual divergence (update if show is extended):
    assert golden_keys - shim_keys == {"capabilities", "license", "system", "tensors"}
    assert shim_keys - golden_keys == {"parameters"}
