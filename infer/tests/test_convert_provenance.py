# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Direct unit tests for `convert_provenance.py`'s dataclass validation and
measurement helpers — independent of the mint-side signer (see
`test_manifest_signing.py` for the full sign->verify round trip via
`scripts/manifest_signer.py`)."""

from __future__ import annotations

from pathlib import Path

import pytest

from yashigani_infer.catalog import ECDSA_P256_SHA256
from yashigani_infer.convert_provenance import (
    ConvertedManifestEntry,
    measure_conversion_tuple,
    measure_source_digest,
)

REVISION = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
GOOD_SHA256 = "c" * 64
ISSUED_AT = "2026-07-22T00:00:00Z"


def _base_fields(**overrides) -> dict:
    fields = {
        "source_sha256": GOOD_SHA256,
        "convert_tool_commit": REVISION,
        "quant": "Q4_K_M",
        "output_sha256": "d" * 64,
        "provenance_tier": "converted-derived",
        "issued_at": ISSUED_AT,
        "max_trust_age_seconds": 3600,
        "signer_key_id": "key-1",
        "signature": b"",
    }
    fields.update(overrides)
    return fields


def test_entry_rejects_malformed_source_sha256() -> None:
    with pytest.raises(ValueError, match="source_sha256"):
        ConvertedManifestEntry(**_base_fields(source_sha256="not-hex"))


def test_entry_rejects_malformed_output_sha256() -> None:
    with pytest.raises(ValueError, match="output_sha256"):
        ConvertedManifestEntry(**_base_fields(output_sha256="not-hex"))


def test_entry_rejects_floating_convert_tool_ref() -> None:
    with pytest.raises(ValueError, match="convert_tool_commit"):
        ConvertedManifestEntry(**_base_fields(convert_tool_commit="main"))


def test_entry_rejects_bad_quant() -> None:
    with pytest.raises(ValueError, match="quant"):
        ConvertedManifestEntry(**_base_fields(quant="not a valid label!"))


def test_entry_rejects_naive_issued_at() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ConvertedManifestEntry(**_base_fields(issued_at="2026-07-22T00:00:00"))


@pytest.mark.parametrize("bad_ttl", [0, -5])
def test_entry_rejects_non_positive_ttl(bad_ttl: int) -> None:
    with pytest.raises(ValueError, match="max_trust_age_seconds"):
        ConvertedManifestEntry(**_base_fields(max_trust_age_seconds=bad_ttl))


def test_entry_rejects_eternal_trust_window() -> None:
    with pytest.raises(ValueError, match="ceiling"):
        ConvertedManifestEntry(**_base_fields(max_trust_age_seconds=999_999_999))


def test_entry_defaults_sig_alg_to_ecdsa_p256_sha256() -> None:
    entry = ConvertedManifestEntry(**_base_fields())
    assert entry.sig_alg == ECDSA_P256_SHA256


def test_entry_rejects_blank_sig_alg() -> None:
    with pytest.raises(ValueError, match="sig_alg"):
        ConvertedManifestEntry(**_base_fields(sig_alg="   "))


def test_sig_alg_is_included_in_the_signed_payload() -> None:
    entry = ConvertedManifestEntry(**_base_fields())
    assert entry.sig_alg in entry.signed_payload().decode("utf-8")


def test_signed_payload_is_deterministic_and_field_complete() -> None:
    entry = ConvertedManifestEntry(**_base_fields())
    payload_bytes = entry.signed_payload()
    assert entry.source_sha256 in payload_bytes.decode("utf-8")
    assert entry.convert_tool_commit in payload_bytes.decode("utf-8")
    assert entry.output_sha256 in payload_bytes.decode("utf-8")
    # canonical: identical fields -> byte-identical payload
    entry_again = ConvertedManifestEntry(**_base_fields())
    assert entry_again.signed_payload() == payload_bytes


def test_measure_source_digest_matches_hashlib(tmp_path: Path) -> None:
    import hashlib

    path = tmp_path / "some.bin"
    content = b"arbitrary bytes to hash"
    path.write_bytes(content)
    assert measure_source_digest(path) == hashlib.sha256(content).hexdigest()


def test_measure_conversion_tuple_measures_both_files_independently(tmp_path: Path) -> None:
    source_path = tmp_path / "source.safetensors"
    output_path = tmp_path / "output.gguf"
    source_path.write_bytes(b"source content")
    output_path.write_bytes(b"different output content")

    measurement = measure_conversion_tuple(source_path, output_path, convert_tool_commit=REVISION, quant="Q8_0")
    assert measurement.source_sha256 != measurement.output_sha256
    assert measurement.source_sha256 == measure_source_digest(source_path)
    assert measurement.output_sha256 == measure_source_digest(output_path)
    assert measurement.convert_tool_commit == REVISION
    assert measurement.quant == "Q8_0"


def test_measure_conversion_tuple_refuses_bad_quant(tmp_path: Path) -> None:
    source_path = tmp_path / "source.safetensors"
    output_path = tmp_path / "output.gguf"
    source_path.write_bytes(b"x")
    output_path.write_bytes(b"y")
    with pytest.raises(ValueError, match="quant"):
        measure_conversion_tuple(source_path, output_path, convert_tool_commit=REVISION, quant="bad quant!")
