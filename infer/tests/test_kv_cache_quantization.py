# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""KV-cache quantization passthrough — the blue/green memory lever.

Weights are SHARED between two engine processes on the same GGUF (measured:
a second engine cost 0.82 GB, not a second copy). So KV is the only thing that
genuinely duplicates per slot, and it is also what scales with context length.
That makes `--cache-type-k`/`--cache-type-v` the highest-value memory control
available, and it was not being passed at all.

These fail on the pre-fix tree: LoadConfig has no such fields and build_args
emits no such flags.
"""

from __future__ import annotations

import pytest

from pathlib import Path

from kuroshio.entrypoint import EntrypointConfigError, _parse_kv_cache_type
from kuroshio.models import Provenance, ProvenanceKind, ResolvedModel
from kuroshio.supervisor.supervisor import LoadConfig, Supervisor


class _NullRunner:
    def spawn(self, *, binary: str, args: list[str], env: dict[str, str]) -> object:
        raise AssertionError("not spawned in these tests")


def _args(**kw: object) -> list[str]:
    sha = "a" * 64
    model = ResolvedModel(
        sha256=sha,
        blob_path=Path(f"/blobs/{sha}.gguf"),
        metadata={"name": "m"},
        provenance=Provenance(kind=ProvenanceKind.LOCAL_FILE, origin="x", sha256=sha),
    )
    sup = Supervisor(process_runner=_NullRunner(), llama_server_binary="llama-server")
    return sup.build_args(model, LoadConfig(**kw), 39000)  # type: ignore[arg-type]


# --- passthrough ------------------------------------------------------------


def test_kv_cache_types_are_passed_through_when_set() -> None:
    a = _args(cache_type_k="q8_0", cache_type_v="q8_0")
    assert "--cache-type-k" in a and a[a.index("--cache-type-k") + 1] == "q8_0"
    assert "--cache-type-v" in a and a[a.index("--cache-type-v") + 1] == "q8_0"


def test_k_and_v_are_independent() -> None:
    """Quantising K but not V is a legitimate posture — V errors matter more."""
    a = _args(cache_type_k="q8_0")
    assert "--cache-type-k" in a
    assert "--cache-type-v" not in a


def test_omitted_by_default_so_llama_server_keeps_its_own_default() -> None:
    """No silent default: the right value differs by model and hardware tier,
    so defaulting here would be us choosing on the operator's behalf."""
    a = _args()
    assert "--cache-type-k" not in a
    assert "--cache-type-v" not in a


# --- positive validation, fails closed (ISSUE-001 class) --------------------


@pytest.mark.parametrize("t", ["f16", "q8_0", "q5_1", "q4_0", "iq4_nl", "bf16"])
def test_recognised_types_accepted(t: str) -> None:
    assert _parse_kv_cache_type({"E": t}, "E") == t


def test_case_and_whitespace_normalised() -> None:
    assert _parse_kv_cache_type({"E": "  Q8_0 "}, "E") == "q8_0"


@pytest.mark.parametrize("bad", ["q3_bogus", "int8", "yes", "q8", "'q8_0'", "q8_0; rm -rf /"])
def test_unrecognised_type_refused_not_forwarded(bad: str) -> None:
    """An unrecognised value must not reach llama-server. Forwarding it gets
    either a process that refuses to start or — worse, silently — one running a
    different cache type than the operator asked for."""
    with pytest.raises(EntrypointConfigError, match="not a recognised KV-cache type"):
        _parse_kv_cache_type({"E": bad}, "E")


def test_blank_is_unset_not_an_error() -> None:
    assert _parse_kv_cache_type({"E": "   "}, "E") is None
    assert _parse_kv_cache_type({}, "E") is None
