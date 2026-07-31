# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Convert-to-GGUF BUILD tests (Tiago 2026-07-31 convert-BUILD decision).

Covers the layers `test_adapter_convert_guard.py` doesn't: the source-DIR
guard, the subprocess invoker (argv/env contract, timeout, failure paths),
the completed `ConvertAdapter.resolve()` provenance chain, directory
source-tree measurement, and the `kuroshio.convert_job` ephemeral-job CLI.

Everything runs with NO llama.cpp tooling and NO network — the invoker's
subprocess seam is exercised against injected fakes and, for the CLI, tiny
local stand-in scripts that only copy pre-built fixture bytes.
"""

from __future__ import annotations

import json
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest

from kuroshio import convert_job
from kuroshio.adapters.convert import (
    ConversionFailedError,
    ConversionInvoker,
    ConvertAdapter,
    PickleRefusedError,
    SubprocessConversionInvoker,
    UnsupportedSourceFormatError,
    guard_convert_source_dir,
)
from kuroshio.blobstore.store import BlobStore, sha256_file
from kuroshio.convert_provenance import measure_source_digest
from kuroshio.gguf.header import GGUFParseError
from kuroshio.models import ProvenanceKind
from tests.fixtures.gguf_builder import build_minimal_gguf

TOOL_COMMIT = "deadbeefcafe1234"


def _fake_safetensors_bytes() -> bytes:
    header = b'{"__metadata__": {"format": "pt"}}'
    return struct.pack("<Q", len(header)) + header + b"\x00" * 16


def _make_model_dir(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.json").write_text('{"architectures": ["LlamaForCausalLM"]}')
    (root / "model.safetensors").write_bytes(_fake_safetensors_bytes())
    (root / "tokenizer.json").write_text("{}")
    return root


# ── guard_convert_source_dir ───────────────────────────────────────────────


def test_source_dir_guard_accepts_hf_style_dir(tmp_path: Path) -> None:
    guard_convert_source_dir(_make_model_dir(tmp_path / "model"))


def test_source_dir_guard_allows_extensionless_dotfiles(tmp_path: Path) -> None:
    root = _make_model_dir(tmp_path / "model")
    (root / ".gitattributes").write_text("*.safetensors filter=lfs\n")
    guard_convert_source_dir(root)


def test_source_dir_guard_refuses_pickle_file_anywhere(tmp_path: Path) -> None:
    root = _make_model_dir(tmp_path / "model")
    (root / "pytorch_model.bin").write_bytes(b"\x80\x04pickle")
    with pytest.raises(PickleRefusedError):
        guard_convert_source_dir(root)


def test_source_dir_guard_refuses_disguised_pickle_regardless_of_name(tmp_path: Path) -> None:
    root = _make_model_dir(tmp_path / "model")
    # ZIP magic in a file wearing an allowlisted extension.
    (root / "tokenizer_config.json").write_bytes(b"PK\x03\x04not-really-json")
    with pytest.raises(PickleRefusedError):
        guard_convert_source_dir(root)


def test_source_dir_guard_refuses_unknown_extension(tmp_path: Path) -> None:
    root = _make_model_dir(tmp_path / "model")
    (root / "mystery.so").write_bytes(b"\x7fELF")
    with pytest.raises(UnsupportedSourceFormatError, match="allowlist"):
        guard_convert_source_dir(root)


def test_source_dir_guard_refuses_symlink(tmp_path: Path) -> None:
    root = _make_model_dir(tmp_path / "model")
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    (root / "linked.json").symlink_to(outside)
    with pytest.raises(UnsupportedSourceFormatError, match="symlink"):
        guard_convert_source_dir(root)


def test_source_dir_guard_requires_weights_and_config(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "config.json").write_text("{}")
    with pytest.raises(UnsupportedSourceFormatError, match="no .safetensors"):
        guard_convert_source_dir(empty)

    no_config = tmp_path / "no-config"
    no_config.mkdir()
    (no_config / "model.safetensors").write_bytes(_fake_safetensors_bytes())
    with pytest.raises(UnsupportedSourceFormatError, match="config.json"):
        guard_convert_source_dir(no_config)


# ── measure_source_digest on directories ───────────────────────────────────


def test_tree_digest_is_deterministic_and_content_sensitive(tmp_path: Path) -> None:
    a = _make_model_dir(tmp_path / "a")
    b = _make_model_dir(tmp_path / "b")
    assert measure_source_digest(a) == measure_source_digest(b)
    (b / "config.json").write_text('{"architectures": ["Changed"]}')
    assert measure_source_digest(a) != measure_source_digest(b)


def test_tree_digest_differs_from_any_single_file_digest(tmp_path: Path) -> None:
    root = _make_model_dir(tmp_path / "a")
    assert measure_source_digest(root) != sha256_file(root / "model.safetensors")


def test_tree_digest_refuses_symlinks(tmp_path: Path) -> None:
    root = _make_model_dir(tmp_path / "a")
    (root / "sneaky.json").symlink_to(tmp_path / "a" / "config.json")
    with pytest.raises(ValueError, match="symlink"):
        measure_source_digest(root)


def test_tree_digest_refuses_empty_dir(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="no regular files"):
        measure_source_digest(empty)


# ── SubprocessConversionInvoker ────────────────────────────────────────────


class _FakeCompleted:
    def __init__(self, returncode: int = 0, stderr: bytes = b"") -> None:
        self.returncode = returncode
        self.stderr = stderr


class _FakeRun:
    """Injected in place of subprocess.run: records calls, simulates the tools."""

    def __init__(self, *, convert_rc: int = 0, quantize_rc: int = 0, gguf_bytes: bytes | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._convert_rc = convert_rc
        self._quantize_rc = quantize_rc
        self._gguf_bytes = gguf_bytes if gguf_bytes is not None else build_minimal_gguf()

    def __call__(self, argv: list[str], **kwargs: Any) -> _FakeCompleted:
        self.calls.append({"argv": argv, **kwargs})
        if "--outfile" in argv:  # the convert_hf_to_gguf step
            if self._convert_rc == 0:
                Path(argv[argv.index("--outfile") + 1]).write_bytes(b"f16-intermediate")
            return _FakeCompleted(self._convert_rc, b"convert boom")
        # the llama-quantize step: argv = [bin, in, out, quant]
        if self._quantize_rc == 0:
            Path(argv[2]).write_bytes(self._gguf_bytes)
        return _FakeCompleted(self._quantize_rc, b"quantize boom")


@pytest.fixture()
def tool_paths(tmp_path: Path) -> tuple[Path, Path]:
    convert_script = tmp_path / "convert_hf_to_gguf.py"
    convert_script.write_text("# stand-in\n")
    quantize_bin = tmp_path / "llama-quantize"
    quantize_bin.write_text("# stand-in\n")
    return convert_script, quantize_bin


def _invoker(tool_paths: tuple[Path, Path], run: Any, **kwargs: Any) -> SubprocessConversionInvoker:
    convert_script, quantize_bin = tool_paths
    return SubprocessConversionInvoker(
        convert_script=convert_script,
        quantize_binary=quantize_bin,
        tool_commit=TOOL_COMMIT,
        run=run,
        **kwargs,
    )


def test_invoker_happy_path_argv_and_env_contract(tmp_path: Path, tool_paths: tuple[Path, Path]) -> None:
    fake = _FakeRun()
    out = _invoker(tool_paths, fake).convert(tmp_path / "src", out_dir=tmp_path / "out", quant="Q4_K_M")
    assert out.is_file() and out.read_bytes() == build_minimal_gguf()
    assert out.name == "converted.Q4_K_M.gguf"
    assert (tmp_path / "out").resolve() in out.resolve().parents
    assert len(fake.calls) == 2
    convert_call, quantize_call = fake.calls
    # No shell, no trust-remote-code flag, ever (TRUST_REMOTE_CODE contract).
    for call in fake.calls:
        assert isinstance(call["argv"], list)
        assert not any("trust" in str(a).lower() for a in call["argv"])
        assert call["env"]["HF_HUB_OFFLINE"] == "1"
        assert call["env"]["TRANSFORMERS_OFFLINE"] == "1"
        assert call["timeout"] == pytest.approx(3600.0)
    assert convert_call["argv"][-1] == "f16"
    assert quantize_call["argv"][-1] == "Q4_K_M"
    # Intermediate f16 never leaves scratch.
    assert not list((tmp_path / "out").rglob("*.f16.gguf"))


def test_invoker_convert_step_failure_carries_stderr(tmp_path: Path, tool_paths: tuple[Path, Path]) -> None:
    with pytest.raises(ConversionFailedError, match="convert boom"):
        _invoker(tool_paths, _FakeRun(convert_rc=1)).convert(tmp_path / "src", out_dir=tmp_path / "out", quant="Q4_K_M")
    # Failed conversions leave no scratch behind.
    assert not list((tmp_path / "out").iterdir())


def test_invoker_quantize_step_failure(tmp_path: Path, tool_paths: tuple[Path, Path]) -> None:
    with pytest.raises(ConversionFailedError, match="quantize boom"):
        _invoker(tool_paths, _FakeRun(quantize_rc=2)).convert(
            tmp_path / "src", out_dir=tmp_path / "out", quant="Q4_K_M"
        )


def test_invoker_timeout_is_conversion_failure(tmp_path: Path, tool_paths: tuple[Path, Path]) -> None:
    def _hang(argv: list[str], **kwargs: Any) -> _FakeCompleted:
        raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs["timeout"])

    with pytest.raises(ConversionFailedError, match="timeout"):
        _invoker(tool_paths, _hang, timeout_seconds=5.0).convert(
            tmp_path / "src", out_dir=tmp_path / "out", quant="Q4_K_M"
        )


def test_invoker_refuses_bad_quant_before_running_anything(tmp_path: Path, tool_paths: tuple[Path, Path]) -> None:
    fake = _FakeRun()
    with pytest.raises(ValueError, match="quant"):
        _invoker(tool_paths, fake).convert(tmp_path / "src", out_dir=tmp_path / "out", quant="Q4; rm -rf /")
    assert fake.calls == []


def test_invoker_refuses_unpinned_tool_commit(tool_paths: tuple[Path, Path]) -> None:
    convert_script, quantize_bin = tool_paths
    with pytest.raises(ValueError, match="pinned commit"):
        SubprocessConversionInvoker(
            convert_script=convert_script,
            quantize_binary=quantize_bin,
            tool_commit="v1.2.3",
        )


# ── ConvertAdapter.resolve() end to end ────────────────────────────────────


class _FakeInvoker(ConversionInvoker):
    """Writes fixture GGUF bytes into a scratch subdir, like the real invoker."""

    def __init__(self, gguf_bytes: bytes, *, escape_to: Path | None = None) -> None:
        self._gguf_bytes = gguf_bytes
        self._escape_to = escape_to

    @property
    def tool_commit(self) -> str:
        return TOOL_COMMIT

    def convert(self, source_path: Path, *, out_dir: Path, quant: str) -> Path:
        target_dir = self._escape_to if self._escape_to is not None else out_dir / "convert-fake"
        target_dir.mkdir(parents=True, exist_ok=True)
        out = target_dir / f"converted.{quant}.gguf"
        out.write_bytes(self._gguf_bytes)
        return out


def test_convert_adapter_full_chain(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    source = _make_model_dir(tmp_path / "model-src")
    gguf_bytes = build_minimal_gguf(name="converted-model", license="apache-2.0")
    adapter = ConvertAdapter(tmp_blob_store, invoker=_FakeInvoker(gguf_bytes))

    resolved = adapter.resolve(source_path=source, quant="Q4_K_M")

    assert resolved.provenance.kind is ProvenanceKind.CONVERTED
    assert resolved.provenance.operator_supplied is True
    assert resolved.provenance.extra["provenance_tier"] == "converted-derived"
    conversion = resolved.provenance.extra["conversion"]
    # Both digests measured from actual bytes — source is the tree digest,
    # output matches the ingested blob.
    assert conversion["source_sha256"] == measure_source_digest(source)
    assert conversion["output_sha256"] == resolved.sha256
    assert conversion["convert_tool_commit"] == TOOL_COMMIT
    assert conversion["quant"] == "Q4_K_M"
    assert resolved.metadata["name"] == "converted-model"
    assert resolved.metadata["license"] == "apache-2.0"
    # Blob really ingested + scratch cleaned up.
    assert tmp_blob_store.get_path(resolved.sha256) is not None
    assert not list((tmp_blob_store.root / "scratch" / "convert").iterdir())


def test_convert_adapter_refuses_artifact_outside_scratch(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    source = _make_model_dir(tmp_path / "model-src")
    escape = tmp_path / "elsewhere"
    adapter = ConvertAdapter(tmp_blob_store, invoker=_FakeInvoker(build_minimal_gguf(), escape_to=escape))
    with pytest.raises(ConversionFailedError, match="outside the conversion scratch"):
        adapter.resolve(source_path=source)


def test_convert_adapter_refuses_non_gguf_output(tmp_blob_store: BlobStore, tmp_path: Path) -> None:
    source = _make_model_dir(tmp_path / "model-src")
    adapter = ConvertAdapter(tmp_blob_store, invoker=_FakeInvoker(b"not a gguf at all"))
    with pytest.raises(GGUFParseError):  # via the first-parse jail seam
        adapter.resolve(source_path=source)
    # Refused output never reaches the blob store, and scratch is cleaned.
    assert tmp_blob_store.list_digests() == []
    assert not list((tmp_blob_store.root / "scratch" / "convert").iterdir())


# ── kuroshio.convert_job CLI ───────────────────────────────────────────────


@pytest.fixture()
def job_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the job env at tiny stand-in tools that copy fixture bytes."""
    gguf_fixture = tmp_path / "fixture.gguf"
    gguf_fixture.write_bytes(build_minimal_gguf(name="job-model"))

    convert_script = tmp_path / "convert_hf_to_gguf.py"
    convert_script.write_text(
        f"import shutil, sys\nshutil.copy({str(gguf_fixture)!r}, sys.argv[sys.argv.index('--outfile') + 1])\n"
    )
    quantize_bin = tmp_path / "llama-quantize"
    quantize_bin.write_text('#!/bin/sh\ncp "$1" "$2"\n')
    quantize_bin.chmod(0o755)

    monkeypatch.setenv("YSG_KUROSHIO_CONVERT_SCRIPT", str(convert_script))
    monkeypatch.setenv("YSG_KUROSHIO_QUANTIZE_BIN", str(quantize_bin))
    monkeypatch.setenv("YSG_KUROSHIO_CONVERT_TOOL_COMMIT", TOOL_COMMIT)
    monkeypatch.setenv("YSG_KUROSHIO_CONVERT_TIMEOUT_SECONDS", "60")
    return tmp_path


def test_convert_job_success_end_to_end(job_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = _make_model_dir(job_env / "src")
    out_dir = job_env / "out"

    # The stand-in convert script needs the real python on PATH: the
    # invoker hard-sets a minimal env, so sys.executable must be reachable.
    rc = convert_job.main(["--source", str(source), "--out-dir", str(out_dir), "--quant", "Q4_K_M"])
    assert rc == convert_job.EXIT_OK

    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "success"
    gguf_path = Path(result["gguf_path"])
    assert gguf_path.is_file()
    assert result["output_sha256"] == sha256_file(gguf_path)
    assert result["source_sha256"] == measure_source_digest(source)
    measurement = json.loads(Path(result["measurement_path"]).read_text())
    assert measurement["output_sha256"] == result["output_sha256"]
    assert measurement["convert_tool_commit"] == TOOL_COMMIT


def test_convert_job_refuses_pickle_source(job_env: Path) -> None:
    source = _make_model_dir(job_env / "src")
    (source / "pytorch_model.bin").write_bytes(b"\x80\x04pickle")
    rc = convert_job.main(["--source", str(source), "--out-dir", str(job_env / "out")])
    assert rc == convert_job.EXIT_REFUSED


def test_convert_job_requires_env(job_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("YSG_KUROSHIO_CONVERT_TOOL_COMMIT")
    rc = convert_job.main(["--source", str(job_env), "--out-dir", str(job_env / "out")])
    assert rc == convert_job.EXIT_USAGE


def test_convert_job_missing_source_is_usage_error(job_env: Path) -> None:
    rc = convert_job.main(["--source", str(job_env / "nope"), "--out-dir", str(job_env / "out")])
    assert rc == convert_job.EXIT_USAGE
