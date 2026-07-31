# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Convert-to-GGUF adapter — safetensors -> GGUF, guarded end to end.

BUILT 2026-07-31 (Tiago's convert-BUILD decision, overriding the earlier v2
park). Three layers, in trust order:

  1. **Hard security guard** (unchanged from the v1 skeleton, council review
     §3b): accept `safetensors` sources ONLY. PyTorch `.bin`/`.pt`/`.pth`/
     `.ckpt` pickle files are REFUSED before any parse — pickle
     deserialization is arbitrary-code-execution, and "a malicious model"
     for these formats is an RCE payload, not just bad weights ("single
     most dangerous surface in the whole engine"). Real conversion sources
     are Hugging Face-style model DIRECTORIES; `guard_convert_source_dir`
     applies the same refusal to every file in the tree (content-sniff
     first, extension allowlist second, symlinks refused outright).
  2. **`SubprocessConversionInvoker`** — invokes llama.cpp's
     `convert_hf_to_gguf.py` + `llama-quantize` as argv-list subprocesses
     (no shell), with a hard timeout and a hard-set offline environment
     (`HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`). It NEVER passes any
     trust-remote-code flag (see `TRUST_REMOTE_CODE` below). Process-level
     flags are defence-in-depth only: the REAL boundary is that production
     conversions run inside an isolated, ephemeral, network-denied job
     container (first-parse-jail pattern) — never in the long-running
     serving process, which keeps `StubConversionInvoker` as its default.
  3. **Provenance measurement** (Nico finding #4): both digests of the
     `(source, tool_commit, quant, output)` tuple are measured from actual
     bytes by `convert_provenance.measure_conversion_tuple` inside the same
     process that ran the conversion, before any hand-off — and the blob
     store re-verifies the output digest during ingestion, closing the
     substitution window between measurement and admission. Mint-side
     signing of the measured tuple stays in `scripts/manifest_signer.py`
     (signing-infra custody, never this runtime package).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from kuroshio.adapters.base import SourceAdapter
from kuroshio.convert_provenance import measure_conversion_tuple
from kuroshio.models import Provenance, ProvenanceKind, ResolvedModel

# Extensions that are refused outright (naming-discipline check — see
# ordering note on `guard_safetensors_only`: this runs SECOND, after the
# content-sniff, per red-council item #5 "pickle refused by CONTENT-SNIFF
# not extension"). `.pt`/`.pth`/`.bin` are conventionally pickle
# (`torch.save` default `pickle_module=pickle`); `.ckpt` is the same for
# most training frameworks (Lightning etc).
_REFUSED_EXTENSIONS = frozenset({".bin", ".pt", ".pth", ".ckpt"})
_ACCEPTED_EXTENSION = ".safetensors"

# Non-weight files a Hugging Face-style model directory legitimately
# carries and `convert_hf_to_gguf.py` reads: config/tokenizer JSON, merges/
# vocab text, sentencepiece `.model` protobufs, chat-template jinja, docs.
# Anything outside this allowlist fails closed — an unexpected file type in
# a conversion source is refused, not silently ignored.
_ALLOWED_AUX_EXTENSIONS = frozenset({".json", ".txt", ".model", ".jinja", ".md"})

# Bound on files in a source tree — a real model dir has dozens of files at
# most; this ceiling only bounds worst-case walk time on a hostile tree.
_MAX_SOURCE_TREE_FILES = 4096

# A `torch.save` pickle checkpoint is either:
#   - a raw pickle stream, whose first byte is the pickle protocol opcode
#     `\x80` (PROTOCOL) for protocol 2+, or an ASCII opcode for protocol 0;
#   - (modern default) a ZIP container (`torch.save` zipfile format), whose
#     first bytes are the ZIP local-file-header magic `PK\x03\x04`.
_PICKLE_ZIP_MAGIC = b"PK\x03\x04"
_PICKLE_PROTO_OPCODE = b"\x80"

# Bounds ceiling for a safetensors JSON header — real headers are at most a
# few MiB even for huge multi-shard models (one small JSON dict of tensor
# metadata); this ceiling exists purely to bound worst-case parse time/memory
# against a hostile file claiming an absurd header length.
_MAX_SAFETENSORS_HEADER_BYTES = 64 * 1024 * 1024  # 64 MiB

# Red-council item #5: any conversion path that goes through HF
# `transformers` (e.g. `AutoConfig`/`AutoModel.from_pretrained` as part of
# `convert_hf_to_gguf.py`'s tokenizer/config loading) MUST hard-pin
# `trust_remote_code=False` — `trust_remote_code=True` executes arbitrary
# Python shipped in the repo, which is exactly the class of RCE this whole
# guard exists to prevent. `SubprocessConversionInvoker` honours this by
# never emitting any trust-remote-code flag on its argv; the isolated
# ephemeral job container is the backstop for anything the tool does
# internally despite that.
TRUST_REMOTE_CODE = False

# Mirrors `convert_provenance._CONVERT_TOOL_COMMIT_RE` / `_QUANT_RE` intent;
# `measure_conversion_tuple` re-validates both authoritatively — these early
# checks exist so a bad configuration fails at invoker construction/call
# time, before any subprocess ever runs.
_COMMIT_HEX_CHARS = frozenset("0123456789abcdef")


class PickleRefusedError(ValueError):
    """Raised when a source file is (or looks like) a pickle-based checkpoint.

    This is a hard security refusal, not a warning — pickle deserialization
    is remote/local code execution. There is no sandboxed path; the file is
    rejected outright, before any parse is attempted.
    """


class UnsupportedSourceFormatError(ValueError):
    """Raised for any source format that is neither safetensors nor a refused pickle format."""


class ConversionFailedError(RuntimeError):
    """Raised when the conversion tooling fails, times out, or produces no usable output."""


def _read_head(path: Path, n: int) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(n)


def guard_safetensors_only(path: Path) -> None:
    """Hard guard: raise unless `path` is a plausible, well-formed safetensors file.

    Red-council item #5: content-sniff is the AUTHORITATIVE check, not the
    file extension — a `.safetensors`-named file whose bytes are actually a
    pickle/ZIP checkpoint is refused regardless of its name, and (as
    defense-in-depth) the extension denylist/allowlist still runs as a
    SECOND, independent check afterwards.

    Order of checks:
      1. content-sniff (ZIP/pickle magic) -> refuse, regardless of extension;
      2. bounds-checked safetensors structural validation (8-byte length
         prefix must not exceed the real file size; the declared header
         must decode as UTF-8 JSON) -> refuse anything structurally invalid;
      3. extension denylist/allowlist -> a final naming-discipline check.
    """
    file_size = path.stat().st_size
    head = _read_head(path, 8)

    # 1. Content-sniff — authoritative, independent of the file's name.
    if head.startswith(_PICKLE_ZIP_MAGIC) or head.startswith(_PICKLE_PROTO_OPCODE):
        raise PickleRefusedError(
            f"{path.name}: file content looks like a pickle/ZIP checkpoint "
            f"(magic bytes {head[:4]!r}) — refused regardless of extension. "
            "Pickle deserialization is arbitrary code execution."
        )

    # 2. Bounds-checked safetensors structural validation.
    if len(head) < 8:
        raise UnsupportedSourceFormatError(f"{path.name}: too small to contain a safetensors header")
    header_len = int.from_bytes(head, byteorder="little", signed=False)
    if header_len <= 0 or header_len > _MAX_SAFETENSORS_HEADER_BYTES:
        raise UnsupportedSourceFormatError(
            f"{path.name}: safetensors header length {header_len} is out of bounds "
            f"(must be 1..{_MAX_SAFETENSORS_HEADER_BYTES})"
        )
    if 8 + header_len > file_size:
        raise UnsupportedSourceFormatError(
            f"{path.name}: safetensors header claims {header_len} bytes but the file is only "
            f"{file_size} bytes total (8 + {header_len} > {file_size}) — malformed/truncated"
        )
    with open(path, "rb") as fh:
        fh.seek(8)
        header_bytes = fh.read(header_len)
    try:
        header_json = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UnsupportedSourceFormatError(f"{path.name}: safetensors header is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(header_json, dict):
        raise UnsupportedSourceFormatError(f"{path.name}: safetensors header JSON is not an object")

    # 3. Extension denylist/allowlist — final naming-discipline check, run
    # AFTER content validation so it can never be the only gate.
    suffix = path.suffix.lower()
    if suffix in _REFUSED_EXTENSIONS:
        raise PickleRefusedError(
            f"{path.name}: PyTorch pickle-checkpoint extensions ({sorted(_REFUSED_EXTENSIONS)}) are "
            "refused outright even though content-sniff passed — naming discipline requires "
            "'.safetensors'. Convert to safetensors upstream before importing."
        )
    if suffix != _ACCEPTED_EXTENSION:
        raise UnsupportedSourceFormatError(
            f"{path.name}: only {_ACCEPTED_EXTENSION!r} is accepted for convert-to-GGUF (got {suffix!r})"
        )


def guard_convert_source_dir(root: Path) -> None:
    """Hard guard for a Hugging Face-style model directory used as a
    conversion source.

    Every file in the tree is checked, in the same trust order as
    `guard_safetensors_only`:

      - symlinks (file or directory) are refused outright — a symlink can
        smuggle bytes from outside the tree past both the guard and the
        source-tree digest;
      - every regular file is content-sniffed for pickle/ZIP magic first,
        regardless of its name — then weight files (`.safetensors`) get the
        full structural guard, and everything else must be on the aux-file
        extension allowlist (config/tokenizer JSON, merges/vocab text,
        sentencepiece `.model`, jinja, docs). Extension-less dotfiles
        (`.gitattributes` in a downloaded snapshot) pass on the sniff alone;
      - the directory must actually be a convertible model: at least one
        `.safetensors` shard and a root `config.json`, else
        `convert_hf_to_gguf.py` cannot work and the refusal happens here,
        clearly, instead of as a tool stack-trace.
    """
    if not root.is_dir():
        raise UnsupportedSourceFormatError(f"convert source is not a directory: {root}")
    safetensors_count = 0
    seen = 0
    for candidate in sorted(root.rglob("*")):
        if candidate.is_symlink():
            raise UnsupportedSourceFormatError(
                f"{candidate}: symlinks are refused inside a conversion source tree — a symlink "
                "can point outside the tree the guard and source digest cover"
            )
        if not candidate.is_file():
            continue
        seen += 1
        if seen > _MAX_SOURCE_TREE_FILES:
            raise UnsupportedSourceFormatError(
                f"{root}: more than {_MAX_SOURCE_TREE_FILES} files in conversion source tree — refused"
            )
        head = _read_head(candidate, 8)
        if head.startswith(_PICKLE_ZIP_MAGIC) or head.startswith(_PICKLE_PROTO_OPCODE):
            raise PickleRefusedError(
                f"{candidate.relative_to(root)}: file content looks like a pickle/ZIP checkpoint "
                f"(magic bytes {head[:4]!r}) — refused regardless of extension. "
                "Pickle deserialization is arbitrary code execution."
            )
        suffix = candidate.suffix.lower()
        if suffix == _ACCEPTED_EXTENSION:
            guard_safetensors_only(candidate)
            safetensors_count += 1
        elif suffix in _REFUSED_EXTENSIONS:
            raise PickleRefusedError(
                f"{candidate.relative_to(root)}: PyTorch pickle-checkpoint extensions "
                f"({sorted(_REFUSED_EXTENSIONS)}) are refused outright. Convert to safetensors "
                "upstream before importing."
            )
        elif suffix in _ALLOWED_AUX_EXTENSIONS:
            pass  # sniffed clean above; extension is on the aux allowlist
        elif suffix == "" and candidate.name.startswith("."):
            pass  # extension-less dotfile (e.g. .gitattributes) — sniffed clean above
        else:
            raise UnsupportedSourceFormatError(
                f"{candidate.relative_to(root)}: file type {suffix!r} is not on the conversion "
                f"source allowlist ({_ACCEPTED_EXTENSION!r} + {sorted(_ALLOWED_AUX_EXTENSIONS)})"
            )
    if safetensors_count == 0:
        raise UnsupportedSourceFormatError(f"{root}: no .safetensors weight files found — nothing to convert")
    if not (root / "config.json").is_file():
        raise UnsupportedSourceFormatError(
            f"{root}: no root config.json — convert_hf_to_gguf.py requires a Hugging Face-style model directory"
        )


class ConversionInvoker(ABC):
    """Abstraction over invoking llama.cpp's convert/quantize tooling.

    Design intent (council review §3b): the real implementation shells out
    to `convert_hf_to_gguf.py` + `llama-quantize` inside an isolated,
    ephemeral job — never in the long-running inference-serving process,
    and never with torch as a dependency of this control-plane package.
    """

    @property
    @abstractmethod
    def tool_commit(self) -> str:
        """Pinned commit hash of the convert tooling this invoker runs.

        Flows into the signed provenance tuple (`measure_conversion_tuple`
        validates it authoritatively) — never a release tag or branch name.
        """
        raise NotImplementedError

    @abstractmethod
    def convert(self, source_path: Path, *, out_dir: Path, quant: str) -> Path:
        """Convert a validated safetensors source into a GGUF file, return its path."""
        raise NotImplementedError


class StubConversionInvoker(ConversionInvoker):
    """Serving-process default — always refuses.

    Conversion never runs in the long-running serving process; a deploy
    wires `SubprocessConversionInvoker` only inside the isolated ephemeral
    convert job (see `kuroshio.convert_job`).
    """

    @property
    def tool_commit(self) -> str:
        # Never reachable through resolve(): convert() below raises before
        # any measurement can consume this.
        return "0000000"

    def convert(self, source_path: Path, *, out_dir: Path, quant: str) -> Path:
        raise NotImplementedError(
            "conversion is not wired in the serving process by design — run conversions via "
            "the isolated ephemeral convert job (kuroshio.convert_job), which wires "
            "SubprocessConversionInvoker explicitly."
        )


class SubprocessConversionInvoker(ConversionInvoker):
    """Real invoker: `convert_hf_to_gguf.py` (f16) then `llama-quantize` (quant).

    Both steps run as argv-list subprocesses — no shell, no
    trust-remote-code flag ever emitted (`TRUST_REMOTE_CODE` contract), a
    hard-set offline environment, a hard wall-clock timeout each, and
    stderr captured (bounded) into `ConversionFailedError` on failure.
    Process-level flags are defence-in-depth: the production boundary is
    the network-denied ephemeral job container this runs inside.
    """

    def __init__(
        self,
        *,
        convert_script: Path,
        quantize_binary: Path,
        tool_commit: str,
        python_binary: str | None = None,
        timeout_seconds: float = 3600.0,
        run: Any = subprocess.run,
    ) -> None:
        commit = tool_commit.strip().lower()
        if not (7 <= len(commit) <= 40) or not set(commit) <= _COMMIT_HEX_CHARS:
            raise ValueError(
                f"tool_commit {tool_commit!r} is not a pinned commit hash (7-40 hex chars) — "
                "a release tag or branch name is refused; pin the exact commit"
            )
        if timeout_seconds <= 0:
            raise ValueError(f"timeout_seconds must be positive, got {timeout_seconds!r}")
        self._convert_script = Path(convert_script)
        self._quantize_binary = Path(quantize_binary)
        self._tool_commit = commit
        self._python_binary = python_binary or sys.executable
        self._timeout_seconds = timeout_seconds
        self._run = run

    @property
    def tool_commit(self) -> str:
        return self._tool_commit

    def _run_step(self, argv: list[str], *, step: str, cwd: Path) -> None:
        env = {
            # Hard-set offline: the convert tool must never reach for the
            # network mid-conversion (the job container denies it anyway —
            # this makes the tool fail fast + honestly instead of hanging).
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        }
        try:
            result = self._run(
                argv,
                capture_output=True,
                timeout=self._timeout_seconds,
                env=env,
                cwd=str(cwd),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ConversionFailedError(
                f"{step}: exceeded the {self._timeout_seconds:.0f}s conversion timeout — killed"
            ) from exc
        if result.returncode != 0:
            stderr = result.stderr or b""
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            raise ConversionFailedError(f"{step}: exit code {result.returncode}; stderr tail: {stderr[-2000:]}")

    def convert(self, source_path: Path, *, out_dir: Path, quant: str) -> Path:
        if not quant.strip() or len(quant) > 32 or not quant.replace("_", "").isalnum():
            raise ValueError(f"quant {quant!r} failed the allowlist guard")
        if not self._convert_script.is_file():
            raise ConversionFailedError(f"convert script not found: {self._convert_script}")
        if not self._quantize_binary.is_file():
            raise ConversionFailedError(f"quantize binary not found: {self._quantize_binary}")
        out_dir.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="convert-", dir=out_dir))
        try:
            f16_path = work / "intermediate.f16.gguf"
            out_path = work / f"converted.{quant}.gguf"
            self._run_step(
                [
                    self._python_binary,
                    str(self._convert_script),
                    str(source_path),
                    "--outfile",
                    str(f16_path),
                    "--outtype",
                    "f16",
                ],
                step="convert_hf_to_gguf",
                cwd=work,
            )
            if not f16_path.is_file() or f16_path.stat().st_size == 0:
                raise ConversionFailedError("convert_hf_to_gguf: exit code 0 but produced no f16 GGUF output")
            self._run_step(
                [str(self._quantize_binary), str(f16_path), str(out_path), quant],
                step="llama-quantize",
                cwd=work,
            )
            f16_path.unlink(missing_ok=True)  # scratch hygiene — only the quantized artifact leaves
            if not out_path.is_file() or out_path.stat().st_size == 0:
                raise ConversionFailedError("llama-quantize: exit code 0 but produced no quantized GGUF output")
            return out_path
        except BaseException:
            # A failed conversion never leaves scratch behind — the work dir
            # only outlives this call when it holds the produced artifact.
            shutil.rmtree(work, ignore_errors=True)
            raise


class ConvertAdapter(SourceAdapter):
    """Safetensors -> GGUF adapter: guard -> convert -> measure -> ingest."""

    def __init__(self, blob_store: Any, invoker: ConversionInvoker | None = None) -> None:
        super().__init__(blob_store)
        self._invoker = invoker or StubConversionInvoker()

    def resolve(self, *, source_path: Path, quant: str = "Q4_K_M", **_: Any) -> ResolvedModel:  # type: ignore[override]
        source_path = Path(source_path)

        # The hard guard runs unconditionally, before the invoker is ever
        # reached — a caller cannot bypass it by swapping invokers.
        if source_path.is_dir():
            guard_convert_source_dir(source_path)
        elif source_path.is_file():
            guard_safetensors_only(source_path)
        else:
            raise FileNotFoundError(f"convert source not found: {source_path}")

        out_dir = self.blob_store.root / "scratch" / "convert"
        out_dir.mkdir(parents=True, exist_ok=True)
        gguf_path = Path(self._invoker.convert(source_path, out_dir=out_dir, quant=quant))
        try:
            # Containment: the produced artifact must live under the scratch
            # dir this adapter handed the invoker — an invoker returning a
            # path elsewhere (e.g. into the live blob area) is refused.
            if out_dir.resolve() not in gguf_path.resolve().parents:
                raise ConversionFailedError(f"invoker returned a path outside the conversion scratch dir: {gguf_path}")
            if not gguf_path.is_file():
                raise ConversionFailedError(f"invoker returned a non-file: {gguf_path}")

            # Nico finding #4: measure the whole tuple from actual bytes, in
            # this same process, before any hand-off (TOCTOU) — and validate
            # this is really a GGUF (first-parse jail seam) before ingesting.
            measurement = measure_conversion_tuple(
                source_path,
                gguf_path,
                convert_tool_commit=self._invoker.tool_commit,
                quant=quant,
            )
            header = self._first_parse_gguf_header(gguf_path)

            metadata = {
                "family": header.architecture,
                "name": header.name or source_path.stem,
                "parameter_size": header.parameter_size_label(),
                "quantization_level": header.quantization_level,
                "gguf_version": header.version,
                "chat_template": header.chat_template,
                "license": header.license,
            }
            provenance = Provenance(
                kind=ProvenanceKind.CONVERTED,
                origin=str(source_path.resolve()),
                sha256=measurement.output_sha256,
                operator_supplied=True,
                extra={
                    # Red-team finding #5: a converted artifact is honestly a
                    # step further removed than a counter-signed HF pull.
                    "provenance_tier": "converted-derived",
                    "conversion": {
                        "source_sha256": measurement.source_sha256,
                        "convert_tool_commit": measurement.convert_tool_commit,
                        "quant": measurement.quant,
                        "output_sha256": measurement.output_sha256,
                    },
                },
            )
            # `expected_sha256` makes the blob store re-hash the bytes it
            # actually copies — a swap between measurement and ingestion
            # fails the put instead of laundering substituted bytes.
            return self.blob_store.put_from_path(
                gguf_path,
                metadata=metadata,
                provenance=provenance,
                expected_sha256=measurement.output_sha256,
            )
        finally:
            # The invoker's per-conversion scratch dir (parent of the
            # produced artifact when the real invoker ran) never outlives
            # the resolve — the ingested blob-store copy is the only output.
            if out_dir.resolve() in gguf_path.resolve().parents and gguf_path.parent != out_dir:
                shutil.rmtree(gguf_path.parent, ignore_errors=True)


__all__ = [
    "ConversionInvoker",
    "StubConversionInvoker",
    "SubprocessConversionInvoker",
    "ConvertAdapter",
    "ConversionFailedError",
    "PickleRefusedError",
    "UnsupportedSourceFormatError",
    "guard_safetensors_only",
    "guard_convert_source_dir",
    "TRUST_REMOTE_CODE",
]
