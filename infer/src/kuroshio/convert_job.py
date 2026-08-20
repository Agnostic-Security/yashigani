# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Ephemeral convert-job entry — `python -m kuroshio.convert_job`.

The ONLY sanctioned way to run a real safetensors -> GGUF conversion in
production (council review §3b + Nico finding #4): an isolated, ephemeral,
network-denied job container runs this module, which

  1. guards the source (pickle refusal, structural safetensors validation,
     symlink refusal — `adapters/convert.py`),
  2. invokes `convert_hf_to_gguf.py` + `llama-quantize` via
     `SubprocessConversionInvoker` (argv-list, offline env, hard timeout,
     never any trust-remote-code flag),
  3. measures the `(source, tool_commit, quant, output)` provenance tuple
     from actual bytes IN THIS SAME PROCESS, before teardown (TOCTOU), and
  4. writes the produced GGUF plus `conversion-measurement.json` to
     `--out-dir` and a machine-readable result object to stdout.

Signing the measured tuple into a `ConvertedManifestEntry` is the NEXT step
in the SAME job (`scripts/manifest_signer.py`, chained by the job
entrypoint) — mint-side key custody stays out of this runtime package, so
this module emits the unsigned measurement only.

The long-running serving process never converts anything: `ConvertAdapter`
defaults to `StubConversionInvoker`, and nothing in the ASGI app imports
this module.

Exit codes: 0 success; 2 source refused by the security guard;
3 conversion tooling failed/timed out; 4 bad usage or configuration.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from kuroshio.adapters.convert import (
    ConversionFailedError,
    PickleRefusedError,
    SubprocessConversionInvoker,
    UnsupportedSourceFormatError,
    guard_convert_source_dir,
    guard_safetensors_only,
)
from kuroshio.convert_provenance import measure_conversion_tuple, measure_source_digest

_ENV_CONVERT_SCRIPT = "YSG_KUROSHIO_CONVERT_SCRIPT"
_ENV_QUANTIZE_BIN = "YSG_KUROSHIO_QUANTIZE_BIN"
_ENV_TOOL_COMMIT = "YSG_KUROSHIO_CONVERT_TOOL_COMMIT"
_ENV_TIMEOUT_SECONDS = "YSG_KUROSHIO_CONVERT_TIMEOUT_SECONDS"

EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_CONVERSION_FAILED = 3
EXIT_USAGE = 4


def _fail(code: int, message: str) -> int:
    print(json.dumps({"status": "error", "error": message}), file=sys.stderr)
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="kuroshio.convert_job",
        description="Guarded safetensors -> GGUF conversion inside an ephemeral job.",
    )
    parser.add_argument("--source", required=True, help="safetensors file or HF-style model directory")
    parser.add_argument("--out-dir", required=True, help="directory the GGUF + measurement JSON land in")
    parser.add_argument("--quant", default="Q4_K_M", help="llama-quantize type (default Q4_K_M)")
    parser.add_argument(
        "--measurement-out",
        default=None,
        help="measurement JSON path (default <out-dir>/conversion-measurement.json)",
    )
    args = parser.parse_args(argv)

    convert_script = os.environ.get(_ENV_CONVERT_SCRIPT, "")
    quantize_binary = os.environ.get(_ENV_QUANTIZE_BIN, "")
    tool_commit = os.environ.get(_ENV_TOOL_COMMIT, "")
    if not convert_script or not quantize_binary or not tool_commit:
        return _fail(
            EXIT_USAGE,
            f"missing required env: {_ENV_CONVERT_SCRIPT}, {_ENV_QUANTIZE_BIN}, {_ENV_TOOL_COMMIT} "
            "must all be set (the job image pins these)",
        )
    try:
        timeout_seconds = float(os.environ.get(_ENV_TIMEOUT_SECONDS, "3600"))
    except ValueError:
        return _fail(EXIT_USAGE, f"{_ENV_TIMEOUT_SECONDS} is not a number")

    source = Path(args.source)
    out_dir = Path(args.out_dir)
    measurement_out = Path(args.measurement_out) if args.measurement_out else out_dir / "conversion-measurement.json"

    try:
        invoker = SubprocessConversionInvoker(
            convert_script=Path(convert_script),
            quantize_binary=Path(quantize_binary),
            tool_commit=tool_commit,
            timeout_seconds=timeout_seconds,
        )
    except ValueError as exc:
        return _fail(EXIT_USAGE, str(exc))

    # 1. Guard — the refusal path, before any tool runs.
    try:
        if source.is_dir():
            guard_convert_source_dir(source)
        elif source.is_file():
            guard_safetensors_only(source)
        else:
            return _fail(EXIT_USAGE, f"convert source not found: {source}")
    except (PickleRefusedError, UnsupportedSourceFormatError) as exc:
        return _fail(EXIT_REFUSED, str(exc))

    # Laura KUROSHIO60-001 (TOCTOU): measure the source digest here, between
    # guard and conversion — not re-walked at teardown — so a mid-conversion
    # source swap cannot write a false `source_sha256` into the signed
    # record. The job image's source mount must be read-only for the guard's
    # symlink refusal to hold across the conversion (deploy/README.md).
    try:
        source_sha256 = measure_source_digest(source)
    except ValueError as exc:
        return _fail(EXIT_REFUSED, str(exc))

    # 2. Convert + 3. measure — same process, before teardown (finding #4).
    try:
        gguf_path = invoker.convert(source, out_dir=out_dir, quant=args.quant)
        measurement = measure_conversion_tuple(
            source,
            gguf_path,
            convert_tool_commit=invoker.tool_commit,
            quant=args.quant,
            source_sha256=source_sha256,
        )
    except (ConversionFailedError, ValueError) as exc:
        return _fail(EXIT_CONVERSION_FAILED, str(exc))

    # 4. Emit — measurement sidecar + result object for the job entrypoint
    # (which chains scripts/manifest_signer.py over the measurement next).
    measurement_dict = {
        "source_sha256": measurement.source_sha256,
        "convert_tool_commit": measurement.convert_tool_commit,
        "quant": measurement.quant,
        "output_sha256": measurement.output_sha256,
    }
    measurement_out.parent.mkdir(parents=True, exist_ok=True)
    measurement_out.write_text(json.dumps(measurement_dict, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "status": "success",
                "gguf_path": str(gguf_path),
                "measurement_path": str(measurement_out),
                **measurement_dict,
            }
        )
    )
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover — exercised via main() in tests
    raise SystemExit(main())
