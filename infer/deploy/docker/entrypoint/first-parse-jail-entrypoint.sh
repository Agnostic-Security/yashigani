#!/bin/sh
# First-parse jail entrypoint — invocation contract documented in
# Dockerfile.kuroshio-first-parse-jail. Reads raw GGUF header bytes from stdin (bounded to 8 MiB
# — a real GGUF header/metadata/tensor-info section for any model in the wild is well under
# this; a hostile input trying to exhaust jail memory via an oversized stdin stream is capped
# HERE, at the shell layer, before a single byte reaches the Python parser), invokes the
# existing pure-Python defensive parser, emits a JSON verdict on stdout, and exits.
#
# This container has --network=none and a seccomp-strict profile (kuroshio-first-parse-jail.json)
# applied by the invoking orchestrator (compose `invoke-first-parse-jail` service / k8s
# job-first-parse-jail.yaml) — this script does not and cannot enforce those itself; it is the
# in-container half of the control, not the whole control.

set -eu

MAX_HEADER_BYTES=8388608  # 8 MiB

python3 - "${MAX_HEADER_BYTES}" <<'PYEOF'
import json
import sys

max_bytes = int(sys.argv[1])
raw = sys.stdin.buffer.read(max_bytes + 1)
if len(raw) > max_bytes:
    print(json.dumps({"ok": False, "error": "header_exceeds_jail_size_ceiling"}))
    sys.exit(0)

try:
    from kuroshio.gguf.header import GGUFParseError, parse_gguf_header

    header = parse_gguf_header(raw, parse_tensors=True)
    print(
        json.dumps(
            {
                "ok": True,
                "header": {
                    "version": header.version,
                    "tensor_count": header.tensor_count,
                    "architecture": header.architecture,
                    "name": header.name,
                    "quantization_level": header.quantization_level,
                    "parameter_size_label": header.parameter_size_label(),
                },
            }
        )
    )
except GGUFParseError as exc:
    # Structural refusal — a clean, expected outcome for a malformed/hostile file.
    # Never leak the raw exception message verbatim to the wire (could echo attacker-
    # controlled bytes back); classify to a fixed error tag instead.
    print(json.dumps({"ok": False, "error": "gguf_parse_error", "detail_class": type(exc).__name__}))
except Exception as exc:  # noqa: BLE001 - jail boundary: any other failure is "unsafe", not a crash we propagate
    print(json.dumps({"ok": False, "error": "unexpected_parse_failure", "detail_class": type(exc).__name__}))
PYEOF
