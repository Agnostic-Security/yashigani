#!/usr/bin/env python3
"""
lib/pki_ownership_append.py — Idempotent PKI ownership map mutator.

S1 (SHIP-BLOCKER): mutates lib/pki_ownership.sh via Python file-rewrite,
NOT via sed, to avoid the macOS BSD vs GNU sed -i trap.

Idempotent EXACT-string match:
  - "letta" must NOT match "letta-pgbouncer"
  - Only exact service-name equality is used.
  - Running twice with the same arguments is a no-op.

Security:
  - Output file mode is preserved (or set to 0600 if new entry would be
    world-readable — S1 CWE-732 prevention).
  - Warns on overlap: if a service with the same name already exists with
    a different UID or mode, logs a WARNING but does not overwrite silently
    (operator must either pass --force-update or match exactly).

Usage:
  python3 lib/pki_ownership_append.py \\
      --service <name> --uid <uid> --mode <mode> \\
      [--force-update] [--lib lib/pki_ownership.sh]

  python3 lib/pki_ownership_append.py \\
      --remove <name> [--lib lib/pki_ownership.sh]

Exit codes:
  0   — success (appended or already present and matching)
  1   — error (mode forbidden, conflict without --force-update, file error)
  2   — service removed successfully
  3   — remove: service not found (not an error — idempotent)

Last updated: 2026-05-29T00:00:00+00:00 (feat(p1-w4): S1 idempotent PKI map mutator)
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Pattern for a valid tuple entry in _YSG_PKI_SERVICE_MAP.
# Format: "  \"<service>:<uid>:<mode>\""
# The entry may have leading spaces and uses exact double-quoted string.
_ENTRY_RE = re.compile(
    r'^(?P<indent>[ \t]*)"(?P<service>[A-Za-z0-9_-]+):(?P<uid>\d+):(?P<mode>0\d{3})"',
    re.MULTILINE,
)

# Sentinel comments that bracket the _YSG_PKI_SERVICE_MAP array.
_MAP_OPEN  = "_YSG_PKI_SERVICE_MAP=("
_MAP_CLOSE = ")"

# Allowed modes — S1: never 0644 or any world-readable mode.
_ALLOWED_MODES = frozenset({"0600", "0640", "0400", "0440"})

# Sentinel comment for onboarded (codegen-managed) entries.
# BEGIN/END brackets an agent's tuple in the map.
_SENTINEL_BEGIN = "  # BEGIN YSG-ONBOARD-{service}"
_SENTINEL_END   = "  # END YSG-ONBOARD-{service}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_mode(mode: str) -> None:
    """Reject any mode not in _ALLOWED_MODES (S1 — CWE-732 prevention)."""
    if mode not in _ALLOWED_MODES:
        raise ValueError(
            "S1 CWE-732: mode %r is not in the allowed set %s. "
            "Never use 0644 or any world-readable mode for PKI keys." % (
                mode, sorted(_ALLOWED_MODES))
        )


def _validate_service_name(name: str) -> None:
    """Reject service names with shell metacharacters."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
        raise ValueError(
            "service name %r contains illegal characters; "
            "only [A-Za-z0-9_-] are permitted." % name
        )


def _find_existing_entry(content: str, service: str) -> Optional[re.Match]:
    """
    Find the EXACT-match tuple entry for <service> in the map body.

    EXACT-STRING match: "letta" must NOT match "letta-pgbouncer".
    We scan for '"<service>:<uid>:<mode>"' where <service> is surrounded by
    the double-quote and colon delimiters.
    """
    pattern = re.compile(
        r'"' + re.escape(service) + r':\d+:0\d{3}"',
        re.MULTILINE,
    )
    return pattern.search(content)


def _find_sentinel_range(content: str, service: str) -> Optional[tuple[int, int]]:
    """
    Return (start, end) byte offsets for the BEGIN/END sentinel block for
    this service, or None if no sentinel block exists.
    """
    begin_marker = "# BEGIN YSG-ONBOARD-%s" % service
    end_marker   = "# END YSG-ONBOARD-%s"   % service

    begin_pos = content.find(begin_marker)
    if begin_pos == -1:
        return None

    # Find the start of the line containing BEGIN
    line_start = content.rfind("\n", 0, begin_pos) + 1

    end_pos = content.find(end_marker, begin_pos)
    if end_pos == -1:
        # Malformed — sentinel BEGIN without END; log and treat as not found.
        _log.warning(
            "Malformed sentinel: BEGIN YSG-ONBOARD-%s found but no END — "
            "treating as absent (manual cleanup required).", service
        )
        return None

    # Include the newline after END marker line.
    end_line_end = content.find("\n", end_pos)
    if end_line_end == -1:
        end_line_end = len(content)
    else:
        end_line_end += 1  # include the newline

    return line_start, end_line_end


def _map_body_end(content: str) -> Optional[int]:
    """
    Return the byte offset of the closing ')' of _YSG_PKI_SERVICE_MAP.
    Returns None if the map is not found.
    """
    open_pos = content.find(_MAP_OPEN)
    if open_pos == -1:
        return None
    # Find the ')' that closes the array.
    # The closing paren is on its own line per the existing format.
    close_pos = content.find("\n)", open_pos)
    if close_pos == -1:
        return None
    # Return position of the '\n' before ')' so insertion lands just before.
    return close_pos  # points to the '\n' before ')'


def _build_entry_block(service: str, uid: int, mode: str, comment: Optional[str]) -> str:
    """
    Build the sentinel-bracketed entry block to insert into the map.

    Format:
      # BEGIN YSG-ONBOARD-<service>
      # <comment> (if provided)
      "<service>:<uid>:<mode>"
      # END YSG-ONBOARD-<service>
    """
    lines = ["  # BEGIN YSG-ONBOARD-%s" % service]
    if comment:
        for cl in comment.splitlines():
            lines.append("  # %s" % cl)
    lines.append('  "%s:%d:%s"' % (service, uid, mode))
    lines.append("  # END YSG-ONBOARD-%s" % service)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main operations
# ---------------------------------------------------------------------------

def append_entry(
    lib_path: Path,
    service: str,
    uid: int,
    mode: str,
    comment: Optional[str] = None,
    force_update: bool = False,
) -> int:
    """
    Append or idempotently update an entry for <service> in lib_path.

    Returns:
      0 — success (appended, or already present and matching — no-op)
      1 — error
    """
    _validate_mode(mode)
    _validate_service_name(service)

    content = lib_path.read_text(encoding="utf-8")

    # --- Check for overlap (exact service name already in map) ---
    existing = _find_existing_entry(content, service)
    if existing:
        existing_str = existing.group(0)
        expected_str = '"%s:%d:%s"' % (service, uid, mode)
        if existing_str == expected_str:
            _log.info(
                "pki_ownership_append: service %r already present with matching "
                "uid=%d mode=%s — no-op (idempotent).", service, uid, mode
            )
            return 0
        else:
            # Conflict: service exists with different uid or mode.
            if not force_update:
                _log.error(
                    "pki_ownership_append: OVERLAP — service %r already exists as %s; "
                    "requested uid=%d mode=%s. "
                    "Pass --force-update to overwrite, or check for a pre-existing "
                    "0644 multi-UID secret (S1 CWE-732).",
                    service, existing_str, uid, mode,
                )
                return 1
            # force_update: replace the sentinel block (or inline entry).
            _log.warning(
                "pki_ownership_append: --force-update: replacing existing %s entry "
                "with uid=%d mode=%s.", service, existing_str, uid, mode
            )
            sentinel_range = _find_sentinel_range(content, service)
            if sentinel_range:
                start, end = sentinel_range
                new_block = _build_entry_block(service, uid, mode, comment)
                content = content[:start] + new_block + content[end:]
            else:
                # No sentinel — replace the inline entry line.
                new_entry = '"%s:%d:%s"' % (service, uid, mode)
                content = content.replace(existing_str, new_entry, 1)

            _write_atomically(lib_path, content)
            _log.info(
                "pki_ownership_append: updated entry for %r (uid=%d mode=%s).",
                service, uid, mode,
            )
            return 0

    # --- No existing entry — append inside the sentinel block ---
    insert_pos = _map_body_end(content)
    if insert_pos is None:
        _log.error(
            "pki_ownership_append: _YSG_PKI_SERVICE_MAP not found in %s.", lib_path
        )
        return 1

    new_block = _build_entry_block(service, uid, mode, comment)
    content = content[:insert_pos] + new_block + content[insert_pos:]

    _write_atomically(lib_path, content)
    _log.info(
        "pki_ownership_append: appended entry for %r (uid=%d mode=%s).",
        service, uid, mode,
    )
    return 0


def remove_entry(lib_path: Path, service: str) -> int:
    """
    Remove the sentinel-bracketed entry for <service> from lib_path.

    Returns:
      2 — service removed successfully
      3 — service not found (idempotent — not an error)
      1 — error
    """
    _validate_service_name(service)

    content = lib_path.read_text(encoding="utf-8")

    sentinel_range = _find_sentinel_range(content, service)
    if sentinel_range is None:
        # Check if there's an inline (non-sentinel) entry — refuse to
        # remove non-sentinel entries (those are core services, not onboarded agents).
        existing = _find_existing_entry(content, service)
        if existing:
            _log.error(
                "pki_ownership_append: service %r has an inline entry (not sentinel-managed). "
                "Core services cannot be removed via offboard. "
                "Remove manually if this is intentional.", service
            )
            return 1
        _log.info(
            "pki_ownership_append: service %r not found — already removed (idempotent).",
            service
        )
        return 3

    start, end = sentinel_range
    content = content[:start] + content[end:]

    _write_atomically(lib_path, content)
    _log.info("pki_ownership_append: removed sentinel entry for %r.", service)
    return 2


def _write_atomically(path: Path, content: str) -> None:
    """
    Write content to path atomically (temp + rename) with preserved permissions.

    S1: never widen permissions — copy the original mode; if the file is
    new, set 0600 explicitly (never inherit umask which could be 0022).
    """
    # Preserve original file mode
    try:
        orig_mode = path.stat().st_mode & 0o777
    except FileNotFoundError:
        orig_mode = 0o600

    # Atomic write via temp file in same directory
    dir_path = path.parent
    fd, tmp_path_str = tempfile.mkstemp(
        dir=str(dir_path),
        prefix=".ysg-pki-tmp-",
        suffix=".sh",
    )
    try:
        os.write(fd, content.encode("utf-8"))
        os.close(fd)
        fd = -1
        # Apply original mode to temp file before rename
        os.chmod(tmp_path_str, orig_mode)
        # Atomic rename
        os.rename(tmp_path_str, str(path))
    except Exception:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp_path_str)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Idempotent PKI ownership map mutator (S1 — Python file-rewrite, "
            "not sed). Appends or removes entries from lib/pki_ownership.sh."
        )
    )
    p.add_argument(
        "--lib",
        default="lib/pki_ownership.sh",
        help="Path to lib/pki_ownership.sh (default: lib/pki_ownership.sh)",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    sub = p.add_subparsers(dest="subcmd")

    # append subcommand
    ap = sub.add_parser("append", help="Append or idempotently update an entry")
    ap.add_argument("--service", required=True, help="Service name (exact match)")
    ap.add_argument("--uid",     required=True, type=int, help="Container UID")
    ap.add_argument("--mode",    required=True, help="Key file mode (0600, 0640, 0400, 0440)")
    ap.add_argument("--comment", default=None,  help="Optional comment line to include")
    ap.add_argument(
        "--force-update",
        action="store_true",
        help="Replace an existing entry even if uid/mode differ (warns on overlap)",
    )

    # remove subcommand
    rp = sub.add_parser("remove", help="Remove a sentinel-managed entry")
    rp.add_argument("--service", required=True, help="Service name (exact match)")

    return p


def main(argv: Optional[list[str]] = None) -> int:
    p = _build_parser()
    args = p.parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="[pki_append] %(levelname)s: %(message)s")

    lib_path = Path(args.lib)
    if not lib_path.is_file():
        _log.error("lib file not found: %s", lib_path)
        return 1

    if args.subcmd == "append":
        try:
            return append_entry(
                lib_path,
                service=args.service,
                uid=args.uid,
                mode=args.mode,
                comment=args.comment,
                force_update=args.force_update,
            )
        except ValueError as exc:
            _log.error("%s", exc)
            return 1

    elif args.subcmd == "remove":
        try:
            return remove_entry(lib_path, service=args.service)
        except ValueError as exc:
            _log.error("%s", exc)
            return 1

    else:
        p.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
