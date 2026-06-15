#!/usr/bin/env python3
"""
check_counter_key_rotation.py — MC-02 treadmill gate (2026-06-15)

Verifies that COUNTER_PUBLIC_KEY_PEM in the current working tree's _integrity.py
differs from the value embedded in the previous release tag.

Fails with exit code 1 (prints a clear error) if:
  - The counter key is identical to the previous release tag's value.
  - Either value is still a placeholder sentinel.
  - The previous tag's _integrity.py cannot be read via `git show`.

Passes (exit 0) if:
  - The counter key has been rotated (differs from the previous release tag).
  - No previous release tag exists (first release — no comparison possible).

Usage:
    python scripts/check_counter_key_rotation.py [PREV_RELEASE_TAG] [INTEGRITY_PY_RELPATH]

    PREV_RELEASE_TAG    — git tag to compare against (default: most recent vX.Y.Z tag).
    INTEGRITY_PY_RELPATH — path to _integrity.py relative to repo root
                           (default: src/yashigani/licensing/_integrity.py).

Invoked by:
    make check-counter-key-rotation
    (or directly in CI: python scripts/check_counter_key_rotation.py)

Treadmill guarantee:
    Without this gate, a release engineer could forget to rotate the counter key
    and the build pipeline would proceed silently — the treadmill stalls, and a
    bypass recipe developed against release N carries forward into N+1.
    This gate closes that gap (Laura T10 / T16 finding, key-management-threat-model-20260615.md).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

SENTINEL = "PLACEHOLDER_YASHIGANI_INTEGRITY"
# Also match the Python-expression form used in source control:
#   COUNTER_PUBLIC_KEY_PEM: str = _PLACEHOLDER_INTEGRITY + "_COUNTER_KEY"
# where _PLACEHOLDER_INTEGRITY is the Python variable holding the sentinel string.
SENTINEL_EXPR = "_PLACEHOLDER_INTEGRITY"


def _is_placeholder(value: str) -> bool:
    """Return True if the extracted value is a placeholder in any form."""
    return SENTINEL in value or SENTINEL_EXPR in value
DEFAULT_INTEGRITY_PATH = "src/yashigani/licensing/_integrity.py"


def _find_previous_release_tag() -> str | None:
    """
    Return the most recent vX.Y.Z annotated git tag, or None if none exists.
    """
    try:
        out = subprocess.check_output(
            ["git", "tag", "--sort=-version:refname"],
            text=True,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        print(f"[MC-02] WARNING: git tag listing failed: {exc.stderr.strip()}", file=sys.stderr)
        return None

    for line in out.splitlines():
        tag = line.strip()
        if re.fullmatch(r"v\d+\.\d+\.\d+", tag):
            return tag
    return None


def _extract_counter_key_value(content: str) -> str:
    """
    Extract the RHS of the COUNTER_PUBLIC_KEY_PEM assignment from file content.

    Handles both placeholder expressions and injected triple-quoted PEM blocks.
    Returns the raw matched value string (not evaluated Python).
    """
    # Triple-quoted multi-line form (injected by build pipeline):
    # COUNTER_PUBLIC_KEY_PEM: str = """\
    # -----BEGIN PUBLIC KEY-----
    # ...
    # -----END PUBLIC KEY-----
    # """
    m = re.search(
        r'^COUNTER_PUBLIC_KEY_PEM\s*:\s*str\s*=\s*"""\\?\n(.*?)\n"""',
        content,
        re.MULTILINE | re.DOTALL,
    )
    if m:
        return m.group(1).strip()

    # Single-line form (placeholder or simple quoted string):
    # COUNTER_PUBLIC_KEY_PEM: str = "..."
    # COUNTER_PUBLIC_KEY_PEM: str = _PLACEHOLDER_INTEGRITY + "_COUNTER_KEY"
    m = re.search(
        r'^COUNTER_PUBLIC_KEY_PEM\s*:\s*str\s*=\s*(.*)$',
        content,
        re.MULTILINE,
    )
    if m:
        return m.group(1).strip()

    raise ValueError("COUNTER_PUBLIC_KEY_PEM constant not found in file")


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    prev_tag_arg = argv[0] if len(argv) > 0 else ""
    integrity_relpath = argv[1] if len(argv) > 1 else DEFAULT_INTEGRITY_PATH

    # Determine the previous release tag.
    if prev_tag_arg:
        prev_tag: str | None = prev_tag_arg
    else:
        prev_tag = _find_previous_release_tag()

    if not prev_tag:
        print("[MC-02] No previous release tag found — this appears to be the first release.")
        print("[MC-02] PASS (no previous tag to compare against).")
        return 0

    print(f"[MC-02] Comparing COUNTER_PUBLIC_KEY_PEM against tag: {prev_tag}")
    print(f"[MC-02] Integrity file: {integrity_relpath}")

    # Read the previous tag's _integrity.py via git show.
    try:
        prev_content = subprocess.check_output(
            ["git", "show", f"{prev_tag}:{integrity_relpath}"],
            text=True,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        print(
            f"[MC-02] ERROR: could not read {integrity_relpath} from tag {prev_tag}: "
            f"{exc.stderr.strip()}",
            file=sys.stderr,
        )
        return 1

    # Read the current working tree's _integrity.py.
    curr_path = Path(integrity_relpath)
    if not curr_path.exists():
        print(
            f"[MC-02] ERROR: {integrity_relpath} not found in working tree.",
            file=sys.stderr,
        )
        return 1
    curr_content = curr_path.read_text(encoding="utf-8")

    # Extract the counter public key value from each.
    try:
        prev_key = _extract_counter_key_value(prev_content)
    except ValueError as exc:
        print(f"[MC-02] ERROR: in tag {prev_tag}: {exc}", file=sys.stderr)
        return 1

    try:
        curr_key = _extract_counter_key_value(curr_content)
    except ValueError as exc:
        print(f"[MC-02] ERROR: in working tree: {exc}", file=sys.stderr)
        return 1

    # Fail if either is a placeholder.
    if _is_placeholder(prev_key):
        print(
            f"[MC-02] ERROR: COUNTER_PUBLIC_KEY_PEM in tag {prev_tag} is still a placeholder — "
            "build pipeline may not have run for that release.",
            file=sys.stderr,
        )
        return 1

    if _is_placeholder(curr_key):
        print(
            "[MC-02] ERROR: COUNTER_PUBLIC_KEY_PEM in working tree is still a placeholder — "
            "run the build pipeline (inject_hashes.sh) first.",
            file=sys.stderr,
        )
        return 1

    # The core check: fail if the keys are identical.
    if prev_key == curr_key:
        print(
            f"[MC-02] FAIL: COUNTER_PUBLIC_KEY_PEM is IDENTICAL to the value in {prev_tag}.",
            file=sys.stderr,
        )
        print(
            "[MC-02]   The counter key has NOT been rotated for this release.",
            file=sys.stderr,
        )
        print(
            "[MC-02]   Fix:\n"
            "[MC-02]     1. python scripts/keygen.py --out-dir keys/ --force\n"
            "[MC-02]     2. Embed the new counter public key in _integrity.py "
            "(COUNTER_PUBLIC_KEY_PEM).\n"
            "[MC-02]     3. Re-run the build pipeline: bash scripts/inject_hashes.sh\n"
            "[MC-02]     4. Re-run: make check-counter-key-rotation",
            file=sys.stderr,
        )
        return 1

    print(
        f"[MC-02] PASS: COUNTER_PUBLIC_KEY_PEM differs from {prev_tag} — "
        "counter key has been rotated."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
