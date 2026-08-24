#!/usr/bin/env bash
# scripts/check-version-consistency.sh
#
# Council remediation (2026-07-15, Tiago-approved) — mechanical Phase-1 win.
#
# Fails if pyproject.toml [project].version != src/yashigani/__init__.py
# __version__. Catches the "v4.1.0-on-4.0.0-pyproject" wart class one PR
# early instead of at release-tag time. Run as a pre-commit hook (triggers
# on pyproject.toml / __init__.py changes) and as a CI step on every PR.
#
# Plain-regex parse (no tomllib dependency) so this runs under any Python
# 3.x found on PATH, not just the project's >=3.12 venv interpreter —
# mirrors src/tests/unit/test_version.py's parsing approach.

set -euo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"

"$PYTHON_BIN" - "$REPO_ROOT" <<'PY'
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])

pyproject_text = (repo_root / "pyproject.toml").read_text()
pyproject_match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject_text, re.MULTILINE)
if not pyproject_match:
    print("FAIL: version not found in pyproject.toml", file=sys.stderr)
    sys.exit(1)
pyproject_version = pyproject_match.group(1)

init_text = (repo_root / "src" / "yashigani" / "__init__.py").read_text()
init_match = re.search(r'^__version__\s*=\s*"([^"]+)"', init_text, re.MULTILINE)
if not init_match:
    print("FAIL: __version__ not found in src/yashigani/__init__.py", file=sys.stderr)
    sys.exit(1)
init_version = init_match.group(1)

if pyproject_version != init_version:
    print(
        f"FAIL: version mismatch — pyproject.toml={pyproject_version!r} "
        f"src/yashigani/__init__.py={init_version!r}",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"OK: version consistent ({pyproject_version})")
PY
