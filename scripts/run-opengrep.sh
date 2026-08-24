#!/usr/bin/env bash
# scripts/run-opengrep.sh
#
# Council remediation (2026-07-15, Tiago-approved) — mechanical Phase-1 win.
#
# Runs every rule under opengrep-rules/ against the given files (staged
# files from pre-commit, or the PR diff in CI).
#
#   ERROR-severity rules   → hard block (exit 1 on any finding).
#   WARNING-severity rules → informational only (never fails the commit/PR).
#     These are heuristics (e.g. opengrep-rules/authz/deny-without-allow-
#     heuristic.yml) that flag a suspicious SHAPE, not a proven bug — a
#     human reviewer decides, the gate does not block.
#
# Usage: scripts/run-opengrep.sh <file> [<file> ...]

set -euo pipefail
# NOTE: unlike the hardened install/entrypoint scripts in this directory,
# this is a dev-tooling helper invoked by pre-commit/CI and MUST inherit the
# caller's PATH (project venv, GitHub Actions actions/setup-python tool-cache,
# homebrew, pyenv, asdf) rather than a fixed system PATH — a static PATH here
# would silently fail to find venv-installed pytest/ruff/mypy or the
# runner-installed opengrep binary.
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [ "$#" -eq 0 ]; then
    echo "run-opengrep.sh: no files given, nothing to scan."
    exit 0
fi

if ! command -v opengrep >/dev/null 2>&1; then
    echo "run-opengrep.sh: opengrep not on PATH — install from https://github.com/opengrep/opengrep" >&2
    exit 1
fi

echo "--- opengrep: ERROR-severity rules (blocking) ---"
error_status=0
opengrep scan --quiet --error --severity ERROR --config opengrep-rules/ "$@" || error_status=$?

echo "--- opengrep: WARNING-severity rules (informational, non-blocking) ---"
opengrep scan --quiet --severity WARNING --config opengrep-rules/ "$@" || true

exit "$error_status"
