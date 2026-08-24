#!/usr/bin/env bash
# scripts/run-staged-pytest.sh
#
# Council remediation (2026-07-15, Tiago-approved) — mechanical Phase-1 win.
#
# pytest-on-staged-tests: run ONLY the test file(s) being committed. Fast
# per-commit feedback loop, not a substitute for the full suite (CI runs
# the full suite separately in a scheduled/nightly job — out of scope for
# this mechanical gate).
#
# Usage: scripts/run-staged-pytest.sh <test_file.py> [<test_file.py> ...]

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
    echo "run-staged-pytest.sh: no staged test files, nothing to run."
    exit 0
fi

if ! command -v pytest >/dev/null 2>&1; then
    echo "run-staged-pytest.sh: pytest not on PATH — run 'pip install -e .[dev]' first" >&2
    exit 1
fi

pytest -q "$@"
