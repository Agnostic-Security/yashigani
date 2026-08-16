"""FIND-0813-011 — the per-test ceiling must actually be ENFORCEABLE.

conftest.py's pytest_collection_modifyitems() applies a per-test timeout marker,
which requires the `pytest-timeout` plugin. That plugin was declared in
pyproject but ABSENT from uv.lock (FIND-0813-004), so `uv sync --frozen`
never installed it and the marker was silently INERT for the whole 4.1.2
campaign — the exact 45-minute-orphan failure the pin exists to prevent
recurred, and a headed Tier-B leg hung with zero browser processes.

A ceiling nobody can observe is not a ceiling. This guard fails loudly if the
plugin is missing, instead of letting the protection vanish again.

2026-08-16 (pre-push code-quality review NB-3): two of the three tests below
were dead weight -- ``test_timeout_marker_is_registered_and_effective``
duplicated ``test_pytest_timeout_plugin_is_installed`` behind a name that
promised more than it checked, and ``test_an_explicit_marker_survives_
collection`` was a literal ``assert True`` that could never fail regardless
of what the collection hook did. Both are replaced with static-source
property checks against ``src/tests/playwright/conftest.py``'s actual
``pytest_collection_modifyitems``/``pytest_configure`` hooks: this Tier-A
file is in-process/offline by design (YTF §3) and playwright/conftest.py
cannot be imported here at all -- its module-level ``BASE_URL =
_resolve_base_url()`` / ``STACK_RUNNING = _stack_running()`` require (or
network-probe for) a live stack, which is exactly the live-stack dependency
Tier-A deselects. Static-string analysis of the extracted hook body is the
established pattern this repo already uses for the same "can't import it
from here" constraint (see src/tests/regression/v2.23.4/
test_layer_b_installer_path.py's ``_code_only`` -- same idea, applied to
Python source instead of bash). These two tests now guard the actual
dispatch mechanism this file's own headline fix changed: whether the
per-test budget is decided by an explicit, greppable pytest marker or by a
fragile nodeid-substring match that a directory rename could silently flip
(NB-3's own root cause, fixed in the same commit as this test change).
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

# regression/v4.1.2 -> regression -> tests -> src -> repo root
_REPO_ROOT = Path(__file__).resolve().parents[4]
_PLAYWRIGHT_CONFTEST = _REPO_ROOT / "src" / "tests" / "playwright" / "conftest.py"


def _extract_function(func_name: str, source: str) -> str:
    """Return the source of a top-level ``def func_name(...):`` block (up to
    the next top-level ``def``/``class`` at column 0, or EOF)."""
    m = re.search(rf"^def {re.escape(func_name)}\(", source, flags=re.MULTILINE)
    assert m, f"{func_name}() not found in {_PLAYWRIGHT_CONFTEST}"
    start = m.start()
    nxt = re.search(r"^(def|class) ", source[m.end():], flags=re.MULTILINE)
    end = m.end() + nxt.start() if nxt else len(source)
    return source[start:end]


def _conftest_source() -> str:
    return _PLAYWRIGHT_CONFTEST.read_text(encoding="utf-8")


def _code_only(source: str) -> str:
    """Strip pure-comment lines (BLOCK-2 pattern, test_layer_b_installer_
    path.py): a static-text scan is only sound if it excludes prose. This
    file's own docstring/comments legitimately discuss the OLD
    nodeid-substring heuristic by name while explaining why it was replaced
    -- without this, that history would trip the regression check it is
    meant to protect."""
    return "\n".join(
        line for line in source.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def test_pytest_timeout_plugin_is_installed():
    assert importlib.util.find_spec("pytest_timeout") is not None, (
        "pytest-timeout is NOT installed, so conftest.py's per-test ceiling is "
        "INERT — a hung test will orphan the run with no output (FIND-0813-011). "
        "Fix: uv sync --frozen --all-groups --all-extras"
    )


def test_multi_identity_marker_is_registered_not_just_used():
    """``multi_identity`` must be registered via ``pytest_configure`` (not
    just referenced ad hoc), or pytest emits PytestUnknownMarkWarning and a
    future ``--strict-markers`` run would fail collection outright."""
    configure_block = _code_only(_extract_function("pytest_configure", _conftest_source()))
    assert '"multi_identity:' in configure_block or "'multi_identity:" in configure_block, (
        "multi_identity marker is not registered in pytest_configure() -- "
        "conftest.py's collection hook depends on it for the extended "
        "timeout budget (FIND-0813-011)"
    )


def test_timeout_budget_dispatches_on_marker_not_nodeid_substring():
    """NB-3 regression guard: the extended per-test timeout budget must be
    decided by ``item.get_closest_marker("multi_identity")`` (or an
    equivalent marker lookup), NOT by substring-matching ``item.nodeid``.
    nodeid includes the collected file's PATH, so a substring match lets an
    unrelated directory/file rename silently change every test's timeout
    underneath it with no code change -- the exact bug this file's own fix
    closed. Reverting to a nodeid/nodeid.lower() substring match must fail
    this test."""
    hook_block = _code_only(_extract_function("pytest_collection_modifyitems", _conftest_source()))
    assert "get_closest_marker(\"multi_identity\")" in hook_block or (
        "iter_markers()" in hook_block and "multi_identity" in hook_block
    ), (
        "pytest_collection_modifyitems no longer dispatches the extended "
        "timeout budget via the multi_identity marker -- check it hasn't "
        "regressed back to a nodeid-substring heuristic (NB-3)"
    )
    assert ".nodeid.lower()" not in hook_block and "_MULTI_IDENTITY_HINTS" not in hook_block, (
        "pytest_collection_modifyitems is back to matching the timeout "
        "budget against item.nodeid -- nodeid includes the file PATH, so "
        "an unrelated rename silently changes every test's timeout (NB-3)"
    )


def test_explicit_timeout_marker_is_skipped_by_the_collection_hook():
    """The hook must not overwrite a test's own explicit
    ``@pytest.mark.timeout(...)`` -- it has to check for and skip items that
    already carry one before assigning the default/extended budget."""
    hook_block = _code_only(_extract_function("pytest_collection_modifyitems", _conftest_source()))
    m = re.search(
        r'if\s+any\(.*m\.name\s*==\s*["\']timeout["\'].*\)\s*:\s*\n\s*continue',
        hook_block,
    )
    assert m, (
        "pytest_collection_modifyitems no longer skips items that already "
        "carry an explicit @pytest.mark.timeout(...) -- it would overwrite "
        "a test author's deliberate per-test timeout"
    )
    # The skip must be evaluated BEFORE the budget is assigned, or the skip
    # is dead code that never prevents the overwrite it claims to prevent.
    assign_idx = hook_block.index('pytest.mark.timeout(_budget')
    assert m.start() < assign_idx, (
        "the explicit-marker skip must come BEFORE the budget assignment "
        "in the hook, or it never actually protects an explicit marker"
    )
