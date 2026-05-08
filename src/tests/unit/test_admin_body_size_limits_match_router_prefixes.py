"""
Regression test — every body-size limit path prefix must correspond to an
actual mounted router prefix (or a static route) in the backoffice app.

An orphaned limit entry (one whose prefix string does not match any route)
silently fails to protect the intended endpoint while adding config noise.

These tests parse the backoffice app.py source to enumerate:
  1. All entries in _BODY_LIMITS (prefix strings).
  2. All router prefixes passed to app.include_router(..., prefix="...").
  3. All router prefixes baked into APIRouter(prefix="...") calls in
     route modules (for routers included without a top-level prefix= argument).
  4. A small allowlist of static paths registered directly on the app
     (e.g. /auth/login from the auth router that carries its prefix).

Each _BODY_LIMITS entry is asserted to be a prefix of at least one known
route path. The test fails if any limit entry does not correspond to a real
route — catching the class of bug where a path is renamed or mistyped and
the limit entry is left behind.

Last updated: 2026-05-08T12:00:00+01:00
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths under test
# ---------------------------------------------------------------------------

_BACKOFFICE_DIR = Path(__file__).parents[2] / "yashigani" / "backoffice"
_APP_PY = _BACKOFFICE_DIR / "app.py"
_ROUTES_DIR = _BACKOFFICE_DIR / "routes"


# ---------------------------------------------------------------------------
# Helpers: extract data from source
# ---------------------------------------------------------------------------


def _read_source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_body_limit_prefixes(source: str) -> list[str]:
    """
    Parse the _BODY_LIMITS list from app.py source.
    Matches lines of the form:
        ("/some/path",    <int>),
    """
    pattern = re.compile(r'^\s*\("(/[^"]+)"', re.MULTILINE)
    return pattern.findall(source)


def _extract_include_router_prefixes(source: str) -> list[str]:
    """
    Parse all prefix="..." values from app.include_router(...) calls.
    These are the externally-supplied prefixes that FastAPI prepends.
    """
    pattern = re.compile(r'app\.include_router\([^)]+prefix\s*=\s*"(/[^"]*)"', re.DOTALL)
    return pattern.findall(source)


def _extract_apirouter_prefixes_from_routes_dir() -> list[str]:
    """
    Scan all .py files under routes/ for APIRouter(prefix="...") declarations.
    These are routers that carry their own prefix and may be included without
    an explicit prefix= in app.include_router(...).
    """
    pattern = re.compile(r'APIRouter\([^)]*prefix\s*=\s*"(/[^"]*)"', re.DOTALL)
    prefixes: list[str] = []
    for py_file in _ROUTES_DIR.glob("*.py"):
        source = py_file.read_text(encoding="utf-8")
        prefixes.extend(pattern.findall(source))
    return prefixes


def _extract_add_api_route_paths(source: str) -> list[str]:
    """
    Parse paths from app.add_api_route("path", ...) calls in app.py.
    These are direct single-endpoint registrations that bypass include_router
    and therefore carry no router prefix — only the literal path string.
    A body-size limit entry that narrows one of these paths must be matched
    against the literal path, not a router prefix.

    v2.23.3 example: app.add_api_route("/api/v1/license/status", ...) is
    covered by _BODY_LIMITS entry ("/api/v1/license", 256).
    """
    pattern = re.compile(r'app\.add_api_route\(\s*"(/[^"]+)"', re.DOTALL)
    return pattern.findall(source)


def _collect_all_known_route_prefixes() -> set[str]:
    """
    Union of:
    - Prefixes passed to app.include_router(prefix=...)
    - APIRouter(prefix=...) from every routes/*.py module
    - Literal paths from app.add_api_route("path", ...) in app.py
    """
    app_source = _read_source(_APP_PY)
    prefixes: set[str] = set()
    prefixes.update(_extract_include_router_prefixes(app_source))
    prefixes.update(_extract_apirouter_prefixes_from_routes_dir())
    prefixes.update(_extract_add_api_route_paths(app_source))
    return prefixes


def _limit_entry_is_covered(limit_prefix: str, route_prefixes: set[str]) -> bool:
    """
    Return True when limit_prefix is a prefix of (or exactly matches) at
    least one known route prefix, OR when some known route prefix is a prefix
    of limit_prefix (i.e. the limit narrows a path inside a broader router).

    Examples:
      limit "/admin/audit/search" — covered by route prefix "/admin/audit"
      limit "/admin/budget"       — covered by APIRouter prefix "/admin/budget"
      limit "/auth/login"         — covered by route prefix "/auth"
    """
    for route_prefix in route_prefixes:
        # The limit prefix sits inside a mounted router subtree
        if limit_prefix.startswith(route_prefix):
            return True
        # The limit prefix IS the router prefix (exact or the router subtree
        # is narrower than the limit — less common but valid)
        if route_prefix.startswith(limit_prefix):
            return True
    return False


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBodySizeLimitsMatchRouterPrefixes:
    """
    Each entry in _BODY_LIMITS must correspond to a real mounted route.
    Orphaned entries — where the path string was mistyped or the router was
    renamed — never fire and silently leave the intended endpoint unprotected.
    """

    def test_app_py_exists(self):
        """Sanity: app.py must exist where expected."""
        assert _APP_PY.exists(), f"backoffice app.py not found at {_APP_PY}"

    def test_body_limits_list_is_non_empty(self):
        """_BODY_LIMITS must contain at least one entry."""
        source = _read_source(_APP_PY)
        prefixes = _extract_body_limit_prefixes(source)
        assert len(prefixes) > 0, (
            "_BODY_LIMITS appears to be empty or the regex failed to parse it. Check the source format in app.py."
        )

    def test_each_body_limit_prefix_matches_a_mounted_route(self):
        """
        For every (prefix, max_bytes) entry in _BODY_LIMITS, assert that
        prefix corresponds to at least one known router prefix.

        Failure here means a limit entry is an orphan — its prefix has drifted
        from the actual router path and the limit never fires.
        """
        source = _read_source(_APP_PY)
        limit_prefixes = _extract_body_limit_prefixes(source)
        route_prefixes = _collect_all_known_route_prefixes()

        orphans = [p for p in limit_prefixes if not _limit_entry_is_covered(p, route_prefixes)]

        assert orphans == [], (
            f"Body-size limit entries with no matching mounted router prefix:\n"
            + "\n".join(f"  {p!r}" for p in orphans)
            + "\n\nKnown route prefixes:\n"
            + "\n".join(f"  {p!r}" for p in sorted(route_prefixes))
            + "\n\nEach _BODY_LIMITS entry must correspond to a real mounted "
            "router or static route. Check for typos or stale entries after "
            "router renames."
        )

    def test_budget_limit_uses_singular_prefix(self):
        """
        Explicit regression guard: the budget body-size limit must use
        '/admin/budget' (singular), matching the APIRouter prefix in
        routes/budget.py. The previously dead entry used '/admin/budgets'
        (plural) which matched no route.
        """
        source = _read_source(_APP_PY)
        limit_prefixes = _extract_body_limit_prefixes(source)

        assert "/admin/budget" in limit_prefixes, (
            "'/admin/budget' (singular) not found in _BODY_LIMITS. "
            "The budget body-size limit entry is missing or misnamed."
        )
        assert "/admin/budgets" not in limit_prefixes, (
            "'/admin/budgets' (plural) found in _BODY_LIMITS — this is the "
            "dead entry that was corrected. It must not reappear."
        )

    def test_budget_router_prefix_is_singular(self):
        """
        The budget APIRouter must declare prefix='/admin/budget' (singular).
        This test catches any future rename of the router prefix that would
        reintroduce a mismatch with the body-size limit entry.
        """
        budget_py = _ROUTES_DIR / "budget.py"
        assert budget_py.exists(), f"routes/budget.py not found at {budget_py}"
        source = budget_py.read_text(encoding="utf-8")
        assert 'prefix="/admin/budget"' in source, (
            "APIRouter(prefix='/admin/budget') not found in routes/budget.py. "
            "If the router prefix changes, update _BODY_LIMITS in app.py to match."
        )
