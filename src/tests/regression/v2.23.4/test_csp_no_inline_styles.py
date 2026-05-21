"""
Regression tests for CSP-INLINE-STYLE-SPA (backlog #6/#7, v2.23.4).

Root cause: dashboard.html contained 229 inline style="..." attributes.
Under the strict CSP already emitted by backoffice app.py line 496
  ("style-src 'self'") each attribute either generates a browser violation
  report or (if 'unsafe-inline' were ever added) defeats the control entirely.

This file asserts:

1. Zero inline style="..." attributes remain in any admin HTML template.
2. Zero inline <style>...</style> blocks remain in admin HTML templates.
3. The CSP emitted by the Python middleware (app.py) does NOT contain
   'unsafe-inline' in the style-src directive.
4. The CSP header in each Caddyfile (selfsigned, ca, acme) does NOT contain
   'unsafe-inline' in the style-src directive.
5. Each admin HTML template references an external CSS file via <link> and
   does NOT reference any CDN stylesheet (self-hosted only, ASVS V14.4.3).

Test strategy: static-string analysis of source files — no live service
required (same pattern as test_layer_b_installer_path.py).

Last updated: 2026-05-13T00:00:00+01:00
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parents[4]
TEMPLATES_DIR = REPO_ROOT / "src" / "yashigani" / "backoffice" / "templates"
STATIC_CSS_DIR = REPO_ROOT / "src" / "yashigani" / "backoffice" / "static" / "css"
APP_PY = REPO_ROOT / "src" / "yashigani" / "backoffice" / "app.py"
DOCKER_DIR = REPO_ROOT / "docker"

# Admin HTML templates that must be free of inline styles.
ADMIN_TEMPLATES = [
    TEMPLATES_DIR / "dashboard.html",
    TEMPLATES_DIR / "login.html",
    TEMPLATES_DIR / "user_login.html",
]

# Caddyfiles that carry security headers.
CADDYFILES = [
    DOCKER_DIR / "Caddyfile.selfsigned",
    DOCKER_DIR / "Caddyfile.ca",
    DOCKER_DIR / "Caddyfile.acme",
]


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _read(path: Path) -> str:
    assert path.exists(), f"Expected file not found: {path}"
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. No inline style="..." attributes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("template", ADMIN_TEMPLATES, ids=[t.name for t in ADMIN_TEMPLATES])
def test_no_inline_style_attributes(template: Path) -> None:
    """Every admin template must have zero inline style='...' attributes."""
    content = _read(template)
    matches = re.findall(r'\bstyle="', content)
    assert matches == [], (
        f"{template.name}: found {len(matches)} inline style attribute(s). "
        "All styles must be in external CSS files (ASVS V14.4.3 + feedback_no_inline_js.md). "
        f"First occurrence context: {_first_context(content, 'style=')}"
    )


# ---------------------------------------------------------------------------
# 2. No inline <style> blocks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("template", ADMIN_TEMPLATES, ids=[t.name for t in ADMIN_TEMPLATES])
def test_no_inline_style_blocks(template: Path) -> None:
    """Every admin template must have zero inline <style>...</style> blocks."""
    content = _read(template)
    # Match opening <style tags (with or without attributes)
    matches = re.findall(r"<style[\s>]", content, re.IGNORECASE)
    assert matches == [], (
        f"{template.name}: found {len(matches)} inline <style> block(s). "
        "All styles must be in external CSS files."
    )


# ---------------------------------------------------------------------------
# 3. Python middleware CSP does not contain 'unsafe-inline' in style-src
# ---------------------------------------------------------------------------


def test_python_middleware_csp_no_unsafe_inline_style() -> None:
    """app.py CSP header must not include 'unsafe-inline' in style-src."""
    content = _read(APP_PY)
    # Extract the _csp assignment line(s)
    csp_lines = [ln.strip() for ln in content.splitlines() if "_csp" in ln and "style-src" in ln]
    assert csp_lines, (
        "Could not find a line in app.py containing both '_csp' and 'style-src'. "
        "Check that the CSP is still set in the middleware."
    )
    for line in csp_lines:
        assert "'unsafe-inline'" not in line, (
            f"app.py: CSP line contains 'unsafe-inline': {line!r}"
        )
    # Also assert style-src 'self' is present
    combined = " ".join(csp_lines)
    assert "style-src 'self'" in combined, (
        f"app.py: Expected \"style-src 'self'\" in CSP. Got: {combined!r}"
    )


# ---------------------------------------------------------------------------
# 4. Caddyfile CSP headers do not contain 'unsafe-inline' in style-src
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("caddyfile", CADDYFILES, ids=[c.name for c in CADDYFILES])
def test_caddyfile_csp_no_unsafe_inline_style(caddyfile: Path) -> None:
    """Each Caddyfile CSP header must not include 'unsafe-inline' in style-src."""
    content = _read(caddyfile)
    csp_lines = [
        ln.strip()
        for ln in content.splitlines()
        if "Content-Security-Policy" in ln and "style-src" in ln
    ]
    assert csp_lines, (
        f"{caddyfile.name}: Could not find a CSP line containing 'style-src'. "
        "Check that the Caddyfile still sets Content-Security-Policy."
    )
    for line in csp_lines:
        assert "'unsafe-inline'" not in line, (
            f"{caddyfile.name}: CSP line contains 'unsafe-inline': {line!r}"
        )
    combined = " ".join(csp_lines)
    assert "style-src 'self'" in combined, (
        f"{caddyfile.name}: Expected \"style-src 'self'\" in CSP. Got: {combined!r}"
    )


# ---------------------------------------------------------------------------
# 5. Admin templates reference external CSS only (no CDN stylesheets)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("template", ADMIN_TEMPLATES, ids=[t.name for t in ADMIN_TEMPLATES])
def test_no_cdn_stylesheets(template: Path) -> None:
    """Admin templates must not load CSS from external CDNs."""
    content = _read(template)
    # Any <link rel="stylesheet"> pointing outside 'self'
    cdn_links = re.findall(
        r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']https?://', content, re.IGNORECASE
    )
    cdn_links += re.findall(
        r'<link[^>]+href=["\']https?://[^>]+rel=["\']stylesheet["\']', content, re.IGNORECASE
    )
    assert cdn_links == [], (
        f"{template.name}: found CDN stylesheet link(s): {cdn_links}. "
        "All CSS must be served from 'self' (ASVS V14.4.3)."
    )


# ---------------------------------------------------------------------------
# 6. dashboard.html references the external CSS file
# ---------------------------------------------------------------------------


def test_dashboard_links_external_css() -> None:
    """dashboard.html must include a <link> to dashboard.css."""
    content = _read(TEMPLATES_DIR / "dashboard.html")
    assert 'href="/static/css/dashboard.css"' in content, (
        "dashboard.html does not link to /static/css/dashboard.css. "
        "The external stylesheet must be present."
    )


# ---------------------------------------------------------------------------
# 7. dashboard.css exists and is non-empty
# ---------------------------------------------------------------------------


def test_dashboard_css_exists_and_nonempty() -> None:
    """The external dashboard.css file must exist and contain rules."""
    css_path = STATIC_CSS_DIR / "dashboard.css"
    assert css_path.exists(), f"dashboard.css not found at {css_path}"
    content = css_path.read_text(encoding="utf-8")
    assert len(content.strip()) > 100, (
        "dashboard.css appears to be empty or near-empty. "
        "Extracted styles must be present."
    )
    # Must not contain 'unsafe-inline' (defensive: CSS files shouldn't contain CSP strings,
    # but this catches accidental merge of CSP config into CSS)
    assert "'unsafe-inline'" not in content, (
        "dashboard.css unexpectedly contains the string 'unsafe-inline'."
    )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _first_context(content: str, pattern: str, context: int = 80) -> str:
    """Return a short context string around the first occurrence of pattern."""
    idx = content.find(pattern)
    if idx < 0:
        return "<not found>"
    start = max(0, idx - 20)
    end = min(len(content), idx + context)
    return repr(content[start:end])
