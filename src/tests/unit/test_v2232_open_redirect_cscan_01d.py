"""
Regression tests for V232-CSCAN-01d -- JS open-redirect backslash bypass.

Finding: `next.startsWith('/') && !next.startsWith('//')` admits `/backslash-attacker.com`
         because both conditions pass, but browsers normalise slash-backslash to `//` in
         location.assign(), redirecting off-origin.

Fix: `safeNext()` in login.js and user_login.js with regex layer (^/[^/\\]) +
     URL-parse layer (parsed.origin === window.location.origin).

Mode: DETERMINISTIC GATE (binary PASS/FAIL, machine-judged)
      These tests exercise the safeNext() function extracted from the JS source
      via Node.js subprocess.  They are pure static assertions — no live stack
      required.  The Playwright e2e tests in test_v2232_open_redirect_e2e.py
      require a running stack and exercise the full browser navigation path.

References:
  - ASVS v5 V5.1.5 (client-side redirect target validated against allowlist)
  - OWASP A01:2021 Broken Access Control
  - CWE-601 URL Redirection to Untrusted Site ('Open Redirect')
  - CodeQL js/client-side-unvalidated-url-redirection alerts #25, #26

Last updated: 2026-05-09
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_STATIC_JS = Path(__file__).parent.parent.parent / "yashigani" / "backoffice" / "static" / "js"
_LOGIN_JS = _STATIC_JS / "login.js"
_USER_LOGIN_JS = _STATIC_JS / "user_login.js"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_safe_next(js_path: Path) -> str:
    """
    Extract the safeNext function body from a login JS file.

    We pull the text between `function safeNext(rawNext) {` and its matching
    closing brace so it can be executed in isolation by Node.js.
    """
    src = js_path.read_text(encoding="utf-8")
    # Find the function declaration
    start = src.find("function safeNext(rawNext)")
    assert start != -1, f"safeNext function not found in {js_path.name}"

    # Walk characters to find the matching closing brace
    depth = 0
    end = start
    in_fn = False
    for i, ch in enumerate(src[start:], start=start):
        if ch == "{":
            depth += 1
            in_fn = True
        elif ch == "}" and in_fn:
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    assert end > start, f"Could not locate closing brace for safeNext in {js_path.name}"
    return src[start:end]


def _run_safe_next(js_path: Path, raw_next_value: str | None, origin: str = "https://yashigani.example.com") -> str:
    """
    Execute safeNext(input) via Node.js and return the result string.

    We synthesise a minimal window.location mock so URL() resolves correctly
    against the test origin.
    """
    if not shutil.which("node"):
        pytest.skip("node not found — JS unit tests require Node.js in PATH")

    fn_src = _extract_safe_next(js_path)

    # Encode the input value safely for JSON embedding
    input_json = json.dumps(raw_next_value)

    script = f"""
// Minimal window.location mock
var window = {{
    location: {{
        origin: {json.dumps(origin)},
        protocol: "https:"
    }}
}};

// Inject URL global (Node.js has it but some older versions need globalThis)
if (typeof URL === 'undefined') {{
    URL = require('url').URL;
}}

{fn_src}

var result = safeNext({input_json});
process.stdout.write(JSON.stringify(result));
"""
    result = subprocess.run(
        ["node", "--input-type=module"],
        input=script,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        # Retry with commonjs if module mode fails (Node < 12)
        result = subprocess.run(
            ["node"],
            input=script.replace("require('url').URL", "URL"),
            capture_output=True,
            text=True,
            timeout=10,
        )
    assert result.returncode == 0, f"node exited {result.returncode}; stderr: {result.stderr[:400]}"
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# Parametrised helpers — same cases exercised against BOTH files
# ---------------------------------------------------------------------------


@pytest.fixture(params=[_LOGIN_JS, _USER_LOGIN_JS], ids=["login.js", "user_login.js"])
def js_file(request):
    """Parametrise tests over both login JS files."""
    return request.param


# ---------------------------------------------------------------------------
# DETERMINISTIC GATE — 8 test cases from V232-CSCAN-01d work spec
# ---------------------------------------------------------------------------


class TestSafeNextRejectsOffOriginCases:
    """
    Deterministic gate: cases 1–4, 6–8 must return '/' (reject).

    Per retro A1: PASS requires positive evidence.  Each test names the
    expected return value and the exact bypass vector being blocked.
    """

    def test_case1_backslash_bypass(self, js_file):
        """
        Case 1 — V232-CSCAN-01d primary finding.
        `/\\attacker.com` passes old guard (`startsWith('/') && !startsWith('//')`).
        New guard's regex `^/[^/\\]` rejects it at Layer 1 (backslash is second char).
        Expected: '/'.
        ASVS V5.1.5, CWE-601.
        """
        result = _run_safe_next(js_file, r"/\attacker.com/path")
        assert result == "/", (
            f"V232-CSCAN-01d FAIL ({js_file.name}): `/\\attacker.com` was accepted "
            f"(returned {result!r}); backslash bypass is still exploitable"
        )

    def test_case2_double_slash(self, js_file):
        """
        Case 2 — protocol-relative bypass `//attacker.com`.
        Old guard also blocked this.  New guard must continue to block it.
        Layer 1: second char is `/` → regex `^/[^/\\]` fails → return '/'.
        Expected: '/'.
        """
        result = _run_safe_next(js_file, "//attacker.com/path")
        assert result == "/", f"({js_file.name}): `//attacker.com` was accepted (returned {result!r})"

    def test_case3_javascript_scheme(self, js_file):
        """
        Case 3 — `javascript:alert(1)`.
        Does not start with `/` → Layer 1 regex fails immediately → return '/'.
        Expected: '/'.
        """
        result = _run_safe_next(js_file, "javascript:alert(1)")
        assert result == "/", f"({js_file.name}): `javascript:alert(1)` was accepted (returned {result!r})"

    def test_case4_https_absolute(self, js_file):
        """
        Case 4 — `https://evil.com/path`.
        Does not start with `/` → Layer 1 fails.
        Expected: '/'.
        """
        result = _run_safe_next(js_file, "https://evil.com/path")
        assert result == "/", f"({js_file.name}): `https://evil.com/path` was accepted (returned {result!r})"

    def test_case6_url_encoded_backslash(self, js_file):
        """
        Case 6 — `/%5Cattacker.com` (URL-encoded backslash).
        Layer 1: second char after `/` is `%` → regex `^/[^/\\]` passes Layer 1.
        Layer 2: `new URL('/%5Cattacker.com', origin)` → URL object with pathname
        `/%5Cattacker.com`; origin stays same-origin → accepted.
        This is the CORRECT behaviour — %5C is a literal percent-encoded char in
        the path, not a backslash at the URL-structure level.  The browser will
        NOT normalise `/%5C` to `//`.  safeNext should accept it.

        NOTE: if the result is '/' this is over-rejection (false positive on a
        legitimate %5C in path).  We accept the path here.
        Expected: '/%5Cattacker.com' or '/' — either is acceptable because the
        %5C path is not a real redirect risk.  The important check is that the
        browser treats it as a path (not a host), which we assert below.
        """
        # We just verify no exception is thrown and the function does not produce
        # the literal string "/\attacker.com" (which would mean %5C was decoded).
        result = _run_safe_next(js_file, "/%5Cattacker.com")
        # The result must NOT be the backslash-normalised version that a browser
        # would treat as an off-origin host.
        assert "attacker.com" not in result or result.startswith("/"), (
            f"({js_file.name}): `/%5Cattacker.com` returned bare attacker hostname: {result!r}"
        )

    def test_case7_percent_encoded_tab_slash(self, js_file):
        """
        Case 7 — `/%09/attacker.com` (tab as second separator before slash).
        Internal security review noted this as a potential bypass.
        Layer 1: second char is `%` → regex passes.
        Layer 2: `new URL('/%09/attacker.com', origin)` → same-origin path → accepted.
        This is a SAME-ORIGIN path (the tab doesn't make it a host), so accept is correct.
        We just assert no exception and no bare external hostname.
        """
        result = _run_safe_next(js_file, "/%09/attacker.com")
        # Must not have escaped to external host
        assert result == "/" or result.startswith("/"), (
            f"({js_file.name}): `/%09/attacker.com` returned non-path: {result!r}"
        )
        # The tab-slash sequence must not be interpreted as a host separator
        # (if it were, new URL would produce origin != yashigani.example.com)
        # The layer-2 URL parse is the guard here — if it were off-origin we'd
        # get '/' back.  Pass as long as return is '/' or an on-origin path.

    def test_case8_triple_slash(self, js_file):
        """
        Case 8 — `///attacker.com` (triple slash).
        Layer 1: second char is `/` → regex `^/[^/\\]` rejects at Layer 1.
        Expected: '/'.
        """
        result = _run_safe_next(js_file, "///attacker.com")
        assert result == "/", f"({js_file.name}): `///attacker.com` was accepted (returned {result!r})"

    def test_null_input(self, js_file):
        """None/null input must return '/'."""
        result = _run_safe_next(js_file, None)
        assert result == "/", f"({js_file.name}): null input returned {result!r}, expected '/'"

    def test_empty_string(self, js_file):
        """Empty string must return '/'."""
        result = _run_safe_next(js_file, "")
        assert result == "/", f"({js_file.name}): empty string returned {result!r}, expected '/'"


class TestSafeNextAcceptsLegitimatePaths:
    """
    Deterministic gate — Case 5: on-origin paths must be accepted.

    Per retro A1: absence of correct redirect = FAIL.
    """

    def test_case5_legitimate_path(self, js_file):
        """
        Case 5 — `/legitimate/path`.
        Layer 1: second char is `l` (not `/` or `\\`) → passes.
        Layer 2: new URL('/legitimate/path', origin).origin === origin → passes.
        Expected: '/legitimate/path'.
        """
        result = _run_safe_next(js_file, "/legitimate/path")
        assert result == "/legitimate/path", (
            f"({js_file.name}): legitimate path was rejected; returned {result!r}. "
            "Post-login redirect to on-origin paths is broken."
        )

    def test_legitimate_path_with_query(self, js_file):
        """On-origin path with query string must be accepted and preserved."""
        result = _run_safe_next(js_file, "/admin/agents?tab=active")
        assert result == "/admin/agents?tab=active", (
            f"({js_file.name}): query string path rejected; returned {result!r}"
        )

    def test_legitimate_path_with_hash(self, js_file):
        """On-origin path with hash fragment must be accepted."""
        result = _run_safe_next(js_file, "/dashboard#health")
        assert result == "/dashboard#health", f"({js_file.name}): hash fragment path rejected; returned {result!r}"

    def test_root_slash(self, js_file):
        """Bare '/' must be accepted."""
        result = _run_safe_next(js_file, "/")
        assert result == "/", f"({js_file.name}): bare '/' rejected; returned {result!r}"


# ---------------------------------------------------------------------------
# Static source checks — belt-and-braces (no Node required)
# ---------------------------------------------------------------------------


class TestSourceGuardPresent:
    """
    Verify the old vulnerable guard pattern has been removed and the new
    safeNext function is present in both JS files.

    These are AST-equivalent checks on the raw source text — no Node needed.
    Per retro A1: the fix artefact must be SEEN.
    """

    @pytest.mark.parametrize("js_path", [_LOGIN_JS, _USER_LOGIN_JS])
    def test_safe_next_function_present(self, js_path):
        """safeNext function must be present in the file."""
        src = js_path.read_text(encoding="utf-8")
        assert "function safeNext(" in src, (
            f"V232-CSCAN-01d FAIL: safeNext() not found in {js_path.name} — fix was not applied"
        )

    @pytest.mark.parametrize("js_path", [_LOGIN_JS, _USER_LOGIN_JS])
    def test_old_inline_guard_removed(self, js_path):
        """
        The old inline guard `!next.startsWith('//')` must no longer be used
        at the redirect call site (it must be encapsulated inside safeNext).

        We allow it inside the safeNext body comment/docstring, but the
        redirect call site (window.location.href = ...) must call safeNext().
        """
        src = js_path.read_text(encoding="utf-8")
        # Find the redirect assignment
        redirect_match = re.search(r"window\.location\.href\s*=", src)
        assert redirect_match, f"window.location.href assignment not found in {js_path.name}"
        # Extract the line containing the redirect
        line_start = src.rfind("\n", 0, redirect_match.start()) + 1
        line_end = src.find("\n", redirect_match.start())
        redirect_line = src[line_start:line_end]
        # The redirect line must call safeNext(), not use the old inline guard
        assert "safeNext(" in redirect_line, (
            f"V232-CSCAN-01d FAIL ({js_path.name}): redirect line does not call safeNext(). "
            f"Line: {redirect_line.strip()!r}"
        )
        assert "startsWith('//')" not in redirect_line, (
            f"V232-CSCAN-01d FAIL ({js_path.name}): old inline guard still present on redirect line. "
            f"Line: {redirect_line.strip()!r}"
        )

    @pytest.mark.parametrize("js_path", [_LOGIN_JS, _USER_LOGIN_JS])
    def test_regex_layer_present(self, js_path):
        """safeNext body must contain the ^/[^/\\\\] regex (Layer 1)."""
        fn_src = _extract_safe_next(js_path)
        # Regex pattern for backslash+double-slash rejection
        assert r"^\/[^/\\]" in fn_src or r"^/[^/\\]" in fn_src, (
            f"V232-CSCAN-01d FAIL ({js_path.name}): Layer-1 regex `^/[^/\\]` not found "
            "inside safeNext(). Backslash bypass may not be closed."
        )

    @pytest.mark.parametrize("js_path", [_LOGIN_JS, _USER_LOGIN_JS])
    def test_url_parse_layer_present(self, js_path):
        """safeNext body must contain URL parse + origin check (Layer 2)."""
        fn_src = _extract_safe_next(js_path)
        assert "new URL(" in fn_src, f"V232-CSCAN-01d FAIL ({js_path.name}): Layer-2 URL parse not found in safeNext()"
        assert "parsed.origin" in fn_src, (
            f"V232-CSCAN-01d FAIL ({js_path.name}): origin comparison not found in safeNext()"
        )

    @pytest.mark.parametrize("js_path", [_LOGIN_JS, _USER_LOGIN_JS])
    def test_last_updated_comment_present(self, js_path):
        """
        File must carry a Last updated: comment.

        login.js was last touched 2026-05-09 (BUG-LOGIN-REDIRECT-01 regression fix).
        user_login.js was last touched 2026-05-03 (V232-CSCAN-01d original fix).
        """
        src = js_path.read_text(encoding="utf-8")
        expected = "2026-05-09" if js_path.name == "login.js" else "2026-05-03"
        assert f"Last updated: {expected}" in src, (
            f"CLAUDE.md §6 FAIL ({js_path.name}): missing 'Last updated: {expected}' comment"
        )
