"""
Regression test -- v4.1.2 FIND-B-F (MEDIUM, batch-fix 2026-08-04).

Ava's Tier-B webui_conformance run (`test_capability_policy_ui.py`,
PW-CAP-05) proved `test_origin_with_path_rejected` failing: adding the
origin "https://example.com/some/path" via the allow-list input produced
NO client-side error and (per the ticket's framing) an over-permissive
allow-list entry, contrary to the documented contract "https://hostname
[:port] -- no path, no wildcard".

Root cause (both the ui4 module AND the legacy admin-legacy page share the
identical bug): `_addOrigin()` / `capPolAddOrigin()` called
`normaliseOrigin()`/`_capNormalizeOrigin()` on the raw input FIRST, then
validated the ALREADY-NORMALISED value. `new URL("https://example.com/some
/path")` parses successfully, and normaliseOrigin() rebuilds
"${url.protocol}//${url.host}" == "https://example.com" -- silently
dropping the path -- BEFORE isValidOrigin()/_capValidateOrigin() ever saw
the original string. The clean, path-stripped value then passes validation
with no error at all: a path-bearing (or query/hash/credentials-bearing)
origin is silently accepted-with-correction instead of rejected.
isValidOrigin() itself was already correct when given the RAW string (both
the path check and the wildcard check -- confirmed '*' survives WHATWG URL
host parsing and is explicitly checked for) -- the defect was purely the
CALL ORDER.

Fix: validate the raw input first, THEN normalise for storage, in both
`static/ui4/admin/modules/capability-policy.js` (`_addOrigin`) and
`static/js/capability-policy.js` (`capPolAddOrigin`, the legacy
admin-legacy page). `isValidOrigin`/`normaliseOrigin` were additionally
exported from the ui4 module (harmless additive export) so this test can
exercise the real, unmodified functions directly via Node rather than a
hand-copied duplicate that could silently drift from the source.

Server-side note (defense-in-depth, unaffected either way):
`yashigani.capability_policy.model._HTTPS_ORIGIN_RE` already rejects a
path-bearing/wildcard origin in the raw request body server-side (no path
is possible in the regex's fullmatch), so this bug never weakened the
eventual Permissions-Policy header the server renders -- it was a
client-side UX/validation-bypass ordering bug only. Covered here anyway
since PW-CAP-05 tests the client-side contract directly.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_UI4_MODULE = _REPO_ROOT / "yashigani" / "backoffice" / "static" / "ui4" / "admin" / "modules" / "capability-policy.js"
_LEGACY_JS = _REPO_ROOT / "yashigani" / "backoffice" / "static" / "js" / "capability-policy.js"


def _extract_function(source: str, name: str) -> str:
    """Extract a top-level `function <name>(...) { ... }` block by brace
    counting (handles nested braces inside the body, e.g. try/catch)."""
    m = re.search(r"function\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{", source)
    assert m is not None, f"function {name} not found"
    start = m.end() - 1  # index of the opening '{'
    depth = 0
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[m.start():i + 1]
    raise AssertionError(f"unbalanced braces extracting {name}")


def _extract_method(source: str, name: str) -> str:
    """Extract a class method body `<name>(cap) { ... }` the same way."""
    m = re.search(re.escape(name) + r"\s*\([^)]*\)\s*\{", source)
    assert m is not None, f"method {name} not found"
    start = m.end() - 1
    depth = 0
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[m.start():i + 1]
    raise AssertionError(f"unbalanced braces extracting {name}")


class TestFindBFOriginValidationOrderUi4:
    """Structural proof: _addOrigin() must validate the RAW input BEFORE
    normalising it (the actual root cause). Fails on the pre-fix source
    (normaliseOrigin call appears before the isValidOrigin call)."""

    def test_addorigin_validates_before_normalising(self):
        # Accepts EITHER `row.input` directly or a raw alias (`const raw =
        # (row.input || '').trim()`), matching the idiom the legacy twin below
        # has always used (`_capValidateOrigin(raw)`). What is asserted is the
        # property FIND-B-F is about — the SAME un-normalised expression is
        # validated, and validation happens BEFORE normalisation. An alias is
        # only accepted if it is derived from row.input by trim alone; anything
        # that routes through normaliseOrigin() first still fails.
        source = _UI4_MODULE.read_text(encoding="utf-8")
        method = _extract_method(source, "_addOrigin")

        m = re.search(r"isValidOrigin\(\s*([A-Za-z_$][\w.$]*)\s*\)", method)
        assert m, "_addOrigin must call isValidOrigin(...) on the RAW input"
        arg = m.group(1)
        validate_idx = m.start()

        n = re.search(r"normaliseOrigin\(\s*" + re.escape(arg) + r"\s*\)", method)
        assert n, (
            f"_addOrigin must call normaliseOrigin({arg}) — the SAME expression it "
            f"validated; normalising a different value reopens FIND-B-F"
        )
        normalise_idx = n.start()

        if arg != "row.input":
            alias = re.search(
                r"(?:const|let|var)\s+" + re.escape(arg) + r"\s*=\s*\(?\s*row\.input\b[^;]*;",
                method,
            )
            assert alias, (
                f"isValidOrigin({arg}) is validating an alias that is not visibly "
                f"derived from row.input — FIND-B-F requires the RAW input"
            )
            assert "normaliseOrigin" not in alias.group(0), (
                f"alias `{arg}` is normalised before validation — this is exactly "
                f"the FIND-B-F ordering bug in a new shape"
            )
            assert alias.start() < validate_idx, f"alias `{arg}` must be assigned before use"

        assert validate_idx < normalise_idx, (
            "FIND-B-F: _addOrigin must validate the raw input BEFORE normalising it — "
            "validating an already-normalised value lets a path-bearing origin "
            "silently pass (path is stripped by normalisation first)"
        )

    def test_isvalidorigin_and_normaliseorigin_are_exported(self):
        source = _UI4_MODULE.read_text(encoding="utf-8")
        assert re.search(r"export\s+function\s+isValidOrigin", source)
        assert re.search(r"export\s+function\s+normaliseOrigin", source)


class TestFindBFOriginValidationOrderLegacy:
    """Same structural proof for the legacy admin-legacy page's twin
    function, capPolAddOrigin()."""

    def test_cappoladdorigin_validates_before_normalising(self):
        source = _LEGACY_JS.read_text(encoding="utf-8")
        method = _extract_function(source, "capPolAddOrigin")
        validate_idx = method.find("_capValidateOrigin(raw)")
        normalise_idx = method.find("_capNormalizeOrigin(raw)")
        assert validate_idx != -1, "capPolAddOrigin must call _capValidateOrigin(raw) on the RAW input"
        assert normalise_idx != -1, "capPolAddOrigin must call _capNormalizeOrigin(raw) on the RAW input"
        assert validate_idx < normalise_idx, (
            "FIND-B-F: capPolAddOrigin must validate raw BEFORE normalising it"
        )


class TestFindBFIsValidOriginBehaviourNode:
    """Behavioural proof, executing the REAL (unmodified) isValidOrigin /
    normaliseOrigin functions from the ui4 module via Node — not a
    hand-copied duplicate. Requires node; skips if unavailable (matches the
    existing YSG-RISK-163 precedent for JS checks in this repo, which has
    no JS test runner)."""

    @pytest.fixture(autouse=True)
    def _require_node(self):
        self.node = shutil.which("node")
        if not self.node:
            pytest.skip("node not installed — behavioural JS check skipped")

    def _run(self, harness_tail: str) -> str:
        source = _UI4_MODULE.read_text(encoding="utf-8")
        is_valid_origin_src = _extract_function(source, "isValidOrigin").replace(
            "export function isValidOrigin", "function isValidOrigin", 1
        )
        # The exported source keeps the `export` keyword on the same line
        # the extractor captured ("export function isValidOrigin(...)");
        # strip it so the snippet is plain (non-module-export) JS runnable
        # standalone via `node --input-type=module` (module context still
        # permits top-level function decls without `export`).
        is_valid_origin_src = re.sub(r"^export\s+", "", is_valid_origin_src)
        normalise_origin_src = _extract_function(source, "normaliseOrigin")
        normalise_origin_src = re.sub(r"^export\s+", "", normalise_origin_src)

        script = f"{is_valid_origin_src}\n{normalise_origin_src}\n{harness_tail}\n"
        result = subprocess.run(
            [self.node, "--input-type=module"],
            input=script,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, (
            f"node execution failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
        )
        return result.stdout.strip()

    def test_isvalidorigin_rejects_raw_path_bearing_origin(self):
        out = self._run(
            'console.log(JSON.stringify(isValidOrigin("https://example.com/some/path")));'
        )
        assert out == "false", (
            "isValidOrigin must reject a RAW path-bearing origin outright"
        )

    def test_isvalidorigin_rejects_wildcard_origin(self):
        out = self._run(
            'console.log(JSON.stringify(isValidOrigin("https://*.example.com")));'
        )
        assert out == "false"

    def test_isvalidorigin_rejects_http_scheme(self):
        out = self._run(
            'console.log(JSON.stringify(isValidOrigin("http://not-https.com")));'
        )
        assert out == "false"

    def test_isvalidorigin_accepts_clean_https_origin(self):
        out = self._run(
            'console.log(JSON.stringify(isValidOrigin("https://trusted.example.com")));'
        )
        assert out == "true"

    def test_normalise_then_validate_would_have_masked_the_path_bug(self):
        """Documents WHY the bug existed: proves that validating the
        ALREADY-NORMALISED value (the pre-fix order) incorrectly accepts a
        path-bearing origin — the exact defect this ticket closes."""
        out = self._run(
            "const raw = 'https://example.com/some/path';"
            "const normalised = normaliseOrigin(raw);"
            "console.log(JSON.stringify({normalised, wouldPassPreFix: isValidOrigin(normalised), correctlyRejectsRaw: !isValidOrigin(raw)}));"
        )
        import json

        parsed = json.loads(out)
        assert parsed["normalised"] == "https://example.com", (
            "sanity: normaliseOrigin must strip the path (this is the mechanism of the bug)"
        )
        assert parsed["wouldPassPreFix"] is True, (
            "sanity: validating the normalised value alone would incorrectly accept it — "
            "this is exactly why validation must run on the RAW value first"
        )
        assert parsed["correctlyRejectsRaw"] is True, (
            "isValidOrigin correctly rejects the RAW path-bearing string — "
            "the fix's job is simply to call it in that order"
        )
