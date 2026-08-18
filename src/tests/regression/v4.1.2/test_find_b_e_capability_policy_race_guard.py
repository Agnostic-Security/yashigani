"""
Regression test -- v4.1.2 FIND-B-E (product, lost-update race, fixed
2026-08-06).

`capability-policy.js` (`_onScopeTypeChange`/`_fetchScope` in the ui4
module, `capPolLoad`/`_capFetchAndRender` in the legacy admin-legacy page)
had no in-flight guard: a rapid scope-type change (or a double-clicked
"Load") could kick off a second `_fetchScope()`/`_capFetchAndRender()` call
while a previous one was still awaiting its network round-trip. Whichever
response happened to arrive LAST won the DOM, regardless of which request
was actually the user's most recent intent -- if the OLDER request's
response arrived after the newer one, it silently clobbered the
already-rendered (correct, newer) state with stale data, and (worse) used
the CURRENT (by-then-changed) scope-type to decide how to parse a response
that was actually fetched for a DIFFERENT scope ('org' vs 'overrides'
response-shape key). Ava's live Tier-B run (headless+headed, both legs)
observed this as a save-confirm timeout / lost edit
(test_capability_policy_ui.py::TestCapPolSave::test_save_org_policy_camera_off's
own docstring documents the identical underlying mechanism: an in-flight
_fetchScope() unconditionally overwriting _rows/_policy).

Fix: both copies now capture the scope (`scopeType`/`scopeId`) and claim a
monotonic sequence token (`_fetchSeq` / `_capFetchSeq`) BEFORE the network
await; after the await, the response is applied ONLY if the token still
matches the latest claimed value -- an older, slower-resolving fetch whose
token has been superseded is silently dropped instead of applied.

This test:
  1. Structurally proves the guard exists in the right place (token claimed
     before the await, checked after) in BOTH files.
  2. Behaviourally proves it via Node, executing the REAL (unmodified)
     `_fetchScope` method (ui4) and `_capFetchAndRender` function (legacy)
     against a fake network that resolves an OLDER request AFTER a NEWER
     one -- the exact out-of-order scenario a rapid scope-type change
     produces. Fails on the pre-fix source (older response clobbers the
     newer one); passes on the fix (older response is discarded).
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_UI4_MODULE = _REPO_ROOT / "yashigani" / "backoffice" / "static" / "ui4" / "admin" / "modules" / "capability-policy.js"
_LEGACY_JS = _REPO_ROOT / "yashigani" / "backoffice" / "static" / "js" / "capability-policy.js"


def _extract_method(source: str, name: str) -> str:
    """Extract a class method body `[async ]<name>(...) { ... }` by brace
    counting. Preserves a preceding `async` keyword (if present) so the
    extracted snippet remains valid standalone JS when it contains `await`."""
    m = re.search(r"(async\s+)?" + re.escape(name) + r"\s*\([^)]*\)\s*\{", source)
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


def _extract_function(source: str, name: str) -> str:
    """Extract a top-level `[async ]function <name>(...) { ... }` block.
    Preserves a preceding `async` keyword (if present)."""
    m = re.search(
        r"(async\s+)?function\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{", source
    )
    assert m is not None, f"function {name} not found"
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


# ---------------------------------------------------------------------------
# Structural proof — the token claim must happen BEFORE the awaited fetch,
# and the guard check must happen AFTER it, in both copies.
# ---------------------------------------------------------------------------

class TestFindBEGuardStructureUi4:
    def test_fetchscope_claims_token_before_await_and_checks_after(self):
        source = _UI4_MODULE.read_text(encoding="utf-8")
        method = _extract_method(source, "_fetchScope")
        claim_idx = method.find("++this._fetchSeq")
        await_idx = method.find("await this.api.get(")
        check_idx = method.find("if (seq !== this._fetchSeq)")
        assert claim_idx != -1, "_fetchScope must claim a fresh _fetchSeq token"
        assert await_idx != -1, "_fetchScope must await the scope fetch"
        assert check_idx != -1, (
            "FIND-B-E: _fetchScope must discard a stale response by checking "
            "the sequence token after the await"
        )
        assert claim_idx < await_idx < check_idx, (
            "FIND-B-E: token claim must precede the await, and the staleness "
            "check must follow it — got claim_idx=%d await_idx=%d check_idx=%d"
            % (claim_idx, await_idx, check_idx)
        )


class TestFindBEGuardStructureLegacy:
    def test_capfetchandrender_claims_token_before_await_and_checks_after(self):
        source = _LEGACY_JS.read_text(encoding="utf-8")
        fn = _extract_function(source, "_capFetchAndRender")
        claim_idx = fn.find("++_capFetchSeq")
        await_idx = fn.find("await api(")
        check_idx = fn.find("if (seq !== _capFetchSeq)")
        assert claim_idx != -1, "_capFetchAndRender must claim a fresh _capFetchSeq token"
        assert await_idx != -1, "_capFetchAndRender must await the scope fetch"
        assert check_idx != -1, (
            "FIND-B-E: _capFetchAndRender must discard a stale response by "
            "checking the sequence token after the await"
        )
        assert claim_idx < await_idx < check_idx, (
            "FIND-B-E: token claim must precede the await, and the staleness "
            "check must follow it — got claim_idx=%d await_idx=%d check_idx=%d"
            % (claim_idx, await_idx, check_idx)
        )


# ---------------------------------------------------------------------------
# Behavioural proof via Node — real (unmodified) functions, fake network
# that resolves the OLDER request after the NEWER one.
# ---------------------------------------------------------------------------

class _NodeRunner:
    @pytest.fixture(autouse=True)
    def _require_node(self):
        self.node = shutil.which("node")
        if not self.node:
            pytest.skip("node not installed — behavioural JS race check skipped")

    def _run(self, script: str) -> str:
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


class TestFindBEFetchScopeRaceUi4(_NodeRunner):
    """Drives the REAL _fetchScope() method against a fake api.get() where
    the FIRST call (scope='org') is slow and the SECOND call (scope='group',
    fired while the first is still in flight — simulating a rapid
    scope-type change) is fast. Pre-fix: the slow 'org' response resolves
    last and clobbers the state the fast 'group' response already rendered.
    Post-fix: the stale 'org' response is dropped; final state reflects
    'group'."""

    def test_older_slower_response_does_not_clobber_newer_faster_one(self):
        source = _UI4_MODULE.read_text(encoding="utf-8")
        fetch_scope_src = _extract_method(source, "_fetchScope")
        scope_url_src = _extract_method(source, "_scopeUrl")

        script = f"""
class FakeCtx {{
  constructor() {{
    this._scopeType = 'org';
    this._scopeId = '';
    this._fetchSeq = 0;
    this._result = null;
    this._policy = null;
    this._rows = null;
    this._dirty = false;
    this._fetchInFlight = false;
    this.api = {{ get: null }};
  }}
  {scope_url_src}
  _buildRows(policy) {{ return {{ builtFrom: policy, atScopeType: this._scopeType }}; }}
  {fetch_scope_src}
}}

async function main() {{
  const ctx = new FakeCtx();
  const responses = {{
    '/admin/api/capability-policy': {{ delayMs: 80, body: {{ org: {{ camera: {{ value: 'STALE-ORG' }} }} }} }},
    '/admin/api/capability-policy/groups/g1': {{ delayMs: 5, body: {{ overrides: {{ camera: {{ value: 'FRESH-GROUP' }} }} }} }},
  }};
  ctx.api.get = (url) => new Promise((resolve) => {{
    const r = responses[url];
    setTimeout(() => resolve(r.body), r.delayMs);
  }});

  const p1 = ctx._fetchScope();   // scopeType='org' captured here, SLOW (80ms)
  ctx._scopeType = 'group';
  ctx._scopeId = 'g1';
  const p2 = ctx._fetchScope();   // scopeType='group' captured here, FAST (5ms)
  await Promise.all([p1, p2]);

  console.log(JSON.stringify({{ policy: ctx._policy, rows: ctx._rows }}));
}}
main();
"""
        out = self._run(script)
        result = json.loads(out)
        assert result["policy"] == {"camera": {"value": "FRESH-GROUP"}}, (
            "FIND-B-E: the slower, OLDER 'org' response resolved after the "
            "faster, NEWER 'group' response and must NOT overwrite it "
            f"(lost-update race) — got {result!r}"
        )
        assert result["rows"]["atScopeType"] == "group", (
            f"FIND-B-E: final rendered state must reflect the LATEST scope "
            f"selection ('group'), not a stale response — got {result!r}"
        )


class TestFindBEFetchAndRenderRaceLegacy(_NodeRunner):
    """Same race, driven against the REAL legacy _capFetchAndRender()
    function (static/js/capability-policy.js)."""

    def test_older_slower_response_does_not_clobber_newer_faster_one(self):
        source = _LEGACY_JS.read_text(encoding="utf-8")
        fn_src = _extract_function(source, "_capFetchAndRender")

        script = f"""
var _capScopeType = 'org';
var _capScopeId = '';
var _capFetchSeq = 0;

var _renderedPolicy = null;
var _renderedAtScope = null;
function _capSetResult(_html) {{ /* no-op */ }}
function _capRenderRows(policy) {{ _renderedPolicy = policy; _renderedAtScope = _capScopeType; }}

var document = {{ getElementById: function() {{ return null; }} }};

var _responses = {{
  '/admin/api/capability-policy': {{ delayMs: 80, body: {{ org: {{ camera: {{ value: 'STALE-ORG' }} }} }} }},
  '/admin/api/capability-policy/groups/g1': {{ delayMs: 5, body: {{ overrides: {{ camera: {{ value: 'FRESH-GROUP' }} }} }} }},
}};
function api(url) {{
  return new Promise((resolve) => {{
    var r = _responses[url];
    setTimeout(function() {{ resolve(r.body); }}, r.delayMs);
  }});
}}

{fn_src}

async function main() {{
  var p1 = _capFetchAndRender();   // _capScopeType='org' captured here, SLOW (80ms)
  _capScopeType = 'group';
  _capScopeId = 'g1';
  var p2 = _capFetchAndRender();   // _capScopeType='group' captured here, FAST (5ms)
  await Promise.all([p1, p2]);
  console.log(JSON.stringify({{ policy: _renderedPolicy, atScope: _renderedAtScope }}));
}}
main();
"""
        out = self._run(script)
        result = json.loads(out)
        assert result["policy"] == {"camera": {"value": "FRESH-GROUP"}}, (
            "FIND-B-E (legacy static/js copy): the slower, OLDER 'org' "
            "response resolved after the faster, NEWER 'group' response "
            f"and must NOT overwrite it (lost-update race) — got {result!r}"
        )
        assert result["atScope"] == "group", (
            f"FIND-B-E: final rendered state must reflect the LATEST scope "
            f"selection ('group'), not a stale response — got {result!r}"
        )
