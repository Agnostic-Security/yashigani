"""
Regression test -- FIND-CAPPOLICY-RACE-NOT-FIXED (v4.1.2 podman browser
retest, 2026-08-06).

`test_capability_policy_ui.py::TestCapPolSave::test_save_org_policy_camera_off`
still failed on 1c76dd25, AFTER the FIND-B-E in-flight sequence-token guard
(see test_find_b_e_capability_policy_race_guard.py) had already landed --
but the SYMPTOM changed: previously a stale-value `.ys-badge` rendered
instantly; after the guard, `.ys-badge` never appeared at all (8000ms
Playwright timeout).

Root cause (NOT the seq-token guard itself -- that guard's ordering check
is correct and untouched by this fix):

  ui4 module (`static/ui4/admin/modules/capability-policy.js`):
    `_fetchScope()` set `this._result = null` UNCONDITIONALLY at its very
    top, synchronously, before any `await`. `_save()` (and `_delete()`) set
    `this._result = { ok: true, message: 'Saved.' }` and then immediately
    `await this._fetchScope()` to refresh the row data from the server.
    Because both `_result` writes happen synchronously in the same tick --
    Lit's reactive-property setter schedules a render via a microtask, and
    does not flush until the synchronous call stack unwinds -- the render
    that actually paints only ever observes the LATER value (`null`). The
    "Saved." badge was clobbered before it ever painted, not merely raced.

  Legacy module (`static/js/capability-policy.js`):
    Same defect, expressed via direct DOM writes instead of reactive state:
    `capPolSave()`/`capPolDelete()` write the "Saved."/"Override removed."
    badge via `_capSetResult(...)`, then `await _capFetchAndRender()`, whose
    body unconditionally calls `_capSetResult('<span class="loading">
    Loading…</span>')` and then, after the fetch resolves, `_capSetResult('')`
    -- both of which stomp the badge the caller just set, with no guard at
    all (not even a stale-response race -- this happens on EVERY save/delete,
    100% of the time).

Fix (this commit): both `_fetchScope(clearResult = true)` and
`_capFetchAndRender(clearResult = true)` gained a `clearResult` parameter.
`_save()`/`_delete()` (ui4) and `capPolSave()`/`capPolDelete()` (legacy) now
call the refresh with `clearResult=false`, preserving the badge they just
set. User-initiated fresh scope loads (`_onScopeTypeChange`, `_onLoadScope`,
`loadCapabilityPolicy()`, `capPolLoad()`) keep the default `true`, so a
stale badge from a previous action still correctly clears when the operator
switches scope.

This test drives the REAL (unmodified) `_save()` / `_fetchScope()` methods
(ui4) and `capPolSave()` / `_capFetchAndRender()` functions (legacy) via
Node against a fake API, proving:
  1. A successful save's "Saved." result SURVIVES the post-save refetch.
  2. The pre-existing FIND-B-E out-of-order-response guard is untouched --
     a stale scope-type response still cannot clobber a newer one, even
     with `clearResult=false` in play.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_UI4_MODULE = (
    _REPO_ROOT
    / "yashigani"
    / "backoffice"
    / "static"
    / "ui4"
    / "admin"
    / "modules"
    / "capability-policy.js"
)
_LEGACY_JS = _REPO_ROOT / "yashigani" / "backoffice" / "static" / "js" / "capability-policy.js"


def _extract_method(source: str, name: str) -> str:
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
                return source[m.start() : i + 1]
    raise AssertionError(f"unbalanced braces extracting {name}")


def _extract_function(source: str, name: str) -> str:
    m = re.search(r"(async\s+)?function\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{", source)
    assert m is not None, f"function {name} not found"
    start = m.end() - 1
    depth = 0
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[m.start() : i + 1]
    raise AssertionError(f"unbalanced braces extracting {name}")


class _NodeRunner:
    @pytest.fixture(autouse=True)
    def _require_node(self):
        self.node = shutil.which("node")
        if not self.node:
            pytest.skip("node not installed — behavioural JS check skipped")

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


# ---------------------------------------------------------------------------
# Structural proof — clearResult must gate the _result/_capSetResult resets,
# and the save/delete call sites must pass clearResult=false.
# ---------------------------------------------------------------------------


class TestClearResultStructureUi4:
    def test_fetchscope_has_clearresult_param_gating_reset(self):
        source = _UI4_MODULE.read_text(encoding="utf-8")
        method = _extract_method(source, "_fetchScope")
        assert "clearResult" in method.split("{", 1)[0], (
            "_fetchScope must accept a clearResult parameter"
        )
        assert "if (clearResult) this._result = null;" in method, (
            "_fetchScope must only null out this._result when clearResult is true"
        )

    def test_save_and_delete_pass_clearresult_false(self):
        source = _UI4_MODULE.read_text(encoding="utf-8")
        save_method = _extract_method(source, "_save")
        delete_method = _extract_method(source, "_delete")
        assert "this._fetchScope(false)" in save_method, (
            "FIND-CAPPOLICY-RACE-NOT-FIXED: _save() must refresh with "
            "clearResult=false so the 'Saved.' badge survives"
        )
        assert "this._fetchScope(false)" in delete_method, (
            "FIND-CAPPOLICY-RACE-NOT-FIXED: _delete() must refresh with "
            "clearResult=false so the 'Override removed.' badge survives"
        )


class TestClearResultStructureLegacy:
    def test_capfetchandrender_has_clearresult_param_gating_reset(self):
        source = _LEGACY_JS.read_text(encoding="utf-8")
        fn = _extract_function(source, "_capFetchAndRender")
        assert "if (clearResult === undefined) clearResult = true;" in fn
        assert 'if (clearResult) _capSetResult(\'<span class="loading">Loading…</span>\');' in fn
        assert "if (clearResult) _capSetResult('');" in fn

    def test_savepol_and_delete_pass_clearresult_false(self):
        source = _LEGACY_JS.read_text(encoding="utf-8")
        save_fn = _extract_function(source, "capPolSave")
        delete_fn = _extract_function(source, "capPolDelete")
        assert "_capFetchAndRender(false)" in save_fn, (
            "FIND-CAPPOLICY-RACE-NOT-FIXED: capPolSave() must refresh with "
            "clearResult=false so the 'Saved.' badge survives"
        )
        assert "_capFetchAndRender(false)" in delete_fn, (
            "FIND-CAPPOLICY-RACE-NOT-FIXED: capPolDelete() must refresh with "
            "clearResult=false so the 'Override removed.' badge survives"
        )


# ---------------------------------------------------------------------------
# Behavioural proof via Node — drives the REAL _save()/_fetchScope() (ui4)
# and capPolSave()/_capFetchAndRender() (legacy) against a fake network.
# ---------------------------------------------------------------------------


class TestSaveBadgeSurvivesRefetchUi4(_NodeRunner):
    def test_save_result_not_clobbered_by_post_save_fetchscope(self):
        source = _UI4_MODULE.read_text(encoding="utf-8")
        save_src = _extract_method(source, "_save")
        fetch_scope_src = _extract_method(source, "_fetchScope")
        scope_url_src = _extract_method(source, "_scopeUrl")
        collect_policy_src = _extract_method(source, "_collectPolicy")

        script = f"""
const CAP_NAMES = ['camera', 'microphone', 'geolocation', 'display-capture', 'fullscreen'];

class FakeCtx {{
  constructor() {{
    this._scopeType = 'org';
    this._scopeId = '';
    this._fetchSeq = 0;
    this._result = null;
    this._policy = null;
    this._rows = {{}};
    CAP_NAMES.forEach((cap) => {{ this._rows[cap] = {{ value: cap === 'camera' ? 'off' : 'self', origins: [], input: '', error: '' }}; }});
    this.app = null;
    this.api = {{
      get: (url) => Promise.resolve({{ org: {{ camera: {{ value: 'off' }} }} }}),
      mutate: (url, opts) => Promise.resolve({{ ok: true }}),
    }};
  }}
  {scope_url_src}
  {collect_policy_src}
  _buildRows(policy) {{ return this._rows; }}
  {fetch_scope_src}
  {save_src}
}}

async function main() {{
  const ctx = new FakeCtx();
  await ctx._save();
  console.log(JSON.stringify({{ result: ctx._result }}));
}}
main();
"""
        out = self._run(script)
        result = json.loads(out)
        assert result["result"] == {"ok": True, "message": "Saved."}, (
            "FIND-CAPPOLICY-RACE-NOT-FIXED: after _save() (including its "
            "internal post-save _fetchScope() refresh), _result must still "
            f"be the 'Saved.' badge — got {result!r}"
        )

    def test_stale_response_guard_still_works_with_clearresult_false(self):
        """Confirms the badge fix does NOT reintroduce FIND-B-E: an
        out-of-order response must still be discarded even when
        clearResult=false is passed."""
        source = _UI4_MODULE.read_text(encoding="utf-8")
        fetch_scope_src = _extract_method(source, "_fetchScope")
        scope_url_src = _extract_method(source, "_scopeUrl")

        script = f"""
class FakeCtx {{
  constructor() {{
    this._scopeType = 'org';
    this._scopeId = '';
    this._fetchSeq = 0;
    this._result = {{ ok: true, message: 'Saved.' }};
    this._policy = null;
    this._rows = null;
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

  const p1 = ctx._fetchScope(false);   // clearResult=false, as _save() now does
  ctx._scopeType = 'group';
  ctx._scopeId = 'g1';
  const p2 = ctx._fetchScope(false);
  await Promise.all([p1, p2]);

  console.log(JSON.stringify({{ policy: ctx._policy, result: ctx._result }}));
}}
main();
"""
        out = self._run(script)
        result = json.loads(out)
        assert result["policy"] == {"camera": {"value": "FRESH-GROUP"}}, (
            f"FIND-B-E must still hold with clearResult=false — got {result!r}"
        )
        assert result["result"] == {"ok": True, "message": "Saved."}, (
            "clearResult=false must never null out a pre-existing _result — "
            f"got {result!r}"
        )


class TestSaveBadgeSurvivesRefetchLegacy(_NodeRunner):
    def test_save_result_not_clobbered_by_post_save_fetchandrender(self):
        source = _LEGACY_JS.read_text(encoding="utf-8")
        save_fn_src = _extract_function(source, "capPolSave")
        fetch_fn_src = _extract_function(source, "_capFetchAndRender")
        collect_fn_src = _extract_function(source, "_capCollectPolicy")
        get_origins_fn_src = _extract_function(source, "_capGetOrigins")
        cap_id_fn_src = _extract_function(source, "_capId")

        script = f"""
var CAP_NAMES = ['camera', 'microphone', 'geolocation', 'display-capture', 'fullscreen'];
var _capScopeType = 'org';
var _capScopeId = '';
var _capFetchSeq = 0;

var _lastResultHtml = null;
function _capSetResult(html) {{ _lastResultHtml = html; }}
function _capRenderRows(policy) {{ /* no-op */ }}

var _fakeValues = {{ camera: 'off', microphone: 'self', geolocation: 'self', 'display-capture': 'self', fullscreen: 'self' }};
var document = {{
  getElementById: function(id) {{
    var m = /^cap-val-(.+)$/.exec(id);
    if (!m) return null;
    var cap = m[1].replace(/_/g, '-');
    return {{ value: _fakeValues[cap] }};
  }}
}};

{cap_id_fn_src}
{get_origins_fn_src}
{collect_fn_src}

function api(url) {{
  return Promise.resolve({{ org: {{ camera: {{ value: 'off' }} }} }});
}}
function apiMutate(url, opts) {{
  return Promise.resolve({{ ok: true, json: function() {{ return Promise.resolve({{}}); }} }});
}}

{fetch_fn_src}
{save_fn_src}

async function main() {{
  await capPolSave();
  console.log(JSON.stringify({{ result: _lastResultHtml }}));
}}
main();
"""
        out = self._run(script)
        result = json.loads(out)
        assert result["result"] == '<span class="badge badge-green">Saved.</span>', (
            "FIND-CAPPOLICY-RACE-NOT-FIXED (legacy): after capPolSave() "
            "(including its internal post-save _capFetchAndRender() "
            f"refresh), the result span must still show 'Saved.' — got {result!r}"
        )
