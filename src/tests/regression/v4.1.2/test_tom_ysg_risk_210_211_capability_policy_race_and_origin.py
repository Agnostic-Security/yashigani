"""
Regression tests -- v4.1.2 YSG-RISK-210 / FIND-0805-003 / YSG-RISK-211
(capability-policy.js, ui4 admin module).

Prior art read before touching anything (Change Management SS4.2):
  - AgnosticSecurity/Risk Management/yashigani-risks.md YSG-RISK-210, -211.
  - `git log -S_fetchScope` / `git log -S_onLoadScope` on this file: only
    prior touch is 6576d477 (YSG-RISK-163, ui4 port) -- no earlier fix
    attempt on this specific defect to be consistent with or avoid undoing.
  - Ava's in-file triage in
    src/tests/playwright/test_capability_policy_ui.py::TestCapPolSave
    (test_save_org_policy_camera_off docstring) -- root cause and both live
    repro methods documented there; this test file does not repeat that
    narrative, it locks the fix down structurally.

Three distinct defects, same file, same visible symptom in one case:

  YSG-RISK-210 (lost-update race): `_fetchScope()`'s completion
  unconditionally overwrote `this._rows` from server data, silently
  discarding any edit made while the GET was in flight. Fixed via a
  `_dirty` guard (an edit landing mid-fetch is kept, not clobbered, and the
  user is told) plus a `_fetchInFlight` re-entrancy guard, plus a no-op
  guard on `_onScopeTypeChange()` (it used to re-fetch even when the
  <select> value hadn't changed).

  FIND-0805-003 (dead success badge): `_save()` set `_result` to the
  success message, then called `_fetchScope()`, which unconditionally
  nulled `_result` again in the same Lit update batch -- "Saved." could
  never paint. Distinct mechanism from YSG-RISK-210 (fixing one does not
  fix the other) -- fixed by no longer touching `_result` inside
  `_fetchScope()` at all; callers that want a fresh load to clear a stale
  result (Load button, scope switch) clear it themselves before fetching.

  YSG-RISK-211 (origin validation bypass): `_addOrigin()` called
  `normaliseOrigin(row.input)` BEFORE validating, then validated the
  *normalised* value. `https://example.com/some/path` had its path
  silently stripped by normaliseOrigin() before isValidOrigin() ever saw
  it (passed). `https://*.example.com` had its '*' percent-encoded to
  '%2A' by `new URL()` inside normaliseOrigin() before isValidOrigin()'s
  `indexOf('*')` check ran on the already-encoded string (also passed).
  Live-confirmed both bypasses via a headless-Chromium eval against the
  file's actual isValidOrigin()/normaliseOrigin() bodies before fixing.
  Fixed by validating the RAW trimmed input first, normalising only a
  value that already passed. Server-side (capability_policy/model.py
  `_HTTPS_ORIGIN_RE`) was checked and already rejected both shapes
  correctly -- see TestValidation::test_allow_list_path_in_origin_rejected
  and ::test_allow_list_wildcard_host_rejected in
  src/tests/regression/v3.0/test_capability_policy.py (both PASS already,
  unaffected by this change) -- this was a client-side-only gap.

Runtime/behavioural proof (not repeated as static assertions here):
  - src/tests/playwright/test_capability_policy_ui.py::
    TestCapPolLostUpdateRaceRegression and ::TestCapPolSaveBadgeRegression
    -- live-stack Playwright tests, deterministic repro via page.route()
    holding the capability-policy GET open. Confirmed FAILING against the
    currently-deployed (pre-fix) backoffice image (no static/ bind-mount --
    image: yashigani/backoffice:${YASHIGANI_VERSION}, built not mounted);
    will pass once that image is rebuilt from this branch.
  - A standalone before/after harness (real module, real LitElement, real
    Chromium, mocked ApiClient with controllable GET timing -- no Docker
    needed) proved was-buggy -> now-closed deterministically for all three
    defects using the actual git-HEAD (pre-fix) and working-tree (post-fix)
    file contents. Evidence + scripts:
    testing_runs/yashigani/ytf-412-20260805/verification/tom-210-211/
    (run_regression.py, harness.html, serve.py -- not part of the shipped
    product, kept out of the repo per CLAUDE.md).

These tests are structural (source-text assertions), matching this repo's
established pattern for JS regression coverage (see the sibling
test_tom_ysg_risk_163_capability_policy_ui4_nav.py docstring: "this repo has
no JS test runner"). Runtime behaviour is covered by the Playwright tests
and the standalone harness referenced above, not re-derived here.
"""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_MODULE_FILE = (
    _REPO_ROOT / "yashigani" / "backoffice" / "static" / "ui4" / "admin"
    / "modules" / "capability-policy.js"
)


@pytest.fixture(scope="module")
def src() -> str:
    return _MODULE_FILE.read_text()


class TestModuleSyntaxValid:
    def test_module_is_valid_es_module_syntax(self, src):
        node = shutil.which("node")
        if not node:
            pytest.skip("node not installed -- syntax check skipped")
        result = subprocess.run(
            [node, "--input-type=module", "--check"],
            input=src, capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, f"node --check failed:\n{result.stderr}"


class TestYsgRisk210LostUpdateRaceGuard:
    """The fix has three independent load-bearing pieces; each is checked
    separately so a partial revert (e.g. someone "simplifying" _fetchScope()
    back to an unconditional overwrite while leaving the state fields in
    place) is caught."""

    def test_dirty_and_inflight_state_declared(self, src):
        assert re.search(r"_dirty:\s*\{\s*state:\s*true\s*\}", src), (
            "_dirty reactive property missing -- YSG-RISK-210 guard state"
        )
        assert re.search(r"_fetchInFlight:\s*\{\s*state:\s*true\s*\}", src), (
            "_fetchInFlight reactive property missing -- YSG-RISK-210 guard state"
        )

    def test_fetch_scope_does_not_unconditionally_overwrite_rows(self, src):
        """The historical bug: _fetchScope() ran `this._rows =
        this._buildRows(...)` unconditionally after the GET resolved. The
        fix must gate that assignment on `this._dirty` being false."""
        m = re.search(r"async _fetchScope\(\)\s*\{.*?\n  \}\n", src, re.DOTALL)
        assert m, "could not locate _fetchScope() body"
        body = m.group(0)
        assert "this._dirty" in body, (
            "_fetchScope() no longer checks _dirty -- YSG-RISK-210 regression risk"
        )
        # The row-rebuild assignment must be reachable only via a path that
        # already tested _dirty (or the early-return branches, which are
        # dirty-safe by construction -- no data was fetched). Concretely:
        # the string "this._dirty" must appear BEFORE
        # "this._rows = this._buildRows(" in the function body, i.e. the
        # dirty check happens before the clobbering assignment could run.
        dirty_idx = body.index("this._dirty")
        rebuild_idx = body.index("this._rows = this._buildRows(")
        assert dirty_idx < rebuild_idx, (
            "_dirty is checked AFTER the row-rebuild in _fetchScope() -- "
            "that reintroduces the YSG-RISK-210 clobber"
        )

    def test_fetch_scope_has_reentrancy_guard(self, src):
        m = re.search(r"async _fetchScope\(\)\s*\{(.*?)\n  \}\n", src, re.DOTALL)
        assert m
        body = m.group(1)
        assert re.search(r"if\s*\(\s*this\._fetchInFlight\s*\)\s*return", body), (
            "_fetchScope() missing the _fetchInFlight re-entrancy guard"
        )

    def test_scope_type_change_has_noop_guard(self, src):
        """_onScopeTypeChange() used to re-fetch even when the <select>
        value hadn't actually changed -- confirmed live re-triggering the
        exact same clobber even on a same-value reselect."""
        m = re.search(r"_onScopeTypeChange\(e\)\s*\{(.*?)\n  \}\n", src, re.DOTALL)
        assert m, "could not locate _onScopeTypeChange() body"
        body = m.group(1)
        assert re.search(
            r"if\s*\(\s*e\.target\.value\s*===\s*this\._scopeType\s*\)\s*return",
            body,
        ), "_onScopeTypeChange() missing the no-op (unchanged value) guard"

    def test_row_edit_handlers_mark_dirty(self, src):
        """An edit that isn't tracked as dirty is an edit that can still be
        silently discarded by a same-tick race -- every mutator of the
        persisted policy state (_onValueChange, successful _addOrigin,
        _removeOrigin) must set _dirty = true."""
        for fn_name in ("_onValueChange", "_addOrigin", "_removeOrigin"):
            m = re.search(rf"{fn_name}\([^)]*\)\s*\{{(.*?)\n  \}}\n", src, re.DOTALL)
            assert m, f"could not locate {fn_name}() body"
            assert "this._dirty = true" in m.group(1), (
                f"{fn_name}() no longer marks _dirty -- YSG-RISK-210 regression risk"
            )


class TestFind0805003SuccessBadgeNotDead:
    def test_fetch_scope_no_longer_nulls_result(self, src):
        m = re.search(r"async _fetchScope\(\)\s*\{(.*?)\n  \}\n", src, re.DOTALL)
        assert m
        body = m.group(1)
        assert "this._result = null" not in body, (
            "_fetchScope() nulls _result again -- this is exactly what made "
            "the 'Saved.' badge dead code (FIND-0805-003); _save()/_delete() "
            "set _result then call _fetchScope() in the same tick, and Lit "
            "batches both writes -- only the null survived"
        )

    def test_save_clears_dirty_before_refresh(self, src):
        """_save() must clear _dirty (the edit is now persisted, no longer
        "unsaved") BEFORE calling _fetchScope(), otherwise the post-save
        refresh would hit the YSG-RISK-210 dirty-guard and show a spurious
        "kept your edit" warning instead of "Saved."."""
        m = re.search(r"async _save\(\)\s*\{(.*?)\n  \}\n", src, re.DOTALL)
        assert m, "could not locate _save() body"
        body = m.group(1)
        assert "this._dirty = false" in body
        dirty_idx = body.index("this._dirty = false")
        fetch_idx = body.index("await this._fetchScope()")
        assert dirty_idx < fetch_idx, (
            "_save() clears _dirty AFTER calling _fetchScope() -- ordering "
            "must be dirty-clear then refresh"
        )

    def test_delete_clears_dirty_before_refresh(self, src):
        m = re.search(r"async _delete\(\)\s*\{(.*?)\n  \}\n", src, re.DOTALL)
        assert m, "could not locate _delete() body"
        body = m.group(1)
        assert "this._dirty = false" in body
        dirty_idx = body.index("this._dirty = false")
        fetch_idx = body.index("await this._fetchScope()")
        assert dirty_idx < fetch_idx


class TestYsgRisk211OriginValidationOrder:
    def test_add_origin_validates_before_normalising(self, src):
        """The historical bug: normaliseOrigin(row.input) ran BEFORE
        isValidOrigin(), so both a path-bearing origin (path silently
        stripped by normaliseOrigin's `${url.protocol}//${url.host}`
        rebuild) and a wildcard origin ('*' percent-encoded to '%2A' by
        `new URL()` before the indexOf('*') check ever saw it) passed
        validation. The fix validates the untouched raw input first."""
        m = re.search(r"_addOrigin\(cap\)\s*\{(.*?)\n  \}\n", src, re.DOTALL)
        assert m, "could not locate _addOrigin() body"
        body = m.group(1)
        # Strip `//`-style comment lines first -- the fix's own explanatory
        # comment mentions both function names (in the opposite order, as
        # narrative), which would otherwise confuse a plain substring search
        # over the raw body text.
        code_only = "\n".join(
            line for line in body.splitlines() if not line.strip().startswith("//")
        )
        valid_match = re.search(r"isValidOrigin\(raw\)", code_only)
        normalise_match = re.search(r"normaliseOrigin\(raw\)", code_only)
        assert valid_match, "isValidOrigin() is not validating the raw trimmed input"
        assert normalise_match, (
            "normaliseOrigin() is not normalising the same raw input that was validated"
        )
        assert valid_match.start() < normalise_match.start(), (
            "_addOrigin() calls normaliseOrigin(raw) before isValidOrigin(raw) -- "
            "that reintroduces the YSG-RISK-211 path-strip/wildcard-encode "
            "bypass (both silently pass validation once normalised first)"
        )

    def test_is_valid_origin_checks_wildcard_before_url_parse(self, src):
        """The '*' check must run on the untouched string, before any
        `new URL()` round-trip that would percent-encode it."""
        m = re.search(r"function isValidOrigin\(s\)\s*\{(.*?)\n\}\n", src, re.DOTALL)
        assert m, "could not locate isValidOrigin() function"
        body = m.group(1)
        star_idx = body.index("indexOf('*')")
        url_idx = body.index("new URL(")
        assert star_idx < url_idx, (
            "isValidOrigin() parses the URL before checking for a literal "
            "'*' -- new URL() percent-encodes '*' to '%2A', which would "
            "make this check unreachable for wildcard input"
        )

    def test_is_valid_origin_rejects_non_root_path(self, src):
        m = re.search(r"function isValidOrigin\(s\)\s*\{(.*?)\n\}\n", src, re.DOTALL)
        assert m
        assert "url.pathname !== '/'" in m.group(1), (
            "isValidOrigin() no longer rejects a non-root pathname"
        )
