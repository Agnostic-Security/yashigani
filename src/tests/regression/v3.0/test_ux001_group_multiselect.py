"""
Regression tests — UX-001 (AVA-2255-XX): agent group fields converted from
free-text inputs to pre-populated multi-select dropdowns.

Verifies (source-level, no browser required):
  1. dashboard.html has <select multiple> for agent-groups (not <input type="text">).
  2. dashboard.html has <select multiple> for agent-caller-groups (not <input type="text">).
  3. dashboard.html has <select multiple> for edit-agent-groups (not <input type="text">).
  4. dashboard.html has <select multiple> for edit-agent-caller-groups (not <input type="text">).
  5. dashboard.html contains options for 'users' and 'owui-users' in agent-groups.
  6. dashboard.js defines populateGroupSelects() function.
  7. dashboard.js defines _getSelectedGroups() helper.
  8. dashboard.js defines _setSelectedGroups() helper.
  9. dashboard.js uses _getSelectedGroups, not .value.trim().split for group fields.
  10. dashboard.js calls populateGroupSelects() inside loadAgents().
"""
from __future__ import annotations

import pathlib
import re

import pytest

_STATIC = pathlib.Path(__file__).parents[3] / "yashigani" / "backoffice"
_HTML = _STATIC / "templates" / "dashboard.html"
_JS = _STATIC / "static" / "js" / "dashboard.js"


@pytest.fixture(scope="module")
def html_src():
    return _HTML.read_text()


@pytest.fixture(scope="module")
def js_src():
    return _JS.read_text()


# ---------------------------------------------------------------------------
# 1-4. dashboard.html uses <select multiple> not <input type="text"> for groups
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sel_id", [
    "agent-groups",
    "agent-caller-groups",
    "edit-agent-groups",
    "edit-agent-caller-groups",
])
def test_group_field_is_select_multiple(html_src, sel_id):
    """UX-001: group fields must be <select multiple>, not <input type='text'>."""
    # Must NOT be an input type text
    bad_pattern = re.compile(
        r'<input[^>]+id=["\']' + re.escape(sel_id) + r'["\'][^>]+type=["\']text["\']'
        r'|'
        r'<input[^>]+type=["\']text["\'][^>]+id=["\']' + re.escape(sel_id) + r'["\']',
    )
    assert not bad_pattern.search(html_src), (
        f"UX-001 REGRESSION: #{sel_id} is still an <input type='text'> — "
        "must be a <select multiple>"
    )
    # Must be a <select multiple>
    good_pattern = re.compile(
        r'<select[^>]+id=["\']' + re.escape(sel_id) + r'["\'][^>]*multiple'
        r'|'
        r'<select[^>]*multiple[^>]+id=["\']' + re.escape(sel_id) + r'["\']',
    )
    assert good_pattern.search(html_src), (
        f"UX-001: #{sel_id} must have a <select multiple> element in dashboard.html"
    )


# ---------------------------------------------------------------------------
# 5. Baseline options 'users' and 'owui-users' present in HTML
# ---------------------------------------------------------------------------

def test_baseline_options_present(html_src):
    """UX-001: 'users' and 'owui-users' options must be in dashboard.html agent-groups."""
    assert 'value="users"' in html_src, (
        "UX-001: 'users' option not found in dashboard.html — baseline group missing"
    )
    assert 'value="owui-users"' in html_src, (
        "UX-001: 'owui-users' option not found in dashboard.html — baseline group missing"
    )


# ---------------------------------------------------------------------------
# 6-8. dashboard.js defines the required helper functions
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fn_name", [
    "populateGroupSelects",
    "_getSelectedGroups",
    "_setSelectedGroups",
])
def test_js_helper_functions_defined(js_src, fn_name):
    """UX-001: dashboard.js must define the group-select helper functions."""
    assert f"function {fn_name}" in js_src, (
        f"UX-001: {fn_name}() not found in dashboard.js"
    )


# ---------------------------------------------------------------------------
# 9. dashboard.js uses _getSelectedGroups, not .value.trim().split for groups
# ---------------------------------------------------------------------------

def test_no_stale_split_on_group_fields(js_src):
    """UX-001: registerAgent/saveEditAgent must use _getSelectedGroups, not .value.split."""
    # The old pattern was: .getElementById('agent-groups').value.trim().split(...)
    # After the fix it must not appear for any of the 4 group selects.
    stale_pattern = re.compile(
        r"getElementById\(['\"](?:agent-groups|agent-caller-groups|"
        r"edit-agent-groups|edit-agent-caller-groups)['\"]"
        r"\)\.value"
    )
    assert not stale_pattern.search(js_src), (
        "UX-001 REGRESSION: stale .value read on a group select field found in "
        "dashboard.js — must use _getSelectedGroups() instead"
    )


# ---------------------------------------------------------------------------
# 10. populateGroupSelects() called inside loadAgents()
# ---------------------------------------------------------------------------

def test_populate_called_in_load_agents(js_src):
    """UX-001: loadAgents() must call populateGroupSelects()."""
    # Find the loadAgents function body
    match = re.search(r'async function loadAgents\(\)(.*?)^(?:async )?function ', js_src, re.DOTALL | re.MULTILINE)
    assert match, "loadAgents() not found in dashboard.js"
    fn_body = match.group(1)
    assert "populateGroupSelects" in fn_body, (
        "UX-001: loadAgents() must call populateGroupSelects() to populate dropdowns "
        "when the Agents tab loads"
    )
