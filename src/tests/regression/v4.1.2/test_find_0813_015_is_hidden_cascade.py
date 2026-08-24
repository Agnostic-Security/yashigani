"""
FIND-0813-015 — the `.is-hidden` visibility utility was silently defeated by
later component rules of identical specificity.

Found in pre-push code-quality review (Change Management 4.4), NOT by a test.
That is the point of this file.

## The defect

`dashboard.css` defines `.is-hidden { display: none }` at :171 and then defines
component rules further down that also set `display` with the SAME specificity
(one class each). CSS resolves equal-specificity conflicts by source order, so
every such component rule wins and `.is-hidden` does nothing to those elements:

  - `.dp-protection-banner` (:414, `display:flex`) — both data-protection
    banners rendered permanently visible and empty, and
    `classList.add('is-hidden')` (dashboard.js:796,810) was a no-op, so the red
    "data-protection controls weakened" warning could never be dismissed.
  - `.cap-scope-picker` (:619, `display:flex`) — 5 group/user/agent pickers.
  - `.pol-row` (:174, `display:flex`) — the policy rego edit controls.

The banner case was introduced when two `style="display:none"` attributes were
replaced with the class to satisfy the no-inline-styles CSP guard. The other two
predate it. So the CSP fix converted a working inline style into a non-working
class — the assertion passed and the behaviour broke.

## Why the existing guards could not see it

`test_csp_no_inline_styles.py` counts `style=` attributes in the template. A
cascade conflict lives in the interaction between the stylesheet's rule ORDER
and the template's class usage. No count of inline attributes can detect it,
and neither can a test that checks the rule merely EXISTS.

## What this test asserts

The property, not the spelling: for every class that appears on an element
alongside `is-hidden` in dashboard.html, hiding must actually win. That holds if
`.is-hidden` is `!important` (the current fix), and also holds if a future
refactor instead reorders the file or scopes the component rules — this test
does not mandate the mechanism, only the outcome.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# parents: [0]=v4.1.2 [1]=regression [2]=tests [3]=src — the package lives under
# src/yashigani, so anchor on [3] rather than the repo root.
_BACKOFFICE = Path(__file__).resolve().parents[3] / "yashigani" / "backoffice"
_CSS = _BACKOFFICE / "static" / "css" / "dashboard.css"
_HTML = _BACKOFFICE / "templates" / "dashboard.html"

# Fail loudly at import rather than letting a bad path masquerade as a finding:
# a FileNotFoundError inside a test body reads as "the guard fired" when it
# actually means the guard never ran (cf. YTF 5.14).
assert _CSS.is_file(), f"dashboard.css not at {_CSS}"
assert _HTML.is_file(), f"dashboard.html not at {_HTML}"

_HIDE_UTILITY = "is-hidden"


def _companion_classes() -> set[str]:
    """Every class sharing an element with `is-hidden` in the template."""
    html = _HTML.read_text(encoding="utf-8")
    out: set[str] = set()
    for attr in re.findall(r'class="([^"]*)"', html):
        classes = attr.split()
        if _HIDE_UTILITY in classes:
            out.update(c for c in classes if c != _HIDE_UTILITY)
    return out


def _utility_rule() -> tuple[int, str]:
    """(line number, declaration body) of the single-class .is-hidden rule."""
    for i, line in enumerate(_CSS.read_text(encoding="utf-8").splitlines(), 1):
        m = re.match(rf"^\.{_HIDE_UTILITY}\s*\{{(.*)\}}", line.strip())
        if m:
            return i, m.group(1)
    pytest.fail(f".{_HIDE_UTILITY} single-class rule not found in {_CSS.name}")


def _display_setting_rules(cls: str) -> list[tuple[int, str]]:
    """Single-class rules for `cls` that set `display`, with line numbers.

    Only bare `.cls { ... }` rules are considered — those are the ones with
    specificity equal to `.is-hidden`. A more specific selector legitimately
    wins and is out of scope here.
    """
    hits: list[tuple[int, str]] = []
    for i, line in enumerate(_CSS.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not re.match(rf"^\.{re.escape(cls)}\s*\{{", stripped):
            continue
        if re.search(r"\bdisplay\s*:", stripped):
            hits.append((i, stripped[:100]))
    return hits


def test_hide_utility_is_not_defeated_by_equal_specificity_component_rules():
    util_line, util_body = _utility_rule()
    util_wins_regardless = "!important" in util_body

    losers: list[str] = []
    for cls in sorted(_companion_classes()):
        for line_no, text in _display_setting_rules(cls):
            # Equal specificity: later source position wins unless the utility
            # is marked !important.
            if line_no > util_line and not util_wins_regardless:
                losers.append(
                    f"  .{cls} at :{line_no} sets display after "
                    f".{_HIDE_UTILITY} at :{util_line} and therefore wins\n"
                    f"    {text}"
                )

    assert not losers, (
        f"`.{_HIDE_UTILITY}` cannot hide these elements — adding the class is a "
        f"no-op on them:\n" + "\n".join(losers) +
        f"\n\nFix by making .{_HIDE_UTILITY} authoritative (!important), or by "
        f"giving the component rules a hidden/shown pair the way .n1-banner "
        f"does. Do NOT fix by deleting the class from the template: that "
        f"reintroduces the inline style CSP forbids."
    )


@pytest.mark.parametrize(
    "element_id",
    ["dp-protection-banner", "dp-weaken-pending-banner"],
)
def test_data_protection_banners_start_hidden_and_are_hideable(element_id):
    """These two are called out by id because their failure mode is a security
    UX one: the banner that tells an admin data-protection controls have been
    weakened must be able to appear AND disappear in step with the real state.
    A permanently-visible empty banner trains operators to ignore it."""
    html = _HTML.read_text(encoding="utf-8")
    m = re.search(rf'<div id="{element_id}"[^>]*class="([^"]*)"', html)
    assert m, f"{element_id} not found in dashboard.html"
    classes = m.group(1).split()

    assert _HIDE_UTILITY in classes, (
        f"{element_id} must start hidden via the .{_HIDE_UTILITY} class"
    )
    assert "style=" not in m.group(0), (
        f"{element_id} must not use an inline style (CSP) — that is what the "
        f"class is for"
    )

    _, util_body = _utility_rule()
    component_rules = [
        r for c in classes if c != _HIDE_UTILITY
        for r in _display_setting_rules(c)
    ]
    util_line, _ = _utility_rule()
    if "!important" not in util_body:
        assert not [r for r in component_rules if r[0] > util_line], (
            f"{element_id} carries .{_HIDE_UTILITY} but a later component rule "
            f"overrides display, so it renders visible anyway: {component_rules}"
        )
