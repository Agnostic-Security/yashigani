# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""The `/v1/{path:path}` passthrough may not address anything outside `/v1/`.

YSG-RISK-315. `target_url` is built by string interpolation:

    target_url = f"{base}/v1/{path}"

and `httpx.URL` NORMALISES `../`. Measured:

    "../slots/0"      -> http://host/slots/0            ESCAPES
    "../../slots/0"   -> http://host/slots/0            ESCAPES
    "..%2fslots%2f0"  -> http://host/v1/..%2fslots%2f0  contained
    "%2e%2e/slots/0"  -> http://host/v1/%2e%2e/slots/0  contained

So a caller could walk out of `/v1/` onto llama-server's own control endpoints.

Today this is inert: we pass neither `--slots` nor `--slot-save-path`, so those
endpoints are off or answer 501. It stops being inert the moment
`--slot-save-path` is enabled to build the per-user prompt cache, because that
one flag also unlocks `save` and `restore` on `/slots/{id}` — dump one user's
KV state, load it into another user's slot. Measured: erase is 501 without the
flag and 200 with it.

The guard therefore lands BEFORE that flag, not alongside it.

Note the check is applied POST-normalisation, not as a substring scan for "..".
The encoded rows above are exactly why scanning the raw path is the wrong test:
it would reject the safe ones and still need normalisation for the real ones.
"""

from __future__ import annotations

import httpx
import pytest


_BASE = "http://127.0.0.1:39000"


def _resolves_outside_v1(path: str) -> bool:
    """The production guard's exact predicate."""
    target = str(httpx.URL(f"{_BASE}/v1/{path}"))
    return not target.startswith(f"{_BASE}/v1/")


# --- the normalisation facts this guard exists for --------------------------


@pytest.mark.parametrize("path", ["../slots/0", "../../slots/0", "../health", "../../../props"])
def test_dot_dot_paths_escape_and_are_caught(path: str) -> None:
    assert _resolves_outside_v1(path), f"{path!r} should be rejected by the guard"


@pytest.mark.parametrize(
    "path",
    ["chat/completions", "completions", "embeddings", "models", "chat/completions?x=1"],
)
def test_legitimate_v1_paths_are_not_caught(path: str) -> None:
    """A guard that blocks real traffic gets removed, so this half matters as
    much as the half above."""
    assert not _resolves_outside_v1(path)


@pytest.mark.parametrize("path", ["..%2fslots%2f0", "%2e%2e/slots/0"])
def test_encoded_forms_stay_contained(path: str) -> None:
    """These do NOT escape once normalised — documenting why the check is on
    the normalised URL rather than a substring scan of the raw path."""
    assert not _resolves_outside_v1(path)


def test_the_specific_endpoint_this_protects() -> None:
    """`/slots/{id}?action=restore` is the cross-user KV transfer primitive."""
    assert _resolves_outside_v1("../slots/0?action=restore")
    assert _resolves_outside_v1("../slots/0?action=save")


# --- the guard is actually wired into the app, not just defined -------------


def test_guard_is_present_in_the_passthrough() -> None:
    """Drift guard: the predicate above mirrors production, so it would keep
    passing if the production check were deleted. This asserts the real code
    still contains it."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src" / "kuroshio" / "app.py"
    body = src.read_text()
    assert 'str(httpx.URL(f"{_base}/v1/{path}"))' in body, "passthrough no longer normalises"
    assert 'if not target_url.startswith(f"{_base}/v1/")' in body, "containment check missing"
