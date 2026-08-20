# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Contract tests for the kuroshio-front `/api/pull` URL-convention fix (Iris F1
cutover-prep map, Seam 5, her recommended option (b)) + the single-source
Helm mirror discipline for `Caddyfile.kuroshio-front`.

Background: `backoffice/routes/models.py` builds pull URLs as
`base + "/api/pull"` (the ollama convention). If `base` ever points at the
engine's Caddy front, that resolves to `/kuroshio/api/pull` — which the
pre-existing literal `handle_path /kuroshio/pull*` route does NOT match (no
`/api` segment). Without a dedicated route it falls through the generic
`handle_path /kuroshio/*` catch-all to kuroshio-chat, whose `/api/pull` returns 501
(no `pull_resolver` on that role) — a silent pull failure at cutover. The fix
adds `handle_path /kuroshio/api/pull*`, rewriting to `/api/pull` and reaching
the SAME puller upstream as the pre-existing `/kuroshio/pull*` route.

Pins three invariants:
  (a) `/kuroshio/api/pull*` is present, ordered ahead of the generic `/kuroshio/*`
      catch-all, rewrites to `/api/pull`, and reaches the same kuroshio-puller
      upstream as the literal `/kuroshio/pull*` route.
  (b) `caddy adapt` succeeds against the canonical Caddyfile.
  (c) The canonical file and its Helm ConfigMap mirror
      (`helm/yashigani-kuroshio/files/Caddyfile.kuroshio-front`) stay byte-identical
      (`scripts/sync-kuroshio-deploy-artifacts-to-helm.sh` single-source
      discipline).

Skip policy: the `caddy adapt` / JSON-structure assertions skip cleanly if no
`caddy` binary is on PATH; the byte-parity check has no such dependency and
always runs.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

_INFER_ROOT = Path(__file__).parent.parent  # infer/
_CANONICAL = _INFER_ROOT / "deploy" / "docker" / "Caddyfile.kuroshio-front"
_MIRROR = _INFER_ROOT / "deploy" / "helm" / "yashigani-kuroshio" / "files" / "Caddyfile.kuroshio-front"
_SYNC_SCRIPT = _INFER_ROOT / "deploy" / "scripts" / "sync-kuroshio-deploy-artifacts-to-helm.sh"
_CONFIGMAP_TEMPLATE = (
    _INFER_ROOT / "deploy" / "helm" / "yashigani-kuroshio" / "templates" / "configmap-caddy-kuroshio-front.yaml"
)


def _caddy_binary() -> str | None:
    return shutil.which("caddy")


def _read_bytes(path: Path) -> bytes:
    assert path.exists(), f"file not found: {path}"
    return path.read_bytes()


# ---------------------------------------------------------------------------
# (a) /kuroshio/api/pull* route present, correctly ordered
# ---------------------------------------------------------------------------


def test_infer_api_pull_route_present_and_ordered_before_catchall() -> None:
    text = _CANONICAL.read_text(encoding="utf-8")
    assert "handle_path /kuroshio/api/pull*" in text, (
        "\nCaddyfile.kuroshio-front is missing the /kuroshio/api/pull* route (Iris F1 "
        'Seam 5 fix, option (b)) — a caller using the ollama base+"/api/pull" '
        "URL convention will fall through the generic /kuroshio/* catch-all to "
        "kuroshio-chat, which 501s (no pull_resolver on that role)."
    )
    # Caddyfile handle/handle_path blocks are mutually exclusive, first-match:
    # the specific /kuroshio/api/pull* route MUST be declared before the generic
    # /kuroshio/* catch-all or it would never get a chance to match.
    assert text.index("handle_path /kuroshio/api/pull*") < text.index("handle_path /kuroshio/*"), (
        "/kuroshio/api/pull* must be declared before the generic /kuroshio/* catch-all in file order."
    )


def _matcher_paths(route: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for matcher in route.get("match", []):
        paths.extend(matcher.get("path", []))
    return paths


def _subroutes(route: dict[str, Any]) -> list[dict[str, Any]]:
    return list(route["handle"][0]["routes"])  # route["handle"][0] is the "subroute" handler


def _rewrite_targets(route: dict[str, Any]) -> list[str]:
    targets: list[str] = []
    for subroute in _subroutes(route):
        for handler in subroute.get("handle", []):
            if handler.get("handler") == "rewrite" and "uri" in handler:
                targets.append(handler["uri"])
    return targets


def _puller_upstreams(route: dict[str, Any]) -> list[str]:
    upstreams: list[str] = []
    for subroute in _subroutes(route):
        for handler in subroute.get("handle", []):
            if handler.get("handler") == "reverse_proxy":
                upstreams.extend(u["dial"] for u in handler.get("upstreams", []))
    return upstreams


def _adapt_canonical() -> dict[str, Any]:
    caddy = _caddy_binary()
    assert caddy is not None
    result = subprocess.run(
        [caddy, "adapt", "--config", str(_CANONICAL), "--adapter", "caddyfile"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"\ncaddy adapt FAILED (exit {result.returncode}) for {_CANONICAL}:\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    config: dict[str, Any] = json.loads(result.stdout)
    return config


def test_caddy_adapt_succeeds_on_canonical() -> None:
    """(b) — catches structural breakage (missing brace, bad directive) of
    the canonical file, including anything introduced by the fix."""
    if _caddy_binary() is None:
        pytest.skip("caddy binary not found on PATH")
    _adapt_canonical()  # asserts returncode == 0 internally


def test_infer_api_pull_rewrites_to_api_pull_and_reaches_puller_upstream() -> None:
    """(a) — the adapted-JSON assertion: the new route rewrites to /api/pull
    and dials the SAME kuroshio-puller upstream as the pre-existing literal
    /kuroshio/pull* route (not kuroshio-chat/kuroshio-classifier)."""
    if _caddy_binary() is None:
        pytest.skip("caddy binary not found on PATH")
    config = _adapt_canonical()
    routes = config["apps"]["http"]["servers"]["srv0"]["routes"]

    api_pull_route = next((r for r in routes if "/kuroshio/api/pull*" in _matcher_paths(r)), None)
    assert api_pull_route is not None, "no adapted route matches /kuroshio/api/pull*"

    literal_pull_route = next((r for r in routes if "/kuroshio/pull*" in _matcher_paths(r)), None)
    assert literal_pull_route is not None, "no adapted route matches /kuroshio/pull* (pre-existing route missing?)"

    assert "/api/pull" in _rewrite_targets(api_pull_route), (
        f"/kuroshio/api/pull* does not rewrite to /api/pull: {_rewrite_targets(api_pull_route)}"
    )

    api_pull_upstreams = _puller_upstreams(api_pull_route)
    literal_pull_upstreams = _puller_upstreams(literal_pull_route)
    assert api_pull_upstreams, "/kuroshio/api/pull* has no reverse_proxy upstream at all"
    assert api_pull_upstreams == literal_pull_upstreams, (
        "/kuroshio/api/pull* must reach the SAME puller upstream as the literal "
        f"/kuroshio/pull* route: {api_pull_upstreams} != {literal_pull_upstreams}"
    )
    assert all("kuroshio-puller" in dial for dial in api_pull_upstreams), (
        f"/kuroshio/api/pull* upstream is not kuroshio-puller (would silently route "
        f"to the wrong role — kuroshio-chat/-classifier 501 on /api/pull): {api_pull_upstreams}"
    )


# ---------------------------------------------------------------------------
# (c) Caddyfile <-> Helm ConfigMap mirror byte-parity
# ---------------------------------------------------------------------------


def test_helm_mirror_byte_identical_to_canonical() -> None:
    assert _MIRROR.exists(), f"\nhelm mirror MISSING: {_MIRROR}\nFIX: run {_SYNC_SCRIPT}"
    canonical = _read_bytes(_CANONICAL)
    mirror = _read_bytes(_MIRROR)
    assert canonical == mirror, (
        "\nCaddyfile.kuroshio-front DRIFT — the helm mirror differs from the "
        "canonical docker file.\nNEVER hand-edit the helm copy: edit the "
        f"canonical file, then run {_SYNC_SCRIPT}"
    )


def test_mutation_planted_drift_is_caught(tmp_path: Path) -> None:
    """Mutation guard: a gate that passes on a mutated fixture is evidence
    fabrication — plant a one-byte drift and confirm the same comparison
    the parity test uses detects it."""
    canonical = _read_bytes(_CANONICAL)
    planted = canonical + b"\n# planted drift\n"
    mutated_mirror = tmp_path / "Caddyfile.kuroshio-front"
    mutated_mirror.write_bytes(planted)
    assert _read_bytes(_CANONICAL) != mutated_mirror.read_bytes(), (
        "MUTATION TEST FAILED: a planted one-byte drift was NOT detected by "
        "the byte comparison — the contract is broken."
    )


def test_sync_script_check_mode_catches_planted_drift(tmp_path: Path) -> None:
    """The sync script's --check mode is the pre-commit fix-path twin of the
    parity test above — verify it fails on a planted drift against a staged
    copy (never mutates the real tree)."""
    assert _SYNC_SCRIPT.exists(), f"sync script missing: {_SYNC_SCRIPT}"
    staged_deploy = tmp_path / "deploy"
    (staged_deploy / "docker").mkdir(parents=True)
    (staged_deploy / "scripts").mkdir()
    mirror_dir = staged_deploy / "helm" / "yashigani-kuroshio" / "files"
    mirror_dir.mkdir(parents=True)

    staged_script = staged_deploy / "scripts" / _SYNC_SCRIPT.name
    shutil.copy(_SYNC_SCRIPT, staged_script)
    staged_script.chmod(0o755)
    shutil.copy(_CANONICAL, staged_deploy / "docker" / _CANONICAL.name)
    (mirror_dir / _CANONICAL.name).write_bytes(_read_bytes(_CANONICAL) + b"\n# planted drift\n")

    result = subprocess.run([str(staged_script), "--check"], capture_output=True, text=True)
    assert result.returncode != 0, (
        "MUTATION TEST FAILED: sync-kuroshio-deploy-artifacts-to-helm.sh --check "
        f"exited 0 on a planted drift.\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "DRIFT" in result.stderr, f"--check failure message lacks 'DRIFT' diagnostic: {result.stderr!r}"


def test_configmap_template_uses_files_get_not_reinlined_copy() -> None:
    """The ConfigMap template must render via .Files.Get (single-source), not
    a re-inlined hand-coded copy of the listener internals."""
    text = _CONFIGMAP_TEMPLATE.read_text(encoding="utf-8")
    assert '.Files.Get "files/Caddyfile.kuroshio-front"' in text, (
        "\nconfigmap-caddy-kuroshio-front.yaml no longer loads the Caddyfile via "
        '.Files.Get "files/Caddyfile.kuroshio-front" — the single-source render '
        "has been removed or renamed."
    )
    reinlined_markers = (
        "(kuroshio-front-caller-gate)",
        "handle_path /kuroshio/pull*",
        "handle_path /kuroshio/api/pull*",
    )
    reinlined = [m for m in reinlined_markers if m in text]
    assert not reinlined, (
        "\nCaddyfile.kuroshio-front listener internals RE-INLINED in "
        f"configmap-caddy-kuroshio-front.yaml: {reinlined}\nEdit the canonical "
        f"file + run {_SYNC_SCRIPT}; never hand-code the routes in the helm template."
    )
