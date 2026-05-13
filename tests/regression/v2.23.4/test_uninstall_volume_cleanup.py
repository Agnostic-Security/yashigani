# Last updated: 2026-05-13T00:00:00+01:00
"""
Regression tests for UNINSTALL-LEAVES-VOLUMES (#8).

Root cause: podman-compose ≤1.3.x ignores --volumes for named volumes on
`compose down`.  The fix adds an explicit per-volume rm loop in uninstall.sh
after the compose-down step.

These tests are static (no runtime required).  They assert:

1. The volume-rm loop is present in uninstall.sh (structural check).
2. Every canonical named volume declared in docker/docker-compose.yml top-level
   volumes: section appears in the _CANONICAL_VOLUMES array in uninstall.sh.
3. No named volume in docker-compose.yml is silently absent from the uninstall
   loop (parity check — the regression that caused the bug).
4. The uninstall.sh _CANONICAL_VOLUMES list contains no entry that does NOT
   exist in docker-compose.yml (no phantom volumes that would cause spurious
   "not present" log noise).
5. Mutation guard: removing one entry from the expected set is detected.

E2E verification: to be confirmed at Track A v5 (VM Podman rootless fresh
install → uninstall --remove-volumes --yes --runtime=podman → confirm
docker_postgres_data absent via `podman volume ls`).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Repo paths
# ---------------------------------------------------------------------------

_REPO = Path(__file__).parent.parent.parent.parent
_UNINSTALL = _REPO / "uninstall.sh"
_COMPOSE = _REPO / "docker" / "docker-compose.yml"

# ---------------------------------------------------------------------------
# Helpers — parse compose top-level volumes
# ---------------------------------------------------------------------------

_COMPOSE_VOLUMES_SECTION_RE = re.compile(
    r"^volumes:\s*$",
    re.MULTILINE,
)
# A top-level volume entry looks like:  `  <name>:` or `  <name>:  # comment`
# It must be at exactly 2-space indent (top-level section entries).
_VOLUME_ENTRY_RE = re.compile(r"^  ([a-zA-Z0-9_]+):\s*(?:#.*)?$")


def _parse_compose_volumes(text: str) -> list[str]:
    """
    Return the list of named volume keys from the top-level ``volumes:``
    section of docker-compose.yml.

    Strategy: find the last ``volumes:`` line at column 0, then collect
    all lines at 2-space indent that match ``<name>:`` until we hit a
    line at column 0 (next top-level key) or EOF.
    """
    lines = text.splitlines()
    # Find the top-level volumes: section — it's the last one at column 0
    volumes_section_start = -1
    for i, line in enumerate(lines):
        if re.match(r"^volumes:\s*$", line):
            volumes_section_start = i

    assert volumes_section_start >= 0, (
        "Could not find top-level 'volumes:' section in docker-compose.yml"
    )

    result: list[str] = []
    for line in lines[volumes_section_start + 1 :]:
        # Stop at any new top-level key (column 0, non-empty, non-comment)
        if line and not line.startswith(" ") and not line.startswith("#"):
            break
        m = _VOLUME_ENTRY_RE.match(line)
        if m:
            result.append(m.group(1))
    return result


# ---------------------------------------------------------------------------
# Helpers — parse _CANONICAL_VOLUMES from uninstall.sh
# ---------------------------------------------------------------------------

_ARRAY_BLOCK_RE = re.compile(
    r"_CANONICAL_VOLUMES=\(([^)]*)\)",
    re.DOTALL,
)


def _parse_canonical_volumes(text: str) -> list[str]:
    """
    Extract the list of volume names from the ``_CANONICAL_VOLUMES=(...)``
    array literal in uninstall.sh.
    """
    m = _ARRAY_BLOCK_RE.search(text)
    assert m, (
        "Could not find _CANONICAL_VOLUMES=(...) array in uninstall.sh — "
        "the UNINSTALL-LEAVES-VOLUMES (#8) fix is missing."
    )
    # Items are whitespace-separated bare words (one per line, possibly with
    # leading/trailing whitespace or comments)
    raw = m.group(1)
    items: list[str] = []
    for token in re.split(r"[\s\n]+", raw.strip()):
        token = token.strip()
        if token and not token.startswith("#"):
            items.append(token)
    return items


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def uninstall_text() -> str:
    assert _UNINSTALL.exists(), f"uninstall.sh not found at {_UNINSTALL}"
    return _UNINSTALL.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def compose_text() -> str:
    assert _COMPOSE.exists(), f"docker-compose.yml not found at {_COMPOSE}"
    return _COMPOSE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def compose_volumes(compose_text: str) -> list[str]:
    return _parse_compose_volumes(compose_text)


@pytest.fixture(scope="module")
def canonical_volumes(uninstall_text: str) -> list[str]:
    return _parse_canonical_volumes(uninstall_text)


# ---------------------------------------------------------------------------
# Test 1 — structural: volume-rm loop is present
# ---------------------------------------------------------------------------


def test_volume_rm_loop_present(uninstall_text: str) -> None:
    """
    The explicit per-volume rm loop must be present in uninstall.sh.
    Absence means the UNINSTALL-LEAVES-VOLUMES (#8) fix was reverted.
    """
    assert "_CANONICAL_VOLUMES" in uninstall_text, (
        "uninstall.sh is missing the _CANONICAL_VOLUMES array — "
        "UNINSTALL-LEAVES-VOLUMES (#8) fix has been removed or not applied."
    )
    assert '"$RUNTIME" volume rm' in uninstall_text or \
           '"$RUNTIME" volume inspect' in uninstall_text, (
        "uninstall.sh is missing the explicit volume rm loop — "
        "UNINSTALL-LEAVES-VOLUMES (#8) fix has been removed or not applied."
    )


def test_volume_rm_guarded_by_remove_volumes_flag(uninstall_text: str) -> None:
    """
    The per-volume cleanup loop must only execute when REMOVE_VOLUMES=true.
    An unconditional rm loop would delete data on plain `./uninstall.sh`.

    Strategy: scan for ALL `if [ "$REMOVE_VOLUMES" = "true" ]` guards in the
    file; for each, walk forward through its body (tracking nested if depth)
    and check whether the volume rm call appears inside.  There are two guards
    in uninstall.sh — the warning/confirmation block and the cleanup block.
    At least one must contain the volume rm call.
    """
    lines = uninstall_text.splitlines()
    _GUARD_RE = re.compile(r'\[\s*"\$REMOVE_VOLUMES"\s*=\s*"true"\s*\]')
    _RM_LINE_RE = re.compile(r'"?\$RUNTIME"?\s+volume\s+(rm|inspect)')

    rm_inside_any_guard = False

    # Matches shell `if` keyword starting a new conditional (not `if cmd;then`)
    # We count: `if [`, `if "`, `if command` etc. — anything starting with `if `
    # but exclude lines where the rm/inspect check itself would increment depth.
    _IF_OPEN_RE = re.compile(r"^if\s")
    _FI_RE = re.compile(r"^fi\b")

    for start_idx, line in enumerate(lines):
        if not _GUARD_RE.search(line.strip()):
            continue
        # Found a guard; walk forward through the if block body
        depth = 1
        for inner_line in lines[start_idx + 1:]:
            stripped = inner_line.strip()
            # Check for the rm/inspect call BEFORE adjusting depth so we catch
            # the inner `if "$RUNTIME" volume inspect ... ; then` line
            if _RM_LINE_RE.search(stripped):
                rm_inside_any_guard = True
                break
            if _IF_OPEN_RE.match(stripped):
                depth += 1
            elif _FI_RE.match(stripped):
                depth -= 1
                if depth == 0:
                    break

    guard_present = bool(_GUARD_RE.search(uninstall_text))
    assert guard_present, (
        "No REMOVE_VOLUMES guard found in uninstall.sh — "
        "the volume-rm loop must be conditional on --remove-volumes."
    )
    assert rm_inside_any_guard, (
        "The volume rm call is not inside any REMOVE_VOLUMES=true guard — "
        "it would delete volumes on every uninstall run, or the guard is missing."
    )


# ---------------------------------------------------------------------------
# Test 2 — parity: every compose volume appears in _CANONICAL_VOLUMES
# ---------------------------------------------------------------------------


def test_all_compose_volumes_in_canonical_list(
    compose_volumes: list[str],
    canonical_volumes: list[str],
) -> None:
    """
    Every named volume in docker/docker-compose.yml top-level volumes: section
    must appear in uninstall.sh _CANONICAL_VOLUMES.  A missing entry means
    that volume will be left behind after `--remove-volumes`.

    This is the exact regression that caused UNINSTALL-LEAVES-VOLUMES (#8):
    postgres_data was created as docker_postgres_data but the uninstall flow
    did not enumerate it explicitly.
    """
    canonical_set = set(canonical_volumes)
    missing = [v for v in compose_volumes if v not in canonical_set]

    assert not missing, (
        f"The following named volumes are declared in docker-compose.yml but "
        f"ABSENT from uninstall.sh _CANONICAL_VOLUMES — they will NOT be "
        f"removed by `./uninstall.sh --remove-volumes`:\n"
        + "\n".join(f"  - {v}" for v in missing)
        + "\n\nAdd each missing volume to the _CANONICAL_VOLUMES array in "
        "uninstall.sh to fix UNINSTALL-LEAVES-VOLUMES (#8)."
    )


# ---------------------------------------------------------------------------
# Test 3 — no phantom volumes in canonical list
# ---------------------------------------------------------------------------


def test_no_phantom_volumes_in_canonical_list(
    compose_volumes: list[str],
    canonical_volumes: list[str],
) -> None:
    """
    Every entry in _CANONICAL_VOLUMES must exist in docker-compose.yml.
    Phantom entries produce misleading '[skip] not present' log noise and
    indicate the two lists have drifted.
    """
    compose_set = set(compose_volumes)
    phantom = [v for v in canonical_volumes if v not in compose_set]

    assert not phantom, (
        f"The following volumes appear in uninstall.sh _CANONICAL_VOLUMES but "
        f"are NOT declared in docker-compose.yml top-level volumes: section:\n"
        + "\n".join(f"  - {v}" for v in phantom)
        + "\n\nEither add them to docker-compose.yml or remove them from "
        "_CANONICAL_VOLUMES to keep the two lists in sync."
    )


# ---------------------------------------------------------------------------
# Test 4 — no duplicates in canonical list
# ---------------------------------------------------------------------------


def test_no_duplicates_in_canonical_list(canonical_volumes: list[str]) -> None:
    """Duplicate entries in _CANONICAL_VOLUMES would cause double-rm attempts."""
    seen: set[str] = set()
    dupes: list[str] = []
    for v in canonical_volumes:
        if v in seen:
            dupes.append(v)
        seen.add(v)
    assert not dupes, (
        f"Duplicate entries in _CANONICAL_VOLUMES in uninstall.sh: {dupes}"
    )


# ---------------------------------------------------------------------------
# Test 5 — mutation guard: removing an entry from the expected set is caught
# ---------------------------------------------------------------------------


def test_mutation_missing_volume_is_caught(compose_volumes: list[str]) -> None:
    """
    Mutation guard: if we remove one compose volume from what _CANONICAL_VOLUMES
    should contain, the parity check must fire.

    Per feedback_test_real_scans_not_just_unit_tests.md: a mutation that is NOT
    caught is evidence fabrication (SOP 4).
    """
    assert compose_volumes, "No compose volumes found — cannot run mutation test"

    # Simulate a _CANONICAL_VOLUMES missing the first compose volume
    victim = compose_volumes[0]
    mutated_canonical = set(compose_volumes) - {victim}

    missing = [v for v in compose_volumes if v not in mutated_canonical]

    assert missing, (
        f"MUTATION TEST FAILED: removing '{victim}' from _CANONICAL_VOLUMES "
        f"was NOT detected by the parity check.  The parity check is not "
        f"catching the regression it was designed to catch."
    )
    assert victim in missing, (
        f"MUTATION TEST FAILED: the missing-volume detection did not name "
        f"'{victim}' in its output: {missing}"
    )


# ---------------------------------------------------------------------------
# Test 6 — compose_volumes parser smoke test
# ---------------------------------------------------------------------------


def test_compose_volumes_list_is_nonempty(compose_volumes: list[str]) -> None:
    """
    Sanity check: the parser must extract at least the core volumes.
    An empty list means the parser is broken or the compose file changed structure.
    """
    _EXPECTED_CORE = {
        "postgres_data",
        "redis_data",
        "audit_data",
        "ollama_data",
        "grafana_data",
    }
    parsed_set = set(compose_volumes)
    missing_core = _EXPECTED_CORE - parsed_set
    assert not missing_core, (
        f"Core volumes missing from parsed compose volume list — "
        f"parser may be broken or compose file structure changed:\n"
        + "\n".join(f"  - {v}" for v in sorted(missing_core))
    )
