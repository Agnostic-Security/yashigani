"""
BUG-C838004-CADDY-COPY / YSG-RISK-226 Contract Tests
Captain: Dockerfile COPY path validation against build.context.

Regression guard for the bug introduced in commit c838004 where
docker/caddy/Dockerfile.caddy contained:

    COPY caddy/caddy-entrypoint.sh /usr/local/bin/caddy-entrypoint.sh

but docker-compose.yml sets build.context: .. (repo root, one level above
docker/). The COPY path resolves relative to the build context, so the
correct path is:

    COPY docker/caddy/caddy-entrypoint.sh /usr/local/bin/caddy-entrypoint.sh

This file was absent at <repo-root>/caddy/caddy-entrypoint.sh, causing all
Podman builds to fail with "no such file or directory" at the COPY step.

These tests assert:
  1. Every COPY source path in docker/caddy/Dockerfile.caddy resolves to a
     real file when interpreted relative to the build.context (repo root).
  2. The entrypoint source path specifically uses docker/caddy/ prefix.
  3. The docker-compose.yml caddy service build.context is repo root (..).
  4. The Dockerfile used by compose matches docker/caddy/Dockerfile.caddy.

If any test here fails, the Caddy image CANNOT be built — install is blocked
on all Podman platforms (Mac and Linux/VM). This is a SHIP-BLOCKER class bug.
"""

import pathlib
import re

import pytest
import yaml

REPO = pathlib.Path(__file__).parent.parent.parent
DOCKER_DIR = REPO / "docker"
CADDY_DIR = DOCKER_DIR / "caddy"
DOCKERFILE = CADDY_DIR / "Dockerfile.caddy"
COMPOSE = DOCKER_DIR / "docker-compose.yml"

# The known entrypoint file name — tightly-scoped to avoid false passes.
ENTRYPOINT_FILENAME = "caddy-entrypoint.sh"
ENTRYPOINT_CORRECT_COPY_SOURCE = f"docker/caddy/{ENTRYPOINT_FILENAME}"


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def dockerfile_lines():
    assert DOCKERFILE.exists(), f"Dockerfile.caddy not found at {DOCKERFILE}"
    return DOCKERFILE.read_text().splitlines()


@pytest.fixture(scope="module")
def compose_data():
    assert COMPOSE.exists(), f"docker-compose.yml not found at {COMPOSE}"
    with COMPOSE.open() as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def copy_sources(dockerfile_lines):
    """Extract all COPY source paths from the Dockerfile (first token after COPY)."""
    sources = []
    for line in dockerfile_lines:
        stripped = line.strip()
        if stripped.startswith("COPY ") and not stripped.startswith("COPY --"):
            # COPY <src> [<src2> ...] <dest>
            # All tokens except the last are sources.
            tokens = stripped.split()
            # tokens[0] = "COPY", tokens[1:-1] = sources, tokens[-1] = dest
            if len(tokens) >= 3:
                sources.extend(tokens[1:-1])
            elif len(tokens) == 2:
                # Degenerate COPY with no dest — treat single token as source
                sources.append(tokens[1])
    return sources


# ── Tests ──────────────────────────────────────────────────────────────────────


class TestDockerfileCopyPathsResolveFromRepoRoot:
    """All COPY source paths in Dockerfile.caddy must exist relative to the
    build context (repo root), not relative to docker/caddy/."""

    def test_dockerfile_exists(self):
        assert DOCKERFILE.exists(), (
            f"docker/caddy/Dockerfile.caddy not found at {DOCKERFILE}. "
            "Cannot validate COPY paths."
        )

    def test_at_least_one_copy_directive(self, copy_sources):
        assert len(copy_sources) >= 1, (
            "Expected at least one COPY directive in Dockerfile.caddy. "
            "If the Dockerfile was refactored, update this test."
        )

    def test_all_copy_sources_exist_relative_to_repo_root(self, copy_sources):
        """
        Core regression test for BUG-C838004-CADDY-COPY.

        docker-compose.yml caddy service sets build.context: .. (repo root).
        All COPY <src> paths resolve relative to the repo root.
        A path like 'caddy/caddy-entrypoint.sh' would require the file at
        <repo-root>/caddy/caddy-entrypoint.sh, which does NOT exist.
        The correct path is 'docker/caddy/caddy-entrypoint.sh'.
        """
        missing = []
        for src in copy_sources:
            resolved = REPO / src
            if not resolved.exists():
                missing.append(
                    f"  COPY source '{src}' not found at '{resolved}' "
                    f"(build.context is repo root: {REPO})"
                )
        assert not missing, (
            "SHIP-BLOCKER: The following COPY source path(s) in "
            f"docker/caddy/Dockerfile.caddy do not exist relative to the "
            f"build context (repo root = {REPO}):\n"
            + "\n".join(missing)
            + "\n\nThis is the bug class documented as BUG-C838004-CADDY-COPY / "
            "YSG-RISK-226. The path must include the 'docker/' prefix when the "
            "build context is the repo root."
        )

    def test_entrypoint_copy_uses_docker_caddy_prefix(self, dockerfile_lines):
        """
        Tightly-scoped assertion: the caddy-entrypoint.sh COPY line specifically
        uses the 'docker/caddy/' prefix (not bare 'caddy/').

        This catches regressions even if the general path-existence test above
        were somehow bypassed (e.g., someone creates a spurious caddy/ directory
        at repo root).
        """
        copy_lines = [
            line.strip()
            for line in dockerfile_lines
            if line.strip().startswith("COPY ") and ENTRYPOINT_FILENAME in line
        ]
        assert copy_lines, (
            f"No COPY line containing '{ENTRYPOINT_FILENAME}' found in "
            "docker/caddy/Dockerfile.caddy. If the entrypoint was renamed, "
            "update this test."
        )
        for copy_line in copy_lines:
            tokens = copy_line.split()
            # tokens: ['COPY', '<src>', '<dest>']
            # May also have --chown or --chmod flags; skip those.
            src_tokens = [t for t in tokens[1:] if not t.startswith("--")]
            if len(src_tokens) >= 2:
                src = src_tokens[0]  # first non-flag token after COPY = source
            else:
                src = src_tokens[0] if src_tokens else ""
            assert src == ENTRYPOINT_CORRECT_COPY_SOURCE, (
                f"COPY source for {ENTRYPOINT_FILENAME} is '{src}' but must be "
                f"'{ENTRYPOINT_CORRECT_COPY_SOURCE}'. "
                "Build context is repo root (..); bare 'caddy/' prefix "
                "resolves to a non-existent path. "
                "Bug: BUG-C838004-CADDY-COPY / YSG-RISK-226."
            )


class TestComposeContextConsistency:
    """docker-compose.yml caddy service build block must be consistent with the
    Dockerfile COPY path assumptions checked above."""

    def test_compose_exists(self):
        assert COMPOSE.exists(), f"docker-compose.yml not found at {COMPOSE}"

    def test_caddy_service_build_context_is_repo_root(self, compose_data):
        """Build context for caddy must be '..' (repo root) not 'docker/'."""
        caddy = compose_data.get("services", {}).get("caddy", {})
        build = caddy.get("build", {})
        if isinstance(build, str):
            # Short-form: build: <context>
            context = build
        else:
            context = build.get("context", "")
        assert context == "..", (
            f"caddy service build.context is '{context}' but must be '..' "
            "(repo root). The Dockerfile COPY paths depend on this context "
            "being set to the repo root."
        )

    def test_caddy_service_dockerfile_is_correct(self, compose_data):
        """Dockerfile path in compose must point to docker/caddy/Dockerfile.caddy."""
        caddy = compose_data.get("services", {}).get("caddy", {})
        build = caddy.get("build", {})
        if isinstance(build, str):
            # Short-form build specifies context only; Dockerfile defaults to
            # Dockerfile in the context dir. Skip assertion — not our bug class.
            pytest.skip("Caddy build is short-form (context only); no explicit dockerfile key.")
        dockerfile = build.get("dockerfile", "")
        assert dockerfile == "docker/caddy/Dockerfile.caddy", (
            f"caddy service build.dockerfile is '{dockerfile}' but expected "
            "'docker/caddy/Dockerfile.caddy'. If this changed intentionally, "
            "update this test AND verify all COPY paths are still correct."
        )

    def test_caddy_entrypoint_file_exists_at_expected_location(self):
        """The actual entrypoint file must exist at docker/caddy/caddy-entrypoint.sh."""
        entrypoint = CADDY_DIR / ENTRYPOINT_FILENAME
        assert entrypoint.exists(), (
            f"caddy-entrypoint.sh not found at {entrypoint}. "
            "If it was moved, update both this test and the Dockerfile COPY path."
        )


class TestBrokenPathWouldFail:
    """
    Prove that the broken pre-fix path does NOT exist (regression proof).

    These tests assert that 'caddy/caddy-entrypoint.sh' relative to repo root
    does NOT exist — confirming that if a future commit reverts the fix, the
    tests in TestDockerfileCopyPathsResolveFromRepoRoot above would correctly
    catch it.
    """

    def test_broken_path_does_not_exist(self):
        """
        The pre-fix COPY source 'caddy/caddy-entrypoint.sh' resolves to
        <repo-root>/caddy/caddy-entrypoint.sh, which must NOT exist.

        If this test fails, someone has created a file at that spurious path,
        which would hide the BUG-C838004 regression. Remove that file.
        """
        broken_path = REPO / "caddy" / ENTRYPOINT_FILENAME
        assert not broken_path.exists(), (
            f"Spurious file found at {broken_path}. "
            "This path corresponds to the pre-fix broken COPY source "
            "('caddy/caddy-entrypoint.sh' relative to repo root). "
            "Remove this file — it would mask the BUG-C838004 regression "
            "by making the broken COPY path accidentally resolve."
        )
