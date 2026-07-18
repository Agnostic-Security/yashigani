"""
Regression tests for the 3 Agnostic Security patches (AS-FIX-1/2/3) applied
to vendored podman-compose 1.5.0 -> podman-compose-ysg 1.5.0+ysg.1.

Scope note (GPL-2.0 boundary hygiene, Petra memo §2.3): these tests import
`podman_compose` directly to exercise the vendored fork's own internals.
This is testing of the GPL-2.0 component itself, not a Yashigani proprietary
module depending on it — it does not touch src/ or lib/ (Yashigani product
code), and Yashigani's own product code never imports this module (CLI/
subprocess-only boundary, enforced separately). Kept inside this fork's own
tests/ directory per "fork lives in its own package/dir" hygiene.

Each test is root-caused to the exact defect from Laura's threat model
(threat-model-podman-compose-fork-20260718.md) and source-citations.md, not
just "does the new code run".

Run: python3 -m pytest vendor/podman-compose-ysg/tests/ -v
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import podman_compose as pc  # noqa: E402


# ---------------------------------------------------------------------------
# AS-FIX-2: real topological sort (was sort-by-dependency-COUNT)
# ---------------------------------------------------------------------------


def _service(deps: list[pc.ServiceDependency]) -> dict:
    return {"_deps": set(deps)}


class TestTopologicalSort:
    def test_transitive_dependency_with_more_direct_deps_still_sorts_after(self):
        """
        Reproduces probe Defect 2 exactly: a service with FEWER direct deps
        (leaf, 1 direct dep) must still sort AFTER a service it transitively
        depends on which itself has MORE direct deps (2 direct deps).
        The old `sorted(len(deps), name)` algorithm would put the
        fewer-direct-deps leaf BEFORE its own transitive dependency.
        """
        services = {
            # 'base' has 2 direct deps of its own -> old algorithm ranks it last
            "base": _service([
                pc.ServiceDependency("dep_a", "service_started"),
                pc.ServiceDependency("dep_b", "service_started"),
            ]),
            "dep_a": _service([]),
            "dep_b": _service([]),
            # 'leaf' has only 1 direct dep (on 'base') -> old algorithm would
            # rank it BEFORE 'base' because count(1) < count(2), even though
            # 'leaf' cannot exist until 'base' exists.
            "leaf": _service([pc.ServiceDependency("base", "service_started")]),
        }

        # Sanity: prove the OLD algorithm gets this wrong (documents the bug
        # this fix closes, doesn't just assert the new behaviour in a vacuum)
        old_order = [name for _, name in sorted(
            (len(srv["_deps"]), name) for name, srv in services.items()
        )]
        leaf_idx_old = old_order.index("leaf")
        base_idx_old = old_order.index("base")
        assert leaf_idx_old < base_idx_old, (
            "test fixture invariant broken: this must reproduce the old "
            "count-based defect (leaf sorting before its own dependency)"
        )

        order = pc._topological_sort_service_names(services)

        assert order.index("dep_a") < order.index("base")
        assert order.index("dep_b") < order.index("base")
        assert order.index("base") < order.index("leaf")

    def test_deterministic_tie_break_by_insertion_order(self):
        services = {
            "c": _service([]),
            "a": _service([]),
            "b": _service([]),
        }
        order = pc._topological_sort_service_names(services)
        assert order == ["c", "a", "b"]

    def test_dependency_cycle_does_not_drop_services(self):
        services = {
            "x": _service([pc.ServiceDependency("y", "service_started")]),
            "y": _service([pc.ServiceDependency("x", "service_started")]),
        }
        order = pc._topological_sort_service_names(services)
        assert set(order) == {"x", "y"}, "a cycle must not silently drop a service"

    def test_unknown_dependency_name_ignored_not_crashed(self):
        services = {
            "solo": _service([pc.ServiceDependency("does-not-exist", "service_started")]),
        }
        order = pc._topological_sort_service_names(services)
        assert order == ["solo"]


# ---------------------------------------------------------------------------
# AS-FIX-3: required:false threaded through + honored in check_dep_conditions
# ---------------------------------------------------------------------------


class _FakeCompose:
    """Minimal stand-in for PodmanCompose — only the attribute
    check_dep_conditions() actually reads."""

    def __init__(self, container_names_by_service: dict[str, list[str]]):
        self.container_names_by_service = container_names_by_service
        self.podman_version = "5.0.0"


class TestRequiredFlagHonored:
    def test_required_flag_survives_flat_deps_construction(self):
        """
        Root cause per Laura: ServiceDependency.__init__ / flat_deps()
        discarded `required` at graph-construction time, long before
        check_dep_conditions() ever ran. Prove it now survives.
        """
        services = {
            "web": {
                "depends_on": {
                    "cache": {"condition": "service_started", "required": False},
                    "db": {"condition": "service_started"},  # required omitted -> True
                }
            },
            "cache": {},
            "db": {},
        }
        pc.flat_deps(services)
        deps_by_name = {d.name: d for d in services["web"]["_deps"]}
        assert deps_by_name["cache"].required is False
        assert deps_by_name["db"].required is True

    def test_check_dep_conditions_skips_missing_optional_dependency(self):
        """
        Reproduces probe Defect 3 exactly: a service excluded by --profile
        (e.g. demo-mcp profile without 'ollama-init') has no entry in
        container_names_by_service. With required: false this must NOT
        raise (the old code raised a raw, unguarded KeyError here).
        """
        compose = _FakeCompose(container_names_by_service={})  # nothing created
        deps = {pc.ServiceDependency("ollama-init", "service_started", required=False)}
        # Must not raise.
        asyncio.run(pc.check_dep_conditions(compose, deps))

    def test_check_dep_conditions_raises_clearly_on_missing_required_dependency(self):
        """
        The Laura merge condition: the required:false guard must NOT swallow
        a genuine required-dependency failure. If a REQUIRED dependency's
        containers were never created (e.g. AS-FIX-2's ordering regressed,
        or the compose file/profile selection is simply wrong), this must
        fail loudly and specifically — not silently continue, and not a
        raw/unguarded KeyError either.
        """
        compose = _FakeCompose(container_names_by_service={})  # nothing created
        deps = {pc.ServiceDependency("ollama-init", "service_started", required=True)}
        with pytest.raises(RuntimeError, match="Required dependency 'ollama-init'"):
            asyncio.run(pc.check_dep_conditions(compose, deps))

    def test_check_dep_conditions_default_required_true_when_omitted(self):
        """default required=True (compose-spec semantics) must still raise,
        not silently pass, for a dependency where `required` was never
        specified in the compose file at all."""
        compose = _FakeCompose(container_names_by_service={})
        deps = {pc.ServiceDependency("db", "service_started")}  # required defaults True
        with pytest.raises(RuntimeError):
            asyncio.run(pc.check_dep_conditions(compose, deps))


# ---------------------------------------------------------------------------
# AS-FIX-1: seccomp relative-path resolution in container_to_args()
# ---------------------------------------------------------------------------


class _FakeComposeForArgs:
    def __init__(self, dirname: str):
        self.dirname = dirname
        self.container_names_by_service: dict[str, list[str]] = {}
        self.environ: dict[str, str] = {}


class TestSeccompPathResolution:
    def test_relative_seccomp_path_resolved_to_absolute(self, tmp_path):
        project_dir = tmp_path / "project"
        (project_dir / "seccomp").mkdir(parents=True)
        profile = project_dir / "seccomp" / "yashigani.json"
        profile.write_text("{}")

        compose = _FakeComposeForArgs(dirname=str(project_dir))
        cnt = {
            "name": "gateway",
            "service_name": "gateway",
            "image": "yashigani/gateway:latest",
            "network_mode": "none",  # avoids compose.networks/podman calls
            "security_opt": ["seccomp=./seccomp/yashigani.json"],
        }
        args = asyncio.run(pc.container_to_args(compose, cnt))
        idx = args.index("--security-opt")
        resolved = args[idx + 1]
        assert resolved == f"seccomp={os.path.realpath(str(profile))}"
        assert resolved.startswith("seccomp=/"), "must be an absolute path, not relative"

    def test_seccomp_unconfined_not_treated_as_a_path(self, tmp_path):
        compose = _FakeComposeForArgs(dirname=str(tmp_path))
        cnt = {
            "name": "gateway",
            "service_name": "gateway",
            "image": "x",
            "network_mode": "none",
            "security_opt": ["seccomp=unconfined"],
        }
        args = asyncio.run(pc.container_to_args(compose, cnt))
        idx = args.index("--security-opt")
        assert args[idx + 1] == "seccomp=unconfined"

    def test_apparmor_and_label_options_untouched(self, tmp_path):
        """Only the seccomp= path-bearing key is normalized — apparmor/label
        values are profile names, not filesystem paths, and must pass
        through verbatim (do not invent a new scheme beyond the exact
        root-cause fix Laura specified)."""
        compose = _FakeComposeForArgs(dirname=str(tmp_path))
        cnt = {
            "name": "gateway",
            "service_name": "gateway",
            "image": "x",
            "network_mode": "none",
            "security_opt": ["apparmor=unconfined", "label=disable"],
        }
        args = asyncio.run(pc.container_to_args(compose, cnt))
        opts = [args[i + 1] for i, a in enumerate(args) if a == "--security-opt"]
        assert opts == ["apparmor=unconfined", "label=disable"]

    def test_already_absolute_seccomp_path_unchanged_in_meaning(self, tmp_path):
        profile = tmp_path / "abs-profile.json"
        profile.write_text("{}")
        compose = _FakeComposeForArgs(dirname=str(tmp_path))
        cnt = {
            "name": "gateway",
            "service_name": "gateway",
            "image": "x",
            "network_mode": "none",
            "security_opt": [f"seccomp={profile}"],
        }
        args = asyncio.run(pc.container_to_args(compose, cnt))
        idx = args.index("--security-opt")
        assert args[idx + 1] == f"seccomp={os.path.realpath(str(profile))}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
