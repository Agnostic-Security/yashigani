"""
Regression tests for the 5 Agnostic Security patches (AS-FIX-1/2/3/4/5) applied
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
import yaml

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


# ---------------------------------------------------------------------------
# AS-FIX-4: exclude service_completed_successfully (one-shot) deps from
# --requires= (YSG-PODMAN-LETTA-001)
# ---------------------------------------------------------------------------


class _FakeComposeForDeps:
    def __init__(self, container_names_by_service: dict[str, list[str]]):
        self.dirname = "/tmp"
        self.container_names_by_service = container_names_by_service
        self.environ: dict[str, str] = {}


class TestOneShotDepsExcludedFromRequires:
    def test_stopped_condition_dep_excluded_from_requires(self):
        """
        Reproduces YSG-PODMAN-LETTA-001 exactly: a dependency declared with
        service_completed_successfully (-> ServiceDependencyCondition.STOPPED)
        must NOT appear in the baked --requires= list. podman's --requires
        means "must be running" and has no equivalent for "ran to completion
        once" — including a one-shot job there caused podman's own engine to
        try to restart the already-exited job as part of resolving
        --requires, which then hit a dependency-graph-construction bug when
        the one-shot's own dependency (postgres) was already running
        ("... not found in input list"). letta-pgbouncer and letta both
        stuck in Created on every from-scratch podman install before this
        fix.
        """
        compose = _FakeComposeForDeps(container_names_by_service={
            "postgres": ["proj_postgres_1"],
            "agent-db-init": ["proj_agent-db-init_1"],
        })
        cnt = {
            "name": "letta-pgbouncer",
            "service_name": "letta-pgbouncer",
            "image": "x",
            "network_mode": "none",
            "_deps": [
                pc.ServiceDependency("postgres", "service_healthy"),
                pc.ServiceDependency("agent-db-init", "service_completed_successfully"),
            ],
        }
        args = asyncio.run(pc.container_to_args(compose, cnt, detached=False))
        requires = [a for a in args if a.startswith("--requires=")]
        assert len(requires) == 1, "expected exactly one --requires= flag"
        requires_names = requires[0][len("--requires="):].split(",")
        assert "proj_postgres_1" in requires_names
        assert "proj_agent-db-init_1" not in requires_names, (
            "a service_completed_successfully (one-shot) dependency must "
            "never be walked via podman's engine-level --requires="
        )

    def test_only_stopped_deps_excluded_running_deps_unaffected(self):
        """service_started / service_healthy deps are UNCHANGED by this fix —
        only the STOPPED-condition class is excluded. If ALL deps happen to
        be STOPPED, no --requires= flag should be emitted at all (empty list,
        not --requires= with a trailing/empty value)."""
        compose = _FakeComposeForDeps(container_names_by_service={
            "one-shot": ["proj_one-shot_1"],
        })
        cnt = {
            "name": "dependent",
            "service_name": "dependent",
            "image": "x",
            "network_mode": "none",
            "_deps": [
                pc.ServiceDependency("one-shot", "service_completed_successfully"),
            ],
        }
        args = asyncio.run(pc.container_to_args(compose, cnt, detached=False))
        requires = [a for a in args if a.startswith("--requires=")]
        assert requires == [], (
            "a service with ONLY one-shot (STOPPED) deps must produce no "
            "--requires= flag at all, not an empty/malformed one"
        )

    def test_healthy_and_started_deps_still_in_requires(self):
        """Sanity: this fix must not regress the non-one-shot case at all —
        service_healthy / service_started deps still translate to
        --requires= exactly as before AS-FIX-4."""
        compose = _FakeComposeForDeps(container_names_by_service={
            "postgres": ["proj_postgres_1"],
            "gateway": ["proj_gateway_1"],
        })
        cnt = {
            "name": "letta",
            "service_name": "letta",
            "image": "x",
            "network_mode": "none",
            "_deps": [
                pc.ServiceDependency("postgres", "service_healthy"),
                pc.ServiceDependency("gateway", "service_healthy"),
            ],
        }
        args = asyncio.run(pc.container_to_args(compose, cnt, detached=False))
        requires = [a for a in args if a.startswith("--requires=")]
        assert len(requires) == 1
        requires_names = set(requires[0][len("--requires="):].split(","))
        assert requires_names == {"proj_postgres_1", "proj_gateway_1"}



# ---------------------------------------------------------------------------
# AS-FIX-5: rec_merge_one() unwraps !override/!reset on first-introduced keys
# ---------------------------------------------------------------------------


class TestRecMergeFirstIntroducedOverrideReset:
    def test_first_introduced_override_key_is_unwrapped_not_raw_tag(self):
        """
        Reproduces FIND-IRIS-DUP-AGENT-REGRESSION's true root cause exactly:
        Yashigani's docker-compose.gpu-mac-metal-podman.yml is the FIRST (and
        only) -f overlay to define `profiles:` for its `ollama` service —
        `target` (the merge accumulator from earlier -f files) has no
        'profiles' key yet when this overlay's `profiles: !override [...]`
        is merged in.

        Pre-fix: rec_merge_one()'s first loop stored the raw OverrideTag
        object verbatim (`target[key] = clone(value)`), which crashed
        `_resolve_profiles()`'s `set(config.get("profiles", []))` with
        `TypeError: 'OverrideTag' object is not iterable` on every
        podman-compose invocation that included this overlay — before any
        container was ever reached (compose exec, compose up, everything).
        """
        target = {"image": "docker.io/library/ollama:latest"}
        source = yaml.safe_load("profiles: !override [mac-metal-host-ollama-only]")

        merged = pc.rec_merge_one(target, source)

        assert not isinstance(merged["profiles"], pc.OverrideTag), (
            "AS-FIX-5: a first-introduced !override-tagged key must be "
            "unwrapped to its plain value, not left as a raw OverrideTag "
            "object — downstream consumers like _resolve_profiles() do not "
            "understand OverrideTag and crash with "
            "`TypeError: 'OverrideTag' object is not iterable`"
        )
        assert merged["profiles"] == ["mac-metal-host-ollama-only"]

        # Exact downstream operation that crashed pre-fix (_resolve_profiles()
        # shape): `set(config.get("profiles", []))` must not raise.
        resolved = set(merged.get("profiles", []))
        assert resolved == {"mac-metal-host-ollama-only"}

    def test_first_introduced_reset_key_is_a_no_op_not_stored(self):
        """A first-introduced `!reset` has nothing to reset — must be
        skipped entirely, not leave a raw ResetTag object in the merged
        dict (which would be equally unconsumable by downstream code)."""
        target = {"image": "x"}
        source = yaml.safe_load("some_new_key: !reset")

        merged = pc.rec_merge_one(target, source)

        assert "some_new_key" not in merged, (
            "AS-FIX-5: !reset on a key with no prior value in target is a "
            "true no-op — it must not appear in the merged dict at all, "
            "raw ResetTag or otherwise"
        )

    def test_existing_key_override_behaviour_unchanged(self):
        """Sanity: this fix must not regress the ALREADY-correct case (key
        exists in target, absent from source, tagged !override in target)
        — that unwrap path (the second loop) is untouched by this patch."""
        _tagged = yaml.safe_load("profiles: !override [a]")
        target = {"profiles": _tagged["profiles"]}
        source: dict = {}

        merged = pc.rec_merge_one(target, source)

        assert merged["profiles"] == ["a"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
