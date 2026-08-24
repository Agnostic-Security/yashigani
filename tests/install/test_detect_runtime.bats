#!/usr/bin/env bats
# tests/install/test_detect_runtime.bats
# Unit tests for lib/detect_runtime.sh — _detect_runtime() 4-way detection.
#
# Plan reference: §2.D L4 / HIGH-01 / L10
# Truth table coverage: all 7 cases from _detect_runtime_truth_table().
#
# Runs WITHOUT a live container daemon. Every external command (_dr_podman_reachable,
# _dr_docker_reachable, _dr_is_k8s_incluster, id, getent) is stubbed via
# PATH override or function override so tests are fully hermetic.
#
# Requirements:
#   bats-core >= 1.10.0
#   shellcheck (invoked by TEST-S1 lint check)
#
# Run:
#   bats tests/install/test_detect_runtime.bats
#   # or via make:
#   make test-detect-runtime

# ── Test setup ────────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
DETECT_RUNTIME_SH="${REPO_ROOT}/lib/detect_runtime.sh"

# Stub helpers — override internal detection functions.
# Bats sources each test in a subshell; we override functions after sourcing.

_stub_k8s() {
    _dr_is_k8s_incluster() { return 0; }
}
_stub_no_k8s() {
    _dr_is_k8s_incluster() { return 1; }
}
_stub_podman() {
    _dr_podman_reachable() { return 0; }
}
_stub_no_podman() {
    _dr_podman_reachable() { return 1; }
}
_stub_docker() {
    _dr_docker_reachable() { return 0; }
}
_stub_no_docker() {
    _dr_docker_reachable() { return 1; }
}
_stub_rootless() {
    _dr_is_rootless_podman() { return 0; }
}
_stub_rootful() {
    _dr_is_rootless_podman() { return 1; }
}

setup() {
    # Unset state variables so each test starts clean.
    unset YSG_RUNTIME_4WAY YSG_RUNTIME_4WAY_NOTE YSG_RUNTIME _YSG_DETECT_RUNTIME_LOADED
    # Source the library (guard will be cleared by unset above in subshell).
    source "${DETECT_RUNTIME_SH}"
}

# ── Lint gate ─────────────────────────────────────────────────────────────────

@test "S1: shellcheck no new warnings on detect_runtime.sh" {
    run shellcheck --enable=all --shell=sh "${DETECT_RUNTIME_SH}"
    [ "$status" -eq 0 ]
}

@test "S2: bash -n parses detect_runtime.sh cleanly" {
    run bash -n "${DETECT_RUNTIME_SH}"
    [ "$status" -eq 0 ]
}

# ── Case 1: K8s in-cluster ────────────────────────────────────────────────────

@test "Case 1: K8s in-cluster -> k8s" {
    _stub_k8s
    _stub_no_podman
    _stub_no_docker
    run _detect_runtime
    [ "$status" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "k8s" ]
}

@test "Case 1: K8s in-cluster -> YSG_RUNTIME_4WAY_NOTE contains 'K8s in-cluster'" {
    _stub_k8s
    _stub_no_podman
    _stub_no_docker
    _detect_runtime
    [[ "${YSG_RUNTIME_4WAY_NOTE}" == *"K8s in-cluster"* ]]
}

@test "Case 1b: K8s hint via legacy YSG_RUNTIME=k8s -> k8s" {
    _stub_no_k8s
    _stub_no_podman
    _stub_no_docker
    export YSG_RUNTIME=k8s
    run _detect_runtime
    [ "$status" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "k8s" ]
}

# ── Case 2: rootless Podman with /etc/subuid entry ────────────────────────────

@test "Case 2: Podman reachable + rootless (/etc/subuid) -> podman-rootless" {
    _stub_no_k8s
    _stub_podman
    _stub_no_docker
    _stub_rootless
    run _detect_runtime
    [ "$status" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "podman-rootless" ]
}

@test "Case 2: podman-rootless -> NOTE contains L1-GAP" {
    _stub_no_k8s
    _stub_podman
    _stub_no_docker
    _stub_rootless
    _detect_runtime
    [[ "${YSG_RUNTIME_4WAY_NOTE}" == *"L1-GAP"* ]]
}

@test "Case 2: podman-rootless -> NOTE mentions L2+L3" {
    _stub_no_k8s
    _stub_podman
    _stub_no_docker
    _stub_rootless
    _detect_runtime
    [[ "${YSG_RUNTIME_4WAY_NOTE}" == *"L2"* ]] && [[ "${YSG_RUNTIME_4WAY_NOTE}" == *"L3"* ]]
}

# ── Case 3: rootless Podman on macOS (no /etc/subuid) ─────────────────────────
# Same result as Case 2 — _dr_is_rootless_podman uses uid check as fallback.

@test "Case 3: Podman reachable + uid!=0 (macOS, no subuid) -> podman-rootless" {
    _stub_no_k8s
    _stub_podman
    _stub_no_docker
    _stub_rootless   # _dr_is_rootless_podman returns 0
    run _detect_runtime
    [ "$status" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "podman-rootless" ]
}

# ── Case 4: rootful Podman ────────────────────────────────────────────────────

@test "Case 4: Podman reachable + rootful (uid=0) -> podman-rootful" {
    _stub_no_k8s
    _stub_podman
    _stub_no_docker
    _stub_rootful    # _dr_is_rootless_podman returns 1
    run _detect_runtime
    [ "$status" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "podman-rootful" ]
}

@test "Case 4: podman-rootful -> NOTE mentions NET_ADMIN" {
    _stub_no_k8s
    _stub_podman
    _stub_no_docker
    _stub_rootful
    _detect_runtime
    [[ "${YSG_RUNTIME_4WAY_NOTE}" == *"NET_ADMIN"* ]]
}

@test "Case 4: podman-rootful -> NOTE does NOT mention L1-GAP" {
    _stub_no_k8s
    _stub_podman
    _stub_no_docker
    _stub_rootful
    _detect_runtime
    [[ "${YSG_RUNTIME_4WAY_NOTE}" != *"L1-GAP"* ]]
}

# ── Case 5: Docker only ────────────────────────────────────────────────────────

@test "Case 5: Docker reachable only -> docker" {
    _stub_no_k8s
    _stub_no_podman
    _stub_docker
    run _detect_runtime
    [ "$status" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "docker" ]
}

@test "Case 5: docker -> NOTE mentions NET_ADMIN" {
    _stub_no_k8s
    _stub_no_podman
    _stub_docker
    _detect_runtime
    [[ "${YSG_RUNTIME_4WAY_NOTE}" == *"NET_ADMIN"* ]]
}

# ── Case 6: Both Podman and Docker reachable (Podman preferred) ────────────────

@test "Case 6: Both Podman (rootless) + Docker reachable -> podman-rootless (Podman preferred)" {
    _stub_no_k8s
    _stub_podman
    _stub_docker
    _stub_rootless
    run _detect_runtime
    [ "$status" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "podman-rootless" ]
}

@test "Case 6: Both Podman (rootful) + Docker reachable -> podman-rootful (Podman preferred)" {
    _stub_no_k8s
    _stub_podman
    _stub_docker
    _stub_rootful
    run _detect_runtime
    [ "$status" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "podman-rootful" ]
}

# ── L10-RUNTIME-HINT-2026-08-16: explicit YSG_RUNTIME hint must win over Case-6 Podman
# preference on a host where both runtimes are reachable ─────────────────────
# Regression coverage for the bug: _legacy_hint (YSG_RUNTIME, set by
# install.sh's `--runtime docker` / resolve_compose_cmd()) was read but never
# consulted for docker/podman, only k8s — so a Docker install on a dual-
# runtime host mislabelled itself podman-rootless and produced a real L1
# ring-fence gap in codegen for anything onboarded afterwards.

@test "L10-RUNTIME-HINT-2026-08-16: YSG_RUNTIME=docker hint wins over Case 6 Podman preference" {
    _stub_no_k8s
    _stub_podman    # Podman also reachable — would win Case 6 without the hint
    _stub_docker
    _stub_rootless
    export YSG_RUNTIME=docker
    _detect_runtime
    _rc=$?
    [ "$_rc" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "docker" ]
}

@test "L10-RUNTIME-HINT-2026-08-16: YSG_RUNTIME=docker hint -> NOTE explains Podman ignored" {
    _stub_no_k8s
    _stub_podman
    _stub_docker
    _stub_rootless
    export YSG_RUNTIME=docker
    _detect_runtime
    [[ "${YSG_RUNTIME_4WAY_NOTE}" == *"ignored"* ]]
}

@test "FAIL-CLOSED (§4.4 review 2026-08-17): YSG_RUNTIME=docker hint but Docker unreachable -> unknown/1, NEVER substitutes Podman" {
    # THE ORIGINAL DEFECT REPRODUCED ON THE ERROR PATH: the first cut of this
    # fix fell through to the generic auto-detect here and silently returned
    # podman-rootless — a DIFFERENT runtime than the one explicitly named.
    # That is precisely the bug this fix exists to close (a named runtime
    # must never be silently substituted), just triggered by transient
    # unreachability instead of dual-install ambiguity. A guessed runtime is
    # worse than an aborted onboard for a label that gates ring-fence
    # emission (codegen.py) — must fail closed, not fall back.
    _stub_no_k8s
    _stub_podman    # Podman IS reachable — must NOT be silently substituted
    _stub_no_docker
    _stub_rootless
    export YSG_RUNTIME=docker
    # `if` context, not a bare call: bats runs test bodies under errexit-like
    # semantics, so a bare nonzero-returning `_detect_runtime` (which is what
    # this test correctly expects) would abort the test before `$?` is ever
    # read. Same reasoning as the pre-existing "Case 7" test's use of `run`
    # — here we need the exported vars too, so `run`'s subshell (which loses
    # them, per this file's documented bats-version scoping issue) isn't an
    # option; the `if` guard is the propagation-safe equivalent.
    if _detect_runtime; then _rc=0; else _rc=$?; fi
    [ "$_rc" -eq 1 ]
    [ "${YSG_RUNTIME_4WAY}" = "unknown" ]
    [ "${YSG_RUNTIME_4WAY}" != "podman-rootless" ]
    [[ "${YSG_RUNTIME_4WAY_NOTE}" == *"docker"* ]]
    [[ "${YSG_RUNTIME_4WAY_NOTE}" == *"NOT reachable"* ]]
}

@test "L10-RUNTIME-HINT-2026-08-16: YSG_RUNTIME=podman hint still disambiguates rootful vs rootless" {
    _stub_no_k8s
    _stub_podman
    _stub_docker
    _stub_rootful
    export YSG_RUNTIME=podman
    _detect_runtime
    _rc=$?
    [ "$_rc" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "podman-rootful" ]
}

@test "FAIL-CLOSED (§4.4 review 2026-08-17): YSG_RUNTIME=podman hint but Podman unreachable -> unknown/1, NEVER substitutes Docker" {
    # Same class as the docker case above, mirrored: an operator who pinned
    # YSG_RUNTIME=podman and hits a transient Podman-unreachable window must
    # not silently land on Docker instead — that changes which containment
    # layers apply just as much as the reverse substitution does.
    _stub_no_k8s
    _stub_no_podman
    _stub_docker    # Docker IS reachable — must NOT be silently substituted
    export YSG_RUNTIME=podman
    if _detect_runtime; then _rc=0; else _rc=$?; fi
    [ "$_rc" -eq 1 ]
    [ "${YSG_RUNTIME_4WAY}" = "unknown" ]
    [ "${YSG_RUNTIME_4WAY}" != "docker" ]
    [[ "${YSG_RUNTIME_4WAY_NOTE}" == *"podman"* ]]
    [[ "${YSG_RUNTIME_4WAY_NOTE}" == *"NOT reachable"* ]]
}

# ── Case 7: Unknown ────────────────────────────────────────────────────────────

@test "Case 7: No runtime reachable -> unknown (returns 1)" {
    _stub_no_k8s
    _stub_no_podman
    _stub_no_docker
    run _detect_runtime
    [ "$status" -eq 1 ]
    [ "${YSG_RUNTIME_4WAY}" = "unknown" ]
}

@test "Case 7: unknown -> NOTE instructs operator to set YSG_RUNTIME_4WAY explicitly" {
    _stub_no_k8s
    _stub_no_podman
    _stub_no_docker
    _detect_runtime || true
    [[ "${YSG_RUNTIME_4WAY_NOTE}" == *"YSG_RUNTIME_4WAY"* ]]
}

# ── Explicit override (no re-detection) ───────────────────────────────────────

@test "Explicit YSG_RUNTIME_4WAY=docker is accepted without re-detecting" {
    export YSG_RUNTIME_4WAY=docker
    _stub_no_k8s
    _stub_podman   # Would normally pick podman, but explicit wins
    run _detect_runtime
    [ "$status" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "docker" ]
}

@test "Explicit YSG_RUNTIME_4WAY=k8s is accepted" {
    export YSG_RUNTIME_4WAY=k8s
    _stub_no_k8s
    _stub_no_podman
    _stub_no_docker
    run _detect_runtime
    [ "$status" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "k8s" ]
}

@test "Explicit YSG_RUNTIME_4WAY=podman-rootless is accepted" {
    export YSG_RUNTIME_4WAY=podman-rootless
    run _detect_runtime
    [ "$status" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "podman-rootless" ]
}

@test "Explicit YSG_RUNTIME_4WAY=podman-rootful is accepted" {
    export YSG_RUNTIME_4WAY=podman-rootful
    run _detect_runtime
    [ "$status" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "podman-rootful" ]
}

# ── Helper functions ───────────────────────────────────────────────────────────

@test "L1-gap annotation contains ROOTLESS-PODMAN-L1-GAP" {
    run _detect_runtime_l1_gap_annotation
    [ "$status" -eq 0 ]
    [[ "$output" == *"ROOTLESS-PODMAN-L1-GAP"* ]]
}

@test "L1-gap annotation mentions L2 and L3 active controls" {
    run _detect_runtime_l1_gap_annotation
    [[ "$output" == *"L2"* ]] && [[ "$output" == *"L3"* ]]
}

@test "Artifact comment embeds YSG_RUNTIME_4WAY value" {
    export YSG_RUNTIME_4WAY=podman-rootless
    run _detect_runtime_artifact_comment
    [ "$status" -eq 0 ]
    [[ "$output" == *"YSG_RUNTIME_4WAY=podman-rootless"* ]]
}

@test "Truth table output contains all 4 runtime values" {
    run _detect_runtime_truth_table
    [ "$status" -eq 0 ]
    [[ "$output" == *"docker"* ]]
    [[ "$output" == *"podman-rootful"* ]]
    [[ "$output" == *"podman-rootless"* ]]
    [[ "$output" == *"k8s"* ]]
}

@test "Truth table output mentions L1-gap for podman-rootless" {
    run _detect_runtime_truth_table
    [[ "$output" == *"L1-gap"* ]] || [[ "$output" == *"L1-GAP"* ]]
}

# ── Guard against double-source ────────────────────────────────────────────────

@test "Double-source is safe (guard _YSG_DETECT_RUNTIME_LOADED)" {
    source "${DETECT_RUNTIME_SH}"  # second source
    # If the guard works, _detect_runtime is still callable and not redefined in error
    _stub_no_k8s
    _stub_no_podman
    _stub_docker
    run _detect_runtime
    [ "$status" -eq 0 ]
    [ "${YSG_RUNTIME_4WAY}" = "docker" ]
}
