#!/usr/bin/env bats
# tests/install/test_uninstall_honest_volume_summary.bats
#
# Regression tests for the uninstall.sh final-summary honesty gap (dispatch
# item 4 follow-up to YSG-RISK-197, 2026-08-16): after a teardown that
# printed a WARN naming N unattributed anonymous dangling volumes it
# deliberately left in place (they cannot be safely attributed to this
# project — Docker/Podman anonymous volumes carry no project label — and
# must never be blind-removed on a possibly-shared/multi-org host, per
# CROSS-ORG-DANGLING-VOL-2026-07-22), the script's LAST line still said
# unconditionally: "All volumes deleted." — the exact "reports success
# whether or not the work happened" defect class already fixed once in this
# same commit's YSG-RISK-197 root-cause work (leak-at-source +
# reconciliation-pass honesty), just left unclosed at the final print.
#
# Prior art read before writing this fix (Documentation review before ANY
# change, CLAUDE.md / Change Management SS4.2):
#   - AgnosticSecurity Risk Management/yashigani-risks.md YSG-RISK-197 —
#     "After a full teardown that printed ... 'All volumes deleted', 20
#     dangling volumes remained; 2 were created by the very install being
#     torn down, the other 18 accumulated from earlier install/uninstall
#     cycles on the same host." The 2 (this run's own leak) are fixed at
#     the source by this same 2026-08-16 commit's YSG-RISK-197 root-cause
#     fix (_remove_containers -v). The other (pre-existing / cross-cycle)
#     volumes are OUT OF SCOPE for automated removal — same
#     CROSS-ORG-DANGLING-VOL-2026-07-22 safety posture already coded into
#     the reconciliation pass's WARN-only branch (uninstall.sh, "cannot
#     attribute to project ... NOT removing"). This fix does not attempt to
#     identify or remove those — it only makes the FINAL line stop
#     contradicting the WARN that was already printed moments earlier.
#   - git log -S on the ANON-VOL-LEAK section (5ae7d48f, and this same
#     commit's earlier _remove_containers -v fix) — both deliberately left
#     unattributed volumes WARN-only, never removed; this fix is
#     reporting-only, consistent with that established posture.
#
# Extraction strategy: uninstall.sh's summary section is top-level script
# code (not a function), anchored between the ANON-VOL-LEAK reconciliation
# `if` guard and end-of-file — line-range extraction (not the brace-counting
# `_extract_fn` helper used elsewhere in this suite, which only applies to
# `name() { ... }` function definitions). The extracted tail references
# `_ysg_unattributed_dangling_total`, which the real script declares near
# the top (outside this extracted range) so it is always defined under
# `set -u` — tests must pre-set it too, matching that real-script contract.
#
# Requirements: bats-core >= 1.10, bash 4+.
# Run:
#   bats tests/install/test_uninstall_honest_volume_summary.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
UNINSTALL_SH="${REPO_ROOT}/uninstall.sh"

_extract_summary_tail() {
  # From the (unique) ANON-VOL-LEAK reconciliation `if` guard through EOF.
  local _start_line
  _start_line="$(grep -n '^if \[ "\$REMOVE_VOLUMES" = "true" \] && \[ "\$RUNTIME_SUBTYPE" != "k8s" \]; then$' "${UNINSTALL_SH}" \
    | while IFS=: read -r ln _; do
        if sed -n "$((ln+1))p" "${UNINSTALL_SH}" | grep -q 'ANON-VOL-LEAK reconciliation pass'; then
          echo "$ln"
          break
        fi
      done)"
  [[ -n "$_start_line" ]] || return 1
  tail -n +"${_start_line}" "${UNINSTALL_SH}"
}

setup() {
  local tail_src
  tail_src="$(_extract_summary_tail)"
  [[ -n "$tail_src" ]] || { echo "ERROR: could not locate ANON-VOL-LEAK summary tail in uninstall.sh" >&2; return 1; }

  SCRATCH="$(mktemp -d "${BATS_TEST_TMPDIR}/uninstall-scratch.XXXXXX")"
  mkdir -p "${SCRATCH}/docker"

  TAIL_SCRIPT="${SCRATCH}/tail.sh"
  printf '%s\n' "$tail_src" > "$TAIL_SCRIPT"

  # Shared docker() stub dispatch table, sourced into every sub-shell below.
  DOCKER_STUB="${SCRATCH}/docker_stub.sh"
  cat > "$DOCKER_STUB" <<'STUBEOF'
docker() {
  case "$1 $2" in
    "volume prune")
      printf "Deleted Volumes:\nTotal reclaimed space: 0B\n"
      ;;
    "volume ls")
      if [ "${MOCK_UNATTRIBUTED:-0}" -gt 0 ]; then
        printf "anon-vol-1\n"
      fi
      ;;
    *) : ;;
  esac
}
export -f docker
STUBEOF
}

teardown() {
  rm -rf "${SCRATCH:-}" 2>/dev/null || true
}

# Runs the extracted uninstall.sh tail in a fresh, isolated bash -c
# environment with the docker() stub sourced first and the exact variable
# contract the real script provides at that point (including the
# unconditional top-of-file _ysg_unattributed_dangling_total=0 init).
_run_summary_tail() {
  local remove_volumes="$1" mock_unattributed="$2"
  MOCK_UNATTRIBUTED="$mock_unattributed" \
  REMOVE_VOLUMES="$remove_volumes" \
  RUNTIME_SUBTYPE="docker-engine" \
  RUNTIME="docker" \
  SCRIPT_DIR="$SCRATCH" \
  _PROJECT_PREFIX="yashigani-test" \
  DOCKER_STUB="$DOCKER_STUB" \
  TAIL_SCRIPT="$TAIL_SCRIPT" \
  bash -c '
    set -uo pipefail
    source "$DOCKER_STUB"
    _ysg_unattributed_dangling_total=0
    source "$TAIL_SCRIPT"
  '
}

# ── Lint gates ────────────────────────────────────────────────────────────

@test "LINT: bash -n parses uninstall.sh cleanly" {
  run bash -n "${UNINSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "LINT: _ysg_unattributed_dangling_total is declared unconditionally (set -u safe)" {
  run grep -c '^_ysg_unattributed_dangling_total=0' "${UNINSTALL_SH}"
  [ "$output" -eq 1 ]
}

# ── THE ORIGINAL BUG: unattributed volumes WARNed but "All volumes deleted."
#    still printed ─────────────────────────────────────────────────────────

@test "THE ORIGINAL BUG: unattributed dangling volumes present -> final line no longer claims 'All volumes deleted.'" {
  run _run_summary_tail "true" "1"
  [ "$status" -eq 0 ]
  [[ "$output" == *"unattributed dangling volume(s)"* ]]
  [[ "$output" != *"All volumes deleted."* ]]
}

@test "unattributed dangling volumes present -> WARN was ALSO printed (not just the summary line change)" {
  run _run_summary_tail "true" "1"
  [[ "$output" == *"[WARN]"*"anonymous dangling volume(s) found"* ]]
}

# ── Genuinely clean run: no unattributed volumes -> "All volumes deleted."
#    is still printed (behaviour preserved for the true-clean case) ───────

@test "no unattributed dangling volumes -> 'All volumes deleted.' still printed (unchanged for the clean case)" {
  run _run_summary_tail "true" "0"
  [ "$status" -eq 0 ]
  [[ "$output" == *"All volumes deleted."* ]]
}

@test "REMOVE_VOLUMES=false -> 'Data volumes preserved.' (baseline unaffected)" {
  run _run_summary_tail "false" "0"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Data volumes preserved."* ]]
  [[ "$output" != *"All volumes deleted."* ]]
}
