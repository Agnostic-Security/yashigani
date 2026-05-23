#!/usr/bin/env bash
# Last updated: 2026-05-23T00:00:00+01:00
#
# lint_compose_command_vars.sh — Fail if any compose command/args/entrypoint
# block-scalar contains a bare ${VAR} or $VAR reference that will be consumed
# by Docker Compose YAML preprocessing before the shell ever sees it.
#
# Bug class: VEB-Compose (Variable-Expansion-Boundary — Compose layer)
# -----------------------------------------------------------------
# Docker Compose preprocesses ${VAR} and $VAR against .env + host environment
# at YAML parse time, BEFORE passing the value to the container's shell.  If
# VAR is absent from compose's scope the slot silently becomes empty.
#
# The correct escape is $$VAR (or $${VAR}): compose collapses $$ → $ at
# parse time, deferring expansion to the shell at runtime.
#
# Reference:
#   - docker/docker-compose.yml:720 (redis) — canonical correct pattern
#   - docs/shell-interpolation-discipline.md — full explanation
#   - internal-docs/yashigani/sanitization-map-20260523.md — Class A inventory
#   - internal-docs/yashigani/iris-v240-sanitization-structural-design.md
#   - internal-docs/yashigani/laura-v240-sanitization-structural-threat-model.md
#
# Two classes detected:
#
#   CLASS A — braced form:  ${VAR} or ${VAR_NAME} inside a block-scalar
#             command/args/entrypoint section of a compose YAML file.
#             This is the confirmed active bug form (sanitization-map A1/A2).
#             EXEMPT: ${VAR:-default} and ${VAR:?error} — those are
#             intentional compose-level substitution with fallback/error.
#             EXEMPT: $${VAR} — that is the correct escape (compose → $$).
#
#   CLASS B — unbraced form:  $VAR or $VARNAME (unbraced, uppercase or
#             lowercase) inside the same context.  Same compose-eat behaviour;
#             a contributor might use lowercase to evade an upper-case-only
#             regex.  EXEMPT: $$ prefix (correct double-dollar escape).
#
# Scope:
#   Scans ONLY the 5 compose files under docker/:
#     docker/docker-compose.yml
#     docker/docker-compose.podman-override.yml
#     docker/docker-compose.podman-virtiofs-override.yml
#     docker/docker-compose.release.yml
#     docker/docker-compose.wazuh.yml
#
#   Does NOT scan helm/yashigani/templates/*.yaml — helm K8s args: blocks use
#   ${VAR} correctly (K8s passes args verbatim to /bin/sh -c; no YAML
#   preprocessing).  Including helm would produce false positives on
#   pgbouncer.yaml:69, ollama.yaml:203-220, configmaps.yaml:1370-1411.
#
# Usage
#   bash scripts/lint_compose_command_vars.sh [repo_root]
#   (no args = derive repo root from script location)
#   bash scripts/lint_compose_command_vars.sh --test-fixtures
#   (run self-test against fixtures in tests/lint/)

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
NC='\033[0m'

info()  { printf "${GRN}[lint-compose-vars]${NC} %s\n" "$*"; }
warn()  { printf "${YLW}[lint-compose-vars]${NC} %s\n" "$*"; }
error() { printf "${RED}[lint-compose-vars]${NC} %s\n" "$*" >&2; }

# ---------------------------------------------------------------------------
# Argument / path resolution
# ---------------------------------------------------------------------------
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SELF_DIR%/scripts}"   # parent of scripts/

# Allow explicit repo root override (e.g. ci runs from checkout root).
# If the first argument is --test-fixtures, defer to fixture self-test below.
RUN_FIXTURES=0
if [[ "${1:-}" == "--test-fixtures" ]]; then
    RUN_FIXTURES=1
elif [[ -n "${1:-}" ]]; then
    REPO_ROOT="$1"
fi

# ---------------------------------------------------------------------------
# Target files (fixed list per Iris drift map — do NOT glob *.yml globally)
# ---------------------------------------------------------------------------
COMPOSE_FILES=(
    "${REPO_ROOT}/docker/docker-compose.yml"
    "${REPO_ROOT}/docker/docker-compose.podman-override.yml"
    "${REPO_ROOT}/docker/docker-compose.podman-virtiofs-override.yml"
    "${REPO_ROOT}/docker/docker-compose.release.yml"
    "${REPO_ROOT}/docker/docker-compose.wazuh.yml"
)

# ---------------------------------------------------------------------------
# Core scanner — awk-based block-scalar parser
#
# Algorithm:
#   1. Detect a block-scalar header line: line whose stripped content matches
#      /^(command|args|entrypoint):[[:space:]]*(|>|\|)$/ (key only on the line,
#      value is | or > or empty+next-line-is-block-scalar).
#      List-form headers like "command: [...]" are NOT block scalars — skip.
#   2. Record the indent level of the header line.
#   3. All subsequent lines whose indent is STRICTLY GREATER than the header
#      indent are inside the block scalar.
#   4. Exit block when a line at indent ≤ header indent appears.
#   5. Within the block, flag:
#        CLASS A: ${VAR}  where VAR is [A-Za-z_][A-Za-z0-9_]*
#                 but NOT ${VAR:-...} or ${VAR:?...} or ${VAR:+...} (compose substitution)
#                 and NOT $${...} (correct double-dollar escape)
#        CLASS B: $VAR    unbraced identifier [A-Za-z_][A-Za-z0-9_]*
#                 but NOT $$VAR (double-dollar escape)
#                 and NOT $$ alone (shell exit-code variable)
#                 and NOT $1 $2 etc. (positional params — not expanded by compose)
# ---------------------------------------------------------------------------

# Returns findings in "file:line:class:content" format, one per line.
scan_file() {
    local filepath="$1"
    awk '
    BEGIN {
        in_block   = 0
        block_indent = -1
    }

    # Helper: count leading spaces (tabs count as 1 each for YAML indent)
    function leading_spaces(s,    i, n) {
        n = 0
        for (i = 1; i <= length(s); i++) {
            c = substr(s, i, 1)
            if (c == " ") { n++ }
            else if (c == "\t") { n++ }
            else { break }
        }
        return n
    }

    # Helper: strip leading whitespace
    function lstrip(s) {
        sub(/^[[:space:]]+/, "", s)
        return s
    }

    {
        line_num    = NR
        raw_line    = $0
        stripped    = lstrip(raw_line)
        cur_indent  = leading_spaces(raw_line)

        # ---------------------------------------------------------------
        # Exit block if we have stepped back to same or lesser indent
        # ---------------------------------------------------------------
        if (in_block && cur_indent <= block_indent) {
            in_block     = 0
            block_indent = -1
        }

        # ---------------------------------------------------------------
        # Detect new block-scalar header
        # Matches:
        #   "  command: |"  "  command: >"  "  command:"  (bare — next item is block)
        #   "  args: |"     "  args: >"     "  args:"
        #   "  entrypoint: |"  etc.
        # Does NOT match list forms like "  command: [...]"
        #
        # Two conditions to avoid empty-alternation in POSIX awk regex:
        #   1. Key followed by : then | or > (block-scalar with explicit indicator)
        #   2. Key followed by : then end-of-line (bare — value on next line)
        # ---------------------------------------------------------------
        if (!in_block) {
            is_block_header = 0
            if (stripped ~ /^(command|args|entrypoint)[[:space:]]*:[[:space:]]*[|>][[:space:]]*$/) {
                is_block_header = 1
            } else if (stripped ~ /^(command|args|entrypoint)[[:space:]]*:[[:space:]]*$/) {
                is_block_header = 1
            }
            if (is_block_header) {
                in_block     = 1
                block_indent = cur_indent
            }
        }

        # ---------------------------------------------------------------
        # If we are inside a block, scan for bad patterns
        # Skip pure comment lines (stripped starts with #) — developers
        # write $VAR / ${VAR} in comments to document the problem pattern;
        # the shell ignores comment lines at runtime too.
        # ---------------------------------------------------------------
        if (in_block && cur_indent > block_indent && stripped !~ /^#/) {
            work = raw_line

            # -- CLASS A: ${VAR} without :- :? :+ modifier ---------------
            # Pattern: ${ followed by identifier, then } — but NOT $${ (double-dollar)
            # and NOT ${VAR:- / ${VAR:? / ${VAR:+
            pos = 1
            while (pos <= length(work)) {
                # Find next occurrence of ${
                idx = index(substr(work, pos), "${")
                if (idx == 0) break
                abs_idx = pos + idx - 1

                # Check for preceding $$ (double-dollar escape: $${VAR})
                if (abs_idx >= 2 && substr(work, abs_idx - 1, 1) == "$") {
                    pos = abs_idx + 2
                    continue
                }

                # Extract the content inside {...}
                rest = substr(work, abs_idx + 2)
                close_brace = index(rest, "}")
                if (close_brace == 0) { pos = abs_idx + 2; continue }

                inner = substr(rest, 1, close_brace - 1)

                # Check if it is a compose-substitution with modifier (:-  :?  :+)
                # These are intentional and correct; skip them.
                if (inner ~ /^[A-Za-z_][A-Za-z0-9_]*[[:space:]]*:[?+-]/) {
                    pos = abs_idx + 2 + close_brace
                    continue
                }

                # Must be a plain identifier (no modifier) to be flagged
                if (inner ~ /^[A-Za-z_][A-Za-z0-9_]*$/) {
                    print FILENAME "\t" line_num "\tA\t${" inner "}\t" raw_line
                }

                pos = abs_idx + 2 + close_brace
            }

            # -- CLASS B: $VAR unbraced (not preceded by $) ---------------
            # Scan for $ followed by an identifier character that is NOT:
            #   $$VAR  (double-dollar escape)
            #   $1/$2  (positional params — compose ignores these)
            #   $(     (command substitution — different issue, not in scope)
            #   ${     (already handled in CLASS A)
            work2 = raw_line
            pos2 = 1
            while (pos2 <= length(work2)) {
                idx2 = index(substr(work2, pos2), "$")
                if (idx2 == 0) break
                abs2 = pos2 + idx2 - 1

                next_char = substr(work2, abs2 + 1, 1)

                # Skip $$  (double-dollar — correct escape or shell $$)
                if (next_char == "$") { pos2 = abs2 + 2; continue }

                # Skip ${ (handled above) and $( (command subst — not in scope)
                if (next_char == "{" || next_char == "(") { pos2 = abs2 + 2; continue }

                # Skip positional params $0-$9
                if (next_char ~ /[0-9]/) { pos2 = abs2 + 2; continue }

                # Skip $ at end of line or $ followed by non-identifier char
                if (next_char !~ /[A-Za-z_]/) { pos2 = abs2 + 2; continue }

                # Extract the identifier
                rest2 = substr(work2, abs2 + 1)
                varname = ""
                for (ci = 1; ci <= length(rest2); ci++) {
                    c2 = substr(rest2, ci, 1)
                    if (c2 ~ /[A-Za-z0-9_]/) { varname = varname c2 }
                    else { break }
                }

                if (length(varname) > 0) {
                    print FILENAME "\t" line_num "\tB\t$" varname "\t" raw_line
                }

                pos2 = abs2 + 1 + length(varname)
            }
        }
    }
    ' "$filepath"
}

# ---------------------------------------------------------------------------
# Fixture self-test (--test-fixtures mode)
# ---------------------------------------------------------------------------
if [[ "$RUN_FIXTURES" -eq 1 ]]; then
    FIXTURE_DIR="${REPO_ROOT}/tests/lint"
    ALL_PASS=1

    run_fixture_test() {
        local fixture="$1"
        local expect_fail="$2"   # 1 = expect findings; 0 = expect clean
        local label="$3"
        local filepath="${FIXTURE_DIR}/${fixture}"

        if [[ ! -f "$filepath" ]]; then
            warn "  SKIP  $label (fixture not found: $filepath)"
            return
        fi

        local findings
        findings=$(scan_file "$filepath" || true)

        if [[ "$expect_fail" -eq 1 ]]; then
            if [[ -n "$findings" ]]; then
                info "  PASS  $label (correctly flagged findings)"
            else
                error "  FAIL  $label (expected findings but got none)"
                ALL_PASS=0
            fi
        else
            if [[ -z "$findings" ]]; then
                info "  PASS  $label (correctly clean)"
            else
                error "  FAIL  $label (expected clean but got findings):"
                while IFS= read -r f; do
                    error "         $f"
                done <<< "$findings"
                ALL_PASS=0
            fi
        fi
    }

    info "Running fixture self-tests from ${FIXTURE_DIR}/"
    run_fixture_test "compose_bad_braced.yml.fixture"       1 "CLASS A braced \${VAR} triggers"
    run_fixture_test "compose_bad_unbraced.yml.fixture"     1 "CLASS B unbraced \$VAR triggers"
    run_fixture_test "compose_good_dollar2.yml.fixture"     0 "\$\$PASS exempt (correct escape)"
    run_fixture_test "compose_good_substitution.yml.fixture" 0 "\${VAR:-default} exempt (compose subst)"
    run_fixture_test "compose_list_form.yml.fixture"        0 "List-form command exempt (no block scalar)"

    if [[ "$ALL_PASS" -eq 1 ]]; then
        info "All fixture tests PASSED."
        exit 0
    else
        error "One or more fixture tests FAILED."
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------
TOTAL_FINDINGS=0
EXIT_CODE=0

info "Scanning for VEB-Compose \${VAR}/\$VAR in command/args/entrypoint block scalars..."
info "Repo root : ${REPO_ROOT}"
info "Scope     : docker/docker-compose*.yml (5 files — helm excluded by design)"

for compose_file in "${COMPOSE_FILES[@]}"; do
    if [[ ! -f "$compose_file" ]]; then
        warn "Skipping (not found): ${compose_file}"
        continue
    fi

    findings=$(scan_file "$compose_file" || true)
    if [[ -z "$findings" ]]; then
        continue
    fi

    while IFS= read -r raw; do
        [[ -z "$raw" ]] && continue

        # awk output format: FILEPATH<TAB>LINENO<TAB>CLASS<TAB>VARREF<TAB>RAW_LINE
        # TAB delimiter avoids splitting on colons that appear in file content.
        IFS=$'\t' read -r found_file found_line found_class found_varref found_content <<< "$raw"

        if [[ "$found_class" == "A" ]]; then
            error "CLASS A | ${found_file}:${found_line} | \${VAR} eaten by compose YAML preprocessing"
        else
            error "CLASS B | ${found_file}:${found_line} | \$VAR eaten by compose YAML preprocessing"
        fi
        error "  Line    : ${found_content}"
        error "  Pattern : ${found_varref}"
        error "  Fix     : prefix with an extra \$ so compose collapses \$\$ -> \$ at parse time"
        error "            e.g.  \${PASS}  ->  \$\$PASS   |   \$VAR  ->  \$\$VAR"
        error ""
        TOTAL_FINDINGS=$(( TOTAL_FINDINGS + 1 ))
        EXIT_CODE=1
    done <<< "$findings"
done

if [[ "$EXIT_CODE" -ne 0 ]]; then
    error "${TOTAL_FINDINGS} VEB-Compose finding(s) detected."
    error "See docs/shell-interpolation-discipline.md and docker-compose.yml:720 for the correct pattern."
    error "Canonical fix: \${PASS} → \$\$PASS  |  \$(cat ...) → \$\$(cat ...) in block-scalar command/args/entrypoint"
else
    info "No VEB-Compose findings. Clean."
fi

exit "$EXIT_CODE"
