#!/usr/bin/env bash
# tests/install/test_install_sh_lint.sh
# Lint: detect apostrophes inside multi-line python3 -c '...' blocks in install.sh.
#
# Bug class: a single-quote ( ' ) inside the body of a shell single-quoted string
# terminates the string at runtime even though bash -n may report PASS (static
# analysis balances delimiters across lines).  Apostrophes in prose comments or
# Python string literals are the most common trigger.  See ISSUE-023 (2026-05-19).
#
# Tests:
#   (1) No apostrophes in any multi-line python3 -c block body in install.sh.
#   (2) Runtime parse-probe: wrap the python3 -c block in a shell function and
#       confirm bash -n parses it cleanly (catches the class bash -n misses on
#       the whole-file level because delimiters accidentally re-balance later).
#   (3) No other cmd -c ' multi-line blocks contain embedded apostrophes.
#
# This test requires no Docker daemon and no live stack.
# Exit codes: 0 = all PASS; 1 = one or more FAIL.
#
# ISSUE-023 close — 2026-05-19
# last-updated: 2026-05-19

set -uo pipefail
IFS=$'\n\t'

PASS=0
FAIL=0

_pass() { printf "[PASS] %s\n" "$1"; (( PASS++ )) || true; }
_fail() { printf "[FAIL] %s\n" "$1" >&2; (( FAIL++ )) || true; }
_info() { printf "[INFO] %s\n" "$1"; }
_section() { printf "\n--- %s ---\n" "$1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
INSTALL_SH="${INSTALL_SH:-${REPO_ROOT}/install.sh}"

_info "install.sh: ${INSTALL_SH}"
_info "repo root:  ${REPO_ROOT}"

if [[ ! -f "$INSTALL_SH" ]]; then
    printf "[FAIL] install.sh not found at: %s\n" "$INSTALL_SH" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# find_multiline_c_blocks: emit "start_line end_line" pairs (1-indexed, inclusive)
# for every  <cmd> -c '  ...  '  multi-line construct in install.sh.
# "Multi-line" = the opening delimiter line ends with a bare ' and the closing
# delimiter line begins with a bare ' (possibly followed by whitespace or shell
# continuation tokens like 2>&1).
find_multiline_c_blocks() {
    local file="$1"
    local lineno=0
    local open_lineno=0
    local in_block=0
    while IFS= read -r line; do
        (( lineno++ )) || true
        if [[ $in_block -eq 0 ]]; then
            # Opening: line ends with -c ' (with optional leading whitespace/prefix)
            if [[ "$line" =~ [[:space:]]-c[[:space:]]\'[[:space:]]*$ ]]; then
                open_lineno=$lineno
                in_block=1
            fi
        else
            # Closing: line starts with optional whitespace then a bare '
            # followed by optional shell tokens (2>&1, |, ;, ), etc.)
            if [[ "$line" =~ ^[[:space:]]*\'([[:space:]]|$) ]]; then
                printf "%d %d\n" "$open_lineno" "$lineno"
                in_block=0
                open_lineno=0
            fi
        fi
    done < "$file"
}

# check_block_for_apostrophes: given a file and start/end line numbers,
# grep the BODY (excluding the opening and closing delimiter lines themselves)
# for any single-quote character.  Prints "lineno: text" for each hit.
check_block_for_apostrophes() {
    local file="$1"
    local start="$2"
    local end="$3"
    local body_start=$(( start + 1 ))
    local body_end=$(( end - 1 ))
    if (( body_end < body_start )); then
        return 0  # empty body
    fi
    # sed extracts the body; grep finds any ' character; awk re-adds line numbers.
    sed -n "${body_start},${body_end}p" "$file" | \
        grep -n "'" | \
        awk -v base="$body_start" -F: '{ printf "%d: %s\n", base + $1 - 1, substr($0, index($0,$2)) }'
}

# ---------------------------------------------------------------------------
# TEST (1): No apostrophes in any multi-line python3 -c block body
# ---------------------------------------------------------------------------
_section "TEST (1): Apostrophes in multi-line python3 -c block bodies"

_block_count=0
_apostrophe_block_count=0

while IFS=' ' read -r blk_start blk_end; do
    (( _block_count++ )) || true
    _hits="$(check_block_for_apostrophes "$INSTALL_SH" "$blk_start" "$blk_end")"
    if [[ -n "$_hits" ]]; then
        (( _apostrophe_block_count++ )) || true
        _fail "(1) Apostrophe(s) in python3 -c block at L${blk_start}-L${blk_end}:"
        while IFS= read -r hit; do
            printf "    L%s\n" "$hit" >&2
        done <<< "$_hits"
    fi
done < <(find_multiline_c_blocks "$INSTALL_SH" | grep -v '^$')

if [[ $_block_count -eq 0 ]]; then
    _info "(1) No multi-line python3 -c blocks found (nothing to check)"
elif [[ $_apostrophe_block_count -eq 0 ]]; then
    _pass "(1) ${_block_count} multi-line block(s) checked — no embedded apostrophes found"
fi

# ---------------------------------------------------------------------------
# TEST (2): Runtime parse-probe on the register_agent_bundles python3 -c block
# The block is the only multi-line one in install.sh as of ISSUE-023.
# We wrap it in a shell function and run bash -n on the fragment — this catches
# the specific failure mode where bash -n on the whole file gives PASS (delimiters
# re-balance later) but the block itself is broken at runtime.
# ---------------------------------------------------------------------------
_section "TEST (2): Runtime parse-probe on python3 -c block (bash -n on fragment)"

_probe_file="$(mktemp /Users/max/Documents/Claude/yashigani/tests/install/parse_probe_XXXXXX.sh)"
trap 'rm -f "$_probe_file"' EXIT

_first_block_start=0
_first_block_end=0
while IFS=' ' read -r blk_start blk_end; do
    if (( blk_start > 0 && _first_block_start == 0 )); then
        _first_block_start=$blk_start
        _first_block_end=$blk_end
    fi
done < <(find_multiline_c_blocks "$INSTALL_SH" | grep -v '^$')

if (( _first_block_start == 0 )); then
    _info "(2) No multi-line python3 -c block found — skipping runtime parse-probe"
else
    # Emit: shebang + function wrapper + the surrounding shell lines of the block
    # (2 lines before, 2 lines after for context) so bash -n sees a valid fragment.
    _ctx_start=$(( _first_block_start > 2 ? _first_block_start - 2 : 1 ))
    _ctx_end=$(( _first_block_end + 2 ))

    {
        printf '#!/usr/bin/env bash\n'
        printf '_parse_probe_fn() {\n'
        sed -n "${_ctx_start},${_ctx_end}p" "$INSTALL_SH"
        printf '\n}\n'
    } > "$_probe_file"

    _parse_out="$(bash -n "$_probe_file" 2>&1)"
    _parse_rc=$?
    if [[ $_parse_rc -eq 0 ]]; then
        _pass "(2) bash -n parse-probe on L${_first_block_start}-L${_first_block_end} block PASS"
    else
        _fail "(2) bash -n parse-probe FAIL on L${_first_block_start}-L${_first_block_end}: ${_parse_out}"
    fi
fi

# ---------------------------------------------------------------------------
# TEST (3): No other cmd -c ' multi-line blocks with apostrophes
# This is a broader sweep: any <cmd> -c ' multi-line block in install.sh.
# Covers future additions beyond python3 (e.g. perl -e, node -e, etc.).
# ---------------------------------------------------------------------------
_section "TEST (3): Broader sweep — all multi-line cmd -c blocks for apostrophes"

_other_count=0
_other_fail=0

while IFS=' ' read -r blk_start blk_end; do
    _cmd_line="$(sed -n "${blk_start}p" "$INSTALL_SH")"
    # Skip python3 blocks (already handled in TEST 1)
    if echo "$_cmd_line" | grep -q 'python3'; then
        continue
    fi
    (( _other_count++ )) || true
    _hits="$(check_block_for_apostrophes "$INSTALL_SH" "$blk_start" "$blk_end")"
    if [[ -n "$_hits" ]]; then
        (( _other_fail++ )) || true
        _fail "(3) Apostrophe(s) in non-python3 -c block at L${blk_start}-L${blk_end}:"
        while IFS= read -r hit; do
            printf "    L%s\n" "$hit" >&2
        done <<< "$_hits"
    fi
done < <(find_multiline_c_blocks "$INSTALL_SH" | grep -v '^$')

if [[ $_other_count -eq 0 ]]; then
    _info "(3) No non-python3 multi-line cmd -c blocks found — nothing to sweep"
elif [[ $_other_fail -eq 0 ]]; then
    _pass "(3) ${_other_count} non-python3 block(s) swept — no embedded apostrophes"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf "\n=== RESULTS: PASS=%d FAIL=%d ===\n" "$PASS" "$FAIL"
if [[ "$FAIL" -gt 0 ]]; then
    printf "\nRESULT: FAIL — %d check(s) failed. (ISSUE-023 apostrophe lint)\n" "$FAIL"
    exit 1
fi
printf "\nRESULT: PASS — %d check(s) passed. (ISSUE-023 apostrophe lint)\n" "$PASS"
exit 0
