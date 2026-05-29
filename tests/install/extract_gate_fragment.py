#!/usr/bin/env python3
"""
Extract _ysg_onboard_stepup_gate() + log helpers from install.sh into a
minimal bash fragment suitable for subshell unit testing.

Usage: python3 extract_gate_fragment.py <install_sh_path>
Output: bash source fragment on stdout
"""
import sys

path = sys.argv[1]
lines = open(path).readlines()

# Collect log_* helpers
log_lines = []
for line in lines:
    if any(line.startswith(f) for f in
           ('log_step()', 'log_info()', 'log_success()', 'log_warn()', 'log_error()')):
        log_lines.append(line)

# Extract _ysg_onboard_stepup_gate() body
result = []
inside = False
depth = 0
for line in lines:
    stripped = line.rstrip()
    if not inside and stripped == '_ysg_onboard_stepup_gate() {':
        inside = True
    if inside:
        result.append(line)
        depth += line.count('{') - line.count('}')
        if depth <= 0:
            break

print('set +euo pipefail 2>/dev/null || true; set -euo pipefail')
print("C_BLUE='' C_BOLD='' C_GREEN='' C_YELLOW='' C_RED='' C_RESET=''")
for ln in log_lines:
    print(ln, end='')
for ln in result:
    print(ln, end='')
