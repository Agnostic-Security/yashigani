#!/usr/bin/env python3
"""
Extract _verify_stepup_proof_token() + _require_stepup_mi4() + log helpers
from uninstall.sh into a minimal bash fragment suitable for subshell unit
testing (YSG-RISK-195 parity fix).

Usage: python3 extract_uninstall_stepup_fragment.py <uninstall_sh_path>
Output: bash source fragment on stdout
"""
import sys

path = sys.argv[1]
lines = open(path).readlines()

# Collect log_* helpers
log_lines = []
for line in lines:
    if any(line.startswith(f) for f in
           ('log_info()', 'log_success()', 'log_warn()', 'log_error()')):
        log_lines.append(line)

TARGET_FUNCS = ("_verify_stepup_proof_token() {", "_require_stepup_mi4() {")

result = []
inside = False
depth = 0
for line in lines:
    stripped = line.rstrip()
    if not inside and stripped in TARGET_FUNCS:
        inside = True
    if inside:
        result.append(line)
        depth += line.count('{') - line.count('}')
        if depth <= 0:
            inside = False

print("C_BLUE='' C_BOLD='' C_GREEN='' C_YELLOW='' C_RED='' C_RESET=''")
for ln in log_lines:
    print(ln, end='')
for ln in result:
    print(ln, end='')
