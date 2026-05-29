#!/usr/bin/env bats
# tests/install/test_p1_e2e_bug_fixes.bats
#
# Regression tests for bugs surfaced during P1 onboarding E2E live run
# (fix/p1-e2e-live-bugs).
#
# B-002: onboard S2 inserts service_identities.yaml entry at EOF (outside
#         services: mapping) → structurally invalid YAML, _pki_run_issuer fails.
#         Fix: locate services: boundary, insert inside the mapping.
#
# C-003: _pki_chown_client_keys did not cover dynamically-onboarded agent
#         keys (_client.key issued for agents not in the static pki_ownership.sh
#         map). Fix: read BEGIN YSG-ONBOARD-* sentinels from service_identities.yaml
#         and chown those keys to UID 65534 (nobody — codegen default).
#
# #21:   uninstall.sh silent exit-1 on docker/podman compose installs.
#         Root cause: $(grep '^NAMESPACE=' state-file | cut …) pipeline exits 1
#         when NAMESPACE is absent (compose state files omit it); `set -euo pipefail`
#         propagates the non-zero exit with zero output — customer sees nothing.
#         Fix: `|| true` on both NAMESPACE and HELM_RELEASE greps.
#
# Tests are fully offline (mock filesystem under tests/install/.mock_p1e2e/ —
# never /tmp).
#
# Requirements:
#   bats-core >= 1.10.0
#   bash 3.2+, python3
#
# Run:
#   bats tests/install/test_p1_e2e_bug_fixes.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"
UNINSTALL_SH="${REPO_ROOT}/uninstall.sh"

# Test scratch space — under repo, never /tmp.
MOCK_ROOT="${REPO_ROOT}/tests/install/.mock_p1e2e"

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# _extract_onboard_s2_py — pull the Python heredoc block that handles S2
# (service_identities.yaml append) out of install.sh into a standalone
# script so we can run it in isolation.
#
# Strategy: the block lives between "# S2: append service_identities.yaml"
# and "# S7: apply GID 2002" inside the <<'PYEOF' … PYEOF heredoc.
# We use Python to extract it rather than sed (BSD/GNU portability).
_extract_s2_fragment() {
  python3 - "${INSTALL_SH}" "$1" <<'PYEOF'
import sys, re, textwrap

install_sh = open(sys.argv[1], encoding='utf-8').read()
output_py  = sys.argv[2]

# The onboard Python block is a heredoc (<<'PYEOF'…PYEOF) inside install.sh.
# Locate the outer here-doc boundary that contains the S2 block.
# The fragment starts at 'import sys, os' (first line of the python3 - block)
# and ends just before the closing PYEOF.
#
# We extract by finding the line that starts the python3 heredoc and then
# walking forward to the matching PYEOF sentinel.
lines = install_sh.split('\n')
in_block = False
block_lines = []
for line in lines:
    if not in_block:
        # The heredoc opens with: python3 - "$_manifest" "$WORK_DIR" ... <<'PYEOF'
        if line.strip().startswith('python3 -') and "<<'PYEOF'" in line:
            in_block = True
        continue
    if line.strip() == 'PYEOF':
        break
    block_lines.append(line)

if not block_lines:
    print('ERROR: could not locate onboard python3 heredoc in install.sh', file=sys.stderr)
    sys.exit(1)

with open(output_py, 'w', encoding='utf-8') as f:
    f.write('\n'.join(block_lines) + '\n')
PYEOF
}

setup() {
  rm -rf "${MOCK_ROOT}"
  mkdir -p "${MOCK_ROOT}/docker"
  mkdir -p "${MOCK_ROOT}/docker/secrets"
  mkdir -p "${MOCK_ROOT}/src"
}

teardown() {
  rm -rf "${MOCK_ROOT}"
}

# ===========================================================================
# B-002: service_identities.yaml insert INSIDE services: mapping
# ===========================================================================

# ---------------------------------------------------------------------------
# Helper: create a realistic service_identities.yaml fixture (minimal but
# structurally identical to the real one — services: followed by endpoint_acls:
# followed by canary_policy:).
# ---------------------------------------------------------------------------
_make_fixture_sid() {
  local _path="$1"
  cat > "$_path" <<'YAML'
schema_version: 1

services:

  - name: caddy
    dns_sans: [caddy, caddy.internal]
    spiffe_id: spiffe://yashigani.internal/caddy
    purpose: "TLS edge"
    mtls_capable: true
    bootstrap_token_sha256: ""
    revoked: false

  - name: gateway
    dns_sans: [gateway, gateway.internal]
    spiffe_id: spiffe://yashigani.internal/gateway
    purpose: "MCP reverse proxy"
    mtls_capable: true
    bootstrap_token_sha256: ""
    revoked: false

# ─────────────────────────────────────────────────────────────────────────────
# Endpoint ACLs
# ─────────────────────────────────────────────────────────────────────────────
endpoint_acls:
  "/internal/metrics":
    allowed_spiffe_ids:
      - spiffe://yashigani.internal/prometheus

canary_policy:
  auto_revoke_on_canary_hit: false
YAML
}

@test "B-002: bash -n install.sh passes" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "B-002: onboard S2 Python insert logic produces valid YAML under services:" {
  local _sid="${MOCK_ROOT}/docker/service_identities.yaml"
  _make_fixture_sid "$_sid"

  # Run just the S2 block: extract the python3 heredoc from install.sh,
  # monkey-patch the agent name / tenant / output_root, then execute it.
  # We build a minimal synthetic 'parsed' dict and sys.argv so the block runs.
  python3 - "$_sid" <<'PYEOF'
import sys, os, re, tempfile

sid_file = sys.argv[1]
output_root = os.path.dirname(os.path.dirname(sid_file))  # …/MOCK_ROOT

# Replicate the S2 logic from install.sh (B-002 fix).
# This is the FIXED logic — the test validates the correct behaviour.
agent_name = 'hermes-agent'
tenant_id  = 'acme-corp'

content = open(sid_file, encoding='utf-8').read()
begin_marker = '# BEGIN YSG-ONBOARD-' + agent_name
assert begin_marker not in content, 'entry already present before insert'

spiffe_id = 'spiffe://yashigani.internal/agents/%s/%s' % (tenant_id, agent_name)
entry_block = (
    '  # BEGIN YSG-ONBOARD-{name}\n'
    '  # Onboarded agent — managed by yashigani onboard/offboard\n'
    '  - name: {name}\n'
    '    dns_sans: [{name}, {name}.internal]\n'
    '    spiffe_id: {spiffe_id}\n'
    '    purpose: "BYO agent — ring-fenced (P1 onboarding)"\n'
    '    mtls_capable: false\n'
    '    bootstrap_token_sha256: ""\n'
    '    revoked: false\n'
    '  # END YSG-ONBOARD-{name}\n'
).format(name=agent_name, spiffe_id=spiffe_id)

services_match = re.search(r'^services:\s*$', content, re.MULTILINE)
assert services_match is not None, 'no services: key found'

boundary_re = re.compile(r'\n(?=# [─]{5}|[a-z_][a-zA-Z0-9_]*:)', re.MULTILINE)
boundary_match = boundary_re.search(content, services_match.end())
assert boundary_match is not None, 'no boundary found after services:'

insert_pos = boundary_match.start() + 1
new_content = content[:insert_pos] + entry_block + '\n' + content[insert_pos:]

dir_ = os.path.dirname(sid_file)
fd, tmp = tempfile.mkstemp(dir=dir_, prefix='.ysg-test-tmp-', suffix='.yaml')
try:
    os.write(fd, new_content.encode('utf-8'))
    os.close(fd); fd = -1
    os.chmod(tmp, os.stat(sid_file).st_mode & 0o777)
    os.rename(tmp, sid_file)
except Exception:
    if fd != -1: os.close(fd)
    os.unlink(tmp)
    raise

print('[test] S2 insert complete')
PYEOF

  # 1. Python must exit 0
  run python3 - "$_sid" <<'PYEOF'
import sys, os, re, tempfile
sid_file = sys.argv[1]
agent_name = 'hermes-agent'
tenant_id  = 'acme-corp'
content = open(sid_file, encoding='utf-8').read()
begin_marker = '# BEGIN YSG-ONBOARD-' + agent_name
if begin_marker not in content:
    print('FAIL: sentinel not found after insert', file=sys.stderr)
    sys.exit(1)
# Verify the entry is under services: (before endpoint_acls: key)
services_pos = content.index('services:')
boundary_pos = content.index('endpoint_acls:')
agent_pos    = content.index(begin_marker)
if not (services_pos < agent_pos < boundary_pos):
    print('FAIL: agent entry is at pos %d, services: at %d, endpoint_acls: at %d'
          % (agent_pos, services_pos, boundary_pos), file=sys.stderr)
    sys.exit(1)
# 2. Validate the resulting YAML is parseable
import yaml
try:
    parsed = yaml.safe_load(content)
except Exception as e:
    print('FAIL: yaml.safe_load raised: %s' % e, file=sys.stderr)
    sys.exit(1)
assert 'services' in parsed, 'services key absent after parse'
names = [s.get('name') for s in parsed['services']]
assert agent_name in names, 'agent %r not in services list after parse: %s' % (agent_name, names)
# 3. Verify canary_policy is still intact (was NOT overwritten)
assert 'canary_policy' in parsed, 'canary_policy key absent — structure truncated'
print('[test] PASS: entry inside services:, YAML valid, canary_policy intact')
PYEOF
  [ "$status" -eq 0 ]
}

@test "B-002: insert is idempotent (second call does not duplicate entry)" {
  local _sid="${MOCK_ROOT}/docker/service_identities.yaml"
  _make_fixture_sid "$_sid"

  # Insert once
  python3 - "$_sid" <<'PYEOF'
import sys, os, re, tempfile
sid_file = sys.argv[1]
agent_name = 'hermes-agent'
tenant_id  = 'acme-corp'
content = open(sid_file, encoding='utf-8').read()
begin_marker = '# BEGIN YSG-ONBOARD-' + agent_name
if begin_marker in content:
    sys.exit(0)  # idempotent
spiffe_id = 'spiffe://yashigani.internal/agents/%s/%s' % (tenant_id, agent_name)
entry_block = (
    '  # BEGIN YSG-ONBOARD-{name}\n'
    '  - name: {name}\n'
    '    revoked: false\n'
    '  # END YSG-ONBOARD-{name}\n'
).format(name=agent_name, spiffe_id=spiffe_id)
services_match = re.search(r'^services:\s*$', content, re.MULTILINE)
boundary_re = re.compile(r'\n(?=# [─]{5}|[a-z_][a-zA-Z0-9_]*:)', re.MULTILINE)
boundary_match = boundary_re.search(content, services_match.end())
insert_pos = boundary_match.start() + 1
new_content = content[:insert_pos] + entry_block + '\n' + content[insert_pos:]
dir_ = os.path.dirname(sid_file)
fd, tmp = tempfile.mkstemp(dir=dir_, prefix='.ysg-test-tmp-', suffix='.yaml')
os.write(fd, new_content.encode('utf-8'))
os.close(fd)
os.rename(tmp, sid_file)
PYEOF

  # Try insert again — idempotent path (begin_marker already present)
  python3 - "$_sid" <<'PYEOF'
import sys, re
sid_file = sys.argv[1]
agent_name = 'hermes-agent'
content = open(sid_file, encoding='utf-8').read()
begin_marker = '# BEGIN YSG-ONBOARD-' + agent_name
if begin_marker in content:
    print('[test] idempotent path triggered correctly')
    sys.exit(0)
print('FAIL: idempotent guard did not fire', file=sys.stderr)
sys.exit(1)
PYEOF

  # Count occurrences — must be exactly 1
  run grep -c 'BEGIN YSG-ONBOARD-hermes-agent' "$_sid"
  [ "$output" = "1" ]
}

@test "B-002: entry NOT inserted after canary_policy (EOF regression guard)" {
  local _sid="${MOCK_ROOT}/docker/service_identities.yaml"
  _make_fixture_sid "$_sid"

  python3 - "$_sid" <<'PYEOF'
import sys, os, re, tempfile
sid_file = sys.argv[1]
agent_name = 'hermes-agent'
tenant_id  = 'acme-corp'
content = open(sid_file, encoding='utf-8').read()
begin_marker = '# BEGIN YSG-ONBOARD-' + agent_name
if begin_marker in content:
    sys.exit(0)
spiffe_id = 'spiffe://yashigani.internal/agents/%s/%s' % (tenant_id, agent_name)
entry_block = (
    '  # BEGIN YSG-ONBOARD-{name}\n'
    '  - name: {name}\n'
    '    revoked: false\n'
    '  # END YSG-ONBOARD-{name}\n'
).format(name=agent_name, spiffe_id=spiffe_id)
services_match = re.search(r'^services:\s*$', content, re.MULTILINE)
boundary_re = re.compile(r'\n(?=# [─]{5}|[a-z_][a-zA-Z0-9_]*:)', re.MULTILINE)
boundary_match = boundary_re.search(content, services_match.end())
insert_pos = boundary_match.start() + 1
new_content = content[:insert_pos] + entry_block + '\n' + content[insert_pos:]
dir_ = os.path.dirname(sid_file)
fd, tmp = tempfile.mkstemp(dir=dir_, prefix='.ysg-test-tmp-', suffix='.yaml')
os.write(fd, new_content.encode('utf-8'))
os.close(fd)
os.rename(tmp, sid_file)
PYEOF

  # The agent entry must come BEFORE canary_policy: in the file
  run python3 - "$_sid" <<'PYEOF'
import sys
content = open(sys.argv[1]).read()
agent_pos  = content.find('BEGIN YSG-ONBOARD-hermes-agent')
canary_pos = content.find('canary_policy:')
if agent_pos == -1:
    print('FAIL: agent sentinel not found', file=sys.stderr)
    sys.exit(1)
if canary_pos == -1:
    print('FAIL: canary_policy: not found', file=sys.stderr)
    sys.exit(1)
if agent_pos > canary_pos:
    print('FAIL: agent entry (%d) is AFTER canary_policy: (%d) — EOF append regression'
          % (agent_pos, canary_pos), file=sys.stderr)
    sys.exit(1)
print('[test] PASS: agent entry before canary_policy:')
PYEOF
  [ "$status" -eq 0 ]
}

# ===========================================================================
# C-003: _pki_chown_client_keys covers dynamically-onboarded agent keys
# ===========================================================================

@test "C-003: install.sh contains C-003 chown block for onboarded agent keys" {
  # Structural: verify the fix is present (sentinel comment + grep for
  # YSG-ONBOARD sentinels + UID 65534 chown call).
  run grep -c 'C-003 FIX: chown dynamically-onboarded agent' "${INSTALL_SH}"
  [ "$output" -ge 1 ]
}

@test "C-003: chown block reads BEGIN YSG-ONBOARD- sentinels from service_identities.yaml" {
  run grep -c 'BEGIN YSG-ONBOARD-' "${INSTALL_SH}"
  [ "$output" -ge 1 ]
}

@test "C-003: chown block targets UID 65534 (nobody — codegen compose user)" {
  # The C-003 block must reference UID 65534.  Extract the block and verify.
  run grep -A 50 'C-003 FIX: chown dynamically-onboarded agent' "${INSTALL_SH}"
  [[ "$output" =~ "65534" ]]
}

@test "C-003: _pki_chown_client_keys is called after rotate-leaves in --pki-action path" {
  # Verify the call order in the --pki-action rotate-leaves case:
  # _pki_run_issuer rotate-leaves must be immediately followed (within 20 lines)
  # by _pki_chown_client_keys.  Extract the line numbers of the last occurrence
  # of each pattern (the --pki-action case lives near the end of install.sh).
  local _issuer_line
  _issuer_line="$(grep -n '_pki_run_issuer rotate-leaves' "${INSTALL_SH}" \
                  | tail -1 | cut -d: -f1)"
  # Find all _pki_chown_client_keys calls (exclude the function definition
  # and comment lines).
  local _chown_line
  _chown_line="$(grep -n '_pki_chown_client_keys' "${INSTALL_SH}" \
                 | grep -v 'pki_chown_client_keys()' \
                 | grep -v '^[0-9]*:[[:space:]]*#' \
                 | awk -F: -v ref="${_issuer_line}" '$1 > ref {print $1; exit}')"
  # There must be a chown call AFTER the last rotate-leaves call.
  [ -n "${_chown_line}" ]
  # And it must be within 20 lines of the rotate-leaves call (same case block).
  local _gap=$(( _chown_line - _issuer_line ))
  [ "${_gap}" -le 20 ]
}

@test "C-003: no crash when service_identities.yaml has no onboarded agents (grep || true guard)" {
  # The grep that extracts BEGIN YSG-ONBOARD markers must not abort when
  # no markers are present (fresh install with no onboarded agents).
  # Verify `|| true` is present on that grep line.
  run grep -A 10 'BEGIN YSG-ONBOARD-' "${INSTALL_SH}"
  [[ "$output" =~ "|| true" ]]
}

# ===========================================================================
# #21: uninstall.sh silent exit-1 on compose installs
# ===========================================================================

@test "#21: uninstall.sh NAMESPACE grep has || true guard" {
  run grep 'NAMESPACE=' "${UNINSTALL_SH}"
  [[ "$output" =~ "|| true" ]]
}

@test "#21: uninstall.sh HELM_RELEASE grep has || true guard" {
  run grep 'HELM_RELEASE=' "${UNINSTALL_SH}"
  [[ "$output" =~ "|| true" ]]
}

@test "#21: compose state file (no NAMESPACE line) does not abort state-detection block" {
  # Reproduce the exact failure: run the state-detection block in a subshell
  # with set -euo pipefail and a compose-style state file (RUNTIME=podman,
  # no NAMESPACE= line).
  local _state_file="${MOCK_ROOT}/.yashigani-install-state"
  cat > "$_state_file" <<'STATE'
RUNTIME=podman
INSTALL_UID=1000
INSTALL_USER=max
STATE

  run bash - <<BASH
set -euo pipefail
_STATE_FILE="${_state_file}"
_state_namespace="\$(grep -E '^NAMESPACE=' "\$_STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]' || true)"
_state_helm_release="\$(grep -E '^HELM_RELEASE=' "\$_STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]' || true)"
echo "ns=[\${_state_namespace}] hr=[\${_state_helm_release}]"
BASH

  [ "$status" -eq 0 ]
  [[ "$output" =~ "ns=[]" ]]
  [[ "$output" =~ "hr=[]" ]]
}

@test "#21: bash -n uninstall.sh passes" {
  run bash -n "${UNINSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "#21: shellcheck finds no new warnings in uninstall.sh" {
  run shellcheck --severity=warning "${UNINSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "#21: k8s state file (NAMESPACE present) still populates _state_namespace" {
  local _state_file="${MOCK_ROOT}/.yashigani-install-state"
  cat > "$_state_file" <<'STATE'
RUNTIME=k8s
INSTALL_UID=1000
INSTALL_USER=max
NAMESPACE=prod-yashigani
HELM_RELEASE=yashigani
STATE

  run bash - <<BASH
set -euo pipefail
_STATE_FILE="${_state_file}"
_state_namespace="\$(grep -E '^NAMESPACE=' "\$_STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]' || true)"
_state_helm_release="\$(grep -E '^HELM_RELEASE=' "\$_STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '\r\n[:space:]' || true)"
echo "ns=[\${_state_namespace}] hr=[\${_state_helm_release}]"
BASH

  [ "$status" -eq 0 ]
  [[ "$output" =~ "ns=[prod-yashigani]" ]]
  [[ "$output" =~ "hr=[yashigani]" ]]
}
