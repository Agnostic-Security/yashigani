#!/usr/bin/env bats
# tests/install/test_gateway_socket_override.bats
#
# FINDING-V412-RESTART-007 regression test — gateway's /var/run/docker.sock
# bind-mount must be REMOVED on macOS Podman (Pool Manager stub mode,
# unconditionally — not dependent on whether a docker.sock happens to exist
# on the host), and UNCHANGED on Docker + Linux Podman.
#
# Root cause: Podman on macOS cannot statfs Docker Desktop's docker.sock (a
# non-standard grpc-fuse/VPNKit forward) — `podman create` hard-fails with
# "Error: statfs ...docker.sock: operation not supported" whenever a real
# docker.sock exists on the host (e.g. Docker Desktop running for a parallel
# Docker-leg test). Fix: docker-compose.podman-virtiofs-override.yml (macOS
# Podman ONLY, per install.sh's `uname -s == Darwin` gate) fully replaces
# gateway.volumes via the podman-compose-ysg fork's `!override` merge-control
# tag, omitting the docker.sock line. docker-compose.podman-override.yml (the
# ALL-Podman file, Linux included) and docker-compose.yml (the Docker path)
# are both left untouched.
#
# This test renders the ACTUAL merged compose config via the vendored fork's
# own `config` subcommand for all three runtime combinations — not a
# reimplemented parser — so it fails the same way a real install would if the
# override regresses. No live podman/docker daemon required (`config` is a
# pure static render).
#
# Run:
#   bats tests/install/test_gateway_socket_override.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
DOCKER_DIR="${REPO_ROOT}/docker"
FORK="${REPO_ROOT}/vendor/podman-compose-ysg/podman_compose.py"

setup() {
  command -v python3 >/dev/null 2>&1 || skip "python3 not available"
  python3 -c "import yaml, dotenv" >/dev/null 2>&1 || skip "PyYAML/python-dotenv not available"
  [[ -f "$FORK" ]] || skip "vendored fork not present in this tree"

  # Iris review condition C1 (2026-07-19): on a bare checkout (no
  # docker/.env — a real install has never run), the fork's `config` render
  # traceback-crashes while substituting `${VAR:?message}` compose-spec
  # required-var syntax for the handful of vars install.sh normally writes
  # to docker/.env (CADDY_INTERNAL_HMAC, YASHIGANI_DB_AES_KEY, etc). That is
  # a hard failure, not a skip — this test must PASS on a fresh checkout,
  # not depend on a prior install having run in this worktree.
  #
  # Fix: a throwaway fixture .env (dummy values, content is irrelevant — this
  # test only inspects the RENDERED gateway.volumes list, never anything
  # these vars actually gate) passed via the fork's own `--env-file <path>`
  # flag. Per podman_compose.py's env-file loading (~line 2335-2343):
  # passing an explicit path (anything other than the literal string ".env")
  # uses ONLY that file's values and does NOT also auto-load docker/.env —
  # so this is fully hermetic and gives IDENTICAL results whether or not a
  # real docker/.env happens to exist in this worktree (bare checkout or a
  # worktree with a completed install both render the same way). Never
  # written into docker/.env itself — never touches the real file, never /tmp.
  FIXTURE_ENV="${BATS_TEST_TMPDIR}/fixture.env"
  cat > "$FIXTURE_ENV" <<'EOF'
YASHIGANI_INTERNAL_BEARER=test-fixture-value
YASHIGANI_TLS_DOMAIN=localhost
PROMETHEUS_BASICAUTH_HASH=test-fixture-value
CADDY_INTERNAL_HMAC=test-fixture-value
UPSTREAM_MCP_URL=http://demo-mcp:8000
YASHIGANI_DB_AES_KEY=test-fixture-value
EOF
}

# Render the merged gateway.volumes list for a given set of compose files
# (relative to docker/), one per line, via the fork's own `config` subcommand.
_render_gateway_volumes() {
  local -a _f_args=()
  local _f
  for _f in "$@"; do
    _f_args+=("-f" "$_f")
  done
  ( cd "$DOCKER_DIR" && python3 "$FORK" --env-file "$FIXTURE_ENV" "${_f_args[@]}" config 2>/dev/null ) \
    | python3 -c "
import sys, yaml
d = yaml.safe_load(sys.stdin)
for v in d['services']['gateway']['volumes']:
    print(v)
"
}

@test "macOS Podman path: gateway.volumes has NO docker.sock mount" {
  run _render_gateway_volumes \
    docker-compose.yml \
    docker-compose.podman-override.yml \
    docker-compose.podman-virtiofs-override.yml
  [ "$status" -eq 0 ]
  [[ "$output" != *"docker.sock"* ]]
}

@test "Linux Podman path (no virtiofs override): gateway.volumes STILL HAS the docker.sock mount (not regressed)" {
  run _render_gateway_volumes \
    docker-compose.yml \
    docker-compose.podman-override.yml
  [ "$status" -eq 0 ]
  [[ "$output" == *"/var/run/docker.sock:/var/run/docker.sock:ro"* ]]
}

@test "Docker path (base file only): gateway.volumes STILL HAS the docker.sock mount (not regressed)" {
  run _render_gateway_volumes docker-compose.yml
  [ "$status" -eq 0 ]
  [[ "$output" == *"/var/run/docker.sock:/var/run/docker.sock:ro"* ]]
}

@test "docker-compose.podman-override.yml (ALL-Podman file) does not itself define a gateway.volumes override" {
  # Confirms the fix is scoped to the macOS-only virtiofs override file, not
  # the Linux-inclusive one — a change here would silently affect Linux too.
  run python3 -c "
import yaml, sys
sys.path.insert(0, '${REPO_ROOT}/vendor/podman-compose-ysg')
import podman_compose  # registers !override/!reset constructors
with open('${DOCKER_DIR}/docker-compose.podman-override.yml') as f:
    d = yaml.safe_load(f)
gw = d.get('services', {}).get('gateway', {})
sys.exit(1 if 'volumes' in gw else 0)
"
  [ "$status" -eq 0 ]
}

@test "DRIFT GUARD: virtiofs-override's gateway.volumes !override list matches base list (by mount target), minus docker.sock, minus :U suffix" {
  # If docker-compose.yml's base gateway.volumes ever changes, this test fails
  # loudly instead of silently dropping a future mount from the macOS Podman
  # path (the !override tag is a full-list REPLACE, not a merge).
  run python3 -c "
import yaml, sys
sys.path.insert(0, '${REPO_ROOT}/vendor/podman-compose-ysg')
import podman_compose  # registers !override/!reset constructors

def targets(entries):
    out = set()
    for e in entries:
        parts = e.split(':')
        if len(parts) >= 2:
            out.add(parts[1])
    return out

with open('${DOCKER_DIR}/docker-compose.yml') as f:
    base = yaml.safe_load(f)
base_vols = base['services']['gateway']['volumes']
base_targets = targets(base_vols)
base_targets_minus_sock = base_targets - {'/var/run/docker.sock'}

with open('${DOCKER_DIR}/docker-compose.podman-virtiofs-override.yml') as f:
    ov = yaml.safe_load(f)
ov_vols = ov['services']['gateway']['volumes']
# unwrap the OverrideTag to get the actual list
if isinstance(ov_vols, podman_compose.OverrideTag):
    ov_vols = ov_vols.value
ov_targets = targets(ov_vols)

missing = base_targets_minus_sock - ov_targets
extra = ov_targets - base_targets_minus_sock

if missing:
    print('MISSING from override (present in base, dropped):', sorted(missing))
if extra:
    print('EXTRA in override (not in base — check for typos):', sorted(extra))
if '/var/run/docker.sock' in ov_targets:
    print('docker.sock STILL PRESENT in override — fix did not remove it')
    sys.exit(1)

sys.exit(1 if (missing or extra) else 0)
"
  [ "$status" -eq 0 ]
  [ -z "$output" ]
}

@test "LINT: base docker-compose.yml still carries the docker.sock mount for gateway (Docker/Linux source of truth unchanged)" {
  # docker-compose.yml also mounts docker.sock into 'promtail' (container-log
  # scraping — a separate, pre-existing, unrelated mount that is out of scope
  # for this fix and is itself profile-gated off by default on Podman via
  # docker-compose.podman-override.yml's promtail-disabled profile). Scope the
  # assertion to gateway's own service block, not a whole-file grep.
  run python3 -c "
import yaml, sys
with open('${DOCKER_DIR}/docker-compose.yml') as f:
    d = yaml.safe_load(f)
vols = d['services']['gateway']['volumes']
sys.exit(0 if '/var/run/docker.sock:/var/run/docker.sock:ro' in vols else 1)
"
  [ "$status" -eq 0 ]
}

@test "LINT: virtiofs override applied macOS-only in install.sh (uname -s == Darwin gate still present)" {
  run grep -c 'uname -s.*Darwin' "${REPO_ROOT}/install.sh"
  [ "$output" -ge 1 ]
}
