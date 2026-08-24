#!/usr/bin/env bats
# tests/install/test_run_wizard_hard_required_flags.bats
#
# Regression tests for the LIVE 4.1.2 docker e2e install failure (2026-08-13/17):
#   bash install.sh --deploy production --runtime docker --non-interactive \
#     --domain localhost --admin-email admin@agnosticsec.com
# died at step 9/13 with:
#   error while interpolating services.gateway.environment.YASHIGANI_UPSTREAM_URL:
#   required variable UPSTREAM_MCP_URL is missing a value: set UPSTREAM_MCP_URL
#
# Root cause: run_wizard()'s --non-interactive branch built a `missing=()`
# list including --upstream-url, then on finding entries logged
#   log_warn "Non-interactive mode: the following flags were not provided: ..."
#   log_warn "Defaults or empty values will be used; reconfigure via your .env file."
# and CONTINUED. There is no default for UPSTREAM_URL outside --deploy demo,
# and docker/docker-compose.yml declares it required
# (`${UPSTREAM_MCP_URL:?set UPSTREAM_MCP_URL}`) — the warning was false, and
# the run died three steps later inside `docker compose build` with an
# interpolation error naming neither the missing flag nor a fix. Same
# defect class as the air-gap SHA fail-open, the HIBP "all clean", and the
# uninstall "All volumes deleted" bugs fixed the same session (a check that
# DETECTS the problem, prints something reassuring, and continues).
#
# Prior art read before writing this fix (Documentation review before ANY
# change, CLAUDE.md / Change Management SS4.2):
#   - git log -S"UPSTREAM_MCP_URL" -- install.sh -> 75ead401 ("harden the
#     upgrade path"): UPSTREAM_MCP_URL reuse-from-.env on --upgrade was
#     ALREADY built, specifically because compose declares it required.
#     That reuse logic (install.sh run_wizard, immediately before the
#     required-flag check) is preserved byte-for-byte by this fix and MUST
#     keep firing before the new fail-closed check — tested below.
#   - git log -S"run_wizard" -- install.sh -> cd45cce4 (v4.1 username-fix):
#     unrelated (YASHIGANI_ADMIN_USERNAME vs ADMIN_EMAIL), confirms
#     --admin-email has never fed a compose-required variable.
#   - docs/risk-register.yml + AgnosticSecurity Risk Management/
#     yashigani-risks.md: no prior YSG-RISK-NNN entry for this exact
#     class on run_wizard's non-interactive branch — new finding.
#   - Per-flag verification (grep against docker/docker-compose.yml, not
#     assumed): YASHIGANI_TLS_DOMAIN (:193) and UPSTREAM_MCP_URL (:613) are
#     BOTH declared `${VAR:?...}` (no `:-` fallback) for the gateway
#     service; YASHIGANI_ADMIN_EMAIL is not referenced by
#     docker-compose.yml, any Helm template, or any *.py at all — genuinely
#     no downstream requirement, so --admin-email correctly stays a soft
#     warn-and-continue. DOMAIN and UPSTREAM_URL both have a real default
#     ONLY inside the --deploy demo branches (_apply_deploy_defaults'
#     demo case; the step-5 demo-mcp block) — production/enterprise get no
#     default for either, matching compose's requiredness.
#   - k8s path deliberately EXCLUDED from the new hard-fail: helm/yashigani/
#     values.yaml already carries its own (softer) defaults for both
#     (global.tlsDomain: "yashigani.example.com"; gateway.env.upstreamUrl:
#     ""), so changing k8s requiredness is a different, unverified claim
#     and out of scope for this fix — k8s keeps the original soft-warn
#     behaviour (tested below).
#
# Requirements: bats-core >= 1.10, bash 4+.
# Run:
#   bats tests/install/test_run_wizard_hard_required_flags.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"

# ── extraction helper — same brace-counting technique used throughout this
# test suite (see test_ysg_risk_202_podman_cdi_fail_closed.bats). ──────────
_extract_fn() {
  local fn="$1"
  awk -v fn="$fn" '
    $0 ~ "^"fn"\\(\\)[ \t]*\\{" { f=1 }
    f {
      print
      d += gsub(/{/, "{")
      d -= gsub(/}/, "}")
      if (f && d <= 0) { exit }
    }
  ' "${INSTALL_SH}"
}

setup() {
  local fn_body
  fn_body="$(_extract_fn "run_wizard")"
  [[ -n "$fn_body" ]] || { echo "ERROR: run_wizard not found in install.sh" >&2; return 1; }
  eval "$fn_body"

  # Minimal stand-ins for install.sh's shared plumbing. None of these are
  # under test here — only the non-interactive required-flag logic inside
  # run_wizard is.
  set_step() { :; }
  log_step() { :; }
  log_info() { printf '[INFO] %s\n'  "$*" >&2; }
  log_warn() { printf '[WARN] %s\n'  "$*" >&2; }
  log_error() { printf '[ERROR] %s\n' "$*" >&2; }
  log_success() { printf '[OK] %s\n' "$*" >&2; }

  SCRATCH="$(mktemp -d "${BATS_TEST_TMPDIR}/run-wizard-scratch.XXXXXX")"
  WORK_DIR="${SCRATCH}"
  mkdir -p "${WORK_DIR}/docker"
  TOTAL_STEPS=13
  NON_INTERACTIVE=true
  MODE="compose"
  DEPLOY_MODE="production"
  TLS_MODE="acme"
  DOMAIN=""
  ADMIN_EMAIL=""
  UPSTREAM_URL=""
}

teardown() {
  rm -rf "${SCRATCH:-}" 2>/dev/null || true
}

# ── Lint gate ─────────────────────────────────────────────────────────────

@test "LINT: bash -n parses install.sh cleanly" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

# ── THE ORIGINAL BUG: missing --upstream-url on a fresh non-interactive
#    compose install must abort at step 6, naming the flag ────────────────

@test "THE ORIGINAL BUG: compose mode, --domain given, --upstream-url missing -> exit 1 at step 6, names --upstream-url" {
  DOMAIN="localhost"
  ADMIN_EMAIL="admin@agnosticsec.com"
  UPSTREAM_URL=""

  run run_wizard
  [ "$status" -eq 1 ]
  [[ "$output" == *"--upstream-url"* ]]
  [[ "$output" == *"missing required configuration"* ]]
  # must never reach the point of exporting/continuing
  [[ "$output" != *"Configuration complete"* ]]
}

@test "compose mode, BOTH --domain and --upstream-url missing -> exit 1, names both flags in one message" {
  DOMAIN=""
  UPSTREAM_URL=""

  run run_wizard
  [ "$status" -eq 1 ]
  [[ "$output" == *"--domain"* ]]
  [[ "$output" == *"--upstream-url"* ]]
}

@test "vm mode is also compose-backed -> same hard-fail as compose mode" {
  MODE="vm"
  DOMAIN="localhost"
  UPSTREAM_URL=""

  run run_wizard
  [ "$status" -eq 1 ]
  [[ "$output" == *"--upstream-url"* ]]
}

# ── Soft flag: --admin-email has no compose/helm/app requirement, must
#    stay warn-and-continue, never abort ───────────────────────────────────

@test "--admin-email missing alone -> warns but returns 0 (no compose requirement)" {
  DOMAIN="localhost"
  UPSTREAM_URL="https://mcp.example.com"
  ADMIN_EMAIL=""

  run run_wizard
  [ "$status" -eq 0 ]
  [[ "$output" == *"--admin-email"* ]]
  [[ "$output" != *"missing required configuration"* ]]
}

# ── Upgrade-reuse path MUST still work, and MUST run before the fail-closed
#    check (install.sh:75ead401) — this is the exact regression the brief
#    calls out as "do not break the documented upgrade path" ─────────────

@test "upgrade reuse: empty --upstream-url + --domain reuses BOTH from docker/.env and succeeds (no re-pass needed)" {
  cat > "${WORK_DIR}/docker/.env" << 'EOF'
YASHIGANI_TLS_DOMAIN=gateway.example.com
UPSTREAM_MCP_URL=https://mcp.example.com
EOF
  DOMAIN=""
  UPSTREAM_URL=""
  ADMIN_EMAIL="admin@agnosticsec.com"

  run run_wizard
  [ "$status" -eq 0 ]
  [[ "$output" == *"Reusing existing YASHIGANI_TLS_DOMAIN from .env"* ]]
  [[ "$output" == *"Reusing existing UPSTREAM_MCP_URL from .env"* ]]
  [[ "$output" != *"missing required configuration"* ]]
}

@test "upgrade reuse: only UPSTREAM_MCP_URL persisted, --domain passed explicitly on argv -> still succeeds" {
  cat > "${WORK_DIR}/docker/.env" << 'EOF'
UPSTREAM_MCP_URL=https://mcp.example.com
EOF
  DOMAIN="gateway.example.com"
  UPSTREAM_URL=""

  run run_wizard
  [ "$status" -eq 0 ]
  [[ "$output" == *"Reusing existing UPSTREAM_MCP_URL from .env"* ]]
}

@test "explicit --upstream-url on argv always wins over a stale persisted .env value" {
  cat > "${WORK_DIR}/docker/.env" << 'EOF'
UPSTREAM_MCP_URL=https://stale.example.com
EOF
  DOMAIN="localhost"
  UPSTREAM_URL="https://correct.example.com"

  run run_wizard
  [ "$status" -eq 0 ]
  [[ "$output" != *"Reusing existing UPSTREAM_MCP_URL"* ]]
}

# ── k8s mode: deliberately NOT hard-failed by this fix (Helm carries its
#    own softer defaults) — must retain the original warn-and-continue ────

@test "k8s mode: missing --domain and --upstream-url -> still warns and returns 0 (unchanged, out of scope)" {
  MODE="k8s"
  DOMAIN=""
  UPSTREAM_URL=""

  run run_wizard
  [ "$status" -eq 0 ]
  [[ "$output" == *"--domain"* ]]
  [[ "$output" == *"--upstream-url"* ]]
  [[ "$output" != *"missing required configuration"* ]]
}

# ── Positive path: everything provided -> clean pass, correct exports ─────

@test "all flags provided -> succeeds, exports the right values, no warnings at all" {
  DOMAIN="gateway.example.com"
  ADMIN_EMAIL="admin@agnosticsec.com"
  UPSTREAM_URL="https://mcp.example.com"

  run run_wizard
  [ "$status" -eq 0 ]
  [[ "$output" != *"were not provided"* ]]
  [[ "$output" != *"missing required configuration"* ]]
}
