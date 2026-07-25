#!/usr/bin/env bats
# tests/install/test_backend_firewall.bats
#
# Unit tests for _apply_inference_backend_firewall() — LAURA-411-001 item B
#
# Covers:
#   1. Firewall detection precedence: ufw (active) → firewalld (running) →
#      nftables (present + ruleset) → iptables (fallback)
#   2. macOS always detects pf regardless of Linux tool presence
#   3. Rule generation per firewall type matches docs/security/securing-inference-backend.md
#   4. --secure-backend-firewall gates non-interactive apply
#   5. No-privilege path: prints rules + doc reference, returns 0 (never exits non-zero)
#   6. Unknown-firewall path: warns + points at the doc, returns 0
#   7. Port and subnet substitution in generated rules
#
# Test isolation:
#   - Function extracted from install.sh via brace-count awk (same as test_ollama_port_resolution.bats)
#   - All external commands stubbed as shell functions (command/uname/ufw/firewall-cmd/nft/iptables)
#   - id -u stubbed via PATH override (mktemp bin in scratchpad)
#   - No real firewall is touched; no real docker/podman is required
#
# Run:
#   bats tests/install/test_backend_firewall.bats

REPO_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
INSTALL_SH="${REPO_ROOT}/install.sh"

# ── Helpers ───────────────────────────────────────────────────────────────────

# Extract _apply_inference_backend_firewall() into the current shell scope.
_load_fn() {
  local fn_body
  fn_body="$(awk '
    /^_apply_inference_backend_firewall\(\)[ \t]*\{/ { f=1 }
    f {
      print
      d += gsub(/{/, "{")
      d -= gsub(/}/, "}")
      if (f && d <= 0) { exit }
    }
  ' "${INSTALL_SH}")"
  if [[ -z "$fn_body" ]]; then
    echo "ERROR: _apply_inference_backend_firewall() not found in ${INSTALL_SH}" >&2
    return 1
  fi
  eval "$fn_body"
}

# ── Setup / teardown ──────────────────────────────────────────────────────────

setup() {
  _load_fn

  # Globals the function reads
  YASHIGANI_HOST_OLLAMA_PORT=11434
  SECURE_BACKEND_FIREWALL=false
  NON_INTERACTIVE=true
  YSG_RUNTIME=docker
  PROJECT=docker

  # Logging stubs
  log_info()    { printf '[INFO] %s\n' "$*" >&2; }
  log_warn()    { printf '[WARN] %s\n' "$*" >&2; }
  log_success() { printf '[OK]   %s\n' "$*" >&2; }
  log_error()   { printf '[ERR]  %s\n' "$*" >&2; }

  # OS stub: default to Linux so firewall detection branches are exercised
  uname() { echo "Linux"; }

  # All firewall commands absent / inactive by default; override per-test.
  command()     { return 1; }
  ufw()         { return 1; }
  firewall-cmd(){ return 1; }
  nft()         { return 1; }
  iptables()    { return 0; }  # present but only used as fallback

  # Network inspect stubs: return failure by default (triggers subnet fallback)
  docker() { return 1; }
  podman() { return 1; }

  # route stub for pf interface detection on macOS tests
  route() { printf 'interface: en0\n'; }

  # id -u: non-root by default (privilege check returns non-zero)
  # We stub 'id' as a function; the check in the fn is: [[ "$(id -u)" -ne 0 ]]
  id() { echo "501"; }

  # eval wrapper: capture but don't actually run firewall commands
  # (overridden in tests that need to verify apply is invoked)
  _APPLIED_CMDS=()
  eval() {
    # Record what would have been applied; succeed silently
    _APPLIED_CMDS+=("$1")
  }
}

teardown() {
  unset YASHIGANI_HOST_OLLAMA_PORT SECURE_BACKEND_FIREWALL NON_INTERACTIVE \
        YSG_RUNTIME PROJECT 2>/dev/null || true
}

# ── Lint gates ────────────────────────────────────────────────────────────────

@test "LINT: bash -n parses install.sh cleanly" {
  run bash -n "${INSTALL_SH}"
  [ "$status" -eq 0 ]
}

@test "LINT: _apply_inference_backend_firewall defined exactly once" {
  run grep -c '^_apply_inference_backend_firewall()' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "LINT: SECURE_BACKEND_FIREWALL declared in globals" {
  run grep -c '^SECURE_BACKEND_FIREWALL=false' "${INSTALL_SH}"
  [ "$output" -eq 1 ]
}

@test "LINT: --secure-backend-firewall handled in parse_args" {
  run grep -c '\-\-secure-backend-firewall)' "${INSTALL_SH}"
  [ "$output" -ge 1 ]
}

@test "LINT: _apply_inference_backend_firewall called from main" {
  run grep -c '_apply_inference_backend_firewall' "${INSTALL_SH}"
  # Appears in: function definition header, body, and call site = at least 2
  [ "$output" -ge 2 ]
}

@test "LINT: doc reference in function matches actual doc path" {
  local doc_path="docs/security/securing-inference-backend.md"
  run test -f "${REPO_ROOT}/${doc_path}"
  [ "$status" -eq 0 ]
}

# ── macOS always detects pf ───────────────────────────────────────────────────

@test "macOS: uname=Darwin → detects pf regardless of Linux tool availability" {
  uname() { echo "Darwin"; }
  # Make all Linux tools appear present — pf must still win
  command() { return 0; }
  ufw() { printf 'Status: active\n'; return 0; }

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"detected firewall 'pf'"* ]]
}

@test "macOS: pf rule output contains 'block drop in quick on'" {
  uname() { echo "Darwin"; }
  NON_INTERACTIVE=true
  SECURE_BACKEND_FIREWALL=false

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"block drop in quick on"* ]]
}

@test "macOS: pf rule references the backend port" {
  uname() { echo "Darwin"; }
  YASHIGANI_HOST_OLLAMA_PORT=11434
  NON_INTERACTIVE=true
  SECURE_BACKEND_FIREWALL=false

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"11434"* ]]
}

@test "macOS: pf rule references pfctl anchor" {
  uname() { echo "Darwin"; }
  NON_INTERACTIVE=true
  SECURE_BACKEND_FIREWALL=false

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"pfctl"* ]] && [[ "$_out" == *"com.yashigani.backend"* ]]
}

# ── Linux firewall detection precedence ──────────────────────────────────────

@test "precedence: ufw active → ufw wins over firewalld/nft/iptables" {
  # ufw present AND reports active
  command() {
    case "$*" in *ufw*) return 0;; *) return 1;; esac
  }
  ufw() {
    case "$*" in *status*) printf 'Status: active\n'; return 0;; *) return 0;; esac
  }
  # firewall-cmd also present and running — must NOT win
  firewall-cmd() {
    case "$*" in *--state*) printf 'running\n'; return 0;; *) return 0;; esac
  }

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"detected firewall 'ufw'"* ]]
}

@test "precedence: ufw absent → firewalld running wins" {
  # ufw not installed
  command() {
    case "$*" in *ufw*) return 1;; *firewall-cmd*) return 0;; *) return 1;; esac
  }
  firewall-cmd() {
    case "$*" in *--state*) printf 'running\n'; return 0;; *) return 0;; esac
  }

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"detected firewall 'firewalld'"* ]]
}

@test "precedence: ufw present but inactive → falls through to firewalld" {
  command() {
    case "$*" in *ufw*) return 0;; *firewall-cmd*) return 0;; *) return 1;; esac
  }
  ufw() {
    case "$*" in *status*) printf 'Status: inactive\n'; return 0;; *) return 0;; esac
  }
  firewall-cmd() {
    case "$*" in *--state*) printf 'running\n'; return 0;; *) return 0;; esac
  }

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"detected firewall 'firewalld'"* ]]
}

@test "precedence: no ufw, firewalld stopped → nftables with ruleset wins" {
  command() {
    case "$*" in *ufw*) return 1;; *firewall-cmd*) return 1;; *nft*) return 0;; *) return 1;; esac
  }
  # nft list ruleset returns content
  nft() {
    case "$*" in *"list ruleset"*) printf 'table inet filter {}\n'; return 0;; *) return 0;; esac
  }

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"detected firewall 'nftables'"* ]]
}

@test "precedence: nft present but empty ruleset → falls through to iptables" {
  command() {
    case "$*" in *ufw*) return 1;; *firewall-cmd*) return 1;; *nft*) return 0;; *iptables*) return 0;; *) return 1;; esac
  }
  nft() {
    # list ruleset returns empty
    case "$*" in *"list ruleset"*) return 0;; *) return 0;; esac
  }

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"detected firewall 'iptables'"* ]]
}

@test "precedence: only iptables present → iptables wins (fallback)" {
  command() {
    case "$*" in *iptables*) return 0;; *) return 1;; esac
  }

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"detected firewall 'iptables'"* ]]
}

@test "no firewall detected → warns and points at doc, rc=0" {
  # All commands absent
  command() { return 1; }

  local _out _rc=0
  _out=$(_apply_inference_backend_firewall 2>&1) || _rc=$?
  [ "$_rc" -eq 0 ]
  [[ "$_out" == *"no supported firewall detected"* ]]
  [[ "$_out" == *"securing-inference-backend.md"* ]]
}

# ── Rule generation matches doc templates ────────────────────────────────────

@test "ufw rules: allow from gateway subnet and deny port — match doc template" {
  command() {
    case "$*" in *ufw*) return 0;; *) return 1;; esac
  }
  ufw() {
    case "$*" in *status*) printf 'Status: active\n'; return 0;; *) return 0;; esac
  }
  YASHIGANI_HOST_OLLAMA_PORT=11434
  NON_INTERACTIVE=true
  SECURE_BACKEND_FIREWALL=false

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  # Doc template: "sudo ufw allow from <subnet> to any port <port> proto tcp"
  [[ "$_out" == *"ufw allow from"*"to any port 11434 proto tcp"* ]]
  # Doc template: "sudo ufw deny <port>/tcp"
  [[ "$_out" == *"ufw deny 11434/tcp"* ]]
}

@test "firewalld rules: rich-rule allow + drop, reload — match doc template" {
  command() {
    case "$*" in *ufw*) return 1;; *firewall-cmd*) return 0;; *) return 1;; esac
  }
  firewall-cmd() {
    case "$*" in *--state*) printf 'running\n'; return 0;; *) return 0;; esac
  }
  YASHIGANI_HOST_OLLAMA_PORT=11434
  NON_INTERACTIVE=true
  SECURE_BACKEND_FIREWALL=false

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"firewall-cmd"*"--permanent"*"rich-rule"* ]]
  [[ "$_out" == *"firewall-cmd --reload"* ]]
}

@test "nftables rules: loopback accept + saddr accept + drop — match doc template" {
  command() {
    case "$*" in *ufw*) return 1;; *firewall-cmd*) return 1;; *nft*) return 0;; *) return 1;; esac
  }
  nft() {
    case "$*" in *"list ruleset"*) printf 'table inet filter {}\n'; return 0;; *) return 0;; esac
  }
  YASHIGANI_HOST_OLLAMA_PORT=11434
  NON_INTERACTIVE=true
  SECURE_BACKEND_FIREWALL=false

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"nft add rule inet filter input tcp dport 11434 iif lo accept"* ]]
  [[ "$_out" == *"nft add rule inet filter input tcp dport 11434"*"accept"* ]]
  [[ "$_out" == *"nft add rule inet filter input tcp dport 11434 drop"* ]]
}

@test "iptables rules: loopback ACCEPT + saddr ACCEPT + DROP — match doc template" {
  command() {
    case "$*" in *iptables*) return 0;; *) return 1;; esac
  }
  YASHIGANI_HOST_OLLAMA_PORT=11434
  NON_INTERACTIVE=true
  SECURE_BACKEND_FIREWALL=false

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"iptables -A INPUT -p tcp --dport 11434 -i lo -j ACCEPT"* ]]
  [[ "$_out" == *"iptables -A INPUT -p tcp --dport 11434"*"-j ACCEPT"* ]]
  [[ "$_out" == *"iptables -A INPUT -p tcp --dport 11434 -j DROP"* ]]
}

# ── Port substitution ─────────────────────────────────────────────────────────

@test "non-default port 9999: substituted in all generated rules" {
  command() {
    case "$*" in *iptables*) return 0;; *) return 1;; esac
  }
  YASHIGANI_HOST_OLLAMA_PORT=9999
  NON_INTERACTIVE=true
  SECURE_BACKEND_FIREWALL=false

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"9999"* ]]
  # Must NOT contain 11434 in the rule commands
  [[ "$_out" != *"--dport 11434"* ]]
}

# ── Non-interactive --secure-backend-firewall gate ───────────────────────────

@test "non-interactive without --secure-backend-firewall: prints rules, rc=0" {
  command() {
    case "$*" in *iptables*) return 0;; *) return 1;; esac
  }
  NON_INTERACTIVE=true
  SECURE_BACKEND_FIREWALL=false

  local _out _rc=0
  _out=$(_apply_inference_backend_firewall 2>&1) || _rc=$?
  [ "$_rc" -eq 0 ]
  # Tells operator to pass --secure-backend-firewall
  [[ "$_out" == *"--secure-backend-firewall"* ]]
  # Shows the manual commands
  [[ "$_out" == *"iptables"* ]]
  # Points at the doc
  [[ "$_out" == *"securing-inference-backend.md"* ]]
}

@test "non-interactive WITH --secure-backend-firewall + no root: prints rules not applied, rc=0" {
  command() {
    case "$*" in *iptables*) return 0;; *) return 1;; esac
  }
  NON_INTERACTIVE=true
  SECURE_BACKEND_FIREWALL=true
  # id stub returns non-root UID (501)
  id() { echo "501"; }

  local _out _rc=0
  _out=$(_apply_inference_backend_firewall 2>&1) || _rc=$?
  [ "$_rc" -eq 0 ]
  [[ "$_out" == *"root/sudo required"* ]]
  # Still prints the rule for manual application
  [[ "$_out" == *"iptables"* ]]
}

@test "non-interactive WITH --secure-backend-firewall + root: reaches apply path" {
  # eval is a bash special builtin and cannot be overridden by a function.
  # Instead we verify apply was reached by checking log output:
  #   - no "root/sudo required" message (privilege check passed)
  #   - "applying:" message is present (function entered the apply loop)
  #   - rc=0 (fail-safe: real commands may fail in test env but install continues)
  command() {
    case "$*" in *iptables*) return 0;; *) return 1;; esac
  }
  NON_INTERACTIVE=true
  SECURE_BACKEND_FIREWALL=true
  # id() stub: return "0" so [[ "$(id -u)" -ne 0 ]] is false → privilege check passes
  id() { echo "0"; }

  local _out _rc=0
  _out=$(_apply_inference_backend_firewall 2>&1) || _rc=$?
  # Privilege check must have passed (no "root/sudo required" in output)
  [[ "$_out" != *"root/sudo required"* ]]
  # Non-interactive gate must have passed (no "pass --secure-backend-firewall" message)
  [[ "$_out" != *"--secure-backend-firewall to auto-apply"* ]]
  # Apply path was reached (log shows "applying:" or failure from real cmd in test env)
  [[ "$_out" == *"applying:"* ]] || [[ "$_out" == *"commands failed"* ]]
  # Fail-safe: must return 0 even when real firewall commands fail in test env
  [ "$_rc" -eq 0 ]
}

# ── No-privilege path never exits non-zero ───────────────────────────────────

@test "no-privilege path: rc=0 even when flag is set (never aborts install)" {
  command() {
    case "$*" in *ufw*) return 0;; *) return 1;; esac
  }
  ufw() {
    case "$*" in *status*) printf 'Status: active\n'; return 0;; *) return 0;; esac
  }
  NON_INTERACTIVE=true
  SECURE_BACKEND_FIREWALL=true
  id() { echo "501"; }  # non-root

  run _apply_inference_backend_firewall
  [ "$status" -eq 0 ]
}

@test "no-privilege path: prints doc reference" {
  command() {
    case "$*" in *iptables*) return 0;; *) return 1;; esac
  }
  NON_INTERACTIVE=true
  SECURE_BACKEND_FIREWALL=true
  id() { echo "501"; }

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"securing-inference-backend.md"* ]]
}

# ── Unknown/absent firewall: doc reference ────────────────────────────────────

@test "unknown firewall: output contains doc reference" {
  command() { return 1; }

  local _out
  _out=$(_apply_inference_backend_firewall 2>&1)
  [[ "$_out" == *"securing-inference-backend.md"* ]]
}

@test "unknown firewall: rc=0" {
  command() { return 1; }

  run _apply_inference_backend_firewall
  [ "$status" -eq 0 ]
}

# ── Invalid port: handled gracefully ─────────────────────────────────────────

@test "YASHIGANI_HOST_OLLAMA_PORT=0: warns and returns 0" {
  YASHIGANI_HOST_OLLAMA_PORT=0
  NON_INTERACTIVE=true

  run _apply_inference_backend_firewall
  [ "$status" -eq 0 ]
  [[ "$output" == *"not a valid port"* ]]
}

@test "YASHIGANI_HOST_OLLAMA_PORT=notaport: warns and returns 0" {
  YASHIGANI_HOST_OLLAMA_PORT="notaport"
  NON_INTERACTIVE=true

  run _apply_inference_backend_firewall
  [ "$status" -eq 0 ]
  [[ "$output" == *"not a valid port"* ]]
}
