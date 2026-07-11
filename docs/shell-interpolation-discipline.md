# Shell Interpolation Discipline — Yashigani

Reference for the two VEB (Variable-Expansion-Boundary) failure modes found in
v2.24.0 and their canonical fixes. Read this before adding any `command:`,
`args:`, or `entrypoint:` block to a compose file or modifying install.sh's
`_do_chown` / `_do_chgrp` / `_do_chmod` functions.

---

## 1. The two failure modes

### VEB-Compose — `${VAR}` in compose block-scalar `command:`

**What happens:** Docker Compose preprocesses the entire YAML at parse time,
before any container starts. Any `${VAR}` or `$VAR` in a `command:` /
`args:` / `entrypoint:` *block-scalar* block (the `|` or `>` form) is
substituted against `.env` and the host environment. If `VAR` is absent from
compose's scope the slot silently becomes an empty string. The shell running
inside the container never sees the `$VAR` reference — it sees the empty value
or the compose-time value, not the runtime secret.

**Evidence:** `docker inspect docker-pgbouncer-1` after a broken install shows:

```
DATABASE_URL="postgresql://pgbouncer_authenticator:@postgres:5432/yashigani"
                                                    ^
                                             password slot empty
```

That `${PASS}` was eaten by compose at parse time. `PASS` was not in `.env`
(it is set inside the script by reading a secret file at runtime), so compose
substituted it to empty.

**Active instances caught:** `docker-compose.yml:1668` (letta-pgbouncer) and
10 further variable references in the `ollama-init` block (lines 855-870).

---

### VEB-Strip — `${var#"$prefix/"}` when `$var == $prefix`

**What happens:** Bash parameter expansion `${VAR#"$PREFIX/"}` strips
`$PREFIX/` from the left of `$VAR`. When `$VAR == $PREFIX` (i.e. the file to
chown IS the bind-mount root, with no trailing `/`), the pattern does not match
and the expansion returns `$VAR` unchanged. Downstream code then builds a
container path like `/s/${_rel_file}` where `_rel_file` is the full absolute
host path — the path does not exist inside the alpine container, chown fails.

**Active instance:** `install.sh:5539` (`_do_chown` docker_run branch),
triggered at caller `install.sh:1396` (bind-mount-dir chown where `_file ==
_mount_base`).

---

## 2. The correct patterns

### Compose shell-context — `$$VAR` or `$$(...)` in block scalars

The escape: compose collapses `$$` → `$` at parse time, deferring expansion
to the shell at runtime.

**Canonical correct pattern** (`docker-compose.yml:720`, redis service):

```yaml
command: >
  sh -c 'redis-server
  ...
  --requirepass "$$(cat /run/secrets/redis_password)"'
```

`$$(cat ...)` → compose sees `$$` → collapses to `$` → passes `$(cat
/run/secrets/redis_password)` to the shell → shell evaluates at runtime →
secret content interpolated. Correct.

**How to fix a broken instance:**

```diff
# Braced form:
- export DATABASE_URL="postgresql://user:${PASS}@host:5432/db"
+ export DATABASE_URL="postgresql://user:$$PASS@host:5432/db"

# Unbraced form:
- if [ -n "$AVAIL_KB" ] && [ "$AVAIL_KB" -lt "$REQUIRED_KB" ]; then
+ if [ -n "$$AVAIL_KB" ] && [ "$$AVAIL_KB" -lt "$$REQUIRED_KB" ]; then
```

---

### Compose substitution-from-env — `${VAR:-default}` in `environment:` / top-level

This is intentional and **correct**. Compose reads `${VAR:-default}` in
`environment:` blocks, `image:`, `volumes:`, and other top-level fields from
`.env` and the host environment. This is compose doing its designed job.

```yaml
environment:
  YASHIGANI_DB_DSN: "postgresql://app:${POSTGRES_PASSWORD_URLENC}@..."
  MEM_LIMIT: "${YASHIGANI_PROMETHEUS_MEM_LIMIT:-1024m}"
```

Do NOT change these to `$$`. They are meant to be resolved at parse time.

---

### Helm shell-context (K8s `args: [...]`) — `${VAR}` is correct

K8s does not preprocess `command:` or `args:` values. When using the exec
form:

```yaml
command: ["/bin/sh", "-c"]
args:
  - |
    PASS=$(cat /run/secrets/pass)
    export DATABASE_URL="postgresql://user:${PASS}@host:5432/db"
```

K8s passes each element of `args:` verbatim to the container's entrypoint.
`/bin/sh -c` receives the script as a string and the shell expands `${PASS}`
at runtime. `${VAR}` here is **correct**. Helm uses `{{ }}` for template
substitution and leaves `${ }` untouched.

**Do NOT add `$$` to helm templates.** The lint script does not scan them for
exactly this reason.

See `sanitization-map-20260523.md Class C` for the six confirmed-safe helm
instances.

---

### Bash strip-with-equality-edge guard in `_do_chown` / `_do_chgrp` / `_do_chmod`

```bash
local _rel_file="${_file#"${_mount_base}/"}"
# Defensive: when _file == _mount_base (bind-mount-dir chown), the strip
# above is a no-op and returns the full absolute path. Container target
# must be /s (the mount root), not /s/<abs-path>. Force _rel_file empty.
[[ "$_rel_file" == "$_file" ]] && _rel_file=""
local _chown_target="/s${_rel_file:+/${_rel_file}}"
```

Then use `"$_chown_target"` instead of `"/s/${_rel_file}"` in the chown command.
Apply the same guard to the equivalent positions in `_do_chgrp` and `_do_chmod`.

---

## 3. Why the two contexts differ

### Compose YAML preprocessing

Docker Compose reads the YAML file top-to-bottom using Python's `yaml.safe_load`
and then performs variable substitution on string values using a Go-template-like
engine (`${VAR}`, `${VAR:-default}`, `${VAR:?error}`) against a merged
`.env` + host-environment scope. This happens **before any container is started**
and **before any shell is invoked**. The substituted YAML is what compose sends
to the container runtime.

Block scalars (`|`, `>`) are string values in YAML — compose applies the same
substitution to them. There is no "shell quoting" that protects a `$VAR` from
compose; only the `$$` escape is recognised.

### Bash parameter expansion edge case

Bash `${VAR#pattern}` is a prefix-strip operation. The POSIX specification
states: if the expansion of `pattern` does not match the beginning of `$VAR`,
the result is `$VAR` unchanged. When `_file == _mount_base` (no trailing `/`),
the prefix `$mount_base/` (with the slash) is not present at the start of
`_file`, so the strip fails silently and returns the full path. This is correct
POSIX behaviour — it is the caller's assumption ("_file is always strictly
inside the prefix") that was wrong.

---

## 4. The lint

`scripts/lint_compose_command_vars.sh` enforces this discipline in CI.

**What it catches:**
- `${VAR}` (braced, no modifier) inside a compose `command:` / `args:` /
  `entrypoint:` block scalar → CLASS A
- `$VAR` (unbraced identifier) in the same context → CLASS B

**What it exempts:**
- `${VAR:-default}`, `${VAR:?error}`, `${VAR:+value}` — compose-substitution
  with modifier; intentional
- `$$VAR` and `$${VAR}` — correct double-dollar escape
- `$1`, `$2`, `$(` — positional params and command substitution; different
  semantics, not consumed by compose variable substitution
- Comment lines (lines whose first non-whitespace character is `#`)
- All `helm/yashigani/templates/*.yaml` files — K8s args semantics, no
  YAML preprocessing

**CI job:** `lint-compose-command-vars` in `.github/workflows/ci.yml`. Runs
in parallel with the other lint jobs. Required-status gate: no `needs:`
dependency; it is an independent blocking job alongside `lint-sudo-pattern` and
`lint-tmp-paths`.

Run locally:

```bash
bash scripts/lint_compose_command_vars.sh           # scan 5 compose files
bash scripts/lint_compose_command_vars.sh --test-fixtures  # run self-tests
```

---

## 5. For new services — checklist when adding a service to compose

Before committing a new service block to any `docker/docker-compose*.yml`:

1. **If `command:` or `entrypoint:` uses a block scalar (`|` or `>`):**
   - Audit every `$` in the block body
   - Shell-local variables set earlier in the same script → `$$VAR` (compose
     eats `$VAR` even if set three lines above, because compose parses at YAML
     load time, not script execution time)
   - Values that come from `environment:` or `env_file:` → these are set by
     compose before the container starts; inside the shell they are regular env
     vars. Use `$$VAR` to reference them in block scalars, or reference via
     `"$VAR"` in the shell if the block is a bare list-item string (not a block
     scalar). When in doubt: `$$VAR`.
   - Values from secret files at runtime → `$$(cat /run/secrets/name)`
   - Compose-substitution with defaults → `${VAR:-default}` in `environment:`
     blocks only, NOT inside block scalars

2. **If `command:` uses list form (`command: [...]`):**
   - List items are passed verbatim to the container; compose does NOT preprocess
     them. `${VAR}` inside a list-form string is safe (K8s-style).
   - Verify: the service actually uses this form correctly for its entrypoint.

3. **Run the lint before pushing:**
   ```bash
   bash scripts/lint_compose_command_vars.sh
   ```
   If it exits non-zero, fix all findings before pushing.

4. **Do not add `$$` to helm templates** — Helm + K8s context is different.
   If you are porting a compose service to Helm, use single `$` (or
   `${VAR}`) in `args:` block bodies; remove the extra `$` you added for
   compose.

---

## 6. References

- `internal-docs/yashigani/sanitization-map-20260523.md` — Stage 1 exhaustive
  map of all VEB bug instances, severity table, and fix specification
- `internal-docs/yashigani/iris-v240-sanitization-structural-design.md` — Iris
  design memo: option analysis, drift map, lint scope constraints
- `internal-docs/yashigani/laura-v240-sanitization-structural-threat-model.md` —
  Laura threat model: OWASP mapping, fail-open/fail-closed assessment, CI
  enforcement requirement
- `scripts/lint_compose_command_vars.sh` — the lint implementation
- `docker/docker-compose.yml:720` — canonical `$$(cat ...)` example (redis)
