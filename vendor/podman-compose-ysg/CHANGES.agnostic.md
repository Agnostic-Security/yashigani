# CHANGES.agnostic.md — Agnostic Security Ltd modifications to podman-compose

Fork: **podman-compose-ysg**, based on upstream `podman-compose` **1.5.0** (GPL-2.0-only).
Fork version: **1.5.0+ysg.1**.

This file is the GPL-2.0 §2(a) change-marking record required for a modified copy
of a GPL-2.0 work: it enumerates every substantive change Agnostic Security Ltd
has made to the upstream source, with dates and rationale. Per-file "Modified
by Agnostic Security Ltd" headers are also present at the top of every touched
file (`podman_compose.py`).

All patches are discrete, dated commits on branch `feat/v412-podman-compose-fork`
(off `release/4.1.2` @ `8dc7c860`).

---

## 2026-07-18 — AS-FIX-1: `security_opt` seccomp path normalization

**File:** `podman_compose.py`, `container_to_args()`, ~line 1118 (upstream line
numbering).

**Root cause (source-verified, not assumed from behaviour — credit: Laura,
Agnostic Security offensive-security review, `threat-model-podman-compose-
fork-20260718.md` + `source-citations.md`):** `security_opt` was the only
path-bearing compose key in the file with **no path normalization**.
`env_file` handling (same function) and `get_secret_args()` both do
`os.path.realpath(os.path.join(dirname, path))` before use; `security_opt`
passed its value straight through to `podman create --security-opt <value>`
verbatim. A relative `seccomp=<path>` value (the compose-file's own default
form, e.g. `seccomp=./seccomp/yashigani.json`) was therefore resolved by
`podman` against podman's own invocation cwd, not the compose project
directory — those are not guaranteed to be the same thing (podman-machine
client/server split, `podman-compose` invoked from an unrelated cwd, etc.).
Confirmed failure mode: `Error: opening seccomp profile failed: open
./seccomp/yashigani.json: no such file or directory`.

**Fix:** mirror the existing, already-proven `env_file`/`get_secret_args`
realpath pattern, applied ONLY to the `seccomp=` key (the only `security_opt`
value that names a filesystem path — `unconfined`, `apparmor=<name>`, and
`label=<value>` are not paths and are left untouched). No new scheme was
invented; this is the exact fix Laura's root-cause analysis specified.

**Live-verified 2026-07-18** (see `../../testing_runs/yashigani/v412-fork-
build-20260718/evidence/`): with `YASHIGANI_SECCOMP_PROFILE=./seccomp/
yashigani.json` (the exact relative form that crashed upstream podman-compose
1.5.0 per the probe), the fork resolves it to an absolute path
(`/…/docker/seccomp/yashigani.json`), bakes that into `podman create
--security-opt seccomp=<absolute>`, and the container (`extractor-svc`) runs
healthy with the REAL seccomp profile enforced (not `unconfined`) — zero
ENOENT.

**NOT closed by this fix — explicitly left open (Laura condition 4, GO-WITH-
CONDITIONS):** whether this proves the path is resolvable/enforceable on
every podman-machine client/server split (this Mac uses `applehv` +
virtiofs) is still a live-test condition, not something this patch closes by
itself. **YSG-RISK-074's `seccomp=unconfined` workaround for install.sh's
compose-v2 path stays in place** — this patch does not retire it; retirement
requires the separate live-test legs (Mac + Linux, syscall-probe test) Laura
specified. This fork is not wired into install.sh yet (a later, separate
step), so YSG-RISK-074's current in-product behaviour is unaffected by this
patch existing.

## 2026-07-18 — AS-FIX-2: real topological sort (replaces sort-by-dependency-count)

**File:** `podman_compose.py`, two call sites (upstream line ~2325 and
~2448), plus new helper `_topological_sort_service_names()`.

**Root cause (source-verified):** both sites sorted services/containers by
`len(deps)` — the COUNT of direct dependencies — not real dependency order.
A service with fewer *direct* dependencies can still have a *transitive*
dependency with more direct dependencies of its own, and would sort BEFORE
it. Confirmed failure mode (from the probe): `Error: "localhost_caddy_1" …
not a valid container, cannot be used as a dependency … no such container` —
`caddy`, `extractor-svc`, `backoffice` were never created because
podman-compose tried to wire them as `--requires=` dependents of services
before those services existed.

**Fix:** genuine topological sort (Kahn's algorithm) over the `_deps` set
already built by `flat_deps()`/`rec_deps()`. Deterministic: ties broken by
original compose-file (dict-insertion) order. A dependency cycle is
surfaced with a warning and the cyclic services are appended in original
order rather than silently dropped — a cycle is a compose-file authoring
error this function should not mask.

**Live-verified 2026-07-18:** brought up the real 4.1.2 compose project
(demo-mcp profile, Mac-Metal-relay overlay) with this fork; every container's
baked-in `--requires=` list contained only already-created container names —
e.g. `gateway`'s `--requires=sufork_postgres_1,sufork_ollama_1,
sufork_redis_1,sufork_policy_1,sufork_pgbouncer_1`, all already `Created`
when `gateway` itself was created. Zero "not a valid container" errors
across all 17 containers.

**Ships atomically with AS-FIX-3** (see Laura's merge condition below).

## 2026-07-18 — AS-FIX-3: `depends_on.<svc>.required: false` honored

**Files:** `podman_compose.py` — `ServiceDependency.__init__`/`flat_deps()`
(upstream ~line 1383/1449) and `check_dep_conditions()` (upstream ~line
3030-3060/3053).

**Root cause (source-verified):** the compose-spec `depends_on.<svc>.
required: false` field survived YAML normalization (`normalize_service()`
only sets a `condition` default, leaving the rest of the per-dependency dict
alone) but was **discarded at dependency-graph construction** —
`ServiceDependency.__init__` only ever accepted `name`+`condition`;
`flat_deps()` built every `ServiceDependency` from `v["condition"]` alone,
never reading `v.get("required")`. By the time `check_dep_conditions()` ran,
there was no way to distinguish "optional dependency, correctly absent
(e.g. excluded by `--profile`)" from "required dependency that should have
been created". `check_dep_conditions()` then did an unconditional
`compose.container_names_by_service[d.name]` with no existence guard,
crashing with `KeyError: 'ollama-init'` when `ollama-init` (profile-gated to
`langflow`/`letta`/`openclaw`) was correctly absent under a `demo-mcp`-only
profile selection — a common, intentional pattern in Yashigani's compose
file (optional agent bundles), not an edge case.

**Fix:** thread `required` through `ServiceDependency` (new constructor
param, default `True` — compose-spec semantics when the field is omitted)
and `flat_deps()` (`v.get("required", True)`). In `check_dep_conditions()`,
when a dependency's service has no entry in `container_names_by_service`:
skip it (debug log) if `required is False`; **raise a clear, specific
`RuntimeError`** (not a bare `KeyError`) if `required is True` — a genuinely
missing required dependency is a real bug (compose-file error or an ordering
regression) and must still fail loudly, not be silently swallowed.

**Merge condition honored (Laura, hard, GO-WITH-CONDITIONS item 1):**
AS-FIX-2 and AS-FIX-3 ship as a single atomic change and are tested
together in the same commit/PR — a bare `except KeyError` guard for
AS-FIX-3 without AS-FIX-2's real topological-sort fix would silently mask a
genuine required-dependency ordering failure as "optional and absent".
Regression test `test_check_dep_conditions_raises_clearly_on_missing_
required_dependency` in `tests/test_as_fixes.py` proves the guard does NOT
swallow a genuinely-missing required dependency.

**Live-verified 2026-07-18:** brought up the real 4.1.2 compose project
(demo-mcp profile only — the exact profile-limited case that crashed
upstream podman-compose 1.5.0 with `KeyError: 'ollama-init'`) — zero crash,
all containers created successfully.

## 2026-07-23 — AS-FIX-4: exclude one-shot (`service_completed_successfully`) deps from `--requires=`

**File:** `podman_compose.py`, `container_to_args()`, ~line 1138.

**Root cause (source-verified, Captain live-repro, byte-identical across 3
from-scratch podman installs — YSG-PODMAN-LETTA-001; deterministic, NOT a
race):** `container_to_args()` translated every entry in a service's
transitively-flattened `_deps` set into `podman create --requires=<name>`,
regardless of the dependency's declared condition. `--requires=` is a
podman-engine-level primitive meaning "must be RUNNING" — when the engine
resolves `podman start <dependent>`, any `--requires` member that is not
currently running (including a one-shot init job that already **exited 0**,
e.g. `agent-db-init`, or `ollama-init`) is itself queued for a restart as
part of satisfying the dependent's start. Compose's
`service_completed_successfully` condition ("ran to completion once") has
**no equivalent state** in podman's `--requires` model. Walking a
`--requires` chain that re-enters an exited one-shot whose own dependency
(`postgres`) is already running then hits a podman dependency-graph
construction bug: `Error: ... container agent-db-init depends on container
postgres not found in input list: no such container`. Confirmed failure:
`letta` and `letta-pgbouncer` both stuck in `Created` (never reach `Up`) on
every from-scratch podman install with the `letta` profile active.

**Fix:** in `container_to_args()`, skip any `_deps` entry whose
`ServiceDependencyCondition` is `STOPPED` (the internal enum value
`docker_to_podman_cond` maps `service_completed_successfully` to) when
building the `--requires=` list. `service_started` / `service_healthy`
dependencies are unchanged. This does **not** weaken dependency
correctness: `check_dep_conditions()` (same file, ~line 3174) already
independently enforces `service_completed_successfully` via `podman wait
--condition=stopped <dep>` **before** this fork ever issues `podman start
<dependent>` — that application-level, state-reached wait is authoritative
for one-shot completion and was already running in parallel with
`--requires`; the engine-level `--requires` was pure redundant (and, for
this specific condition class, actively harmful) belt-and-suspenders.

**Live-verified 2026-07-23** on the live `wt-integrated` podman stack
(`/Users/max/Documents/Claude/testing_runs/yashigani/wt-integrated/ysg`):
recreated `letta-pgbouncer` and `letta` with the corrected `--requires=`
(`localhost_postgres_1` only, and the full non-one-shot chain respectively —
both drop `localhost_agent-db-init_1`; `letta` additionally drops
`localhost_ollama-init_1`, also a `service_completed_successfully` dep
inherited transitively via `gateway`→`ollama`→`ollama-init`). Both
containers reached `Up (healthy)` with zero dependency-graph errors
(`.State.Error` empty on both); the other 25 containers in the stack were
untouched.

**Pairs with defect 2 (install.sh `_podman_compose_letta_waitloop`
false-positive-success fix, same date, YSG-PODMAN-LETTA-001):** that
wait-loop was a install.sh-level workaround for the identical class of
failure; it now verifies real container state instead of assuming success
from a non-checked `podman start` return code.

## 2026-08-05 — AS-FIX-5: `rec_merge_one()` unwraps `!override`/`!reset` on first-introduced keys

**File:** `podman_compose.py`, `rec_merge_one()`, ~line 2004.

**Root cause (source-verified, live-repro against `docker-compose.yml` +
`docker-compose.gpu-mac-metal-podman.yml` on the exact commit that shipped
FIND-IRIS-DUP-AGENT-REGRESSION, `d2ed22b0`):** `rec_merge_one()`'s first loop
(introducing keys that exist in `source` but not yet in `target`) did
`target[key] = clone(value)` unconditionally. When `value` is a raw
`OverrideTag`/`ResetTag` (the compose-spec `!override`/`!reset` YAML merge
tags), the SECOND loop a few lines below already unwraps them correctly —
but only for the opposite case (key exists in `target`, absent from
`source`). The first-introduction case was never handled: a raw `OverrideTag`
object survived into the merged compose dict for any key whose FIRST
`-f` file to define it used `!override`.

Yashigani's `docker-compose.gpu-mac-metal-podman.yml` does exactly this —
`profiles: !override [...]` on its `ollama` service, the first (and only)
`-f` file in install.sh's assembled overlay chain to give that service a
`profiles:` key at all. Every `podman-compose-ysg` invocation that included
this overlay (which install.sh's `_ysg_assemble_compose_files()` always
does on macOS/Mac-Metal Podman) therefore crashed inside
`_parse_compose_file()` -> `_resolve_profiles()` -> `set(config.get
("profiles", []))` with `TypeError: 'OverrideTag' object is not iterable`,
**before any container was ever reached** — this broke `compose exec`,
`compose up`, everything, identically.

**Live-verified 2026-08-05:** this crash is the true root cause of
FIND-IRIS-DUP-AGENT-REGRESSION (Yashigani `install.sh`'s
`register_agent_bundles()` reporting both "could not query durable
agent_registry" AND "No agents were registered" on every fresh Podman
install with the GPU-mac-metal overlay active) — both `register_agent_
bundles()` exec calls that assemble the full overlay set (the durable-
Postgres pre-check AND the container-side agent-registration script) hit
this exact crash and never reached their target container at all.
Reproduced standalone (no Yashigani code involved) by invoking
`podman_compose.py exec` with `-f docker-compose.yml -f docker-compose.
gpu-mac-metal-podman.yml` against a live stack on the same commit;
confirmed the crash disappears and `compose exec` reaches the target
container after this fix.

**Fix:** mirror the second loop's ResetTag/OverrideTag unwrap logic in the
first loop. A first-introduced `!reset` is a genuine no-op (nothing exists
yet to reset) — skipped entirely, not stored. A first-introduced `!override`
is unwrapped to its `.value` (same "unneeded but harmless" info-log the
second loop already uses), so downstream consumers of the merged dict
(`_resolve_profiles()`, and any future caller) see a plain list/dict/scalar,
never a raw tag object.

**Yashigani-side companion fix:** `register_agent_bundles()` (install.sh)
additionally hardens its result-parsing loop to treat "the compose-exec
call itself produced zero recognised OK/SKIP/FAIL/ERROR lines" as a loud,
distinct error — not the same silent "No agents were registered" warning
used for the (legitimate) "everything was already registered" case — so a
future regression in this class fails loudly instead of looking identical
to a no-op success. See Yashigani `AgnosticSecurity/Operations/Compliance/
yashigani/4.1.2/` retro for the full incident writeup.

## Version string

`__version__` changed from `"1.5.0"` to `"1.5.0+ysg.1"` (GPL-2.0 fork-naming
hygiene, Petra memo §3.1 — this is not bare `podman-compose`).

---

## Explicitly NOT changed in this fork

- **AppArmor / `label=` / `unconfined` handling** in `security_opt` —
  untouched; only the `seccomp=<path>` value is normalized (AS-FIX-1 scope
  discipline — do not invent a new scheme beyond the exact root cause).
- **YSG-RISK-074's `seccomp=unconfined` workaround** in Yashigani's
  `install.sh`/compose overlays — untouched. Not retired. See AS-FIX-1 note
  above.
- **Pin at 1.5.0** — this fork does not attempt to track or merge upstream
  1.6.x (1.6.0 introduced a separate, unfixed dependency-graph-hang class;
  not applicable to a frozen 1.5.0 fork).

## Supply-chain / CVE-watch

**Owner:** Lu (GRC) — process-level, per Laura's threat-model condition 3.
**Cadence:** reviewed every Yashigani release cycle (minimum quarterly),
checking `containers/podman-compose` upstream issue tracker + CVE feeds for
any 1.5.x-line security advisory. Freezing at 1.5.0+ysg.1 means this fork
does NOT automatically inherit upstream fixes released after 1.5.0 — this is
a standing obligation, not a one-time check. See
`vendor-integrity.md` in this directory for the artifact-integrity manifest
approach.

## A 4th defect found during live verification — OUT OF SCOPE, not patched here

During the live atomic-bringup proof, bringing `gateway` up (which
`depends_on: ollama: {condition: service_healthy}`, overridden by
Yashigani's Mac-Metal-relay overlay to `condition: service_started`) hung
indefinitely. Root cause (isolated, reproduced without podman-compose at
all): `podman wait --condition=running <container>` hangs forever if the
target container has *already* exited by the time the wait call is issued —
it waits for a future transition INTO the running state, and Yashigani's
Mac-Metal `ollama` no-op container (`entrypoint: ["true"]`) starts and exits
within milliseconds, before `check_dep_conditions()`'s `podman wait
--condition=running` call is even issued. This reproduces identically
against a throwaway container with no podman-compose involved at all — it is
a `podman wait` / `service_started`-condition interaction, not a defect in
any of the 3 patches above, and it is NOT one of Laura's 3 root causes. It
was masked in every previous test run because AS-FIX-3's un-fixed
predecessor crashed (Defect 3, `KeyError`) before ever reaching this point.
**Not patched in this build** — flagged to Maxine/Laura as a new,
out-of-scope finding for a follow-up dispatch. The live-verification evidence
bridges past it with a manual `podman start` to complete the health-check
proof (see `evidence/` in the build directory); this bridge is NOT part of
the shipped fork.
