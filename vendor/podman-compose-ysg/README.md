<!-- Last-Updated: 2026-07-18 -->

# podman-compose-ysg

A first-party-patched fork of upstream
[`podman-compose`](https://github.com/containers/podman-compose) 1.5.0,
maintained by Agnostic Security Ltd for Yashigani's rootless-Podman deploy
path. **Not affiliated with, and not endorsed by, the Podman / `containers`
project or Red Hat.**

- **Fork version:** `1.5.0+ysg.1`
- **License:** GPL-2.0-only (unchanged from upstream — see [`LICENSE`](./
  LICENSE); our changes do not, and cannot, relicense this work — GPL-2.0
  §2(b)).
- **Changes:** exactly 3 upstream bug fixes. See [`CHANGES.agnostic.md`](./
  CHANGES.agnostic.md) for the full root-cause analysis, dates, and
  rationale for each.
- **Legal notice:** see [`NOTICE.md`](./NOTICE.md).
- **Supply-chain / integrity manifest:** see [`vendor-integrity.md`](./
  vendor-integrity.md) and [`MANIFEST.sha256`](./MANIFEST.sha256).

## What this is not

- This is **not** wired into `install.sh` yet. That integration is a
  deliberately separate, later step, pending Iris's universal-installer
  design + council ratification of the integration approach. This build
  delivers the tool + GPL compliance + supply-chain verification artifact
  only.
- This is **not** a general-purpose replacement recommendation for
  `podman-compose` outside Yashigani's specific install flow.
- Yashigani's own product code **never imports** this module. The only
  supported interface is CLI/subprocess invocation, exactly as upstream
  `podman-compose` is invoked:

  ```sh
  python3 vendor/podman-compose-ysg/podman_compose.py \
    -f docker/docker-compose.yml \
    -f docker/docker-compose.podman-override.yml \
    --in-pod=false --profile <profile> up -d
  ```

  (Add `-f docker/docker-compose.podman-virtiofs-override.yml` on macOS, and
  the appropriate GPU overlay — see `install.sh`'s own compose-file
  selection logic, which this fork does not change.)

## The 3 fixes (summary — full detail in CHANGES.agnostic.md)

| # | Defect | Root cause | Fix |
|---|---|---|---|
| AS-FIX-1 | `security_opt` seccomp relative-path ENOENT | `security_opt` was the only path-bearing compose key with no `realpath()` normalization (unlike `env_file`/secrets) | mirror the existing realpath pattern, applied only to `seccomp=<path>` |
| AS-FIX-2 | Dependency-ordering `--requires=<not-yet-created>` crash | 2 sort sites ordered by dependency COUNT, not real topological order | genuine topological sort (Kahn's algorithm) |
| AS-FIX-3 | `KeyError` on a `required: false` dependency missing (e.g. profile-excluded) | `required` was discarded at graph-construction time, before `check_dep_conditions()` ever ran | thread `required` through `ServiceDependency`/`flat_deps()`; honor it explicitly (skip if optional, raise a clear error if genuinely-required-and-missing) |

**AS-FIX-2 and AS-FIX-3 ship atomically** (see CHANGES.agnostic.md) — a bare
except-KeyError guard for AS-FIX-3 without AS-FIX-2's real ordering fix would
silently mask a genuine required-dependency failure.

## Live verification (2026-07-18)

Brought up the real Yashigani 4.1.2 compose project (demo-mcp profile only —
the exact profile-limited case that crashed unpatched podman-compose 1.5.0
with `KeyError: 'ollama-init'`), from a clean state, on this podman-6 host
(macOS, `applehv`). Full stack (17 containers) reached healthy via
Yashigani's own merged `scripts/health-check.sh`, twice — once with
`YASHIGANI_SECCOMP_PROFILE=unconfined` (install.sh's current default) and
once with the profile forced to the relative real path
(`./seccomp/yashigani.json`, the exact value that triggered the ENOENT crash
against unpatched upstream) to directly prove AS-FIX-1. See the build
session's `evidence/` directory for full logs.

A 4th, unrelated, out-of-scope defect was discovered during this live
verification (a `podman wait --condition=running` hang against an
intentionally-instant-exiting dependency container, specific to Yashigani's
Mac-Metal-relay `ollama` overlay) — documented in `CHANGES.agnostic.md`'s
final section, surfaced as a new finding, **not patched in this fork**.

## Testing

Unit tests for all 3 fixes: [`tests/test_as_fixes.py`](./tests/
test_as_fixes.py). These import `podman_compose` directly to exercise the
fork's own internals — testing of the GPL component itself, not a
Yashigani-proprietary-code import (see boundary note in `NOTICE.md`).

```sh
python3 -m pytest vendor/podman-compose-ysg/tests/ -v
```
