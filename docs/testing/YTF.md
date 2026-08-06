# Yashigani Test Framework (YTF)

**Owner:** Iris (framework/contract layer) — per-tier content owned by Tom (conformance API),
Su (shell/install), Captain (containers/K8s), Ava (WebUI/API), Laura (offensive).
**Scope:** 4.1.2+. Built as an extension of the canonical `feat/v412-conformance-suite`
lineage (already an ancestor of this branch's base, `250b486d` — see §7), so it travels
into 5.0 unchanged in shape: new 5.0 endpoints/surfaces slot into the SAME Tier-A
enumeration and the SAME `tests/MATRIX.yaml` leg rows, not a second framework.
**Mirror:** this file is mirrored to `AgnosticSecurity/Compliance/SOPs/` (git-backed ops repo)
so it is discoverable alongside the Release & Tagging / Penetration-Testing SOPs it feeds.
**Last updated:** 2026-07-29.

---

## 1. The problem this replaces

Before YTF, six exhaustive-but-separate suites existed (`conf/v412-auth-identity-rbac`,
`conf/v412-admin-config-obs`, `conf/v412-dataplane-gateway-mcp`, `conf/v412-opa-templates`,
`conf/v412-webui`, `conf/v412-pentest`) plus the pre-existing 12-group conformance program,
plus a live E2E suite (`src/tests/e2e/`), plus ad-hoc Playwright coverage — none of them
wired together, none of them run as ONE command, and (found during consolidation) at least
one shared fixture (`tests/conformance/test_user_plane_agents.py`'s `me_state`) that
**masked a CRITICAL cross-datastore divergence** by handing two production-disjoint Redis
logical databases the same fake client. YTF exists to end that: one canonical tree, one
runner, one full-matrix manifest, exhaustive-by-construction.

## 2. Three tiers

### Tier-A — IN-PROCESS, matrix-INVARIANT
No live stack. Runs **once per code head**; the result applies identically to **every**
runtime/platform leg in `tests/MATRIX.yaml` — a leg's Tier-A cell is never re-run per-leg.
This is the whole point of separating it: a PKI-mount-path bug or an auth-tier gap is a bug
regardless of whether it's caught on docker or k8s, so prove it ONCE, cheaply, on every
commit.

Contents (2,667 assertions at time of writing: 2,134 pytest + 533 `opa test`):
- `tests/conformance/` — 12-group pre-existing suite (1,117 tests) + 3 consolidated groups
  (auth/identity/rbac 189, admin/config/observability 281, dataplane/gateway/mcp 165) +
  `test_wiring_config_audit.py` (mechanical wiring/config audit, §4).
- `tests/security/` — pentest: static analysis + authored-live in-process attacks (regression
  table, auth/identity/secrets, policy/admin/budget, userplane/gateway/mcp, audit/PII/onboarding).
- `policy/` (`opa test policy/`) — 533/533, every documented deny reason + obligation across
  all 8 live-loaded OPA example templates.

Invocation: `scripts/run-test-framework.sh --tier a`

### Tier-B — LIVE, per-deployment (WebUI Playwright)
Requires `--runtime <docker|podman|k8s> --version <ver> --platform <macos|linux>`. `--target
<url>` is OPTIONAL (FIND-B-TARGET, 4.1.2 3-runtime retest, 2026-08-04) — if omitted,
`src/tests/playwright/conftest.py`'s `_resolve_base_url()` auto-probes `https://localhost:8443`
(podman leg), then `https://localhost` (docker leg), then `http://localhost:8080`, in that
order, and uses whichever answers `/healthz` with 200. Pass `--target` explicitly only to pin
a non-default port/host.

Contents (491 pytest test IDs, run in **both** browser modes = 982 executions per leg):
- WebUI conformance (`test_webui_conformance_full.py`) — the 39 pages / 34 forms / 137
  buttons / 118 endpoints inventoried in Ava's `webui-inventory.md`.
- WebUI adversarial (`test_pentest_webui_adversarial.py`) — 91 forms, OWASP-mapped.

**Hard requirements (both non-negotiable, both baked into the runner + MATRIX.yaml pass
criteria):**
1. **Headed AND headless, both.** `--browser-mode both|headed|headless` (default `both`).
   A leg's WebUI Tier-B cell is not GREEN until **both** modes pass.
2. **Screenshot of every state transition.** Every page/panel load, every form (before
   submit + after result), every button/action (before + after), every error state — one
   file per test+step, under
   `testing_runs/yashigani/ytf/<runtime>-<platform>/screenshots/<mode>/`. A leg with zero
   screenshots is **not** a complete Tier-B pass regardless of exit code (the runner checks
   the directory is non-empty and fails the leg if not).

Invocation (podman leg, Caddy on :8443): `scripts/run-test-framework.sh --tier b --target https://localhost:8443 --runtime podman --version 4.1.2 --platform macos --browser-mode both`

Invocation (docker leg, Caddy on :443 — **note the different port**, FIND-B-TARGET):
`scripts/run-test-framework.sh --tier b --target https://localhost --runtime docker --version 4.1.2 --platform macos --browser-mode both`

Invocation (either leg, `--target` omitted, auto-resolved):
`scripts/run-test-framework.sh --tier b --runtime docker --version 4.1.2 --platform macos --browser-mode both`

Physical path note: the WebUI suite lives at `src/tests/playwright/`, **not** a root
`tests/playwright/` — see §7 "canonical name vs physical path."

### Tier-C — LIVE, per-deployment (integration/lifecycle/chaos/parity)
Requires the same `--runtime/--version/--platform` triple as Tier-B; `--target` is likewise
optional (see FIND-B-TARGET note above). The bug-class this tier
targets: **a value written on service A, silently trusted (not re-verified) on service B's
own read path** — the shape of 112 (audit-events-registered-not-emitted), 128 (toggle
returned 200/"on", downstream path unaffected), 131 (DB1/DB3 divergence),
"cache-vs-store" (Postgres vs Redis disagreeing). Tier-A/Tier-B structurally cannot see this
class because each looks at one service's surface at a time.

**Absorbs, does not duplicate**, the pre-existing `src/tests/e2e/` live suite (29 tests:
`test_zz_chaos.py` self-heal chaos, `test_agent_dispatch_e2e.py` real
OpenWebUI→gateway→langflow/letta→Ollama dispatch, `test_budget_e2e.py` real budget-redis
degradation) — see `tests/MATRIX.yaml` `tier_c.paths`.

8 categories (`tests/MATRIX.yaml` `tier_c.categories`):

| Category | Home | Status |
|---|---|---|
| `data_flow_seam` | `src/tests/e2e/` (absorbed) + `tests/integration_live/test_data_flow_seam.py` | absorbed real + new scaffold (2 tests) |
| `lifecycle` (install→upgrade N-1→N→uninstall/partial-nuke/full-nuke→reinstall) | `src/tests/e2e/` (absorbed) | absorbed real |
| `failure_injection_chaos` (kill redis/postgres/OPA mid-run; fail-CLOSED + self-heal) | `src/tests/e2e/test_zz_chaos.py` (absorbed) | absorbed real |
| `cross_runtime_parity` | `tests/integration_live/test_cross_runtime_parity.py` | new scaffold (2 tests) |
| `egress_ringfence_injection` (both legs: ingress AND egress) | `tests/integration_live/test_egress_ringfence_injection.py` | new scaffold (2 tests) |
| `audit_observability_integrity` | `tests/integration_live/test_audit_observability_integrity.py` | new scaffold (2 tests) |
| `dataplane_byte_proof` | `tests/integration_live/test_dataplane_byte_proof.py` | new scaffold (2 tests) |
| `multitenant_licensing` | `tests/integration_live/test_multitenant_licensing.py` | new scaffold (2 tests) |

**Tier-C status honesty note:** the 6 "new scaffold" categories are REAL, running (not
placeholder-text) pytest modules — every test issues a real HTTP call and will genuinely
pass or fail the first time it's pointed at a live stack; they `SKIP` (not error) when no
stack is reachable (verified: 12/12 skip cleanly with no `--target`). "Scaffold" describes
DEPTH (more scenarios per category are expected as each leg is actually exercised live), not
authenticity. Author-only per the dispatch brief — **no live run performed this session.**

Invocation: `scripts/run-test-framework.sh --tier c --target https://localhost:8443 --runtime k8s --version 4.1.2 --platform linux`

### `--full`
`scripts/run-test-framework.sh --full --target ... --runtime ... --version ... --platform ...`
runs Tier-A + Tier-B + Tier-C in one invocation.

---

## 3. The "Tier-A is runtime-invariant" principle

A PKI mount-path bug, an auth-tier gap, a dark-default security flag — none of these change
behaviour based on whether the *stack* is docker, podman, or k8s; they are properties of the
CODE. Tier-A tests the code in-process, once, and that single result is inherited by every
leg row in `tests/MATRIX.yaml`. Only what genuinely differs BY RUNTIME (Caddy wiring, PKI
mount paths, Kyverno policies, Helm values, cross-runtime parity itself) needs a live,
per-leg Tier-C run. Do not re-run Tier-A per leg — that's wasted compute proving the same
fact eight times.

## 4. Tier-A wiring/config audit (`test_wiring_config_audit.py`)

A NEW mechanical, static grep/AST audit module — Iris's own "intersection plane" checks,
expressed as pytest so they run on every Tier-A invocation. Catches the class of bug that
per-endpoint conformance tests structurally cannot see:

- registered-but-never-emitted handlers/event-types
- env-var set on one service manifest but not its peers (122-class)
- hardcoded version-tag fallbacks reachable when a var is unset (123-class)
- two-datastore source-of-truth mismatches (131/128-class)
- dead catch-all stub endpoints (named, not broadly grepped — see module docstring for why a
  broad `NotImplementedError`/"not wired" regex was tried first and dropped as noise: every
  hit was a legitimate fail-closed defensive guard, not a dead stub)
- security-flag dark-defaults (`os.environ.get(<ENFORCE/VERIFY/REQUIRE/MTLS/AUTH/STRICT
  flag>, "false")`)
- stale config snapshots / drifted image-tag fallbacks across compose vs product Python

**Real findings from the first run** (evidence-backed, routed not fixed — see §6):
- **W1**: `src/yashigani/documents/sandbox.py` `DEFAULT_IMAGE = "yashigani/extractor:2.26.0"`
  (ancient — predates the 3.0 rename) vs `docker/docker-compose.extractor.yml`'s own fallback
  `yashigani/extractor:${YASHIGANI_VERSION:-4.1.0}` — two different, mutually-disagreeing,
  normally-unreachable version fallbacks for the same image. Same class as YSG-RISK-123.
- **W2**: `YASHIGANI_PERMISSION_STRICT` dark-default `"false"` (`gateway/openai_router.py`,
  2 call sites) — needs an explicit off-by-default sign-off.

Every check either regression-guards an already-fixed bug (e.g. `BUDGET_REDIS_HOST` on both
Helm templates — YSG-RISK-122) or asserts a documented, evidence-backed finding is STILL
present (proving the check works, not a fossil). A check that can't fail is not an audit.

## 5. Feature-driven, per-field, positive+negative, effect-verified (cross-tier discipline)

Two structural requirements apply across Tier-A and Tier-B alike:

**5.1 Full 2×2 per surface: {admin, user} × {WebUI, API}.** Every surface must be exercised
as admin AND as user, over both the WebUI and the API path where both exist. Enumeration
source: Ava's `webui-inventory.md` (39 pages, 34 forms, 137 buttons, 118 endpoints,
role-tagged ADMIN/USER/SHARED-PREAUTH/BOTH) for the WebUI half; the API conformance route
lists (`declared_routes`/`route_prefix_filter` fixtures) for the API half. A surface is not
covered until all applicable quadrants are green.

**5.2 Per-page/per-FIELD, positive AND negative.** For each page/form field: enumerate its
features (required?, type, length/range bounds, format/regex, allowed set, cross-field
deps, RBAC visibility), and write BOTH a positive test (valid input → documented success)
AND a negative test (missing/wrong-type/out-of-bounds/malformed/forbidden → correct
rejection: right status, inline error, no 500, no leak). Tier-A field-negatives (API side)
run in-process now; WebUI field cases run in Tier-B (headed+headless+screenshot).

**5.3 Effect-verified, not response-verified — the standing rule.** YSG-RISK-128 is the
concrete lesson: a toggle returned 200/"on", but the governed behaviour on the real
enforcement path was untouched. Applied universally:
- **Every toggle:** turn ON → assert the governed behaviour is genuinely ACTIVE on the real
  path (not just that the toggle shows on). Turn OFF → assert genuinely DISABLED. Prove the
  downstream effect, both states.
- **Every field:** correct value → accepted AND produces the documented effect/state. Wrong
  value → the SPECIFIC error (right status, right message, no 500, no leak).
- **Every button/action:** does it do the documented thing (verify resulting state), and
  does it fail correctly on bad preconditions.

This applies in both tiers: Tier-A verifies state in-process (real fakeredis-backed store
reads, not just the HTTP response body); Tier-B verifies state via headed+headless +
screenshot of each resulting state.

## 6. Findings register (this build — routed, not fixed)

Framework-build discipline: Iris builds and runs the framework, does not fix product code
or pre-existing test-suite internals beyond the test-isolation hygiene needed to make Tier-A
run as ONE repeatable suite (see §6.1). Everything else below is routed to its owner.

**6.1 Fixed as part of consolidation (test-harness hygiene, not product code):**
- `tests/conformance/test_conformance_admin_config_obs.py`: a test directly assigned
  `backoffice_state.kms_provider`/`siem_backend`/`siem_endpoint` (module singleton) instead
  of `monkeypatch.setattr(..., raising=False)` — leaked for the rest of the pytest process,
  causing 4 spurious failures in `test_secrets_pki_vault.py` (94/94 green alone; 4 failures
  only when run after this file in the same process). Fixed: converted to monkeypatch.
- New autouse fixture `_reset_cluster_az_count` (shared conftest, both copies): the REAL
  product route `POST /admin/infrastructure/topology`
  (`src/yashigani/backoffice/routes/infrastructure.py:72`) sets
  `backoffice_state.cluster_az_count` via a bare attribute assignment with no dataclass
  field/default — any test that posts ≥2 zones leaks it for the rest of the process.
  Confirmed collision: `test_budget_models_inspection.py`'s own az_count==2 case
  (pre-existing 12-group suite) leaked into `test_conformance_admin_config_obs.py`'s
  "defaults to 1" test purely due to alphabetical file order. Fixed centrally (deletes the
  attribute before+after every test in `tests/conformance/` and `tests/security/`).

**6.2 Flagged, not fixed (route to owner):**
- **P0 — Tom, urgent, needs root-cause before this suite is fully GREEN**:
  `tests/conformance/test_conformance_dataplane_gateway_mcp.py::test_risk128_disposition_ladder_when_enabled`
  — REDACT and PSEUDONYMIZE parametrisations FAIL EVEN IN ISOLATION (163/165 in-file; not a
  test-order artifact). The test mocks OPA's decision to REDACT/PSEUDONYMIZE and drives it
  through the REAL `DocumentInspectionPipeline`, but observes `BLOCK` for both; LOG and
  BLOCK parametrisations pass. Could be a genuine disposition-ladder regression (the exact
  "effect not proven" class this framework exists to catch) or a test-harness wiring gap in
  `_real_pipeline`/`_fake_opa_decision`. File: lines ~855–885.
- **W1/W2** (§4, Captain/Su/Tom/Lu).
- **W3 — Tom**: `tests/conformance/test_user_plane_agents.py:233-239` `me_state` fixture
  still shares one fakeredis instance across `session_store`+`identity_registry` — masks the
  DB1/DB3 divergence for its own test class (the new auth/identity/rbac suite's two-client
  pattern only fixes this for itself, not for the pre-existing file). Recommend migrating it
  to the same `session_redis_client`/`identity_redis_client` pattern.
- **W4 — Tom, informational**: `identity/durable_store.py:378` "not wired" guard — confirm
  intentional defensive design vs a real init-ordering gap.
- **Gate-script drift — Su/Lu**: `release-gate-check.sh`'s `RUNTIME_MATRIX` array has no k8s
  leg even though `matrix-evidence.md` tracks one (`MATRIX k8s LIFECYCLE (docker-desktop):
  ...`) — a k8s regression does not currently hard-block C5.

**6.3 Genuine integration-seam finding, resolved in-framework (not a product bug):**
- Root `tests/` and `src/tests/` are two same-named `tests` Python packages. Moving
  `src/tests/playwright/` to a root `tests/playwright/` (as the brief's canonical-tree naming
  literally suggests) breaks `test_webui_conformance_full.py`'s absolute
  `from tests.playwright.conftest import (...)` import (it silently resolves to whichever
  `tests` package wins the sys.path race, which after the move is neither). Resolution:
  physical location stays `src/tests/playwright/`; `tests/MATRIX.yaml` and this doc use
  "tests/playwright" as the CANONICAL NAME throughout, with the physical-path caveat
  documented once, here and in `tests/MATRIX.yaml`. Do not "fix" this by adding
  `tests/__init__.py` at repo root — that would flip the collision the other way (whichever
  of the two `tests` packages sys.path resolves first silently wins, breaking the other).

## 7. Coordination with the 5.0 rebase + canonical conformance-suite lineage

- **Canonical lineage confirmed, no divergence.** `feat/v412-conformance-suite` (the
  original 12-group "360/360 API endpoints" program) IS an ancestor of this branch's base
  commit `250b486d` (`git merge-base --is-ancestor feat/v412-conformance-suite 250b486d` →
  true). This branch (`feat/v412-test-framework-ytf`, off
  `mustui/acc/v412-integrated-latest-20260722` @ `250b486d`) is built ON TOP of that lineage,
  not a parallel island — it consolidates the six `conf/v412-*` suites INTO the same
  `tests/conformance/` tree the canonical program already occupies.
- **5.0 non-interference confirmed.** Did not touch `feat/6.0-inference-engine`,
  `acc/v50-rebase-412-*`, or any other 5.0-session branch. `tests/{conformance,security}/` +
  `src/tests/playwright/` + `scripts/run-test-framework.sh` + `tests/MATRIX.yaml` are
  designed to travel with the code through the 5.0 rebase unchanged in shape — new 5.0
  endpoints slot into the SAME conformance modules' route-completeness gates (`_EXPECTED_ROUTES`
  sets, `declared_routes`/`route_prefix_filter` fixtures), new 5.0 surfaces get new rows in
  `tests/MATRIX.yaml`, not a new file.
- Push target: `mustui` remote, branch `feat/v412-test-framework-ytf`. **Not merged to
  `acc/v412-integrated-latest-20260722`** — per dispatch brief, coordinate with the active
  x8x branch + register-numbering reconciliation before any merge.

## 8. Release-gate C5 wiring

`AgnosticSecurity/Operations/Releases/scripts/release-gate-check.sh` C5 reads
`AgnosticSecurity/Operations/Compliance/yashigani/<ver>/matrix-evidence.md` and greps for:
`MATRIX <leg>: GREEN|EX-<id>` (one per `RUNTIME_MATRIX` entry), `AVA E2E: GREEN`,
`LAURA PENTEST: GREEN` (with a clean-round attestation), `CONFORMANCE COVERAGE:
COMPLETE|GREEN`. YTF satisfies this as follows (full mapping in `tests/MATRIX.yaml`
`release_gate_c5_mapping`):

- Tier-A pass (whole-suite, matrix-invariant) → `CONFORMANCE COVERAGE: COMPLETE`
- Tier-B pass (both browser modes + full screenshot set, per leg) → `AVA E2E: GREEN`
- Tier-C pass (live DAST/chaos/parity half) + Tier-A `tests/security/` (static half) →
  `LAURA PENTEST: GREEN`
- A leg is GREEN in YTF's sense only when: Tier-A (head-level, inherited) PASS + that leg's
  own Tier-B PASS + that leg's own Tier-C PASS. **The gate is not weakened** — C5 still fails
  if any leg is absent or not GREEN/EX-`<id>`.

## 9. Running it

```bash
# Tier-A — in-process, no stack, run this on every commit
scripts/run-test-framework.sh --tier a

# Tier-B — live WebUI, needs a running stack
scripts/run-test-framework.sh --tier b \
  --target https://localhost:8443 --runtime docker --version 4.1.2 --platform macos \
  --browser-mode both

# Tier-C — live integration/lifecycle/chaos/parity
scripts/run-test-framework.sh --tier c \
  --target https://localhost:8443 --runtime k8s --version 4.1.2 --platform linux

# Everything
scripts/run-test-framework.sh --full \
  --target https://localhost:8443 --runtime podman-6 --version 4.1.2 --platform macos
```

Evidence lands under `testing_runs/yashigani/ytf/` by default (override with
`YTF_EVIDENCE_ROOT`); Tier-A evidence under `testing_runs/yashigani/ytf/tier-a/`
(junit XML + full pytest log + `opa test` log).

## 10. Full runtime matrix

See `tests/MATRIX.yaml` for the machine-readable version (this is the human summary):

| Runtime | Platform | Tiers | Status |
|---|---|---|---|
| docker | macos | A, B, C | primary dev/test rig |
| docker | linux | A, B, C | x8x |
| podman-4.9 | macos | A | EX (podman-mac = 6.x only; same compose-path) |
| podman-4.9 | linux | A, B, C | x8x, genuinely distinct engine |
| podman-5 | macos | A | EX (same compose-path as podman-6 macOS) |
| podman-5 | linux | A, B, C | x8x |
| podman-6 | macos | A, B, C | the one podman-mac leg that actually runs |
| podman-6 | linux | A, B, C | x8x |
| k8s (k3s+Cilium) | linux | A, B, C | x8x-only, Cilium-gated (vanilla Docker-Desktop k8s can't test NetworkPolicy enforcement / CoreDNS DoT) |
