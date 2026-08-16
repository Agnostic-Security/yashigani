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

## 5.4 NO TEST MAY BYPASS THE USER PATHWAY (added 2026-08-07 — Tiago directive)

**Every test reaches the product the way a user reaches it.** No `docker exec` /
`kubectl exec` into a container to call an internal port, no direct instantiation of a
product class, no internal service bearer, no reading a secret off a host path to skip
authentication.

This is not a style preference. §5.3 already required *effect-verified*, but nothing forbade
producing that effect by reaching past the layers under test — so tests did, and they were
green while the product was broken:

| module | what it did | what it reported | truth |
|---|---|---|---|
| `test_ollama_sensitivity.py` | `docker exec` gateway → `SensitivityClassifier().classify()` | **9 passed** | every real request on that path was failing |
| `test_agent_dispatch_e2e.py` | internal bearer → gateway's own mesh port from inside the gateway | 4 failures with **empty output** | a harness `PermissionError`, mistaken for a product defect on two runtimes |
| `test_egress_ringfence_injection.py` | unauthenticated probe; `GET /healthz == 200` under a prompt-injection name | pass | the named security category verified **nothing** |

A test that bypasses a layer cannot see any defect in that layer — which is most of them. It
also produces *false information*, which is worse than no test, because a gate consumes it.

**Required shape:** real account → real `POST /auth/login` with a fresh, never-replayed TOTP →
the same endpoint the browser calls (`/user/chat/completions`; direct `/v1/chat/completions`
from a browser 401s by design) → assert the EFFECT.

**Permitted exceptions, both narrow:**
1. **Verification by observation.** The ACTION goes through the user pathway; the EVIDENCE may
   come from the product's own record (audit chain, decision log, DB row). Nothing there drives
   the product.
2. **Properties with no user-plane surface.** L1 netns default-deny is a network-namespace fact.
   Assert it directly, and SKIP with a reason where it cannot be read — never pass by inference.

**When a control cannot be exercised from the user plane on a given profile, SKIP with the
reason.** Never assert a weaker property and report it as the stronger one.

## 5.5 Deploy-mode coverage (added 2026-08-07)

The matrix must state the deploy mode per leg, and must not be satisfied entirely by
`--deploy demo`. `install.sh` sets `YASHIGANI_ENV=dev` for demo and `production` otherwise, and
several controls only engage in production — the pool manager runs `backend=stub` under demo, so
per-identity container isolation is never exercised. A matrix of demo-only legs proves those
paths by code-reading, not by runtime. At least one leg per runtime family must be non-demo.

## 5.6 A tier must PROVE its target, and never invent one (added 2026-08-09)

**Rule:** a tier that cannot resolve the stack it was told to test must FAIL, naming what it
tried. It must never fall back to a default address, and it must never accept a bare status
code as proof of life.

This rule exists because its absence cost an entire campaign. `run_tier_b()` validated
`--target` and then never exported it to the tests. `_resolve_base_url()` therefore probed
`localhost:8443` → `localhost` → `localhost:8080` and, when none was the stack, **returned the
hardcoded default anyway**. Two things answered `200` on those ports — a leftover
`rootlessport` from a torn-down leg, and Caddy itself, which routes by Host and returns an
empty `200` catch-all for `localhost` — so the probe "succeeded".

Consequences, measured:
* Every Tier-B test on every leg ran against an endpoint that returns `200` with an empty body
  to everything, including `/healthz`.
* Login returned `200`, zero-length, no `Set-Cookie`; the browser never got a session; every
  `admin_ctx` fixture landed on `/admin/login`.
* **110 fixture errors per leg**, identical on docker and podman, headed and headless, across
  ~6 full runs ≈ 660 phantom failures and ~18 hours of browser wall-clock.
* Three successive wrong diagnoses (auth throttle, `SameSite=Strict`, HTTP client), each with a
  fix that changed nothing. `curl` "worked" and `httpx` "failed" because they were pointed at
  different hosts.

**Required of every tier:**
1. The runner MUST export the resolved target to the tests (`YASHIGANI_ADMIN_URL`). Accepting
   `--target` and not passing it on is a defect, not an omission.
2. Liveness MUST be content-verified — a non-empty `/healthz` body that identifies the product.
   A status code alone proves only that *something* is listening.
3. On failure, RAISE and list every candidate tried. Silence plus a default is how a suite
   spends 18 hours testing nothing.
4. The leg pre-flight (§YSG-RISK-207) checks the SAME resolution path the tests use. A
   pre-flight that passes while the suite resolves elsewhere — which is exactly what happened
   here — provides false assurance.

**Corollary for triage:** when many tests fail identically across runtimes AND browser modes,
suspect the shared input (target, credentials, fixture) before any product subsystem. A defect
that is invariant across every axis you vary is not in the thing you are varying.

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

## 5.7 SIGKILLing an install poisons every later install (added 2026-08-12)

**This is a TEST-RIG discipline note, not an installer defect.** The installer was working
correctly throughout; the damage was self-inflicted by `kill -9` on a hung install.

`install.sh` holds an flock at `/run/lock/yashigani-install.lock` for its lifetime and releases
it on exit. When the installer is SIGKILLed it never reaches that exit path, and its orphaned
children (observed: `tee`, `python3`, plus `conmon`/`pasta`) were still holding the lock 20 hours
later. Every subsequent install — podman 4.9, 5.1.2, 6.0.1 alike — then died immediately after
the banner with exit 1 and a ~510-byte log. Clearing the orphans restored normal installs
immediately, with no change to `install.sh`.

**Do:** stop a stuck install with SIGTERM first and let it unwind. Reserve `kill -9` for when
that fails, and clean up after it.

**Before diagnosing any "install fails instantly" symptom:**
```bash
fuser -v /run/lock/yashigani-install.lock     # who holds it
flock -n /run/lock/yashigani-install.lock -c true && echo FREE
```

**Open question, NOT yet a finding:** install.sh:19285 states the lock fd is FD_CLOEXEC so
children never inherit it, yet `tee` was observed holding it after SIGKILL. That may be a real
gap in the guarantee or an artefact of how the log pipeline is set up. It needs a controlled
test before anyone files it as a defect — do not cite this note as proof that CLOEXEC is broken.

## 5.8 `$?` must be captured IMMEDIATELY, and never after a pipeline (added 2026-08-12)

Three separate false-greens in one campaign, all the same bug:
- `USERS_INSTALLER_EXIT=$?` after `python … | tail -25` captured **tail's** status → a dead users
  installer reported 0. Fixed with `${PIPESTATUS[0]}`.
- `install-podman.sh` printed `INSTALL_EXIT_CODE=$?` at the end of the script → a failed install
  reported 0, and a proof run recorded "install exit=0" while `healthz` was 000.
- A wrapper read `$?` of a `nohup … &` launcher and reported the job as complete.

Rule: capture into `rc=$?` on the line IMMEDIATELY after the command, use `${PIPESTATUS[0]}` for
pipelines, and `exit $rc` so the status propagates. A tier/leg/install that cannot prove its own
exit status is NOT RUN, not GREEN (same principle as YSG-RISK-206).

## 5.9 Podman 5.x/6.x healthchecks need the storage flags (added 2026-08-12)

Podman generates healthcheck systemd units as `ExecStart=<binary> healthcheck run <id>` — the
BARE binary, with only `PATH` in the unit environment. The side-by-side 5.x/6.x prefixes rely on
`--root/--runroot` for isolation (5.1.2 ignores storage.conf's `runroot`), so every generated
healthcheck ran against the DEFAULT storage, failed `no such container`, and left every
container `(starting)` forever — `install.sh` then waited on convergence that could never
happen (20h lost, 2026-08-11).

Fix: a shim at the exact binary path the units invoke
(`podman-versions/podman-<v>/usr/bin/podman`) that injects `--root/--runroot` and execs
`podman.real`. Verified: the failing `healthcheck run` command exits 0 and the container reports
`healthy`.

## 5.10 One TOTP secret = ONE window record (added 2026-08-12)

The anti-replay ledger was keyed on the PURPOSE of the code, not the identity that
owns it: `do_admin_stepup()` waited on `stepup:admin1`, while the admin login path kept
private state (`_api_totp_last_used`) and published to the shared ledger not at all.
So a login spent a code, step-up saw an empty ledger, ran inside the SAME 30s window,
and the server rejected the replay -> `401 invalid_totp_code`.

**The server is correct. Anti-replay is a control.** Never "fix" this by widening the
server's replay window or by retrying until a code sticks.

**Required:** every path that consumes a TOTP code for identity X — browser login, API
login, step-up, a diagnostic script — waits on and marks the SAME ledger key for X.

**Corollary for operators:** do not run a manual login/verification script next to a
live test run. The ledger is per-process, so an external script silently spends the
window the suite is about to use and the suite fails with a credential error that looks
like a product fault. This cost several false diagnoses on 2026-08-12.

## 5.11 Provision test users through BOTH pathways (added 2026-08-12)

`test_user_provisioning_mixed.py` creates 3 end users through the real admin UI form and
2 through `POST /admin/users`, then asserts the cap refuses the 6th.

Rationale (Tiago, 2026-08-12): a suite that only ever creates users over the API proves
the endpoint and nothing about the form. That is the blind spot behind LAURA-001 (broken
chat UI shipped three times, every API test green) and YSG-RISK-137 (browser step-up
universally broken, because step-up was only ever verified by direct `/auth/stepup`
calls). Creating through the UI drives the ui4 step-up modal end-to-end, which is the
only way that path is covered.

Every UI creation is confirmed by a subsequent API read — a form that appears to succeed
but persists nothing must FAIL (effect-verified, 5.3).

**Do not delete this in favour of the API-only version because it is slower or flakier.**
The UI path is the one that has repeatedly shipped broken.

**populate-demo.py stays the demo seeder** (Tiago, 2026-08-12: "keep the populate script
for demos don't erase it"). This test provisions users for TEST runs; it does not replace
demo seeding.

## 5.12 ONE login session per run; brute-force and injection lanes run LAST (added 2026-08-13 — Tiago directive)

**Rule, verbatim:** *"login once, test it all, no more login again and again and again. One
login session you run all but the brute force testing or injections."*

1. **Authenticate ONCE per identity per run** and reuse that session for the entire functional
   sweep. Session-scoped auth fixtures, not function-scoped. Refresh ONLY on genuine
   expiry/server-side eviction — never on a timer, never per test/class/file.
2. **Brute-force, auth-abuse and injection lanes run LAST**, as their own stage, after the
   functional sweep has completed and its evidence is captured. Never interleaved.

### Why — both halves are measured, not theoretical (4.1.2 docker leg, 2026-08-13)

**Cost of re-login.** Every fresh login pays the TOTP anti-replay wait — up to **62s**
(`conftest.py:1910-1913`, `max(62 - elapsed, …)`) under the one-code-per-identity-per-window
rule (§5.10). A test doing ~5 fresh logins burns ~310s in sleeps alone. That is what blew the
300s per-test ceiling and killed the headed leg at 17% (FIND-0813-011), and it is why Tier-B
takes ~1h17m per browser mode.

**Cost of interleaving.** The auth throttle is keyed on account **AND source IP** (correct
anti-enumeration design). The adversarial lane's deliberate bad-credential probes drove
`ip_level=5 delay=900s`, and because the delay served is `max(acct_level, ip_level)`
(`auth.py:710`), a single legitimate account failure in the functional lane inherited the full
IP-driven severity. Measured: interleaved → ~50% F/E by 42%; same suite with the adversarial
lane split out → **365/378 clean**. Those failures were self-inflicted, not product defects —
the exact class of false signal this framework exists to eliminate.

### How this interacts with rules already in force
- **§4.17 Rule 5 (lane separation by identity AND source IP)** still applies to the adversarial
  stage — running it last does not remove the requirement that it come from a different source
  IP (a container/netns), because `_real_client_ip()` resolves to the TCP peer, so every
  host-originated request shares one address regardless of process.
- **§5.10 (one TOTP secret = one window record)** becomes largely moot for the functional sweep
  once there is only one login: the wait is paid once, not per test.
- **§5.4 (no bypass)** is unaffected — one session still reaches the product the way a user does.

### Conformance gap in the CURRENT suite (action item, not yet fixed)
`src/tests/playwright/` re-authenticates extensively (`_api_get_session_cookies`,
`playwright_login_admin`, `bootstrap_user_session`, per-fixture `force_fresh=True`,
`refresh_*_context_if_stale`). Bringing it to this rule means session-scoped auth reused across
files, with refresh driven by the `_admin_session_dirty`/`_user_session_dirty` eviction flags
rather than elapsed time. Until that lands, Tier-B legs must at minimum run the adversarial
suite as a separate final stage — which is what the 4.1.2 Linux legs now do.

## 5.13 A verification run requires a QUIESCENT tree (added 2026-08-16 — Tiago directive, applied to Tier-A)

**Rule: never run a tier against a working tree that anything else is concurrently mutating.
The result of such a run is not a weak signal — it is not a signal at all, and must not be
reported as one.**

This is Tiago's standing "don't do parallel test unless they can be fully isolated" applied to
Tier-A, not just to deploy stacks. Parallel *fixing* is encouraged and fast. Parallel fixing
*during* a verification run is a measurement of a moving target.

### What triggered it
2026-08-16: a full Tier-A run (`tests/conformance tests/security tests/contracts tests/install
src/tests`) was started, and five fix agents were then dispatched into the SAME working tree.
The run began clean and accumulated 40+ failures as files changed underneath it. None of those
failures was a product defect. Had that number been reported, it would have been a fabricated
regression — and worse, the inverse is equally possible: an agent's mid-run edit can make a
genuinely failing test pass. A concurrent-tree run can report EITHER direction wrongly.

This is the same defect class the framework already names in §5.6 and FIND-0813-012: a run that
reports a result it did not earn. It is not excused by the runner exiting 0.

### Required practice
1. **Verification is a barrier.** Land the concurrent work first, then run the tier once on a
   still tree. Do not overlap them to save wall-clock.
2. If a tier MUST run while work is in flight, run it against an isolated checkout at a named
   commit — a git worktree under `~/Documents/Claude/` per CLAUDE.md, removed when finished —
   never against the shared tree. State the commit in the verdict line.
3. **A run interrupted by tree mutation is discarded, not interpreted.** Do not salvage a
   subset, do not report "N passed before it got noisy", do not attribute individual failures
   to specific agents. Kill it and re-run.
4. A per-agent suite run (an agent checking its own change) is exempt only for the files that
   agent owns; it is NOT a substitute for the gate run, and its pass/fail count must not be
   quoted as the tier verdict.
5. Corollary for agent reports: when a subagent reports a failure in a file outside its own
   scope while other agents are active, treat that as UNVERIFIED. Re-run on a quiescent tree
   before filing it as a finding or routing it to another owner.

### Why this matters beyond tidiness
Tier-A is matrix-invariant (§3) — it runs once per head and its verdict is inherited by every
runtime leg. A polluted Tier-A verdict therefore propagates to docker, podman and k8s
simultaneously, and it propagates SILENTLY.
