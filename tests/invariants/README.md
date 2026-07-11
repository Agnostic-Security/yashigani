# `tests/invariants/` — the release-gate invariant suite

> Owner: Iris (integration / systems-of-systems). Added for the **v3.0** release to close
> Lu's **GATE-1** (`tests/invariants/` ABSENT → L3 release gate NEEDS REVIEW;
> `lu-3.0-readiness-signoff-20260610.md` §4).

## What this is (and is not)

These are **invariants** — properties of the security contract that must hold on **every**
release, written to be **stable across refactors**. They are *not* feature tests: they do
not exercise behaviour end-to-end, they assert the load-bearing contract is **present and
fail-closed** in the code/policy that ships. A green run here means "the v3.0 security
contract did not silently regress."

The thick behavioural coverage (request/response E2E, OPA allow/deny per principal, live
forge/replay probes) lives in `src/tests/` (unit/integration/e2e/security) and in the
**#44 live VM campaign**. This directory is the **thin gate** that proves the contract
still exists so a refactor can't quietly delete it.

Run as the release gate:

```
pytest tests/invariants/ -q
```

(`yashigani` resolves from `src/`; pure-Python + file/text assertions, no live stack, no
Helm/OPA binary required — CI-portable, mirroring `tests/contracts/`.)

## Invariant → test-file map

| # | Invariant (must ALWAYS hold) | File | Grounded in |
|---|------------------------------|------|-------------|
| I1 | Every-hop OPA, data plane, both legs, **fail-closed** (OPA-unreachable ⇒ deny, never fail-open) on the CONFORMS surfaces (chat `/v1/*`, agent `/agents/*`, catch-all/MCP proxy req+resp) | `test_i1_opa_every_hop_fail_closed.py` | Iris S1/S3/S4 audit; GAP-002 now closed |
| I2 | Admin plane is **NOT OPA-gated by design** — `/admin/*` authorises via AdminSession/StepUp (+SPIFFE-on-writes), never via an OPA authz query (lock the deliberate boundary; the PII-paradox guard) | `test_i2_admin_plane_not_opa_gated.py` | Iris S7/GAP-003 design-call; Lu §2.1 |
| I3 | Trust-domain isolation — a non-legacy instance ACCEPTS its own `<project>.yashigani.internal` and REJECTS foreign/legacy across the six F1–F6 validators; legacy unchanged | `test_i3_trust_domain_isolation.py` | Nico MI-6 review (F1–F6) |
| I4 | De-tokenize — identity+tenant-bound + single-use; cross-identity / cross-tenant / unbound reveal ⇒ deny; handle/secret never leaks | `test_i4_detokenize_binding.py` | Lu §2.2; `pseudonymize.py` |
| I5 | Capability-envelope — invocation fail-closed on unpinned/blocked tool; sidecar escalate-to-block-**only**; drift measured vs **ORIGINAL** baseline | `test_i5_capability_envelope.py` | Lu §2.2; `mcp/_envelope.py` |
| I6 | Signed orchestration principal — verified claim only; forged / replayed / wrong-audience ⇒ reject fail-closed | `test_i6_signed_principal.py` | Lu §2.2; `gateway/principal_token.py` |
| I7 | Fail-closed everywhere — extraction-fail/incomplete ⇒ BLOCK; the 4 document actions' default-BLOCK posture | `test_i7_fail_closed_document.py` | Lu §2.1; `policy/document.rego` |
| I8 | Rego bundle parity — compose↔helm policy files byte-identical (the drift class Iris fixed twice; LAURA-OPA-002) | `test_i8_rego_bundle_parity.py` | Iris drift map; `tests/contracts/test_helm_opa_bundle_parity.py` |

## Code-asserted-here vs live-VM (#44) proof

These tests assert the **code-level contract**. Where an invariant can only be *proven*
on a live stack (real OPA-unreachable network behaviour, two live instances cross-rejecting
leaf certs, real forge/replay over the wire), the test asserts the in-code contract and the
live proof is flagged as a **#44 / VM item** in each file's module docstring under
`LIVE-PROOF (#44)`. We do **not** fake the live behaviour here.

| Invariant | Asserted here | Live #44 / VM proof still required |
|---|---|---|
| I1 | fail-closed return paths + startup-mandatory-OPA guard present in code | real OPA-down deny over the wire, per-principal both-legs |
| I2 | no OPA authz query in any `/admin/*` route module | live admin-plane denial-without-OPA walk |
| I3 | all six validators source `trust_domain()`; accept-own / reject-foreign string logic | **two live instances** leaf-cert cross-rejection |
| I4 | reveal binding/single-use/no-leak contract in code | live cross-principal/cross-tenant reveal probe |
| I5 | diff-vs-ORIGINAL + escalate-only + fail-closed-default in code | live MCP rug-pull probe |
| I6 | sign/verify forge+replay+audience rejection in code | live forged/replayed claim over the wire |
| I7 | `default action := "BLOCK"` + BLOCK-on-incomplete in rego | live doc round-trip post-converge |
| I8 | byte-identical compose↔helm (fully proven here — no live gap) | — |
