# Yashigani Compliance Reports — 4.1.2

**Status: Yashigani 4.1.2 has not been assessed against any compliance framework.**
No report in this directory asserts that any control passes. No compliance rate is published.

## What happened to the previous contents

Until 2026-08-16 this directory published per-control verdicts for 20 frameworks — 1,062 PASS
verdicts and 24 headline percentages, including 100.0% figures for FedRAMP Moderate, CMMC 2.0
Level 2, the HIPAA Security Rule and DORA.

Those verdicts and percentages are **withdrawn in full** under finding
`YCS-20260816-v4.1.2-TB-01`. The reasons, in order of severity:

1. **Roughly 700 of the 1,062 PASS verdicts were not assessments.** Their entire evidence was a
   keyword substring match in an unrelated repository file. The published example that makes
   the class clearest: `CC6.6 Encryption in transit | PASS | Found 'https' in
   scripts/generate_training_data.py`. In the worst-affected reports the share reached 99%
   (NIST SP 800-53 Moderate) and 98% (ISO/IEC 27001:2022).

2. **Four frameworks were published at 100.0% that could not have been at any figure.**
   Yashigani holds no FedRAMP ATO, has had no CMMC C3PAO assessment, and runs no Business
   Associate Agreement programme.

3. **The OWASP ASVS report was mislabelled.** It was published as ASVS v5 while using the ASVS
   v4 chapter taxonomy, and 38% of its control identifiers are not ASVS v5 controls.

4. **At least one cited evidence file does not exist.** `docs/incident_response_plan.md`, cited
   as the evidence for SOC 2 CC7.4, is not present in this repository.

5. **The whole set described v2.23.2** (assessed 2026-05-08) and shipped unchanged through five
   subsequent releases without re-verification.

The files remain in place, each stating NOT ASSESSED and enumerating its control scope, so that
the withdrawal is visible to anyone who previously relied on the figures. The withdrawn
assessment and its working papers are retained in Agnostic Security's internal compliance
archive, outside this repository, for audit-trail purposes.

## What evidence does exist for 4.1.2

None of the following is a compliance verdict. Each is a runnable or readable artefact in this
repository that a reader can check without trusting a claim in a document:

| Artefact | Path | What it gives you |
|---|---|---|
| Architectural invariant suite | `tests/invariants/` (11 tests, I1–I10) | Executable assertions on OPA every-hop fail-closed, admin-plane authorisation, trust-domain isolation, capability envelope, signed principal, PKI chain of continuity, Rego bundle parity |
| Regression suites | `src/tests/regression/` (per release; 77 files for v4.1.2) | Each closed security finding has a test that fails if the defect returns |
| Control design notes | `docs/security/` | Per-surface design documentation — authentication, SSRF, SQL injection, XFF trust boundary, audit-DB least privilege, agent image scanning, release signing |
| Open findings | `docs/risk-register.yml` | Findings that are open, mitigated, or accepted, with severity |
| Version consistency | `pyproject.toml:8`, `src/yashigani/__init__.py:16` | Both declare `4.1.2`; enforced by `scripts/check-version-consistency.sh` |

Run the invariant suite and the regression suites yourself; do not take a report's word for it.

## What is required before verdicts are republished

1. Control text taken from the canonical published framework source, at the correct framework
   version, using canonical control identifiers.
2. Every verdict citing a `file:line` in this repository, at the assessed commit, that a reader
   can open and check without access to any internal or non-shipped document.
3. The cited code read, not pattern-matched, with the attacker scenario recorded against which
   the control was tested.
4. Absence of an expected artefact recorded as NEEDS REVIEW, never as PASS.
5. Any rate recomputed from the verdicts in the same file at the same commit — and no
   cross-framework headline percentage at all.
6. Re-assessment on every release. A verdict inherited across a release boundary without
   re-verification is an unverified claim, not an inherited one.

No automated gate currently regenerates this directory. Earlier revisions of this file claimed
regeneration "on every release-tag cut, per release-process gate G17"; no such gate exists
anywhere in the repository, and the directory's own five-release staleness disproved it. That
claim is removed rather than softened.

## Disclaimer

Reports in this directory are produced by Agnostic Security Ltd against its own product and are
not a substitute for independent assessment. For an audit opinion, engage a qualified
third-party auditor.

> *We don't replace your auditor — we make their job easier.*
