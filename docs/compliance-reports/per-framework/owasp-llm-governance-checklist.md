# OWASP LLM AI Cybersecurity & Governance Checklist — Yashigani 4.1.2 — NOT ASSESSED

**Assessment status:** NOT ASSESSED FOR RELEASE 4.1.2. **No compliance rate is published for this framework.**

**Framework version:** v1.0 — February 2024

**Controls in scope:** 46

**Prior assessment:** v2.23.2 (assessed 2026-05-08) — **verdicts withdrawn 2026-08-16**, finding `YCS-20260816-v4.1.2-TB-01`.

> **No control in this document is asserted to pass, fail, or be out of scope.**
> Yashigani 4.1.2 has not been assessed against this framework. Any statement to
> the contrary that predates this file is withdrawn and must not be relied on.

## Why the previous verdicts were withdrawn

The verdicts previously published here carried no code citation of their own.
Every row's evidence was a pointer of the form `see <pack>.md § <n>` into an internal
compliance working paper that is not part of this repository and is not resolvable by a
customer or a third-party auditor. Evidence by pointer to an absent document is not evidence.

The control identifiers used here were also not confirmed against the canonical OWASP
identifier set, and the assessment was performed against v2.23.2 (2026-05-08) and never
re-run for 4.1.2.

## Control scope (enumeration only — no verdicts)

The control set below records which controls a future assessment would need to
cover. It carries no verdicts and no evidence.

| Control ID | Control name | 4.1.2 status |
|---|---|---|
| GRC.1 | AI governance policy documented and owned | NOT ASSESSED |
| GRC.2 | AI use-case registry with risk classification | NOT ASSESSED |
| GRC.3 | AI risk register maintained | NOT ASSESSED |
| ASSET.1 | AI model inventory file present | NOT ASSESSED |
| ASSET.2 | Model registry or config references model identifiers | NOT ASSESSED |
| ASSET.3 | Third-party AI service dependencies documented | NOT ASSESSED |
| TM.1 | AI threat model documented | NOT ASSESSED |
| TM.2 | Attack surface reviewed on major AI changes | NOT ASSESSED |
| TRAIN.1 | Training data provenance documented | NOT ASSESSED |
| TRAIN.2 | PII scrubbed from training datasets | NOT ASSESSED |
| TRAIN.3 | Data poisoning detection controls | NOT ASSESSED |
| MSEC.1 | Model digest pinning in gateway config | NOT ASSESSED |
| MSEC.2 | Model card or model documentation present | NOT ASSESSED |
| MSEC.3 | Access controls on model artefacts | NOT ASSESSED |
| SC.1 | Dependency manifest committed to source control | NOT ASSESSED |
| SC.2 | SBOM generation in release pipeline | NOT ASSESSED |
| SC.3 | Container image signing in release pipeline | NOT ASSESSED |
| SC.4 | Supplier security policy covering AI components | NOT ASSESSED |
| DEPLOY.1 | Authentication required on inference endpoints | NOT ASSESSED |
| DEPLOY.2 | Rate limiting enforced on inference endpoints | NOT ASSESSED |
| DEPLOY.3 | Security headers present on AI API endpoints | NOT ASSESSED |
| DEPLOY.4 | Input validation on inference request parameters | NOT ASSESSED |
| DEPLOY.5 | Outbound URL validation preventing SSRF from AI tool calls | NOT ASSESSED |
| DEPLOY.6 | Secrets managed via KMS or environment injection, not hardcoded | NOT ASSESSED |
| OPS.1 | Audit logging of AI inference calls | NOT ASSESSED |
| OPS.2 | Audit log retention policy configured | NOT ASSESSED |
| OPS.3 | Anomaly and threshold alerting configured | NOT ASSESSED |
| OPS.4 | Metrics exported for AI inference observability | NOT ASSESSED |
| IR.1 | Incident response plan covers AI-specific scenarios | NOT ASSESSED |
| IR.2 | Model rollback procedure documented | NOT ASSESSED |
| IR.3 | Vulnerability disclosure process for AI components | NOT ASSESSED |
| LEGAL.1 | EU AI Act risk classification documented (where applicable) | NOT ASSESSED |
| LEGAL.2 | GDPR / data protection obligations assessed for AI processing | NOT ASSESSED |
| LEGAL.3 | IP and copyright terms reviewed for training/fine-tuning data | NOT ASSESSED |
| LEGAL.4 | Contract terms for AI API usage reviewed | NOT ASSESSED |
| REDTEAM.1 | AI red-team scope documented | NOT ASSESSED |
| REDTEAM.2 | Prompt injection tests in CI/CD pipeline | NOT ASSESSED |
| REDTEAM.3 | Assurance findings tracked to closure | NOT ASSESSED |
| ETHICS.1 | Responsible AI principles documented and published | NOT ASSESSED |
| ETHICS.2 | AI-generated output labelled as AI-generated | NOT ASSESSED |
| ETHICS.3 | Human oversight mechanism for high-stakes AI decisions | NOT ASSESSED |
| ETHICS.4 | Bias and fairness assessment for high-risk AI use cases | NOT ASSESSED |
| PRIVACY.1 | PII detection and masking in inference traffic | NOT ASSESSED |
| PRIVACY.2 | Data handling procedures cover AI-processed data | NOT ASSESSED |
| PRIVACY.3 | Purpose limitation enforced for AI data processing | NOT ASSESSED |
| PRIVACY.4 | Configurable data retention with auto-deletion | NOT ASSESSED |

## What is required before any verdict is published here

A verdict may be re-published in this file only when all of the following hold
for the release being assessed:

1. The control text is taken from the canonical published framework source, at the correct
   framework version, using canonical control identifiers.
2. Each verdict cites a `file:line` in this repository, at the assessed commit, that a reader
   can open and check without access to any internal or non-shipped document.
3. The cited code was read, not pattern-matched, and the reviewer recorded the attacker
   scenario the control was tested against.
4. Absence of an expected artefact is recorded as NEEDS REVIEW, never as PASS.
5. Any headline rate is recomputed from the verdicts in that same file at that same commit.

Until then this report asserts nothing.

## Prior working papers

The withdrawn v2.23.2 assessment and its working papers are retained in Agnostic
Security's internal compliance archive, outside this repository, for audit-trail
purposes. They are superseded and are not offered as evidence for any release.

> **Disclaimer.** This report is produced by Agnostic Security Ltd against its own
> product and is not a substitute for independent assessment. For an audit opinion, engage a
> qualified third-party auditor. *We don't replace your auditor — we make their job easier.*
