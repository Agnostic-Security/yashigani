# OWASP Agentic AI Top 10 — Yashigani 4.1.2 — NOT ASSESSED

**Assessment status:** NOT ASSESSED FOR RELEASE 4.1.2. **No compliance rate is published for this framework.**

**Framework version:** 2025 edition (working draft, GitHub canonical)

**Controls in scope:** 10

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
| AGT1 | Agent Identity Spoofing | NOT ASSESSED |
| AGT2 | Privilege Escalation | NOT ASSESSED |
| AGT3 | Prompt Injection | NOT ASSESSED |
| AGT4 | Credential Exfiltration | NOT ASSESSED |
| AGT5 | Data Exfiltration | NOT ASSESSED |
| AGT6 | Agent-to-Agent Content Laundering | NOT ASSESSED |
| AGT7 | Container Escape | NOT ASSESSED |
| AGT8 | Model Poisoning | NOT ASSESSED |
| AGT9 | Budget Exhaustion | NOT ASSESSED |
| AGT10 | Audit Evasion | NOT ASSESSED |

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
