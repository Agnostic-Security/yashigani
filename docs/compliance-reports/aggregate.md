# Yashigani 4.1.2 — Cross-Framework Compliance Status

**Yashigani release:** 4.1.2
**Status:** **NO CROSS-FRAMEWORK ASSESSMENT HAS BEEN PERFORMED FOR THIS RELEASE.**
**Prior aggregate:** v2.23.2 (2026-05-08) — **withdrawn 2026-08-16**, finding `YCS-20260816-v4.1.2-TB-01`.

> **No compliance rate, control count, or pass rate is published in this document.**
> Any previously published cross-framework figure for Yashigani is withdrawn.

## What was withdrawn and why

The aggregate previously published here reported a **93.0% cross-framework PASS rate** over
842 applicable controls, and per-framework rates including **100.0% for FedRAMP Moderate,
CMMC 2.0 Level 2, HIPAA Security Rule and DORA**.

Those figures are withdrawn in full. Three defects, each sufficient on its own:

1. **The inputs were not assessments.** Approximately 700 of the 1,062 per-control PASS
   verdicts feeding the aggregate had, as their entire evidence, a keyword substring match in
   an unrelated repository file — for example `CC6.6 Encryption in transit | PASS | Found
   'https' in scripts/generate_training_data.py`. The arithmetic was correct; the inputs were
   void. A correct average of fabricated inputs is a fabricated number.

2. **The four 100.0% figures were unsupportable by construction.** Yashigani holds no FedRAMP
   ATO, has had no CMMC C3PAO assessment, and operates no Business Associate Agreement
   programme. A 100.0% figure against FedRAMP Moderate, CMMC 2.0 L2 or the HIPAA Security Rule
   could not have been true regardless of the underlying code.

3. **The figures described a different release.** The assessment ran against v2.23.2 on
   2026-05-08 and shipped unchanged through five subsequent releases without re-verification.

A fourth, lesser defect: this file previously shipped an unrendered template placeholder
(`{len(all_rows)}`) in its interpretation section, which is direct evidence that the document
was emitted by tooling and never read by a human before publication.

## Frameworks in scope for a future assessment

The table records control scope only. **It contains no verdicts and no rates.** Each linked
file states that the framework is NOT ASSESSED for 4.1.2 and enumerates its control set.

| Framework | Controls in scope | 4.1.2 status |
|---|---:|---|
| [OWASP ASVS v5](per-framework/owasp-asvs-v5.md) | 182 | NOT ASSESSED |
| [OWASP Agentic AI Top 10](per-framework/owasp-agentic-ai.md) | 10 | NOT ASSESSED |
| [OWASP LLM Top 10](per-framework/owasp-llm-top-10.md) | 10 | NOT ASSESSED |
| [OWASP LLM Governance Checklist](per-framework/owasp-llm-governance-checklist.md) | 46 | NOT ASSESSED |
| [OWASP API Security](per-framework/owasp-api-security.md) | 38 | NOT ASSESSED |
| [OWASP API Security Top 10](per-framework/owasp-top-10-api.md) | 7 | NOT ASSESSED |
| [OWASP Web Application Top 10](per-framework/owasp-top-10-web.md) | 8 | NOT ASSESSED |
| [PCI DSS v4.0](per-framework/pci-dss-v4.md) | 148 | NOT ASSESSED |
| [SOC 2 Type II](per-framework/soc2-type2.md) | 25 | NOT ASSESSED |
| [ISO/IEC 27001:2022](per-framework/iso-27001-2022.md) | 53 | NOT ASSESSED |
| [NIST SP 800-53 Rev 5 Moderate](per-framework/nist-800-53-moderate.md) | 157 | NOT ASSESSED |
| [NIST CSF 2.0](per-framework/nist-csf-2-0.md) | 61 | NOT ASSESSED |
| [FedRAMP Moderate](per-framework/fedramp-moderate.md) | 42 | NOT ASSESSED |
| [HIPAA Security Rule](per-framework/hipaa-security.md) | 51 | NOT ASSESSED |
| [GDPR](per-framework/gdpr.md) | 5 | NOT ASSESSED |
| [EU AI Act](per-framework/eu-ai-act.md) | 31 | NOT ASSESSED |
| [DORA](per-framework/dora.md) | 17 | NOT ASSESSED |
| [NIS 2 Directive](per-framework/nis2.md) | 14 | NOT ASSESSED |
| [CMMC 2.0 Level 2](per-framework/cmmc-l2.md) | 33 | NOT ASSESSED |
| [Infrastructure Security baseline](per-framework/infrastructure.md) | 7 | NOT ASSESSED |

"Controls in scope" is the size of the control set a future assessment would need to cover.
It is not a coverage figure and implies no result.

## Why no aggregate number will be republished

A single cross-framework percentage averages control sets of incompatible scope and weight —
PCI DSS v4.0 carries 148 applicable controls and GDPR carries 5; they do not share an axis.
Even computed from sound inputs, the number would mislead. Future reporting will be
per-framework only, with per-control evidence, and no cross-framework headline.

> **Disclaimer.** Reports in this directory are produced by Agnostic Security Ltd against its
> own product and are not a substitute for independent assessment. For an audit opinion,
> engage a qualified third-party auditor.
