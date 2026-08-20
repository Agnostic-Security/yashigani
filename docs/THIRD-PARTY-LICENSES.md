<!-- Last-Updated: 2026-05-24T07:42:00+01:00 -->

# Third-Party Components — License Attribution

Yashigani is itself distributed under the [Apache License 2.0](../LICENSE). The platform integrates a number of third-party open-source components, each governed by its own license. This document lists the components Yashigani ships or depends on at runtime, the upstream project, the version pinned by the reference compose / Helm artefacts, the upstream SPDX license identifier, and the upstream source URL.

This attribution is provided in good faith to satisfy the notice obligations of the listed third-party licenses and to make it easy for operators to verify license compatibility before deployment. **It is not a substitute for an operator's own license-compatibility review.** Operators redistributing Yashigani in modified or repackaged form remain responsible for ensuring their distribution complies with each upstream license.

## How to read this document

- **Component** — the third-party project Yashigani integrates with or ships pinned via the reference compose / Helm artefacts.
- **Version (pinned)** — the version pinned at the time of this document's `Last-Updated` header. Operators may run different versions; the upstream license applies to whichever version is actually deployed.
- **SPDX identifier** — the upstream-declared SPDX license expression.
- **Upstream source** — the canonical upstream repository URL where the full license text is available.
- **Notes** — any non-trivial restriction, dual-license consideration, or operational caveat operators should be aware of.

## 1. Runtime container images (reference compose / Helm)

| Component | Version (pinned) | SPDX | Upstream source | Notes |
|---|---|---|---|---|
| **Caddy** | `2.11.2-alpine` | `Apache-2.0` | https://github.com/caddyserver/caddy | Reverse proxy / auth perimeter (`docker/Caddyfile.*`). |
| **Open Policy Agent (OPA)** | `1.16.1` | `Apache-2.0` | https://github.com/open-policy-agent/opa | Policy decision point for routing + agent-to-agent calls. |
| **PostgreSQL (pgvector image)** | `0.8.2-pg16` | `PostgreSQL` | https://github.com/pgvector/pgvector ; https://www.postgresql.org/about/licence/ | Primary database. pgvector extension under the PostgreSQL License. |
| **Redis** | `7.4.9-alpine` | `RSALv2 OR SSPLv1` | https://github.com/redis/redis | Redis Inc. dual-licensed starting Redis 7.4 (RSALv2 / SSPLv1). Operators with redistribution use cases should review the dual-license terms upstream. |
| **pgbouncer (edoburu image)** | `v1.25.1-p0` | `MIT` (image scripts) ; `BSD-3-Clause-like` (pgbouncer itself) | https://github.com/edoburu/docker-pgbouncer ; https://github.com/pgbouncer/pgbouncer | Connection pooler used by `letta-pgbouncer` sidecar. |
| **Prometheus** | `v3.11.3` | `Apache-2.0` | https://github.com/prometheus/prometheus | Metrics. |
| **Alertmanager** | `v0.32.1` | `Apache-2.0` | https://github.com/prometheus/alertmanager | Alert routing. |
| **Grafana** | `13.0.1` | `AGPL-3.0` | https://github.com/grafana/grafana | Dashboards. Grafana adopted AGPL-3.0 from v8.0 onwards. **Operators distributing Yashigani-as-a-service over a network should review their AGPL obligations.** Yashigani itself does not modify Grafana — the upstream image is shipped unmodified. |
| **Grafana Loki** | `3.7.1` | `AGPL-3.0` | https://github.com/grafana/loki | Log aggregation. Same AGPL-3.0 considerations as Grafana. |
| **Grafana Promtail** | `3.6.10` | `AGPL-3.0` | https://github.com/grafana/loki (clients/cmd/promtail) | Log shipper for Loki. Same AGPL-3.0 considerations. |
| **OpenTelemetry Collector Contrib** | `0.151.0` | `Apache-2.0` | https://github.com/open-telemetry/opentelemetry-collector-contrib | Telemetry pipeline. |
| **Jaeger** | `2.17.0` | `Apache-2.0` | https://github.com/jaegertracing/jaeger | Distributed tracing. |
| **Keycloak** | `26.6.1` | `Apache-2.0` | https://github.com/keycloak/keycloak | Identity provider (optional). |
| **HashiCorp Vault** | `2.0.0` (Vault Enterprise lineage — verify pinned upstream lineage at deploy time) | `BUSL-1.1` (Change License: `MPL-2.0` after 4 years) | https://github.com/hashicorp/vault | **License change:** HashiCorp moved Vault from MPL-2.0 to BUSL-1.1 in August 2023. Operators evaluating Yashigani's Vault integration should review BUSL-1.1 production-use restrictions. The community-maintained MPL-2.0 fork [OpenBao](https://openbao.org/) is a drop-in alternative; Yashigani's integration is configurable and not Vault-locked. |
| **Ollama** | `0.23.1` | `MIT` | https://github.com/ollama/ollama | Local LLM runtime. |
| **Wazuh Manager** | `4.14.5` | `GPL-2.0` (with OpenSSL linkage exception) | https://github.com/wazuh/wazuh | SIEM (optional, `--wazuh` flag). |

## 2. Agent bundles (optional, `--agent-bundles` flag)

Each agent bundle is gated behind an explicit installer flag (`--agent-bundles` enables langflow/letta/openclaw compose profiles). Operators not enabling agent bundles do not ship these images.

| Component | Version (pinned) | SPDX | Upstream source | Notes |
|---|---|---|---|---|
| **Langflow** | `1.9.2` | `MIT` | https://github.com/langflow-ai/langflow | Visual agent / flow builder. |
| **Letta** | `0.16.7` | `Apache-2.0` | https://github.com/letta-ai/letta | Stateful agent runtime. |
| **OpenClaw** | `2026.5.6` | `MIT` | https://github.com/openclaw/openclaw | MCP-adjacent agent tooling. |

## 3. Open WebUI (optional, `--with-openwebui` flag)

Open WebUI is shipped under a **modified BSD-3-Clause license** that imposes a non-standard branding restriction. This restriction is the basis for the platform's internal posture on Open WebUI handling.

| Component | Version (pinned) | License | Upstream source | Notes |
|---|---|---|---|---|
| **Open WebUI** | `v0.9.2` | BSD-3-Clause with branding restriction | https://github.com/open-webui/open-webui | The Open WebUI license prohibits removal or alteration of "Open WebUI" branding except for deployments with fewer than 50 end users in 30 days, with explicit written permission from the upstream maintainers, or under an enterprise license. **Yashigani ships the upstream image unmodified, routes traffic via Caddy + forward_auth, and configures only via environment variables.** Yashigani does not patch the Open WebUI source, modify the image, alter or remove its branding, white-label it, or bypass any free-tier mechanism. Operators redistributing Yashigani in modified form must observe these branding restrictions themselves. |

## 4. Build-time and CI-only third-party components

The following components are used by Yashigani's build, CI, or operator-side tooling but are not shipped as part of the runtime deployment artefact. They are listed for completeness; operators do not need to vendor them.

- **trivy** (`Apache-2.0`) — image vulnerability scanning. https://github.com/aquasecurity/trivy
- **cosign / sigstore** (`Apache-2.0`) — release signature verification. https://github.com/sigstore/cosign
- **gitleaks** (`MIT`) — secret-scanning CI gate. https://github.com/gitleaks/gitleaks
- **checkov** (`Apache-2.0`) — Helm/IaC scanning CI gate. https://github.com/bridgecrewio/checkov
- **Kyverno** (`Apache-2.0`) — admission-policy gate (Helm path). https://github.com/kyverno/kyverno
- **Opengrep** (`LGPL-2.1`) — SAST scanning. https://github.com/opengrep/opengrep

## 5. Trademark notice

The names "Yashigani", "Agnostic Security", and the Yashigani logo are trademarks of Agnostic Security Ltd. The names and logos of all third-party components listed above are trademarks or registered trademarks of their respective owners; their appearance in this document is for attribution and identification purposes only and does not imply endorsement.

## 6. Reporting attribution gaps

If you spot a component used by Yashigani that is not attributed in this document, or a license identifier or restriction that has changed upstream since the `Last-Updated` header above, please open an issue at https://github.com/Agnostic-Security/yashigani/issues with the label `license-attribution`.

---

**Note on scope.** This document attributes third-party components shipped or depended upon by Yashigani at runtime, plus the build-time / CI tooling listed in §4. It does not cover the transitive dependencies of those components (each upstream project maintains its own attribution); operators conducting their own license audits should consult each upstream project's own license documentation.
