# Helm vs Docker/Podman Compose — Deployment Footprint Differences

**Finding:** B11 — DRIFT-001 (Iris) / Lu A.8.15/A.8.16  
**Resolution:** v2.25.0 P2 wave 2  

This document explicitly enumerates the components available in Yashigani's
Docker/Podman Compose deployment that are **not** present in the Helm/Kubernetes
chart. Auditors and operators MUST consult this table when mapping compliance
controls to deployment topology.

## Component Parity Matrix

| Component            | Compose (Docker/Podman) | Helm/Kubernetes | Notes                                                                                 |
|----------------------|-------------------------|-----------------|---------------------------------------------------------------------------------------|
| Wazuh Manager        | YES                     | NO              | K8s: deploy external Wazuh cluster; forward logs via Fluent Bit or Logstash          |
| Wazuh Indexer        | YES                     | NO              | (same — part of 3-container Wazuh stack)                                              |
| Wazuh Dashboard      | YES                     | NO              | (same — part of 3-container Wazuh stack)                                              |
| Keycloak IdP         | NO                      | NO              | Planned; use external OIDC provider + Caddy forward_auth                             |
| HashiCorp Vault      | NO                      | NO              | Use external-secrets-operator for K8s secret injection                               |
| step-ca (ACME CA)    | NO                      | NO              | Use cert-manager with Let's Encrypt or internal CA                                   |
| Promtail log agent   | NO                      | NO              | K8s: Loki discovers logs natively via Kubernetes service discovery                   |
| OpenClaw full UI     | Partial                 | Partial         | API gateway mode only; full UI requires separate host configuration                  |
| Audit log (always-on)| YES (bind-mounted)      | Opt-in (`auditLog.enabled=true`) | K8s default is emptyDir (non-persistent); see values.yaml |

## Wazuh on Kubernetes

The Helm chart explicitly blocks `wazuh.enabled=true` at `helm install/upgrade`
time with a configuration error. This prevents false compliance posture where an
operator sets the flag believing SIEM is running when no Wazuh templates exist.

**Migration path for K8s SIEM:**
1. Deploy an external Wazuh cluster (Wazuh Cloud or self-hosted).
2. Configure Fluent Bit as a DaemonSet to forward container logs to the Wazuh
   indexer.
3. Update your compliance control evidence to reference the external cluster,
   not the Yashigani chart.

## Audit Log Durability Gap

On Docker/Podman Compose, audit logging is always-on: logs write to a
bind-mounted host directory that persists across container restarts and is
captured by the backup CronJob.

On Kubernetes, `auditLog.enabled` defaults to `false`. In this state:
- Logs write to an `emptyDir` volume (50 MiB).
- Pod restarts wipe the audit trail.
- The PVC-backed audit path is only active when `auditLog.enabled=true`.

Compliance controls under SOC 2 CC7.2, ISO 27001 A.8.15, NIST AU-9/AU-11,
CMMC AU.L2-3.3.4/8/9, and EU AI Act Art.12 require durable audit records.
`auditLog.enabled=false` does NOT satisfy these controls.

**Action required:** Set `auditLog.enabled=true` in production K8s deployments.

## Impact on Compliance Posture

If your organisation's compliance mapping references Wazuh SIEM as an active
control, the following MUST be updated:

- ISO 27001 A.8.15 (Monitoring activities): must reference external SIEM.
- ISO 27001 A.8.16 (Monitoring activities): same.
- SOC 2 CC7.2 (Monitoring of system components): same.
- Any GRC tool entries (Drata, Vanta, Secureframe) that cite "Wazuh active on
  Kubernetes" must be corrected before the next audit cycle.

## Version History

| Version | Change |
|---------|--------|
| v2.25.0 | Added this document; added explicit `wazuh.enabled` guard in chart |
