# Yashigani Pre-Installation Checklist

**Version:** v2.23.2
**Last updated:** 2026-05-07
**Purpose:** Everything you must gather, configure, or verify *before* running `install.sh` or `docker compose up`. The automated installer handles software installation and secret generation — but it cannot know your infrastructure topology, DNS records, upstream server addresses, or credentials for external services. Collect all items marked **Required** before you start.

> **Last public release — v2.23.2**
>
> v2.23.2 is the final public release of Yashigani. Future development moves to a private tier.
>
> - **Existing public users:** this release will remain available; no automatic deprecation.
> - **Continued updates (v2.23.3+):** require a paid licence — see [agnosticsec.com/yashigani/licensing](https://agnosticsec.com/yashigani/licensing).
> - **Free tier (Community):** continues with v2.23.2; security patches delivered under the published support window.
> - **Non-profit and education:** access remains free forever — see [agnosticsec.com/yashigani/non-profit](https://agnosticsec.com/yashigani/non-profit).
> - **Public repository:** transitions to a private programme **by end of Q2 2026 (2026-06-30)**, subject to Petra IP review milestone confirmation.

---

## How to Use This Document

Work through each section that applies to your deployment. Items marked:

- **Required** — installer will fail or Yashigani will not start without this
- **Required for mode** — only required if you choose that TLS/KMS/SSO/SIEM option
- **Recommended** — safe defaults exist but you should set this for production
- **Optional** — only needed if you enable that feature

At the end of each section there is a short checklist you can print and tick off.

---

## Section 1 — Core Infrastructure (All Installations)

These items are required regardless of deployment mode.

### 1.1 Server

| Item | Required? | Where Used | Example |
|------|-----------|------------|---------|
| Server IPv4 address | Required | DNS A record, firewall rules | `203.0.113.42` |
| Server hostname/FQDN | Required | `YASHIGANI_TLS_DOMAIN` | `mcp-gateway.example.com` |
| Operating system and version | Required | Installer picks correct Docker install method | Ubuntu 22.04 LTS x86_64 |
| CPU architecture | Required | Installer selects correct image variants | `amd64` or `arm64` |
| Available RAM (GB) | Required | Preflight check — minimum 2 GB, 4 GB for Ollama | 8 GB |
| Available disk on Docker data root (GB) | Required | Preflight check — minimum 10 GB. On macOS, `preflight.sh` uses `df -k` (POSIX-compatible) instead of `df -BG` (GNU-only). | 50 GB |
| Shell | Informational | Preflight reports the user's login shell (`$SHELL`) — typically zsh on modern macOS. The installer is compatible with bash 3.2+ (macOS default) and zsh 5+. | zsh 5.9, bash 5.2 |

### 1.2 Upstream MCP Server

Yashigani proxies ALL traffic to one primary upstream. You must know where it is.

| Item | Required? | Notes |
|------|-----------|-------|
| Upstream MCP server URL (base URL) | **Required** | `UPSTREAM_MCP_URL`. Must be reachable from the Docker internal network. If on the same host, use the host's internal IP, not `localhost` (Docker networking). |
| Protocol (HTTP or HTTPS) | Required | If HTTPS, ensure the container can validate or skip TLS for internal servers. |
| Authentication the upstream expects | Recommended | Yashigani strips agent credentials from payloads *it* inspects, but must still forward auth to the upstream. Confirm upstream auth scheme (bearer token, mTLS, API key header). |
| MCP tool paths/endpoints | Recommended | Used when writing OPA policy rules (`/tools/read`, `/tools/write`, etc.). List all paths agents will call. |
| Expected request body size | Recommended | Default limit is 4 MB. If your MCP tools receive larger payloads, increase `YASHIGANI_BODY_LIMIT_MB`. |

> **Note:** If you have multiple upstream MCP servers, Yashigani v0.6.0 routes to one primary upstream. Use path-based OPA policy to allow/deny specific sub-paths per agent.

### 1.3 Network and Firewall

| Port | Direction | Required? | Service |
|------|-----------|-----------|---------|
| 80/tcp | Inbound | Required (ACME mode) or redirect | Caddy HTTP → HTTPS redirect + ACME HTTP-01 challenge |
| 443/tcp | Inbound | **Required** | Caddy HTTPS (all user and agent traffic) |
| 22/tcp | Inbound | Recommended | SSH admin access |
| 5432/tcp | Internal only | Must NOT be exposed externally | PostgreSQL |
| 6379/tcp | Internal only | Must NOT be exposed externally | Redis |
| 6380/tcp | Internal only | Must NOT be exposed externally | Budget-Redis (since v2.0) |
| 8181/tcp | Internal only | Must NOT be exposed externally | OPA |
| 11434/tcp | Internal only | Must NOT be exposed externally | Ollama |
| 8080/tcp | Internal only | Must NOT be exposed externally | Gateway |
| 8443/tcp | Internal only | Must NOT be exposed externally | Backoffice |
| 18789/tcp | Inbound | Optional — OpenClaw bundle only | OpenClaw Gateway (messaging webhooks) |

> **Warning:** The Docker Compose `internal: true` flag on the `internal` network prevents direct external access to most services. Still verify your host firewall (iptables/ufw/nftables) blocks these ports at the host level if you have other containers or processes that bypass the Docker network.

### Checklist — Section 1

```
[ ] Server IPv4 address noted
[ ] FQDN chosen and noted (this becomes YASHIGANI_TLS_DOMAIN)
[ ] Upstream MCP server URL confirmed reachable
[ ] Upstream MCP tool paths documented for OPA policy
[ ] Ports 80 and 443 open inbound (or 443 only if you redirect 80 externally)
[ ] Internal ports (5432, 6379, 6380, 8181, etc.) blocked at host firewall
[ ] Server has ≥ 2 GB RAM (4 GB recommended), ≥ 10 GB free disk
```

---

## Section 2 — DNS (Required for ACME and CA TLS Modes)

### 2.1 DNS Records

| Record | Type | Value | Required for |
|--------|------|-------|-------------|
| `your-domain.com` | A | Server IPv4 | ACME, CA |
| `your-domain.com` | AAAA | Server IPv6 (optional) | ACME (if IPv6) |

> **Note:** DNS must be fully propagated before you run the installer in ACME mode. Let's Encrypt's HTTP-01 challenge will fail if the domain does not resolve to your server's IP. Use `dig +short your-domain.com` from the server itself to confirm.

### 2.2 DNS TTL

For production: set DNS TTL to 300 seconds (5 minutes) before cutover, and restore to 3600 after. This makes rollback faster if something goes wrong.

### Checklist — Section 2

```
[ ] DNS A record created pointing FQDN → server IP
[ ] DNS propagation verified (dig +short your-domain.com = your server IP)
[ ] TTL set to 300 for initial deployment
[ ] Wildcard certificate not required (Yashigani uses a single domain)
```

---

## Section 3 — TLS Mode Selection

Choose **one** TLS mode before installation. This cannot be changed without restarting Caddy.

### 3.1 ACME / Let's Encrypt (Production Default)

**Pre-requirements:**
- DNS record pointing to the server (Section 2)
- Ports 80 and 443 open from the public internet
- Admin email address for Let's Encrypt expiry notifications

| Item | Required? | Value |
|------|-----------|-------|
| Admin email for ACME | Required | `YASHIGANI_ADMIN_EMAIL` or `CADDY_ACME_EMAIL` |
| Confirm port 80 open from internet | Required | Let's Encrypt HTTP-01 uses this |
| Confirm port 443 open from internet | Required | Traffic and TLS termination |

> **Note:** Caddy handles certificate issuance and renewal automatically. No manual cert management needed.

### 3.2 CA-Signed Certificate (Enterprise/Internal)

**Pre-requirements:**
- Certificate file (PEM format, full chain): `server.crt`
- Private key file (PEM format, unencrypted): `server.key`
- Both files for the exact FQDN in `YASHIGANI_TLS_DOMAIN`

| Item | Required? | Notes |
|------|-----------|-------|
| `server.crt` (full chain PEM) | **Required** | Place in `docker/tls/server.crt` |
| `server.key` (unencrypted PEM) | **Required** | Place in `docker/tls/server.key`. chmod 600. |
| Certificate CN or SAN matches domain | **Required** | Caddy will reject mismatched certificates |
| Certificate not expired | **Required** | Check: `openssl x509 -in server.crt -noout -dates` |
| CA bundle included in chain | Recommended | Clients that don't trust the CA root need the full chain |

```bash
# Verify before placement:
openssl x509 -in server.crt -noout -subject -issuer -dates
openssl verify -CAfile ca-bundle.crt server.crt
# Confirm key matches cert:
diff <(openssl x509 -pubkey -noout -in server.crt) \
     <(openssl pkey -pubout -in server.key)
```

### 3.3 Self-Signed (Demo / Local Only)

No pre-requirements. Caddy generates an internal CA automatically.
Set `YASHIGANI_TLS_DOMAIN=localhost` and `YASHIGANI_TLS_MODE=selfsigned`.

> **Warning:** Self-signed mode is NOT suitable for production. Browsers and agents will reject the certificate unless they trust Caddy's internal CA.

### Checklist — Section 3

```
[ ] TLS mode selected: [ ] acme  [ ] ca  [ ] selfsigned
[ ] ACME: admin email noted, ports 80+443 open
[ ] CA: server.crt and server.key obtained and verified
[ ] CA: cert CN/SAN matches YASHIGANI_TLS_DOMAIN exactly
[ ] Selfsigned: understand demo-only limitation
```

---

## Section 4 — Cloud / VM Environment

The installer auto-detects these but you should confirm them in advance for non-interactive installs.

| Item | Required? | Notes |
|------|-----------|-------|
| Cloud provider | Recommended | AWS / GCP / Azure / DigitalOcean / Hetzner / none |
| VM hypervisor | Info only | KVM / VMware / VirtualBox / HyperV / bare metal |
| Container runtime preference | Recommended | Docker Engine, Docker Desktop, or Podman — all supported as first-class runtimes. On macOS the installer checks for Docker Desktop at `/Applications/Docker.app` first. If Docker Desktop is installed but the `docker` CLI is not in PATH, the preflight offers to create the symlink automatically with a single Y/n prompt. Podman support includes runtime auto-detection, `podman compose` command resolution, and automatic application of the Podman Compose override file. The health check script auto-detects the compose command for Docker or Podman. In v2.0, the Container Pool Manager requires Docker or Podman API access for managing per-identity isolation containers. |
| If AWS: region | Required for AWS KMS | e.g. `us-east-1` |
| If AWS: IAM role or access keys | Required for AWS KMS | EC2 instance role preferred over static keys |
| If GCP: project ID | Required for GCP KMS | e.g. `my-project-123456` |
| If Azure: subscription / resource group | Required for Azure KMS | For Key Vault access |

---

## Section 4a — GPU Detection (since v0.8.4)

The installer runs GPU detection automatically via `platform-detect.sh`. No action is required for the detection itself. Use this section to verify your GPU is supported and to choose an appropriate Ollama model before installation.

### 4a.1 Supported GPU Platforms

| Platform | Detection Method | Compute Framework | Notes |
|----------|-----------------|-------------------|-------|
| Apple Silicon (M-series) | `sysctl hw.memsize` + chip model | Unified memory, Metal, ANE | No VRAM separation — system RAM is shared. Installer recommends model based on total RAM. |
| NVIDIA | `nvidia-smi` | CUDA | Requires `nvidia-container-toolkit` for Docker GPU passthrough. |
| AMD | `rocm-smi` | ROCm | Requires ROCm-compatible driver and container runtime. |
| Unknown discrete GPU | `lspci` (fallback) | None | Detected but not accelerated. Installer warns and recommends CPU inference. |
| No dedicated GPU | Software fallback | CPU only | Installer recommends small models (3B parameters or less) for CPU inference. |

### 4a.2 Model Recommendations by VRAM

The installer prints a recommended Ollama model based on detected GPU VRAM or unified memory:

| Available VRAM / Unified Memory | Recommended Model |
|---------------------------------|-------------------|
| < 4 GB | `qwen2.5:0.5b` (CPU only or very low-end GPU) |
| 4–6 GB | `qwen2.5:3b` (default) |
| 8–12 GB | `llama3.2:8b` or `mistral:7b` |
| 16 GB+ | `llama3.1:14b` or `qwen2.5:14b` |

> **Note:** These are starting recommendations. Actual performance depends on memory bandwidth and concurrent workload. Monitor Ollama container memory usage during the first week and adjust `OLLAMA_MODEL` in `.env` as needed.

### 4a.3 NVIDIA GPU — Pre-requirements

If the installer detects an NVIDIA GPU and you want to use it for Ollama:

| Item | Required? | Notes |
|------|-----------|-------|
| NVIDIA driver 525+ | Required | `nvidia-smi` must succeed |
| `nvidia-container-toolkit` | Required | Install: `sudo apt-get install nvidia-container-toolkit` |
| CUDA-compatible GPU | Required | Pascal (GTX 1000 series) or newer |

After installing `nvidia-container-toolkit`, uncomment the `deploy.resources` GPU block in `docker-compose.yml` under the `ollama` service.

### 4a.4 Apple Silicon — Pre-requirements

Docker Desktop 4.x on macOS automatically enables Apple Silicon acceleration for Ollama. No additional packages are required. Set memory allocation to at least 10 GB in Docker Desktop preferences when running 7B+ models.

### Checklist — Section 4a

```
[ ] GPU detection result noted (Apple Silicon / NVIDIA / AMD / CPU-only)
[ ] NVIDIA: nvidia-container-toolkit installed (if using NVIDIA GPU)
[ ] Apple Silicon: Docker Desktop memory allocation ≥ 10 GB for 7B+ models
[ ] Ollama model selected based on available VRAM / unified memory
```

---

## Section 5 — KMS / Secrets Provider

### 5.1 Docker Secrets (Default — Community, No Pre-requirements)

Auto-managed. No pre-requirements. Secrets stored in `docker/secrets/` on the host.

> **Warning:** Docker secrets mode is suitable for single-node deployments. For multi-node or production environments, use a managed secrets provider.

### 5.2 AWS Secrets Manager

| Item | Required? | Notes |
|------|-----------|-------|
| AWS region | **Required** | `AWS_DEFAULT_REGION` |
| IAM role with Secrets Manager access | Required | Preferred: EC2 instance profile. Otherwise: static access keys. |
| Permissions needed | Required | `secretsmanager:GetSecretValue`, `secretsmanager:PutSecretValue`, `secretsmanager:CreateSecret` |
| Secret name prefix (optional) | Optional | Defaults to `yashigani/` |
| VPC endpoint for Secrets Manager | Recommended | Avoids public internet for secret retrieval |

If using static access keys instead of instance role:
```
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
```

### 5.3 Azure Key Vault

| Item | Required? | Notes |
|------|-----------|-------|
| Key Vault URL | **Required** | `https://your-vault.vault.azure.net` → `AZURE_KEYVAULT_URL` |
| Azure tenant ID | Required | `AZURE_TENANT_ID` |
| Service principal client ID + secret | Required (if not managed identity) | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |
| Managed identity (preferred) | Recommended | Assign the VM identity Key Vault Secrets Officer role |
| Key Vault permissions | Required | `Get`, `Set`, `List` on secrets |

### 5.4 GCP Secret Manager

| Item | Required? | Notes |
|------|-----------|-------|
| GCP project ID | **Required** | `GOOGLE_CLOUD_PROJECT` |
| Service account JSON key | Required (if not Workload Identity) | Mount at `/run/secrets/gcp_sa_key.json` |
| Workload Identity (GKE preferred) | Recommended | No JSON key needed |
| IAM role | Required | `roles/secretmanager.secretAccessor` + `roles/secretmanager.secretVersionManager` |

### 5.5 HashiCorp Vault

| Item | Required? | Notes |
|------|-----------|-------|
| Vault address | **Required** | External: `VAULT_ADDR=https://vault.internal:8200`. Self-hosted dev: `http://vault:8200` |
| AppRole role_id | Required | Place in `docker/secrets/vault_role_id` |
| AppRole secret_id | Required | Place in `docker/secrets/vault_secret_id` |
| KV v2 mount path | Required | Default: `secret/` |
| Vault namespace (Enterprise) | Optional | `VAULT_NAMESPACE=your-namespace` |

> **Warning:** The included `vault` Docker Compose service runs in **dev mode** — data is not persisted and is NOT suitable for production. For production, connect to an external Vault cluster.

### 5.6 Keeper Secrets Manager

| Item | Required? | Notes |
|------|-----------|-------|
| Keeper One-Time Token | **Required** | Generated from Keeper Admin Console |
| Keeper record UIDs for each secret | Required | Map Yashigani secret names to Keeper record UIDs |

### Checklist — Section 5

```
[ ] KMS provider selected: [ ] docker  [ ] aws  [ ] azure  [ ] gcp  [ ] vault  [ ] keeper
[ ] Required credentials/config for chosen provider collected
[ ] IAM permissions or service account roles confirmed
[ ] (Production) Managed identity / instance role preferred over static keys
```

---

## Section 6 — Inspection Pipeline (LLM Backends)

Yashigani uses Ollama locally by default. No pre-requirements for the default configuration.

### 6.1 Ollama (Default — No Pre-requirements)

| Item | Required? | Notes |
|------|-----------|-------|
| Model name | Optional | Default: `qwen2.5:3b`. Alternatives: `llama3.2:3b`, `mistral:7b` |
| Internet access for model pull | Required (first start) | `ollama-init` pulls the model on first run. ~2 GB download. |
| NVIDIA GPU (optional) | Optional | Uncomment GPU section in docker-compose.yml. Requires nvidia-container-toolkit. |

### 6.2 Anthropic Claude (Optional Cloud Backend)

| Item | Required? | Notes |
|------|-----------|-------|
| Anthropic API key | Required | Stored in KMS under key name `anthropic_api_key` |
| API key permissions | Required | Must have access to `claude-haiku-4-5` model |
| Outbound HTTPS to `api.anthropic.com` | Required | Port 443 |

### 6.3 Google Gemini (Optional Cloud Backend)

| Item | Required? | Notes |
|------|-----------|-------|
| Google AI API key | Required | Stored in KMS under key name `gemini_api_key` |
| Outbound HTTPS to `generativelanguage.googleapis.com` | Required | Port 443 |

### 6.4 Azure OpenAI (Optional Cloud Backend)

| Item | Required? | Notes |
|------|-----------|-------|
| Azure OpenAI endpoint URL | Required | `AZURE_OPENAI_ENDPOINT=https://your-instance.openai.azure.com` |
| Azure OpenAI API key | Required | Stored in KMS under key name `azure_openai_key` |
| Deployment name | Required | `AZURE_OPENAI_DEPLOYMENT=gpt-4o-mini` (or your deployment name) |
| API version | Optional | Default: `2024-02-01` |

### Checklist — Section 6

```
[ ] Inspection backend selected: [ ] ollama (default)  [ ] anthropic  [ ] gemini  [ ] azure_openai
[ ] Ollama: internet access confirmed for first-run model pull (~2 GB)
[ ] Cloud backend: API key obtained and ready to load into KMS
[ ] Fallback chain planned (e.g. ollama,gemini,fail_closed)
[ ] Injection threshold decided (default 0.85 — increase for lower false positives)
```

---

## Section 7 — SSO Configuration (Professional / Enterprise Only)

If you are on the Community tier, skip this section. OIDC SSO requires Starter or higher. SAML and SCIM require Professional or higher.

### 7.1 SAML v2

| Item | Required? | Notes |
|------|-----------|-------|
| Identity Provider type | Required | Okta / Azure AD / PingFederate / Keycloak / ADFS / other |
| IdP metadata XML file or URL | **Required** | Uploaded to Yashigani Admin → SSO → SAML |
| Yashigani SP Entity ID | Needed for IdP config | Auto-generated: `https://your-domain/admin/sso/saml/metadata` |
| Yashigani ACS URL | Needed for IdP config | `https://your-domain/admin/sso/saml/acs` |
| SAML attribute mapping | Required | Which SAML attribute contains email/username (e.g. `NameID`, `email`) |
| Signing and encryption requirements | Recommended | Yashigani signs AuthnRequests and accepts signed/encrypted assertions |
| Admin account email matches IdP email | Required | Initial login must match the bootstrap admin email |

### 7.2 OpenID Connect

| Item | Required? | Notes |
|------|-----------|-------|
| OIDC issuer URL | **Required** | `https://accounts.example.com` or your IdP discovery endpoint |
| Client ID | **Required** | Obtained from IdP after registering Yashigani as an app |
| Client secret | **Required** | Stored in KMS under `oidc_client_secret` |
| Redirect URI to register in IdP | Required for IdP config | `https://your-domain/admin/sso/oidc/callback` |
| Requested scopes | Recommended | At minimum: `openid email profile` |
| User info claim for email | Required | Default: `email` |

### 7.3 SCIM Provisioning

| Item | Required? | Notes |
|------|-----------|-------|
| SCIM endpoint to configure in IdP | Required | `https://your-domain/scim/v2` |
| SCIM bearer token | Required | Generated in Yashigani Admin → SCIM → Token. Generated AFTER first login. |
| Supported SCIM operations | Info | Yashigani supports: Users (create/update/deactivate), Groups (create/update/delete) |
| IdP SCIM version | Required | SCIM 2.0 only |

### Checklist — Section 7

```
[ ] SAML: IdP metadata XML or URL obtained
[ ] SAML: ACS URL and Entity ID noted to register in IdP
[ ] OIDC: client ID and client secret obtained from IdP
[ ] OIDC: redirect URI registered in IdP
[ ] SCIM: plan to generate bearer token after initial admin login
[ ] OIDC only: Starter license or higher
[ ] SAML / SCIM: Professional license or higher
```

---

## Section 8 — SIEM Integration

### 8.1 Splunk HEC

| Item | Required? | Notes |
|------|-----------|-------|
| Splunk HEC URL | **Required** | `https://splunk.internal:8088/services/collector/event` |
| HEC token | **Required** | Created in Splunk → Settings → Data Inputs → HTTP Event Collector |
| Index name | Required | e.g. `yashigani_audit` (must exist in Splunk) |
| Source type | Recommended | `yashigani:audit` |
| CA certificate for Splunk TLS | Required if self-signed | Mount into container |

### 8.2 Elasticsearch

| Item | Required? | Notes |
|------|-----------|-------|
| Elasticsearch base URL | **Required** | `https://es.internal:9200` |
| API key | **Required** | Stored in KMS under `elasticsearch_api_key` |
| Index pattern | Required | e.g. `yashigani-audit-*` |
| ILM policy name | Recommended | For index lifecycle management |
| Kibana URL (optional, for dashboard) | Optional | For log visualization |

### 8.3 Wazuh (Self-Hosted, Auto-Deploy)

No pre-requirements — Wazuh manager, indexer, and dashboard are deployed automatically via the compose override. Yashigani auto-generates Wazuh admin credentials.

| Item | Required? | Notes |
|------|-----------|-------|
| Extra disk for Wazuh (≥ 5 GB recommended) | Required | Wazuh indexer stores event data |
| Extra RAM (≥ 2 GB additional) | Required | Wazuh indexer (OpenSearch-based) is memory-intensive |
| Port 1514/tcp (optional, for agent forwarding) | Optional | If you also run Wazuh agents on other hosts |

### Checklist — Section 8

```
[ ] SIEM mode selected: [ ] none  [ ] splunk  [ ] elasticsearch  [ ] wazuh
[ ] Splunk: HEC token obtained, index pre-created
[ ] Elasticsearch: API key obtained, index pattern decided
[ ] Wazuh: additional 5 GB disk and 2 GB RAM available
```

---

## Section 9 — Alertmanager Notification Channels

Edit `config/alertmanager.yml` after installation. Pre-collect:

### 9.1 Email (SMTP)

| Item | Required? | Notes |
|------|-----------|-------|
| SMTP server hostname and port | Required | e.g. `smtp.sendgrid.net:587` |
| SMTP username | Required | Often the API key itself (SendGrid) |
| SMTP password / API key | Required | Stored in `/run/secrets/smtp_password` |
| From address | Required | e.g. `alerts@example.com` |
| To address(es) for alerts | Required | Ops/security team distribution list |
| TLS mode (starttls / tls / none) | Required | Use TLS or STARTTLS always in production |

### 9.2 Slack

| Item | Required? | Notes |
|------|-----------|-------|
| Slack webhook URL | Required | Create at api.slack.com → Apps → Incoming Webhooks |
| Channel name | Required | e.g. `#security-alerts` |

### 9.3 PagerDuty

| Item | Required? | Notes |
|------|-----------|-------|
| PagerDuty Events v2 API key (integration key) | Required | Created in PagerDuty → Service → Integrations → Add Integration (Events v2 API) |
| Service name | Info | The PagerDuty service that will receive alerts |

### 9.4 Twilio SMS (Optional)

| Item | Required? | Notes |
|------|-----------|-------|
| Twilio Account SID | Required | Stored in secrets |
| Twilio Auth Token | Required | Stored in secrets |
| Twilio From number | Required | e.g. `+15551234567` |
| Recipient phone number(s) | Required | On-call mobile numbers |

### 9.5 Direct Webhook Alert Sinks (since v0.7.0)

Yashigani has a second, independent alerting channel — direct webhook sinks configured in the backoffice. These fire immediately on security events (credential exfil, licence expiry) without going through Alertmanager. Collect these separately from the Alertmanager credentials above.

| Item | Required? | Notes |
|------|-----------|-------|
| Slack incoming webhook URL (direct sink) | Optional | Different URL from the Alertmanager Slack URL if desired; configured post-install in Admin → Settings → Alert Sinks |
| Microsoft Teams incoming webhook URL | Optional | Created in Teams → Channel → Connectors → Incoming Webhook |
| PagerDuty Events API v2 routing key (direct sink) | Optional | Create at PagerDuty → Service → Integrations → Events API v2 |
| Licence expiry warning threshold (days) | Optional | Default 14 days; adjust in alert sink config |

### Checklist — Section 9

```
[ ] At least one notification receiver configured (recommended: Slack minimum)
[ ] Email: SMTP credentials obtained
[ ] PagerDuty: integration key obtained (for critical/production alerts)
[ ] Slack: webhook URL created
[ ] SMS: Twilio credentials obtained (optional)
[ ] (since v0.7.0) Direct webhook sink URLs gathered if using lightweight alerting
[ ] (since v0.7.0) Microsoft Teams webhook URL created if applicable
```

---

## Section 9b — AES Key Provisioning (since v0.9.0)

v0.9.0 requires an AES-256-GCM key for PostgreSQL column encryption. The installer manages this automatically, but review the options before starting.

| Item | Required? | Notes |
|------|-----------|-------|
| AES key provisioning mode | **Required** | Auto-generate (default) or BYOK |
| BYOK key file | Required if BYOK | 32-byte random key in binary format. Pass with `--aes-key /path/to/key.bin`. The installer stores it in the configured KMS. |
| Key backup | Required | If auto-generated, the installer stores the key in KMS. Ensure your KMS is backed up before starting. If using Docker secrets, back up `docker/secrets/aes_key` to a secure location. |
| Key rotation plan | Recommended | AES key rotation requires a DB re-encryption job. Plan the rotation cycle before production deployment. |

> **Warning:** Loss of the AES key renders all encrypted PostgreSQL columns (audit events, inference payloads, WebAuthn credentials) unreadable. Ensure the key is stored in a backed-up KMS or secure key store before starting.

### Checklist — Section 9b

```
[ ] AES key provisioning mode decided: [ ] auto-generate  [ ] BYOK
[ ] BYOK: 32-byte key file prepared and path noted
[ ] KMS backup confirmed (key will be stored there)
[ ] Key recovery plan documented
```

---

## Section 10 — Agent and MCP Registration

You register agents (AI clients) in the admin panel after installation. Prepare:

| Item | Required? | Notes |
|------|-----------|-------|
| List of agents to register | Required | Each agent needs: name, description, path prefix |
| Path prefix per agent | Required | Which MCP paths each agent is allowed to call (e.g. `/tools/read`, `/tools`) |
| Token management plan | Required | Tokens are shown only once. Have a secure storage plan (vault, 1Password, etc.) |
| Tier limits | Note | Community: 5 agents / 10 end users / 2 admin seats. Starter: 100/250/25. Professional: 500/1,000/50. Pro Plus: 2,000/10,000/200. Enterprise: unlimited. |

For each agent, note:
- **Name**: human-readable (e.g. `claude-code-agent`)
- **Description**: what it does (e.g. `VSCode Claude Code extension`)
- **Path prefix**: the MCP sub-path it should access (e.g. `/tools`)
- **Rate limit override**: if different from global default
- **IP allowlist** (since v0.7.0): if the agent will only ever connect from known CIDRs (e.g. `10.0.0.0/8`), prepare the CIDR list now — it can be set at registration time or updated later

The registration response includes a `quick_start` field with copy-paste curl, Python httpx, and health-check snippets using the live bearer token. Save these along with the token.

### Checklist — Section 10

```
[ ] Agent inventory created (name, description, path prefix for each)
[ ] Token storage method decided (secret manager, vault, encrypted file)
[ ] (since v0.7.0) IP CIDR allowlists defined for agents with known source IPs
[ ] (v2.23.2+) If using agent bundles: verify YASHIGANI_AGENT_UPSTREAM_HOSTNAMES on backoffice contains the bundle hostnames you intend to register (default: langflow,letta,openclaw); add custom internal agent service names if needed
[ ] Community: agents ≤ 5, end users ≤ 10, admin seats ≤ 2
[ ] Starter: agents ≤ 100, end users ≤ 250, admin seats ≤ 25
[ ] Professional: agents ≤ 500, end users ≤ 1,000, admin seats ≤ 50
[ ] Professional Plus: agents ≤ 2,000, end users ≤ 10,000, admin seats ≤ 200
[ ] Enterprise: unlimited — no pre-check needed
```

---

## Section 11 — License File (Starter / Professional / Professional Plus / Enterprise)

If deploying on the Community tier (free, Apache 2.0), skip this section. Starter and above require a signed `.ysg` license file.

| Item | Required? | Notes |
|------|-----------|-------|
| License file (`.ysg`) | **Required** | Obtained from Yashigani team |
| License tier matches intended use | Required | Starter: 1 org, 100 agents, 250 end users, OIDC only. Professional: 500 agents, 1,000 end users, full SSO. Professional Plus: 2,000 agents, 10,000 end users, 5 orgs. Enterprise: unlimited. |
| `org_domain` in license matches your domain | Required | The domain in the license must match the org domain you configure |
| License not expired | Required | Check expiry: the installer verifies this at startup |
| Secure storage for license file | Required | Do not commit `.ysg` to version control (already in `.gitignore`) |

**Loading options (choose one):**
1. Installer flag: `--license-key /path/to/license.ysg`
2. Docker secret: copy to `docker/secrets/license_key` before `docker compose up`
3. Env var: `YASHIGANI_LICENSE_FILE=/path/to/license.ysg`
4. Admin panel: Admin → License → Activate (after first start)

### Checklist — Section 11

```
[ ] License .ysg file obtained from Yashigani
[ ] License tier confirmed: [ ] Starter  [ ] Professional  [ ] Professional Plus  [ ] Enterprise
[ ] org_domain in license matches your deployment domain
[ ] License expiry date noted (set a calendar reminder)
[ ] Secure storage location decided for the .ysg file
```

---

## Section 12 — Kubernetes Deployment Only

Skip this section if deploying with Docker Compose (the default).

| Item | Required? | Notes |
|------|-----------|-------|
| Kubernetes cluster version | Required | ≥ 1.26 |
| `kubectl` access and correct context | **Required** | `kubectl get nodes` must succeed |
| Helm installed | **Required** | Helm 3.x |
| Namespace | Required | Default: `yashigani` |
| Ingress controller | **Required** | nginx-ingress or Traefik. Caddy is disabled in K8s mode. |
| cert-manager installed | Required (ACME mode) | For Let's Encrypt certificate issuance |
| StorageClass for PVCs | Required | For Postgres, Redis, Prometheus data. Confirm default StorageClass or specify. |
| `ClusterIssuer` or `Issuer` name | Required (ACME) | cert-manager issuer to use for TLS |
| Image pull secret | Required (if private registry) | `docker/secrets/registry_auth` |
| Minimum PVC sizes | Required | Postgres: 20 GiB, Prometheus: 10 GiB, Grafana: 2 GiB |
| Resource limits | Recommended | Set `resources.requests` and `resources.limits` in Helm values |
| External secrets (if not Docker secrets) | Recommended | ExternalSecrets operator or sealed-secrets for KMS integration |

```bash
# Verify prerequisites:
kubectl version --short
helm version --short
kubectl get sc                          # list StorageClasses
kubectl get ns yashigani 2>/dev/null   # check if namespace exists
kubectl get ingressclass                # confirm ingress controller
kubectl -n cert-manager get clusterissuer  # confirm cert-manager
```

### Checklist — Section 12

```
[ ] kubectl connected to correct cluster
[ ] Helm 3.x installed
[ ] Ingress controller deployed and working
[ ] cert-manager installed (for ACME)
[ ] StorageClass confirmed (with ReadWriteOnce support)
[ ] Namespace decided
[ ] Resource limits planned
```

---

## Section 13 — Observability Pre-Requirements

### 13.1 Prometheus / Grafana

No external pre-requirements. Both are included in the stack.

| Item | Notes |
|------|-------|
| Basic auth for `/metrics-federate` | Auto-generated. Note the hash from `docker compose logs backoffice`. |
| Grafana admin password | Auto-generated at first run. |
| External Prometheus federation | Optional. If you have a central Prometheus, configure scrape job for `https://your-domain/metrics-federate`. |

### 13.2 Jaeger Tracing

No pre-requirements. Jaeger is included in the stack (in-memory storage).

> **Note:** Default Jaeger uses in-memory storage — traces are lost on restart. For production, configure a persistent Jaeger backend (Cassandra, Elasticsearch). Set `SPAN_STORAGE_TYPE=elasticsearch` and configure Jaeger's ES connection.

### 13.3 Loki Log Aggregation

No external pre-requirements. Loki + Promtail are included.

> **Note:** Promtail mounts `/var/lib/docker/containers` and `/var/run/docker.sock` to ship container logs. Ensure the Docker socket is accessible and the Promtail container has read permission.

---

## Section 14 — PostgreSQL

The Postgres instance is embedded in the stack. No external database is needed by default.

| Item | Required? | Notes |
|------|-----------|-------|
| Backup strategy for `postgres_data` volume | **Recommended for production** | Use `docker run --volumes-from postgres pgbackup` or a volume snapshot |
| External Postgres (optional) | Optional | Override `YASHIGANI_DB_DSN` in `.env` to use an external PG instance (RDS, AlloyDB, etc.) |
| If external Postgres: version | Required | PostgreSQL ≥ 14. pgcrypto extension must be enabled. |
| If external Postgres: SSL mode | Required | Use `sslmode=require` or `verify-full` |
| If external Postgres: user privileges | Required | Superuser for initial migration, then `yashigani_app` role for runtime |

```sql
-- Pre-create if using external Postgres:
CREATE DATABASE yashigani;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE ROLE yashigani_app WITH LOGIN PASSWORD 'generated_at_runtime';
GRANT ALL PRIVILEGES ON DATABASE yashigani TO yashigani_app;
```

---

## Section 15 — Security and Hardening

These are not installer inputs but must be planned before go-live.

| Item | Required? | Notes |
|------|-----------|-------|
| OPA policy review | **Required** | The default policy is permissive. Review and customize `policy/` for your use case. |
| Admin account inventory | Required | Minimum 2 admin accounts required. Plan who will hold them. |
| TOTP enrollment plan | Required | All admin accounts must enroll TOTP before the bootstrap admin password is distributed. |
| Admin initial password handling | Required | Printed at first run, one-time display. Store in password manager immediately. |
| Host-level audit logging | Recommended | `/var/log/auth.log` + SSH logging in addition to Yashigani's own audit |
| Container image pinning | Recommended | Replace `:latest` tags in docker-compose.yml with specific digest-pinned versions for production. |
| Seccomp/AppArmor | Recommended | Verify profiles are loading: `docker inspect --format='{{.HostConfig.SecurityOpt}}' yashigani-gateway-1` |
| Volume encryption | Recommended | For cloud deployments, use encrypted EBS/Persistent Disk/Azure Managed Disk for the Docker data root |
| Backup encryption | Recommended | Encrypt all Postgres backups at rest |

### Checklist — Section 15

```
[ ] OPA policy (`policy/` directory) reviewed and customized
[ ] At least 2 admin accounts planned with named owners
[ ] TOTP enrollment scheduled for all admin accounts at first login
[ ] Postgres backup strategy decided and scheduled
[ ] Container image pinning done for production docker-compose.yml
[ ] OPA deny-by-default confirmed for unlisted paths
```

---

## Section 16 — Interactive Fallback Prompts (since v0.8.4)

In v0.8.4, when automatic detection fails for OS, container runtime, or GPU, the installer falls back to interactive selection menus rather than aborting. This section documents what to expect and what to have ready.

### 16.1 When Fallback Prompts Appear

| Detection Scenario | Fallback Behavior |
|--------------------|------------------|
| OS could not be determined | Installer presents a numbered list: `1) linux  2) macos  3) other` |
| Container runtime not found | Installer presents: `1) docker  2) docker-desktop  3) podman` |
| GPU detection failed or no GPU found | Installer presents: `1) nvidia  2) apple-silicon  3) amd  4) none (CPU only)` |

### 16.2 Non-Interactive Mode

For automated or CI deployments, bypass interactive prompts using flags:

```bash
./install.sh \
  --os linux \
  --runtime docker \
  --gpu nvidia \
  --non-interactive
```

If `--non-interactive` is set and required detection fails, the installer aborts with a clear error rather than hanging for input.

### Checklist — Section 16

```
[ ] Understood: interactive prompts may appear if detection fails
[ ] Non-interactive deployments: --os, --runtime, --gpu flags prepared
[ ] CI/CD pipelines: --non-interactive flag added to install command
```

---

## Section 17 — Updating an Existing Installation (since v0.8.4)

`update.sh` handles updating an existing Yashigani installation. It is the recommended path for patch and minor version updates.

### 17.1 What update.sh Does

1. **Backs up** the current `.env`, `docker/secrets/`, and `config/` directories to a timestamped archive.
2. **Pulls** the latest Docker images for all stack services.
3. **Restarts** the stack with `docker compose up -d --remove-orphans`.
4. **Runs** Alembic migrations automatically via the backoffice start sequence.
5. **Rolls back** automatically if the backoffice fails to reach `healthy` status within the configured timeout — restores the pre-update backup and brings the previous image versions back up.

### 17.2 Running the Update

```bash
./update.sh
```

For a specific version:

```bash
./update.sh --version v0.8.4
```

To skip the interactive confirmation:

```bash
./update.sh --non-interactive
```

### 17.3 Pre-Update Checklist

| Item | Required? | Notes |
|------|-----------|-------|
| Postgres volume snapshot | **Recommended** | Take a snapshot before any update. See Section 14. |
| `.env` backup | Auto-handled by `update.sh` | Also back up manually to an off-host location |
| Confirm no pending Alembic state | Recommended | `docker compose exec backoffice alembic current` should show a clean head |
| Disk space for new images | Required | Ensure ≥ 5 GB free on Docker data root |

### Checklist — Section 17

```
[ ] Postgres volume backed up (or snapshot taken)
[ ] Disk space confirmed ≥ 5 GB free
[ ] `update.sh` reviewed (in repo root)
[ ] Rollback plan understood (update.sh handles automatically; manual restore from backup is the fallback)
```

---

## Master Pre-Installation Summary Checklist

Print this page and tick every item before running the installer.

### Mandatory (All Deployments)

```
[ ] Server IP address:          ___________________________
[ ] Domain / FQDN:              ___________________________
[ ] Upstream MCP server URL:    ___________________________
[ ] TLS mode chosen:            [ ] acme  [ ] ca  [ ] selfsigned
[ ] KMS provider chosen:        [ ] docker  [ ] aws  [ ] azure  [ ] gcp  [ ] vault  [ ] keeper
[ ] Container runtime confirmed: [ ] Docker Engine  [ ] Docker Desktop  [ ] Podman
[ ] GPU noted (installer detects automatically): [ ] Apple Silicon  [ ] NVIDIA  [ ] AMD  [ ] CPU-only
[ ] Ollama model selected based on GPU/RAM (see Section 4a.2)
[ ] Ports 80 + 443 open inbound
[ ] Server has ≥ 4 GB RAM, ≥ 20 GB free disk
[ ] Docker Engine 24+, Docker Desktop 4.x+, or Podman installed (or installer will handle it)
[ ] If Docker Desktop on macOS: `docker` CLI in PATH (or let installer create symlink)
[ ] Optional: run `bash scripts/test-installer.sh` to verify environment before install
```

### ACME TLS Mode

```
[ ] DNS A record created and propagated
[ ] Admin email for Let's Encrypt: ________________________
```

### CA TLS Mode

```
[ ] server.crt placed in docker/tls/
[ ] server.key placed in docker/tls/ (chmod 600)
[ ] Certificate CN/SAN verified
```

### Cloud KMS (if not docker secrets)

```
[ ] Cloud credentials / IAM permissions confirmed
[ ] Required env vars noted
```

### SSO (Starter and above)

```
[ ] IdP metadata XML or URL obtained
[ ] OIDC client ID and secret obtained
[ ] Redirect URIs registered in IdP
[ ] License .ysg file obtained
```

### SIEM (if not none)

```
[ ] SIEM credentials / API keys obtained
[ ] Network connectivity to SIEM endpoint verified
```

### Alertmanager

```
[ ] At minimum: Slack webhook URL or SMTP credentials ready
```

### Kubernetes Only

```
[ ] kubectl access confirmed
[ ] Helm installed
[ ] Ingress controller deployed
[ ] cert-manager installed (for ACME)
[ ] StorageClass confirmed
```

### Optional Agent Bundles (Lala / Julietta / Scout)

The current agent lineup is: Lala (Langflow), Julietta (Letta), Scout (OpenClaw). Goose and LangGraph have been removed.

```
[ ] Decision made: which bundles to enable (or none)
[ ] Sufficient disk space confirmed (Langflow ~300 MB; Letta ~200 MB; OpenClaw ~800 MB)
[ ] Scout (OpenClaw) only: port 18789 open inbound if messaging webhooks are required
[ ] Scout (OpenClaw) only: no other service using port 18789 on the host
[ ] Agent bundles work out of the box with --agent-bundles flag
[ ] Installer auto-registers agents via backoffice API and writes PSK tokens to docker/secrets/
[ ] Agent bundles registered with unified identity model (kind: service)
[ ] Agent chaining reviewed: @Scout -> @Julietta -> @qwen (@Help agent for chaining guide)
```

### Optional Services

```
[ ] Open WebUI: enabled with --with-openwebui flag (optional compose profile)
[ ] Open WebUI: trusted header authentication confirmed
[ ] Internal CA: enabled with --with-internal-ca flag (Smallstep step-ca, optional)
[ ] Internal CA: additional disk/RAM for step-ca service
[ ] Wazuh SIEM: enabled with --wazuh flag (optional)
[ ] Wazuh: additional 5 GB disk and 2 GB RAM available for Wazuh indexer
[ ] All services manageable from admin panel via API (API-first architecture)
```

### v2.0+ Systems

```
[ ] Budget system: org cap, group budgets, and individual budgets planned
[ ] Budget-redis: port 6380 not exposed externally
[ ] Optimization Engine: default priority level decided (default P5)
[ ] Container Pool Manager: min warm containers and max containers planned
[ ] Sensitivity pipeline: all three stages (regex + FastText + Ollama) enabled by default
[ ] Identity model: existing agents migrated to unified model with kind field
[ ] Multi-IdP: additional OIDC/SAML v2 providers identified (if applicable)
[ ] OPA: policy/v1_routing.rego reviewed (identity, model access, routing safety, sensitivity ceiling)
[ ] OPA: response_decision enforcement confirmed on all /v1 traffic
```

### Production Go-Live

```
[ ] OPA policy reviewed (including v1_routing.rego and response_decision)
[ ] 2+ admin accounts planned
[ ] Postgres backup strategy confirmed (restore.sh for backup recovery)
[ ] Postgres migrations run on startup confirmed
[ ] Image versions pinned in docker-compose.yml
[ ] Monitoring/alerting receivers configured
[ ] Budget tiers configured and tested
[ ] Pre-release OWASP review completed (manual review of ASVS, API Security, Agentic AI controls against current code)
[ ] Fail2ban auth throttle verified (x5 escalation -> permanent IP block)
[ ] IP allowlist + blocklist configured (IPv4/IPv6/CIDR)
```

---

*Once all items in the Master Checklist are ticked, you are ready to run `install.sh` or `docker compose up -d`.*
