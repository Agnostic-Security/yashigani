# Yashigani Backoffice API Reference

The Backoffice API is the operator management plane. It controls users,
agents, policies, audit sinks, rate limits, RBAC, PKI, and licensing.

## Authentication

All endpoints require a valid admin session cookie obtained via
`POST /auth/login` followed by TOTP step-up where required.

```
Cookie: __Host-yashigani_admin_session=<session-token>
```

High-value endpoints (key rotation, user deletion, PKI operations)
additionally require a step-up TOTP confirmation via `POST /auth/stepup`
before the request is accepted.

## Base URL

The Backoffice is isolated on port 8443 (TLS only). The Swagger UI is
available at `/admin/api-docs` after logging in.

## Endpoints

### `GET /admin/accounts`

**List Admins**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/accounts \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/accounts`

**Create Admin**

Create an admin account. Server generates a 36-char temporary password
and a TOTP secret. Both are returned once — caller shares them
out-of-band. Admin must change password and provision TOTP at first login.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/accounts \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "username": "<string>"
}'
        ```

---

### `DELETE /admin/accounts/{username}`

**Delete Admin**

Delete an admin account. Blocked if total would drop below 2.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/accounts/{username} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/accounts/{username}/disable`

**Disable Admin**

Disable account. Blocked if active count would drop below 2.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/accounts/{username}/disable \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/accounts/{username}/enable`

**Enable Admin**

Re-enable a disabled admin account.

Iris MISSING-04 / GROUP-2-6: enforce admin seat limit before re-enabling.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/accounts/{username}/enable \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/accounts/{username}/force-reset`

**Force Reset**

Force password reset or TOTP reprovision for an admin account.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/accounts/{username}/force-reset \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "action": "<string>"
}'
        ```

---

### `GET /admin/agent-bundles/`

**List Agent Bundles**

Return all available optional agent bundles with their metadata and disclaimer.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `bundles` | `array[AgentBundleResponse]` | Yes |  |
| `disclaimer` | `string` | Yes |  |

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/agent-bundles/ \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/agent-bundles/disclaimer`

**Get Disclaimer**

Return the standard third-party agent bundle disclaimer for use in UI banners.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `disclaimer` | `string` | Yes |  |

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/agent-bundles/disclaimer \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/agents`

**List Agents**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/agents \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/agents`

**Register Agent**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` | Yes | Agent slug: lowercase letter, then lowercase alphanumeric, underscore, or hyphen. Max 64 chars. No path traversal chars permitted (V232-CSCAN-01a / CWE-22). |
| `upstream_url` | `string` | Yes |  |
| `protocol` | `string` | No | Agent protocol: openai, letta, or langflow |
| `groups` | `array[string]` | No |  |
| `allowed_caller_groups` | `array[string]` | No |  |
| `allowed_paths` | `array[string]` | No |  |
| `allowed_cidrs` | `array[string]` | No | Optional CIDR allowlist. Empty = no IP restriction. E.g. ['10.0.0.0/8', '192.168.1.100/32'] |

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | `string` | Yes |  |
| `name` | `string` | Yes |  |
| `upstream_url` | `string` | Yes |  |
| `status` | `string` | Yes |  |
| `created_at` | `string` | Yes |  |
| `last_seen_at` | `string` | Yes |  |
| `groups` | `array[any]` | Yes |  |
| `allowed_caller_groups` | `array[any]` | Yes |  |
| `allowed_paths` | `array[any]` | Yes |  |
| `allowed_cidrs` | `array[any]` | No |  |
| `token_last_rotated` | `string` | No |  |
| `token_rotation_schedule` | `string` | No |  |
| `token` | `string` | Yes | Plaintext PSK token. Store immediately — never shown again. |
| `quick_start` | `object` | No | Copy-paste integration snippets for curl, Python, and health check. |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/agents \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "<string>",
  "upstream_url": "<string>"
}'
        ```

---

### `DELETE /admin/agents/{agent_id}`

**Deactivate Agent**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/agents/{agent_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/agents/{agent_id}`

**Get Agent**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | `string` | Yes |  |
| `name` | `string` | Yes |  |
| `upstream_url` | `string` | Yes |  |
| `status` | `string` | Yes |  |
| `created_at` | `string` | Yes |  |
| `last_seen_at` | `string` | Yes |  |
| `groups` | `array[any]` | Yes |  |
| `allowed_caller_groups` | `array[any]` | Yes |  |
| `allowed_paths` | `array[any]` | Yes |  |
| `allowed_cidrs` | `array[any]` | No |  |
| `token_last_rotated` | `string` | No |  |
| `token_rotation_schedule` | `string` | No |  |

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/agents/{agent_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /admin/agents/{agent_id}`

**Update Agent**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `any` | No | Agent slug: lowercase letter, then lowercase alphanumeric, underscore, or hyphen. Max 64 chars. No path traversal chars permitted (V232-CSCAN-01a / CWE-22). |
| `upstream_url` | `any` | No |  |
| `groups` | `any` | No |  |
| `allowed_caller_groups` | `any` | No |  |
| `allowed_paths` | `any` | No |  |
| `allowed_cidrs` | `any` | No |  |

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | `string` | Yes |  |
| `name` | `string` | Yes |  |
| `upstream_url` | `string` | Yes |  |
| `status` | `string` | Yes |  |
| `created_at` | `string` | Yes |  |
| `last_seen_at` | `string` | Yes |  |
| `groups` | `array[any]` | Yes |  |
| `allowed_caller_groups` | `array[any]` | Yes |  |
| `allowed_paths` | `array[any]` | Yes |  |
| `allowed_cidrs` | `array[any]` | No |  |
| `token_last_rotated` | `string` | No |  |
| `token_rotation_schedule` | `string` | No |  |

**Example:**

      ```bash
      curl -X PUT https://<gateway-host>/admin/agents/{agent_id} \
        -H 'Cookie: __Host-yashigani_admin_session=<token>' \
-H 'Content-Type: application/json' \
-d '{}'
      ```

---

### `GET /admin/agents/{agent_id}/quickstart`

**Get Agent Quickstart**

Return copy-paste integration snippets for the agent detail page.

The token placeholder ``<your-token>`` is used in place of the actual
token, which is only available at registration / rotation time.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | `string` | Yes |  |
| `quick_start` | `object` | Yes | Copy-paste integration snippets (token placeholder — use your stored token). |

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/agents/{agent_id}/quickstart \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/agents/{agent_id}/token/rotate`

**Rotate Agent Token**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | `string` | Yes |  |
| `token` | `string` | Yes | New plaintext PSK token. Store immediately — never shown again. |
| `quick_start` | `object` | No |  |

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/agents/{agent_id}/token/rotate \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/alerts/config`

**Get Alert Config**

Return current alert sink configuration. URLs and keys are masked.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/alerts/config \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /admin/alerts/config`

**Update Alert Config**

Update alert sink configuration and rebuild the dispatcher.

V232-CSCAN-01b: URL guard is applied inside _rebuild_dispatcher() via the
SlackSink/TeamsSink constructors. A WebhookUrlForbidden exception is caught
here and converted to HTTP 400 so the malicious URL is never persisted.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `slack_webhook_url` | `string` | No | Slack incoming webhook URL. Empty = disabled. |
| `teams_webhook_url` | `string` | No | Microsoft Teams incoming webhook URL. Empty = disabled. |
| `pagerduty_routing_key` | `string` | No | PagerDuty Events API v2 routing key. Empty = disabled. |
| `alert_on_credential_exfil` | `boolean` | No |  |
| `alert_on_anomaly_threshold` | `boolean` | No |  |
| `license_expiry_warning_days` | `integer` | No |  |
| `license_limit_warning_pct` | `integer` | No |  |

**Example:**

      ```bash
      curl -X PUT https://<gateway-host>/admin/alerts/config \
        -H 'Cookie: __Host-yashigani_admin_session=<token>' \
-H 'Content-Type: application/json' \
-d '{}'
      ```

---

### `POST /admin/alerts/test/{sink_type}`

**Test Alert Sink**

Send a test alert to a specific configured sink.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/alerts/test/{sink_type} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/audit/export`

**Export Filtered Audit Log**

Export filtered audit log as NDJSON or CSV.
Hard cap of 10,000 rows regardless of filter breadth.
Never buffers the full result set in memory.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/audit/export \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/audit/export/raw`

**Export Audit Log**

Stream the audit log as NDJSON or CSV. Never buffers the full file in memory.

AVA-2026-04-29-002 fix (ASVS V7.1.3):
- AuditLogExporter.export() is the canonical method; export_ndjson() / export_csv()
  never existed and caused AttributeError mid-stream (HTTP 200 then 502 cascade).
- ndjson maps to AuditLogExporter format 'json' (newline-delimited JSON).
- Mid-stream exceptions are caught inside the generator and logged; the response
  is closed cleanly so keep-alive connections are not corrupted.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/audit/export/raw \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/audit/masking/scope`

**Get Masking Scope**

Return the current masking scope configuration.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/audit/masking/scope \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /admin/audit/masking/scope`

**Set Masking Default**

Update the global masking default (mask all vs mask none by default).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mask_all_by_default` | `boolean` | Yes |  |

**Example:**

        ```bash
        curl -X PUT https://<gateway-host>/admin/audit/masking/scope \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "mask_all_by_default": "<boolean>"
}'
        ```

---

### `POST /admin/audit/masking/scope/agent`

**Set Agent Override**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | `string` | Yes |  |
| `mask` | `boolean` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/audit/masking/scope/agent \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "agent_id": "<string>",
  "mask": "<boolean>"
}'
        ```

---

### `DELETE /admin/audit/masking/scope/agent/{agent_id}`

**Remove Agent Override**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/audit/masking/scope/agent/{agent_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/audit/masking/scope/component`

**Set Component Override**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `component` | `string` | Yes |  |
| `mask` | `boolean` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/audit/masking/scope/component \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "component": "<string>",
  "mask": "<boolean>"
}'
        ```

---

### `DELETE /admin/audit/masking/scope/component/{component}`

**Remove Component Override**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/audit/masking/scope/component/{component} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/audit/masking/scope/user`

**Set User Override**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_handle` | `string` | Yes |  |
| `mask` | `boolean` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/audit/masking/scope/user \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "user_handle": "<string>",
  "mask": "<boolean>"
}'
        ```

---

### `DELETE /admin/audit/masking/scope/user/{handle}`

**Remove User Override**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/audit/masking/scope/user/{handle} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/audit/search`

**Search Audit Log**

Search the audit log with optional filters.
Returns up to 100 rows per page. Provide cursor from a previous response
to fetch the next page.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/audit/search \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/audit/siem`

**List Siem Targets**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/audit/siem \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/audit/siem`

**Add Siem Target**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `string` | Yes |  |
| `target_type` | `string` | Yes |  |
| `url` | `string` | Yes |  |
| `auth_header` | `string` | No |  |
| `auth_value` | `string` | Yes |  |
| `enabled` | `boolean` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/audit/siem \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "<string>",
  "target_type": "<string>",
  "url": "<string>",
  "auth_value": "<string>"
}'
        ```

---

### `GET /admin/audit/siem/config`

**Get Siem Config**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `backend` | `string` | Yes |  |
| `endpoint` | `any` | Yes |  |
| `wazuh_auto_deploy` | `boolean` | Yes |  |

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/audit/siem/config \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /admin/audit/siem/config`

**Update Siem Config**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `backend` | `string` | Yes |  |
| `endpoint` | `any` | No |  |
| `token_secret_key` | `any` | No |  |
| `wazuh_auto_deploy` | `any` | No |  |

**Example:**

        ```bash
        curl -X PUT https://<gateway-host>/admin/audit/siem/config \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "backend": "<string>"
}'
        ```

---

### `POST /admin/audit/siem/config/test`

**Test Siem**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/audit/siem/config/test \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `DELETE /admin/audit/siem/{name}`

**Remove Siem Target**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/audit/siem/{name} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/audit/siem/{name}/test`

**Test Siem Target**

Send a synthetic test event to the named SIEM target.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/audit/siem/{name}/test \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/audit/sinks`

**List Sinks**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/audit/sinks \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/backup/status`

**Backup Status**

List all backups with MANIFEST integrity state.

Returns empty state (backups=[], latest=null) if no backup directory exists
or directory is empty — never 500.

CWE-200: backups_dir is always "backups" (relative), never an absolute path.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/backup/status \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/backup/verify`

**Backup Verify**

Re-hash a named backup and compare against MANIFEST.sha256.

Path traversal guard: backup_name must match [A-Za-z0-9_\-.]+
and resolved path must be a direct child of BACKUPS_DIR.

MANIFEST states:
- unsigned: ok=True, no comparison (warn: no integrity record)
- signed:   ok=(mismatches == [])
- corrupt:  ok=False, error=manifest_corrupt

ASVS 7.1.2: audit log on every verify invocation.
CWE-200: no absolute paths in response.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `backup_name` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/backup/verify \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "backup_name": "<string>"
}'
        ```

---

### `GET /admin/budget/groups`

**List Group Budgets**

List all group budgets.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/budget/groups \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/budget/groups`

**Create Group Budget**

Set a group's budget.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `group_id` | `string` | Yes |  |
| `provider` | `string` | No |  |
| `token_budget` | `integer` | Yes |  |
| `period` | `string` | No |  |
| `distribute_evenly` | `boolean` | No |  |

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `group_id` | `string` | Yes |  |
| `provider` | `string` | Yes |  |
| `token_budget` | `integer` | Yes |  |
| `period` | `string` | Yes |  |
| `auto_calculated` | `boolean` | Yes |  |
| `used` | `integer` | No |  |
| `pct` | `integer` | No |  |
| `member_count` | `integer` | No |  |
| `allocated` | `integer` | No |  |
| `unallocated` | `integer` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/budget/groups \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "group_id": "<string>",
  "token_budget": "<integer>"
}'
        ```

---

### `GET /admin/budget/individuals`

**List Individual Budgets**

List all individual budgets.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/budget/individuals \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/budget/individuals`

**Create Individual Budget**

Set an individual identity's budget.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `identity_id` | `string` | Yes |  |
| `provider` | `string` | No |  |
| `token_budget` | `integer` | Yes |  |
| `period` | `string` | No |  |

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `identity_id` | `string` | Yes |  |
| `provider` | `string` | Yes |  |
| `token_budget` | `integer` | Yes |  |
| `period` | `string` | Yes |  |
| `used` | `integer` | No |  |
| `pct` | `integer` | No |  |
| `remaining` | `integer` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/budget/individuals \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "identity_id": "<string>",
  "token_budget": "<integer>"
}'
        ```

---

### `GET /admin/budget/org-caps`

**List Org Caps**

List all organisation cloud caps.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/budget/org-caps \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/budget/org-caps`

**Create Org Cap**

Set an organisation's cloud token cap for a provider.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `org_id` | `string` | Yes |  |
| `provider` | `string` | Yes |  |
| `token_cap` | `integer` | Yes |  |
| `period` | `string` | No |  |

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `org_id` | `string` | Yes |  |
| `provider` | `string` | Yes |  |
| `token_cap` | `integer` | Yes |  |
| `period` | `string` | Yes |  |
| `used` | `integer` | No |  |
| `pct` | `integer` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/budget/org-caps \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "org_id": "<string>",
  "provider": "<string>",
  "token_cap": "<integer>"
}'
        ```

---

### `GET /admin/budget/tree`

**Get Budget Tree**

Full budget tree view: org -> groups -> identities.
Shows total, used, remaining at every level.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/budget/tree \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/budget/usage/{identity_id}`

**Get Usage**

Get token usage across all providers for an identity.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/budget/usage/{identity_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/cache`

**List Cache Configs**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/cache \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `DELETE /admin/cache/{tenant_id}`

**Invalidate Cache**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/cache/{tenant_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/cache/{tenant_id}`

**Get Cache Config**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/cache/{tenant_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /admin/cache/{tenant_id}`

**Set Cache Config**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | `boolean` | No |  |
| `ttl_seconds` | `integer` | No |  |

**Example:**

      ```bash
      curl -X PUT https://<gateway-host>/admin/cache/{tenant_id} \
        -H 'Cookie: __Host-yashigani_admin_session=<token>' \
-H 'Content-Type: application/json' \
-d '{}'
      ```

---

### `GET /admin/crypto/inventory`

**Crypto Inventory**

Return the full cryptographic algorithm inventory.
ASVS 11.1.3 — all algorithms, strength levels, and PQ readiness.
Requires admin session.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/crypto/inventory \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/events/inspection-feed`

**Inspection Feed**

Server-Sent Events stream for real-time inspection event visibility.
Connect once; events are pushed as they occur at the gateway.
Heartbeat comments are sent every 15 seconds to maintain the connection.

Event format (text/event-stream):
    data: {"timestamp": "...", "agent_id": "...", ...}

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/events/inspection-feed \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/identities`

**List Identities**

List identities from the IdentityRegistry.

Optional ``kind`` filter: ``human`` | ``service``.  Defaults to all.
Returns 503 if the identity registry is not available (community-tier).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/identities \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/infrastructure/autoscaling`

**Get Autoscaling**

Return current autoscaling config for all workloads.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/infrastructure/autoscaling \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /admin/infrastructure/autoscaling/{workload}`

**Update Autoscaling**

Update autoscaling parameters for a workload.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `min_replicas` | `integer` | Yes |  |
| `max_replicas` | `integer` | Yes |  |
| `cpu_threshold` | `any` | No |  |
| `memory_threshold` | `any` | No |  |

**Example:**

        ```bash
        curl -X PUT https://<gateway-host>/admin/infrastructure/autoscaling/{workload} \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "min_replicas": "<integer>",
  "max_replicas": "<integer>"
}'
        ```

---

### `GET /admin/infrastructure/topology`

**Get Topology**

Return current AZ topology info and warnings.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/infrastructure/topology \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /admin/infrastructure/topology`

**Update Topology**

Update topology spread configuration.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `zones` | `array[string]` | Yes | List of AZ names, e.g. ['us-east-1a', 'us-east-1b'] |
| `spread_policy` | `string` | No | K8s topology spread policy |
| `max_skew` | `integer` | No |  |

**Example:**

        ```bash
        curl -X PUT https://<gateway-host>/admin/infrastructure/topology \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "zones": "<array[string]>"
}'
        ```

---

### `GET /admin/inspection/backend`

**Get Active Backend**

Return the active backend name, config (no secrets), fallback chain, and health.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/inspection/backend \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /admin/inspection/backend`

**Swap Backend**

Hot-swap the active inspection backend.
Validates config, instantiates the new backend, calls BackendRegistry.swap(),
persists to Redis, and writes an INSPECTION_BACKEND_CHANGED audit event.

API keys are NOT accepted in this request body — they come from KMS only.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `active_backend` | `string` | Yes | Backend name to activate |
| `fallback_chain` | `any` | No | Ordered fallback backend names. 'fail_closed' terminates the chain. |
| `config` | `any` | No | Non-secret backend configuration. API keys come from KMS only. |

**Example:**

        ```bash
        curl -X PUT https://<gateway-host>/admin/inspection/backend \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "active_backend": "<string>"
}'
        ```

---

### `GET /admin/inspection/backend/{backend_name}/health`

**Get Backend Health**

Ping a specific backend and return its health status.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/inspection/backend/{backend_name}/health \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/inspection/backend/{backend_name}/test`

**Test Backend**

Run a test classification against a registered backend.
Uses a safe, benign test string — never user-provided content.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/inspection/backend/{backend_name}/test \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/inspection/mode`

**Get Mode**

Return the current pipeline mode.

strict     — any detection at or above threshold triggers sanitization/discard.
permissive — detections below threshold are logged but allowed through with an alert.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/inspection/mode \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/inspection/mode`

**Set Mode**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mode` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/inspection/mode \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "mode": "<string>"
}'
        ```

---

### `POST /admin/inspection/model`

**Set Model**

Switch the active classifier model. Model must be available in Ollama.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `model` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/inspection/model \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "model": "<string>"
}'
        ```

---

### `GET /admin/inspection/models`

**List Models**

Return all model tags currently available in the local Ollama instance.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/inspection/models \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/inspection/status`

**Inspection Status**

Return current pipeline configuration and health.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/inspection/status \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/inspection/threshold`

**Get Threshold**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/inspection/threshold \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/inspection/threshold`

**Set Threshold**

Update the sanitization confidence threshold (0.70–0.99).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `threshold` | `number` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/inspection/threshold \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "threshold": "<number>"
}'
        ```

---

### `GET /admin/jwt/config`

**List Jwt Configs**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/jwt/config \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /admin/jwt/config`

**Set Jwt Config**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tenant_id` | `string` | No |  |
| `jwks_url` | `string` | Yes |  |
| `issuer` | `string` | Yes |  |
| `audience` | `string` | Yes |  |
| `fail_closed` | `boolean` | No |  |
| `scope` | `string` | No |  |

**Example:**

        ```bash
        curl -X PUT https://<gateway-host>/admin/jwt/config \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "jwks_url": "<string>",
  "issuer": "<string>",
  "audience": "<string>"
}'
        ```

---

### `POST /admin/jwt/config/test`

**Test Jwt Config**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `token` | `string` | Yes |  |
| `tenant_id` | `string` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/jwt/config/test \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "token": "<string>"
}'
        ```

---

### `DELETE /admin/jwt/config/{tenant_id}`

**Delete Jwt Config**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/jwt/config/{tenant_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/kms/rotate-now`

**Rotate Now**

Trigger an immediate out-of-band rotation.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/kms/rotate-now \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/kms/schedule`

**Get Schedule**

Return the current rotation schedule.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/kms/schedule \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/kms/schedule`

**Update Schedule**

Update the rotation cron schedule. Validates 1-hour minimum interval.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cron_expr` | `string` | Yes | Standard 5-field cron expression. Minimum interval: 1 hour. |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/kms/schedule \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "cron_expr": "<string>"
}'
        ```

---

### `GET /admin/kms/secrets`

**List Secrets**

List secret key names managed by the current KSM provider. Values never returned.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/kms/secrets \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/kms/status`

**Kms Status**

Return provider identity and basic health probe.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/kms/status \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/kms/vault/secrets`

**Vault List Secrets**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/kms/vault/secrets \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/kms/vault/status`

**Vault Status**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/kms/vault/status \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `DELETE /admin/license`

**Revert License**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `confirm` | `boolean` | No |  |

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/license \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/license`

**Get License Status**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/license \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/license/activate`

**Activate License**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/license/activate \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/license/status`

**Machine-readable expiry status**

GET /admin/license/status

Returns a machine-readable summary of licence expiry state.  Also available
as GET /api/v1/license/status (mounted separately in app.py).

Response shape (v2.23.3):
  {
    "valid": bool,
    "expires_at": "ISO-8601" | null,
    "days_remaining": int | null,
    "grace_period_active": bool,
    "mode": "active" | "warning" | "critical" | "expired" | "readonly" | "blocked"
  }

Authentication: admin session required (same as all /admin/* routes).

mode semantics:
  active   — >30 days until expiry, or no expiry date
  warning  — 7–30 days remaining (yellow banner)
  critical — 1–7 days remaining (orange banner)
  expired  — within 14-day grace period (red banner, continues serving)
  readonly — 14–30 days past expiry (admin view-only; new runs blocked)
  blocked  — 30+ days past expiry (HTTP 503 on data-plane)

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/license/status \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/models`

**List Aliases**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/models \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/models`

**Create Alias**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `alias` | `string` | Yes |  |
| `provider` | `string` | Yes |  |
| `model` | `string` | Yes |  |
| `force_local` | `boolean` | No |  |
| `sensitivity_ceiling` | `any` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/models \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "alias": "<string>",
  "provider": "<string>",
  "model": "<string>"
}'
        ```

---

### `GET /admin/models/allocations`

**List Allocations**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/models/allocations \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/models/allocations`

**Create Allocation**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `model_alias` | `string` | Yes |  |
| `target_type` | `string` | Yes |  |
| `target_id` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/models/allocations \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "model_alias": "<string>",
  "target_type": "<string>",
  "target_id": "<string>"
}'
        ```

---

### `DELETE /admin/models/allocations/{alloc_id}`

**Delete Allocation**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/models/allocations/{alloc_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/models/available`

**List Available Models**

List models available from Ollama.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/models/available \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `DELETE /admin/models/{alias}`

**Delete Alias**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/models/{alias} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/opa-assistant/apply`

**Apply Suggestion**

Apply a validated RBAC suggestion to OPA.
The suggestion must pass schema validation before being accepted.
Admin must have reviewed it before calling this endpoint.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `suggestion` | `object` | Yes | Validated RBAC document to apply. |
| `description` | `string` | No | Short description of what this change does (for audit log). |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/opa-assistant/apply \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "suggestion": "<object>"
}'
        ```

---

### `POST /admin/opa-assistant/reject`

**Reject Suggestion**

Record that the admin rejected a suggestion. Audit log only — nothing changes.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reason` | `string` | No |  |

**Example:**

      ```bash
      curl -X POST https://<gateway-host>/admin/opa-assistant/reject \
        -H 'Cookie: __Host-yashigani_admin_session=<token>' \
-H 'Content-Type: application/json' \
-d '{}'
      ```

---

### `GET /admin/opa-assistant/schema`

**Get Schema**

Return the RBAC data document JSON schema for client-side validation.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/opa-assistant/schema \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/opa-assistant/suggest`

**Suggest**

Generate an RBAC JSON suggestion from a natural language description.
The suggestion must be reviewed and approved by the admin before anything changes.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | `string` | Yes | Natural language description of the access control requirement. |
| `include_current` | `boolean` | No | If true, pass the current RBAC document to the assistant as context. |

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `suggestion` | `any` | No |  |
| `valid` | `boolean` | Yes |  |
| `error` | `any` | No |  |
| `raw_response` | `string` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/opa-assistant/suggest \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "description": "<string>"
}'
        ```

---

### `GET /admin/pii/cloud-bypass`

**Get Pii Cloud Bypass**

Return the current PII cloud bypass setting.

When cloud bypass is enabled, PII filtering is skipped for cloud-routed
requests. Local (Ollama) traffic is always filtered.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/pii/cloud-bypass \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /admin/pii/cloud-bypass`

**Update Pii Cloud Bypass**

Toggle the PII cloud bypass setting.

Requires pii_redact license tier (same as REDACT/BLOCK modes) because
enabling bypass has equivalent data exposure implications.

Local (Ollama) traffic is NEVER affected — it is always filtered.
This setting only controls whether PII filtering runs for requests
that the optimization engine routes to cloud providers.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | `boolean` | Yes | When true, PII filtering is skipped for cloud-routed requests. Local (Ollama) traffic is ALWAYS filtered regardless of this flag. Enabling this is an explicit opt-in to allow PII to reach cloud LLMs. |

**Example:**

        ```bash
        curl -X PUT https://<gateway-host>/admin/pii/cloud-bypass \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "enabled": "<boolean>"
}'
        ```

---

### `GET /admin/pii/config`

**Get Pii Config**

Return the current PII detection configuration.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/pii/config \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /admin/pii/config`

**Update Pii Config**

Update PII detection mode and enabled types.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mode` | `string` | Yes | Detection mode: log \| redact \| block |
| `enabled_types` | `array[string]` | No | List of PiiType values to enable. Empty list enables all. |

**Example:**

        ```bash
        curl -X PUT https://<gateway-host>/admin/pii/config \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "mode": "<string>"
}'
        ```

---

### `POST /admin/pii/test`

**Test Pii Detection**

Test PII detection against a sample text.

Uses the currently configured (or override) mode.
Results are returned to the caller; nothing is written to audit logs.
Raw matched values are NEVER returned — only masked_value is included.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `text` | `string` | Yes |  |
| `mode` | `any` | No | Override mode for this test call (log \| redact \| block). Defaults to the currently configured mode. |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/pii/test \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "text": "<string>"
}'
        ```

---

### `GET /admin/ratelimit/config`

**Get Ratelimit Config**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/ratelimit/config \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /admin/ratelimit/config`

**Update Ratelimit Config**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | `boolean` | No |  |
| `adaptive_enabled` | `boolean` | No |  |
| `global_rps` | `number` | No |  |
| `global_burst` | `integer` | No |  |
| `per_ip_rps` | `number` | No |  |
| `per_ip_burst` | `integer` | No |  |
| `per_agent_rps` | `number` | No |  |
| `per_agent_burst` | `integer` | No |  |
| `per_session_rps` | `number` | No |  |
| `per_session_burst` | `integer` | No |  |
| `rpi_scale_medium` | `number` | No |  |
| `rpi_scale_high` | `number` | No |  |
| `rpi_scale_critical` | `number` | No |  |

**Example:**

      ```bash
      curl -X PUT https://<gateway-host>/admin/ratelimit/config \
        -H 'Cookie: __Host-yashigani_admin_session=<token>' \
-H 'Content-Type: application/json' \
-d '{}'
      ```

---

### `GET /admin/ratelimit/endpoints`

**List Endpoint Overrides**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/ratelimit/endpoints \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/ratelimit/endpoints`

**Set Endpoint Override**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `endpoint_template` | `string` | Yes |  |
| `rps` | `integer` | Yes |  |
| `burst` | `integer` | Yes |  |
| `window_seconds` | `integer` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/ratelimit/endpoints \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "endpoint_template": "<string>",
  "rps": "<integer>",
  "burst": "<integer>"
}'
        ```

---

### `DELETE /admin/ratelimit/endpoints/{endpoint_hash}`

**Delete Endpoint Override**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/ratelimit/endpoints/{endpoint_hash} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/ratelimit/reset/{bucket_key}`

**Reset Bucket**

Delete a specific rate limit bucket from Redis (unblocks a client/agent/session).
bucket_key must be a full Redis key, e.g. yashigani:rl:ip:<hash>.
Only keys prefixed yashigani:rl: are accepted.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/ratelimit/reset/{bucket_key} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/ratelimit/status`

**Ratelimit Status**

Return current adaptive multiplier and RPI context.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/ratelimit/status \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/rbac/groups`

**List Groups**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/rbac/groups \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/rbac/groups`

**Create Group**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `display_name` | `string` | Yes |  |
| `allowed_resources` | `array[ResourcePatternIn]` | No |  |
| `rate_limit_override` | `any` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/rbac/groups \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "display_name": "<string>"
}'
        ```

---

### `DELETE /admin/rbac/groups/{group_id}`

**Delete Group**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/rbac/groups/{group_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/rbac/groups/{group_id}`

**Get Group**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/rbac/groups/{group_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /admin/rbac/groups/{group_id}`

**Update Group**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `display_name` | `any` | No |  |
| `allowed_resources` | `any` | No |  |
| `rate_limit_override` | `any` | No |  |

**Example:**

      ```bash
      curl -X PUT https://<gateway-host>/admin/rbac/groups/{group_id} \
        -H 'Cookie: __Host-yashigani_admin_session=<token>' \
-H 'Content-Type: application/json' \
-d '{}'
      ```

---

### `POST /admin/rbac/groups/{group_id}/members`

**Add Member**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/rbac/groups/{group_id}/members \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "<string>"
}'
        ```

---

### `DELETE /admin/rbac/groups/{group_id}/members/{email}`

**Remove Member**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/rbac/groups/{group_id}/members/{email} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/rbac/policy/push`

**Force Push**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/rbac/policy/push \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/rbac/users/{email}/groups`

**Get User Groups**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/rbac/users/{email}/groups \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/sensitivity/patterns`

**List Patterns**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/sensitivity/patterns \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/sensitivity/patterns`

**Create Pattern**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `classification` | `string` | Yes |  |
| `type` | `string` | No |  |
| `pattern` | `string` | Yes |  |
| `description` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/sensitivity/patterns \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "classification": "<string>",
  "pattern": "<string>",
  "description": "<string>"
}'
        ```

---

### `DELETE /admin/sensitivity/patterns/{pattern_id}`

**Delete Pattern**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/sensitivity/patterns/{pattern_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/sensitivity/status`

**Pipeline Status**

Return which layers of the sensitivity pipeline are active.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/sensitivity/status \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/sensitivity/test`

**Test Classify**

Test the sensitivity classifier against a text sample.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `text` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/sensitivity/test \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "text": "<string>"
}'
        ```

---

### `GET /admin/settings/webauthn/credentials`

**List Credentials**

List all WebAuthn credentials registered for the current admin account.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/settings/webauthn/credentials \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `DELETE /admin/settings/webauthn/credentials/{credential_id}`

**Delete Credential**

Delete a WebAuthn credential by its UUID.
Only the credential's owner can delete it.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/settings/webauthn/credentials/{credential_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /admin/users`

**List Users**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/admin/users \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/users`

**Create User**

Create a user account. Server generates a 16-char temporary password
and a TOTP secret. Both are returned once — admin shares them
out-of-band with the user. User must change password and provision
TOTP at first login.

Gap 1 / v2.23.4: email is now the canonical identity for user-tier
accounts. The `email` field is REQUIRED. `username` is derived from
the email local part if not supplied.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `email` | `string (email)` | Yes | Email address for the new user (required). Used as the canonical identity. |
| `username` | `any` | No | Optional username override. If omitted, derived from email using the Q1 algorithm: <sanitised-local><first-domain-label>, lowercase, max 64 chars. |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/users \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "email": "<string (email)>"
}'
        ```

---

### `DELETE /admin/users/{username}`

**Delete User**

Delete a user. Blocked if last user (USER_MINIMUM_VIOLATION).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/admin/users/{username} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/users/{username}/api-key`

**Admin Issue User Api Key**

Admin override — issue or rotate a target user's API key.

Requirements:
  - Caller: admin tier + fresh StepUp (StepUpAdminSession).
  - Target: must exist, must be account_tier == "user".
  - 30-second grace window on the prior token (client transition window).

Returns plaintext_token ONCE — admin must deliver securely to the user.
Audit-logged with acting admin identity.

Gap 4 / v2.23.4 arch-completion — mirrors admin override for agents
(agents/token_rotation.py pattern).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/users/{username}/api-key \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/users/{username}/disable`

**Disable User**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/users/{username}/disable \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/users/{username}/enable`

**Enable User**

Re-enable a disabled user account.

Iris MISSING-04 / GROUP-2-6: enforce end-user seat limit before re-enabling.
A disabled user is not counted in the canonical end-user count, so re-enabling
one could push the deployment over the licensed seat limit.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/admin/users/{username}/enable \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /admin/users/{username}/full-reset`

**Full Reset User**

Full reset a user account. Requires admin TOTP re-verification.
Strips all RBAC roles, sessions, API keys, TOTP, password.
Retains: username, UUID, audit history.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `totp_code` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/admin/users/{username}/full-reset \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "totp_code": "<string>"
}'
        ```

---

### `POST /admin/users/{username}/reactivate`

**Reactivate User**

Reactivate a suspended HUMAN identity for a user-tier account.

Q3 / v2.23.4 arch-completion: auto-reactivate on login was reverted (Tiago
directive 2026-05-15 — "admin-action-only, audit-logged"). This endpoint is
the sole reactivation path.

Requirements:
  - Caller: admin tier + fresh StepUp (StepUpAdminSession, TOTP within 5 min).
  - Target: must exist, must be account_tier == "user" (404 if admin).
  - Resolves target's HUMAN identity via slug; calls registry.reactivate().
  - Audit-logged with admin actor + target user + optional reason.

Returns 200 with reactivated identity metadata on success.
Returns 404 if user not found or not user-tier.
Returns 404 if no HUMAN identity exists in registry (user never logged in).
Returns 409 if identity is already active (idempotent — callers may retry).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reason` | `any` | No | Optional admin-supplied reason for this reactivation (audit log). |

**Example:**

      ```bash
      curl -X POST https://<gateway-host>/admin/users/{username}/reactivate \
        -H 'Cookie: __Host-yashigani_admin_session=<token>' \
-H 'Content-Type: application/json' \
-d '{}'
      ```

---

### `DELETE /api/v1/admin/auth/hibp/key`

**Clear Hibp Key**

Clear the HIBP API key stored in the admin panel.

Falls back to env var YASHIGANI_HIBP_API_KEY, then anonymous (no key).
Requires step-up TOTP (ASVS V6.8.4).

Audit event HIBP_API_KEY_CLEARED is written.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/api/v1/admin/auth/hibp/key \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PUT /api/v1/admin/auth/hibp/key`

**Set Hibp Key**

Set (or update) the HIBP API key stored in the admin panel.

Requires step-up TOTP (ASVS V6.8.4). The key is encrypted at rest using
pgp_sym_encrypt with the deployment AES key.

Audit event HIBP_API_KEY_UPDATED is written. The key value is NOT written
to the audit log — only the masked hint (first 3 + '…' + last 3 chars).

Returns the new status (same shape as GET /status).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_key` | `string` | Yes | HIBP API key for rate-limit lift or mirror auth. Empty string clears the stored key (prefer DELETE instead). Alphanumeric + hyphens only, 8–128 chars. |

**Example:**

        ```bash
        curl -X PUT https://<gateway-host>/api/v1/admin/auth/hibp/key \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "api_key": "<string>"
}'
        ```

---

### `GET /api/v1/admin/auth/hibp/status`

**Hibp Key Status**

Return HIBP API key configuration status.

Response never includes the full key value — only a masked hint
(first 3 + '…' + last 3 chars) when a key is configured.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/api/v1/admin/auth/hibp/status \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /api/v1/admin/pki/bundle/{service}`

**Download Cert Bundle**

Download PEM bundle for a service: leaf cert + intermediate(s).

NEVER includes the private key.
Content-Disposition: attachment forces browser to download rather than render.
Content-Type: application/x-pem-file

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/api/v1/admin/pki/bundle/{service} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /api/v1/admin/pki/chain/{service}`

**Get Cert Chain**

Return cert chain metadata for a service.

CWE-200: private key material is never included.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `service` | `string` | Yes |  |
| `subject_cn` | `string` | Yes |  |
| `issuer_cn` | `string` | Yes |  |
| `serial_hex` | `string` | Yes |  |
| `not_before` | `string` | Yes |  |
| `not_after` | `string` | Yes |  |
| `fingerprint_sha256` | `string` | Yes |  |
| `dns_sans` | `array[string]` | Yes |  |
| `uri_sans` | `array[string]` | Yes |  |
| `ip_sans` | `array[string]` | Yes |  |
| `chain_depth` | `integer` | Yes |  |
| `ca_mode` | `string` | Yes |  |
| `needs_renewal` | `boolean` | Yes |  |
| `last_rotated_at` | `any` | No |  |

**Example:**

```bash
curl -X GET https://<gateway-host>/api/v1/admin/pki/chain/{service} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /api/v1/admin/pki/rotate/{service}`

**Rotate Cert**

Trigger cert rotation for a service.

Requires step-up TOTP (ASVS V6.8.4).
Emits PKI_CERT_ROTATED or PKI_CERT_ROTATION_FAILED audit events.
The CA driver determines the rotation mechanism (internal or BYO).
Never silently falls back between drivers.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `request_id` | `string` | Yes |  |
| `service` | `string` | Yes |  |
| `success` | `boolean` | Yes |  |
| `error` | `any` | No |  |
| `new_chain` | `any` | No |  |

**Example:**

```bash
curl -X POST https://<gateway-host>/api/v1/admin/pki/rotate/{service} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /api/v1/admin/pki/status`

**Pki Status**

List all live services with cert health summary.

Returns a summary row per service; individual errors are surfaced in each
row (error field) — the endpoint itself does not 500 if one service fails.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ca_mode` | `string` | Yes |  |
| `services` | `array[ServiceCertStatus]` | Yes |  |

**Example:**

```bash
curl -X GET https://<gateway-host>/api/v1/admin/pki/status \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /api/v1/admin/secrets/rotate`

**Rotate Secret**

Admin-triggered secret rotation.

Requires fresh step-up TOTP (ASVS V6.8.4).
Writes audit events for request, success, and failure.
Secret values are NEVER written to audit logs.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `secret` | `string` | Yes |  |

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `request_id` | `string` | Yes |  |
| `secret` | `string` | Yes |  |
| `success` | `boolean` | Yes |  |
| `rotated_at` | `string` | Yes |  |
| `error` | `any` | No |  |
| `reverted` | `boolean` | No |  |
| `revert_failed` | `boolean` | No |  |
| `child_results` | `array[ChildRotationResult]` | No |  |
| `warning` | `any` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/api/v1/admin/secrets/rotate \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "secret": "<string>"
}'
        ```

---

### `GET /api/v1/admin/webauthn/credentials`

**List registered WebAuthn credentials**

List all WebAuthn credentials registered for the authenticated admin.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/api/v1/admin/webauthn/credentials \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `DELETE /api/v1/admin/webauthn/credentials/{credential_id}`

**Revoke a WebAuthn credential (step-up required)**

Revoke a WebAuthn credential by UUID.
Requires a fresh TOTP step-up (within YASHIGANI_STEPUP_TTL_SECONDS, default 5 min).

Recovery: password + TOTP login is always available as a fallback.
Audit event: WEBAUTHN_CREDENTIAL_REVOKED.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/api/v1/admin/webauthn/credentials/{credential_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /api/v1/admin/webauthn/login/finish`

**Complete WebAuthn authentication and issue session (public endpoint)**

Complete the WebAuthn authentication ceremony.
PUBLIC endpoint — does not require a session cookie.

On success: verifies assertion, creates admin session cookie, returns 200.
On failure: WEBAUTHN_LOGIN_FAILURE audit event + 401.

Audit events: WEBAUTHN_LOGIN_SUCCESS | WEBAUTHN_LOGIN_FAILURE.

W20 (Iris PR #62): applies the same per-IP blocklist + progressive-delay
throttle as login/start and the password login route.  Records auth failure
on bad assertion (sign_count rollback, wrong key, bad challenge) so that
automated probing accumulates throttle delay across attempts.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | `string` | Yes |  |
| `credential_response` | `object` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/api/v1/admin/webauthn/login/finish \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "username": "<string>",
  "credential_response": "<object>"
}'
        ```

---

### `POST /api/v1/admin/webauthn/login/start`

**Begin WebAuthn authentication (public endpoint)**

Begin the WebAuthn authentication ceremony.
PUBLIC endpoint — does not require a session cookie.

Looks up the admin's account_id by username, then generates a challenge.
Returns allow_credentials list and challenge for navigator.credentials.get().

W20 (Iris PR #62): applies the same per-IP blocklist + progressive-delay
throttle as the password login route.  An unauthenticated DB-query endpoint
without a rate gate is an invitation to enumerate admin usernames at scale.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | `string` | Yes | Admin username (email). Used to look up registered credentials. |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/api/v1/admin/webauthn/login/start \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "username": "<string>"
}'
        ```

---

### `POST /api/v1/admin/webauthn/register/finish`

**Complete WebAuthn credential registration**

Complete WebAuthn registration, verify attestation, and persist credential.
Audit event: WEBAUTHN_CREDENTIAL_REGISTERED.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credential_response` | `object` | Yes |  |
| `credential_name` | `string` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/api/v1/admin/webauthn/register/finish \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "credential_response": "<object>"
}'
        ```

---

### `POST /api/v1/admin/webauthn/register/start`

**Begin WebAuthn credential registration**

Start the WebAuthn registration ceremony for a new FIDO2 credential.
Returns PublicKeyCredentialCreationOptions for the browser.
Caller must be authenticated (admin session cookie required).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credential_name` | `string` | No | Human-readable label for this credential (e.g. 'YubiKey 5 Nano work'). |

**Example:**

      ```bash
      curl -X POST https://<gateway-host>/api/v1/admin/webauthn/register/start \
        -H 'Cookie: __Host-yashigani_admin_session=<token>' \
-H 'Content-Type: application/json' \
-d '{}'
      ```

---

### `GET /api/v1/license/status`

**Machine-readable licence expiry status (v2.23.3)**

GET /admin/license/status

Returns a machine-readable summary of licence expiry state.  Also available
as GET /api/v1/license/status (mounted separately in app.py).

Response shape (v2.23.3):
  {
    "valid": bool,
    "expires_at": "ISO-8601" | null,
    "days_remaining": int | null,
    "grace_period_active": bool,
    "mode": "active" | "warning" | "critical" | "expired" | "readonly" | "blocked"
  }

Authentication: admin session required (same as all /admin/* routes).

mode semantics:
  active   — >30 days until expiry, or no expiry date
  warning  — 7–30 days remaining (yellow banner)
  critical — 1–7 days remaining (orange banner)
  expired  — within 14-day grace period (red banner, continues serving)
  readonly — 14–30 days past expiry (admin view-only; new runs blocked)
  blocked  — 30+ days past expiry (HTTP 503 on data-plane)

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/api/v1/license/status \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /auth/webauthn/authenticate/begin`

**Authenticate Begin**

Start WebAuthn authentication ceremony.
Returns PublicKeyCredentialRequestOptions for the browser.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/auth/webauthn/authenticate/begin \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /auth/webauthn/authenticate/complete`

**Authenticate Complete**

Complete WebAuthn authentication assertion.
Verifies assertion and updates sign_count for replay protection.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credential_response` | `object` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/auth/webauthn/authenticate/complete \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "credential_response": "<object>"
}'
        ```

---

### `POST /auth/webauthn/register/begin`

**Register Begin**

Start WebAuthn credential registration.
Returns PublicKeyCredentialCreationOptions for the browser.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_name` | `string` | Yes |  |
| `credential_name` | `any` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/auth/webauthn/register/begin \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "user_name": "<string>"
}'
        ```

---

### `POST /auth/webauthn/register/complete`

**Register Complete**

Complete WebAuthn credential registration.
Verifies attestation and stores the new credential.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `credential_response` | `object` | Yes |  |
| `credential_name` | `any` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/auth/webauthn/register/complete \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "credential_response": "<object>"
}'
        ```

---

### `GET /dashboard/alerts`

**Recent Alerts**

Return the most recent admin alerts from the in-memory ring buffer.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/dashboard/alerts \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /dashboard/health`

**System Health**

Aggregate health check across all subsystems.
Returns per-component status and an overall ok/degraded/critical status.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/dashboard/health \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /dashboard/resources`

**Resource Pressure**

Return the current resource pressure index and TTL tier from cgroup v2.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/dashboard/resources \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /healthz`

**Healthz**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/healthz \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /internal/metrics`

**Internal Metrics**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/internal/metrics \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /me/api-key`

**Issue Api Key**

Issue or rotate the caller's HUMAN-identity Bearer token.

Requirements:
  - account_tier == "user"
  - force_password_change == false
  - force_totp_provision == false
  - Fresh StepUp (TOTP within last STEPUP_TTL_SECONDS seconds)

Returns plaintext_token ONCE. User must record it — it cannot be
retrieved again via any route.

Prior token is immediately invalidated (no grace period on self-rotation).
Rate-limited to 5 attempts per hour per user.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X POST https://<gateway-host>/me/api-key \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /me/api-keys`

**List Api Keys**

Return current API key metadata for the caller.

NEVER includes plaintext token. NEVER re-fetchable.
Returns empty array if no key has been issued yet.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/me/api-keys \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `DELETE /me/api-keys/{key_id}`

**Revoke Api Key**

Revoke a specific API key for the caller.

Returns 204 on success.
403 if the key belongs to another user.
404 if the key does not exist.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/me/api-keys/{key_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `GET /scim/v2/Groups`

**Scim List Groups**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/scim/v2/Groups \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /scim/v2/Groups`

**Scim Create Group**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schemas` | `array[string]` | No |  |
| `displayName` | `string` | Yes |  |
| `members` | `any` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/scim/v2/Groups \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "displayName": "<string>"
}'
        ```

---

### `DELETE /scim/v2/Groups/{group_id}`

**Scim Delete Group**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/scim/v2/Groups/{group_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `PATCH /scim/v2/Groups/{group_id}`

**Scim Patch Group**

SCIM PATCH — supports add/remove on the 'members' attribute.

Each Operation value for 'members' must be a list of:
    [{"value": "<email>", "display": "<optional>"}, ...]

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schemas` | `array[string]` | No |  |
| `Operations` | `array[ScimPatchOperation]` | Yes |  |

**Example:**

        ```bash
        curl -X PATCH https://<gateway-host>/scim/v2/Groups/{group_id} \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "Operations": "<array[ScimPatchOperation]>"
}'
        ```

---

### `GET /scim/v2/Users`

**Scim List Users**

List SCIM users with optional filter.

ACS gap #95 (injection): filter is now a typed FastAPI Query param with
max_length=256, replacing the previous raw request.query_params.get()
which bypassed Pydantic/FastAPI input validation (OWASP ASVS V5.1.1).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X GET https://<gateway-host>/scim/v2/Users \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---

### `POST /scim/v2/Users`

**Scim Provision User**

Provision a user.  If the user is already a member of groups, this is
a no-op (idempotent).  The userName field is treated as the user's email.
Membership is assigned separately via SCIM Group PATCH.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schemas` | `array[string]` | No |  |
| `userName` | `string` | Yes |  |
| `name` | `any` | No |  |
| `emails` | `any` | No |  |
| `active` | `boolean` | No |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/scim/v2/Users \
          -H 'Cookie: __Host-yashigani_admin_session=<token>' \
  -H 'Content-Type: application/json' \
  -d '{
  "userName": "<string>"
}'
        ```

---

### `DELETE /scim/v2/Users/{user_id}`

**Scim Deprovision User**

Deprovision a user by removing them from all groups.
user_id is treated as the user's email address.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token>

**Example:**

```bash
curl -X DELETE https://<gateway-host>/scim/v2/Users/{user_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token>'
```

---
