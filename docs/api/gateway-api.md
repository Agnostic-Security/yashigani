# Yashigani Gateway API Reference

The Gateway API is the AI traffic control plane. All LLM requests and
MCP protocol traffic passes through this endpoint.

## Authentication

All requests require a valid API key issued by your administrator via
the Backoffice.

```
Authorization: Bearer <api-key>
```

Alternatively, if your operator has configured SSO, the Gateway accepts
an `X-Forwarded-User` header injected by the Caddy reverse proxy after
a successful SSO login.

## Transport

The Gateway listens on HTTPS only. Mutual TLS (mTLS) is enforced by
the Caddy edge layer for agent-to-gateway connections. API key holders
connect over standard HTTPS.

## Endpoints

### `POST /v1/chat/completions`

**Chat Completions**

OpenAI-compatible chat completions endpoint.

Full pipeline:
1. Identity resolution (API key or SSO headers)
2. Sensitivity scan on input
3. Complexity scoring
4. Budget check
5. Route to backend (local Ollama or cloud)
6a. [streaming] Forward with stream=true; inspect chunks via StreamingInspector;
    return StreamingResponse. Budget headers skipped (see module docstring).
6b. [buffered]  Buffer full response (legacy path, v1.0 Decision 13).
7. Response inspection (buffered path only — streaming uses StreamingInspector)
8. Token counting + budget recording
9. Audit event
10. Return response with budget headers (buffered path only)

**Auth required:** Authorization: Bearer <api-key>

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `model` | `string` | Yes | Model name or alias |
| `messages` | `array[ChatMessage]` | Yes |  |
| `temperature` | `any` | No |  |
| `max_tokens` | `any` | No |  |
| `top_p` | `any` | No |  |
| `stream` | `boolean` | No |  |
| `force_local` | `any` | No |  |
| `force_cloud` | `any` | No |  |

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | `string` | Yes |  |
| `object` | `string` | No |  |
| `created` | `integer` | Yes |  |
| `model` | `string` | Yes |  |
| `choices` | `array[ChatCompletionChoice]` | Yes |  |
| `usage` | `CompletionUsage` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/v1/chat/completions \
          -H 'Authorization: Bearer <api-key>' \
  -H 'Content-Type: application/json' \
  -d '{
  "model": "<string>",
  "messages": "<array[ChatMessage]>"
}'
        ```

---

### `GET /v1/models`

**List Models**

List available models (for Open WebUI model picker).

AUTH REQUIRED. QA #59 / FINDING-59-01 (2026-04-29): unauthenticated
callers were receiving the full Ollama model list + every active service
identity slug + every active agent slug — internal-topology disclosure
(OWASP API9 Improper Inventory Management, A01 Broken Access Control).
Caddy's `/v1/*` block does not gate via `forward_auth`; the gate is here.
Open WebUI carries the admin session cookie (it lives at /chat/* behind
the same Caddy auth) so the picker still populates after login. MCP
clients that hit `/v1/models` directly must present a valid Bearer
token or X-Forwarded-User header to enumerate.

**Auth required:** Authorization: Bearer <api-key>

**Response (200):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `object` | `string` | No |  |
| `data` | `array[ModelInfo]` | Yes |  |

**Example:**

```bash
curl -X GET https://<gateway-host>/v1/models \
  -H 'Authorization: Bearer <api-key>'
```

---
