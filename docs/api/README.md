# Yashigani API Reference

| Document | Audience | Description |
|----------|----------|-------------|
| [Gateway API](gateway-api.md) | Operators, AI agents | LLM proxy + MCP traffic control |
| [Admin API](admin-api.md) | Operators | Backoffice management plane |
| [Auth API](auth-api.md) | All | Login, step-up, session management |

## Quick start

1. Log in via the Backoffice at `https://<host>:8443/admin/login`
2. Create an API key for your agent identity under **Agents**
3. Use `Authorization: Bearer <key>` on all Gateway API requests

## Interactive docs

Once logged in, the interactive Swagger UI is available at:

- Backoffice: `https://<host>:8443/admin/api-docs`
- Backoffice (ReDoc): `https://<host>:8443/admin/api-redoc`
- Gateway: `https://<host>/docs` (requires valid Bearer token)

Last updated: 2026-05-17
