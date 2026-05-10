# BOPLA Per-Property Allowlist Audit

**Control:** OWASP API3:2023 — Broken Object Property Level Authorization  
**Standard:** ASVS V4.2.1 — Verify that object-level property access authorisation is enforced  
**Issue:** #90 (v2.23.3)  
**Last updated:** 2026-05-09T00:00:00+01:00

---

## Summary

Every backoffice endpoint that returns account, credential, or configuration data is
enumerated below with its public-view Pydantic model and the set of sensitive properties
explicitly excluded.

The canonical allowlist schema lives at:
`src/yashigani/backoffice/schemas/bopla.py`

---

## Endpoint Allowlist Table

| Endpoint | Method | Response type | Public-view model | Sensitive fields excluded |
|---|---|---|---|---|
| `/admin/accounts` (list admins) | GET | admin account list | `AdminAccountPublic` | `password_hash`, `totp_secret`, `recovery_codes`, `failed_attempts`, `locked_until`, `totp_failed_attempts`, `totp_backoff_until`, `last_login_at`, `inactive_disabled_at` |
| `/admin/accounts` (create admin) | POST | one-time bootstrap | `AdminCreateResponse` | _(exception — see below)_ |
| `/admin/users` (list users) | GET | user account list | `UserAccountPublic` | `password_hash`, `totp_secret`, `recovery_codes`, `failed_attempts`, `locked_until`, `totp_failed_attempts`, `totp_backoff_until`, `last_login_at`, `inactive_disabled_at` |
| `/admin/users` (create user) | POST | one-time bootstrap | `UserCreateResponse` | _(exception — see below)_ |
| `/admin/audit/siem` (list targets) | GET | SIEM target list | `SiemTargetPublic` | `auth_value` (bearer token / API key) |
| `/auth/sso/select` (list IdPs) | GET | IdP list | `IdPPublic` | `client_secret`, `client_id`, `private_key`, `signing_cert`, `org_id`, `default_sensitivity` |
| `/admin/jwt/config` (list configs) | GET | JWT config list | `JWTConfigPublic` | _(no secrets in config rows; allowlist enforced for schema stability)_ |
| `/admin/jwt/config/test` (test token) | POST | JWT test result | `JWTTestResultPublic` + `SAFE_JWT_CLAIMS` | `email`, `phone_number`, `address`, `birthdate`, `ssn`, and any claim not in the `SAFE_JWT_CLAIMS` set |
| `/admin/agents` (list agents) | GET | agent list | `AgentResponse` (Pydantic model) | `token_hash` (hashed PSK; token itself never stored) |
| `/admin/agents/{id}` (get agent) | GET | agent detail | `AgentResponse` (Pydantic model) | `token_hash` |
| `/admin/agents/{id}/token/rotate` | POST | rotate response | `AgentRotateResponse` (Pydantic model) | _(token returned once on rotate — same as create exception)_ |

---

## Intentional One-Time-Delivery Exceptions

The following endpoints intentionally return credentials as part of bootstrap flows.
These are not BOPLA violations — they are the only delivery channel for the credential
and the credential is not stored in retrievable form after this response.

### `POST /admin/accounts` — `AdminCreateResponse`

Returns `temporary_password` and `totp_secret` exactly once at account creation.
The admin must deliver these to the new account holder out-of-band. After this
call:
- `temporary_password` is stored as an Argon2id hash (not reversible)
- `totp_secret` is stored in the auth service but is **not** returned on any
  subsequent GET endpoint

**Mitigation:** The account has `force_password_change=True` and `force_totp_provision=False`
(pre-provisioned). The admin is authenticated and the audit log records the creation event
(`admin_account_created`).

### `POST /admin/users` — `UserCreateResponse`

Same rationale as admin create.

### `POST /admin/agents` (register) + `POST /admin/agents/{id}/token/rotate`

Returns the plaintext PSK token exactly once (on create or rotate). Stored as
bcrypt hash. The response body explicitly states "Store immediately — never shown again."

---

## Fields Never Returned (Global)

These fields exist on internal models but have no public endpoint that returns them:

| Field | Model | Reason |
|---|---|---|
| `password_hash` | `AccountRecord` | Argon2id hash; exposure enables offline cracking |
| `totp_secret` | `AccountRecord` | TOTP seed; exposure allows OTP forgery (except one-time create) |
| `recovery_codes` | `AccountRecord` | Backup codes; exposure allows session takeover |
| `failed_attempts` | `AccountRecord` | Lockout counter; exposure aids timing attacks |
| `locked_until` | `AccountRecord` | Lockout expiry; same reasoning |
| `totp_failed_attempts` | `AccountRecord` | TOTP-specific backoff counter |
| `totp_backoff_until` | `AccountRecord` | TOTP backoff expiry |
| `auth_value` | `SiemTarget` | API key / HEC token — write-only credential |
| `client_secret` | IdPConfig | OAuth2 client secret |
| `private_key` | IdPConfig | SAML private key |

---

## Schema Location

```
src/yashigani/backoffice/schemas/
├── __init__.py          — barrel exports
└── bopla.py             — all public-view models + SAFE_JWT_CLAIMS allowlist
```

## Tests

`src/tests/unit/test_v2233_bopla_allowlist.py` — parametrised assertions that
sensitive fields are absent from each list/get response. Runs in the unit test
suite (`pytest src/tests/unit/`).
