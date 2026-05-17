# Yashigani Auth API Reference

Authentication endpoints shared by the Backoffice admin portal and
user login flow.

## Login flow

1. `POST /auth/login` — submit username + password
2. `POST /auth/stepup` — submit TOTP code (required for privileged ops)
3. Use the returned session cookie on subsequent requests

## Endpoints

### `GET /auth/allowed-ips`

**List Allowed Ips**

List all IPs/CIDRs in the login allowlist. Empty = allow all.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X GET https://<gateway-host>/auth/allowed-ips \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `POST /auth/allowed-ips`

**Add Allowed Ip**

Add an IP or CIDR to the login allowlist. Supports IPv4 and IPv6.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X POST https://<gateway-host>/auth/allowed-ips \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `DELETE /auth/allowed-ips/{ip_or_cidr}`

**Remove Allowed Ip**

Remove an IP/CIDR from the allowlist.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X DELETE https://<gateway-host>/auth/allowed-ips/{ip_or_cidr} \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `GET /auth/blocked-ips`

**List Blocked Ips**

List permanently blocked IPs AND currently soft-throttled IPs.

Previously only returned permanent blocks, which gave operators no
self-visibility when they were themselves being slow-throttled
(QA Wave 2 Issue F). Now includes:

  * ``blocked_ips`` — permanent blocks (auth:blocked:*)
  * ``throttled_ips`` — IPs with a current non-zero throttle level
    (auth:throttle:ip:* > 0), mapped to {level, delay_s, fail_count}
  * ``self`` — the caller's own IP + throttle state so an admin
    can see if they are throttled from the UI (fixes the "login
    page hangs and /auth/blocked-ips says {}" diagnostic gap)

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X GET https://<gateway-host>/auth/blocked-ips \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `DELETE /auth/blocked-ips/{ip}`

**Unblock Ip**

Remove an IP from the permanent blocklist (admin only).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X DELETE https://<gateway-host>/auth/blocked-ips/{ip} \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `POST /auth/login`

**Login**

Authenticate with username + password + TOTP.
Issues a session cookie on success.
Returns 401 for any failure (no credential enumeration).
Includes brute-force throttle per ASVS 6.3.5.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | `string` | Yes |  |
| `password` | `string` | Yes |  |
| `totp_code` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/auth/login \
          -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)' \
  -H 'Content-Type: application/json' \
  -d '{
  "username": "<string>",
  "password": "<string>",
  "totp_code": "<string>"
}'
        ```

---

### `POST /auth/logout`

**Logout**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X POST https://<gateway-host>/auth/logout \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `POST /auth/password/change`

**Change Password**

Force-change password. Invalidates ALL sessions (ASVS V2.1.4).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `current_password` | `string` | Yes |  |
| `new_password` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/auth/password/change \
          -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)' \
  -H 'Content-Type: application/json' \
  -d '{
  "current_password": "<string>",
  "new_password": "<string>"
}'
        ```

---

### `POST /auth/password/self-reset`

**Self Service Password Reset**

Self-service password reset — no session required.
User proves identity via username + TOTP code, receives a new temporary password.
ASVS V2.1: authenticated password reset without admin intervention.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | `string` | Yes |  |
| `totp_code` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/auth/password/self-reset \
          -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)' \
  -H 'Content-Type: application/json' \
  -d '{
  "username": "<string>",
  "totp_code": "<string>"
}'
        ```

---

### `GET /auth/sso/2fa`

**Sso 2Fa Page**

Serve the 2FA verification prompt after SSO.
The user must submit their Yashigani TOTP code to complete login.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X GET https://<gateway-host>/auth/sso/2fa \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `POST /auth/sso/2fa/verify`

**Sso 2Fa Verify**

Verify the Yashigani TOTP code after SSO authentication.
On success, upgrade the pending session to a full session.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X POST https://<gateway-host>/auth/sso/2fa/verify \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `GET /auth/sso/oidc/{idp_id}`

**Initiate Oidc**

Initiate an OIDC authorization flow.
Generates a cryptographically random state + nonce, stores them in Redis
with a 10-minute TTL, then redirects the browser to the IdP.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X GET https://<gateway-host>/auth/sso/oidc/{idp_id} \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `GET /auth/sso/oidc/{idp_id}/callback`

**Oidc Callback**

Handle the OIDC authorization code callback from the IdP.

On success: resolves/creates the Yashigani identity, issues a session
cookie, and redirects to /chat.
On failure: redirects to /login with an error query parameter.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X GET https://<gateway-host>/auth/sso/oidc/{idp_id}/callback \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `POST /auth/sso/saml/{idp_id}/acs`

**Saml Acs**

SAML v2 Assertion Consumer Service endpoint.
Receives the IdP POST with SAMLResponse, validates the assertion,
resolves/creates the identity, and issues a session.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X POST https://<gateway-host>/auth/sso/saml/{idp_id}/acs \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `GET /auth/sso/select`

**List Idps**

Return the list of enabled IdPs available for SSO login.
Unauthenticated — shown to anonymous users on the login page.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X GET https://<gateway-host>/auth/sso/select \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `GET /auth/status`

**Session Status**

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X GET https://<gateway-host>/auth/status \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `POST /auth/stepup`

**Stepup Verify**

Step-up TOTP verification for high-value admin flows (ASVS V6.8.4).

The admin submits their current TOTP code.  On success, the session's
last_totp_verified_at is updated.  The caller may then retry the
high-value endpoint that returned step_up_required.  The verification
window is YASHIGANI_STEPUP_TTL_SECONDS (default 300 s / 5 min).

Security guarantees:
- Replay prevention: codes are checked against the Postgres-backed
  used_totp_codes table (same mechanism as login TOTP).
- Wrong code: 401, session is NOT updated, TOTP failure counter is
  incremented on the session prefix.
- No credential enumeration: same HTTP 401 body for wrong code or
  no session.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `totp_code` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/auth/stepup \
          -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)' \
  -H 'Content-Type: application/json' \
  -d '{
  "totp_code": "<string>"
}'
        ```

---

### `POST /auth/totp/provision`

**Provision Totp**

Atomic TOTP enrolment — back-compat for clients that already hold
the seed (e.g. CLI provisioning flows where the secret is delivered
out-of-band). Generates a fresh seed, verifies the provided code
against it, and on success commits the enrolment in one call.

For the first-time web-UI flow, prefer the split endpoints:
:func:`provision_totp_start` + :func:`provision_totp_confirm`
(QA Wave 2 Issue C).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `totp_code` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/auth/totp/provision \
          -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)' \
  -H 'Content-Type: application/json' \
  -d '{
  "totp_code": "<string>"
}'
        ```

---

### `POST /auth/totp/provision/confirm`

**Provision Totp Confirm**

Finalise TOTP enrolment by confirming a code generated from the seed
returned by :func:`provision_totp_start`.

On success the account is fully enrolled
(``force_totp_provision=False``). On failure the seed is preserved
so the client can retry without losing the QR code / recovery codes
(protects against time-drift and typo retries).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `totp_code` | `string` | Yes |  |

**Example:**

        ```bash
        curl -X POST https://<gateway-host>/auth/totp/provision/confirm \
          -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)' \
  -H 'Content-Type: application/json' \
  -d '{
  "totp_code": "<string>"
}'
        ```

---

### `POST /auth/totp/provision/start`

**Provision Totp Start**

Start TOTP enrolment for the current account.

Generates a fresh TOTP seed + recovery codes and returns the QR code
+ provisioning URI for the client to display. Does NOT clear
``force_totp_provision`` — the account cannot complete authenticated
actions until :func:`provision_totp_confirm` verifies a code derived
from the returned seed.

Part of the split-enrolment flow (QA Wave 2 Issue C). The previous
atomic ``/totp/provision`` required a ``totp_code`` on the same call
that returned the seed, which was impossible for a first-time client.

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X POST https://<gateway-host>/auth/totp/provision/start \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---

### `GET /auth/verify`

**Verify Session**

Caddy forward_auth endpoint. Validates the session cookie and returns
the authenticated user's identity in response headers.
200 + X-Forwarded-User header → Caddy proceeds with the request.
401 → Caddy redirects to login.
Checks both user cookie (__Host-yashigani_session) and admin cookie (__Host-yashigani_admin_session).

**Auth required:** Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)

**Example:**

```bash
curl -X GET https://<gateway-host>/auth/verify \
  -H 'Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)'
```

---
