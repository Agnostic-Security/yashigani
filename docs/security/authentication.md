# Authentication Controls

<!-- Last updated: 2026-05-09T00:00:00+00:00 — v2.23.3 -->

This document describes authentication security controls in Yashigani, covering
local-auth password policy, TOTP multi-factor authentication, WebAuthn/FIDO2
hardware key support, and password hygiene enforcement.

ASVS coverage: V2.1, V2.4, V2.7, V2.8. CMMC L2 coverage: IA.L2-3.5.1 through
IA.L2-3.5.8.

---

## Local Authentication

Yashigani's local authentication mode (`YASHIGANI_AUTH_MODE=local`) stores
accounts in Postgres and enforces the following controls at the application layer.

### Password minimum length

Minimum 36 characters. Enforced at account creation, password change, and
admin-triggered reset. OWASP ASVS V2.1.1.

### Password complexity

Argon2id hashing (OWASP ASVS V2.4): `m=65536`, `t=3`, `p=4`, `hash_len=32`,
`salt_len=16`. Parameters are stored per-hash; a future parameter change
triggers automatic rehash on next successful login.

### Breach check (HIBP)

All user-chosen passwords are checked against the Have I Been Pwned k-Anonymity
API before acceptance. Only the first 5 characters of the SHA-1 hash are
transmitted — the plaintext never leaves the system. Fail-open: HIBP API
unreachability does not block authentication (OWASP ASVS V2.1.7).

### Context-specific banned words

Passwords containing product, company, domain, or common default terms
(`yashigani`, `agnostic`, `security`, `admin`, `password`, `gateway`) are
rejected at the application layer (OWASP ASVS 6.1.2 + 6.2.11).

### Account lockout

Five consecutive failed attempts trigger a 30-minute lockout. The same
generic error message is returned for unknown user, wrong password, and
locked account to prevent username enumeration (OWASP ASVS V2.1, V2.2.1).

---

## Password Reuse History

**Introduced in v2.23.3. Control: CMMC L2 IA.L2-3.5.8 / NIST SP 800-63B §5.1.1.2.**

Yashigani prohibits reuse of the last N passwords on self-service password
change. The depth defaults to 12 and is configurable via the
`PASSWORD_HISTORY_DEPTH` environment variable.

### How it works

1. When a user changes their password, Yashigani fetches the last
   `PASSWORD_HISTORY_DEPTH` Argon2id hashes from the `password_history` table.
2. The new password is checked against each stored hash using Argon2id
   `verify()` (constant-time-ish per call). If any match is found, the change
   is rejected with HTTP 422 and error code `password_reuse`.
3. On successful change, the old hash is inserted into `password_history` and
   the table is pruned to keep at most `PASSWORD_HISTORY_DEPTH` entries per
   user.

Hashes are never stored in plaintext. The matching position within history is
not disclosed to the user or logged (no ordering information that could assist
an attacker in narrowing the history window).

### Audit event

On rejection, a `PASSWORD_REUSE_REJECTED` audit event is emitted with:

| Field | Value |
|---|---|
| `event_type` | `PASSWORD_REUSE_REJECTED` |
| `user_id` | Account UUID (never plaintext username) |
| `history_depth_checked` | Value of `PASSWORD_HISTORY_DEPTH` at call time |
| `masking_applied` | Always `true` |

The event never contains the new password, the matched hash, or the match
position.

### Configuration

| Variable | Default | Range | Notes |
|---|---|---|---|
| `PASSWORD_HISTORY_DEPTH` | `12` | `1`–`24` | Number of previous passwords checked. Values outside range are clamped with a warning log. Invalid (non-integer) values fall back to `12`. |

### Database schema

```sql
CREATE TABLE password_history (
    user_id       UUID        NOT NULL
                  REFERENCES admin_accounts (account_id) ON DELETE CASCADE,
    password_hash TEXT        NOT NULL,
    changed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, changed_at)
);
```

Added by migration `0010_password_history`. Cascade delete ensures history
rows are removed when an account is deleted. The table is bounded: after
each successful change, rows older than the most-recent `depth` entries are
deleted.

### Compliance mapping

| Framework | Control | Status |
|---|---|---|
| CMMC Level 2 | IA.L2-3.5.8 | Closed (v2.23.3) |
| NIST SP 800-171 | IA-5(1)(e) | Closed (v2.23.3) |
| NIST SP 800-63B | §5.1.1.2 — prohibit N previous passwords | Closed (v2.23.3) |
| OWASP ASVS | V2.1 — password policy enforcement | Closed |

---

## TOTP Multi-Factor Authentication

**Phase 13 (Yashigani 3.1): Role-tiered TOTP algorithms.**

Every local-auth account must enrol a TOTP authenticator before being
granted access. The enrolment flow is split into two steps
(`/api/v1/auth/totp/provision/start` and `/api/v1/auth/totp/provision/confirm`)
to ensure the user proves possession of the seed before the account is
unlocked.

### Role-tiered algorithm selection

| Role | Algorithm | Digits | Notes |
|---|---|---|---|
| Admin | HMAC-SHA-512 | 8 | Stronger HMAC; 8-digit codes reduce brute-force window |
| User | HMAC-SHA-256 | 6 | Standard HMAC; 6 digits |

The algorithm and digit count are embedded in the `otpauth://` URI returned by
the provisioning endpoint and printed during install. The `totp_algorithm`
column on `admin_accounts` records the active algorithm for each enrolment.

### Crypto properties

- Dynamic truncation per RFC 4226 §5.3 (works identically for SHA-256 and
  SHA-512 — offset = HMAC[-1] & 0x0F, extract 4 bytes, mask 0x7FFFFFFF,
  mod 10^digits).
- Constant-time comparison via `hmac.compare_digest` (ASVS V11.2.4).
- A code computed with the wrong algorithm or wrong digit count WILL NOT
  match — algorithm isolation is cryptographically enforced, not just
  validated by the code length.

### Required authenticator app

**Classic Google Authenticator (SHA-1 only) is NOT compatible** with
role-tiered TOTP. Use an app that reads all `otpauth://` URI parameters:

- **agnosticOTP** (recommended — supports SHA-256/512, 6/8 digits, iOS/Android)
- **Aegis** (Android, open-source, full URI parameter support)
- **1Password** (iOS/Android/desktop, full URI support)

When displaying provisioning instructions, always recommend **agnosticOTP**
explicitly to avoid silent algorithm mismatches.

### Migration from SHA-1 (legacy accounts)

Pre-3.1 accounts have `totp_algorithm = 'SHA1'` in the database (set by
migration `0023_totp_role_tier`). At first login after the upgrade:

1. Password authentication succeeds.
2. The server detects `totp_algorithm != expected_for_role` and sets
   `force_totp_provision = true`.
3. A restricted `totp_provisioning` session is issued — the user cannot
   access admin/user functions until re-enrolment completes.
4. The user scans a new QR code (with the role-appropriate algorithm/digits)
   and confirms a code.
5. `force_totp_provision` is cleared; `totp_algorithm` is updated.

**Dual-admin safety**: all admins can be in re-enrolment state simultaneously
without lockout. The `totp_provisioning` session allows access to
`/auth/totp/provision/start` and `/auth/totp/provision/confirm` without a
TOTP code, only a valid password.

### TOTP failure backoff and replay prevention

TOTP failures trigger exponential backoff (1s, 2s, 4s, 8s) with a hard
30-minute lockout on the fifth failure, matching the password lockout policy.

Used codes are recorded in the `used_totp_codes` table with a 60-second TTL
to prevent replay across the ±1 accepted TOTP window.

---

## WebAuthn / FIDO2 Hardware Keys

Admins can authenticate with a physical FIDO2 hardware key (YubiKey 5 series,
Security Key NFC, Titan Key, any FIDO2 authenticator) as an alternative to TOTP.

Sign-count monotonic validation is enforced: a new sign_count ≤ stored (when
stored > 0) is rejected as a cloned-authenticator indicator (ASVS V2.8.3,
CWE-287). Challenge replay is prevented by Redis atomic GETDEL (ASVS V2.8.2).

Password + TOTP login is never disabled while WebAuthn is configured. Lost all
hardware keys? Use the TOTP form as normal.

---

## Session Management

Sessions are stored in Redis with a configurable TTL
(`YASHIGANI_SESSION_TTL_SECONDS`, default 3600). Session IDs are 256-bit random
values. All sessions for an account are invalidated on password change (ASVS
V2.1.4).

Step-up re-authentication (`YASHIGANI_STEPUP_TTL_SECONDS`, default 300 seconds)
is required for high-risk operations (credential revocation, TOTP reset, break-glass
activation).
