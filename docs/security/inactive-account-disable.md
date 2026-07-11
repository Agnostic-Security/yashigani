# Inactive Account Disable — FedRAMP AC-2(F2)

<!-- Last updated: 2026-05-08T00:00:00+00:00 — v2.23.3 -->

This document describes the automated inactive-account disable mechanism
introduced in v2.23.3 to satisfy FedRAMP Moderate baseline control AC-2(F2)
and LU-YSG-002.

**FedRAMP evidence pointer (Lu):** This document, migration `0007`, and the
`INACTIVE_ACCOUNT_DISABLED` audit event class in `src/yashigani/audit/schema.py`
are the primary evidence artefacts for LU-YSG-002. Reference these in the
v2.23.3 compliance evidence pack. AU-3.F field coverage is documented in the
audit event class docstring.

---

## Behaviour

A background task runs once every `YASHIGANI_INACTIVE_DISABLE_INTERVAL_HOURS`
hours (default `24`). On each run it:

1. Queries `admin_accounts` for all non-disabled accounts whose `last_login_at`
   is older than `YASHIGANI_INACTIVE_DISABLE_DAYS` days (default `90`).
2. Excludes accounts listed in `YASHIGANI_INACTIVE_DISABLE_EXEMPT_ACCOUNTS`.
3. Applies the **safety rail**: if the candidate set exceeds
   `YASHIGANI_INACTIVE_DISABLE_MAX_PERCENT` percent of all accounts (default `50`),
   the run is halted without disabling any accounts, a warning is logged, and an
   alert is dispatched to all configured alert sinks.
4. For each remaining candidate: sets `disabled = true` and
   `inactive_disabled_at = now()` atomically.
5. Emits one `INACTIVE_ACCOUNT_DISABLED` audit event per disabled account.

`last_login_at` is stamped on every successful local-authentication login (full
password + TOTP success). SSO logins do not stamp `last_login_at` directly —
SSO identity lifecycle is managed by the IdP. Accounts created after v2.23.3
have `last_login_at = NULL` until first login; the migration backfills existing
rows to their `created_at` timestamp.

---

## AU-3.F audit record content

Every `INACTIVE_ACCOUNT_DISABLED` event contains:

| AU-3.F field    | Event field            | Value                                    |
|-----------------|------------------------|------------------------------------------|
| Timestamp       | `timestamp`            | ISO-8601 UTC (from AuditEvent base)      |
| User identity   | `disabled_account_id`  | UUID of the disabled account             |
| Event type      | `event_type`           | `INACTIVE_ACCOUNT_DISABLED`              |
| Success/failure | `outcome`              | `success` (task disables or skips)       |
| Source IP       | `source_ip`            | `system` (no client IP in cron context)  |
| Target resource | `target_resource`      | `admin_accounts/<account_id>`            |

Additional forensic fields: `disabled_username`, `days_inactive`,
`threshold_days`, `last_login_at` (ISO-8601 of the last login or backfill date).

---

## Safety rail

The safety rail prevents a misconfigured threshold from disabling the majority
of all admin accounts in a single run. The default is 50% — if more than 50% of
all accounts are inactive at threshold, the run halts and fires an alert.

This is not the same as "only disable 50% of inactive accounts" — it is a
dead-man switch. If it triggers, investigate why so many accounts appear inactive
before adjusting the threshold or adding exemptions.

To raise the rail (e.g. for initial deployment where accounts have never logged
in): set `YASHIGANI_INACTIVE_DISABLE_MAX_PERCENT=100` temporarily, then review
and reduce. Do not permanently set to `100` in production.

---

## Exemption list

Add break-glass account UUIDs and service-account UUIDs to
`YASHIGANI_INACTIVE_DISABLE_EXEMPT_ACCOUNTS` (comma-separated). These accounts
will never be automatically disabled regardless of inactivity.

```dotenv
YASHIGANI_INACTIVE_DISABLE_EXEMPT_ACCOUNTS=<break-glass-uuid>,<service-acct-uuid>
```

---

## Re-enabling an automatically-disabled account

Automatic disables are distinguishable from operator-initiated disables by the
`inactive_disabled_at` column. An operator-initiated disable has `disabled=true`
and `inactive_disabled_at=NULL`. An automatic disable has both set.

To re-enable:

```bash
# Admin API (authenticated session required):
curl -X PATCH https://<host>/admin/accounts/<username>/enable \
     -H "Cookie: __Host-yashigani_admin_session=<session>"
```

The `inactive_disabled_at` timestamp is retained after re-enable (audit trail).
`last_login_at` is reset on next successful login.

---

## Migration notes

Migration `0007` adds:

- `last_login_at TIMESTAMPTZ` — backfilled to `to_timestamp(created_at)` for
  existing rows. This means the first task run measures inactivity from account
  creation date, not from "now". After deployment, operators who want to reset
  the baseline (to give existing accounts 90 more days) can run:

  ```sql
  UPDATE admin_accounts SET last_login_at = now()
  WHERE last_login_at IS NOT NULL;
  ```

- `inactive_disabled_at TIMESTAMPTZ NULL` — set by the automated task only.
  Operator-initiated disable leaves this NULL.

- Index `idx_admin_accounts_last_login ON admin_accounts (last_login_at) WHERE disabled = false`
  for efficient cron queries.

---

## Compliance mapping

| Control          | Requirement                                          | Implementation                            |
|------------------|------------------------------------------------------|-------------------------------------------|
| FedRAMP AC-2(F2) | Disable accounts after N days of inactivity          | `inactive_account_task.py`                |
| FedRAMP AU-3.F   | Audit records contain all required fields            | `InactiveAccountDisabledEvent` in `schema.py` |
| ASVS V2.1.7      | Account lockout / disable on inactivity              | 90-day default, configurable              |
| NIST SP 800-53r5 AC-2(3) | Disable inactive accounts ≤ 35 days (High) / ≤ 90 days (Moderate) | Configurable default 90d |
