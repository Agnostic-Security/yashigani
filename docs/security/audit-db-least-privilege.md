# Audit DB least-privilege & irrevocable hash chain

Last updated: 2026-06-04

This document describes the database role model and the tamper-evident audit
chain controls introduced in v2.25.2 (Lu wire-sink-gate findings P1 + P2;
combined "irrevocable audit" remediation). It is aimed at operators and
auditors.

## Role model

Yashigani uses **two** PostgreSQL roles. The security boundary between them is
**role privilege**, not the credential — they may share the bootstrap password.

| Role | Privilege | Used by | Connects via |
|------|-----------|---------|--------------|
| `yashigani_admin` | Bootstrap **superuser**; owns all tables | DDL / Alembic migrations, partition maintenance, `pg_dump`, SSL/SCRAM maintenance, init scripts | `YASHIGANI_DB_DSN_ADMIN` (+ `_ADMIN_DIRECT` for the advisory lock); direct to postgres |
| `yashigani_app` | `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`; **not** an owner | All runtime request paths (gateway + backoffice asyncpg pool) | `YASHIGANI_DB_DSN` (via pgbouncer) / `YASHIGANI_DB_DSN_DIRECT` |

`yashigani_admin` is the container bootstrap user (`POSTGRES_USER`). On a fresh
install, migration `0001` creates `yashigani_app` already demoted. On upgrade
from a pre-2.25.2 install (where `yashigani_app` was the bootstrap superuser and
table owner), migration `0015` demotes the role (`ALTER ROLE ... NOSUPERUSER`)
and reassigns table ownership to the admin (`REASSIGN OWNED`).

### Grant matrix

- **Operational tables** (`admin_accounts`, `jwt_config`, `password_history`,
  `used_totp_codes`, `webauthn_credentials`, `runtime_settings`,
  `auth_settings`, budgets, `manifest_registrations`, `anomaly_thresholds`, …):
  `yashigani_app` has the DML each code path needs (per-table, set in migrations
  0001–0013).
- **Audit tables** (`audit_events`, `inference_events`,
  `audit_chain_checkpoints`): `yashigani_app` has **`SELECT` + `INSERT` only**.
  `UPDATE` / `DELETE` are revoked. `FORCE ROW LEVEL SECURITY` is set so even a
  table owner is subject to tenant-isolation RLS.

Because `yashigani_app` is no longer a superuser and no longer owns the audit
tables, the `REVOKE UPDATE, DELETE` and RLS that earlier releases declared are
now actually **enforced** (a superuser/owner previously bypassed them).

## Irrevocable hash chain (immutability by construction)

1. **Chained on every insert.** The production audit write path
   (`build_postgres_audit_sink`, `require_chain=True`) computes `prev_hash` +
   `event_hash` (SHA-384) for every row and **rejects** any event it cannot
   chain — it is never written with NULL chain links.
2. **DB-enforced.** A `CHECK (prev_hash IS NOT NULL AND event_hash IS NOT NULL)`
   constraint on `audit_events` rejects an unchained insert at the database
   (migration 0015; `NOT VALID` so historical rows are not blocked, but every
   new insert is enforced).
3. **Immutable checkpoints.** The daily merkle-root checkpoint is written
   `ON CONFLICT DO NOTHING` — the first checkpoint for a `(tenant, date)` is
   authoritative; a re-run is a no-op, never an overwrite.
4. **Signed checkpoints (non-repudiation).** The checkpoint scheduler runs in
   **backoffice** and signs the merkle root with an ECDSA (P-256 / SHA-384)
   leaf issued by the internal CA. The signing key is mounted **read-only into
   backoffice only** (compose: `./secrets/audit-signing` → `/run/audit-signing`;
   Helm: `audit.signingKey.enabled` + a backoffice-only Secret). It is **never**
   on the gateway/runtime path, so a held `yashigani_app` credential cannot read
   the key and cannot forge a signed history. When the key is absent, checkpoints
   are written **unsigned** — still tamper-evident via the merkle root.
5. **Independent file anchor.** The append-only file sink remains the canonical
   durability anchor, independent of the DB.

## Residual risk (YSG-RISK-058 — accepted)

A rogue install-admin who holds the `yashigani_admin` superuser password **can**
mutate the live database. They **cannot** do so undetectably:

- mutating audit rows breaks the hash chain (detected at checkpoint + by an
  auditor recomputing the chain);
- they cannot forge a *consistent signed* history without the checkpoint signing
  key (held only by the backoffice signing context);
- they cannot erase the independent append-only file sink.

The fully-out-of-scope case is **simultaneous** compromise of BOTH the admin DB
credential AND the backoffice signing key. This is an accepted calculated risk
(Tiago 2026-06-04): a rogue senior IT admin with that level of access has far
more impactful options than subverting the AI audit trail. See risk register
`YSG-RISK-058`.
