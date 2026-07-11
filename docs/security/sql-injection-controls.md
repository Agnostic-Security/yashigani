# SQL Injection Controls

<!-- Last updated: 2026-05-02T09:00:00+01:00 -->

This document describes the SQL injection prevention controls in Yashigani,
covering both application code and database maintenance scripts.

Reviewed by the internal GRC audit function. Findings reference: YCS-20260502-v2.23.1-CWE89-reaudit-001.

---

## Controls summary

| File | Control class | Status |
|------|--------------|--------|
| `scripts/partition_maintenance.py` | Parameterised identifiers + DDL date-literal exception | PASS (internal re-audit) |
| `src/yashigani/db/migrations/` | Alembic `op.drop_table()` native API | PASS (YSG-RISK-002) |
| All gateway routes | asyncpg parameterised queries (`$1`, `$2`, …) | PASS |

ASVS coverage: V5.3.4, V5.3.5, V5.1.4. Framework: CWE-89, CAPEC-66, NIST SP 800-53 r5 SI-10/SI-15.

---

## `partition_maintenance.py` — DDL date-literal exception

### What it does

`scripts/partition_maintenance.py` creates monthly partitions for `audit_events`
and `inference_events` tables using a `CREATE TABLE … PARTITION OF … FOR VALUES
FROM … TO …` DDL statement.

### Why it uses string interpolation for dates

PostgreSQL does **not** accept asyncpg `$1`/`$2` bind parameters in DDL parser
positions. Attempting to use bind parameters for `FOR VALUES FROM ($1) TO ($2)`
causes the server to return "expects 0 arguments" and the statement fails.
This is a PostgreSQL DDL grammar constraint, not an asyncpg limitation.

### Why this is safe

The date values interpolated into the DDL come from `datetime.date.isoformat()`
called on values derived exclusively from `date.today()` arithmetic:

```python
today = date.today().replace(day=1)
for i in range(months_ahead + 1):
    month_offset = today.month - 1 + i
    year = today.year + month_offset // 12
    month = month_offset % 12 + 1
    start, end = _partition_range(year, month)
```

Three independent safety properties hold:

1. **No user input.** `start` and `end` are `datetime.date` instances derived
   from `date.today()` and an integer loop index. The only external input is
   `--months-ahead` (argparse `type=int`); non-integers raise `SystemExit`
   before reaching this code.

2. **Deterministic format.** `datetime.date.isoformat()` is defined by CPython
   (`_Py_DateTime_DateType.tp_methods → date_isoformat`) to return exactly
   `YYYY-MM-DD` — 10 ASCII characters from `[0-9-]` only. There is no quote,
   no space, no semicolon, no escape character. The format is locale-independent
   and cannot be influenced by `LC_TIME` or any environment variable.

3. **Single-quoted literal in Postgres context.** Even if a hypothetical attacker
   injected into `start` or `end` (they cannot), the DDL wraps the value in
   single quotes: `FOR VALUES FROM ('YYYY-MM-DD') TO ('YYYY-MM-DD')`.
   A syntactically invalid date string would fail Postgres's `daterange` parsing,
   not execute attacker SQL.

### Identifier slots — fully parameterised

The two identifier tokens in the same DDL statement (`{q_name}`, `{q_table}`)
are NOT plain f-string interpolation. They are the output of `_quote_ident()`,
which:

- Rejects any name that does not match `^[a-zA-Z_][a-zA-Z0-9_]*$` with
  `ValueError` before the SQL string is composed.
- Double-quotes the validated name per SQL standard.
- Sources `q_table` exclusively from `_PARTITIONED_TABLES = ["audit_events",
  "inference_events"]` — a hardcoded allowlist in the script body.

This is functionally equivalent to `psycopg.sql.Identifier` semantics.

### Audit evidence

- Internal re-audit: `YCS-20260502-v2.23.1-CWE89-reaudit-001` (PASS) — evidence held in the internal compliance archive.
- Closing commits: `75536a5` (identifier quoting), `af114f7` (DDL date-literal exception)
- CHANGELOG entry: `YSG-RISK-001 (CWE-89, HIGH)`

### Regression tests

`src/tests/unit/test_partition_maintenance.py`:

- `TestQuoteIdent` — 9 tests covering identifier allowlist, injection rejection.
- `TestNoFstringInDDL` — structural source-code guards:
  - `test_fstring_dml_pattern_absent` — bare `{name}`/`{table}` absent from DDL.
  - `test_identifier_slots_use_quote_ident` — `{q_name}`/`{q_table}` present.
  - `test_date_slots_use_isoformat` — `start.isoformat()`/`end.isoformat()` present.
- `TestDateLiteralInjectionImpossible` — 3 defence-in-depth tests verifying
  `date.isoformat()` cannot produce SQL-injectable output across all months of
  2025–2027 and 10 injection-class character classes.

### CI gate

`tools/check_partition_helm_parity.py` (wired into ci.yml `contracts` job) asserts
the 8 security-critical lines are byte-identical between
`scripts/partition_maintenance.py` and the Kubernetes ConfigMap embedded copy in
`helm/yashigani/templates/configmaps.yaml`. Drift fails CI.

---

## Application routes — general policy

All Yashigani gateway and backoffice routes that issue SQL use asyncpg
parameterised queries (`$1`, `$2`, …). No route constructs SQL by
string concatenation or f-string interpolation outside
`partition_maintenance.py`.

The single approved exception (DDL date-literal) is documented in full above.

---

## Alembic migrations — `op.drop_table()` vs raw SQL

`YSG-RISK-002 (CWE-89, MEDIUM)` — migration `0003_prepartition_audit_2026_2027.py`
previously used `op.execute(f"DROP TABLE IF EXISTS {name}")` with an f-string.
Replaced with `op.drop_table(name)` using the Alembic native API. Closing
commit `9d867be`.

---

*For controls not covered here, refer to [`docs/compliance-reports/per-framework/owasp-asvs-v5.md`](../compliance-reports/per-framework/owasp-asvs-v5.md) (ASVS v5 L3 mapping)
and the internal compliance archive.*
