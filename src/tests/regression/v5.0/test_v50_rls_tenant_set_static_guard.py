# Last updated: 2026-07-29T00:00:00+00:00
"""
Static class guard — RLS-protected table queried without setting
app.tenant_id first.

This is the class-level regression guard for the whole "RLS-protected table
queried without setting app.tenant_id" bug family closed in this sweep:
  - test_v50_admin_cache_500.py               (V50-CACHE-500)
  - test_v50_028_jwt_config_rls_tenant_set.py  (V50-028 + 2 siblings)
  - test_v50_jwt_inspector_rls_tenant_set.py   (runtime JWT-validation lookup)
  - test_v50_budget_store_rls_tenant_set.py    (BudgetStore, 9 methods)

Definitive RLS-table inventory (mechanized grep of every migration under
src/yashigani/db/migrations/versions/ for `ENABLE ROW LEVEL SECURITY` /
`CREATE POLICY` / `current_setting('app.tenant_id')` — 0001, 0005, 0006,
0011, 0015, 0019, 0027 are the only migrations that touch RLS at all):

  tenant_context, rbac_groups, rbac_members, agent_registry, audit_events,
  inference_events, anomaly_thresholds, jwt_config, cache_config,
  endpoint_ratelimit_overrides, identities, identity_group_membership,
  idp_providers, org_cloud_caps, group_budgets, individual_budgets,
  model_aliases, sensitivity_patterns, trusted_cloud_providers,
  routing_config, admin_accounts, audit_chain_checkpoints, model_allocations

What this guard checks: for every function/method in src/yashigani (outside
migrations and tests) whose source references one of the tables above in a
FROM/INTO/UPDATE/DELETE-FROM SQL position, the SAME function must ALSO
contain one of the established tenant-setting idioms:
  - `set_config(`            — direct SET, e.g. inside `_set_tenant()` /
                                `conn.execute("SELECT set_config('app.tenant_id'...")`
  - `tenant_transaction(`    — db/postgres.py's shared async context manager
  - `_set_tenant(`           — billing/budget_store.py's local helper
  - `_connect(`              — the durable-store idiom (agents/durable_store.py,
                                identity/durable_store.py, models/
                                allocation_durable_store.py): `_connect()` SETs
                                app.tenant_id itself before returning the
                                connection, so any method that calls
                                `self._connect()` is safe by construction.

ESCAPE HATCH (documented limitation): a function whose OWN parameter list
contains `conn` or `connection` is assumed to receive an already tenant-
scoped connection from its caller (verified for every current instance of
this shape during the sweep — e.g. auth/pg_auth.py:_update(self, conn,
record), always called from within a method that itself opened
tenant_transaction()). This guard does NOT verify the caller — it is a
per-function static check, not a call-graph/dataflow analysis. Any new
`conn`-accepting helper added against an RLS table MUST be manually verified
to be called only from an already-scoped transaction; this guard will not
catch a violation introduced that way. This tradeoff (function-local
heuristic vs. full call-graph analysis) is called out explicitly here so a
future auditor does not assume this guard is a complete proof.

Verified: with the sweep's fixes in place, this guard passes. Verified to
FAIL (documented via inline manual check during the sweep, not committed
here as a broken-state test — the assertion messages below cite the exact
violations found and fixed) against the pre-fix tree for jwt_config.py
(list/set/delete), gateway/jwt_inspector.py (_load_tenant_config), and every
RLS method in billing/budget_store.py.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parents[3] / "yashigani"

RLS_TABLES = [
    "tenant_context", "rbac_groups", "rbac_members", "agent_registry",
    "audit_events", "inference_events", "anomaly_thresholds", "jwt_config",
    "cache_config", "endpoint_ratelimit_overrides", "identities",
    "identity_group_membership", "idp_providers", "org_cloud_caps",
    "group_budgets", "individual_budgets", "model_aliases",
    "sensitivity_patterns", "trusted_cloud_providers", "routing_config",
    "admin_accounts", "audit_chain_checkpoints", "model_allocations",
]

# Compiled once: `FROM|INTO|UPDATE <table>` (word-bounded, quote-tolerant).
# Deliberately case-SENSITIVE, matching uppercase SQL keywords only (the
# codebase's SQL style is consistently uppercase, e.g. "FROM cache_config",
# "INSERT INTO", "UPDATE admin_accounts") — a case-insensitive match false-
# positived on prose like a docstring's "budget_total: ... (from
# individual_budgets)", which is English, not SQL.
_TABLE_REF_RE = {
    t: re.compile(rf"(?:FROM|INTO|UPDATE)\s+\"?{re.escape(t)}\"?\b")
    for t in RLS_TABLES
}

_SAFE_MARKERS = ("set_config(", "tenant_transaction(", "_set_tenant(", "_connect(")

_EXCLUDE_DIR_PARTS = {"migrations", "tests", "__pycache__"}


def _iter_python_files():
    for p in sorted(SRC_ROOT.rglob("*.py")):
        if _EXCLUDE_DIR_PARTS & set(p.parts):
            continue
        yield p


def _param_names(node: ast.AST) -> set[str]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return set()
    args = node.args
    names = {a.arg for a in args.args + args.posonlyargs + args.kwonlyargs}
    return names


def _collect_violations() -> list[str]:
    violations: list[str] = []
    for path in _iter_python_files():
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            segment = ast.get_source_segment(source, node)
            if not segment:
                continue

            referenced_tables = [t for t in RLS_TABLES if _TABLE_REF_RE[t].search(segment)]
            if not referenced_tables:
                continue

            if any(marker in segment for marker in _SAFE_MARKERS):
                continue

            # Escape hatch: function receives an already tenant-scoped
            # connection from its caller (see module docstring).
            if _param_names(node) & {"conn", "connection"}:
                continue

            rel = path.relative_to(SRC_ROOT.parent)
            violations.append(
                f"{rel}:{node.lineno} {node.name}() references RLS table(s) "
                f"{referenced_tables} with no tenant-setting idiom "
                f"({_SAFE_MARKERS}) in scope and no conn/connection parameter"
            )
    return violations


class TestNoRlsTableQueriedWithoutTenantSet:
    def test_every_rls_table_query_site_sets_tenant_first(self):
        violations = _collect_violations()
        assert not violations, (
            "V50-RLS-SWEEP class regression — RLS-protected table queried "
            "without setting app.tenant_id first:\n  " + "\n  ".join(violations)
        )

    def test_rls_table_inventory_matches_migrations(self):
        """Guard the inventory itself: fail loudly if a migration adds/removes
        RLS on a table so the list above is kept in sync by hand (mechanized
        grep, not auto-derived, per the sweep brief)."""
        migrations_dir = SRC_ROOT / "db" / "migrations" / "versions"
        found: set[str] = set()
        pattern = re.compile(r"CREATE POLICY tenant_isolation ON (\w+)")
        for f in sorted(migrations_dir.glob("*.py")):
            text = f.read_text(encoding="utf-8")
            found.update(pattern.findall(text))

        assert found == set(RLS_TABLES), (
            "RLS table inventory drift — migrations define RLS on tables not "
            "in RLS_TABLES (or vice versa). Update the list in this file:\n"
            f"  in migrations but not in RLS_TABLES: {found - set(RLS_TABLES)}\n"
            f"  in RLS_TABLES but not in migrations: {set(RLS_TABLES) - found}"
        )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
