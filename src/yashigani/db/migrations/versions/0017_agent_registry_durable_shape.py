"""v2.25.3.1 — make agent_registry the durable mirror of the Redis db/3 agent store.

Revision ID: 0017
Revises: 0016
Create Date: 2026-06-10

Rationale (ISSUE-AGENT-REG-DURABILITY, Iris 2026-06-10):
    @agent registrations live ONLY in Redis db/3, which runs with NO persistence
    (`appendonly no`, `save ""`). Any `docker compose up -d redis` recreate
    silently WIPES every agent registration. The gateway then returns
    `agent_not_found` for every @agent with zero operator signal, and
    register_agent_bundles() only runs at install so the registry never
    self-heals.

    The legacy `agent_registry` table (created in migration 0001, extended in
    0002) already EXISTS but was never used by the live registration path —
    AgentRegistry writes only to Redis. Its column set does not match the
    Redis registration shape (no agent_id slug, no protocol/status/groups/
    allowed_caller_groups/allowed_paths).

    This migration repurposes the table as the durable source of truth that
    AgentRegistry dual-writes to, and that a startup reconciler re-pushes back
    into Redis db/3 on every boot (mirroring the OPA store→OPA re-push pattern,
    commit 2ce1033). Redis db/3 stays the fast request-time lookup.

    Columns added (all the fields AgentRegistry stores in the Redis hash that
    were missing from the legacy table):
      - agent_id              TEXT  (the `agnt_<12hex>` slug — natural reconcile key)
      - protocol              TEXT  (openai | letta | langflow | ...)
      - status               TEXT  (active | inactive — mirrors is_active)
      - groups               JSON
      - allowed_caller_groups JSON
      - allowed_paths         JSON
      - last_seen_at          TIMESTAMPTZ NULL

    agent_id is made UNIQUE per tenant so the dual-write upsert can target it.
    Existing columns (agent_name, upstream_url, token_hash, allowed_cidrs,
    is_active, created_at, updated_at) are reused as-is.

    Legacy UNIQUE (tenant_id, agent_name) is DROPPED (MUST-FIX-2, Iris
    2026-06-10): agent_id is now the natural key and the Redis register path
    enforces uniqueness on agent_id ONLY (registry.py Lua — no name check), so
    agent NAMES are legitimately allowed to collide. The legacy name-unique
    constraint (from migration 0001) would make a second agent with a duplicate
    name raise a unique-violation on agent_name that the durable upsert's
    ``ON CONFLICT (tenant_id, agent_id)`` clause does NOT catch → IntegrityError.
    Because the dual-write is best-effort/logged, the agent would stay live in
    Redis but be SILENTLY non-durable → dropped on the next redis recreate. This
    drop closes that silent-durability-loss hole.

Downgrade:
    Restores the legacy UNIQUE (tenant_id, agent_name) and drops the columns
    added here. The table reverts to its legacy (unused) shape.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_registry",
        sa.Column(
            "agent_id",
            sa.Text(),
            nullable=True,
            comment="The agnt_<12hex> slug — natural key for Redis<->Postgres reconciliation.",
        ),
    )
    op.add_column(
        "agent_registry",
        sa.Column(
            "protocol",
            sa.Text(),
            nullable=False,
            server_default="openai",
            comment="Upstream protocol: openai | letta | langflow | ...",
        ),
    )
    op.add_column(
        "agent_registry",
        sa.Column(
            "status",
            sa.Text(),
            nullable=False,
            server_default="active",
            comment="active | inactive — mirrors is_active for parity with the Redis hash.",
        ),
    )
    op.add_column(
        "agent_registry",
        sa.Column(
            "groups",
            sa.JSON(),
            nullable=False,
            server_default="[]",
            comment="Groups the agent identity belongs to.",
        ),
    )
    op.add_column(
        "agent_registry",
        sa.Column(
            "allowed_caller_groups",
            sa.JSON(),
            nullable=False,
            server_default="[]",
            comment="Caller groups permitted to invoke this agent.",
        ),
    )
    op.add_column(
        "agent_registry",
        sa.Column(
            "allowed_paths",
            sa.JSON(),
            nullable=False,
            server_default="[]",
            comment="Path allowlist for this agent.",
        ),
    )
    op.add_column(
        "agent_registry",
        sa.Column(
            "last_seen_at",
            sa.TIMESTAMP(timezone=True),
            nullable=True,
            comment="Last request-time touch (best-effort; not durability-critical).",
        ),
    )
    # UNIQUE (tenant_id, agent_id) so the durable dual-write can upsert on the slug.
    op.create_unique_constraint(
        "agent_registry_tenant_id_agent_id_key",
        "agent_registry",
        ["tenant_id", "agent_id"],
    )

    # MUST-FIX-2 (Iris 2026-06-10): drop the legacy UNIQUE (tenant_id, agent_name).
    # agent_id is now the natural key; the Redis register path enforces uniqueness
    # on agent_id ONLY, so agent NAMES may collide. The legacy name-unique
    # constraint would make a duplicate-name agent's durable INSERT raise a
    # unique-violation that ON CONFLICT (tenant_id, agent_id) cannot catch →
    # IntegrityError → silent non-durability. IF EXISTS keeps this idempotent: on
    # fresh install the constraint is dropped here; on a DB already at 0017 the
    # follow-up migration 0018 performs the drop instead.
    op.execute(
        "ALTER TABLE agent_registry "
        "DROP CONSTRAINT IF EXISTS agent_registry_tenant_id_agent_name_key"
    )


def downgrade() -> None:
    # Restore the legacy name-unique constraint (reverse of the upgrade drop).
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD CONSTRAINT agent_registry_tenant_id_agent_name_key "
        "UNIQUE (tenant_id, agent_name)"
    )
    op.drop_constraint(
        "agent_registry_tenant_id_agent_id_key",
        "agent_registry",
        type_="unique",
    )
    op.drop_column("agent_registry", "last_seen_at")
    op.drop_column("agent_registry", "allowed_paths")
    op.drop_column("agent_registry", "allowed_caller_groups")
    op.drop_column("agent_registry", "groups")
    op.drop_column("agent_registry", "status")
    op.drop_column("agent_registry", "protocol")
    op.drop_column("agent_registry", "agent_id")
