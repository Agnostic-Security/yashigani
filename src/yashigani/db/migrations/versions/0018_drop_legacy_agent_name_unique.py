"""v2.25.3.1 — drop the legacy UNIQUE (tenant_id, agent_name) on agent_registry.

Revision ID: 0018
Revises: 0017
Create Date: 2026-06-10

Rationale (MUST-FIX-2, Iris 2026-06-10):
    agent_id is now the natural key for agent_registry (migration 0017 added it
    and a UNIQUE (tenant_id, agent_id)). The Redis register path enforces
    uniqueness on agent_id ONLY (registry.py Lua — no name check), so agent
    NAMES are legitimately allowed to collide.

    The legacy UNIQUE (tenant_id, agent_name) constraint (from migration 0001)
    therefore makes a second agent with a duplicate name raise a unique-violation
    on agent_name when AgentDurableStore.upsert() runs its INSERT. The upsert's
    ``ON CONFLICT (tenant_id, agent_id)`` clause does NOT catch a name collision
    → IntegrityError. Because the dual-write is best-effort/logged
    (registry.py), the agent stays live in Redis but is SILENTLY non-durable →
    dropped on the next redis recreate. That is exactly the silent-loss failure
    mode this durability wave exists to eliminate.

Why a separate migration from 0017:
    0017 is already applied on live deployments (alembic head == 0017) and carries
    durable agent rows. Round-tripping 0017 to re-apply a folded-in drop would
    drop the agent_id column → destroy those rows. So the drop ships here as a
    purely additive, reversible follow-up. 0017's upgrade() ALSO performs the
    drop (IF EXISTS) for fresh installs; this migration's IF EXISTS makes the
    fresh-install case a clean no-op and the already-at-0017 case the real drop.

Downgrade:
    Restores UNIQUE (tenant_id, agent_name).
"""
from __future__ import annotations

from alembic import op


# revision identifiers, used by Alembic.
revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE agent_registry "
        "DROP CONSTRAINT IF EXISTS agent_registry_tenant_id_agent_name_key"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE agent_registry "
        "ADD CONSTRAINT agent_registry_tenant_id_agent_name_key "
        "UNIQUE (tenant_id, agent_name)"
    )
