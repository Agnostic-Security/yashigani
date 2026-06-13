"""Track B1 — durable mirror for model-allocation RBAC.

Revision ID: 0019
Revises: 0018
Create Date: 2026-06-11

Rationale (Track B1 model-RBAC enforcement):
    Model allocations (alias -> scope org|group|user) are the admin lever for
    model RBAC. They live in Redis db/3, which runs with NO persistence
    (`appendonly no`, `save ""`) — exactly the SAME drift class as the
    agent-registry durability bug (migration 0017): a `docker compose up -d
    redis` recreate, or a `redis` restart, WIPES every allocation, silently
    dropping model enforcement until the next admin mutation.

    This table is the durable source of truth that ModelAllocationStore
    dual-writes to, and that a startup reconciler re-pushes back into Redis db/3
    on every boot (mirroring the OPA-store re-push + agent-reg reconcile
    patterns). Redis db/3 stays the fast request-time lookup; the gateway hot
    path is unchanged.

    Natural key: (tenant_id, alloc_id) where alloc_id mirrors the Redis
    `model:alloc:{id}` counter id so reconcile is idempotent. A second UNIQUE on
    (tenant_id, model_alias, target_type, target_id) prevents duplicate grants of
    the same alias to the same scope.

Downgrade: drops the table.
"""
from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

_PLATFORM_TENANT_ID = "00000000-0000-0000-0000-000000000000"


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS model_allocations (
            id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            alloc_id      TEXT NOT NULL,
            model_alias   TEXT NOT NULL,
            target_type   TEXT NOT NULL CHECK (target_type IN ('org','group','user')),
            target_id     TEXT NOT NULL,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            UNIQUE (tenant_id, alloc_id),
            UNIQUE (tenant_id, model_alias, target_type, target_id)
        );
        ALTER TABLE model_allocations ENABLE ROW LEVEL SECURITY;
        ALTER TABLE model_allocations FORCE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation ON model_allocations
            USING (tenant_id = current_setting('app.tenant_id')::uuid);
        CREATE INDEX IF NOT EXISTS model_allocations_scope_idx
            ON model_allocations (tenant_id, target_type, target_id);
        """
    )
    # Least-privilege runtime role (0015): ALTER DEFAULT PRIVILEGES grants
    # SELECT/INSERT/UPDATE on new tables but NOT DELETE — the allocation store
    # needs DELETE for de-allocation. Grant it explicitly (idempotent).
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON model_allocations TO yashigani_app")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS model_allocations")
