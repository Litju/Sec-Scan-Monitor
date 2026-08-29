"""Add durable leases for live hunt recovery."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "v03live03"
down_revision = "v03live02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("hunt_plans", sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("hunt_plans", sa.Column("worker_id", sa.String(128), nullable=True))
    op.create_index("ix_hunt_plans_status_lease", "hunt_plans", ["status", "lease_until"])


def downgrade() -> None:
    op.drop_index("ix_hunt_plans_status_lease", table_name="hunt_plans")
    op.drop_column("hunt_plans", "worker_id")
    op.drop_column("hunt_plans", "lease_until")
