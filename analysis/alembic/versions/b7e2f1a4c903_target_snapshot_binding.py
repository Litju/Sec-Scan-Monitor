"""Bind target rows to immutable snapshot identity and digest.

Revision ID: b7e2f1a4c903
Revises: 9c4a7c2e1f20
"""

import sqlalchemy as sa

from alembic import op

revision = "b7e2f1a4c903"
down_revision = "9c4a7c2e1f20"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("targets", sa.Column("snapshot_id", sa.String(length=128), nullable=True))
    op.add_column("targets", sa.Column("snapshot_digest", sa.String(length=128), nullable=True))
    op.add_column("targets", sa.Column("source_identity", sa.String(length=255), nullable=True))


def downgrade() -> None:
    op.drop_column("targets", "source_identity")
    op.drop_column("targets", "snapshot_digest")
    op.drop_column("targets", "snapshot_id")
