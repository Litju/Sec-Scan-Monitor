"""Persist product JWT revocations across hosted function instances."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "r6authrev01"
down_revision = "r6capseed01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "human_token_revocations",
        sa.Column("token_sha256", sa.String(length=64), nullable=False),
        sa.Column("human_principal_id", sa.String(length=96), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("token_sha256"),
    )
    op.create_index(
        "ix_human_token_revocations_human_principal_id",
        "human_token_revocations",
        ["human_principal_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_human_token_revocations_human_principal_id",
        table_name="human_token_revocations",
    )
    op.drop_table("human_token_revocations")
