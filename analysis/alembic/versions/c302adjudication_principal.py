"""Persist the principal that made a security adjudication."""

import sqlalchemy as sa

from alembic import op

revision = "c302adjudication"
down_revision = "c301service01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "adjudications",
        sa.Column("decided_by_principal_id", sa.String(length=64), nullable=True),
    )
    op.create_foreign_key(
        "fk_adjudications_decided_by_principal",
        "adjudications",
        "principals",
        ["decided_by_principal_id"],
        ["principal_id"],
    )


def downgrade() -> None:
    op.drop_constraint("fk_adjudications_decided_by_principal", "adjudications", type_="foreignkey")
    op.drop_column("adjudications", "decided_by_principal_id")
