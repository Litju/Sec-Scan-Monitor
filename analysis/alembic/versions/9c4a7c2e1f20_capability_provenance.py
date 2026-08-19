"""capability provenance contract

Revision ID: 9c4a7c2e1f20
Revises: 78215b6f43e5
Create Date: 2026-08-14
"""

import sqlalchemy as sa

from alembic import op

revision = "9c4a7c2e1f20"
down_revision = "78215b6f43e5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("capability_manifests", sa.Column("tool_license", sa.String(length=64), nullable=False, server_default=""))
    op.add_column("capability_manifests", sa.Column("source_url", sa.String(length=512), nullable=False, server_default=""))
    op.add_column("capability_manifests", sa.Column("release_url", sa.String(length=512), nullable=False, server_default=""))
    op.add_column("capability_manifests", sa.Column("artifact_ref", sa.String(length=512), nullable=False, server_default=""))
    op.add_column("capability_manifests", sa.Column("artifact_digest", sa.String(length=128), nullable=False, server_default=""))
    op.add_column("capability_manifests", sa.Column("normalizer", sa.String(length=128), nullable=False, server_default=""))
    op.add_column("capability_manifests", sa.Column("failure_semantics", sa.Text(), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("capability_manifests", "failure_semantics")
    op.drop_column("capability_manifests", "normalizer")
    op.drop_column("capability_manifests", "artifact_digest")
    op.drop_column("capability_manifests", "artifact_ref")
    op.drop_column("capability_manifests", "release_url")
    op.drop_column("capability_manifests", "source_url")
    op.drop_column("capability_manifests", "tool_license")
