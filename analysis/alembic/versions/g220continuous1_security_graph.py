"""Add canonical, provenance-bearing security graph state."""

import sqlalchemy as sa

from alembic import op

revision = "g220continuous1"
down_revision = "r6authrev01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_graph_snapshots",
        sa.Column("snapshot_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("case_id", sa.String(length=128), nullable=False),
        sa.Column("target_id", sa.String(length=128), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("normalization_version", sa.String(length=64), nullable=False),
        sa.Column("canonical_state", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("snapshot_id"),
        sa.UniqueConstraint("tenant_id", "case_id", "target_id", "digest", name="uq_security_graph_scope_digest"),
    )
    op.create_index("ix_security_graph_snapshots_tenant_id", "security_graph_snapshots", ["tenant_id"])
    op.create_index("ix_security_graph_snapshots_case_id", "security_graph_snapshots", ["case_id"])
    op.create_index("ix_security_graph_snapshots_target_id", "security_graph_snapshots", ["target_id"])

    op.create_table(
        "security_graph_nodes",
        sa.Column("snapshot_id", sa.String(length=128), nullable=False),
        sa.Column("node_key", sa.String(length=255), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("entity_id", sa.String(length=128), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("snapshot_id", "node_key"),
        sa.ForeignKeyConstraint(
            ["snapshot_id"], ["security_graph_snapshots.snapshot_id"], ondelete="CASCADE"
        ),
    )
    op.create_index("ix_security_graph_nodes_entity_type", "security_graph_nodes", ["entity_type"])
    op.create_index("ix_security_graph_nodes_entity_id", "security_graph_nodes", ["entity_id"])

    op.create_table(
        "security_graph_edges",
        sa.Column("snapshot_id", sa.String(length=128), nullable=False),
        sa.Column("edge_id", sa.String(length=96), nullable=False),
        sa.Column("source_node", sa.String(length=255), nullable=False),
        sa.Column("target_node", sa.String(length=255), nullable=False),
        sa.Column("relation", sa.String(length=64), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("snapshot_id", "edge_id"),
        sa.ForeignKeyConstraint(
            ["snapshot_id"], ["security_graph_snapshots.snapshot_id"], ondelete="CASCADE"
        ),
    )
    op.create_index("ix_security_graph_edges_source_node", "security_graph_edges", ["source_node"])
    op.create_index("ix_security_graph_edges_target_node", "security_graph_edges", ["target_node"])
    op.create_index("ix_security_graph_edges_relation", "security_graph_edges", ["relation"])


def downgrade() -> None:
    op.drop_index("ix_security_graph_edges_relation", table_name="security_graph_edges")
    op.drop_index("ix_security_graph_edges_target_node", table_name="security_graph_edges")
    op.drop_index("ix_security_graph_edges_source_node", table_name="security_graph_edges")
    op.drop_table("security_graph_edges")
    op.drop_index("ix_security_graph_nodes_entity_id", table_name="security_graph_nodes")
    op.drop_index("ix_security_graph_nodes_entity_type", table_name="security_graph_nodes")
    op.drop_table("security_graph_nodes")
    op.drop_index("ix_security_graph_snapshots_target_id", table_name="security_graph_snapshots")
    op.drop_index("ix_security_graph_snapshots_case_id", table_name="security_graph_snapshots")
    op.drop_index("ix_security_graph_snapshots_tenant_id", table_name="security_graph_snapshots")
    op.drop_table("security_graph_snapshots")
