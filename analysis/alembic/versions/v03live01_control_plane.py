"""Durable live v0.3 detection-response control-plane seams."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "v03live01"
down_revision = "v03dr01"
branch_labels = None
depends_on = None

LIVE_RLS_TABLES = (
    "security_source_bindings",
    "detection_work_items",
    "hunt_hypotheses",
    "hunt_plans",
    "incident_investigations",
    "response_capability_requests",
)


def _scope() -> list[sa.Column[object]]:
    return [
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("case_id", sa.String(128), nullable=False),
        sa.Column("target_id", sa.String(128), nullable=False),
    ]


def upgrade() -> None:
    # ``content_digest`` identifies the source document.  The canonical
    # digest binds the normalized stored rule fields to that identity.
    op.add_column(
        "detection_rule_versions",
        sa.Column("canonical_digest", sa.String(128), nullable=True),
    )
    op.create_index(
        "ix_detection_rule_versions_canonical_digest",
        "detection_rule_versions",
        ["canonical_digest"],
    )

    op.create_table(
        "security_source_bindings",
        sa.Column("source_id", sa.String(128), primary_key=True),
        sa.Column("principal_id", sa.String(64), sa.ForeignKey("principals.principal_id"), nullable=False),
        *_scope(),
        sa.Column("source_family", sa.String(64), nullable=False),
        sa.Column("source_type", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["case_id", "target_id"],
            ["engagement_targets.engagement_id", "engagement_targets.target_id"],
            name="fk_security_source_binding_engagement_target",
        ),
    )
    op.create_index("ix_security_source_bindings_scope", "security_source_bindings", ["tenant_id", "case_id", "target_id"])

    op.create_table(
        "detection_work_items",
        sa.Column("work_id", sa.String(128), primary_key=True),
        sa.Column("event_id", sa.String(96), nullable=False),
        *_scope(),
        sa.Column("event_fingerprint", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("worker_id", sa.String(128)),
        sa.Column("run_ids", sa.JSON(), nullable=False),
        sa.Column("signal_ids", sa.JSON(), nullable=False),
        sa.Column("last_error", sa.String(128)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("tenant_id", "case_id", "target_id", "event_id", name="uq_detection_work_scope_event"),
    )
    op.create_index("ix_detection_work_scope_status", "detection_work_items", ["tenant_id", "case_id", "target_id", "status"])

    op.create_table(
        "hunt_hypotheses",
        sa.Column("hypothesis_id", sa.String(128), primary_key=True),
        *_scope(),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("entity_keys", sa.JSON(), nullable=False),
        sa.Column("supporting_signal_ids", sa.JSON(), nullable=False),
        sa.Column("required_evidence_refs", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_hunt_hypotheses_scope", "hunt_hypotheses", ["tenant_id", "case_id", "target_id"])

    op.create_table(
        "hunt_plans",
        sa.Column("plan_id", sa.String(128), primary_key=True),
        sa.Column("hypothesis_id", sa.String(128), nullable=False),
        *_scope(),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("query", sa.JSON(), nullable=False),
        sa.Column("exit_criteria", sa.Text(), nullable=False),
        sa.Column("max_events", sa.Integer(), nullable=False, server_default="500"),
        sa.Column("status", sa.String(16), nullable=False, server_default="PENDING"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_hunt_plans_scope_status", "hunt_plans", ["tenant_id", "case_id", "target_id", "status"])

    op.create_table(
        "incident_investigations",
        sa.Column("investigation_id", sa.String(128), primary_key=True),
        sa.Column("hypothesis_id", sa.String(128), nullable=False),
        *_scope(),
        sa.Column("observation_ids", sa.JSON(), nullable=False),
        sa.Column("claim_ids", sa.JSON(), nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incident_investigations_scope", "incident_investigations", ["tenant_id", "case_id", "target_id"])

    op.create_table(
        "response_capability_requests",
        sa.Column("request_id", sa.String(128), primary_key=True),
        sa.Column("proposal_id", sa.String(128), sa.ForeignKey("response_proposals.proposal_id"), nullable=False),
        *_scope(),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("proposal_digest", sa.String(128), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("proposal_id", "proposal_digest", name="uq_response_capability_request_proposal"),
    )
    op.create_index("ix_response_capability_requests_scope", "response_capability_requests", ["tenant_id", "case_id", "target_id"])

    if op.get_bind().dialect.name == "postgresql":
        for table_name in LIVE_RLS_TABLES:
            op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
            policy_name = f"secscan_{table_name}_human_scope"
            predicate = "secscan_human_is_platform_admin() OR secscan_human_can_access_engagement(case_id)"
            op.execute(
                f"CREATE POLICY {policy_name} ON {table_name} USING ({predicate}) WITH CHECK ({predicate})"
            )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table_name in reversed(LIVE_RLS_TABLES):
            op.execute(f"DROP POLICY IF EXISTS secscan_{table_name}_human_scope ON {table_name}")
            op.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_response_capability_requests_scope", table_name="response_capability_requests")
    op.drop_table("response_capability_requests")
    op.drop_index("ix_hunt_plans_scope_status", table_name="hunt_plans")
    op.drop_table("hunt_plans")
    op.drop_index("ix_incident_investigations_scope", table_name="incident_investigations")
    op.drop_table("incident_investigations")
    op.drop_index("ix_hunt_hypotheses_scope", table_name="hunt_hypotheses")
    op.drop_table("hunt_hypotheses")
    op.drop_index("ix_detection_work_scope_status", table_name="detection_work_items")
    op.drop_table("detection_work_items")
    op.drop_index("ix_security_source_bindings_scope", table_name="security_source_bindings")
    op.drop_table("security_source_bindings")
    op.drop_index("ix_detection_rule_versions_canonical_digest", table_name="detection_rule_versions")
    op.drop_column("detection_rule_versions", "canonical_digest")
