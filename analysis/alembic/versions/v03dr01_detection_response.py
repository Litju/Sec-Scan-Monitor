"""Detection and response foundation tables (v0.3, advisory-only)."""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "v03dr01"
down_revision = "g220continuous1"
branch_labels = None
depends_on = None

V03_RLS_TABLES = (
    "security_events",
    "detection_runs",
    "detection_evaluations",
    "detection_signals",
    "hunt_executions",
    "incident_hypotheses",
    "incidents",
    "response_proposals",
)


def _scope() -> list[sa.Column[object]]:
    return [
        sa.Column("tenant_id", sa.String(128), nullable=False),
        sa.Column("case_id", sa.String(128), nullable=False),
        sa.Column("target_id", sa.String(128), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("event_id", sa.String(96), primary_key=True),
        *_scope(),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("source_type", sa.String(128), nullable=False),
        sa.Column("source_family", sa.String(64), nullable=False),
        sa.Column("event_class", sa.String(96), nullable=False),
        sa.Column("ocsf_class", sa.String(96), nullable=False),
        sa.Column("ocsf_version", sa.String(32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("object_ref", sa.String(255), nullable=False),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("outcome", sa.String(96), nullable=False),
        sa.Column("severity", sa.String(16)),
        sa.Column("raw_evidence_ref", sa.String(512), nullable=False),
        sa.Column("source_digest", sa.String(128), nullable=False),
        sa.Column("normalization_version", sa.String(64), nullable=False),
        sa.Column("ordering_metadata", sa.JSON(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.UniqueConstraint("tenant_id", "case_id", "target_id", "fingerprint", name="uq_security_event_scope_fingerprint"),
    )
    op.create_index("ix_security_events_scope_occurred", "security_events", ["tenant_id", "case_id", "target_id", "occurred_at"])
    op.create_index("ix_security_events_source_family", "security_events", ["source_family"])

    op.create_table(
        "detection_rule_versions",
        sa.Column("rule_id", sa.String(128), primary_key=True),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("rule_type", sa.String(48), nullable=False),
        sa.Column("content_digest", sa.String(128), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("source_reference", sa.String(512), nullable=False),
        sa.Column("event_schema", sa.String(96), nullable=False),
        sa.Column("ocsf_version", sa.String(32), nullable=False),
        sa.Column("supported_source_families", sa.JSON(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("confidence_metadata", sa.JSON(), nullable=False),
        sa.Column("attack_mappings", sa.JSON(), nullable=False),
        sa.Column("atlas_mappings", sa.JSON(), nullable=False),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("predicates", sa.JSON(), nullable=False),
        sa.Column("correlation_keys", sa.JSON(), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("threshold", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("evaluation_metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "detection_plans",
        sa.Column("plan_id", sa.String(128), primary_key=True),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("rule_type", sa.String(48), nullable=False),
        sa.Column("content_digest", sa.String(128), nullable=False),
        sa.Column("event_schema", sa.String(96), nullable=False),
        sa.Column("supported_source_families", sa.JSON(), nullable=False),
        sa.Column("predicates", sa.JSON(), nullable=False),
        sa.Column("correlation_keys", sa.JSON(), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("threshold", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_detection_plans_rule", "detection_plans", ["rule_id", "rule_version"])

    op.create_table(
        "detection_runs",
        sa.Column("run_id", sa.String(128), primary_key=True),
        *_scope(),
        sa.Column("rule_ids", sa.JSON(), nullable=False),
        sa.Column("input_event_ids", sa.JSON(), nullable=False),
        sa.Column("evaluation_ids", sa.JSON(), nullable=False),
        sa.Column("signal_ids", sa.JSON(), nullable=False),
        sa.Column("engine_version", sa.String(64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
    )
    op.create_index("ix_detection_runs_scope", "detection_runs", ["tenant_id", "case_id", "target_id"])

    op.create_table(
        "detection_evaluations",
        sa.Column("evaluation_id", sa.String(128), primary_key=True),
        sa.Column("run_id", sa.String(128), nullable=False),
        *_scope(),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("input_event_ids", sa.JSON(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("matched_predicates", sa.JSON(), nullable=False),
        sa.Column("result", sa.String(32), nullable=False),
        sa.Column("signal_id", sa.String(128)),
        sa.Column("engine_version", sa.String(64), nullable=False),
        sa.Column("rule_digest", sa.String(128), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
    )
    op.create_index("ix_detection_evaluations_scope", "detection_evaluations", ["tenant_id", "case_id", "target_id"])

    op.create_table(
        "detection_signals",
        sa.Column("signal_id", sa.String(128), primary_key=True),
        *_scope(),
        sa.Column("rule_id", sa.String(128), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("event_ids", sa.JSON(), nullable=False),
        sa.Column("source_signal_ids", sa.JSON(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("matched_predicates", sa.JSON(), nullable=False),
        sa.Column("raw_evidence_refs", sa.JSON(), nullable=False),
        sa.Column("rule_digest", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
    )
    op.create_index("ix_detection_signals_scope", "detection_signals", ["tenant_id", "case_id", "target_id"])

    op.create_table(
        "hunt_executions",
        sa.Column("execution_id", sa.String(128), primary_key=True),
        sa.Column("plan_id", sa.String(128), nullable=False),
        sa.Column("hypothesis_id", sa.String(128), nullable=False),
        *_scope(),
        sa.Column("query_digest", sa.String(128), nullable=False),
        sa.Column("input_event_ids", sa.JSON(), nullable=False),
        sa.Column("input_signal_ids", sa.JSON(), nullable=False),
        sa.Column("result_id", sa.String(128), nullable=False, unique=True),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_hunt_executions_scope", "hunt_executions", ["tenant_id", "case_id", "target_id"])

    op.create_table(
        "incident_hypotheses",
        sa.Column("hypothesis_id", sa.String(128), primary_key=True),
        *_scope(),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("source_signal_ids", sa.JSON(), nullable=False),
        sa.Column("affected_entities", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incident_hypotheses_scope", "incident_hypotheses", ["tenant_id", "case_id", "target_id"])

    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(128), primary_key=True),
        sa.Column("hypothesis_id", sa.String(128), nullable=False),
        sa.Column("investigation_id", sa.String(128), nullable=False),
        sa.Column("adjudication_id", sa.String(128), nullable=False),
        *_scope(),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("source_signal_ids", sa.JSON(), nullable=False),
        sa.Column("observation_ids", sa.JSON(), nullable=False),
        sa.Column("claim_ids", sa.JSON(), nullable=False),
        sa.Column("supporting_evidence_refs", sa.JSON(), nullable=False),
        sa.Column("contradicting_evidence_refs", sa.JSON(), nullable=False),
        sa.Column("adjudicated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authorized_action_executed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_incidents_scope", "incidents", ["tenant_id", "case_id", "target_id"])

    op.create_table(
        "response_proposals",
        sa.Column("proposal_id", sa.String(128), primary_key=True),
        sa.Column("incident_id", sa.String(128), nullable=False),
        *_scope(),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("supporting_evidence_refs", sa.JSON(), nullable=False),
        sa.Column("expected_impact", sa.Text(), nullable=False),
        sa.Column("risk", sa.Text(), nullable=False),
        sa.Column("rollback_plan", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("proposal_digest", sa.String(128), nullable=False, unique=True),
        sa.Column("opa_decision", sa.String(32), nullable=False),
        sa.Column("human_approval_state", sa.String(32), nullable=False),
        sa.Column("authorized_action_executed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_response_proposals_scope", "response_proposals", ["tenant_id", "case_id", "target_id"])

    # These rows are durable tenant/case projections.  The v0.2 RLS
    # functions are already present at this revision's parent head; apply the
    # same human-access decision to every v0.3 row that carries case_id.
    if op.get_bind().dialect.name == "postgresql":
        for table_name in V03_RLS_TABLES:
            op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
            policy_name = f"secscan_{table_name}_human_scope"
            predicate = "secscan_human_is_platform_admin() OR secscan_human_can_access_engagement(case_id)"
            op.execute(
                f"CREATE POLICY {policy_name} ON {table_name} USING ({predicate}) WITH CHECK ({predicate})"
            )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table_name in reversed(V03_RLS_TABLES):
            op.execute(f"DROP POLICY IF EXISTS secscan_{table_name}_human_scope ON {table_name}")
            op.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_response_proposals_scope", table_name="response_proposals")
    op.drop_table("response_proposals")
    op.drop_index("ix_incidents_scope", table_name="incidents")
    op.drop_table("incidents")
    op.drop_index("ix_incident_hypotheses_scope", table_name="incident_hypotheses")
    op.drop_table("incident_hypotheses")
    op.drop_index("ix_hunt_executions_scope", table_name="hunt_executions")
    op.drop_table("hunt_executions")
    op.drop_index("ix_detection_signals_scope", table_name="detection_signals")
    op.drop_table("detection_signals")
    op.drop_index("ix_detection_evaluations_scope", table_name="detection_evaluations")
    op.drop_table("detection_evaluations")
    op.drop_index("ix_detection_runs_scope", table_name="detection_runs")
    op.drop_table("detection_runs")
    op.drop_index("ix_detection_plans_rule", table_name="detection_plans")
    op.drop_table("detection_plans")
    op.drop_table("detection_rule_versions")
    op.drop_index("ix_security_events_source_family", table_name="security_events")
    op.drop_index("ix_security_events_scope_occurred", table_name="security_events")
    op.drop_table("security_events")
