"""Enforce engagement-scoped foreign-key pairs for new writes.

Historical F-200 rows contain known cross-engagement references. PostgreSQL
``NOT VALID`` foreign keys preserve those rows while enforcing the invariant
for every new insert/update; a later reconciliation can validate them after
historical correction is separately approved.
"""

import sqlalchemy as sa

from alembic import op

revision = "e6f200scope1"
down_revision = "b7e2f1a4c903"
branch_labels = None
depends_on = None


def _add_scope_fk(
    table: str,
    name: str,
    columns: tuple[str, str],
    referred_table: str,
    referred_columns: tuple[str, str],
) -> None:
    local = ", ".join(columns)
    remote = ", ".join(referred_columns)
    op.execute(
        sa.text(
            f"ALTER TABLE {table} ADD CONSTRAINT {name} "
            f"FOREIGN KEY ({local}) REFERENCES {referred_table} ({remote}) NOT VALID"
        )
    )


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_workflow_run_engagement", "workflow_runs", ["workflow_run_id", "engagement_id"]
    )
    op.create_unique_constraint(
        "uq_agent_run_engagement", "agent_runs", ["agent_run_id", "engagement_id"]
    )
    op.create_unique_constraint(
        "uq_tool_invocation_engagement", "tool_invocations", ["tool_invocation_id", "engagement_id"]
    )
    op.create_unique_constraint(
        "uq_approval_engagement", "approvals", ["approval_id", "engagement_id"]
    )
    op.create_unique_constraint(
        "uq_adjudication_engagement", "adjudications", ["adjudication_id", "engagement_id"]
    )

    _add_scope_fk(
        "approvals",
        "fk_approval_engagement_target",
        ("engagement_id", "target_id"),
        "engagement_targets",
        ("engagement_id", "target_id"),
    )
    _add_scope_fk(
        "tool_invocations",
        "fk_invocation_workflow_engagement",
        ("workflow_run_id", "engagement_id"),
        "workflow_runs",
        ("workflow_run_id", "engagement_id"),
    )
    _add_scope_fk(
        "tool_invocations",
        "fk_invocation_agent_engagement",
        ("agent_run_id", "engagement_id"),
        "agent_runs",
        ("agent_run_id", "engagement_id"),
    )
    _add_scope_fk(
        "tool_invocations",
        "fk_invocation_approval_engagement",
        ("approval_id", "engagement_id"),
        "approvals",
        ("approval_id", "engagement_id"),
    )
    _add_scope_fk(
        "evidence_metadata",
        "fk_evidence_engagement_target",
        ("engagement_id", "target_id"),
        "engagement_targets",
        ("engagement_id", "target_id"),
    )
    _add_scope_fk(
        "evidence_metadata",
        "fk_evidence_invocation_engagement",
        ("invocation_id", "engagement_id"),
        "tool_invocations",
        ("tool_invocation_id", "engagement_id"),
    )
    _add_scope_fk(
        "evidence_metadata",
        "fk_evidence_agent_engagement",
        ("agent_run_id", "engagement_id"),
        "agent_runs",
        ("agent_run_id", "engagement_id"),
    )
    _add_scope_fk(
        "claims",
        "fk_claim_agent_engagement",
        ("agent_run_id", "engagement_id"),
        "agent_runs",
        ("agent_run_id", "engagement_id"),
    )
    _add_scope_fk(
        "findings",
        "fk_finding_adjudication_engagement",
        ("originating_adjudication_id", "engagement_id"),
        "adjudications",
        ("adjudication_id", "engagement_id"),
    )


def downgrade() -> None:
    for table, name in (
        ("findings", "fk_finding_adjudication_engagement"),
        ("claims", "fk_claim_agent_engagement"),
        ("evidence_metadata", "fk_evidence_agent_engagement"),
        ("evidence_metadata", "fk_evidence_invocation_engagement"),
        ("evidence_metadata", "fk_evidence_engagement_target"),
        ("tool_invocations", "fk_invocation_approval_engagement"),
        ("tool_invocations", "fk_invocation_agent_engagement"),
        ("tool_invocations", "fk_invocation_workflow_engagement"),
        ("approvals", "fk_approval_engagement_target"),
    ):
        op.drop_constraint(name, table_name=table, type_="foreignkey")
    for table, name in (
        ("adjudications", "uq_adjudication_engagement"),
        ("approvals", "uq_approval_engagement"),
        ("tool_invocations", "uq_tool_invocation_engagement"),
        ("agent_runs", "uq_agent_run_engagement"),
        ("workflow_runs", "uq_workflow_run_engagement"),
    ):
        op.drop_constraint(name, table_name=table, type_="unique")
