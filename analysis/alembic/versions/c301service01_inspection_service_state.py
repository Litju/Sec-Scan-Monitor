"""Persist Release 0.1 inspection-service state and AQS receipts."""

import sqlalchemy as sa

from alembic import op

revision = "c301service01"
down_revision = "a230hosted1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "target_security_profiles",
        sa.Column("profile_id", sa.String(length=96), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("snapshot_id", sa.String(length=128), nullable=False),
        sa.Column("target_class", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("profile_id"),
        sa.ForeignKeyConstraint(["client_id"], ["clients.client_id"]),
        sa.ForeignKeyConstraint(["target_id"], ["targets.target_id"]),
        sa.UniqueConstraint("target_id", "snapshot_id", name="uq_security_profile_target_snapshot"),
    )
    op.create_index("ix_target_security_profiles_client_id", "target_security_profiles", ["client_id"])
    op.create_index("ix_target_security_profiles_target_id", "target_security_profiles", ["target_id"])
    op.create_index("ix_target_security_profiles_snapshot_id", "target_security_profiles", ["snapshot_id"])

    op.create_table(
        "assessment_plans",
        sa.Column("plan_id", sa.String(length=96), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("engagement_id", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("profile_id", sa.String(length=96), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("plan_id"),
        sa.ForeignKeyConstraint(["client_id"], ["clients.client_id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.engagement_id"]),
        sa.ForeignKeyConstraint(["target_id"], ["targets.target_id"]),
        sa.ForeignKeyConstraint(["profile_id"], ["target_security_profiles.profile_id"]),
        sa.ForeignKeyConstraint(
            ["engagement_id", "target_id"],
            ["engagement_targets.engagement_id", "engagement_targets.target_id"],
            name="fk_assessment_plan_engagement_target",
        ),
    )
    op.create_index("ix_assessment_plans_client_id", "assessment_plans", ["client_id"])
    op.create_index("ix_assessment_plans_engagement_id", "assessment_plans", ["engagement_id"])
    op.create_index("ix_assessment_plans_target_id", "assessment_plans", ["target_id"])

    op.create_table(
        "security_service_runs",
        sa.Column("run_id", sa.String(length=96), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("engagement_id", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("snapshot_id", sa.String(length=128), nullable=False),
        sa.Column("service_id", sa.String(length=64), nullable=False),
        sa.Column("service_version", sa.String(length=32), nullable=False),
        sa.Column("specialist_id", sa.String(length=96), nullable=False),
        sa.Column("assessment_plan_id", sa.String(length=96), nullable=False),
        sa.Column("authority_level", sa.String(length=32), nullable=False),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("claim_ids", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("qualification_version", sa.String(length=32), nullable=False),
        sa.Column("limitations", sa.JSON(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("run_id"),
        sa.ForeignKeyConstraint(["client_id"], ["clients.client_id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.engagement_id"]),
        sa.ForeignKeyConstraint(["target_id"], ["targets.target_id"]),
        sa.ForeignKeyConstraint(["assessment_plan_id"], ["assessment_plans.plan_id"]),
        sa.ForeignKeyConstraint(
            ["engagement_id", "target_id"],
            ["engagement_targets.engagement_id", "engagement_targets.target_id"],
            name="fk_service_run_engagement_target",
        ),
    )
    op.create_index("ix_security_service_runs_client_id", "security_service_runs", ["client_id"])
    op.create_index("ix_security_service_runs_engagement_id", "security_service_runs", ["engagement_id"])
    op.create_index("ix_security_service_runs_target_id", "security_service_runs", ["target_id"])
    op.create_index("ix_security_service_runs_snapshot_id", "security_service_runs", ["snapshot_id"])
    op.create_index("ix_security_service_runs_service_id", "security_service_runs", ["service_id"])
    op.create_index("ix_security_service_runs_assessment_plan_id", "security_service_runs", ["assessment_plan_id"])
    op.create_index("ix_security_service_runs_status", "security_service_runs", ["status"])

    op.create_table(
        "service_qualifications",
        sa.Column("service_id", sa.String(length=64), nullable=False),
        sa.Column("service_version", sa.String(length=32), nullable=False),
        sa.Column("qualification_state", sa.String(length=48), nullable=False),
        sa.Column("receipt", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("service_id", "service_version"),
    )
    op.create_index("ix_service_qualifications_qualification_state", "service_qualifications", ["qualification_state"])

    if op.get_bind().dialect.name != "postgresql":
        return

    for table_name in ("target_security_profiles", "assessment_plans", "security_service_runs"):
        op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY secscan_target_security_profiles_human_scope ON target_security_profiles
        USING (secscan_human_is_platform_admin() OR secscan_human_can_access_client(client_id))
        WITH CHECK (secscan_human_is_platform_admin() OR secscan_human_can_access_client(client_id))
        """
    )
    for table_name in ("assessment_plans", "security_service_runs"):
        policy_name = f"secscan_{table_name}_human_scope"
        op.execute(
            f"""
            CREATE POLICY {policy_name} ON {table_name}
            USING (secscan_human_can_access_engagement(engagement_id))
            WITH CHECK (secscan_human_can_access_engagement(engagement_id))
            """
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table_name in ("security_service_runs", "assessment_plans", "target_security_profiles"):
            op.execute(f"DROP POLICY IF EXISTS secscan_{table_name}_human_scope ON {table_name}")
            op.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY")

    op.drop_index("ix_service_qualifications_qualification_state", table_name="service_qualifications")
    op.drop_table("service_qualifications")
    for index_name in (
        "ix_security_service_runs_status",
        "ix_security_service_runs_assessment_plan_id",
        "ix_security_service_runs_service_id",
        "ix_security_service_runs_snapshot_id",
        "ix_security_service_runs_target_id",
        "ix_security_service_runs_engagement_id",
        "ix_security_service_runs_client_id",
    ):
        op.drop_index(index_name, table_name="security_service_runs")
    op.drop_table("security_service_runs")
    for index_name in (
        "ix_assessment_plans_target_id",
        "ix_assessment_plans_engagement_id",
        "ix_assessment_plans_client_id",
    ):
        op.drop_index(index_name, table_name="assessment_plans")
    op.drop_table("assessment_plans")
    for index_name in (
        "ix_target_security_profiles_snapshot_id",
        "ix_target_security_profiles_target_id",
        "ix_target_security_profiles_client_id",
    ):
        op.drop_index(index_name, table_name="target_security_profiles")
    op.drop_table("target_security_profiles")
