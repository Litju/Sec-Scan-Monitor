"""Add human access records, target ownership, and PostgreSQL RLS policies."""

import sqlalchemy as sa

from alembic import op

revision = "a230hosted1"
down_revision = "f210scientific1"
branch_labels = None
depends_on = None

RLS_ENGAGEMENT_TABLES = (
    "engagement_targets",
    "authority_grants",
    "workflow_runs",
    "agent_runs",
    "tool_invocations",
    "evidence_metadata",
    "observations",
    "claims",
    "findings",
    "approvals",
    "reports",
    "audit_events",
)


def upgrade() -> None:
    op.add_column("targets", sa.Column("client_id", sa.String(length=64), nullable=True))
    op.create_index("ix_targets_client_id", "targets", ["client_id"])
    op.create_foreign_key("fk_targets_client_id", "targets", "clients", ["client_id"], ["client_id"])

    op.create_table(
        "human_principals",
        sa.Column("human_principal_id", sa.String(length=96), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("human_principal_id"),
    )
    op.create_index("ix_human_principals_status", "human_principals", ["status"])
    op.create_table(
        "external_identities",
        sa.Column("external_identity_id", sa.String(length=96), nullable=False),
        sa.Column("human_principal_id", sa.String(length=96), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("subject", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("external_identity_id"),
        sa.ForeignKeyConstraint(["human_principal_id"], ["human_principals.human_principal_id"]),
        sa.UniqueConstraint("issuer", "subject", name="uq_external_identity_issuer_subject"),
    )
    op.create_index("ix_external_identities_human_principal_id", "external_identities", ["human_principal_id"])
    op.create_table(
        "client_memberships",
        sa.Column("membership_id", sa.String(length=96), nullable=False),
        sa.Column("human_principal_id", sa.String(length=96), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("membership_id"),
        sa.ForeignKeyConstraint(["human_principal_id"], ["human_principals.human_principal_id"]),
        sa.ForeignKeyConstraint(["client_id"], ["clients.client_id"]),
        sa.UniqueConstraint("human_principal_id", "client_id", name="uq_client_membership_principal_client"),
    )
    op.create_index("ix_client_memberships_human_principal_id", "client_memberships", ["human_principal_id"])
    op.create_index("ix_client_memberships_client_id", "client_memberships", ["client_id"])
    op.create_index("ix_client_memberships_status", "client_memberships", ["status"])

    if op.get_bind().dialect.name != "postgresql":
        return

    op.execute(
        """
        CREATE OR REPLACE FUNCTION secscan_human_can_access_client(target_client_id text)
        RETURNS boolean
        LANGUAGE sql
        SECURITY DEFINER
        SET search_path = public
        STABLE
        AS $$
          SELECT EXISTS (
            SELECT 1
            FROM client_memberships membership
            WHERE membership.human_principal_id = current_setting('secscan.human_principal_id', true)
              AND membership.client_id = target_client_id
              AND membership.status = 'active'
          )
        $$
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secscan_human_can_access_engagement(target_engagement_id text)
        RETURNS boolean
        LANGUAGE sql
        SECURITY DEFINER
        SET search_path = public
        STABLE
        AS $$
          SELECT EXISTS (
            SELECT 1
            FROM engagements engagement
            WHERE engagement.engagement_id = target_engagement_id
              AND secscan_human_can_access_client(engagement.client_id)
          )
        $$
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION secscan_human_is_platform_admin()
        RETURNS boolean
        LANGUAGE sql
        SECURITY DEFINER
        SET search_path = public
        STABLE
        AS $$
          SELECT EXISTS (
            SELECT 1
            FROM client_memberships membership
            WHERE membership.human_principal_id = current_setting('secscan.human_principal_id', true)
              AND membership.role = 'PLATFORM_ADMIN'
              AND membership.status = 'active'
          )
        $$
        """
    )

    for table_name in ("clients", "targets", "engagements"):
        op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY secscan_clients_human_scope ON clients
        USING (secscan_human_is_platform_admin() OR secscan_human_can_access_client(client_id))
        WITH CHECK (secscan_human_is_platform_admin() OR secscan_human_can_access_client(client_id))
        """
    )
    op.execute(
        """
        CREATE POLICY secscan_targets_human_scope ON targets
        USING (client_id IS NOT NULL AND (secscan_human_is_platform_admin() OR secscan_human_can_access_client(client_id)))
        WITH CHECK (client_id IS NOT NULL AND (secscan_human_is_platform_admin() OR secscan_human_can_access_client(client_id)))
        """
    )
    op.execute(
        """
        CREATE POLICY secscan_engagements_human_scope ON engagements
        USING (secscan_human_is_platform_admin() OR secscan_human_can_access_client(client_id))
        WITH CHECK (secscan_human_is_platform_admin() OR secscan_human_can_access_client(client_id))
        """
    )

    op.execute("ALTER TABLE client_memberships ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE client_memberships FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY secscan_memberships_human_scope ON client_memberships
        USING (human_principal_id = current_setting('secscan.human_principal_id', true))
        WITH CHECK (human_principal_id = current_setting('secscan.human_principal_id', true))
        """
    )
    op.execute("ALTER TABLE human_principals ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE human_principals FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY secscan_human_principal_scope ON human_principals
        USING (human_principal_id = current_setting('secscan.human_principal_id', true)
               OR secscan_human_is_platform_admin())
        WITH CHECK (secscan_human_is_platform_admin())
        """
    )
    op.execute("ALTER TABLE external_identities ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE external_identities FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY secscan_external_identity_scope ON external_identities
        USING (human_principal_id = current_setting('secscan.human_principal_id', true)
               OR secscan_human_is_platform_admin())
        WITH CHECK (secscan_human_is_platform_admin())
        """
    )

    for table_name in RLS_ENGAGEMENT_TABLES:
        op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
        policy_name = f"secscan_{table_name}_human_scope"
        if table_name == "audit_events":
            predicate = "engagement_id IS NULL AND secscan_human_is_platform_admin() OR (engagement_id IS NOT NULL AND secscan_human_can_access_engagement(engagement_id))"
        else:
            predicate = "secscan_human_can_access_engagement(engagement_id)"
        op.execute(f"CREATE POLICY {policy_name} ON {table_name} USING ({predicate}) WITH CHECK ({predicate})")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table_name in reversed(RLS_ENGAGEMENT_TABLES):
            op.execute(f"DROP POLICY IF EXISTS secscan_{table_name}_human_scope ON {table_name}")
            op.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY")
        for table_name in ("engagements", "targets", "clients"):
            op.execute(f"DROP POLICY IF EXISTS secscan_{table_name}_human_scope ON {table_name}")
            op.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY")
        for table_name, policy_name in (
            ("external_identities", "secscan_external_identity_scope"),
            ("human_principals", "secscan_human_principal_scope"),
            ("client_memberships", "secscan_memberships_human_scope"),
        ):
            op.execute(f"DROP POLICY IF EXISTS {policy_name} ON {table_name}")
            op.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY")
        for function_name in (
            "secscan_human_can_access_engagement(text)",
            "secscan_human_can_access_client(text)",
            "secscan_human_is_platform_admin()",
        ):
            op.execute(f"DROP FUNCTION IF EXISTS {function_name}")

    op.drop_index("ix_client_memberships_status", table_name="client_memberships")
    op.drop_index("ix_client_memberships_client_id", table_name="client_memberships")
    op.drop_index("ix_client_memberships_human_principal_id", table_name="client_memberships")
    op.drop_table("client_memberships")
    op.drop_index("ix_external_identities_human_principal_id", table_name="external_identities")
    op.drop_table("external_identities")
    op.drop_index("ix_human_principals_status", table_name="human_principals")
    op.drop_table("human_principals")
    op.drop_constraint("fk_targets_client_id", "targets", type_="foreignkey")
    op.drop_index("ix_targets_client_id", table_name="targets")
    op.drop_column("targets", "client_id")
