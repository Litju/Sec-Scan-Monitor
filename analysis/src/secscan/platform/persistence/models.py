"""SQLAlchemy 2.x ORM models — canonical PostgreSQL state (ADR-0003).

Adapters only: these models back the domain objects; the domain never
imports this module. Timestamps are timezone-aware (TIMESTAMPTZ). All
cross-table references use foreign keys; idempotency keys are UNIQUE.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    return datetime.now(UTC)


def gen_uuid() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class ClientRow(Base):
    __tablename__ = "clients"
    client_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    contact: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    engagements: Mapped[list["EngagementRow"]] = relationship(
        back_populates="client", foreign_keys="EngagementRow.client_id"
    )


class HumanPrincipalRow(Base):
    __tablename__ = "human_principals"
    human_principal_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ExternalIdentityRow(Base):
    __tablename__ = "external_identities"
    external_identity_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    human_principal_id: Mapped[str] = mapped_column(ForeignKey("human_principals.human_principal_id"), index=True)
    issuer: Mapped[str] = mapped_column(String(512))
    subject: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    __table_args__ = (UniqueConstraint("issuer", "subject", name="uq_external_identity_issuer_subject"),)


class HumanTokenRevocationRow(Base):
    __tablename__ = "human_token_revocations"
    token_sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    human_principal_id: Mapped[str] = mapped_column(String(96), index=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ClientMembershipRow(Base):
    __tablename__ = "client_memberships"
    membership_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    human_principal_id: Mapped[str] = mapped_column(ForeignKey("human_principals.human_principal_id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.client_id"), index=True)
    role: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    __table_args__ = (
        UniqueConstraint("human_principal_id", "client_id", name="uq_client_membership_principal_client"),
    )


class TargetRow(Base):
    __tablename__ = "targets"
    target_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.client_id"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    snapshot_id: Mapped[str | None] = mapped_column(String(128))
    snapshot_digest: Mapped[str | None] = mapped_column(String(128))
    source_identity: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class PrincipalRow(Base):
    __tablename__ = "principals"
    principal_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(255))
    manifest_ref: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    engagements: Mapped[list["EngagementRow"]] = relationship(
        back_populates="requester_principal", foreign_keys="EngagementRow.requester_principal_id"
    )


class EngagementRow(Base):
    __tablename__ = "engagements"
    engagement_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.client_id"), index=True)
    requester_principal_id: Mapped[str] = mapped_column(ForeignKey("principals.principal_id"))
    scope: Mapped[str] = mapped_column(Text)
    pass_type: Mapped[str] = mapped_column(String(32))
    authority_level: Mapped[str] = mapped_column(String(32), default="inspection-only")
    constraints: Mapped[list[Any]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="draft", index=True)
    status_history: Mapped[list[Any]] = mapped_column(JSON, default=list)
    refusal_reason: Mapped[str | None] = mapped_column(Text)
    suspended_from: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    client: Mapped["ClientRow"] = relationship(
        back_populates="engagements", foreign_keys=[client_id]
    )
    requester_principal: Mapped["PrincipalRow"] = relationship(
        back_populates="engagements", foreign_keys=[requester_principal_id]
    )


class EngagementTargetRow(Base):
    __tablename__ = "engagement_targets"
    engagement_target_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.target_id"), index=True)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    scope_note: Mapped[str] = mapped_column(Text, default="")
    __table_args__ = (UniqueConstraint("engagement_id", "target_id", name="uq_engagement_target"),)


class AuthorityGrantRow(Base):
    __tablename__ = "authority_grants"
    grant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.principal_id"), index=True)
    action: Mapped[str] = mapped_column(String(32))
    capability_id: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(64))
    conditions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    not_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ApprovalRow(Base):
    __tablename__ = "approvals"
    approval_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    requested_by_principal_id: Mapped[str] = mapped_column(ForeignKey("principals.principal_id"))
    decided_by_principal_id: Mapped[str | None] = mapped_column(ForeignKey("principals.principal_id"))
    request_ref: Mapped[str] = mapped_column(String(64))
    target_id: Mapped[str] = mapped_column(String(64))
    capability_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(32))
    decision: Mapped[str] = mapped_column(String(16), default="pending")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rationale: Mapped[str] = mapped_column(Text, default="")
    __table_args__ = (
        UniqueConstraint("engagement_id", "request_ref", name="uq_approval_request"),
        UniqueConstraint("approval_id", "engagement_id", name="uq_approval_engagement"),
        ForeignKeyConstraint(
            ["engagement_id", "target_id"],
            ["engagement_targets.engagement_id", "engagement_targets.target_id"],
            name="fk_approval_engagement_target",
        ),
    )


class WorkflowRunRow(Base):
    __tablename__ = "workflow_runs"
    workflow_run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    started_by_principal_id: Mapped[str] = mapped_column(ForeignKey("principals.principal_id"))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    current_phase: Mapped[str] = mapped_column(String(64), default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (UniqueConstraint("workflow_run_id", "engagement_id", name="uq_workflow_run_engagement"),)

    tool_invocations: Mapped[list["ToolInvocationRow"]] = relationship(
        back_populates="workflow_run", foreign_keys="ToolInvocationRow.workflow_run_id"
    )


class AgentManifestRow(Base):
    __tablename__ = "agent_manifests"
    manifest_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True, unique=True)
    role: Mapped[str] = mapped_column(String(64))
    version: Mapped[str] = mapped_column(String(32))
    accepted_inputs: Mapped[list[Any]] = mapped_column(JSON, default=list)
    produced_outputs: Mapped[list[Any]] = mapped_column(JSON, default=list)
    requested_capabilities: Mapped[list[Any]] = mapped_column(JSON, default=list)
    allowed_tools: Mapped[list[Any]] = mapped_column(JSON, default=list)
    forbidden_tools: Mapped[list[Any]] = mapped_column(JSON, default=list)
    authority_ceiling: Mapped[str] = mapped_column(String(32))
    evidence_consumed: Mapped[list[Any]] = mapped_column(JSON, default=list)
    evidence_produced: Mapped[list[Any]] = mapped_column(JSON, default=list)
    escalation_rules: Mapped[list[Any]] = mapped_column(JSON, default=list)
    refusal_rules: Mapped[list[Any]] = mapped_column(JSON, default=list)
    model_policy: Mapped[str] = mapped_column(Text, default="")
    timeout_policy: Mapped[str] = mapped_column(Text, default="")
    retry_policy: Mapped[str] = mapped_column(Text, default="")
    __table_args__ = (UniqueConstraint("agent_id", "version", name="uq_agent_manifest_version"),)


class AgentRunRow(Base):
    __tablename__ = "agent_runs"
    agent_run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agent_manifests.agent_id"))
    agent_version: Mapped[str] = mapped_column(String(32))
    model_identity: Mapped[str] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(64))
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.principal_id"))
    authority_refs: Mapped[list[Any]] = mapped_column(JSON, default=list)
    input_refs: Mapped[list[Any]] = mapped_column(JSON, default=list)
    tool_invocation_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    output_claim_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (UniqueConstraint("agent_run_id", "engagement_id", name="uq_agent_run_engagement"),)


class CapabilityManifestRow(Base):
    __tablename__ = "capability_manifests"
    capability_id: Mapped[str] = mapped_column(String(64), primary_key=True, unique=True)
    version: Mapped[str] = mapped_column(String(32), primary_key=True)
    description: Mapped[str] = mapped_column(Text)
    risk_class: Mapped[str] = mapped_column(String(16))
    accepted_inputs: Mapped[list[Any]] = mapped_column(JSON, default=list)
    produced_outputs: Mapped[list[Any]] = mapped_column(JSON, default=list)
    required_authority: Mapped[str] = mapped_column(String(32))
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    sandbox_profile: Mapped[str] = mapped_column(String(64), default="default")
    sandbox_requirement: Mapped[str] = mapped_column(String(16), default="none")
    network_policy: Mapped[str] = mapped_column(String(32), default="none")
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=60)
    resource_limits: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    tool_identity: Mapped[str] = mapped_column(String(128), default="")
    tool_version: Mapped[str] = mapped_column(String(32), default="")
    tool_license: Mapped[str] = mapped_column(String(64), default="")
    source_url: Mapped[str] = mapped_column(String(512), default="")
    release_url: Mapped[str] = mapped_column(String(512), default="")
    artifact_ref: Mapped[str] = mapped_column(String(512), default="")
    artifact_digest: Mapped[str] = mapped_column(String(128), default="")
    evidence_type: Mapped[str] = mapped_column(String(64), default="")
    normalizer: Mapped[str] = mapped_column(String(128), default="")
    failure_semantics: Mapped[str] = mapped_column(Text, default="")
    command_allowlist: Mapped[list[Any]] = mapped_column(JSON, default=list)


class ToolInvocationRow(Base):
    __tablename__ = "tool_invocations"
    tool_invocation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    workflow_run_id: Mapped[str] = mapped_column(ForeignKey("workflow_runs.workflow_run_id"))
    capability_id: Mapped[str] = mapped_column(ForeignKey("capability_manifests.capability_id"))
    agent_run_id: Mapped[str | None] = mapped_column(ForeignKey("agent_runs.agent_run_id"))
    requested_by_principal_id: Mapped[str] = mapped_column(ForeignKey("principals.principal_id"))
    policy_decision: Mapped[str] = mapped_column(String(32), default="")
    approval_id: Mapped[str | None] = mapped_column(ForeignKey("approvals.approval_id"))
    sandbox_id: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="requested", index=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result_evidence_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    error: Mapped[str] = mapped_column(Text, default="")

    __table_args__ = (
        UniqueConstraint("tool_invocation_id", "engagement_id", name="uq_tool_invocation_engagement"),
        ForeignKeyConstraint(
            ["workflow_run_id", "engagement_id"],
            ["workflow_runs.workflow_run_id", "workflow_runs.engagement_id"],
            name="fk_invocation_workflow_engagement",
        ),
        ForeignKeyConstraint(
            ["agent_run_id", "engagement_id"],
            ["agent_runs.agent_run_id", "agent_runs.engagement_id"],
            name="fk_invocation_agent_engagement",
        ),
        ForeignKeyConstraint(
            ["approval_id", "engagement_id"],
            ["approvals.approval_id", "approvals.engagement_id"],
            name="fk_invocation_approval_engagement",
        ),
    )

    workflow_run: Mapped["WorkflowRunRow"] = relationship(
        back_populates="tool_invocations", foreign_keys=[workflow_run_id]
    )
    evidence_objects: Mapped[list["EvidenceMetadataRow"]] = relationship(
        back_populates="invocation", foreign_keys="EvidenceMetadataRow.invocation_id"
    )


class EvidenceMetadataRow(Base):
    __tablename__ = "evidence_metadata"
    evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.target_id"))
    collector: Mapped[str] = mapped_column(String(128))
    tool_version: Mapped[str] = mapped_column(String(32))
    capability_id: Mapped[str] = mapped_column(ForeignKey("capability_manifests.capability_id"))
    invocation_id: Mapped[str] = mapped_column(ForeignKey("tool_invocations.tool_invocation_id"))
    sandbox_id: Mapped[str | None] = mapped_column(String(64))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    content_type: Mapped[str] = mapped_column(String(128))
    byte_size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    storage_ref: Mapped[str] = mapped_column(String(512))
    sanitization_state: Mapped[str] = mapped_column(String(32))
    source_identity: Mapped[str] = mapped_column(String(128), default="")
    agent_run_id: Mapped[str | None] = mapped_column(ForeignKey("agent_runs.agent_run_id"))
    secret_observations: Mapped[list[Any]] = mapped_column(JSON, default=list)

    __table_args__ = (
        ForeignKeyConstraint(
            ["engagement_id", "target_id"],
            ["engagement_targets.engagement_id", "engagement_targets.target_id"],
            name="fk_evidence_engagement_target",
        ),
        ForeignKeyConstraint(
            ["invocation_id", "engagement_id"],
            ["tool_invocations.tool_invocation_id", "tool_invocations.engagement_id"],
            name="fk_evidence_invocation_engagement",
        ),
        ForeignKeyConstraint(
            ["agent_run_id", "engagement_id"],
            ["agent_runs.agent_run_id", "agent_runs.engagement_id"],
            name="fk_evidence_agent_engagement",
        ),
        UniqueConstraint("sha256", "engagement_id", name="uq_evidence_sha256_engagement"),
    )

    invocation: Mapped["ToolInvocationRow"] = relationship(
        back_populates="evidence_objects", foreign_keys=[invocation_id]
    )


class ObservationRow(Base):
    __tablename__ = "observations"
    observation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    evidence_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    kind: Mapped[str] = mapped_column(String(64))
    statement: Mapped[str] = mapped_column(Text)
    recorded_by_agent_id: Mapped[str] = mapped_column(String(64))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ClaimRow(Base):
    __tablename__ = "claims"
    claim_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(64))
    agent_run_id: Mapped[str] = mapped_column(ForeignKey("agent_runs.agent_run_id"))
    observation_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    statement: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(16), default="unknown")
    uncertainty: Mapped[str] = mapped_column(Text, default="")
    supporting_note: Mapped[str] = mapped_column(Text, default="")
    made_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        UniqueConstraint("claim_id", "engagement_id", name="uq_claim_engagement"),
        ForeignKeyConstraint(
            ["agent_run_id", "engagement_id"],
            ["agent_runs.agent_run_id", "agent_runs.engagement_id"],
            name="fk_claim_agent_engagement",
        ),
    )


class FindingRow(Base):
    __tablename__ = "findings"
    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    originating_adjudication_id: Mapped[str] = mapped_column(ForeignKey("adjudications.adjudication_id"))
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    summary: Mapped[str] = mapped_column(Text)
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation_guidance: Mapped[str] = mapped_column(Text, default="")
    verification_step: Mapped[str] = mapped_column(Text, default="")
    supporting_evidence_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    contradicting_evidence_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    rationale: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[str] = mapped_column(String(16), default="unknown")
    status: Mapped[str] = mapped_column(String(32), default="open")
    closed_by_principal_id: Mapped[str | None] = mapped_column(ForeignKey("principals.principal_id"))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("finding_id", "engagement_id", name="uq_finding_engagement"),
        ForeignKeyConstraint(
            ["originating_adjudication_id", "engagement_id"],
            ["adjudications.adjudication_id", "adjudications.engagement_id"],
            name="fk_finding_adjudication_engagement",
        ),
    )


class AdjudicationRow(Base):
    __tablename__ = "adjudications"
    adjudication_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    claim_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    supporting_evidence_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    contradicting_evidence_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    verdict: Mapped[str] = mapped_column(String(32))
    rationale: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(16), default="unknown")
    specialist_identity: Mapped[str] = mapped_column(String(128), default="")
    tool_confidence: Mapped[str | None] = mapped_column(String(16))
    scope_note: Mapped[str] = mapped_column(Text, default="")
    decided_by_principal_id: Mapped[str | None] = mapped_column(ForeignKey("principals.principal_id"))
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (UniqueConstraint("adjudication_id", "engagement_id", name="uq_adjudication_engagement"),)



class RefusalRow(Base):
    __tablename__ = "refusals"
    refusal_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.engagement_id"))
    requested_by_principal_id: Mapped[str | None] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(Text)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class RemediationRow(Base):
    __tablename__ = "remediations"
    remediation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.target_id"))
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.finding_id"))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="staged")
    applied_by_principal_id: Mapped[str | None] = mapped_column(String(64))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rollback_note: Mapped[str] = mapped_column(Text, default="")


class ReportRow(Base):
    __tablename__ = "reports"
    report_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    path: Mapped[str] = mapped_column(String(512))
    sha256: Mapped[str] = mapped_column(String(64))
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[str] = mapped_column(String(16), default="go")
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    no_secrets_asserted: Mapped[bool] = mapped_column(Boolean, default=False)


class BaselineRow(Base):
    __tablename__ = "baselines"
    baseline_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.target_id"))
    sha256: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text, default="")
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class DriftEventRow(Base):
    __tablename__ = "drift_events"
    drift_event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    baseline_id: Mapped[str] = mapped_column(ForeignKey("baselines.baseline_id"), index=True)
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.engagement_id"))
    drift_kind: Mapped[str] = mapped_column(String(64), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AuditEventRow(Base):
    __tablename__ = "audit_events"
    audit_event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    engagement_id: Mapped[str | None] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    principal_id: Mapped[str | None] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(64), index=True)
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    previous_event_id: Mapped[str | None] = mapped_column(ForeignKey("audit_events.audit_event_id"))

    __table_args__ = (Index("ix_audit_events_engagement_occurred", "engagement_id", "occurred_at"),)


class WorkflowSideEffectRow(Base):
    """Idempotency backing for workflow side effects (R2, data/state review).

    The unique key constraint is the canonical exactly-once guarantee:
    two records with the same idempotency key can only ever produce one
    row; replays read the recorded effect back (replay, not duplicate).
    """

    __tablename__ = "workflow_side_effects"
    idempotency_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    effect: Mapped[dict[str, Any]] = mapped_column(JSON)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class SecurityGraphSnapshotRow(Base):
    """Canonical PostgreSQL record for one deterministic security graph."""

    __tablename__ = "security_graph_snapshots"
    snapshot_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    digest: Mapped[str] = mapped_column(String(64))
    normalization_version: Mapped[str] = mapped_column(String(64), default="security-graph-v1")
    canonical_state: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    nodes: Mapped[list["SecurityGraphNodeRow"]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan"
    )
    edges: Mapped[list["SecurityGraphEdgeRow"]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "case_id", "target_id", "digest", name="uq_security_graph_scope_digest"
        ),
    )


class TargetSecurityProfileRow(Base):
    """Snapshot-bound profile facts; raw source content is never persisted here."""

    __tablename__ = "target_security_profiles"
    profile_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.client_id"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.target_id"), index=True)
    snapshot_id: Mapped[str] = mapped_column(String(128), index=True)
    target_class: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    __table_args__ = (
        UniqueConstraint("target_id", "snapshot_id", name="uq_security_profile_target_snapshot"),
    )


class AssessmentPlanRow(Base):
    """Deterministic service routing bound to one engagement and target."""

    __tablename__ = "assessment_plans"
    plan_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.client_id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.target_id"), index=True)
    profile_id: Mapped[str] = mapped_column(ForeignKey("target_security_profiles.profile_id"))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    __table_args__ = (
        ForeignKeyConstraint(
            ["engagement_id", "target_id"],
            ["engagement_targets.engagement_id", "engagement_targets.target_id"],
            name="fk_assessment_plan_engagement_target",
        ),
    )


class SecurityGraphNodeRow(Base):
    __tablename__ = "security_graph_nodes"
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("security_graph_snapshots.snapshot_id", ondelete="CASCADE"), primary_key=True
    )
    node_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(64), index=True)
    entity_id: Mapped[str] = mapped_column(String(128), index=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    provenance: Mapped[list[Any]] = mapped_column(JSON, default=list)

    snapshot: Mapped["SecurityGraphSnapshotRow"] = relationship(back_populates="nodes")


class SecurityGraphEdgeRow(Base):
    __tablename__ = "security_graph_edges"
    snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("security_graph_snapshots.snapshot_id", ondelete="CASCADE"), primary_key=True
    )
    edge_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    source_node: Mapped[str] = mapped_column(String(255), index=True)
    target_node: Mapped[str] = mapped_column(String(255), index=True)
    relation: Mapped[str] = mapped_column(String(64), index=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    provenance: Mapped[list[Any]] = mapped_column(JSON, default=list)

    snapshot: Mapped["SecurityGraphSnapshotRow"] = relationship(back_populates="edges")


class SecurityServiceRunRow(Base):
    """Durable service-run receipt with explicit tenant and engagement scope."""

    __tablename__ = "security_service_runs"
    run_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.client_id"), index=True)
    engagement_id: Mapped[str] = mapped_column(ForeignKey("engagements.engagement_id"), index=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.target_id"), index=True)
    snapshot_id: Mapped[str] = mapped_column(String(128), index=True)
    service_id: Mapped[str] = mapped_column(String(64), index=True)
    service_version: Mapped[str] = mapped_column(String(32))
    specialist_id: Mapped[str] = mapped_column(String(96))
    assessment_plan_id: Mapped[str] = mapped_column(ForeignKey("assessment_plans.plan_id"), index=True)
    authority_level: Mapped[str] = mapped_column(String(32), default="inspection-only")
    capabilities: Mapped[list[Any]] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    claim_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), index=True)
    qualification_version: Mapped[str] = mapped_column(String(32), default="AQS-V1")
    limitations: Mapped[list[Any]] = mapped_column(JSON, default=list)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    __table_args__ = (
        ForeignKeyConstraint(
            ["engagement_id", "target_id"],
            ["engagement_targets.engagement_id", "engagement_targets.target_id"],
            name="fk_service_run_engagement_target",
        ),
    )


class ServiceQualificationRow(Base):
    """Machine-readable AQS receipt for one service contract version."""

    __tablename__ = "service_qualifications"
    service_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    service_version: Mapped[str] = mapped_column(String(32), primary_key=True)
    qualification_state: Mapped[str] = mapped_column(String(48), index=True)
    receipt: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class SecurityEventRow(Base):
    """Canonical normalized security event; raw source content stays external."""

    __tablename__ = "security_events"
    event_id: Mapped[str] = mapped_column(String(96), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(128))
    source_type: Mapped[str] = mapped_column(String(128))
    source_family: Mapped[str] = mapped_column(String(64), index=True)
    event_class: Mapped[str] = mapped_column(String(96), index=True)
    ocsf_class: Mapped[str] = mapped_column(String(96))
    ocsf_version: Mapped[str] = mapped_column(String(32), default="1.8.0")
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    actor: Mapped[str] = mapped_column(String(255))
    object_ref: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(255))
    outcome: Mapped[str] = mapped_column(String(96))
    severity: Mapped[str | None] = mapped_column(String(16))
    raw_evidence_ref: Mapped[str] = mapped_column(String(512))
    source_digest: Mapped[str] = mapped_column(String(128))
    normalization_version: Mapped[str] = mapped_column(String(64))
    ordering_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    fingerprint: Mapped[str] = mapped_column(String(64))

    __table_args__ = (
        UniqueConstraint("tenant_id", "case_id", "target_id", "fingerprint", name="uq_security_event_scope_fingerprint"),
        Index("ix_security_events_scope_occurred", "tenant_id", "case_id", "target_id", "occurred_at"),
    )


class DetectionRuleVersionRow(Base):
    __tablename__ = "detection_rule_versions"
    rule_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    rule_type: Mapped[str] = mapped_column(String(48))
    content_digest: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(128))
    source_reference: Mapped[str] = mapped_column(String(512))
    owner: Mapped[str] = mapped_column(String(64), default="SecScanMonitor", server_default="SecScanMonitor")
    event_schema: Mapped[str] = mapped_column(String(96))
    ocsf_version: Mapped[str] = mapped_column(String(32))
    supported_source_families: Mapped[list[Any]] = mapped_column(JSON, default=list)
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    confidence_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    attack_mappings: Mapped[list[Any]] = mapped_column(JSON, default=list)
    atlas_mappings: Mapped[list[Any]] = mapped_column(JSON, default=list)
    references: Mapped[list[Any]] = mapped_column(JSON, default=list)
    predicates: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    correlation_keys: Mapped[list[Any]] = mapped_column(JSON, default=list)
    window_seconds: Mapped[int] = mapped_column(Integer, default=0)
    threshold: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(32), index=True)
    evaluation_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Digest of the complete normalized rule record.  ``content_digest`` is
    # the source/Sigma digest; this second digest detects a database row that
    # was altered after registration without changing its source digest.
    canonical_digest: Mapped[str | None] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    modified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class DetectionPlanRow(Base):
    __tablename__ = "detection_plans"
    plan_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_version: Mapped[int] = mapped_column(Integer)
    rule_type: Mapped[str] = mapped_column(String(48))
    content_digest: Mapped[str] = mapped_column(String(128))
    event_schema: Mapped[str] = mapped_column(String(96))
    supported_source_families: Mapped[list[Any]] = mapped_column(JSON, default=list)
    predicates: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    correlation_keys: Mapped[list[Any]] = mapped_column(JSON, default=list)
    window_seconds: Mapped[int] = mapped_column(Integer, default=0)
    threshold: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class DetectionRunRow(Base):
    __tablename__ = "detection_runs"
    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    input_event_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    evaluation_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    signal_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    engine_version: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(32), index=True)


class DetectionEvaluationRow(Base):
    __tablename__ = "detection_evaluations"
    evaluation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(128), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_version: Mapped[int] = mapped_column(Integer)
    input_event_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    matched_predicates: Mapped[list[Any]] = mapped_column(JSON, default=list)
    result: Mapped[str] = mapped_column(String(32))
    signal_id: Mapped[str | None] = mapped_column(String(128), index=True)
    engine_version: Mapped[str] = mapped_column(String(64))
    rule_digest: Mapped[str] = mapped_column(String(128))
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)


class DetectionSignalRow(Base):
    __tablename__ = "detection_signals"
    signal_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    rule_version: Mapped[int] = mapped_column(Integer)
    event_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    source_signal_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    matched_predicates: Mapped[list[Any]] = mapped_column(JSON, default=list)
    raw_evidence_refs: Mapped[list[Any]] = mapped_column(JSON, default=list)
    rule_digest: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)


class HuntExecutionRow(Base):
    __tablename__ = "hunt_executions"
    execution_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    plan_id: Mapped[str] = mapped_column(String(128), index=True)
    hypothesis_id: Mapped[str] = mapped_column(String(128), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    query_digest: Mapped[str] = mapped_column(String(128))
    input_event_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    input_signal_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    result_id: Mapped[str] = mapped_column(String(128), unique=True)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IncidentHypothesisRow(Base):
    __tablename__ = "incident_hypotheses"
    hypothesis_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    question: Mapped[str] = mapped_column(Text)
    source_signal_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    affected_entities: Mapped[list[Any]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class IncidentRow(Base):
    __tablename__ = "incidents"
    incident_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    hypothesis_id: Mapped[str] = mapped_column(String(128), index=True)
    investigation_id: Mapped[str] = mapped_column(String(128), index=True)
    adjudication_id: Mapped[str] = mapped_column(String(128), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    state: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    source_signal_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    observation_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    claim_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    supporting_evidence_refs: Mapped[list[Any]] = mapped_column(JSON, default=list)
    contradicting_evidence_refs: Mapped[list[Any]] = mapped_column(JSON, default=list)
    adjudicated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    authorized_action_executed: Mapped[bool] = mapped_column(Boolean, default=False)


class ResponseProposalRow(Base):
    __tablename__ = "response_proposals"
    proposal_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(128), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(Text)
    supporting_evidence_refs: Mapped[list[Any]] = mapped_column(JSON, default=list)
    expected_impact: Mapped[str] = mapped_column(Text)
    risk: Mapped[str] = mapped_column(Text)
    rollback_plan: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    proposal_digest: Mapped[str] = mapped_column(String(128), unique=True)
    opa_decision: Mapped[str] = mapped_column(String(32))
    human_approval_state: Mapped[str] = mapped_column(String(32), index=True)
    authorized_action_executed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class SecuritySourceBindingRow(Base):
    """A registered source identity bound to one canonical engagement scope."""

    __tablename__ = "security_source_bindings"
    source_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.principal_id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    source_family: Mapped[str] = mapped_column(String(64))
    source_type: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        ForeignKeyConstraint(
            ["case_id", "target_id"],
            ["engagement_targets.engagement_id", "engagement_targets.target_id"],
            name="fk_security_source_binding_engagement_target",
        ),
    )


class DetectionWorkItemRow(Base):
    """Durable event-to-detection handoff with lease-based recovery."""

    __tablename__ = "detection_work_items"
    work_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(96), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    event_fingerprint: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="PENDING", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    worker_id: Mapped[str | None] = mapped_column(String(128))
    run_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    signal_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    last_error: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "case_id", "target_id", "event_id", name="uq_detection_work_scope_event"
        ),
        Index("ix_detection_work_scope_status", "tenant_id", "case_id", "target_id", "status"),
    )


class HuntHypothesisRow(Base):
    """Durable explicit hunt request; persistence precedes execution."""

    __tablename__ = "hunt_hypotheses"
    hypothesis_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    question: Mapped[str] = mapped_column(Text)
    entity_keys: Mapped[list[Any]] = mapped_column(JSON, default=list)
    supporting_signal_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    required_evidence_refs: Mapped[list[Any]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class HuntPlanRow(Base):
    """Durable bounded hunt plan and its recoverable request state."""

    __tablename__ = "hunt_plans"
    plan_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    hypothesis_id: Mapped[str] = mapped_column(String(128), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    query: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    exit_criteria: Mapped[str] = mapped_column(Text)
    max_events: Mapped[int] = mapped_column(Integer, default=500)
    status: Mapped[str] = mapped_column(String(16), default="PENDING", index=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    worker_id: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_hunt_plans_scope_status", "tenant_id", "case_id", "target_id", "status"),
        Index("ix_hunt_plans_status_lease", "status", "lease_until"),
    )


class IncidentInvestigationRow(Base):
    """Durable evidence/claim investigation opened for one hypothesis."""

    __tablename__ = "incident_investigations"
    investigation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    hypothesis_id: Mapped[str] = mapped_column(String(128), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    observation_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    claim_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ResponseCapabilityRequestRow(Base):
    """Durable proposal capability request; it has no execution path."""

    __tablename__ = "response_capability_requests"
    request_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    proposal_id: Mapped[str] = mapped_column(ForeignKey("response_proposals.proposal_id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    case_id: Mapped[str] = mapped_column(String(128), index=True)
    target_id: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(64))
    proposal_digest: Mapped[str] = mapped_column(String(128))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    __table_args__ = (
        UniqueConstraint("proposal_id", "proposal_digest", name="uq_response_capability_request_proposal"),
    )
