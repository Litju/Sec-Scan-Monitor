"""Append-oriented canonical audit event model (ADR audit ledger)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import Field

from secscan.platform.domain.common import DomainModel, utc_now
from secscan.platform.domain.ids import AuditEventId, EngagementId, PrincipalId


class AuditEventKind(str, Enum):
    ENGAGEMENT_STATE_CHANGE = "engagement_state_change"
    AUTHORITY_CREATED = "authority_created"
    AUTHORITY_REVOKED = "authority_revoked"
    APPROVAL_DECISION = "approval_decision"
    AGENT_RUN = "agent_run"
    CAPABILITY_REQUEST = "capability_request"
    POLICY_DECISION = "policy_decision"
    TOOL_INVOCATION = "tool_invocation"
    SANDBOX_LIFECYCLE = "sandbox_lifecycle"
    EVIDENCE_INGESTION = "evidence_ingestion"
    CLAIM_CREATED = "claim_created"
    ADJUDICATION = "adjudication"
    FINDING_CREATED = "finding_created"
    SPECIALIST_SERVICE_EVENT = "specialist_service_event"
    REPORT_GENERATED = "report_generated"
    REFUSAL = "refusal"
    REMEDIATION_APPLIED = "remediation_applied"
    SYSTEM = "system"


class AuditEvent(DomainModel):
    """One append-only governance record. Never updated or deleted."""

    audit_event_id: AuditEventId
    engagement_id: EngagementId | None = None
    principal_id: PrincipalId | None = None
    kind: AuditEventKind
    summary: str
    details: dict[str, str] = Field(default_factory=dict)
    occurred_at: datetime = Field(default_factory=utc_now)
    previous_event_id: AuditEventId | None = None  # hash-chain linkage

    def link(self, previous: "AuditEvent | None") -> None:
        self.previous_event_id = previous.audit_event_id if previous else None
