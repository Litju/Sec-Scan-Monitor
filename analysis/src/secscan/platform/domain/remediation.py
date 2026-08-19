"""Remediation, refusal, report, baseline, and drift domain objects."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import Field

from secscan.platform.domain.common import DomainModel, utc_now
from secscan.platform.domain.ids import (
    BaselineId,
    DriftEventId,
    EngagementId,
    PrincipalId,
    RefusalId,
    RemediationId,
    ReportId,
    TargetId,
)


class RemediationStatus(str, Enum):
    STAGED = "staged"
    APPROVED = "approved"
    APPLIED = "applied"
    VERIFIED = "verified"
    REJECTED = "rejected"


class Remediation(DomainModel):
    """Authorized fix applied to a target. Requires remediation authority."""

    remediation_id: RemediationId
    engagement_id: EngagementId
    target_id: TargetId
    finding_id: str
    description: str
    status: RemediationStatus = RemediationStatus.STAGED
    applied_by_principal_id: PrincipalId | None = None
    applied_at: datetime | None = None
    rollback_note: str = ""


class Refusal(DomainModel):
    """Recorded refusal of an engagement or request. Refusals are a feature."""

    refusal_id: RefusalId
    engagement_id: EngagementId | None = None
    requested_by_principal_id: PrincipalId | None = None
    reason: str
    recorded_at: datetime = Field(default_factory=utc_now)


class Report(DomainModel):
    """Sanitized firm report artifact. Rendered by the case engine."""

    report_id: ReportId
    engagement_id: EngagementId
    path: str  # artifact location (evidence-store or filesystem reference)
    sha256: str
    findings_count: int = 0
    verdict: str = "go"  # go | conditional | no-go
    generated_at: datetime = Field(default_factory=utc_now)
    no_secrets_asserted: bool = False


class Baseline(DomainModel):
    """Deterministic snapshot for drift comparison."""

    baseline_id: BaselineId
    target_id: TargetId
    sha256: str
    description: str = ""
    captured_at: datetime = Field(default_factory=utc_now)


class DriftEvent(DomainModel):
    """Deterministic artifact comparison result."""

    drift_event_id: DriftEventId
    baseline_id: BaselineId
    engagement_id: EngagementId | None = None
    drift_kind: str = ""
    summary: str = ""
    detected_at: datetime = Field(default_factory=utc_now)
