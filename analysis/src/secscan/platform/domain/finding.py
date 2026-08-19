"""Findings and adjudication.

A Finding is created ONLY through adjudication. Scanner or model output can
never instantiate a Finding directly.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from secscan.platform.domain.common import AdjudicationVerdict, Confidence, DomainModel, Severity, utc_now
from secscan.platform.domain.ids import (
    AdjudicationId,
    ClaimId,
    EngagementId,
    EvidenceId,
    FindingId,
    PrincipalId,
)


class Adjudication(DomainModel):
    """Verdict over claims + evidence, with corroboration and rationale."""

    adjudication_id: AdjudicationId
    engagement_id: EngagementId
    claim_ids: list[ClaimId]
    supporting_evidence_ids: list[EvidenceId] = Field(default_factory=list)
    contradicting_evidence_ids: list[EvidenceId] = Field(default_factory=list)
    verdict: AdjudicationVerdict
    rationale: str
    confidence: Confidence = Confidence.UNKNOWN
    specialist_identity: str = ""
    tool_confidence: Confidence | None = None
    scope_note: str = ""
    decided_by_principal_id: PrincipalId | None = None
    decided_at: datetime = Field(default_factory=utc_now)


class Finding(DomainModel):
    """Adjudicated conclusion. Exactly one originating adjudication."""

    finding_id: FindingId
    engagement_id: EngagementId
    originating_adjudication_id: AdjudicationId
    title: str
    severity: Severity
    summary: str
    impact: str = ""
    remediation_guidance: str = ""
    verification_step: str = ""
    supporting_evidence_ids: list[EvidenceId] = Field(default_factory=list)
    contradicting_evidence_ids: list[EvidenceId] = Field(default_factory=list)
    rationale: str = ""
    confidence: Confidence = Confidence.UNKNOWN
    status: str = "open"  # open | resolved | waived
    closed_by_principal_id: PrincipalId | None = None
    closed_at: datetime | None = None
    contributing_services: list[str] = Field(default_factory=list)
    dedupe_key: str = ""
    affected_component: str = ""
    preconditions: list[str] = Field(default_factory=list)
    standard_references: list[str] = Field(default_factory=list)


__all__ = ["Adjudication", "AdjudicationVerdict", "Finding"]
