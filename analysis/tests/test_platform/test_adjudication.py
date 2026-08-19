"""Adjudication engine tests: verdicts, finding-creation law, engagement
scope enforcement, cross-engagement claims rejected."""

from __future__ import annotations

import pytest

from secscan.platform.adjudication import AdjudicationInputError, AdjudicationService
from secscan.platform.domain.common import Confidence, Severity
from secscan.platform.domain.evidence import Claim
from secscan.platform.domain.finding import AdjudicationVerdict
from secscan.platform.domain.ids import (
    AgentId,
    AgentRunId,
    ClaimId,
    EngagementId,
    EvidenceId,
    PrincipalId,
)


def _claim(
    engagement_id: EngagementId = EngagementId("ENG-1"),  # noqa: B008
    confidence: Confidence = Confidence.MEDIUM,
    evidence: bool = True,
) -> Claim:
    return Claim(
        claim_id=ClaimId("CL-1"),
        engagement_id=engagement_id,
        agent_id=AgentId("AGT-SPEC"),
        agent_run_id=AgentRunId("AR-1"),
        observation_ids=[],
        evidence_ids=[EvidenceId("EV-1")] if evidence else [],
        statement="hardcoded credential found in config",
        confidence=confidence,
        uncertainty="single source",
    )


def _service() -> AdjudicationService:
    return AdjudicationService()


def test_confirmed_verdict_creates_finding() -> None:
    service = _service()
    adjudication, finding = service.adjudicate(
        engagement_id=EngagementId("ENG-1"),
        claim=_claim(confidence=Confidence.HIGH),
        supporting_evidence_ids=[EvidenceId("EV-1")],
        contradicting_evidence_ids=[],
        specialist_identity="secscan-review-specialist",
        tool_confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        decided_by_principal_id=PrincipalId("PRN-ADJ"),
    )
    assert adjudication.verdict == AdjudicationVerdict.CONFIRMED
    assert finding is not None
    assert finding.originating_adjudication_id == adjudication.adjudication_id
    assert finding.severity == Severity.HIGH


def test_supported_verdict_creates_finding() -> None:
    service = _service()
    adjudication, finding = service.adjudicate(
        engagement_id=EngagementId("ENG-1"),
        claim=_claim(confidence=Confidence.LOW),
        supporting_evidence_ids=[EvidenceId("EV-1")],
        contradicting_evidence_ids=[],
        specialist_identity="secscan-review-specialist",
        severity=Severity.LOW,
        decided_by_principal_id=PrincipalId("PRN-ADJ"),
    )
    assert adjudication.verdict == AdjudicationVerdict.SUPPORTED
    assert finding is not None


def test_inconclusive_no_finding() -> None:
    service = _service()
    adjudication, finding = service.adjudicate(
        engagement_id=EngagementId("ENG-1"),
        claim=_claim(evidence=False),
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[],
        specialist_identity="secscan-review-specialist",
        decided_by_principal_id=PrincipalId("PRN-ADJ"),
    )
    assert adjudication.verdict == AdjudicationVerdict.INCONCLUSIVE
    assert finding is None


def test_contradiction_forces_inconclusive_or_rejected() -> None:
    service = _service()
    adjudication, finding = service.adjudicate(
        engagement_id=EngagementId("ENG-1"),
        claim=_claim(confidence=Confidence.HIGH),
        supporting_evidence_ids=[EvidenceId("EV-1")],
        contradicting_evidence_ids=[EvidenceId("EV-2")],
        specialist_identity="secscan-review-specialist",
        tool_confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        decided_by_principal_id=PrincipalId("PRN-ADJ"),
    )
    assert adjudication.verdict == AdjudicationVerdict.INCONCLUSIVE
    assert finding is None


def test_rejected_when_no_evidence_and_contradiction() -> None:
    service = _service()
    adjudication, finding = service.adjudicate(
        engagement_id=EngagementId("ENG-1"),
        claim=_claim(evidence=False),
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[EvidenceId("EV-2")],
        specialist_identity="secscan-review-specialist",
        decided_by_principal_id=PrincipalId("PRN-ADJ"),
    )
    assert adjudication.verdict == AdjudicationVerdict.REJECTED
    assert finding is None


def test_cross_engagement_claim_rejected() -> None:
    service = _service()
    with pytest.raises(AdjudicationInputError):
        service.adjudicate(
            engagement_id=EngagementId("ENG-OTHER"),
            claim=_claim(engagement_id=EngagementId("ENG-1")),
            supporting_evidence_ids=[EvidenceId("EV-1")],
            contradicting_evidence_ids=[],
            specialist_identity="secscan-review-specialist",
            severity=Severity.MEDIUM,
            decided_by_principal_id=PrincipalId("PRN-ADJ"),
        )


def test_confirmed_requires_severity() -> None:
    service = _service()
    with pytest.raises(AdjudicationInputError):
        service.adjudicate(
            engagement_id=EngagementId("ENG-1"),
            claim=_claim(confidence=Confidence.HIGH),
            supporting_evidence_ids=[EvidenceId("EV-1")],
            contradicting_evidence_ids=[],
            specialist_identity="secscan-review-specialist",
            tool_confidence=Confidence.HIGH,
            severity=None,
            decided_by_principal_id=PrincipalId("PRN-ADJ"),
        )


def test_adjudication_preserves_evidence_and_rationale() -> None:
    service = _service()
    adjudication, finding = service.adjudicate(
        engagement_id=EngagementId("ENG-1"),
        claim=_claim(confidence=Confidence.HIGH),
        supporting_evidence_ids=[EvidenceId("EV-1"), EvidenceId("EV-3")],
        contradicting_evidence_ids=[],
        specialist_identity="secscan-review-specialist",
        tool_confidence=Confidence.HIGH,
        severity=Severity.CRITICAL,
        decided_by_principal_id=PrincipalId("PRN-ADJ"),
    )
    assert adjudication.supporting_evidence_ids == [EvidenceId("EV-1"), EvidenceId("EV-3")]
    assert adjudication.rationale
    assert finding is not None
    assert finding.supporting_evidence_ids == [EvidenceId("EV-1"), EvidenceId("EV-3")]
