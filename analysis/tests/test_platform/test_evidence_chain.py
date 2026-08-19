"""Evidence chain separation tests: raw -> observation -> claim -> finding.

A scanner/model output can never directly instantiate a Finding: there is no
constructor path from EvidenceObject to Finding. Findings are created only
through adjudication (asserted structurally here and behaviorally in the
adjudication tests).
"""

from __future__ import annotations

import hashlib

import pydantic
import pytest

from secscan.platform.domain.audit import AuditEvent, AuditEventKind
from secscan.platform.domain.common import Confidence, Severity
from secscan.platform.domain.evidence import (
    Claim,
    EvidenceObject,
    Observation,
    SanitizationState,
    SecretClass,
    SecretObservation,
)
from secscan.platform.domain.finding import Adjudication, AdjudicationVerdict, Finding
from secscan.platform.domain.ids import (
    AdjudicationId,
    AgentId,
    AgentRunId,
    AuditEventId,
    CapabilityId,
    ClaimId,
    EngagementId,
    EvidenceId,
    FindingId,
    ObservationId,
    TargetId,
    ToolInvocationId,
)


def _evidence(content: bytes) -> EvidenceObject:
    return EvidenceObject(
        evidence_id=EvidenceId("EV-1"),
        engagement_id=EngagementId("ENG-1"),
        target_id=TargetId("TGT-1"),
        collector="scanner-demo",
        tool_version="1.2.3",
        capability_id=CapabilityId("CAP-REPO-READONLY-INSPECTION"),
        invocation_id=ToolInvocationId("TI-1"),
        content_type="text/plain",
        byte_size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        storage_ref=f"blob/{hashlib.sha256(content).hexdigest()}",
        sanitization_state=SanitizationState.SANITIZED,
    )


def test_evidence_provenance_complete() -> None:
    content = b"hello"
    evidence = _evidence(content)
    assert evidence.sha256 == hashlib.sha256(content).hexdigest()
    assert evidence.tool_version
    assert evidence.capability_id
    assert evidence.invocation_id
    assert evidence.collected_at.tzinfo is not None


def test_chain_objects_are_distinct_types() -> None:
    """Observation and Claim reference evidence; neither IS a Finding."""
    evidence = _evidence(b"data")
    observation = Observation(
        observation_id=ObservationId("OB-1"),
        engagement_id=evidence.engagement_id,
        evidence_ids=[evidence.evidence_id],
        kind="file-presence",
        statement="file exists",
        recorded_by_agent_id=AgentId("AGT-1"),
    )
    claim = Claim(
        claim_id=ClaimId("CL-1"),
        engagement_id=evidence.engagement_id,
        agent_id=AgentId("AGT-1"),
        agent_run_id=AgentRunId("AR-1"),
        observation_ids=[observation.observation_id],
        evidence_ids=[evidence.evidence_id],
        statement="file exists with sensitive pattern",
        confidence=Confidence.MEDIUM,
        uncertainty="pattern match unverified by second source",
    )
    assert observation.evidence_ids == [EvidenceId("EV-1")]
    assert claim.observation_ids == [ObservationId("OB-1")]
    assert claim.confidence == Confidence.MEDIUM
    # No path from evidence/claim to Finding without adjudication:
    with pytest.raises(pydantic.ValidationError):
        Finding(finding_id=FindingId("F-1"), engagement_id=claim.engagement_id)  # type: ignore[call-arg]


def test_finding_requires_originating_adjudication() -> None:
    adjudication = Adjudication(
        adjudication_id=AdjudicationId("AD-1"),
        engagement_id=EngagementId("ENG-1"),
        claim_ids=[ClaimId("CL-1")],
        supporting_evidence_ids=[EvidenceId("EV-1")],
        verdict=AdjudicationVerdict.CONFIRMED,
        rationale="evidence corroborates claim",
        confidence=Confidence.HIGH,
    )
    finding = Finding(
        finding_id=FindingId("F-1"),
        engagement_id=EngagementId("ENG-1"),
        originating_adjudication_id=adjudication.adjudication_id,
        title="secret-like pattern confirmed",
        severity=Severity.MEDIUM,
        summary="pattern verified in evidence EV-1",
        supporting_evidence_ids=[EvidenceId("EV-1")],
    )
    assert finding.originating_adjudication_id == AdjudicationId("AD-1")
    assert finding.status == "open"


def test_secret_observations_are_metadata_only() -> None:
    """Secret values are never stored: only class + redacted location."""
    secret_obs = SecretObservation(
        secret_class=SecretClass.API_KEY,
        redacted_location="src/config.py:12 [REDACTED]",
        evidence_id=EvidenceId("EV-1"),
        detection_source="gitleaks-like-detector",
    )
    dumped = secret_obs.model_dump()
    assert "sk-" not in str(dumped)
    assert dumped["secret_class"] == "api_key"
    assert "REDACTED" in dumped["redacted_location"]


def test_audit_event_is_append_oriented() -> None:
    event = AuditEvent(
        audit_event_id=AuditEventId("AE-1"),
        engagement_id=EngagementId("ENG-1"),
        kind=AuditEventKind.POLICY_DECISION,
        summary="capability request denied: out-of-scope target",
        details={"capability_id": "CAP-1", "target_id": "TGT-2", "decision": "deny"},
    )
    event2 = AuditEvent(
        audit_event_id=AuditEventId("AE-2"),
        engagement_id=EngagementId("ENG-1"),
        kind=AuditEventKind.CLAIM_CREATED,
        summary="claim recorded",
    )
    event2.link(event)
    assert event2.previous_event_id == AuditEventId("AE-1")
