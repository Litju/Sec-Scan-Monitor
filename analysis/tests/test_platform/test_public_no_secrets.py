from __future__ import annotations

from secscan.platform.application.evidence_service import EvidenceService
from secscan.platform.domain.evidence import SanitizationState
from secscan.platform.domain.ids import (
    CapabilityId,
    EngagementId,
    PrincipalId,
    TargetId,
    ToolInvocationId,
)
from secscan.platform.evidence import InMemoryContentAddressedEvidenceStore


def test_synthetic_secret_like_values_are_not_persisted() -> None:
    store = InMemoryContentAddressedEvidenceStore()
    service = EvidenceService(store, audit=[])
    evidence = service.ingest(
        engagement_id=EngagementId("ENG-PUBLIC-SECRET"),
        target_id=TargetId("TGT-PUBLIC-SECRET"),
        principal_id=PrincipalId("PRN-PUBLIC"),
        collector="synthetic-detector",
        tool_version="0.1.0",
        capability_id=CapabilityId("CAP-REPO-READONLY-INSPECTION"),
        invocation_id=ToolInvocationId("TI-PUBLIC-SECRET"),
        content=b"api_key = 'fixture-value'",
        content_type="text/plain",
    )
    assert evidence.sanitization_state == SanitizationState.REDACTED
    assert b"fixture-value" not in store.get(evidence.sha256)
