from __future__ import annotations

import pytest

from secscan.platform.audit import InMemoryAuditSink, reconstruct_timeline
from secscan.platform.domain.audit import AuditEvent, AuditEventKind
from secscan.platform.domain.ids import AuditEventId, EngagementId, PrincipalId
from secscan.platform.observability import SpanAttributePolicyError, safe_attributes


def test_observability_accepts_only_safe_identifiers() -> None:
    assert safe_attributes(engagement_id="ENG-PUBLIC", decision="allow")["decision"] == "allow"
    with pytest.raises(SpanAttributePolicyError):
        safe_attributes(raw_prompt="fixture input")


def test_audit_timeline_is_reconstructable() -> None:
    sink = InMemoryAuditSink()
    sink.append(
        AuditEvent(
            audit_event_id=AuditEventId("AE-PUBLIC-1"),
            engagement_id=EngagementId("ENG-PUBLIC"),
            principal_id=PrincipalId("PRN-PUBLIC"),
            kind=AuditEventKind.ADJUDICATION,
            summary="claim adjudicated inconclusive [REDACTED]",
        )
    )
    timeline = reconstruct_timeline(sink.read_since())
    assert "AE-PUBLIC-1" in timeline
    assert "REDACTED" in timeline
