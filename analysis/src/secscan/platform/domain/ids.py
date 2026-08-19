"""Strongly typed identifiers for every platform entity.

Identifiers are NewType wrappers so accidental cross-assignment between entity
ids is a type error, while JSON/YAML interop stays trivial (they serialize as
plain strings). UUIDv4 where uniqueness is minted at creation.
"""

from __future__ import annotations

import uuid
from typing import NewType

ClientId = NewType("ClientId", str)
TargetId = NewType("TargetId", str)
PrincipalId = NewType("PrincipalId", str)
EngagementId = NewType("EngagementId", str)
EngagementTargetId = NewType("EngagementTargetId", str)
AgentId = NewType("AgentId", str)
AgentManifestId = NewType("AgentManifestId", str)
CapabilityId = NewType("CapabilityId", str)
AuthorityGrantId = NewType("AuthorityGrantId", str)
ApprovalId = NewType("ApprovalId", str)
WorkflowRunId = NewType("WorkflowRunId", str)
AgentRunId = NewType("AgentRunId", str)
ToolInvocationId = NewType("ToolInvocationId", str)
EvidenceId = NewType("EvidenceId", str)
ObservationId = NewType("ObservationId", str)
ClaimId = NewType("ClaimId", str)
FindingId = NewType("FindingId", str)
AdjudicationId = NewType("AdjudicationId", str)
RemediationId = NewType("RemediationId", str)
RefusalId = NewType("RefusalId", str)
ReportId = NewType("ReportId", str)
BaselineId = NewType("BaselineId", str)
DriftEventId = NewType("DriftEventId", str)
AuditEventId = NewType("AuditEventId", str)


def new_id(prefix: str) -> str:
    """Mint a new identifier: '<prefix>-<uuid4 hex>'."""
    return f"{prefix}-{uuid.uuid4().hex}"
