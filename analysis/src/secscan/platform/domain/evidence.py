"""Evidence chain domain objects.

RAW EVIDENCE (EvidenceObject) -> OBSERVATION -> CLAIM -> (adjudication) -> FINDING.

Laws:
- Scanner/tool output is always EvidenceObject material, never Finding.
- No-secrets: secret values are never persisted; only safe metadata.
- Evidence bytes are content-addressed (SHA-256) and immutable by content.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import Field

from secscan.platform.domain.common import Confidence, DomainModel, utc_now
from secscan.platform.domain.ids import (
    AgentId,
    AgentRunId,
    CapabilityId,
    ClaimId,
    EngagementId,
    EvidenceId,
    ObservationId,
    TargetId,
    ToolInvocationId,
)


class SanitizationState(str, Enum):
    UNSANITIZED = "unsanitized"
    SANITIZED = "sanitized"
    REDACTED = "redacted"  # secret material removed; only safe metadata retained
    NONE_REQUIRED = "none_required"


class SecretClass(str, Enum):
    """Secret classes recorded as safe metadata only — never the value itself."""

    API_KEY = "api_key"
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    TOKEN = "token"
    RECOVERY_KEY = "recovery_key"
    RECOVERY_CODE = "recovery_code"
    ENROLLMENT_SECRET = "enrollment_secret"
    CLIENT_CREDENTIAL = "client_credential"
    OTHER = "other"


class SecretObservation(DomainModel):
    """Safe metadata about a discovered secret. The value is NEVER stored."""

    secret_class: SecretClass
    redacted_location: str  # e.g. "path:line" with no secret content
    safe_fingerprint: str | None = None  # keyed/derived safe fingerprint only
    evidence_id: EvidenceId
    detection_source: str


class EvidenceObject(DomainModel):
    """Captured artifact with complete provenance and sanitized durable content."""

    evidence_id: EvidenceId
    engagement_id: EngagementId
    target_id: TargetId
    collector: str  # tool or agent name
    tool_version: str
    capability_id: CapabilityId
    invocation_id: ToolInvocationId
    sandbox_id: str | None = None
    collected_at: datetime = Field(default_factory=utc_now)
    content_type: str
    byte_size: int
    sha256: str
    storage_ref: str  # content-addressed location in the evidence store
    sanitization_state: SanitizationState = SanitizationState.UNSANITIZED
    source_identity: str = ""
    sanitized_payload: str = ""
    agent_run_id: AgentRunId | None = None
    secret_observations: list[SecretObservation] = Field(default_factory=list)


class Observation(DomainModel):
    """Normalized statement grounded in evidence. Never a verdict."""

    observation_id: ObservationId
    engagement_id: EngagementId
    evidence_ids: list[EvidenceId]
    kind: str
    statement: str
    recorded_by_agent_id: AgentId
    recorded_at: datetime = Field(default_factory=utc_now)


class Claim(DomainModel):
    """Agent assertion over observations. Carries categorical confidence."""

    claim_id: ClaimId
    engagement_id: EngagementId
    agent_id: AgentId
    agent_run_id: AgentRunId
    observation_ids: list[ObservationId]
    evidence_ids: list[EvidenceId]
    statement: str
    confidence: Confidence = Confidence.UNKNOWN
    uncertainty: str = ""  # stated uncertainty is required by specialist contract
    supporting_note: str = ""
    made_at: datetime = Field(default_factory=utc_now)
