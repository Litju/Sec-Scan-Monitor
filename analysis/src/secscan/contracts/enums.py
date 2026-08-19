"""Shared enumerations for canonical and advisory contract models."""

from enum import StrEnum


class AssetRole(StrEnum):
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    PHONE_ANCHOR = "phone-anchor"
    EDGE_DEVICE = "edge-device"
    OTHER = "other"


class PostureStatus(StrEnum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class EvidenceSensitivity(StrEnum):
    LOCAL_SENSITIVE = "local-sensitive"
    SANITIZED_REFERENCE = "sanitized-reference"


class FindingSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class RiskBand(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PromotionStatus(StrEnum):
    NOT_YET = "not-yet"
    BLOCKED = "blocked"
    ELIGIBLE = "eligible"
    APPROVED = "approved"


class SufficiencyAssessment(StrEnum):
    SUFFICIENT = "sufficient"
    PARTIAL = "partial"
    INSUFFICIENT = "insufficient"


class BlockerSourceType(StrEnum):
    POLICY = "policy"
    DETERMINISTIC_ANALYSIS = "deterministic-analysis"
    ADVISORY_RESTATEMENT = "advisory-restatement"
