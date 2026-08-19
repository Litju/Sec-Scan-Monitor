"""Shared value objects: severity, confidence, time handling."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    """Timezone-aware current time, UTC-normalized."""
    return datetime.now(UTC)


class Severity(str, Enum):
    """Fixed severity scale from the engagement protocol. Never extensible by tools."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(str, Enum):
    """Categorical confidence. No fabricated numeric calibration."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class AdjudicationVerdict(str, Enum):
    """Shared adjudication vocabulary for specialist assessments."""

    CONFIRMED = "confirmed"
    SUPPORTED = "supported"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"


class DomainModel(BaseModel):
    """Base for all domain models: strict validation, tz-aware datetimes."""

    model_config = ConfigDict(extra="forbid", frozen=False)

    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
