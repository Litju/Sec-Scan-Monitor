"""Authority model: grants, approvals, policy decisions.

Authority is canonical data, never prompt text. A grant answers WHO may
perform WHAT ACTION through WHICH CAPABILITY against WHICH TARGET inside
WHICH ENGAGEMENT under WHICH CONDITIONS until WHEN.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import Field

from secscan.platform.domain.common import DomainModel, utc_now
from secscan.platform.domain.ids import (
    ApprovalId,
    AuthorityGrantId,
    CapabilityId,
    EngagementId,
    PrincipalId,
    TargetId,
)


class Action(str, Enum):
    INSPECT = "inspect"
    COLLECT = "collect"
    ACTIVE_TEST = "active_test"
    MUTATE = "mutate"
    REMEDIATE = "remediate"


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class RiskLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Actions permitted under each engagement authority level (protocol terms).
INSPECTION_ONLY_ACTIONS = frozenset({Action.INSPECT, Action.COLLECT})
# ACTIVE_TEST is a mutation-class action (matches the policy kernel's
# mutation_actions set): it requires remediation engagement authority.
REMEDIATION_ACTIONS = INSPECTION_ONLY_ACTIONS | frozenset({Action.MUTATE, Action.REMEDIATE, Action.ACTIVE_TEST})





def _as_utc(value: datetime) -> datetime:
    """Coerce naive datetimes to UTC (defensive against persistence without
    tz metadata); aware values pass through unchanged."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value

class AuthorityGrant(DomainModel):
    """WHO/WHAT/WHICH/WHERE/WHEN authority record."""

    grant_id: AuthorityGrantId
    engagement_id: EngagementId
    principal_id: PrincipalId
    action: Action
    capability_id: CapabilityId | None = None  # None = any capability the engagement authorizes
    target_id: TargetId | None = None  # None = any target declared in engagement scope
    conditions: list[str] = Field(default_factory=list)
    not_before: datetime = Field(default_factory=utc_now)
    not_after: datetime | None = None
    revoked_at: datetime | None = None

    def is_active(self, *, now: datetime | None = None, action: Action | None = None) -> bool:
        """Active unless revoked, expired, or not-yet-valid for the action.

        Naive timestamps (e.g. restored from persistence without tz
        metadata) are coerced to UTC rather than crashing the decision
        path (security-review robustness finding).
        """
        now = now or utc_now()
        now = _as_utc(now)
        if self.revoked_at is not None and now >= _as_utc(self.revoked_at):
            return False
        if now < _as_utc(self.not_before):
            return False
        if self.not_after is not None and now >= _as_utc(self.not_after):
            return False
        if action is not None and self.action != action:
            return False
        return True


class Approval(DomainModel):
    """Human/operator decision on a REQUIRE_APPROVAL outcome.

    An approval references the exact request it approves (request reference +
    target + capability + action); it can never authorize a different target.
    """

    approval_id: ApprovalId
    engagement_id: EngagementId
    requested_by_principal_id: PrincipalId
    decided_by_principal_id: PrincipalId | None = None
    request_ref: str  # e.g. capability execution id or tool invocation id
    target_id: TargetId
    capability_id: CapabilityId
    action: Action
    decision: str = "pending"  # pending | approved | denied
    decided_at: datetime | None = None
    rationale: str = ""

    def decide(self, *, decision: str, by: PrincipalId, rationale: str = "") -> None:
        if decision not in {"approved", "denied"}:
            raise ValueError(f"Invalid approval decision: {decision}")
        self.decision = decision
        self.decided_by_principal_id = by
        self.decided_at = utc_now()
        self.rationale = rationale
        self.updated_at = self.decided_at
