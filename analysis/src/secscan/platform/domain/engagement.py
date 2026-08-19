"""Engagement aggregate and executable state machine.

Canonical lifecycle (docs/SECSCANMONITOR_FIRM_DOMAIN_MODEL_V1.md):
DRAFT -> INTAKE -> SCOPE_VALIDATED -> AUTHORIZED -> ACTIVE
-> EVIDENCE_COLLECTION -> ANALYSIS -> ADJUDICATION -> REPORTING
-> REMEDIATION -> CLOSED

Terminal/abnormal: REFUSED, SUSPENDED (reversible), REVOKED, FAILED, PARTIAL.

Laws:
- Invalid transitions fail deterministically (InvalidEngagementTransition).
- Every transition produces an AuditEvent via the supplied recorder.
- No LLM may change engagement state outside the application service that
  uses this module.
"""

from __future__ import annotations

from enum import Enum
from typing import Protocol

from pydantic import Field

from secscan.platform.domain.common import DomainModel, utc_now
from secscan.platform.domain.ids import (
    AuditEventId,
    ClientId,
    EngagementId,
    EngagementTargetId,
    PrincipalId,
    TargetId,
)


class EngagementStatus(str, Enum):
    DRAFT = "draft"
    INTAKE = "intake"
    SCOPE_VALIDATED = "scope_validated"
    AUTHORIZED = "authorized"
    ACTIVE = "active"
    EVIDENCE_COLLECTION = "evidence_collection"
    ANALYSIS = "analysis"
    ADJUDICATION = "adjudication"
    REPORTING = "reporting"
    REMEDIATION = "remediation"
    CLOSED = "closed"
    # abnormal / terminal
    REFUSED = "refused"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    FAILED = "failed"
    PARTIAL = "partial"


TERMINAL_STATES = frozenset(
    {
        EngagementStatus.REFUSED,
        EngagementStatus.REVOKED,
        EngagementStatus.FAILED,
        EngagementStatus.PARTIAL,
        EngagementStatus.CLOSED,
    }
)

_TRANSITIONS: dict[EngagementStatus, frozenset[EngagementStatus]] = {
    EngagementStatus.DRAFT: frozenset({EngagementStatus.INTAKE, EngagementStatus.REFUSED}),
    EngagementStatus.INTAKE: frozenset({EngagementStatus.SCOPE_VALIDATED, EngagementStatus.REFUSED}),
    EngagementStatus.SCOPE_VALIDATED: frozenset({EngagementStatus.AUTHORIZED, EngagementStatus.REFUSED}),
    EngagementStatus.AUTHORIZED: frozenset(
        {EngagementStatus.ACTIVE, EngagementStatus.SUSPENDED, EngagementStatus.REVOKED}
    ),
    EngagementStatus.ACTIVE: frozenset(
        {EngagementStatus.EVIDENCE_COLLECTION, EngagementStatus.SUSPENDED, EngagementStatus.REVOKED, EngagementStatus.FAILED}
    ),
    EngagementStatus.EVIDENCE_COLLECTION: frozenset(
        {EngagementStatus.ANALYSIS, EngagementStatus.SUSPENDED, EngagementStatus.REVOKED, EngagementStatus.FAILED}
    ),
    EngagementStatus.ANALYSIS: frozenset(
        {EngagementStatus.ADJUDICATION, EngagementStatus.SUSPENDED, EngagementStatus.REVOKED, EngagementStatus.FAILED}
    ),
    EngagementStatus.ADJUDICATION: frozenset(
        {EngagementStatus.REPORTING, EngagementStatus.SUSPENDED, EngagementStatus.REVOKED, EngagementStatus.FAILED}
    ),
    EngagementStatus.REPORTING: frozenset(
        {
            EngagementStatus.REMEDIATION,
            EngagementStatus.CLOSED,
            EngagementStatus.PARTIAL,
            EngagementStatus.SUSPENDED,
            EngagementStatus.REVOKED,
            EngagementStatus.FAILED,
        }
    ),
    EngagementStatus.REMEDIATION: frozenset(
        {
            EngagementStatus.CLOSED,
            EngagementStatus.PARTIAL,
            EngagementStatus.REVOKED,
            EngagementStatus.FAILED,
        }
    ),
    # SUSPENDED resumes to the state it left (caller supplies target state;
    # validated against _TRANSITIONS of the target's predecessor here).
    EngagementStatus.SUSPENDED: frozenset(
        {
            EngagementStatus.AUTHORIZED,
            EngagementStatus.ACTIVE,
            EngagementStatus.EVIDENCE_COLLECTION,
            EngagementStatus.ANALYSIS,
            EngagementStatus.ADJUDICATION,
            EngagementStatus.REPORTING,
            EngagementStatus.REMEDIATION,
        }
    ),
    # terminal states accept nothing
    EngagementStatus.REFUSED: frozenset(),
    EngagementStatus.REVOKED: frozenset(),
    EngagementStatus.FAILED: frozenset(),
    EngagementStatus.PARTIAL: frozenset(),
    EngagementStatus.CLOSED: frozenset(),
}

_SUSPENDABLE = frozenset(
    {
        EngagementStatus.AUTHORIZED,
        EngagementStatus.ACTIVE,
        EngagementStatus.EVIDENCE_COLLECTION,
        EngagementStatus.ANALYSIS,
        EngagementStatus.ADJUDICATION,
        EngagementStatus.REPORTING,
        EngagementStatus.REMEDIATION,
    }
)


class InvalidEngagementTransition(ValueError):
    """Raised when a transition is not permitted by the state machine."""


class PassType(str, Enum):
    """Pass types from contracts/engagement-protocol.md."""

    DIFF_GATE = "diff-gate"
    POSTURE = "posture"
    TRIAGE = "triage"
    BRIEFING = "briefing"
    DRIFT_REVIEW = "drift-review"


class AuthorityLevel(str, Enum):
    """Authority levels from the engagement protocol (established terms)."""

    INSPECTION_ONLY = "inspection-only"
    REMEDIATION = "remediation"


class AuditRecorder(Protocol):
    """Application-layer hook: every transition must produce an audit event."""

    def record_engagement_transition(
        self,
        *,
        event_id: AuditEventId,
        engagement_id: EngagementId,
        principal_id: PrincipalId,
        from_status: EngagementStatus,
        to_status: EngagementStatus,
        reason: str,
        occurred_at: str,
    ) -> None: ...


class EngagementTarget(DomainModel):
    """Engagement<->Target scoping join."""

    engagement_target_id: EngagementTargetId
    engagement_id: EngagementId
    target_id: TargetId
    in_scope: bool = True
    scope_note: str = ""


class Engagement(DomainModel):
    """The contract-governed unit of work."""

    engagement_id: EngagementId
    client_id: ClientId
    requester_principal_id: PrincipalId
    target_ids: list[TargetId] = Field(default_factory=list)
    scope: str
    pass_type: PassType
    authority_level: AuthorityLevel = AuthorityLevel.INSPECTION_ONLY
    constraints: list[str] = Field(default_factory=list)
    status: EngagementStatus = EngagementStatus.DRAFT
    status_history: list[dict[str, str]] = Field(default_factory=list)
    refusal_reason: str | None = None
    suspended_from: EngagementStatus | None = None

    def transition(
        self,
        to_status: EngagementStatus,
        *,
        reason: str,
        recorder: AuditRecorder,
        principal_id: PrincipalId,
        event_id: AuditEventId,
    ) -> None:
        """Apply a status transition with deterministic validation + audit.

        Only the application engagement service should call this; the LLM
        never transitions state directly.
        """
        if to_status not in _TRANSITIONS[self.status]:
            raise InvalidEngagementTransition(
                f"Engagement {self.engagement_id}: invalid transition {self.status.value} -> {to_status.value}"
            )
        if to_status == EngagementStatus.SUSPENDED and self.status not in _SUSPENDABLE:
            raise InvalidEngagementTransition(
                f"Engagement {self.engagement_id}: {self.status.value} is not suspendable"
            )
        if self.status == EngagementStatus.SUSPENDED:
            # resume: only back to a previously-left non-terminal state
            if self.suspended_from is None:
                raise InvalidEngagementTransition(
                    f"Engagement {self.engagement_id}: suspended without a recorded suspended-from state"
                )
            if to_status in TERMINAL_STATES or to_status == EngagementStatus.SUSPENDED:
                raise InvalidEngagementTransition(
                    f"Engagement {self.engagement_id}: cannot resume {self.status.value} -> {to_status.value}"
                )
            if to_status != self.suspended_from:
                raise InvalidEngagementTransition(
                    f"Engagement {self.engagement_id}: resume target {to_status.value} "
                    f"does not match suspended-from state {self.suspended_from.value}"
                )
            self.suspended_from = None

        from_status = self.status
        self.status = to_status
        if from_status != EngagementStatus.SUSPENDED and to_status == EngagementStatus.SUSPENDED:
            self.suspended_from = from_status
        self.updated_at = utc_now()
        self.status_history.append(
            {
                "from": from_status.value,
                "to": to_status.value,
                "reason": reason,
                "principal_id": principal_id,
                "at": self.updated_at.isoformat(),
            }
        )
        recorder.record_engagement_transition(
            event_id=event_id,
            engagement_id=self.engagement_id,
            principal_id=principal_id,
            from_status=from_status,
            to_status=to_status,
            reason=reason,
            occurred_at=self.updated_at.isoformat(),
        )
