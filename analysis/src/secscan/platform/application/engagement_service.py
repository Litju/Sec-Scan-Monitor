"""Engagement application service.

The ONLY component that transitions engagement state. LLMs never call this
directly; agents and workflows go through its use cases. Every transition
is validated by the domain state machine and recorded in the audit ledger.
"""

from __future__ import annotations

from secscan.platform.domain.audit import AuditEvent, AuditEventKind
from secscan.platform.domain.engagement import (
    AuthorityLevel,
    Engagement,
    EngagementStatus,
    PassType,
)
from secscan.platform.domain.ids import (
    AuditEventId,
    ClientId,
    EngagementId,
    PrincipalId,
    TargetId,
    new_id,
)
from secscan.platform.domain.ports import AuditSink


class EngagementAlreadyExistsError(ValueError):
    pass


class EngagementNotFoundError(KeyError):
    pass


class EngagementService:
    """Use cases for engagement lifecycle. Persistence behind a port."""

    def __init__(self, audit: AuditSink) -> None:
        self._audit = audit

    def create(
        self,
        *,
        engagement_id: EngagementId,
        client_id: ClientId,
        requester_principal_id: PrincipalId,
        target_ids: list[TargetId],
        scope: str,
        pass_type: PassType,
        authority_level: AuthorityLevel = AuthorityLevel.INSPECTION_ONLY,
        constraints: list[str] | None = None,
    ) -> Engagement:
        engagement = Engagement(
            engagement_id=engagement_id,
            client_id=client_id,
            requester_principal_id=requester_principal_id,
            target_ids=target_ids,
            scope=scope,
            pass_type=pass_type,
            authority_level=authority_level,
            constraints=constraints or [],
        )
        self._audit.append(
            AuditEvent(
                audit_event_id=AuditEventId(new_id("AE")),
                engagement_id=engagement_id,
                principal_id=requester_principal_id,
                kind=AuditEventKind.ENGAGEMENT_STATE_CHANGE,
                summary=f"engagement {engagement_id} created (draft)",
                details={"to": EngagementStatus.DRAFT.value},
            )
        )
        return engagement

    def transition(
        self,
        engagement: Engagement,
        to_status: EngagementStatus,
        *,
        principal_id: PrincipalId,
        reason: str,
    ) -> Engagement:
        event_id = AuditEventId(new_id("AE"))
        engagement.transition(
            to_status,
            reason=reason,
            recorder=_TransitionRecorder(self._audit),
            principal_id=principal_id,
            event_id=event_id,
        )
        return engagement

    def refuse(
        self,
        engagement: Engagement,
        *,
        principal_id: PrincipalId,
        reason: str,
    ) -> Engagement:
        engagement.refusal_reason = reason
        self.transition(engagement, EngagementStatus.REFUSED, principal_id=principal_id, reason=reason)
        self._audit.append(
            AuditEvent(
                audit_event_id=AuditEventId(new_id("AE")),
                engagement_id=engagement.engagement_id,
                principal_id=principal_id,
                kind=AuditEventKind.REFUSAL,
                summary=f"engagement {engagement.engagement_id} refused: {reason}",
            )
        )
        return engagement

    def suspend(self, engagement: Engagement, *, principal_id: PrincipalId, reason: str) -> Engagement:
        return self.transition(engagement, EngagementStatus.SUSPENDED, principal_id=principal_id, reason=reason)

    def resume(self, engagement: Engagement, *, principal_id: PrincipalId, reason: str) -> Engagement:
        if engagement.suspended_from is None:
            raise ValueError(f"engagement {engagement.engagement_id} is not suspended")
        return self.transition(engagement, engagement.suspended_from, principal_id=principal_id, reason=reason)


class _TransitionRecorder:
    """Adapts the domain AuditRecorder protocol to the audit sink."""

    def __init__(self, audit: AuditSink) -> None:
        self._audit = audit

    def record_engagement_transition(self, **kwargs: object) -> None:
        def _status_text(value: object) -> str:
            return value.value if hasattr(value, "value") else str(value)

        self._audit.append(
            AuditEvent(
                audit_event_id=kwargs["event_id"],  # type: ignore[arg-type]
                engagement_id=kwargs["engagement_id"],  # type: ignore[arg-type]
                principal_id=kwargs["principal_id"],  # type: ignore[arg-type]
                kind=AuditEventKind.ENGAGEMENT_STATE_CHANGE,
                summary=(
                    f"engagement {str(kwargs['engagement_id'])}: "
                    f"{_status_text(kwargs['from_status'])} -> {_status_text(kwargs['to_status'])} "
                    f"({str(kwargs['reason'])})"
                ),
                details={
                    "from": _status_text(kwargs["from_status"]),
                    "to": _status_text(kwargs["to_status"]),
                    "reason": str(kwargs["reason"]),
                },
            )
        )
