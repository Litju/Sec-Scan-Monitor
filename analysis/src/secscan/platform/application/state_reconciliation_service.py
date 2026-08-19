"""Reconcile PostgreSQL workflow state without rewriting historical evidence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from secscan.platform.domain.audit import AuditEvent, AuditEventKind
from secscan.platform.domain.ids import AuditEventId, EngagementId, PrincipalId
from secscan.platform.persistence import models
from secscan.platform.persistence.repositories import PostgresAuditSink, PostgresEngagementRepository

TemporalProbe = Callable[[str], str]

_TERMINAL_ENGAGEMENTS = {"closed", "refused", "revoked", "failed", "partial"}
_TERMINAL_WORKFLOWS = {"completed", "failed", "cancelled"}
_KNOWN_TEMPORAL_STATES = {"running", "completed", "failed", "cancelled", "not_found", "unavailable"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class WorkflowReconciliationResult:
    workflow_run_id: str
    engagement_id: str
    decision: str
    engagement_status: str
    workflow_status_before: str
    workflow_status_after: str
    temporal_status: str


class WorkflowReconciliationService:
    """Reconcile impossible PostgreSQL/Temporal combinations idempotently.

    The optional probe is the only Temporal integration point. When no real
    Temporal client is available, the service records ``unavailable`` and
    applies only the safe terminal-state rule.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def reconcile(
        self,
        workflow_run_id: str,
        *,
        principal_id: str,
        temporal_probe: TemporalProbe | None = None,
    ) -> WorkflowReconciliationResult:
        workflow = self._session.get(models.WorkflowRunRow, workflow_run_id)
        if workflow is None:
            raise ValueError(f"workflow run {workflow_run_id} is missing")
        engagement = PostgresEngagementRepository(self._session).get(workflow.engagement_id)
        if engagement is None:
            raise ValueError(f"engagement {workflow.engagement_id} is missing")

        temporal_status = "unavailable"
        if temporal_probe is not None:
            try:
                candidate = temporal_probe(workflow_run_id).strip().lower()
            except Exception:
                candidate = "unavailable"
            temporal_status = candidate if candidate in _KNOWN_TEMPORAL_STATES else "unavailable"

        before = workflow.status
        engagement_status = engagement.status.value
        if before in _TERMINAL_WORKFLOWS:
            decision = "ALREADY_TERMINAL"
        elif engagement_status in _TERMINAL_ENGAGEMENTS and temporal_status not in {"running"}:
            workflow.status = "failed" if engagement_status in {"failed", "partial"} else "cancelled"
            workflow.current_phase = "reconciled"
            workflow.finished_at = workflow.finished_at or _now()
            workflow.updated_at = _now()
            decision = "RECONCILED"
        elif engagement_status in _TERMINAL_ENGAGEMENTS and temporal_status == "running":
            decision = "REVIEW_REQUIRED"
        else:
            decision = "NO_ACTION"

        self._audit(
            workflow_run_id=workflow_run_id,
            engagement_id=workflow.engagement_id,
            principal_id=principal_id,
            decision=decision,
            details={
                "workflow_status_before": before,
                "workflow_status_after": workflow.status,
                "engagement_status": engagement_status,
                "temporal_status": temporal_status,
            },
        )
        self._session.commit()
        return WorkflowReconciliationResult(
            workflow_run_id=workflow_run_id,
            engagement_id=workflow.engagement_id,
            decision=decision,
            engagement_status=engagement_status,
            workflow_status_before=before,
            workflow_status_after=workflow.status,
            temporal_status=temporal_status,
        )

    def _audit(
        self,
        *,
        workflow_run_id: str,
        engagement_id: str,
        principal_id: str,
        decision: str,
        details: dict[str, str],
    ) -> None:
        summary = f"workflow reconciliation {workflow_run_id}: {decision}"
        event_id = AuditEventId(
            f"AE-RECON-{hashlib.sha256(summary.encode('utf-8')).hexdigest()[:24]}"
        )
        if self._session.get(models.AuditEventRow, str(event_id)) is not None:
            return
        previous = self._session.scalars(
            select(models.AuditEventRow)
            .where(models.AuditEventRow.engagement_id == engagement_id)
            .order_by(models.AuditEventRow.occurred_at.desc())
            .limit(1)
        ).first()
        PostgresAuditSink(self._session).append(
            AuditEvent(
                audit_event_id=event_id,
                engagement_id=EngagementId(engagement_id),
                principal_id=PrincipalId(principal_id),
                kind=AuditEventKind.SYSTEM,
                summary=summary,
                details=details,
                previous_event_id=AuditEventId(previous.audit_event_id) if previous else None,
            )
        )
