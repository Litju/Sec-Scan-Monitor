"""Canonical hosted command boundary.

This module composes the existing domain services with PostgreSQL. It does
not execute scanners or make tenant decisions from client-supplied identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from secscan.platform.application.engagement_service import EngagementService
from secscan.platform.domain.audit import AuditEvent, AuditEventKind
from secscan.platform.domain.common import utc_now
from secscan.platform.domain.engagement import (
    AuthorityLevel,
    Engagement,
    EngagementStatus,
    PassType,
)
from secscan.platform.domain.ids import AuditEventId, ClientId, EngagementId, PrincipalId, TargetId
from secscan.platform.hosted.identity import VerifiedHumanIdentity
from secscan.platform.persistence import models
from secscan.platform.persistence.repositories import (
    PostgresAuditSink,
    PostgresEngagementRepository,
    engagement_to_row,
)
from secscan.platform.persistence.session import human_context


class HostedCommandError(RuntimeError):
    """A hosted command could not be completed without weakening a boundary."""


class HostedWorkflowUnavailable(HostedCommandError):
    """The durable workflow adapter is not configured or failed closed."""


@dataclass(frozen=True)
class HostedWorkflowRequest:
    engagement_id: str
    workflow_run_id: str
    client_id: str
    target_id: str
    principal_id: str
    target_snapshot_id: str
    target_snapshot_sha256: str
    target_source_identity: str


class HostedWorkflowStarter(Protocol):
    """Idempotent durable-workflow starter used by the command boundary."""

    def start(self, request: HostedWorkflowRequest) -> str: ...


class HostedWorkflowHttpStarter:
    """Start the existing workflow contract through a private server route."""

    def __init__(self, endpoint: str, shared_secret: str, *, timeout_seconds: float = 10.0) -> None:
        if not endpoint.strip() or not shared_secret.strip():
            raise ValueError("hosted workflow starter requires endpoint and server credential")
        self._endpoint = endpoint.rstrip("/")
        self._shared_secret = shared_secret
        self._timeout = timeout_seconds

    def start(self, request: HostedWorkflowRequest) -> str:
        payload = {
            "engagement_id": request.engagement_id,
            "workflow_run_id": request.workflow_run_id,
            "client_id": request.client_id,
            "target_id": request.target_id,
            "principal_id": request.principal_id,
            "target_snapshot_id": request.target_snapshot_id,
            "target_snapshot_sha256": request.target_snapshot_sha256,
            "target_source_identity": request.target_source_identity,
        }
        try:
            response = httpx.post(
                self._endpoint,
                json=payload,
                headers={"X-Secscan-Workflow-Secret": self._shared_secret},
                timeout=self._timeout,
            )
            if response.status_code not in {200, 202}:
                raise HostedWorkflowUnavailable("hosted workflow starter rejected the request")
            body = response.json()
            run_id = str(body.get("workflow_run_id", "")) if isinstance(body, dict) else ""
            if run_id != request.workflow_run_id:
                raise HostedWorkflowUnavailable("hosted workflow starter returned the wrong run identity")
            return run_id
        except httpx.HTTPError as exc:
            raise HostedWorkflowUnavailable("hosted workflow starter request failed") from exc
        except (ValueError, TypeError, KeyError) as exc:
            raise HostedWorkflowUnavailable("hosted workflow starter returned invalid JSON") from exc


@dataclass
class _BufferedAudit:
    events: list[AuditEvent] = field(default_factory=list)

    def append(self, event: AuditEvent) -> None:
        self.events.append(event)

    def read_since(self, since: datetime | None = None) -> list[AuditEvent]:
        return list(self.events)


class PostgresHostedCommandService:
    """Hosted case/inspection commands under transaction-scoped human RLS."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        workflow_starter: HostedWorkflowStarter | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._workflow_starter = workflow_starter

    def create_case(
        self,
        *,
        identity: VerifiedHumanIdentity,
        engagement_id: str,
        client_id: str,
        target_ids: list[str],
        scope: str,
        pass_type: str,
        constraints: list[str],
    ) -> Engagement:
        if not target_ids or len(set(target_ids)) != len(target_ids):
            raise ValueError("case requires unique target ids")
        try:
            resolved_pass_type = PassType(pass_type)
        except ValueError as exc:
            raise ValueError("unsupported pass type") from exc

        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            repository = PostgresEngagementRepository(session)
            existing = repository.get(EngagementId(engagement_id))
            if existing is not None:
                if (
                    str(existing.client_id) != client_id
                    or str(existing.requester_principal_id) != identity.human_principal_id
                    or [str(value) for value in existing.target_ids] != target_ids
                    or existing.scope != scope
                    or existing.pass_type != resolved_pass_type
                ):
                    raise ValueError("case id is already bound to different canonical state")
                return existing

            client = session.get(models.ClientRow, client_id)
            targets = list(
                session.scalars(
                    select(models.TargetRow).where(
                        models.TargetRow.target_id.in_(target_ids),
                        models.TargetRow.client_id == client_id,
                    )
                )
            )
            if client is None or len(targets) != len(target_ids):
                raise KeyError("case scope is not available")
            if session.get(models.PrincipalRow, identity.human_principal_id) is None:
                raise KeyError("human principal is not provisioned")

            buffered_audit = _BufferedAudit()
            engagement = EngagementService(buffered_audit).create(
                engagement_id=EngagementId(engagement_id),
                client_id=ClientId(client_id),
                requester_principal_id=PrincipalId(identity.human_principal_id),
                target_ids=[TargetId(value) for value in target_ids],
                scope=scope,
                pass_type=resolved_pass_type,
                authority_level=AuthorityLevel.INSPECTION_ONLY,
                constraints=constraints,
            )
            session.merge(engagement_to_row(engagement))
            for target_id in target_ids:
                session.add(
                    models.EngagementTargetRow(
                        engagement_target_id=f"ET-{engagement_id}-{target_id}",
                        engagement_id=engagement_id,
                        target_id=target_id,
                        in_scope=True,
                    )
                )
            session.flush()
            audit = PostgresAuditSink(session)
            for event in buffered_audit.events:
                audit.append(event)
            return engagement

    def authorize_case(self, *, identity: VerifiedHumanIdentity, engagement_id: str) -> Engagement:
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            repository = PostgresEngagementRepository(session)
            engagement = repository.get(EngagementId(engagement_id))
            if engagement is None:
                raise KeyError("case not found")
            if engagement.requester_principal_id != PrincipalId(identity.human_principal_id):
                raise PermissionError("case requester mismatch")
            service = EngagementService(PostgresAuditSink(session))
            if engagement.status in {
                EngagementStatus.DRAFT,
                EngagementStatus.INTAKE,
                EngagementStatus.SCOPE_VALIDATED,
            }:
                while engagement.status != EngagementStatus.AUTHORIZED:
                    next_status = {
                        EngagementStatus.DRAFT: EngagementStatus.INTAKE,
                        EngagementStatus.INTAKE: EngagementStatus.SCOPE_VALIDATED,
                        EngagementStatus.SCOPE_VALIDATED: EngagementStatus.AUTHORIZED,
                    }[engagement.status]
                    service.transition(
                        engagement,
                        next_status,
                        principal_id=PrincipalId(identity.human_principal_id),
                        reason="hosted case authorization",
                    )
            elif engagement.status != EngagementStatus.AUTHORIZED:
                raise ValueError(f"case cannot be authorized from {engagement.status.value}")
            grant_id = f"GRANT-{engagement_id}-INSPECTION"
            grant = session.get(models.AuthorityGrantRow, grant_id)
            if grant is None:
                now = utc_now()
                session.add(
                    models.AuthorityGrantRow(
                        grant_id=grant_id,
                        engagement_id=engagement_id,
                        principal_id=identity.human_principal_id,
                        action="inspect",
                        capability_id=None,
                        target_id=None,
                        conditions=[
                            "immutable_snapshot_only",
                            "no_client_writes",
                            "no_production_active_testing",
                        ],
                        not_before=now,
                        not_after=None,
                        revoked_at=None,
                        created_at=now,
                        updated_at=now,
                    )
                )
            elif (
                grant.engagement_id != engagement_id
                or grant.principal_id != identity.human_principal_id
                or grant.action != "inspect"
                or grant.capability_id is not None
                or grant.target_id is not None
                or grant.revoked_at is not None
            ):
                raise HostedCommandError("inspection grant binding mismatch")
            session.merge(engagement_to_row(engagement))
            return engagement

    def start_inspection(
        self,
        *,
        identity: VerifiedHumanIdentity,
        engagement_id: str,
        target_id: str,
        target_snapshot_id: str,
    ) -> models.WorkflowRunRow:
        if self._workflow_starter is None:
            raise HostedWorkflowUnavailable("durable workflow adapter is not configured")
        if not target_snapshot_id.strip():
            raise ValueError("immutable target snapshot id is required")

        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            repository = PostgresEngagementRepository(session)
            engagement = repository.get(EngagementId(engagement_id))
            if engagement is None:
                raise KeyError("case not found")
            if engagement.status != EngagementStatus.AUTHORIZED:
                raise ValueError("case must be authorized before inspection")
            if target_id not in {str(value) for value in engagement.target_ids}:
                raise KeyError("target is outside the case")
            target = session.get(models.TargetRow, target_id)
            if target is None or target.client_id != str(engagement.client_id):
                raise KeyError("target not found")
            if target.snapshot_id != target_snapshot_id or not target.snapshot_digest or not target.source_identity:
                raise ValueError("target is not bound to the requested immutable snapshot")

            workflow_run_id = f"WR-{engagement_id}"
            workflow = session.get(models.WorkflowRunRow, workflow_run_id)
            if workflow is None:
                workflow = models.WorkflowRunRow(
                    workflow_run_id=workflow_run_id,
                    engagement_id=engagement_id,
                    started_by_principal_id=identity.human_principal_id,
                    status="pending",
                    current_phase="queued",
                    started_at=None,
                    finished_at=None,
                    created_at=utc_now(),
                    updated_at=utc_now(),
                )
                session.add(workflow)
                session.flush()
            elif workflow.engagement_id != engagement_id:
                raise HostedCommandError("workflow run identity mismatch")
            elif workflow.status in {"running", "completed"}:
                return workflow

            request = HostedWorkflowRequest(
                engagement_id=engagement_id,
                workflow_run_id=workflow_run_id,
                client_id=str(engagement.client_id),
                target_id=target_id,
                principal_id=identity.human_principal_id,
                target_snapshot_id=target_snapshot_id,
                target_snapshot_sha256=target.snapshot_digest,
                target_source_identity=target.source_identity,
            )
            try:
                self._workflow_starter.start(request)
            except Exception as exc:
                workflow.status = "failed"
                workflow.current_phase = "workflow_start"
                workflow.updated_at = utc_now()
                session.commit()
                raise HostedWorkflowUnavailable("durable workflow start failed closed") from exc
            workflow.status = "running"
            workflow.current_phase = "queued"
            workflow.started_at = workflow.started_at or utc_now()
            workflow.updated_at = utc_now()
            PostgresAuditSink(session).append(
                AuditEvent(
                    audit_event_id=AuditEventId(f"AE-{workflow_run_id}-START"),
                    engagement_id=EngagementId(engagement_id),
                    principal_id=PrincipalId(identity.human_principal_id),
                    kind=AuditEventKind.SYSTEM,
                    summary=f"hosted inspection workflow {workflow_run_id} started",
                    details={"workflow_run_id": workflow_run_id, "target_id": target_id},
                )
            )
            return workflow
