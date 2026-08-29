"""Repository implementations backing domain ports with PostgreSQL.

- `PostgresAuditSink` implements the AuditSink port (append-oriented).
- `PostgresEngagementRepository` persists engagement aggregates.
All writes are idempotency-guarded by primary keys / unique constraints.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping, TypeVar

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

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
)
from secscan.platform.domain.planning import AssessmentPlan
from secscan.platform.domain.profiles import TargetSecurityProfile
from secscan.platform.domain.qualification import QualificationReceipt
from secscan.platform.domain.services import SecurityServiceContract, ServiceRun
from secscan.platform.hosted.identity import ClientMembership, HumanRole, VerifiedHumanIdentity
from secscan.platform.persistence import models
from secscan.platform.persistence.session import human_context
from secscan.platform.read_models import (
    AuditEventReadModel,
    ClientReadModel,
    CursorPage,
    DetectionSignalReadModel,
    EngagementReadModel,
    EvidenceMetadataReadModel,
    FindingReadModel,
    FirmSummaryReadModel,
    HuntReadModel,
    IncidentReadModel,
    ReadModelError,
    ResponseProposalReadModel,
    TargetReadModel,
    _decode_cursor,
    _encode_cursor,
    compose_experience_snapshot,
)

T = TypeVar("T")


def engagement_to_row(engagement: Engagement) -> models.EngagementRow:
    return models.EngagementRow(
        engagement_id=engagement.engagement_id,
        client_id=engagement.client_id,
        requester_principal_id=engagement.requester_principal_id,
        scope=engagement.scope,
        pass_type=engagement.pass_type.value,
        authority_level=engagement.authority_level.value,
        constraints=engagement.constraints,
        status=engagement.status.value,
        status_history=engagement.status_history,
        refusal_reason=engagement.refusal_reason,
        suspended_from=engagement.suspended_from.value if engagement.suspended_from else None,
        created_at=engagement.created_at,
        updated_at=engagement.updated_at,
    )


def row_to_engagement(row: models.EngagementRow) -> Engagement:
    return Engagement(
        engagement_id=EngagementId(row.engagement_id),
        client_id=ClientId(row.client_id),
        requester_principal_id=PrincipalId(row.requester_principal_id),
        target_ids=[],
        scope=row.scope,
        pass_type=PassType(row.pass_type),
        authority_level=AuthorityLevel(row.authority_level),
        constraints=row.constraints or [],
        status=EngagementStatus(row.status),
        status_history=row.status_history or [],
        refusal_reason=row.refusal_reason,
        suspended_from=EngagementStatus(row.suspended_from) if row.suspended_from else None,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class PostgresEngagementRepository:
    """Engagement persistence. Not the service: no transitions here."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, engagement: Engagement) -> None:
        row = engagement_to_row(engagement)
        self._session.merge(row)
        # The repository boundary is where a save becomes durable; the API
        # composition (and the workflow activities) rely on this commit.
        self._session.commit()

    def save_target_link(self, engagement: Engagement, target_id: TargetId, in_scope: bool = True) -> None:
        link = models.EngagementTargetRow(
            engagement_target_id=f"ET-{engagement.engagement_id}-{target_id}",
            engagement_id=engagement.engagement_id,
            target_id=target_id,
            in_scope=in_scope,
        )
        self._session.merge(link)

    def get(self, engagement_id: EngagementId | str) -> Engagement | None:
        row = self._session.get(models.EngagementRow, str(engagement_id))
        if row is None:
            return None
        target_ids = [
            TargetId(link.target_id)
            for link in self._session.scalars(
                select(models.EngagementTargetRow).where(
                    models.EngagementTargetRow.engagement_id == str(engagement_id),
                    models.EngagementTargetRow.in_scope.is_(True),
                )
            )
        ]
        engagement = row_to_engagement(row)
        engagement.target_ids = target_ids
        return engagement


class PostgresHumanMembershipStore:
    """Tenant membership lookup with transaction-scoped human RLS context."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def memberships_for(self, human_principal_id: str, client_id: str) -> tuple[ClientMembership, ...]:
        with self._session_factory() as session, human_context(session, human_principal_id):
            rows = session.scalars(
                select(models.ClientMembershipRow).where(
                    models.ClientMembershipRow.human_principal_id == human_principal_id,
                    models.ClientMembershipRow.client_id == client_id,
                    models.ClientMembershipRow.status == "active",
                )
            )
            return tuple(
                ClientMembership(
                    human_principal_id=row.human_principal_id,
                    client_id=row.client_id,
                    role=HumanRole(row.role),
                    active=row.status == "active",
                )
                for row in rows
            )

    def is_platform_admin(self, human_principal_id: str) -> bool:
        with self._session_factory() as session, human_context(session, human_principal_id):
            return bool(
                session.scalar(
                    select(models.ClientMembershipRow.membership_id).where(
                        models.ClientMembershipRow.human_principal_id == human_principal_id,
                        models.ClientMembershipRow.role == HumanRole.PLATFORM_ADMIN.value,
                        models.ClientMembershipRow.status == "active",
                    ).limit(1)
                )
            )


class PostgresHumanTokenRevocationStore:
    """Persist only token digests so product logout survives function reuse."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def is_revoked(self, token: str) -> bool:
        with self._session_factory() as session:
            return session.get(models.HumanTokenRevocationRow, self._digest(token)) is not None

    def revoke(self, token: str, human_principal_id: str) -> None:
        digest = self._digest(token)
        with self._session_factory() as session:
            if session.get(models.HumanTokenRevocationRow, digest) is None:
                now = datetime.now(timezone.utc)
                session.add(
                    models.HumanTokenRevocationRow(
                        token_sha256=digest,
                        human_principal_id=human_principal_id,
                        revoked_at=now,
                        created_at=now,
                    )
                )
                session.commit()


class PostgresReadModelService:
    """Read-only typed DTO adapter; every query runs inside human RLS context."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    @staticmethod
    def _client_scope(session: Session, identity: VerifiedHumanIdentity) -> Any:
        """Return the application tenant scope even if the DB role is misconfigured."""
        is_admin = session.scalar(
            select(models.ClientMembershipRow.membership_id)
            .where(
                models.ClientMembershipRow.human_principal_id == identity.human_principal_id,
                models.ClientMembershipRow.role == HumanRole.PLATFORM_ADMIN.value,
                models.ClientMembershipRow.status == "active",
            )
            .limit(1)
        )
        if is_admin is not None:
            return None
        return select(models.ClientMembershipRow.client_id).where(
            models.ClientMembershipRow.human_principal_id == identity.human_principal_id,
            models.ClientMembershipRow.status == "active",
        )

    def firm_summary(self, *, identity: VerifiedHumanIdentity) -> FirmSummaryReadModel:
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            clients = select(func.count()).select_from(models.ClientRow)
            targets = select(func.count()).select_from(models.TargetRow)
            engagements = select(func.count()).select_from(models.EngagementRow)
            findings = select(func.count()).select_from(models.FindingRow).join(
                models.EngagementRow,
                models.EngagementRow.engagement_id == models.FindingRow.engagement_id,
            )
            evidence_items = select(func.count()).select_from(models.EvidenceMetadataRow).join(
                models.EngagementRow,
                models.EngagementRow.engagement_id == models.EvidenceMetadataRow.engagement_id,
            )
            audit_events = select(func.count()).select_from(models.AuditEventRow).outerjoin(
                models.EngagementRow,
                models.EngagementRow.engagement_id == models.AuditEventRow.engagement_id,
            )
            if scope is not None:
                clients = clients.where(models.ClientRow.client_id.in_(scope))
                targets = targets.where(models.TargetRow.client_id.in_(scope))
                engagements = engagements.where(models.EngagementRow.client_id.in_(scope))
                findings = findings.where(models.EngagementRow.client_id.in_(scope))
                evidence_items = evidence_items.where(models.EngagementRow.client_id.in_(scope))
                audit_events = audit_events.where(models.EngagementRow.client_id.in_(scope))
            counts = {
                "clients": session.scalar(clients) or 0,
                "targets": session.scalar(targets) or 0,
                "engagements": session.scalar(engagements) or 0,
                "findings": session.scalar(findings) or 0,
                "evidence_items": session.scalar(evidence_items) or 0,
                "audit_events": session.scalar(audit_events) or 0,
            }
        return FirmSummaryReadModel(**counts, data_mode="HOSTED_INTEGRATED")

    def experience(self, *, identity: VerifiedHumanIdentity) -> dict[str, Any]:
        """Return one bounded, scope-filtered snapshot for the operator console."""
        clients_page = self.list_clients(identity=identity, limit=100)
        targets_page = self.list_targets(identity=identity, limit=100)
        cases_page = self.list_engagements(identity=identity, limit=100)
        findings_page = self.list_findings(identity=identity, limit=100)
        evidence_page = self.list_evidence(identity=identity, limit=100)
        audit_page = self.list_audit(identity=identity, limit=100)
        signals_page = self.list_detection_signals(identity=identity, limit=100)
        hunts_page = self.list_hunts(identity=identity, limit=100)
        incidents_page = self.list_incidents(identity=identity, limit=100)
        proposals_page = self.list_response_proposals(identity=identity, limit=100)
        return compose_experience_snapshot(
            mode="HOSTED_INTEGRATED",
            source_label="HOSTED / AUTHENTICATED / CANONICAL_POSTGRESQL",
            cases=cases_page.items,
            findings=findings_page.items,
            evidence_count_by_case={
                case.engagement_id: sum(1 for item in evidence_page.items if item.engagement_id == case.engagement_id)
                for case in cases_page.items
            },
            activity_count_by_case={
                case.engagement_id: sum(1 for item in audit_page.items if item.engagement_id == case.engagement_id)
                for case in cases_page.items
            },
            audit=audit_page.items,
            clients={item.client_id: item.name for item in clients_page.items},
            targets={item.target_id: item.name for item in targets_page.items},
            detection_signals=signals_page.items,
            hunts=hunts_page.items,
            incidents=incidents_page.items,
            response_proposals=proposals_page.items,
        )

    def list_clients(
        self, *, identity: VerifiedHumanIdentity, cursor: str | None = None, limit: int = 50
    ) -> CursorPage[ClientReadModel]:
        offset, fetch = _read_window(cursor, limit)
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            stmt = select(models.ClientRow)
            if scope is not None:
                stmt = stmt.where(models.ClientRow.client_id.in_(scope))
            rows = list(
                session.scalars(
                    stmt
                    .order_by(models.ClientRow.client_id)
                    .offset(offset)
                    .limit(fetch)
                )
            )
        items = [ClientReadModel(client_id=row.client_id, name=row.name, contact=row.contact) for row in rows]
        return _read_page(items, offset=offset, limit=limit)

    def list_targets(
        self,
        *,
        identity: VerifiedHumanIdentity,
        client_id: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[TargetReadModel]:
        offset, fetch = _read_window(cursor, limit)
        stmt = select(models.TargetRow).where(models.TargetRow.client_id.is_not(None))
        if client_id is not None:
            stmt = stmt.where(models.TargetRow.client_id == client_id)
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            if scope is not None:
                stmt = stmt.where(models.TargetRow.client_id.in_(scope))
            rows = list(session.scalars(stmt.order_by(models.TargetRow.target_id).offset(offset).limit(fetch)))
        items = [
            TargetReadModel(
                target_id=row.target_id,
                client_id=row.client_id,
                kind=row.kind,
                name=row.name,
                snapshot_id=row.snapshot_id,
                snapshot_digest=row.snapshot_digest,
            )
            for row in rows
        ]
        return _read_page(items, offset=offset, limit=limit)

    def list_engagements(
        self,
        *,
        identity: VerifiedHumanIdentity,
        client_id: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[EngagementReadModel]:
        offset, fetch = _read_window(cursor, limit)
        stmt = select(models.EngagementRow)
        if client_id is not None:
            stmt = stmt.where(models.EngagementRow.client_id == client_id)
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            rows = list(session.scalars(stmt.order_by(models.EngagementRow.engagement_id).offset(offset).limit(fetch)))
            links = self._target_links(session, [row.engagement_id for row in rows])
        items = [_engagement_read_model(row, links.get(row.engagement_id, [])) for row in rows]
        return _read_page(items, offset=offset, limit=limit)

    def get_engagement(
        self, *, identity: VerifiedHumanIdentity, engagement_id: str
    ) -> EngagementReadModel | None:
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            stmt = select(models.EngagementRow).where(models.EngagementRow.engagement_id == engagement_id)
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            row = session.scalar(stmt)
            if row is None:
                return None
            links = self._target_links(session, [row.engagement_id])
        return _engagement_read_model(row, links.get(row.engagement_id, []))

    def list_findings(
        self,
        *,
        identity: VerifiedHumanIdentity,
        engagement_id: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[FindingReadModel]:
        offset, fetch = _read_window(cursor, limit)
        stmt = (
            select(models.FindingRow, models.EngagementRow.client_id)
            .join(models.EngagementRow, models.EngagementRow.engagement_id == models.FindingRow.engagement_id)
        )
        if engagement_id is not None:
            stmt = stmt.where(models.FindingRow.engagement_id == engagement_id)
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            rows = list(
                session.execute(stmt.order_by(models.FindingRow.finding_id).offset(offset).limit(fetch))
            )
            items = [
                self._finding_read_model(finding, client_id, session)
                for finding, client_id in rows
            ]
        return _read_page(items, offset=offset, limit=limit)

    def list_evidence(
        self,
        *,
        identity: VerifiedHumanIdentity,
        engagement_id: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage[EvidenceMetadataReadModel]:
        offset, fetch = _read_window(cursor, limit)
        stmt = (
            select(models.EvidenceMetadataRow, models.EngagementRow.client_id)
            .join(models.EngagementRow, models.EngagementRow.engagement_id == models.EvidenceMetadataRow.engagement_id)
        )
        if engagement_id is not None:
            stmt = stmt.where(models.EvidenceMetadataRow.engagement_id == engagement_id)
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            rows = list(
                session.execute(
                    stmt.order_by(models.EvidenceMetadataRow.evidence_id).offset(offset).limit(fetch)
                )
            )
        items = [
            EvidenceMetadataReadModel(
                evidence_id=evidence.evidence_id,
                engagement_id=evidence.engagement_id,
                client_id=client_id,
                sha256=evidence.sha256,
                sanitization_state=evidence.sanitization_state,
            )
            for evidence, client_id in rows
        ]
        return _read_page(items, offset=offset, limit=limit)

    def list_audit(
        self, *, identity: VerifiedHumanIdentity, cursor: str | None = None, limit: int = 50
    ) -> CursorPage[AuditEventReadModel]:
        offset, fetch = _read_window(cursor, limit)
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            stmt = select(models.AuditEventRow).outerjoin(
                models.EngagementRow,
                models.EngagementRow.engagement_id == models.AuditEventRow.engagement_id,
            )
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            rows = list(
                session.scalars(
                    stmt
                    .order_by(models.AuditEventRow.occurred_at, models.AuditEventRow.audit_event_id)
                    .offset(offset)
                    .limit(fetch)
                )
            )
        items = [
            AuditEventReadModel(
                audit_event_id=row.audit_event_id,
                engagement_id=row.engagement_id,
                principal_id=row.principal_id,
                kind=row.kind,
                summary=row.summary,
                occurred_at=row.occurred_at.isoformat(),
            )
            for row in rows
        ]
        return _read_page(items, offset=offset, limit=limit)

    def list_detection_signals(
        self, *, identity: VerifiedHumanIdentity, cursor: str | None = None, limit: int = 50
    ) -> CursorPage[DetectionSignalReadModel]:
        offset, fetch = _read_window(cursor, limit)
        stmt = (
            select(models.DetectionSignalRow)
            .join(models.EngagementRow, models.EngagementRow.engagement_id == models.DetectionSignalRow.case_id)
        )
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            rows = list(session.scalars(stmt.order_by(models.DetectionSignalRow.signal_id).offset(offset).limit(fetch)))
        items = [
            DetectionSignalReadModel(
                signal_id=row.signal_id,
                tenant_id=row.tenant_id,
                case_id=row.case_id,
                rule_id=row.rule_id,
                rule_version=row.rule_version,
                severity=row.severity,
                confidence=row.confidence,
                status=row.status,
                event_ids=list(row.event_ids or []),
                evidence_refs=list(row.raw_evidence_refs or []),
                source="canonical detection engine",
            )
            for row in rows
        ]
        return _read_page(items, offset=offset, limit=limit)

    def list_hunts(
        self, *, identity: VerifiedHumanIdentity, cursor: str | None = None, limit: int = 50
    ) -> CursorPage[HuntReadModel]:
        offset, fetch = _read_window(cursor, limit)
        stmt = (
            select(models.HuntExecutionRow)
            .join(models.EngagementRow, models.EngagementRow.engagement_id == models.HuntExecutionRow.case_id)
        )
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            rows = list(session.scalars(stmt.order_by(models.HuntExecutionRow.execution_id).offset(offset).limit(fetch)))
        values: list[HuntReadModel] = []
        for row in rows:
            result = row.result or {}
            disposition = str(result.get("disposition", "INCONCLUSIVE"))
            status = "VERIFIED" if disposition == "SUPPORTS" else "CONTRADICTED" if disposition == "REFUTES" else "INCONCLUSIVE"
            evidence_refs = (
                result.get("supporting_evidence_refs", [])
                if disposition == "SUPPORTS"
                else result.get("refuting_evidence_refs", [])
                if disposition == "REFUTES"
                else [
                    *result.get("supporting_evidence_refs", []),
                    *result.get("refuting_evidence_refs", []),
                ]
            )
            values.append(
                HuntReadModel(
                    hunt_id=row.execution_id,
                    hypothesis_id=row.hypothesis_id,
                    tenant_id=row.tenant_id,
                    case_id=row.case_id,
                    disposition=disposition,
                    status=status,
                    evidence_refs=[str(item) for item in evidence_refs],
                    source="canonical threat-hunt engine",
                )
            )
        return _read_page(values, offset=offset, limit=limit)

    def list_incidents(
        self, *, identity: VerifiedHumanIdentity, cursor: str | None = None, limit: int = 50
    ) -> CursorPage[IncidentReadModel]:
        offset, fetch = _read_window(cursor, limit)
        stmt = (
            select(models.IncidentRow)
            .join(models.EngagementRow, models.EngagementRow.engagement_id == models.IncidentRow.case_id)
        )
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            rows = list(session.scalars(stmt.order_by(models.IncidentRow.incident_id).offset(offset).limit(fetch)))
        items = [
            IncidentReadModel(
                incident_id=row.incident_id,
                tenant_id=row.tenant_id,
                case_id=row.case_id,
                status=row.state,
                severity=row.severity,
                confidence=row.confidence,
                signal_ids=list(row.source_signal_ids or []),
                evidence_refs=list(row.supporting_evidence_refs or []),
                provenance_source="canonical incident adjudication",
                provenance_source_type="postgresql",
                adjudicated_at=row.adjudicated_at.isoformat(),
            )
            for row in rows
        ]
        return _read_page(items, offset=offset, limit=limit)

    def list_response_proposals(
        self, *, identity: VerifiedHumanIdentity, cursor: str | None = None, limit: int = 50
    ) -> CursorPage[ResponseProposalReadModel]:
        offset, fetch = _read_window(cursor, limit)
        stmt = (
            select(models.ResponseProposalRow)
            .join(models.EngagementRow, models.EngagementRow.engagement_id == models.ResponseProposalRow.case_id)
        )
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            rows = list(session.scalars(stmt.order_by(models.ResponseProposalRow.proposal_id).offset(offset).limit(fetch)))
        items = [
            ResponseProposalReadModel(
                proposal_id=row.proposal_id,
                incident_id=row.incident_id,
                tenant_id=row.tenant_id,
                case_id=row.case_id,
                target_id=row.target_id,
                action=row.action,
                opa_decision=row.opa_decision,
                human_approval_state=row.human_approval_state,
                status=row.human_approval_state,
                evidence_refs=list(row.supporting_evidence_refs or []),
                source="canonical response proposal service",
            )
            for row in rows
        ]
        return _read_page(items, offset=offset, limit=limit)

    def get_finding(self, *, identity: VerifiedHumanIdentity, finding_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            stmt = (
                select(models.FindingRow)
                .join(models.EngagementRow, models.EngagementRow.engagement_id == models.FindingRow.engagement_id)
                .where(models.FindingRow.finding_id == finding_id)
            )
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            row = session.scalar(stmt)
            if row is None:
                return None
            adjudication = session.scalar(
                select(models.AdjudicationRow).where(
                    models.AdjudicationRow.adjudication_id == row.originating_adjudication_id,
                    models.AdjudicationRow.engagement_id == row.engagement_id,
                )
            )
            return {
                "finding_id": row.finding_id,
                "engagement_id": row.engagement_id,
                "title": row.title,
                "severity": row.severity,
                "summary": row.summary,
                "impact": row.impact,
                "remediation_guidance": row.remediation_guidance,
                "verification_step": row.verification_step,
                "supporting_evidence_ids": list(row.supporting_evidence_ids or []),
                "contradicting_evidence_ids": list(row.contradicting_evidence_ids or []),
                "confidence": row.confidence,
                "status": row.status,
                "adjudication": adjudication.verdict if adjudication is not None else None,
                "originating_adjudication_id": row.originating_adjudication_id,
            }

    @staticmethod
    def _finding_read_model(
        finding: models.FindingRow,
        client_id: str,
        session: Session,
    ) -> FindingReadModel:
        adjudication = session.scalar(
            select(models.AdjudicationRow).where(
                models.AdjudicationRow.adjudication_id == finding.originating_adjudication_id,
                models.AdjudicationRow.engagement_id == finding.engagement_id,
            )
        )
        return FindingReadModel(
            finding_id=finding.finding_id,
            engagement_id=finding.engagement_id,
            client_id=client_id,
            severity=finding.severity,
            confidence=finding.confidence,
            title=finding.title,
            summary=finding.summary,
            impact=finding.impact,
            status=finding.status,
            adjudication=adjudication.verdict if adjudication is not None else None,
            supporting_evidence_ids=list(finding.supporting_evidence_ids or []),
            contradicting_evidence_ids=list(finding.contradicting_evidence_ids or []),
            verification_step=finding.verification_step,
            remediation_guidance=finding.remediation_guidance,
        )

    def list_workflow_runs(
        self, *, identity: VerifiedHumanIdentity, engagement_id: str
    ) -> list[dict[str, Any]]:
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            workflow_stmt = (
                select(models.WorkflowRunRow)
                .join(models.EngagementRow, models.EngagementRow.engagement_id == models.WorkflowRunRow.engagement_id)
                .where(models.WorkflowRunRow.engagement_id == engagement_id)
            )
            invocation_stmt = (
                select(models.ToolInvocationRow)
                .join(models.EngagementRow, models.EngagementRow.engagement_id == models.ToolInvocationRow.engagement_id)
                .where(models.ToolInvocationRow.engagement_id == engagement_id)
            )
            if scope is not None:
                workflow_stmt = workflow_stmt.where(models.EngagementRow.client_id.in_(scope))
                invocation_stmt = invocation_stmt.where(models.EngagementRow.client_id.in_(scope))
            rows = list(
                session.scalars(
                    workflow_stmt
                    .order_by(models.WorkflowRunRow.created_at, models.WorkflowRunRow.workflow_run_id)
                )
            )
            invocations = list(
                session.scalars(
                    invocation_stmt
                    .order_by(models.ToolInvocationRow.requested_at, models.ToolInvocationRow.tool_invocation_id)
                )
            )
        by_workflow: dict[str, list[dict[str, Any]]] = {}
        for invocation in invocations:
            by_workflow.setdefault(invocation.workflow_run_id, []).append(
                {
                    "tool_invocation_id": invocation.tool_invocation_id,
                    "capability_id": invocation.capability_id,
                    "policy_decision": invocation.policy_decision,
                    "status": invocation.status,
                    "sandbox_id": invocation.sandbox_id,
                    "result_evidence_ids": list(invocation.result_evidence_ids or []),
                    "error": invocation.error,
                }
            )
        return [self._workflow_view(row, by_workflow.get(row.workflow_run_id, [])) for row in rows]

    def get_workflow_run(
        self, *, identity: VerifiedHumanIdentity, workflow_run_id: str
    ) -> dict[str, Any] | None:
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            stmt = (
                select(models.WorkflowRunRow)
                .join(models.EngagementRow, models.EngagementRow.engagement_id == models.WorkflowRunRow.engagement_id)
                .where(models.WorkflowRunRow.workflow_run_id == workflow_run_id)
            )
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            row = session.scalar(stmt)
            if row is None:
                return None
            invocation_stmt = (
                select(models.ToolInvocationRow)
                .join(models.EngagementRow, models.EngagementRow.engagement_id == models.ToolInvocationRow.engagement_id)
                .where(models.ToolInvocationRow.workflow_run_id == workflow_run_id)
            )
            if scope is not None:
                invocation_stmt = invocation_stmt.where(models.EngagementRow.client_id.in_(scope))
            invocations = list(
                session.scalars(
                    invocation_stmt
                    .order_by(models.ToolInvocationRow.requested_at, models.ToolInvocationRow.tool_invocation_id)
                )
            )
        activities = [
            {
                "tool_invocation_id": item.tool_invocation_id,
                "capability_id": item.capability_id,
                "policy_decision": item.policy_decision,
                "status": item.status,
                "sandbox_id": item.sandbox_id,
                "result_evidence_ids": list(item.result_evidence_ids or []),
                "error": item.error,
            }
            for item in invocations
        ]
        return self._workflow_view(row, activities)

    def get_report(
        self, *, identity: VerifiedHumanIdentity, engagement_id: str
    ) -> dict[str, Any] | None:
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            stmt = (
                select(models.ReportRow)
                .join(models.EngagementRow, models.EngagementRow.engagement_id == models.ReportRow.engagement_id)
                .where(models.ReportRow.engagement_id == engagement_id)
                .order_by(models.ReportRow.generated_at.desc(), models.ReportRow.report_id)
            )
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            row = session.scalar(stmt)
            if row is None:
                return None
            return self._report_view(row)

    def get_report_by_id(
        self, *, identity: VerifiedHumanIdentity, report_id: str
    ) -> dict[str, Any] | None:
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            stmt = (
                select(models.ReportRow)
                .join(models.EngagementRow, models.EngagementRow.engagement_id == models.ReportRow.engagement_id)
                .where(models.ReportRow.report_id == report_id)
            )
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            row = session.scalar(stmt)
            return self._report_view(row) if row is not None else None

    def get_report_storage(
        self, *, identity: VerifiedHumanIdentity, report_id: str
    ) -> tuple[str, str, str] | None:
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            stmt = (
                select(models.ReportRow)
                .join(models.EngagementRow, models.EngagementRow.engagement_id == models.ReportRow.engagement_id)
                .where(models.ReportRow.report_id == report_id)
            )
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            row = session.scalar(stmt)
            if row is None:
                return None
            return row.sha256, row.path, row.engagement_id

    def get_evidence_storage(
        self, *, identity: VerifiedHumanIdentity, evidence_id: str
    ) -> tuple[str, str, str] | None:
        with self._session_factory() as session, human_context(session, identity.human_principal_id):
            scope = self._client_scope(session, identity)
            stmt = (
                select(models.EvidenceMetadataRow)
                .join(
                    models.EngagementRow,
                    models.EngagementRow.engagement_id == models.EvidenceMetadataRow.engagement_id,
                )
                .where(models.EvidenceMetadataRow.evidence_id == evidence_id)
            )
            if scope is not None:
                stmt = stmt.where(models.EngagementRow.client_id.in_(scope))
            row = session.scalar(stmt)
            if row is None:
                return None
            return row.storage_ref, row.content_type, row.engagement_id

    @staticmethod
    def _workflow_view(row: models.WorkflowRunRow, activities: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "workflow_run_id": row.workflow_run_id,
            "engagement_id": row.engagement_id,
            "status": row.status,
            "current_phase": row.current_phase,
            "started_at": row.started_at.isoformat() if row.started_at else None,
            "finished_at": row.finished_at.isoformat() if row.finished_at else None,
            "activities": activities,
        }

    @staticmethod
    def _report_view(row: models.ReportRow) -> dict[str, Any]:
        return {
            "report_id": row.report_id,
            "engagement_id": row.engagement_id,
            "sha256": row.sha256,
            "findings_count": row.findings_count,
            "verdict": row.verdict,
            "generated_at": row.generated_at.isoformat(),
            "no_secrets_asserted": row.no_secrets_asserted,
            "retrieval": "authenticated-backend-only",
        }

    @staticmethod
    def _target_links(session: Session, engagement_ids: list[str]) -> dict[str, list[str]]:
        if not engagement_ids:
            return {}
        links: dict[str, list[str]] = {engagement_id: [] for engagement_id in engagement_ids}
        for row in session.scalars(
            select(models.EngagementTargetRow).where(
                models.EngagementTargetRow.engagement_id.in_(engagement_ids),
                models.EngagementTargetRow.in_scope.is_(True),
            )
        ):
            links[row.engagement_id].append(row.target_id)
        return links


def _engagement_read_model(row: models.EngagementRow, target_ids: list[str]) -> EngagementReadModel:
    return EngagementReadModel(
        engagement_id=row.engagement_id,
        client_id=row.client_id,
        requester_principal_id=row.requester_principal_id,
        target_ids=target_ids,
        scope=row.scope,
        pass_type=row.pass_type,
        authority_level=row.authority_level,
        status=row.status,
        updated_at=row.updated_at.isoformat(),
    )


def _read_window(cursor: str | None, limit: int) -> tuple[int, int]:
    if not 1 <= limit <= 100:
        raise ReadModelError("limit must be between 1 and 100")
    return _decode_cursor(cursor), limit + 1


def _read_page(items: list[T], *, offset: int, limit: int) -> CursorPage[T]:
    if len(items) > limit:
        items = items[:limit]
        next_cursor = _encode_cursor(offset + limit)
    else:
        next_cursor = None
    return CursorPage(items=items, next_cursor=next_cursor, limit=limit)


class PostgresAuditSink:
    """Append-only audit ledger in PostgreSQL (AuditSink port)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def append(self, event: AuditEvent) -> None:
        if self._session.get(models.AuditEventRow, str(event.audit_event_id)) is not None:
            return
        self._session.add(
            models.AuditEventRow(
                audit_event_id=event.audit_event_id,
                engagement_id=event.engagement_id,
                principal_id=event.principal_id,
                kind=event.kind.value,
                summary=event.summary,
                details=event.details,
                occurred_at=event.occurred_at,
                previous_event_id=event.previous_event_id,
            )
        )
        self._session.flush()  # visible to reconstruction queries in the same unit of work

    def read_since(self, since: datetime | None = None) -> list[AuditEvent]:
        stmt = select(models.AuditEventRow).order_by(models.AuditEventRow.occurred_at)
        if since is not None:
            stmt = stmt.where(models.AuditEventRow.occurred_at >= since)
        rows = self._session.scalars(stmt)
        return [
            AuditEvent(
                audit_event_id=AuditEventId(row.audit_event_id),
                engagement_id=EngagementId(row.engagement_id) if row.engagement_id else None,
                principal_id=PrincipalId(row.principal_id) if row.principal_id else None,
                kind=AuditEventKind(row.kind),
                summary=row.summary,
                details=row.details or {},
                occurred_at=row.occurred_at,
                previous_event_id=AuditEventId(row.previous_event_id) if row.previous_event_id else None,
            )
            for row in rows
        ]


class PostgresSecurityServiceRepository:
    """Persist profile, plan, run, and AQS receipts under existing tenant scope."""

    def __init__(self, session: Session) -> None:
        self._session = session

    @staticmethod
    def profile_id(profile: TargetSecurityProfile) -> str:
        return f"PROF-{profile.target_id}-{profile.snapshot_id}"[:96]

    def save_profile(self, *, profile: TargetSecurityProfile, client_id: ClientId) -> str:
        profile_id = self.profile_id(profile)
        self._session.merge(
            models.TargetSecurityProfileRow(
                profile_id=profile_id,
                client_id=client_id,
                target_id=profile.target_id,
                snapshot_id=profile.snapshot_id,
                target_class=profile.target_class,
                payload=profile.model_dump(mode="json"),
            )
        )
        self._session.flush()
        return profile_id

    def save_plan(self, *, plan: AssessmentPlan, client_id: ClientId, profile_id: str) -> None:
        payload = plan.model_dump(mode="json")
        payload["profile_id"] = profile_id
        self._session.merge(
            models.AssessmentPlanRow(
                plan_id=plan.plan_id,
                client_id=client_id,
                engagement_id=plan.engagement_id,
                target_id=plan.target_id,
                profile_id=profile_id,
                payload=payload,
            )
        )
        self._session.flush()

    def commit(self) -> None:
        self._session.commit()

    def save_run(self, *, run: ServiceRun, payload: Mapping[str, Any] | None = None) -> None:
        self._session.merge(
            models.SecurityServiceRunRow(
                run_id=run.run_id,
                client_id=run.client_id,
                engagement_id=run.engagement_id,
                target_id=run.target_id,
                snapshot_id=run.snapshot_id,
                service_id=run.service_id,
                service_version=run.service_version,
                specialist_id=run.specialist_id,
                assessment_plan_id=run.assessment_plan_id,
                authority_level=run.authority_level.value,
                capabilities=run.capabilities,
                evidence_ids=run.evidence_ids,
                claim_ids=run.claim_ids,
                status=run.status.value,
                qualification_version=run.qualification_version,
                limitations=run.limitations,
                payload=dict(payload or {}),
                started_at=run.started_at,
                finished_at=run.finished_at,
            )
        )
        self._session.flush()

    def save_qualification(
        self,
        *,
        contract: SecurityServiceContract,
        receipt: QualificationReceipt,
    ) -> None:
        self._session.merge(
            models.ServiceQualificationRow(
                service_id=contract.service_id,
                service_version=contract.version,
                qualification_state=receipt.qualification_level.value,
                receipt=receipt.model_dump(mode="json"),
            )
        )
        self._session.flush()

    def list_runs(self, *, client_id: ClientId, engagement_id: EngagementId) -> list[models.SecurityServiceRunRow]:
        return list(
            self._session.scalars(
                select(models.SecurityServiceRunRow)
                .where(
                    models.SecurityServiceRunRow.client_id == str(client_id),
                    models.SecurityServiceRunRow.engagement_id == str(engagement_id),
                )
                .order_by(models.SecurityServiceRunRow.run_id)
            )
        )

    def get_plan(self, *, client_id: ClientId, engagement_id: EngagementId) -> dict[str, Any] | None:
        row = self._session.scalar(
            select(models.AssessmentPlanRow)
            .where(
                models.AssessmentPlanRow.client_id == str(client_id),
                models.AssessmentPlanRow.engagement_id == str(engagement_id),
            )
            .order_by(models.AssessmentPlanRow.plan_id)
        )
        return dict(row.payload) if row is not None else None

    def get_assessment_chain(
        self,
        *,
        client_id: ClientId,
        engagement_id: EngagementId,
    ) -> dict[str, Any] | None:
        """Load the canonical, process-independent service assessment chain."""
        for row in self.list_runs(client_id=client_id, engagement_id=engagement_id):
            payload = row.payload if isinstance(row.payload, dict) else {}
            chain = payload.get("assessment_chain")
            if isinstance(chain, dict):
                return dict(chain)
        return None

    def get_profile_for_engagement(
        self,
        *,
        client_id: ClientId,
        engagement_id: EngagementId,
    ) -> dict[str, Any] | None:
        row = self._session.scalar(
            select(models.TargetSecurityProfileRow)
            .join(
                models.AssessmentPlanRow,
                models.AssessmentPlanRow.profile_id == models.TargetSecurityProfileRow.profile_id,
            )
            .where(
                models.TargetSecurityProfileRow.client_id == str(client_id),
                models.AssessmentPlanRow.client_id == str(client_id),
                models.AssessmentPlanRow.engagement_id == str(engagement_id),
            )
            .order_by(models.TargetSecurityProfileRow.profile_id)
        )
        return dict(row.payload) if row is not None else None

    def list_qualifications(self) -> list[models.ServiceQualificationRow]:
        return list(
            self._session.scalars(
                select(models.ServiceQualificationRow).order_by(
                    models.ServiceQualificationRow.service_id,
                    models.ServiceQualificationRow.service_version,
                )
            )
        )
