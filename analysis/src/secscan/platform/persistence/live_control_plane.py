"""Canonical PostgreSQL adapter for the live v0.3 control plane.

The adapter owns no detector or policy semantics.  It provides durable source
bindings, event work leases, canonical reconstruction, and append/replay
operations for the existing v0.3 domain services.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Iterator, Sequence

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from secscan.platform.continuous_security.events import EventIdentityConflict, SecurityEvent
from secscan.platform.detection_response.domain import (
    DetectionEvaluation,
    DetectionInputError,
    DetectionPlan,
    DetectionRule,
    DetectionRuleType,
    DetectionRuleVersion,
    DetectionRun,
    DetectionSignal,
    DetectionWorkItem,
    DetectionWorkStatus,
    HumanApprovalState,
    HuntExecution,
    HuntHypothesis,
    HuntPlan,
    HuntResult,
    Incident,
    IncidentAdjudication,
    IncidentHypothesis,
    IncidentInvestigation,
    IncidentState,
    OpaDecision,
    ResponseAction,
    ResponseProposal,
    RuleStatus,
    Scope,
    SecuritySourceBinding,
    stable_id,
)
from secscan.platform.domain.authority import Action, Approval
from secscan.platform.domain.common import Confidence, Severity
from secscan.platform.domain.evidence import Claim
from secscan.platform.domain.ids import (
    AgentId,
    AgentRunId,
    ApprovalId,
    CapabilityId,
    ClaimId,
    EngagementId,
    EvidenceId,
    ObservationId,
    PrincipalId,
    TargetId,
)
from secscan.platform.persistence import models
from secscan.platform.persistence.detection_response import (
    PostgresDetectionResponseRepository,
    canonical_rule_digest,
)
from secscan.platform.persistence.session import human_context
from secscan.sanitize.filters import payload_contains_secret_like_content


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class PostgresLiveControlPlaneRepository:
    """Session-factory adapter for live detection/response state."""

    def __init__(self, session_factory: sessionmaker[Session] | Callable[[], Session]) -> None:
        self._session_factory = session_factory

    @contextmanager
    def _transaction(self, access_principal_id: str | None = None) -> Iterator[Session]:
        with self._session_factory() as session:
            if access_principal_id:
                with human_context(session, access_principal_id):
                    yield session
            else:
                with session.begin():
                    yield session

    @staticmethod
    def _scope(row: Any) -> Scope:
        return Scope(tenant=row.tenant_id, case=row.case_id, target=row.target_id)

    @staticmethod
    def _assert_scope(row: Any, scope: Scope) -> None:
        if (row.tenant_id, row.case_id, row.target_id) != scope.key():
            raise PermissionError("canonical live record is outside the requested scope")

    @staticmethod
    def _reject_secret_like(payload: Any) -> None:
        if payload_contains_secret_like_content(payload):
            raise DetectionInputError("canonical live text contains secret-like content")

    @staticmethod
    def _validate_engagement_scope(session: Session, scope: Scope) -> None:
        engagement = session.get(models.EngagementRow, scope.case_id)
        if engagement is None or engagement.client_id != scope.tenant_id:
            raise PermissionError("scope is not bound to a canonical engagement")
        target = session.scalar(
            select(models.EngagementTargetRow).where(
                models.EngagementTargetRow.engagement_id == scope.case_id,
                models.EngagementTargetRow.target_id == scope.target_id,
                models.EngagementTargetRow.in_scope.is_(True),
            )
        )
        if target is None:
            raise PermissionError("target is not in the canonical engagement scope")

    @staticmethod
    def _binding(row: models.SecuritySourceBindingRow) -> SecuritySourceBinding:
        return SecuritySourceBinding(
            source_id=row.source_id,
            principal_id=row.principal_id,
            scope=Scope(tenant=row.tenant_id, case=row.case_id, target=row.target_id),
            source_family=row.source_family,
            source_type=row.source_type,
            status=row.status,
        )

    def register_source(
        self, binding: SecuritySourceBinding, *, access_principal_id: str | None = None
    ) -> SecuritySourceBinding:
        with self._transaction(access_principal_id) as session:
            self._validate_engagement_scope(session, binding.scope)
            if session.get(models.PrincipalRow, binding.principal_id) is None:
                raise PermissionError("source principal is not canonical")
            existing = session.get(models.SecuritySourceBindingRow, binding.source_id)
            if existing is not None:
                if self._binding(existing) != binding:
                    raise DetectionInputError("source identity was reused for different binding")
                return binding
            session.add(
                models.SecuritySourceBindingRow(
                    source_id=binding.source_id,
                    principal_id=binding.principal_id,
                    tenant_id=binding.scope.tenant_id,
                    case_id=binding.scope.case_id,
                    target_id=binding.scope.target_id,
                    source_family=binding.source_family,
                    source_type=binding.source_type,
                    status=binding.status,
                )
            )
            session.flush()
        return binding

    def load_source(
        self, source_id: str, *, access_principal_id: str | None = None
    ) -> SecuritySourceBinding | None:
        with self._transaction(access_principal_id) as session:
            row = session.get(models.SecuritySourceBindingRow, source_id)
            return None if row is None else self._binding(row)

    @staticmethod
    def _work(row: models.DetectionWorkItemRow) -> DetectionWorkItem:
        return DetectionWorkItem(
            work_id=row.work_id,
            event_id=row.event_id,
            scope=Scope(tenant=row.tenant_id, case=row.case_id, target=row.target_id),
            event_fingerprint=row.event_fingerprint,
            status=DetectionWorkStatus(row.status),
            attempts=row.attempts,
            lease_until=_utc(row.lease_until),
            worker_id=row.worker_id,
            run_ids=tuple(row.run_ids or []),
            signal_ids=tuple(row.signal_ids or []),
            last_error=row.last_error,
            created_at=_utc(row.created_at),  # type: ignore[arg-type]
            updated_at=_utc(row.updated_at),  # type: ignore[arg-type]
            completed_at=_utc(row.completed_at),
        )

    def ingest_event(
        self,
        event: SecurityEvent,
        *,
        access_principal_id: str | None = None,
    ) -> tuple[DetectionWorkItem, bool, bool]:
        """Atomically append/replay an event and its durable work item."""

        scope = Scope(tenant=event.tenant, case=event.case, target=event.target)
        with self._transaction(access_principal_id) as session:
            self._validate_engagement_scope(session, scope)
            response_repo = PostgresDetectionResponseRepository(session)
            existing_event = session.get(models.SecurityEventRow, event.event_id)
            event_created = existing_event is None
            if existing_event is None:
                try:
                    with session.begin_nested():
                        response_repo.save_event(event)
                        session.flush()
                except IntegrityError as exc:
                    # A concurrent identical replay may win the unique event
                    # insert between the read and flush.  Resolve the winner
                    # from PostgreSQL before exposing an infrastructure error.
                    existing_event = session.get(models.SecurityEventRow, event.event_id)
                    if existing_event is not None:
                        response_repo.save_event(event)
                        event_created = False
                    else:
                        existing_fingerprint = session.scalar(
                            select(models.SecurityEventRow).where(
                                models.SecurityEventRow.tenant_id == scope.tenant_id,
                                models.SecurityEventRow.case_id == scope.case_id,
                                models.SecurityEventRow.target_id == scope.target_id,
                                models.SecurityEventRow.fingerprint == event.fingerprint,
                            )
                        )
                        if existing_fingerprint is not None:
                            raise EventIdentityConflict("same event payload was assigned multiple identities") from exc
                        raise
            else:
                response_repo.save_event(event)
            session.flush()
            work = session.scalar(
                select(models.DetectionWorkItemRow).where(
                    models.DetectionWorkItemRow.tenant_id == scope.tenant_id,
                    models.DetectionWorkItemRow.case_id == scope.case_id,
                    models.DetectionWorkItemRow.target_id == scope.target_id,
                    models.DetectionWorkItemRow.event_id == event.event_id,
                )
            )
            created = work is None
            if work is None:
                candidate = models.DetectionWorkItemRow(
                    work_id=stable_id("WORK-", scope.key(), event.event_id, event.fingerprint),
                    event_id=event.event_id,
                    tenant_id=scope.tenant_id,
                    case_id=scope.case_id,
                    target_id=scope.target_id,
                    event_fingerprint=event.fingerprint,
                    status=DetectionWorkStatus.PENDING.value,
                    attempts=0,
                    run_ids=[],
                    signal_ids=[],
                )
                try:
                    with session.begin_nested():
                        session.add(candidate)
                        session.flush()
                except IntegrityError as exc:
                    work = session.scalar(
                        select(models.DetectionWorkItemRow).where(
                            models.DetectionWorkItemRow.tenant_id == scope.tenant_id,
                            models.DetectionWorkItemRow.case_id == scope.case_id,
                            models.DetectionWorkItemRow.target_id == scope.target_id,
                            models.DetectionWorkItemRow.event_id == event.event_id,
                        )
                    )
                    if work is None:
                        raise
                    if work.event_fingerprint != event.fingerprint:
                        raise EventIdentityConflict("detection work identity was reused for different content") from exc
                    created = False
                else:
                    work = candidate
            elif work.event_fingerprint != event.fingerprint:
                raise EventIdentityConflict("detection work identity was reused for different content")
            elif work.status == DetectionWorkStatus.FAILED.value:
                work.status = DetectionWorkStatus.PENDING.value
                work.last_error = None
                work.lease_until = None
                work.worker_id = None
            session.flush()
            return self._work(work), created, event_created

    def get_work(
        self, work_id: str, *, scope: Scope | None = None, access_principal_id: str | None = None
    ) -> DetectionWorkItem | None:
        with self._transaction(access_principal_id) as session:
            row = session.get(models.DetectionWorkItemRow, work_id)
            if row is None:
                return None
            if scope is not None:
                self._assert_scope(row, scope)
            return self._work(row)

    def claim_work(
        self,
        *,
        worker_id: str,
        limit: int = 20,
        scope: Scope | None = None,
        work_id: str | None = None,
        lease_seconds: int = 120,
        access_principal_id: str | None = None,
    ) -> tuple[DetectionWorkItem, ...]:
        if not worker_id.strip() or not 1 <= limit <= 100 or not 1 <= lease_seconds <= 3600:
            raise ValueError("work claim bounds are invalid")
        now = datetime.now(UTC)
        with self._transaction(access_principal_id) as session:
            # The OR expression is deliberately explicit: completed work is
            # never claimable and claimed work requires an expired lease.
            status_filter = or_(
                models.DetectionWorkItemRow.status.in_(
                    [DetectionWorkStatus.PENDING.value, DetectionWorkStatus.FAILED.value]
                ),
                (models.DetectionWorkItemRow.status == DetectionWorkStatus.CLAIMED.value)
                & (models.DetectionWorkItemRow.lease_until <= now),
            )
            stmt = select(models.DetectionWorkItemRow).where(status_filter)
            if work_id is not None:
                stmt = stmt.where(models.DetectionWorkItemRow.work_id == work_id)
            if scope is not None:
                stmt = stmt.where(
                    models.DetectionWorkItemRow.tenant_id == scope.tenant_id,
                    models.DetectionWorkItemRow.case_id == scope.case_id,
                    models.DetectionWorkItemRow.target_id == scope.target_id,
                )
            rows = list(
                session.scalars(
                    stmt.order_by(models.DetectionWorkItemRow.created_at, models.DetectionWorkItemRow.work_id)
                    .limit(limit)
                    .with_for_update(skip_locked=True)
                )
            )
            for row in rows:
                row.status = DetectionWorkStatus.CLAIMED.value
                row.attempts += 1
                row.worker_id = worker_id
                row.lease_until = now + timedelta(seconds=lease_seconds)
                row.updated_at = now
                row.last_error = None
            session.flush()
            return tuple(self._work(row) for row in rows)

    def claim_one(
        self,
        work_id: str,
        *,
        worker_id: str,
        lease_seconds: int = 120,
        access_principal_id: str | None = None,
    ) -> DetectionWorkItem | None:
        work = self.get_work(work_id, access_principal_id=access_principal_id)
        if work is None or work.status == DetectionWorkStatus.COMPLETED:
            return work
        if work.status == DetectionWorkStatus.CLAIMED and work.lease_until and work.lease_until > datetime.now(UTC):
            if work.worker_id != worker_id:
                return None
        claimed = self.claim_work(
            worker_id=worker_id,
            limit=1,
            scope=work.scope,
            work_id=work_id,
            lease_seconds=lease_seconds,
            access_principal_id=access_principal_id,
        )
        return claimed[0] if claimed and claimed[0].work_id == work_id else None

    def complete_work(
        self,
        work_id: str,
        *,
        worker_id: str,
        run_ids: Sequence[str],
        signal_ids: Sequence[str],
        access_principal_id: str | None = None,
    ) -> DetectionWorkItem:
        now = datetime.now(UTC)
        with self._transaction(access_principal_id) as session:
            row = session.get(models.DetectionWorkItemRow, work_id)
            if row is None:
                raise KeyError("detection work item not found")
            if row.status == DetectionWorkStatus.COMPLETED.value:
                return self._work(row)
            lease_until = _utc(row.lease_until)
            if (
                row.status != DetectionWorkStatus.CLAIMED.value
                or row.worker_id != worker_id
                or lease_until is None
                or lease_until <= now
            ):
                raise PermissionError("detection work completion is not bound to its active lease")
            row.status = DetectionWorkStatus.COMPLETED.value
            row.run_ids = list(dict.fromkeys(run_ids))
            row.signal_ids = list(dict.fromkeys(signal_ids))
            row.lease_until = None
            row.worker_id = None
            row.last_error = None
            row.completed_at = now
            row.updated_at = now
            session.flush()
            return self._work(row)

    def fail_work(
        self,
        work_id: str,
        *,
        worker_id: str,
        error_type: str,
        access_principal_id: str | None = None,
    ) -> DetectionWorkItem:
        now = datetime.now(UTC)
        safe_error = error_type[:128] or "unknown"
        with self._transaction(access_principal_id) as session:
            row = session.get(models.DetectionWorkItemRow, work_id)
            if row is None:
                raise KeyError("detection work item not found")
            if row.status != DetectionWorkStatus.COMPLETED.value:
                lease_until = _utc(row.lease_until)
                if (
                    row.status != DetectionWorkStatus.CLAIMED.value
                    or row.worker_id != worker_id
                    or lease_until is None
                    or lease_until <= now
                ):
                    raise PermissionError("detection work failure is not bound to its active lease")
                row.status = DetectionWorkStatus.FAILED.value
                row.last_error = safe_error
                row.lease_until = None
                row.worker_id = None
                row.updated_at = now
            session.flush()
            return self._work(row)

    def load_events(
        self, scope: Scope, *, access_principal_id: str | None = None
    ) -> tuple[SecurityEvent, ...]:
        with self._transaction(access_principal_id) as session:
            rows = list(
                session.scalars(
                    select(models.SecurityEventRow)
                    .where(
                        models.SecurityEventRow.tenant_id == scope.tenant_id,
                        models.SecurityEventRow.case_id == scope.case_id,
                        models.SecurityEventRow.target_id == scope.target_id,
                    )
                    .order_by(models.SecurityEventRow.occurred_at, models.SecurityEventRow.event_id)
                )
            )
            response_repo = PostgresDetectionResponseRepository(session)
            events: list[SecurityEvent] = []
            for row in rows:
                event = response_repo.load_event(event_id=row.event_id, scope=scope)
                if event is None:
                    raise DetectionInputError("canonical event row is missing its payload")
                events.append(event)
            return tuple(events)

    @staticmethod
    def _rule_version(row: models.DetectionRuleVersionRow) -> DetectionRuleVersion:
        return DetectionRuleVersion(
            rule_id=row.rule_id,
            version=row.version,
            title=row.title,
            rule_type=DetectionRuleType(row.rule_type),
            content_digest=row.content_digest,
            source=row.source,
            source_reference=row.source_reference,
            owner=row.owner,
            event_schema=row.event_schema,
            ocsf_version=row.ocsf_version,
            supported_source_families=tuple(row.supported_source_families or []),
            severity=Severity(row.severity),
            confidence=Confidence(row.confidence),
            confidence_metadata=row.confidence_metadata or {},
            attack_mappings=tuple(row.attack_mappings or []),
            atlas_mappings=tuple(row.atlas_mappings or []),
            references=tuple(row.references or []),
            predicates=row.predicates or {},
            correlation_keys=tuple(row.correlation_keys or []),
            window_seconds=row.window_seconds,
            threshold=row.threshold,
            status=RuleStatus(row.status),
            evaluation_metadata=row.evaluation_metadata or {},
            created_at=_utc(row.created_at),  # type: ignore[arg-type]
            modified_at=_utc(row.modified_at),  # type: ignore[arg-type]
        )

    @staticmethod
    def _plan(rule: DetectionRuleVersion) -> DetectionPlan:
        return DetectionPlan(
            plan_id=stable_id("PLAN-", rule.rule_id, rule.version, rule.content_digest),
            rule_id=rule.rule_id,
            rule_version=rule.version,
            rule_type=rule.rule_type,
            content_digest=rule.content_digest,
            event_schema=rule.event_schema,
            supported_source_families=rule.supported_source_families,
            predicates=rule.predicates,
            correlation_keys=rule.correlation_keys,
            window_seconds=rule.window_seconds,
            threshold=rule.threshold,
        )

    def register_rule(
        self,
        rule: DetectionRule,
        plan: DetectionPlan | None = None,
        *,
        access_principal_id: str | None = None,
    ) -> DetectionPlan:
        selected = rule.active
        if (
            selected.status.value != "ACTIVE"
            or rule.owner != "SecScanMonitor"
            or selected.owner != "SecScanMonitor"
        ):
            raise DetectionInputError("live rules must be SecScanMonitor-owned ACTIVE rules")
        expected_plan = self._plan(selected)
        plan = plan or expected_plan
        if plan != expected_plan:
            raise DetectionInputError("registered plan does not bind to the active rule content")
        with self._transaction(access_principal_id) as session:
            response_repo = PostgresDetectionResponseRepository(session)
            response_repo.save_rule_version(selected)
            response_repo.save_plan(plan)
            session.flush()
        return plan

    def active_rules(
        self, *, access_principal_id: str | None = None
    ) -> tuple[tuple[DetectionRule, DetectionPlan], ...]:
        with self._transaction(access_principal_id) as session:
            rows = list(
                session.scalars(
                    select(models.DetectionRuleVersionRow)
                    .where(models.DetectionRuleVersionRow.status == "ACTIVE")
                    .order_by(models.DetectionRuleVersionRow.rule_id, models.DetectionRuleVersionRow.version)
                )
            )
            grouped: dict[str, list[DetectionRuleVersion]] = {}
            for row in rows:
                version = self._rule_version(row)
                if version.owner != "SecScanMonitor":
                    raise DetectionInputError("active rule is not SecScanMonitor-owned")
                if not row.canonical_digest or canonical_rule_digest(version) != row.canonical_digest:
                    raise DetectionInputError("active rule failed its canonical digest binding")
                grouped.setdefault(version.rule_id, []).append(version)
            if any(len(versions) != 1 for versions in grouped.values()):
                raise DetectionInputError("each live rule must have exactly one ACTIVE version")
            return tuple(
                (
                    DetectionRule(
                        rule_id=rule_id,
                        name=max(versions, key=lambda item: item.version).title,
                        versions=tuple(sorted(versions, key=lambda item: item.version)),
                        active_version=max(versions, key=lambda item: item.version).version,
                        owner="SecScanMonitor",
                    ),
                    self._plan(max(versions, key=lambda item: item.version)),
                )
                for rule_id, versions in sorted(grouped.items())
            )

    def load_signals(
        self,
        scope: Scope,
        signal_ids: Sequence[str] | None = None,
        *,
        access_principal_id: str | None = None,
    ) -> tuple[DetectionSignal, ...]:
        with self._transaction(access_principal_id) as session:
            stmt = select(models.DetectionSignalRow).where(
                models.DetectionSignalRow.tenant_id == scope.tenant_id,
                models.DetectionSignalRow.case_id == scope.case_id,
                models.DetectionSignalRow.target_id == scope.target_id,
            )
            requested = tuple(dict.fromkeys(signal_ids or ()))
            if requested:
                stmt = stmt.where(models.DetectionSignalRow.signal_id.in_(requested))
            rows = list(session.scalars(stmt.order_by(models.DetectionSignalRow.signal_id)))
            if requested and {row.signal_id for row in rows} != set(requested):
                raise PermissionError("one or more signals are absent or outside the requested scope")
            if not rows:
                return ()

            if requested:
                loaded_rows = {row.signal_id: row for row in rows}
                pending_source_ids = {
                    source_id
                    for row in rows
                    for source_id in (row.source_signal_ids or [])
                    if source_id not in loaded_rows
                }
                while pending_source_ids:
                    source_rows = list(
                        session.scalars(
                            select(models.DetectionSignalRow).where(
                                models.DetectionSignalRow.tenant_id == scope.tenant_id,
                                models.DetectionSignalRow.case_id == scope.case_id,
                                models.DetectionSignalRow.target_id == scope.target_id,
                                models.DetectionSignalRow.signal_id.in_(pending_source_ids),
                            )
                        )
                    )
                    found_source_ids = {row.signal_id for row in source_rows}
                    if found_source_ids != pending_source_ids:
                        raise PermissionError("canonical signal references an unknown source signal")
                    loaded_rows.update({row.signal_id: row for row in source_rows})
                    pending_source_ids = {
                        source_id
                        for row in source_rows
                        for source_id in (row.source_signal_ids or [])
                        if source_id not in loaded_rows
                    }
                rows = sorted(loaded_rows.values(), key=lambda row: row.signal_id)

            response_repo = PostgresDetectionResponseRepository(session)
            event_rows = list(
                session.scalars(
                    select(models.SecurityEventRow).where(
                        models.SecurityEventRow.tenant_id == scope.tenant_id,
                        models.SecurityEventRow.case_id == scope.case_id,
                        models.SecurityEventRow.target_id == scope.target_id,
                    )
                )
            )
            events: dict[str, SecurityEvent] = {}
            for event_row in event_rows:
                event = response_repo.load_event(event_id=event_row.event_id, scope=scope)
                if event is None:
                    raise PermissionError("canonical signal evidence is missing its event payload")
                events[event.event_id] = event

            signals: dict[str, DetectionSignal] = {}
            rules: dict[tuple[str, int], DetectionRuleVersion] = {}
            for row in rows:
                try:
                    signal = DetectionSignal(
                        signal_id=row.signal_id,
                        scope=scope,
                        rule_id=row.rule_id,
                        rule_version=row.rule_version,
                        event_ids=tuple(row.event_ids or []),
                        source_signal_ids=tuple(row.source_signal_ids or []),
                        detected_at=_utc(row.detected_at),  # type: ignore[arg-type]
                        severity=Severity(row.severity),
                        confidence=Confidence(row.confidence),
                        matched_predicates=tuple(row.matched_predicates or []),
                        raw_evidence_refs=tuple(row.raw_evidence_refs or []),
                        rule_digest=row.rule_digest,
                        status=row.status,
                    )
                except (TypeError, ValueError) as exc:
                    raise PermissionError("canonical detection signal failed validation") from exc
                if (
                    tuple(sorted(set(signal.event_ids))) != signal.event_ids
                    or len(signal.source_signal_ids) != len(set(signal.source_signal_ids))
                    or tuple(sorted(set(signal.raw_evidence_refs))) != signal.raw_evidence_refs
                ):
                    raise PermissionError("canonical detection signal is not deterministically ordered")
                signals[signal.signal_id] = signal

                key = (signal.rule_id, signal.rule_version)
                rule = rules.get(key)
                if rule is None:
                    rule_row = session.get(models.DetectionRuleVersionRow, key)
                    if rule_row is None:
                        raise PermissionError("canonical signal references an unknown rule version")
                    try:
                        rule = self._rule_version(rule_row)
                        if (
                            rule.owner != "SecScanMonitor"
                            or not rule_row.canonical_digest
                            or canonical_rule_digest(rule) != rule_row.canonical_digest
                        ):
                            raise PermissionError("canonical signal rule binding is invalid")
                    except (TypeError, ValueError) as exc:
                        raise PermissionError("canonical signal rule binding failed validation") from exc
                    rules[key] = rule
                    plan_rows = list(
                        session.scalars(
                            select(models.DetectionPlanRow).where(
                                models.DetectionPlanRow.rule_id == rule.rule_id,
                                models.DetectionPlanRow.rule_version == rule.version,
                            )
                        )
                    )
                    expected_plan = self._plan(rule)
                    if not any(
                        plan_row.plan_id == expected_plan.plan_id
                        and plan_row.rule_id == expected_plan.rule_id
                        and plan_row.rule_version == expected_plan.rule_version
                        and plan_row.rule_type == expected_plan.rule_type.value
                        and plan_row.content_digest == expected_plan.content_digest
                        and plan_row.event_schema == expected_plan.event_schema
                        and list(plan_row.supported_source_families or [])
                        == list(expected_plan.supported_source_families)
                        and plan_row.predicates == expected_plan.predicates
                        and list(plan_row.correlation_keys or []) == list(expected_plan.correlation_keys)
                        and plan_row.window_seconds == expected_plan.window_seconds
                        and plan_row.threshold == expected_plan.threshold
                        for plan_row in plan_rows
                    ):
                        raise PermissionError("canonical signal detection plan binding is invalid")
                if (
                    signal.rule_digest != rule.content_digest
                    or signal.severity != rule.severity
                    or signal.confidence != rule.confidence
                ):
                    raise PermissionError("canonical signal does not match its registered rule version")

            def evidence_refs(signal_id: str, seen: frozenset[str] = frozenset()) -> set[str]:
                if signal_id in seen:
                    raise PermissionError("canonical signal provenance contains a cycle")
                signal = signals.get(signal_id)
                if signal is None:
                    raise PermissionError("canonical signal references an unknown source signal")
                refs = set()
                for event_id in signal.event_ids:
                    event = events.get(event_id)
                    if event is None:
                        raise PermissionError("canonical signal references an unknown event")
                    refs.add(event.raw_evidence_ref)
                for source_signal_id in signal.source_signal_ids:
                    refs.update(evidence_refs(source_signal_id, seen | {signal_id}))
                if not refs:
                    raise PermissionError("canonical signal has no resolvable event evidence")
                return refs

            for signal in signals.values():
                if set(signal.raw_evidence_refs) != evidence_refs(signal.signal_id):
                    raise PermissionError("canonical signal evidence is not bound to its source events")

            signal_keys = tuple(signals)
            evaluations = list(
                session.scalars(
                    select(models.DetectionEvaluationRow).where(
                        models.DetectionEvaluationRow.tenant_id == scope.tenant_id,
                        models.DetectionEvaluationRow.case_id == scope.case_id,
                        models.DetectionEvaluationRow.target_id == scope.target_id,
                        models.DetectionEvaluationRow.signal_id.in_(signal_keys),
                    )
                )
            )
            run_ids = tuple({row.run_id for row in evaluations})
            runs = {
                row.run_id: row
                for row in (
                    session.scalars(
                        select(models.DetectionRunRow).where(models.DetectionRunRow.run_id.in_(run_ids))
                    )
                    if run_ids
                    else ()
                )
            }
            for signal in signals.values():
                if not any(
                    evaluation.signal_id == signal.signal_id
                    and evaluation.result == "MATCH"
                    and evaluation.rule_id == signal.rule_id
                    and evaluation.rule_version == signal.rule_version
                    and list(evaluation.input_event_ids or []) == list(signal.event_ids)
                    and list(evaluation.matched_predicates or []) == list(signal.matched_predicates)
                    and evaluation.rule_digest == signal.rule_digest
                    and (
                        run := runs.get(evaluation.run_id)
                    ) is not None
                    and run.status == "COMPLETED"
                    and (run.tenant_id, run.case_id, run.target_id) == scope.key()
                    and run.engine_version.strip()
                    and evaluation.engine_version == run.engine_version
                    and signal.rule_id in (run.rule_ids or [])
                    and signal.signal_id in (run.signal_ids or [])
                    and evaluation.evaluation_id in (run.evaluation_ids or [])
                    and set(signal.event_ids).issubset(set(run.input_event_ids or []))
                    for evaluation in evaluations
                ):
                    raise PermissionError("canonical signal has no matching completed detection evaluation")

            selected = signal_keys if not requested else requested
            return tuple(signals[signal_id] for signal_id in selected)

    def persist_detection_outputs(
        self,
        rule: DetectionRule,
        plan: DetectionPlan,
        run: DetectionRun,
        evaluations: Sequence[DetectionEvaluation],
        signals: Sequence[DetectionSignal],
        *,
        access_principal_id: str | None = None,
    ) -> None:
        if (
            rule.owner != "SecScanMonitor"
            or rule.active.owner != "SecScanMonitor"
            or rule.active.status.value != "ACTIVE"
        ):
            raise DetectionInputError("live outputs require a SecScanMonitor-owned ACTIVE rule")
        if plan != self._plan(rule.active):
            raise DetectionInputError("detection output plan does not bind to the active rule content")
        if any(item.run_id != run.run_id or item.scope != run.scope for item in evaluations):
            raise DetectionInputError("detection evaluation crossed its canonical run scope")
        if any(item.scope != run.scope for item in signals):
            raise DetectionInputError("detection signal crossed its canonical run scope")
        with self._transaction(access_principal_id) as session:
            self._validate_engagement_scope(session, run.scope)
            response_repo = PostgresDetectionResponseRepository(session)
            response_repo.save_rule_version(rule.active)
            response_repo.save_plan(plan)
            response_repo.save_run(run)
            for evaluation in evaluations:
                response_repo.save_evaluation(evaluation)
            for signal in signals:
                response_repo.save_signal(signal)
            session.flush()

    @staticmethod
    def _save_exact(session: Session, model: Any, row: Any, identity: Any, fields: Sequence[str]) -> None:
        existing = session.get(model, identity)
        if existing is not None:
            if any(getattr(existing, field) != getattr(row, field) for field in fields):
                raise DetectionInputError(f"{row.__tablename__} identity was reused for different content")
            return
        session.add(row)

    def save_hunt_request(
        self,
        hypothesis: HuntHypothesis,
        plan: HuntPlan,
        *,
        access_principal_id: str | None = None,
    ) -> None:
        if hypothesis.scope != plan.scope or hypothesis.hypothesis_id != plan.hypothesis_id:
            raise PermissionError("hunt request scope and hypothesis binding do not match")
        self._reject_secret_like(
            {
                "hypothesis": hypothesis.model_dump(mode="json", by_alias=True),
                "plan": plan.model_dump(mode="json", by_alias=True),
            }
        )
        with self._transaction(access_principal_id) as session:
            self._validate_engagement_scope(session, plan.scope)
            self._save_exact(
                session,
                models.HuntHypothesisRow,
                models.HuntHypothesisRow(
                    hypothesis_id=hypothesis.hypothesis_id,
                    tenant_id=hypothesis.scope.tenant_id,
                    case_id=hypothesis.scope.case_id,
                    target_id=hypothesis.scope.target_id,
                    question=hypothesis.question,
                    entity_keys=list(hypothesis.entity_keys),
                    supporting_signal_ids=list(hypothesis.supporting_signal_ids),
                    required_evidence_refs=list(hypothesis.required_evidence_refs),
                    created_at=hypothesis.created_at,
                ),
                hypothesis.hypothesis_id,
                ("tenant_id", "case_id", "target_id", "question", "entity_keys", "supporting_signal_ids", "required_evidence_refs"),
            )
            self._save_exact(
                session,
                models.HuntPlanRow,
                models.HuntPlanRow(
                    plan_id=plan.plan_id,
                    hypothesis_id=plan.hypothesis_id,
                    tenant_id=plan.scope.tenant_id,
                    case_id=plan.scope.case_id,
                    target_id=plan.scope.target_id,
                    window_start=plan.window_start,
                    window_end=plan.window_end,
                    query=plan.query,
                    exit_criteria=plan.exit_criteria,
                    max_events=plan.max_events,
                    status="PENDING",
                    lease_until=None,
                    worker_id=None,
                    created_at=hypothesis.created_at,
                ),
                plan.plan_id,
                ("hypothesis_id", "tenant_id", "case_id", "target_id", "window_start", "window_end", "query", "exit_criteria", "max_events"),
            )
            session.flush()

    def load_hunt_request(
        self, plan_id: str, *, access_principal_id: str | None = None
    ) -> tuple[HuntHypothesis, HuntPlan] | None:
        with self._transaction(access_principal_id) as session:
            plan_row = session.get(models.HuntPlanRow, plan_id)
            if plan_row is None:
                return None
            hypothesis_row = session.get(models.HuntHypothesisRow, plan_row.hypothesis_id)
            if hypothesis_row is None:
                raise DetectionInputError("hunt plan is missing its canonical hypothesis")
            scope = Scope(tenant=plan_row.tenant_id, case=plan_row.case_id, target=plan_row.target_id)
            hypothesis = HuntHypothesis(
                hypothesis_id=hypothesis_row.hypothesis_id,
                scope=scope,
                question=hypothesis_row.question,
                entity_keys=tuple(hypothesis_row.entity_keys or []),
                supporting_signal_ids=tuple(hypothesis_row.supporting_signal_ids or []),
                required_evidence_refs=tuple(hypothesis_row.required_evidence_refs or []),
                created_at=_utc(hypothesis_row.created_at),  # type: ignore[arg-type]
            )
            plan = HuntPlan(
                plan_id=plan_row.plan_id,
                hypothesis_id=plan_row.hypothesis_id,
                scope=scope,
                window_start=_utc(plan_row.window_start),  # type: ignore[arg-type]
                window_end=_utc(plan_row.window_end),  # type: ignore[arg-type]
                query=plan_row.query or {},
                exit_criteria=plan_row.exit_criteria,
                max_events=plan_row.max_events,
            )
            return hypothesis, plan

    def claim_hunt(
        self,
        plan_id: str,
        *,
        worker_id: str,
        lease_seconds: int = 120,
        access_principal_id: str | None = None,
    ) -> bool:
        if not worker_id.strip() or not 1 <= lease_seconds <= 3600:
            raise ValueError("hunt claim bounds are invalid")
        now = datetime.now(UTC)
        with self._transaction(access_principal_id) as session:
            row = session.get(models.HuntPlanRow, plan_id, with_for_update=True)
            if row is None:
                raise KeyError("hunt plan not found")
            if row.status == "COMPLETED":
                return True
            lease_until = _utc(row.lease_until)
            if (
                row.status == "CLAIMED"
                and row.worker_id != worker_id
                and lease_until is not None
                and lease_until > now
            ):
                return False
            if row.status not in {"PENDING", "CLAIMED"}:
                return False
            row.status = "CLAIMED"
            row.worker_id = worker_id
            row.lease_until = now + timedelta(seconds=lease_seconds)
            session.flush()
            return True

    def pending_hunt_plans(
        self, *, access_principal_id: str | None = None
    ) -> tuple[str, ...]:
        now = datetime.now(UTC)
        with self._transaction(access_principal_id) as session:
            return tuple(
                session.scalars(
                    select(models.HuntPlanRow.plan_id)
                    .where(
                        or_(
                            models.HuntPlanRow.status == "PENDING",
                            (models.HuntPlanRow.status == "CLAIMED")
                            & (
                                models.HuntPlanRow.lease_until.is_(None)
                                | (models.HuntPlanRow.lease_until <= now)
                            ),
                        )
                    )
                    .order_by(models.HuntPlanRow.created_at, models.HuntPlanRow.plan_id)
                )
            )

    def save_hunt(
        self,
        execution: HuntExecution,
        result: HuntResult,
        *,
        worker_id: str | None = None,
        access_principal_id: str | None = None,
    ) -> None:
        with self._transaction(access_principal_id) as session:
            plan_row = session.get(models.HuntPlanRow, execution.plan_id)
            if plan_row is None:
                raise DetectionInputError("hunt execution is missing its canonical plan")
            if (plan_row.tenant_id, plan_row.case_id, plan_row.target_id) != execution.scope.key():
                raise PermissionError("hunt execution crossed its canonical plan scope")
            now = datetime.now(UTC)
            if plan_row.status == "CLAIMED":
                lease_until = _utc(plan_row.lease_until)
                if (
                    worker_id is None
                    or plan_row.worker_id != worker_id
                    or lease_until is None
                    or lease_until <= now
                ):
                    raise PermissionError("hunt completion is not bound to its active lease")
            elif plan_row.status != "COMPLETED" and worker_id is not None:
                raise PermissionError("hunt completion is not bound to its claimed plan")
            PostgresDetectionResponseRepository(session).save_hunt(execution, result)
            plan_row.status = "COMPLETED"
            plan_row.lease_until = None
            plan_row.worker_id = None
            plan_row.completed_at = now
            session.flush()

    def load_hypothesis(
        self, hypothesis_id: str, *, access_principal_id: str | None = None
    ) -> IncidentHypothesis | None:
        with self._transaction(access_principal_id) as session:
            row = session.get(models.IncidentHypothesisRow, hypothesis_id)
            if row is None:
                return None
            return IncidentHypothesis(
                hypothesis_id=row.hypothesis_id,
                scope=Scope(tenant=row.tenant_id, case=row.case_id, target=row.target_id),
                question=row.question,
                source_signal_ids=tuple(row.source_signal_ids or []),
                affected_entities=tuple(row.affected_entities or []),
                created_at=_utc(row.created_at),  # type: ignore[arg-type]
            )

    def save_incident_hypothesis(
        self,
        hypothesis: IncidentHypothesis,
        *,
        access_principal_id: str | None = None,
    ) -> None:
        self._reject_secret_like(hypothesis.model_dump(mode="json", by_alias=True))
        with self._transaction(access_principal_id) as session:
            self._validate_engagement_scope(session, hypothesis.scope)
            PostgresDetectionResponseRepository(session).save_incident_hypothesis(hypothesis)
            session.flush()

    def load_claims(
        self,
        claim_ids: Sequence[str],
        scope: Scope,
        *,
        access_principal_id: str | None = None,
    ) -> dict[str, Claim]:
        requested = tuple(dict.fromkeys(claim_ids))
        if not requested:
            return {}
        with self._transaction(access_principal_id) as session:
            self._validate_engagement_scope(session, scope)
            rows = list(session.scalars(select(models.ClaimRow).where(models.ClaimRow.claim_id.in_(requested))))
            if len(rows) != len(requested) or any(row.engagement_id != scope.case_id for row in rows):
                raise PermissionError("claim is absent or outside the requested scope")
            observation_ids = {item for row in rows for item in (row.observation_ids or [])}
            observations = list(
                session.scalars(select(models.ObservationRow).where(models.ObservationRow.observation_id.in_(observation_ids)))
            )
            if len(observations) != len(observation_ids) or any(row.engagement_id != scope.case_id for row in observations):
                raise PermissionError("claim observation is absent or outside the requested scope")
            observation_evidence_ids = {
                row.observation_id: tuple(row.evidence_ids or [])
                for row in observations
            }
            evidence_values = [
                item
                for row in rows
                for item in (row.evidence_ids or [])
            ] + [
                item
                for row in observations
                for item in (row.evidence_ids or [])
            ]
            if any(not isinstance(item, str) or not item.strip() for item in evidence_values):
                raise DetectionInputError("canonical claim evidence references are invalid")
            evidence_ids = set(evidence_values)
            if not evidence_ids:
                raise PermissionError("claim has no canonical evidence")
            evidence_rows = list(
                session.scalars(
                    select(models.EvidenceMetadataRow).where(
                        models.EvidenceMetadataRow.evidence_id.in_(evidence_ids)
                    )
                )
            )
            if (
                len(evidence_rows) != len(evidence_ids)
                or any(
                    row.engagement_id != scope.case_id or row.target_id != scope.target_id
                    for row in evidence_rows
                )
            ):
                raise PermissionError("claim evidence is absent or outside the requested scope")
            result: dict[str, Claim] = {}
            for row in rows:
                claim_evidence_ids = list(
                    dict.fromkeys(
                        [*(row.evidence_ids or [])]
                        + [
                            item
                            for observation_id in (row.observation_ids or [])
                            for item in observation_evidence_ids[observation_id]
                        ]
                    )
                )
                try:
                    confidence = Confidence(row.confidence)
                except ValueError as exc:
                    raise DetectionInputError("canonical claim confidence is invalid") from exc
                result[row.claim_id] = Claim(
                    claim_id=ClaimId(row.claim_id),
                    engagement_id=EngagementId(row.engagement_id),
                    agent_id=AgentId(row.agent_id),
                    agent_run_id=AgentRunId(row.agent_run_id),
                    observation_ids=[ObservationId(item) for item in (row.observation_ids or [])],
                    evidence_ids=[EvidenceId(item) for item in claim_evidence_ids],
                    statement=row.statement,
                    confidence=confidence,
                    uncertainty=row.uncertainty,
                    supporting_note=row.supporting_note,
                    made_at=_utc(row.made_at),  # type: ignore[arg-type]
                )
            return result

    def load_claim_evidence_refs(
        self,
        claim_ids: Sequence[str],
        scope: Scope,
        *,
        access_principal_id: str | None = None,
    ) -> dict[str, tuple[str, ...]]:
        claims = self.load_claims(
            claim_ids,
            scope,
            access_principal_id=access_principal_id,
        )
        if not claims:
            return {}
        evidence_ids = tuple(
            dict.fromkeys(
                str(evidence_id)
                for claim in claims.values()
                for evidence_id in claim.evidence_ids
            )
        )
        with self._transaction(access_principal_id) as session:
            self._validate_engagement_scope(session, scope)
            rows = list(
                session.scalars(
                    select(models.EvidenceMetadataRow).where(
                        models.EvidenceMetadataRow.evidence_id.in_(evidence_ids)
                    )
                )
            )
            if (
                len(rows) != len(evidence_ids)
                or any(
                    row.engagement_id != scope.case_id
                    or row.target_id != scope.target_id
                    or not isinstance(row.storage_ref, str)
                    or not row.storage_ref.strip()
                    for row in rows
                )
            ):
                raise PermissionError("claim evidence is absent or outside the requested scope")
            refs_by_id = {row.evidence_id: row.storage_ref for row in rows}
            return {
                claim_id: tuple(sorted({refs_by_id[str(evidence_id)] for evidence_id in claim.evidence_ids}))
                for claim_id, claim in claims.items()
            }

    def is_canonical_adjudicator(
        self, principal_id: str, *, access_principal_id: str | None = None
    ) -> bool:
        with self._transaction(access_principal_id) as session:
            return self._canonical_human(session, principal_id)

    def save_investigation_and_adjudication(
        self,
        investigation: IncidentInvestigation,
        adjudication: IncidentAdjudication,
        incident: Incident,
        *,
        access_principal_id: str | None = None,
    ) -> None:
        if investigation.scope != incident.scope or adjudication.scope != incident.scope:
            raise PermissionError("incident records crossed their canonical scope")
        self._reject_secret_like(
            {
                "investigation": investigation.model_dump(mode="json", by_alias=True),
                "adjudication": adjudication.model_dump(mode="json", by_alias=True),
            }
        )
        with self._transaction(access_principal_id) as session:
            self._validate_engagement_scope(session, incident.scope)
            self._save_exact(
                session,
                models.IncidentInvestigationRow,
                models.IncidentInvestigationRow(
                    investigation_id=investigation.investigation_id,
                    hypothesis_id=investigation.hypothesis_id,
                    tenant_id=investigation.scope.tenant_id,
                    case_id=investigation.scope.case_id,
                    target_id=investigation.scope.target_id,
                    observation_ids=list(investigation.observation_ids),
                    claim_ids=list(investigation.claim_ids),
                    opened_at=investigation.opened_at,
                ),
                investigation.investigation_id,
                ("hypothesis_id", "tenant_id", "case_id", "target_id", "observation_ids", "claim_ids"),
            )
            self._save_exact(
                session,
                models.AdjudicationRow,
                models.AdjudicationRow(
                    adjudication_id=adjudication.adjudication_id,
                    engagement_id=adjudication.scope.case_id,
                    claim_ids=list(adjudication.supporting_claim_ids) + list(adjudication.contradicting_claim_ids),
                    supporting_evidence_ids=list(adjudication.supporting_evidence_refs),
                    contradicting_evidence_ids=list(adjudication.contradicting_evidence_refs),
                    verdict=incident.state.value,
                    rationale=adjudication.reason,
                    confidence=adjudication.confidence.value,
                    specialist_identity="secscan-v03-incident-adjudicator",
                    decided_by_principal_id=adjudication.decided_by,
                    decided_at=adjudication.decided_at,
                ),
                adjudication.adjudication_id,
                (
                    "engagement_id",
                    "claim_ids",
                    "supporting_evidence_ids",
                    "contradicting_evidence_ids",
                    "verdict",
                    "rationale",
                    "confidence",
                    "decided_by_principal_id",
                ),
            )
            PostgresDetectionResponseRepository(session).save_incident(incident)
            session.flush()

    def load_incident(
        self, incident_id: str, *, scope: Scope, access_principal_id: str | None = None
    ) -> Incident | None:
        with self._transaction(access_principal_id) as session:
            row = session.get(models.IncidentRow, incident_id)
            if row is None:
                return None
            self._assert_scope(row, scope)
            return Incident(
                incident_id=row.incident_id,
                hypothesis_id=row.hypothesis_id,
                investigation_id=row.investigation_id,
                adjudication_id=row.adjudication_id,
                scope=scope,
                state=IncidentState(row.state),
                severity=Severity(row.severity),
                confidence=Confidence(row.confidence),
                source_signal_ids=tuple(row.source_signal_ids or []),
                observation_ids=tuple(row.observation_ids or []),
                claim_ids=tuple(row.claim_ids or []),
                supporting_evidence_refs=tuple(row.supporting_evidence_refs or []),
                contradicting_evidence_refs=tuple(row.contradicting_evidence_refs or []),
                adjudicated_at=_utc(row.adjudicated_at),  # type: ignore[arg-type]
                authorized_action_executed=bool(row.authorized_action_executed),
            )

    def persist_response_proposal(
        self,
        proposal: ResponseProposal,
        *,
        requested_by_principal_id: str,
        access_principal_id: str | None = None,
    ) -> None:
        from secscan.platform.detection_response.domain import CapabilityRequest

        self._reject_secret_like(proposal.model_dump(mode="json", by_alias=True))
        with self._transaction(access_principal_id) as session:
            self._validate_engagement_scope(session, proposal.scope)
            if session.get(models.PrincipalRow, requested_by_principal_id) is None:
                raise PermissionError("proposal requester is not canonical")
            response_repo = PostgresDetectionResponseRepository(session)
            response_repo.save_proposal(proposal)
            if proposal.human_approval_state != HumanApprovalState.APPROVAL_REQUIRED:
                session.flush()
                return
            request = CapabilityRequest(
                request_id=stable_id("CAPREQ-", proposal.proposal_id, proposal.proposal_digest),
                proposal_id=proposal.proposal_id,
                scope=proposal.scope,
                target_id=proposal.target_id,
                action=proposal.action,
                proposal_digest=proposal.proposal_digest,
                requested_at=datetime.now(UTC),
            )
            approval = Approval(
                approval_id=ApprovalId(stable_id("AP-", proposal.proposal_id)),
                engagement_id=EngagementId(proposal.scope.case_id),
                requested_by_principal_id=PrincipalId(requested_by_principal_id),
                request_ref=proposal.proposal_id,
                target_id=TargetId(proposal.target_id),
                capability_id=CapabilityId("CAP-V03-RESPONSE-PROPOSAL"),
                action=Action.REMEDIATE,
            )
            self._save_exact(
                session,
                models.ResponseCapabilityRequestRow,
                models.ResponseCapabilityRequestRow(
                    request_id=request.request_id,
                    proposal_id=request.proposal_id,
                    tenant_id=request.scope.tenant_id,
                    case_id=request.scope.case_id,
                    target_id=request.target_id,
                    action=request.action.value,
                    proposal_digest=request.proposal_digest,
                    requested_at=request.requested_at,
                ),
                request.request_id,
                ("proposal_id", "tenant_id", "case_id", "target_id", "action", "proposal_digest"),
            )
            self._save_exact(
                session,
                models.ApprovalRow,
                models.ApprovalRow(
                    approval_id=approval.approval_id,
                    engagement_id=approval.engagement_id,
                    requested_by_principal_id=approval.requested_by_principal_id,
                    decided_by_principal_id=None,
                    request_ref=approval.request_ref,
                    target_id=approval.target_id,
                    capability_id=approval.capability_id,
                    action=approval.action.value,
                    decision=approval.decision,
                    rationale=approval.rationale,
                ),
                str(approval.approval_id),
                (
                    "engagement_id",
                    "requested_by_principal_id",
                    "request_ref",
                    "target_id",
                    "capability_id",
                    "action",
                    "decision",
                ),
            )
            session.flush()

    def load_proposal(
        self, proposal_id: str, *, scope: Scope, access_principal_id: str | None = None
    ) -> ResponseProposal | None:
        with self._transaction(access_principal_id) as session:
            row = session.get(models.ResponseProposalRow, proposal_id)
            if row is None:
                return None
            self._assert_scope(row, scope)
            return ResponseProposal(
                proposal_id=row.proposal_id,
                incident_id=row.incident_id,
                scope=scope,
                target_id=row.target_id,
                action=ResponseAction(row.action),
                reason=row.reason,
                supporting_evidence_refs=tuple(row.supporting_evidence_refs or []),
                expected_impact=row.expected_impact,
                risk=row.risk,
                rollback_plan=row.rollback_plan,
                expires_at=_utc(row.expires_at),  # type: ignore[arg-type]
                proposal_digest=row.proposal_digest,
                opa_decision=OpaDecision(row.opa_decision),
                human_approval_state=HumanApprovalState(row.human_approval_state),
                authorized_action_executed=bool(row.authorized_action_executed),
            )

    def load_approval(
        self,
        proposal: ResponseProposal,
        *,
        access_principal_id: str | None = None,
    ) -> Approval:
        with self._transaction(access_principal_id) as session:
            return self._approval_from_row(self._approval_row(session, proposal))

    @staticmethod
    def _canonical_human(session: Session, principal_id: str) -> bool:
        row = session.get(models.PrincipalRow, principal_id)
        return row is not None and row.kind.lower() in {"operator", "human"}

    @staticmethod
    def _approval_row(
        session: Session,
        proposal: ResponseProposal,
        *,
        for_update: bool = False,
    ) -> models.ApprovalRow:
        engagement = session.get(models.EngagementRow, proposal.scope.case_id)
        if engagement is None or engagement.client_id != proposal.scope.tenant_id:
            raise PermissionError("approval is outside the requested tenant scope")
        statement = select(models.ApprovalRow).where(
            models.ApprovalRow.engagement_id == proposal.scope.case_id,
            models.ApprovalRow.request_ref == proposal.proposal_id,
        )
        if for_update:
            statement = statement.with_for_update()
        row = session.scalar(statement)
        if row is None:
            raise PermissionError("response proposal has no canonical approval record")
        if row.target_id != proposal.target_id or row.capability_id != "CAP-V03-RESPONSE-PROPOSAL":
            raise PermissionError("approval is not bound to the canonical proposal")
        if row.engagement_id != proposal.scope.case_id or row.action != Action.REMEDIATE.value:
            raise PermissionError("approval is outside the requested engagement scope")
        request = session.scalar(
            select(models.ResponseCapabilityRequestRow).where(
                models.ResponseCapabilityRequestRow.proposal_id == proposal.proposal_id,
                models.ResponseCapabilityRequestRow.tenant_id == proposal.scope.tenant_id,
                models.ResponseCapabilityRequestRow.case_id == proposal.scope.case_id,
                models.ResponseCapabilityRequestRow.target_id == proposal.target_id,
                models.ResponseCapabilityRequestRow.action == proposal.action.value,
                models.ResponseCapabilityRequestRow.proposal_digest == proposal.proposal_digest,
            )
        )
        if request is None or request.request_id != stable_id(
            "CAPREQ-", proposal.proposal_id, proposal.proposal_digest
        ):
            raise PermissionError("capability request is not bound to the exact response proposal")
        return row

    @staticmethod
    def _approval_from_row(row: models.ApprovalRow) -> Approval:
        return Approval(
            approval_id=ApprovalId(row.approval_id),
            engagement_id=EngagementId(row.engagement_id),
            requested_by_principal_id=PrincipalId(row.requested_by_principal_id),
            decided_by_principal_id=PrincipalId(row.decided_by_principal_id)
            if row.decided_by_principal_id
            else None,
            request_ref=row.request_ref,
            target_id=TargetId(row.target_id),
            capability_id=CapabilityId(row.capability_id),
            action=Action(row.action),
            decision=row.decision,
            decided_at=_utc(row.decided_at),
            rationale=row.rationale,
        )

    def decide_approval(
        self,
        proposal: ResponseProposal,
        *,
        decided_by: str,
        decision: str,
        proposal_state: str,
        rationale: str = "",
        access_principal_id: str | None = None,
    ) -> Approval:
        if decision not in {"approved", "denied"}:
            raise ValueError("approval decision must be approved or denied")
        if proposal_state not in {"APPROVED", "DENIED"} or proposal_state != decision.upper():
            raise ValueError("approval and proposal decisions must match")
        self._reject_secret_like({"rationale": rationale})
        with self._transaction(access_principal_id) as session:
            row = self._approval_row(session, proposal, for_update=True)
            if not self._canonical_human(session, decided_by):
                raise PermissionError("approval requires a canonical human operator")
            if decided_by == row.requested_by_principal_id:
                raise PermissionError("requester cannot approve its own response proposal")
            proposal_row = session.get(models.ResponseProposalRow, proposal.proposal_id, with_for_update=True)
            if proposal_row is None:
                raise PermissionError("response proposal disappeared during decision")
            self._assert_scope(proposal_row, proposal.scope)
            if proposal_row.proposal_digest != proposal.proposal_digest or proposal_row.authorized_action_executed:
                raise PermissionError("proposal binding is invalid or already executed")
            if proposal_row.human_approval_state not in {"APPROVAL_REQUIRED", proposal_state}:
                raise PermissionError("response proposal approval state cannot transition")
            if row.decision != "pending":
                if (
                    row.decision == decision
                    and row.decided_by_principal_id == decided_by
                    and row.rationale == rationale
                ):
                    return self._approval_from_row(row)
                raise PermissionError("approval decision is already canonical")
            approval = self._approval_from_row(row)
            approval.decide(decision=decision, by=PrincipalId(decided_by), rationale=rationale)
            row.decided_by_principal_id = decided_by
            row.decision = decision
            row.decided_at = approval.decided_at
            row.rationale = rationale
            proposal_row.human_approval_state = proposal_state
            session.flush()
        return approval

    def opa_request(
        self,
        context: dict[str, Any],
        *,
        access_principal_id: str | None = None,
    ) -> dict[str, Any]:
        """Build OPA input solely from canonical engagement/capability/grant data."""

        scope_values = context.get("scope")
        if not isinstance(scope_values, dict):
            raise PermissionError("response policy scope is missing")
        scope = Scope(tenant=scope_values.get("tenant", ""), case=scope_values.get("case", ""), target=scope_values.get("target", ""))
        target_id = context.get("target_id")
        if target_id != scope.target_id:
            raise PermissionError("response target is outside its canonical scope")
        capability_id = "CAP-V03-RESPONSE-PROPOSAL"
        with self._transaction(access_principal_id) as session:
            engagement = session.get(models.EngagementRow, scope.case_id)
            if engagement is None or engagement.client_id != scope.tenant_id:
                raise PermissionError("response policy scope is not bound to its engagement")
            links = list(
                session.scalars(
                    select(models.EngagementTargetRow).where(
                        models.EngagementTargetRow.engagement_id == scope.case_id,
                        models.EngagementTargetRow.in_scope.is_(True),
                    )
                )
            )
            if target_id not in {link.target_id for link in links}:
                raise PermissionError("response policy target is not in the canonical engagement scope")
            capability = session.scalar(
                select(models.CapabilityManifestRow)
                .where(models.CapabilityManifestRow.capability_id == capability_id)
                .order_by(models.CapabilityManifestRow.version.desc())
            )
            grants = list(
                session.scalars(
                    select(models.AuthorityGrantRow).where(
                        models.AuthorityGrantRow.engagement_id == scope.case_id,
                        models.AuthorityGrantRow.action == Action.REMEDIATE.value,
                        models.AuthorityGrantRow.capability_id == capability_id,
                        models.AuthorityGrantRow.revoked_at.is_(None),
                    )
                )
            )
            now = datetime.now(UTC)
            grant = next(
                (
                    item
                    for item in grants
                    if item.target_id in {None, target_id}
                    and (_utc(item.not_before) or now) <= now
                    and (item.not_after is None or (_utc(item.not_after) or now) > now)
                ),
                None,
            )
            registered = capability is not None
            principal_id = grant.principal_id if grant is not None else "secscan-v03-response-authority"
            target_ids = [link.target_id for link in links]
            return {
                "principal": {"id": principal_id},
                "agent": {"id": "secscan-v03-response-service"},
                "engagement": {
                    "id": scope.case_id,
                    "status": engagement.status if engagement is not None else "unknown",
                    "authority_level": engagement.authority_level if engagement is not None else "unknown",
                    "target_ids": target_ids,
                },
                "target": {"id": target_id},
                "capability": {
                    "id": capability_id,
                    "registered": registered,
                    "risk_class": capability.risk_class if capability is not None else "high",
                    "requires_approval": bool(capability.requires_approval) if capability is not None else True,
                    "required_authority": capability.required_authority if capability is not None else Action.REMEDIATE.value,
                },
                "action": Action.REMEDIATE.value,
                "risk": context.get("risk", "high"),
                "authority_grant": {
                    "matched": grant is not None,
                    "grant_ids": [grant.grant_id] if grant is not None else [],
                    "conditions": list(grant.conditions or []) if grant is not None else [],
                    "principal_id": grant.principal_id if grant is not None else "",
                    "engagement_id": grant.engagement_id if grant is not None else "",
                    "capability_id": grant.capability_id if grant is not None and grant.capability_id else "",
                    "target_id": grant.target_id if grant is not None and grant.target_id else "",
                    "action": grant.action if grant is not None else "",
                },
                "approval": {
                    "id": "",
                    "recorded": False,
                    "decision": "pending",
                    "target_id": "",
                    "capability_id": "",
                    "action": "",
                    "engagement_id": "",
                    "decided_by_principal_id": "",
                },
                "workflow_phase": "adjudication",
                "requested_resources": {
                    "response_proposal": str(context.get("proposal_digest", "")),
                    "snapshot": "",
                },
            }

    def read_detection_signals(self, *, access_principal_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(access_principal_id) as session:
            rows = list(session.scalars(select(models.DetectionSignalRow).order_by(models.DetectionSignalRow.signal_id)))
            return [
                {
                    "signal_id": row.signal_id,
                    "tenant_id": row.tenant_id,
                    "case_id": row.case_id,
                    "rule_id": row.rule_id,
                    "rule_version": row.rule_version,
                    "severity": row.severity,
                    "confidence": row.confidence,
                    "status": row.status,
                    "event_ids": list(row.event_ids or []),
                    "evidence_refs": list(row.raw_evidence_refs or []),
                    "source": "canonical detection engine",
                }
                for row in rows
            ]

    def read_hunts(self, *, access_principal_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(access_principal_id) as session:
            rows = list(session.scalars(select(models.HuntExecutionRow).order_by(models.HuntExecutionRow.execution_id)))
            result: list[dict[str, Any]] = []
            for row in rows:
                payload = row.result or {}
                disposition = str(payload.get("disposition", "INCONCLUSIVE"))
                evidence_refs = (
                    payload.get("supporting_evidence_refs", [])
                    if disposition == "SUPPORTS"
                    else payload.get("refuting_evidence_refs", [])
                    if disposition == "REFUTES"
                    else [
                        *payload.get("supporting_evidence_refs", []),
                        *payload.get("refuting_evidence_refs", []),
                    ]
                )
                result.append(
                    {
                        "hunt_id": row.execution_id,
                        "hypothesis_id": row.hypothesis_id,
                        "tenant_id": row.tenant_id,
                        "case_id": row.case_id,
                        "disposition": disposition,
                        "status": "VERIFIED" if disposition == "SUPPORTS" else "CONTRADICTED" if disposition == "REFUTES" else "INCONCLUSIVE",
                        "evidence_refs": [str(item) for item in evidence_refs],
                        "source": "canonical threat-hunt engine",
                    }
                )
            return result

    def read_incidents(self, *, access_principal_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(access_principal_id) as session:
            rows = list(session.scalars(select(models.IncidentRow).order_by(models.IncidentRow.incident_id)))
            return [
                {
                    "incident_id": row.incident_id,
                    "tenant_id": row.tenant_id,
                    "case_id": row.case_id,
                    "status": row.state,
                    "severity": row.severity,
                    "confidence": row.confidence,
                    "signal_ids": list(row.source_signal_ids or []),
                    "evidence_refs": list(row.supporting_evidence_refs or []),
                    "provenance_source": "canonical incident adjudication",
                    "provenance_source_type": "postgresql",
                    "adjudicated_at": (_utc(row.adjudicated_at) or datetime.now(UTC)).isoformat(),
                }
                for row in rows
            ]

    def read_response_proposals(self, *, access_principal_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(access_principal_id) as session:
            rows = list(session.scalars(select(models.ResponseProposalRow).order_by(models.ResponseProposalRow.proposal_id)))
            return [
                {
                    "proposal_id": row.proposal_id,
                    "incident_id": row.incident_id,
                    "tenant_id": row.tenant_id,
                    "case_id": row.case_id,
                    "target_id": row.target_id,
                    "action": row.action,
                    "opa_decision": row.opa_decision,
                    "human_approval_state": row.human_approval_state,
                    "status": row.human_approval_state,
                    "evidence_refs": list(row.supporting_evidence_refs or []),
                    "source": "canonical response proposal service",
                }
                for row in rows
            ]

    def read_approvals(self, *, access_principal_id: str | None = None) -> list[dict[str, Any]]:
        with self._transaction(access_principal_id) as session:
            rows = list(session.scalars(select(models.ApprovalRow).order_by(models.ApprovalRow.approval_id)))
            return [
                {
                    "approval_id": row.approval_id,
                    "engagement_id": row.engagement_id,
                    "requested_by": row.requested_by_principal_id,
                    "request_ref": row.request_ref,
                    "target_id": row.target_id,
                    "capability_id": row.capability_id,
                    "action": row.action,
                    "risk": "not_validated",
                    "decision": row.decision,
                    "request_fingerprint": f"canonical:{row.approval_id}",
                    "rationale": row.rationale,
                }
                for row in rows
            ]


__all__ = ["PostgresLiveControlPlaneRepository"]
