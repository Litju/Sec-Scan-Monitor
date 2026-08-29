"""PostgreSQL adapter for the v0.3 detection-response contracts."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from secscan.platform.continuous_security.events import EventIdentityConflict, SecurityEvent
from secscan.platform.detection_response.domain import (
    DetectionEvaluation,
    DetectionInputError,
    DetectionPlan,
    DetectionRuleVersion,
    DetectionRun,
    DetectionScopeError,
    DetectionSignal,
    HuntExecution,
    HuntResult,
    Incident,
    IncidentHypothesis,
    ResponseProposal,
    Scope,
    content_digest,
)
from secscan.platform.persistence import models


def canonical_rule_digest(rule: DetectionRuleVersion) -> str:
    """Digest normalized rule fields independently of its source digest."""

    return content_digest(
        {
            "rule_id": rule.rule_id,
            "version": rule.version,
            "title": rule.title,
            "rule_type": rule.rule_type.value,
            "content_digest": rule.content_digest,
            "source": rule.source,
            "source_reference": rule.source_reference,
            "owner": rule.owner,
            "event_schema": rule.event_schema,
            "ocsf_version": rule.ocsf_version,
            "supported_source_families": rule.supported_source_families,
            "severity": rule.severity.value,
            "confidence": rule.confidence.value,
            "confidence_metadata": rule.confidence_metadata,
            "attack_mappings": rule.attack_mappings,
            "atlas_mappings": rule.atlas_mappings,
            "references": rule.references,
            "predicates": rule.predicates,
            "correlation_keys": rule.correlation_keys,
            "window_seconds": rule.window_seconds,
            "threshold": rule.threshold,
            "status": rule.status.value,
            "evaluation_metadata": rule.evaluation_metadata,
        }
    )


class PostgresDetectionResponseRepository:
    """Append/replay adapter; the surrounding transaction owns commit/rollback."""

    def __init__(self, session: Session) -> None:
        self._session = session

    @staticmethod
    def _scope(row: Any) -> tuple[str, str, str]:
        return row.tenant_id, row.case_id, row.target_id

    @staticmethod
    def _assert_scope(row: object, scope: Scope) -> None:
        if PostgresDetectionResponseRepository._scope(row) != scope.key():
            raise DetectionScopeError("canonical detection-response record is outside the requested scope")

    def _insert_or_replay(
        self,
        row: Any,
        model: Any,
        identity: Any,
        *,
        ignored_fields: frozenset[str] = frozenset(),
    ) -> None:
        """Insert an immutable row or accept an exact replay without merging over truth."""

        existing = self._session.get(model, identity)
        if existing is not None:
            for column in row.__table__.columns:
                field = column.name
                if field in ignored_fields:
                    continue
                if getattr(existing, field) != getattr(row, field):
                    raise DetectionInputError(f"{row.__tablename__} identity was reused for different content")
            return
        self._session.add(row)

    def save_event(self, event: SecurityEvent) -> None:
        row = self._session.get(models.SecurityEventRow, event.event_id)
        if row is not None:
            self._assert_scope(row, Scope(tenant=event.tenant, case=event.case, target=event.target))
            if row.fingerprint != event.fingerprint:
                raise EventIdentityConflict("security event identity was reused for different content")
            return
        self._session.add(
            models.SecurityEventRow(
                event_id=event.event_id,
                tenant_id=event.tenant,
                case_id=event.case,
                target_id=event.target,
                source=event.source,
                source_type=event.source_type,
                source_family=event.source_family,
                event_class=event.event_class.value,
                ocsf_class=event.ocsf_class,
                ocsf_version=event.ocsf_version,
                occurred_at=event.occurred_at,
                observed_at=event.observed_at,
                ingested_at=event.ingested_at,
                actor=event.actor,
                object_ref=event.object_ref,
                action=event.action,
                outcome=event.outcome,
                severity=event.severity,
                raw_evidence_ref=event.raw_evidence_ref,
                source_digest=event.provenance.source_digest,
                normalization_version=event.normalization_version,
                ordering_metadata=event.ordering_metadata,
                # ``canonical_dict`` deliberately omits transport metadata so
                # replay fingerprints remain stable.  The durable payload
                # must retain that metadata; it is part of the normalized
                # event contract even though it is not part of identity.
                payload=event.model_dump(mode="json", by_alias=True),
                fingerprint=event.fingerprint,
            )
        )

    def load_event(self, *, event_id: str, scope: Scope) -> SecurityEvent | None:
        row = self._session.get(models.SecurityEventRow, event_id)
        if row is None:
            return None
        self._assert_scope(row, scope)
        # The ORM JSON column contains JSON-mode enum/timestamp values while
        # the event model is strict when validating Python objects.  Validate
        # the serialized envelope so the canonical JSON representation is
        # parsed through the same typed boundary as normalization.
        try:
            event = SecurityEvent.model_validate_json(json.dumps(row.payload))
        except (TypeError, ValueError) as exc:
            raise EventIdentityConflict("stored security event payload failed canonical validation") from exc
        if event.event_id != row.event_id or event.fingerprint != row.fingerprint:
            raise EventIdentityConflict("stored security event payload does not match its replay fingerprint")
        return event

    def save_rule_version(self, rule: DetectionRuleVersion) -> None:
        self._insert_or_replay(
            models.DetectionRuleVersionRow(
                rule_id=rule.rule_id,
                version=rule.version,
                title=rule.title,
                rule_type=rule.rule_type.value,
                content_digest=rule.content_digest,
                source=rule.source,
                source_reference=rule.source_reference,
                owner=rule.owner,
                event_schema=rule.event_schema,
                ocsf_version=rule.ocsf_version,
                supported_source_families=list(rule.supported_source_families),
                severity=rule.severity.value,
                confidence=rule.confidence.value,
                confidence_metadata=rule.confidence_metadata,
                attack_mappings=list(rule.attack_mappings),
                atlas_mappings=list(rule.atlas_mappings),
                references=list(rule.references),
                predicates=rule.predicates,
                correlation_keys=list(rule.correlation_keys),
                window_seconds=rule.window_seconds,
                threshold=rule.threshold,
                status=rule.status.value,
                evaluation_metadata=rule.evaluation_metadata,
                canonical_digest=canonical_rule_digest(rule),
                created_at=rule.created_at,
                modified_at=rule.modified_at,
            ),
            models.DetectionRuleVersionRow,
            (rule.rule_id, rule.version),
            ignored_fields=frozenset({"created_at", "modified_at"}),
        )

    def save_plan(self, plan: DetectionPlan) -> None:
        self._insert_or_replay(
            models.DetectionPlanRow(
                plan_id=plan.plan_id,
                rule_id=plan.rule_id,
                rule_version=plan.rule_version,
                rule_type=plan.rule_type.value,
                content_digest=plan.content_digest,
                event_schema=plan.event_schema,
                supported_source_families=list(plan.supported_source_families),
                predicates=plan.predicates,
                correlation_keys=list(plan.correlation_keys),
                window_seconds=plan.window_seconds,
                threshold=plan.threshold,
            ),
            models.DetectionPlanRow,
            plan.plan_id,
            ignored_fields=frozenset({"created_at"}),
        )

    def save_run(self, run: DetectionRun) -> None:
        self._insert_or_replay(
            models.DetectionRunRow(
                run_id=run.run_id,
                tenant_id=run.scope.tenant_id,
                case_id=run.scope.case_id,
                target_id=run.scope.target_id,
                rule_ids=list(run.rule_ids),
                input_event_ids=list(run.input_event_ids),
                evaluation_ids=list(run.evaluation_ids),
                signal_ids=list(run.signal_ids),
                engine_version=run.engine_version,
                started_at=run.started_at,
                completed_at=run.completed_at,
                status=run.status,
            ),
            models.DetectionRunRow,
            run.run_id,
            ignored_fields=frozenset({"started_at", "completed_at"}),
        )

    def save_evaluation(self, evaluation: DetectionEvaluation) -> None:
        self._insert_or_replay(
            models.DetectionEvaluationRow(
                evaluation_id=evaluation.evaluation_id,
                run_id=evaluation.run_id,
                tenant_id=evaluation.scope.tenant_id,
                case_id=evaluation.scope.case_id,
                target_id=evaluation.scope.target_id,
                rule_id=evaluation.rule_id,
                rule_version=evaluation.rule_version,
                input_event_ids=list(evaluation.input_event_ids),
                evaluated_at=evaluation.evaluated_at,
                matched_predicates=list(evaluation.matched_predicates),
                result=evaluation.result.value,
                signal_id=evaluation.signal_id,
                engine_version=evaluation.engine_version,
                rule_digest=evaluation.rule_digest,
                idempotency_key=evaluation.idempotency_key,
            ),
            models.DetectionEvaluationRow,
            evaluation.evaluation_id,
            ignored_fields=frozenset({"evaluated_at"}),
        )

    def save_signal(self, signal: DetectionSignal) -> None:
        self._insert_or_replay(
            models.DetectionSignalRow(
                signal_id=signal.signal_id,
                tenant_id=signal.scope.tenant_id,
                case_id=signal.scope.case_id,
                target_id=signal.scope.target_id,
                rule_id=signal.rule_id,
                rule_version=signal.rule_version,
                event_ids=list(signal.event_ids),
                source_signal_ids=list(signal.source_signal_ids),
                detected_at=signal.detected_at,
                severity=signal.severity.value,
                confidence=signal.confidence.value,
                matched_predicates=list(signal.matched_predicates),
                raw_evidence_refs=list(signal.raw_evidence_refs),
                rule_digest=signal.rule_digest,
                status=signal.status,
                idempotency_key=signal.signal_id,
            ),
            models.DetectionSignalRow,
            signal.signal_id,
            ignored_fields=frozenset({"detected_at"}),
        )

    def save_hunt(self, execution: HuntExecution, result: HuntResult) -> None:
        """Persist one bounded hunt execution and its deterministic result."""

        if execution.scope != result.scope or execution.result_id != result.result_id:
            raise DetectionInputError("hunt execution and result are not bound to the same scope/result")
        if execution.execution_id != result.execution_id:
            raise DetectionInputError("hunt execution and result are not bound to the same execution")
        result_payload = result.model_dump(mode="json", by_alias=True)
        existing = self._session.get(models.HuntExecutionRow, execution.execution_id)
        if existing is not None:
            self._assert_scope(existing, execution.scope)
            if (
                existing.plan_id != execution.plan_id
                or existing.hypothesis_id != result.hypothesis_id
                or existing.result_id != execution.result_id
                or existing.query_digest != execution.query_digest
                or list(existing.input_event_ids or []) != list(execution.input_event_ids)
                or list(existing.input_signal_ids or []) != list(execution.input_signal_ids)
                or existing.result != result_payload
            ):
                raise DetectionInputError("hunt execution identity was reused for different content")
            return
        self._session.add(
            models.HuntExecutionRow(
                execution_id=execution.execution_id,
                plan_id=execution.plan_id,
                hypothesis_id=result.hypothesis_id,
                tenant_id=execution.scope.tenant_id,
                case_id=execution.scope.case_id,
                target_id=execution.scope.target_id,
                query_digest=execution.query_digest,
                input_event_ids=list(execution.input_event_ids),
                input_signal_ids=list(execution.input_signal_ids),
                result_id=execution.result_id,
                result=result_payload,
                started_at=execution.started_at,
                completed_at=execution.completed_at,
            )
        )

    def save_incident_hypothesis(self, hypothesis: IncidentHypothesis) -> None:
        """Persist the evidence-backed hypothesis before adjudication."""

        existing = self._session.get(models.IncidentHypothesisRow, hypothesis.hypothesis_id)
        if existing is not None:
            self._assert_scope(existing, hypothesis.scope)
            if (
                existing.question != hypothesis.question
                or list(existing.source_signal_ids or []) != list(hypothesis.source_signal_ids)
                or list(existing.affected_entities or []) != list(hypothesis.affected_entities)
            ):
                raise DetectionInputError("incident hypothesis identity was reused for different content")
            return
        self._session.add(
            models.IncidentHypothesisRow(
                hypothesis_id=hypothesis.hypothesis_id,
                tenant_id=hypothesis.scope.tenant_id,
                case_id=hypothesis.scope.case_id,
                target_id=hypothesis.scope.target_id,
                question=hypothesis.question,
                source_signal_ids=list(hypothesis.source_signal_ids),
                affected_entities=list(hypothesis.affected_entities),
                created_at=hypothesis.created_at,
            )
        )

    def save_incident(self, incident: Incident) -> None:
        self._insert_or_replay(
            models.IncidentRow(
                incident_id=incident.incident_id,
                hypothesis_id=incident.hypothesis_id,
                investigation_id=incident.investigation_id,
                adjudication_id=incident.adjudication_id,
                tenant_id=incident.scope.tenant_id,
                case_id=incident.scope.case_id,
                target_id=incident.scope.target_id,
                state=incident.state.value,
                severity=incident.severity.value,
                confidence=incident.confidence.value,
                source_signal_ids=list(incident.source_signal_ids),
                observation_ids=list(incident.observation_ids),
                claim_ids=list(incident.claim_ids),
                supporting_evidence_refs=list(incident.supporting_evidence_refs),
                contradicting_evidence_refs=list(incident.contradicting_evidence_refs),
                adjudicated_at=incident.adjudicated_at,
                authorized_action_executed=incident.authorized_action_executed,
            ),
            models.IncidentRow,
            incident.incident_id,
            ignored_fields=frozenset({"adjudicated_at"}),
        )

    def save_proposal(self, proposal: ResponseProposal) -> None:
        self._insert_or_replay(
            models.ResponseProposalRow(
                proposal_id=proposal.proposal_id,
                incident_id=proposal.incident_id,
                tenant_id=proposal.scope.tenant_id,
                case_id=proposal.scope.case_id,
                target_id=proposal.target_id,
                action=proposal.action.value,
                reason=proposal.reason,
                supporting_evidence_refs=list(proposal.supporting_evidence_refs),
                expected_impact=proposal.expected_impact,
                risk=proposal.risk,
                rollback_plan=proposal.rollback_plan,
                expires_at=proposal.expires_at,
                proposal_digest=proposal.proposal_digest,
                opa_decision=proposal.opa_decision.value,
                human_approval_state=proposal.human_approval_state.value,
                authorized_action_executed=proposal.authorized_action_executed,
            ),
            models.ResponseProposalRow,
            proposal.proposal_id,
            ignored_fields=frozenset({"created_at"}),
        )


__all__ = ["PostgresDetectionResponseRepository", "canonical_rule_digest"]
