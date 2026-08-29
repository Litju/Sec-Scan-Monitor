"""Live hunt, incident-adjudication, and response-proposal services."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping, Sequence, cast

from secscan.platform.continuous_security.events import SecurityEventPlane
from secscan.platform.detection_response.domain import (
    AdjudicationRefused,
    HumanApproval,
    HumanApprovalState,
    HuntHypothesis,
    HuntPlan,
    IncidentHypothesis,
    OpaDecision,
    ResponseAction,
    ResponseProposal,
    Scope,
    stable_id,
)
from secscan.platform.detection_response.engine import (
    BoundedSecurityEventIngestor,
    DetectionEngine,
    IncidentAdjudicator,
    ResponseProposalService,
    ThreatHuntEngine,
)
from secscan.platform.domain.common import Confidence, Severity, utc_now
from secscan.platform.domain.ids import new_id
from secscan.sanitize.filters import payload_contains_secret_like_content


class CanonicalResponsePolicy:
    """Policy port adapter whose input is assembled from canonical rows."""

    def __init__(self, repository: Any, policy_client: Any, access_principal_id: str | None) -> None:
        self._repository = repository
        self._policy_client = policy_client
        self._access_principal_id = access_principal_id

    def decide(self, context: Mapping[str, Any]) -> OpaDecision:
        if self._policy_client is None:
            return OpaDecision.DENY
        try:
            request = self._repository.opa_request(
                dict(context),
                access_principal_id=self._access_principal_id,
            )
            decision = self._policy_client.decide(request)
            value = getattr(decision, "value", decision)
            return OpaDecision(str(value).upper())
        except Exception:
            # Policy and dependency errors fail closed; no proposal can become
            # an executable action in this v0.3 control plane.
            return OpaDecision.DENY


class LiveIncidentControlPlaneService:
    """Compose canonical records around the existing pure domain engines."""

    def __init__(self, repository: Any, policy_client: Any | None) -> None:
        self._repository = repository
        self._policy_client = policy_client

    def _require_operator(self, principal_id: str, access_principal_id: str | None) -> None:
        if access_principal_id is not None and principal_id != access_principal_id:
            raise PermissionError("operator identity must match the verified access principal")
        if not self._repository.is_canonical_adjudicator(
            principal_id,
            access_principal_id=access_principal_id,
        ):
            raise PermissionError("operation requires a canonical human operator")

    def _engine(
        self,
        scope: Scope,
        *,
        access_principal_id: str | None,
    ) -> tuple[DetectionEngine, tuple[Any, ...]]:
        events = self._repository.load_events(scope, access_principal_id=access_principal_id)
        plane = SecurityEventPlane()
        ingestor = BoundedSecurityEventIngestor(plane, scope=scope)
        for event in events:
            ingestor.ingest(event, scope=scope)
        detector = DetectionEngine(ingestor, scope=scope)
        signals = self._repository.load_signals(scope, access_principal_id=access_principal_id)
        event_ids = {event.event_id for event in events}
        for signal in signals:
            if not set(signal.event_ids).issubset(event_ids):
                raise PermissionError("canonical signal references an unknown event")
            detector.bind_signal(signal)
        return detector, events

    def request_hunt(
        self,
        hypothesis: HuntHypothesis,
        plan: HuntPlan,
        *,
        requested_by: str,
        access_principal_id: str | None = None,
    ) -> Any:
        self._require_operator(requested_by, access_principal_id)
        if hypothesis.scope != plan.scope or hypothesis.hypothesis_id != plan.hypothesis_id:
            raise PermissionError("hunt request crossed its canonical scope")
        if payload_contains_secret_like_content(
            {
                "hypothesis": hypothesis.model_dump(mode="json", by_alias=True),
                "plan": plan.model_dump(mode="json", by_alias=True),
            }
        ):
            raise ValueError("live control-plane text must not contain secret-like content")
        signal_ids = tuple(hypothesis.supporting_signal_ids)
        query_signal_ids = plan.query.get("signal_ids")
        if query_signal_ids is not None:
            if not isinstance(query_signal_ids, (list, tuple, set)):
                raise ValueError("hunt signal_ids must be a bounded sequence")
            signal_ids = tuple(dict.fromkeys((*signal_ids, *(str(item) for item in query_signal_ids))))
        signals = self._repository.load_signals(
            plan.scope,
            signal_ids,
            access_principal_id=access_principal_id,
        )
        if len(signals) != len(set(signal_ids)):
            raise PermissionError("hunt references an unknown signal")
        self._validate_hunt_evidence(hypothesis, plan, signals, access_principal_id)
        self._repository.save_hunt_request(
            hypothesis,
            plan,
            access_principal_id=access_principal_id,
        )
        return self.execute_hunt(plan.plan_id, access_principal_id=access_principal_id)

    def _validate_hunt_evidence(
        self,
        hypothesis: HuntHypothesis,
        plan: HuntPlan,
        signals: Sequence[Any],
        access_principal_id: str | None,
    ) -> None:
        events = self._repository.load_events(plan.scope, access_principal_id=access_principal_id)
        by_id = {event.event_id: event for event in events}
        in_window_events = tuple(
            event for event in events if plan.window_start <= event.occurred_at <= plan.window_end
        )
        allowed_refs = {event.raw_evidence_ref for event in in_window_events}
        all_signals = {signal.signal_id: signal for signal in signals}
        pending_source_ids = {
            source_id for signal in signals for source_id in signal.source_signal_ids
        }
        while pending_source_ids:
            dependencies = self._repository.load_signals(
                plan.scope,
                tuple(sorted(pending_source_ids)),
                access_principal_id=access_principal_id,
            )
            if {signal.signal_id for signal in dependencies} != pending_source_ids:
                raise PermissionError("hunt signal evidence references an unknown source signal")
            all_signals.update({signal.signal_id: signal for signal in dependencies})
            pending_source_ids = {
                source_id
                for signal in dependencies
                for source_id in signal.source_signal_ids
                if source_id not in all_signals
            }

        def signal_event_ids(signal_id: str, seen: frozenset[str] = frozenset()) -> set[str]:
            if signal_id in seen:
                raise PermissionError("hunt signal evidence contains a cycle")
            signal = all_signals.get(signal_id)
            if signal is None:
                raise PermissionError("hunt signal evidence references an unknown source signal")
            event_ids = set(signal.event_ids)
            for source_id in signal.source_signal_ids:
                event_ids.update(signal_event_ids(source_id, seen | {signal_id}))
            return event_ids

        for signal in signals:
            event_ids = signal_event_ids(signal.signal_id)
            if any(
                (event := by_id.get(event_id)) is None
                or not plan.window_start <= event.occurred_at <= plan.window_end
                for event_id in event_ids
            ):
                raise PermissionError("hunt signal evidence is stale or outside its window")
            if not set(signal.raw_evidence_refs).issubset(allowed_refs):
                raise PermissionError("hunt signal evidence is stale or outside its window")
            allowed_refs.update(signal.raw_evidence_refs)
        if not set(hypothesis.required_evidence_refs).issubset(allowed_refs):
            raise PermissionError("hunt evidence is not canonical")

    def execute_hunt(
        self,
        plan_id: str,
        *,
        worker_id: str | None = None,
        access_principal_id: str | None = None,
    ) -> Any:
        worker = worker_id or new_id("HUNT-WORKER")
        if not self._repository.claim_hunt(
            plan_id,
            worker_id=worker,
            access_principal_id=access_principal_id,
        ):
            raise RuntimeError("hunt plan is currently leased by another worker")
        return self._execute_claimed_hunt(
            plan_id,
            worker_id=worker,
            access_principal_id=access_principal_id,
        )

    def recover_pending_hunts(self, *, access_principal_id: str | None = None) -> tuple[Any, ...]:
        worker = new_id("HUNT-RECOVERY")
        results: list[Any] = []
        for plan_id in self._repository.pending_hunt_plans(access_principal_id=access_principal_id):
            if not self._repository.claim_hunt(
                plan_id,
                worker_id=worker,
                access_principal_id=access_principal_id,
            ):
                continue
            results.append(
                self._execute_claimed_hunt(
                    plan_id,
                    worker_id=worker,
                    access_principal_id=access_principal_id,
                )
            )
        return tuple(results)

    def _execute_claimed_hunt(
        self,
        plan_id: str,
        *,
        worker_id: str,
        access_principal_id: str | None,
    ) -> Any:
        request = self._repository.load_hunt_request(
            plan_id,
            access_principal_id=access_principal_id,
        )
        if request is None:
            raise KeyError("hunt plan not found")
        hypothesis, plan = request
        detector, _events = self._engine(plan.scope, access_principal_id=access_principal_id)
        hunt_engine = ThreatHuntEngine(detector.events, detector)
        result = hunt_engine.run(hypothesis, plan)
        execution = hunt_engine.execution(result.result_id, scope=plan.scope)
        self._repository.save_hunt(
            execution,
            result,
            worker_id=worker_id,
            access_principal_id=access_principal_id,
        )
        return result

    def open_incident_hypothesis(
        self,
        *,
        scope: Scope,
        question: str,
        source_signal_ids: Sequence[str],
        affected_entities: Sequence[str],
        requested_by: str,
        access_principal_id: str | None = None,
    ) -> IncidentHypothesis:
        self._require_operator(requested_by, access_principal_id)
        if payload_contains_secret_like_content(
            {
                "question": question,
                "source_signal_ids": list(source_signal_ids),
                "affected_entities": list(affected_entities),
            }
        ):
            raise ValueError("live control-plane text must not contain secret-like content")
        signals = self._repository.load_signals(
            scope,
            source_signal_ids,
            access_principal_id=access_principal_id,
        )
        if len(signals) != len(set(source_signal_ids)):
            raise PermissionError("incident hypothesis references an unknown signal")
        if not question.strip() or not affected_entities:
            raise ValueError("incident hypothesis requires a question and affected entities")
        hypothesis = IncidentHypothesis(
            hypothesis_id=stable_id(
                "IH-",
                scope.key(),
                question,
                tuple(sorted(set(source_signal_ids))),
                tuple(sorted(set(affected_entities))),
            ),
            scope=scope,
            question=question,
            source_signal_ids=tuple(sorted(set(source_signal_ids))),
            affected_entities=tuple(sorted(set(affected_entities))),
        )
        self._repository.save_incident_hypothesis(
            hypothesis,
            access_principal_id=access_principal_id,
        )
        return hypothesis

    def adjudicate_incident(
        self,
        *,
        hypothesis_id: str,
        supporting_claim_ids: Sequence[str],
        supporting_evidence_refs: Sequence[str],
        decided_by: str,
        reason: str,
        severity: Severity,
        confidence: Confidence,
        contradicting_claim_ids: Sequence[str] = (),
        contradicting_evidence_refs: Sequence[str] = (),
        observation_ids: Sequence[str] = (),
        access_principal_id: str | None = None,
    ) -> Any:
        self._require_operator(decided_by, access_principal_id)
        if payload_contains_secret_like_content(
            {
                "supporting_claim_ids": list(supporting_claim_ids),
                "supporting_evidence_refs": list(supporting_evidence_refs),
                "contradicting_claim_ids": list(contradicting_claim_ids),
                "contradicting_evidence_refs": list(contradicting_evidence_refs),
                "observation_ids": list(observation_ids),
                "reason": reason,
            }
        ):
            raise ValueError("live control-plane text must not contain secret-like content")
        hypothesis = self._repository.load_hypothesis(
            hypothesis_id,
            access_principal_id=access_principal_id,
        )
        if hypothesis is None:
            raise KeyError("incident hypothesis not found")
        claims = self._repository.load_claims(
            (*supporting_claim_ids, *contradicting_claim_ids),
            hypothesis.scope,
            access_principal_id=access_principal_id,
        )
        claim_evidence_refs = self._repository.load_claim_evidence_refs(
            (*supporting_claim_ids, *contradicting_claim_ids),
            hypothesis.scope,
            access_principal_id=access_principal_id,
        )
        detector, _events = self._engine(
            hypothesis.scope,
            access_principal_id=access_principal_id,
        )
        adjudicator = IncidentAdjudicator(
            detector,
            scope=hypothesis.scope,
            canonical_adjudicator_ids=(decided_by,),
            canonical_claims=claims,
            canonical_claim_evidence_refs=claim_evidence_refs,
        )
        incident = adjudicator.adjudicate(
            hypothesis,
            supporting_claim_ids=supporting_claim_ids,
            supporting_evidence_refs=supporting_evidence_refs,
            contradicting_claim_ids=contradicting_claim_ids,
            contradicting_evidence_refs=contradicting_evidence_refs,
            decided_by=decided_by,
            reason=reason,
            severity=severity,
            confidence=confidence,
            observation_ids=observation_ids,
        )
        self._repository.save_investigation_and_adjudication(
            adjudicator.get_investigation(incident.incident_id, scope=hypothesis.scope),
            adjudicator.get_adjudication(incident.incident_id, scope=hypothesis.scope),
            incident,
            access_principal_id=access_principal_id,
        )
        return incident

    def propose_response(
        self,
        *,
        incident_id: str,
        scope: Scope,
        action: ResponseAction,
        reason: str,
        expected_impact: str,
        risk: str,
        rollback_plan: str,
        expires_at: datetime,
        requested_by: str,
        access_principal_id: str | None = None,
    ) -> ResponseProposal:
        self._require_operator(requested_by, access_principal_id)
        if payload_contains_secret_like_content(
            {
                "incident_id": incident_id,
                "reason": reason,
                "expected_impact": expected_impact,
                "risk": risk,
                "rollback_plan": rollback_plan,
            }
        ):
            raise ValueError("live control-plane text must not contain secret-like content")
        incident = self._repository.load_incident(
            incident_id,
            scope=scope,
            access_principal_id=access_principal_id,
        )
        if incident is None:
            raise KeyError("incident not found")
        policy = CanonicalResponsePolicy(self._repository, self._policy_client, access_principal_id)
        service = ResponseProposalService(
            policy=policy,
            scope=scope,
            canonical_incidents={incident.incident_id: incident},
        )
        proposal = service.propose(
            incident,
            action=action,
            reason=reason,
            expected_impact=expected_impact,
            risk=risk,
            rollback_plan=rollback_plan,
            expires_at=expires_at,
        )
        self._repository.persist_response_proposal(
            proposal,
            requested_by_principal_id=requested_by,
            access_principal_id=access_principal_id,
        )
        return proposal

    def decide_response_approval(
        self,
        *,
        proposal_id: str,
        scope: Scope,
        decided_by: str,
        decision: str,
        rationale: str = "",
        access_principal_id: str | None = None,
    ) -> ResponseProposal:
        self._require_operator(decided_by, access_principal_id)
        if payload_contains_secret_like_content({"rationale": rationale}):
            raise ValueError("live control-plane text must not contain secret-like content")
        proposal = self._repository.load_proposal(
            proposal_id,
            scope=scope,
            access_principal_id=access_principal_id,
        )
        if proposal is None:
            raise KeyError("response proposal not found")
        approval = self._repository.load_approval(
            proposal,
            access_principal_id=access_principal_id,
        )
        if decision == "denied":
            self._repository.decide_approval(
                proposal,
                decided_by=decided_by,
                decision=decision,
                proposal_state=HumanApprovalState.DENIED.value,
                rationale=rationale,
                access_principal_id=access_principal_id,
            )
            return cast(
                ResponseProposal,
                self._repository.load_proposal(
                    proposal_id,
                    scope=scope,
                    access_principal_id=access_principal_id,
                ),
            )
        if decision != "approved":
            raise ValueError("approval decision must be approved or denied")
        current_policy = CanonicalResponsePolicy(
            self._repository,
            self._policy_client,
            access_principal_id,
        ).decide(
            {
                "incident_id": proposal.incident_id,
                "scope": proposal.scope.model_dump(mode="json", by_alias=True),
                "target_id": proposal.target_id,
                "action": proposal.action.value,
                "reason": proposal.reason,
                "supporting_evidence_refs": list(proposal.supporting_evidence_refs),
                "expected_impact": proposal.expected_impact,
                "risk": proposal.risk,
                "rollback_plan": proposal.rollback_plan,
                "expires_at": proposal.expires_at.isoformat(),
                "proposal_digest": proposal.proposal_digest,
            }
        )
        if current_policy == OpaDecision.DENY:
            raise PermissionError("current OPA policy denies the response proposal")
        candidate = HumanApproval(
            approval_id=str(approval.approval_id),
            proposal_id=proposal.proposal_id,
            proposal_digest=proposal.proposal_digest,
            scope=proposal.scope,
            target_id=proposal.target_id,
            action=proposal.action,
            decision=HumanApprovalState.APPROVED,
            decided_by=decided_by,
            decided_at=utc_now(),
            source="human_operator",
            expires_at=proposal.expires_at,
        )
        incident = self._repository.load_incident(
            proposal.incident_id,
            scope=scope,
            access_principal_id=access_principal_id,
        )
        if incident is None:
            raise AdjudicationRefused("response proposal incident is not canonical")
        service = ResponseProposalService(
            policy=CanonicalResponsePolicy(self._repository, self._policy_client, access_principal_id),
            scope=scope,
            canonical_incidents={incident.incident_id: incident},
            canonical_approvals={candidate.approval_id: candidate},
            canonical_approver_ids=(decided_by,),
        )
        service.bind_canonical_proposal(proposal)
        service.approve(candidate)
        self._repository.decide_approval(
            proposal,
            decided_by=decided_by,
            decision=decision,
            proposal_state=HumanApprovalState.APPROVED.value,
            rationale=rationale,
            access_principal_id=access_principal_id,
        )
        return cast(
            ResponseProposal,
            self._repository.load_proposal(
                proposal_id,
                access_principal_id=access_principal_id,
                scope=scope,
            ),
        )
__all__ = ["CanonicalResponsePolicy", "LiveIncidentControlPlaneService"]
