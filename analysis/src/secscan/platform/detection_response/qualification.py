"""Executable synthetic qualification campaign for the v0.3 foundation."""

from __future__ import annotations

import tracemalloc
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter
from typing import Any

from secscan.platform.continuous_security.events import EventClass, EventIdentityConflict, SecurityEventPlane
from secscan.platform.domain.common import Confidence, Severity
from secscan.platform.domain.evidence import Claim
from secscan.platform.domain.ids import AgentId, AgentRunId, ClaimId, EngagementId, EvidenceId, ObservationId

from .domain import (
    AdjudicationRefused,
    DetectionInputError,
    DetectionRule,
    DetectionRuleType,
    DetectionRuleVersion,
    DetectionScopeError,
    FixtureLabel,
    HumanApproval,
    HumanApprovalState,
    HuntDisposition,
    HuntHypothesis,
    HuntPlan,
    IncidentHypothesis,
    LabeledFixture,
    ResponseAction,
    ResponseAuthorizationError,
    ResponseExecutionDisabled,
    Scope,
    content_digest,
)
from .engine import (
    BoundedSecurityEventIngestor,
    DetectionEngine,
    IncidentAdjudicator,
    OpaResponsePolicy,
    ResponseProposalService,
    ThreatHuntEngine,
)
from .evaluation import DetectionEvaluator
from .sigma import SigmaSubsetImporter

QUALIFICATION_NOW = datetime(2026, 1, 1, 12, tzinfo=UTC)
CONTENT_DIR = Path(__file__).with_name("content")


def _raw_event(
    scope: Scope,
    record_id: str,
    *,
    source_family: str,
    event_class: EventClass,
    action: str,
    outcome: str,
    object_ref: str = "object",
    actor: str = "agent-v03",
    attributes: dict[str, Any] | None = None,
    occurred_at: datetime = QUALIFICATION_NOW,
) -> dict[str, Any]:
    return {
        "source": f"v03-{source_family}",
        "source_record_id": record_id,
        "source_digest": f"digest-{record_id}",
        "source_system": "secscan-v03-qualification",
        "collector_version": "qualification-v1",
        "source_type": source_family,
        "source_family": source_family,
        "event_class": event_class.value,
        "ocsf_class": event_class.value,
        "ocsf_version": "1.8.0",
        "occurred_at": occurred_at,
        "observed_at": occurred_at + timedelta(seconds=1),
        "ingested_at": QUALIFICATION_NOW + timedelta(minutes=1),
        "tenant": scope.tenant_id,
        "case": scope.case_id,
        "target": scope.target_id,
        "actor": actor,
        "object": object_ref,
        "action": action,
        "outcome": outcome,
        "raw_evidence_ref": f"metadata://v03/{record_id}",
        "normalization_version": "security-events-v2",
        "attributes": attributes or {},
        "ordering_metadata": {"source_sequence": record_id},
    }


def _event(scope: Scope, record_id: str, **kwargs: Any):  # type: ignore[no-untyped-def]
    return SecurityEventPlane().normalize(_raw_event(scope, record_id, **kwargs))


def load_owned_rules() -> tuple[tuple[DetectionRule, Any], ...]:
    importer = SigmaSubsetImporter()
    results = tuple(importer.import_path(path) for path in sorted(CONTENT_DIR.glob("*.yml")))
    return tuple((result.rule, result.plan) for result in results)


def _fixtures(scope: Scope, rule: DetectionRule) -> tuple[LabeledFixture, ...]:
    version = rule.active
    family = version.supported_source_families[0]
    positive: dict[str, Any] | None
    negative: dict[str, Any] | None
    near_miss: dict[str, Any] | None
    base: dict[str, Any]
    if rule.rule_id.endswith("endpoint-encoded-process"):
        event_class = EventClass.ENDPOINT_ACTIVITY
        positive = {"process": {"name": "powershell", "command_line": "-encoded command"}}
        negative = {"process": {"name": "cmd", "command_line": "plain command"}}
        near_miss = {"process": {"name": "powershell", "command_line": "encodedish command"}}
        base = {"action": "execute", "outcome": "allowed", "object_ref": "process"}
    elif rule.rule_id.endswith("cloud-privileged-identity"):
        event_class = EventClass.CLOUD_AUDIT_ACTIVITY
        positive = negative = near_miss = None
        base = {"action": "CreateAccessKey", "outcome": "success", "object_ref": "identity"}
    elif rule.rule_id.endswith("mcp-privileged-tool"):
        event_class = EventClass.MCP_ACTIVITY
        positive = negative = near_miss = None
        base = {"action": "deploy", "outcome": "allowed", "object_ref": "privileged_tool"}
    else:
        event_class = EventClass.CAPABILITY_DECISION
        positive = negative = near_miss = None
        base = {"action": "execute", "outcome": "denied", "object_ref": "runner", "attributes": {"capability": "privileged_runner"}}

    def make(record_id: str, label: FixtureLabel, rationale: str, **updates: Any) -> LabeledFixture:
        values = dict(base)
        values.update(updates)
        return LabeledFixture(
            fixture_id=record_id,
            label=label,
            event=_event(scope, record_id, source_family=family, event_class=event_class, **values),
            rule_id=rule.rule_id,
            rationale=rationale,
        )

    if positive is not None:
        return (
            make("positive-" + rule.rule_id, FixtureLabel.EXPECTED_MATCH, "both endpoint predicates match", attributes=positive),
            make("negative-" + rule.rule_id, FixtureLabel.EXPECTED_NO_MATCH, "process name is outside the rule", attributes=negative),
            make("near-miss-" + rule.rule_id, FixtureLabel.NEAR_MISS, "encoded token is only a prefix-like near miss", attributes=near_miss),
        )
    if rule.rule_id.endswith("cloud-privileged-identity"):
        return (
            make("positive-" + rule.rule_id, FixtureLabel.EXPECTED_MATCH, "privileged identity action and success match"),
            make("negative-" + rule.rule_id, FixtureLabel.EXPECTED_NO_MATCH, "same action was denied", outcome="denied"),
            make("near-miss-" + rule.rule_id, FixtureLabel.NEAR_MISS, "similar identity action is not the exact action", action="UpdateUser"),
        )
    if rule.rule_id.endswith("mcp-privileged-tool"):
        return (
            make("positive-" + rule.rule_id, FixtureLabel.EXPECTED_MATCH, "privileged MCP deploy was allowed"),
            make("negative-" + rule.rule_id, FixtureLabel.EXPECTED_NO_MATCH, "unprivileged MCP object", object_ref="read_tool"),
            make("near-miss-" + rule.rule_id, FixtureLabel.NEAR_MISS, "tool action is close but not deploy", action="preview"),
        )
    return (
        make("positive-" + rule.rule_id, FixtureLabel.EXPECTED_MATCH, "denied privileged runner capability"),
        make("negative-" + rule.rule_id, FixtureLabel.EXPECTED_NO_MATCH, "ordinary runner capability", attributes={"capability": "read_only"}),
        make("near-miss-" + rule.rule_id, FixtureLabel.NEAR_MISS, "same capability was allowed", outcome="allowed"),
    )


def _correlation_rule() -> tuple[DetectionRule, Any]:
    definition: dict[str, Any] = {
        "rule_id": "secscan-v03-mcp-admin-correlation",
        "version": 1,
        "rule_type": DetectionRuleType.COUNT_OVER_WINDOW.value,
        "predicates": {"action": "admin_call", "outcome": "allowed"},
        "correlation_keys": ("actor", "target"),
        "window_seconds": 120,
        "threshold": 2,
    }
    digest = content_digest(definition)
    rule_id = str(definition["rule_id"])
    predicates = dict(definition["predicates"])
    correlation_keys = tuple(str(item) for item in definition["correlation_keys"])
    version = DetectionRuleVersion(
        rule_id=rule_id,
        version=1,
        title="SecScan bounded MCP admin-call correlation",
        rule_type=DetectionRuleType.COUNT_OVER_WINDOW,
        content_digest=digest,
        source="secscan-owned",
        source_reference="analysis/src/secscan/platform/detection_response/qualification.py",
        supported_source_families=("mcp_a2a_gateway",),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        predicates=predicates,
        correlation_keys=correlation_keys,
        window_seconds=120,
        threshold=2,
    )
    rule = DetectionRule(rule_id=version.rule_id, name=version.title, versions=(version,), active_version=1)
    from .domain import DetectionPlan, stable_id

    plan = DetectionPlan(
        plan_id=stable_id("PLAN-", version.rule_id, version.version, digest),
        rule_id=version.rule_id,
        rule_version=1,
        rule_type=version.rule_type,
        content_digest=digest,
        event_schema="OCSF",
        supported_source_families=version.supported_source_families,
        predicates=version.predicates,
        correlation_keys=version.correlation_keys,
        window_seconds=version.window_seconds,
        threshold=version.threshold,
    )
    return rule, plan


def run_campaign() -> dict[str, Any]:
    """Run all local qualification assertions and return sanitized details."""

    scope = Scope(tenant="tenant-v03", case="case-detection-response", target="agent-platform-v03")
    plane = SecurityEventPlane()
    ingestor = BoundedSecurityEventIngestor(plane, scope=scope)
    def clock() -> datetime:
        return QUALIFICATION_NOW
    detector = DetectionEngine(ingestor, scope=scope, clock=clock)
    owned_rules = load_owned_rules()
    for rule, plan in owned_rules:
        detector.register_rule(rule, plan=plan)
    correlation_rule, correlation_plan = _correlation_rule()
    detector.register_rule(correlation_rule, plan=correlation_plan)

    baseline_scope = Scope(tenant="tenant-v03", case="case-v03-benign-baseline", target="agent-platform-v03")
    baseline_plane = SecurityEventPlane()
    baseline_ingestor = BoundedSecurityEventIngestor(baseline_plane, scope=baseline_scope)
    baseline_detector = DetectionEngine(baseline_ingestor, scope=baseline_scope, clock=clock)
    for rule, plan in owned_rules:
        baseline_detector.register_rule(rule, plan=plan)
    baseline_events = (
        _event(
            baseline_scope,
            "baseline-endpoint-normal",
            source_family="endpoint_fixture",
            event_class=EventClass.ENDPOINT_ACTIVITY,
            action="read",
            outcome="allowed",
            object_ref="file",
            attributes={"process": {"name": "cmd", "command_line": "dir"}},
        ),
        _event(
            baseline_scope,
            "baseline-cloud-normal",
            source_family="cloud_audit_fixture",
            event_class=EventClass.CLOUD_AUDIT_ACTIVITY,
            action="ListBuckets",
            outcome="success",
            object_ref="inventory",
        ),
        _event(
            baseline_scope,
            "baseline-mcp-normal",
            source_family="mcp_a2a_gateway",
            event_class=EventClass.MCP_ACTIVITY,
            action="preview",
            outcome="allowed",
            object_ref="read_tool",
        ),
        _event(
            baseline_scope,
            "baseline-runner-normal",
            source_family="edge_runner",
            event_class=EventClass.CAPABILITY_DECISION,
            action="execute",
            outcome="allowed",
            object_ref="runner",
            attributes={"capability": "read_only"},
        ),
    )
    for event in baseline_events:
        baseline_ingestor.ingest(event, scope=baseline_scope)
    baseline_runs = [baseline_detector.run(rule, scope=baseline_scope) for rule, _plan in owned_rules]
    baseline_signal_count = sum(len(run.signal_ids) for run in baseline_runs)
    baseline_incident_count = len(IncidentAdjudicator(baseline_detector, scope=baseline_scope).incidents(scope=baseline_scope))
    if baseline_signal_count or baseline_incident_count:
        raise AssertionError("benign baseline created detection signals or incidents")

    integrated_events = (
        _event(
            scope,
            "integrated-endpoint",
            source_family="endpoint_fixture",
            event_class=EventClass.ENDPOINT_ACTIVITY,
            action="execute",
            outcome="allowed",
            object_ref="process",
            attributes={"process": {"name": "powershell", "command_line": "-encoded command"}},
        ),
        _event(
            scope,
            "integrated-cloud",
            source_family="cloud_audit_fixture",
            event_class=EventClass.CLOUD_AUDIT_ACTIVITY,
            action="CreateAccessKey",
            outcome="success",
            object_ref="identity",
        ),
        _event(
            scope,
            "integrated-mcp",
            source_family="mcp_a2a_gateway",
            event_class=EventClass.MCP_ACTIVITY,
            action="deploy",
            outcome="allowed",
            object_ref="privileged_tool",
        ),
        _event(
            scope,
            "integrated-runner",
            source_family="edge_runner",
            event_class=EventClass.CAPABILITY_DECISION,
            action="execute",
            outcome="denied",
            object_ref="runner",
            attributes={"capability": "privileged_runner"},
        ),
        _event(
            scope,
            "correlation-1",
            source_family="mcp_a2a_gateway",
            event_class=EventClass.MCP_ACTIVITY,
            action="admin_call",
            outcome="allowed",
        ),
        _event(
            scope,
            "correlation-2",
            source_family="mcp_a2a_gateway",
            event_class=EventClass.MCP_ACTIVITY,
            action="admin_call",
            outcome="allowed",
            occurred_at=QUALIFICATION_NOW + timedelta(seconds=30),
        ),
    )
    stale_occurred_at = QUALIFICATION_NOW - timedelta(days=2)
    stale_event = _event(
        scope,
        "integrated-stale",
        source_family="endpoint_fixture",
        event_class=EventClass.ENDPOINT_ACTIVITY,
        action="historical",
        outcome="allowed",
        object_ref="historical-object",
        attributes={"process": {"name": "cmd", "command_line": "plain command"}},
        occurred_at=stale_occurred_at,
    )
    campaign_events = integrated_events + (stale_event,)
    for event in campaign_events:
        ingestor.ingest(event, scope=scope)
    duplicate = ingestor.ingest(integrated_events[0], scope=scope)
    if not duplicate.duplicate:
        raise AssertionError("event replay was not idempotent")

    metrics = []
    mutation_inputs: list[object] = []
    for rule, _plan in owned_rules:
        fixtures = _fixtures(scope, rule)
        metrics.append(DetectionEvaluator().evaluate(rule, fixtures))
        mutation_inputs.append((rule.active.model_dump(mode="json"), {"mutation": "predicate_changed"}))
    runs = [detector.run(rule, scope=scope) for rule, _plan in owned_rules]
    correlation_run = detector.run(correlation_rule, scope=scope)
    all_signals = detector.signals(scope=scope)
    if len(runs) != 4 or not all(run.signal_ids for run in runs) or not correlation_run.signal_ids:
        raise AssertionError("integrated detection baseline did not emit the expected signals")

    hunt_engine = ThreatHuntEngine(ingestor, detector, clock=clock)
    hunt_hypothesis = HuntHypothesis(
        hypothesis_id="HYP-V03-MCP-1",
        scope=scope,
        question="Was a privileged MCP action corroborated by bounded source events?",
        entity_keys=("actor", "target", "object"),
        supporting_signal_ids=tuple(runs[2].signal_ids),
    )
    hunt_plan = HuntPlan(
        plan_id="HUNT-PLAN-V03-MCP-1",
        hypothesis_id=hunt_hypothesis.hypothesis_id,
        scope=scope,
        window_start=QUALIFICATION_NOW - timedelta(minutes=1),
        window_end=QUALIFICATION_NOW + timedelta(minutes=2),
        query={"event": {"action": "deploy"}, "signal_ids": list(runs[2].signal_ids)},
        exit_criteria="one scoped deploy event and one matching signal",
    )
    hunt_result = hunt_engine.run(hunt_hypothesis, hunt_plan)
    if not hunt_result.supporting_evidence_refs:
        raise AssertionError("hunt did not preserve evidence references")
    stale_hunt_result = hunt_engine.run(
        HuntHypothesis(
            hypothesis_id="HYP-V03-STALE-1",
            scope=scope,
            question="Does the bounded current window contain the historical event?",
            entity_keys=("actor",),
        ),
        HuntPlan(
            plan_id="HUNT-PLAN-V03-STALE-1",
            hypothesis_id="HYP-V03-STALE-1",
            scope=scope,
            window_start=QUALIFICATION_NOW - timedelta(minutes=1),
            window_end=QUALIFICATION_NOW + timedelta(minutes=2),
            query={"event": {"action": "historical", "object": "historical-object"}},
            exit_criteria="historical events outside the bounded window are not current evidence",
        ),
    )
    if stale_hunt_result.disposition != HuntDisposition.REFUTES or stale_hunt_result.event_ids:
        raise AssertionError("stale event escaped the bounded hunt window")

    source_signal_ids = tuple(dict.fromkeys(runs[2].signal_ids + correlation_run.signal_ids))
    incident_hypothesis = IncidentHypothesis(
        hypothesis_id="INC-HYP-V03-MCP-1",
        scope=scope,
        question="Did the bounded evidence support an operational privileged MCP incident?",
        source_signal_ids=source_signal_ids,
        affected_entities=("agent-v03", "privileged_tool", scope.target_id),
    )
    canonical_claims = {
        "CLM-V03-MCP-1": Claim(
            claim_id=ClaimId("CLM-V03-MCP-1"),
            engagement_id=EngagementId(scope.case_id),
            agent_id=AgentId("AGT-V03-ADJUDICATION"),
            agent_run_id=AgentRunId("RUN-V03-ADJUDICATION"),
            observation_ids=[ObservationId("OBS-V03-MCP-1")],
            evidence_ids=[EvidenceId("EVID-V03-MCP-1")],
            statement="The bounded MCP evidence supports the operational incident hypothesis.",
            confidence=Confidence.HIGH,
            uncertainty="Synthetic qualification claim; not a calibrated production assertion.",
        )
    }
    adjudicator = IncidentAdjudicator(
        detector,
        scope=scope,
        canonical_adjudicator_ids=("human-security-adjudicator",),
        canonical_claims=canonical_claims,
        canonical_claim_evidence_refs={
            "CLM-V03-MCP-1": tuple(sorted(set(hunt_result.supporting_evidence_refs)))
        },
        clock=clock,
    )
    incident = adjudicator.adjudicate(
        incident_hypothesis,
        supporting_claim_ids=("CLM-V03-MCP-1",),
        supporting_evidence_refs=tuple(sorted(set(hunt_result.supporting_evidence_refs))),
        decided_by="human-security-adjudicator",
        reason="Two independent bounded detector paths and retained event references support the hypothesis.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        observation_ids=("OBS-V03-MCP-1",),
    )
    canonical_approvals: dict[str, HumanApproval] = {}
    proposal_service = ResponseProposalService(
        OpaResponsePolicy(),
        scope=scope,
        canonical_incidents={incident.incident_id: incident},
        canonical_approvals=canonical_approvals,
        canonical_approver_ids=("human-operator-v03",),
        clock=clock,
    )
    proposal = proposal_service.propose(
        incident,
        action=ResponseAction.BLOCK_TOOL,
        reason="Bounded proposal to pause the implicated privileged tool for human review.",
        expected_impact="Prevent further use of the named tool in this case.",
        risk="Potential interruption of legitimate agent work.",
        rollback_plan="Human operator removes the tool restriction after review; no action is executed by v0.3.",
        expires_at=QUALIFICATION_NOW + timedelta(hours=1),
    )
    capability_request = proposal_service.capability_request(proposal)
    approval = HumanApproval(
        approval_id="APR-V03-1",
        proposal_id=proposal.proposal_id,
        proposal_digest=proposal.proposal_digest,
        scope=scope,
        target_id=proposal.target_id,
        action=proposal.action,
        decision=HumanApprovalState.APPROVED,
        decided_by="human-operator-v03",
        decided_at=QUALIFICATION_NOW,
        source="human_operator",
        expires_at=QUALIFICATION_NOW + timedelta(hours=1),
    )
    canonical_approvals[approval.approval_id] = approval
    approved = proposal_service.approve(approval)
    if approved.human_approval_state != HumanApprovalState.APPROVED or approved.authorized_action_executed:
        raise AssertionError("human approval did not remain a non-executing proposal")
    try:
        proposal_service.execute(proposal.proposal_id, scope=scope)
    except ResponseExecutionDisabled:
        pass
    else:
        raise AssertionError("v0.3 exposed an action execution path")

    replay_runs = [detector.run(rule, scope=scope) for rule, _plan in owned_rules]
    if [run.signal_ids for run in replay_runs] != [run.signal_ids for run in runs]:
        raise AssertionError("detection replay changed signal identities")

    other_scope = Scope(tenant="tenant-other", case="case-other", target="agent-other")
    cross_scope_checks = 0
    for callback in (
        lambda: ingestor.events(scope=other_scope),
        lambda: detector.signals(scope=other_scope),
        lambda: proposal_service.proposals(scope=other_scope),
    ):
        try:
            callback()
        except DetectionScopeError:
            cross_scope_checks += 1
    if cross_scope_checks != 3:
        raise AssertionError("cross-scope access did not fail closed")

    try:
        adjudicator.adjudicate(
            IncidentHypothesis(
                hypothesis_id="INC-HYP-NO-EVIDENCE",
                scope=scope,
                question="unsupported",
                source_signal_ids=(runs[2].signal_ids[0],),
                affected_entities=(scope.target_id,),
            ),
            supporting_claim_ids=(),
            supporting_evidence_refs=(),
            decided_by="agent-opinion",
            reason="untrusted assertion",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )
    except (AdjudicationRefused, DetectionScopeError):
        pass
    else:
        raise AssertionError("unsupported evidence created an incident")

    try:
        proposal_service.approve(
            HumanApproval(
                approval_id="APR-V03-1",
                proposal_id=proposal.proposal_id,
                proposal_digest=proposal.proposal_digest,
                scope=scope,
                target_id=proposal.target_id,
                action=proposal.action,
                decision=HumanApprovalState.APPROVED,
                decided_by="model-output",
                decided_at=QUALIFICATION_NOW,
                source="llm",
                expires_at=QUALIFICATION_NOW + timedelta(hours=1),
            )
        )
    except ResponseAuthorizationError:
        pass
    else:
        raise AssertionError("untrusted approval source was accepted")

    tampered = integrated_events[0].model_copy(update={"event_id": "SE-forged"})
    try:
        plane.ingest(tampered)
    except EventIdentityConflict:
        pass
    else:
        raise AssertionError("forged event identity was accepted")

    try:
        detector.register_rule(owned_rules[0][0], plan=owned_rules[0][1].model_copy(update={"content_digest": "tampered"}))
    except DetectionInputError:
        pass
    else:
        raise AssertionError("tampered rule digest was accepted")

    tracemalloc.start()
    timings: list[float] = []
    benchmark_start = perf_counter()
    for _ in range(5):
        start = perf_counter()
        detector.run(owned_rules[0][0], scope=scope)
        timings.append((perf_counter() - start) * 1000)
    benchmark_duration_seconds = perf_counter() - benchmark_start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    ordered_timings = sorted(timings)
    p50 = ordered_timings[len(ordered_timings) // 2]
    p95 = ordered_timings[min(len(ordered_timings) - 1, int(len(ordered_timings) * 0.95))]
    benchmark_input_events = sum(
        1 for event in campaign_events if event.source_family in owned_rules[0][1].supported_source_families
    ) * 5
    benchmark_rule_evaluations = benchmark_input_events
    performance = {
        "events": len(campaign_events),
        "benchmark_iterations": 5,
        "benchmark_duration_seconds": round(benchmark_duration_seconds, 6),
        "event_rate_per_second": round(benchmark_input_events / max(benchmark_duration_seconds, 0.000001), 3),
        "rule_evaluations": len(detector.evaluations(scope=scope)),
        "rule_evaluation_attempts": benchmark_rule_evaluations,
        "rule_evaluation_rate_per_second": round(benchmark_rule_evaluations / max(benchmark_duration_seconds, 0.000001), 3),
        "p50_ms": round(p50, 3),
        "p95_ms": round(p95, 3),
        "peak_traced_memory_bytes": peak,
        "deduplication": "one duplicate replay accepted without a second event",
        "measurement_scope": "synthetic local fixture only",
    }

    return {
        "status": "PASS",
        "scope": scope.model_dump(mode="json", by_alias=True),
        "owned_rule_count": len(owned_rules),
        "benign_baseline": "PASS",
        "baseline_signal_count": baseline_signal_count,
        "baseline_incident_count": baseline_incident_count,
        "signal_count": len(all_signals),
        "correlation_signal_count": len(correlation_run.signal_ids),
        "hunt_disposition": hunt_result.disposition.value,
        "incident_state": incident.state.value,
        "proposal_id": proposal.proposal_id,
        "capability_request_id": capability_request.request_id,
        "human_approval_state": approved.human_approval_state.value,
        "opa_response_authority": "PASS",
        "authorized_action_executed": "NO",
        "metrics": [metric.model_dump(mode="json") for metric in metrics],
        "mutation_digests": [content_digest(item) for item in mutation_inputs],
        "replay": "PASS",
        "cross_scope_fail_closed": "PASS",
        "stale_event_window_bound": "PASS",
        "adversarial_controls": "PASS",
        "performance": performance,
    }
