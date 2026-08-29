"""Public-interface qualification tests for the v0.3 foundation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from secscan.platform.continuous_security.events import EventClass, EventIdentityConflict, SecurityEventPlane
from secscan.platform.detection_response import (
    MAX_CORRELATION_WINDOW_SECONDS,
    MAX_HUNT_QUERY_BYTES,
    SUPPORTED_OCSF_VERSION,
    AdjudicationRefused,
    ApprovalRequiredPolicy,
    BoundedSecurityEventIngestor,
    DetectionEngine,
    DetectionInputError,
    DetectionPlan,
    DetectionRule,
    DetectionRuleType,
    DetectionRuleVersion,
    DetectionScopeError,
    HumanApproval,
    HumanApprovalState,
    HuntDisposition,
    HuntHypothesis,
    HuntPlan,
    IncidentAdjudicator,
    IncidentHypothesis,
    OpaDecision,
    ResponseAction,
    ResponseAuthorizationError,
    ResponseExecutionDisabled,
    ResponseProposalService,
    Scope,
    SigmaSubsetImporter,
    ThreatHuntEngine,
    run_campaign,
)
from secscan.platform.domain.common import Confidence, Severity
from secscan.platform.domain.evidence import Claim

NOW = datetime(2026, 1, 1, 12, tzinfo=UTC)


def _raw(scope: Scope, record_id: str, **updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "source": "test-fixture",
        "source_record_id": record_id,
        "source_digest": "digest-" + record_id,
        "source_system": "test-fixture",
        "collector_version": "test-v1",
        "source_type": "endpoint_fixture",
        "source_family": "endpoint_fixture",
        "event_class": EventClass.ENDPOINT_ACTIVITY.value,
        "ocsf_class": EventClass.ENDPOINT_ACTIVITY.value,
        "ocsf_version": SUPPORTED_OCSF_VERSION,
        "occurred_at": NOW,
        "observed_at": NOW + timedelta(seconds=1),
        "ingested_at": NOW + timedelta(minutes=1),
        "tenant": scope.tenant_id,
        "case": scope.case_id,
        "target": scope.target_id,
        "actor": "agent-test",
        "object": "process",
        "action": "execute",
        "outcome": "allowed",
        "raw_evidence_ref": "metadata://test/" + record_id,
        "normalization_version": "security-events-v2",
        "attributes": {"process": {"name": "powershell", "command_line": "encoded"}},
    }
    payload.update(updates)
    return payload


def _claim(scope: Scope, claim_id: str, *, evidence_id: str = "evidence://test") -> Claim:
    return Claim(
        claim_id=claim_id,
        engagement_id=scope.case_id,
        agent_id="agent-test",
        agent_run_id="agent-run-test",
        observation_ids=["observation://test"],
        evidence_ids=[evidence_id],
        statement="canonical test claim",
        confidence=Confidence.HIGH,
        uncertainty="fixture-only claim",
    )


def test_event_ingest_parses_iso_time_and_replays_without_duplication() -> None:
    scope = Scope(tenant="tenant-test", case="case-test", target="target-test")
    plane = SecurityEventPlane()
    ingestor = BoundedSecurityEventIngestor(plane, scope=scope)
    raw = _raw(scope, "record-1")
    raw["occurred_at"] = NOW.isoformat()
    raw["observed_at"] = (NOW + timedelta(seconds=1)).isoformat()
    first = ingestor.ingest_raw(raw, scope=scope)
    second = ingestor.ingest_raw(raw, scope=scope)
    assert first.created and second.duplicate
    assert first.event.fingerprint == second.event.fingerprint
    with pytest.raises(EventIdentityConflict):
        plane.ingest(first.event.model_copy(update={"event_id": "SE-forged"}))


def test_sigma_subset_refuses_boolean_and_malformed_tag_constructs() -> None:
    importer = SigmaSubsetImporter()
    with pytest.raises(DetectionInputError):
        importer.import_rule(
            {
                "title": "unsupported",
                "logsource": {"category": "process_creation"},
                "detection": {"selection": {"action": "x"}, "filter": {"outcome": "y"}, "condition": "selection and filter"},
            }
        )
    with pytest.raises(DetectionInputError):
        importer.import_rule(
            {
                "title": "forged tag",
                "logsource": {"category": "process_creation"},
                "detection": {"selection": {"action": "x"}, "condition": "selection"},
                "tags": ["attack.not-a-technique"],
            }
        )
    with pytest.raises(DetectionInputError):
        importer.import_rule(
            {
                "title": "regex is outside the bounded subset",
                "logsource": {"category": "process_creation"},
                "detection": {
                    "selection": {"process.command_line|re": ".*powershell.*"},
                    "condition": "selection",
                },
            }
        )


@pytest.mark.parametrize(
    ("document", "_label"),
    [
        (
            "title: one\ntitle: two\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    action: execute\n  condition: selection\n",
            "duplicate YAML keys",
        ),
        (
            {
                "title": "unknown logsource field",
                "logsource": {"category": "process_creation", "unbounded": "value"},
                "detection": {"selection": {"action": "execute"}, "condition": "selection"},
            },
            "unknown logsource field",
        ),
        (
            {
                "title": "non-string id",
                "id": 42,
                "logsource": {"category": "process_creation"},
                "detection": {"selection": {"action": "execute"}, "condition": "selection"},
            },
            "non-string id",
        ),
        (
            {
                "title": "fractional version",
                "x_secscan_version": 1.5,
                "logsource": {"category": "process_creation"},
                "detection": {"selection": {"action": "execute"}, "condition": "selection"},
            },
            "fractional version",
        ),
        (
            {
                "title": "null selector",
                "logsource": {"category": "process_creation"},
                "detection": {"selection": {"action": None}, "condition": "selection"},
            },
            "null selector",
        ),
        (
            {
                "title": "unknown SecScan extension",
                "x_secscan_unvalidated": "ignored",
                "logsource": {"category": "process_creation"},
                "detection": {"selection": {"action": "execute"}, "condition": "selection"},
            },
            "unknown SecScan extension",
        ),
        (
            {
                "title": "ambiguous logsource",
                "logsource": {"category": "process_creation", "product": "aws"},
                "detection": {"selection": {"action": "execute"}, "condition": "selection"},
            },
            "ambiguous logsource",
        ),
        (
            {
                "title": "empty rationale",
                "x_secscan_rationale": None,
                "logsource": {"category": "process_creation"},
                "detection": {"selection": {"action": "execute"}, "condition": "selection"},
            },
            "empty rationale",
        ),
    ],
)
def test_sigma_subset_refuses_ambiguous_or_malformed_inputs(document: object, _label: str) -> None:
    with pytest.raises(DetectionInputError):
        SigmaSubsetImporter().import_rule(document)  # type: ignore[arg-type]


def test_detection_engine_requires_scope_and_digest_binding() -> None:
    scope = Scope(tenant="tenant-test", case="case-test", target="target-test")
    plane = SecurityEventPlane()
    ingestor = BoundedSecurityEventIngestor(plane, scope=scope)
    ingestor.ingest_raw(_raw(scope, "record-2"), scope=scope)
    def clock() -> datetime:
        return NOW

    engine = DetectionEngine(ingestor, scope=scope, clock=clock)
    version = DetectionRuleVersion(
        rule_id="rule-test",
        version=1,
        title="test rule",
        rule_type=DetectionRuleType.EVENT_MATCH,
        content_digest="digest-test",
        source="test",
        source_reference="test",
        supported_source_families=("endpoint_fixture",),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        predicates={"action": "execute"},
    )
    rule = DetectionRule(rule_id="rule-test", name="test rule", versions=(version,), active_version=1)
    run = engine.run(rule, scope=scope)
    assert run.signal_ids
    invalid_version = version.model_dump()
    invalid_version["event_schema"] = "JSON"
    with pytest.raises(ValueError, match="only the OCSF event schema"):
        DetectionRuleVersion(**invalid_version)
    invalid_plan = {
        "plan_id": "plan-invalid-schema",
        "rule_id": version.rule_id,
        "rule_version": version.version,
        "rule_type": version.rule_type,
        "content_digest": version.content_digest,
        "event_schema": "JSON",
        "supported_source_families": version.supported_source_families,
        "predicates": version.predicates,
    }
    with pytest.raises(ValueError, match="only the OCSF event schema"):
        DetectionPlan(**invalid_plan)
    with pytest.raises(DetectionScopeError):
        engine.signals(scope=Scope(tenant="other", case="other", target="other"))
    with pytest.raises(DetectionInputError):
        engine.register_rule(
            rule,
            plan=DetectionPlan(
                plan_id="plan-wrong",
                rule_id="rule-test",
                rule_version=1,
                rule_type=DetectionRuleType.EVENT_MATCH,
                content_digest="wrong",
                event_schema="OCSF",
                supported_source_families=("endpoint_fixture",),
                predicates={"action": "execute"},
            ),
        )
    unsupported_version = version.model_copy(
        update={"rule_id": "rule-unsupported-modifier", "predicates": {"action|re": ".*execute.*"}}
    )
    unsupported_rule = DetectionRule(
        rule_id="rule-unsupported-modifier",
        name="unsupported modifier",
        versions=(unsupported_version,),
        active_version=1,
    )
    with pytest.raises(DetectionInputError, match="unsupported predicate modifier"):
        engine.run(unsupported_rule, scope=scope)
    with pytest.raises(DetectionInputError):
        engine.register_rule(
            rule,
            plan=DetectionPlan(
                plan_id="plan-substitution",
                rule_id="rule-test",
                rule_version=1,
                rule_type=DetectionRuleType.EVENT_MATCH,
                content_digest="digest-test",
                event_schema="OCSF",
                supported_source_families=("endpoint_fixture",),
                predicates={"action": "execute"},
            ),
        )


def test_detection_replay_does_not_mutate_canonical_objects() -> None:
    scope = Scope(tenant="tenant-test", case="case-test", target="target-test")
    plane = SecurityEventPlane()
    ingestor = BoundedSecurityEventIngestor(plane, scope=scope)
    ingestor.ingest_raw(_raw(scope, "record-replay"), scope=scope)
    timestamps = iter(NOW + timedelta(seconds=offset) for offset in range(20))
    engine = DetectionEngine(ingestor, scope=scope, clock=lambda: next(timestamps))
    version = DetectionRuleVersion(
        rule_id="rule-replay",
        version=1,
        title="replay rule",
        rule_type=DetectionRuleType.EVENT_MATCH,
        content_digest="digest-replay",
        source="test",
        source_reference="test",
        supported_source_families=("endpoint_fixture",),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        predicates={"action": "execute"},
    )
    rule = DetectionRule(rule_id="rule-replay", name="replay rule", versions=(version,), active_version=1)
    first_run = engine.run(rule, scope=scope)
    first_evaluation = engine.evaluations(scope=scope)[0]
    first_signal = engine.signals(scope=scope)[0]
    second_run = engine.run(rule, scope=scope)
    second_evaluation = engine.evaluations(scope=scope)[0]
    second_signal = engine.signals(scope=scope)[0]
    assert second_run == first_run
    assert second_evaluation == first_evaluation
    assert second_signal == first_signal


def test_incremental_detection_replay_does_not_rewrite_existing_signal() -> None:
    scope = Scope(tenant="tenant-test", case="case-test", target="target-test")
    plane = SecurityEventPlane()
    ingestor = BoundedSecurityEventIngestor(plane, scope=scope)
    ingestor.ingest_raw(_raw(scope, "record-incremental-match"), scope=scope)
    current_time = [NOW]
    engine = DetectionEngine(ingestor, scope=scope, clock=lambda: current_time[0])
    version = DetectionRuleVersion(
        rule_id="rule-incremental-replay",
        version=1,
        title="incremental replay rule",
        rule_type=DetectionRuleType.EVENT_MATCH,
        content_digest="digest-incremental-replay",
        source="test",
        source_reference="test",
        supported_source_families=("endpoint_fixture",),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        predicates={"action": "execute"},
    )
    rule = DetectionRule(
        rule_id="rule-incremental-replay",
        name="incremental replay rule",
        versions=(version,),
        active_version=1,
    )
    first_run = engine.run(rule, scope=scope)
    first_signal = engine.get_signal(first_run.signal_ids[0], scope=scope)
    current_time[0] = NOW + timedelta(hours=1)
    ingestor.ingest_raw(_raw(scope, "record-incremental-no-match", action="inspect"), scope=scope)
    second_run = engine.run(rule, scope=scope)
    assert second_run.run_id != first_run.run_id
    assert engine.get_signal(first_signal.signal_id, scope=scope) == first_signal


def test_rule_versions_are_unique_and_explicit_runs_bind_the_selected_plan() -> None:
    scope = Scope(tenant="tenant-test", case="case-test", target="target-test")
    plane = SecurityEventPlane()
    ingestor = BoundedSecurityEventIngestor(plane, scope=scope)
    ingestor.ingest_raw(_raw(scope, "record-versioned"), scope=scope)

    version_one = DetectionRuleVersion(
        rule_id="rule-versioned",
        version=1,
        title="version one",
        rule_type=DetectionRuleType.EVENT_MATCH,
        content_digest="digest-version-one",
        source="test",
        source_reference="test",
        supported_source_families=("endpoint_fixture",),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        predicates={"action": "execute"},
    )
    version_two = version_one.model_copy(
        update={"version": 2, "title": "version two", "content_digest": "digest-version-two", "predicates": {"action": "never"}}
    )
    rule = DetectionRule(
        rule_id="rule-versioned",
        name="versioned rule",
        versions=(version_one, version_two),
        active_version=2,
    )
    engine = DetectionEngine(ingestor, scope=scope, clock=lambda: NOW)
    active_run = engine.run(rule, scope=scope)
    selected_old_run = engine.run(rule, scope=scope, version=1)
    selected_old_by_id = engine.run("rule-versioned", scope=scope, version=1)
    assert active_run.signal_ids == ()
    assert selected_old_run.signal_ids == selected_old_by_id.signal_ids
    assert selected_old_run.signal_ids
    with pytest.raises(DetectionInputError):
        engine.run("rule-versioned", scope=scope)

    version_two.predicates["action"] = "tampered-after-binding"
    with pytest.raises(DetectionInputError):
        engine.run("rule-versioned", scope=scope, version=2)
    with pytest.raises(DetectionInputError):
        engine.register_rule(
            rule,
            version_number=1,
            plan=DetectionPlan(
                plan_id="plan-substituted",
                rule_id="rule-versioned",
                rule_version=1,
                rule_type=DetectionRuleType.EVENT_MATCH,
                content_digest="digest-version-one",
                event_schema="OCSF",
                supported_source_families=("endpoint_fixture",),
                predicates={"action": "tampered"},
            ),
        )
    with pytest.raises(ValueError):
        DetectionRule(rule_id="rule-versioned", name="duplicate", versions=(version_one, version_one), active_version=1)


def test_correlation_and_hunt_bounds_reject_unbounded_inputs() -> None:
    with pytest.raises(ValueError):
        DetectionRuleVersion(
            rule_id="rule-correlation-invalid",
            version=1,
            title="invalid correlation",
            rule_type=DetectionRuleType.COUNT_OVER_WINDOW,
            content_digest="digest-correlation-invalid",
            source="test",
            source_reference="test",
            supported_source_families=("endpoint_fixture",),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            predicates={"action": "execute"},
            correlation_keys=("actor",),
            window_seconds=0,
            threshold=2,
        )
    with pytest.raises(ValueError):
        DetectionRuleVersion(
            rule_id="rule-correlation-too-wide",
            version=1,
            title="too-wide correlation",
            rule_type=DetectionRuleType.COUNT_OVER_WINDOW,
            content_digest="digest-correlation-too-wide",
            source="test",
            source_reference="test",
            supported_source_families=("endpoint_fixture",),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            predicates={"action": "execute"},
            correlation_keys=("actor",),
            window_seconds=MAX_CORRELATION_WINDOW_SECONDS + 1,
            threshold=2,
        )
    scope = Scope(tenant="tenant-test", case="case-test", target="target-test")
    with pytest.raises(ValueError):
        HuntPlan(
            plan_id="unbounded-hunt",
            hypothesis_id="hypothesis",
            scope=scope,
            window_start=NOW,
            window_end=NOW + timedelta(minutes=1),
            query={"event": {"action": "execute"}},
            exit_criteria="bounded result",
            max_events=5001,
        )
    with pytest.raises(ValueError):
        HuntPlan(
            plan_id="oversized-hunt-query",
            hypothesis_id="hypothesis",
            scope=scope,
            window_start=NOW,
            window_end=NOW + timedelta(minutes=1),
            query={"event": {"action": "execute"}, "padding": "x" * MAX_HUNT_QUERY_BYTES},
            exit_criteria="bounded result",
        )


def test_correlation_does_not_group_events_with_missing_keys() -> None:
    scope = Scope(tenant="tenant-test", case="case-test", target="target-test")
    plane = SecurityEventPlane()
    ingestor = BoundedSecurityEventIngestor(plane, scope=scope)
    for record_id, actor in (("correlation-missing-1", "actor-one"), ("correlation-missing-2", "actor-two")):
        ingestor.ingest_raw(
            _raw(scope, record_id, actor=actor, action="admin_call"),
            scope=scope,
        )
    version = DetectionRuleVersion(
        rule_id="rule-missing-correlation-key",
        version=1,
        title="missing correlation key",
        rule_type=DetectionRuleType.COUNT_OVER_WINDOW,
        content_digest="digest-missing-correlation-key",
        source="test",
        source_reference="test",
        supported_source_families=("endpoint_fixture",),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        predicates={"action": "admin_call"},
        correlation_keys=("attributes.missing_key",),
        window_seconds=60,
        threshold=2,
    )
    rule = DetectionRule(
        rule_id="rule-missing-correlation-key",
        name="missing correlation key",
        versions=(version,),
        active_version=1,
    )
    run = DetectionEngine(ingestor, scope=scope, clock=lambda: NOW).run(rule, scope=scope)
    assert run.signal_ids == ()


def test_v03_campaign_qualifies_the_complete_non_executing_chain() -> None:
    receipt = run_campaign()
    assert receipt["status"] == "PASS"
    assert receipt["owned_rule_count"] == 4
    assert receipt["benign_baseline"] == "PASS"
    assert receipt["baseline_incident_count"] == 0
    assert receipt["hunt_disposition"] == "SUPPORTS"
    assert receipt["incident_state"] == "CONFIRMED"
    assert receipt["human_approval_state"] == "APPROVED"
    assert receipt["authorized_action_executed"] == "NO"
    assert receipt["cross_scope_fail_closed"] == "PASS"


def test_event_boundary_rejects_malformed_spoofed_and_cross_scope_input_but_orders_late_arrivals() -> None:
    scope = Scope(tenant="tenant-test", case="case-test", target="target-test")
    plane = SecurityEventPlane()
    ingestor = BoundedSecurityEventIngestor(plane, scope=scope)

    with pytest.raises(ValueError):
        ingestor.ingest_raw({"event_class": EventClass.ENDPOINT_ACTIVITY.value}, scope=scope)
    with pytest.raises(EventIdentityConflict):
        ingestor.ingest_raw(_raw(scope, "record-spoofed", event_id="SE-not-derived"), scope=scope)
    with pytest.raises(DetectionInputError):
        ingestor.ingest_raw(_raw(scope, "record-unsupported", source_family="spoofed-source"), scope=scope)
    with pytest.raises(DetectionInputError):
        ingestor.ingest_raw(_raw(scope, "record-malformed", action=None), scope=scope)
    with pytest.raises(DetectionInputError, match="OCSF class"):
        ingestor.ingest_raw(
            _raw(scope, "record-class-mismatch", ocsf_class=EventClass.CLOUD_AUDIT_ACTIVITY.value),
            scope=scope,
        )
    with pytest.raises(DetectionScopeError):
        ingestor.ingest_raw(
            _raw(Scope(tenant="tenant-other", case="case-other", target="target-other"), "record-cross"),
            scope=scope,
        )

    late = _raw(scope, "record-late", occurred_at=NOW + timedelta(seconds=10), observed_at=NOW + timedelta(seconds=11), ordering_metadata={"sequence": 2})
    early = _raw(scope, "record-early", occurred_at=NOW, observed_at=NOW + timedelta(seconds=1), ordering_metadata={"sequence": 1})
    ingestor.ingest_raw(late, scope=scope)
    ingestor.ingest_raw(early, scope=scope)
    events = ingestor.events(scope=scope)
    assert [event.provenance.source_record_id for event in events] == ["record-early", "record-late"]
    assert events[-1].ordering_metadata == {"sequence": 2}


def test_hunt_and_incident_authority_require_scoped_evidence_and_adjudication() -> None:
    scope = Scope(tenant="tenant-test", case="case-test", target="target-test")
    plane = SecurityEventPlane()
    ingestor = BoundedSecurityEventIngestor(plane, scope=scope)
    ingestor.ingest_raw(_raw(scope, "record-hunt", action="deploy"), scope=scope)
    stale_occurred_at = NOW - timedelta(days=2)
    ingestor.ingest_raw(
        _raw(
            scope,
            "record-stale",
            action="historical",
            object="historical-object",
            occurred_at=stale_occurred_at,
            observed_at=stale_occurred_at + timedelta(seconds=1),
        ),
        scope=scope,
    )
    engine = DetectionEngine(ingestor, scope=scope, clock=lambda: NOW)
    version = DetectionRuleVersion(
        rule_id="rule-hunt",
        version=1,
        title="hunt rule",
        rule_type=DetectionRuleType.EVENT_MATCH,
        content_digest="digest-hunt",
        source="test",
        source_reference="test",
        supported_source_families=("endpoint_fixture",),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        predicates={"action": "deploy"},
    )
    rule = DetectionRule(rule_id="rule-hunt", name="hunt rule", versions=(version,), active_version=1)
    run = engine.run(rule, scope=scope)
    assert len(run.signal_ids) == 1
    stale_version = DetectionRuleVersion(
        rule_id="rule-stale-hunt",
        version=1,
        title="stale hunt rule",
        rule_type=DetectionRuleType.EVENT_MATCH,
        content_digest="digest-stale-hunt",
        source="test",
        source_reference="test",
        supported_source_families=("endpoint_fixture",),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        predicates={"action": "historical"},
    )
    stale_rule = DetectionRule(
        rule_id="rule-stale-hunt", name="stale hunt rule", versions=(stale_version,), active_version=1
    )
    stale_run = engine.run(stale_rule, scope=scope)
    assert len(stale_run.signal_ids) == 1

    current_signal = engine.get_signal(run.signal_ids[0], scope=scope)
    stale_signal = engine.get_signal(stale_run.signal_ids[0], scope=scope)
    composite_signal = current_signal.model_copy(
        update={
            "signal_id": "SIG-COMPOSITE-WINDOW",
            "source_signal_ids": (stale_signal.signal_id,),
            "raw_evidence_refs": tuple(
                sorted((*current_signal.raw_evidence_refs, *stale_signal.raw_evidence_refs))
            ),
        }
    )
    engine.bind_signal(composite_signal)

    hunt = ThreatHuntEngine(ingestor, engine, clock=lambda: NOW)
    hypothesis = HuntHypothesis(hypothesis_id="hunt-hyp", scope=scope, question="did deployment occur?", entity_keys=("actor",))
    plan = HuntPlan(
        plan_id="hunt-plan",
        hypothesis_id=hypothesis.hypothesis_id,
        scope=scope,
        window_start=NOW - timedelta(minutes=1),
        window_end=NOW + timedelta(minutes=1),
        query={"event": {"action": "deploy"}, "signal_ids": list(run.signal_ids), "evidence_refs": ["injected-ref"]},
        exit_criteria="one matching event",
    )
    result = hunt.run(hypothesis, plan)
    assert result.disposition == HuntDisposition.SUPPORTS
    assert "injected-ref" not in result.supporting_evidence_refs
    replay_times = iter((NOW, NOW + timedelta(seconds=1), NOW + timedelta(minutes=2), NOW + timedelta(minutes=3)))
    replay_hunt = ThreatHuntEngine(ingestor, engine, clock=lambda: next(replay_times))
    first_replay = replay_hunt.run(hypothesis, plan)
    second_replay = replay_hunt.run(hypothesis, plan)
    assert second_replay == first_replay
    stale_result = hunt.run(
        HuntHypothesis(
            hypothesis_id="stale-hunt-hyp",
            scope=scope,
            question="does the current window contain the historical event?",
            entity_keys=("actor",),
        ),
        HuntPlan(
            plan_id="stale-hunt-plan",
            hypothesis_id="stale-hunt-hyp",
            scope=scope,
            window_start=NOW - timedelta(hours=1),
            window_end=NOW + timedelta(hours=1),
            query={"event": {"action": "historical", "object": "historical-object"}},
            exit_criteria="exclude events outside the bounded current window",
        ),
    )
    assert stale_result.disposition == HuntDisposition.REFUTES
    assert stale_result.event_ids == ()
    assert stale_result.supporting_evidence_refs == ()
    stale_signal_result = hunt.run(
        HuntHypothesis(
            hypothesis_id="stale-signal-hunt-hyp",
            scope=scope,
            question="does the current window contain the historical signal?",
            entity_keys=("actor",),
        ),
        HuntPlan(
            plan_id="stale-signal-hunt-plan",
            hypothesis_id="stale-signal-hunt-hyp",
            scope=scope,
            window_start=NOW - timedelta(hours=1),
            window_end=NOW + timedelta(hours=1),
            query={"event": {"action": "historical"}, "signal_ids": list(stale_run.signal_ids)},
            exit_criteria="exclude signals whose source events are outside the bounded current window",
        ),
    )
    assert stale_signal_result.disposition == HuntDisposition.REFUTES
    assert stale_signal_result.signal_ids == ()
    assert stale_signal_result.supporting_evidence_refs == ()
    composite_result = hunt.run(
        HuntHypothesis(
            hypothesis_id="composite-signal-hunt-hyp",
            scope=scope,
            question="does a composite signal include stale source evidence?",
            entity_keys=("actor",),
        ),
        HuntPlan(
            plan_id="composite-signal-hunt-plan",
            hypothesis_id="composite-signal-hunt-hyp",
            scope=scope,
            window_start=NOW - timedelta(hours=1),
            window_end=NOW + timedelta(hours=1),
            query={"signal_ids": [composite_signal.signal_id]},
            exit_criteria="exclude composite signals with stale source events",
        ),
    )
    assert composite_result.disposition == HuntDisposition.REFUTES
    assert composite_result.signal_ids == ()
    with pytest.raises(DetectionInputError, match="hunt plan identity"):
        hunt.run(
            hypothesis,
            plan.model_copy(update={"window_end": NOW + timedelta(minutes=2)}),
        )
    with pytest.raises(DetectionScopeError):
        hunt.run(
            hypothesis.model_copy(update={"hypothesis_id": "different-hypothesis"}),
            plan,
        )
    with pytest.raises(DetectionInputError, match="hunt hypothesis identity"):
        hunt.run(
            hypothesis.model_copy(update={"question": "the question was changed"}),
            plan,
        )
    with pytest.raises(DetectionScopeError):
        hunt.results(scope=Scope(tenant="other", case="other", target="other"))
    with pytest.raises(DetectionScopeError):
        hunt.run(
            hypothesis,
            plan.model_copy(update={"scope": Scope(tenant="other", case="other", target="other")}),
        )

    evidence_ref = next(event.raw_evidence_ref for event in ingestor.events(scope=scope) if event.action == "deploy")
    adjudicator = IncidentAdjudicator(
        engine,
        scope=scope,
        canonical_adjudicator_ids=("human-adjudicator",),
        canonical_claims={
            "claim-1": _claim(scope, "claim-1", evidence_id=evidence_ref),
            "claim-contradiction": _claim(scope, "claim-contradiction", evidence_id=evidence_ref),
        },
        clock=lambda: NOW,
    )
    incident_hypothesis = IncidentHypothesis(
        hypothesis_id="incident-hyp",
        scope=scope,
        question="does evidence support an incident?",
        source_signal_ids=(composite_signal.signal_id,),
        affected_entities=(scope.target_id,),
    )
    with pytest.raises(AdjudicationRefused):
        adjudicator.adjudicate(
            incident_hypothesis.model_copy(update={"hypothesis_id": "incident-fabricated-evidence"}),
            supporting_claim_ids=("claim-1",),
            supporting_evidence_refs=("metadata://fabricated",),
            decided_by="human-adjudicator",
            reason="unbound evidence must not create an incident",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )
    unrelated_evidence_ref = next(
        event.raw_evidence_ref
        for event in ingestor.events(scope=scope)
        if event.raw_evidence_ref != evidence_ref and event.action == "historical"
    )
    with pytest.raises(AdjudicationRefused, match="supporting incident evidence"):
        adjudicator.adjudicate(
            incident_hypothesis.model_copy(update={"hypothesis_id": "incident-unrelated-claim-evidence"}),
            supporting_claim_ids=("claim-1",),
            supporting_evidence_refs=(unrelated_evidence_ref,),
            decided_by="human-adjudicator",
            reason="unrelated claim evidence must be refused",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )
    with pytest.raises(AdjudicationRefused):
        adjudicator.adjudicate(
            incident_hypothesis.model_copy(update={"hypothesis_id": "incident-fake-authority"}),
            supporting_claim_ids=("claim-1",),
            supporting_evidence_refs=(evidence_ref,),
            decided_by="human-not-registered",
            reason="unregistered authority must not create an incident",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )
    with pytest.raises(AdjudicationRefused):
        adjudicator.adjudicate(
            incident_hypothesis,
            supporting_claim_ids=(),
            supporting_evidence_refs=(),
            decided_by="agent-opinion",
            reason="unsupported",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )
    with pytest.raises(AdjudicationRefused):
        adjudicator.adjudicate(
            incident_hypothesis.model_copy(update={"hypothesis_id": "incident-unregistered-claim"}),
            supporting_claim_ids=("claim-not-registered",),
            supporting_evidence_refs=(evidence_ref,),
            decided_by="human-adjudicator",
            reason="unregistered claim must not create an incident",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )
    with pytest.raises(AdjudicationRefused):
        adjudicator.adjudicate(
            incident_hypothesis.model_copy(update={"hypothesis_id": "incident-unbound-observation"}),
            supporting_claim_ids=("claim-1",),
            supporting_evidence_refs=(evidence_ref,),
            decided_by="human-adjudicator",
            reason="unbound observation must not create an incident",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            observation_ids=("observation-not-registered",),
        )
    negative = adjudicator.adjudicate(
        incident_hypothesis.model_copy(update={"hypothesis_id": "incident-negative"}),
        supporting_claim_ids=("claim-1",),
        supporting_evidence_refs=(evidence_ref,),
        contradicting_claim_ids=("claim-contradiction",),
        decided_by="human-adjudicator",
        reason="contradictory evidence remains unresolved",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
    )
    assert negative.state.value == "CANDIDATE"
    replayed_negative = adjudicator.adjudicate(
        incident_hypothesis.model_copy(update={"hypothesis_id": "incident-negative"}),
        supporting_claim_ids=("claim-1",),
        supporting_evidence_refs=(evidence_ref,),
        contradicting_claim_ids=("claim-contradiction",),
        decided_by="human-adjudicator",
        reason="contradictory evidence remains unresolved",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
    )
    assert replayed_negative == negative
    with pytest.raises(AdjudicationRefused):
        adjudicator.adjudicate(
            incident_hypothesis.model_copy(update={"hypothesis_id": "incident-negative"}),
            supporting_claim_ids=("claim-1",),
            supporting_evidence_refs=(evidence_ref,),
            contradicting_claim_ids=("claim-contradiction",),
            decided_by="human-adjudicator",
            reason="mutated adjudication must not overwrite the canonical record",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
        )
    with pytest.raises(AdjudicationRefused):
        adjudicator.adjudicate(
            incident_hypothesis.model_copy(update={"hypothesis_id": "incident-negative", "affected_entities": ("changed",)}),
            supporting_claim_ids=("claim-1",),
            supporting_evidence_refs=(evidence_ref,),
            contradicting_claim_ids=("claim-contradiction",),
            decided_by="human-adjudicator",
            reason="the canonical hypothesis must not be replaced",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
        )


def test_response_proposals_fail_closed_for_fake_approval_expiry_scope_and_execution() -> None:
    scope = Scope(tenant="tenant-test", case="case-test", target="target-test")
    plane = SecurityEventPlane()
    ingestor = BoundedSecurityEventIngestor(plane, scope=scope)
    ingestor.ingest_raw(_raw(scope, "record-response", action="block"), scope=scope)
    engine = DetectionEngine(ingestor, scope=scope, clock=lambda: NOW)
    version = DetectionRuleVersion(
        rule_id="rule-response",
        version=1,
        title="response rule",
        rule_type=DetectionRuleType.EVENT_MATCH,
        content_digest="digest-response",
        source="test",
        source_reference="test",
        supported_source_families=("endpoint_fixture",),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        predicates={"action": "block"},
    )
    response_rule = DetectionRule(rule_id="rule-response", name="response rule", versions=(version,), active_version=1)
    run = engine.run(response_rule, scope=scope)
    evidence_ref = ingestor.events(scope=scope)[0].raw_evidence_ref
    adjudicator = IncidentAdjudicator(
        engine,
        scope=scope,
        canonical_adjudicator_ids=("human-adjudicator",),
        canonical_claims={"claim-response": _claim(scope, "claim-response", evidence_id=evidence_ref)},
        clock=lambda: NOW,
    )
    incident = adjudicator.adjudicate(
        IncidentHypothesis(hypothesis_id="incident-response", scope=scope, question="response", source_signal_ids=tuple(run.signal_ids), affected_entities=(scope.target_id,)),
        supporting_claim_ids=("claim-response",),
        supporting_evidence_refs=(evidence_ref,),
        decided_by="human-adjudicator",
        reason="evidence-backed response proposal",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    )
    canonical_approvals: dict[str, HumanApproval] = {}
    service = ResponseProposalService(
        ApprovalRequiredPolicy(OpaDecision.REQUIRE_APPROVAL),
        scope=scope,
        canonical_incidents={incident.incident_id: incident},
        canonical_approvals=canonical_approvals,
        canonical_approver_ids=("human",),
        clock=lambda: NOW,
    )
    with pytest.raises(ResponseAuthorizationError):
        service.propose(
            incident.model_copy(update={"incident_id": "fake-incident"}),
            action=ResponseAction.BLOCK_TOOL,
            reason="fake incident must not authorize a proposal",
            expected_impact="none",
            risk="none",
            rollback_plan="none",
            expires_at=NOW + timedelta(hours=1),
        )
    proposal = service.propose(
        incident,
        action=ResponseAction.BLOCK_TOOL,
        reason="bounded proposal",
        expected_impact="stop the implicated tool",
        risk="operational interruption",
        rollback_plan="human review",
        expires_at=NOW + timedelta(hours=1),
    )
    request_time = [NOW]
    service.clock = lambda: request_time[0]
    first_request = service.capability_request(proposal)
    request_time[0] = NOW + timedelta(seconds=1)
    second_request = service.capability_request(proposal)
    assert second_request == first_request
    canonical_approval = HumanApproval(
        approval_id="approval-1",
        proposal_id=proposal.proposal_id,
        proposal_digest=proposal.proposal_digest,
        scope=scope,
        target_id=proposal.target_id,
        action=proposal.action,
        decision=HumanApprovalState.APPROVED,
        decided_by="human",
        decided_at=NOW,
        source="human_operator",
        expires_at=NOW + timedelta(hours=1),
    )
    canonical_approvals[canonical_approval.approval_id] = canonical_approval
    with pytest.raises(ResponseAuthorizationError):
        service.approve(HumanApproval(approval_id="approval-1", proposal_id=proposal.proposal_id, proposal_digest=proposal.proposal_digest, scope=scope, target_id=proposal.target_id, action=proposal.action, decision=HumanApprovalState.APPROVED, decided_by="model-output", decided_at=NOW, source="llm", expires_at=NOW + timedelta(hours=1)))
    with pytest.raises(ResponseAuthorizationError):
        service.approve(HumanApproval(approval_id="approval-unknown", proposal_id=proposal.proposal_id, proposal_digest=proposal.proposal_digest, scope=scope, target_id=proposal.target_id, action=proposal.action, decision=HumanApprovalState.APPROVED, decided_by="human", decided_at=NOW, source="human_operator", expires_at=NOW + timedelta(hours=1)))
    with pytest.raises(ResponseAuthorizationError):
        service.approve(HumanApproval(approval_id="approval-1", proposal_id=proposal.proposal_id, proposal_digest=proposal.proposal_digest, scope=scope, target_id=proposal.target_id, action=proposal.action, decision=HumanApprovalState.APPROVED, decided_by="fake-human", decided_at=NOW, source="human_operator", expires_at=NOW + timedelta(hours=1)))
    with pytest.raises(DetectionScopeError):
        service.capability_request(proposal, scope=Scope(tenant="other", case="other", target="other"))
    approved = service.approve(canonical_approval)
    assert approved.human_approval_state == HumanApprovalState.APPROVED
    with pytest.raises(ResponseExecutionDisabled):
        service.execute(proposal.proposal_id, scope=scope)


def test_response_proposal_replay_does_not_rewrite_opa_decision() -> None:
    scope = Scope(tenant="tenant-test", case="case-test", target="target-test")
    plane = SecurityEventPlane()
    ingestor = BoundedSecurityEventIngestor(plane, scope=scope)
    ingestor.ingest_raw(_raw(scope, "record-proposal-replay", action="block"), scope=scope)
    engine = DetectionEngine(ingestor, scope=scope, clock=lambda: NOW)
    version = DetectionRuleVersion(
        rule_id="rule-proposal-replay",
        version=1,
        title="proposal replay rule",
        rule_type=DetectionRuleType.EVENT_MATCH,
        content_digest="digest-proposal-replay",
        source="test",
        source_reference="test",
        supported_source_families=("endpoint_fixture",),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        predicates={"action": "block"},
    )
    rule = DetectionRule(
        rule_id="rule-proposal-replay",
        name="proposal replay rule",
        versions=(version,),
        active_version=1,
    )
    run = engine.run(rule, scope=scope)
    evidence_ref = ingestor.events(scope=scope)[0].raw_evidence_ref
    incident = IncidentAdjudicator(
        engine,
        scope=scope,
        canonical_adjudicator_ids=("human-adjudicator",),
        canonical_claims={"claim-proposal-replay": _claim(scope, "claim-proposal-replay", evidence_id=evidence_ref)},
        clock=lambda: NOW,
    ).adjudicate(
        IncidentHypothesis(
            hypothesis_id="incident-proposal-replay",
            scope=scope,
            question="proposal replay",
            source_signal_ids=tuple(run.signal_ids),
            affected_entities=(scope.target_id,),
        ),
        supporting_claim_ids=("claim-proposal-replay",),
        supporting_evidence_refs=(evidence_ref,),
        decided_by="human-adjudicator",
        reason="evidence-backed proposal replay",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    )

    class FlippingPolicy:
        def __init__(self) -> None:
            self.calls = 0

        def decide(self, _context: object) -> OpaDecision:
            self.calls += 1
            return OpaDecision.REQUIRE_APPROVAL if self.calls == 1 else OpaDecision.DENY

    policy = FlippingPolicy()
    service = ResponseProposalService(
        policy,  # type: ignore[arg-type]
        scope=scope,
        canonical_incidents={incident.incident_id: incident},
        clock=lambda: NOW,
    )
    values = {
        "action": ResponseAction.BLOCK_TOOL,
        "reason": "bounded proposal replay",
        "expected_impact": "stop the implicated tool",
        "risk": "operational interruption",
        "rollback_plan": "human review",
        "expires_at": NOW + timedelta(hours=1),
    }
    first = service.propose(incident, **values)
    second = service.propose(incident, **values)
    assert second == first
    assert policy.calls == 1
