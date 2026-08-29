"""Behavioral tests for the live v0.3 control-plane composition."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from secscan.platform.api import create_app
from secscan.platform.application.live_control_plane import LiveControlPlaneService
from secscan.platform.application.live_ingest import LiveSecurityEventInput
from secscan.platform.continuous_security.events import EventClass, EventIdentityConflict
from secscan.platform.detection_response.domain import (
    DetectionInputError,
    DetectionPlan,
    DetectionRule,
    DetectionRuleType,
    DetectionRuleVersion,
    HumanApprovalState,
    HuntHypothesis,
    HuntPlan,
    ResponseAction,
    Scope,
    SecuritySourceBinding,
    stable_id,
)
from secscan.platform.domain.authority import PolicyDecision
from secscan.platform.domain.common import Confidence, Severity
from secscan.platform.live import build_live_control_plane
from secscan.platform.persistence import models
from secscan.platform.persistence.detection_response import PostgresDetectionResponseRepository
from secscan.platform.persistence.live_control_plane import PostgresLiveControlPlaneRepository


class ApprovalRequiredOpa:
    def decide(self, _request: dict[str, object]) -> PolicyDecision:
        return PolicyDecision.REQUIRE_APPROVAL


@pytest.fixture()
def live_fixture():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    models.Base.metadata.create_all(engine)
    scope = Scope(tenant="CLI-LIVE", case="ENG-LIVE", target="TGT-LIVE")
    with Session(engine) as session:
        session.add_all(
            [
                models.ClientRow(client_id="CLI-LIVE", name="live client"),
                models.TargetRow(target_id="TGT-LIVE", client_id="CLI-LIVE", kind="system", name="live target"),
                models.PrincipalRow(principal_id="PRN-SOURCE", kind="source", name="endpoint source"),
                models.PrincipalRow(principal_id="PRN-OP", kind="operator", name="operator"),
                models.PrincipalRow(principal_id="PRN-APPROVER", kind="operator", name="approver"),
                models.PrincipalRow(
                    principal_id="PRN-V03-RESPONSE-SERVICE", kind="system", name="response service"
                ),
                models.EngagementRow(
                    engagement_id="ENG-LIVE",
                    client_id="CLI-LIVE",
                    requester_principal_id="PRN-OP",
                    scope="live test",
                    pass_type="posture",
                    authority_level="remediation",
                    status="adjudication",
                ),
                models.EngagementTargetRow(
                    engagement_target_id="ET-LIVE",
                    engagement_id="ENG-LIVE",
                    target_id="TGT-LIVE",
                    in_scope=True,
                ),
                models.CapabilityManifestRow(
                    capability_id="CAP-V03-RESPONSE-PROPOSAL",
                    version="1.0.0",
                    description="proposal only",
                    risk_class="high",
                    required_authority="remediate",
                    requires_approval=True,
                ),
                models.WorkflowRunRow(
                    workflow_run_id="WR-LIVE",
                    engagement_id="ENG-LIVE",
                    started_by_principal_id="PRN-OP",
                    status="completed",
                    current_phase="evidence",
                    started_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
                    finished_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
                ),
                models.ToolInvocationRow(
                    tool_invocation_id="TI-LIVE",
                    engagement_id="ENG-LIVE",
                    workflow_run_id="WR-LIVE",
                    capability_id="CAP-V03-RESPONSE-PROPOSAL",
                    agent_run_id=None,
                    requested_by_principal_id="PRN-OP",
                    policy_decision="allow",
                    approval_id=None,
                    sandbox_id=None,
                    status="succeeded",
                    requested_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
                    executed_at=None,
                    finished_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
                    result_evidence_ids=["EV-LIVE"],
                    error="",
                ),
                models.EvidenceMetadataRow(
                    evidence_id="EV-LIVE",
                    engagement_id="ENG-LIVE",
                    target_id="TGT-LIVE",
                    collector="live-test",
                    tool_version="live-test-v1",
                    capability_id="CAP-V03-RESPONSE-PROPOSAL",
                    invocation_id="TI-LIVE",
                    sandbox_id=None,
                    collected_at=datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
                    content_type="application/vnd.secscan.metadata+json",
                    byte_size=0,
                    sha256="0" * 64,
                    storage_ref="metadata://live/record-1",
                    sanitization_state="sanitized",
                    source_identity="live-test",
                    agent_run_id=None,
                    secret_observations=[],
                ),
                models.AuthorityGrantRow(
                    grant_id="GR-LIVE",
                    engagement_id="ENG-LIVE",
                    principal_id="PRN-V03-RESPONSE-SERVICE",
                    action="remediate",
                    capability_id="CAP-V03-RESPONSE-PROPOSAL",
                    target_id="TGT-LIVE",
                    conditions=[],
                ),
                models.AgentManifestRow(
                    manifest_id="AM-LIVE",
                    agent_id="AGT-LIVE",
                    role="live-test",
                    version="1.0.0",
                    authority_ceiling="inspect",
                ),
                models.AgentRunRow(
                    agent_run_id="AR-LIVE",
                    engagement_id="ENG-LIVE",
                    agent_id="AGT-LIVE",
                    agent_version="1.0.0",
                    model_identity="test",
                    prompt_version="test",
                    principal_id="PRN-OP",
                    status="succeeded",
                ),
                models.ObservationRow(
                    observation_id="OBS-LIVE",
                    engagement_id="ENG-LIVE",
                    evidence_ids=["EV-LIVE"],
                    kind="event",
                    statement="canonical event observation",
                    recorded_by_agent_id="AGT-LIVE",
                ),
                models.ClaimRow(
                    claim_id="CLM-LIVE",
                    engagement_id="ENG-LIVE",
                    agent_id="AGT-LIVE",
                    agent_run_id="AR-LIVE",
                    observation_ids=["OBS-LIVE"],
                    evidence_ids=["EV-LIVE"],
                    statement="canonical event claim",
                    confidence="high",
                ),
            ]
        )
        session.commit()
    repository = PostgresLiveControlPlaneRepository(factory)
    control = LiveControlPlaneService(repository, policy_client=ApprovalRequiredOpa())
    control.ingest.register_source(
        SecuritySourceBinding(
            source_id="src-endpoint",
            principal_id="PRN-SOURCE",
            scope=scope,
            source_family="endpoint_fixture",
            source_type="endpoint",
        )
    )
    version = DetectionRuleVersion(
        rule_id="rule-live-endpoint",
        version=1,
        title="live endpoint match",
        rule_type=DetectionRuleType.EVENT_MATCH,
        content_digest="source-digest-live",
        source="secscan-owned",
        source_reference="tests/live",
        supported_source_families=("endpoint_fixture",),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        predicates={"action": "execute", "process.name": "powershell"},
    )
    rule = DetectionRule(rule_id=version.rule_id, name=version.title, versions=(version,), active_version=1)
    plan = DetectionPlan(
        plan_id=stable_id("PLAN-", version.rule_id, version.version, version.content_digest),
        rule_id=version.rule_id,
        rule_version=1,
        rule_type=version.rule_type,
        content_digest=version.content_digest,
        event_schema="OCSF",
        supported_source_families=version.supported_source_families,
        predicates=version.predicates,
    )
    control.detection.register_owned_rule(rule, plan)
    return engine, factory, scope, control


def _event_input(record_id: str, *, action: str = "execute") -> LiveSecurityEventInput:
    occurred = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    return LiveSecurityEventInput(
        source_id="src-endpoint",
        source_record_id=record_id,
        source_digest=f"digest-{record_id}",
        event_class=EventClass.ENDPOINT_ACTIVITY.value,
        occurred_at=occurred,
        observed_at=occurred + timedelta(seconds=1),
        actor="endpoint-agent",
        object="process",
        action=action,
        outcome="allowed",
        raw_evidence_ref=f"metadata://live/{record_id}",
        normalization_version="security-events-v2",
        collector_version="live-test-v1",
        source_system="live-test",
        attributes={"process": {"name": "powershell"}},
    )


def test_live_event_metadata_rejects_raw_payload_fields_and_oversize_values() -> None:
    payload = _event_input("record-metadata").model_dump(mode="json", by_alias=True)
    payload["attributes"] = {"payload": {"raw": "event content"}}
    with pytest.raises(ValueError):
        LiveSecurityEventInput.model_validate(payload)
    payload["attributes"] = {"process": {"name": "x" * 1_025}}
    with pytest.raises(ValueError):
        LiveSecurityEventInput.model_validate(payload)


def test_live_event_rejects_secret_like_top_level_text() -> None:
    payload = _event_input("record-top-level-secret").model_dump(mode="json", by_alias=True)
    payload["actor"] = "password=synthetic-marker"
    with pytest.raises(ValueError):
        LiveSecurityEventInput.model_validate(payload)
    payload["actor"] = "github_pat_" + "x" * 24
    with pytest.raises(ValueError):
        LiveSecurityEventInput.model_validate(payload)
    payload["actor"] = "sk-" + "x" * 24
    with pytest.raises(ValueError):
        LiveSecurityEventInput.model_validate(payload)


def test_live_event_rejects_unsupported_ocsf_metadata() -> None:
    payload = _event_input("record-ocsf").model_dump(mode="json", by_alias=True)
    payload["ocsf_version"] = "1.7.0"
    with pytest.raises(ValueError):
        LiveSecurityEventInput.model_validate(payload)
    payload["ocsf_version"] = "1.8.0"
    payload["ocsf_class"] = "cloud_audit_activity"
    with pytest.raises(ValueError):
        LiveSecurityEventInput.model_validate(payload)


def test_live_ingest_is_scoped_atomic_and_idempotent(live_fixture) -> None:
    engine, _factory, _scope, control = live_fixture
    first = control.ingest.ingest(_event_input("record-1"), principal_id="PRN-SOURCE")
    second = control.ingest.ingest(_event_input("record-1"), principal_id="PRN-SOURCE")
    assert first.event_id == second.event_id
    assert first.event_created is True
    assert second.event_created is False
    assert first.work_id == second.work_id
    with Session(engine) as session:
        assert session.query(models.SecurityEventRow).count() == 1
        assert session.query(models.DetectionWorkItemRow).count() == 1
    with pytest.raises(PermissionError):
        control.ingest.ingest(_event_input("record-2"), principal_id="PRN-OP")
    with pytest.raises(EventIdentityConflict):
        control.ingest.ingest(_event_input("record-1", action="delete"), principal_id="PRN-SOURCE")


def test_dispatch_reconstructs_from_postgres_and_retry_has_one_signal(live_fixture) -> None:
    engine, _factory, scope, control = live_fixture
    receipt = control.ingest.ingest(_event_input("record-1"), principal_id="PRN-SOURCE")
    dispatched = control.detection.dispatch_one(receipt.work_id)
    retried = control.detection.dispatch_one(receipt.work_id)
    assert dispatched.signal_ids
    assert retried.signal_ids == dispatched.signal_ids
    with Session(engine) as session:
        assert session.query(models.DetectionSignalRow).count() == 1
        work = session.get(models.DetectionWorkItemRow, receipt.work_id)
        assert work is not None and work.status == "COMPLETED"


def test_adjudication_rejects_tampered_persisted_signal_rule_provenance(live_fixture) -> None:
    engine, _factory, scope, control = live_fixture
    receipt = control.ingest.ingest(_event_input("record-tampered-rule"), principal_id="PRN-SOURCE")
    dispatch = control.detection.dispatch_one(receipt.work_id)
    with Session(engine) as session:
        signal = session.get(models.DetectionSignalRow, dispatch.signal_ids[0])
        assert signal is not None
        signal.rule_digest = "tampered-rule-digest"
        session.commit()

    with pytest.raises(PermissionError):
        control.incidents.open_incident_hypothesis(
            scope=scope,
            question="does a tampered signal remain admissible?",
            source_signal_ids=(dispatch.signal_ids[0],),
            affected_entities=(scope.target_id,),
            requested_by="PRN-OP",
        )


def test_adjudication_rejects_signal_evidence_not_bound_to_events(live_fixture) -> None:
    engine, _factory, scope, control = live_fixture
    receipt = control.ingest.ingest(_event_input("record-tampered-evidence"), principal_id="PRN-SOURCE")
    dispatch = control.detection.dispatch_one(receipt.work_id)
    with Session(engine) as session:
        signal = session.get(models.DetectionSignalRow, dispatch.signal_ids[0])
        assert signal is not None
        signal.raw_evidence_refs = ["metadata://live/not-the-source-event"]
        session.commit()

    with pytest.raises(PermissionError):
        control.incidents.open_incident_hypothesis(
            scope=scope,
            question="does an evidence-substituted signal remain admissible?",
            source_signal_ids=(dispatch.signal_ids[0],),
            affected_entities=(scope.target_id,),
            requested_by="PRN-OP",
        )


def test_requested_signal_rehydrates_its_canonical_source_graph(live_fixture) -> None:
    engine, _factory, scope, control = live_fixture
    first = control.ingest.ingest(_event_input("record-source-root"), principal_id="PRN-SOURCE")
    first_dispatch = control.detection.dispatch_one(first.work_id)
    version = DetectionRuleVersion(
        rule_id="rule-live-child",
        version=1,
        title="live child rule",
        rule_type=DetectionRuleType.EVENT_MATCH,
        content_digest="source-digest-live-child",
        source="secscan-owned",
        source_reference="tests/live-child",
        supported_source_families=("endpoint_fixture",),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        predicates={"action": "execute"},
    )
    control.detection.register_owned_rule(
        DetectionRule(rule_id=version.rule_id, name=version.title, versions=(version,), active_version=1),
        DetectionPlan(
            plan_id=stable_id("PLAN-", version.rule_id, version.version, version.content_digest),
            rule_id=version.rule_id,
            rule_version=version.version,
            rule_type=version.rule_type,
            content_digest=version.content_digest,
            event_schema=version.event_schema,
            supported_source_families=version.supported_source_families,
            predicates=version.predicates,
        ),
    )
    second = control.ingest.ingest(_event_input("record-source-child"), principal_id="PRN-SOURCE")
    control.detection.dispatch_one(second.work_id)
    with Session(engine) as session:
        source = session.get(models.DetectionSignalRow, first_dispatch.signal_ids[0])
        child = next(
            row
            for row in session.scalars(
                select(models.DetectionSignalRow).where(models.DetectionSignalRow.rule_id == "rule-live-child")
            )
            if second.event_id in (row.event_ids or [])
        )
        assert source is not None and child is not None
        child_id = child.signal_id
        child.source_signal_ids = [source.signal_id]
        child.raw_evidence_refs = sorted(
            [
                _event_input("record-source-root").raw_evidence_ref,
                _event_input("record-source-child").raw_evidence_ref,
            ]
        )
        session.commit()

    loaded = control.repository.load_signals(scope, (child_id,))
    assert [signal.signal_id for signal in loaded] == [child_id]


def test_operator_identity_must_match_verified_access_principal(live_fixture) -> None:
    _engine, _factory, scope, control = live_fixture
    with pytest.raises(PermissionError):
        control.incidents.open_incident_hypothesis(
            scope=scope,
            question="operator binding must be exact",
            source_signal_ids=(),
            affected_entities=(scope.target_id,),
            requested_by="PRN-APPROVER",
            access_principal_id="PRN-OP",
        )


def test_live_control_plane_rejects_secret_like_operator_text(live_fixture) -> None:
    _engine, _factory, scope, control = live_fixture
    with pytest.raises(ValueError):
        control.incidents.open_incident_hypothesis(
            scope=scope,
            question="password=synthetic-marker",
            source_signal_ids=(),
            affected_entities=(scope.target_id,),
            requested_by="PRN-OP",
        )


def test_hunt_claims_are_owner_bound_and_expire_for_recovery(live_fixture) -> None:
    engine, _factory, scope, control = live_fixture
    hypothesis = HuntHypothesis(
        hypothesis_id="HYP-LEASE",
        scope=scope,
        question="does a leased hunt recover?",
        entity_keys=("actor",),
    )
    plan = HuntPlan(
        plan_id="HPLAN-LEASE",
        hypothesis_id=hypothesis.hypothesis_id,
        scope=scope,
        window_start=datetime(2026, 8, 28, 11, 59, tzinfo=UTC),
        window_end=datetime(2026, 8, 28, 12, 1, tzinfo=UTC),
        query={},
        exit_criteria="lease recovery",
    )
    control.repository.save_hunt_request(hypothesis, plan)
    assert control.repository.claim_hunt(plan.plan_id, worker_id="hunt-worker-a") is True
    assert control.repository.claim_hunt(plan.plan_id, worker_id="hunt-worker-b") is False
    with Session(engine) as session:
        stored = session.get(models.HuntPlanRow, plan.plan_id)
        assert stored is not None
        stored.lease_until = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    assert plan.plan_id in control.repository.pending_hunt_plans()
    assert control.repository.claim_hunt(plan.plan_id, worker_id="hunt-worker-b") is True


def test_active_rule_plan_and_version_selection_fail_closed(live_fixture) -> None:
    engine, _factory, _scope, control = live_fixture
    rule, plan = control.repository.active_rules()[0]
    with pytest.raises(DetectionInputError):
        control.repository.register_rule(
            rule,
            plan.model_copy(update={"predicates": {"action": "tampered"}}),
        )
    version_two = rule.active.model_copy(
        update={
            "version": 2,
            "title": "unexpected second active version",
            "content_digest": "second-active-digest",
        }
    )
    with Session(engine) as session:
        PostgresDetectionResponseRepository(session).save_rule_version(version_two)
        session.commit()
    with pytest.raises(DetectionInputError):
        control.repository.active_rules()


def test_claim_one_only_leases_the_requested_work_item(live_fixture) -> None:
    engine, _factory, _scope, control = live_fixture
    first = control.ingest.ingest(_event_input("claim-first"), principal_id="PRN-SOURCE")
    second = control.ingest.ingest(_event_input("claim-second"), principal_id="PRN-SOURCE")
    claimed = control.repository.claim_one(second.work_id, worker_id="worker-second")
    assert claimed is not None and claimed.work_id == second.work_id
    with Session(engine) as session:
        assert session.get(models.DetectionWorkItemRow, first.work_id).status == "PENDING"
        assert session.get(models.DetectionWorkItemRow, second.work_id).status == "CLAIMED"


def test_active_rule_owner_is_canonical_and_persisted(live_fixture) -> None:
    engine, _factory, _scope, control = live_fixture
    with Session(engine) as session:
        row = session.get(models.DetectionRuleVersionRow, ("rule-live-endpoint", 1))
        assert row is not None
        row.owner = "untrusted-source"
        session.commit()
    with pytest.raises(DetectionInputError):
        control.repository.active_rules()


def test_expired_worker_lease_cannot_complete_or_fail_work(live_fixture) -> None:
    engine, _factory, _scope, control = live_fixture
    receipt = control.ingest.ingest(_event_input("record-expired"), principal_id="PRN-SOURCE")
    claimed = control.repository.claim_one(receipt.work_id, worker_id="worker-expired")
    assert claimed is not None
    with Session(engine) as session:
        row = session.get(models.DetectionWorkItemRow, receipt.work_id)
        assert row is not None
        row.lease_until = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    with pytest.raises(PermissionError):
        control.repository.complete_work(
            receipt.work_id,
            worker_id="worker-expired",
            run_ids=(),
            signal_ids=(),
        )
    with pytest.raises(PermissionError):
        control.repository.fail_work(
            receipt.work_id,
            worker_id="worker-expired",
            error_type="late-worker",
        )


def test_local_api_uses_canonical_live_projection(live_fixture) -> None:
    _engine, _factory, _scope, control = live_fixture
    client = TestClient(create_app(live_control_plane=control))
    response = client.post(
        "/security-events",
        headers={"X-Secscan-Principal": "PRN-SOURCE"},
        json=_event_input("record-api").model_dump(mode="json", by_alias=True),
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["ingest"]["work_created"]
    assert "dispatch" not in payload
    dispatch = control.detection.dispatch_one(payload["ingest"]["work_id"])
    assert dispatch.signal_ids
    page = client.get(
        "/detection/signals",
        headers={"X-Secscan-Principal": "PRN-OP"},
    )
    assert page.status_code == 200
    assert page.json()["items"][0]["source"] == "canonical detection engine"
    experience = client.get(
        "/experience",
        headers={"X-Secscan-Principal": "PRN-OP"},
    )
    assert experience.status_code == 200
    assert experience.json()["sourceLabel"] == "LOCAL / LOOPBACK / CANONICAL_POSTGRESQL"
    assert experience.json()["detectionSignals"]


def test_live_experience_overlay_uses_canonical_reader_for_unified_projection(live_fixture) -> None:
    _engine, _factory, _scope, control = live_fixture
    canonical = {
        "mode": "LOCAL_INTEGRATED",
        "connectionState": "CONNECTED",
        "sourceLabel": "LOCAL / LOOPBACK / CANONICAL_POSTGRESQL",
        "tenantId": "CLI-LIVE",
        "attention": [{"id": "signal-1"}],
        "cases": [{"caseId": "ENG-LIVE"}],
    }
    reader_calls: list[str] = []

    def read_experience(principal_id: str) -> dict[str, object]:
        reader_calls.append(principal_id)
        return canonical

    reader_control = LiveControlPlaneService(
        control.repository,
        policy_client=ApprovalRequiredOpa(),
        experience_reader=read_experience,
    )
    response = reader_control.experience_overlay(
        {"mode": "LOCAL_INTEGRATED", "attention": [], "cases": []},
        access_principal_id="PRN-OP",
    )

    assert reader_calls == ["PRN-OP"]
    assert response["attention"] == canonical["attention"]
    assert response["cases"] == canonical["cases"]


def test_hunt_rejects_required_evidence_outside_its_window(live_fixture) -> None:
    _engine, _factory, scope, control = live_fixture
    now = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    in_window = control.ingest.ingest(_event_input("record-in-window"), principal_id="PRN-SOURCE")
    dispatch = control.detection.dispatch_one(in_window.work_id)
    stale_input = _event_input("record-out-of-window", action="read").model_copy(
        update={
            "occurred_at": now + timedelta(hours=2),
            "observed_at": now + timedelta(hours=2, seconds=1),
        }
    )
    stale = control.ingest.ingest(stale_input, principal_id="PRN-SOURCE")
    control.detection.dispatch_one(stale.work_id)
    with pytest.raises(PermissionError):
        control.incidents.request_hunt(
            HuntHypothesis(
                hypothesis_id="HYP-OUT-OF-WINDOW",
                scope=scope,
                question="does the in-window event have stale support?",
                entity_keys=("actor",),
                supporting_signal_ids=(dispatch.signal_ids[0],),
                required_evidence_refs=(stale_input.raw_evidence_ref,),
            ),
            HuntPlan(
                plan_id="HPLAN-OUT-OF-WINDOW",
                hypothesis_id="HYP-OUT-OF-WINDOW",
                scope=scope,
                window_start=now - timedelta(minutes=1),
                window_end=now + timedelta(minutes=1),
                query={"action": "execute", "signal_ids": [dispatch.signal_ids[0]]},
                exit_criteria="one event",
            ),
            requested_by="PRN-OP",
        )


def test_live_hunt_projection_preserves_refuting_evidence(live_fixture) -> None:
    _engine, _factory, scope, control = live_fixture
    event_input = _event_input("record-refuting")
    control.ingest.ingest(event_input, principal_id="PRN-SOURCE")
    result = control.incidents.request_hunt(
        HuntHypothesis(
            hypothesis_id="HYP-REFUTING-PROJECTION",
            scope=scope,
            question="does a read event exist in the bounded window?",
            entity_keys=("actor",),
        ),
        HuntPlan(
            plan_id="HPLAN-REFUTING-PROJECTION",
            hypothesis_id="HYP-REFUTING-PROJECTION",
            scope=scope,
            window_start=datetime(2026, 8, 28, 11, 59, tzinfo=UTC),
            window_end=datetime(2026, 8, 28, 12, 1, tzinfo=UTC),
            query={"event": {"action": "read"}},
            exit_criteria="no matching read event",
        ),
        requested_by="PRN-OP",
    )

    assert result.disposition.value == "REFUTES"
    projected = control.repository.read_hunts()
    assert projected[0]["status"] == "CONTRADICTED"
    assert projected[0]["evidence_refs"] == [event_input.raw_evidence_ref]


def test_pending_hunt_recovers_after_service_restart(live_fixture) -> None:
    engine, factory, scope, control = live_fixture
    receipt = control.ingest.ingest(_event_input("record-pending-hunt"), principal_id="PRN-SOURCE")
    dispatch = control.detection.dispatch_one(receipt.work_id)
    signal_id = dispatch.signal_ids[0]
    now = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    hypothesis = HuntHypothesis(
        hypothesis_id="HYP-PENDING-RECOVERY",
        scope=scope,
        question="does the pending plan recover after restart?",
        entity_keys=("actor",),
        supporting_signal_ids=(signal_id,),
    )
    plan = HuntPlan(
        plan_id="HPLAN-PENDING-RECOVERY",
        hypothesis_id=hypothesis.hypothesis_id,
        scope=scope,
        window_start=now - timedelta(minutes=1),
        window_end=now + timedelta(minutes=1),
        query={"event": {"action": "execute"}, "signal_ids": [signal_id]},
        exit_criteria="one canonical endpoint event",
    )
    control.repository.save_hunt_request(hypothesis, plan)

    restarted = build_live_control_plane(
        factory,
        policy_client=ApprovalRequiredOpa(),
        recovery_access_principal_id="PRN-OP",
    )

    assert restarted.incidents.recover_pending_hunts() == ()
    with Session(engine) as session:
        stored_plan = session.get(models.HuntPlanRow, plan.plan_id)
        assert stored_plan is not None and stored_plan.status == "COMPLETED"
        assert session.query(models.HuntExecutionRow).count() == 1


def test_adjudication_rejects_claims_with_unresolved_evidence(live_fixture) -> None:
    engine, _factory, scope, control = live_fixture
    receipt = control.ingest.ingest(_event_input("record-fake-claim"), principal_id="PRN-SOURCE")
    dispatch = control.detection.dispatch_one(receipt.work_id)
    hypothesis = control.incidents.open_incident_hypothesis(
        scope=scope,
        question="is the endpoint activity an incident?",
        source_signal_ids=(dispatch.signal_ids[0],),
        affected_entities=("endpoint-agent",),
        requested_by="PRN-OP",
    )
    with pytest.raises(PermissionError, match="supporting incident evidence"):
        control.incidents.adjudicate_incident(
            hypothesis_id=hypothesis.hypothesis_id,
            supporting_claim_ids=("CLM-LIVE",),
            supporting_evidence_refs=("metadata://live/record-fake-claim",),
            decided_by="PRN-OP",
            reason="claim evidence must match the canonical metadata reference",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            observation_ids=("OBS-LIVE",),
        )
    with Session(engine) as session:
        claim = session.get(models.ClaimRow, "CLM-LIVE")
        assert claim is not None
        claim.evidence_ids = ["EV-NOT-CANONICAL"]
        session.commit()
    with pytest.raises(PermissionError):
        control.incidents.adjudicate_incident(
            hypothesis_id=hypothesis.hypothesis_id,
            supporting_claim_ids=("CLM-LIVE",),
            supporting_evidence_refs=(_event_input("record-fake-claim").raw_evidence_ref,),
            decided_by="PRN-OP",
            reason="unresolved evidence must be refused",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            observation_ids=("OBS-LIVE",),
        )


def test_live_hunt_incident_and_response_stop_at_approval(live_fixture) -> None:
    engine, _factory, scope, control = live_fixture
    receipt = control.ingest.ingest(_event_input("record-1"), principal_id="PRN-SOURCE")
    dispatch = control.detection.dispatch_one(receipt.work_id)
    signal_id = dispatch.signal_ids[0]
    now = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    hunt = control.incidents.request_hunt(
        HuntHypothesis(
            hypothesis_id="HYP-LIVE",
            scope=scope,
            question="is the endpoint process event corroborated?",
            entity_keys=("actor", "target"),
            supporting_signal_ids=(signal_id,),
        ),
        HuntPlan(
            plan_id="HPLAN-LIVE",
            hypothesis_id="HYP-LIVE",
            scope=scope,
            window_start=now - timedelta(minutes=1),
            window_end=now + timedelta(minutes=1),
            query={"event": {"action": "execute"}, "signal_ids": [signal_id]},
            exit_criteria="one canonical endpoint event",
        ),
        requested_by="PRN-OP",
    )
    assert hunt.signal_ids == (signal_id,)
    hypothesis = control.incidents.open_incident_hypothesis(
        scope=scope,
        question="is the endpoint activity an incident?",
        source_signal_ids=(signal_id,),
        affected_entities=("endpoint-agent",),
        requested_by="PRN-OP",
    )
    incident = control.incidents.adjudicate_incident(
        hypothesis_id=hypothesis.hypothesis_id,
        supporting_claim_ids=("CLM-LIVE",),
        supporting_evidence_refs=("metadata://live/record-1",),
        decided_by="PRN-OP",
        reason="canonical claim and event evidence agree",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        observation_ids=("OBS-LIVE",),
    )
    assert incident.state.value == "CONFIRMED"
    proposal = control.incidents.propose_response(
        incident_id=incident.incident_id,
        scope=scope,
        action=ResponseAction.ISOLATE_RUNNER,
        reason="isolate the affected runner pending review",
        expected_impact="stop further activity",
        risk="service interruption",
        rollback_plan="restore the runner after human review",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        requested_by="PRN-OP",
    )
    assert proposal.opa_decision.value == "REQUIRE_APPROVAL"
    assert proposal.human_approval_state == HumanApprovalState.APPROVAL_REQUIRED
    with Session(engine) as session:
        request = session.scalar(
            select(models.ResponseCapabilityRequestRow).where(
                models.ResponseCapabilityRequestRow.proposal_id == proposal.proposal_id
            )
        )
        assert request is not None
        request.action = ResponseAction.BLOCK_TOOL.value
        session.commit()
    with pytest.raises(PermissionError):
        control.incidents.decide_response_approval(
            proposal_id=proposal.proposal_id,
            scope=scope,
            decided_by="PRN-APPROVER",
            decision="approved",
        )
    with Session(engine) as session:
        request = session.scalar(
            select(models.ResponseCapabilityRequestRow).where(
                models.ResponseCapabilityRequestRow.proposal_id == proposal.proposal_id
            )
        )
        assert request is not None
        request.action = ResponseAction.ISOLATE_RUNNER.value
        session.commit()
    approved = control.incidents.decide_response_approval(
        proposal_id=proposal.proposal_id,
        scope=scope,
        decided_by="PRN-APPROVER",
        decision="approved",
    )
    assert approved.human_approval_state == HumanApprovalState.APPROVED
    with pytest.raises(PermissionError):
        control.incidents.decide_response_approval(
            proposal_id=proposal.proposal_id,
            scope=scope,
            decided_by="PRN-APPROVER",
            decision="denied",
        )
    with Session(engine) as session:
        assert session.query(models.IncidentRow).count() == 1
        assert session.query(models.ResponseCapabilityRequestRow).count() == 1
        assert session.query(models.ApprovalRow).count() == 1
        assert session.scalar(select(models.ApprovalRow.decision)) == "approved"
        assert session.scalar(select(models.ResponseProposalRow.human_approval_state)) == "APPROVED"
        assert not session.scalar(select(models.ResponseProposalRow.authorized_action_executed))
