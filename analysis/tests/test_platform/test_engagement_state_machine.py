"""Domain state machine tests: valid path, invalid transitions, suspension,
audit events per transition."""

from __future__ import annotations

import pytest

from secscan.platform.domain.common import utc_now
from secscan.platform.domain.engagement import (
    Engagement,
    EngagementStatus,
    InvalidEngagementTransition,
)
from secscan.platform.domain.ids import (
    AuditEventId,
    ClientId,
    EngagementId,
    PrincipalId,
    TargetId,
)


class _Recorder:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def record_engagement_transition(self, **kwargs: object) -> None:
        self.events.append(kwargs)


def _engagement() -> tuple[Engagement, _Recorder]:
    recorder = _Recorder()
    engagement = Engagement(
        engagement_id=EngagementId("ENG-PUBLIC-002"),
        client_id=ClientId("CLI-1"),
        requester_principal_id=PrincipalId("PRN-OPERATOR"),
        target_ids=[TargetId("TGT-1")],
        scope="repo path under test",
        pass_type="posture",
    )
    return engagement, recorder


def _transition(engagement: Engagement, recorder: _Recorder, to: EngagementStatus, reason: str = "test") -> None:
    engagement.transition(
        to,
        reason=reason,
        recorder=recorder,
        principal_id=PrincipalId("PRN-OPERATOR"),
        event_id=AuditEventId(f"AE-{utc_now().timestamp()}-{len(recorder.events)}"),
    )


def test_normal_lifecycle_path() -> None:
    engagement, recorder = _engagement()
    path = [
        EngagementStatus.INTAKE,
        EngagementStatus.SCOPE_VALIDATED,
        EngagementStatus.AUTHORIZED,
        EngagementStatus.ACTIVE,
        EngagementStatus.EVIDENCE_COLLECTION,
        EngagementStatus.ANALYSIS,
        EngagementStatus.ADJUDICATION,
        EngagementStatus.REPORTING,
        EngagementStatus.CLOSED,
    ]
    for state in path:
        _transition(engagement, recorder, state)
    assert engagement.status == EngagementStatus.CLOSED
    assert len(recorder.events) == len(path)  # audit per transition


def test_remediation_path_before_close() -> None:
    engagement, recorder = _engagement()
    for state in [
        EngagementStatus.INTAKE,
        EngagementStatus.SCOPE_VALIDATED,
        EngagementStatus.AUTHORIZED,
        EngagementStatus.ACTIVE,
        EngagementStatus.EVIDENCE_COLLECTION,
        EngagementStatus.ANALYSIS,
        EngagementStatus.ADJUDICATION,
        EngagementStatus.REPORTING,
        EngagementStatus.REMEDIATION,
        EngagementStatus.CLOSED,
    ]:
        _transition(engagement, recorder, state)
    assert engagement.status == EngagementStatus.CLOSED


def test_refusal_chain() -> None:
    engagement, recorder = _engagement()
    _transition(engagement, recorder, EngagementStatus.REFUSED)
    assert engagement.status == EngagementStatus.REFUSED
    with pytest.raises(InvalidEngagementTransition):
        _transition(engagement, recorder, EngagementStatus.INTAKE)


@pytest.mark.parametrize(
    "from_state,to_state",
    [
        (EngagementStatus.DRAFT, EngagementStatus.ACTIVE),  # skip intake
        (EngagementStatus.INTAKE, EngagementStatus.CLOSED),  # skip everything
        (EngagementStatus.ACTIVE, EngagementStatus.CLOSED),  # skip chain
        (EngagementStatus.REPORTING, EngagementStatus.ACTIVE),  # backwards
        (EngagementStatus.CLOSED, EngagementStatus.ACTIVE),  # terminal
        (EngagementStatus.FAILED, EngagementStatus.REPORTING),  # terminal
        (EngagementStatus.DRAFT, EngagementStatus.EVIDENCE_COLLECTION),
    ],
)
def test_invalid_transitions_fail_deterministically(from_state: EngagementStatus, to_state: EngagementStatus) -> None:
    engagement, recorder = _engagement()
    engagement.status = from_state
    with pytest.raises(InvalidEngagementTransition):
        _transition(engagement, recorder, to_state)


def test_suspend_resume_round_trip() -> None:
    engagement, recorder = _engagement()
    for state in [
        EngagementStatus.INTAKE,
        EngagementStatus.SCOPE_VALIDATED,
        EngagementStatus.AUTHORIZED,
        EngagementStatus.ACTIVE,
        EngagementStatus.EVIDENCE_COLLECTION,
    ]:
        _transition(engagement, recorder, state)
    _transition(engagement, recorder, EngagementStatus.SUSPENDED)
    assert engagement.status == EngagementStatus.SUSPENDED
    assert engagement.suspended_from == EngagementStatus.EVIDENCE_COLLECTION
    _transition(engagement, recorder, EngagementStatus.EVIDENCE_COLLECTION)  # resume
    assert engagement.status == EngagementStatus.EVIDENCE_COLLECTION
    assert engagement.suspended_from is None


def test_resume_must_match_suspended_from() -> None:
    engagement, recorder = _engagement()
    for state in [
        EngagementStatus.INTAKE,
        EngagementStatus.SCOPE_VALIDATED,
        EngagementStatus.AUTHORIZED,
        EngagementStatus.ACTIVE,
    ]:
        _transition(engagement, recorder, state)
    _transition(engagement, recorder, EngagementStatus.SUSPENDED)
    with pytest.raises(InvalidEngagementTransition):
        _transition(engagement, recorder, EngagementStatus.ANALYSIS)


def test_revoked_is_terminal() -> None:
    engagement, recorder = _engagement()
    for state in [EngagementStatus.INTAKE, EngagementStatus.SCOPE_VALIDATED, EngagementStatus.AUTHORIZED]:
        _transition(engagement, recorder, state)
    _transition(engagement, recorder, EngagementStatus.REVOKED)
    with pytest.raises(InvalidEngagementTransition):
        _transition(engagement, recorder, EngagementStatus.ACTIVE)


def test_failed_and_partial_are_terminal() -> None:
    engagement, recorder = _engagement()
    engagement.status = EngagementStatus.ACTIVE
    _transition(engagement, recorder, EngagementStatus.FAILED)
    assert engagement.status == EngagementStatus.FAILED

    engagement2, recorder2 = _engagement()
    engagement2.status = EngagementStatus.REPORTING
    _transition(engagement2, recorder2, EngagementStatus.PARTIAL)
    assert engagement2.status == EngagementStatus.PARTIAL


def test_status_history_records_every_transition() -> None:
    engagement, recorder = _engagement()
    _transition(engagement, recorder, EngagementStatus.INTAKE, reason="intake accepted")
    assert len(engagement.status_history) == 1
    assert engagement.status_history[0]["from"] == "draft"
    assert engagement.status_history[0]["to"] == "intake"
    assert engagement.status_history[0]["reason"] == "intake accepted"


def test_suspended_without_recorded_state_cannot_resume() -> None:
    """Data-consistency review finding: a SUSPENDED engagement whose
    suspended_from was never recorded must not be resumable."""
    engagement, recorder = _engagement()
    # simulate a corrupted direct-state mutation (service never does this,
    # but the aggregate must be defensive)
    engagement.status = EngagementStatus.SUSPENDED
    engagement.suspended_from = None
    with pytest.raises(InvalidEngagementTransition):
        _transition(engagement, recorder, EngagementStatus.ACTIVE)
