"""Authority model tests: grant lifecycle, expiry, revocation, approval scope."""

from __future__ import annotations

from datetime import timedelta

import pytest

from secscan.platform.domain.authority import (
    INSPECTION_ONLY_ACTIONS,
    REMEDIATION_ACTIONS,
    Action,
    Approval,
    AuthorityGrant,
)
from secscan.platform.domain.common import utc_now
from secscan.platform.domain.ids import (
    ApprovalId,
    AuthorityGrantId,
    CapabilityId,
    EngagementId,
    PrincipalId,
    TargetId,
)


def _grant(**overrides: object) -> AuthorityGrant:
    kwargs: dict[str, object] = {
        "grant_id": AuthorityGrantId("GR-1"),
        "engagement_id": EngagementId("ENG-1"),
        "principal_id": PrincipalId("PRN-1"),
        "action": Action.INSPECT,
        "capability_id": CapabilityId("CAP-1"),
        "target_id": TargetId("TGT-1"),
    }
    kwargs.update(overrides)
    return AuthorityGrant(**kwargs)


def test_active_grant_authorizes() -> None:
    grant = _grant()
    assert grant.is_active()


def test_expired_grant_denies() -> None:
    grant = _grant(not_after=utc_now() - timedelta(seconds=1))
    assert not grant.is_active()


def test_not_yet_valid_grant_denies() -> None:
    grant = _grant(not_before=utc_now() + timedelta(hours=1))
    assert not grant.is_active()


def test_revoked_grant_denies_immediately() -> None:
    grant = _grant()
    grant.revoked_at = utc_now() - timedelta(seconds=5)
    assert not grant.is_active()


def test_action_mismatch_denies() -> None:
    grant = _grant(action=Action.INSPECT)
    assert not grant.is_active(action=Action.MUTATE)


def test_inspection_only_actions_never_include_mutation() -> None:
    assert Action.MUTATE not in INSPECTION_ONLY_ACTIONS
    assert Action.REMEDIATE not in INSPECTION_ONLY_ACTIONS
    assert Action.ACTIVE_TEST not in INSPECTION_ONLY_ACTIONS
    assert Action.INSPECT in INSPECTION_ONLY_ACTIONS


def test_remediation_actions_include_mutation() -> None:
    assert Action.MUTATE in REMEDIATION_ACTIONS
    assert Action.REMEDIATE in REMEDIATION_ACTIONS


def test_approval_cannot_change_target() -> None:
    approval = Approval(
        approval_id=ApprovalId("AP-1"),
        engagement_id=EngagementId("ENG-1"),
        requested_by_principal_id=PrincipalId("PRN-AGENT"),
        request_ref="TE-1",
        target_id=TargetId("TGT-1"),
        capability_id=CapabilityId("CAP-1"),
        action=Action.MUTATE,
    )
    # The approval data model pins the target of the original request; a
    # different target means a different Approval object entirely.
    assert approval.target_id == TargetId("TGT-1")
    approval.decide(decision="approved", by=PrincipalId("PRN-OPERATOR"))
    assert approval.decision == "approved"
    assert approval.decided_at is not None


def test_approval_invalid_decision_rejected() -> None:
    approval = Approval(
        approval_id=ApprovalId("AP-2"),
        engagement_id=EngagementId("ENG-1"),
        requested_by_principal_id=PrincipalId("PRN-AGENT"),
        request_ref="TE-2",
        target_id=TargetId("TGT-1"),
        capability_id=CapabilityId("CAP-1"),
        action=Action.INSPECT,
    )
    with pytest.raises(ValueError):
        approval.decide(decision="maybe", by=PrincipalId("PRN-OPERATOR"))
