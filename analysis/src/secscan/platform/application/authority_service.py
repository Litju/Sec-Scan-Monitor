"""Authority application service.

Authority-as-data use cases: grant creation/revocation, capability request
decisions through the policy engine, approvals. The model may recommend an
action; only this boundary (via the OPA kernel) authorizes it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from secscan.platform.domain.audit import AuditEvent, AuditEventKind
from secscan.platform.domain.authority import (
    Action,
    Approval,
    AuthorityGrant,
    PolicyDecision,
)
from secscan.platform.domain.capability import CapabilityManifest
from secscan.platform.domain.engagement import Engagement
from secscan.platform.domain.ids import (
    ApprovalId,
    AuditEventId,
    AuthorityGrantId,
    CapabilityId,
    EngagementId,
    PrincipalId,
    TargetId,
    new_id,
)
from secscan.platform.domain.ports import AuditSink, PolicyEngine


@dataclass(frozen=True)
class CapabilityRequest:
    """The full context for one authorization decision."""

    principal_id: PrincipalId
    agent_id: str | None
    engagement_id: EngagementId
    target_id: TargetId
    capability_id: CapabilityId
    action: Action
    risk: str
    authority_grant_id: AuthorityGrantId | None
    approval_id: ApprovalId | None
    workflow_phase: str
    requested_resources: dict[str, str]


class AuthorityService:
    """Grant lifecycle + capability request authorization."""

    def __init__(
        self,
        policy: PolicyEngine,
        audit: AuditSink,
        approver_authorizer: Callable[[Approval, PrincipalId], bool] | None = None,
    ) -> None:
        self._policy = policy
        self._audit = audit
        self._approver_authorizer = approver_authorizer

    def grant(
        self,
        *,
        engagement_id: EngagementId,
        principal_id: PrincipalId,
        action: Action,
        capability_id: CapabilityId | None,
        target_id: TargetId | None,
        not_after: datetime | None = None,
        granted_by: PrincipalId,
    ) -> AuthorityGrant:
        grant = AuthorityGrant(
            grant_id=AuthorityGrantId(new_id("GR")),
            engagement_id=engagement_id,
            principal_id=principal_id,
            action=action,
            capability_id=capability_id,
            target_id=target_id,
            not_after=not_after,
        )
        self._audit.append(
            AuditEvent(
                audit_event_id=AuditEventId(new_id("AE")),
                engagement_id=engagement_id,
                principal_id=granted_by,
                kind=AuditEventKind.AUTHORITY_CREATED,
                summary=f"grant {grant.grant_id}: {action.value} on capability "
                f"{capability_id or 'any'} for principal {principal_id}",
            )
        )
        return grant

    def revoke(self, grant: AuthorityGrant, *, revoked_by: PrincipalId) -> AuthorityGrant:
        from secscan.platform.domain.common import utc_now

        grant.revoked_at = utc_now()
        self._audit.append(
            AuditEvent(
                audit_event_id=AuditEventId(new_id("AE")),
                engagement_id=grant.engagement_id,
                principal_id=revoked_by,
                kind=AuditEventKind.AUTHORITY_REVOKED,
                summary=f"grant {grant.grant_id} revoked",
            )
        )
        return grant

    def decide(
        self,
        request: CapabilityRequest,
        *,
        engagement: Engagement,
        grants: list[AuthorityGrant],
        capability: CapabilityManifest,
        approval: Approval | None = None,
    ) -> PolicyDecision:
        """Route a capability request through the canonical policy kernel."""
        from secscan.platform.capabilities import CapabilityRegistry, UnknownCapabilityError

        try:
            canonical_capability = CapabilityRegistry().get(request.capability_id)
        except UnknownCapabilityError:
            input_hash = hashlib.sha256(
                json.dumps(
                    {"capability_id": str(request.capability_id), "engagement_id": str(request.engagement_id)},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            self._audit.append(
                AuditEvent(
                    audit_event_id=AuditEventId(new_id("AE")),
                    engagement_id=request.engagement_id,
                    principal_id=request.principal_id,
                    kind=AuditEventKind.POLICY_DECISION,
                    summary=f"unknown capability {request.capability_id}: deny",
                    details={"decision": PolicyDecision.DENY.value, "input_sha256": input_hash},
                )
            )
            return PolicyDecision.DENY

        policy_input = {
            "principal": {"id": str(request.principal_id)},
            "agent": {"id": request.agent_id} if request.agent_id else {},
            "engagement": {
                "id": str(request.engagement_id),
                "status": engagement.status.value,
                "authority_level": engagement.authority_level.value,
                "target_ids": [str(value) for value in engagement.target_ids],
            },
            "target": {"id": str(request.target_id)},
            "capability": {
                "id": str(canonical_capability.capability_id),
                "registered": True,
                "risk_class": canonical_capability.risk_class.value,
                "requires_approval": canonical_capability.requires_approval,
                "required_authority": canonical_capability.required_authority,
            },
            "action": request.action.value,
            "risk": request.risk,
            "authority_grant": _grant_input(request, grants),
            "approval": _approval_input(approval),
            "workflow_phase": request.workflow_phase,
            "requested_resources": request.requested_resources,
        }
        decision = self._policy.decide(policy_input)
        input_hash = hashlib.sha256(
            json.dumps(policy_input, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        self._audit.append(
            AuditEvent(
                audit_event_id=AuditEventId(new_id("AE")),
                engagement_id=request.engagement_id,
                principal_id=request.principal_id,
                kind=AuditEventKind.POLICY_DECISION,
                summary=f"capability request {request.capability_id} on {request.target_id}: {decision.value}",
                details={
                    "capability_id": str(request.capability_id),
                    "target_id": str(request.target_id),
                    "action": request.action.value,
                    "decision": decision.value,
                    "input_sha256": input_hash,
                    "grant_id": str(request.authority_grant_id) if request.authority_grant_id else "",
                    "approval_id": str(request.approval_id) if request.approval_id else "",
                    "agent_id": request.agent_id or "",
                    "workflow_phase": request.workflow_phase,
                    "snapshot": request.requested_resources.get("snapshot", ""),
                },
            )
        )
        return decision

    def create_approval(
        self,
        *,
        engagement_id: EngagementId,
        requested_by_principal_id: PrincipalId,
        request_ref: str,
        target_id: TargetId,
        capability_id: CapabilityId,
        action: Action,
    ) -> Approval:
        return Approval(
            approval_id=ApprovalId(new_id("AP")),
            engagement_id=engagement_id,
            requested_by_principal_id=requested_by_principal_id,
            request_ref=request_ref,
            target_id=target_id,
            capability_id=capability_id,
            action=action,
        )

    def decide_approval(
        self,
        approval: Approval,
        *,
        decision: str,
        by: PrincipalId,
        rationale: str = "",
    ) -> Approval:
        if not str(by).strip():
            raise PermissionError("approval requires a non-empty approver principal")
        if by == approval.requested_by_principal_id:
            raise PermissionError("requester cannot approve its own request")
        if self._approver_authorizer is not None and not self._approver_authorizer(approval, by):
            raise PermissionError(f"principal {by} is not authorized to decide this approval")
        approval.decide(decision=decision, by=by, rationale=rationale)
        self._audit.append(
            AuditEvent(
                audit_event_id=AuditEventId(new_id("AE")),
                engagement_id=approval.engagement_id,
                principal_id=by,
                kind=AuditEventKind.APPROVAL_DECISION,
                summary=f"approval {approval.approval_id}: {decision} for request {approval.request_ref}",
                details={
                    "request_ref": approval.request_ref,
                    "target_id": approval.target_id,
                    "capability_id": approval.capability_id,
                    "decision": decision,
                },
            )
        )
        return approval


def _grant_input(request: CapabilityRequest, grants: list[AuthorityGrant]) -> dict[str, object]:
    matching = [
        g
        for g in grants
        if request.authority_grant_id is not None
        and g.grant_id == request.authority_grant_id
        and g.engagement_id == request.engagement_id
        and g.principal_id == request.principal_id
        and (g.capability_id is None or g.capability_id == request.capability_id)
        and (g.target_id is None or g.target_id == request.target_id)
        and g.is_active(action=request.action)
    ]
    if not matching:
        return {
            "matched": False,
            "grant_ids": [],
            "conditions": [],
            "principal_id": "",
            "engagement_id": "",
            "capability_id": "",
            "target_id": "",
            "action": "",
        }
    grant = matching[0]
    return {
        "matched": True,
        "grant_ids": [str(grant.grant_id)],
        "conditions": list(grant.conditions),
        "principal_id": str(grant.principal_id),
        "engagement_id": str(grant.engagement_id),
        "capability_id": str(grant.capability_id) if grant.capability_id else "",
        "target_id": str(grant.target_id) if grant.target_id else "",
        "action": grant.action.value,
    }


def _approval_input(approval: Approval | None) -> dict[str, object]:
    """The kernel receives the FULL loaded approval record, so decision and
    request-binding are verified against the request — never a bare id."""
    if approval is None:
        return {
            "id": "",
            "recorded": False,
            "decision": "pending",
            "target_id": "",
            "capability_id": "",
            "action": "",
            "engagement_id": "",
            "decided_by_principal_id": "",
        }
    return {
        "id": str(approval.approval_id),
        "recorded": True,
        "decision": approval.decision,
        "target_id": str(approval.target_id),
        "capability_id": str(approval.capability_id),
        "action": approval.action.value,
        "engagement_id": str(approval.engagement_id),
        "decided_by_principal_id": str(approval.decided_by_principal_id) if approval.decided_by_principal_id else "",
    }
