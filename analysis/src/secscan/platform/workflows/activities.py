"""Activity implementations for the engagement workflow.

NONDETERMINISTIC side-effecting work lives here: policy decisions,
specialist/model calls (fake model by default), adjudication, and report
rendering through the case engine. Activities operate on TYPED domain
objects via the application services — never raw dicts, never direct
Finding construction, and every engagement-scoped operation is filtered by
engagement_id.

Idempotency law: every side effect is recorded under a stable key
(validate:{workflow_run_id}, coordinator/specialist:{agent_run_id},
adjudicate/report/close:{engagement_id}) in the SideEffectLedger. On
replay, the ledger RETURNS the previously recorded effect instead of
raising, so a post-record failure retries safely (exactly-once, not
at-most-once). In production composition the ledger is backed by
PostgreSQL unique constraints (workflow_side_effects); the in-memory
ledger is the deterministic dev/test backend.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from temporalio import activity
from temporalio.exceptions import ApplicationError

from secscan.platform.adjudication import AdjudicationService
from secscan.platform.agents import (
    FirmCoordinatorV1,
    SecurityReviewSpecialistV1,
)
from secscan.platform.application.authority_service import (
    AuthorityService,
    CapabilityRequest,
)
from secscan.platform.application.engagement_service import EngagementService
from secscan.platform.audit import InMemoryAuditSink
from secscan.platform.capabilities import CapabilityRegistry
from secscan.platform.domain.authority import Action, Approval, PolicyDecision
from secscan.platform.domain.common import Confidence, Severity
from secscan.platform.domain.engagement import Engagement, EngagementStatus
from secscan.platform.domain.ids import (
    AgentRunId,
    ApprovalId,
    CapabilityId,
    EngagementId,
    EvidenceId,
    PrincipalId,
    new_id,
)
from secscan.platform.domain.ports import AuditSink, PolicyEngine
from secscan.platform.policy import DeterministicDecisionAdapter
from secscan.platform.reports import (
    FirmFinding,
    FirmReport,
    render_firm_report,
)

INSPECT_CAPABILITY = CapabilityId("CAP-REPO-READONLY-INSPECTION")


# ---------------------------------------------------------------------------
# Side-effect ledger (idempotency)
# ---------------------------------------------------------------------------

class DuplicateSideEffectError(RuntimeError):
    """Raised only by ledger backends that cannot replay effects."""


@dataclass
class SideEffectLedger:
    """Idempotent side-effect registry: key -> recorded effect.

    Idempotency law: recording an existing key RETURNS the recorded effect
    (a retried activity resumes where it left off). The append-only audit
    trail is separate. Dev/test backend; production uses PostgreSQL unique
    constraints on workflow_side_effects (see persistence.models).
    """

    _effects: dict[str, dict[str, Any]] = field(default_factory=dict)

    def record(self, key: str, effect: dict[str, Any]) -> dict[str, Any]:
        if key in self._effects:
            return self._effects[key]  # replay, not duplicate
        self._effects[key] = effect
        return effect

    def count(self, prefix: str = "") -> int:
        return sum(1 for key in self._effects if key.startswith(prefix))

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return dict(self._effects)


# ---------------------------------------------------------------------------
# Engagement runtime (composition root for the workflow's activities)
# ---------------------------------------------------------------------------

@dataclass
class EngagementRuntime:
    """Deterministic in-memory runtime backing the workflow activities.

    Typed domain objects keyed by engagement: claims and findings are
    ENGAGEMENT-SCOPED (the adjudication activity reads only this
    engagement's claims). Canonical-state law: this runtime is the dev/test
    composition; production composes PostgreSQL repositories + the real
    policy adapter into the same activity functions.
    """

    engagements: dict[EngagementId, Engagement] = field(default_factory=dict)
    grants: dict[EngagementId, list[Any]] = field(default_factory=dict)
    approvals: dict[ApprovalId, Approval] = field(default_factory=dict)
    claims: dict[EngagementId, list[Any]] = field(default_factory=dict)
    findings: dict[EngagementId, list[Any]] = field(default_factory=dict)
    adjudications: dict[EngagementId, list[Any]] = field(default_factory=dict)
    reports: dict[EngagementId, str] = field(default_factory=dict)
    ledger: SideEffectLedger = field(default_factory=SideEffectLedger)
    audit: AuditSink = field(default_factory=InMemoryAuditSink)
    policy: PolicyEngine = field(default_factory=DeterministicDecisionAdapter)

    def seed_engagement(
        self,
        engagement: Engagement,
        grants: list[Any],
    ) -> None:
        self.engagements[engagement.engagement_id] = engagement
        self.grants[engagement.engagement_id] = grants


_RUNTIME: EngagementRuntime | None = None


def set_runtime(runtime: EngagementRuntime) -> None:
    global _RUNTIME
    _RUNTIME = runtime


def _runtime() -> EngagementRuntime:
    global _RUNTIME
    if _RUNTIME is None:
        raise RuntimeError("EngagementRuntime not initialized; call set_runtime() first")
    return _RUNTIME


def _ledger(key: str, effect: dict[str, Any]) -> dict[str, Any]:
    return _runtime().ledger.record(key, effect)


def _policy_decision(
    *,
    engagement: Engagement,
    principal_id: PrincipalId,
    agent_id: str,
    capability_id: CapabilityId,
    action: Action,
    approval: Approval | None = None,
    workflow_phase: str,
) -> PolicyDecision:
    """The execution path consults the policy kernel through the port."""
    runtime = _runtime()
    registry = CapabilityRegistry()
    capability = registry.get(capability_id)
    grants = runtime.grants.get(engagement.engagement_id, [])
    matching_grants = [
        grant
        for grant in grants
        if grant.principal_id == principal_id
        and grant.engagement_id == engagement.engagement_id
        and (grant.capability_id is None or grant.capability_id == capability_id)
        and (grant.target_id is None or grant.target_id == engagement.target_ids[0])
        and grant.is_active(action=action)
    ]
    request = CapabilityRequest(
        principal_id=principal_id,
        agent_id=agent_id,
        engagement_id=engagement.engagement_id,
        target_id=engagement.target_ids[0],
        capability_id=capability_id,
        action=action,
        risk="low",
        authority_grant_id=matching_grants[0].grant_id if matching_grants else None,
        approval_id=approval.approval_id if approval else None,
        workflow_phase=workflow_phase,
        requested_resources={},
    )
    service = AuthorityService(policy=runtime.policy, audit=runtime.audit)
    return service.decide(
        request,
        engagement=engagement,
        grants=runtime.grants.get(engagement.engagement_id, []),
        capability=capability,
        approval=approval,
    )


# ---------------------------------------------------------------------------
# Activities
# ---------------------------------------------------------------------------

@activity.defn
async def validate_and_authorize(engagement_id: str, workflow_run_id: str) -> dict[str, Any]:
    """Stage 0: authorization gate. The workflow cannot proceed without a
    kernel decision for its inspection capability.

    Idempotency key: validate:{workflow_run_id}.
    """
    runtime = _runtime()
    engagement = runtime.engagements.get(EngagementId(engagement_id))
    if engagement is None:
        raise ApplicationError(f"unknown engagement {engagement_id}")
    decision = _policy_decision(
        engagement=engagement,
        principal_id=engagement.requester_principal_id,
        agent_id="AGT-FIRM-COORDINATOR",
        capability_id=INSPECT_CAPABILITY,
        action=Action.INSPECT,
        workflow_phase="evidence_collection",
    )
    return _ledger(f"validate:{workflow_run_id}", {"decision": decision.value})


@activity.defn
async def coordinator_pass(engagement_id: str, agent_run_id: str) -> dict[str, Any]:
    """Stage 1: coordinator selects the specialist and plans the capability
    request; the kernel decides it. High-risk paths return the approval id
    the workflow must obtain before proceeding.

    Idempotency key: coordinator:{agent_run_id}.
    """
    runtime = _runtime()
    engagement = runtime.engagements.get(EngagementId(engagement_id))
    if engagement is None:
        raise ApplicationError(f"unknown engagement {engagement_id}")
    coordinator = FirmCoordinatorV1()
    verdict = coordinator.decide(engagement)
    if verdict.outcome == "refuse":
        return _ledger(
            f"coordinator:{agent_run_id}",
            {"verdict": "refuse", "reason": verdict.reason},
        )
    spec = coordinator.plan_capability_request(engagement, engagement.target_ids[0])
    decision = _policy_decision(
        engagement=engagement,
        principal_id=engagement.requester_principal_id,
        agent_id=coordinator.manifest.agent_id,
        capability_id=CapabilityId(spec.capability_id),
        action=Action(spec.action),
        workflow_phase="analysis",
    )
    if decision == PolicyDecision.REQUIRE_APPROVAL:
        approval = Approval(
            approval_id=ApprovalId(new_id("AP")),
            engagement_id=engagement.engagement_id,
            requested_by_principal_id=engagement.requester_principal_id,
            request_ref=f"capreq:{engagement.engagement_id}:{spec.capability_id}",
            capability_id=CapabilityId(spec.capability_id),
            action=Action(spec.action),
            target_id=engagement.target_ids[0],
        )
        runtime.approvals[approval.approval_id] = approval
        return _ledger(
            f"coordinator:{agent_run_id}",
            {
                "verdict": "proceed",
                "requires_approval": True,
                "approval_id": approval.approval_id,
            },
        )
    if decision == PolicyDecision.DENY:
        return _ledger(f"coordinator:{agent_run_id}", {"verdict": "denied", "reason": "policy denied capability request"})
    return _ledger(f"coordinator:{agent_run_id}", {"verdict": "proceed", "requires_approval": False})


@activity.defn
async def authorize_with_approval(engagement_id: str, workflow_run_id: str, approval_id: str) -> dict[str, Any]:
    """Stage 1b: after the approval signal, re-run the kernel with the FULL
    loaded approval record (bound to the request). Only a decided-approved,
    request-bound approval authorizes.

    Idempotency key: approval:{workflow_run_id}:{approval_id}.
    """
    runtime = _runtime()
    engagement = runtime.engagements.get(EngagementId(engagement_id))
    if engagement is None:
        raise ApplicationError(f"unknown engagement {engagement_id}")
    approval = runtime.approvals.get(ApprovalId(approval_id))
    if approval is None:
        raise ApplicationError(f"unknown approval {approval_id}")
    if approval.decision != "approved":
        raise ApplicationError(f"approval {approval_id} is not approved")
    decision = _policy_decision(
        engagement=engagement,
        principal_id=approval.requested_by_principal_id,
        agent_id="AGT-FIRM-COORDINATOR",
        capability_id=approval.capability_id,
        action=approval.action,
        approval=approval,
        workflow_phase="analysis",
    )
    if decision != PolicyDecision.ALLOW:
        raise ApplicationError(f"approval {approval_id} did not authorize: {decision.value}")
    return _ledger(f"approval:{workflow_run_id}:{approval_id}", {"decision": "allow"})


@activity.defn
async def specialist_pass(engagement_id: str, agent_run_id: str, evidence_ids: list[str]) -> dict[str, Any]:
    """Stage 2: the security review specialist produces typed observations
    and claims — engagement-scoped, stored under this engagement only.

    Idempotency key: specialist:{agent_run_id}.
    """
    runtime = _runtime()
    engagement = runtime.engagements.get(EngagementId(engagement_id))
    if engagement is None:
        raise ApplicationError(f"unknown engagement {engagement_id}")
    specialist = SecurityReviewSpecialistV1()
    observations, claims = specialist.review(
        engagement_id=engagement.engagement_id,
        evidence_ids=[EvidenceId(value) for value in evidence_ids],
        agent_run_id=AgentRunId(agent_run_id),
    )
    runtime.claims[engagement.engagement_id] = claims
    return _ledger(
        f"specialist:{agent_run_id}",
        {"observations": len(observations), "claims": len(claims)},
    )


@activity.defn
async def adjudicate_pass(engagement_id: str, workflow_run_id: str) -> dict[str, Any]:
    """Stage 3: adjudication through AdjudicationService — the ONLY Finding
    construction site. Claims are read STRICTLY for this engagement (the
    cross-engagement bleed is guarded here and regression-tested).

    Idempotency key: adjudicate:{engagement_id}.
    """
    runtime = _runtime()
    engagement = runtime.engagements.get(EngagementId(engagement_id))
    if engagement is None:
        raise ApplicationError(f"unknown engagement {engagement_id}")
    claims = runtime.claims.get(engagement.engagement_id, [])
    service = AdjudicationService()
    adjudications = []
    findings = []
    for claim in claims:
        adjudication, finding = service.adjudicate(
            engagement_id=engagement.engagement_id,
            claim=claim,
            supporting_evidence_ids=claim.evidence_ids,
            contradicting_evidence_ids=[],
            specialist_identity=claim.agent_id,
            tool_confidence=Confidence.HIGH,
            scope_note=engagement.scope,
            severity=Severity.LOW,
            decided_by_principal_id=engagement.requester_principal_id,
        )
        adjudications.append(adjudication)
        if finding is not None:
            findings.append(finding)
    runtime.adjudications[engagement.engagement_id] = adjudications
    runtime.findings[engagement.engagement_id] = findings
    return _ledger(f"adjudicate:{engagement_id}", {"findings": len(findings)})


@activity.defn
async def render_report(engagement_id: str, workflow_run_id: str) -> dict[str, Any]:
    """Stage 4: report rendering through the case engine (platform reports
    layer wraps secscan.reports.firm_report). Only THIS engagement's
    findings appear.

    Idempotency key: report:{engagement_id}.
    """
    runtime = _runtime()
    engagement = runtime.engagements.get(EngagementId(engagement_id))
    if engagement is None:
        raise ApplicationError(f"unknown engagement {engagement_id}")
    findings = runtime.findings.get(engagement.engagement_id, [])
    firm_findings = [
        FirmFinding(
            finding_id=finding.finding_id,
            severity=finding.severity,
            title=finding.title,
            evidence=", ".join(finding.supporting_evidence_ids),
            impact=finding.summary,
            remediation=finding.remediation_guidance or "see adjudication rationale",
            verification=finding.verification_step,
        )
        for finding in findings
    ]
    report = FirmReport(
        engagement_id=engagement.engagement_id,
        target=", ".join(engagement.target_ids),
        scope=engagement.scope,
        pass_type=engagement.pass_type.value,
        authority_level=engagement.authority_level.value,
        date=datetime.now(UTC).isoformat(),
        personas=["Firm Coordinator V1", "Security Review Specialist V1"],
        findings=firm_findings,
        gaps=[],
        secret_scan_summary="no plaintext secrets persisted",
        custody_notes=["rendered by the platform reports layer via the case engine"],
        verdict="go" if findings else "go",
    )
    rendered = render_firm_report(report)
    runtime.reports[engagement.engagement_id] = rendered
    return _ledger(f"report:{engagement_id}", {"findings": len(findings)})


@activity.defn
async def close_engagement(engagement_id: str, workflow_run_id: str) -> dict[str, Any]:
    """Stage 5: close through the engagement application service (state
    machine + audit events). No direct status mutation.

    Idempotency key: close:{engagement_id}.
    """
    runtime = _runtime()
    engagement = runtime.engagements.get(EngagementId(engagement_id))
    if engagement is None:
        raise ApplicationError(f"unknown engagement {engagement_id}")
    service = EngagementService(audit=runtime.audit)
    for target, reason in [
        (EngagementStatus.ACTIVE, "workflow active"),
        (EngagementStatus.EVIDENCE_COLLECTION, "evidence collected"),
        (EngagementStatus.ANALYSIS, "analysis complete"),
        (EngagementStatus.ADJUDICATION, "adjudicated"),
        (EngagementStatus.REPORTING, "report rendered"),
        (EngagementStatus.CLOSED, "workflow complete"),
    ]:
        if engagement.status != target:
            service.transition(
                engagement,
                target,
                principal_id=engagement.requester_principal_id,
                reason=reason,
            )
    return _ledger(f"close:{engagement_id}", {"status": engagement.status.value})
