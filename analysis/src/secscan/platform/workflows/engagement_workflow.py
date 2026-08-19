"""Temporal workflow definitions (ADR-0005).

DETERMINISTIC workflow code ONLY: no wall-clock, no randomness, no I/O, no
model calls. All nondeterministic work lives in activities
(`secscan.platform.workflows.activities`), and EVERY authorization decision
on this execution path comes from the policy kernel through the activities —
the workflow itself never decides authority, and approval signals must
carry the exact approval id the kernel produced for this run.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    # pass_through applies to the imported module only; transitive imports
    # (application services, agents, domain) are sandbox-restricted unless
    # listed here — and the agents module calls utc_now at import time.
    import secscan.platform.adjudication  # noqa: F401
    import secscan.platform.agents  # noqa: F401
    import secscan.platform.application  # noqa: F401
    import secscan.platform.application.authority_service  # noqa: F401
    import secscan.platform.application.engagement_service  # noqa: F401
    import secscan.platform.capabilities  # noqa: F401
    import secscan.platform.domain  # noqa: F401
    import secscan.platform.domain.authority  # noqa: F401
    import secscan.platform.domain.common  # noqa: F401
    import secscan.platform.domain.engagement  # noqa: F401
    import secscan.platform.domain.evidence  # noqa: F401
    import secscan.platform.domain.ids  # noqa: F401
    import secscan.platform.domain.ports  # noqa: F401
    import secscan.platform.evidence  # noqa: F401
    import secscan.platform.policy  # noqa: F401
    import secscan.platform.reports  # noqa: F401
    from secscan.platform.workflows.activities import (
        adjudicate_pass,
        authorize_with_approval,
        close_engagement,
        coordinator_pass,
        render_report,
        specialist_pass,
        validate_and_authorize,
    )

_ACTIVITY_TIMEOUT = timedelta(minutes=2)
_RETRY_3 = RetryPolicy(
    maximum_attempts=3,
    initial_interval=timedelta(seconds=1),
)


@dataclass
class EngagementWorkflowInput:
    engagement_id: str
    workflow_run_id: str
    coordinator_agent_run_id: str
    specialist_agent_run_id: str
    evidence_ids: list[str] | None = None


@dataclass
class EngagementWorkflowResult:
    status: str
    findings_count: int
    report_rendered: bool
    approval_waited: bool
    denials: list[str] | None = None


@workflow.defn
class EngagementWorkflow:
    def __init__(self) -> None:
        self._paused = False
        self._approval_decision: dict[str, Any] | None = None

    @workflow.run
    async def run(self, wf_input: EngagementWorkflowInput) -> EngagementWorkflowResult:
        workflow.logger.info("engagement workflow starting for %s", wf_input.engagement_id)
        evidence_ids = wf_input.evidence_ids or []
        denials: list[str] = []

        await self._check_pause()

        # Stage 0: authorization gate — kernel decision required to proceed.
        gate = await workflow.execute_activity(
            validate_and_authorize,
            args=[wf_input.engagement_id, wf_input.workflow_run_id],
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=_RETRY_3,
        )
        if gate.get("decision") == "deny":
            return EngagementWorkflowResult(
                status="denied",
                findings_count=0,
                report_rendered=False,
                approval_waited=False,
                denials=["authorization gate denied"],
            )
        await self._check_pause()

        # Stage 1: coordinator plans the capability request; the kernel
        # decides it inside the activity.
        coordinator = await workflow.execute_activity(
            coordinator_pass,
            args=[wf_input.engagement_id, wf_input.coordinator_agent_run_id],
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=_RETRY_3,
        )
        if coordinator.get("verdict") in {"denied", "refuse"}:
            return EngagementWorkflowResult(
                status="denied",
                findings_count=0,
                report_rendered=False,
                approval_waited=False,
                denials=[coordinator.get("reason", "coordinator refused")],
            )

        approval_waited = False
        if coordinator.get("requires_approval"):
            approval_id = coordinator.get("approval_id")
            if not approval_id:
                return EngagementWorkflowResult(
                    status="failed",
                    findings_count=0,
                    report_rendered=False,
                    approval_waited=False,
                    denials=["requires_approval without approval id"],
                )
            approval_waited = True
            await workflow.wait_condition(
                lambda: self._approval_decision is not None
                and self._approval_decision.get("approval_id") == approval_id
            )
            decision = self._approval_decision or {}
            if decision.get("decision") != "approved":
                return EngagementWorkflowResult(
                    status="denied",
                    findings_count=0,
                    report_rendered=False,
                    approval_waited=True,
                    denials=["approval denied"],
                )
            # Re-run the kernel WITH the loaded, decided approval record:
            # a pending/denied/foreign approval can never pass this gate.
            authorized = await workflow.execute_activity(
                authorize_with_approval,
                args=[wf_input.engagement_id, wf_input.workflow_run_id, approval_id],
                start_to_close_timeout=_ACTIVITY_TIMEOUT,
                retry_policy=_RETRY_3,
            )
            if authorized.get("decision") != "allow":
                return EngagementWorkflowResult(
                    status="denied",
                    findings_count=0,
                    report_rendered=False,
                    approval_waited=True,
                    denials=["approval did not authorize"],
                )

        await self._check_pause()

        # Stage 2: specialist pass (typed observations + claims).
        await workflow.execute_activity(
            specialist_pass,
            args=[wf_input.engagement_id, wf_input.specialist_agent_run_id, evidence_ids],
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=_RETRY_3,
        )
        await self._check_pause()

        # Stage 3: adjudication — engagement-scoped, through the engine.
        adjudication = await workflow.execute_activity(
            adjudicate_pass,
            args=[wf_input.engagement_id, wf_input.workflow_run_id],
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=_RETRY_3,
        )
        await self._check_pause()

        # Stage 4: sanitized report via the case engine.
        report = await workflow.execute_activity(
            render_report,
            args=[wf_input.engagement_id, wf_input.workflow_run_id],
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=_RETRY_3,
        )
        await self._check_pause()

        # Stage 5: close through the engagement application service.
        closed = await workflow.execute_activity(
            close_engagement,
            args=[wf_input.engagement_id, wf_input.workflow_run_id],
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=_RETRY_3,
        )
        return EngagementWorkflowResult(
            status=closed.get("status", "closed"),
            findings_count=report.get("findings", adjudication.get("findings", 0)),
            report_rendered=bool(report.get("findings", -1) >= 0),
            approval_waited=approval_waited,
            denials=denials,
        )

    @workflow.signal
    def pause(self) -> None:
        self._paused = True

    @workflow.signal
    def resume(self) -> None:
        self._paused = False

    @workflow.signal
    def approve(self, approval_id: str) -> None:
        """The signal MUST carry the approval id the kernel produced for
        this run; anything else is ignored by the wait condition."""
        self._approval_decision = {"approval_id": approval_id, "decision": "approved"}

    @workflow.signal
    def deny(self, approval_id: str) -> None:
        self._approval_decision = {"approval_id": approval_id, "decision": "denied"}

    @workflow.query
    def is_paused(self) -> bool:
        return self._paused

    async def _check_pause(self) -> None:
        if self._paused:
            await workflow.wait_condition(lambda: not self._paused)
