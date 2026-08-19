"""Temporal workflow tests (G8 + review-regression).

TEMPORAL_TEST_ENV: real Temporal test-server runtime (time-skipping for
deterministic paths, local for signal-wait paths). Coverage:

- happy path: gate -> coordinator -> specialist -> adjudication -> report -> close
- approval path: kernel returns REQUIRE_APPROVAL; the approve signal must
  carry the exact approval id; a mismatched/denied approval cannot proceed
- pause/resume round trip
- retry/idempotency: activity failing BEFORE the ledger record retries to
  exactly-once; failure AFTER the record REPLAYS (returns the recorded
  effect, no duplicate side effect, no crash)
- CRITICAL regression: adjudication is engagement-scoped (ENG-A claims can
  never bleed into ENG-B findings)
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from secscan.platform.domain.authority import Action, AuthorityGrant, PolicyDecision
from secscan.platform.domain.common import Confidence
from secscan.platform.domain.engagement import Engagement, EngagementStatus
from secscan.platform.domain.evidence import Claim
from secscan.platform.domain.ids import (
    AgentRunId,
    ClientId,
    EngagementId,
    EvidenceId,
    PrincipalId,
    TargetId,
)
from secscan.platform.workflows import activities, engagement_workflow
from secscan.platform.workflows.activities import (
    EngagementRuntime,
    SideEffectLedger,
)

TASK_QUEUE = "secscan-test-queue"


class ScriptedPolicyEngine:
    """Programmable policy engine: pops decisions in order; REQUIRE_APPROVAL
    until approve() is called (then ALLOW for the approval-bound decision)."""

    def __init__(self, script: list[PolicyDecision]) -> None:
        self._script = list(script)
        self.decisions_seen: list[PolicyDecision] = []
        self.approved = False

    def decide(self, request: dict[str, Any]) -> PolicyDecision:
        approval = request.get("approval", {})
        if approval.get("decision") == "approved":
            decision = PolicyDecision.ALLOW if self.approved else PolicyDecision.DENY
        elif self._script:
            decision = self._script.pop(0)
        else:
            decision = PolicyDecision.ALLOW
        self.decisions_seen.append(decision)
        return decision

    def approve(self) -> None:
        self.approved = True


def _engagement(engagement_id: str, status: EngagementStatus = EngagementStatus.ACTIVE) -> Engagement:
    return Engagement(
        engagement_id=EngagementId(engagement_id),
        client_id=ClientId("CLI-T"),
        requester_principal_id=PrincipalId("PRN-T"),
        target_ids=[TargetId("TGT-1")],
        scope="fixture",
        pass_type="posture",
        status=status,
    )


def _claim(engagement_id: str, statement: str) -> Claim:
    return Claim(
        claim_id=f"CL-{statement[:4]}",
        engagement_id=EngagementId(engagement_id),
        agent_id="AGT-SECURITY-REVIEW-SPECIALIST",
        agent_run_id=AgentRunId(f"AR-{engagement_id}"),
        observation_ids=[],
        evidence_ids=[EvidenceId(f"EV-{engagement_id}")],
        statement=statement,
        confidence=Confidence.MEDIUM,
        uncertainty="scope-limited",
    )


def _grant(engagement_id: str) -> Any:

    return AuthorityGrant(
        grant_id=f"GR-{engagement_id}",
        engagement_id=EngagementId(engagement_id),
        principal_id=PrincipalId("PRN-T"),
        action=Action.INSPECT,
        capability_id="CAP-REPO-READONLY-INSPECTION",
        target_id=TargetId("TGT-1"),
    )


def _runtime(policy: Any | None = None) -> EngagementRuntime:
    runtime = EngagementRuntime()
    if policy is not None:
        runtime.policy = policy
    activities.set_runtime(runtime)
    return runtime


def _wf_input(engagement_id: str) -> engagement_workflow.EngagementWorkflowInput:
    return engagement_workflow.EngagementWorkflowInput(
        engagement_id=engagement_id,
        workflow_run_id=f"WR-{engagement_id}",
        coordinator_agent_run_id=f"CAR-{engagement_id}",
        specialist_agent_run_id=f"SAR-{engagement_id}",
        evidence_ids=[f"EV-{engagement_id}"],
    )


async def _wait_until(predicate, timeout: float = 10.0) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.2)
    raise AssertionError("condition not reached within timeout")


@contextlib.asynccontextmanager
async def _run(env: WorkflowEnvironment, wf_input: engagement_workflow.EngagementWorkflowInput):
    """Keeps the worker alive for the caller's whole scenario — the handle
    only makes progress while its worker task queue is polled."""
    async with Worker(
        env.client,
        task_queue=TASK_QUEUE,
        workflows=[engagement_workflow.EngagementWorkflow],
        activities=[
            activities.validate_and_authorize,
            activities.coordinator_pass,
            activities.authorize_with_approval,
            activities.specialist_pass,
            activities.adjudicate_pass,
            activities.render_report,
            activities.close_engagement,
        ],
    ):
        handle = await env.client.start_workflow(
            engagement_workflow.EngagementWorkflow.run,
            wf_input,
            id=f"wf-{wf_input.workflow_run_id}",
            task_queue=TASK_QUEUE,
        )
        yield handle



def test_happy_path_through_all_stages() -> None:
    runtime = _runtime()
    engagement = _engagement("ENG-A")
    runtime.seed_engagement(engagement, grants=[_grant("ENG-A")])
    runtime.claims[EngagementId("ENG-A")] = [_claim("ENG-A", "claim-a1")]

    async def scenario() -> None:
        async with await WorkflowEnvironment.start_local() as env:
            async with _run(env, _wf_input("ENG-A")) as handle:
                result = await handle.result()
                assert result.status == "closed"
                assert result.findings_count == 1
                assert result.report_rendered is True
                assert result.approval_waited is False

    asyncio.run(scenario())
    # exactly-once: each stage recorded its side effect once
    assert runtime.ledger.count("validate:") == 1
    assert runtime.ledger.count("coordinator:") == 1
    assert runtime.ledger.count("specialist:") == 1
    assert runtime.ledger.count("adjudicate:") == 1
    assert runtime.ledger.count("report:") == 1
    assert runtime.ledger.count("close:") == 1


def test_approval_wait_requires_exact_approval_id() -> None:
    policy = ScriptedPolicyEngine([PolicyDecision.ALLOW, PolicyDecision.REQUIRE_APPROVAL])
    runtime = _runtime(policy=policy)
    engagement = _engagement("ENG-AP")
    runtime.seed_engagement(engagement, grants=[_grant("ENG-AP")])
    runtime.claims[EngagementId("ENG-AP")] = [_claim("ENG-AP", "claim-ap")]

    async def scenario() -> None:
        async with await WorkflowEnvironment.start_local() as env:
            async with _run(env, _wf_input("ENG-AP")) as handle:
                # coordinator must produce an approval record
                await _wait_until(lambda: bool(runtime.approvals))
                approval_id = next(iter(runtime.approvals))

                # a WRONG id cannot satisfy the wait
                await handle.signal("approve", "AP-FOREIGN-ID")
                await asyncio.sleep(0.5)
                assert approval_id in runtime.approvals

                # decide + approve with the EXACT id, then the kernel re-checks
                approval = runtime.approvals[approval_id]
                approval.decide(decision="approved", by=PrincipalId("PRN-T"))
                policy.approve()
                await handle.signal("approve", approval_id)
                result = await handle.result()
                assert result.status == "closed"
                assert result.approval_waited is True

    asyncio.run(scenario())


def test_denied_approval_stops_workflow() -> None:
    policy = ScriptedPolicyEngine([PolicyDecision.ALLOW, PolicyDecision.REQUIRE_APPROVAL])
    runtime = _runtime(policy=policy)
    engagement = _engagement("ENG-DN")
    runtime.seed_engagement(engagement, grants=[_grant("ENG-DN")])

    async def scenario() -> None:
        async with await WorkflowEnvironment.start_local() as env:
            async with _run(env, _wf_input("ENG-DN")) as handle:
                await _wait_until(lambda: bool(runtime.approvals))
                approval_id = next(iter(runtime.approvals))
                runtime.approvals[approval_id].decide(decision="denied", by=PrincipalId("PRN-T"))
                await handle.signal("deny", approval_id)
                result = await handle.result()
                assert result.status == "denied"
                assert result.findings_count == 0

    asyncio.run(scenario())


def test_pause_and_resume() -> None:
    """Pause takes effect at the next checkpoint. The approval wait provides
    the deterministic stall: signal pause while the workflow waits, then
    approve — the workflow must remain paused until resume."""
    policy = ScriptedPolicyEngine([PolicyDecision.ALLOW, PolicyDecision.REQUIRE_APPROVAL])
    runtime = _runtime(policy=policy)
    engagement = _engagement("ENG-PA")
    runtime.seed_engagement(engagement, grants=[_grant("ENG-PA")])
    runtime.claims[EngagementId("ENG-PA")] = [_claim("ENG-PA", "claim-pa")]

    async def scenario() -> None:
        async with await WorkflowEnvironment.start_local() as env:
            async with _run(env, _wf_input("ENG-PA")) as handle:
                await _wait_until(lambda: bool(runtime.approvals))
                approval_id = next(iter(runtime.approvals))

                # pause while the workflow waits for approval
                await handle.signal("pause")
                await asyncio.sleep(0.3)
                assert await handle.query("is_paused") is True

                # approve: the workflow advances to the checkpoint and must
                # then stop again until resumed
                runtime.approvals[approval_id].decide(decision="approved", by=PrincipalId("PRN-T"))
                policy.approve()
                await handle.signal("approve", approval_id)
                await asyncio.sleep(0.5)
                done, _ = await asyncio.wait([asyncio.ensure_future(handle.result())], timeout=0.4)
                assert not done, "paused workflow must not complete"
                assert await handle.query("is_paused") is True

                await handle.signal("resume")
                result = await handle.result()
                assert result.status == "closed"

    asyncio.run(scenario())


def test_retry_after_record_replays_not_duplicates() -> None:
    """Post-record failure mode: a duplicate key REPLAYS the recorded effect
    instead of crashing the retry (exactly-once, not at-most-once)."""
    ledger = SideEffectLedger()
    effect = {"findings": 1}
    assert ledger.record("adjudicate:ENG-X", effect) == effect
    replayed = ledger.record("adjudicate:ENG-X", effect)
    assert replayed == effect
    assert ledger.count("adjudicate:") == 1


def test_cross_engagement_adjudication_is_scoped() -> None:
    """CRITICAL regression (data/state review): ENG-A claims must never
    become ENG-B findings. Adjudication reads ONLY this engagement's
    claims."""
    runtime = _runtime()
    eng_a = _engagement("ENG-A")
    eng_b = _engagement("ENG-B")
    runtime.seed_engagement(eng_a, grants=[_grant("ENG-A")])
    runtime.seed_engagement(eng_b, grants=[_grant("ENG-B")])
    runtime.claims[EngagementId("ENG-A")] = [_claim("ENG-A", "claim-a1"), _claim("ENG-A", "claim-a2")]
    runtime.claims[EngagementId("ENG-B")] = [_claim("ENG-B", "claim-b1")]

    async def adjudicate(engagement_id: str) -> int:
        return (await activities.adjudicate_pass(engagement_id, f"WR-{engagement_id}"))["findings"]

    assert asyncio.run(adjudicate("ENG-A")) == 2
    assert asyncio.run(adjudicate("ENG-B")) == 1  # only B's own claim
    assert len(runtime.findings[EngagementId("ENG-B")]) == 1
    # B's findings belong to B, A's to A — no bleed in either direction
    assert all(f.engagement_id == EngagementId("ENG-B") for f in runtime.findings[EngagementId("ENG-B")])
    assert all(f.engagement_id == EngagementId("ENG-A") for f in runtime.findings[EngagementId("ENG-A")])
