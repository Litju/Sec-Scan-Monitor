"""Workflow runs and tool invocations (idempotency keys live here)."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import Field

from secscan.platform.domain.common import DomainModel, utc_now
from secscan.platform.domain.ids import (
    EngagementId,
    PrincipalId,
    ToolInvocationId,
    WorkflowRunId,
)


class WorkflowRunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WorkflowRun(DomainModel):
    """One durable engagement execution (Temporal)."""

    workflow_run_id: WorkflowRunId
    engagement_id: EngagementId
    started_by_principal_id: PrincipalId
    status: WorkflowRunStatus = WorkflowRunStatus.PENDING
    current_phase: str = ""
    started_at: datetime | None = None
    finished_at: datetime | None = None


class ToolInvocation(DomainModel):
    """One capability/tool execution. `tool_invocation_id` is an idempotency key."""

    tool_invocation_id: ToolInvocationId
    engagement_id: EngagementId
    workflow_run_id: WorkflowRunId
    capability_id: str
    agent_run_id: str | None = None
    requested_by_principal_id: PrincipalId
    policy_decision: str = ""  # allow | deny | require_approval
    approval_id: str | None = None
    sandbox_id: str | None = None
    status: str = "requested"  # requested | approved | denied | running | succeeded | failed | refused
    requested_at: datetime = Field(default_factory=utc_now)
    executed_at: datetime | None = None
    finished_at: datetime | None = None
    result_evidence_ids: list[str] = Field(default_factory=list)
    error: str = ""
