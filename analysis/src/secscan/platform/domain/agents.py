"""Agent manifests and runs. See ADR-0002 (runtime independence) and the
agent-contract skill.

Canonical firm state is independent of Hermes, Pydantic AI, OpenAI, Anthropic,
Nous, and any single model.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import Field

from secscan.platform.domain.common import DomainModel, utc_now
from secscan.platform.domain.ids import (
    AgentId,
    AgentManifestId,
    AgentRunId,
    CapabilityId,
    EngagementId,
    PrincipalId,
)


class AgentRole(str, Enum):
    FIRM_COORDINATOR = "firm-coordinator"
    SECURITY_REVIEW_SPECIALIST = "security-review-specialist"
    APPSEC_SPECIALIST = "appsec-specialist"
    AGENTSEC_SPECIALIST = "agentsec-specialist"
    VULNERABILITY_INTELLIGENCE_SPECIALIST = "vulnerability-intelligence-specialist"
    SUPPLY_CHAIN_SPECIALIST = "supply-chain-specialist"


class AgentManifest(DomainModel):
    """Static contract of a firm agent."""

    manifest_id: AgentManifestId
    agent_id: AgentId
    role: AgentRole | str
    version: str
    accepted_inputs: list[str] = Field(default_factory=list)
    produced_outputs: list[str] = Field(default_factory=list)
    requested_capabilities: list[CapabilityId] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    forbidden_tools: list[str] = Field(default_factory=list)
    authority_ceiling: str  # max action name the agent may ever request
    evidence_consumed: list[str] = Field(default_factory=list)
    evidence_produced: list[str] = Field(default_factory=list)
    escalation_rules: list[str] = Field(default_factory=list)
    refusal_rules: list[str] = Field(default_factory=list)
    model_policy: str = "deterministic-fake-first; live-model only with explicit credentials"
    timeout_policy: str = ""
    retry_policy: str = ""


class AgentRunStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUSED = "refused"


class AgentRun(DomainModel):
    """One agent execution inside an engagement."""

    agent_run_id: AgentRunId
    engagement_id: EngagementId
    agent_id: AgentId
    agent_version: str
    model_identity: str  # e.g. "deterministic-fake-v1" or a provider model id
    prompt_version: str
    principal_id: PrincipalId
    authority_refs: list[str] = Field(default_factory=list)
    input_refs: list[str] = Field(default_factory=list)
    tool_invocation_ids: list[str] = Field(default_factory=list)
    output_claim_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    status: AgentRunStatus = AgentRunStatus.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None

    def mark_running(self) -> None:
        self.status = AgentRunStatus.RUNNING
        self.started_at = self.started_at or utc_now()

    def mark_finished(self, status: AgentRunStatus) -> None:
        if status in {AgentRunStatus.COMPLETED, AgentRunStatus.FAILED, AgentRunStatus.REFUSED}:
            self.status = status
            self.finished_at = utc_now()
            self.updated_at = self.finished_at
