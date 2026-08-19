"""Transient advisory contract models for SecScanMonitor."""

from __future__ import annotations

from pydantic import ConfigDict

from .canonical import (
    Asset,
    ContractModel,
    Delta,
    ExposureSummary,
    Finding,
    HostPostureSummary,
    PhaseState,
    PromotionBlocker,
    RiskScore,
    RunbookRef,
)
from .enums import SufficiencyAssessment


class AdvisoryContractModel(ContractModel):
    """Immutable advisory contract base type."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class AgentInputContract(AdvisoryContractModel):
    contract_version: str
    generated_at: str
    phase_state: PhaseState
    assets: list[Asset]
    findings: list[Finding]
    deltas: list[Delta]
    risk_scores: list[RiskScore]
    runbook_refs: list[RunbookRef]
    exposure_summaries: list[ExposureSummary]
    host_posture_summaries: list[HostPostureSummary]
    sanitization_notes: list[str]


class AlphaOutputContract(AdvisoryContractModel):
    contract_version: str
    routed_agents: list[str]
    scope_ok: bool
    rejected_reasons: list[str]
    confidence: float


class BravoOutputContract(AdvisoryContractModel):
    contract_version: str
    interpreted_blockers: list[PromotionBlocker]
    policy_notes: list[str]
    confidence: float


class DeltaOutputContract(AdvisoryContractModel):
    contract_version: str
    delta_summary: str
    key_changes: list[str]
    confidence: float


class EchoOutputContract(AdvisoryContractModel):
    contract_version: str
    digest_id: str
    summary: str
    confidence: float


class FoxtrotOutputContract(AdvisoryContractModel):
    contract_version: str
    sufficiency_assessment: SufficiencyAssessment
    evidence_gaps: list[str]
    confidence: float


class GolfOutputContract(AdvisoryContractModel):
    contract_version: str
    suggested_views: list[str]
    visualization_notes: list[str]
    confidence: float


class SierraOutputContract(AdvisoryContractModel):
    contract_version: str
    mapped_runbooks: list[RunbookRef]
    runbook_notes: list[str]
    confidence: float


class RecommendedAction(AdvisoryContractModel):
    contract_version: str
    action_id: str
    title: str
    rationale: str
    runbook_ref_id: str
    blocking: bool


class PapaOutputContract(AdvisoryContractModel):
    contract_version: str
    recommended_actions: list[RecommendedAction]
    blocked_actions: list[str]
    confidence: float


class OperatorDigest(AdvisoryContractModel):
    contract_version: str
    title: str
    summary: str
    blockers: list[PromotionBlocker]
    recommended_actions: list[RecommendedAction]
    confidence: float
