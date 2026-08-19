"""Canonical persisted contract models for SecScanMonitor."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .enums import (
    AssetRole,
    BlockerSourceType,
    EvidenceSensitivity,
    FindingSeverity,
    FindingStatus,
    PostureStatus,
    PromotionStatus,
    RiskBand,
)


class ContractModel(BaseModel):
    """Shared immutable configuration for FL-002 contract models."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Asset(ContractModel):
    contract_version: str
    asset_id: str
    hostname: str
    asset_role: AssetRole
    trust_zone: str
    platform: str
    posture_status: PostureStatus
    latest_evidence_refs: list[str]


class EvidenceRef(ContractModel):
    contract_version: str
    evidence_ref_id: str
    source_collector: str
    evidence_kind: str
    captured_at: str
    local_path_hint: str
    hash_sha256: str
    sensitivity: EvidenceSensitivity


class Finding(ContractModel):
    contract_version: str
    finding_id: str
    asset_id: str
    category: str
    title: str
    severity: FindingSeverity
    status: FindingStatus
    evidence_refs: list[str]
    policy_basis: str
    confidence: float


class Delta(ContractModel):
    contract_version: str
    delta_id: str
    asset_id: str
    category: str
    prior_value: str
    current_value: str
    detected_at: str
    evidence_refs: list[str]


class RiskScore(ContractModel):
    contract_version: str
    scope_id: str
    score: float
    band: RiskBand
    contributing_findings: list[str]
    scoring_policy_version: str
    confidence_basis: str


class PhaseState(ContractModel):
    contract_version: str
    current_phase: str
    phase_label: str
    promotion_status: PromotionStatus
    blockers: list[str]
    policy_sources: list[str]


class RunbookRef(ContractModel):
    contract_version: str
    runbook_id: str
    title: str
    path: str
    applies_to_categories: list[str]
    phase_scope: str


class ExposureSummary(ContractModel):
    contract_version: str
    scope_id: str
    externally_reachable_count: int
    sensitive_service_count: int
    blocked_execution_note: str
    evidence_refs: list[str]


class HostPostureSummary(ContractModel):
    contract_version: str
    asset_id: str
    posture_status: PostureStatus
    risk_score: float
    open_findings: int
    recent_delta_count: int
    top_blockers: list[str]


class PromotionBlocker(ContractModel):
    contract_version: str
    blocker_id: str
    title: str
    reason: str
    source_type: BlockerSourceType
    severity: FindingSeverity
    runbook_ref_id: str
