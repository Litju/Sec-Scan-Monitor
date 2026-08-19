"""Canonical security-service contracts, registry, and scoped runs.

Services are data contracts first.  A specialist may interpret evidence, but
the registry and the engagement boundary remain authoritative.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Iterable

from pydantic import Field, field_validator

from secscan.platform.domain.common import DomainModel, utc_now
from secscan.platform.domain.engagement import AuthorityLevel, Engagement
from secscan.platform.domain.ids import (
    ClaimId,
    ClientId,
    EngagementId,
    EvidenceId,
    TargetId,
    new_id,
)


class ServiceVisibility(str, Enum):
    PUBLIC_CORE = "PUBLIC_CORE"
    PRIVATE = "PRIVATE"
    SPLIT = "SPLIT"


class ServiceQualificationState(str, Enum):
    NOT_QUALIFIED = "NOT_QUALIFIED"
    SYNTHETIC_QUALIFIED = "SYNTHETIC_QUALIFIED"
    ADVERSARIAL_QUALIFIED = "ADVERSARIAL_QUALIFIED"
    REAL_READ_ONLY_QUALIFIED = "REAL_READ_ONLY_QUALIFIED"
    SHADOW_QUALIFIED = "SHADOW_QUALIFIED"
    LIMITED_PRODUCTION = "LIMITED_PRODUCTION"
    FULLY_QUALIFIED = "FULLY_QUALIFIED"


class ServiceRunStatus(str, Enum):
    PLANNED = "PLANNED"
    REFUSED = "REFUSED"
    NOT_QUALIFIED = "NOT_QUALIFIED"
    RUNNING = "RUNNING"
    DEGRADED = "DEGRADED"
    INCONCLUSIVE = "INCONCLUSIVE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class UnknownServiceError(LookupError):
    """Raised when a caller requests a service outside the canonical registry."""


class ServiceContractError(ValueError):
    """Raised when a service contract or run violates a platform invariant."""


class SecurityServiceContract(DomainModel):
    """Reviewable, canonical contract for one client-facing security service."""

    service_id: str
    name: str
    version: str
    description: str
    target_classes: list[str] = Field(min_length=1)
    required_inputs: list[str] = Field(default_factory=list)
    required_authority: list[str] = Field(default_factory=list)
    optional_authority: list[str] = Field(default_factory=list)
    required_capabilities: list[str] = Field(default_factory=list)
    optional_capabilities: list[str] = Field(default_factory=list)
    required_evidence_classes: list[str] = Field(default_factory=list)
    control_reference_baselines: list[str] = Field(default_factory=list)
    output_contract: list[str] = Field(default_factory=list)
    refusal_conditions: list[str] = Field(default_factory=list)
    degraded_mode_conditions: list[str] = Field(default_factory=list)
    qualification_state: ServiceQualificationState = ServiceQualificationState.NOT_QUALIFIED
    visibility: ServiceVisibility = ServiceVisibility.PUBLIC_CORE
    specialist_owner: str
    deterministic_engines: list[str] = Field(default_factory=list)
    supported_target_types: list[str] = Field(default_factory=list)

    @field_validator("service_id")
    @classmethod
    def _service_id_is_canonical(cls, value: str) -> str:
        value = value.strip().upper()
        if not value or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for char in value):
            raise ValueError("service_id must be an uppercase identifier")
        return value


class SecurityServiceRegistry:
    """Immutable-by-default registry of canonical service contracts."""

    def __init__(self, contracts: Iterable[SecurityServiceContract]) -> None:
        values = list(contracts)
        by_id: dict[str, SecurityServiceContract] = {}
        for contract in values:
            if contract.service_id in by_id:
                raise ServiceContractError(f"duplicate service contract: {contract.service_id}")
            by_id[contract.service_id] = contract
        self._contracts = by_id

    def get(self, service_id: str) -> SecurityServiceContract:
        key = service_id.strip().upper()
        try:
            return self._contracts[key]
        except KeyError as exc:
            raise UnknownServiceError(f"unknown security service: {service_id}") from exc

    def all(self) -> tuple[SecurityServiceContract, ...]:
        return tuple(self._contracts[key] for key in sorted(self._contracts))

    def with_contracts(self, contracts: Iterable[SecurityServiceContract]) -> "SecurityServiceRegistry":
        """Return a product composition without teaching the platform its services."""
        return SecurityServiceRegistry([*self.all(), *contracts])

    def contains(self, service_id: str) -> bool:
        return service_id.strip().upper() in self._contracts

    def qualified(self, service_id: str) -> bool:
        state = self.get(service_id).qualification_state
        return state != ServiceQualificationState.NOT_QUALIFIED


class ServiceRun(DomainModel):
    """One service execution bound to one engagement, target, and snapshot."""

    run_id: str = Field(default_factory=lambda: new_id("SR"))
    client_id: ClientId
    engagement_id: EngagementId
    target_id: TargetId
    snapshot_id: str
    service_id: str
    service_version: str
    specialist_id: str
    assessment_plan_id: str
    authority_level: AuthorityLevel = AuthorityLevel.INSPECTION_ONLY
    capabilities: list[str] = Field(default_factory=list)
    evidence_ids: list[EvidenceId] = Field(default_factory=list)
    claim_ids: list[ClaimId] = Field(default_factory=list)
    status: ServiceRunStatus = ServiceRunStatus.PLANNED
    qualification_version: str = "AQS-V1"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    limitations: list[str] = Field(default_factory=list)

    def bind_contract(self, contract: SecurityServiceContract) -> None:
        if self.service_id != contract.service_id or self.service_version != contract.version:
            raise ServiceContractError("service run does not match the canonical service contract")
        if self.authority_level != AuthorityLevel.INSPECTION_ONLY:
            raise ServiceContractError("Release 0.1 service runs are inspection-only")
        self.capabilities = sorted(set(self.capabilities))

    def assert_engagement_scope(self, engagement: Engagement) -> None:
        if self.engagement_id != engagement.engagement_id:
            raise ServiceContractError("service run crosses engagement scope")
        if self.client_id != engagement.client_id:
            raise ServiceContractError("service run crosses client scope")
        if self.target_id not in engagement.target_ids:
            raise ServiceContractError("service run target is outside engagement scope")

    def start(self) -> None:
        if self.status not in {ServiceRunStatus.PLANNED, ServiceRunStatus.DEGRADED, ServiceRunStatus.INCONCLUSIVE}:
            raise ServiceContractError(f"cannot start service run from {self.status.value}")
        self.status = ServiceRunStatus.RUNNING
        self.started_at = self.started_at or utc_now()

    def add_evidence(self, evidence_id: EvidenceId) -> None:
        if evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)

    def add_claim(self, claim_id: ClaimId) -> None:
        if claim_id not in self.claim_ids:
            self.claim_ids.append(claim_id)

    def finish(self, status: ServiceRunStatus = ServiceRunStatus.COMPLETED, *, limitation: str = "") -> None:
        if status not in {
            ServiceRunStatus.COMPLETED,
            ServiceRunStatus.DEGRADED,
            ServiceRunStatus.INCONCLUSIVE,
            ServiceRunStatus.NOT_QUALIFIED,
            ServiceRunStatus.REFUSED,
            ServiceRunStatus.FAILED,
        }:
            raise ServiceContractError("service run must finish in a terminal or explicit degraded state")
        self.status = status
        if limitation and limitation not in self.limitations:
            self.limitations.append(limitation)
        self.finished_at = utc_now()


def default_service_registry() -> SecurityServiceRegistry:
    """Build the public-safe Release 0.1 registry.

    Qualification starts conservatively.  The qualification runner can build
    a receipt-backed registry for a campaign after the evidence exists.
    """

    common_refusals = [
        "missing engagement contract or target scope",
        "authority is insufficient for inspection",
        "evidence is incomplete or out of scope",
        "required deterministic capability is unavailable",
    ]
    return SecurityServiceRegistry(
        [
            SecurityServiceContract(
                service_id="APPSEC",
                name="Application Security",
                version="0.1.0",
                description="Evidence-grounded application and API security assessment.",
                target_classes=["agentic_web_saas", "web_application", "static_library"],
                required_inputs=["engagement_contract", "target_security_profile", "repository_snapshot"],
                required_authority=["inspect", "collect"],
                required_capabilities=["CAP-REPO-READONLY-INSPECTION"],
                required_evidence_classes=["source", "configuration", "test", "scanner_output"],
                control_reference_baselines=["OWASP ASVS 5.0.0", "NIST SSDF 1.1"],
                output_contract=["observations", "claims", "adjudication_candidates", "limitations"],
                refusal_conditions=common_refusals,
                degraded_mode_conditions=["scanner unavailable", "deployment evidence absent", "control not assessed"],
                specialist_owner="AGT-APPSEC-SPECIALIST",
                deterministic_engines=["architecture-detectors", "read-only-source-inspection", "scanner-adapter-boundary"],
                supported_target_types=["repository", "web_application", "static_library"],
            ),
            SecurityServiceContract(
                service_id="AGENTSEC",
                name="Agent Security",
                version="0.1.0",
                description="Security assessment of agent identity, authority, tools, memory, and external content paths.",
                target_classes=["agentic_web_saas", "agent_system"],
                required_inputs=["engagement_contract", "target_security_profile", "agent_system_manifest"],
                required_authority=["inspect", "collect"],
                required_capabilities=["CAP-REPO-READONLY-INSPECTION"],
                required_evidence_classes=["agent_manifest", "tool_registry", "authority_config", "memory_config"],
                control_reference_baselines=["OWASP Agentic Security Initiative 2025", "OWASP LLM Top 10 v2.0"],
                output_contract=["agent_security_observations", "claims", "authority_graph", "limitations"],
                refusal_conditions=common_refusals + ["agentic attack surface is not evidenced"],
                degraded_mode_conditions=["runtime authority is unknown", "MCP implementation is not present"],
                qualification_state=ServiceQualificationState.NOT_QUALIFIED,
                specialist_owner="AGT-AGENTSEC-SPECIALIST",
                deterministic_engines=["manifest-diff", "authority-graph", "memory-boundary-checks", "injection-fixture-detector"],
                supported_target_types=["agent_system", "agentic_web_saas"],
            ),
            SecurityServiceContract(
                service_id="VULNINTEL",
                name="Vulnerability Intelligence",
                version="0.1.0",
                description="Normalized vulnerability enrichment and explainable target-specific prioritization.",
                target_classes=["agentic_web_saas", "web_application", "static_library"],
                required_inputs=["engagement_contract", "target_security_profile", "dependency_inventory"],
                required_authority=["inspect", "collect"],
                required_capabilities=["CAP-REPO-READONLY-INSPECTION"],
                required_evidence_classes=["dependency_manifest", "lockfile", "osv_advisory", "kev_catalog", "epss_record"],
                control_reference_baselines=["OSV Schema 1.0 / API 1.0", "CISA KEV", "FIRST EPSS API v1"],
                output_contract=["normalized_vulnerabilities", "priority_decisions", "feed_health", "limitations"],
                refusal_conditions=common_refusals,
                degraded_mode_conditions=["feed unavailable", "feed stale", "reachability unknown"],
                specialist_owner="AGT-VULNINTEL-SPECIALIST",
                deterministic_engines=["osv-normalizer", "kev-enrichment", "epss-enrichment", "priority-explainer"],
                supported_target_types=["repository", "web_application", "static_library"],
            ),
            SecurityServiceContract(
                service_id="SUPPLYCHAIN",
                name="Supply-Chain Security",
                version="0.1.0",
                description="Assessment of dependency resolution, build, CI/CD, provenance, SBOM, and release paths.",
                target_classes=["agentic_web_saas", "web_application", "static_library"],
                required_inputs=["engagement_contract", "target_security_profile", "repository_snapshot"],
                required_authority=["inspect", "collect"],
                required_capabilities=["CAP-REPO-READONLY-INSPECTION"],
                required_evidence_classes=["sbom", "lockfile", "ci_workflow", "provenance", "container_definition"],
                control_reference_baselines=["CycloneDX 1.7", "OWASP SCVS 1.0", "SLSA 1.2", "NIST SSDF 1.1"],
                output_contract=["supply_chain_observations", "claims", "control_status", "limitations"],
                refusal_conditions=common_refusals,
                degraded_mode_conditions=["SBOM missing", "provenance absent", "container evidence absent"],
                specialist_owner="AGT-SUPPLYCHAIN-SPECIALIST",
                deterministic_engines=["cyclonedx-parser", "workflow-analyzer", "package-resolution-checker", "provenance-checker"],
                supported_target_types=["repository", "web_application", "static_library"],
            ),
        ]
    )


__all__ = [
    "SecurityServiceContract",
    "SecurityServiceRegistry",
    "ServiceContractError",
    "ServiceQualificationState",
    "ServiceRun",
    "ServiceRunStatus",
    "ServiceVisibility",
    "UnknownServiceError",
    "default_service_registry",
]
