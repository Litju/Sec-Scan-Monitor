"""Deterministic assessment-plan value object and routing validation."""

from __future__ import annotations

from pydantic import Field

from secscan.platform.domain.common import DomainModel
from secscan.platform.domain.engagement import AuthorityLevel, Engagement
from secscan.platform.domain.profiles import TargetSecurityProfile
from secscan.platform.domain.services import SecurityServiceRegistry, ServiceContractError


class AssessmentPlan(DomainModel):
    """Final service selection for one engagement and one immutable snapshot."""

    plan_id: str
    engagement_id: str
    target_id: str
    profile_snapshot_id: str
    target_class: str
    required_services: list[str] = Field(default_factory=list)
    optional_services: list[str] = Field(default_factory=list)
    selected_service_versions: dict[str, str] = Field(default_factory=dict)
    allowed_capabilities: list[str] = Field(default_factory=list)
    blocked_capabilities: list[str] = Field(default_factory=list)
    service_dependencies: dict[str, list[str]] = Field(default_factory=dict)
    expected_outputs: dict[str, list[str]] = Field(default_factory=dict)
    known_limitations: list[str] = Field(default_factory=list)

    @property
    def selected_services(self) -> list[str]:
        return sorted(set(self.required_services + self.optional_services))

    def validate_plan(self, registry: SecurityServiceRegistry, engagement: Engagement) -> None:
        if self.engagement_id != engagement.engagement_id or self.target_id not in engagement.target_ids:
            raise ServiceContractError("assessment plan escapes engagement target scope")
        if engagement.authority_level != AuthorityLevel.INSPECTION_ONLY:
            raise ServiceContractError("Release 0.1 assessment plans are inspection-only")
        if set(self.allowed_capabilities) & set(self.blocked_capabilities):
            raise ServiceContractError("capability cannot be both allowed and blocked")
        for service_id in self.selected_services:
            contract = registry.get(service_id)
            if self.selected_service_versions.get(service_id) != contract.version:
                raise ServiceContractError(f"plan version mismatch for {service_id}")
            required = set(contract.required_capabilities)
            if not required.issubset(set(self.allowed_capabilities)):
                raise ServiceContractError(f"plan omits required capabilities for {service_id}")
        if any(capability in {"mutate", "remediate", "active_test"} for capability in self.allowed_capabilities):
            raise ServiceContractError("assessment plan contains a non-inspection capability")


def route_services(
    *,
    profile: TargetSecurityProfile,
    engagement: Engagement,
    registry: SecurityServiceRegistry,
) -> AssessmentPlan:
    """Route services from evidence-backed profile facts only."""
    required = ["APPSEC", "VULNINTEL", "SUPPLYCHAIN"]
    optional: list[str] = []
    if profile.has_agentic_surface or "agent" in engagement.scope.lower():
        optional.append("AGENTSEC")
    selected = sorted(set(required + optional))
    versions = {service_id: registry.get(service_id).version for service_id in selected}
    capabilities = sorted({capability for service_id in selected for capability in registry.get(service_id).required_capabilities})
    plan = AssessmentPlan(
        plan_id=f"PLAN-{engagement.engagement_id}-{profile.snapshot_id}",
        engagement_id=str(engagement.engagement_id),
        target_id=profile.target_id,
        profile_snapshot_id=profile.snapshot_id,
        target_class=profile.target_class,
        required_services=required,
        optional_services=optional,
        selected_service_versions=versions,
        allowed_capabilities=capabilities,
        service_dependencies={"APPSEC": [], "VULNINTEL": ["APPSEC"], "SUPPLYCHAIN": [], "AGENTSEC": []},
        expected_outputs={service_id: registry.get(service_id).output_contract for service_id in selected},
        known_limitations=["runtime deployment exposure is not inferred from repository routes"]
        if "deployment" not in engagement.scope.lower()
        else [],
    )
    plan.validate_plan(registry, engagement)
    return plan


__all__ = ["AssessmentPlan", "route_services"]
