"""One canonical Release 0.1 firm assessment report."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Sequence

from pydantic import BaseModel, ConfigDict, Field

from secscan.contracts.enums import FindingSeverity
from secscan.platform.application.security_services import ServiceResult
from secscan.platform.domain.finding import Finding
from secscan.platform.domain.planning import AssessmentPlan
from secscan.platform.domain.profiles import TargetSecurityProfile
from secscan.reports.firm_report import FirmFinding, FirmReport, build_firm_report


class AssessmentFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    severity: FindingSeverity
    title: str
    contributing_services: list[str] = Field(default_factory=list)
    affected_component: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    standard_references: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    verification: str = ""


def _canonical_output(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _canonical_output(item)
            for key, item in value.items()
            if key not in {"created_at", "updated_at"}
        }
    if isinstance(value, list):
        return [_canonical_output(item) for item in value]
    return value


class FirmAssessmentReport(BaseModel):
    """Typed report assembled from canonical profile, claims, findings, and runs."""

    model_config = ConfigDict(extra="forbid")

    engagement_id: str
    target_id: str
    scope: str
    services_performed: list[str]
    profile_summary: dict[str, Any]
    findings: list[AssessmentFinding] = Field(default_factory=list)
    vulnerability_priorities: list[dict[str, Any]] = Field(default_factory=list)
    agent_security_summary: dict[str, Any] | None = None
    supply_chain_summary: dict[str, Any] | None = None
    limitations: list[str] = Field(default_factory=list)
    evidence_count: int = 0
    qualification: dict[str, str] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def from_canonical(
        cls,
        *,
        engagement: Any,
        profile: TargetSecurityProfile,
        plan: AssessmentPlan,
        results: Sequence[ServiceResult],
        findings: Sequence[Finding],
        evidence_count: int,
    ) -> "FirmAssessmentReport":
        report_findings = [
            AssessmentFinding(
                finding_id=str(finding.finding_id),
                severity=FindingSeverity(finding.severity.value),
                title=finding.title,
                contributing_services=finding.contributing_services,
                affected_component=finding.affected_component,
                evidence_ids=[str(value) for value in finding.supporting_evidence_ids],
                standard_references=finding.standard_references,
                impact=finding.impact,
                remediation=finding.remediation_guidance,
                verification=finding.verification_step,
            )
            for finding in findings
        ]
        profile_summary = {
            "target_class": profile.target_class,
            "snapshot_id": profile.snapshot_id,
            "languages": sorted({str(fact.value) for fact in profile.languages}),
            "frameworks": sorted({str(fact.value) for fact in profile.frameworks}),
            "package_ecosystems": sorted({str(fact.value) for fact in profile.package_ecosystems}),
            "agentic_surface": profile.has_agentic_surface,
            "unknowns": profile.unknowns,
            "contradictions": profile.contradictions,
        }
        return cls(
            engagement_id=str(engagement.engagement_id),
            target_id=profile.target_id,
            scope=engagement.scope,
            services_performed=[result.service_id for result in results],
            profile_summary=profile_summary,
            findings=report_findings,
            vulnerability_priorities=next((result.outputs.get("priority_decisions", []) for result in results if result.service_id == "VULNINTEL"), []),
            agent_security_summary=_canonical_output(next((result.outputs.get("agent_system_security_profile") for result in results if result.service_id == "AGENTSEC"), None)),
            supply_chain_summary=_canonical_output(next((result.outputs.get("assessment") for result in results if result.service_id == "SUPPLYCHAIN"), None)),
            limitations=sorted({limitation for result in results for limitation in result.limitations} | set(plan.known_limitations)),
            evidence_count=evidence_count,
            qualification={service_id: "NOT_VALIDATED" for service_id in plan.selected_services},
            # The engagement is the canonical clock.  A wall-clock default
            # would make identical snapshot assessments hash differently.
            generated_at=engagement.created_at,
        )

    def render(self) -> tuple[str, list[str]]:
        """Render through the existing case-engine sanitizer and report builder."""
        case_report = FirmReport(
            engagement_id=self.engagement_id,
            target=self.target_id,
            scope=self.scope,
            pass_type="posture",
            authority_level="inspection-only",
            date=self.generated_at.date().isoformat(),
            personas=self.services_performed,
            findings=[
                FirmFinding(
                    finding_id=finding.finding_id,
                    severity=finding.severity,
                    title=finding.title,
                    evidence=", ".join(finding.evidence_ids) or "not recorded",
                    impact=finding.impact,
                    remediation=finding.remediation,
                    verification=finding.verification,
                )
                for finding in self.findings
            ],
            gaps=self.limitations,
            custody_notes=[f"evidence objects: {self.evidence_count}", "finding creation path: adjudication only"],
            verdict="conditional" if self.limitations else "go",
        )
        return build_firm_report(case_report)


__all__ = ["AssessmentFinding", "FirmAssessmentReport"]
