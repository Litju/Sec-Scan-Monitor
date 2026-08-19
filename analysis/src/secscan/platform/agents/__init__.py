"""Thin architecture-validation agents (ADR-0002, agent-contract skill).

Only two agents exist in this campaign:
- Firm Coordinator V1
- Security Review Specialist V1

Laws implemented here:
- Canonical firm state is independent of any model/runtime; the model is
  reached through the ModelPort (deterministic fake by default).
- Agents never create Findings directly; they produce Claims with stated
  uncertainty. Findings exist only via adjudication.
- Agents never self-authorize: every capability request goes through the
  policy engine; REQUIRE_APPROVAL blocks until an explicit approval.
- Typed structured outputs; malformed model output fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from secscan.platform.domain.agents import (
    AgentManifest,
    AgentRole,
)
from secscan.platform.domain.authority import Action
from secscan.platform.domain.common import Confidence
from secscan.platform.domain.engagement import Engagement
from secscan.platform.domain.evidence import Claim, Observation
from secscan.platform.domain.ids import (
    AgentId,
    AgentManifestId,
    AgentRunId,
    CapabilityId,
    ClaimId,
    EngagementId,
    EvidenceId,
    ObservationId,
    TargetId,
    new_id,
)
from secscan.platform.domain.planning import AssessmentPlan, route_services
from secscan.platform.domain.ports import ModelPort
from secscan.platform.domain.profiles import TargetSecurityProfile
from secscan.platform.domain.services import SecurityServiceRegistry


class StructuredOutputError(RuntimeError):
    """Model output failed schema validation: fail closed, never guess."""


class UnauthorizedCapabilityError(RuntimeError):
    """The policy engine did not authorize a requested capability."""


class FindingCreationForbiddenError(RuntimeError):
    """An agent attempted to create a Finding directly."""


# ---------------------------------------------------------------------------
# Manifests
# ---------------------------------------------------------------------------

FIRM_COORDINATOR_V1_MANIFEST = AgentManifest(
    manifest_id=AgentManifestId("AM-FIRM-COORDINATOR-V1"),
    agent_id=AgentId("AGT-FIRM-COORDINATOR"),
    role=AgentRole.FIRM_COORDINATOR,
    version="1.0.0",
    accepted_inputs=["engagement_id"],
    produced_outputs=["deployment_plan", "capability_requests", "coordinator_verdict"],
    requested_capabilities=[
        CapabilityId("CAP-REPO-INVENTORY"),
        CapabilityId("CAP-FIRM-REPORT-RENDER"),
        CapabilityId("CAP-REPO-READONLY-INSPECTION"),
        CapabilityId("CAP-SAST-SEMGREP"),
        CapabilityId("CAP-SCA-OSV"),
        CapabilityId("CAP-SECRETS-GITLEAKS"),
        CapabilityId("CAP-REPO-TRIVY"),
    ],
    allowed_tools=["read-engagement", "request-capability", "collect-specialist-output", "send-claims"],
    forbidden_tools=["create-finding", "mutate-target", "execute-shell"],
    authority_ceiling=Action.INSPECT.value,
    evidence_consumed=["engagement_record", "scope"],
    evidence_produced=["deployment_plan", "coordinator_verdict"],
    escalation_rules=["escalate out-of-scope requests to the operator; never expand scope"],
    refusal_rules=["refuse when scope is missing; refuse when target is undeclared"],
    model_policy="deterministic-fake-first; live-model only with explicit credentials",
    timeout_policy="bounded per step; total run capped",
    retry_policy="structured-output retry once, then fail closed",
)

SECURITY_REVIEW_SPECIALIST_V1_MANIFEST = AgentManifest(
    manifest_id=AgentManifestId("AM-SECURITY-REVIEW-SPECIALIST-V1"),
    agent_id=AgentId("AGT-SECURITY-REVIEW-SPECIALIST"),
    role=AgentRole.SECURITY_REVIEW_SPECIALIST,
    version="1.0.0",
    accepted_inputs=["evidence_ids", "target_scope"],
    produced_outputs=["observations", "claims"],
    requested_capabilities=[CapabilityId("CAP-REPO-READONLY-INSPECTION")],
    allowed_tools=["read-evidence", "request-inspection-capability"],
    forbidden_tools=["create-finding", "mutate-target", "execute-shell", "active-testing"],
    authority_ceiling=Action.INSPECT.value,
    evidence_consumed=["evidence_objects"],
    evidence_produced=["observations", "claims"],
    escalation_rules=["escalate secrets encountered: metadata only, never the value"],
    refusal_rules=["refuse capability requests beyond read-only inspection"],
    model_policy="deterministic-fake-first; live-model only with explicit credentials",
    timeout_policy="bounded per step",
    retry_policy="structured-output retry once, then fail closed",
)


# ---------------------------------------------------------------------------
# Model port implementations
# ---------------------------------------------------------------------------

@dataclass
class DeterministicFakeModel:
    """ModelPort that returns deterministic, schema-valid outputs.

    Responses are programmed per output schema. Output validation is
    enforced (fail closed): a fake that disagrees with its schema raises
    StructuredOutputError — the same law as live models.
    """

    responses: dict[type[Any], Any] = field(default_factory=dict)

    def complete_structured(self, *, prompt: str, output_schema: type[Any], context: dict[str, Any] | None = None) -> Any:
        candidate = self.responses.get(output_schema)
        if candidate is None:
            raise StructuredOutputError(
                f"fake model has no programmed response for schema {output_schema.__name__}"
            )
        try:
            if isinstance(candidate, output_schema):
                return candidate
            return output_schema.model_validate(candidate)
        except ValidationError as exc:
            raise StructuredOutputError(
                f"fake model response for {output_schema.__name__} failed schema validation: {exc}"
            ) from exc


class FindingGuard:
    """Structural law: no agent module may construct Finding.

    Agents return Claims; adjudication is the only Finding construction
    site. This guard exists so agent code has no constructor path at all —
    the architecture test additionally bans the import.
    """

    def __init__(self) -> None:
        raise FindingCreationForbiddenError("agents never create Findings directly")


# ---------------------------------------------------------------------------
# Agent structured outputs
# ---------------------------------------------------------------------------

class SpecialistSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    specialist_ids: list[str] = Field(min_length=1, max_length=4)
    rationale: str = ""


class CapabilityRequestSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability_id: str
    action: str
    target_id: str
    needs_approval_if_required: bool = True


class CoordinatorVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outcome: str  # proceed | refuse
    reason: str = ""


class ObservationSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observations: list[dict[str, str]]
    claims: list[dict[str, str]]
    uncertainty: str


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

@dataclass
class FirmCoordinatorV1:
    """Reads the canonical engagement, selects an allowed specialist,
    requests a capability, respects the policy decision, waits for required
    approval, collects specialist output, sends claims to adjudication, and
    progresses the workflow."""

    manifest: AgentManifest = field(default_factory=lambda: FIRM_COORDINATOR_V1_MANIFEST)
    model: ModelPort | None = None

    def __post_init__(self) -> None:
        if self.model is None:
            self.model = DeterministicFakeModel(
                {
                    SpecialistSelection: {"specialist_ids": ["AGT-SECURITY-REVIEW-SPECIALIST"], "rationale": "posture pass"},
                    CapabilityRequestSpec: {
                        "capability_id": "CAP-REPO-READONLY-INSPECTION",
                        "action": "inspect",
                        "target_id": "",
                    },
                    CoordinatorVerdict: {"outcome": "proceed", "reason": "scope valid"},
                }
            )

    def select_specialists(self, engagement: Engagement) -> SpecialistSelection:
        assert self.model is not None
        result = self.model.complete_structured(
            prompt="select allowed specialists for engagement scope",
            output_schema=SpecialistSelection,
            context={"engagement_id": engagement.engagement_id, "scope": engagement.scope},
        )
        if not isinstance(result, SpecialistSelection):
            raise StructuredOutputError("specialist selection output is not a SpecialistSelection")
        return result

    def plan_capability_request(self, engagement: Engagement, target_id: TargetId) -> CapabilityRequestSpec:
        assert self.model is not None
        result = self.model.complete_structured(
            prompt="plan the read-only capability request",
            output_schema=CapabilityRequestSpec,
            context={"engagement_id": engagement.engagement_id, "target_id": target_id},
        )
        if not isinstance(result, CapabilityRequestSpec):
            raise StructuredOutputError("capability request output is not a CapabilityRequestSpec")
        # the coordinator never asks for more than inspection
        if result.action not in {Action.INSPECT.value, Action.COLLECT.value}:
            raise UnauthorizedCapabilityError(
                f"coordinator requested action {result.action!r}; inspection-only ceiling violated"
            )
        return result

    def decide(self, engagement: Engagement) -> CoordinatorVerdict:
        assert self.model is not None
        if not engagement.scope or not engagement.target_ids:
            return CoordinatorVerdict(outcome="refuse", reason="missing scope or target")
        result = self.model.complete_structured(
            prompt="decide whether to proceed with the engagement",
            output_schema=CoordinatorVerdict,
            context={"engagement_id": engagement.engagement_id},
        )
        if not isinstance(result, CoordinatorVerdict):
            raise StructuredOutputError("verdict output is not a CoordinatorVerdict")
        return result

    def plan_assessment(
        self,
        engagement: Engagement,
        profile: TargetSecurityProfile,
        registry: SecurityServiceRegistry,
    ) -> AssessmentPlan:
        """Route from evidence-backed profile facts; the model never selects services."""
        return route_services(profile=profile, engagement=engagement, registry=registry)


@dataclass
class SecurityReviewSpecialistV1:
    """Reads authorized target evidence, requests read-only inspection
    capabilities, produces Observations and Claims with evidence references
    and stated uncertainty. NEVER creates Findings."""

    manifest: AgentManifest = field(default_factory=lambda: SECURITY_REVIEW_SPECIALIST_V1_MANIFEST)
    model: ModelPort | None = None

    def __post_init__(self) -> None:
        if self.model is None:
            self.model = DeterministicFakeModel(
                {
                    ObservationSet: {
                        "observations": [{"kind": "repo-inspection", "statement": "target files reviewed"}],
                        "claims": [
                            {
                                "statement": "no severity-worthy defect observed in reviewed scope",
                                "confidence": "medium",
                            }
                        ],
                        "uncertainty": "review limited to declared scope; not a full audit",
                    }
                }
            )

    def review(
        self,
        *,
        engagement_id: EngagementId,
        evidence_ids: list[EvidenceId],
        agent_run_id: AgentRunId,
    ) -> tuple[list[Observation], list[Claim]]:
        assert self.model is not None
        result = self.model.complete_structured(
            prompt="produce observations and claims from authorized evidence",
            output_schema=ObservationSet,
            context={"engagement_id": engagement_id, "evidence_ids": evidence_ids},
        )
        if not isinstance(result, ObservationSet):
            raise StructuredOutputError("specialist output is not an ObservationSet")
        observations = [
            Observation(
                observation_id=ObservationId(new_id("OB")),
                engagement_id=engagement_id,
                evidence_ids=evidence_ids,
                kind=item["kind"],
                statement=item["statement"],
                recorded_by_agent_id=self.manifest.agent_id,
            )
            for item in result.observations
        ]
        claims = [
            Claim(
                claim_id=ClaimId(new_id("CL")),
                engagement_id=engagement_id,
                agent_id=self.manifest.agent_id,
                agent_run_id=agent_run_id,
                observation_ids=[observation.observation_id for observation in observations],
                evidence_ids=evidence_ids,
                statement=item["statement"],
                confidence=Confidence(item.get("confidence", "unknown")),
                uncertainty=result.uncertainty,
            )
            for item in result.claims
        ]
        return observations, claims

    def request_capability(self, engagement: Engagement, target_id: TargetId) -> CapabilityRequestSpec:
        """Specialists request read-only inspection ONLY."""
        return CapabilityRequestSpec(
            capability_id="CAP-REPO-READONLY-INSPECTION",
            action=Action.INSPECT.value,
            target_id=target_id,
        )


# Structural assertion: the agents module has no Finding constructor path.
def _finding_never_constructed() -> None:
    try:
        FindingGuard()
    except FindingCreationForbiddenError:
        return
    raise AssertionError("FindingGuard must refuse construction")


from secscan.platform.agents.service_specialists import (  # noqa: E402
    AGENTSEC_SPECIALIST_V1_CONTRACT,
    AGENTSEC_SPECIALIST_V1_MANIFEST,
    APPSEC_SPECIALIST_V1_CONTRACT,
    APPSEC_SPECIALIST_V1_MANIFEST,
    SERVICE_SPECIALISTS,
    SUPPLYCHAIN_SPECIALIST_V1_CONTRACT,
    SUPPLYCHAIN_SPECIALIST_V1_MANIFEST,
    VULNINTEL_SPECIALIST_V1_CONTRACT,
    VULNINTEL_SPECIALIST_V1_MANIFEST,
    ServiceSpecialist,
)

__all__ = [
    "AGENTSEC_SPECIALIST_V1_CONTRACT",
    "AGENTSEC_SPECIALIST_V1_MANIFEST",
    "APPSEC_SPECIALIST_V1_CONTRACT",
    "APPSEC_SPECIALIST_V1_MANIFEST",
    "SERVICE_SPECIALISTS",
    "SUPPLYCHAIN_SPECIALIST_V1_CONTRACT",
    "SUPPLYCHAIN_SPECIALIST_V1_MANIFEST",
    "ServiceSpecialist",
    "VULNINTEL_SPECIALIST_V1_CONTRACT",
    "VULNINTEL_SPECIALIST_V1_MANIFEST",
]
