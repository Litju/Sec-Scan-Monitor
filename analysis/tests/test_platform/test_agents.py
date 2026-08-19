"""Agent contract tests (G14/G15).

- Typed structured outputs; fake model; fail-closed on schema mismatch.
- No direct Finding creation (structural + behavioral).
- Authority ceiling: coordinator cannot request mutation.
- Specialist produces observations + claims with uncertainty.
- No paid model required anywhere in this suite.
"""

from __future__ import annotations

import pytest

from secscan.platform.agents import (
    CapabilityRequestSpec,
    CoordinatorVerdict,
    DeterministicFakeModel,
    FindingCreationForbiddenError,
    FindingGuard,
    FirmCoordinatorV1,
    SecurityReviewSpecialistV1,
    SpecialistSelection,
    StructuredOutputError,
    UnauthorizedCapabilityError,
)
from secscan.platform.domain.engagement import Engagement
from secscan.platform.domain.ids import (
    AgentRunId,
    ClientId,
    EngagementId,
    EvidenceId,
    PrincipalId,
    TargetId,
)


def _engagement() -> Engagement:
    return Engagement(
        engagement_id=EngagementId("ENG-AGT-1"),
        client_id=ClientId("CLI-1"),
        requester_principal_id=PrincipalId("PRN-OP"),
        target_ids=[TargetId("TGT-1")],
        scope="fixture repo",
        pass_type="posture",
    )


class TestManifests:
    def test_coordinator_manifest_authority_ceiling(self) -> None:
        manifest = FirmCoordinatorV1().manifest
        assert manifest.authority_ceiling == "inspect"
        assert "create-finding" in manifest.forbidden_tools
        assert "mutate-target" in manifest.forbidden_tools

    def test_coordinator_manifest_declares_f200_scanners(self) -> None:
        manifest = FirmCoordinatorV1().manifest
        for capability_id in (
            "CAP-REPO-READONLY-INSPECTION",
            "CAP-SAST-SEMGREP",
            "CAP-SCA-OSV",
            "CAP-SECRETS-GITLEAKS",
            "CAP-REPO-TRIVY",
        ):
            assert capability_id in manifest.requested_capabilities

    def test_specialist_manifest_read_only(self) -> None:
        manifest = SecurityReviewSpecialistV1().manifest
        assert manifest.authority_ceiling == "inspect"
        assert "active-testing" in manifest.forbidden_tools
        assert "CAP-REPO-READONLY-INSPECTION" in manifest.requested_capabilities


class TestStructuredOutputs:
    def test_fake_model_returns_valid_typed_output(self) -> None:
        model = DeterministicFakeModel(
            {SpecialistSelection: {"specialist_ids": ["AGT-X"], "rationale": "ok"}}
        )
        result = model.complete_structured(prompt="x", output_schema=SpecialistSelection)
        assert isinstance(result, SpecialistSelection)
        assert result.specialist_ids == ["AGT-X"]

    def test_fake_model_fails_closed_on_schema_mismatch(self) -> None:
        model = DeterministicFakeModel(
            {SpecialistSelection: {"specialist_ids": [], "rationale": "empty"}}  # min_length violated
        )
        with pytest.raises(StructuredOutputError):
            model.complete_structured(prompt="x", output_schema=SpecialistSelection)

    def test_fake_model_unknown_schema_fails_closed(self) -> None:
        model = DeterministicFakeModel({})
        with pytest.raises(StructuredOutputError):
            model.complete_structured(prompt="x", output_schema=CoordinatorVerdict)


class TestCoordinator:
    def test_selects_specialist_and_decides(self) -> None:
        coordinator = FirmCoordinatorV1()
        engagement = _engagement()
        selection = coordinator.select_specialists(engagement)
        assert "AGT-SECURITY-REVIEW-SPECIALIST" in selection.specialist_ids
        verdict = coordinator.decide(engagement)
        assert verdict.outcome == "proceed"

    def test_refuses_missing_scope(self) -> None:
        coordinator = FirmCoordinatorV1()
        engagement = Engagement(
            engagement_id=EngagementId("ENG-AGT-2"),
            client_id=ClientId("CLI-1"),
            requester_principal_id=PrincipalId("PRN-OP"),
            target_ids=[],
            scope="",
            pass_type="posture",
        )
        verdict = coordinator.decide(engagement)
        assert verdict.outcome == "refuse"

    def test_capability_request_stays_inspection_only(self) -> None:
        coordinator = FirmCoordinatorV1()
        request = coordinator.plan_capability_request(_engagement(), TargetId("TGT-1"))
        assert request.action == "inspect"
        assert request.capability_id == "CAP-REPO-READONLY-INSPECTION"

    def test_mutation_request_violates_ceiling(self) -> None:
        model = DeterministicFakeModel(
            {
                CapabilityRequestSpec: {
                    "capability_id": "CAP-X",
                    "action": "mutate",
                    "target_id": "TGT-1",
                }
            }
        )
        coordinator = FirmCoordinatorV1(model=model)
        with pytest.raises(UnauthorizedCapabilityError):
            coordinator.plan_capability_request(_engagement(), TargetId("TGT-1"))


class TestSpecialist:
    def test_produces_observations_and_claims_with_uncertainty(self) -> None:
        specialist = SecurityReviewSpecialistV1()
        observations, claims = specialist.review(
            engagement_id=EngagementId("ENG-AGT-1"),
            evidence_ids=[EvidenceId("EV-1")],
            agent_run_id=AgentRunId("AR-1"),
        )
        assert observations
        assert claims
        assert claims[0].uncertainty  # stated uncertainty required
        assert claims[0].evidence_ids == [EvidenceId("EV-1")]

    def test_specialist_requests_read_only_capability(self) -> None:
        specialist = SecurityReviewSpecialistV1()
        request = specialist.request_capability(_engagement(), TargetId("TGT-1"))
        assert request.action == "inspect"
        assert request.capability_id == "CAP-REPO-READONLY-INSPECTION"


class TestNoDirectFindingCreation:
    def test_finding_guard_refuses_construction(self) -> None:
        with pytest.raises(FindingCreationForbiddenError):
            FindingGuard()

    def test_agent_outputs_are_claims_not_findings(self) -> None:
        """Agents produce Claim objects; the type system keeps Finding out of
        the agent output path."""
        specialist = SecurityReviewSpecialistV1()
        _, claims = specialist.review(
            engagement_id=EngagementId("ENG-AGT-1"),
            evidence_ids=[EvidenceId("EV-1")],
            agent_run_id=AgentRunId("AR-1"),
        )
        from secscan.platform.domain.evidence import Claim
        from secscan.platform.domain.finding import Finding

        assert all(isinstance(claim, Claim) for claim in claims)
        assert all(not isinstance(claim, Finding) for claim in claims)
