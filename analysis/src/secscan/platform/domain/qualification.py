"""AQS-V1 contracts, gates, and evidence-derived qualification receipts."""

from __future__ import annotations

from enum import Enum
from typing import Iterable, Mapping

from pydantic import Field

from secscan.platform.domain.agents import AgentManifest
from secscan.platform.domain.common import DomainModel


class AqsMaturity(str, Enum):
    PERSONA = "PERSONA"
    CONTRACTED = "CONTRACTED"
    SYNTHETIC_QUALIFIED = "SYNTHETIC_QUALIFIED"
    ADVERSARIAL_QUALIFIED = "ADVERSARIAL_QUALIFIED"
    REAL_READ_ONLY_QUALIFIED = "REAL_READ_ONLY_QUALIFIED"
    SHADOW_QUALIFIED = "SHADOW_QUALIFIED"
    LIMITED_PRODUCTION = "LIMITED_PRODUCTION"
    FULLY_QUALIFIED = "FULLY_QUALIFIED"


class AqsGateStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_RUN = "NOT_RUN"
    NOT_APPLICABLE_WITH_JUSTIFICATION = "NOT_APPLICABLE_WITH_JUSTIFICATION"
    BLOCKED = "BLOCKED"


class AqsGateId(str, Enum):
    AQS_01 = "AQS-01"
    AQS_02 = "AQS-02"
    AQS_03 = "AQS-03"
    AQS_04 = "AQS-04"
    AQS_05 = "AQS-05"
    AQS_06 = "AQS-06"
    AQS_07 = "AQS-07"
    AQS_08 = "AQS-08"
    AQS_09 = "AQS-09"
    AQS_10 = "AQS-10"
    AQS_11 = "AQS-11"
    AQS_12 = "AQS-12"
    AQS_13 = "AQS-13"
    AQS_14 = "AQS-14"
    AQS_15 = "AQS-15"
    AQS_16 = "AQS-16"
    AQS_17 = "AQS-17"
    AQS_18 = "AQS-18"
    AQS_19 = "AQS-19"
    AQS_20 = "AQS-20"
    AQS_21 = "AQS-21"
    AQS_22 = "AQS-22"
    AQS_23 = "AQS-23"
    AQS_24 = "AQS-24"


class AgentContract(DomainModel):
    """Canonical specialist contract; prompts are not the authority."""

    agent_id: str
    version: str
    mission: str
    allowed_inputs: list[str] = Field(default_factory=list)
    allowed_outputs: list[str] = Field(default_factory=list)
    authority_ceiling: str
    allowed_capabilities: list[str] = Field(default_factory=list)
    forbidden_capabilities: list[str] = Field(default_factory=list)
    evidence_requirements: list[str] = Field(default_factory=list)
    claim_requirements: list[str] = Field(default_factory=list)
    refusal_behavior: list[str] = Field(default_factory=list)
    uncertainty_behavior: list[str] = Field(default_factory=list)
    secret_handling: list[str] = Field(default_factory=list)
    cross_engagement_law: str
    model_provider_independence: str


class AqsGateResult(DomainModel):
    gate_id: AqsGateId
    status: AqsGateStatus
    evidence_refs: list[str] = Field(default_factory=list)
    notes: str = ""


class QualificationReceipt(DomainModel):
    """Machine-readable receipt derived from executed gate evidence."""

    agent_id: str
    agent_version: str
    aqs_version: str = "AQS-V1"
    gates: list[AqsGateResult]
    fixtures: list[str] = Field(default_factory=list)
    positive_controls: list[str] = Field(default_factory=list)
    negative_controls: list[str] = Field(default_factory=list)
    adversarial_controls: list[str] = Field(default_factory=list)
    tests: list[str] = Field(default_factory=list)
    qualification_level: AqsMaturity = AqsMaturity.PERSONA
    limitations: list[str] = Field(default_factory=list)
    source_commit: str = ""

    @property
    def failed_gates(self) -> list[AqsGateResult]:
        return [
            gate
            for gate in self.gates
            if gate.status not in {AqsGateStatus.PASS, AqsGateStatus.NOT_APPLICABLE_WITH_JUSTIFICATION}
        ]

    @property
    def not_run_gates(self) -> list[AqsGateResult]:
        return [gate for gate in self.gates if gate.status == AqsGateStatus.NOT_RUN]

    def assert_honest(self) -> None:
        if self.qualification_level in {
            AqsMaturity.SYNTHETIC_QUALIFIED,
            AqsMaturity.ADVERSARIAL_QUALIFIED,
            AqsMaturity.REAL_READ_ONLY_QUALIFIED,
            AqsMaturity.SHADOW_QUALIFIED,
            AqsMaturity.LIMITED_PRODUCTION,
            AqsMaturity.FULLY_QUALIFIED,
        } and self.failed_gates:
            raise ValueError("qualified receipt contains failed or unrun gates")
        if self.qualification_level == AqsMaturity.REAL_READ_ONLY_QUALIFIED and not any(
            "real" in fixture.lower() or "dogfood" in fixture.lower() for fixture in self.fixtures
        ):
            raise ValueError("real-read-only qualification requires real/dogfood evidence")


class AqsQualificationRunner:
    """Small deterministic runner that never promotes from a manual boolean."""

    def qualify(
        self,
        *,
        manifest: AgentManifest,
        contract: AgentContract,
        gate_evidence: Mapping[str, tuple[AqsGateStatus, list[str], str]],
        fixtures: Iterable[str],
        positive_controls: Iterable[str],
        negative_controls: Iterable[str],
        adversarial_controls: Iterable[str],
        tests: Iterable[str],
        real_read_only: bool = False,
        source_commit: str = "",
    ) -> QualificationReceipt:
        if manifest.agent_id != contract.agent_id:
            raise ValueError("agent manifest and contract identity differ")
        gates = [
            AqsGateResult(
                gate_id=gate,
                status=gate_evidence.get(gate.value, (AqsGateStatus.NOT_RUN, [], "not executed"))[0],
                evidence_refs=gate_evidence.get(gate.value, (AqsGateStatus.NOT_RUN, [], "not executed"))[1],
                notes=gate_evidence.get(gate.value, (AqsGateStatus.NOT_RUN, [], "not executed"))[2],
            )
            for gate in AqsGateId
        ]
        fixture_values = list(fixtures)
        positive_values = list(positive_controls)
        negative_values = list(negative_controls)
        adversarial_values = list(adversarial_controls)
        test_values = list(tests)
        all_pass = all(
            gate.status in {AqsGateStatus.PASS, AqsGateStatus.NOT_APPLICABLE_WITH_JUSTIFICATION}
            for gate in gates
        )
        if not all_pass:
            level = AqsMaturity.CONTRACTED if contract.mission else AqsMaturity.PERSONA
        elif real_read_only:
            level = AqsMaturity.REAL_READ_ONLY_QUALIFIED
        elif adversarial_values:
            level = AqsMaturity.ADVERSARIAL_QUALIFIED
        elif positive_values and negative_values:
            level = AqsMaturity.SYNTHETIC_QUALIFIED
        else:
            level = AqsMaturity.CONTRACTED
        receipt = QualificationReceipt(
            agent_id=str(manifest.agent_id),
            agent_version=manifest.version,
            gates=gates,
            fixtures=fixture_values,
            positive_controls=positive_values,
            negative_controls=negative_values,
            adversarial_controls=adversarial_values,
            tests=test_values,
            qualification_level=level,
            limitations=[] if all_pass else ["AQS gate evidence is incomplete"],
            source_commit=source_commit,
        )
        if level in {AqsMaturity.REAL_READ_ONLY_QUALIFIED, AqsMaturity.ADVERSARIAL_QUALIFIED, AqsMaturity.SYNTHETIC_QUALIFIED}:
            receipt.assert_honest()
        return receipt


__all__ = [
    "AgentContract",
    "AqsGateId",
    "AqsGateResult",
    "AqsGateStatus",
    "AqsMaturity",
    "AqsQualificationRunner",
    "QualificationReceipt",
]
