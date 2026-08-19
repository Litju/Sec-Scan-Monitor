"""Canonical contracts/manifests for Release 0.1 service specialists."""

from __future__ import annotations

from dataclasses import dataclass

from secscan.platform.domain.agents import AgentManifest, AgentRole
from secscan.platform.domain.authority import Action
from secscan.platform.domain.ids import AgentId, AgentManifestId, CapabilityId
from secscan.platform.domain.qualification import AgentContract


def _manifest(*, agent_id: str, manifest_id: str, role: AgentRole, capabilities: list[str], outputs: list[str]) -> AgentManifest:
    return AgentManifest(
        manifest_id=AgentManifestId(manifest_id),
        agent_id=AgentId(agent_id),
        role=role,
        version="0.1.0",
        accepted_inputs=["engagement_contract", "target_security_profile", "authorized_evidence"],
        produced_outputs=outputs,
        requested_capabilities=[CapabilityId(capability) for capability in capabilities],
        allowed_tools=["read-evidence", "request-inspection-capability", "send-claims"],
        forbidden_tools=["create-finding", "mutate-target", "execute-shell", "change-authority"],
        authority_ceiling=Action.INSPECT.value,
        evidence_consumed=["evidence_objects", "profile_facts"],
        evidence_produced=["observations", "claims"],
        escalation_rules=["request missing evidence; never expand scope"],
        refusal_rules=["refuse out-of-scope, unqualified, or secret-bearing requests"],
        timeout_policy="bounded per service run",
        retry_policy="idempotent replay by engagement and service run identity",
    )


APPSEC_SPECIALIST_V1_MANIFEST = _manifest(
    agent_id="AGT-APPSEC-SPECIALIST",
    manifest_id="AM-APPSEC-SPECIALIST-V1",
    role=AgentRole.APPSEC_SPECIALIST,
    capabilities=["CAP-REPO-READONLY-INSPECTION"],
    outputs=["appsec_observations", "appsec_claims"],
)
AGENTSEC_SPECIALIST_V1_MANIFEST = _manifest(
    agent_id="AGT-AGENTSEC-SPECIALIST",
    manifest_id="AM-AGENTSEC-SPECIALIST-V1",
    role=AgentRole.AGENTSEC_SPECIALIST,
    capabilities=["CAP-REPO-READONLY-INSPECTION"],
    outputs=["agent_security_observations", "agent_security_claims"],
)
VULNINTEL_SPECIALIST_V1_MANIFEST = _manifest(
    agent_id="AGT-VULNINTEL-SPECIALIST",
    manifest_id="AM-VULNINTEL-SPECIALIST-V1",
    role=AgentRole.VULNERABILITY_INTELLIGENCE_SPECIALIST,
    capabilities=["CAP-REPO-READONLY-INSPECTION"],
    outputs=["vulnerability_context", "priority_explanations"],
)
SUPPLYCHAIN_SPECIALIST_V1_MANIFEST = _manifest(
    agent_id="AGT-SUPPLYCHAIN-SPECIALIST",
    manifest_id="AM-SUPPLYCHAIN-SPECIALIST-V1",
    role=AgentRole.SUPPLY_CHAIN_SPECIALIST,
    capabilities=["CAP-REPO-READONLY-INSPECTION"],
    outputs=["supply_chain_observations", "supply_chain_claims"],
)


def _contract(manifest: AgentManifest, mission: str, outputs: list[str], evidence: list[str]) -> AgentContract:
    return AgentContract(
        agent_id=str(manifest.agent_id),
        version=manifest.version,
        mission=mission,
        allowed_inputs=manifest.accepted_inputs,
        allowed_outputs=outputs,
        authority_ceiling=manifest.authority_ceiling,
        allowed_capabilities=[str(value) for value in manifest.requested_capabilities],
        forbidden_capabilities=["mutate", "remediate", "active_test", "create-finding", "execute-shell"],
        evidence_requirements=evidence,
        claim_requirements=["claim references evidence", "claim states uncertainty", "finding is adjudication-only"],
        refusal_behavior=manifest.refusal_rules,
        uncertainty_behavior=["say not validated when evidence is absent", "preserve contradictory evidence"],
        secret_handling=["never reproduce values", "retain only safe metadata and evidence references"],
        cross_engagement_law="all inputs, evidence, claims, and runs must match the engagement and target scope",
        model_provider_independence="deterministic engine is canonical; model adapters are replaceable and untrusted",
    )


APPSEC_SPECIALIST_V1_CONTRACT = _contract(APPSEC_SPECIALIST_V1_MANIFEST, "Assess application security controls from authorized evidence.", ["observations", "claims"], ["source", "configuration", "test", "scanner_output"])
AGENTSEC_SPECIALIST_V1_CONTRACT = _contract(AGENTSEC_SPECIALIST_V1_MANIFEST, "Assess agent identity, authority, memory, tools, and external content risks.", ["observations", "claims", "authority_graph"], ["agent_manifest", "tool_registry", "authority_config", "memory_config"])
VULNINTEL_SPECIALIST_V1_CONTRACT = _contract(VULNINTEL_SPECIALIST_V1_MANIFEST, "Explain deterministic vulnerability enrichment and target-specific priority.", ["observations", "claims", "priority_decisions"], ["dependency_manifest", "advisory", "feed_provenance"])
SUPPLYCHAIN_SPECIALIST_V1_CONTRACT = _contract(SUPPLYCHAIN_SPECIALIST_V1_MANIFEST, "Interpret deterministic dependency, build, provenance, and release evidence.", ["observations", "claims", "control_status"], ["sbom", "lockfile", "ci_workflow", "provenance"])


@dataclass(frozen=True)
class ServiceSpecialist:
    manifest: AgentManifest
    contract: AgentContract

    def assert_capability_allowed(self, capability_id: str) -> None:
        if capability_id not in self.contract.allowed_capabilities:
            raise PermissionError(f"specialist {self.manifest.agent_id} refused capability {capability_id}")


SERVICE_SPECIALISTS = (
    ServiceSpecialist(APPSEC_SPECIALIST_V1_MANIFEST, APPSEC_SPECIALIST_V1_CONTRACT),
    ServiceSpecialist(AGENTSEC_SPECIALIST_V1_MANIFEST, AGENTSEC_SPECIALIST_V1_CONTRACT),
    ServiceSpecialist(VULNINTEL_SPECIALIST_V1_MANIFEST, VULNINTEL_SPECIALIST_V1_CONTRACT),
    ServiceSpecialist(SUPPLYCHAIN_SPECIALIST_V1_MANIFEST, SUPPLYCHAIN_SPECIALIST_V1_CONTRACT),
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
