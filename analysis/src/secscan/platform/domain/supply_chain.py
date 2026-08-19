"""Software supply-chain assessment value objects."""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from secscan.platform.domain.common import Confidence, DomainModel


class SupplyChainStage(str, Enum):
    SOURCE = "SOURCE"
    DEPENDENCY_RESOLUTION = "DEPENDENCY_RESOLUTION"
    BUILD_ENVIRONMENT = "BUILD_ENVIRONMENT"
    CICD = "CI_CD"
    ARTIFACT = "ARTIFACT"
    PROVENANCE = "PROVENANCE"
    RELEASE = "RELEASE"
    UNKNOWN = "UNKNOWN"


class ControlStatus(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_ASSESSED = "NOT_ASSESSED"
    INCONCLUSIVE = "INCONCLUSIVE"


class SbomComponent(DomainModel):
    name: str
    version: str
    ecosystem: str = ""
    purl: str | None = None
    hashes: list[str] = Field(default_factory=list)
    dependency_refs: list[str] = Field(default_factory=list)


class SbomAssessment(DomainModel):
    present: bool
    format: str = ""
    version: str = ""
    source_ref: str = ""
    fresh: bool | None = None
    components: list[SbomComponent] = Field(default_factory=list)
    completeness: ControlStatus = ControlStatus.NOT_ASSESSED
    unknowns: list[str] = Field(default_factory=list)


class ProvenanceAssessment(DomainModel):
    present: bool
    source_ref: str = ""
    builder_identity: str = ""
    source_revision: str = ""
    subjects: list[str] = Field(default_factory=list)
    attestation_type: str = ""
    slsa_version: str = "1.2"
    status: ControlStatus = ControlStatus.NOT_ASSESSED
    contradictions: list[str] = Field(default_factory=list)


class WorkflowAssessment(DomainModel):
    path: str
    action_refs: list[str] = Field(default_factory=list)
    mutable_action_refs: list[str] = Field(default_factory=list)
    permissions: dict[str, str] = Field(default_factory=dict)
    dangerous_permissions: list[str] = Field(default_factory=list)
    pull_request_target: bool = False
    script_injection_candidates: list[str] = Field(default_factory=list)
    release_permissions: list[str] = Field(default_factory=list)
    status: ControlStatus = ControlStatus.NOT_ASSESSED


class PackageResolutionAssessment(DomainModel):
    manifests: list[str] = Field(default_factory=list)
    lockfiles: list[str] = Field(default_factory=list)
    missing_lockfiles: list[str] = Field(default_factory=list)
    registries: list[str] = Field(default_factory=list)
    integrity_hashes_present: bool | None = None
    workspace_resolution: bool = False
    status: ControlStatus = ControlStatus.NOT_ASSESSED
    unknowns: list[str] = Field(default_factory=list)


class SupplyChainAssessment(DomainModel):
    stages: dict[SupplyChainStage, ControlStatus] = Field(default_factory=dict)
    sbom: SbomAssessment
    provenance: ProvenanceAssessment
    workflows: list[WorkflowAssessment] = Field(default_factory=list)
    package_resolution: PackageResolutionAssessment
    containers: list[str] = Field(default_factory=list)
    container_base_refs: list[str] = Field(default_factory=list)
    digest_pinned_bases: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    claims: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.UNKNOWN


__all__ = [
    "ControlStatus",
    "PackageResolutionAssessment",
    "ProvenanceAssessment",
    "SbomAssessment",
    "SbomComponent",
    "SupplyChainAssessment",
    "SupplyChainStage",
    "WorkflowAssessment",
]
