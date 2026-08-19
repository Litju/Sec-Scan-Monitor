"""Capability manifests: agents request registered capabilities, never
arbitrary binaries. See ADR-0007."""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from secscan.platform.domain.common import DomainModel
from secscan.platform.domain.ids import CapabilityId


class RiskClass(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SandboxRequirement(str, Enum):
    NONE = "none"
    REQUIRED = "required"
    OPTIONAL = "optional"


class NetworkPolicy(str, Enum):
    NONE = "none"
    LOOPBACK_ONLY = "loopback-only"
    ALLOWLISTED = "allowlisted"


class CapabilityManifest(DomainModel):
    """Static contract of one registered capability."""

    capability_id: CapabilityId
    version: str
    description: str
    risk_class: RiskClass
    accepted_inputs: list[str] = Field(default_factory=list)
    produced_outputs: list[str] = Field(default_factory=list)
    required_authority: str  # action name required to run this capability
    requires_approval: bool = False
    sandbox_profile: str = "default"
    sandbox_requirement: SandboxRequirement = SandboxRequirement.NONE
    network_policy: NetworkPolicy = NetworkPolicy.NONE
    timeout_seconds: int = 60
    resource_limits: dict[str, str] = Field(default_factory=dict)  # cpu/memory/pids bounds
    tool_identity: str = ""
    tool_version: str = ""
    tool_license: str = ""
    source_url: str = ""
    release_url: str = ""
    artifact_ref: str = ""
    artifact_digest: str = ""
    evidence_type: str = ""
    normalizer: str = ""
    failure_semantics: str = ""
    command_allowlist: list[str] = Field(default_factory=list)
