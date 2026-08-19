"""Shared, provenance-backed target security profile value objects."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import Field

from secscan.platform.domain.common import Confidence, DomainModel


class ProfileFactStatus(str, Enum):
    DECLARED = "DECLARED"
    DISCOVERED = "DISCOVERED"
    IMPLEMENTED = "IMPLEMENTED"
    TESTED = "TESTED"
    CONFIGURED = "CONFIGURED"
    CONTRADICTED = "CONTRADICTED"
    UNKNOWN = "UNKNOWN"


class ProfileProvenance(DomainModel):
    """Safe provenance for a profile fact; never contains raw secret values."""

    source_kind: str
    source_ref: str
    snapshot_id: str
    evidence_id: str | None = None
    source_digest: str | None = None


class ProfileFact(DomainModel):
    """One factual profile assertion with explicit status and provenance."""

    key: str
    value: Any
    status: ProfileFactStatus
    confidence: Confidence = Confidence.UNKNOWN
    provenance: ProfileProvenance
    limitation: str = ""


class TargetSecurityProfile(DomainModel):
    """Shared factual substrate consumed by every Release 0.1 service."""

    target_id: str
    snapshot_id: str
    target_identity: str
    snapshot_identity: str
    target_class: str = "unknown"
    languages: list[ProfileFact] = Field(default_factory=list)
    frameworks: list[ProfileFact] = Field(default_factory=list)
    package_ecosystems: list[ProfileFact] = Field(default_factory=list)
    entry_points: list[ProfileFact] = Field(default_factory=list)
    api_surfaces: list[ProfileFact] = Field(default_factory=list)
    authentication_surfaces: list[ProfileFact] = Field(default_factory=list)
    authorization_surfaces: list[ProfileFact] = Field(default_factory=list)
    database_storage: list[ProfileFact] = Field(default_factory=list)
    network_interfaces: list[ProfileFact] = Field(default_factory=list)
    containers: list[ProfileFact] = Field(default_factory=list)
    infrastructure_as_code: list[ProfileFact] = Field(default_factory=list)
    cicd: list[ProfileFact] = Field(default_factory=list)
    build_release: list[ProfileFact] = Field(default_factory=list)
    external_services: list[ProfileFact] = Field(default_factory=list)
    cloud_integrations: list[ProfileFact] = Field(default_factory=list)
    agentic_components: list[ProfileFact] = Field(default_factory=list)
    model_providers: list[ProfileFact] = Field(default_factory=list)
    mcp_servers: list[ProfileFact] = Field(default_factory=list)
    tool_interfaces: list[ProfileFact] = Field(default_factory=list)
    memory_persistence: list[ProfileFact] = Field(default_factory=list)
    secret_references: list[ProfileFact] = Field(default_factory=list)
    security_configuration: list[ProfileFact] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)

    @property
    def has_agentic_surface(self) -> bool:
        return bool(self.agentic_components or self.tool_interfaces or self.mcp_servers)

    def facts(self) -> list[ProfileFact]:
        """Return facts in stable field order for deterministic consumers."""
        fields = (
            "languages", "frameworks", "package_ecosystems", "entry_points", "api_surfaces",
            "authentication_surfaces", "authorization_surfaces", "database_storage", "network_interfaces",
            "containers", "infrastructure_as_code", "cicd", "build_release", "external_services",
            "cloud_integrations", "agentic_components", "model_providers", "mcp_servers", "tool_interfaces",
            "memory_persistence", "secret_references", "security_configuration",
        )
        return [fact for field in fields for fact in getattr(self, field)]


__all__ = ["ProfileFact", "ProfileFactStatus", "ProfileProvenance", "TargetSecurityProfile"]
