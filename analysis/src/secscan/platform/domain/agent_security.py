"""Typed agent-system security profile and authority graph."""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from secscan.platform.domain.common import Confidence, DomainModel


class AgentRelationshipKind(str, Enum):
    CALLS = "CALLS"
    DELEGATES = "DELEGATES"
    READS = "READS"
    WRITES = "WRITES"
    APPROVES = "APPROVES"
    RETRIEVES = "RETRIEVES"


class AgentNode(DomainModel):
    agent_id: str
    identity: str
    model_provider: str = ""
    declared_capabilities: list[str] = Field(default_factory=list)
    effective_capabilities: list[str] = Field(default_factory=list)
    source_ref: str


class ToolNode(DomainModel):
    tool_id: str
    name: str
    transport: str = ""
    source_ref: str
    schema_ref: str = ""
    dynamic_discovery: bool = False


class ToolAuthorityEdge(DomainModel):
    agent_id: str
    capability_id: str
    tool_id: str
    target_ref: str
    authority_ref: str = ""
    approval_ref: str = ""
    declared: bool = True
    effective: bool = True
    source_ref: str


class MemoryBoundary(DomainModel):
    memory_id: str
    scope: str
    provenance: str = ""
    read_authority: list[str] = Field(default_factory=list)
    write_authority: list[str] = Field(default_factory=list)
    deletion_supported: bool | None = None
    source_ref: str


class AgentSystemManifest(DomainModel):
    """Evidence-derived manifest; declarations and effective authority differ."""

    agents: list[AgentNode] = Field(default_factory=list)
    tools: list[ToolNode] = Field(default_factory=list)
    authority_edges: list[ToolAuthorityEdge] = Field(default_factory=list)
    memory: list[MemoryBoundary] = Field(default_factory=list)
    mcp_servers: list[str] = Field(default_factory=list)
    a2a_relationships: list[str] = Field(default_factory=list)
    external_inputs: list[str] = Field(default_factory=list)
    secret_scopes: list[str] = Field(default_factory=list)
    approval_boundaries: list[str] = Field(default_factory=list)
    execution_authority: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)


class AgentSystemSecurityProfile(DomainModel):
    target_id: str
    snapshot_id: str
    manifest: AgentSystemManifest
    threat_references: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)


class AgentSecurityObservation(DomainModel):
    code: str
    statement: str
    evidence_refs: list[str] = Field(default_factory=list)
    threat_mapping: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.UNKNOWN
    limitation: str = ""


__all__ = [
    "AgentNode",
    "AgentRelationshipKind",
    "AgentSecurityObservation",
    "AgentSystemManifest",
    "AgentSystemSecurityProfile",
    "MemoryBoundary",
    "ToolAuthorityEdge",
    "ToolNode",
]
