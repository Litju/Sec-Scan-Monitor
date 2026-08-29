"""Continuous security foundation: graph, events, patrol, gateway, and runner.

The package deliberately keeps the reusable contracts small. PostgreSQL,
OPA, evidence storage, and sandbox execution remain injected adapters; these
modules do not create a second canonical state store or a protocol proxy.
"""

from secscan.platform.continuous_security.campaign import SyntheticAgentPlatform
from secscan.platform.continuous_security.events import (
    EventClass,
    EventIdentityConflict,
    EventTimestampError,
    SecurityEvent,
    SecurityEventPlane,
)
from secscan.platform.continuous_security.gateway import (
    AgentSecurityGateway,
    GatewayRegistry,
    GatewayRequest,
    GatewayResult,
    ProtocolKind,
    RegisteredAgent,
    RegisteredTool,
)
from secscan.platform.continuous_security.graph import (
    GraphBuilder,
    GraphEdge,
    GraphEntityType,
    GraphNode,
    GraphProvenance,
    GraphProvenanceStatus,
    GraphRelation,
    SecurityGraph,
)
from secscan.platform.continuous_security.patrol import (
    CanonicalSnapshot,
    ChangeState,
    InMemoryFindingStore,
    PatrolCandidate,
    PatrolEngine,
    PatrolFinding,
    PatrolRunResult,
)
from secscan.platform.continuous_security.runner import (
    CanonicalJob,
    EdgeRunnerPort,
    ReferenceEdgeRunner,
    ResultReceipt,
    WorkloadIdentityPort,
)

__all__ = [
    "CanonicalSnapshot",
    "CanonicalJob",
    "ChangeState",
    "EventClass",
    "EventIdentityConflict",
    "EventTimestampError",
    "AgentSecurityGateway",
    "EdgeRunnerPort",
    "GatewayRegistry",
    "GatewayRequest",
    "GatewayResult",
    "GraphBuilder",
    "GraphEdge",
    "GraphEntityType",
    "GraphNode",
    "GraphProvenance",
    "GraphProvenanceStatus",
    "GraphRelation",
    "InMemoryFindingStore",
    "PatrolCandidate",
    "PatrolEngine",
    "PatrolFinding",
    "PatrolRunResult",
    "ProtocolKind",
    "ReferenceEdgeRunner",
    "RegisteredAgent",
    "RegisteredTool",
    "ResultReceipt",
    "SecurityEvent",
    "SecurityEventPlane",
    "SecurityGraph",
    "SyntheticAgentPlatform",
    "WorkloadIdentityPort",
]
