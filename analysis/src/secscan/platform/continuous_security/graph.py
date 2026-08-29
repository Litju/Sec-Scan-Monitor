"""Deterministic, provenance-bearing security graph contracts.

The graph is a projection of canonical state, not an inference engine. Every
node and edge is supplied by a caller with provenance. The PostgreSQL adapter
persists the canonical JSON representation; this module contains the pure
construction, replay, and bounded query behavior.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class GraphEntityType(str, Enum):
    ASSET = "Asset"
    IDENTITY = "Identity"
    AGENT = "Agent"
    SERVICE = "Service"
    INTERFACE = "Interface"
    MCP_SERVER = "MCPServer"
    A2A_AGENT = "A2AAgent"
    TOOL = "Tool"
    CAPABILITY = "Capability"
    DEPENDENCY = "Dependency"
    VULNERABILITY = "Vulnerability"
    POLICY = "Policy"
    DEPLOYMENT = "Deployment"
    EVIDENCE = "Evidence"
    FINDING = "Finding"


class GraphRelation(str, Enum):
    EXPOSES = "EXPOSES"
    CALLS = "CALLS"
    USES = "USES"
    CAN_INVOKE = "CAN_INVOKE"
    ACCESSES = "ACCESSES"
    DEPENDS_ON = "DEPENDS_ON"
    AFFECTED_BY = "AFFECTED_BY"
    GOVERNED_BY = "GOVERNED_BY"
    DEPLOYED_AS = "DEPLOYED_AS"
    SUPPORTED_BY = "SUPPORTED_BY"


class GraphProvenanceStatus(str, Enum):
    DECLARED = "declared"
    DISCOVERED = "discovered"
    VERIFIED = "verified"
    CONTRADICTED = "contradicted"
    UNKNOWN = "unknown"


class GraphProvenance(_FrozenModel):
    """Source and evidence metadata for one graph assertion."""

    source: str
    source_type: str
    observed_at: datetime
    normalization_version: str = "security-graph-v1"
    status: GraphProvenanceStatus = GraphProvenanceStatus.UNKNOWN
    evidence_refs: tuple[str, ...] = ()

    @field_validator("source", "source_type", "normalization_version")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("graph provenance text fields must be non-empty")
        return value

    @field_validator("observed_at")
    @classmethod
    def _timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("graph provenance timestamps must be timezone-aware")
        return value.astimezone(UTC)


class GraphNode(_FrozenModel):
    """One explicitly observed entity in a graph snapshot."""

    entity_id: str
    entity_type: GraphEntityType
    attributes: dict[str, Any] = Field(default_factory=dict)
    provenance: tuple[GraphProvenance, ...]

    @field_validator("entity_id")
    @classmethod
    def _entity_id_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("graph entity_id must be non-empty")
        return value

    @model_validator(mode="after")
    def _requires_provenance(self) -> GraphNode:
        if not self.provenance:
            raise ValueError("every graph node requires provenance")
        return self

    @property
    def node_key(self) -> str:
        return f"{self.entity_type.value}:{self.entity_id}"


class GraphEdge(_FrozenModel):
    """One explicitly observed relationship; it never represents inference."""

    edge_id: str
    source_node: str
    target_node: str
    relation: GraphRelation
    provenance: tuple[GraphProvenance, ...]
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("edge_id", "source_node", "target_node")
    @classmethod
    def _edge_text_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("graph edge identifiers and endpoints must be non-empty")
        return value

    @model_validator(mode="after")
    def _requires_provenance(self) -> GraphEdge:
        if not self.provenance:
            raise ValueError("every graph edge requires provenance")
        return self


@dataclass(frozen=True)
class GraphPath:
    """A bounded directed path returned by a graph query."""

    node_keys: tuple[str, ...]
    edge_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, list[str]]:
        return {"nodes": list(self.node_keys), "edges": list(self.edge_ids)}


class SecurityGraph(_FrozenModel):
    """Immutable graph snapshot reconstructed from canonical state."""

    tenant_id: str
    case_id: str
    target_id: str
    snapshot_id: str
    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()

    @model_validator(mode="after")
    def _validate_state(self) -> SecurityGraph:
        scope = (self.tenant_id, self.case_id, self.target_id, self.snapshot_id)
        if any(not value.strip() for value in scope):
            raise ValueError("graph scope identifiers must be non-empty")
        node_keys = [node.node_key for node in self.nodes]
        if len(node_keys) != len(set(node_keys)):
            raise ValueError("duplicate graph node")
        edge_ids = [edge.edge_id for edge in self.edges]
        if len(edge_ids) != len(set(edge_ids)):
            raise ValueError("duplicate graph edge")
        known = set(node_keys)
        for edge in self.edges:
            if edge.source_node not in known or edge.target_node not in known:
                raise ValueError("graph edges may reference only observed nodes")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload["nodes"] = sorted(payload["nodes"], key=lambda item: (item["entity_type"], item["entity_id"]))
        payload["edges"] = sorted(
            payload["edges"], key=lambda item: (item["source_node"], item["target_node"], item["relation"], item["edge_id"])
        )
        return payload

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def replay(cls, canonical_state: bytes | str | dict[str, Any]) -> SecurityGraph:
        """Reconstruct exactly one graph from persisted canonical state."""
        if isinstance(canonical_state, bytes):
            canonical_state = canonical_state.decode("utf-8")
        if isinstance(canonical_state, str):
            canonical_state = json.loads(canonical_state)
        # Strict models intentionally reject JSON's list/string coercions at
        # normal construction time. Replay is the one serialization seam, so
        # restore the typed tuple/enum/datetime values explicitly.
        if not isinstance(canonical_state, dict):
            raise ValueError("canonical graph state must be an object")
        state = dict(canonical_state)

        def restore_provenance(items: list[dict[str, Any]]) -> tuple[GraphProvenance, ...]:
            restored: list[GraphProvenance] = []
            for item in items:
                value = dict(item)
                observed_at = value.get("observed_at")
                if isinstance(observed_at, str):
                    value["observed_at"] = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
                if isinstance(value.get("status"), str):
                    value["status"] = GraphProvenanceStatus(value["status"])
                if isinstance(value.get("evidence_refs"), list):
                    value["evidence_refs"] = tuple(value["evidence_refs"])
                restored.append(GraphProvenance.model_validate(value))
            return tuple(restored)

        nodes: list[dict[str, Any]] = []
        for item in state.get("nodes", []):
            value = dict(item)
            if isinstance(value.get("entity_type"), str):
                value["entity_type"] = GraphEntityType(value["entity_type"])
            value["provenance"] = restore_provenance(list(value.get("provenance", [])))
            nodes.append(value)
        edges: list[dict[str, Any]] = []
        for item in state.get("edges", []):
            value = dict(item)
            if isinstance(value.get("relation"), str):
                value["relation"] = GraphRelation(value["relation"])
            value["provenance"] = restore_provenance(list(value.get("provenance", [])))
            edges.append(value)
        state["nodes"] = tuple(nodes)
        state["edges"] = tuple(edges)
        return cls.model_validate(state)

    def _adjacency(self) -> dict[str, tuple[GraphEdge, ...]]:
        values: dict[str, list[GraphEdge]] = defaultdict(list)
        for edge in self.edges:
            values[edge.source_node].append(edge)
        return {key: tuple(sorted(value, key=lambda item: (item.target_node, item.edge_id))) for key, value in values.items()}

    def paths_between(
        self,
        *,
        start_types: set[GraphEntityType],
        end_types: set[GraphEntityType],
        start_attribute: tuple[str, Any] | None = None,
        end_attribute: tuple[str, Any] | None = None,
        max_depth: int = 8,
    ) -> tuple[GraphPath, ...]:
        if max_depth < 1:
            raise ValueError("max_depth must be positive")
        nodes = {node.node_key: node for node in self.nodes}
        starts = [
            node
            for node in self.nodes
            if node.entity_type in start_types
            and (start_attribute is None or node.attributes.get(start_attribute[0]) == start_attribute[1])
        ]
        adjacency = self._adjacency()
        results: list[GraphPath] = []
        for start in sorted(starts, key=lambda item: item.node_key):
            queue: deque[tuple[str, tuple[str, ...], tuple[str, ...]]] = deque([(start.node_key, (start.node_key,), ())])
            visited: set[tuple[str, int]] = {(start.node_key, 0)}
            while queue:
                current, node_keys, edge_ids = queue.popleft()
                depth = len(edge_ids)
                if depth > 0:
                    target = nodes[current]
                    if target.entity_type in end_types and (
                        end_attribute is None or target.attributes.get(end_attribute[0]) == end_attribute[1]
                    ):
                        results.append(GraphPath(node_keys=node_keys, edge_ids=edge_ids))
                        continue
                if depth >= max_depth:
                    continue
                for edge in adjacency.get(current, ()):
                    state = (edge.target_node, depth + 1)
                    if state in visited:
                        continue
                    visited.add(state)
                    queue.append((edge.target_node, node_keys + (edge.target_node,), edge_ids + (edge.edge_id,)))
        return tuple(results)

    def externally_reachable_privileged_tool_paths(self) -> tuple[GraphPath, ...]:
        return self.paths_between(
            start_types={GraphEntityType.AGENT},
            end_types={GraphEntityType.TOOL},
            start_attribute=("externally_reachable", True),
            end_attribute=("privileged", True),
        )

    def capability_protected_asset_paths(self) -> tuple[GraphPath, ...]:
        return self.paths_between(
            start_types={GraphEntityType.CAPABILITY},
            end_types={GraphEntityType.ASSET},
            end_attribute=("protected", True),
        )

    def vulnerable_dependency_exposed_service_paths(self) -> tuple[GraphPath, ...]:
        return self.paths_between(
            start_types={GraphEntityType.VULNERABILITY, GraphEntityType.DEPENDENCY},
            end_types={GraphEntityType.SERVICE},
            start_attribute=("vulnerable", True),
            end_attribute=("externally_reachable", True),
        )

    def finding_supporting_evidence_paths(self) -> tuple[GraphPath, ...]:
        return self.paths_between(
            start_types={GraphEntityType.FINDING},
            end_types={GraphEntityType.EVIDENCE},
        )


def edge_id_for(
    *,
    source_node: str,
    target_node: str,
    relation: GraphRelation,
    provenance: Iterable[GraphProvenance],
    attributes: dict[str, Any] | None = None,
) -> str:
    """Derive an edge identity from its complete assertion, not its insertion order."""
    payload = {
        "source_node": source_node,
        "target_node": target_node,
        "relation": relation.value,
        "provenance": [item.model_dump(mode="json") for item in provenance],
        "attributes": attributes or {},
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"GE-{hashlib.sha256(canonical).hexdigest()[:32]}"


class GraphBuilder:
    """Build a graph in sorted order and reject unsupported endpoints."""

    @staticmethod
    def edge(
        *,
        source_node: str,
        target_node: str,
        relation: GraphRelation,
        provenance: tuple[GraphProvenance, ...],
        attributes: dict[str, Any] | None = None,
    ) -> GraphEdge:
        return GraphEdge(
            edge_id=edge_id_for(
                source_node=source_node,
                target_node=target_node,
                relation=relation,
                provenance=provenance,
                attributes=attributes,
            ),
            source_node=source_node,
            target_node=target_node,
            relation=relation,
            provenance=provenance,
            attributes=attributes or {},
        )

    @staticmethod
    def build(
        *,
        tenant_id: str,
        case_id: str,
        target_id: str,
        snapshot_id: str,
        nodes: Iterable[GraphNode],
        edges: Iterable[GraphEdge],
    ) -> SecurityGraph:
        ordered_nodes = tuple(sorted(nodes, key=lambda item: (item.entity_type.value, item.entity_id)))
        ordered_edges = tuple(
            sorted(edges, key=lambda item: (item.source_node, item.target_node, item.relation.value, item.edge_id))
        )
        return SecurityGraph(
            tenant_id=tenant_id,
            case_id=case_id,
            target_id=target_id,
            snapshot_id=snapshot_id,
            nodes=ordered_nodes,
            edges=ordered_edges,
        )
