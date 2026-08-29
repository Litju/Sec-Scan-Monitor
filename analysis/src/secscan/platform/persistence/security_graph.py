"""PostgreSQL adapter for the canonical security graph snapshot."""

from __future__ import annotations

from sqlalchemy.orm import Session

from secscan.platform.continuous_security.graph import SecurityGraph
from secscan.platform.persistence.models import (
    SecurityGraphEdgeRow,
    SecurityGraphNodeRow,
    SecurityGraphSnapshotRow,
)


class GraphScopeError(RuntimeError):
    """A graph read attempted to cross tenant, case, or target scope."""


class GraphStateConflict(RuntimeError):
    """A canonical snapshot identity was reused for different graph state."""


class PostgresSecurityGraphRepository:
    """Persist and replay graph state through the existing SQLAlchemy session.

    The adapter does not commit; the surrounding application transaction owns
    commit/rollback. JSON is the canonical replay payload, while node/edge rows
    provide relational inspection and provenance-preserving query indexes.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def save(self, graph: SecurityGraph) -> None:
        row = self._session.get(SecurityGraphSnapshotRow, graph.snapshot_id)
        if row is not None:
            self._assert_scope(row, graph)
            if row.digest != graph.digest:
                raise GraphStateConflict(f"snapshot {graph.snapshot_id} already has a different digest")
            return
        row = SecurityGraphSnapshotRow(
            snapshot_id=graph.snapshot_id,
            tenant_id=graph.tenant_id,
            case_id=graph.case_id,
            target_id=graph.target_id,
            digest=graph.digest,
            normalization_version="security-graph-v1",
            canonical_state=graph.canonical_dict(),
        )
        row.nodes = [
            SecurityGraphNodeRow(
                snapshot_id=graph.snapshot_id,
                node_key=node.node_key,
                entity_type=node.entity_type.value,
                entity_id=node.entity_id,
                attributes=node.attributes,
                provenance=[item.model_dump(mode="json") for item in node.provenance],
            )
            for node in graph.nodes
        ]
        row.edges = [
            SecurityGraphEdgeRow(
                snapshot_id=graph.snapshot_id,
                edge_id=edge.edge_id,
                source_node=edge.source_node,
                target_node=edge.target_node,
                relation=edge.relation.value,
                attributes=edge.attributes,
                provenance=[item.model_dump(mode="json") for item in edge.provenance],
            )
            for edge in graph.edges
        ]
        self._session.add(row)
        self._session.flush()

    def load(
        self, *, snapshot_id: str, tenant_id: str, case_id: str, target_id: str
    ) -> SecurityGraph | None:
        row = self._session.get(SecurityGraphSnapshotRow, snapshot_id)
        if row is None:
            return None
        if (row.tenant_id, row.case_id, row.target_id) != (tenant_id, case_id, target_id):
            raise GraphScopeError("graph snapshot is outside the requested tenant/case/target scope")
        graph = SecurityGraph.replay(row.canonical_state)
        if graph.digest != row.digest:
            raise GraphStateConflict(f"canonical snapshot {snapshot_id} failed digest replay")
        return graph

    @staticmethod
    def _assert_scope(row: SecurityGraphSnapshotRow, graph: SecurityGraph) -> None:
        if (row.tenant_id, row.case_id, row.target_id) != (graph.tenant_id, graph.case_id, graph.target_id):
            raise GraphScopeError("snapshot identity cannot be rebound across scopes")


__all__ = ["GraphScopeError", "GraphStateConflict", "PostgresSecurityGraphRepository"]
