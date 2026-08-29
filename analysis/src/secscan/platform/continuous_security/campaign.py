"""Synthetic agent platform used by the v0.2 integrated qualification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Iterable

from secscan.platform.continuous_security.events import EventClass, SecurityEventPlane
from secscan.platform.continuous_security.graph import (
    GraphBuilder,
    GraphEntityType,
    GraphNode,
    GraphProvenance,
    GraphProvenanceStatus,
    GraphRelation,
    SecurityGraph,
)
from secscan.platform.continuous_security.patrol import (
    CanonicalSnapshot,
    InMemoryFindingStore,
    PatrolCandidate,
    PatrolEngine,
    PatrolRunResult,
    SnapshotDelta,
)


class SyntheticAgentPlatform:
    """Agent A → MCP server → read_repo, with controlled qualification changes."""

    now = datetime(2026, 1, 1, 12, tzinfo=UTC)

    def __init__(self) -> None:
        self.events = SecurityEventPlane()
        self.findings = InMemoryFindingStore()
        self.patrol = PatrolEngine(self.findings)
        self.baseline = self.snapshot("baseline")
        self.baseline_graph = self.graph("graph-a", privileged=False)
        self.events.ingest_raw(
            {
                "source": "synthetic-agent-platform",
                "source_record_id": "baseline",
                "source_digest": "baseline-digest",
                "source_system": "synthetic-agent-platform",
                "collector_version": "campaign-v1",
                "source_type": "synthetic",
                "event_class": EventClass.GENERIC_SECSCAN.value,
                "occurred_at": self.now,
                "observed_at": self.now + timedelta(seconds=1),
                "tenant": "tenant-a",
                "case": "case-a",
                "target": "platform-a",
                "actor": "agent-a",
                "object": "read_repo",
                "action": "inspect",
                "outcome": "baseline",
                "raw_evidence_ref": "metadata://campaign/baseline",
                "normalization_version": "security-events-v1",
            }
        )

    def snapshot(self, snapshot_id: str, *, changed: bool = False, resolved: bool = False) -> CanonicalSnapshot:
        tools: dict[str, dict[str, object]] = {"read_repo": {"schema": "v1", "privileged": False}}
        dependencies: dict[str, dict[str, object]] = {"clean": {"vulnerable": False}}
        policies: dict[str, dict[str, object]] = {"inspection": {"version": "1", "permits_read_only": True}}
        if changed:
            tools["deploy"] = {"schema": "v1", "privileged": True}
            tools["read_repo"] = {"schema": "v2", "privileged": False}
            dependencies["known-vulnerable-fixture"] = {"vulnerable": True, "advisory": "fixture-advisory"}
            policies["inspection"] = {"version": "2", "permits_read_only": True, "permits_deploy": True}
        if resolved:
            tools = {"read_repo": {"schema": "v1", "privileged": False}}
            dependencies = {"clean": {"vulnerable": False}}
        return CanonicalSnapshot(
            tenant_id="tenant-a",
            case_id="case-a",
            target_id="platform-a",
            snapshot_id=snapshot_id,
            surfaces={
                "source": {"revision": "fixture"},
                "dependencies": dependencies,
                "mcp_tools": tools,
                "opa_policies": policies,
            },
        )

    def graph(self, snapshot_id: str, *, privileged: bool) -> SecurityGraph:
        provenance = (
            GraphProvenance(
                source="synthetic-agent-platform",
                source_type="qualification-fixture",
                observed_at=self.now,
                status=GraphProvenanceStatus.VERIFIED,
                evidence_refs=("EV-campaign",),
            ),
        )
        agent = GraphNode(
            entity_type=GraphEntityType.AGENT,
            entity_id="agent-a",
            attributes={"externally_reachable": True},
            provenance=provenance,
        )
        server = GraphNode(
            entity_type=GraphEntityType.MCP_SERVER,
            entity_id="mcp-a",
            attributes={},
            provenance=provenance,
        )
        tool = GraphNode(
            entity_type=GraphEntityType.TOOL,
            entity_id="deploy" if privileged else "read_repo",
            attributes={"privileged": privileged},
            provenance=provenance,
        )
        edges = (
            GraphBuilder.edge(
                source_node=agent.node_key,
                target_node=server.node_key,
                relation=GraphRelation.EXPOSES,
                provenance=provenance,
            ),
            GraphBuilder.edge(
                source_node=server.node_key,
                target_node=tool.node_key,
                relation=GraphRelation.EXPOSES,
                provenance=provenance,
            ),
        )
        return GraphBuilder.build(
            tenant_id="tenant-a",
            case_id="case-a",
            target_id="platform-a",
            snapshot_id=snapshot_id,
            nodes=(agent, server, tool),
            edges=edges,
        )

    def assess(self, delta: SnapshotDelta) -> Iterable[PatrolCandidate]:
        if delta.affected_surface == "mcp_tools:deploy":
            yield PatrolCandidate(
                condition_key="privileged-tool:deploy",
                title="Privileged deploy tool declared",
                severity="high",
                affected_surface=delta.affected_surface,
                supporting_evidence_refs=("EV-deploy",),
                adjudicated=True,
            )
        elif delta.affected_surface == "mcp_tools:read_repo":
            yield PatrolCandidate(
                condition_key="schema-drift:read_repo",
                title="read_repo schema changed",
                severity="medium",
                affected_surface=delta.affected_surface,
                supporting_evidence_refs=("EV-schema",),
                adjudicated=True,
            )
        elif delta.affected_surface == "dependencies:known-vulnerable-fixture":
            yield PatrolCandidate(
                condition_key="vulnerability:known-vulnerable-fixture",
                title="Known-vulnerable dependency fixture added",
                severity="high",
                affected_surface=delta.affected_surface,
                supporting_evidence_refs=("EV-vulnerability",),
                adjudicated=True,
            )
        elif delta.affected_surface == "opa_policies:inspection":
            yield PatrolCandidate(
                condition_key="authority-policy:inspection",
                title="Inspection authority policy changed",
                severity="high",
                affected_surface=delta.affected_surface,
                supporting_evidence_refs=("EV-policy",),
                adjudicated=True,
            )

    def run_patrol(
        self, current: CanonicalSnapshot, *, baseline: CanonicalSnapshot | None = None
    ) -> PatrolRunResult:
        return self.patrol.run(baseline=baseline or self.baseline, current=current, assess=self.assess)


__all__ = ["SyntheticAgentPlatform"]
