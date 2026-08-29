import type {
  ExperienceActivityView,
  ExperienceAttentionItem,
  ExperienceCaseView,
  ExperienceFindingView,
  ExperienceRunnerView,
  ExperienceDetectionSignalView,
  ExperienceHuntView,
  ExperienceIncidentView,
  ExperienceResponseProposalView,
  ExperienceSnapshot,
  GraphEdgeView,
  GraphNodeView,
  ProvenanceView,
} from "./index";

const scope = { tenantId: "tenant-preview", caseId: "ENG-2026-015" } as const;
const observedAt = "2026-08-15T18:40:00Z";
const provenance: ProvenanceView = { source: "synthetic qualification fixture", sourceType: "preview", observedAt, evidenceRefs: ["E-1181"], status: "INCONCLUSIVE" };

const caseView: ExperienceCaseView = {
  id: "ENG-2026-015",
  caseId: "ENG-2026-015",
  clientLabel: "Synthetic agent client",
  targetLabel: "immutable repository snapshot",
  state: "INCONCLUSIVE",
  summary: "One advisory capability is unavailable under the current network-none policy.",
  updatedAt: observedAt,
  findingIds: ["FND-PREV-015"],
  evidenceCount: 1,
  activityCount: 2,
  scope,
  provenance,
};

const finding: ExperienceFindingView = {
  id: "FND-PREV-015",
  findingId: "FND-PREV-015",
  caseId: "ENG-2026-015",
  title: "Advisory data is unavailable for the review capability.",
  severity: "Low",
  state: "INCONCLUSIVE",
  adjudication: "VERIFIED",
  evidenceRefs: ["E-1181"],
  scope,
  provenance,
};

const attention: ExperienceAttentionItem[] = [
  { id: "attention-finding", kind: "finding", title: "Review an inconclusive finding", detail: finding.title, caseId: finding.caseId, entityId: finding.findingId, status: "INCONCLUSIVE", observedAt, nextAction: "Open the case and inspect evidence references.", evidenceRefs: finding.evidenceRefs, scope, source: "patrol projection" },
  { id: "attention-approval", kind: "approval", title: "Approval required before advisory access", detail: "CAP-ADVISORY-READ is bound to an exact request.", caseId: caseView.caseId, entityId: "APR-015-004", status: "APPROVAL_REQUIRED", observedAt: "2026-08-15T17:43:00Z", nextAction: "Review the exact request binding.", evidenceRefs: [], scope, source: "authority projection" },
];

const activity: ExperienceActivityView[] = [
  { id: "activity-patrol", caseId: caseView.caseId, occurredAt: "2026-08-15T17:43:00Z", sequence: 1, kind: "patrol", title: "Patrol recorded an unavailable advisory source", detail: "The capability remained bounded by network-none policy.", state: "INCONCLUSIVE", evidenceRefs: ["E-1181"], scope, source: "patrol event plane" },
  { id: "activity-approval", caseId: caseView.caseId, occurredAt: "2026-08-15T17:44:00Z", sequence: 2, kind: "approval", title: "Exact capability approval requested", detail: "No broader permission was granted.", state: "APPROVAL_REQUIRED", evidenceRefs: [], scope, source: "authority projection" },
];

const graphNodes: GraphNodeView[] = [
  { id: "node-snapshot", kind: "snapshot", label: "immutable repository snapshot", state: "VERIFIED", relatedIds: [finding.findingId], scope, provenance: { ...provenance, status: "VERIFIED", source: "snapshot registry" } },
  { id: "node-finding", kind: "finding", label: finding.title, state: finding.state, relatedIds: [finding.findingId], scope, provenance },
  { id: "node-capability", kind: "capability", label: "CAP-ADVISORY-READ", state: "APPROVAL_REQUIRED", relatedIds: [finding.findingId], scope, provenance: { ...provenance, status: "APPROVAL_REQUIRED", source: "capability registry" } },
];

const graphEdges: GraphEdgeView[] = [
  { id: "edge-snapshot-finding", sourceId: "node-snapshot", targetId: "node-finding", relation: "supports", state: "VERIFIED", relatedIds: [finding.findingId], scope, provenance: { ...provenance, status: "VERIFIED", source: "evidence linkage" } },
  { id: "edge-finding-capability", sourceId: "node-finding", targetId: "node-capability", relation: "depends on", state: "INCONCLUSIVE", relatedIds: [finding.findingId], scope, provenance },
];

const runners: ExperienceRunnerView[] = [
  { id: "runner-015", caseId: caseView.caseId, runnerId: "AR-015-COORD-01", capabilityId: "CAP-ADVISORY-READ", state: "DEGRADED", policyDecision: "APPROVAL_REQUIRED", evidenceRefs: ["E-1181"], scope, source: "runner receipt" },
];

const detectionSignals: ExperienceDetectionSignalView[] = [
  { id: "SIG-PREV-022-001", signalId: "SIG-PREV-022-001", caseId: "ENG-2026-022", ruleId: "secscan.endpoint.privilege-escalation", ruleVersion: 1, severity: "High", confidence: "High", state: "NEW", eventIds: ["EVT-PREV-ENDPOINT-001", "EVT-PREV-ENDPOINT-002"], evidenceRefs: ["EV-PREV-022-001"], scope: { tenantId: "tenant-preview", caseId: "ENG-2026-022" }, source: "synthetic detection qualification" },
];

const hunts: ExperienceHuntView[] = [
  { id: "HUNT-PREV-022-001", huntId: "HUNT-PREV-022-001", hypothesisId: "HYP-PREV-022-001", caseId: "ENG-2026-022", disposition: "VERIFIED", state: "VERIFIED", evidenceRefs: ["EV-PREV-022-001", "EV-PREV-022-002"], scope: { tenantId: "tenant-preview", caseId: "ENG-2026-022" }, source: "synthetic threat-hunt qualification" },
];

const incidents: ExperienceIncidentView[] = [
  { id: "INC-PREV-022-001", incidentId: "INC-PREV-022-001", caseId: "ENG-2026-022", state: "CONFIRMED", severity: "High", confidence: "High", signalIds: ["SIG-PREV-022-001"], evidenceRefs: ["EV-PREV-022-001", "EV-PREV-022-002"], scope: { tenantId: "tenant-preview", caseId: "ENG-2026-022" }, provenance: { source: "synthetic incident adjudication", sourceType: "qualification", observedAt: "2026-08-16T10:20:00Z", evidenceRefs: ["EV-PREV-022-001", "EV-PREV-022-002"], status: "CONFIRMED" } },
];

const responseProposals: ExperienceResponseProposalView[] = [
  { id: "RSP-PREV-022-001", proposalId: "RSP-PREV-022-001", incidentId: "INC-PREV-022-001", caseId: "ENG-2026-022", targetId: "TGT-AGENT-SNAPSHOT", action: "isolate_target", opaDecision: "APPROVAL_REQUIRED", humanApprovalState: "APPROVAL_REQUIRED", state: "APPROVAL_REQUIRED", evidenceRefs: ["EV-PREV-022-001", "EV-PREV-022-002"], scope: { tenantId: "tenant-preview", caseId: "ENG-2026-022" }, source: "synthetic response proposal qualification" },
];

export const previewExperienceSnapshot: ExperienceSnapshot = {
  mode: "PREVIEW",
  connectionState: "PREVIEW",
  sourceLabel: "SYNTHETIC / NON-PERSONAL / QUALIFICATION_ONLY",
  tenantId: scope.tenantId,
  attention,
  cases: [caseView],
  findings: [finding],
  activity,
  graphNodes,
  graphEdges,
  runners,
  detectionSignals,
  hunts,
  incidents,
  responseProposals,
};
