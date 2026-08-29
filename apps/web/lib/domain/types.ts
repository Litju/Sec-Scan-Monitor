import type {
  DataMode as ExperienceDataMode,
  ExperienceDetectionSignalView,
  ExperienceHuntView,
  ExperienceIncidentView,
  ExperienceResponseProposalView,
  GraphEdgeView,
  GraphNodeView,
} from "../../../../packages/secscan-experience-contracts/src/index";

export type DataMode = ExperienceDataMode;

export type SubsystemStatus = "qualified" | "available" | "degraded" | "unavailable" | "not_validated";

export type HealthState = {
  service: string;
  version: string;
  status: "ok" | "error";
  receivedAt: string;
};

export type EngagementView = {
  engagementId: string;
  clientId: string;
  clientName: string;
  targetIds: string[];
  targetLabel: string;
  snapshotLabel: string;
  scope: string;
  passType: string;
  authorityLevel: "inspection-only" | "remediation" | string;
  constraints: string[];
  status: string;
  updatedAt: string;
  findingCount: number;
  origin: "API" | "SYNTHETIC";
};

export type FindingView = {
  findingId: string;
  engagementId: string;
  severity: "Critical" | "High" | "Medium" | "Low" | string;
  summary: string;
  impact: string;
  status: "open" | "resolved" | "waived" | string;
  confidence: "high" | "medium" | "low" | "unknown" | string;
  adjudication: "CONFIRMED" | "SUPPORTED" | "INCONCLUSIVE" | "REJECTED" | string;
  supportingEvidenceIds: string[];
  contradictingEvidenceIds: string[];
  verificationStep: string;
  remediationGuidance: string;
  origin: "API" | "SYNTHETIC";
};

export type EvidenceView = {
  evidenceId: string;
  engagementId: string;
  targetId: string;
  targetSnapshot: string;
  collector: string;
  toolVersion: string;
  capabilityId: string;
  invocationId: string;
  collectedAt: string;
  contentType: string;
  byteSize: number;
  sha256: string;
  storageRef: string;
  sanitizationState: "SANITIZED" | "UNSANITIZED" | "NOT_VALIDATED";
  usedBy: string[];
  origin: "API" | "SYNTHETIC";
};

export type AgentRunView = {
  agentRunId: string;
  engagementId: string;
  agentId: string;
  agentRole: string;
  agentVersion: string;
  modelIdentity: string;
  promptVersion: string;
  status: "pending" | "running" | "completed" | "failed" | "refused" | string;
  startedAt: string;
  finishedAt: string | null;
  authorityRefs: string[];
  capabilityIds: string[];
  toolInvocationIds: string[];
  evidenceIds: string[];
  outputClaimIds: string[];
  origin: "API" | "SYNTHETIC";
};

export type CapabilityView = {
  capabilityId: string;
  version: string;
  description: string;
  riskClass: string;
  requiredAuthority: string;
  requiresApproval: boolean;
  sandboxProfile: string;
  networkPolicy: string;
  timeoutSeconds: number;
  resourceLimits: Record<string, string>;
  toolIdentity: string;
  toolVersion: string;
  evidenceType: string;
  origin: "API" | "SYNTHETIC";
};

export type SecurityServiceView = {
  serviceId: string;
  name: string;
  version: string;
  qualificationState: string;
  visibility: string;
  supportedTargetTypes: string[];
  origin: "API" | "SYNTHETIC";
};

export type ApprovalView = {
  approvalId: string;
  engagementId: string;
  requestedBy: string;
  requestRef: string;
  targetId: string;
  capabilityId: string;
  action: string;
  risk: string;
  decision: "pending" | "approved" | "denied";
  requestFingerprint: string;
  rationale: string;
  origin: "API" | "SYNTHETIC";
};

export type ClientView = {
  clientId: string;
  name: string;
  targetCount: number;
  engagementCount: number;
  status: string;
  origin: "API" | "SYNTHETIC";
};

export type TargetView = {
  targetId: string;
  clientId: string;
  name: string;
  kind: string;
  snapshot: string;
  snapshotDigest: string;
  liveCheckout: "separate" | "unknown";
  origin: "API" | "SYNTHETIC";
};

export type ReportView = {
  engagementId: string;
  title: string;
  verdict: string;
  scope: string;
  generatedAt: string;
  reportSha256: string;
  limitationCount: number;
  findingIds: string[];
  evidenceIds: string[];
  noSecretsAssertion: "asserted" | "not_validated";
  origin: "API" | "SYNTHETIC";
};

export type AuditEventView = {
  auditEventId: string;
  engagementId: string | null;
  principalId: string | null;
  kind: string;
  summary: string;
  occurredAt: string;
  relatedIds: string[];
  origin: "API" | "SYNTHETIC";
};

export type DetectionSignalView = ExperienceDetectionSignalView & { origin?: "API" | "SYNTHETIC" };
export type HuntView = ExperienceHuntView & { origin?: "API" | "SYNTHETIC" };
export type IncidentView = ExperienceIncidentView & { origin?: "API" | "SYNTHETIC" };
export type ResponseProposalView = ExperienceResponseProposalView & { origin?: "API" | "SYNTHETIC" };

export type PreviewData = {
  mode: DataMode;
  originLabel: string;
  engagements: EngagementView[];
  findings: FindingView[];
  evidence: EvidenceView[];
  runs: AgentRunView[];
  capabilities: CapabilityView[];
  securityServices: SecurityServiceView[];
  approvals: ApprovalView[];
  clients: ClientView[];
  targets: TargetView[];
  reports: ReportView[];
  audit: AuditEventView[];
  graphNodes: GraphNodeView[];
  graphEdges: GraphEdgeView[];
  detectionSignals?: DetectionSignalView[];
  hunts?: HuntView[];
  incidents?: IncidentView[];
  responseProposals?: ResponseProposalView[];
};
