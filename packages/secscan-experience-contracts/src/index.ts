export const EXPERIENCE_STATUSES = [
  "NEW",
  "CHANGED",
  "RESOLVED",
  "DENIED",
  "APPROVAL_REQUIRED",
  "INCONCLUSIVE",
  "UNAVAILABLE",
  "DEGRADED",
  "VERIFIED",
  "CONTRADICTED",
  "UNKNOWN",
] as const;

export type ExperienceStatus = (typeof EXPERIENCE_STATUSES)[number];
export type DataMode = "PREVIEW" | "LOCAL_INTEGRATED" | "HOSTED_INTEGRATED";
export type ConnectionState = "PREVIEW" | "CONNECTED" | "DEGRADED" | "UNAVAILABLE";

const DATA_MODES = ["PREVIEW", "LOCAL_INTEGRATED", "HOSTED_INTEGRATED"] as const;
const CONNECTION_STATES = ["PREVIEW", "CONNECTED", "DEGRADED", "UNAVAILABLE"] as const;

export type ExperienceScope = {
  tenantId: string;
  caseId?: string;
};

export type ProvenanceView = {
  source: string;
  sourceType: string;
  observedAt: string;
  evidenceRefs: string[];
  status: ExperienceStatus;
};

export type ExperienceCaseView = {
  id: string;
  caseId: string;
  clientLabel: string;
  targetLabel: string;
  state: ExperienceStatus;
  summary: string;
  updatedAt: string;
  findingIds: string[];
  evidenceCount: number;
  activityCount: number;
  scope: ExperienceScope;
  provenance: ProvenanceView;
};

export type ExperienceFindingView = {
  id: string;
  findingId: string;
  caseId: string;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low" | string;
  state: ExperienceStatus;
  adjudication: ExperienceStatus;
  evidenceRefs: string[];
  scope: ExperienceScope;
  provenance: ProvenanceView;
};

export type ExperienceAttentionItem = {
  id: string;
  kind: "finding" | "approval" | "patrol" | "activity" | "system" | string;
  title: string;
  detail: string;
  caseId?: string;
  entityId: string;
  status: ExperienceStatus;
  observedAt: string;
  nextAction?: string;
  evidenceRefs: string[];
  scope: ExperienceScope;
  source: string;
};

export type ExperienceActivityView = {
  id: string;
  caseId?: string;
  occurredAt: string;
  sequence: number;
  kind: "finding" | "patrol" | "approval" | "runner" | "system" | string;
  title: string;
  detail: string;
  state: ExperienceStatus;
  evidenceRefs: string[];
  scope: ExperienceScope;
  source: string;
};

export type ExperienceRunnerView = {
  id: string;
  caseId?: string;
  runnerId: string;
  capabilityId: string;
  state: ExperienceStatus;
  policyDecision: ExperienceStatus;
  evidenceRefs: string[];
  scope: ExperienceScope;
  source: string;
};

export type GraphNodeView = {
  id: string;
  kind: "case" | "client" | "target" | "snapshot" | "finding" | "evidence" | "capability" | "runner" | "policy" | string;
  label: string;
  state: ExperienceStatus;
  relatedIds: string[];
  scope: ExperienceScope;
  provenance: ProvenanceView;
};

export type GraphEdgeView = {
  id: string;
  sourceId: string;
  targetId: string;
  relation: string;
  state: ExperienceStatus;
  relatedIds: string[];
  scope: ExperienceScope;
  provenance: ProvenanceView;
};

export type ExperienceSnapshot = {
  mode: DataMode;
  connectionState: ConnectionState;
  sourceLabel: string;
  tenantId: string;
  attention: ExperienceAttentionItem[];
  cases: ExperienceCaseView[];
  findings: ExperienceFindingView[];
  activity: ExperienceActivityView[];
  graphNodes: GraphNodeView[];
  graphEdges: GraphEdgeView[];
  runners: ExperienceRunnerView[];
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object";
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isScope(value: unknown): value is ExperienceScope {
  if (!isRecord(value) || typeof value.tenantId !== "string") return false;
  return value.caseId === undefined || typeof value.caseId === "string";
}

function isProvenance(value: unknown): value is ProvenanceView {
  return isRecord(value)
    && typeof value.source === "string"
    && typeof value.sourceType === "string"
    && typeof value.observedAt === "string"
    && isStringArray(value.evidenceRefs)
    && EXPERIENCE_STATUSES.includes(value.status as ExperienceStatus);
}

export function isExperienceSnapshot(value: unknown): value is ExperienceSnapshot {
  if (!isRecord(value)
    || !DATA_MODES.includes(value.mode as DataMode)
    || !CONNECTION_STATES.includes(value.connectionState as ConnectionState)
    || typeof value.sourceLabel !== "string"
    || typeof value.tenantId !== "string") return false;
  const arrays = ["attention", "cases", "findings", "activity", "graphNodes", "graphEdges", "runners"].map((key) => value[key]);
  if (arrays.some((items) => !Array.isArray(items))) return false;
  const [attention, cases, findings, activity, graphNodes, graphEdges, runners] = arrays as unknown[][];
  return attention.every((item) => isRecord(item)
    && typeof item.id === "string" && typeof item.title === "string" && typeof item.detail === "string"
    && typeof item.entityId === "string" && EXPERIENCE_STATUSES.includes(item.status as ExperienceStatus)
    && isScope(item.scope) && typeof item.source === "string")
    && cases.every((item) => isRecord(item)
      && typeof item.id === "string" && typeof item.caseId === "string" && typeof item.clientLabel === "string"
      && typeof item.targetLabel === "string" && typeof item.summary === "string" && typeof item.updatedAt === "string"
      && EXPERIENCE_STATUSES.includes(item.state as ExperienceStatus) && isStringArray(item.findingIds)
      && typeof item.evidenceCount === "number" && typeof item.activityCount === "number"
      && isScope(item.scope) && isProvenance(item.provenance))
    && findings.every((item) => isRecord(item)
      && typeof item.id === "string" && typeof item.findingId === "string" && typeof item.caseId === "string"
      && typeof item.title === "string" && typeof item.severity === "string"
      && EXPERIENCE_STATUSES.includes(item.state as ExperienceStatus)
      && EXPERIENCE_STATUSES.includes(item.adjudication as ExperienceStatus)
      && isStringArray(item.evidenceRefs) && isScope(item.scope) && isProvenance(item.provenance))
    && activity.every((item) => isRecord(item)
      && typeof item.id === "string" && typeof item.occurredAt === "string" && typeof item.sequence === "number"
      && typeof item.title === "string" && typeof item.detail === "string"
      && EXPERIENCE_STATUSES.includes(item.state as ExperienceStatus) && isStringArray(item.evidenceRefs)
      && isScope(item.scope) && typeof item.source === "string")
    && graphNodes.every((item) => isRecord(item)
      && typeof item.id === "string" && typeof item.kind === "string" && typeof item.label === "string"
      && EXPERIENCE_STATUSES.includes(item.state as ExperienceStatus) && isStringArray(item.relatedIds)
      && isScope(item.scope) && isProvenance(item.provenance))
    && graphEdges.every((item) => isRecord(item)
      && typeof item.id === "string" && typeof item.sourceId === "string" && typeof item.targetId === "string"
      && typeof item.relation === "string" && EXPERIENCE_STATUSES.includes(item.state as ExperienceStatus)
      && isStringArray(item.relatedIds) && isScope(item.scope) && isProvenance(item.provenance))
    && runners.every((item) => isRecord(item)
      && typeof item.id === "string" && typeof item.runnerId === "string" && typeof item.capabilityId === "string"
      && EXPERIENCE_STATUSES.includes(item.state as ExperienceStatus)
      && EXPERIENCE_STATUSES.includes(item.policyDecision as ExperienceStatus)
      && isStringArray(item.evidenceRefs) && isScope(item.scope) && typeof item.source === "string");
}

export type StreamEnvelope<T> = {
  updateId: string;
  objectId: string;
  updateType: "snapshot" | "upsert" | "remove";
  observedAt: string;
  sequence: number;
  version: number;
  resumeCursor?: string | null;
  scope: ExperienceScope;
  payload: T | null;
};

export type LiveProjection<T extends { id: string }> = {
  items: T[];
  lastById: Record<string, { sequence: number; version: number }>;
  seenUpdateIds: Record<string, true>;
  resumeCursor: string | null;
  lastSequence: number;
  connectionState: ConnectionState;
};

export type StreamUpdateResult = "accepted" | "duplicate" | "stale";

export class ScopeMismatchError extends Error {
  constructor() {
    super("The received experience update is outside the active scope.");
    this.name = "ScopeMismatchError";
  }
}

export function createLiveProjection<T extends { id: string }>(): LiveProjection<T> {
  return { items: [], lastById: {}, seenUpdateIds: {}, resumeCursor: null, lastSequence: 0, connectionState: "CONNECTED" };
}

export function setLiveConnectionState<T extends { id: string }>(
  projection: LiveProjection<T>,
  connectionState: ConnectionState,
): LiveProjection<T> {
  return { ...projection, connectionState };
}

export function applyStreamUpdate<T extends { id: string }>(
  projection: LiveProjection<T>,
  envelope: StreamEnvelope<T>,
  expectedScope: ExperienceScope,
): { projection: LiveProjection<T>; result: StreamUpdateResult } {
  if (envelope.scope.tenantId !== expectedScope.tenantId || (expectedScope.caseId && envelope.scope.caseId !== expectedScope.caseId)) {
    throw new ScopeMismatchError();
  }
  if (projection.seenUpdateIds[envelope.updateId]) return { projection, result: "duplicate" };
  if (envelope.sequence <= projection.lastSequence) return { projection, result: "stale" };
  const previous = projection.lastById[envelope.objectId];
  if (previous && (envelope.version < previous.version || (envelope.version === previous.version && envelope.sequence <= previous.sequence))) {
    return { projection, result: "stale" };
  }

  const items = projection.items.filter((item) => item.id !== envelope.objectId);
  if (envelope.updateType !== "remove" && envelope.payload) items.push(envelope.payload);
  items.sort((left, right) => left.id.localeCompare(right.id));
  return {
    projection: {
      items,
      lastById: { ...projection.lastById, [envelope.objectId]: { sequence: envelope.sequence, version: envelope.version } },
      seenUpdateIds: { ...projection.seenUpdateIds, [envelope.updateId]: true },
      resumeCursor: envelope.resumeCursor ?? projection.resumeCursor,
      lastSequence: envelope.sequence,
      connectionState: projection.connectionState,
    },
    result: "accepted",
  };
}

export function sortActivityEntries(entries: ExperienceActivityView[]): ExperienceActivityView[] {
  return [...entries].sort((left, right) => left.occurredAt.localeCompare(right.occurredAt) || left.sequence - right.sequence || left.id.localeCompare(right.id));
}

export function safeDisplay(value: string): string {
  return value
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer <REDACTED>")
    .replace(/\b(?:sk|pk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]+\b/gi, "<REDACTED>")
    .replace(/\b(token|api[_-]?key|secret|password|passwd)\s*[:=]\s*[^\s,;]+/gi, "$1=<REDACTED>");
}

export function emptyExperienceSnapshot(mode: DataMode, sourceLabel: string, connectionState: ConnectionState = "UNAVAILABLE"): ExperienceSnapshot {
  return { mode, connectionState, sourceLabel, tenantId: "unknown", attention: [], cases: [], findings: [], activity: [], graphNodes: [], graphEdges: [], runners: [] };
}
