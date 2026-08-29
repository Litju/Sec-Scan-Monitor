import type {
  ApprovalView,
  AgentRunView,
  CapabilityView,
  DataMode,
  DetectionSignalView,
  EngagementView,
  EvidenceView,
  FindingView,
  HealthState,
  HuntView,
  IncidentView,
  PreviewData,
  ReportView,
  ResponseProposalView,
} from "@/lib/domain/types";
import type { ExperienceStatus } from "../../../../packages/secscan-experience-contracts/src/index";
import { ApiError, createCanonicalClient } from "@secscanmonitor/client";
import { EXPERIENCE_STATUSES } from "../../../../packages/secscan-experience-contracts/src/index";

export { ApiError, PreviewReadOnlyError } from "@secscanmonitor/client";

type HostedPage<T> = { items: T[]; next_cursor: string | null; limit: number };

type HostedClient = { client_id: string; name: string; contact?: string | null };
type HostedTarget = {
  target_id: string;
  client_id?: string | null;
  kind: string;
  name: string;
  snapshot_id?: string | null;
  snapshot_digest?: string | null;
};
type HostedEngagement = {
  engagement_id: string;
  client_id: string;
  target_ids: string[];
  scope: string;
  pass_type: string;
  authority_level: string;
  status: string;
  updated_at: string;
};
type HostedFinding = {
  finding_id: string;
  engagement_id?: string | null;
  client_id?: string | null;
  severity?: string | null;
  confidence?: string | null;
  title?: string | null;
  summary?: string | null;
  impact?: string | null;
  status?: string | null;
  adjudication?: string | null;
  supporting_evidence_ids?: string[];
  contradicting_evidence_ids?: string[];
  verification_step?: string | null;
  remediation_guidance?: string | null;
};
type HostedEvidence = {
  evidence_id: string;
  engagement_id?: string | null;
  sha256?: string | null;
  sanitization_state?: string | null;
};
type HostedService = Record<string, unknown>;
type HostedAudit = {
  audit_event_id: string;
  engagement_id?: string | null;
  principal_id?: string | null;
  kind: string;
  summary: string;
  occurred_at: string;
};
type HostedApproval = {
  approval_id: string;
  engagement_id: string;
  requested_by: string;
  request_ref: string;
  target_id: string;
  capability_id: string;
  action: string;
  risk: string;
  decision: "pending" | "approved" | "denied";
  request_fingerprint: string;
  rationale: string;
};
type HostedReport = {
  report_id: string;
  engagement_id: string;
  sha256: string;
  findings_count: number;
  verdict: string;
  generated_at: string;
  no_secrets_asserted: boolean;
};
type HostedDetectionSignal = {
  signal_id: string;
  tenant_id: string;
  case_id: string;
  rule_id: string;
  rule_version: number;
  severity: string;
  confidence: string;
  status: string;
  event_ids: string[];
  evidence_refs: string[];
  source: string;
};
type HostedHunt = {
  hunt_id: string;
  hypothesis_id: string;
  tenant_id: string;
  case_id: string;
  disposition: string;
  status: string;
  evidence_refs: string[];
  source: string;
};
type HostedIncident = {
  incident_id: string;
  tenant_id: string;
  case_id: string;
  status: string;
  severity: string;
  confidence: string;
  signal_ids: string[];
  evidence_refs: string[];
  provenance_source: string;
  provenance_source_type: string;
  adjudicated_at: string;
};
type HostedResponseProposal = {
  proposal_id: string;
  incident_id: string;
  tenant_id: string;
  case_id: string;
  target_id: string;
  action: string;
  opa_decision: string;
  human_approval_state: string;
  status: string;
  evidence_refs: string[];
  source: string;
};

function mapExperienceStatus(value: string | undefined, fallback: ExperienceStatus = "UNKNOWN"): ExperienceStatus {
  const normalized = (value ?? "").toUpperCase();
  const mapped = {
    SUPPORTS: "VERIFIED",
    REFUTES: "CONTRADICTED",
    REQUIRE_APPROVAL: "APPROVAL_REQUIRED",
    ALLOW: "VERIFIED",
    DENY: "DENIED",
    CONTAINED: "CONFIRMED",
    RECOVERING: "CONFIRMED",
    OPEN: "NEW",
    CLOSED: "RESOLVED",
    REFUSED: "DENIED",
    REVOKED: "DENIED",
  }[normalized] ?? normalized;
  return EXPERIENCE_STATUSES.includes(mapped as ExperienceStatus) ? mapped as ExperienceStatus : fallback;
}

let hostedAuthClient: Promise<{ getJWTToken: () => Promise<string | null> }> | undefined;

function looksLikeJwt(value: string): boolean {
  return value.split(".").length === 3;
}

async function hostedAuthorization(endpoint: string): Promise<string> {
  const authUrl = process.env.NEXT_PUBLIC_NEON_AUTH_URL?.trim();
  if (!authUrl) throw new ApiError("Hosted authentication is not configured.", 503, endpoint);
  hostedAuthClient ??= import("@neondatabase/auth").then(({ createInternalNeonAuth }) => createInternalNeonAuth(authUrl));
  const sessionToken = await (await hostedAuthClient).getJWTToken();
  if (sessionToken && looksLikeJwt(sessionToken)) return `Bearer ${sessionToken}`;
  const response = await fetch(`${authUrl.replace(/\/+$/, "")}/token`, {
    headers: { Accept: "application/json" },
    credentials: "include",
    cache: "no-store",
  });
  if (!response.ok) throw new ApiError("Authentication required.", 401, endpoint);
  const payload = await response.json() as { token?: unknown };
  const token = typeof payload.token === "string" && looksLikeJwt(payload.token) ? payload.token : null;
  if (!token) throw new ApiError("Authentication required.", 401, endpoint);
  return `Bearer ${token}`;
}

export async function getHostedAuthToken(endpoint = "/auth/revoke"): Promise<string> {
  return (await hostedAuthorization(endpoint)).slice("Bearer ".length);
}

export function resolveApiMode(): DataMode {
  const configured =
    process.env.NEXT_PUBLIC_SECSCAN_QUALIFICATION_MODE?.trim().toUpperCase()
    || process.env.NEXT_PUBLIC_SECSCAN_MODE?.trim().toUpperCase();
  if (!configured) return "PREVIEW";
  if (configured === "PREVIEW" || configured === "LOCAL_INTEGRATED" || configured === "HOSTED_INTEGRATED") {
    return configured;
  }
  throw new Error(`Unsupported NEXT_PUBLIC_SECSCAN_MODE: ${configured}`);
}

export function createApiClient(mode: DataMode = resolveApiMode()) {
  const transport = createCanonicalClient({ mode, getAuthorization: mode === "HOSTED_INTEGRATED" ? hostedAuthorization : undefined });
  const get = transport.get;
  const mutate = <T>(endpoint: string, _method: "POST", payload?: unknown) => transport.post<T>(endpoint, payload);

  return {
    mode,
    health: () => get<HealthState>("/health"),
    getEngagement: (id: string) => get<EngagementView>(`/engagements/${encodeURIComponent(id)}`),
    getCapabilities: () => get<CapabilityView[]>("/capabilities"),
    getRuns: (id: string) => get<unknown[]>(`/engagements/${encodeURIComponent(id)}/runs`),
    getFinding: (id: string) => get<FindingView>(`/findings/${encodeURIComponent(id)}`),
    getFindings: (id: string) => get<FindingView[]>(`/engagements/${encodeURIComponent(id)}/findings`),
    getEvidenceMetadata: (id: string) => get<EvidenceView>(`/evidence/${encodeURIComponent(id)}/metadata`),
    getReport: (id: string) => get<HostedReport>(`/engagements/${encodeURIComponent(id)}/report`),
    getClients: () => get<HostedPage<HostedClient>>("/clients"),
    getTargets: () => get<HostedPage<HostedTarget>>("/targets"),
    getEngagements: () => get<HostedPage<HostedEngagement>>("/engagements"),
    getFindingsPage: () => get<HostedPage<HostedFinding>>("/findings"),
    getEvidencePage: () => get<HostedPage<HostedEvidence>>("/evidence"),
    getServices: () => get<HostedService[]>("/services"),
    getAudit: () => get<HostedPage<HostedAudit>>("/audit"),
    getApprovals: () => get<HostedPage<HostedApproval>>("/approvals"),
    getDetectionSignals: () => get<HostedPage<HostedDetectionSignal>>("/detection/signals"),
    getHunts: () => get<HostedPage<HostedHunt>>("/hunts"),
    getIncidents: () => get<HostedPage<HostedIncident>>("/incidents"),
    getResponseProposals: () => get<HostedPage<HostedResponseProposal>>("/response-proposals"),
    createEngagement: (payload: {
      engagement_id: string;
      client_id: string;
      target_ids: string[];
      scope: string;
      pass_type: string;
      constraints: string[];
    }) => mutate<HostedEngagement>("/engagements", "POST", payload),
    startInspection: (id: string, targetId: string, targetSnapshotId: string) => mutate<{ workflow_run_id: string; status: string }>(
      `/engagements/${encodeURIComponent(id)}/start-inspection`,
      "POST",
      { target_id: targetId, target_snapshot_id: targetSnapshotId },
    ),
    approve: (id: string) => mutate<ApprovalView>(`/approvals/${encodeURIComponent(id)}/approve`, "POST"),
    deny: (id: string) => mutate<ApprovalView>(`/approvals/${encodeURIComponent(id)}/deny`, "POST"),
    authorize: (id: string) => mutate<EngagementView>(`/engagements/${encodeURIComponent(id)}/authorize`, "POST"),
    suspend: (id: string) => mutate<EngagementView>(`/engagements/${encodeURIComponent(id)}/suspend`, "POST"),
    resume: (id: string) => mutate<EngagementView>(`/engagements/${encodeURIComponent(id)}/resume`, "POST"),
  };
}

export async function loadHostedData(mode: DataMode = "HOSTED_INTEGRATED"): Promise<PreviewData> {
  const api = createApiClient(mode);
  const [clientsPage, targetsPage, engagementsPage, findingsPage, evidencePage, auditPage, detectionSignalsPage, huntsPage, incidentsPage, responseProposalsPage] = await Promise.all([
    api.getClients(),
    api.getTargets(),
    api.getEngagements(),
    api.getFindingsPage(),
    api.getEvidencePage(),
    api.getAudit(),
    api.getDetectionSignals(),
    api.getHunts(),
    api.getIncidents(),
    api.getResponseProposals(),
  ]);
  const approvalsPage = mode === "LOCAL_INTEGRATED" ? await api.getApprovals() : { items: [] as HostedApproval[] };
  const clientNames = new Map(clientsPage.items.map((client) => [client.client_id, client.name]));
  const targets = targetsPage.items;
  const targetById = new Map(targets.map((target) => [target.target_id, target]));
  const findings = findingsPage.items.map((finding): FindingView => ({
    findingId: finding.finding_id,
    engagementId: finding.engagement_id ?? "",
    severity: finding.severity ?? "not_validated",
    summary: finding.summary ?? finding.title ?? "Canonical finding detail not supplied",
    impact: finding.impact ?? "Canonical finding impact not supplied",
    status: finding.status ?? "not_validated",
    confidence: finding.confidence ?? "not_validated",
    adjudication: finding.adjudication ?? "not_validated",
    supportingEvidenceIds: finding.supporting_evidence_ids ?? [],
    contradictingEvidenceIds: finding.contradicting_evidence_ids ?? [],
    verificationStep: finding.verification_step ?? "Canonical verification step not supplied",
    remediationGuidance: finding.remediation_guidance ?? "Canonical remediation guidance not supplied",
    origin: "API",
  }));
  const evidence = evidencePage.items.map((item): EvidenceView => {
    const engagement = engagementsPage.items.find((candidate) => candidate.engagement_id === item.engagement_id);
    const target = engagement?.target_ids.map((targetId) => targetById.get(targetId)).find(Boolean);
    return {
      evidenceId: item.evidence_id,
      engagementId: item.engagement_id ?? "",
      targetId: target?.target_id ?? "",
      targetSnapshot: target?.snapshot_id ?? "not_validated",
      collector: "Hosted evidence",
      toolVersion: "canonical",
      capabilityId: "not_exposed",
      invocationId: "not_exposed",
      collectedAt: "not_exposed",
      contentType: "application/octet-stream",
      byteSize: 0,
      sha256: item.sha256 ?? "not_validated",
      storageRef: "authenticated-backend-only",
      sanitizationState: item.sanitization_state === "SANITIZED" ? "SANITIZED" : "NOT_VALIDATED",
      usedBy: [],
      origin: "API",
    };
  });
  const runsByEngagement = await Promise.all(engagementsPage.items.map(async (engagement) => {
    const workflows = await api.getRuns(engagement.engagement_id);
    return workflows.flatMap((workflow) => {
      const workflowRecord = workflow as Record<string, unknown>;
      const activities = Array.isArray(workflowRecord.activities)
        ? workflowRecord.activities as Array<Record<string, unknown>>
        : [];
      const source = activities.length ? activities : [workflowRecord];
      return source.map((activity, index): AgentRunView => ({
        agentRunId: String(activity.tool_invocation_id ?? activity.workflow_run_id ?? `${engagement.engagement_id}-activity-${index + 1}`),
        engagementId: engagement.engagement_id,
        agentId: "hosted-workflow",
        agentRole: String(activity.capability_id ?? "Hosted workflow"),
        agentVersion: "canonical",
        modelIdentity: "not_applicable",
        promptVersion: "not_applicable",
        status: String(activity.status ?? workflowRecord.status ?? "not_validated"),
        startedAt: String(workflowRecord.started_at ?? "not_exposed"),
        finishedAt: workflowRecord.finished_at ? String(workflowRecord.finished_at) : null,
        authorityRefs: activity.policy_decision ? [String(activity.policy_decision)] : [],
        capabilityIds: activity.capability_id ? [String(activity.capability_id)] : [],
        toolInvocationIds: activity.tool_invocation_id ? [String(activity.tool_invocation_id)] : [],
        evidenceIds: Array.isArray(activity.result_evidence_ids) ? activity.result_evidence_ids.map(String) : [],
        outputClaimIds: [],
        origin: "API",
      }));
    });
  }));
  const engagements = engagementsPage.items.map((engagement): EngagementView => {
    const firstTarget = engagement.target_ids.map((targetId) => targetById.get(targetId)).find(Boolean);
    return {
      engagementId: engagement.engagement_id,
      clientId: engagement.client_id,
      clientName: clientNames.get(engagement.client_id) ?? engagement.client_id,
      targetIds: engagement.target_ids,
      targetLabel: firstTarget?.name ?? engagement.target_ids.join(", "),
      snapshotLabel: firstTarget?.snapshot_id ?? "snapshot not validated",
      scope: engagement.scope,
      passType: engagement.pass_type,
      authorityLevel: engagement.authority_level,
      constraints: [],
      status: engagement.status,
      updatedAt: engagement.updated_at,
      findingCount: findings.filter((finding) => finding.engagementId === engagement.engagement_id).length,
      origin: "API",
    };
  });
  const reports = (await Promise.all(engagements.map(async (engagement): Promise<ReportView | null> => {
    try {
      const report = await api.getReport(engagement.engagementId);
      return {
        engagementId: report.engagement_id,
        title: `Security report · ${report.engagement_id}`,
        verdict: report.verdict,
        scope: engagement.scope,
        generatedAt: report.generated_at,
        reportSha256: report.sha256,
        limitationCount: 0,
        findingIds: findings.filter((finding) => finding.engagementId === engagement.engagementId).map((finding) => finding.findingId),
        evidenceIds: evidence.filter((item) => item.engagementId === engagement.engagementId).map((item) => item.evidenceId),
        noSecretsAssertion: report.no_secrets_asserted ? "asserted" : "not_validated",
        origin: "API",
      };
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) return null;
      throw error;
    }
  }))).filter((report): report is ReportView => report !== null);
  const detectionSignals: DetectionSignalView[] = detectionSignalsPage.items.map((signal) => ({
    id: signal.signal_id,
    signalId: signal.signal_id,
    caseId: signal.case_id,
    ruleId: signal.rule_id,
    ruleVersion: signal.rule_version,
    severity: signal.severity,
    confidence: signal.confidence,
    state: mapExperienceStatus(signal.status),
    eventIds: signal.event_ids,
    evidenceRefs: signal.evidence_refs,
    scope: { tenantId: signal.tenant_id, caseId: signal.case_id },
    source: signal.source,
    origin: "API",
  }));
  const hunts: HuntView[] = huntsPage.items.map((hunt) => ({
    id: hunt.hunt_id,
    huntId: hunt.hunt_id,
    hypothesisId: hunt.hypothesis_id,
    caseId: hunt.case_id,
    disposition: mapExperienceStatus(hunt.disposition, "INCONCLUSIVE"),
    state: mapExperienceStatus(hunt.status, "INCONCLUSIVE"),
    evidenceRefs: hunt.evidence_refs,
    scope: { tenantId: hunt.tenant_id, caseId: hunt.case_id },
    source: hunt.source,
    origin: "API",
  }));
  const incidents: IncidentView[] = incidentsPage.items.map((incident) => ({
    id: incident.incident_id,
    incidentId: incident.incident_id,
    caseId: incident.case_id,
    state: mapExperienceStatus(incident.status),
    severity: incident.severity,
    confidence: incident.confidence,
    signalIds: incident.signal_ids,
    evidenceRefs: incident.evidence_refs,
    scope: { tenantId: incident.tenant_id, caseId: incident.case_id },
    provenance: {
      source: incident.provenance_source,
      sourceType: incident.provenance_source_type,
      observedAt: incident.adjudicated_at,
      evidenceRefs: incident.evidence_refs,
      status: mapExperienceStatus(incident.status),
    },
    origin: "API",
  }));
  const responseProposals: ResponseProposalView[] = responseProposalsPage.items.map((proposal) => ({
    id: proposal.proposal_id,
    proposalId: proposal.proposal_id,
    incidentId: proposal.incident_id,
    caseId: proposal.case_id,
    targetId: proposal.target_id,
    action: proposal.action,
    opaDecision: mapExperienceStatus(proposal.opa_decision),
    humanApprovalState: mapExperienceStatus(proposal.human_approval_state),
    state: mapExperienceStatus(proposal.status),
    evidenceRefs: proposal.evidence_refs,
    scope: { tenantId: proposal.tenant_id, caseId: proposal.case_id },
    source: proposal.source,
    origin: "API",
  }));
  return {
    mode,
    originLabel: mode === "LOCAL_INTEGRATED" ? "LOCAL / LOOPBACK / LIVE_QUALIFICATION_CANONICAL" : "HOSTED / AUTHENTICATED / CANONICAL_POSTGRESQL",
    engagements,
    findings,
    evidence,
    runs: runsByEngagement.flat(),
    capabilities: [],
    securityServices: [],
    approvals: approvalsPage.items.map((approval): ApprovalView => ({
      approvalId: approval.approval_id,
      engagementId: approval.engagement_id,
      requestedBy: approval.requested_by,
      requestRef: approval.request_ref,
      targetId: approval.target_id,
      capabilityId: approval.capability_id,
      action: approval.action,
      risk: approval.risk,
      decision: approval.decision,
      requestFingerprint: approval.request_fingerprint,
      rationale: approval.rationale,
      origin: "API",
    })),
    clients: clientsPage.items.map((client) => ({
      clientId: client.client_id,
      name: client.name,
      targetCount: targets.filter((target) => target.client_id === client.client_id).length,
      engagementCount: engagements.filter((engagement) => engagement.clientId === client.client_id).length,
      status: "active",
      origin: "API",
    })),
    targets: targets.map((target) => ({
      targetId: target.target_id,
      clientId: target.client_id ?? "",
      name: target.name,
      kind: target.kind,
      snapshot: target.snapshot_id ?? "not_validated",
      snapshotDigest: target.snapshot_digest ?? "not_validated",
      liveCheckout: "separate",
      origin: "API",
    })),
    reports,
    audit: auditPage.items.map((event) => ({
      auditEventId: event.audit_event_id,
      engagementId: event.engagement_id ?? null,
      principalId: event.principal_id ?? null,
      kind: event.kind,
      summary: event.summary,
      occurredAt: event.occurred_at,
      relatedIds: [],
      origin: "API",
    })),
    graphNodes: [],
    graphEdges: [],
    detectionSignals,
    hunts,
    incidents,
    responseProposals,
  };
}
