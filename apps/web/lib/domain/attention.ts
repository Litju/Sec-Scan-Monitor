import type { SurfaceKey } from "@/lib/domain/navigation";
import type { PreviewData } from "@/lib/domain/types";

export type AttentionKind =
  | "FindingNeedsReview"
  | "ApprovalNeeded"
  | "CaseReadyToClose"
  | "CaseBlocked"
  | "CaseDegraded"
  | "CaseFailed"
  | "ImportantResult"
  | "DetectionSignalNew"
  | "ConfirmedIncident"
  | "ResponseProposalApproval";

export type AttentionItem = {
  id: string;
  kind: AttentionKind;
  title: string;
  subject: string;
  reason: string;
  nextAction: string;
  actionLabel: string;
  surface: SurfaceKey;
  entityId: string;
  tone: "warning" | "danger" | "info";
  detail: string;
};

export function buildAttentionItems(data: PreviewData): AttentionItem[] {
  const activeEngagementIds = new Set(data.engagements.filter((engagement) => !["closed", "refused", "revoked"].includes(engagement.status)).map((engagement) => engagement.engagementId));
  const signalItems = (data.detectionSignals ?? [])
    .filter((signal) => signal.state === "NEW" && activeEngagementIds.has(signal.caseId))
    .map<AttentionItem>((signal) => ({
      id: `detection-signal-${signal.signalId}`,
      kind: "DetectionSignalNew",
      title: "New detection signal",
      subject: `${signal.ruleId} · ${signal.severity}`,
      reason: `The detector matched ${signal.eventIds.length} event${signal.eventIds.length === 1 ? "" : "s"}; this is a signal, not an incident.`,
      nextAction: "Inspect the rule, event references, and bounded evidence chain.",
      actionLabel: "Inspect signal",
      surface: "signals",
      entityId: signal.signalId,
      tone: signal.severity.toLowerCase() === "critical" || signal.severity.toLowerCase() === "high" ? "danger" : "warning",
      detail: `${signal.signalId} · ${signal.caseId}`,
    }));

  const incidentItems = (data.incidents ?? [])
    .filter((incident) => incident.state === "CONFIRMED" && activeEngagementIds.has(incident.caseId))
    .map<AttentionItem>((incident) => ({
      id: `incident-${incident.incidentId}`,
      kind: "ConfirmedIncident",
      title: "Confirmed incident",
      subject: `${incident.incidentId} · ${incident.severity}`,
      reason: `Adjudication is ${incident.confidence.toLowerCase()} confidence with ${incident.evidenceRefs.length} evidence reference${incident.evidenceRefs.length === 1 ? "" : "s"}.`,
      nextAction: "Inspect the incident decision and its supporting provenance.",
      actionLabel: "Inspect incident",
      surface: "incidents",
      entityId: incident.incidentId,
      tone: "danger",
      detail: `${incident.incidentId} · ${incident.caseId}`,
    }));

  const responseItems = (data.responseProposals ?? [])
    .filter((proposal) => proposal.humanApprovalState === "APPROVAL_REQUIRED" && activeEngagementIds.has(proposal.caseId))
    .map<AttentionItem>((proposal) => ({
      id: `response-proposal-${proposal.proposalId}`,
      kind: "ResponseProposalApproval",
      title: "Response proposal awaits approval",
      subject: `${proposal.action} · ${proposal.targetId}`,
      reason: `OPA decision is ${proposal.opaDecision}; execution remains disabled until the exact human approval boundary is satisfied.`,
      nextAction: "Review the incident evidence and exact approval binding.",
      actionLabel: "Inspect proposal",
      surface: "response-proposals",
      entityId: proposal.proposalId,
      tone: "warning",
      detail: `${proposal.proposalId} · ${proposal.caseId}`,
    }));

  const findingItems = data.findings
    .filter((finding) => finding.status === "open" && activeEngagementIds.has(finding.engagementId))
    .map<AttentionItem>((finding) => ({
      id: `finding-${finding.findingId}`,
      kind: "FindingNeedsReview",
      title: "Finding needs review",
      subject: finding.summary,
      reason: `Security severity ${finding.severity}; adjudication is ${finding.adjudication.toLowerCase()}.`,
      nextAction: "Confirm the bounded conclusion and its next evidence request.",
      actionLabel: "Review finding",
      surface: "findings",
      entityId: finding.findingId,
      tone: finding.severity === "Critical" || finding.severity === "High" ? "danger" : "warning",
      detail: `${finding.findingId} · ${finding.engagementId}`,
    }));

  const approvalItems = data.approvals
    .filter((approval) => approval.decision === "pending")
    .map<AttentionItem>((approval) => ({
      id: `approval-${approval.approvalId}`,
      kind: "ApprovalNeeded",
      title: "Configuration change requested",
      subject: approval.action,
      reason: `The request is bound to ${approval.targetId} and ${approval.capabilityId}.`,
      nextAction: "Review the exact request before any integrated-mode decision.",
      actionLabel: "Review approval",
      surface: "approvals",
      entityId: approval.approvalId,
      tone: "warning",
      detail: `${approval.approvalId} · ${approval.engagementId}`,
    }));

  return [...signalItems, ...incidentItems, ...findingItems, ...responseItems, ...approvalItems];
}
