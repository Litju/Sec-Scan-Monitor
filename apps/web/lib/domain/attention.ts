import type { SurfaceKey } from "@/lib/domain/navigation";
import type { PreviewData } from "@/lib/domain/types";

export type AttentionKind =
  | "FindingNeedsReview"
  | "ApprovalNeeded"
  | "CaseReadyToClose"
  | "CaseBlocked"
  | "CaseDegraded"
  | "CaseFailed"
  | "ImportantResult";

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

  return [...findingItems, ...approvalItems];
}
