import { describe, expect, it } from "vitest";
import { buildAttentionItems } from "@/lib/domain/attention";
import { previewData } from "@/lib/domain/preview-data";

describe("attention read-model projection", () => {
  it("keeps Today focused on active work and exact requests", () => {
    const items = buildAttentionItems(previewData);
    expect(items).toHaveLength(4);
    expect(items.map((item) => item.kind)).toEqual(["DetectionSignalNew", "ConfirmedIncident", "ResponseProposalApproval", "ApprovalNeeded"]);
    expect(items[0]?.entityId).toBe("SIG-PREV-022-001");
    expect(items[1]?.entityId).toBe("INC-PREV-022-001");
    expect(items[2]?.entityId).toBe("RSP-PREV-022-001");
    expect(items.every((item) => item.nextAction.length > 0)).toBe(true);
  });
});
