import { describe, expect, it } from "vitest";
import { buildAttentionItems } from "@/lib/domain/attention";
import { previewData } from "@/lib/domain/preview-data";

describe("attention read-model projection", () => {
  it("keeps Today focused on active work and exact requests", () => {
    const items = buildAttentionItems(previewData);
    expect(items).toHaveLength(1);
    expect(items.map((item) => item.kind)).toEqual(["ApprovalNeeded"]);
    expect(items[0]?.entityId).toBe("APR-015-004");
    expect(items.every((item) => item.nextAction.length > 0)).toBe(true);
  });
});
