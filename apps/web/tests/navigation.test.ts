import { describe, expect, it } from "vitest";
import { normalizeSurface, pathForSurface, primaryRoutes, surfaceRoutes } from "@/lib/domain/navigation";

describe("product route map", () => {
  it("keeps the simplified primary IA and expert routes in one map", () => {
    expect(primaryRoutes.map((route) => route.key)).toEqual(["today", "cases", "clients", "reports"]);
    expect(surfaceRoutes.map((route) => route.key)).toEqual(expect.arrayContaining([
      "today", "cases", "clients", "reports", "settings", "findings", "evidence", "runs", "capabilities", "approvals", "governance", "audit", "skills", "runtime", "assistant", "command-center", "engagements",
    ]));
  });

  it("keeps old URLs compatible while using the new case paths for navigation", () => {
    expect(pathForSurface("today")).toBe("/");
    expect(pathForSurface("command-center")).toBe("/");
    expect(normalizeSurface("engagements")).toBe("cases");
    expect(pathForSurface("engagements", "ENG-PUBLIC-021")).toBe("/engagements/ENG-PUBLIC-021");
    expect(pathForSurface("cases", "ENG-PUBLIC-021")).toBe("/cases/ENG-PUBLIC-021");
  });
});
