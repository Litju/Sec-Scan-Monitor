import { afterEach, describe, expect, it, vi } from "vitest";
import { createApiClient, getHostedAuthToken, PreviewReadOnlyError, resolveApiMode } from "@/lib/api/client";
import { createCanonicalClient } from "@secscanmonitor/client";

vi.mock("@neondatabase/auth", () => ({
  createInternalNeonAuth: () => ({ getJWTToken: async () => "opaque-session-token" }),
}));

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("SecScan API mode boundary", () => {
  it("defaults to safe preview mode", () => {
    vi.stubEnv("NEXT_PUBLIC_SECSCAN_MODE", "");
    expect(resolveApiMode()).toBe("PREVIEW");
  });

  it("rejects unknown modes instead of falling back silently", () => {
    vi.stubEnv("NEXT_PUBLIC_SECSCAN_MODE", "MOCK");
    expect(() => resolveApiMode()).toThrow("Unsupported NEXT_PUBLIC_SECSCAN_MODE");
  });

  it("blocks preview mutations before any network call", async () => {
    const client = createApiClient("PREVIEW");
    await expect(client.approve("APR-021-004")).rejects.toBeInstanceOf(PreviewReadOnlyError);
  });

  it("uses the controlled API boundary in integrated mode", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ status: "ok", service: "secscan-platform", version: "0.1.0" }), { status: 200 }));
    const health = await createApiClient("LOCAL_INTEGRATED").health();
    expect(health.service).toBe("secscan-platform");
    expect(fetchMock).toHaveBeenCalledWith("/api/secscan/health", expect.objectContaining({ headers: { Accept: "application/json" } }));
  });

  it("normalizes URL boundaries with bounded scans", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ status: "ok" }), { status: 200 }));
    await createCanonicalClient({ mode: "LOCAL_INTEGRATED", baseUrl: "/api/secscan////" }).get("////health");
    expect(fetchMock).toHaveBeenCalledWith("/api/secscan/health", expect.objectContaining({ cache: "no-store" }));
  });

  it("binds an explicitly configured local principal to canonical requests", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ status: "ok" }), { status: 200 }));
    await createCanonicalClient({ mode: "LOCAL_INTEGRATED", principal: " PRN-TUI-OP ", baseUrl: "/api/secscan" }).get("/experience");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/secscan/experience",
      expect.objectContaining({ headers: { Accept: "application/json", "X-Secscan-Principal": "PRN-TUI-OP" } }),
    );
  });

  it("fails closed when hosted authentication is not configured", async () => {
    vi.stubEnv("NEXT_PUBLIC_NEON_AUTH_URL", "");
    await expect(createApiClient("HOSTED_INTEGRATED").health()).rejects.toMatchObject({ status: 503 });
  });

  it("reuses the internal Neon Auth JWT path for hosted revocation", async () => {
    vi.stubEnv("NEXT_PUBLIC_NEON_AUTH_URL", "https://auth.example.test/neondb/auth");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ token: "header.payload.signature" }), { status: 200 }),
    );
    await expect(getHostedAuthToken()).resolves.toBe("header.payload.signature");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://auth.example.test/neondb/auth/token",
      expect.objectContaining({ credentials: "include", cache: "no-store" }),
    );
  });
});
