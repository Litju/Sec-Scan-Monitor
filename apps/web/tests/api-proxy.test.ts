import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GET } from "@/app/api/secscan/[...path]/route";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("Next API boundary", () => {
  it("keeps upstream URL and principal server-side while forwarding the path", async () => {
    vi.stubEnv("NEXT_PUBLIC_SECSCAN_MODE", "LOCAL_INTEGRATED");
    vi.stubEnv("SECSCAN_API_URL", "http://127.0.0.1:8000");
    vi.stubEnv("SECSCAN_PRINCIPAL", "operator-test");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ status: "ok" }), { status: 200, headers: { "content-type": "application/json" } }));
    const request = new NextRequest("http://localhost/api/secscan/health?probe=1");
    const response = await GET(request, { params: Promise.resolve({ path: ["health"] }) });

    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledWith("http://127.0.0.1:8000/health?probe=1", expect.objectContaining({ headers: expect.objectContaining({ "X-Secscan-Principal": "operator-test" }) }));
  });

  it("refuses a browser-exposed upstream URL in hosted mode", async () => {
    vi.stubEnv("NEXT_PUBLIC_SECSCAN_MODE", "HOSTED_INTEGRATED");
    vi.stubEnv("NEXT_PUBLIC_SECSCAN_API_URL", "https://public-backend.example");
    const fetchMock = vi.spyOn(globalThis, "fetch");
    const request = new NextRequest("http://localhost/api/secscan/health");

    const response = await GET(request, { params: Promise.resolve({ path: ["health"] }) });

    expect(response.status).toBe(502);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards only the authenticated hosted request to the server-side upstream", async () => {
    vi.stubEnv("NEXT_PUBLIC_SECSCAN_MODE", "HOSTED_INTEGRATED");
    vi.stubEnv("SECSCAN_API_URL", "https://private-api.example");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    const request = new NextRequest("http://localhost/api/secscan/firm/summary", {
      headers: { Authorization: "Bearer signed-token", Cookie: "neon-session=session" },
    });

    const response = await GET(request, { params: Promise.resolve({ path: ["firm", "summary"] }) });

    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://private-api.example/firm/summary",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: "Bearer signed-token", Cookie: "neon-session=session" }),
      }),
    );
  });
});
