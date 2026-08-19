import { NextRequest } from "next/server";

type RouteContext = {
  params: Promise<{ path: string[] }>;
};

function upstreamBaseUrl() {
  const configuredMode = process.env.NEXT_PUBLIC_SECSCAN_MODE?.trim().toUpperCase();
  const serverUrl = process.env.SECSCAN_API_URL?.trim();
  if (configuredMode === "HOSTED_INTEGRATED") {
    if (!serverUrl) throw new Error("SECSCAN_API_URL is required for HOSTED_INTEGRATED mode.");
    return serverUrl.replace(/\/$/, "");
  }
  const configuredUrl = serverUrl || process.env.NEXT_PUBLIC_SECSCAN_API_URL?.trim();
  return (configuredUrl || "http://127.0.0.1:8000").replace(/\/$/, "");
}

async function proxy(request: NextRequest, context: RouteContext) {
  try {
    const { path } = await context.params;
    const endpoint = `/${path.map((segment) => encodeURIComponent(segment)).join("/")}${request.nextUrl.search}`;
    const method = request.method;
    const configuredMode = process.env.NEXT_PUBLIC_SECSCAN_MODE?.trim().toUpperCase();
    const headers: Record<string, string> = { Accept: "application/json" };
    if (method !== "GET" && method !== "HEAD") {
      headers["Content-Type"] = request.headers.get("content-type") ?? "application/json";
    }
    if (configuredMode === "HOSTED_INTEGRATED") {
      const authorization = request.headers.get("authorization");
      if (authorization) headers.Authorization = authorization;
      const cookie = request.headers.get("cookie");
      if (cookie) headers.Cookie = cookie;
    } else if (process.env.SECSCAN_PRINCIPAL) {
      headers["X-Secscan-Principal"] = process.env.SECSCAN_PRINCIPAL;
    }
    const response = await fetch(`${upstreamBaseUrl()}${endpoint}`, {
      method,
      headers,
      body: method === "GET" || method === "HEAD" ? undefined : await request.arrayBuffer(),
      cache: "no-store",
    });
    return new Response(response.body, {
      status: response.status,
      headers: { "content-type": response.headers.get("content-type") ?? "application/json" },
    });
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : "SecScanMonitor upstream unavailable." }, { status: 502 });
  }
}

export function GET(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}

export function POST(request: NextRequest, context: RouteContext) {
  return proxy(request, context);
}
