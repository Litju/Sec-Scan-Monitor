import type { DataMode } from "../../secscan-experience-contracts/src/index";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly endpoint: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export class PreviewReadOnlyError extends Error {
  constructor(action: string) {
    super(`Preview mode is read-only; ${action} is disabled.`);
    this.name = "PreviewReadOnlyError";
  }
}

type CanonicalClientOptions = {
  mode: DataMode;
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  getAuthorization?: (endpoint: string) => Promise<string>;
};

function joinUrl(baseUrl: string, endpoint: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/${endpoint.replace(/^\/+/, "")}`;
}

export function createCanonicalClient({ mode, baseUrl = "/api/secscan", fetchImpl = fetch, getAuthorization }: CanonicalClientOptions) {
  async function request<T>(endpoint: string, init: RequestInit = {}): Promise<T> {
    if (mode === "PREVIEW") throw new PreviewReadOnlyError(`${init.method ?? "GET"} ${endpoint}`);
    const headers: Record<string, string> = { Accept: "application/json" };
    if (init.body !== undefined) headers["Content-Type"] = "application/json";
    if (getAuthorization) headers.Authorization = await getAuthorization(endpoint);
    const response = await fetchImpl(joinUrl(baseUrl, endpoint), { ...init, headers, cache: "no-store" });
    if (!response.ok) throw new ApiError(`SecScanMonitor API returned ${response.status}.`, response.status, endpoint);
    return (await response.json()) as T;
  }

  return {
    mode,
    get: <T>(endpoint: string) => request<T>(endpoint),
    post: <T>(endpoint: string, payload?: unknown) => request<T>(endpoint, { method: "POST", body: payload === undefined ? undefined : JSON.stringify(payload) }),
  };
}
