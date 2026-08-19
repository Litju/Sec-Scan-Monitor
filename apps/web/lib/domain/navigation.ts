export type SurfaceKey =
  | "today"
  | "cases"
  | "clients"
  | "reports"
  | "settings"
  | "findings"
  | "evidence"
  | "runs"
  | "capabilities"
  | "approvals"
  | "governance"
  | "audit"
  | "skills"
  | "runtime"
  | "assistant"
  | "command-center"
  | "engagements";

export type RouteGroup = "primary" | "settings" | "expert" | "legacy";

export type RouteDefinition = {
  key: SurfaceKey;
  label: string;
  eyebrow: string;
  description: string;
  group: RouteGroup;
  pigment: string;
};

export const primaryRoutes: readonly RouteDefinition[] = [
  { key: "today", label: "Today", eyebrow: "Operator attention", description: "See what needs you, what is moving, and what just finished.", group: "primary", pigment: "prussian-verdigris" },
  { key: "cases", label: "Cases", eyebrow: "Contract-governed work", description: "Move client work through a readable, evidence-aware case view.", group: "primary", pigment: "verdigris-celadon" },
  { key: "clients", label: "Clients", eyebrow: "Client security state", description: "Understand a client’s targets, cases, findings, and reports.", group: "primary", pigment: "celadon-prussian" },
  { key: "reports", label: "Reports", eyebrow: "Firm record", description: "Read editorial conclusions with limitations and provenance in view.", group: "primary", pigment: "quartz-lapis" },
];

export const settingsRoutes: readonly RouteDefinition[] = [
  { key: "settings", label: "Settings", eyebrow: "Administration", description: "Policies, capabilities, audit, skills, and runtime posture.", group: "settings", pigment: "quartz-orpiment" },
];

export const expertRoutes: readonly RouteDefinition[] = [
  { key: "findings", label: "Findings", eyebrow: "Adjudication", description: "Inspect adjudicated conclusions and their evidence chain.", group: "expert", pigment: "orpiment-cinnabar" },
  { key: "evidence", label: "Evidence", eyebrow: "Chain of custody", description: "Inspect safe metadata without retrieving raw evidence in the browser.", group: "expert", pigment: "verdigris-lapis" },
  { key: "runs", label: "Activity", eyebrow: "Execution record", description: "Review bounded activity without treating an agent as authority.", group: "expert", pigment: "tyrian-prussian" },
  { key: "capabilities", label: "Tools", eyebrow: "Execution trust", description: "Follow registered tools, permissions, sandbox, and evidence boundaries.", group: "expert", pigment: "prussian-quartz" },
  { key: "approvals", label: "Approvals", eyebrow: "Exact binding", description: "Decide against one exact target, tool, action, and request.", group: "expert", pigment: "orpiment-cinnabar" },
  { key: "governance", label: "Policies", eyebrow: "Authority stack", description: "See the canonical authority hierarchy without recreating it.", group: "expert", pigment: "quartz-orpiment" },
  { key: "audit", label: "Audit", eyebrow: "Deterministic reconstruction", description: "Reconstruct who requested what, under which authority, and why.", group: "expert", pigment: "prussian-quartz" },
  { key: "skills", label: "Skills", eyebrow: "Institutional memory", description: "Connect observations to tests, patches, review, and reuse.", group: "expert", pigment: "celadon-tyrian" },
  { key: "runtime", label: "Runtime", eyebrow: "Service posture", description: "Inspect integration mode and qualification state.", group: "expert", pigment: "tyrian-prussian" },
  { key: "assistant", label: "Ask", eyebrow: "Context lens", description: "Ask grounded questions without granting authority or inventing evidence.", group: "expert", pigment: "tyrian-prussian" },
];

export const legacyRoutes: readonly RouteDefinition[] = [
  { key: "command-center", label: "Command Center", eyebrow: "Legacy route", description: "Compatibility alias for Today.", group: "legacy", pigment: "prussian-verdigris" },
  { key: "engagements", label: "Engagements", eyebrow: "Legacy route", description: "Compatibility alias for Cases.", group: "legacy", pigment: "verdigris-celadon" },
];

export const surfaceRoutes: readonly RouteDefinition[] = [
  ...primaryRoutes,
  ...settingsRoutes,
  ...expertRoutes,
  ...legacyRoutes,
];

export function normalizeSurface(surface: SurfaceKey): SurfaceKey {
  if (surface === "command-center") return "today";
  if (surface === "engagements") return "cases";
  return surface;
}

export function isSurfaceKey(value: string): value is SurfaceKey {
  return surfaceRoutes.some((route) => route.key === value);
}

export function getRouteDefinition(surface: SurfaceKey): RouteDefinition {
  const normalized = normalizeSurface(surface);
  return surfaceRoutes.find((route) => route.key === normalized) ?? primaryRoutes[0];
}

export function pathForSurface(surface: SurfaceKey, id?: string): string {
  if (surface === "command-center") return id ? `/command-center/${encodeURIComponent(id)}` : "/";
  if (surface === "engagements") return id ? `/engagements/${encodeURIComponent(id)}` : "/engagements";
  const normalized = normalizeSurface(surface);
  return id ? `/${normalized}/${encodeURIComponent(id)}` : normalized === "today" ? "/" : `/${normalized}`;
}
