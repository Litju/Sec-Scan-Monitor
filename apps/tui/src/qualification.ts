import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

type AttestationEvent = {
  event: string;
  mode?: string;
  connectionState?: string;
  screen?: string;
  section?: string;
  hasCase?: boolean;
  hasFinding?: boolean;
  hasEvidence?: boolean;
  hasRunner?: boolean;
  signalCount?: number;
  huntCount?: number;
  incidentCount?: number;
  responseProposalCount?: number;
};

type AttestationFile = {
  attestation: "TUI_DOGFOOD_MACHINE_ATTESTED";
  status?: "PASS";
  sanitizedOnly: true;
  previewFallbackUsed: false;
  events: AttestationEvent[];
};

const outputPath = () => process.env.TUI_DOGFOOD_ATTESTATION_PATH?.trim();

export function recordTuiAttestation(event: AttestationEvent): void {
  const path = outputPath();
  if (!path) return;
  let payload: AttestationFile = {
    attestation: "TUI_DOGFOOD_MACHINE_ATTESTED",
    sanitizedOnly: true,
    previewFallbackUsed: false,
    events: [],
  };
  if (existsSync(path)) {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<AttestationFile>;
    if (parsed.status === "PASS") payload.status = parsed.status;
    if (Array.isArray(parsed.events)) payload.events = parsed.events;
  }
  payload.events.push(event);
  if (event.event === "quit") {
    const loaded = payload.events.find((item) => item.event === "snapshot_loaded");
    const screens = new Set(payload.events.filter((item) => item.event === "navigate").map((item) => item.screen));
    if (loaded?.mode === "LOCAL_INTEGRATED"
      && loaded.connectionState === "CONNECTED"
      && (loaded.signalCount ?? 0) > 0
      && (loaded.huntCount ?? 0) > 0
      && (loaded.incidentCount ?? 0) > 0
      && (loaded.responseProposalCount ?? 0) > 0
      && ["Signals", "Hunts", "Incidents", "Response Proposals"].every((screen) => screens.has(screen))) {
      payload.status = "PASS";
    }
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}
