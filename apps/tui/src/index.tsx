import { createCliRenderer } from "@opentui/core";
import { createDefaultOpenTuiKeymap } from "@opentui/keymap/opentui";
import { createRoot } from "@opentui/react";
import { App } from "./App.tsx";
import { loadTuiSnapshot } from "./data.ts";
import { recordTuiAttestation } from "./qualification.ts";

const renderer = await createCliRenderer({ exitOnCtrlC: true });
const keymap = createDefaultOpenTuiKeymap(renderer);
const snapshot = await loadTuiSnapshot();
recordTuiAttestation({
  event: "snapshot_loaded",
  mode: snapshot.mode,
  connectionState: snapshot.connectionState,
  hasCase: snapshot.cases.length > 0,
  hasFinding: snapshot.findings.length > 0,
  hasEvidence: snapshot.graphNodes.some((node) => node.kind === "evidence"),
  hasRunner: snapshot.runners.length > 0,
  signalCount: snapshot.detectionSignals?.length ?? 0,
  huntCount: snapshot.hunts?.length ?? 0,
  incidentCount: snapshot.incidents?.length ?? 0,
  responseProposalCount: snapshot.responseProposals?.length ?? 0,
});

createRoot(renderer).render(<App renderer={renderer} keymap={keymap} snapshot={snapshot} />);
