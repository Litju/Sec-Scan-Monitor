import { useEffect, useMemo, useState } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { safeDisplay, sortActivityEntries, type ExperienceActivityView, type ExperienceDetectionSignalView, type ExperienceHuntView, type ExperienceIncidentView, type ExperienceResponseProposalView, type ExperienceSnapshot } from "../../../packages/secscan-experience-contracts/src/index.ts";
import { recordTuiAttestation } from "./qualification.ts";

type Screen = "Today" | "Cases" | "Case" | "Graph" | "Activity" | "Runners" | "Signals" | "Hunts" | "Incidents" | "Response Proposals";
type Section = "Overview" | "Findings" | "Activity" | "Evidence";
type RendererLike = { destroy: () => void };
type KeymapLike = { registerLayer: (layer: { commands: Array<{ name: string; run: () => void }>; bindings: Array<{ key: string; cmd: string }> }) => () => void };

type Props = {
  snapshot: ExperienceSnapshot;
  renderer: RendererLike;
  keymap: KeymapLike;
};

function State({ value }: { value: string }) {
  return <span fg={value === "VERIFIED" || value === "RESOLVED" ? "#8dd3a7" : value === "UNAVAILABLE" || value === "DENIED" ? "#ff9b8f" : "#f4c97d"}>{safeDisplay(value)}</span>;
}

function Header({ snapshot, compact }: { snapshot: ExperienceSnapshot; compact: boolean }) {
  if (compact) return <box paddingLeft={1} paddingRight={1}><text><strong>SSM</strong> <State value={snapshot.connectionState} /> <span fg="#8e9aaf">· {safeDisplay(snapshot.mode)}</span></text></box>;
  return <box flexDirection="row" justifyContent="space-between" paddingLeft={1} paddingRight={1}><text><strong>SECSCANMONITOR</strong> <span fg="#8e9aaf">/ OPERATOR CONSOLE</span></text><text><State value={snapshot.connectionState} /> <span fg="#8e9aaf">· {safeDisplay(snapshot.mode)}</span></text></box>;
}

function Nav({ screen, compact }: { screen: Screen; compact: boolean }) {
  if (compact) return <box paddingLeft={1} paddingRight={1}><text fg="#8e9aaf">[t] [c] [s] [h] [i] [o] [/] [q]</text></box>;
  return <box flexDirection="row" gap={2} paddingLeft={1} paddingRight={1}><text fg={screen === "Today" ? "#f4c97d" : "#8e9aaf"}>[t]oday</text><text fg={screen === "Cases" || screen === "Case" ? "#f4c97d" : "#8e9aaf"}>[c]ases</text><text fg={screen === "Signals" ? "#f4c97d" : "#8e9aaf"}>[s]ignals</text><text fg={screen === "Hunts" ? "#f4c97d" : "#8e9aaf"}>[h]unts</text><text fg={screen === "Incidents" ? "#f4c97d" : "#8e9aaf"}>[i]ncidents</text><text fg={screen === "Response Proposals" ? "#f4c97d" : "#8e9aaf"}>[o]proposals</text><text fg="#8e9aaf">[/] search · [q] quit</text></box>;
}

function Unavailable({ snapshot, detail }: { snapshot: ExperienceSnapshot; detail: string }) {
  return <box border borderColor="#7d8797" padding={1}><text><strong fg="#ff9b8f">UNAVAILABLE</strong> <span fg="#c8d0dc">{safeDisplay(detail)}</span>{"\n"}<span fg="#8e9aaf">No preview fallback is active for integrated state.</span>{"\n"}<span fg="#8e9aaf">source: {safeDisplay(snapshot.sourceLabel)}</span></text></box>;
}

function Attention({ snapshot, onOpenCase }: { snapshot: ExperienceSnapshot; onOpenCase: (caseId?: string) => void }) {
  const attention = snapshot.attention.filter((item) => item.scope.tenantId === snapshot.tenantId);
  return <box flexDirection="column" gap={1}><text><strong>Attention</strong> <span fg="#8e9aaf">meaningful change before raw counts</span></text>{attention.length ? attention.map((item) => <box border borderColor="#444e5d" paddingLeft={1} paddingRight={1} key={item.id} onMouseUp={() => onOpenCase(item.caseId)}><text><State value={item.status} /> <strong>{safeDisplay(item.title)}</strong>{"\n"}<span fg="#b6c0ce">{safeDisplay(item.detail)}</span>{"\n"}<span fg="#8e9aaf">next: {safeDisplay(item.nextAction ?? "inspect the canonical record")} · {safeDisplay(item.entityId)}</span></text></box>) : <text fg="#8e9aaf">No attention projection is available.</text>}</box>;
}

function Today({ snapshot, onOpenCase }: { snapshot: ExperienceSnapshot; onOpenCase: (caseId?: string) => void }) {
  const cases = snapshot.cases.filter((item) => item.scope.tenantId === snapshot.tenantId);
  return <box flexDirection="column" gap={1}><text><strong>Today</strong> <span fg="#8e9aaf">what changed, what needs a decision, and what is not yet known</span></text>{snapshot.connectionState === "UNAVAILABLE" ? <Unavailable snapshot={snapshot} detail="The canonical operator read model could not be loaded." /> : null}<Attention snapshot={snapshot} onOpenCase={onOpenCase} />{cases.map((item) => <box border borderColor="#444e5d" padding={1} key={item.id} onMouseUp={() => onOpenCase(item.caseId)}><text><State value={item.state} /> <strong>{safeDisplay(item.caseId)}</strong> · {safeDisplay(item.clientLabel)}{"\n"}<span fg="#b6c0ce">{safeDisplay(item.summary)}</span>{"\n"}<span fg="#8e9aaf">{safeDisplay(item.targetLabel)} · updated {safeDisplay(item.updatedAt)}</span></text></box>)}</box>;
}

function Cases({ snapshot, query, onOpenCase }: { snapshot: ExperienceSnapshot; query: string; onOpenCase: (caseId: string) => void }) {
  const cases = snapshot.cases.filter((item) => item.scope.tenantId === snapshot.tenantId && `${item.caseId} ${item.clientLabel} ${item.targetLabel}`.toLowerCase().includes(query.toLowerCase()));
  return <box flexDirection="column" gap={1}><text><strong>Cases</strong> <span fg="#8e9aaf">{String(cases.length)} visible · [Enter] opens selected case</span></text>{cases.length ? cases.map((item) => <box border borderColor="#444e5d" padding={1} key={item.id} onMouseUp={() => onOpenCase(item.caseId)}><text><State value={item.state} /> <strong>{safeDisplay(item.caseId)}</strong> · {safeDisplay(item.clientLabel)}{"\n"}<span fg="#b6c0ce">{safeDisplay(item.summary)}</span>{"\n"}<span fg="#8e9aaf">findings {String(item.findingIds.length)} · evidence {String(item.evidenceCount)} · activity {String(item.activityCount)}</span></text></box>) : <text fg="#8e9aaf">No case matches this search. No state was inferred.</text>}</box>;
}

function CaseView({ snapshot, caseId, section }: { snapshot: ExperienceSnapshot; caseId?: string; section: Section }) {
  const scopedCases = snapshot.cases.filter((candidate) => candidate.scope.tenantId === snapshot.tenantId);
  const item = scopedCases.find((candidate) => candidate.caseId === caseId) ?? scopedCases[0];
  if (!item) return <Unavailable snapshot={snapshot} detail="No case is selected." />;
  const findings = snapshot.findings.filter((finding) => finding.caseId === item.caseId && finding.scope.tenantId === snapshot.tenantId && finding.scope.caseId === item.caseId);
  const activity = sortActivityEntries(snapshot.activity.filter((entry) => entry.caseId === item.caseId && entry.scope.tenantId === snapshot.tenantId && entry.scope.caseId === item.caseId));
  const signals = (snapshot.detectionSignals ?? []).filter((signal) => signal.caseId === item.caseId && signal.scope.tenantId === snapshot.tenantId);
  const hunts = (snapshot.hunts ?? []).filter((hunt) => hunt.caseId === item.caseId && hunt.scope.tenantId === snapshot.tenantId);
  const incidents = (snapshot.incidents ?? []).filter((incident) => incident.caseId === item.caseId && incident.scope.tenantId === snapshot.tenantId);
  const proposals = (snapshot.responseProposals ?? []).filter((proposal) => proposal.caseId === item.caseId && proposal.scope.tenantId === snapshot.tenantId);
  return <box flexDirection="column" gap={1}><text><strong>Case {safeDisplay(item.caseId)}</strong> <span fg="#8e9aaf">{safeDisplay(item.clientLabel)} · {safeDisplay(item.targetLabel)}</span></text><box flexDirection="row" gap={2}><text fg={section === "Overview" ? "#f4c97d" : "#8e9aaf"}>[p]atrol / overview</text><text fg={section === "Findings" ? "#f4c97d" : "#8e9aaf"}>[f]indings</text><text fg={section === "Activity" ? "#f4c97d" : "#8e9aaf"}>[a]ctivity</text><text fg={section === "Evidence" ? "#f4c97d" : "#8e9aaf"}>[e]vidence</text></box>{section === "Overview" ? <><box border borderColor="#444e5d" padding={1}><text><State value={item.state} /> <strong>Patrol state</strong>{"\n"}{safeDisplay(item.summary)}{"\n"}<span fg="#8e9aaf">what changed: {safeDisplay(item.updatedAt)} · provenance: {safeDisplay(item.provenance.source)} · evidence: {item.provenance.evidenceRefs.map(safeDisplay).join(" · ") || "none"}</span></text></box><DetectionResponseTrace signals={signals} hunts={hunts} incidents={incidents} proposals={proposals} /></> : null}{section === "Findings" ? <box flexDirection="column" gap={1}>{findings.length ? findings.map((finding) => <box border borderColor="#444e5d" padding={1} key={finding.id}><text><State value={finding.state} /> <strong>{safeDisplay(finding.findingId)}</strong> · {safeDisplay(finding.severity)}{"\n"}<span fg="#b6c0ce">{safeDisplay(finding.title)}</span>{"\n"}<span fg="#8e9aaf">adjudication {safeDisplay(finding.adjudication)} · evidence {finding.evidenceRefs.map(safeDisplay).join(" · ") || "none"}</span></text></box>) : <text fg="#8e9aaf">No finding projection is available.</text>}</box> : null}{section === "Activity" ? <ActivityList entries={activity} /> : null}{section === "Evidence" ? <box border borderColor="#444e5d" padding={1}><text><strong>Evidence references</strong>{"\n"}<span fg="#b6c0ce">{findings.flatMap((finding) => finding.evidenceRefs).map(safeDisplay).join(" · ") || "No evidence references were supplied."}</span>{"\n"}<span fg="#8e9aaf">Raw evidence and retrieval commands never enter the console.</span></text></box> : null}</box>;
}

function DetectionResponseTrace({ signals, hunts, incidents, proposals }: { signals: ExperienceDetectionSignalView[]; hunts: ExperienceHuntView[]; incidents: ExperienceIncidentView[]; proposals: ExperienceResponseProposalView[] }) {
  return <box border borderColor="#444e5d" padding={1}><text><strong>Detection → response trace</strong>{"\n"}<span fg="#8e9aaf">Event → Rule → Signal → Hunt → Claim → Incident → Response Proposal</span>{"\n"}<span fg="#b6c0ce">events {String(signals.reduce((count, signal) => count + signal.eventIds.length, 0))} · rules {Array.from(new Set(signals.map((signal) => `${signal.ruleId}@${signal.ruleVersion}`))).map(safeDisplay).join(" · ") || "none"}</span>{"\n"}<span fg="#b6c0ce">signals {signals.map((signal) => safeDisplay(signal.signalId)).join(" · ") || "none"} · hunts {hunts.map((hunt) => safeDisplay(hunt.huntId)).join(" · ") || "none"}</span>{"\n"}<span fg="#b6c0ce">incidents {incidents.map((incident) => safeDisplay(`${incident.incidentId} ${incident.state}`)).join(" · ") || "none"} · proposals {proposals.map((proposal) => safeDisplay(proposal.proposalId)).join(" · ") || "none"}</span>{"\n"}<span fg="#8e9aaf">No detector, model, or console interaction grants incident or response authority.</span></text></box>;
}

function ActivityList({ entries }: { entries: ExperienceActivityView[] }) {
  return <box flexDirection="column" gap={1}>{entries.length ? entries.slice(0, 50).map((entry) => <box border borderColor="#444e5d" paddingLeft={1} key={entry.id}><text><State value={entry.state} /> <strong>{safeDisplay(entry.title)}</strong>{"\n"}<span fg="#b6c0ce">{safeDisplay(entry.detail)}</span>{"\n"}<span fg="#8e9aaf">{safeDisplay(entry.occurredAt)} · {safeDisplay(entry.source)} · evidence {entry.evidenceRefs.map(safeDisplay).join(" · ") || "none"}</span></text></box>) : <text fg="#8e9aaf">No activity projection is available.</text>}</box>;
}

function Graph({ snapshot }: { snapshot: ExperienceSnapshot }) {
  const nodes = snapshot.graphNodes.filter((node) => node.scope.tenantId === snapshot.tenantId);
  const edges = snapshot.graphEdges.filter((edge) => edge.scope.tenantId === snapshot.tenantId);
  return <box flexDirection="column" gap={1}><text><strong>Graph</strong> <span fg="#8e9aaf">bounded canonical projection · accessible list/tree view</span></text>{nodes.length || edges.length ? <box flexDirection="column" gap={1}>{nodes.slice(0, 40).map((node) => <box border borderColor="#444e5d" paddingLeft={1} key={node.id}><text><State value={node.state} /> <strong>{safeDisplay(node.label)}</strong>{"\n"}<span fg="#8e9aaf">{safeDisplay(node.kind)} · {safeDisplay(node.provenance.source)} · observed {safeDisplay(node.provenance.observedAt)} · evidence {node.provenance.evidenceRefs.map(safeDisplay).join(" · ") || "none"}</span></text></box>)}{edges.slice(0, 40).map((edge) => <box border borderColor="#444e5d" paddingLeft={1} key={edge.id}><text><State value={edge.state} /> <strong>{safeDisplay(edge.relation)}</strong>{"\n"}<span fg="#8e9aaf">{safeDisplay(edge.sourceId)} → {safeDisplay(edge.targetId)} · {safeDisplay(edge.provenance.source)}</span></text></box>)}</box> : <text fg="#8e9aaf">Graph projection unavailable. No relationship was inferred.</text>}</box>;
}

function Runners({ snapshot }: { snapshot: ExperienceSnapshot }) {
  const runners = snapshot.runners.filter((runner) => runner.scope.tenantId === snapshot.tenantId);
  return <box flexDirection="column" gap={1}><text><strong>Runners</strong> <span fg="#8e9aaf">receipts only · no shell or arbitrary command construction</span></text>{runners.length ? runners.map((runner) => <box border borderColor="#444e5d" padding={1} key={runner.id}><text><State value={runner.state} /> <strong>{safeDisplay(runner.runnerId)}</strong>{"\n"}<span fg="#b6c0ce">capability {safeDisplay(runner.capabilityId)} · policy {safeDisplay(runner.policyDecision)}</span>{"\n"}<span fg="#8e9aaf">source {safeDisplay(runner.source)} · evidence {runner.evidenceRefs.map(safeDisplay).join(" · ") || "none"}</span></text></box>) : <text fg="#8e9aaf">Runner projection unavailable.</text>}</box>;
}

function Signals({ snapshot }: { snapshot: ExperienceSnapshot }) {
  const signals = (snapshot.detectionSignals ?? []).filter((signal) => signal.scope.tenantId === snapshot.tenantId).slice(0, 50);
  return <box flexDirection="column" gap={1}><text><strong>Signals</strong> <span fg="#8e9aaf">bounded detector output · not findings or incidents</span></text>{signals.length ? signals.map((signal) => <box border borderColor="#444e5d" padding={1} key={signal.id}><text><State value={signal.state} /> <strong>{safeDisplay(signal.signalId)}</strong> · {safeDisplay(signal.severity)} / {safeDisplay(signal.confidence)}{"\n"}<span fg="#b6c0ce">rule {safeDisplay(signal.ruleId)} v{String(signal.ruleVersion)} · case {safeDisplay(signal.caseId)}</span>{"\n"}<span fg="#8e9aaf">events {signal.eventIds.map(safeDisplay).join(" · ") || "none"} · evidence {signal.evidenceRefs.map(safeDisplay).join(" · ") || "none"}</span></text></box>) : <text fg="#8e9aaf">No signal projection is available.</text>}</box>;
}

function Hunts({ snapshot }: { snapshot: ExperienceSnapshot }) {
  const hunts = (snapshot.hunts ?? []).filter((hunt) => hunt.scope.tenantId === snapshot.tenantId).slice(0, 50);
  return <box flexDirection="column" gap={1}><text><strong>Hunts</strong> <span fg="#8e9aaf">scoped hypotheses and evidence only</span></text>{hunts.length ? hunts.map((hunt) => <box border borderColor="#444e5d" padding={1} key={hunt.id}><text><State value={hunt.state} /> <strong>{safeDisplay(hunt.huntId)}</strong> · {safeDisplay(hunt.disposition)}{"\n"}<span fg="#b6c0ce">hypothesis {safeDisplay(hunt.hypothesisId)} · case {safeDisplay(hunt.caseId)}</span>{"\n"}<span fg="#8e9aaf">evidence {hunt.evidenceRefs.map(safeDisplay).join(" · ") || "none"} · source {safeDisplay(hunt.source)}</span></text></box>) : <text fg="#8e9aaf">No hunt projection is available.</text>}</box>;
}

function Incidents({ snapshot }: { snapshot: ExperienceSnapshot }) {
  const incidents = (snapshot.incidents ?? []).filter((incident) => incident.scope.tenantId === snapshot.tenantId).slice(0, 50);
  return <box flexDirection="column" gap={1}><text><strong>Incidents</strong> <span fg="#8e9aaf">adjudicated state · evidence-backed authority</span></text>{incidents.length ? incidents.map((incident) => <box border borderColor="#444e5d" padding={1} key={incident.id}><text><State value={incident.state} /> <strong>{safeDisplay(incident.incidentId)}</strong> · {safeDisplay(incident.severity)} / {safeDisplay(incident.confidence)}{"\n"}<span fg="#b6c0ce">case {safeDisplay(incident.caseId)} · signals {incident.signalIds.map(safeDisplay).join(" · ") || "none"}</span>{"\n"}<span fg="#8e9aaf">evidence {incident.evidenceRefs.map(safeDisplay).join(" · ") || "none"} · provenance {safeDisplay(incident.provenance.source)} · observed {safeDisplay(incident.provenance.observedAt)}</span></text></box>) : <text fg="#8e9aaf">No incident projection is available. A signal alone is not an incident.</text>}</box>;
}

function ResponseProposals({ snapshot }: { snapshot: ExperienceSnapshot }) {
  const proposals = (snapshot.responseProposals ?? []).filter((proposal) => proposal.scope.tenantId === snapshot.tenantId).slice(0, 50);
  return <box flexDirection="column" gap={1}><text><strong>Response Proposals</strong> <span fg="#8e9aaf">advisory only · no direct execution</span></text>{proposals.length ? proposals.map((proposal) => <box border borderColor="#444e5d" padding={1} key={proposal.id}><text><State value={proposal.state} /> <strong>{safeDisplay(proposal.proposalId)}</strong> · {safeDisplay(proposal.action)}{"\n"}<span fg="#b6c0ce">incident {safeDisplay(proposal.incidentId)} · target {safeDisplay(proposal.targetId)}</span>{"\n"}<span fg="#8e9aaf">OPA {safeDisplay(proposal.opaDecision)} · human {safeDisplay(proposal.humanApprovalState)} · evidence {proposal.evidenceRefs.map(safeDisplay).join(" · ") || "none"}</span>{"\n"}<span fg="#f4c97d">AUTHORIZED_ACTION_EXECUTED=NO · exact human approval remains required.</span></text></box>) : <text fg="#8e9aaf">No response proposal projection is available.</text>}</box>;
}

export function App({ snapshot, renderer, keymap }: Props) {
  const { width } = useTerminalDimensions();
  const [screen, setScreen] = useState<Screen>("Today");
  const [section, setSection] = useState<Section>("Overview");
  const [caseId, setCaseId] = useState<string>();
  const [query, setQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const narrow = width < 90;
  const compact = width < 60;

  useKeyboard((key) => {
    if ((key.name === "return" || key.name === "enter") && screen === "Cases") {
      const first = snapshot.cases.find((item) => item.scope.tenantId === snapshot.tenantId && `${item.caseId} ${item.clientLabel} ${item.targetLabel}`.toLowerCase().includes(query.toLowerCase()));
      if (first) { recordTuiAttestation({ event: "case_opened", screen: "Cases" }); setCaseId(first.caseId); setScreen("Case"); }
    }
  });

  useEffect(() => recordTuiAttestation({ event: "screen_rendered", screen, section }), [screen, section]);
  useEffect(() => keymap.registerLayer({
    commands: [
      { name: "quit", run: () => { recordTuiAttestation({ event: "quit", screen, section }); renderer.destroy(); } },
      { name: "today", run: () => { recordTuiAttestation({ event: "navigate", screen: "Today" }); setScreen("Today"); } },
      { name: "cases", run: () => { recordTuiAttestation({ event: "navigate", screen: "Cases" }); setScreen("Cases"); } },
      { name: "graph", run: () => { recordTuiAttestation({ event: "navigate", screen: "Graph" }); setScreen("Graph"); } },
      { name: "activity", run: () => { recordTuiAttestation({ event: "navigate", screen: "Activity" }); setScreen("Activity"); } },
      { name: "runners", run: () => { recordTuiAttestation({ event: "navigate", screen: "Runners" }); setScreen("Runners"); } },
      { name: "signals", run: () => { recordTuiAttestation({ event: "navigate", screen: "Signals" }); setScreen("Signals"); } },
      { name: "hunts", run: () => { recordTuiAttestation({ event: "navigate", screen: "Hunts" }); setScreen("Hunts"); } },
      { name: "incidents", run: () => { recordTuiAttestation({ event: "navigate", screen: "Incidents" }); setScreen("Incidents"); } },
      { name: "response-proposals", run: () => { recordTuiAttestation({ event: "navigate", screen: "Response Proposals" }); setScreen("Response Proposals"); } },
      { name: "search", run: () => { recordTuiAttestation({ event: "search_opened" }); setSearchOpen((value) => !value); } },
      { name: "findings", run: () => { recordTuiAttestation({ event: "section", screen: "Case", section: "Findings" }); setScreen("Case"); setSection("Findings"); } },
      { name: "evidence", run: () => { recordTuiAttestation({ event: "section", screen: "Case", section: "Evidence" }); setScreen("Case"); setSection("Evidence"); } },
      { name: "patrol", run: () => { recordTuiAttestation({ event: "section", screen: "Case", section: "Overview" }); setScreen("Case"); setSection("Overview"); } },
      { name: "back", run: () => { recordTuiAttestation({ event: "navigate", screen: "Today" }); setScreen("Today"); } },
    ],
    bindings: [{ key: "q", cmd: "quit" }, { key: "t", cmd: "today" }, { key: "c", cmd: "cases" }, { key: "g", cmd: "graph" }, { key: "a", cmd: "activity" }, { key: "r", cmd: "runners" }, { key: "s", cmd: "signals" }, { key: "h", cmd: "hunts" }, { key: "i", cmd: "incidents" }, { key: "o", cmd: "response-proposals" }, { key: "/", cmd: "search" }, { key: "f", cmd: "findings" }, { key: "e", cmd: "evidence" }, { key: "p", cmd: "patrol" }, { key: "escape", cmd: "back" }],
  }), [keymap, renderer]);

  const content = useMemo(() => {
    if (screen === "Today") return <Today snapshot={snapshot} onOpenCase={(id) => { setCaseId(id); setScreen("Case"); }} />;
    if (screen === "Cases") return <Cases snapshot={snapshot} query={query} onOpenCase={(id) => { setCaseId(id); setScreen("Case"); }} />;
    if (screen === "Case") return <CaseView snapshot={snapshot} caseId={caseId} section={section} />;
    if (screen === "Graph") return <Graph snapshot={snapshot} />;
    if (screen === "Activity") return <ActivityList entries={sortActivityEntries(snapshot.activity.filter((entry) => entry.scope.tenantId === snapshot.tenantId))} />;
    if (screen === "Runners") return <Runners snapshot={snapshot} />;
    if (screen === "Signals") return <Signals snapshot={snapshot} />;
    if (screen === "Hunts") return <Hunts snapshot={snapshot} />;
    if (screen === "Incidents") return <Incidents snapshot={snapshot} />;
    return <ResponseProposals snapshot={snapshot} />;
  }, [caseId, query, screen, section, snapshot]);

  return <box flexDirection="column" padding={1} gap={1} width="100%" height="100%"><Header snapshot={snapshot} compact={compact} /><Nav screen={screen} compact={compact} />{searchOpen ? <input focused value={query} placeholder="filter case, client, target" onInput={setQuery} /> : null}{snapshot.connectionState === "DEGRADED" ? <text fg="#f4c97d">DEGRADED · reconnecting with the last canonical projection</text> : null}<box flexDirection={narrow ? "column" : "row"} gap={1} flexGrow={1}><box flexGrow={1}>{content}</box>{!narrow ? <box width={28} border borderColor="#444e5d" padding={1}><text><strong>Operator context</strong>{"\n"}<span fg="#8e9aaf">scope: {safeDisplay(snapshot.tenantId)}{"\n"}source: {safeDisplay(snapshot.sourceLabel)}{"\n"}focus: {safeDisplay(screen)}{"\n"}actions: inspection-only{"\n"}q quit · Esc back</span></text></box> : null}</box></box>;
}
