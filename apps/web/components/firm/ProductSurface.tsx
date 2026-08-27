"use client";

import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { Dialog } from "@base-ui/react/dialog";
import { useQuery } from "@tanstack/react-query";
import { Command } from "cmdk";
import { ArrowUpRight, BriefcaseBusiness, Command as CommandIcon, FileText, Home, Search, Settings, Sparkles, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Conversation, ConversationContent } from "@/components/ai-elements/conversation";
import { Message, MessageContent, MessageResponse } from "@/components/ai-elements/message";
import { PromptInput, PromptInputBody, PromptInputFooter, PromptInputSubmit, PromptInputTextarea, type PromptInputMessage } from "@/components/ai-elements/prompt-input";
import { Source, Sources, SourcesContent, SourcesTrigger } from "@/components/ai-elements/sources";
import { Tool, ToolContent, ToolHeader, ToolInput, ToolOutput } from "@/components/ai-elements/tool";
import { createApiClient, loadHostedData, resolveApiMode } from "@/lib/api/client";
import { getRouteDefinition, isSurfaceKey, normalizeSurface, pathForSurface, primaryRoutes, settingsRoutes, surfaceRoutes, type SurfaceKey } from "@/lib/domain/navigation";
import { previewData } from "@/lib/domain/preview-data";
import type { DataMode } from "@/lib/domain/types";
import { SurfaceView } from "@/components/firm/SurfaceView";

type DisplayMode = DataMode | "CONFIG_ERROR";

type Props = {
  initialSurface: SurfaceKey;
  initialId?: string;
};

type PaletteEntry = {
  id: string;
  title: string;
  detail: string;
  type: string;
  surface: SurfaceKey;
  entityId?: string;
};

const flowBySurface: Partial<Record<SurfaceKey, { a: string; b: string; c: string }>> = {
  today: { a: "var(--prussian)", b: "var(--verdigris)", c: "var(--celadon)" },
  cases: { a: "var(--verdigris)", b: "var(--celadon)", c: "var(--prussian)" },
  clients: { a: "var(--celadon)", b: "var(--prussian)", c: "var(--deep-prussian)" },
  reports: { a: "var(--quartz)", b: "var(--lapis)", c: "var(--deep-lapis)" },
  settings: { a: "var(--quartz)", b: "var(--orpiment)", c: "var(--deep-orpiment)" },
  findings: { a: "var(--orpiment)", b: "var(--cinnabar)", c: "var(--deep-cinnabar)" },
  evidence: { a: "var(--verdigris)", b: "var(--lapis)", c: "var(--deep-lapis)" },
  runs: { a: "var(--tyrian)", b: "var(--prussian)", c: "var(--deep-prussian)" },
  capabilities: { a: "var(--prussian)", b: "var(--quartz)", c: "var(--deep-prussian)" },
  approvals: { a: "var(--orpiment)", b: "var(--cinnabar)", c: "var(--deep-cinnabar)" },
  runtime: { a: "var(--tyrian)", b: "var(--prussian)", c: "var(--deep-prussian)" },
  assistant: { a: "var(--tyrian)", b: "var(--prussian)", c: "var(--deep-prussian)" },
};

const iconBySurface: Partial<Record<SurfaceKey, typeof Home>> = {
  today: Home,
  cases: BriefcaseBusiness,
  clients: Users,
  reports: FileText,
  settings: Settings,
  assistant: Sparkles,
};

function readMode(): DisplayMode {
  try {
    return resolveApiMode();
  } catch {
    return "CONFIG_ERROR";
  }
}

function parseLocation(): { surface: SurfaceKey; id?: string } {
  const parts = window.location.pathname.split("/").filter(Boolean).map(decodeURIComponent);
  if (!parts[0]) return { surface: "today" };
  const candidate = parts[0];
  if (!isSurfaceKey(candidate)) return { surface: "today" };
  return { surface: normalizeSurface(candidate), id: parts[1] };
}

function FirmRail({ surface, onNavigate }: { surface: SurfaceKey; onNavigate: (surface: SurfaceKey) => void }) {
  return (
    <aside className="firm-rail" aria-label="SecScanMonitor primary navigation">
      <div className="rail-brand"><span className="brand-mark" aria-hidden="true">S/</span><div className="brand-copy"><div className="brand-name">SecScanMonitor</div><div className="brand-caption">firm control plane</div></div></div>
      <nav className="rail-nav">
        <p className="rail-label">Workspace</p>
        {primaryRoutes.map((route) => {
          const Icon = iconBySurface[route.key] ?? Home;
          return <a aria-label={route.label} className={`route-link ${surface === route.key ? "active" : ""}`} href={pathForSurface(route.key)} key={route.key} onClick={(event) => { event.preventDefault(); onNavigate(route.key); }}><Icon size={17} strokeWidth={1.8} aria-hidden="true" /><span>{route.label}</span></a>;
        })}
        <p className="rail-label rail-label-settings">Admin</p>
        {settingsRoutes.map((route) => <a aria-label={route.label} className={`route-link ${surface === route.key ? "active" : ""}`} href={pathForSurface(route.key)} key={route.key} onClick={(event) => { event.preventDefault(); onNavigate(route.key); }}><Settings size={17} strokeWidth={1.8} aria-hidden="true" /><span>{route.label}</span></a>)}
      </nav>
    </aside>
  );
}

function CommandBar({ route, mode, health, onOpenPalette }: { route: ReturnType<typeof getRouteDefinition>; mode: DisplayMode; health: string; onOpenPalette: () => void }) {
  const isPreview = mode === "PREVIEW";
  return <header className="command-bar"><div className="context-block"><div className="context-eyebrow">{route.eyebrow}</div><div className="context-title">{route.label} <span className="muted">· {isPreview ? "PREVIEW" : mode.replaceAll("_", " ")}</span></div></div><div className="command-actions"><Button className="search-trigger" type="button" onClick={onOpenPalette} aria-label="Open search and ask" variant="outline" size="lg"><Search size={15} aria-hidden="true" /><span>Search / Ask</span><span className="shortcut">⌘ K</span></Button><div className="live-status" aria-label="Live data status" aria-live="polite"><span className={`pip ${health === "API unavailable" ? "offline" : health === "not validated" ? "degraded" : ""}`} aria-hidden="true" /><span>{isPreview ? "Preview · read-only" : health}</span></div></div></header>;
}

function CommandPalette({ open, entries, onClose, onSelect, onAsk }: { open: boolean; entries: PaletteEntry[]; onClose: () => void; onSelect: (entry: PaletteEntry) => void; onAsk: () => void }) {
  return <Command.Dialog open={open} onOpenChange={(next) => { if (!next) onClose(); }} label="Search and ask"><div className="command-dialog-shell"><div className="command-dialog-header"><CommandIcon size={16} aria-hidden="true" /><span>Search and ask</span><kbd>ESC</kbd></div><Command.Input placeholder="Go to, search, or ask…" aria-label="Search firm records" /><Command.List><Command.Empty>No safe records match this query.</Command.Empty><Command.Group heading="Go to"><Command.Item value="Ask SecScanMonitor" onSelect={onAsk}><Sparkles size={15} aria-hidden="true" /><span><strong>Ask SecScanMonitor</strong><small>Grounded answers from the visible context</small></span></Command.Item>{entries.filter((entry) => entry.type === "route").map((entry) => { const Icon = iconBySurface[entry.surface] ?? ArrowUpRight; return <Command.Item value={`${entry.title} ${entry.detail}`} key={entry.id} onSelect={() => onSelect(entry)}><Icon size={15} aria-hidden="true" /><span><strong>{entry.title}</strong><small>{entry.detail}</small></span><em>{entry.surface === "settings" ? "admin" : "go"}</em></Command.Item>; })}</Command.Group><Command.Group heading="Search"><div className="command-results-divider" />{entries.filter((entry) => entry.type !== "route").map((entry) => <Command.Item value={`${entry.title} ${entry.detail}`} key={entry.id} onSelect={() => onSelect(entry)}><Search size={15} aria-hidden="true" /><span><strong>{entry.title}</strong><small>{entry.detail}</small></span><em>{entry.type}</em></Command.Item>)}</Command.Group></Command.List></div></Command.Dialog>;
}

function AssistantDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [asked, setAsked] = useState(false);
  function submit(message: PromptInputMessage) {
    if (message.text.trim()) setAsked(true);
  }
  return <Dialog.Root open={open} onOpenChange={(next) => { if (!next) onClose(); }}><Dialog.Portal><Dialog.Backdrop className="base-ui-backdrop" /><Dialog.Popup className="assistant-drawer"><div className="drawer-header"><div><p className="eyebrow">Context lens · grounded only</p><Dialog.Title className="panel-title" id="assistant-title">Ask SecScanMonitor</Dialog.Title><Dialog.Description className="panel-description">AI Elements surface · preview response · read-only.</Dialog.Description></div><Dialog.Close className="icon-button" aria-label="Close grounded assistant">×</Dialog.Close></div><div className="ai-assistant-body"><div className="grounding-box"><strong>PREVIEW RESPONSE · NOT CONNECTED</strong><p className="small muted" style={{ margin: "6px 0 0" }}>The answer below is a bounded qualification fixture. It cannot approve, mutate, change findings, or invent unsupported interpretation.</p></div><Conversation className="ai-conversation"><ConversationContent>{asked ? <><Message from="user" className="ai-message-user"><MessageContent><p>Why is this inconclusive?</p></MessageContent></Message><Message from="assistant" className="ai-message-assistant"><MessageContent><MessageResponse>This remains inconclusive because the evidence link is missing. The smallest resolving request is permitted metadata; no unsupported conclusion is inferred.</MessageResponse></MessageContent><Sources className="ai-sources"><SourcesTrigger count={4} /><SourcesContent><Source href="/evidence/E-1181" target="_self" title="E-1181 · sanitized metadata" /><Source href="/findings/FND-PREV-015" target="_self" title="FND-PREV-015 · adjudicated finding" /><Source href="/findings/FND-PREV-015" target="_self" title="RPT-015 · report record" /><Source href="/audit" target="_self" title="AUD-015-17 · audit record" /></SourcesContent></Sources><Tool defaultOpen className="ai-tool"><ToolHeader type="dynamic-tool" toolName="CAP-EVIDENCE-METADATA-READ" state="output-available" title="Read permitted metadata" /><ToolContent><ToolInput input={{ evidence: ["E-1181", "FND-PREV-015", "RPT-015", "AUD-015-17"], access: "metadata-only" }} /><ToolOutput output="Sanitized metadata only; raw evidence remains outside browser state." errorText={undefined} /></ToolContent></Tool></Message></> : <div className="ai-empty"><Sparkles size={18} aria-hidden="true" /><p>Ask a bounded question about the visible evidence chain.</p></div>}</ConversationContent></Conversation><PromptInput onSubmit={submit} className="ai-prompt"><PromptInputBody><PromptInputTextarea placeholder="Ask from the visible evidence chain…" aria-label="Ask grounded assistant" /></PromptInputBody><PromptInputFooter><span className="ai-prompt-note">No hidden reasoning · no mutation</span><PromptInputSubmit aria-label="Submit grounded question" /></PromptInputFooter></PromptInput></div></Dialog.Popup></Dialog.Portal></Dialog.Root>;
}

export function ProductSurface({ initialSurface, initialId }: Props) {
  const normalizedInitial = normalizeSurface(initialSurface);
  const [surface, setSurface] = useState<SurfaceKey>(normalizedInitial);
  const [selectedId, setSelectedId] = useState(initialId);
  const [mode] = useState<DisplayMode>(readMode);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [assistantOpen, setAssistantOpen] = useState(normalizedInitial === "assistant");
  const route = getRouteDefinition(surface);
  const flow = flowBySurface[surface] ?? flowBySurface.today!;
  const integratedDataQuery = useQuery({
    queryKey: ["secscan-integrated-data", mode],
    queryFn: () => loadHostedData(mode as DataMode),
    enabled: mode === "HOSTED_INTEGRATED" || mode === "LOCAL_INTEGRATED",
    refetchInterval: 5_000,
    retry: 1,
  });
  const data = mode === "PREVIEW" ? previewData : mode === "CONFIG_ERROR" ? null : integratedDataQuery.data ?? null;
  const flowStyle = { "--flow-a": flow.a, "--flow-b": flow.b, "--flow-c": flow.c } as CSSProperties;
  const healthQuery = useQuery({
    queryKey: ["secscan-health", mode],
    queryFn: () => createApiClient(mode as DataMode).health(),
    enabled: mode !== "PREVIEW" && mode !== "CONFIG_ERROR",
    refetchInterval: 15_000,
    retry: 1,
  });
  const health = mode === "PREVIEW" ? "preview data" : mode === "CONFIG_ERROR" ? "not validated" : healthQuery.isPending ? "checking API" : healthQuery.isError ? "API unavailable" : healthQuery.data?.status === "ok" ? "API healthy" : "API error";

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setPaletteOpen((current) => !current); }
      if (event.key === "Escape") { setPaletteOpen(false); setAssistantOpen(false); }
    }
    function handlePopState() { const location = parseLocation(); setSurface(location.surface); setSelectedId(location.id); setAssistantOpen(location.surface === "assistant"); }
    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("popstate", handlePopState);
    return () => { window.removeEventListener("keydown", handleKeyDown); window.removeEventListener("popstate", handlePopState); };
  }, []);

  function navigate(nextSurface: SurfaceKey, id?: string) {
    const next = normalizeSurface(nextSurface);
    setSurface(next);
    setSelectedId(id);
    setAssistantOpen(next === "assistant");
    setPaletteOpen(false);
    window.history.pushState({}, "", pathForSurface(next, id));
  }

  const paletteEntries = useMemo<PaletteEntry[]>(() => {
    const routes: PaletteEntry[] = surfaceRoutes.filter((item) => item.group !== "legacy").map((item) => ({ id: `route-${item.key}`, title: item.label, detail: item.description, type: "route", surface: item.key }));
    if (!data) return routes;
    return routes.concat(
      data.engagements.map((item) => ({ id: item.engagementId, title: item.engagementId, detail: `${item.clientName} · ${item.status}`, type: "case", surface: "cases" as const, entityId: item.engagementId })),
      data.clients.map((item) => ({ id: item.clientId, title: item.name, detail: `${item.clientId} · ${item.engagementCount} cases`, type: "client", surface: "clients" as const })),
      data.findings.map((item) => ({ id: item.findingId, title: item.findingId, detail: item.summary, type: "finding", surface: "findings" as const, entityId: item.findingId })),
      data.evidence.map((item) => ({ id: item.evidenceId, title: item.evidenceId, detail: `${item.collector} · ${item.sanitizationState}`, type: "evidence", surface: "evidence" as const, entityId: item.evidenceId })),
      data.reports.map((item) => ({ id: `report-${item.engagementId}`, title: item.title, detail: `${item.engagementId} · ${item.verdict}`, type: "report", surface: "reports" as const })),
      data.approvals.map((item) => ({ id: item.approvalId, title: item.approvalId, detail: `${item.capabilityId} · ${item.decision}`, type: "approval", surface: "approvals" as const, entityId: item.approvalId })),
    );
  }, [data]);

  return <div style={flowStyle}><a className="skip-link" href="#main-content">Skip to main content</a><div className="app-shell"><FirmRail surface={surface} onNavigate={navigate} /><div className="main-stage"><CommandBar route={route} mode={mode} health={health} onOpenPalette={() => setPaletteOpen(true)} /><main className="page-canvas" id="main-content">{mode === "CONFIG_ERROR" ? <div className="status-line error-state" role="alert">Frontend mode configuration is invalid. No preview fallback was activated.</div> : null}{mode !== "PREVIEW" && mode !== "CONFIG_ERROR" && integratedDataQuery.isError ? <div className="status-line error-state" role="alert">Canonical integrated read model is unavailable. No preview fallback was activated.</div> : null}<SurfaceView surface={surface} selectedId={selectedId} data={data} mode={mode} onNavigate={navigate} onOpenAssistant={() => setAssistantOpen(true)} /></main></div></div><CommandPalette open={paletteOpen} entries={paletteEntries} onClose={() => setPaletteOpen(false)} onSelect={(entry) => navigate(entry.surface, entry.entityId)} onAsk={() => { setPaletteOpen(false); setAssistantOpen(true); }} /><AssistantDialog open={assistantOpen} onClose={() => setAssistantOpen(false)} /></div>;
}
