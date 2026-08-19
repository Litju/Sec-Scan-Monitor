"use client";

import { motion } from "motion/react";
import { AlertTriangle, ArrowUpRight, CheckCircle2, Clock3, FileCheck2, ShieldAlert } from "lucide-react";
import type { SurfaceKey } from "@/lib/domain/navigation";
import { buildAttentionItems } from "@/lib/domain/attention";
import type { PreviewData } from "@/lib/domain/types";

type Props = {
  data: PreviewData;
  onNavigate: (surface: SurfaceKey, id?: string) => void;
};

const icons = {
  danger: ShieldAlert,
  warning: AlertTriangle,
  info: FileCheck2,
} as const;

function formatDate(value: string) {
  return value.slice(0, 16).replace("T", " ");
}

export function Today({ data, onNavigate }: Props) {
  const attention = buildAttentionItems(data);
  const running = data.runs.filter((run) => run.status === "running");
  const completed = data.runs.filter((run) => run.status === "completed");
  return (
    <div className="stack today-surface">
      <header className="today-heading">
        <div>
          <p className="eyebrow">Operator home</p>
          <h1 className="page-title">Today</h1>
          <p className="page-description">Three clear next steps, then the work that is moving.</p>
        </div>
      </header>

      <div className="today-layout">
        <main className="today-main">
          <section aria-labelledby="attention-title">
            <div className="section-heading">
              <div>
                <p className="eyebrow">Needs You</p>
                <h2 className="section-title" id="attention-title">{attention.length} things need your attention</h2>
                <p className="section-description">Each row names the state, the reason, and the next safe action.</p>
              </div>
              <span className="status warning">read-only</span>
            </div>
            <div className="attention-list">
              {attention.map((item, index) => {
                const Icon = icons[item.tone];
                return (
                  <motion.article
                    className={`task-row task-row-${item.tone}`}
                    key={item.id}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.18, delay: index * 0.035 }}
                  >
                    <div className="task-row-icon" aria-hidden="true"><Icon size={18} /></div>
                    <div className="task-row-main">
                      <div className="task-row-kicker"><span>{item.title}</span><span className="mono">{item.detail}</span></div>
                      <h3>{item.subject}</h3>
                      <p>{item.reason}</p>
                      <div className="task-row-next"><strong>Next</strong> {item.nextAction}</div>
                    </div>
                    <button className="task-row-action" type="button" onClick={() => onNavigate(item.surface, item.entityId)}>
                      {item.actionLabel} <ArrowUpRight size={15} aria-hidden="true" />
                    </button>
                  </motion.article>
                );
              })}
            </div>
          </section>

        </main>

        <aside className="today-side" aria-label="Activity summary">
          <section className="surface-panel side-section" aria-labelledby="running-title">
            <div className="section-heading compact"><div><p className="eyebrow">In motion</p><h2 className="panel-title" id="running-title">Running</h2></div><Clock3 size={18} aria-hidden="true" /></div>
            {running.length ? running.map((run) => <button className="mini-task" type="button" key={run.agentRunId} onClick={() => onNavigate("runs")}><span className="mini-task-dot running" aria-hidden="true" /><span><strong>{run.agentRole}</strong><small>{run.agentRunId} · {run.capabilityIds[0] ?? "bounded activity"}</small></span><ArrowUpRight size={14} aria-hidden="true" /></button>) : <p className="small muted">Nothing is running.</p>}
          </section>
          <section className="surface-panel side-section" aria-labelledby="recent-title">
            <div className="section-heading compact"><div><p className="eyebrow">Latest record</p><h2 className="panel-title" id="recent-title">Recently completed</h2></div><CheckCircle2 size={18} aria-hidden="true" /></div>
            {completed.length ? completed.map((run) => <button className="mini-task" type="button" key={run.agentRunId} onClick={() => onNavigate("runs")}><span className="mini-task-dot complete" aria-hidden="true" /><span><strong>{run.agentRole}</strong><small>{run.agentRunId} · {formatDate(run.finishedAt ?? run.startedAt)}</small></span><ArrowUpRight size={14} aria-hidden="true" /></button>) : <p className="small muted">No completed activity in this view.</p>}
          </section>
        </aside>
      </div>
    </div>
  );
}

export const CommandCenter = Today;
