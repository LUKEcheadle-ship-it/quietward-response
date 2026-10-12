"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { ErrorState, LoadingState } from "@/components/States";
import { SeverityBadge } from "@/components/SeverityBadge";
import { apiFetch, formatRelative } from "@/lib/api";
import type { Overview } from "@/lib/types";
import { BridgeStatus } from "@/components/BridgeStatus";

export default function OverviewPage() {
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<Overview>("/api/v1/overview").then(setData).catch((value: Error) => setError(value.message));
  }, []);

  return (
    <div className="space-y-8">
      <section className="flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
        <div>
          <p className="eyebrow">Response overview</p>
          <h1 className="page-title">Investigate what changed. Control what happens next.</h1>
          <p className="muted mt-3 max-w-3xl">Deterministic correlation turns validated sensor events into explainable incidents, evidence timelines, and approval-gated response actions.</p>
        </div>
        <div className="rounded-lg border border-cyan/20 bg-cyan/5 px-4 py-3 text-xs text-cyan">
          v1 · controlled response · human approval required
        </div>
      </section>

      {error && <ErrorState message={error} />}
      <BridgeStatus />
      {!data && !error && <LoadingState />}
      {data && (
        <>
          <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
            {[
              ["Active incidents", data.active_incidents, "text-white"],
              ["Critical", data.critical_incidents, "text-rose-300"],
              ["High", data.high_incidents, "text-orange-300"],
              ["Known hosts", data.hosts_reporting, "text-cyan"],
              ["Events · 24h", data.events_last_24h, "text-emerald-300"]
            ].map(([label, value, color]) => (
              <div key={String(label)} className="panel">
                <p className="text-xs uppercase tracking-wider text-slate-500">{label}</p>
                <p className={`mt-3 text-3xl font-semibold ${color}`}>{value}</p>
              </div>
            ))}
          </section>

          <section className="grid gap-6 xl:grid-cols-[1.6fr_1fr]">
            <div>
              <div className="mb-4 flex items-end justify-between">
                <div><p className="eyebrow">New signal</p><h2 className="mt-1 text-xl font-semibold">Recently created incidents</h2></div>
                <Link href="/incidents" className="text-sm text-cyan hover:text-white">View all →</Link>
              </div>
              <div className="space-y-3">
                {data.recent_incidents.length === 0 && (
                  <div className="panel">
                    <p className="font-medium text-white">No incidents yet</p>
                    <p className="muted mt-2 text-sm">
                      An incident groups validated security events into an explainable investigation with evidence, timeline context, and approval-gated response recommendations.
                    </p>
                    <p className="mt-4 text-sm text-slate-300">Try the safe synthetic demo from the repository root:</p>
                    <code className="mt-2 block overflow-x-auto rounded-md border border-line bg-slate-950 px-3 py-2 text-xs text-cyan">
                      python scripts/quick_demo.py
                    </code>
                    <div className="mt-4 flex flex-wrap gap-4 text-sm">
                      <a href="http://localhost:8002/docs" target="_blank" rel="noreferrer" className="text-cyan hover:text-white">Open API docs ↗</a>
                      <Link href="/events" className="text-cyan hover:text-white">View validated events →</Link>
                    </div>
                    <p className="muted mt-4 text-xs">
                      Standalone Response accepts authenticated security events directly. Paired mode can also ingest sanitized, verified findings from QuietWard while keeping detection authority and response authority separate.
                    </p>
                  </div>
                )}
                {data.recent_incidents.map((incident) => (
                  <Link key={incident.incident_id} href={`/incidents/${incident.incident_id}`} className="panel block transition hover:border-cyan/40 hover:bg-slate-900">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div><SeverityBadge severity={incident.severity} /><h3 className="mt-3 font-medium text-white">{incident.title}</h3></div>
                      <span className="text-xs text-slate-500">{formatRelative(incident.created_at)}</span>
                    </div>
                    <div className="mt-4 flex flex-wrap gap-x-6 gap-y-2 text-xs text-slate-400">
                      <span>{incident.affected_hosts.join(", ")}</span><span>{incident.event_count} events</span><span>{Math.round(incident.confidence * 100)}% confidence</span><span className="capitalize">{incident.status}</span>
                    </div>
                  </Link>
                ))}
              </div>
            </div>
            <aside className="panel h-fit">
              <p className="eyebrow">Control boundary</p>
              <h2 className="mt-2 text-lg font-semibold">Human decisions remain authoritative</h2>
              <p className="muted mt-3">The current preview supports typed read-only diagnostics and a dedicated demo-fixture action. Each requires analyst approval, policy checks, and independent validation by the Response endpoint agent. QuietWard remains observation-only.</p>
              <div className="mt-5 space-y-3 text-sm">
                <div className="flex justify-between border-b border-line pb-3"><span className="text-slate-400">Correlation</span><span className="text-emerald-300">Deterministic</span></div>
                <div className="flex justify-between border-b border-line pb-3"><span className="text-slate-400">Audit chain</span><span className="text-emerald-300">Tamper-evident</span></div>
                <div className="flex justify-between border-b border-line pb-3"><span className="text-slate-400">Approval</span><span className="text-emerald-300">Required</span></div>
                <div className="flex justify-between"><span className="text-slate-400">Executable scope</span><span className="text-amber-200">Diagnostics + demo fixture</span></div>
              </div>
            </aside>
          </section>
        </>
      )}
    </div>
  );
}
