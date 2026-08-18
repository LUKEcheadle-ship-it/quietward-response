"use client";

import { useEffect, useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { apiFetch, formatTime } from "@/lib/api";
import type { Host } from "@/lib/types";

export default function HostsPage() {
  const [hosts, setHosts] = useState<Host[] | null>(null); const [error, setError] = useState<string | null>(null);
  useEffect(() => { apiFetch<Host[]>("/api/v1/hosts").then(setHosts).catch((value: Error) => setError(value.message)); }, []);
  return <div className="space-y-6"><div><p className="eyebrow">Sensor inventory</p><h1 className="page-title">Hosts</h1><p className="muted mt-3">Reporting identity, source version, activity, and incident coverage without embedding endpoint control.</p></div>
    {error && <ErrorState message={error} />}{!hosts && !error && <LoadingState />}{hosts?.length === 0 && <EmptyState message="No hosts have reported events." />}
    {hosts && hosts.length > 0 && <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{hosts.map((host) => <article className="panel" key={host.host_id}>
      <div className="flex items-start justify-between gap-3"><div><p className="font-semibold text-white">{host.hostname}</p><p className="mt-1 font-mono text-xs text-slate-500">{host.host_id}</p></div><span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-[11px] uppercase text-emerald-300">{host.status}</span></div>
      <dl className="mt-5 grid grid-cols-2 gap-4 text-sm"><div><dt className="text-xs text-slate-500">Operating system</dt><dd className="mt-1">{host.operating_system || "Unknown"}</dd></div><div><dt className="text-xs text-slate-500">Agent</dt><dd className="mt-1">{host.agent} {host.agent_version}</dd></div><div><dt className="text-xs text-slate-500">Events</dt><dd className="mt-1 text-xl font-semibold">{host.event_count}</dd></div><div><dt className="text-xs text-slate-500">Incidents</dt><dd className="mt-1 text-xl font-semibold">{host.incident_count}</dd></div></dl>
      <p className="mt-5 border-t border-line pt-4 text-xs text-slate-500">Last seen {formatTime(host.last_seen)}</p>
    </article>)}</div>}
  </div>;
}
