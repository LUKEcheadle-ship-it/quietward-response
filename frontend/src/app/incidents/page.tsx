"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { SeverityBadge } from "@/components/SeverityBadge";
import { apiFetch, formatTime } from "@/lib/api";
import type { Incident } from "@/lib/types";

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [host, setHost] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [filters, setFilters] = useState("");
  useEffect(() => {
    const controller = new AbortController(); setIncidents(null); setError(null);
    const query = new URLSearchParams(filters);
    if (cursor) query.set("cursor", cursor);
    apiFetch<{items: Incident[]; total: number; next_cursor: string | null}>(`/api/v1/incidents/page?${query}`, {signal: controller.signal})
      .then(data => { setIncidents(data.items); setTotal(data.total); setNextCursor(data.next_cursor); })
      .catch((value: Error) => { if (value.name !== "AbortError") setError(value.message); });
    return () => controller.abort();
  }, [filters, cursor, refresh]);

  return <div className="space-y-6">
    <div><p className="eyebrow">Investigation queue</p><h1 className="page-title">Incidents</h1><p className="muted mt-3">Events grouped by host, time, and shared technical indicators. Every grouping reason remains visible.</p></div>
    <form className="panel flex flex-wrap items-end gap-3" onSubmit={event => {
      event.preventDefault(); const query = new URLSearchParams();
      if (search.trim()) query.set("search", search.trim()); if (host.trim()) query.set("host", host.trim());
      if (severity) query.set("severity", severity); if (status) query.set("status", status);
      setCursor(null); setFilters(query.toString()); setRefresh(value => value+1);
    }}>
      <label className="text-sm">Title or incident ID<input className="mt-1 block rounded bg-slate-950 p-2" maxLength={120} value={search} onChange={e=>setSearch(e.target.value)} /></label>
      <label className="text-sm">Host ID<input className="mt-1 block rounded bg-slate-950 p-2" maxLength={128} value={host} onChange={e=>setHost(e.target.value)} /></label>
      <label className="text-sm">Severity<select className="mt-1 block rounded bg-slate-950 p-2" value={severity} onChange={e=>setSeverity(e.target.value)}><option value="">All</option>{["critical","high","medium","low","info"].map(value=><option key={value}>{value}</option>)}</select></label>
      <label className="text-sm">Status<select className="mt-1 block rounded bg-slate-950 p-2" value={status} onChange={e=>setStatus(e.target.value)}><option value="">All</option>{["new","investigating","contained","resolved","dismissed"].map(value=><option key={value}>{value}</option>)}</select></label>
      <button className="rounded bg-cyan px-4 py-2 text-slate-950">Apply filters</button>
      <button type="button" className="px-3 py-2 text-cyan" onClick={()=>{setCursor(null);setRefresh(value=>value+1);}}>Refresh from newest</button>
    </form>
    {incidents && <p className="text-sm text-slate-400">{total} matching incidents · {incidents.length} on this page</p>}
    {error && <ErrorState message={error} />}{!incidents && !error && <LoadingState />}
    {incidents?.length === 0 && <EmptyState message="No incidents have been created." />}
    {incidents && incidents.length > 0 && <div className="table-wrap"><table className="data-table"><thead><tr><th>Severity</th><th>Incident</th><th>Host</th><th>Confidence</th><th>Events</th><th>First seen</th><th>Last seen</th><th>Status</th></tr></thead><tbody>
      {incidents.map((incident) => <tr key={incident.incident_id}>
        <td><SeverityBadge severity={incident.severity} /></td>
        <td><Link className="font-medium text-white hover:text-cyan" href={`/incidents/${incident.incident_id}`}>{incident.title}</Link><div className="mt-1 font-mono text-[10px] text-slate-600">{incident.incident_id}</div></td>
        <td>{incident.affected_hosts.join(", ")}</td><td>{Math.round(incident.confidence * 100)}%</td><td>{incident.event_count}</td><td className="whitespace-nowrap">{formatTime(incident.first_event_at)}</td><td className="whitespace-nowrap">{formatTime(incident.last_event_at)}</td><td><span className="capitalize">{incident.status}</span></td>
      </tr>)}
    </tbody></table></div>}
    {incidents && <div className="flex gap-4"><button disabled={!cursor} className="text-cyan disabled:opacity-40" onClick={()=>setCursor(null)}>Newest page</button><button disabled={!nextCursor} className="text-cyan disabled:opacity-40" onClick={()=>setCursor(nextCursor)}>Older incidents →</button></div>}
  </div>;
}
