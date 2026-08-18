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
  useEffect(() => { apiFetch<Incident[]>("/api/v1/incidents").then(setIncidents).catch((value: Error) => setError(value.message)); }, []);

  return <div className="space-y-6">
    <div><p className="eyebrow">Investigation queue</p><h1 className="page-title">Incidents</h1><p className="muted mt-3">Events grouped by host, time, and shared technical indicators. Every grouping reason remains visible.</p></div>
    {error && <ErrorState message={error} />}{!incidents && !error && <LoadingState />}
    {incidents?.length === 0 && <EmptyState message="No incidents have been created." />}
    {incidents && incidents.length > 0 && <div className="table-wrap"><table className="data-table"><thead><tr><th>Severity</th><th>Incident</th><th>Host</th><th>Confidence</th><th>Events</th><th>First seen</th><th>Last seen</th><th>Status</th></tr></thead><tbody>
      {incidents.map((incident) => <tr key={incident.incident_id}>
        <td><SeverityBadge severity={incident.severity} /></td>
        <td><Link className="font-medium text-white hover:text-cyan" href={`/incidents/${incident.incident_id}`}>{incident.title}</Link><div className="mt-1 font-mono text-[10px] text-slate-600">{incident.incident_id}</div></td>
        <td>{incident.affected_hosts.join(", ")}</td><td>{Math.round(incident.confidence * 100)}%</td><td>{incident.event_count}</td><td className="whitespace-nowrap">{formatTime(incident.first_event_at)}</td><td className="whitespace-nowrap">{formatTime(incident.last_event_at)}</td><td><span className="capitalize">{incident.status}</span></td>
      </tr>)}
    </tbody></table></div>}
  </div>;
}
