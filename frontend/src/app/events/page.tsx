"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { EmptyState, ErrorState, LoadingState } from "@/components/States";
import { SeverityBadge } from "@/components/SeverityBadge";
import { apiFetch, formatTime } from "@/lib/api";
import type { EventRecord } from "@/lib/types";

export default function EventsPage() {
  const [events, setEvents] = useState<EventRecord[] | null>(null); const [error, setError] = useState<string | null>(null);
  useEffect(() => { apiFetch<EventRecord[]>("/api/v1/events?limit=500").then(setEvents).catch((value: Error) => setError(value.message)); }, []);
  return <div className="space-y-6"><div><p className="eyebrow">Normalized evidence</p><h1 className="page-title">Events</h1><p className="muted mt-3">Validated source observations in reverse chronological order. Use the API filters for host, severity, type, time range, or incident.</p></div>
    {error && <ErrorState message={error} />}{!events && !error && <LoadingState />}{events?.length === 0 && <EmptyState message="No events have been accepted." />}
    {events && events.length > 0 && <div className="table-wrap"><table className="data-table"><thead><tr><th>Time</th><th>Severity</th><th>Event</th><th>Host</th><th>Source</th><th>Incident</th></tr></thead><tbody>{events.map((event) => <tr key={event.event_id}>
      <td className="whitespace-nowrap">{formatTime(event.timestamp)}</td><td><SeverityBadge severity={event.severity} /></td><td><p className="font-medium text-white">{event.summary}</p><p className="mt-1 font-mono text-xs text-slate-500">{event.event_type}</p></td><td>{event.host_name}<div className="text-xs text-slate-500">{event.host_id}</div></td><td>{event.source}<div className="text-xs text-slate-500">{event.source_version}</div></td><td>{event.incident_id ? <Link className="text-cyan hover:text-white" href={`/incidents/${event.incident_id}`}>Open incident</Link> : "—"}</td>
    </tr>)}</tbody></table></div>}
  </div>;
}
