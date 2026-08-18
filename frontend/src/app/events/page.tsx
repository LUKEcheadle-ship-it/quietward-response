import Link from "next/link";
import { EmptyState, PageHeader, SeverityBadge } from "@/components/ui";
import { getEvents } from "@/lib/api";
import { shortId, time } from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function EventsPage() {
  const events = await getEvents().catch(() => []);
  return <><PageHeader eyebrow="Normalized telemetry" title="Events" description="Validated source evidence with links to its correlated investigation."/><section className="panel flush">{!events.length ? <EmptyState label="events"/> : <div className="table-wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Summary</th><th>Host</th><th>Type</th><th>Source</th><th>Incident</th></tr></thead><tbody>{events.map(event => <tr key={event.event_id}><td>{time(event.timestamp)}</td><td><SeverityBadge value={event.severity}/></td><td className="title-cell"><strong>{event.summary}</strong><code>{shortId(event.event_id)}</code></td><td>{event.host_name || event.host_id}</td><td><code>{event.event_type}</code></td><td>{event.source}</td><td>{event.incident_id ? <Link className="text-link" href={`/incidents/${event.incident_id}`}>{shortId(event.incident_id)}</Link> : "—"}</td></tr>)}</tbody></table></div>}</section></>;
}
