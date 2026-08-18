import { time } from "@/lib/format";
import type { Incident } from "@/lib/types";
import { EmptyState, IncidentLink, SeverityBadge, StatusBadge } from "./ui";

export function IncidentTable({ incidents }: { incidents: Incident[] }) {
  if (!incidents.length) return <EmptyState label="incidents"/>;
  return <div className="table-wrap"><table><thead><tr><th>Severity</th><th>Incident</th><th>Host</th><th>Confidence</th><th>Events</th><th>First seen</th><th>Last seen</th><th>Status</th></tr></thead>
    <tbody>{incidents.map(item => <tr key={item.incident_id}><td><SeverityBadge value={item.severity}/></td><td className="title-cell"><IncidentLink id={item.incident_id}>{item.title}</IncidentLink></td><td>{item.affected_hosts[0] || "—"}</td><td><span className="confidence">{Math.round(item.confidence)}%</span></td><td>{item.event_count}</td><td>{time(item.first_event_at)}</td><td>{time(item.last_event_at)}</td><td><StatusBadge value={item.status}/></td></tr>)}</tbody></table></div>;
}
