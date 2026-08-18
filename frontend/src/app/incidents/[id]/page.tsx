import { notFound } from "next/navigation";
import { Icon } from "@/components/icons";
import { StatusControl } from "@/components/status-control";
import { PageHeader, SeverityBadge } from "@/components/ui";
import { getIncident } from "@/lib/api";
import { shortId, time, timeOnly } from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const incident = await getIncident(id).catch(() => null);
  if (!incident) notFound();
  const diagnostic = incident.recommended_actions.filter(item => item.type === "diagnostic");
  const remediation = incident.recommended_actions.filter(item => item.type === "remediation");
  return <><PageHeader eyebrow={`Incident · ${shortId(incident.incident_id)}`} title={incident.title} description={`First evidence ${time(incident.first_event_at)} · ${incident.event_count} correlated events`}><div className="header-actions"><SeverityBadge value={incident.severity}/><StatusControl incidentId={incident.incident_id} initial={incident.status}/></div></PageHeader>
    <section className="incident-facts"><div><span>Confidence</span><strong>{Math.round(incident.confidence)}%</strong><div className="meter"><i style={{ width: `${incident.confidence}%` }}/></div></div><div><span>Affected hosts</span><strong>{incident.affected_hosts.length}</strong><small>{incident.affected_hosts.join(", ")}</small></div><div><span>Evidence window</span><strong>{timeOnly(incident.first_event_at)} → {timeOnly(incident.last_event_at)}</strong><small>Deterministic 5-minute window</small></div></section>
    <div className="detail-grid"><div className="detail-main">
      <section className="panel"><div className="panel-head"><div><span className="section-label">Sequence</span><h2>Incident timeline</h2></div><span className="count-pill">{incident.timeline.length} events</span></div><div className="timeline">{incident.timeline.map((item, index) => <div className="timeline-item" key={item.event_id}><div className="timeline-time">{timeOnly(item.timestamp)}</div><div className={`timeline-node ${item.severity}`}><i/></div><div><span>{item.event_type}</span><strong>{item.summary}</strong><code>{item.event_id}</code></div>{index < incident.timeline.length - 1 && <div className="timeline-line"/>}</div>)}</div></section>
      <section className="panel"><div className="panel-head"><div><span className="section-label">Evidence</span><h2>Raw event details</h2></div></div><div className="evidence-list">{incident.events.map(event => <details key={event.event_id}><summary><SeverityBadge value={event.severity}/><span><strong>{event.summary}</strong><code>{event.event_type} · {shortId(event.event_id)}</code></span><Icon name="arrow"/></summary><pre>{JSON.stringify(event, null, 2)}</pre></details>)}</div></section>
    </div><aside className="detail-side">
      <section className="panel assessment"><span className="section-label">Assessment</span><h2>Probable cause</h2><p>{incident.probable_cause}</p><h3>Why these events were grouped</h3><ul>{incident.correlation_reasons.map(reason => <li key={reason}><Icon name="check" size={15}/>{reason}</li>)}</ul></section>
      <section className="panel recommendations"><span className="section-label">Recommended actions</span><h2>Investigation plan</h2><h3>Diagnostic actions</h3>{diagnostic.map(item => <div className="action enabled" key={item.title}><span><Icon name="check" size={14}/></span>{item.title}</div>)}<h3>Remediation actions</h3>{remediation.map(item => <div className="action disabled" key={item.title}><span><Icon name="lock" size={14}/></span><div>{item.title}<small>{item.note}</small></div></div>)}</section>
      <section className="panel audit"><span className="section-label">Accountability</span><h2>Audit trail</h2>{incident.audit_trail.map(item => <div key={item.audit_id}><i/><span><strong>{item.action.replaceAll(".", " ")}</strong><small>{time(item.timestamp)} · {item.actor_type}</small></span></div>)}</section>
    </aside></div>
  </>;
}
