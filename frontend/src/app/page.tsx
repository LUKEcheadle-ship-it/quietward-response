import Link from "next/link";
import { Icon } from "@/components/icons";
import { EmptyState, PageHeader, SeverityBadge, StatusBadge } from "@/components/ui";
import { getSummary } from "@/lib/api";
import { time } from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function Overview() {
  let data;
  try { data = await getSummary(); } catch { data = { active_incidents: 0, critical_incidents: 0, high_incidents: 0, hosts_reporting: 0, events_last_24h: 0, recent_incidents: [] }; }
  const cards = [["Active incidents", data.active_incidents, "incidents", "blue"], ["Critical", data.critical_incidents, "incidents", "red"], ["High severity", data.high_incidents, "pulse", "amber"], ["Hosts reporting", data.hosts_reporting, "hosts", "teal"], ["Events · 24h", data.events_last_24h, "events", "violet"]] as const;
  return <><PageHeader eyebrow="Operational picture" title="Response overview" description="Explainable correlation and investigation across every reporting host."><span className="mode-pill"><Icon name="lock" size={15}/> Observe-only mode</span></PageHeader>
    <section className="metrics">{cards.map(([label, value, icon, tone]) => <article className={`metric ${tone}`} key={label}><div className="metric-icon"><Icon name={icon}/></div><span>{label}</span><strong>{value}</strong><small>{label.includes("Events") ? "Rolling window" : "Current state"}</small></article>)}</section>
    <section className="panel"><div className="panel-head"><div><span className="section-label">Latest activity</span><h2>Recently created incidents</h2></div><Link href="/incidents">View all incidents <Icon name="arrow" size={15}/></Link></div>
      {!data.recent_incidents.length ? <EmptyState label="incidents"/> : <div className="recent-list">{data.recent_incidents.map(item => <Link href={`/incidents/${item.incident_id}`} key={item.incident_id}><SeverityBadge value={item.severity}/><div><strong>{item.title}</strong><span>Opened {time(item.created_at)}</span></div><StatusBadge value={item.status}/><Icon name="arrow" size={17}/></Link>)}</div>}
    </section>
    <section className="trust-strip"><div><Icon name="check"/><span><strong>Deterministic correlation</strong>Every grouping includes its reasoning.</span></div><div><Icon name="check"/><span><strong>Immutable-style audit</strong>Material operations are recorded.</span></div><div><Icon name="lock"/><span><strong>No endpoint actions</strong>Remediation is disabled in Phase 1.</span></div></section>
  </>;
}
