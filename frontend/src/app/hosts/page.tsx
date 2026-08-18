import { EmptyState, PageHeader, StatusBadge } from "@/components/ui";
import { getHosts } from "@/lib/api";
import { time } from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function HostsPage() {
  const hosts = await getHosts().catch(() => []);
  return <><PageHeader eyebrow="Asset inventory" title="Reporting hosts" description="Endpoint identities observed through the versioned event protocol."/><section className="panel flush">{!hosts.length ? <EmptyState label="hosts"/> : <div className="host-grid">{hosts.map(host => <article className="host-card" key={host.host_id}><div className="host-avatar">{host.hostname.slice(0, 2).toUpperCase()}</div><div className="host-main"><div><h3>{host.hostname}</h3><StatusBadge value={host.status}/></div><code>{host.host_id}</code><dl><div><dt>Operating system</dt><dd>{host.operating_system || "Not reported"}</dd></div><div><dt>Agent</dt><dd>{host.agent} {host.agent_version || ""}</dd></div><div><dt>First seen</dt><dd>{time(host.first_seen)}</dd></div><div><dt>Last seen</dt><dd>{time(host.last_seen)}</dd></div></dl></div></article>)}</div>}</section></>;
}
