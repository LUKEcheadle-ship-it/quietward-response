import { IncidentTable } from "@/components/incident-table";
import { PageHeader } from "@/components/ui";
import { getIncidents } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function IncidentsPage() {
  const incidents = await getIncidents().catch(() => []);
  return <><PageHeader eyebrow="Investigation queue" title="Incidents" description="Correlated activity ordered by the most recent evidence."/><section className="panel flush"><div className="panel-toolbar"><span>{incidents.length} total incidents</span><div className="filter">All severities</div><div className="filter">All statuses</div></div><IncidentTable incidents={incidents}/></section></>;
}
