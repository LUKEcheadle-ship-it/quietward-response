"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { ErrorState, LoadingState } from "@/components/States";
import { ResponseActions } from "@/components/ResponseActions";
import { ResponsePlanPanel } from "@/components/ResponsePlanPanel";
import { SeverityBadge } from "@/components/SeverityBadge";
import { apiFetch, formatTime } from "@/lib/api";
import type { IncidentDetail, ResponsePlan } from "@/lib/types";

export default function IncidentDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [plan, setPlan] = useState<ResponsePlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const loadIncident = useCallback(async () => {
    if (!id) return;
    const [nextIncident, nextPlan] = await Promise.all([
      apiFetch<IncidentDetail>(`/api/v1/incidents/${id}`),
      apiFetch<ResponsePlan>(`/api/v1/incidents/${id}/response-plan`),
    ]);
    setIncident(nextIncident);
    setPlan(nextPlan);
    setError(null);
  }, [id]);

  useEffect(() => {
    void loadIncident().catch((value: Error) => setError(value.message));
  }, [loadIncident]);

  async function setStatus(status: string) {
    if (!incident) return;
    setSaving(true);
    try {
      const next = await apiFetch<IncidentDetail>(`/api/v1/incidents/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
        headers: { "X-Actor-ID": "local-analyst" },
      });
      setIncident(next);
      setError(null);
    } catch (value) {
      setError((value as Error).message);
    } finally {
      setSaving(false);
    }
  }

  if (error && !incident) return <ErrorState message={error} />;
  if (!incident || !plan) return <LoadingState />;

  const diagnostic = incident.recommended_actions.filter((item) => item.action_type === "diagnostic");
  const remediation = incident.recommended_actions.filter((item) => item.action_type === "remediation");

  return (
    <div className="space-y-7">
      {error && (
        <div className="rounded-lg border border-rose-500/20 bg-rose-500/10 p-3 text-sm text-rose-200">
          {error}
        </div>
      )}

      <section className="panel">
        <div className="flex flex-col justify-between gap-5 lg:flex-row lg:items-start">
          <div>
            <SeverityBadge severity={incident.severity} />
            <h1 className="mt-4 text-3xl font-semibold text-white">{incident.title}</h1>
            <p className="mt-3 font-mono text-xs text-slate-500">{incident.incident_id}</p>
          </div>
          <label className="text-xs uppercase tracking-wider text-slate-500">
            Status
            <select
              disabled={saving}
              value={incident.status}
              onChange={(event) => void setStatus(event.target.value)}
              className="mt-2 block rounded-lg border border-line bg-slate-950 px-4 py-2 text-sm capitalize text-white outline-none focus:border-cyan"
            >
              <option value="new">New</option>
              <option value="investigating">Investigating</option>
              <option value="contained">Contained</option>
              <option value="resolved">Resolved</option>
              <option value="dismissed">Dismissed</option>
            </select>
          </label>
        </div>
        <div className="mt-6 grid gap-4 border-t border-line pt-5 sm:grid-cols-4">
          <div><p className="text-xs text-slate-500">Affected hosts</p><p className="mt-1">{incident.affected_hosts.join(", ")}</p></div>
          <div><p className="text-xs text-slate-500">Confidence</p><p className="mt-1">{Math.round(incident.confidence * 100)}%</p></div>
          <div><p className="text-xs text-slate-500">Events</p><p className="mt-1">{incident.event_count}</p></div>
          <div><p className="text-xs text-slate-500">Window</p><p className="mt-1 text-xs">{formatTime(incident.first_event_at)} → {formatTime(incident.last_event_at)}</p></div>
        </div>
      </section>

      <ResponsePlanPanel plan={plan} />

      <div className="grid gap-7 xl:grid-cols-[1.15fr_.85fr]">
        <section>
          <p className="eyebrow">Chronology</p>
          <h2 className="mt-2 text-xl font-semibold">Incident timeline</h2>
          <div className="mt-5 space-y-0">
            {incident.timeline.map((entry, index) => (
              <div key={entry.event_id} className="relative grid grid-cols-[1.8rem_1fr] gap-3 pb-6">
                <div className="relative">
                  <span className="absolute left-[7px] top-3 h-full w-px bg-line" />
                  <span className="relative mt-2 block h-4 w-4 rounded-full border-4 border-panel bg-cyan" />
                </div>
                <div className="panel">
                  <div className="flex flex-wrap justify-between gap-2">
                    <SeverityBadge severity={entry.severity} />
                    <time className="text-xs text-slate-500">{formatTime(entry.timestamp)}</time>
                  </div>
                  <h3 className="mt-3 font-medium text-white">{entry.summary}</h3>
                  <p className="mt-2 font-mono text-xs text-slate-500">{entry.event_type} · evidence link {index + 1}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        <div className="space-y-6">
          <section className="panel">
            <p className="eyebrow">Assessment</p>
            <h2 className="mt-2 text-lg font-semibold">Probable cause</h2>
            <p className="muted mt-3">{incident.probable_cause}</p>
            <h3 className="mt-5 text-sm font-semibold text-white">Why these events were grouped</h3>
            <ul className="mt-3 space-y-2">
              {incident.correlation_reasons.map((reason) => (
                <li key={reason} className="flex gap-2 text-sm text-slate-400"><span className="text-cyan">•</span>{reason}</li>
              ))}
            </ul>
          </section>

          <section className="panel">
            <p className="eyebrow">Recommended actions</p>
            <h3 className="mt-4 text-sm font-semibold text-emerald-300">Diagnostic guidance</h3>
            <div className="mt-3 space-y-3">
              {diagnostic.map((item) => (
                <div key={item.title} className="rounded-lg border border-emerald-500/15 bg-emerald-500/5 p-3">
                  <div className="flex justify-between gap-2">
                    <p className="text-sm font-medium text-white">{item.title}</p>
                    <span className="text-[10px] uppercase text-emerald-200">{item.phase}</span>
                  </div>
                  <p className="mt-1 text-xs leading-5 text-slate-400">{item.description}</p>
                </div>
              ))}
            </div>
            <h3 className="mt-6 text-sm font-semibold text-amber-200">Remediation guidance</h3>
            <div className="mt-3 space-y-3">
              {remediation.map((item) => (
                <div key={item.title} className={`rounded-lg border border-amber-500/15 bg-amber-500/5 p-3 ${item.registry_action_type ? "" : "opacity-75"}`}>
                  <div className="flex justify-between gap-2">
                    <p className="text-sm font-medium text-white">{item.title}</p>
                    <span className="text-[10px] uppercase text-amber-200">{item.phase}</span>
                  </div>
                  <p className="mt-1 text-xs leading-5 text-slate-400">{item.description}</p>
                  {item.registry_action_type ? (
                    <span className="mt-3 inline-block rounded border border-cyan/20 bg-cyan/10 px-2 py-1 text-[10px] uppercase text-cyan">Controlled action available below</span>
                  ) : (
                    <span className="mt-3 inline-block rounded border border-line px-2 py-1 text-[10px] uppercase text-slate-500">Guidance only · not executable</span>
                  )}
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>

      <ResponseActions incident={incident} onIncidentRefresh={loadIncident} />

      <section>
        <p className="eyebrow">Evidence</p>
        <h2 className="mt-2 text-xl font-semibold">Raw event details</h2>
        <div className="mt-4 space-y-3">
          {incident.events.map((event) => (
            <details key={event.event_id} className="panel group">
              <summary className="cursor-pointer list-none font-medium text-white group-open:text-cyan">
                {event.summary}<span className="ml-3 font-mono text-xs text-slate-600">{event.event_id}</span>
              </summary>
              <pre className="mt-4 max-h-[34rem] overflow-auto rounded-lg bg-slate-950 p-4 text-xs leading-5 text-slate-300">{JSON.stringify(event, null, 2)}</pre>
            </details>
          ))}
        </div>
      </section>

      <section>
        <p className="eyebrow">Accountability</p>
        <h2 className="mt-2 text-xl font-semibold">Audit trail</h2>
        <div className="table-wrap mt-4">
          <table className="data-table">
            <thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Resource</th><th>Details</th></tr></thead>
            <tbody>
              {incident.audit_trail.map((entry) => (
                <tr key={entry.audit_id}>
                  <td className="whitespace-nowrap">{formatTime(entry.timestamp)}</td>
                  <td className="font-medium text-white">{entry.action.replaceAll("_", " ")}</td>
                  <td>{entry.actor_type}<div className="text-xs text-slate-500">{entry.actor_id}</div></td>
                  <td>{entry.resource_type}<div className="max-w-44 truncate font-mono text-xs text-slate-500">{entry.resource_id}</div></td>
                  <td><code className="text-xs text-slate-400">{JSON.stringify(entry.details)}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
