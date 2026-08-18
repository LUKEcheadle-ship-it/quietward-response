"use client";

import { useEffect, useState } from "react";
import { ErrorState, LoadingState } from "@/components/States";
import { apiFetch, formatTime } from "@/lib/api";
import type { Agent } from "@/lib/types";

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<Agent[]>("/api/v1/agents").then(setAgents).catch((value: Error) => setError(value.message));
  }, []);

  if (error) return <ErrorState message={error} />;
  if (!agents) return <LoadingState />;

  return (
    <div className="space-y-7">
      <section>
        <p className="eyebrow">Endpoint identities</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">QuietWard agents</h1>
        <p className="muted mt-3 max-w-3xl">
          Enrolled sensors authenticate event delivery and poll for typed, policy-approved response actions. Enrollment secrets are shown only once at enrollment and are never returned here.
        </p>
      </section>
      <section className="panel">
        <div className="table-wrap">
          <table className="data-table">
            <thead><tr><th>Agent</th><th>Host</th><th>Version</th><th>Last seen</th><th>State</th><th>Key ID</th></tr></thead>
            <tbody>
              {agents.map((agent) => (
                <tr key={agent.agent_id}>
                  <td><div className="font-medium text-white">{agent.display_name}</div><div className="font-mono text-xs text-slate-500">{agent.agent_id}</div></td>
                  <td className="font-mono text-xs">{agent.host_id}</td>
                  <td>{agent.agent_version ?? "—"}</td>
                  <td>{agent.last_seen ? formatTime(agent.last_seen) : "Never"}</td>
                  <td><span className={`rounded-full px-2.5 py-1 text-xs ${agent.enabled ? "bg-emerald-500/10 text-emerald-300" : "bg-rose-500/10 text-rose-300"}`}>{agent.enabled ? "Enabled" : "Disabled"}</span></td>
                  <td className="max-w-52 truncate font-mono text-xs text-slate-500">{agent.key_id}</td>
                </tr>
              ))}
              {agents.length === 0 && <tr><td colSpan={6} className="py-10 text-center text-slate-500">No QuietWard agents enrolled yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
