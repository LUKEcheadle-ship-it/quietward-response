"use client";

import { useEffect, useState } from "react";
import { ErrorState, LoadingState } from "@/components/States";
import { apiFetch, formatTime } from "@/lib/api";
import type { Agent } from "@/lib/types";

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function load() {
    try {
      setAgents(await apiFetch<Agent[]>("/api/v1/agents"));
      setError(null);
    } catch (value) {
      setError((value as Error).message);
    }
  }

  useEffect(() => { void load(); }, []);

  async function setEnabled(agent: Agent, enabled: boolean) {
    setBusy(agent.agent_id);
    try {
      await apiFetch<Agent>(`/api/v1/agents/${agent.agent_id}`, {
        method: "PATCH",
        headers: { "X-Actor-ID": "local-analyst" },
        body: JSON.stringify({ enabled }),
      });
      await load();
    } catch (value) {
      setError((value as Error).message);
    } finally {
      setBusy(null);
    }
  }

  if (error && !agents) return <ErrorState message={error} />;
  if (!agents) return <LoadingState />;

  return (
    <div className="space-y-7">
      <section>
        <p className="eyebrow">Endpoint identities</p>
        <h1 className="mt-2 text-3xl font-semibold text-white">Response endpoint agents</h1>
        <p className="muted mt-3 max-w-3xl">
          Response-owned agents authenticate their capability set, receive only typed policy-approved actions, and return signed results. QuietWard remains a separate observation-only detector and sends sanitized evidence through the handoff bridge.
        </p>
      </section>
      {error && <div className="rounded-lg border border-rose-500/20 bg-rose-500/10 p-3 text-sm text-rose-200">{error}</div>}
      <section className="panel">
        <div className="table-wrap">
          <table className="data-table">
            <thead><tr><th>Agent</th><th>Host</th><th>Version</th><th>Capabilities</th><th>Last seen</th><th>State</th><th>Key ID</th><th>Control</th></tr></thead>
            <tbody>
              {agents.map((agent) => (
                <tr key={agent.agent_id}>
                  <td><div className="font-medium text-white">{agent.display_name}</div><div className="font-mono text-xs text-slate-500">{agent.agent_id}</div></td>
                  <td className="font-mono text-xs">{agent.host_id}</td>
                  <td>{agent.agent_version ?? "—"}</td>
                  <td>
                    <div className="flex max-w-72 flex-wrap gap-1.5">
                      {agent.enabled_actions.map((action) => (
                        <span key={action} className="rounded border border-cyan/20 bg-cyan/10 px-2 py-1 text-[10px] text-cyan">
                          {action.replaceAll("_", " ")}
                        </span>
                      ))}
                      {agent.enabled_actions.length === 0 && <span className="text-xs text-slate-500">No trusted actions</span>}
                    </div>
                  </td>
                  <td>{agent.last_seen ? formatTime(agent.last_seen) : "Never"}</td>
                  <td><span className={`rounded-full px-2.5 py-1 text-xs ${agent.enabled ? "bg-emerald-500/10 text-emerald-300" : "bg-rose-500/10 text-rose-300"}`}>{agent.enabled ? "Enabled" : "Disabled"}</span></td>
                  <td className="max-w-52 truncate font-mono text-xs text-slate-500">{agent.key_id}</td>
                  <td>
                    <button
                      disabled={busy !== null}
                      onClick={() => setEnabled(agent, !agent.enabled)}
                      className={`rounded border px-3 py-1.5 text-xs font-medium disabled:cursor-not-allowed disabled:opacity-40 ${agent.enabled ? "border-rose-500/30 bg-rose-500/10 text-rose-300" : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"}`}
                    >
                      {busy === agent.agent_id ? "Saving…" : agent.enabled ? "Disable" : "Enable"}
                    </button>
                  </td>
                </tr>
              ))}
              {agents.length === 0 && <tr><td colSpan={8} className="py-10 text-center text-slate-500">No Response endpoint agents enrolled yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
