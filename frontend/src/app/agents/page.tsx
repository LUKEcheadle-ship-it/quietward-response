"use client";

import { useEffect, useState } from "react";
import { ErrorState, LoadingState } from "@/components/States";
import { apiFetch, formatTime } from "@/lib/api";
import type { Agent } from "@/lib/types";

const CAPABILITY_MAX_AGE_MS = 15 * 60 * 1000;
const CAPABILITY_FUTURE_SKEW_MS = 30 * 1000;

type CapabilityStatus = "Fresh" | "Stale" | "Never reported";

function capabilityStatus(agent: Agent, nowMs: number): CapabilityStatus {
  if (!agent.capabilities_updated_at) return "Never reported";
  const updated = new Date(agent.capabilities_updated_at).getTime();
  if (!Number.isFinite(updated)) return "Stale";
  if (updated > nowMs + CAPABILITY_FUTURE_SKEW_MS) return "Stale";
  if (updated < nowMs - CAPABILITY_MAX_AGE_MS) return "Stale";
  return "Fresh";
}

function capabilitySummary(agent: Agent): string {
  if (!agent.capabilities_updated_at) return "No signed capability report";
  if (agent.enabled_actions.length === 0) return "No enabled actions";
  return agent.enabled_actions.join(", ");
}

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [clock, setClock] = useState(() => Date.now());

  async function load() {
    try {
      setAgents(await apiFetch<Agent[]>("/api/v1/agents"));
      setClock(Date.now());
      setError(null);
    } catch (value) {
      setError((value as Error).message);
    }
  }

  useEffect(() => { void load(); }, []);

  useEffect(() => {
    const timer = window.setInterval(() => setClock(Date.now()), 30_000);
    return () => window.clearInterval(timer);
  }, []);

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
        <h1 className="mt-2 text-3xl font-semibold text-white">Response agents</h1>
        <p className="muted mt-3 max-w-3xl">
          Response agents authenticate outward polling and signed results independently from security sensors. Each agent signs its locally enabled action capabilities; server policy requires a fresh report before any non-demo v1.2 action can be approved or dispatched. Disable an agent immediately if its credential or endpoint is no longer trusted.
        </p>
      </section>
      {error && <div className="rounded-lg border border-rose-500/20 bg-rose-500/10 p-3 text-sm text-rose-200">{error}</div>}
      <section className="panel">
        <div className="table-wrap">
          <table className="data-table">
            <thead><tr><th>Agent</th><th>Host</th><th>Version</th><th>Last seen</th><th>Capabilities</th><th>State</th><th>Key ID</th><th>Control</th></tr></thead>
            <tbody>
              {agents.map((agent) => {
                const capStatus = capabilityStatus(agent, clock);
                const capClass = capStatus === "Fresh"
                  ? "text-emerald-300"
                  : capStatus === "Stale"
                    ? "text-rose-300"
                    : "text-amber-300";
                return (
                <tr key={agent.agent_id}>
                  <td><div className="font-medium text-white">{agent.display_name}</div><div className="font-mono text-xs text-slate-500">{agent.agent_id}</div></td>
                  <td className="font-mono text-xs">{agent.host_id}</td>
                  <td>{agent.agent_version ?? "—"}</td>
                  <td>{agent.last_seen ? formatTime(agent.last_seen) : "Never"}</td>
                  <td className="max-w-80 text-xs">
                    <div className={capClass}>{capStatus} · {capabilitySummary(agent)}</div>
                    <div className="mt-1 text-[10px] text-slate-600">
                      {capStatus === "Fresh" && agent.capabilities_updated_at
                        ? `Signed ${formatTime(agent.capabilities_updated_at)}`
                        : capStatus === "Stale"
                          ? "Run the official Response-agent poll path to refresh before response actions"
                          : "Run the official Response-agent poll path to sync"}
                    </div>
                  </td>
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
              );})}
              {agents.length === 0 && <tr><td colSpan={8} className="py-10 text-center text-slate-500">No Response agents enrolled yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
