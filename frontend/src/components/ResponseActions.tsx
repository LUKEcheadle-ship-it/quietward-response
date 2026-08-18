"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch, formatTime } from "@/lib/api";
import type { Agent, IncidentDetail, RecommendedAction, ResponseAction } from "@/lib/types";

function statusClass(status: ResponseAction["status"]): string {
  if (status === "succeeded") return "bg-emerald-500/10 text-emerald-300 border-emerald-500/20";
  if (status === "failed" || status === "rejected" || status === "expired") return "bg-rose-500/10 text-rose-300 border-rose-500/20";
  if (status === "approved" || status === "dispatching" || status === "executing") return "bg-cyan/10 text-cyan border-cyan/20";
  return "bg-amber-500/10 text-amber-200 border-amber-500/20";
}

function humanStatus(status: ResponseAction["status"]): string {
  const map: Record<ResponseAction["status"], string> = {
    pending: "Awaiting approval",
    approved: "Approved",
    rejected: "Rejected",
    dispatching: "Dispatching",
    executing: "Executing",
    succeeded: "Succeeded",
    failed: "Failed",
    expired: "Expired",
    cancelled: "Cancelled",
  };
  return map[status];
}

export function ResponseActions({ incident }: { incident: IncidentDetail }) {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [agentRows, actionRows] = await Promise.all([
        apiFetch<Agent[]>("/api/v1/agents"),
        apiFetch<ResponseAction[]>(`/api/v1/incidents/${incident.incident_id}/actions`),
      ]);
      setAgents(agentRows);
      setActions(actionRows);
      setError(null);
    } catch (value) {
      setError((value as Error).message);
    }
  }, [incident.incident_id]);

  useEffect(() => { void load(); }, [load]);

  // Refresh active actions so the analyst sees agent polling/result transitions.
  useEffect(() => {
    const active = actions.some((item) => ["approved", "dispatching", "executing"].includes(item.status));
    if (!active) return;
    const timer = window.setInterval(() => { void load(); }, 2500);
    return () => window.clearInterval(timer);
  }, [actions, load]);

  const controlledRecommendations = useMemo(
    () => incident.recommended_actions.filter((item) => item.registry_action_type && item.enabled),
    [incident.recommended_actions],
  );
  const eligibleAgents = agents.filter((agent) => agent.enabled && incident.affected_hosts.includes(agent.host_id));

  async function prepare(recommendation: RecommendedAction) {
    const agent = eligibleAgents[0];
    if (!agent || !recommendation.registry_action_type) return;
    setBusy(`prepare:${recommendation.registry_action_type}`);
    try {
      await apiFetch<ResponseAction>(`/api/v1/incidents/${incident.incident_id}/actions`, {
        method: "POST",
        headers: { "X-Actor-ID": "local-analyst" },
        body: JSON.stringify({
          target_agent_id: agent.agent_id,
          target_host_id: agent.host_id,
          action_type: recommendation.registry_action_type,
          parameters: {},
        }),
      });
      await load();
    } catch (value) {
      setError((value as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function decide(action: ResponseAction, approve: boolean) {
    setBusy(`${approve ? "approve" : "reject"}:${action.action_id}`);
    try {
      await apiFetch<ResponseAction>(`/api/v1/actions/${action.action_id}/${approve ? "approve" : "reject"}`, {
        method: "POST",
        headers: { "X-Actor-ID": "local-analyst" },
        body: JSON.stringify({ reason: approve ? "Approved from incident console" : "Rejected from incident console" }),
      });
      await load();
    } catch (value) {
      setError((value as Error).message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="panel">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="eyebrow">Response actions</p>
          <h2 className="mt-2 text-lg font-semibold text-white">Controlled remediation</h2>
          <p className="muted mt-2 max-w-2xl text-sm">Only typed actions in the server and endpoint allowlists can be dispatched. Phase 2 requires explicit analyst approval; arbitrary command execution is not available.</p>
        </div>
        <span className="rounded-full border border-cyan/20 bg-cyan/10 px-3 py-1 text-xs text-cyan">Observe → Recommend → Approve → Act</span>
      </div>

      {error && <div className="mt-4 rounded-lg border border-rose-500/20 bg-rose-500/10 p-3 text-sm text-rose-200">{error}</div>}

      {controlledRecommendations.length > 0 && actions.length === 0 && (
        <div className="mt-5 space-y-3">
          {controlledRecommendations.map((recommendation) => {
            const agent = eligibleAgents[0];
            return <div key={recommendation.registry_action_type} className="rounded-lg border border-amber-500/15 bg-amber-500/5 p-4">
              <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="font-medium text-white">{recommendation.title}</p><p className="mt-1 text-xs leading-5 text-slate-400">{recommendation.description}</p></div><span className="text-[10px] uppercase tracking-wider text-amber-200">Approval required</span></div>
              <div className="mt-3 text-xs text-slate-500">Target: {agent ? `${agent.display_name} · ${agent.host_id}` : "No enabled agent enrolled for an affected host"}</div>
              <button disabled={!agent || busy !== null} onClick={() => prepare(recommendation)} className="mt-3 rounded border border-cyan/30 bg-cyan/10 px-3 py-1.5 text-xs font-medium text-cyan disabled:cursor-not-allowed disabled:opacity-40">Prepare controlled action</button>
            </div>;
          })}
        </div>
      )}

      {actions.length > 0 && <div className="mt-5 space-y-4">{actions.map((action) => (
        <div key={action.action_id} className="rounded-xl border border-line bg-slate-950/40 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="font-medium text-white">{action.action_type.replaceAll("_", " ")}</p><p className="mt-1 font-mono text-[11px] text-slate-500">{action.action_id}</p></div><span className={`rounded-full border px-2.5 py-1 text-xs ${statusClass(action.status)}`}>{humanStatus(action.status)}</span></div>
          <div className="mt-4 grid gap-3 text-xs sm:grid-cols-3"><div><p className="text-slate-500">Target</p><p className="mt-1 text-slate-300">{action.target_host_id}</p></div><div><p className="text-slate-500">Requested</p><p className="mt-1 text-slate-300">{formatTime(action.requested_at)}</p></div><div><p className="text-slate-500">Policy</p><p className={`mt-1 ${action.policy_allowed === false ? "text-rose-300" : action.policy_allowed === true ? "text-emerald-300" : "text-slate-400"}`}>{action.policy_allowed === null ? "Pending approval" : action.policy_allowed ? "Allowed" : "Blocked"}</p></div></div>
          {action.policy_reasons.length > 0 && <ul className="mt-3 space-y-1 text-xs text-rose-300">{action.policy_reasons.map((reason) => <li key={reason}>• {reason}</li>)}</ul>}
          {action.status === "pending" && <div className="mt-4 flex gap-2"><button disabled={busy !== null} onClick={() => decide(action, true)} className="rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-300 disabled:opacity-40">Approve</button><button disabled={busy !== null} onClick={() => decide(action, false)} className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-xs font-medium text-rose-300 disabled:opacity-40">Reject</button></div>}
          {action.result && <details className="mt-4"><summary className="cursor-pointer text-xs font-medium text-slate-300">Execution result</summary><pre className="mt-2 max-h-72 overflow-auto rounded-lg bg-black/30 p-3 text-xs text-slate-400">{JSON.stringify({ result: action.result, evidence: action.evidence, error: action.error }, null, 2)}</pre></details>}
        </div>
      ))}</div>}

      {controlledRecommendations.length === 0 && actions.length === 0 && <p className="muted mt-5 text-sm">No allowlisted remediation is available for this incident. General remediation remains disabled.</p>}
    </section>
  );
}
