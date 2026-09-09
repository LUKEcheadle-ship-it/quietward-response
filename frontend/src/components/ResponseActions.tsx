"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch, formatTime } from "@/lib/api";
import type { Agent, IncidentDetail, RecommendedAction, ResponseAction } from "@/lib/types";

const ACTIVE_ACTION_STATUSES = new Set<ResponseAction["status"]>([
  "pending",
  "approved",
  "dispatching",
  "executing",
]);
const ACTIONABLE_INCIDENT_STATUSES = new Set(["new", "investigating", "contained"]);
const PARAMETERIZED_ACTIONS = new Set(["terminate_evidence_process"]);
const PROCESS_HANDLE = /^qwrp-[0-9a-f]{32}$/;

type ProcessCandidate = {
  evidenceHandle: string;
  pid: number | null;
  parentPid: number | null;
  image: string;
  targetAgentId: string;
  targetHostId: string;
  sourceActionId: string;
};

function locallyExpired(action: ResponseAction): boolean {
  if (action.status === "executing") return false;
  if (!["pending", "approved", "dispatching"].includes(action.status)) return false;
  return new Date(action.expires_at).getTime() <= Date.now();
}

function effectiveStatus(action: ResponseAction): ResponseAction["status"] {
  return locallyExpired(action) ? "expired" : action.status;
}

function statusClass(status: ResponseAction["status"]): string {
  if (status === "succeeded") return "bg-emerald-500/10 text-emerald-300 border-emerald-500/20";
  if (status === "failed" || status === "rejected" || status === "expired") return "bg-rose-500/10 text-rose-300 border-rose-500/20";
  if (status === "cancelled") return "bg-slate-500/10 text-slate-300 border-slate-500/20";
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

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function processCandidatesFrom(actions: ResponseAction[]): ProcessCandidate[] {
  const candidates: ProcessCandidate[] = [];
  const seen = new Set<string>();
  for (const action of actions) {
    if (action.action_type !== "collect_incident_triage_bundle" || action.status !== "succeeded") continue;
    const result = asRecord(action.result);
    const components = asRecord(result?.components);
    const process = asRecord(components?.process);
    const rows = process?.processes;
    if (!Array.isArray(rows)) continue;
    for (const raw of rows) {
      const row = asRecord(raw);
      if (!row) continue;
      const evidenceHandle = typeof row.evidence_handle === "string" ? row.evidence_handle : "";
      if (!PROCESS_HANDLE.test(evidenceHandle) || seen.has(evidenceHandle)) continue;
      seen.add(evidenceHandle);
      candidates.push({
        evidenceHandle,
        pid: numberOrNull(row.pid),
        parentPid: numberOrNull(row.parent_pid),
        image: typeof row.image === "string" ? row.image : "unknown",
        targetAgentId: action.target_agent_id,
        targetHostId: action.target_host_id,
        sourceActionId: action.action_id,
      });
    }
  }
  return candidates;
}

export function ResponseActions({
  incident,
  onIncidentRefresh,
}: {
  incident: IncidentDetail;
  onIncidentRefresh?: () => Promise<void> | void;
}) {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [selectedAgentIds, setSelectedAgentIds] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [clock, setClock] = useState(() => Date.now());

  const load = useCallback(async () => {
    try {
      const [agentRows, actionRows] = await Promise.all([
        apiFetch<Agent[]>("/api/v1/agents"),
        apiFetch<ResponseAction[]>(`/api/v1/incidents/${incident.incident_id}/actions`),
      ]);
      setAgents(agentRows);
      setActions(actionRows);
      setClock(Date.now());
      setError(null);
      await onIncidentRefresh?.();
    } catch (value) {
      setError((value as Error).message);
    }
  }, [incident.incident_id, onIncidentRefresh]);

  useEffect(() => { void load(); }, [load, incident.status]);

  useEffect(() => {
    const active = actions.some((item) => ["approved", "dispatching", "executing"].includes(effectiveStatus(item)));
    if (!active) return;
    const timer = window.setInterval(() => { void load(); }, 2500);
    return () => window.clearInterval(timer);
  }, [actions, load]);

  useEffect(() => {
    if (!actions.some((item) => item.status === "pending")) return;
    const timer = window.setInterval(() => setClock(Date.now()), 5000);
    return () => window.clearInterval(timer);
  }, [actions]);

  const controlledRecommendations = useMemo(
    () => incident.recommended_actions.filter((item) => item.registry_action_type && item.enabled),
    [incident.recommended_actions],
  );
  const parameterlessRecommendations = useMemo(
    () => controlledRecommendations.filter(
      (item) => item.registry_action_type && !PARAMETERIZED_ACTIONS.has(item.registry_action_type),
    ),
    [controlledRecommendations],
  );
  const processContainmentRecommendation = useMemo(
    () => controlledRecommendations.find((item) => item.registry_action_type === "terminate_evidence_process"),
    [controlledRecommendations],
  );
  const processCandidates = useMemo(() => processCandidatesFrom(actions), [actions]);
  const affectedAgents = agents.filter((agent) => agent.enabled && incident.affected_hosts.includes(agent.host_id));
  const incidentAllowsResponse = ACTIONABLE_INCIDENT_STATUSES.has(incident.status);

  function eligibleAgentsFor(recommendation: RecommendedAction): Agent[] {
    const actionType = recommendation.registry_action_type;
    if (!actionType) return [];
    return affectedAgents.filter((agent) => agent.enabled_actions.includes(actionType));
  }

  function selectedAgentFor(recommendation: RecommendedAction): Agent | undefined {
    const actionType = recommendation.registry_action_type;
    if (!actionType) return undefined;
    const eligibleAgents = eligibleAgentsFor(recommendation);
    const selectedId = selectedAgentIds[actionType];
    return eligibleAgents.find((agent) => agent.agent_id === selectedId) ?? eligibleAgents[0];
  }

  function activeActionFor(
    recommendation: RecommendedAction,
    targetAgent: Agent | undefined,
  ): ResponseAction | undefined {
    if (!recommendation.registry_action_type || !targetAgent) return undefined;
    void clock;
    return actions.find(
      (action) =>
        action.action_type === recommendation.registry_action_type &&
        action.target_host_id === targetAgent.host_id &&
        ACTIVE_ACTION_STATUSES.has(action.status) &&
        !locallyExpired(action),
    );
  }

  function activeProcessContainmentFor(hostId: string): ResponseAction | undefined {
    void clock;
    return actions.find(
      (action) =>
        action.action_type === "terminate_evidence_process" &&
        action.target_host_id === hostId &&
        ACTIVE_ACTION_STATUSES.has(action.status) &&
        !locallyExpired(action),
    );
  }

  async function prepare(recommendation: RecommendedAction) {
    const agent = selectedAgentFor(recommendation);
    const actionType = recommendation.registry_action_type;
    if (!agent || !actionType || !incidentAllowsResponse || PARAMETERIZED_ACTIONS.has(actionType)) return;
    if (activeActionFor(recommendation, agent)) return;
    setBusy(`prepare:${actionType}`);
    try {
      await apiFetch<ResponseAction>(`/api/v1/incidents/${incident.incident_id}/actions`, {
        method: "POST",
        headers: { "X-Actor-ID": "local-analyst" },
        body: JSON.stringify({
          target_agent_id: agent.agent_id,
          target_host_id: agent.host_id,
          action_type: actionType,
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

  async function prepareProcessContainment(candidate: ProcessCandidate) {
    if (!incidentAllowsResponse || !processContainmentRecommendation) return;
    const agent = affectedAgents.find(
      (item) => item.agent_id === candidate.targetAgentId && item.enabled_actions.includes("terminate_evidence_process"),
    );
    if (!agent || activeProcessContainmentFor(candidate.targetHostId)) return;
    setBusy(`terminate:${candidate.evidenceHandle}`);
    try {
      await apiFetch<ResponseAction>(`/api/v1/incidents/${incident.incident_id}/actions`, {
        method: "POST",
        headers: { "X-Actor-ID": "local-analyst" },
        body: JSON.stringify({
          target_agent_id: agent.agent_id,
          target_host_id: candidate.targetHostId,
          action_type: "terminate_evidence_process",
          parameters: { evidence_handle: candidate.evidenceHandle },
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
    if (!incidentAllowsResponse || locallyExpired(action)) return;
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
          <h2 className="mt-2 text-lg font-semibold text-white">Controlled actions</h2>
          <p className="muted mt-2 max-w-2xl text-sm">Only typed actions in the server and endpoint allowlists can be dispatched. Mutating actions require explicit analyst approval, and process containment is bound to endpoint-generated evidence rather than arbitrary PIDs.</p>
        </div>
        <span className="rounded-full border border-cyan/20 bg-cyan/10 px-3 py-1 text-xs text-cyan">Observe → Triage → Select evidence → Approve → Act</span>
      </div>

      {error && <div className="mt-4 rounded-lg border border-rose-500/20 bg-rose-500/10 p-3 text-sm text-rose-200">{error}</div>}

      {parameterlessRecommendations.length > 0 && (
        <div className="mt-5 space-y-3">
          {parameterlessRecommendations.map((recommendation) => {
            const eligibleAgents = eligibleAgentsFor(recommendation);
            const agent = selectedAgentFor(recommendation);
            const activeAction = activeActionFor(recommendation, agent);
            const actionType = recommendation.registry_action_type!;
            return <div key={actionType} className="rounded-lg border border-amber-500/15 bg-amber-500/5 p-4">
              <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="font-medium text-white">{recommendation.title}</p><p className="mt-1 text-xs leading-5 text-slate-400">{recommendation.description}</p></div><span className="text-[10px] uppercase tracking-wider text-amber-200">Approval required</span></div>
              {eligibleAgents.length > 1 ? (
                <label className="mt-3 block text-xs text-slate-500">Target agent
                  <select
                    value={agent?.agent_id ?? ""}
                    onChange={(event) => setSelectedAgentIds((current) => ({ ...current, [actionType]: event.target.value }))}
                    disabled={busy !== null}
                    className="mt-2 block w-full rounded-lg border border-line bg-slate-950 px-3 py-2 text-xs text-white outline-none focus:border-cyan disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {eligibleAgents.map((candidate) => <option key={candidate.agent_id} value={candidate.agent_id}>{candidate.display_name} · {candidate.host_id}</option>)}
                  </select>
                </label>
              ) : (
                <div className="mt-3 text-xs text-slate-500">Target: {agent ? `${agent.display_name} · ${agent.host_id}` : "No enabled agent has declared this capability for an affected host"}</div>
              )}
              {!incidentAllowsResponse ? (
                <span className="mt-3 inline-block rounded border border-slate-500/20 bg-slate-500/10 px-3 py-1.5 text-xs text-slate-400">Incident is closed — response actions disabled</span>
              ) : activeAction ? (
                <span className="mt-3 inline-block rounded border border-cyan/20 bg-cyan/10 px-3 py-1.5 text-xs text-cyan">Active action on {activeAction.target_host_id}: {humanStatus(effectiveStatus(activeAction))}</span>
              ) : (
                <button disabled={!agent || busy !== null} onClick={() => void prepare(recommendation)} className="mt-3 rounded border border-cyan/30 bg-cyan/10 px-3 py-1.5 text-xs font-medium text-cyan disabled:cursor-not-allowed disabled:opacity-40">Prepare controlled action</button>
              )}
            </div>;
          })}
        </div>
      )}

      {processContainmentRecommendation && (
        <div className="mt-5 rounded-xl border border-rose-500/20 bg-rose-500/5 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="font-medium text-white">{processContainmentRecommendation.title}</p>
              <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-400">{processContainmentRecommendation.description}</p>
            </div>
            <span className="text-[10px] uppercase tracking-wider text-rose-300">High impact · approval required</span>
          </div>
          {processCandidates.length === 0 ? (
            <p className="mt-4 text-xs text-slate-500">Run and approve the guided incident triage bundle first. No free-form PID or process target can be entered here.</p>
          ) : (
            <details className="mt-4" open>
              <summary className="cursor-pointer text-xs font-medium text-slate-300">Evidence-bound process candidates ({processCandidates.length})</summary>
              <div className="mt-3 max-h-96 space-y-2 overflow-auto pr-1">
                {processCandidates.slice(0, 128).map((candidate) => {
                  const agent = affectedAgents.find(
                    (item) => item.agent_id === candidate.targetAgentId && item.enabled_actions.includes("terminate_evidence_process"),
                  );
                  const active = activeProcessContainmentFor(candidate.targetHostId);
                  return (
                    <div key={candidate.evidenceHandle} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-line bg-slate-950/40 p-3">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-white">{candidate.image}</p>
                        <p className="mt-1 text-[11px] text-slate-500">PID {candidate.pid ?? "?"} · parent {candidate.parentPid ?? "?"} · {candidate.targetHostId}</p>
                        <p className="mt-1 font-mono text-[10px] text-slate-600">{candidate.evidenceHandle}</p>
                      </div>
                      {active ? (
                        <span className="rounded border border-cyan/20 bg-cyan/10 px-2 py-1 text-[11px] text-cyan">Containment already active on host</span>
                      ) : (
                        <button
                          disabled={!incidentAllowsResponse || !agent || busy !== null}
                          onClick={() => void prepareProcessContainment(candidate)}
                          className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-xs font-medium text-rose-200 disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          Prepare termination
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            </details>
          )}
        </div>
      )}

      {actions.length > 0 && <div className="mt-5 space-y-4">{actions.map((action) => {
        const shownStatus = effectiveStatus(action);
        const canDecide = incidentAllowsResponse && shownStatus === "pending";
        return (
        <div key={action.action_id} className="rounded-xl border border-line bg-slate-950/40 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="font-medium text-white">{action.action_type.replaceAll("_", " ")}</p><p className="mt-1 font-mono text-[11px] text-slate-500">{action.action_id}</p></div><span className={`rounded-full border px-2.5 py-1 text-xs ${statusClass(shownStatus)}`}>{humanStatus(shownStatus)}</span></div>
          <div className="mt-4 grid gap-3 text-xs sm:grid-cols-3"><div><p className="text-slate-500">Target</p><p className="mt-1 text-slate-300">{action.target_host_id}</p><p className="mt-1 font-mono text-[10px] text-slate-600">{action.target_agent_id}</p></div><div><p className="text-slate-500">Requested</p><p className="mt-1 text-slate-300">{formatTime(action.requested_at)}</p></div><div><p className="text-slate-500">Policy</p><p className={`mt-1 ${shownStatus === "expired" || action.policy_allowed === false ? "text-rose-300" : action.policy_allowed === true ? "text-emerald-300" : "text-slate-400"}`}>{shownStatus === "expired" ? "Expired" : action.policy_allowed === null ? "Pending approval" : action.policy_allowed ? "Allowed" : "Blocked"}</p></div></div>
          {action.action_type === "terminate_evidence_process" && typeof action.parameters.evidence_handle === "string" && <p className="mt-3 font-mono text-[10px] text-slate-600">Evidence handle: {action.parameters.evidence_handle}</p>}
          {action.policy_reasons.length > 0 && <ul className="mt-3 space-y-1 text-xs text-rose-300">{action.policy_reasons.map((reason) => <li key={reason}>• {reason}</li>)}</ul>}
          {canDecide && <div className="mt-4 flex gap-2"><button disabled={busy !== null} onClick={() => void decide(action, true)} className="rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-300 disabled:opacity-40">Approve</button><button disabled={busy !== null} onClick={() => void decide(action, false)} className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-xs font-medium text-rose-300 disabled:opacity-40">Reject</button></div>}
          {action.result && <details className="mt-4"><summary className="cursor-pointer text-xs font-medium text-slate-300">Action result</summary><pre className="mt-2 max-h-72 overflow-auto rounded-lg bg-black/30 p-3 text-xs text-slate-400">{JSON.stringify({ result: action.result, evidence: action.evidence, error: action.error }, null, 2)}</pre></details>}
        </div>
      );})}</div>}

      {controlledRecommendations.length === 0 && actions.length === 0 && <p className="muted mt-5 text-sm">No allowlisted controlled action is available for this incident. The vNext release gate blocks shipment while any QuietWard category lacks a tested resolution path.</p>}
    </section>
  );
}
