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

type HandleOption = {
  handle: string;
  label: string;
  expiresAt: string | null;
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

function requiresResourceHandle(actionType: string): boolean {
  return actionType.endsWith("_by_handle");
}

function actionBadge(actionType: string): string {
  if (actionType.startsWith("collect_")) return "Read-only diagnostic · Approval required";
  if (actionType === "terminate_process_by_handle") return "High-impact containment · Opaque handle · Approval required";
  if (actionType === "quarantine_artifact_by_handle") return "Reversible containment · Opaque handle · Approval required";
  if (actionType === "restore_quarantined_artifact_by_handle") return "Rollback · Opaque handle · Approval required";
  return "State-changing demo · Approval required";
}

function prepareLabel(actionType: string): string {
  if (actionType.startsWith("collect_")) return "Prepare read-only diagnostic";
  if (actionType === "terminate_process_by_handle") return "Prepare exact-process termination";
  if (actionType === "quarantine_artifact_by_handle") return "Prepare artifact quarantine";
  if (actionType === "restore_quarantined_artifact_by_handle") return "Prepare quarantine rollback";
  return "Prepare controlled demo action";
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function validHandle(value: unknown): string | null {
  if (typeof value !== "string" || !value.startsWith("qwrh1_") || value.length > 96) return null;
  return value;
}

function stillValid(expiresAt: unknown): boolean {
  if (typeof expiresAt !== "string" || !expiresAt) return true;
  const epoch = new Date(expiresAt).getTime();
  return Number.isFinite(epoch) && epoch > Date.now();
}

function handleOptionsFor(
  actionType: string,
  agent: Agent | undefined,
  actions: ResponseAction[],
): HandleOption[] {
  if (!agent || !requiresResourceHandle(actionType)) return [];
  const options: HandleOption[] = [];
  const seen = new Set<string>();

  const add = (handleValue: unknown, label: string, expiresAt: unknown) => {
    const handle = validHandle(handleValue);
    if (!handle || seen.has(handle) || !stillValid(expiresAt)) return;
    seen.add(handle);
    options.push({
      handle,
      label,
      expiresAt: typeof expiresAt === "string" ? expiresAt : null,
    });
  };

  for (const action of actions) {
    if (
      action.status !== "succeeded" ||
      action.target_agent_id !== agent.agent_id ||
      action.target_host_id !== agent.host_id
    ) continue;
    const result = asRecord(action.result);
    if (!result) continue;

    if (actionType === "terminate_process_by_handle" && action.action_type === "collect_process_diagnostic") {
      const rows = Array.isArray(result.processes) ? result.processes : [];
      for (const value of rows) {
        const row = asRecord(value);
        if (!row) continue;
        const pid = typeof row.pid === "number" || typeof row.pid === "string" ? String(row.pid) : "?";
        const image = typeof row.image === "string" ? row.image : "process";
        add(row.resource_handle, `PID ${pid} · ${image}`, row.expires_at);
      }
    }

    if (actionType === "quarantine_artifact_by_handle" && action.action_type === "collect_file_diagnostic") {
      const rows = Array.isArray(result.files) ? result.files : [];
      for (const value of rows) {
        const row = asRecord(value);
        if (!row) continue;
        const relative = typeof row.relative_path === "string" ? row.relative_path : "managed file";
        const digest = typeof row.sha256 === "string" ? ` · ${row.sha256.slice(0, 12)}…` : "";
        add(row.resource_handle, `${relative}${digest}`, row.expires_at);
      }
    }

    if (
      actionType === "restore_quarantined_artifact_by_handle" &&
      action.action_type === "quarantine_artifact_by_handle"
    ) {
      const relative = typeof result.original_relative_path === "string"
        ? result.original_relative_path
        : "quarantined artifact";
      add(
        result.rollback_resource_handle,
        `Restore ${relative}`,
        result.rollback_expires_at,
      );
    }
  }

  return options;
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
  const [resourceHandles, setResourceHandles] = useState<Record<string, string>>({});
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
  const eligibleAgents = agents.filter((agent) => agent.enabled && incident.affected_hosts.includes(agent.host_id));
  const incidentAllowsResponse = ACTIONABLE_INCIDENT_STATUSES.has(incident.status);

  function selectedAgentFor(recommendation: RecommendedAction): Agent | undefined {
    const actionType = recommendation.registry_action_type;
    if (!actionType) return undefined;
    const selectedId = selectedAgentIds[actionType];
    return eligibleAgents.find((agent) => agent.agent_id === selectedId) ?? eligibleAgents[0];
  }

  function selectionKey(actionType: string, agent: Agent | undefined): string {
    return `${actionType}:${agent?.agent_id ?? "none"}`;
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

  async function prepare(recommendation: RecommendedAction) {
    const agent = selectedAgentFor(recommendation);
    const actionType = recommendation.registry_action_type;
    if (!agent || !actionType || !incidentAllowsResponse) return;
    if (activeActionFor(recommendation, agent)) return;

    const needsHandle = requiresResourceHandle(actionType);
    const key = selectionKey(actionType, agent);
    const resourceHandle = (resourceHandles[key] ?? "").trim();
    const available = handleOptionsFor(actionType, agent, actions);
    if (needsHandle && !available.some((item) => item.handle === resourceHandle)) {
      setError("Select an unexpired opaque handle produced by this incident and target agent before preparing the action.");
      return;
    }

    setBusy(`prepare:${actionType}`);
    try {
      await apiFetch<ResponseAction>(`/api/v1/incidents/${incident.incident_id}/actions`, {
        method: "POST",
        headers: { "X-Actor-ID": "local-analyst" },
        body: JSON.stringify({
          target_agent_id: agent.agent_id,
          target_host_id: agent.host_id,
          action_type: actionType,
          parameters: needsHandle ? { resource_handle: resourceHandle } : {},
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
          <p className="eyebrow">Controlled actions</p>
          <h2 className="mt-2 text-lg font-semibold text-white">Approval-gated execution</h2>
          <p className="muted mt-2 max-w-3xl text-sm">
            v1.2 adds bounded read-only diagnostics plus opt-in handle-bound process termination and managed-file quarantine/restore. High-impact actions accept only short-lived opaque handles issued by the same Response agent; raw PIDs, paths, commands, service names, firewall rules and arbitrary shell input remain unavailable.
          </p>
        </div>
        <span className="rounded-full border border-cyan/20 bg-cyan/10 px-3 py-1 text-xs text-cyan">Observe → Diagnose → Handle → Approve → Act</span>
      </div>

      {error && <div className="mt-4 rounded-lg border border-rose-500/20 bg-rose-500/10 p-3 text-sm text-rose-200">{error}</div>}

      {controlledRecommendations.length > 0 && (
        <div className="mt-5 space-y-3">
          {controlledRecommendations.map((recommendation) => {
            const agent = selectedAgentFor(recommendation);
            const activeAction = activeActionFor(recommendation, agent);
            const actionType = recommendation.registry_action_type!;
            const needsHandle = requiresResourceHandle(actionType);
            const availableHandles = handleOptionsFor(actionType, agent, actions);
            const key = selectionKey(actionType, agent);
            const selectedHandle = resourceHandles[key] ?? "";
            return <div key={`${actionType}:${recommendation.title}`} className="rounded-lg border border-amber-500/15 bg-amber-500/5 p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p className="font-medium text-white">{recommendation.title}</p>
                  <p className="mt-1 text-xs leading-5 text-slate-400">{recommendation.description}</p>
                </div>
                <span className="text-[10px] uppercase tracking-wider text-amber-200">{actionBadge(actionType)}</span>
              </div>
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
                <div className="mt-3 text-xs text-slate-500">Target: {agent ? `${agent.display_name} · ${agent.host_id}` : "No enabled agent enrolled for an affected host"}</div>
              )}
              {needsHandle && (
                <label className="mt-3 block text-xs text-slate-500">Verified resource from prior Response-agent result
                  <select
                    value={selectedHandle}
                    onChange={(event) => setResourceHandles((current) => ({ ...current, [key]: event.target.value }))}
                    disabled={busy !== null || availableHandles.length === 0}
                    className="mt-2 block w-full rounded-lg border border-line bg-slate-950 px-3 py-2 font-mono text-xs text-white outline-none focus:border-cyan disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    <option value="">{availableHandles.length ? "Select an unexpired opaque handle…" : "Run the matching diagnostic/action first"}</option>
                    {availableHandles.map((item) => (
                      <option key={item.handle} value={item.handle}>{item.label} · {item.handle.slice(0, 18)}…</option>
                    ))}
                  </select>
                  <span className="mt-1 block text-[11px] text-slate-600">Only handles returned by this incident and selected agent are offered. Raw PIDs and file paths cannot be entered.</span>
                </label>
              )}
              {!incidentAllowsResponse ? (
                <span className="mt-3 inline-block rounded border border-slate-500/20 bg-slate-500/10 px-3 py-1.5 text-xs text-slate-400">Incident is closed — controlled actions disabled</span>
              ) : activeAction ? (
                <span className="mt-3 inline-block rounded border border-cyan/20 bg-cyan/10 px-3 py-1.5 text-xs text-cyan">Active action on {activeAction.target_host_id}: {humanStatus(effectiveStatus(activeAction))}</span>
              ) : (
                <button disabled={!agent || busy !== null || (needsHandle && !selectedHandle)} onClick={() => void prepare(recommendation)} className="mt-3 rounded border border-cyan/30 bg-cyan/10 px-3 py-1.5 text-xs font-medium text-cyan disabled:cursor-not-allowed disabled:opacity-40">{prepareLabel(actionType)}</button>
              )}
            </div>;
          })}
        </div>
      )}

      {actions.length > 0 && <div className="mt-5 space-y-4">{actions.map((action) => {
        const shownStatus = effectiveStatus(action);
        const canDecide = incidentAllowsResponse && shownStatus === "pending";
        const diagnostic = action.action_type.startsWith("collect_");
        return (
        <div key={action.action_id} className="rounded-xl border border-line bg-slate-950/40 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="flex flex-wrap items-center gap-2"><p className="font-medium text-white">{action.action_type.replaceAll("_", " ")}</p>{diagnostic && <span className="rounded border border-cyan/20 bg-cyan/10 px-2 py-0.5 text-[10px] uppercase tracking-wider text-cyan">Read-only</span>}</div>
              <p className="mt-1 font-mono text-[11px] text-slate-500">{action.action_id}</p>
            </div>
            <span className={`rounded-full border px-2.5 py-1 text-xs ${statusClass(shownStatus)}`}>{humanStatus(shownStatus)}</span>
          </div>
          <div className="mt-4 grid gap-3 text-xs sm:grid-cols-3">
            <div><p className="text-slate-500">Target</p><p className="mt-1 text-slate-300">{action.target_host_id}</p><p className="mt-1 font-mono text-[10px] text-slate-600">{action.target_agent_id}</p></div>
            <div><p className="text-slate-500">Requested</p><p className="mt-1 text-slate-300">{formatTime(action.requested_at)}</p></div>
            <div><p className="text-slate-500">Policy</p><p className={`mt-1 ${shownStatus === "expired" || action.policy_allowed === false ? "text-rose-300" : action.policy_allowed === true ? "text-emerald-300" : "text-slate-400"}`}>{shownStatus === "expired" ? "Expired" : action.policy_allowed === null ? "Pending approval" : action.policy_allowed ? "Allowed" : "Blocked"}</p></div>
          </div>
          {Object.keys(action.parameters).length > 0 && <div className="mt-3 rounded border border-line bg-black/20 p-2 font-mono text-[11px] text-slate-500">Parameters: {JSON.stringify(action.parameters)}</div>}
          {action.policy_reasons.length > 0 && <ul className="mt-3 space-y-1 text-xs text-rose-300">{action.policy_reasons.map((reason) => <li key={reason}>• {reason}</li>)}</ul>}
          {canDecide && <div className="mt-4 flex gap-2"><button disabled={busy !== null} onClick={() => void decide(action, true)} className="rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-300 disabled:opacity-40">Approve</button><button disabled={busy !== null} onClick={() => void decide(action, false)} className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-xs font-medium text-rose-300 disabled:opacity-40">Reject</button></div>}
          {(action.result || action.error) && <details className="mt-4"><summary className="cursor-pointer text-xs font-medium text-slate-300">{diagnostic ? "Diagnostic result / resource handles" : "Execution result / rollback data"}</summary><pre className="mt-2 max-h-96 overflow-auto rounded-lg bg-black/30 p-3 text-xs text-slate-400">{JSON.stringify({ result: action.result, evidence: action.evidence, error: action.error }, null, 2)}</pre></details>}
        </div>
      );})}</div>}

      {controlledRecommendations.length === 0 && actions.length === 0 && <p className="muted mt-5 text-sm">No executable controlled action is available for this incident. Use the response plan above; generic remediation remains disabled.</p>}
    </section>
  );
}
