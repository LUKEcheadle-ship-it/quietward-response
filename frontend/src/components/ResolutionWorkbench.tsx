"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { apiFetch, formatTime } from "@/lib/api";

type Step = { key: string; title: string; instruction: string; acceptance: string; conditional: boolean };
type Playbook = { family: string; title: string; verification: string; escalation_team: string; checkpoints: Step[]; digest: string };
type Scope = { host_id: string; source_category: string };
type Case = Scope & {
  workflow_id: string; incident_id: string; family: string; state: string; revision: number;
  owner: string; approver: string | null; verifier: string | null;
  context_current: boolean; playbook_current: boolean;
  checkpoints: { checkpoint: string; outcome: string; note: string; artifact_sha256: string; artifact_reference: string; actor: string }[];
  plan: { baseline_sha256: string; baseline_summary: string; ticket_reference: string; rollback_plan: string };
  verification: { artifact_sha256: string; artifact_reference: string; note: string; actor: string } | null;
  escalation: { assigned_to: string; ticket_reference: string; due_at: string; acknowledged_by: string | null; note: string } | null;
};
type Catalog = { playbooks: Playbook[]; actor: string | null; named_auth_configured: boolean };
const input = "mt-1 block w-full rounded-lg border border-line bg-slate-950 p-2 text-sm text-white";
const button = "rounded-lg border border-cyan/30 bg-cyan/10 px-4 py-2 text-sm text-cyan disabled:cursor-not-allowed disabled:opacity-40";
const label = "block text-sm text-slate-300";

function field(form: FormData, name: string) { return String(form.get(name) || ""); }
function PlanFields() {
  return <div className="grid gap-3 sm:grid-cols-2">
    <label className={label}>Baseline artifact SHA-256<input className={input} name="baseline_sha256" pattern="[0-9a-f]{64}" required minLength={64} maxLength={64} autoComplete="off" /></label>
    <label className={label}>Existing change or incident ticket<input className={input} name="ticket_reference" required minLength={3} maxLength={160} /></label>
    <label className={label}>Baseline evidence summary<textarea className={input} name="baseline_summary" required minLength={20} maxLength={2000} rows={3} /></label>
    <label className={label}>Owner-approved rollback plan<textarea className={input} name="rollback_plan" required minLength={20} maxLength={2000} rows={3} /></label>
  </div>;
}
function EvidenceFields() {
  return <div className="grid gap-3 sm:grid-cols-2">
    <label className={label}>Evidence artifact SHA-256<input className={input} name="artifact_sha256" pattern="[0-9a-f]{64}" required minLength={64} maxLength={64} autoComplete="off" /></label>
    <label className={label}>Evidence reference<input className={input} name="artifact_reference" required minLength={3} maxLength={160} /></label>
    <label className={label}>Observation time (with timezone)<input className={input} name="observed_at" required placeholder="2026-10-13T17:00:00Z" /></label>
    <label className={label}>Evidence and outcome note<textarea className={input} name="note" required minLength={20} maxLength={2000} rows={3} /></label>
  </div>;
}
function planData(data: FormData) {
  return Object.fromEntries(["baseline_sha256", "ticket_reference", "baseline_summary", "rollback_plan"].map(k => [k, field(data, k)]));
}
function evidenceData(data: FormData) {
  return Object.fromEntries(["artifact_sha256", "artifact_reference", "observed_at", "note"].map(k => [k, field(data, k)]));
}

export function ResolutionWorkbench({ incidentId, onRefresh }: { incidentId: string; onRefresh: () => Promise<void> }) {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [cases, setCases] = useState<Case[]>([]);
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [scopeIndex, setScopeIndex] = useState(0);
  const [family, setFamily] = useState("identity");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const base = `/api/v1/incidents/${incidentId}/resolution-workflows`;
  const load = useCallback(async () => {
    const [catalogue, list] = await Promise.all([
      apiFetch<Catalog>("/api/v1/resolution-playbooks"),
      apiFetch<{items: Case[]; required_scopes: Scope[]}>(base),
    ]);
    setCatalog(catalogue); setCases(list.items); setScopes(list.required_scopes);
  }, [base]);
  useEffect(() => { void load().catch((e: Error) => setError(e.message)); }, [load]);
  async function send(path: string, payload: Record<string, unknown>) {
    setBusy(true); setError(""); setNotice("");
    try {
      await apiFetch(path, {method: "POST", body: JSON.stringify(payload)});
      await load(); await onRefresh(); setNotice("Recorded in the audit trail. No endpoint action was executed by this form.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Recovery update failed");
      // Preserve the failure and show fresh revisions rather than retrying a mutation.
      try { await load(); } catch { /* The original error remains visible. */ }
    } finally { setBusy(false); }
  }
  function submit(event: FormEvent<HTMLFormElement>, path: string, values: (data: FormData) => Record<string, unknown>) {
    event.preventDefault(); const data = new FormData(event.currentTarget); void send(path, values(data));
  }
  const selected = scopes[scopeIndex];
  const chosenFamily = selected?.source_category === "security" ? family : selected?.source_category;
  const selectedPlaybook = catalog?.playbooks.find(p => p.family === chosenFamily);
  const alreadyExists = selected && cases.some(c => c.host_id === selected.host_id && c.source_category === selected.source_category);
  const canClose = scopes.length > 0 && cases.length === scopes.length && cases.every(c => c.state === "verified" && c.context_current && c.playbook_current);
  return <section className="panel space-y-5" data-testid="resolution-workbench">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><p className="eyebrow">Accountable human recovery</p><h2 className="mt-2 text-xl font-semibold">Guided resolution</h2></div>
      <button className={button} disabled={busy} onClick={() => { setError(""); void load().catch((e: Error) => setError(e.message)); }}>Refresh recovery</button>
    </div>
    <p className="text-sm leading-6 text-slate-400">These workflows record human-executed recovery using existing evidence references. They do not run commands, fetch files, scan artifacts, or prove an endpoint was repaired. An independent named analyst must approve the plan and verify the recorded results. Escalation does not mean resolution.</p>
    {error && <p role="alert" className="rounded border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-200">{error}</p>}
    {notice && <p role="status" className="text-sm text-emerald-300">{notice}</p>}
    {!catalog && !error && <p role="status">Loading recovery contracts…</p>}
    {catalog && !catalog.named_auth_configured && <p className="rounded border border-amber-400/30 p-3 text-sm text-amber-200">Demo is read-only for recovery. Configure at least two named analyst credentials to approve and verify real recovery records. Do not paste credentials or raw private evidence into these forms.</p>}
    {catalog && scopes.length > 0 && <details className="rounded-lg border border-line p-4" open={cases.length === 0}>
      <summary className="cursor-pointer font-medium">Start an evidence-bound recovery workflow</summary>
      <form className="mt-4 space-y-4" onSubmit={e => submit(e, base, data => ({...planData(data), host_id: selected?.host_id, source_category: selected?.source_category, family: chosenFamily}))}>
        <label className={label}>Affected host and finding category<select className={input} value={scopeIndex} onChange={e => setScopeIndex(Number(e.target.value))}>{scopes.map((s, i) => <option value={i} key={`${s.host_id}:${s.source_category}`}>{s.host_id} · {s.source_category}</option>)}</select></label>
        {selected?.source_category === "security" && <label className={label}>Concrete recovery family (required for unclassified security)<select className={input} value={family} onChange={e => setFamily(e.target.value)}>{catalog.playbooks.map(p => <option key={p.family} value={p.family}>{p.title}</option>)}</select></label>}
        {selectedPlaybook && <div className="rounded border border-line p-3 text-sm"><h3 className="font-medium">{selectedPlaybook.title}</h3><p className="mt-2 text-slate-400">Escalation expertise: {selectedPlaybook.escalation_team}</p><p className="mt-2 text-slate-400">Independent acceptance: {selectedPlaybook.verification}</p></div>}
        <PlanFields />
        {alreadyExists && <p className="text-sm text-amber-200">This scope already has a workflow. Use its rebaseline form to require a fresh approval without erasing audit history.</p>}
        <button className={button} disabled={busy || !catalog.named_auth_configured || !selectedPlaybook || !!alreadyExists}>Request recovery approval</button>
      </form>
    </details>}
    {cases.map(c => {
      const playbook = catalog?.playbooks.find(p => p.family === c.family);
      const checkpoint = playbook?.checkpoints[c.checkpoints.length];
      const prefix = `${base}/${c.workflow_id}`;
      const owner = catalog?.actor === c.owner;
      const fresh = c.context_current && c.playbook_current;
      return <article key={c.workflow_id} className="space-y-4 rounded-lg border border-line p-4" data-testid="recovery-case">
        <div className="flex flex-wrap justify-between gap-2"><h3 className="font-semibold">{playbook?.title || c.family}</h3><span className="rounded border border-cyan/30 px-2 py-1 text-xs text-cyan" data-testid="recovery-state">{c.state.replaceAll("_", " ")}</span></div>
        <p className="text-xs text-slate-400">Host: {c.host_id} · source: {c.source_category} · operator: {c.owner} · approver: {c.approver || "pending"} · verifier: {c.verifier || "pending"} · revision {c.revision}</p>
        {!fresh && <p role="alert" className="text-sm text-amber-200">Evidence or playbook changed. Prior approval cannot authorize more work or closure. Rebaseline and obtain a fresh approval.</p>}
        <details><summary className="cursor-pointer text-sm text-cyan">Review baseline and rollback plan</summary><dl className="mt-2 space-y-2 break-words text-sm text-slate-400"><dt>Existing ticket</dt><dd>{c.plan.ticket_reference}</dd><dt>Baseline evidence SHA-256</dt><dd className="font-mono text-xs">{c.plan.baseline_sha256}</dd><dt>Baseline summary</dt><dd>{c.plan.baseline_summary}</dd><dt>Rollback plan</dt><dd>{c.plan.rollback_plan}</dd></dl></details>
        <ol className="space-y-3">{playbook?.checkpoints.map((s, i) => <li key={s.key} className="rounded border border-line p-3 text-sm"><h4 className="font-medium">{i + 1}. {s.title}{c.checkpoints[i] ? ` — ${c.checkpoints[i].outcome.replaceAll("_", " ")}` : ""}</h4><p className="mt-1 text-slate-400">{s.instruction}</p><p className="mt-2 text-slate-300">Acceptance: {s.acceptance}</p>{c.checkpoints[i] && <details className="mt-2"><summary className="cursor-pointer text-cyan">Recorded evidence</summary><p className="mt-2">{c.checkpoints[i].note}</p><p className="mt-1 break-all font-mono text-xs">{c.checkpoints[i].artifact_reference} · {c.checkpoints[i].artifact_sha256}</p></details>}</li>)}</ol>
        {c.state === "awaiting_approval" && <form className="space-y-3" onSubmit={e => submit(e, `${prefix}/approve`, d => ({expected_revision: c.revision, note: field(d, "note")}))}><label className={label}>Independent approval rationale<textarea className={input} name="note" required minLength={20} maxLength={2000} /></label><button className={button} disabled={busy || owner || !fresh}>Approve recovery plan</button>{owner && <p className="text-xs text-slate-400">A different named analyst must sign in to approve this plan.</p>}</form>}
        {checkpoint && ["approved", "in_progress"].includes(c.state) && <form className="space-y-3" onSubmit={e => submit(e, `${prefix}/checkpoints`, d => ({...evidenceData(d), expected_revision: c.revision, checkpoint: checkpoint.key, outcome: field(d, "outcome")}))}><h4 className="font-medium">Record checkpoint: {checkpoint.title}</h4><EvidenceFields /><label className={label}>Checkpoint outcome<select className={input} name="outcome"><option value="done">Completed with evidence</option><option value="failed">Failed — block further steps</option>{checkpoint.conditional && <option value="not_applicable">Not applicable — evidence and rationale required</option>}</select></label><button className={button} disabled={busy || !owner || !fresh}>Record checkpoint evidence</button></form>}
        {c.state === "awaiting_verification" && <form className="space-y-3" onSubmit={e => submit(e, `${prefix}/verify`, d => ({...evidenceData(d), expected_revision: c.revision}))}><h4 className="font-medium">Independent recovery verification</h4><p className="text-sm text-slate-400">{playbook?.verification} Provide a new post-recovery artifact, not a reused baseline or checkpoint hash.</p><EvidenceFields /><button className={button} disabled={busy || owner || !fresh}>Verify recorded recovery</button></form>}
        {c.state === "verified" && c.verification && <p className="text-sm text-emerald-300">Independently attested by {c.verifier}. Evidence reference: {c.verification.artifact_reference}. This is human verification, not an automated endpoint scan.</p>}
        {c.escalation && <div className="rounded border border-amber-400/30 p-3 text-sm text-amber-200"><p>Escalated to {c.escalation.assigned_to} · existing ticket {c.escalation.ticket_reference} · follow-up {formatTime(c.escalation.due_at)}</p><p className="mt-2">{c.escalation.note}</p><p className="mt-2">{c.escalation.acknowledged_by ? `Acknowledged by ${c.escalation.acknowledged_by}; incident remains unresolved.` : "Awaiting named recipient acknowledgement; incident remains unresolved."}</p>{!c.escalation.acknowledged_by && <form className="mt-3 space-y-3" onSubmit={e => submit(e, `${prefix}/acknowledge`, d => ({expected_revision: c.revision, note: field(d,"note")}))}><label className={label}>Escalation acknowledgement<textarea className={input} name="note" required minLength={20} maxLength={2000} /></label><button className={button} disabled={busy || catalog?.actor !== c.escalation.assigned_to}>Acknowledge escalation</button></form>}</div>}
        {!["verified", "escalated"].includes(c.state) && <details><summary className="cursor-pointer text-sm text-amber-200">Escalate blocked or unsafe recovery</summary><form className="mt-3 space-y-3" onSubmit={e => submit(e, `${prefix}/escalate`, d => ({expected_revision: c.revision, assigned_to: field(d,"assigned_to"), ticket_reference: field(d,"ticket_reference"), due_at: field(d,"due_at"), note: field(d,"note")}))}><label className={label}>Assigned named analyst<input className={input} name="assigned_to" required maxLength={128} /></label><label className={label}>Existing escalation ticket<input className={input} name="ticket_reference" required minLength={3} maxLength={160} /></label><label className={label}>Follow-up due (timezone required, within seven days)<input className={input} name="due_at" required placeholder="2026-10-14T17:00:00Z" /></label><label className={label}>Reason and required assistance<textarea className={input} name="note" required minLength={20} maxLength={2000} /></label><button className={button} disabled={busy || !owner}>Record escalation</button><p className="text-xs text-slate-400">This records a ticket reference; it does not create an external ticket or send a notification.</p></form></details>}
        <details><summary className="cursor-pointer text-sm text-cyan">Rebaseline and request fresh approval</summary><form className="mt-3 space-y-3" onSubmit={e => submit(e, `${prefix}/rebaseline`, d => ({...planData(d), expected_revision: c.revision, ...(c.source_category === "security" ? {family: field(d,"family")} : {})}))}><p className="text-sm text-slate-400">Use a new baseline artifact. Prior work stays in the audit trail; approvals, checkpoints and verification are reset for the new evidence.</p>{c.source_category === "security" && <label className={label}>Reclassified concrete recovery family<select className={input} name="family" defaultValue={c.family}>{catalog?.playbooks.map(p => <option key={p.family} value={p.family}>{p.title}</option>)}</select></label>}<PlanFields /><button className={button} disabled={busy || !owner}>Request reapproval with new baseline</button></form></details>
      </article>;
    })}
    {cases.length > 0 && <form className="space-y-3 border-t border-line pt-4" onSubmit={e => submit(e, `/api/v1/incidents/${incidentId}/close-verified-recovery`, d => ({expected_revision: cases.reduce((sum,c) => sum + c.revision,0), note: field(d,"note")}))}><label className={label}>Final incident closure rationale<textarea className={input} name="note" required minLength={20} maxLength={2000} /></label><button className={button} disabled={busy || !canClose}>Close independently verified recovery</button><p className="text-xs text-slate-400">Every host/category must be verified against current evidence. Active endpoint actions and escalations block closure.</p></form>}
  </section>;
}
