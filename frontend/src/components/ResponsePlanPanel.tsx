import type { ResponsePlan, ResponsePlanStep } from "@/lib/types";

function stepLabel(step: ResponsePlanStep): string {
  if (step.executable_action_type) return "Executable · approval required";
  if (step.state === "planned") return "Planned · not executable";
  if (step.state === "blocked") return "Blocked · future capability";
  if (step.state === "manual") return step.requires_approval ? "Manual · approval advised" : "Manual";
  return "Available guidance";
}

function StepList({ title, steps }: { title: string; steps: ResponsePlanStep[] }) {
  if (!steps.length) return null;
  return (
    <div>
      <h3 className="text-sm font-semibold text-white">{title}</h3>
      <div className="mt-3 space-y-3">
        {steps.map((step) => (
          <div key={step.step_id} className="rounded-lg border border-line bg-slate-950/45 p-3">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <p className="text-sm font-medium text-white">{step.title}</p>
              <span className="rounded border border-line px-2 py-1 text-[10px] uppercase tracking-wide text-slate-400">
                {stepLabel(step)}
              </span>
            </div>
            <p className="mt-2 text-xs leading-5 text-slate-400">{step.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ResponsePlanPanel({ plan }: { plan: ResponsePlan }) {
  return (
    <section className="panel">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="eyebrow">Response plan</p>
          <h2 className="mt-2 text-xl font-semibold text-white">Incident containment and recovery plan</h2>
          <p className="mt-2 font-mono text-xs text-slate-500">{plan.plan_id}</p>
        </div>
        <div className="text-right">
          <span className="rounded border border-cyan/20 bg-cyan/10 px-2 py-1 text-[10px] uppercase tracking-wide text-cyan">
            {plan.priority} priority
          </span>
          <p className="mt-2 text-xs text-slate-500">Families: {plan.attack_families.join(", ")}</p>
        </div>
      </div>

      <div className="mt-5 rounded-lg border border-line bg-slate-950/35 p-4">
        <h3 className="text-sm font-semibold text-white">Objectives</h3>
        <ul className="mt-3 space-y-2">
          {plan.objectives.map((objective) => (
            <li key={objective} className="flex gap-2 text-sm text-slate-400">
              <span className="text-cyan">•</span>{objective}
            </li>
          ))}
        </ul>
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-3">
        <StepList title="Investigate" steps={plan.investigation_steps} />
        <StepList title="Contain" steps={plan.containment_steps} />
        <StepList title="Recover" steps={plan.recovery_steps} />
      </div>

      {plan.escalation_conditions.length > 0 && (
        <div className="mt-6 border-t border-line pt-5">
          <h3 className="text-sm font-semibold text-amber-200">Escalation conditions</h3>
          <ul className="mt-3 space-y-2">
            {plan.escalation_conditions.map((condition) => (
              <li key={condition} className="flex gap-2 text-sm text-slate-400">
                <span className="text-amber-300">•</span>{condition}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="mt-6 border-t border-line pt-5 text-xs leading-5 text-slate-500">
        <p>
          Executable actions: {plan.executable_actions.length ? plan.executable_actions.join(", ") : "none for this incident"}.
          Planned and manual steps are guidance, not hidden remote commands.
        </p>
      </div>
    </section>
  );
}
