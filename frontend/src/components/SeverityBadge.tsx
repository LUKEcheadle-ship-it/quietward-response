import type { Severity } from "@/lib/types";

const styles: Record<Severity, string> = {
  critical: "border-rose-400/30 bg-rose-500/15 text-rose-300",
  high: "border-orange-400/30 bg-orange-500/15 text-orange-300",
  medium: "border-amber-400/30 bg-amber-500/15 text-amber-200",
  low: "border-sky-400/30 bg-sky-500/15 text-sky-300",
  informational: "border-slate-400/30 bg-slate-500/15 text-slate-300"
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`inline-flex rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider ${styles[severity]}`}>{severity}</span>;
}
