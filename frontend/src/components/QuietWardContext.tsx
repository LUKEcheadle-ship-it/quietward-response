import type { IncidentDetail } from "@/lib/types";

function asStrings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.length > 0);
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function QuietWardContext({ incident }: { incident: IncidentDetail }) {
  const events = incident.events.filter(
    (event) =>
      event.source.toLowerCase() === "quietward" &&
      event.metadata.quietward_response_context_version === "1.0" &&
      event.metadata.observation_only_source === true &&
      event.metadata.executable_authority === false,
  );
  if (events.length === 0) return null;

  const scores = events
    .map((event) => asNumber(event.metadata.quietward_score))
    .filter((value): value is number => value !== null);
  const highestScore = scores.length > 0 ? Math.max(...scores) : null;
  const findingIds = Array.from(
    new Set(
      events
        .map((event) => event.metadata.quietward_finding_id)
        .filter((value): value is string => typeof value === "string" && value.length > 0),
    ),
  );
  const hints = Array.from(
    new Set(events.flatMap((event) => asStrings(event.metadata.investigation_hints))),
  ).sort();
  const signalKinds = Array.from(
    new Set(events.flatMap((event) => asStrings(event.evidence.event_kinds))),
  ).sort();
  const correlationCodes = Array.from(
    new Set(events.flatMap((event) => asStrings(event.evidence.correlation_signal_codes))),
  ).sort();
  const subjectIds = Array.from(
    new Set(
      events
        .map((event) => event.evidence.subject_hmac_sha256)
        .filter((value): value is string => typeof value === "string" && /^[0-9a-f]{32}$/.test(value)),
    ),
  );

  return (
    <section className="panel">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="eyebrow">QuietWard context</p>
          <h2 className="mt-2 text-lg font-semibold text-white">Observation-only detector handoff</h2>
          <p className="muted mt-2 text-sm">
            This incident includes privacy-preserving context produced by QuietWard. Response receives correlation metadata, not QuietWard execution authority or raw finding subjects.
          </p>
        </div>
        <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-[10px] uppercase tracking-wider text-emerald-300">
          No execution authority
        </span>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-3">
        <div className="rounded-lg border border-line bg-slate-950/40 p-3">
          <p className="text-xs text-slate-500">QuietWard findings</p>
          <p className="mt-1 text-lg font-semibold text-white">{findingIds.length || events.length}</p>
        </div>
        <div className="rounded-lg border border-line bg-slate-950/40 p-3">
          <p className="text-xs text-slate-500">Highest detector score</p>
          <p className="mt-1 text-lg font-semibold text-white">
            {highestScore === null ? "—" : `${Math.round(highestScore)}/100`}
          </p>
        </div>
        <div className="rounded-lg border border-line bg-slate-950/40 p-3">
          <p className="text-xs text-slate-500">Privacy-keyed subjects</p>
          <p className="mt-1 text-lg font-semibold text-white">{subjectIds.length}</p>
        </div>
      </div>

      {signalKinds.length > 0 && (
        <div className="mt-4">
          <p className="text-xs uppercase tracking-wider text-slate-500">Observed signal types</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {signalKinds.map((kind) => (
              <span key={kind} className="rounded border border-cyan/20 bg-cyan/10 px-2 py-1 text-xs text-cyan">
                {kind.replaceAll("_", " ")}
              </span>
            ))}
          </div>
        </div>
      )}

      {hints.length > 0 && (
        <div className="mt-4">
          <p className="text-xs uppercase tracking-wider text-slate-500">Suggested investigation lanes</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {hints.map((hint) => (
              <span key={hint} className="rounded border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-300">
                {hint.replaceAll("_", " ")}
              </span>
            ))}
          </div>
        </div>
      )}

      {correlationCodes.length > 0 && (
        <details className="mt-4 rounded-lg border border-line bg-slate-950/30 p-3">
          <summary className="cursor-pointer text-xs font-medium text-slate-300">Detector correlation signals</summary>
          <div className="mt-2 flex flex-wrap gap-2">
            {correlationCodes.map((code) => (
              <code key={code} className="rounded bg-black/20 px-2 py-1 text-[11px] text-slate-400">
                {code}
              </code>
            ))}
          </div>
        </details>
      )}
    </section>
  );
}
