import type { IncidentDetail } from "@/lib/types";

function asStrings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.length > 0);
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asAllowedString(value: unknown, allowed: readonly string[]): string | null {
  return typeof value === "string" && allowed.includes(value) ? value : null;
}

function highestRanked(values: Array<string | null>, ranking: readonly string[]): string | null {
  let selected: string | null = null;
  let selectedRank = -1;
  for (const value of values) {
    if (value === null) continue;
    const rank = ranking.indexOf(value);
    if (rank > selectedRank) {
      selected = value;
      selectedRank = rank;
    }
  }
  return selected;
}

const CONTEXT_VERSIONS = ["1.0", "1.1"] as const;
const RESPONSE_PRIORITIES = ["routine", "elevated", "urgent"] as const;
const EVIDENCE_STRENGTHS = ["limited", "corroborated", "strong"] as const;

export function QuietWardContext({ incident }: { incident: IncidentDetail }) {
  const events = incident.events.filter((event) => {
    const contextVersion = event.metadata.quietward_response_context_version;
    return (
      event.source.toLowerCase() === "quietward" &&
      typeof contextVersion === "string" &&
      CONTEXT_VERSIONS.includes(contextVersion as (typeof CONTEXT_VERSIONS)[number]) &&
      event.metadata.observation_only_source === true &&
      event.metadata.executable_authority === false
    );
  });
  if (events.length === 0) return null;

  const guidedEvents = events.filter(
    (event) => event.metadata.quietward_response_context_version === "1.1",
  );
  const responsePriority = highestRanked(
    guidedEvents.map((event) =>
      asAllowedString(event.metadata.response_priority, RESPONSE_PRIORITIES),
    ),
    RESPONSE_PRIORITIES,
  );
  const evidenceStrength = highestRanked(
    guidedEvents.map((event) =>
      asAllowedString(event.metadata.evidence_strength, EVIDENCE_STRENGTHS),
    ),
    EVIDENCE_STRENGTHS,
  );
  const playbooks = Array.from(
    new Set(
      guidedEvents
        .map((event) => event.metadata.recommended_playbook)
        .filter(
          (value): value is string =>
            typeof value === "string" && /^[a-z0-9_]{1,64}$/.test(value),
        ),
    ),
  ).sort();

  const scores = events
    .map((event) => asNumber(event.metadata.quietward_score))
    .filter((value): value is number => value !== null);
  const highestScore = scores.length > 0 ? Math.max(...scores) : null;
  const findingIds = Array.from(
    new Set(
      events
        .map((event) => event.metadata.quietward_finding_hmac_sha256)
        .filter(
          (value): value is string =>
            typeof value === "string" && /^[0-9a-f]{32}$/.test(value),
        ),
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
  const provenance = events
    .map((event) => ({
      cycle:
        typeof event.metadata.quietward_source_cycle_id === "number"
          ? event.metadata.quietward_source_cycle_id
          : null,
      hash:
        typeof event.metadata.quietward_source_chain_hash === "string" &&
        /^[0-9a-f]{64}$/.test(event.metadata.quietward_source_chain_hash)
          ? event.metadata.quietward_source_chain_hash
          : null,
    }))
    .filter((item) => item.cycle !== null && item.hash !== null);
  const uniqueProvenance = Array.from(
    new Map(provenance.map((item) => [`${item.cycle}:${item.hash}`, item])).values(),
  );

  return (
    <section className="panel">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="eyebrow">QuietWard context</p>
          <h2 className="mt-2 text-lg font-semibold text-white">Observation-only detector handoff</h2>
          <p className="muted mt-2 text-sm">
            This incident includes privacy-preserving context produced by QuietWard. Response receives correlation metadata, not QuietWard execution authority, raw finding identifiers, or raw finding subjects.
          </p>
        </div>
        <span className="rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-[10px] uppercase tracking-wider text-emerald-300">
          No execution authority
        </span>
      </div>

      {guidedEvents.length > 0 && (
        <div className="mt-5 rounded-xl border border-cyan/20 bg-cyan/5 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-xs uppercase tracking-wider text-cyan">Guided triage profile</p>
              <p className="mt-1 text-sm text-slate-300">
                QuietWard v1.1 supplied coarse response guidance so the analyst can choose the next bounded investigation faster.
              </p>
            </div>
            <span className="rounded border border-cyan/20 bg-slate-950/40 px-2 py-1 text-[10px] uppercase tracking-wider text-cyan">
              Context v1.1
            </span>
          </div>
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg border border-line bg-slate-950/40 p-3">
              <p className="text-xs text-slate-500">Response priority</p>
              <p className="mt-1 text-base font-semibold capitalize text-white">
                {responsePriority ?? "Unspecified"}
              </p>
            </div>
            <div className="rounded-lg border border-line bg-slate-950/40 p-3">
              <p className="text-xs text-slate-500">Evidence strength</p>
              <p className="mt-1 text-base font-semibold capitalize text-white">
                {evidenceStrength ?? "Unspecified"}
              </p>
            </div>
          </div>
          {playbooks.length > 0 && (
            <div className="mt-4">
              <p className="text-xs uppercase tracking-wider text-slate-500">Recommended playbook</p>
              <div className="mt-2 flex flex-wrap gap-2">
                {playbooks.map((playbook) => (
                  <span key={playbook} className="rounded border border-cyan/20 bg-cyan/10 px-2 py-1 text-xs text-cyan">
                    {playbook.replaceAll("_", " ")}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

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

      {uniqueProvenance.length > 0 && (
        <div className="mt-4 rounded-lg border border-cyan/15 bg-cyan/5 p-3">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs uppercase tracking-wider text-slate-500">Evidence-chain provenance</p>
            <span className="text-[10px] uppercase tracking-wider text-cyan">Traceable to QuietWard</span>
          </div>
          <div className="mt-2 space-y-2">
            {uniqueProvenance.map((item) => (
              <div key={`${item.cycle}:${item.hash}`} className="flex flex-wrap items-center justify-between gap-2 font-mono text-[11px] text-slate-400">
                <span>cycle {item.cycle}</span>
                <span title={item.hash ?? undefined}>chain {item.hash?.slice(0, 16)}…</span>
              </div>
            ))}
          </div>
        </div>
      )}

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
