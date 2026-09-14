export function LoadingState() {
  return <div className="panel animate-pulse text-sm text-slate-400">Loading current response state…</div>;
}

export function ErrorState({ message }: { message: string }) {
  return <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-5 text-sm text-rose-200">{message}. Confirm the API is running at <code>http://localhost:8002</code>.</div>;
}

export function EmptyState({ message }: { message: string }) {
  return <div className="panel space-y-3 text-sm text-slate-400"><p>{message}</p><p>To explore synthetic incidents, run <code>python scripts/quick_demo.py</code> from your Response checkout. An incident groups related observations into one investigation.</p><p>The demo works independently. Pair QuietWard to ingest verified findings from your own monitor.</p></div>;
}
