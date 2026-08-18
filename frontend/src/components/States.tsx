export function LoadingState() {
  return <div className="panel animate-pulse text-sm text-slate-400">Loading current response state…</div>;
}

export function ErrorState({ message }: { message: string }) {
  return <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-5 text-sm text-rose-200">{message}. Confirm the API is running at <code>http://localhost:8002</code>.</div>;
}

export function EmptyState({ message }: { message: string }) {
  return <div className="panel text-sm text-slate-400">{message}</div>;
}
