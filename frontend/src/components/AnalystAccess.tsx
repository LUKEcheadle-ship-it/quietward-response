"use client";
import { useEffect, useState, type ReactNode, type FormEvent } from "react";
import { apiFetch, setAnalystToken } from "@/lib/api";

export function AnalystAccess({ children }: { children: ReactNode }) {
  const [required, setRequired] = useState<boolean | null>(null);
  const [signedIn, setSignedIn] = useState(false);
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    apiFetch<{authentication_required: boolean}>("/api/v1/access")
      .then(data => setRequired(data.authentication_required))
      .catch((e: Error) => setError(e.message));
  }, []);
  async function signIn(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(""); setAnalystToken(token);
    try {
      await apiFetch("/api/v1/actions/registry");
      setToken(""); setSignedIn(true);
    } catch (e) {
      setAnalystToken(""); setError(e instanceof Error ? e.message : "Sign-in failed");
    } finally { setBusy(false); }
  }
  if (required === null) return <div className="panel" role="status">{error || "Checking analyst access…"}</div>;
  if (required && !signedIn) return <form onSubmit={signIn} className="panel mx-auto max-w-lg space-y-4">
    <h1 className="text-xl font-semibold">Analyst sign-in</h1>
    <p className="muted">Enter your assigned analyst credential. It stays in memory until logout or page reload.</p>
    <label className="block">Analyst credential<input className="mt-2 block w-full rounded border border-line bg-slate-950 p-3"
      type="password" autoComplete="off" minLength={32} maxLength={512} required value={token} onChange={e => setToken(e.target.value)} /></label>
    {error && <p role="alert" className="text-rose-300">{error}</p>}
    <button disabled={busy} className="rounded bg-cyan px-4 py-2 text-slate-950">{busy ? "Signing in…" : "Sign in"}</button>
  </form>;
  return <>{required && <div className="mb-5 flex justify-end"><button className="text-sm text-cyan" onClick={() => { setAnalystToken(""); setSignedIn(false); }}>Sign out</button></div>}{children}</>;
}
