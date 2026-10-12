"use client";
import { useEffect, useState } from "react";
import { apiFetch, formatTime } from "@/lib/api";
type Bridge = {state: string; last_received_at: string | null; received_last_24h: number; source_version: string | null; note: string};

export function BridgeStatus() {
  const [data, setData] = useState<Bridge | null>(null);
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  useEffect(()=>{
    let active=true;
    async function load() {
      try { const value=await apiFetch<Bridge>("/api/v1/overview/bridge"); if(active){setData(value);setError("");} }
      catch(e){if(active)setError(e instanceof Error ? e.message : "Bridge status unavailable");}
    }
    void load(); const timer=setInterval(()=>void load(),30000);
    return ()=>{active=false;clearInterval(timer);};
  },[refresh]);
  return <section className="panel"><div className="flex justify-between"><h2 className="text-lg font-semibold">QuietWard bridge activity</h2><button className="text-sm text-cyan" onClick={()=>setRefresh(v=>v+1)}>Refresh</button></div>
    {error ? <p role="alert" className="mt-3 text-rose-300">{error}</p> : data ? <>
      <p className="mt-3">{data.state === "no_data" ? "No QuietWard observations received yet" : data.state === "recent" ? "Recent observations received" : "No recent observations — bridge may be idle"}</p>
      <p className="muted mt-2">Last received: {data.last_received_at ? formatTime(data.last_received_at) : "None"} · Last 24 hours: {data.received_last_24h} · Source version: {data.source_version || "Unknown"}</p>
      <p className="muted mt-2">{data.note}</p>
    </> : <p className="muted mt-3">Loading bridge activity…</p>}</section>;
}
