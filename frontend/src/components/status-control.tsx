"use client";

import { useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001/api/v1";

export function StatusControl({ incidentId, initial }: { incidentId: string; initial: string }) {
  const [status, setStatus] = useState(initial);
  const [saving, setSaving] = useState(false);
  async function change(value: string) {
    setSaving(true);
    const response = await fetch(`${API}/incidents/${incidentId}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ status: value }) });
    if (response.ok) setStatus(value);
    setSaving(false);
  }
  return <label className="status-control"><span>Status</span><select value={status} disabled={saving} onChange={event => change(event.target.value)}>{["new", "investigating", "contained", "resolved", "dismissed"].map(item => <option key={item}>{item}</option>)}</select></label>;
}
