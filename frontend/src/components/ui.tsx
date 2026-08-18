import Link from "next/link";
import type { Severity } from "@/lib/types";
import { Icon } from "./icons";

export function PageHeader({ eyebrow, title, description, children }: { eyebrow?: string; title: string; description?: string; children?: React.ReactNode }) {
  return <header className="page-header"><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h1>{title}</h1>{description && <p>{description}</p>}</div>{children}</header>;
}

export function SeverityBadge({ value }: { value: Severity | string }) { return <span className={`badge severity ${value}`}>{value}<i/></span>; }
export function StatusBadge({ value }: { value: string }) { return <span className={`badge status ${value}`}>{value}</span>; }

export function EmptyState({ label }: { label: string }) {
  return <div className="empty"><div className="empty-icon"><Icon name="pulse" size={26}/></div><h3>No {label} yet</h3><p>Run <code>python scripts/seed_demo.py</code> to exercise the full pipeline.</p></div>;
}

export function IncidentLink({ id, children }: { id: string; children: React.ReactNode }) {
  return <Link className="row-link" href={`/incidents/${id}`}>{children}<Icon name="arrow" size={16}/></Link>;
}
