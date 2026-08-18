"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Icon } from "./icons";

const nav = [["Overview", "/", "overview"], ["Incidents", "/incidents", "incidents"], ["Hosts", "/hosts", "hosts"], ["Events", "/events", "events"]];

export function Sidebar() {
  const path = usePathname();
  return <aside className="sidebar">
    <div className="brand"><div className="brand-mark"><Icon name="pulse" size={22}/></div><div><strong>QUIETWARD</strong><span>RESPONSE</span></div></div>
    <nav>{nav.map(([label, href, icon]) => {
      const active = href === "/" ? path === "/" : path.startsWith(href);
      return <Link href={href} className={active ? "active" : ""} key={href}><Icon name={icon}/><span>{label}</span>{active && <i/>}</Link>;
    })}</nav>
    <div className="sidebar-foot"><div className="status-dot"/><div><strong>System operational</strong><span>Phase 1 · Observe only</span></div></div>
  </aside>;
}
