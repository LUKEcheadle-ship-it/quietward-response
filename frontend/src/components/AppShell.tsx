"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

const links = [
  ["Overview", "/"],
  ["Incidents", "/incidents"],
  ["Hosts", "/hosts"],
  ["Agents", "/agents"],
  ["Events", "/events"]
];

export function AppShell({ children }: { children: ReactNode }) {
  const path = usePathname();
  return (
    <div className="min-h-screen bg-ink text-slate-100">
      <header className="sticky top-0 z-30 border-b border-line/80 bg-ink/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1500px] items-center justify-between px-6 py-4">
          <Link href="/" className="flex items-center gap-3">
            <span className="grid h-9 w-9 place-items-center rounded-lg border border-cyan/30 bg-cyan/10 text-sm font-black text-cyan">QR</span>
            <span>
              <span className="block text-sm font-semibold tracking-wide">QuietWard Response</span>
              <span className="block text-[11px] uppercase tracking-[0.18em] text-slate-500">Investigation control plane</span>
            </span>
          </Link>
          <div className="flex items-center gap-3 text-xs text-slate-400">
            <span className="hidden rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-emerald-300 sm:inline">Local development</span>
            <span className="rounded-full border border-cyan/20 bg-cyan/10 px-3 py-1 text-cyan">Controlled response · approval required</span>
          </div>
        </div>
        <nav className="mx-auto flex max-w-[1500px] gap-1 px-6">
          {links.map(([label, href]) => {
            const active = href === "/" ? path === "/" : path.startsWith(href);
            return (
              <Link key={href} href={href} className={`border-b-2 px-4 py-3 text-sm transition ${active ? "border-cyan text-cyan" : "border-transparent text-slate-400 hover:text-slate-100"}`}>
                {label}
              </Link>
            );
          })}
        </nav>
      </header>
      <main className="mx-auto max-w-[1500px] px-6 py-8">{children}</main>
    </div>
  );
}
