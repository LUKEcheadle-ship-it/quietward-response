import type { Metadata } from "next";
import { Sidebar } from "@/components/sidebar";
import "./globals.css";

export const metadata: Metadata = { title: "QuietWard Response", description: "Incident investigation and response coordination" };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body><Sidebar/><main className="main"><div className="topline"><span>CONTROL PLANE</span><div><i/> Live telemetry</div></div>{children}</main></body></html>;
}
