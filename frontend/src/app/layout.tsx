import type { Metadata } from "next";
import type { ReactNode } from "react";

import { AppShell } from "@/components/AppShell";
import { AnalystAccess } from "@/components/AnalystAccess";
import "./globals.css";

export const metadata: Metadata = {
  title: "QuietWard Response",
  description: "Event-driven incident investigation and response coordination"
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body><AppShell><AnalystAccess>{children}</AnalystAccess></AppShell></body>
    </html>
  );
}
