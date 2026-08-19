import type { Metadata } from "next";
import { Suspense, type ReactNode } from "react";
import { NuqsAdapter } from "nuqs/adapters/next/app";
import "./globals.css";
import { Geist } from "next/font/google";
import { cn } from "@/lib/utils";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryProvider } from "@/components/firm/QueryProvider";
import { HostedAuthBoundary } from "@/components/auth/HostedAuthBoundary";

const geist = Geist({subsets:['latin'],variable:'--font-sans'});

export const metadata: Metadata = {
  title: "SecScanMonitor | Firm Control Plane",
  description: "Evidence-first operating surface for SecScanMonitor.",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en" className={cn("dark font-sans", geist.variable)}>
      <body>
        <QueryProvider>
          <TooltipProvider>
            <NuqsAdapter>
              <HostedAuthBoundary><Suspense fallback={<main className="route-loading">Loading SecScanMonitor…</main>}>{children}</Suspense></HostedAuthBoundary>
            </NuqsAdapter>
          </TooltipProvider>
        </QueryProvider>
      </body>
    </html>
  );
}
