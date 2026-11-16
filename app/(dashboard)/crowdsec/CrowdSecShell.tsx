"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Banner } from "@/components/ui/Banner";
import { PageHeader } from "@/components/ui/PageHeader";
import { cn } from "@/lib/utils";

const TABS = [
  { href: "/crowdsec", label: "Dashboard" },
  { href: "/crowdsec/alerts", label: "Alerts" },
  { href: "/crowdsec/decisions", label: "Decisions" },
  { href: "/crowdsec/whitelists", label: "Whitelists" },
  { href: "/crowdsec/settings", label: "Settings" },
] as const;

export type CrowdSecShellProps = {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  /** CrowdSec is configured on this instance (CROWDSEC_BOUNCER_KEY is set). */
  configured: boolean;
  /** waf:read, for the breadcrumb's link to Security events. */
  canOpenSecurity: boolean;
  children: ReactNode;
};

/** The header and tabs every CrowdSec page shares, and the notice when CrowdSec is not set up. */
export function CrowdSecShell({ title, description, actions, configured, canOpenSecurity, children }: CrowdSecShellProps) {
  const pathname = usePathname();
  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        className="mb-0"
        breadcrumb={["Observe", canOpenSecurity ? { label: "Security events", href: "/security" } : "Security events", "CrowdSec"]}
        title={title}
        description={description}
        actions={actions}
      />
      <nav aria-label="CrowdSec" className="flex flex-wrap gap-1 border-b border-line">
        {TABS.map((tab) => {
          const active = pathname === tab.href;
          return (
            <Link
              key={tab.href}
              href={tab.href}
              aria-current={active ? "page" : undefined}
              className={cn(
                "-mb-px border-b-2 px-3 py-2 text-[13px] font-medium",
                active ? "border-brand text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"
              )}
            >
              {tab.label}
            </Link>
          );
        })}
      </nav>
      {!configured && (
        <Banner tone="info" title="CrowdSec is not set up on this instance.">
          Start the stack with the CrowdSec overlay (
          <span className="num">docker compose -f docker-compose.yml -f docker-compose.crowdsec.yml up -d</span>) and set
          CROWDSEC_BOUNCER_KEY, CROWDSEC_MACHINE_PASSWORD and CROWDSEC_DB_PASSWORD in .env. See the CrowdSec documentation.
        </Banner>
      )}
      {children}
    </div>
  );
}

/** A CrowdSec error as a banner. */
export function CrowdSecError({ message }: { message: string }) {
  return (
    <Banner tone="bad" title="CrowdSec did not answer.">
      {message}
    </Banner>
  );
}
