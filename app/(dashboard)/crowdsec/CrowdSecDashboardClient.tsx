"use client";

import dynamic from "next/dynamic";
import { useRouter } from "next/navigation";
import { Banner } from "@/components/ui/Banner";
import { KpiTile } from "@/components/ui/KpiTile";
import { SectionCard } from "@/components/ui/SectionCard";
import { SegmentedControl } from "@/components/ui/SegmentedControl";
import { Skeleton } from "@/components/ui/skeleton";
import { StackedBarChart } from "@/components/ui/StackedBarChart";
import { TopList } from "@/components/ui/TopList";
import { formatCount } from "@/components/ui/chart-format";
import type { CrowdSecDashboard } from "@/src/lib/crowdsec/dashboard";
import { CROWDSEC_RANGES, DASHBOARD_ALERT_LIMIT, type CrowdSecRange } from "@/src/lib/crowdsec/ranges";
import { countryName } from "../analytics/present";
import { CrowdSecError, CrowdSecShell } from "./CrowdSecShell";

const WorldMap = dynamic(() => import("../analytics/WorldMapInner"), {
  ssr: false,
  loading: () => <Skeleton className="h-[300px] w-full rounded-lg" />,
});

const SERIES_COLORS = ["var(--waf)", "var(--rl)", "var(--access)", "var(--err4)", "var(--served2)", "var(--soft)"];

export type CrowdSecDashboardProps = {
  range: CrowdSecRange;
  configured: boolean;
  dashboard: CrowdSecDashboard | null;
  error: string | null;
  protectedHosts: number;
  enabledHosts: number;
  canOpenSecurity: boolean;
};

export default function CrowdSecDashboardClient({ range, configured, dashboard, error, protectedHosts, enabledHosts, canOpenSecurity }: CrowdSecDashboardProps) {
  const router = useRouter();
  const alertsHref = (filter: string, value: string) => `/crowdsec/alerts?range=${range}&${filter}=${encodeURIComponent(value)}`;
  return (
    <CrowdSecShell
      title="CrowdSec"
      description={`Alerts and decisions of the ${CROWDSEC_RANGES[range].label}.`}
      configured={configured}
      canOpenSecurity={canOpenSecurity}
      actions={
        <SegmentedControl
          label="Time range"
          mono
          value={range}
          onChange={(next) => router.push(`/crowdsec?range=${next}`)}
          options={(Object.keys(CROWDSEC_RANGES) as CrowdSecRange[]).map((value) => ({ value, label: value }))}
        />
      }
    >
      {error && <CrowdSecError message={error} />}
      {dashboard && (
        <>
          {dashboard.truncated && (
            <Banner tone="warn">
              More than {formatCount(DASHBOARD_ALERT_LIMIT)} alerts in this period: the figures cover the newest {formatCount(DASHBOARD_ALERT_LIMIT)}.
            </Banner>
          )}
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <KpiTile label="Alerts" value={formatCount(dashboard.alerts)} color="var(--waf)" note={`${formatCount(dashboard.attackers)} sources`} href={`/crowdsec/alerts?range=${range}`} />
            <KpiTile
              label="Active decisions"
              value={dashboard.activeDecisions ? formatCount(dashboard.activeDecisions.local) : "—"}
              color="var(--rl)"
              note="CrowdSec's own and manual"
              href="/crowdsec/decisions"
            />
            <KpiTile
              label="Community blocklist"
              value={dashboard.activeDecisions ? formatCount(dashboard.activeDecisions.community + dashboard.activeDecisions.lists) : "—"}
              color="var(--access)"
              note={dashboard.activeDecisions ? "addresses from CAPI and lists" : "metrics not available"}
            />
            <KpiTile label="Protected hosts" value={`${protectedHosts} / ${enabledHosts}`} color="var(--served)" note="enabled hosts using the bouncer" href="/crowdsec/settings" />
          </div>
          <SectionCard title="Alerts by scenario" headingLevel={2} padded>
            <StackedBarChart
              title="Alerts by scenario"
              buckets={dashboard.chart.buckets}
              stepSeconds={CROWDSEC_RANGES[range].bucketMs / 1000}
              series={dashboard.chart.series.map((series, index) => ({ ...series, color: SERIES_COLORS[index % SERIES_COLORS.length] }))}
              emptyText="No alerts in this period."
            />
          </SectionCard>
          <div className="grid gap-3 lg:grid-cols-2">
            <TopList
              title="Scenarios"
              unit="Alerts"
              mono
              rows={dashboard.topScenarios.map((row) => ({ ...row, href: alertsHref("scenario", row.key) }))}
              total={dashboard.alerts}
              emptyText="No alerts in this period."
            />
            <TopList
              title="Sources"
              unit="Alerts"
              mono
              rows={dashboard.topAddresses.map((row) => ({ ...row, href: alertsHref("ip", row.key) }))}
              total={dashboard.alerts}
              emptyText="No alerts in this period."
            />
            <TopList
              title="Countries"
              unit="Alerts"
              rows={dashboard.topCountries.map((row) => ({ ...row, label: countryName(row.key) }))}
              total={dashboard.alerts}
              emptyText="No alerts in this period."
            />
            <TopList title="Networks (AS)" unit="Alerts" rows={dashboard.topAs} total={dashboard.alerts} emptyText="No alerts in this period." />
          </div>
          {dashboard.countries.length > 0 && (
            <SectionCard title="Where alerts come from" headingLevel={2} padded>
              <WorldMap data={dashboard.countries.map((entry) => ({ countryCode: entry.code, total: entry.count, blocked: entry.count }))} />
            </SectionCard>
          )}
        </>
      )}
    </CrowdSecShell>
  );
}
