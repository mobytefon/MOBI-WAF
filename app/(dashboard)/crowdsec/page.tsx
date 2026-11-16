import { requirePermission } from "@/src/lib/auth";
import { can } from "@/src/lib/permissions";
import { isCrowdSecConfigured } from "@/src/lib/crowdsec/config";
import { crowdSecActionError } from "@/src/lib/crowdsec/api";
import { isCrowdSecRange, listCrowdSecHostUse, loadCrowdSecDashboard, type CrowdSecDashboard } from "@/src/lib/crowdsec/dashboard";
import CrowdSecDashboardClient from "./CrowdSecDashboardClient";

export const dynamic = "force-dynamic";
export const metadata = { title: "CrowdSec" };

/** CrowdSec at a glance: alerts of the period, active decisions, top scenarios and sources. */
export default async function CrowdSecDashboardPage({ searchParams }: { searchParams: Promise<{ range?: string }> }) {
  const { access } = await requirePermission("crowdsec:read");
  const params = await searchParams;
  const range = isCrowdSecRange(params.range) ? params.range : "24h";
  const configured = isCrowdSecConfigured();
  let dashboard: CrowdSecDashboard | null = null;
  let error: string | null = null;
  if (configured) {
    try {
      dashboard = await loadCrowdSecDashboard(range);
    } catch (failure) {
      error = crowdSecActionError(failure, "The CrowdSec figures could not be read");
    }
  }
  const hosts = await listCrowdSecHostUse();
  return (
    <CrowdSecDashboardClient
      range={range}
      configured={configured}
      dashboard={dashboard}
      error={error}
      protectedHosts={hosts.filter((host) => host.protected).length}
      enabledHosts={hosts.filter((host) => host.enabled).length}
      canOpenSecurity={can(access, "waf:read")}
    />
  );
}
