import { requirePermission } from "@/src/lib/auth";
import { can } from "@/src/lib/permissions";
import { isCrowdSecConfigured } from "@/src/lib/crowdsec/config";
import { crowdSecActionError } from "@/src/lib/crowdsec/api";
import { listAlerts, type CrowdSecAlert } from "@/src/lib/crowdsec/lapi-client";
import { parseAlertQuery } from "@/src/lib/crowdsec/query";
import { CROWDSEC_RANGES, isCrowdSecRange } from "@/src/lib/crowdsec/ranges";
import CrowdSecAlertsClient from "./CrowdSecAlertsClient";

export const dynamic = "force-dynamic";
export const metadata = { title: "CrowdSec alerts" };

const ALERT_LIST_LIMIT = 500;

type SearchParams = { range?: string; ip?: string; scenario?: string; origin?: string };

/** CrowdSec alerts of a period, filtered by source address, scenario or origin. */
export default async function CrowdSecAlertsPage({ searchParams }: { searchParams: Promise<SearchParams> }) {
  const { access } = await requirePermission("crowdsec:read");
  const params = await searchParams;
  const range = isCrowdSecRange(params.range) ? params.range : "24h";
  const filters = { ip: params.ip?.trim() ?? "", scenario: params.scenario?.trim() ?? "", origin: params.origin?.trim() ?? "" };
  const configured = isCrowdSecConfigured();
  let alerts: CrowdSecAlert[] = [];
  let error: string | null = null;
  if (configured) {
    try {
      const search = new URLSearchParams({ since: CROWDSEC_RANGES[range].since, limit: String(ALERT_LIST_LIMIT) });
      for (const [key, value] of Object.entries(filters)) if (value) search.set(key, value);
      alerts = await listAlerts(parseAlertQuery(search));
    } catch (failure) {
      error = crowdSecActionError(failure, "The alerts could not be read");
    }
  }
  return (
    <CrowdSecAlertsClient
      configured={configured}
      range={range}
      filters={filters}
      alerts={alerts}
      limit={ALERT_LIST_LIMIT}
      error={error}
      canWrite={can(access, "crowdsec:write")}
      canOpenSecurity={can(access, "waf:read")}
    />
  );
}
