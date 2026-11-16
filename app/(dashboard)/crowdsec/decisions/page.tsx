import { requirePermission } from "@/src/lib/auth";
import { can } from "@/src/lib/permissions";
import { isCrowdSecConfigured } from "@/src/lib/crowdsec/config";
import { crowdSecActionError } from "@/src/lib/crowdsec/api";
import { listActiveDecisions, type ActiveDecision } from "@/src/lib/crowdsec/decisions";
import { fetchCrowdSecMetrics } from "@/src/lib/crowdsec/lapi-client";
import CrowdSecDecisionsClient from "./CrowdSecDecisionsClient";

export const dynamic = "force-dynamic";
export const metadata = { title: "CrowdSec decisions" };

/** Active CrowdSec decisions, adding and deleting them, and looking an address up in every list. */
export default async function CrowdSecDecisionsPage({ searchParams }: { searchParams: Promise<{ origin?: string }> }) {
  const { access } = await requirePermission("crowdsec:read");
  const params = await searchParams;
  const origin = params.origin && /^[A-Za-z0-9_.:-]{1,100}$/.test(params.origin) ? params.origin : "";
  const configured = isCrowdSecConfigured();
  let decisions: ActiveDecision[] = [];
  let byOrigin: Record<string, number> | null = null;
  let error: string | null = null;
  if (configured) {
    try {
      const [list, metrics] = await Promise.all([listActiveDecisions({ origin: origin || undefined }), fetchCrowdSecMetrics().catch(() => null)]);
      decisions = list;
      byOrigin = metrics?.activeDecisionsByOrigin ?? null;
    } catch (failure) {
      error = crowdSecActionError(failure, "The decisions could not be read");
    }
  }
  return (
    <CrowdSecDecisionsClient
      configured={configured}
      origin={origin}
      decisions={decisions}
      byOrigin={byOrigin}
      error={error}
      canWrite={can(access, "crowdsec:write")}
      canOpenSecurity={can(access, "waf:read")}
    />
  );
}
