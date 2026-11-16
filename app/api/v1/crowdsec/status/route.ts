import { NextRequest, NextResponse } from "next/server";
import { requireApiPermission } from "@/src/lib/api-auth";
import { crowdSecApiErrorResponse } from "@/src/lib/crowdsec/api";
import { isCrowdSecConfigured } from "@/src/lib/crowdsec/config";
import { getCrowdSecSettings } from "@/src/lib/crowdsec/settings";
import { checkLapi, fetchCrowdSecMetrics } from "@/src/lib/crowdsec/lapi-client";
import { groupActiveDecisions, listCrowdSecHostUse } from "@/src/lib/crowdsec/dashboard";
import { readManagedStatus } from "@/src/lib/crowdsec/managed-sync";

/** Whether CrowdSec is configured and reachable, its settings, active decisions and the hosts it protects. */
export async function GET(request: NextRequest) {
  try {
    await requireApiPermission(request, "crowdsec:read");
    const configured = isCrowdSecConfigured();
    const [settings, hosts] = await Promise.all([getCrowdSecSettings(), listCrowdSecHostUse()]);
    if (!configured) return NextResponse.json({ configured, settings, lapi: null, activeDecisions: null, managed: null, hosts });
    const [lapi, metrics, managed] = await Promise.all([checkLapi(), fetchCrowdSecMetrics().catch(() => null), readManagedStatus()]);
    return NextResponse.json({
      configured,
      settings,
      lapi,
      activeDecisions: metrics ? groupActiveDecisions(metrics.activeDecisionsByOrigin) : null,
      managed: { available: managed.available, written: managed.written, result: managed.result },
      hosts,
    });
  } catch (error) {
    return crowdSecApiErrorResponse(error);
  }
}
