import { NextRequest, NextResponse } from "next/server";
import { requireApiPermission } from "@/src/lib/api-auth";
import { crowdSecApiErrorResponse, crowdSecNotConfiguredResponse } from "@/src/lib/crowdsec/api";
import { listAlerts } from "@/src/lib/crowdsec/lapi-client";
import { parseAlertQuery } from "@/src/lib/crowdsec/query";

/** CrowdSec alerts, newest first (the community blocklist excluded). */
export async function GET(request: NextRequest) {
  try {
    await requireApiPermission(request, "crowdsec:read");
    const notConfigured = crowdSecNotConfiguredResponse();
    if (notConfigured) return notConfigured;
    return NextResponse.json(await listAlerts(parseAlertQuery(request.nextUrl.searchParams)));
  } catch (error) {
    return crowdSecApiErrorResponse(error);
  }
}
