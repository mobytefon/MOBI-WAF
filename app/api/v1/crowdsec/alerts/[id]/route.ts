import { NextRequest, NextResponse } from "next/server";
import { requireApiPermission } from "@/src/lib/api-auth";
import { crowdSecApiErrorResponse, crowdSecNotConfiguredResponse } from "@/src/lib/crowdsec/api";
import { getAlert } from "@/src/lib/crowdsec/lapi-client";
import { routeRowId } from "@/src/lib/row-ids";

/** One CrowdSec alert with its events and decisions. */
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    await requireApiPermission(request, "crowdsec:read");
    const notConfigured = crowdSecNotConfiguredResponse();
    if (notConfigured) return notConfigured;
    const { id } = await params;
    return NextResponse.json(await getAlert(routeRowId(id, "Alert not found")));
  } catch (error) {
    return crowdSecApiErrorResponse(error);
  }
}
