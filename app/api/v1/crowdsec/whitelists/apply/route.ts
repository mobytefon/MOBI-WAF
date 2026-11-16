import { NextRequest, NextResponse } from "next/server";
import { requireApiPermission } from "@/src/lib/api-auth";
import { crowdSecApiErrorResponse } from "@/src/lib/crowdsec/api";
import { reapplyCrowdSecWhitelists } from "@/src/lib/models/crowdsec-whitelists";

/** Hands the whitelists to CrowdSec again (a new generation), e.g. after a failed apply was fixed. */
export async function POST(request: NextRequest) {
  try {
    const { userId } = await requireApiPermission(request, "crowdsec:write");
    return NextResponse.json({ generation: await reapplyCrowdSecWhitelists(userId) }, { status: 202 });
  } catch (error) {
    return crowdSecApiErrorResponse(error);
  }
}
