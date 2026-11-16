import { NextRequest, NextResponse } from "next/server";
import { requireApiPermission } from "@/src/lib/api-auth";
import { crowdSecApiErrorResponse } from "@/src/lib/crowdsec/api";
import { readJsonBody } from "@/src/lib/access-list-http";
import { createCrowdSecWhitelist, readCrowdSecWhitelistState, type CrowdSecWhitelistInput } from "@/src/lib/models/crowdsec-whitelists";
import { readManagedStatus } from "@/src/lib/crowdsec/managed-sync";

/** The managed whitelists, their generation and how far CrowdSec has applied them. */
export async function GET(request: NextRequest) {
  try {
    await requireApiPermission(request, "crowdsec:read");
    const [state, managed] = await Promise.all([readCrowdSecWhitelistState(), readManagedStatus()]);
    return NextResponse.json({ generation: state.generation, whitelists: state.entries, applied: managed.result, written: managed.written });
  } catch (error) {
    return crowdSecApiErrorResponse(error);
  }
}

/** Creates a whitelist. */
export async function POST(request: NextRequest) {
  try {
    const { userId } = await requireApiPermission(request, "crowdsec:write");
    const body = (await readJsonBody(request)) as CrowdSecWhitelistInput;
    return NextResponse.json(await createCrowdSecWhitelist(body, userId), { status: 201 });
  } catch (error) {
    return crowdSecApiErrorResponse(error);
  }
}
