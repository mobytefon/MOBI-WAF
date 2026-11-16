import { NextRequest, NextResponse } from "next/server";
import { requireApiPermission } from "@/src/lib/api-auth";
import { crowdSecApiErrorResponse } from "@/src/lib/crowdsec/api";
import { readJsonBody } from "@/src/lib/access-list-http";
import { deleteCrowdSecWhitelist, updateCrowdSecWhitelist, type CrowdSecWhitelistInput } from "@/src/lib/models/crowdsec-whitelists";
import { routeRowId } from "@/src/lib/row-ids";

/** Replaces a whitelist (every field; `enabled` defaults to true). */
export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { userId } = await requireApiPermission(request, "crowdsec:write");
    const { id } = await params;
    const body = (await readJsonBody(request)) as CrowdSecWhitelistInput;
    return NextResponse.json(await updateCrowdSecWhitelist(routeRowId(id, "Whitelist not found"), body, userId));
  } catch (error) {
    return crowdSecApiErrorResponse(error);
  }
}

/** Deletes a whitelist. */
export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { userId } = await requireApiPermission(request, "crowdsec:write");
    const { id } = await params;
    await deleteCrowdSecWhitelist(routeRowId(id, "Whitelist not found"), userId);
    return NextResponse.json({ ok: true });
  } catch (error) {
    return crowdSecApiErrorResponse(error);
  }
}
