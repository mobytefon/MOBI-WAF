import { NextRequest, NextResponse } from "next/server";
import { requireApiPermission } from "@/src/lib/api-auth";
import { crowdSecApiErrorResponse, crowdSecNotConfiguredResponse } from "@/src/lib/crowdsec/api";
import { unbanDecision } from "@/src/lib/crowdsec/decisions";
import { routeRowId } from "@/src/lib/row-ids";

/** Deletes one decision. */
export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { userId } = await requireApiPermission(request, "crowdsec:write");
    const notConfigured = crowdSecNotConfiguredResponse();
    if (notConfigured) return notConfigured;
    const { id } = await params;
    return NextResponse.json({ deleted: await unbanDecision(routeRowId(id, "Decision not found"), userId) });
  } catch (error) {
    return crowdSecApiErrorResponse(error);
  }
}
