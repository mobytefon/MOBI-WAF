import { NextRequest, NextResponse } from "next/server";
import { requireApiPermission } from "@/src/lib/api-auth";
import { crowdSecApiErrorResponse, crowdSecNotConfiguredResponse } from "@/src/lib/crowdsec/api";
import { readJsonBody } from "@/src/lib/access-list-http";
import { ApiValidationError } from "@/src/lib/api-errors";
import { decisionsForAddress } from "@/src/lib/crowdsec/lapi-client";
import { banFromDashboard, listActiveDecisions, unbanAddress } from "@/src/lib/crowdsec/decisions";

/**
 * Active decisions. With `ip` (an address or range): the decisions for it
 * from every origin, community blocklist included; otherwise CrowdSec's own
 * and manual decisions, optionally of one `origin`.
 */
export async function GET(request: NextRequest) {
  try {
    await requireApiPermission(request, "crowdsec:read");
    const notConfigured = crowdSecNotConfiguredResponse();
    if (notConfigured) return notConfigured;
    const params = request.nextUrl.searchParams;
    const ip = params.get("ip");
    if (ip) return NextResponse.json(await decisionsForAddress(ip));
    return NextResponse.json(await listActiveDecisions({ origin: params.get("origin") ?? undefined }));
  } catch (error) {
    return crowdSecApiErrorResponse(error);
  }
}

/** Adds a decision (ban by default). A whitelisted address answers 409 unless `bypassWhitelist` is true. */
export async function POST(request: NextRequest) {
  try {
    const { userId } = await requireApiPermission(request, "crowdsec:write");
    const notConfigured = crowdSecNotConfiguredResponse();
    if (notConfigured) return notConfigured;
    const body = (await readJsonBody(request)) as Record<string, unknown> | null;
    if (!body || typeof body !== "object" || Array.isArray(body)) throw new ApiValidationError("Body must be an object");
    const result = await banFromDashboard(
      {
        target: String(body.value ?? ""),
        type: (body.type ?? "ban") as "ban",
        duration: String(body.duration ?? "4h"),
        reason: typeof body.reason === "string" ? body.reason : "",
        bypassWhitelist: body.bypassWhitelist === true,
      },
      userId
    );
    return NextResponse.json({ alertId: result.alertId }, { status: 201 });
  } catch (error) {
    return crowdSecApiErrorResponse(error);
  }
}

/** Deletes every decision for `ip` (an address or range). */
export async function DELETE(request: NextRequest) {
  try {
    const { userId } = await requireApiPermission(request, "crowdsec:write");
    const notConfigured = crowdSecNotConfiguredResponse();
    if (notConfigured) return notConfigured;
    const ip = request.nextUrl.searchParams.get("ip");
    if (!ip) throw new ApiValidationError("Give the address or range as ?ip=");
    return NextResponse.json({ deleted: await unbanAddress(ip, userId) });
  } catch (error) {
    return crowdSecApiErrorResponse(error);
  }
}
