/** Shared pieces of the /api/v1/crowdsec routes. */
import { NextResponse } from "next/server";
import { apiErrorResponse } from "../api-auth";
import { ApiClientError } from "../api-errors";
import { isCrowdSecConfigured } from "./config";
import { CrowdSecUnavailableError } from "./lapi-client";

/** apiErrorResponse, with CrowdSec being unreachable as 502 and its (application-written) message. */
export function crowdSecApiErrorResponse(error: unknown): NextResponse {
  if (error instanceof CrowdSecUnavailableError) {
    return NextResponse.json({ error: error.message, code: "CROWDSEC_UNAVAILABLE" }, { status: 502 });
  }
  return apiErrorResponse(error);
}

/** 404 when CrowdSec is not configured on this instance, else null. */
export function crowdSecNotConfiguredResponse(): NextResponse | null {
  if (isCrowdSecConfigured()) return null;
  return NextResponse.json(
    { error: "CrowdSec is not configured on this instance (see docker-compose.crowdsec.yml)", code: "CROWDSEC_NOT_CONFIGURED" },
    { status: 404 }
  );
}

/** The action result of a dashboard server action, with CrowdSec's own messages kept. */
export function crowdSecActionError(error: unknown, fallback: string): string {
  if (error instanceof CrowdSecUnavailableError) return error.message;
  if (error instanceof ApiClientError) return error.message;
  return fallback;
}
