"use server";

import { requirePermission } from "@/src/lib/auth";
import { getWafEventByEventId, isWafEventId } from "@/src/lib/models/waf-events";
import { wafRequestViewOf, type WafRequestView } from "@/src/lib/waf-request-capture";

export type WafRequestResult = { ok: true; value: WafRequestView } | { ok: false; error: string };

/**
 * The full HTTP request of a WAF event (request line, headers, the body kept)
 * and the matched values kept at ingest: the Full HTTP request of an event on
 * the Security events page. Credentials were redacted at ingest
 * (waf-log-parser.ts, waf-request-capture.ts).
 */
export async function wafRequestAction(eventId: string): Promise<WafRequestResult> {
  await requirePermission("waf:read");
  if (typeof eventId !== "string" || !isWafEventId(eventId)) return { ok: false, error: "This is not a WAF event id." };
  const event = await getWafEventByEventId(eventId);
  if (!event) return { ok: false, error: "This event is no longer stored." };
  const view = wafRequestViewOf(event.rawData);
  if (!view) return { ok: false, error: "No audit record was stored with this event." };
  return { ok: true, value: view };
}
