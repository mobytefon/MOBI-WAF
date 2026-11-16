/** Formatting shared by the CrowdSec pages (client-safe). */
import type { CrowdSecAlert } from "@/src/lib/crowdsec/lapi-client";

/** A LAPI time as "16 Nov 2026, 14:03:12 UTC", or "—". */
export function formatWhen(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime()) || date.getUTCFullYear() < 2000) return "—";
  return `${date.toLocaleString("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", timeZone: "UTC" })} UTC`;
}

/** An alert's source address and where it is (country · AS). */
export function sourceOf(alert: CrowdSecAlert): { address: string; where: string } {
  const source = alert.source ?? {};
  const address = source.ip || source.range || source.value || "unknown";
  const where = [source.cn, source.as_number ? `AS${source.as_number}${source.as_name ? ` ${source.as_name}` : ""}` : null].filter(Boolean).join(" · ");
  return { address, where };
}
