/** Time ranges of the CrowdSec pages (safe to import in client components). */

export const CROWDSEC_RANGES = {
  "24h": { since: "24h", bucketMs: 3_600_000, buckets: 24, label: "last 24 hours" },
  "7d": { since: "168h", bucketMs: 6 * 3_600_000, buckets: 28, label: "last 7 days" },
} as const;
export type CrowdSecRange = keyof typeof CROWDSEC_RANGES;

export function isCrowdSecRange(value: unknown): value is CrowdSecRange {
  return typeof value === "string" && Object.hasOwn(CROWDSEC_RANGES, value);
}

/** At most this many alerts are read for the dashboard figures; it says so when it is reached. */
export const DASHBOARD_ALERT_LIMIT = 10_000;
