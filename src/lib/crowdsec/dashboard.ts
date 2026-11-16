/**
 * The CrowdSec dashboard's figures, worked out from the LAPI's alerts of the
 * chosen period (no copy is kept here) and its Prometheus metrics.
 */
import { appDb } from "../db";
import { proxyHosts } from "../db/schema";
import { crowdSecAppliesToHost, type CrowdSecHostConfig } from "./host-mode";
import { fetchCrowdSecMetrics, listAlerts, type CrowdSecAlert } from "./lapi-client";
import { getCrowdSecSettings } from "./settings";
import { CROWDSEC_RANGES, DASHBOARD_ALERT_LIMIT, type CrowdSecRange } from "./ranges";

export { CROWDSEC_RANGES, DASHBOARD_ALERT_LIMIT, isCrowdSecRange, type CrowdSecRange } from "./ranges";

const TOP = 10;
const CHART_SCENARIOS = 5;

export type Ranked = { key: string; label: string; count: number; sub?: string; code?: string };

export type CrowdSecDashboard = {
  range: CrowdSecRange;
  alerts: number;
  /** The alert limit was reached, so the figures cover the newest alerts only. */
  truncated: boolean;
  attackers: number;
  alertsWithDecision: number;
  activeDecisions: { local: number; community: number; lists: number; byOrigin: Record<string, number> } | null;
  chart: { buckets: number[]; series: { key: string; label: string; values: number[] }[] };
  topScenarios: Ranked[];
  topAddresses: Ranked[];
  topCountries: Ranked[];
  topAs: Ranked[];
  /** Alerts by country code, for the map. */
  countries: { code: string; count: number }[];
};

function alertTime(alert: CrowdSecAlert): number {
  for (const value of [alert.start_at, alert.created_at, alert.stop_at]) {
    const ms = value ? Date.parse(value) : NaN;
    if (Number.isFinite(ms)) return ms;
  }
  return NaN;
}

function addressOf(alert: CrowdSecAlert): string {
  return alert.source?.ip || alert.source?.range || alert.source?.value || "unknown";
}

function rank(counts: Map<string, { count: number; label?: string; sub?: string; code?: string }>, limit = TOP): Ranked[] {
  return [...counts.entries()]
    .sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([key, entry]) => ({ key, label: entry.label ?? key, count: entry.count, ...(entry.sub ? { sub: entry.sub } : {}), ...(entry.code ? { code: entry.code } : {}) }));
}

function bump(counts: Map<string, { count: number; label?: string; sub?: string; code?: string }>, key: string, extra: { label?: string; sub?: string; code?: string } = {}) {
  const entry = counts.get(key);
  if (entry) entry.count += 1;
  else counts.set(key, { count: 1, ...extra });
}

/** The figures of a list of alerts. Pure: `now` sets the chart's last bucket. */
export function summarizeAlerts(alerts: readonly CrowdSecAlert[], range: CrowdSecRange, now: number): Omit<CrowdSecDashboard, "activeDecisions" | "truncated"> {
  const { bucketMs, buckets: count } = CROWDSEC_RANGES[range];
  const end = Math.floor(now / bucketMs) * bucketMs;
  const buckets = Array.from({ length: count }, (_, i) => end - (count - 1 - i) * bucketMs);
  const scenarios = new Map<string, { count: number }>();
  const addresses = new Map<string, { count: number; sub?: string; code?: string }>();
  const countries = new Map<string, { count: number; code?: string }>();
  const asns = new Map<string, { count: number; label?: string; sub?: string }>();
  let withDecision = 0;

  for (const alert of alerts) {
    const scenario = alert.scenario || "unknown";
    bump(scenarios, scenario);
    const country = alert.source?.cn?.toUpperCase();
    bump(addresses, addressOf(alert), { ...(country ? { code: country } : {}), ...(alert.source?.as_name ? { sub: alert.source.as_name } : {}) });
    if (country) bump(countries, country, { code: country });
    if (alert.source?.as_number) {
      bump(asns, alert.source.as_number, { label: `AS${alert.source.as_number}`, ...(alert.source.as_name ? { sub: alert.source.as_name } : {}) });
    }
    if ((alert.decisions?.length ?? 0) > 0) withDecision += 1;
  }

  const chartScenarios = rank(scenarios, CHART_SCENARIOS).map((row) => row.key);
  const series = [...chartScenarios, "other"].map((key) => ({ key, label: key === "other" ? "Other scenarios" : key, values: buckets.map(() => 0) }));
  const seriesIndex = new Map(series.map((entry, index) => [entry.key, index]));
  for (const alert of alerts) {
    const at = alertTime(alert);
    if (!Number.isFinite(at)) continue;
    const bucket = Math.floor((Math.floor(at / bucketMs) * bucketMs - buckets[0]) / bucketMs);
    if (bucket < 0 || bucket >= count) continue;
    const index = seriesIndex.get(alert.scenario) ?? seriesIndex.get("other")!;
    series[index].values[bucket] += 1;
  }

  return {
    range,
    alerts: alerts.length,
    attackers: addresses.size,
    alertsWithDecision: withDecision,
    chart: { buckets, series: series.filter((entry) => entry.key !== "other" || entry.values.some((value) => value > 0)) },
    topScenarios: rank(scenarios),
    topAddresses: rank(addresses),
    topCountries: rank(countries),
    topAs: rank(asns),
    countries: [...countries.entries()].map(([code, entry]) => ({ code, count: entry.count })),
  };
}

/** Active decisions by origin: CrowdSec's own and manual ones, the community blocklist, and other lists. */
export function groupActiveDecisions(byOrigin: Record<string, number>): NonNullable<CrowdSecDashboard["activeDecisions"]> {
  let local = 0;
  let community = 0;
  let lists = 0;
  for (const [origin, value] of Object.entries(byOrigin)) {
    if (origin === "CAPI") community += value;
    else if (origin.startsWith("lists")) lists += value;
    else local += value;
  }
  return { local, community, lists, byOrigin };
}

export async function loadCrowdSecDashboard(range: CrowdSecRange): Promise<CrowdSecDashboard> {
  const [alerts, metrics] = await Promise.all([
    listAlerts({ since: CROWDSEC_RANGES[range].since, limit: DASHBOARD_ALERT_LIMIT }),
    fetchCrowdSecMetrics().catch(() => null),
  ]);
  return {
    ...summarizeAlerts(alerts, range, Date.now()),
    truncated: alerts.length >= DASHBOARD_ALERT_LIMIT,
    activeDecisions: metrics ? groupActiveDecisions(metrics.activeDecisionsByOrigin) : null,
  };
}

export type CrowdSecHostUse = { id: number; name: string; enabled: boolean; mode: "inherit" | "on" | "off"; protected: boolean };

/** Every proxy host with its CrowdSec mode and whether the bouncer runs on it. */
export async function listCrowdSecHostUse(): Promise<CrowdSecHostUse[]> {
  const [settings, rows] = await Promise.all([
    getCrowdSecSettings(),
    appDb.select({ id: proxyHosts.id, name: proxyHosts.name, enabled: proxyHosts.enabled, meta: proxyHosts.meta }).from(proxyHosts).orderBy(proxyHosts.name),
  ]);
  return rows.map((row) => {
    let config: CrowdSecHostConfig | undefined;
    try {
      config = (JSON.parse(row.meta ?? "{}") as { crowdsec?: CrowdSecHostConfig }).crowdsec;
    } catch {
      config = undefined;
    }
    const mode = config?.enabled === true ? "on" : config?.enabled === false ? "off" : "inherit";
    return { id: row.id, name: row.name, enabled: Boolean(row.enabled), mode, protected: Boolean(row.enabled) && crowdSecAppliesToHost(settings, config) };
  });
}
