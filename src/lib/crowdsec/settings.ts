/**
 * Global CrowdSec settings, stored under the "crowdsec" settings key. The
 * bouncer itself (LAPI URL, API key) comes from the environment
 * (./config.ts); these choose whether and where it blocks.
 */
import { getEffectiveSetting, setSetting } from "../settings";

export const CROWDSEC_SETTINGS_KEY = "crowdsec";

export type CrowdSecSettings = {
  /** Master switch: off means no host uses the bouncer, whatever its own setting. */
  enabled: boolean;
  /** Whether hosts that inherit (no setting of their own) use the bouncer. */
  apply_to_all_hosts: boolean;
  /** How often the bouncer pulls new and deleted decisions from the LAPI (Go duration). */
  ticker_interval: string;
  /** Time limit of each LAPI request the bouncer makes (Go duration). */
  lapi_timeout: string;
};

export const CROWDSEC_DEFAULT_SETTINGS: CrowdSecSettings = {
  enabled: false,
  apply_to_all_hosts: false,
  ticker_interval: "60s",
  lapi_timeout: "10s",
};

const DURATION_PATTERN = /^(?:\d+(?:ms|s|m|h))+$/;
const UNIT_MS: Record<string, number> = { ms: 1, s: 1_000, m: 60_000, h: 3_600_000 };

/** A Go-style duration ("60s", "1m30s") in milliseconds, or null when it is not one. */
export function parseCrowdSecDuration(value: unknown): number | null {
  if (typeof value !== "string" || !DURATION_PATTERN.test(value)) return null;
  let total = 0;
  for (const [, amount, unit] of value.matchAll(/(\d+)(ms|s|m|h)/g)) {
    total += Number(amount) * UNIT_MS[unit];
  }
  return total;
}

export const CROWDSEC_TICKER_RANGE_MS = { min: 5_000, max: 3_600_000 } as const;
export const CROWDSEC_TIMEOUT_RANGE_MS = { min: 1_000, max: 120_000 } as const;

/** Stored settings with defaults filled in and anything invalid replaced by its default. */
export function normalizeCrowdSecSettings(stored: Partial<CrowdSecSettings> | null | undefined): CrowdSecSettings {
  const inRange = (value: unknown, range: { min: number; max: number }) => {
    const ms = parseCrowdSecDuration(value);
    return ms !== null && ms >= range.min && ms <= range.max;
  };
  return {
    enabled: stored?.enabled === true,
    apply_to_all_hosts: stored?.apply_to_all_hosts === true,
    ticker_interval: inRange(stored?.ticker_interval, CROWDSEC_TICKER_RANGE_MS)
      ? (stored!.ticker_interval as string)
      : CROWDSEC_DEFAULT_SETTINGS.ticker_interval,
    lapi_timeout: inRange(stored?.lapi_timeout, CROWDSEC_TIMEOUT_RANGE_MS)
      ? (stored!.lapi_timeout as string)
      : CROWDSEC_DEFAULT_SETTINGS.lapi_timeout,
  };
}

const SETTINGS_FIELDS = ["enabled", "apply_to_all_hosts", "ticker_interval", "lapi_timeout"] as const;

/**
 * Why a settings write is invalid, or null when it is valid. `enabled` and
 * `apply_to_all_hosts` are required booleans; the durations are optional
 * Go durations within their ranges.
 */
export function crowdSecSettingsError(value: Record<string, unknown>): string | null {
  const unknownKeys = Object.keys(value).filter((key) => !(SETTINGS_FIELDS as readonly string[]).includes(key));
  if (unknownKeys.length > 0) return `CrowdSec settings have unknown field(s): ${unknownKeys.join(", ")}`;
  for (const key of ["enabled", "apply_to_all_hosts"] as const) {
    if (typeof value[key] !== "boolean") return `crowdsec.${key} must be true or false`;
  }
  const durations = [
    ["ticker_interval", CROWDSEC_TICKER_RANGE_MS, "5s", "1h"],
    ["lapi_timeout", CROWDSEC_TIMEOUT_RANGE_MS, "1s", "2m"],
  ] as const;
  for (const [key, range, min, max] of durations) {
    if (value[key] === undefined) continue;
    const ms = parseCrowdSecDuration(value[key]);
    if (ms === null || ms < range.min || ms > range.max) {
      return `crowdsec.${key} must be a duration such as "60s" or "1m30s", from ${min} to ${max}`;
    }
  }
  return null;
}

export async function getCrowdSecSettings(): Promise<CrowdSecSettings> {
  return normalizeCrowdSecSettings(await getEffectiveSetting<Partial<CrowdSecSettings>>(CROWDSEC_SETTINGS_KEY));
}

export async function saveCrowdSecSettings(settings: CrowdSecSettings): Promise<void> {
  await setSetting(CROWDSEC_SETTINGS_KEY, normalizeCrowdSecSettings(settings));
}
