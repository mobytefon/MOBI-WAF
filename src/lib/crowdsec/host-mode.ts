/**
 * Whether one proxy host uses the CrowdSec bouncer. Stored in the host's
 * meta.crowdsec: no setting (or no `enabled`) inherits the global "apply to
 * all hosts" switch, `enabled: true` turns it on and `enabled: false` off.
 * The global master switch (`enabled`) wins over both.
 */
import { ApiValidationError } from "../api-errors";
import type { CrowdSecSettings } from "./settings";

export type CrowdSecHostConfig = {
  enabled?: boolean;
};

export const CROWDSEC_HOST_MODES = ["inherit", "on", "off"] as const;
export type CrowdSecHostMode = (typeof CROWDSEC_HOST_MODES)[number];

export function isCrowdSecHostMode(value: unknown): value is CrowdSecHostMode {
  return (CROWDSEC_HOST_MODES as readonly unknown[]).includes(value);
}

export function crowdSecHostModeOf(config: CrowdSecHostConfig | null | undefined): CrowdSecHostMode {
  if (config?.enabled === true) return "on";
  if (config?.enabled === false) return "off";
  return "inherit";
}

/** The stored config for a mode; null (no setting) for inherit. */
export function crowdSecConfigForMode(mode: CrowdSecHostMode): CrowdSecHostConfig | null {
  if (mode === "on") return { enabled: true };
  if (mode === "off") return { enabled: false };
  return null;
}

/** Whether the bouncer runs on a host with this config under these global settings. */
export function crowdSecAppliesToHost(
  settings: CrowdSecSettings | null | undefined,
  config: CrowdSecHostConfig | null | undefined
): boolean {
  if (!settings?.enabled) return false;
  const mode = crowdSecHostModeOf(config);
  if (mode === "on") return true;
  if (mode === "off") return false;
  return settings.apply_to_all_hosts;
}

/** Validates a host's `crowdsec` input; only `enabled` (a boolean, or absent) is allowed. */
export function validateCrowdSecHostConfig(value: unknown): CrowdSecHostConfig {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ApiValidationError("crowdsec must be an object such as { \"enabled\": true }, or null to inherit");
  }
  const unknownKeys = Object.keys(value).filter((key) => key !== "enabled");
  if (unknownKeys.length > 0) {
    throw new ApiValidationError(`crowdsec has unknown field(s): ${unknownKeys.join(", ")}`);
  }
  const enabled = (value as { enabled?: unknown }).enabled;
  if (enabled !== undefined && typeof enabled !== "boolean") {
    throw new ApiValidationError("crowdsec.enabled must be true, false, or left out to inherit");
  }
  return enabled === undefined ? {} : { enabled };
}
